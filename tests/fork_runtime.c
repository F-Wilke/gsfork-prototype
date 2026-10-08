#define _GNU_SOURCE
#include <asm/prctl.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/memfd.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static const uintptr_t space_start = 0x2000000000ULL;
static const uintptr_t parent_span = 0x40000000ULL;
static const uintptr_t child_stack_span = 0x02000000ULL;
static const uintptr_t gs_delta = 0x10000000000ULL;

uint64_t fork_native_global = 23;
uintptr_t fork_observed_rsp;

typedef uint64_t (*probe_fn)(void *, uint64_t, uint64_t);

extern uint64_t fork_memory_probe(void *, uint64_t, uint64_t);
extern uint64_t fork_indirect_call(void *, uint64_t, uint64_t);
extern uint64_t fork_indirect_jump(void *, uint64_t, uint64_t);
extern uint64_t fork_rip_probe(void *, uint64_t, uint64_t);
extern uint64_t fork_jump_target(void *, uint64_t, uint64_t);
extern uint64_t fork_call_on_stack(
    void *stack_top, probe_fn function, void *arg1, uint64_t arg2, uint64_t arg3
);
extern pid_t fork_raw_to_child_stack(
    void *stack_top, probe_fn function, void *arg1, uint64_t arg2, uint64_t arg3
);

struct alias {
    void *logical;
    void *shifted;
    size_t bytes;
};

struct runtime_result {
    uint64_t memory;
    uint64_t indirect_call;
    uint64_t indirect_jump;
    uint64_t rip;
    uintptr_t observed_rsp;
    uintptr_t parent_rsp_at_fork;
    int child_alias_matches;
    int parent_alias_matches;
    int verified;
};

static struct alias data_mapping;
static struct alias parent_stack_mapping;
static struct alias child_stack_mapping;
static struct alias jump_table_mapping;
static uintptr_t parent_stack_start;
static uintptr_t child_stack_start;
static uintptr_t parent_rsp_at_fork;
static int result_pipe[2];
static struct runtime_result parent_result;
static int parent_result_valid;

static void die(const char *message)
{
    perror(message);
    exit(1);
}

static void set_gs(uintptr_t base)
{
    if (syscall(SYS_arch_prctl, ARCH_SET_GS, base))
        die("ARCH_SET_GS");
}

static struct alias map_alias(uintptr_t address, size_t bytes)
{
    int fd = memfd_create("gsfork-fork-test", MFD_CLOEXEC);
    if (fd < 0 || ftruncate(fd, (off_t)bytes))
        die("memfd");
    void *logical = mmap(
        (void *)address, bytes, PROT_READ | PROT_WRITE,
        MAP_SHARED | MAP_FIXED_NOREPLACE, fd, 0
    );
    if (logical == MAP_FAILED)
        die("mmap logical");
    void *shifted = mmap(
        (void *)(address + gs_delta), bytes, PROT_READ | PROT_WRITE,
        MAP_SHARED | MAP_FIXED_NOREPLACE, fd, 0
    );
    if (shifted == MAP_FAILED)
        die("mmap shifted");
    close(fd);
    return (struct alias){logical, shifted, bytes};
}

static void protect_logical(struct alias *mapping, int protect)
{
    if (mprotect(
            mapping->logical, mapping->bytes,
            protect ? PROT_NONE : PROT_READ | PROT_WRITE
        ))
        die("mprotect");
}

static struct runtime_result run_child(
    int shifted
)
{
    unsigned long saved_gs;
    if (syscall(SYS_arch_prctl, ARCH_GET_GS, &saved_gs))
        die("ARCH_GET_GS");
    int parent_alias_matches = !memcmp(
        parent_stack_mapping.logical, parent_stack_mapping.shifted,
        parent_stack_mapping.bytes
    );
    set_gs(shifted ? gs_delta : 0);
    if (shifted) {
        protect_logical(&data_mapping, 1);
        protect_logical(&parent_stack_mapping, 1);
        protect_logical(&jump_table_mapping, 1);
    }

    void *stack_top = (char *)child_stack_mapping.logical +
                      child_stack_mapping.bytes - 16;
    struct runtime_result result = {0};
    result.memory = fork_call_on_stack(
        stack_top, fork_memory_probe, data_mapping.logical,
        (uint64_t)(uintptr_t)parent_stack_mapping.logical, 29
    );
    result.indirect_call = fork_call_on_stack(
        stack_top, fork_indirect_call,
        jump_table_mapping.logical, 37, 0
    );
    result.indirect_jump = fork_call_on_stack(
        stack_top, fork_indirect_jump,
        jump_table_mapping.logical, 41, 0
    );
    result.rip = fork_call_on_stack(
        stack_top, fork_rip_probe, NULL, 0, 0
    );
    result.observed_rsp = fork_observed_rsp;
    result.parent_rsp_at_fork = parent_rsp_at_fork;
    result.child_alias_matches =
        !memcmp(
            child_stack_mapping.logical, child_stack_mapping.shifted,
            child_stack_mapping.bytes
        );
    result.parent_alias_matches = parent_alias_matches;
    int stack_in_child_range =
        result.observed_rsp >= child_stack_start &&
        result.observed_rsp < child_stack_start + child_stack_mapping.bytes;
    int fork_used_parent_stack =
        result.parent_rsp_at_fork >= parent_stack_start &&
        result.parent_rsp_at_fork <
            parent_stack_start + parent_stack_mapping.bytes;
    result.verified =
        result.memory == 86 && result.indirect_call == 42 &&
        result.indirect_jump == 46 && result.rip == fork_native_global &&
        stack_in_child_range && fork_used_parent_stack &&
        result.child_alias_matches && result.parent_alias_matches;
    set_gs(saved_gs);
    return result;
}

static uint64_t child_entry(void *unused, uint64_t shifted, uint64_t ignored)
{
    (void)unused;
    (void)ignored;
    close(result_pipe[0]);
    struct runtime_result result = run_child((int)shifted);
    ssize_t written = write(result_pipe[1], &result, sizeof(result));
    close(result_pipe[1]);
    _exit(written == (ssize_t)sizeof(result) && result.verified ? 0 : 1);
}

static uint64_t fork_entry(void *unused, uint64_t shifted, uint64_t ignored)
{
    (void)unused;
    (void)ignored;
    __asm__ volatile("mov %%rsp, %0" : "=r"(parent_rsp_at_fork));
    void *child_stack_top = (char *)child_stack_mapping.logical +
                            child_stack_mapping.bytes - 16;
    pid_t child = fork_raw_to_child_stack(
        child_stack_top, child_entry, NULL, shifted, 0
    );
    if (child < 0) {
        errno = -child;
        die("fork");
    }

    close(result_pipe[1]);
    ssize_t received = read(
        result_pipe[0], &parent_result, sizeof(parent_result)
    );
    close(result_pipe[0]);
    int status;
    if (waitpid(child, &status, 0) != child)
        die("waitpid");
    if (WIFSIGNALED(status)) {
        int child_signal = WTERMSIG(status);
        signal(child_signal, SIG_DFL);
        raise(child_signal);
        return 128 + (uint64_t)child_signal;
    }
    parent_result_valid =
        received == (ssize_t)sizeof(parent_result) &&
        WIFEXITED(status) && WEXITSTATUS(status) == 0 &&
        parent_result.verified;
    return parent_result_valid ? 0 : 1;
}

int main(int argc, char **argv)
{
    if (argc != 1)
        return 2;
    size_t page = (size_t)sysconf(_SC_PAGESIZE);
    uintptr_t data_address = space_start + 4 * page;
    parent_stack_start = space_start + parent_span - 8 * page;
    child_stack_start = space_start + parent_span + 2 * page;
    if (child_stack_start + 8 * page >=
        space_start + parent_span + child_stack_span)
        return 2;

    data_mapping = map_alias(data_address, page);
    parent_stack_mapping = map_alias(parent_stack_start, 8 * page);
    child_stack_mapping = map_alias(child_stack_start, 8 * page);
    jump_table_mapping = map_alias(space_start + 8 * page, page);
    *(uint64_t *)data_mapping.logical = 11;
    *(uint64_t *)parent_stack_mapping.logical = 17;
    *(void **)jump_table_mapping.logical = fork_jump_target;

    int shifted = strstr(argv[0], "rewritten") != NULL ||
                  strstr(argv[0], "unrewritten-shift") != NULL;
    if (pipe2(result_pipe, O_CLOEXEC))
        die("pipe2");
    void *parent_stack_top = (char *)parent_stack_mapping.logical +
                             parent_stack_mapping.bytes - 16;
    uint64_t fork_status = fork_call_on_stack(
        parent_stack_top, fork_entry, NULL, (uint64_t)shifted, 0
    );
    int verified = !fork_status && parent_result_valid;
    printf(
        "{\"variant\":\"%s\",\"memory\":%" PRIu64
        ",\"indirect_call\":%" PRIu64 ",\"indirect_jump\":%" PRIu64
        ",\"rip\":%" PRIu64 ",\"observed_rsp\":%" PRIuPTR
        ",\"parent_rsp_at_fork\":%" PRIuPTR
        ",\"parent_stack_start\":%" PRIuPTR
        ",\"parent_stack_end\":%" PRIuPTR
        ",\"child_stack_start\":%" PRIuPTR
        ",\"child_stack_end\":%" PRIuPTR
        ",\"child_alias_matches\":%s,\"parent_alias_matches\":%s"
        ",\"verified\":%s}\n",
        shifted ? "shifted" : "baseline",
        parent_result.memory, parent_result.indirect_call,
        parent_result.indirect_jump, parent_result.rip,
        parent_result.observed_rsp, parent_result.parent_rsp_at_fork,
        parent_stack_start,
        parent_stack_start + parent_stack_mapping.bytes,
        child_stack_start,
        child_stack_start + child_stack_mapping.bytes,
        parent_result.child_alias_matches ? "true" : "false",
        parent_result.parent_alias_matches ? "true" : "false",
        verified ? "true" : "false"
    );
    return verified ? 0 : 1;
}
