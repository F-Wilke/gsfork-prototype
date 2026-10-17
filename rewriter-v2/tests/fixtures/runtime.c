#define _GNU_SOURCE
#include <asm/prctl.h>
#include <dlfcn.h>
#include <elf.h>
#include <errno.h>
#include <link.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <ucontext.h>
#include <unistd.h>

static _Thread_local struct {
    uint64_t scratch_rax;
    uint64_t sandbox_offset;
} control;

struct invocation {
    uint64_t gs, old_gs, function, stack, rax, rdi, rsi, rcx, flags, rdx;
};
extern long run_kernel(struct invocation *);
static const size_t page = 4096;
static unsigned char *logical, *actual, *stack;
static uintptr_t active_gs, initial_gs, copy_function, rep_address;
static volatile sig_atomic_t faults, nested_signals;

static void check(int condition, const char *message) {
    if (!condition) {
        fprintf(stderr, "runtime: %s (errno=%d)\n", message, errno);
        exit(1);
    }
}

static void *map_at(uintptr_t address, size_t length, int flags, int fd) {
    void *result = mmap((void *)address, length, PROT_READ | PROT_WRITE,
                        flags | MAP_FIXED_NOREPLACE, fd, 0);
    if (result == MAP_FAILED)
        fprintf(stderr, "mmap address=%#lx length=%zu\n", (unsigned long)address, length);
    check(result != MAP_FAILED, "mmap alias");
    return result;
}

static struct invocation invocation(uintptr_t function, uint64_t old_gs, size_t stack_offset) {
    struct invocation value = {
        .gs = active_gs, .old_gs = old_gs, .function = function,
        .stack = (uintptr_t)stack + stack_offset, .flags = 0x202,
    };
    return value;
}

static void nested_copy(void) {
    uint64_t saved_scratch = control.scratch_rax;
    struct invocation value = invocation(copy_function, active_gs, page * 4);
    value.rax = UINT64_C(0xabcd1234eeff9876);
    value.rsi = (uintptr_t)logical + 128;
    value.rdi = (uintptr_t)logical + page * 4 + 128;
    value.rcx = 8;
    if (run_kernel(&value) || value.rcx || value.rax != UINT64_C(0xabcd1234eeff9876))
        _exit(91);
    control.scratch_rax = saved_scratch;
}

static void handler(int signal, siginfo_t *info, void *raw_context) {
    uint64_t saved_scratch = control.scratch_rax;
    if (signal == SIGUSR1) {
        ++nested_signals;
        nested_copy();
    } else {
        ucontext_t *context = raw_context;
        if (++faults != 1 || (uintptr_t)info->si_addr != (uintptr_t)actual + page
            || (uintptr_t)context->uc_mcontext.gregs[REG_RIP] != rep_address
            || (uintptr_t)context->uc_mcontext.gregs[REG_RSI] != (uintptr_t)actual + page
            || (uintptr_t)context->uc_mcontext.gregs[REG_RDI] != (uintptr_t)actual + page * 5
            || context->uc_mcontext.gregs[REG_RCX] != 48)
            _exit(92);
        if (mprotect(actual + page, page, PROT_READ | PROT_WRITE))
            _exit(93);
        nested_copy();
        if (raise(SIGUSR1))
            _exit(94);
    }
    control.scratch_rax = saved_scratch;
}

int main(int argc, char **argv) {
    check(argc == 4, "usage: runtime library {zero|shift} rep-offset");
    uintptr_t fs;
    check(!syscall(SYS_arch_prctl, ARCH_GET_FS, &fs), "get FS");
    check((intptr_t)&control.scratch_rax - (intptr_t)fs == -16
          && (intptr_t)&control.sandbox_offset - (intptr_t)fs == -8, "fixture TLS offsets");
    check(!syscall(SYS_arch_prctl, ARCH_GET_GS, &initial_gs), "get GS");
    active_gs = strcmp(argv[2], "zero") ? UINT64_C(0x1000000) : 0;
    control.sandbox_offset = active_gs;
    void *library = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    check(library != NULL, dlerror());
    uintptr_t probe = (uintptr_t)dlsym(library, "gs_probe");
    uintptr_t jump = (uintptr_t)dlsym(library, "gs_jump");
    uintptr_t plt = (uintptr_t)dlsym(library, "gs_plt");
    uintptr_t tls = (uintptr_t)dlsym(library, "gs_tls");
    uintptr_t ifunc = (uintptr_t)dlsym(library, "call_ifunc");
    uintptr_t resolver = (uintptr_t)dlsym(library, "exercise_resolver");
    uintptr_t lock = (uintptr_t)dlsym(library, "gs_lock");
    uintptr_t tls_value = (uintptr_t)dlsym(library, "tls_value");
    uintptr_t tls_change = (uintptr_t)dlsym(library, "tls_change");
    uintptr_t masked_table = (uintptr_t)dlsym(library, "gs_masked_table");
    struct string_case { const char *name; size_t width; int stos, repeated; uintptr_t function; };
    struct string_case strings[] = {
        {"gs_copy", 1, 0, 1, 0}, {"gs_movsw", 2, 0, 1, 0},
        {"gs_movsd", 4, 0, 1, 0}, {"gs_movsq", 8, 0, 1, 0},
        {"gs_stosb", 1, 1, 1, 0}, {"gs_stosw", 2, 1, 1, 0},
        {"gs_stosd", 4, 1, 1, 0}, {"gs_stosq", 8, 1, 1, 0},
        {"gs_one_movsb", 1, 0, 0, 0}, {"gs_one_movsw", 2, 0, 0, 0},
        {"gs_one_movsd", 4, 0, 0, 0}, {"gs_one_movsq", 8, 0, 0, 0},
        {"gs_one_stosb", 1, 1, 0, 0}, {"gs_one_stosw", 2, 1, 0, 0},
        {"gs_one_stosd", 4, 1, 0, 0}, {"gs_one_stosq", 8, 1, 0, 0},
    };
    for (unsigned i = 0; i < sizeof(strings) / sizeof(strings[0]); ++i) {
        strings[i].function = (uintptr_t)dlsym(library, strings[i].name);
        check(strings[i].function != 0, "string function export");
    }
    copy_function = (uintptr_t)dlsym(library, "gs_copy");
    uintptr_t (*address)(void) = (uintptr_t (*)(void))dlsym(library, "gs_address");
    check(probe && jump && plt && tls && ifunc && resolver && lock && tls_value && tls_change && masked_table
          && copy_function && address, "exported functions");
    uintptr_t global = address();
    rep_address = copy_function + strtoull(argv[3], NULL, 0);
    struct link_map *map;
    check(!dlinfo(library, RTLD_DI_LINKMAP, &map), "link map");
    Elf64_Ehdr *eh = (void *)map->l_addr;
    Elf64_Phdr *ph = (void *)(map->l_addr + eh->e_phoff);
    struct region { void *original; void *alias; size_t size; int prot; } regions[16];
    unsigned region_count = 0;
    for (unsigned i = 0; i < eh->e_phnum && active_gs; ++i) {
        if (ph[i].p_type != PT_LOAD || ph[i].p_flags & PF_X)
            continue;
        uintptr_t start = (map->l_addr + ph[i].p_vaddr) & ~(page - 1);
        size_t size = ((map->l_addr + ph[i].p_vaddr + ph[i].p_memsz + page - 1)
                       & ~(page - 1)) - start;
        check(region_count < 16, "segment count");
        void *alias = map_at(start + active_gs, size, MAP_PRIVATE | MAP_ANONYMOUS, -1);
        memcpy(alias, (void *)start, size);
        regions[region_count++] = (struct region){
            (void *)start, alias, size, PROT_READ | ((ph[i].p_flags & PF_W) ? PROT_WRITE : 0)
        };
    }
    logical = map_at(UINT64_C(0x2000000000), page * 8, MAP_PRIVATE | MAP_ANONYMOUS, -1);
    actual = active_gs ? map_at((uintptr_t)logical + active_gs, page * 8,
                               MAP_PRIVATE | MAP_ANONYMOUS, -1) : logical;
    memset(actual, 0xa5, page * 8);
    *(uint64_t *)actual = 7;
    if (active_gs) {
        *(uint64_t *)(global + active_gs) = 17;
        check(!mprotect(logical, page * 8, PROT_NONE), "protect logical heap");
    }
    int fd = memfd_create("gsfork-stack-fixture", MFD_CLOEXEC);
    check(fd >= 0 && !ftruncate(fd, page * 16), "stack backing");
    stack = map_at(UINT64_C(0x3000000000), page * 16, MAP_SHARED, fd);
    void *stack_alias = active_gs ? map_at((uintptr_t)stack + active_gs, page * 16, MAP_SHARED, fd) : stack;
    check(!close(fd), "close stack backing");
    for (unsigned i = 0; i < region_count; ++i)
        check(!mprotect(regions[i].original, regions[i].size, PROT_NONE), "protect original library data");
    struct invocation value = invocation(probe, initial_gs, page * 16);
    value.rdi = (uintptr_t)logical;
    check(!run_kernel(&value), "probe GS setup/restore");
    uint64_t expected = active_gs ? 32 : 26;
    check(value.rax == expected, "translated heap/RIP/indirect call result");
    check(((uint64_t *)(stack + page * 16))[-4] == expected
          && ((uint64_t *)((unsigned char *)stack_alias + page * 16))[-4] == expected,
          "implicit/explicit stack aliases and LEAVE");
    value = invocation(jump, initial_gs, page * 16);
    value.rax = 41;
    check(!run_kernel(&value) && value.rax == 42, "memory-indirect jump preserves code address");
    value = invocation(plt, initial_gs, page * 16);
    check(!run_kernel(&value) && value.rax == (uint64_t)getpid(), "GS-aware generated PLT");
    value = invocation(tls, initial_gs, page * 16);
    check(!run_kernel(&value) && value.rax == active_gs, "preserved FS-relative input access");
    value = invocation(ifunc, initial_gs, page * 16);
    value.rdi = 13;
    check(!run_kernel(&value) && value.rax == 84, "IFUNC implementation via translated PLT/GOT");
    value = invocation(resolver, initial_gs, page * 16);
    value.rdi = 13;
    check(!run_kernel(&value) && value.rax == 42, "resolver code uses ordinary GS translation");
    for (unsigned locked = 0; locked < 2; ++locked) {
        value = invocation(lock, initial_gs, page * 16);
        value.rdi = (uintptr_t)logical;
        value.rsi = locked;
        check(!run_kernel(&value) && *(uint64_t *)actual == 8 + locked, "LOCK-skipping GS entry");
    }
    value = invocation(tls_value, initial_gs, page * 16);
    check(!run_kernel(&value) && value.rax == 42, "initial-exec TLS initial value");
    value = invocation(tls_change, initial_gs, page * 16);
    check(!run_kernel(&value), "initial-exec TLS update");
    value = invocation(tls_value, initial_gs, page * 16);
    check(!run_kernel(&value) && value.rax == 45, "initial-exec TLS updated value");
    value = invocation(masked_table, initial_gs, page * 16);
    check(!run_kernel(&value) && value.rax == 85, "pre-biased masked table references");
    static const unsigned flag_bits[] = {0, 2, 4, 6, 7, 11};
    static const size_t counts[] = {0, 1, 37};
    unsigned cases = 0;
    for (unsigned form = 0; form < sizeof(strings) / sizeof(strings[0]); ++form) {
    struct string_case *spec = &strings[form];
    for (unsigned bits = 0; bits < 64; ++bits) {
        for (unsigned backward = 0; backward < 2; ++backward) {
            for (unsigned c = 0; c < 3; ++c) {
                size_t count = counts[c], elements = spec->repeated ? count : 1;
                size_t bytes = elements * spec->width;
                size_t offset = 256 + (backward && elements ? (elements - 1) * spec->width : 0);
                for (size_t n = 0; n < 512; ++n) {
                    actual[256 + n] = (unsigned char)(n * 7 + 3);
                    actual[page * 4 + 256 + n] = 0x5a;
                }
                value = invocation(spec->function, initial_gs, page * 16);
                value.rax = UINT64_C(0x123456789abcdef0);
                value.rdx = UINT64_C(0x1122334455667788);
                value.rsi = (uintptr_t)logical + offset;
                value.rdi = (uintptr_t)logical + page * 4 + offset;
                value.rcx = count;
                for (unsigned b = 0; b < 6; ++b)
                    if (bits & (1u << b))
                        value.flags |= 1u << flag_bits[b];
                if (backward)
                    value.flags |= 0x400;
                uint64_t flags = value.flags;
                uintptr_t source = value.rsi, dest = value.rdi;
                check(!run_kernel(&value), "copy invocation");
                intptr_t delta = backward ? -(intptr_t)bytes : (intptr_t)bytes;
                check(value.rax == UINT64_C(0x123456789abcdef0)
                      && value.rdx == UINT64_C(0x1122334455667788)
                      && value.rcx == (spec->repeated ? 0 : count)
                      && value.rsi == source + (spec->stos ? 0 : delta) && value.rdi == dest + delta,
                      "REP register results");
                check((value.flags & 0xcd5) == (flags & 0xcd5), "REP arithmetic flags and DF");
                for (size_t n = 0; n < bytes; ++n) {
                    unsigned char expected_byte = spec->stos
                        ? (unsigned char)(value.rax >> ((n % spec->width) * 8)) : actual[256 + n];
                    check(actual[page * 4 + 256 + n] == expected_byte, "string memory effects");
                }
                for (size_t n = bytes; n < 512; ++n)
                    check(actual[page * 4 + 256 + n] == 0x5a, "REP bounds/zero count");
                ++cases;
            }
        }
        }
    }
    if (active_gs && strtoull(argv[3], NULL, 0)) {
        struct sigaction action = {.sa_sigaction = handler, .sa_flags = SA_SIGINFO};
        sigemptyset(&action.sa_mask);
        check(!sigaction(SIGSEGV, &action, NULL) && !sigaction(SIGUSR1, &action, NULL), "signal handlers");
        check(!mprotect(actual + page, page, PROT_NONE), "arm partial REP fault");
        value = invocation(copy_function, initial_gs, page * 16);
        value.rax = UINT64_C(0x8877665544332211);
        value.rsi = (uintptr_t)logical + page - 16;
        value.rdi = (uintptr_t)logical + page * 5 - 16;
        value.rcx = 64;
        check(!run_kernel(&value) && faults == 1 && nested_signals == 1, "nested signal delivery");
        check(value.rax == UINT64_C(0x8877665544332211) && value.rcx == 0,
              "scratch preserved across nested signal instrumentation");
        check(!memcmp(actual + page - 16, actual + page * 5 - 16, 64), "partial REP restart");
    }
    for (unsigned i = 0; i < region_count; ++i) {
        check(!mprotect(regions[i].original, regions[i].size, regions[i].prot), "restore library mapping");
        check(!munmap(regions[i].alias, regions[i].size), "unmap library alias");
    }
    check(!dlclose(library), "dlclose");
    check(!munmap(logical, page * 8) && !munmap(stack, page * 16), "unmap logical mappings");
    if (active_gs)
        check(!munmap(actual, page * 8) && !munmap(stack_alias, page * 16), "unmap aliases");
    printf("runtime-ok cases=%u faults=%d nested=%d\n", cases, faults, nested_signals);
    return 0;
}
