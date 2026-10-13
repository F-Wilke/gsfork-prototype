#define _GNU_SOURCE
#include "kernels.h"
#include <asm/prctl.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <poll.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

/* FS-relative TLS slots used by the REP MOVSB wrapper. Keep per host thread. */
__thread uintptr_t rep_sandbox_offset;
__thread uint64_t rep_scratch_rax;
static void die(const char *s) { perror(s); exit(1); }
static uint64_t ns(clockid_t c) {
    struct timespec t;
    if (clock_gettime(c, &t)) die("clock_gettime");
    return (uint64_t)t.tv_sec * 1000000000ULL + t.tv_nsec;
}
static uint64_t rand64(uint64_t *s) { *s ^= *s << 13; *s ^= *s >> 7; *s ^= *s << 17; return *s; }
static void set_gs(uintptr_t base) {
    if (syscall(SYS_arch_prctl, ARCH_SET_GS, base)) die("ARCH_SET_GS");
}
/* perf --delay=-1 --control=fifo:ctl,ack. Opening RDWR avoids FIFO-open
   deadlocks; a missing controller is detected by the bounded ack wait. */
static int ctl_fd = -1, ack_fd = -1;
static void perf_init(void) {
    const char *ctl = getenv("GSFORK_PERF_CTL"), *ack = getenv("GSFORK_PERF_ACK");
    if (!ctl && !ack) return;
    if (!ctl || !ack) { fprintf(stderr,"Both perf FIFO paths are required\n"); exit(2); }
    ctl_fd = open(ctl, O_RDWR|O_NONBLOCK|O_CLOEXEC);
    ack_fd = open(ack, O_RDWR|O_NONBLOCK|O_CLOEXEC);
    if (ctl_fd < 0 || ack_fd < 0) die("open perf FIFO");
}
static void perf_command(const char *command) {
    if (ctl_fd < 0) return;
    size_t len = strlen(command);
    ssize_t sent;
    do { sent = write(ctl_fd, command, len); } while (sent < 0 && errno == EINTR);
    if (sent != (ssize_t)len) die("write perf command");
    char ack[5] = {0}; size_t received = 0;
    uint64_t deadline = ns(CLOCK_MONOTONIC) + 5000000000ULL;
    while (received < 4) {
        uint64_t now = ns(CLOCK_MONOTONIC);
        if (now >= deadline) { fprintf(stderr,"perf acknowledgement timed out\n"); exit(1); }
        struct pollfd p = { .fd=ack_fd, .events=POLLIN };
        int ready = poll(&p, 1, (int)((deadline-now+999999)/1000000));
        if (ready < 0 && errno == EINTR) continue;
        if (ready < 0) die("poll perf ack");
        if (!ready) continue;
        char byte;
        ssize_t got = read(ack_fd, &byte, 1);
        if (got < 0 && (errno == EINTR || errno == EAGAIN)) continue;
        if (got <= 0) die("read perf ack");
        if (!byte && !received) continue;
        ack[received++] = byte;
    }
    if (strcmp(ack,"ack\n")) { fprintf(stderr,"Invalid perf acknowledgement\n"); exit(1); }
}
int main(int argc, char **argv) {
    if (argc != 6 && argc != 8) {
        fprintf(stderr, "usage: %s sum|update|avx2|chase|rep_movsb native|zero|shift|direct bytes rounds cpu [--mapping copy|alias]\n", argv[0]);
        return 2;
    }
    int alias = 0;
    if (argc == 8) {
        if (strcmp(argv[6],"--mapping") || (strcmp(argv[7],"copy") && strcmp(argv[7],"alias"))) return 2;
        alias = !strcmp(argv[7],"alias");
    }
    const char *kernel = argv[1], *mode = argv[2];
    size_t bytes = strtoull(argv[3], NULL, 0), rounds = strtoull(argv[4], NULL, 0);
    int cpu = atoi(argv[5]);
    int shifted = !strcmp(mode, "shift"), direct = !strcmp(mode,"direct");
    int child_selected = shifted || direct, chase = !strcmp(kernel, "chase");
    int rep = !strcmp(kernel, "rep_movsb");
    int mutating = !strcmp(kernel, "update") || !strcmp(kernel, "avx2");
    if ((strcmp(mode,"native") && strcmp(mode,"zero") && !shifted && !direct) ||
        (!chase && !mutating && !rep && strcmp(kernel,"sum")) || bytes < 4096 ||
        bytes > (1ULL<<28) || bytes % 4096 || !rounds || cpu < 0 || cpu >= CPU_SETSIZE) return 2;
    if (!strcmp(kernel,"avx2") && !__builtin_cpu_supports("avx2")) {
        fprintf(stderr, "AVX2 not supported\n"); return 77;
    }
    cpu_set_t cpus;
    CPU_ZERO(&cpus); CPU_SET(cpu, &cpus);
    if (sched_setaffinity(0, sizeof(cpus), &cpus)) die("sched_setaffinity");
    const uintptr_t logical = 0x1000000000ULL, delta = 0x10000000000ULL;
    int backing = -1;
    if (alias) {
        backing = memfd_create("gsfork-data", MFD_CLOEXEC);
        if (backing < 0 || ftruncate(backing, (off_t)bytes)) die("memfd arena");
    }
    int mapping_flags = MAP_FIXED_NOREPLACE | (alias ? MAP_SHARED : MAP_PRIVATE|MAP_ANONYMOUS);
    void *parent = mmap((void *)logical, bytes, PROT_READ|PROT_WRITE,
                        mapping_flags, backing, 0);
    if (parent == MAP_FAILED) die("mmap parent");
    void *child = mmap((void *)(logical+delta), bytes, PROT_READ|PROT_WRITE,
                       mapping_flags, backing, 0);
    if (child == MAP_FAILED) die("mmap child");
    if (backing >= 0) close(backing);
    // Avoid dependence on transparent hugepage policy across samples.
    if (madvise(parent, bytes, MADV_NOHUGEPAGE) || madvise(child, bytes, MADV_NOHUGEPAGE)) die("madvise");
    size_t n = bytes / (chase ? sizeof(struct node) : sizeof(uint64_t));
    uint64_t initial_sum = 0;
    if (chase) {
        size_t *order = malloc(n * sizeof(*order));
        if (!order) die("malloc");
        for (size_t i=0; i<n; ++i) order[i] = i;
        uint64_t state = 0x61a231bc97ULL;
        for (size_t i=n-1; i>0; --i) {
            size_t j = rand64(&state) % (i+1), t=order[i]; order[i]=order[j]; order[j]=t;
        }
        struct node *p = parent;
        for (size_t i=0; i<n; ++i) {
            /* direct is the baseline for identical FINAL addresses. Only this
               control builds high-address pointers; shift still preserves P. */
            uintptr_t next = (uintptr_t)&p[order[(i+1)%n]];
            p[order[i]].next = (struct node *)(next + (direct ? delta : 0));
            p[i].value = i+1; initial_sum += i+1;
        }
        free(order);
    } else {
        uint64_t *p = parent;
        for (size_t i=0; i<n; ++i) { p[i] = i+1; initial_sum += i+1; }
    }
    if (!alias) memcpy(child, parent, bytes); // Pointer bits copied without fixups.
    unsigned long saved_gs;
    if (syscall(SYS_arch_prctl, ARCH_GET_GS, &saved_gs)) die("ARCH_GET_GS");
    set_gs(shifted ? delta : 0);
    rep_sandbox_offset = shifted ? delta : 0;
    // A missed prefix in shifted code faults instead of silently reading parent data.
    if (child_selected && mprotect(parent, bytes, PROT_NONE)) die("mprotect");
    perf_init();
    void *argument = direct ? child : parent;
    uint64_t (*fn)(uint64_t *, size_t, size_t) = kernel_sum;
    if (!strcmp(kernel,"update")) fn=kernel_update;
    if (!strcmp(kernel,"avx2")) fn=kernel_avx2;
    if (rep) fn = (getenv("GSFORK_REP_WRAPPED") &&
                   !strcmp(getenv("GSFORK_REP_WRAPPED"), "1"))
                      ? kernel_rep_movsb_wrapped : kernel_rep_movsb_native;
    for (int i=0; i<3; ++i) {
        if (chase) (void)kernel_chase(argument,n,1); else (void)fn(argument,n,1);
    }
    int cpu_before = sched_getcpu();
    perf_command("enable\n");
    uint64_t wall0 = ns(CLOCK_MONOTONIC_RAW), thread0 = ns(CLOCK_THREAD_CPUTIME_ID);
    uint64_t result = chase ? kernel_chase(argument,n,rounds) : fn(argument,n,rounds);
    uint64_t thread_ns = ns(CLOCK_THREAD_CPUTIME_ID)-thread0;
    uint64_t wall_ns = ns(CLOCK_MONOTONIC_RAW)-wall0;
    perf_command("disable\n");
    int cpu_after = sched_getcpu();
    set_gs(saved_gs);
    if (child_selected && mprotect(parent, bytes, PROT_READ|PROT_WRITE)) die("restore parent");
    uint64_t expected = rep ? n/2 : (mutating ? n+rounds+3 : initial_sum*rounds);
    int ok = result == expected && cpu_before == cpu && cpu_after == cpu;
    if (rep) {
        const uint64_t *p = parent, *c = child;
        for (size_t i=0; i<n; ++i) {
            uint64_t original = i+1;
            uint64_t copied = i < n/2 ? original : i-n/2+1;
            uint64_t want_p = (!child_selected || alias) ? copied : original;
            uint64_t want_c = (child_selected || alias) ? copied : original;
            if (p[i] != want_p || c[i] != want_c) { ok=0; break; }
        }
    } else if (mutating) {
        const uint64_t *p = parent, *c = child;
        for (size_t i=0; i<n; ++i) {
            uint64_t want_p = i+1+((alias || !child_selected) ? rounds+3 : 0);
            uint64_t want_c = i+1+((alias || child_selected) ? rounds+3 : 0);
            if (p[i] != want_p || c[i] != want_c) { ok=0; break; }
        }
    } else if (memcmp(parent, child, bytes)) ok=0;
    printf("{\"kernel\":\"%s\",\"mode\":\"%s\",\"bytes\":%zu,\"rounds\":%zu,"
           "\"cpu\":%d,\"wall_ns\":%" PRIu64 ",\"thread_ns\":%" PRIu64 ","
           "\"checksum\":%" PRIu64 ",\"expected\":%" PRIu64 ",\"verified\":%s,"
           "\"gs_base\":%" PRIuPTR ",\"logical_base\":%" PRIuPTR ","
           "\"mapping\":\"%s\",\"perf_gated\":%s}\n",
           kernel,mode,bytes,rounds,cpu,wall_ns,thread_ns,result,expected,
           ok ? "true":"false",shifted ? delta:0,logical,
           alias ? "alias":"copy",ctl_fd >= 0 ? "true":"false");
    if (ctl_fd >= 0) { close(ctl_fd); close(ack_fd); }
    munmap(parent,bytes); munmap(child,bytes);
    return ok ? 0 : 1;
}
