#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <math.h>
#include <poll.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <asm/prctl.h>
#include <linux/memfd.h>

#include "gs_types.h"
#include "crc.h"
#include "fourier.h"
#include "adpcm.h"

#ifndef MIBENCH_BINARY_REWRITE
#define MIBENCH_BINARY_REWRITE 0
#endif

static const uintptr_t logical_base = 0x1000000000ULL;
static const uintptr_t mapping_stride = 0x40000000ULL;
static const uintptr_t gs_delta = 0x10000000000ULL;
static int shifted_mode;

struct arena {
    void *logical;
    void *shifted;
    size_t bytes;
};

struct measurement {
    uint64_t checksum;
    uint64_t wall_ns;
    uint64_t thread_ns;
};

static void die(const char *message)
{
    perror(message);
    exit(1);
}

static uint64_t ns(clockid_t clock_id)
{
    struct timespec value;
    if (clock_gettime(clock_id, &value))
        die("clock_gettime");
    return (uint64_t)value.tv_sec * 1000000000ULL + (uint64_t)value.tv_nsec;
}

static size_t page_round(size_t bytes)
{
    size_t page = (size_t)sysconf(_SC_PAGESIZE);
    if (!bytes || bytes > mapping_stride)
        return 0;
    return (bytes + page - 1) & ~(page - 1);
}

static struct arena arena_create(unsigned slot, size_t requested)
{
    size_t bytes = page_round(requested);
    if (!bytes || slot >= 16) {
        fprintf(stderr, "invalid arena request\n");
        exit(2);
    }
    int backing = memfd_create("mibench-gs-data", MFD_CLOEXEC);
    if (backing < 0 || ftruncate(backing, (off_t)bytes))
        die("memfd arena");
    uintptr_t logical = logical_base + (uintptr_t)slot * mapping_stride;
    void *parent = mmap((void *)logical, bytes, PROT_READ | PROT_WRITE,
                        MAP_SHARED | MAP_FIXED_NOREPLACE, backing, 0);
    if (parent == MAP_FAILED)
        die("mmap logical arena");
    void *child = mmap((void *)(logical + gs_delta), bytes, PROT_READ | PROT_WRITE,
                       MAP_SHARED | MAP_FIXED_NOREPLACE, backing, 0);
    if (child == MAP_FAILED)
        die("mmap shifted arena");
    close(backing);
    if (madvise(parent, bytes, MADV_NOHUGEPAGE) ||
        madvise(child, bytes, MADV_NOHUGEPAGE))
        die("madvise");
    return (struct arena){parent, child, bytes};
}

static void arena_protect(struct arena *arenas, size_t count, int protect)
{
    for (size_t i = 0; i < count; ++i) {
        if (mprotect(arenas[i].logical, arenas[i].bytes,
                     protect ? PROT_NONE : PROT_READ | PROT_WRITE))
            die("mprotect arena");
    }
}

static void arena_destroy(struct arena *arena)
{
    munmap(arena->logical, arena->bytes);
    munmap(arena->shifted, arena->bytes);
}

static void set_gs(uintptr_t base)
{
    if (syscall(SYS_arch_prctl, ARCH_SET_GS, base))
        die("ARCH_SET_GS");
}

static uint64_t hash_bytes(const void *data, size_t bytes)
{
    const unsigned char *p = data;
    uint64_t hash = 1469598103934665603ULL;
    for (size_t i = 0; i < bytes; ++i) {
        hash ^= p[i];
        hash *= 1099511628211ULL;
    }
    return hash;
}

static int control_fd = -1;
static int ack_fd = -1;

static void perf_init(void)
{
    const char *control = getenv("GSFORK_PERF_CTL");
    const char *ack = getenv("GSFORK_PERF_ACK");
    if (!control && !ack)
        return;
    if (!control || !ack) {
        fprintf(stderr, "Both perf FIFO paths are required\n");
        exit(2);
    }
    control_fd = open(control, O_RDWR | O_NONBLOCK | O_CLOEXEC);
    ack_fd = open(ack, O_RDWR | O_NONBLOCK | O_CLOEXEC);
    if (control_fd < 0 || ack_fd < 0)
        die("open perf FIFO");
}

static void perf_command(const char *command)
{
    if (control_fd < 0)
        return;
    size_t length = strlen(command);
    ssize_t sent;
    do {
        sent = write(control_fd, command, length);
    } while (sent < 0 && errno == EINTR);
    if (sent != (ssize_t)length)
        die("write perf command");

    char response[5] = {0};
    size_t received = 0;
    uint64_t deadline = ns(CLOCK_MONOTONIC) + 5000000000ULL;
    while (received < 4) {
        uint64_t now = ns(CLOCK_MONOTONIC);
        if (now >= deadline) {
            fprintf(stderr, "perf acknowledgement timed out\n");
            exit(1);
        }
        struct pollfd poll_fd = {.fd = ack_fd, .events = POLLIN};
        int ready = poll(&poll_fd, 1, (int)((deadline - now + 999999) / 1000000));
        if (ready < 0 && errno == EINTR)
            continue;
        if (ready < 0)
            die("poll perf ack");
        if (!ready)
            continue;
        char byte;
        ssize_t got = read(ack_fd, &byte, 1);
        if (got < 0 && (errno == EINTR || errno == EAGAIN))
            continue;
        if (got <= 0)
            die("read perf ack");
        if (!byte && !received)
            continue;
        response[received++] = byte;
    }
    if (strcmp(response, "ack\n")) {
        fprintf(stderr, "Invalid perf acknowledgement\n");
        exit(1);
    }
}

static struct measurement run_crc(size_t bytes, size_t iterations)
{
    struct arena arena = arena_create(0, bytes);
    unsigned char *input = arena.logical;
    uint64_t state = 0x123456789abcdef0ULL;
    for (size_t i = 0; i < bytes; ++i) {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        input[i] = (unsigned char)state;
    }

    set_gs(0);
    DWORD expected = crc32buf((gs_char *)arena.logical, bytes);
    set_gs(shifted_mode ? gs_delta : 0);
    if (shifted_mode)
        arena_protect(&arena, 1, 1);
    (void)crc32buf((gs_char *)arena.logical, bytes);
    perf_init();
    perf_command("enable\n");
    uint64_t wall_start = ns(CLOCK_MONOTONIC_RAW);
    uint64_t thread_start = ns(CLOCK_THREAD_CPUTIME_ID);
    uint64_t result = 0;
    for (size_t i = 0; i < iterations; ++i)
        result = crc32buf((gs_char *)arena.logical, bytes);
    uint64_t thread_ns = ns(CLOCK_THREAD_CPUTIME_ID) - thread_start;
    uint64_t wall_ns = ns(CLOCK_MONOTONIC_RAW) - wall_start;
    perf_command("disable\n");
    if (shifted_mode)
        arena_protect(&arena, 1, 0);
    if (result != expected) {
        fprintf(stderr, "CRC mismatch: expected %lu, got %" PRIu64 "\n",
                (unsigned long)expected, result);
        exit(1);
    }
    arena_destroy(&arena);
    return (struct measurement){result, wall_ns, thread_ns};
}

static struct measurement run_fft(size_t samples, size_t iterations)
{
    if (samples < 2 || (samples & (samples - 1))) {
        fprintf(stderr, "FFT work size must be a power of two\n");
        exit(2);
    }
    size_t bytes = samples * sizeof(float);
    struct arena arenas[4];
    for (unsigned i = 0; i < 4; ++i)
        arenas[i] = arena_create(i, bytes);
    float *real_in = arenas[0].logical;
    float *imag_in = arenas[1].logical;
    for (size_t i = 0; i < samples; ++i) {
        real_in[i] = (float)(sin((double)i * 0.013) + cos((double)i * 0.031));
        imag_in[i] = (float)sin((double)i * 0.007);
    }

    set_gs(0);
    fft_float((unsigned)samples, 0, (gs_float *)arenas[0].logical,
              (gs_float *)arenas[1].logical, (gs_float *)arenas[2].logical,
              (gs_float *)arenas[3].logical);
    uint64_t expected = hash_bytes(arenas[2].logical, bytes) ^
                        hash_bytes(arenas[3].logical, bytes);

    set_gs(shifted_mode ? gs_delta : 0);
    if (shifted_mode)
        arena_protect(arenas, 4, 1);
    fft_float((unsigned)samples, 0, (gs_float *)arenas[0].logical,
              (gs_float *)arenas[1].logical, (gs_float *)arenas[2].logical,
              (gs_float *)arenas[3].logical);
    perf_init();
    perf_command("enable\n");
    uint64_t wall_start = ns(CLOCK_MONOTONIC_RAW);
    uint64_t thread_start = ns(CLOCK_THREAD_CPUTIME_ID);
    for (size_t i = 0; i < iterations; ++i)
        fft_float((unsigned)samples, 0, (gs_float *)arenas[0].logical,
              (gs_float *)arenas[1].logical, (gs_float *)arenas[2].logical,
              (gs_float *)arenas[3].logical);
    uint64_t thread_ns = ns(CLOCK_THREAD_CPUTIME_ID) - thread_start;
    uint64_t wall_ns = ns(CLOCK_MONOTONIC_RAW) - wall_start;
    perf_command("disable\n");
    if (shifted_mode)
        arena_protect(arenas, 4, 0);
    uint64_t result = hash_bytes(arenas[2].logical, bytes) ^
                      hash_bytes(arenas[3].logical, bytes);
    if (result != expected) {
        fprintf(stderr, "FFT output mismatch\n");
        exit(1);
    }
    for (unsigned i = 0; i < 4; ++i)
        arena_destroy(&arenas[i]);
    return (struct measurement){result, wall_ns, thread_ns};
}

static struct measurement run_adpcm(size_t samples, size_t iterations)
{
    size_t input_bytes = samples * sizeof(short);
    size_t output_bytes = (samples + 1) / 2;
    struct arena arenas[2] = {
        arena_create(0, input_bytes),
        arena_create(1, output_bytes),
    };
    short *input = arenas[0].logical;
    for (size_t i = 0; i < samples; ++i)
        input[i] = (short)((i * 257U + (i >> 3)) & 0xffffU);

    struct adpcm_state codec = {0};
    set_gs(0);
    adpcm_coder((gs_short *)arenas[0].logical, (gs_char *)arenas[1].logical,
                (int)samples, &codec);
    uint64_t expected = hash_bytes(arenas[1].logical, output_bytes);

    set_gs(shifted_mode ? gs_delta : 0);
    if (shifted_mode)
        arena_protect(arenas, 2, 1);
    codec = (struct adpcm_state){0};
    adpcm_coder((gs_short *)arenas[0].logical, (gs_char *)arenas[1].logical,
                (int)samples, &codec);
    perf_init();
    perf_command("enable\n");
    uint64_t wall_start = ns(CLOCK_MONOTONIC_RAW);
    uint64_t thread_start = ns(CLOCK_THREAD_CPUTIME_ID);
    for (size_t i = 0; i < iterations; ++i) {
        codec = (struct adpcm_state){0};
        adpcm_coder((gs_short *)arenas[0].logical, (gs_char *)arenas[1].logical,
                    (int)samples, &codec);
    }
    uint64_t thread_ns = ns(CLOCK_THREAD_CPUTIME_ID) - thread_start;
    uint64_t wall_ns = ns(CLOCK_MONOTONIC_RAW) - wall_start;
    perf_command("disable\n");
    if (shifted_mode)
        arena_protect(arenas, 2, 0);
    uint64_t result = hash_bytes(arenas[1].logical, output_bytes);
    if (result != expected) {
        fprintf(stderr, "ADPCM output mismatch\n");
        exit(1);
    }
    arena_destroy(&arenas[0]);
    arena_destroy(&arenas[1]);
    return (struct measurement){result, wall_ns, thread_ns};
}

int main(int argc, char **argv)
{
    if (argc != 5) {
        fprintf(stderr, "usage: %s crc|fft|adpcm work iterations cpu\n", argv[0]);
        return 2;
    }
    const char *benchmark = argv[1];
    shifted_mode = strstr(argv[0], "gsshift") != NULL;
#if GS_INSTRUMENTED
    const char *variant = shifted_mode ? "gsshift" : "gs0";
#elif MIBENCH_BINARY_REWRITE
    int rewritten_mode = strstr(argv[0], "gs0") != NULL || shifted_mode;
    if (!rewritten_mode)
        shifted_mode = 0;
    const char *variant = rewritten_mode
        ? (shifted_mode ? "gsshift" : "gs0")
        : "baseline";
#else
    const char *variant = "baseline";
    if (shifted_mode) {
        fprintf(stderr, "baseline binary cannot run shifted\n");
        return 2;
    }
#endif
    size_t work = strtoull(argv[2], NULL, 0);
    size_t iterations = strtoull(argv[3], NULL, 0);
    int cpu = atoi(argv[4]);
    if (!work || !iterations || cpu < 0 || cpu >= CPU_SETSIZE)
        return 2;

    cpu_set_t cpus;
    CPU_ZERO(&cpus);
    CPU_SET(cpu, &cpus);
    if (sched_setaffinity(0, sizeof(cpus), &cpus))
        die("sched_setaffinity");

    unsigned long saved_gs;
    if (syscall(SYS_arch_prctl, ARCH_GET_GS, &saved_gs))
        die("ARCH_GET_GS");
    int cpu_before = sched_getcpu();
    struct measurement result;
    if (!strcmp(benchmark, "crc"))
        result = run_crc(work, iterations);
    else if (!strcmp(benchmark, "fft"))
        result = run_fft(work, iterations);
    else if (!strcmp(benchmark, "adpcm"))
        result = run_adpcm(work, iterations);
    else
        return 2;
    int cpu_after = sched_getcpu();
    set_gs(saved_gs);

    int verified = cpu_before == cpu && cpu_after == cpu;
    printf("{\"benchmark\":\"%s\",\"variant\":\"%s\",\"work\":%zu,"
           "\"iterations\":%zu,\"work_items\":%zu,\"cpu\":%d,"
           "\"wall_ns\":%" PRIu64 ",\"thread_ns\":%" PRIu64 ","
           "\"checksum\":%" PRIu64 ",\"verified_cpu\":%s,"
           "\"gs_base\":%" PRIuPTR ",\"perf_gated\":%s}\n",
           benchmark, variant, work, iterations, work * iterations, cpu,
           result.wall_ns, result.thread_ns, result.checksum, verified ? "true" : "false",
           shifted_mode ? gs_delta : 0, control_fd >= 0 ? "true" : "false");
    if (control_fd >= 0) {
        close(control_fd);
        close(ack_fd);
    }
    return verified ? 0 : 1;
}
