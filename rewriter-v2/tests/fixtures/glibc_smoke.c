#include <pthread.h>
#include <execinfo.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static _Thread_local volatile uint64_t control[2];
static int initialized;
static _Thread_local int per_thread = 7;

__attribute__((constructor)) static void initialize(void) {
    initialized = 1;
}

static void *thread_main(void *argument) {
    if (per_thread != 7 || control[0] || control[1])
        return (void *)1;
    per_thread = 19;
    return argument;
}

int main(void) {
    if ((intptr_t)&control[0] - (intptr_t)__builtin_thread_pointer() != -16
        || (intptr_t)&control[1] - (intptr_t)__builtin_thread_pointer() != -8)
        return 7;
    if (!initialized || control[0] || control[1])
        return 1;
    void *frames[16];
    if (backtrace(frames, 16) < 3)
        return 8;
    unsigned char *a = malloc(65536), *b = malloc(65536);
    if (!a || !b)
        return 2;
    for (size_t i = 0; i < 65536; ++i)
        a[i] = (unsigned char)(i * 17 + 3);
    void *(*volatile copy)(void *, const void *, size_t) = memcpy;
    void *(*volatile fill)(void *, int, size_t) = memset;
    copy(b, a, 65536);
    if (memcmp(a, b, 65536))
        return 3;
    fill(b, 0x51, 65536);
    if (b[0] != 0x51 || b[65535] != 0x51)
        return 4;
    pthread_t thread;
    void *result;
    if (pthread_create(&thread, NULL, thread_main, NULL) || pthread_join(thread, &result) || result)
        return 5;
    if (per_thread != 7)
        return 6;
    free(a);
    free(b);
    puts("glibc-smoke-ok");
    return 0;
}
