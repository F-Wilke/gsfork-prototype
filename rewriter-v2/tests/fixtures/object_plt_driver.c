#define _GNU_SOURCE
#include <asm/prctl.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/syscall.h>

extern int entry(int *);
static int alternate(int n) { return 3*n; }

/* Changing GS also affects the driver's patched PLT, so restore it via syscall. */
static long arch_prctl_raw(long op, unsigned long value)
{
    long result;
    __asm__ volatile ("syscall" : "=a"(result)
                      : "0"((long)SYS_arch_prctl), "D"(op), "S"(value)
                      : "rcx", "r11", "memory");
    return result;
}

int main(int argc, char **argv)
{
    if (argc != 2) return 1;
    uintptr_t slot = strtoull(argv[1], NULL, 0);
    uintptr_t translated[4] = {(uintptr_t)alternate};
    unsigned long saved_gs;
    int n = 7;
    if (entry(&n) != 15) return 2; /* DSO returns n+1 */
    int *physical = (int *)&n;
    uintptr_t delta = (uintptr_t)translated - slot;
    if (arch_prctl_raw(ARCH_GET_GS, (uintptr_t)&saved_gs)) return 3;
    if (arch_prctl_raw(ARCH_SET_GS, delta)) return 4;
    int result = entry((int *)((uintptr_t)physical - delta));
    if (arch_prctl_raw(ARCH_SET_GS, saved_gs)) return 5;
    return result == 28 ? 0 : 6;
}
