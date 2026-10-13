#include "kernels.h"
#include <immintrin.h>
#define K(name) __attribute__((noinline, noclone, section(".gsfork." #name)))
K(sum) uint64_t kernel_sum(uint64_t *p, size_t n, size_t rounds) {
    uint64_t sum = 0;
    for (size_t r = 0; r < rounds; ++r) {
        for (size_t i = 0; i < n; ++i) sum += p[i];
        __asm__ volatile("" ::: "memory");
    }
    return sum;
}
K(update) uint64_t kernel_update(uint64_t *p, size_t n, size_t rounds) {
    for (size_t r = 0; r < rounds; ++r) {
        for (size_t i = 0; i < n; ++i) p[i] += 1;
        __asm__ volatile("" ::: "memory");
    }
    return p[n - 1];
}
K(avx2) __attribute__((target("avx2")))
uint64_t kernel_avx2(uint64_t *p, size_t n, size_t rounds) {
    // n must be a nonzero multiple of 4.
    uint64_t one;
    // Keep this dummy kernel free of RIP-relative constant-pool accesses.
    __asm__("mov $1, %0" : "=r"(one));
    __m256i ones = _mm256_set1_epi64x((long long)one);
    for (size_t r = 0; r < rounds; ++r) {
        for (size_t i = 0; i < n; i += 4) {
            __m256i v = _mm256_loadu_si256((const __m256i *)(p+i));
            _mm256_storeu_si256((__m256i *)(p+i), _mm256_add_epi64(v, ones));
        }
        __asm__ volatile("" ::: "memory");
    }
    return p[n - 1];
}
K(chase) uint64_t kernel_chase(struct node *p, size_t steps, size_t rounds) {
    uint64_t sum = 0;
    for (size_t r = 0; r < rounds; ++r)
        for (size_t i = 0; i < steps; ++i) {
            sum += p->value;
            p = p->next;
        }
    return sum;
}

/* Copy the lower half into the upper half, repeating enough times to
 * benchmark the REP engine rather than a single function call. Both variants
 * have identical copy volume and output; only the copy primitive differs.
 * This is a hand-written equivalent of the intended binary rewrite. */
extern void rep_movsb_copy_native(void *, const void *, size_t);
extern void rep_movsb_copy_wrapped(void *, const void *, size_t);
#define REP_COPY_KERNEL(name) \
__attribute__((noinline, noclone)) \
uint64_t kernel_rep_movsb_##name(uint64_t *p, size_t n, size_t rounds) { \
    for (size_t r = 0; r < rounds; ++r) { \
        rep_movsb_copy_##name(p + n/2, p, (n/2)*sizeof(*p)); \
        __asm__ volatile("" ::: "memory"); \
    } \
    return p[n-1]; \
}
REP_COPY_KERNEL(native)
REP_COPY_KERNEL(wrapped)
