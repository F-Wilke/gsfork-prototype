#ifndef KERNELS_H
#define KERNELS_H
#include <stdint.h>
#include <stddef.h>
struct node { struct node *next; uint64_t value; };
uint64_t kernel_sum(uint64_t *, size_t, size_t);
uint64_t kernel_update(uint64_t *, size_t, size_t);
uint64_t kernel_avx2(uint64_t *, size_t, size_t);
uint64_t kernel_chase(struct node *, size_t, size_t);
uint64_t kernel_rep_movsb_native(uint64_t *, size_t, size_t);
uint64_t kernel_rep_movsb_wrapped(uint64_t *, size_t, size_t);
#endif
