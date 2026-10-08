#ifndef GSFORK_MIBENCH_GS_TYPES_H
#define GSFORK_MIBENCH_GS_TYPES_H

#if GS_INSTRUMENTED
#define GS_DATA __attribute__((address_space(256)))
#else
#define GS_DATA
#endif

typedef char GS_DATA gs_char;
typedef signed char GS_DATA gs_schar;
typedef short GS_DATA gs_short;
typedef float GS_DATA gs_float;

#endif
