# MiBench GS evaluation

This extension evaluates three representative kernels from
[`ekut-es/mibench`](https://github.com/ekut-es/mibench) at pinned commit
`54cdff6764b231fdb0a6e45c36c0cb8e7acf74ee`:

- CRC32: streaming input plus a table lookup.
- FFT: dense floating-point array reads and writes.
- ADPCM encoder: streaming input/output with scalar state computation.

CRC32 states that it is free of restrictions, FFT is public domain with an
attribution request, and ADPCM has a permissive attribution license. The build
script fetches the pinned upstream checkout and copies only the required source
files into `build/mibench/src`.

Two implementations are available:

- `mibench_build.py`: the original source-instrumented implementation described
  below.
- `mibench_binary_build.py`: an additional implementation that compiles the
  pinned upstream C and headers unchanged, then adds GS prefixes by rewriting
  the linked ELF only.

## Binary-rewritten implementation

Use this implementation when evaluating the binary-rewriting mechanism itself:

```sh
make mibench-binary-build
make mibench-binary-test
make mibench-binary-perf PROFILE_ARGS="--seconds 1 --repeat 3"
```

It produces `build/mibench-binary/mibench-baseline`,
`mibench-gs0`, and `mibench-gsshift`. The upstream CRC32, FFT, and ADPCM files
are compiled directly from the pinned checkout. No transformed source copy,
address-space type, source patch, or preprocessor rename is used. The CRC
translation unit's conflicting `main` symbol is renamed only after compilation
with `objcopy --redefine-sym`.

`mibench_binary_slots.ld` places `crc32buf`, `fft_float`, and `adpcm_coder` in
dedicated 4 KiB executable slots. `mibench_rewrite.py` decodes those functions,
adds GS overrides to a compiler-specific allowlist of proven data-buffer
operands, re-encodes branches, calls, and RIP-relative references, and patches
the ELF in place. The current pinned Clang 19 build rewrites:

| Function | Rewritten buffer operands |
|---|---:|
| `crc32buf` | 3 |
| `fft_float` | 35 |
| `adpcm_coder` | 4 |

The selector excludes LEA, stack and frame memory, the ADPCM state structure,
CRC/ADPCM global lookup tables, FFT constants, and all library code. It checks
the SHA-256 of each original function plus the exact expected operand count,
and rejects compiler output that no longer matches the reviewed shape.
`build/mibench-binary/rewrite.json` records every edited instruction.
`build/mibench-binary/build.json` records the unchanged upstream source hashes,
tool versions, and binary hashes.

As in the source-instrumented implementation, GS=0 and shifted-GS are
byte-identical copies of one rewritten executable. Shifted mode protects every
logical data mapping, so incomplete buffer rewriting faults. The baseline and
rewritten variants use the same unchanged upstream source and compiler flags;
their selected linked instructions differ only through the offline rewrite.

## Variants and instrumentation boundary

The build produces:

- `mibench-baseline`: ordinary address-space-zero data pointers.
- `mibench-gs0`: data-buffer pointers use Clang x86 address space 256, emitting
  genuine `gs:` memory operands, with GS.base set to zero.
- `mibench-gsshift`: the exact same instrumented executable bytes as GS=0, run
  with GS.base set to 1 TiB.

GS=0 and shifted-GS are copied from one linked executable and select their
runtime mode from `argv[0]`. Their SHA-256 hashes must therefore match. This
prevents code layout from becoming a confounder.

Only benchmark input/output array element types are GS-qualified. Stack,
globals, state structures, libc, TLS, control data, and syscall buffers remain
native. Whole-binary prefixing would be invalid because those objects do not
share one relocation policy.

Shifted mode maps each data arena twice from the same `memfd`: once at its
logical address and once at logical address plus 1 TiB. The driver passes the
logical pointer, sets GS.base to 1 TiB, and protects the logical mapping during
the kernel. A missed GS annotation therefore faults instead of silently using
the wrong alias. GS.base and mapping permissions are restored before output
verification.

## Build and validation

Requirements are Linux x86-64, Clang, binutils, Python 3, and permission to use
`arch_prctl(ARCH_SET_GS)`.

```sh
make mibench-build
make mibench-test
```

`mibench-test` runs every benchmark in all three variants and requires matching
checksums. `build/mibench/build.json` records the pinned commit, source hashes,
binary hashes, and GS operand counts. The current build has zero GS operands in
the baseline and 44 in each instrumented name; the two instrumented hashes are
identical.

An existing pinned checkout can be reused:

```sh
make mibench-build MIBENCH_SOURCE=/path/to/mibench
```

## Performance collection

The runner calibrates one common iteration count per benchmark using the
baseline, executes randomized paired blocks on one CPU, and gates perf around
the kernel only. Setup, mapping, GS changes, page protection, and checksumming
are outside the measured region.

```sh
make mibench-perf PROFILE_ARGS="--seconds 1 --repeat 3"
```

Useful focused passes include:

```sh
python3 mibench_profile.py --events \
  'L1-dcache-loads,L1-dcache-load-misses,LLC-loads,LLC-load-misses'

python3 mibench_profile.py --events \
  'cycle_activity.stalls_total:u,cycle_activity.stalls_l1d_miss:u,\
cycle_activity.stalls_l2_miss:u,cycle_activity.stalls_l3_miss:u'

python3 mibench_profile.py --benchmarks fft --repeat 7 --seconds 1 --events \
  'cycles:u,instructions:u,cycle_activity.stalls_total:u,resource_stalls.any:u'
```

Each output directory contains executable snapshots, commands, stdout/stderr,
raw perf CSV files, `runs.jsonl`, metadata, and median summaries. No outliers
are discarded. Keep event groups small enough to avoid multiplexing; the
summary records the minimum running percentage for every counter.

## Current result

See `profiles/20261007-mibench-analysis.md` and
`profiles/20261007-mibench-metrics.csv`.

CRC32 and ADPCM show no reproducible nonzero-GS penalty. FFT shows a focused
median increase from 201.62 to 212.65 cycles per sample item, or 5.47%, between
the byte-identical GS=0 and shifted-GS modes. Instructions are unchanged.
Resource stalls increase by 9.35 per item, accounting for most of the 11.04
additional cycles.

The FFT effect is not explained by cache or TLB misses. L1 data-cache misses
increase by only 0.0128 per item (0.24%), while LLC, retired L3, and dTLB misses
are slightly lower in shifted mode in the focused run. The evidence therefore
matches the dependent-load microbenchmark: the meaningful signal is backend
resource pressure associated with a nonzero GS base, not extra cache misses.

## Scope

This is not a full MiBench port or whole-program GS transformation. It covers
three permissively licensed kernels and intentionally instruments only explicit
data-buffer accesses. Results apply to the measured Intel Core i7-7700/Kaby
Lake system and should be rerun on other microarchitectures.
