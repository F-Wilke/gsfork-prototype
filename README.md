# GS-Fork binary rewriting prototype

A runnable **restricted offline ELF rewriter**, plus a GS-relocated data demonstration and reproducible benchmarks. It implements the central GS-Fork idea: retain original pointer bits while selecting a copied data arena with GS.base. This is a dummy/proof of concept, not a whole-program rewriter or a secure runtime.

## Perf profiling extension

See `PERF.md` for the `profile.py` runner: region-gated `perf stat` and `perf record`, assembly annotation, size sweeps, copy/alias mapping selection, and direct-child address controls. Start with `make perf-stat KERNEL=chase SIZE=32K SECONDS=3`. The current extension passed 432 correctness executions plus profiling protocol tests. Hardware-counter results and attribution are in `profiles/20261007-comprehensive-analysis.md`.

The historical Xeon v1 benchmark outputs are in `results-v1/`, with their exact matching package in `reference-v1.zip`. `REPORT.md` describes those v1 measurements; current PMU collections are documented separately under `profiles/`.

## MiBench evaluation

`MIBENCH.md` documents the CRC32, FFT, and ADPCM evaluation derived from
`ekut-es/mibench`. It builds a native baseline and byte-identical GS=0/GS=1 TiB
instrumented binaries, verifies all output checksums, and supports paired,
region-gated hardware-counter runs:

```sh
make mibench-test
make mibench-perf PROFILE_ARGS="--seconds 1 --repeat 3"
```

The measured report is `profiles/20261007-mibench-analysis.md`; its complete
long-form counter table is `profiles/20261007-mibench-metrics.csv`.

A second implementation compiles the pinned MiBench files unchanged and adds
GS prefixes only through post-link ELF rewriting:

```sh
make mibench-binary-test
make mibench-binary-perf PROFILE_ARGS="--seconds 1 --repeat 3"
```

See the "Binary-rewritten implementation" section in `MIBENCH.md`.

## Run

Requirements: Linux x86-64, GCC, GNU ld/binutils, Python 3.10+, AVX2 for the vector test, and permission to use `arch_prctl(ARCH_SET_GS)`. No root required. The executable reserves two fixed virtual ranges using `MAP_FIXED_NOREPLACE`; it fails without replacing anything if either range is occupied.

```sh
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
make clean all
make test
python3 benchmark.py --samples 31 --target-ms 80 --output results-local
```

`make bench` runs validation and overwrites `results/` with a fresh benchmark. Historical measurements are in `results-v1/`; use another output directory for a fresh study. The v1 reference binaries were built on Ubuntu with GCC 13.3.0; rebuild on your machine if its glibc differs.

## What is actually rewritten

`src/kernels.c` is compiled once. `rewrite.py` reads that **linked ELF's machine code**, uses iced-x86 to decode it, classifies memory operands, sets the GS override, and re-encodes the instruction block. It does not substitute handwritten GS benchmark implementations. The block encoder repairs branch displacements and promotes short branches when needed.

For example, the pointer-chasing loop contains:

```asm
; original                           ; rewritten
add rcx, [rdi + 8]                    add rcx, gs:[rdi + 8]
mov rdi, [rdi]                        mov rdi, gs:[rdi]
```

LEA remains a logical address calculation. NOP memory syntax does not cause a data access. Both are left unprefixed. Plain RET uses the host's native stack. No application stack pointer or stack data enters these leaf kernels.

`slots.ld` reserves one 4-KiB executable slot per function, so growth does not move function entry points, surrounding ELF sections, or external references. This deliberate preparation avoids needing trampolines and ELF segment expansion in the dummy. The rewriter updates function symbol sizes, fills unused slot space with INT3, and records every edit in `build/rewrite.json`. It requires the four named symbols and dedicated slots; it cannot accept an arbitrary stripped executable.

Three binaries are produced:

- `build/original`: the compiler-generated baseline, without GS memory prefixes.
- `build/rewritten`: the same binary with its four kernel functions rewritten.
- `build/reencoded`: re-encoding-only control, without GS prefixes. The shipped control's function bytes exactly match the original function bytes. Slot padding changes to INT3 just as in the rewritten binary.

## Relocated-copy demonstration

The harness maps two **independent anonymous data buffers**, at logical address `0x1000000000` (64 GiB) and that address plus `0x10000000000` (1 TiB). It initializes the parent, then copies its bytes to the child. Linked-list `next` pointers retain their original parent-address bit patterns.

The `shift` mode sets GS.base to 1 TiB, makes the parent's data mapping `PROT_NONE`, and invokes rewritten code with the original pointer. A load from logical pointer P therefore accesses P + GS.base. Loading a `next` pointer still produces a logical P, and the next GS-relative load selects the child again. Scalar and vector writes modify only the child, which is checked after restoring the parent's permissions. FS-based glibc TLS is unchanged. Previous GS.base is restored after the timed kernel.

The `native` and `zero` modes use GS.base=0 and the parent. An unmodified binary in `shift` mode is an intentional negative test and must SIGSEGV. This catches accidentally skipping all rewriting; tests also inspect individual prefixes and validate all output elements.

## Supported boundary

The supported subset is ordinary scalar arithmetic, loads/stores/read-modify-write, selected AVX2 instructions, LEA, NOP, in-function direct branches, and plain RET. `rewrite.py` contains the exact small mnemonic allowlist. It rejects unsupported input rather than claiming to translate it.

Excluded: explicit RSP/RBP usage and stack spills, push/pop/calls, indirect control flow and jump tables, RIP-relative references, existing FS/GS/other segment overrides, REP/string instructions, syscalls, arbitrary library code, TLS translation, signal frames, unwind/DWARF rewriting, dynamic linking changes, JIT/self-modifying code, and full ABI crossings. No MPK, COW, actual fork/clone, multi-thread GS setup, or adversarial-code confinement is implemented. The allowlist is an implementation boundary, not a security validator.

In a complete implementation the stack model must be settled explicitly. Prefixing a direct RSP memory operand while leaving native PUSH/CALL/RET unchanged is not generally correct. Pointers to stack objects also prevent assuming all register-based pointers refer to relocated heap data. Likewise RIP-relative references need a shared-code/shared-data/relocated-data policy. The prototype intentionally makes neither assumption.

The dummy's code is shared and unchanged in address; only data is copied. All tested pointers are to the data arena. This does not establish correctness for a whole address-space copy.

## Benchmark method

Compiler-only memory barriers between sum/update/vector passes prevent GCC from merging repeated traversals; they emit no instructions. Four kernels: scalar sum, scalar read-modify-write increment, AVX2 increment, and a deterministic shuffled linked-list traversal. Each uses 32 KiB and 8 MiB working sets. A node is 16 bytes; scalar/vector elements are 8 bytes. 8 MiB is a larger-cache test on this machine, not a claim of DRAM bandwidth saturation.

Each case calibrates a common round count with the original binary. Then 31 blocks each run original, re-encoded control, rewritten/GS=0, and rewritten/GS=1 TiB in deterministic randomized order, each as a fresh process pinned to one CPU. All variants use exactly the same round count and must produce the same checksum. Three untimed passes warm each kernel. Timing surrounds only the kernel call; it excludes process start, mapping/copying, GS setup, parent protection, warmup, and correctness checks. CPU affinity is verified before and after timing. Hugepages are disabled for the arenas.

Both CLOCK_MONOTONIC_RAW wall time and CLOCK_THREAD_CPUTIME_ID thread CPU time are retained. Headline overhead is the median of within-block wall-time ratios minus one. The report supplies percentile bootstrap 95% intervals for that median, with 5,000 resamples. These intervals describe observed sample dispersion, not systematic VM interference or population-wide hardware uncertainty. No outliers are discarded. Separate processes have distinct physical allocations, so the nonzero-GS comparison includes translation, code layout, physical-page placement, and measurement noise; it is not a pure instruction-latency measurement.

The environment is a KVM VM. CPU pinning does not pin the host's physical CPU or eliminate host scheduling, frequency variation, cache contention, or VM steal. Hardware performance counters are not collected (`perf` is unavailable). Re-encode control deviation is a useful indication of measurement noise. Negative overheads should not be interpreted as proven improvements without further measurement.

`results-v1/samples.csv` and `.jsonl` contain every measured v1 run. `summary.json` includes wall and thread CPU ratios. `environment.json` records the exposed CPU, compiler, affinity, cgroup statistics and executable hashes. The v1 `validation.json` records 144 correctness executions and four expected fault controls. Current `results/validation.json` records 432 correctness runs and eight expected fault controls, including direct-child and copy/alias cases.

## Files

- `rewrite.py`: restricted decoder/classifier/encoder and ELF patcher.
- `src/kernels.c`, `src/harness.c`: workloads and runtime/measurement harness.
- `slots.ld`, `Makefile`, `requirements.txt`: reproducible build.
- `tests/test_rewrite.py`: branch-growth, prefix, and unsupported-input tests.
- `validate.py`: cross-binary correctness and protected-parent checks.
- `benchmark.py`: randomized measurement and statistics.
- `profile.py`, `PERF.md`: perf runner and attribution guide.
- `mibench_build.py`, `mibench_profile.py`, `MIBENCH.md`: MiBench build,
  validation, and paired perf evaluation.
- `results-v1/`, `reference-v1.zip`: historical measurements and matching package.
- `REPORT.md`: measured results and interpretation.
- `build/`: original, rewritten, control binaries and edit reports.

## Technical references

- Linux FS/GS userspace documentation: https://www.kernel.org/doc/html/latest/arch/x86/x86_64/fsgs.html
- iced-x86 Python decoder/encoder documentation: https://github.com/icedland/iced/blob/master/src/rust/iced-x86-py/README.md
- Intel architecture manuals: https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html

The next engineering step is to add explicit relocation metadata and a stack/runtime ABI, then broaden the accepted instruction set and ELF layout support. This prototype supplies executable evidence for the basic pointer-preserving data translation and its measured kernel cost.
