# GS-Fork prototype: implementation and performance

> Historical v1 Xeon/KVM measurements. The profiling extension is documented in `PERF.md`; these numbers have not been replaced by a new perf collection. Raw results now live in `results-v1/`, and matching original binaries/sources are in `reference-v1.zip`. Current `build/` contains the extended harness.

Measured 2026-10-06 on Linux x86-64, inside KVM, with an exposed Intel Xeon Platinum 8573C and GCC 13.3.0. All measurements were made here; they are not estimates or results from your own hardware.

## Outcome

The restricted binary rewrite works for the tested kernels. Ordinary pointer bits survive a copy of the data arena, including pointers stored in linked-list nodes. With GS.base=1 TiB, the rewritten machine code reads and writes the child while the parent data mapping is inaccessible. The rewriter operates on an already linked ELF, adding actual GS prefixes and fixing branch offsets.

The strongest measured nonzero-GS costs were **+27.98% for scalar updates** and **+36.61% for dependent pointer chasing**, both at 32 KiB. The pointer-chasing bootstrap interval was [+30.82%, +44.32%]. Other measured medians were between −3.51% and +4.00%. These results do not support assuming that GS-relative rewriting is universally free.

## Results

Overheads are versus the unmodified binary. Positive means slower. GS=0 isolates the prefixed/layout-changed code without translating the data address; GS=1 TiB uses the copied arena and preserved logical pointers. The re-encode control has byte-identical function bodies to the original and unchanged entry addresses.

| Kernel | Data | Original ns/element | GS=0 overhead | GS=1 TiB overhead (95% CI) | Re-encode control |
|---|---:|---:|---:|---:|---:|
| sum | 32 KiB | 0.382 | +2.42% | -1.16% [-5.39%, +1.85%] | -3.21% |
| sum | 8,192 KiB | 0.413 | +6.05% | +0.21% [-3.39%, +5.07%] | +1.53% |
| update | 32 KiB | 0.281 | +4.31% | +27.98% [+19.42%, +36.17%] | +2.48% |
| update | 8,192 KiB | 0.392 | -0.38% | +4.00% [+0.79%, +12.09%] | -1.61% |
| avx2 | 32 KiB | 0.099 | -1.75% | -3.51% [-5.86%, +0.84%] | -5.75% |
| avx2 | 8,192 KiB | 0.363 | -1.45% | -3.30% [-5.43%, -0.16%] | +0.07% |
| chase | 32 KiB | 1.887 | +3.03% | +36.61% [+30.82%, +44.32%] | -6.48% |
| chase | 8,192 KiB | 40.164 | +2.09% | -0.50% [-5.24%, +12.26%] | -1.18% |


An element means one 64-bit scalar/vector lane, or one 16-byte node visited for `chase`. Reported overhead uses the median of paired ratios; it is deliberately not computed as the ratio of the two independently calculated medians below.

| Kernel | Data | Original median ms | Shifted median ms | Shifted wall overhead | Shifted thread CPU overhead |
|---|---:|---:|---:|---:|---:|
| sum | 32 KiB | 54.88 | 53.92 | -1.16% | -1.64% |
| sum | 8,192 KiB | 84.51 | 84.83 | +0.21% | +0.21% |
| update | 32 KiB | 82.05 | 105.90 | +27.98% | +27.98% |
| update | 8,192 KiB | 90.79 | 94.79 | +4.00% | +4.00% |
| avx2 | 32 KiB | 49.87 | 48.76 | -3.51% | -3.50% |
| avx2 | 8,192 KiB | 78.89 | 76.17 | -3.30% | -3.22% |
| chase | 32 KiB | 86.75 | 120.83 | +36.61% | +36.61% |
| chase | 8,192 KiB | 84.23 | 87.55 | -0.50% | -0.50% |


The same-code control ranges from roughly −6.5% to +2.5% across cases. This exposes substantial VM/run-to-run uncertainty even with CPU pinning. The small negative numbers are not a basis for claiming that GS improves performance. The 8-MiB AVX2 sample interval narrowly excludes zero, but systematic interference and physical-memory placement are not represented by that interval. The 32-KiB update and pointer-chase penalties are considerably larger than the observed control deviations.

## Measurement protocol

- 31 paired blocks per workload/size; four variants in randomized order in each block: original, re-encode-only, rewritten/GS=0, rewritten/GS=1 TiB.
- 8 cases × 31 blocks × 4 variants = **992 measured executions**, all checksum-verified, with no outlier removal.
- Pinned to guest CPU 4. Common round counts calibrated to approximately 80 ms per original run; three warmup passes precede the timed region.
- Compiler-only memory barriers prevent fusion of repeated passes. Scalar auto-vectorization is disabled; the AVX2 workload uses intrinsics. The runtime constant is constructed in a register to stay within the no-RIP-relative-data subset.
- Wall clock: CLOCK_MONOTONIC_RAW. Thread clock: CLOCK_THREAD_CPUTIME_ID. Timing excludes initialization, copying, GS setup, protection changes, warmup, and checking.
- Median paired wall ratios; 95% percentile bootstrap intervals using 5,000 resamples. This is sample uncertainty, not a guarantee across CPUs or environments.
- Independent private parent and child mappings with 4-KiB pages; transparent hugepages disabled for the arenas. Physical-page allocation differs across processes. 8 MiB can fit in this machine's larger caches; it is not a DRAM-bandwidth experiment.
- KVM host scheduling, CPU-frequency behavior, cache contention, and translation effects remain uncontrolled. Hardware counters were not available through `perf`.

## Correctness and binary evidence

144 dedicated executions covered four kernels, four binary/mode combinations, three buffer sizes, and three round counts. All agreed with expected results. Every scalar/vector output element was checked, and the inactive copy remained unchanged. The pointer-chase test traversed a deterministic shuffled cycle containing unchanged parent-address pointers while that parent mapping was PROT_NONE.

Four negative controls ran unmodified kernels in shifted mode. All terminated with the expected SIGSEGV, demonstrating that the protected logical range catches missing rewriting. Unit tests cover prefix insertion, unmodified LEA, re-encoding identity, short-to-near branch growth with retargeting, and rejection of 17 unsupported instruction patterns.

| Function | Original bytes | Rewritten bytes | GS-prefixed memory instructions |
|---|---:|---:|---:|
| kernel_sum | 77 | 78 | 1 |
| kernel_update | 116 | 120 | 4 |
| kernel_avx2 | 116 | 119 | 3 |
| kernel_chase | 61 | 63 | 2 |

The transformed function bodies grow from 370 to 380 bytes (+2.70%). There are ten static GS-prefixed data-memory instructions. The whole ELF remains 42,144 bytes because original and rewritten versions have the same reserved slots. Padding overhead is present in every version. `results-v1/disassembly.txt` gives both instruction streams, and the v1 `build/rewrite.json` in `reference-v1.zip` includes exact original/rewritten bytes and hashes.

## What this prototype does not establish

It is not an arbitrary-ELF or whole-program translator. Inputs must contain four named leaf functions in dedicated expandable slots. It rejects explicit stack/frame-register use, push/pop/calls, indirect control flow, RIP-relative references, existing segment overrides/TLS, string instructions, and unsupported operations. Plain RET uses the host stack. Only arena pointers are valid application data pointers in these kernels.

There is **no MPK isolation, COW, fork/clone implementation, multi-threading, signal/TLS integration, unwind metadata update, or syscall marshalling**. The workload does not measure those costs. Prefixing explicit stack accesses alone would not solve implicit CALL/RET/PUSH/POP accesses or pointers to stack objects; a complete GS-Fork stack/runtime ABI is required. GS prefixes also do not constrain adversarial code.

Thus the experiment validates pointer-preserving translation for a restricted data workload and measures its runtime cost. The observed nonzero-base penalty could involve address-generation/dependency behavior and code layout, but this experiment does not isolate a microarchitectural cause.

## Reproduce and extend

See `README.md` for build requirements and the full design boundary. From the extracted directory:

```sh
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
make test
python3 benchmark.py --samples 31 --target-ms 80 --output results-local
```

`results-v1/` contains CSV/JSONL raw samples, summary statistics, machine/compiler metadata and hashes, correctness records, and disassembly. The exact v1 original/rewritten/control ELF binaries are included in `reference-v1.zip`.

The next implementation step is an explicit stack/runtime ABI and relocation classification for RIP-relative code/data. Broader ELF layout rewriting and library integration can then extend this dummy beyond its prepared leaf-function slots.

## Sources for implementation semantics

- Linux FS/GS userspace interface: https://www.kernel.org/doc/html/latest/arch/x86/x86_64/fsgs.html
- iced-x86 decoder and block encoder: https://github.com/icedland/iced/blob/master/src/rust/iced-x86-py/README.md
- Intel architecture manuals: https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html

The numerical results above come from the included benchmark outputs, not these references.
