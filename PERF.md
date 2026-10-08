# Profiling GS-Fork with perf

The extension adds kernel-region `perf stat`, `perf record`, instruction annotation, an automatic working-set sweep, and address/mapping controls. The original correctness demonstration remains available. `profile.py` uses only Python's standard library; build/rewrite dependencies are unchanged.

## Quick start

Extract the package, enter `gsfork-prototype`, install `requirements.txt`, and run:

```sh
make clean all
python3 profile.py doctor

# Three-second original workload, equal work in every variant, five paired blocks.
python3 profile.py stat --kernel chase --size 32K --seconds 3 --repeat 5

# Sample the rewritten/nonzero-GS code for instruction-level inspection.
python3 profile.py record --kernel chase --size 32K --seconds 10 --variant gs_shift

# Repeat at sizes spanning L1, L2, LLC, and potentially DRAM.
python3 profile.py sweep --kernel chase --seconds 1 --repeat 5
```

The runner chooses an allowed CPU and pins the workload. Add `--cpu 2` if CPU 2 belongs to your affinity mask. It prints the `perf report` and `perf annotate` commands for each recording. Output goes into a new timestamped `profiles/` directory by default; `--output profiles/my-run` selects an empty destination. `doctor` reports perf availability, a hardware-counter probe, CPU/cache metadata, affinity, and `perf_event_paranoid`; it does not modify the system.

Equivalent Make targets:

```sh
make perf-stat KERNEL=update SIZE=32K SECONDS=5
make perf-record KERNEL=chase SIZE=32K SECONDS=10
make perf-sweep KERNEL=chase SECONDS=1
make perf-stat PROFILE_ARGS='--cpu 2 --repeat 5 --variants original,gs_zero,gs_shift'
```

No root is required by the benchmark itself. Install the Linux perf package appropriate to your distribution/kernel. Permissions or VM PMU exposure may prevent hardware counting even when `perf` is installed. The runner reports failures and unsupported events rather than manufacturing counter values.

## What gets counted

The default runner starts perf with `--delay=-1` and `--control=fifo:CONTROL,ACK`. The harness initializes the mappings, sets GS, applies protection and warms up before sending `enable\n`. It waits for `ack\n`, times one kernel invocation with the calibrated round count, then sends `disable\n` and waits again. Copying, warmup, setup, full-buffer verification and teardown are excluded from the enabled region. A few instructions for clocks and control boundaries are counted alongside the kernel; use multi-second workloads to make them negligible. The harness's reported kernel wall/thread durations exclude the control acknowledgement waits.

The wrapper owns temporary FIFOs, generates exact perf/harness commands, and imposes subprocess and five-second acknowledgement timeouts. `--whole-process` is a compatibility fallback for older perf without control FIFOs. It counts setup/checking as well; do not compare its normalized counters with region-gated runs. For large arenas, setup can be significant even if the timed kernel runs for several seconds.

`--seconds` calibrates a **common round count using the original binary**, outside perf. Every variant then does the same work, even if a slower variant runs longer. This is not a fixed-time, unequal-work comparison. `--rounds N` skips calibration if you want a known work count. `stat`/`sweep` randomize variant order in each paired block; `record` captures one selected variant once.

## Controls for attributing overhead

| Variant | Binary | GS.base | Kernel pointer values | Final data addresses |
|---|---|---:|---|---|
| `original` | original | 0 | Parent/logical addresses | Parent |
| `reencoded` | re-encode-only | 0 | Parent/logical addresses | Parent |
| `gs_zero` | rewritten | 0 | Parent/logical addresses | Parent |
| `gs_shift` | rewritten | 1 TiB | Parent/logical addresses | Child |
| `original_child` | original | 0 | Actual child addresses | Child |
| `gs_zero_child` | rewritten | 0 | Actual child addresses | Child |

For pointer chasing, the direct-child controls intentionally initialize `next` fields with actual child addresses. `gs_shift` still preserves the parent's logical pointer bits. The topology, number of loads, node values and results are identical. The parent mapping is protected during all child-address runs. These are diagnostic controls, not an alternative implementation of fork.

The profiling runner defaults to `--mapping alias`: both virtual arenas map the same memfd pages, so the two aliases share physical cache lines inside each run. This reduces the physical-data-placement difference between logical and translated mappings. The original harness's default is still `--mapping copy`, with independent buffers and checks that writes affect only the chosen copy. Select `--mapping copy` on the runner to profile that demonstration. In alias mode both aliases necessarily show the writes after permissions are restored.

The strongest comparisons are:

- **`original_child` vs `gs_zero_child`:** same final data addresses and pointer values; isolates the added prefixes and consequent instruction-layout effects.
- **`gs_zero_child` vs `gs_shift`:** exact same rewritten instruction bytes and final data addresses; changes GS.base and whether pointers are actual or logical. A penalty here supports an address-generation/dependency explanation, rather than instruction layout alone.
- **`original` vs `original_child`:** checks whether virtual address selection itself matters.
- **`original` vs `reencoded`:** byte-identical kernel-body control for run-to-run noise.

Use:

```sh
python3 profile.py stat --kernel chase --size 16K --seconds 5 --repeat 7 \
  --variants original_child,gs_zero_child,gs_shift
```

Every run is a separate process with new physical allocations. Alias mode does not force identical physical placement **across separate processes**. Repetition, interleaving, the same-address controls, and CPU pinning reduce confounding; they cannot eliminate host interference, page placement or frequency variation. On NUMA hardware also arrange CPU and memory placement, e.g. with `numactl` where appropriate.

## Counters and normalization

The default stat event set is `cycles:u,instructions:u,branches:u,branch-misses:u`. Results retain raw perf semicolon-separated output, per-event runtime and running percentage, exact commands, stdout/stderr, and every verified harness result. `summary.json`/`.md` report median **cycles per element**, instructions per element, ns per element and paired wall ratios. An element is one visited node for `chase` or one 64-bit lane for the other kernels. Ratios use the first requested variant as reference; the default reference is `original`.

Unsupported/not-counted events remain missing, never zero. Perf's counts may be scaled when multiplexed; the runner records running percentages and warns below 95%. Collect fewer events per pass when attribution depends on small differences. This new perf summary does not estimate confidence intervals; retain the per-run data or use the original `benchmark.py` for its bootstrap timing analysis.

If your `perf list` exposes generic cache events, collect a separate small set:

```sh
perf list
python3 profile.py stat --kernel chase --size 32K --seconds 5 \
  --events 'cycles:u,instructions:u,L1-dcache-loads:u,L1-dcache-load-misses:u'

python3 profile.py sweep --kernel chase --seconds 1 --repeat 5 \
  --sizes 8K,16K,32K,64K,256K,1M,8M,64M \
  --events 'cycles:u,instructions:u,dTLB-loads:u,dTLB-load-misses:u'
```

These event aliases are not implemented uniformly on all CPUs/VMs. Generic `cache-misses` is not an L1 miss counter. For more detail, use the load-hit/miss, completed page-walk, retired-uop/dispatch, store and front-end stall events your CPU exposes; select names from its `perf list` or vendor PMU documentation rather than copying raw event codes from another microarchitecture. Intel top-down metrics or AMD equivalents can help distinguish front-end, core execution, and memory bottlenecks, when supported.

Interpretation:

| Observation, for equal work | What it supports |
|---|---|
| Similar retired instructions and L1 miss counts, extra cycles/node for nonzero GS at 8–16 KiB | Extra hot-cache address-generation/load-use latency is plausible |
| GS=0 and GS!=0 both slower than original by similar amounts | Prefix/layout/front-end or general rewritten-instruction cost is plausible |
| GS!=0 slower than GS=0 with identical code/final addresses | Nonzero-base/logical-address handling becomes a stronger candidate |
| Larger sizes have more L1 misses and much larger baseline cycles/node, but only a small absolute GS delta | Cache/memory waiting dilutes the percentage penalty |
| Large size also increases page-walk/TLB events | Translation contributes; do not assign everything to cache capacity |
| Same-code control is similarly variable | More repetitions and a less noisy environment are needed |

Equal retired instruction counts do not imply equal uop counts, port usage, address-generation latency or execution time. No particular perf event uniquely proves “GS addition cost”; the controls and multiple observations matter.

## Sampling and annotate

The leaf kernels retain ELF function symbols and accurate rewritten function sizes. Assembly annotation works without adding frame-pointer prologues or stale DWARF line mappings. The rewriter does not update DWARF/unwind data, so the runner uses instruction sampling rather than pretending to provide correct rewritten source lines or full call chains.

```sh
python3 profile.py record --kernel chase --size 16K --seconds 10 \
  --variant original_child --output profiles/chase-original
python3 profile.py record --kernel chase --size 16K --seconds 10 \
  --variant gs_zero_child --output profiles/chase-gs-zero
python3 profile.py record --kernel chase --size 16K --seconds 10 \
  --variant gs_shift --output profiles/chase-gs-shift

perf report --stdio -i profiles/chase-gs-shift/chase-16384-gs_shift-0.data
perf annotate --stdio --symbol kernel_chase \
  -i profiles/chase-gs-shift/chase-16384-gs_shift-0.data
```

Each output includes a snapshot of the exact executable in `binaries/` and its SHA-256, so rebuilding the working `build/` directory does not invalidate an existing capture. Record disables build-id collection and annotation uses the captured ELF pathname. Keep the profiling directory in place; after moving it, use perf's symbol-path facilities if necessary. If you select another perf executable with `--perf`, use that executable for report/annotate as well.

Cycle samples can skid and are not precise per-instruction latency measurements. A load's delay may appear on a following instruction; compare totals and dependency chains before assigning a cause. Use CPU-supported precise load events if you need that level of attribution. An event such as `cpu-clock` can provide software sampling when hardware counters are unavailable, but it will not explain uop or cache behavior.

## Why smaller working sets can show a larger GS penalty

The earlier v1 Xeon pointer chase measured about **1.89 ns/node at 32 KiB** and **40.16 ns/node at 8 MiB** for the original binary. Each load of `next` determines the address of the next node, creating a serialized dependency chain. With hot data, a small extra address-generation or load-use delay can dominate. When accesses miss L1 and wait for L2/LLC/memory or translation, that delay is small relative to the much larger baseline and may overlap some of the waiting.

For illustration only, an extra 0.7 ns/node on a 1.9 ns baseline is roughly 37%; on a 40 ns baseline it is about 1.75%. That is not a measured universal GS delay. The observed 8-MiB ratio was noisy and does not establish that the absolute penalty is zero there.

Not fitting in L1 is therefore a plausible contributor to the percentage difference, but it does not identify what caused the added cost. Candidates include nonzero-segment address-generation/load-use behavior, prefix-induced loop alignment/front-end effects, translation/page placement, and VM interference. Sequential update and AVX loops can overlap/prefetch memory work and behave differently from a dependent random pointer chase. Changing data size does not itself change the code footprint. An 8-MiB workload also need not spill to DRAM: it may fit in LLC, while its random accesses still have poor L1/L2 or TLB locality.

The exact prior Xeon per-core L1 size was not recorded through sysfs, and its exposed `lscpu` cache topology was aggregated. Do not infer a sharp boundary from only 32 KiB versus 8 MiB. Inspect your machine's cache information and sweep sizes below and above its L1/L2 capacities. Compare **absolute cycles or ns per node**, along with percentage overhead and cache/TLB events.

## Validation performed here

The profiling extension passed 11 unit/integration test methods, including the FIFO enable/disable/acknowledgement protocol using an explicitly labelled synthetic controller, stat parsing with unsupported/multiplexed counters, record command generation and binary snapshots, whole-process fallback, and a bounded failure when no controller acknowledges the command. The runtime passed **432 correctness executions** spanning all six variants, copy/alias mappings, four kernels, three sizes and three round counts; eight unmodified shifted controls correctly faulted. A short 40-run timing-only sweep verified calibration, normalization, pairing and output generation.

**No real perf hardware-counter or sample capture was performed here**, because this session does not have `perf` installed. The FIFO integration test validates the protocol and command wiring, not a kernel PMU or a real perf data file. The current VM exposes an AMD EPYC processor; the earlier v1 results came from a Xeon. `results/perf-doctor.json` and `results/profile-smoke/metadata.json` record the current validation environment. The smoke sweep is not a new high-confidence performance study.

The previous package is preserved verbatim in `reference-v1.zip`, and its results are copied into `results-v1/`. Current `build/` binaries contain the profiling extension and must not be matched to v1 executable hashes.

## References

- perf stat control and output documentation: https://man7.org/linux/man-pages/man1/perf-stat.1.html
- perf record control and sampling documentation: https://man7.org/linux/man-pages/man1/perf-record.1.html
- perf annotate documentation: https://man7.org/linux/man-pages/man1/perf-annotate.1.html
- Intel memory-bound/L1/L2/L3/DRAM metric definitions: https://www.intel.com/content/www/us/en/docs/vtune-profiler/user-guide/2024-2/memory-access-analysis.html
