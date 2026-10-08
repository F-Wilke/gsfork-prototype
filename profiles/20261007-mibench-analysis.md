# MiBench GS performance analysis

## Conclusion

The MiBench extension reproduces the microbenchmark finding at application-kernel
scale: a nonzero GS base can add backend resource pressure, but the effect is
workload-dependent and is not caused by additional cache misses.

- CRC32: no measurable GS=0 or shifted-GS penalty.
- ADPCM: no reproducible shifted-GS penalty.
- FFT: shifted GS is 5.47% slower than the byte-identical GS=0 executable in
  the focused seven-block run, increasing from 201.62 to 212.65 cycles per
  sample item.
- FFT instructions are unchanged at 488.071/item.
- FFT resource stalls increase by 9.35/item, accounting for most of the 11.04
  additional cycles.
- FFT L1 data-cache misses increase by only 0.0128/item, while LLC, retired L3,
  and dTLB misses decrease slightly. Cache and TLB misses cannot explain the
  observed cycle increase.

The strongest comparison is GS=0 versus shifted-GS. These names are copies of
one linked executable with identical SHA-256 hashes, instruction bytes, and
code addresses. They differ only in the runtime GS base and alias selected for
the instrumented data buffers.

## Workloads and correctness

The build pins `ekut-es/mibench` commit
`54cdff6764b231fdb0a6e45c36c0cb8e7acf74ee` and evaluates:

| Benchmark | Access pattern | Work per iteration |
|---|---|---:|
| CRC32 | streaming input and table lookup | 16 MiB |
| FFT | dense floating-point array reads/writes | 65,536 samples |
| ADPCM encoder | streaming input/output plus scalar state | 4 Mi samples |

Every measured execution reported a verified checksum. Shifted mode protects
the logical mappings during the kernel, so a missing GS annotation would fault.
The baseline contains zero `gs:` operands; each instrumented name contains 44.
The GS=0 and shifted-GS binaries both hash to
`6724dbe483d81010f25133b9aacbe2af25dcf996cb10353c86708ded5cd84e37`.

## Primary counters

Three randomized paired blocks were run for approximately one second per
variant, with perf enabled only around the kernel.

| Benchmark | Variant | Cycles/item | Instructions/item | Relative to baseline wall time |
|---|---|---:|---:|---:|
| CRC32 | baseline | 8.116 | 6.500 | 1.000x |
| CRC32 | GS=0 | 8.118 | 6.500 | 1.001x |
| CRC32 | shifted GS | 8.117 | 6.500 | 0.997x |
| FFT | baseline | 204.175 | 488.071 | 1.000x |
| FFT | GS=0 | 207.418 | 488.071 | 0.999x |
| FFT | shifted GS | 213.276 | 488.071 | 1.034x |
| ADPCM | baseline | 25.374 | 62.754 | 1.000x |
| ADPCM | GS=0 | 25.559 | 62.754 | 0.989x |
| ADPCM | shifted GS | 24.843 | 62.754 | 0.983x |

CRC32 is insensitive to both instrumentation and the GS base. ADPCM variation
changes sign across passes and does not support a slowdown claim. FFT repeatedly
places shifted GS above GS=0, motivating the longer focused run.

## Focused FFT attribution

Seven randomized paired blocks co-measured cycles, instructions, total stalls,
and resource stalls:

| Variant | ns/item | Cycles/item | Instructions/item | Total stalls/item | Resource stalls/item |
|---|---:|---:|---:|---:|---:|
| baseline | 49.634 | 203.072 | 488.071 | 32.619 | 56.225 |
| GS=0 | 49.262 | 201.616 | 488.071 | 28.627 | 55.511 |
| shifted GS | 51.939 | 212.653 | 488.071 | 28.907 | 64.865 |
| shifted / GS=0 | 1.054 | 1.055 | 1.000 | 1.010 | 1.169 |

The shifted execution adds 11.037 cycles/item and 9.354 resource-stall
events/item. Frontend-independent instruction work is unchanged. The generic
`cycle_activity.stalls_total` event does not account for the delta, while the
backend `resource_stalls.any` event tracks it closely. This is consistent with
the earlier dependent-load result, where the nonzero segment base manifested
as backend/resource pressure.

## Cache and TLB trajectory

A second seven-block FFT run collected miss events:

| Event | Baseline/item | GS=0/item | Shifted GS/item | Shifted / GS=0 |
|---|---:|---:|---:|---:|
| L1 data-cache load misses | 5.194108 | 5.222346 | 5.235100 | 1.0024x |
| LLC load misses | 0.000513 | 0.000837 | 0.000794 | 0.9477x |
| Retired L3 load misses | 0.000226 | 0.000506 | 0.000475 | 0.9387x |
| dTLB load misses | 0.000351 | 0.000397 | 0.000380 | 0.9563x |

The only positive miss delta is 0.012754 L1 misses/item. Even assigning an
implausibly large cost to every extra L1 miss cannot produce the 11.037-cycle
delta, and the lower-level cache and TLB miss counts move in the opposite
direction. The slowdown is therefore not a cache-miss trajectory.

The broader three-block passes agree:

| Benchmark | Cycles shifted/GS=0 | L1 misses | dTLB misses | Resource stalls | Total stalls |
|---|---:|---:|---:|---:|---:|
| CRC32 | 1.000x | 1.002x | 0.997x | 0.999x | 1.002x |
| FFT | 1.055x focused | 1.002x focused | 0.956x focused | 1.169x focused | 1.010x focused |
| ADPCM | no stable delta | 1.001x | 0.987x | 0.989x | 1.053x |

Additional passes found no explanatory change in instruction count, branches,
address-alias stalls, machine clears, page faults, CPU migrations, or context
switches. All reported hardware events ran at 100%, so the tables do not rely
on multiplex scaling.

## Method

Only explicit benchmark input/output data buffers are instrumented using
Clang's x86 address space 256. Stack, globals, state structures, libc, TLS,
control data, and syscall buffers remain native. Shifted mode maps each memfd
arena at both its logical address and logical address plus 1 TiB, passes the
logical pointer, sets GS.base to 1 TiB, and protects the logical alias.

The runner:

1. pins each process to CPU 0;
2. calibrates a common iteration count from the baseline;
3. randomizes variant order within paired blocks;
4. measures only the kernel region through perf control FIFOs;
5. uses identical work and iteration counts within a benchmark/pass;
6. verifies the checksum after every run;
7. retains every sample without outlier removal.

The full 312-row long-form table is
`profiles/20261007-mibench-metrics.csv`. Raw commands, perf CSVs, executable
snapshots, stdout/stderr, metadata, and run records are under
`results/mibench-primary`, `results/mibench-metrics`, and
`results/mibench-fft-focused`.

## Limitations

This evaluates three MiBench kernels, not the complete suite. The instrumentation
boundary is intentionally data-buffer-only because whole-program GS prefixing
would incorrectly relocate stack, TLS, globals, library accesses, and syscall
buffers. Baseline versus GS=0 includes the effect of changed instruction
encoding; GS=0 versus shifted-GS is the controlled nonzero-base comparison.

Measurements were collected on an Intel Core i7-7700/Kaby Lake system running
Linux 6.12 and perf 6.12.111. CPU affinity does not eliminate interrupts,
frequency changes, or activity elsewhere on the machine. The FFT result is
consistent over longer paired runs, but other microarchitectures should be
measured rather than assumed to behave identically.
