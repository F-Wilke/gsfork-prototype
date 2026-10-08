# Comprehensive perf trajectories

All counters were collected in separate low-count passes with 100% running time. Values are medians normalized per visited node. `gs_zero_child` and `gs_shift` use identical rewritten bytes and final data addresses; this is the causal isolation comparison.

## Primary trajectory

| KiB | Wall ratio GS/original | Cycles original -> GS | Instructions original -> GS | Branch misses original -> GS |
|---:|---:|---:|---:|---:|
| 8 | 1.750x | 4.013 -> 7.016 | 5.012 -> 5.012 | 0.001955 -> 0.001954 |
| 16 | 1.753x | 4.020 -> 7.021 | 5.006 -> 5.006 | 0.000978 -> 0.000977 |
| 32 | 1.754x | 4.150 -> 7.261 | 5.003 -> 5.003 | 0.000490 -> 0.000489 |
| 64 | 1.217x | 12.981 -> 15.790 | 5.001 -> 5.001 | 0.000247 -> 0.000245 |
| 256 | 1.169x | 21.720 -> 25.259 | 5.000 -> 5.000 | 0.000065 -> 0.000063 |
| 1,024 | 1.081x | 42.061 -> 45.546 | 5.000 -> 5.000 | 0.000023 -> 0.000018 |
| 8,192 | 1.011x | 113.712 -> 113.279 | 5.000 -> 5.000 | 0.000017 -> 0.000008 |
| 65,536 | 1.007x | 316.202 -> 318.743 | 5.000 -> 5.000 | 0.000021 -> 0.000029 |

## Same-address cache/TLB and stall trajectory

| KiB | L1 misses GS=0 -> shifted | L2 misses GS=0 -> shifted | L3 misses GS=0 -> shifted | dTLB misses GS=0 -> shifted | Total stalls GS=0 -> shifted | Resource stalls GS=0 -> shifted |
|---:|---:|---:|---:|---:|---:|---:|
| 8 | 0.000299103 -> 0.000426473 | 2.94289e-05 -> 5.10884e-05 | 1.29554e-06 -> 2.57708e-06 | 8.09712e-08 -> 1.29954e-07 | 1.294 -> 3.344 | 1.917 -> 4.598 |
| 16 | 0.0067235 -> 0.016125 | 0.000594271 -> 0.000874418 | 2.87195e-06 -> 5.02815e-06 | 1.61491e-07 -> 1.69466e-07 | 1.303 -> 3.348 | 1.949 -> 4.657 |
| 32 | 0.0492699 -> 0.058969 | 0.00110338 -> 0.00163138 | 1.05047e-05 -> 1.59032e-05 | 2.65967e-07 -> 4.40571e-07 | 1.464 -> 3.611 | 2.149 -> 4.967 |
| 64 | 0.598822 -> 0.60544 | 0.00239275 -> 0.00419697 | 2.51975e-05 -> 3.38887e-05 | 5.95952e-07 -> 6.31387e-07 | 11.184 -> 12.544 | 10.728 -> 13.590 |
| 256 | 0.907091 -> 0.907562 | 0.307628 -> 0.246968 | 9.22637e-07 -> 6.67555e-06 | 1.2537e-06 -> 1.03661e-06 | 23.586 -> 24.115 | 21.111 -> 24.292 |
| 1,024 | 0.957108 -> 0.960331 | 0.814467 -> 0.804924 | 1.49453e-06 -> 4.77621e-06 | 1.13605e-05 -> 6.08261e-06 | 42.602 -> 44.760 | 41.743 -> 44.043 |
| 8,192 | 0.953325 -> 0.944439 | 0.942227 -> 0.935748 | 0.283118 -> 0.210355 | 0.259685 -> 0.266366 | 251.658 -> 243.483 | 246.932 -> 239.262 |
| 65,536 | 0.989812 -> 0.987186 | 0.98749 -> 0.984809 | 0.907632 -> 0.908453 | 0.908091 -> 0.909768 | 327.234 -> 333.814 | 323.224 -> 327.565 |

## Frequency trajectory

| KiB | Cycles original -> GS | Reference cycles original -> GS | Cycles/reference original -> GS |
|---:|---:|---:|---:|
| 8 | 4.016 -> 7.018 | 3.545 -> 6.208 | 1.1328 -> 1.1305 |
| 16 | 4.023 -> 7.023 | 3.556 -> 6.209 | 1.1314 -> 1.1310 |
| 32 | 4.202 -> 7.699 | 3.719 -> 6.794 | 1.1298 -> 1.1332 |
| 64 | 14.247 -> 15.832 | 12.609 -> 13.981 | 1.1299 -> 1.1323 |
| 256 | 22.780 -> 26.944 | 20.109 -> 23.762 | 1.1328 -> 1.1339 |
| 1,024 | 42.242 -> 45.712 | 37.339 -> 40.431 | 1.1313 -> 1.1306 |
| 8,192 | 109.572 -> 113.305 | 96.592 -> 99.942 | 1.1344 -> 1.1337 |
| 65,536 | 311.739 -> 314.093 | 275.263 -> 277.919 | 1.1325 -> 1.1302 |

## Interpretation

- At 8-32 KiB, almost exactly two retired loads per node hit L1 in both variants; cache and TLB misses are orders of magnitude too rare to explain the roughly 3-cycle gap.
- The large difference tracks total/resource stall cycles, not L1/L2/L3 or TLB misses. Front-end starvation, branch misses, instruction count, address-alias blocks, migrations, and page faults do not track the slowdown.
- As cache/TLB miss latency grows, both variants acquire nearly identical memory-stall trajectories and the fixed GS-related stall becomes a shrinking fraction of total latency.
- This supports a nonzero-GS address-generation/load-use dependency penalty on this Kaby Lake CPU, not a cache-miss explanation. Generic cache aliases are noisier than retired-load events and should not be interpreted alone.

Long-form data for every collected event is in `profiles/20261007-comprehensive-metrics.csv`.
