# REP MOVSB FS-offset wrapper microbenchmark

The standard `make bench` suite now includes `rep_movsb` at 32 KiB and 8 MiB,
alongside `sum`, `update`, `avx2`, and `chase`.

The native control calls `rep_movsb_copy_native`, which executes a plain
`rep movsb`. The `gs_zero` and `gs_shift` variants instead call the
hand-written `rep_movsb_copy_wrapped` function. These two implementations
copy the lower half of the requested arena into the upper half for each round.
The wrapper adjusts RSI and RDI by a per-thread offset loaded from FS-relative
TLS, performs the *same hardware REP MOVSB*, then undoes both adjustments.
It saves RAX in a per-thread FS scratch slot and preserves flags using
`LAHF`, `SETO`, `ADD AL, 0x7f`, and `SAHF`. No stack writes or red-zone
writes are inserted. This is a hand-written stand-in for a future binary
rewriter transformation; the existing restricted rewriter still rejects
string instructions.

## Run

```bash
python3 -m pip install -r requirements.txt
make test
make bench
# Faster smoke run:
python3 benchmark.py --samples 7 --target-ms 30 --output results/rep-movsb
```

The table's REP MOVSB rate is **nanoseconds per byte copied** (half the arena
size per round), rather than nanoseconds per 8-byte element. The native,
re-encoded, GS-zero, and GS-shifted variants remain paired and randomized.
All four existing kernels run in the same invocation.

The new GitHub Actions workflow runs `make test` and the full five-kernel
microbenchmark suite, printing `table.md` and uploading the raw JSON/CSV
samples and environment metadata as artifacts. This is the source of actual
CI-run measurements; no performance numbers are assumed in advance.

## Limitations

- This benchmark measures **the wrapper**, not runtime binary patching.
- Calls into the assembly routine and its C outer loop are included; at
  small transfer sizes they can dominate the result.
- Real Lind signal delivery must swap the scratch state and translate
  partially adjusted RSI/RDI when interrupted within the wrapper.
- The wrapper assumes `DF=0`, as required by the System V AMD64 ABI for
  function entry. For arbitrary inline instructions with `DF=1`, validate
  those semantics separately.
- Scratch TLS must be private per native thread. The benchmark uses glibc's
  native FS-based TLS slots rather than Lind supervisor's reserved region.
- A future real rewriter must also preserve the original RCX semantics:
  this benchmark's explicit kernel ABI passes the byte count in RDX
  and initializes RCX immediately before the REP instruction.
