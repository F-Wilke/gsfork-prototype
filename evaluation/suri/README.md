# SURI evaluation on GCC cc1

Use x86-64 Linux, .NET SDK 9, Python 3 with pyelftools 0.32, GNU binutils,
GNU time, and GCC/G++ 11 (the upstream emitter uses absolute compiler paths).
Build and run on an OS compatible with the input compiler's dynamic libraries.

```bash
git clone https://github.com/SoftSec-KAIST/SURI.git
git -C SURI checkout 4f66872a9597f0c18cd3ff45516ac25d600b4576
git -C SURI submodule update --init
dotnet build -c Release SURI/superCFGBuilder/superCFGBuilder
python3 -m venv .venv
.venv/bin/pip install pyelftools==0.32
PYTHON="$PWD/.venv/bin/python" bash evaluation/suri/evaluate.sh \
  ./SURI /absolute/path/to/cc1 ./suri-cc1-results
```

Use the exact input from the Ddisasm run for a paired comparison. SURI targets
CET-enabled x86-64 PIE binaries. Treat other inputs as compatibility probes.
The results directory must be new and its absolute path must be
shell-safe (e.g. no whitespace) because the upstream emitter constructs
its compiler command using a shell.

Each stage writes a log and GNU time metrics. Recovery is B2R2 CFG analysis
and JSON generation. Symbolization produces assembly. Reassembly includes
compilation/linking and ELF reconstruction. Sum the three wall times for
elapsed tool time. Report each stage's peak RSS separately. The default
timeout is two hours **per stage**. Override it with `STAGE_TIMEOUT=6h`.
Intermediate artifacts remain in place on failure.

The smoke check compares assembly emitted by the original and rewritten
`cc1` for a small C fixture. Matching output tests that path through the
compiler. Record the input hash, ELF properties, host, and SURI revision
from `environment.txt` alongside timing results.

To check the harness on a small CET/PIE executable before starting a large job:

```bash
gcc-11 -O2 -fPIE -pie -fcf-protection=full -Wl,-z,ibt,-z,shstk \
  evaluation/suri/smoke.c -o /tmp/suri-smoke
PYTHON="$PWD/.venv/bin/python" bash evaluation/suri/evaluate.sh \
  ./SURI /tmp/suri-smoke ./suri-smoke-results
```

The fixture accepts the same output argument as cc1 and emits a fixed assembly
directive. It tests the recovery, symbolization, relinking, and execution
plumbing. The cc1 run tests actual compilation.

On the Debian GCC 14 / binutils host used for the local smoke test, the upstream
emitter produced a binary that crashed at startup. The optional
`debian-gcc14.patch` selects the system GCC/G++, removes the fixed placement of
`.note.ABI-tag`, and preserves page congruence when appending the new segments.
Use it only for a separately labelled compatibility run:

```bash
git -C SURI apply "$PWD/evaluation/suri/debian-gcc14.patch"
```

The local CET/PIE fixture passed all stages with this patch. This does not
establish compatibility with arbitrary linker layouts.
