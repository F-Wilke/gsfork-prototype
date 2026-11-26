# GCC and Clang object-first evaluation

These experimental scripts reproduce the object-first compiler rewrite, not the
older whole-executable `mpk/assess.py` pipeline. They produce candidates, not a
GS-Fork certification. `rewrite_link_inputs.py` runs a baseline link with GNU
ld's double trace, extracts every selected archive member, strips debug info
from copies, rewrites every traced object, links those objects explicitly, and
patches the final eager PLT. It refuses to link if any object is rejected.
Source files, original objects, and archives are never modified.

The relink flattens selected archive members into explicit objects; this is
specific to these compiler links and is not guaranteed equivalent for arbitrary
link commands. Check `baseline.map`, `rewritten.map`, dynamic symbol resolution,
and behavior. It checks PIE type, interpreter, and the set of `DT_NEEDED`
names; it does **not** prove equivalent symbol versions or dynamic resolution.
In particular, these compiler links reordered `DT_NEEDED` entries. The script
requires `--allow-needed-reordering` to acknowledge that this can affect
interposition. The PLT report covers PLT slots only; the explicit shared
libraries, loader, runtime and every other execution boundary remain the
operator's responsibility.

## Prerequisites

- Linux x86-64, Python 3.10+, GNU make, GCC/G++, GNU binutils, CMake for Clang;
  for the optional native smoke, GDB and permission to trace a child process.
- The `feature/object-rewrite-plt` rewriter installed using `make install` in
  `rewriter-v2`. Source checkouts of `lind-wasm-apps`, `lind-wasm`, and custom
  Lind glibc are required. The recipes and compiler wrappers below come from
  `lind-wasm-apps/mpk`.
- Build Lind glibc and install its headers. The layout ELF must retain DWARF
  describing `struct pthread` and must match the runtime libc/loader that will
  execute the compiler. Do not copy offsets from another build.
- A real Lind MPK evaluation additionally needs CPU/kernel `pku` support,
  `lind-boot`, compatible GS-rewritten loader/libc/libm staged in lindfs, and
  a documented instrumentation/trust decision for all dynamic dependencies.
  The original experiments used **host** `libm` at link time; neither that
  library nor the native smoke establishes GS-Fork runtime compatibility.
- GCC's prerequisite download may require network access. Preserve the exact
  source revisions, toolchain versions, configure flags and input manifests
  when comparing runs; compiler outputs can differ between machines.

For the separate SURI workflow, `lind-wasm-dotnet-9.patch` contains the .NET 9
SDK addition to `lind-wasm/Docker/Dockerfile.mnt.dev` (based on Lind commit
`7863fbeea`). Apply it from the `lind-wasm` checkout with
`git apply /path/to/gsfork-prototype/rewriter-v2/tools/lind-wasm-dotnet-9.patch`
and rebuild the image. .NET is not required for this object-first workflow.

`suri-cc1-experiment.patch` preserves the separate experimental SURI
compatibility edits, based on SURI commit `4f66872a9597f0c18cd3ff45516ac25d600b4576`.
Apply with `git apply --unidiff-zero /path/to/gsfork-prototype/rewriter-v2/tools/suri-cc1-experiment.patch`.
These changes did **not** produce a runnable rewritten `cc1`; they are retained
for investigation, not as a working SURI solution.

The examples use the existing committed compiler wrappers, which select the
custom glibc at link time. Set absolute paths for your checkouts and output
location; use a writable scratch directory with sufficient disk space.

```sh
export APPS=/path/to/lind-wasm-apps
export LIND_WASM_ROOT=/path/to/lind-wasm
export LIND_GLIBC=/path/to/glibc-2.35
export RW=/path/to/gsfork-prototype/rewriter-v2
export WORK=/path/to/compiler-evaluation
export JOBS=32
mkdir -p "$WORK"
cd "$RW" && make install
```

## Build GCC `cc1`

Use the GCC source from `lind-wasm-apps`; obtain GMP, MPFR and MPC as in
`mpk/recipes/gcc.sh` before configuring. The wrapper supplies PIC and the
custom libc; `--enable-host-pie` makes GCC's host executables PIE. This builds
the C compiler and retains all selected objects and libraries.

```sh
GCC_SOURCE="$APPS/gcc"
GCC_BUILD="$WORK/gcc-build"
mkdir -p "$GCC_BUILD"
cd "$GCC_BUILD"
"$GCC_SOURCE/configure" \
  CC="$APPS/mpk/bin/lind-mpk-cc" CXX="$APPS/mpk/bin/lind-mpk-c++" \
  CC_FOR_BUILD=gcc CXX_FOR_BUILD=g++ --prefix="$WORK/gcc-prefix" \
  --enable-languages=c --disable-bootstrap --disable-multilib --disable-nls \
  --disable-shared --disable-plugin --disable-lto --without-isl --without-zstd \
  --disable-libsanitizer --enable-host-pie MAKEINFO=true
make -j"$JOBS" MAKEINFO=true all-gcc
cd "$GCC_BUILD/gcc"
make -n -B cc1 > "$WORK/cc1-link-plan.txt"
```

Review the captured plan: it must contain one actual compiler link command
with `-o cc1`. The rewrite script parses it as arguments, not as shell code.
The logged baseline link retains the wrapper environment and working directory.

## Build Clang

This mirrors the Clang portions of `mpk/recipes/llvm-project.sh`, but builds
Clang only and retains its inputs. This is a separate native build, not the
WASI cross-build. The previous experiment used GCC/G++ 11.4, binutils 2.38,
CMake 3.22, and LLVM/Clang 18.1.8.

```sh
CLANG_BUILD="$WORK/clang-build"
cmake -G "Unix Makefiles" -S "$APPS/llvm-project/llvm" -B "$CLANG_BUILD" \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_COMPILER="$APPS/mpk/bin/lind-mpk-cc" \
  -DCMAKE_CXX_COMPILER="$APPS/mpk/bin/lind-mpk-c++" \
  -DCMAKE_C_FLAGS="-g1 -fPIC -fasynchronous-unwind-tables" \
  -DCMAKE_CXX_FLAGS="-g1 -fPIC -fasynchronous-unwind-tables" \
  -DCMAKE_EXE_LINKER_FLAGS="-pie -Wl,-z,now,--no-relax" \
  -DLLVM_ENABLE_PROJECTS=clang -DLLVM_TARGETS_TO_BUILD=X86 \
  -DLLVM_INCLUDE_TESTS=OFF -DLLVM_BUILD_TESTS=OFF \
  -DLLVM_INCLUDE_BENCHMARKS=OFF -DLLVM_INCLUDE_EXAMPLES=OFF \
  -DCLANG_INCLUDE_TESTS=OFF -DLLVM_ENABLE_ZLIB=OFF -DLLVM_ENABLE_ZSTD=OFF \
  -DLLVM_ENABLE_LIBXML2=OFF -DLLVM_ENABLE_TERMINFO=OFF \
  -DLLVM_ENABLE_LIBEDIT=OFF -DLLVM_ENABLE_LIBPFM=OFF \
  -DLLVM_ENABLE_PLUGINS=OFF -DCLANG_PLUGIN_SUPPORT=OFF \
  -DLLVM_BUILD_LLVM_DYLIB=OFF -DLLVM_TOOL_LLVM_DRIVER_BUILD=OFF \
  -DCMAKE_SKIP_RPATH=ON
cmake --build "$CLANG_BUILD" --target clang -j"$JOBS"
```

## Rewrite, link, and inspect

Supply **explicit shared ELF files**, in link order, for the rewritten link.
The following paths reproduce the original experiment on Ubuntu x86-64;
adjust for the actual baseline link, and do not assume the host libm is a safe
Lind runtime. `--shared` rejects static archives. Use a new output directory
for every attempt. For these builds `--allow-needed-reordering` is necessary;
omit it to fail instead of accepting a change in dependency lookup order.

```sh
HOST_LIBM=/lib/x86_64-linux-gnu/libm.so.6

cd "$RW"
.venv/bin/python tools/rewrite_link_inputs.py \
  --link-directory "$GCC_BUILD/gcc" --link-command "$WORK/cc1-link-plan.txt" \
  --link-target cc1 --tcb-layout "$LIND_GLIBC/build/libc.so" \
  --shared "$HOST_LIBM" --shared "$LIND_GLIBC/build/libc.so" \
  --shared "$LIND_GLIBC/build/elf/ld.so" --allow-needed-reordering \
  --jobs "$JOBS" --output "$WORK/cc1-rewrite"

CLANG_LINK_DIR="$CLANG_BUILD/tools/clang/tools/driver"
.venv/bin/python tools/rewrite_link_inputs.py \
  --link-directory "$CLANG_LINK_DIR" \
  --link-command "$CLANG_LINK_DIR/CMakeFiles/clang.dir/link.txt" \
  --tcb-layout "$LIND_GLIBC/build/libc.so" \
  --shared "$HOST_LIBM" --shared "$LIND_GLIBC/build/libc.so" \
  --shared "$LIND_GLIBC/build/elf/ld.so" --allow-needed-reordering \
  --gc-sections --jobs "$JOBS" --output "$WORK/clang-rewrite"
```

The script records commands, linker logs and maps, input hashes, per-object
audit results, timings, TCB layout hash/offsets and PLT validation in the
output directory. `rewritten` is the candidate and `result.json` explicitly
records that GS-Fork execution was **not** verified. It stops before linking
on rejected objects, ambiguous archive members, unrecognized object inputs,
or incompatible dynamic dependencies. `.gsfork/` is the PLT-only report.

### Optional native diagnostic

For comparison only, GDB stops each native test process at `_start` and writes
zero to the two derived offsets in its **host** TCB. These slots are not
reserved by ordinary host libc and the writes can interfere with host runtime
state; use an isolated diagnostic environment. This exercises GS=0, not MPK,
nonzero GS translation, fork, or Lind. It does not configure a GS-Fork runtime.

```sh
.venv/bin/python tools/compiler_smoke.py --result "$WORK/cc1-rewrite" \
  --compiler cc1 --acknowledge-host-tcb-writes
.venv/bin/python tools/compiler_smoke.py --result "$WORK/clang-rewrite" \
  --compiler clang --resource-dir "$CLANG_BUILD/lib/clang/18" \
  --acknowledge-host-tcb-writes
```

The Clang resource directory's version must match the build. The smoke compares
baseline and candidate C output at `-O0` and `-O2`; Clang also compiles a C++20
fixture. It links and runs the resulting fixture programs on the host. For a
real evaluation, separately integrate the compiler, its resource files and
runtime dependencies into lindfs, then run compiler and fork tests under
`lind-boot` on a PKU-capable machine. GCC's candidate here is `cc1`, not a
validated GCC driver or complete toolchain.
