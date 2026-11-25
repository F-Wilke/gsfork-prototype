#!/usr/bin/env python3
"""Compare source-built and rewritten compilers with a diagnostic GS=0 ABI."""
import argparse
import json
from pathlib import Path
import subprocess
import sys


C_SOURCE = r"""
static int f(int n) { switch (n) {
case 0:return 11; case 1:return 3; case 2:return 9; case 3:return 8;
case 4:return 6; case 5:return 5; default:return 1; } }
int main(void) {
  int total=0; for(int i=0;i<6;i++) total+=f(i);
  return total!=42;
}
"""

CPP_SOURCE = r"""
#include <numeric>
#include <stdexcept>
#include <vector>
int main() {
  std::vector<int> values{1,2,3,4};
  try { if (std::accumulate(values.begin(),values.end(),0)==10)
      throw std::runtime_error("expected"); }
  catch (const std::runtime_error &error) { return error.what()[0]!='e'; }
  return 1;
}
"""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--result", required=True, type=Path, help="pipeline output directory")
    parser.add_argument("--compiler", choices=("cc1", "clang"), required=True)
    parser.add_argument("--resource-dir", type=Path, help="Clang build's lib/clang/<version>")
    parser.add_argument("--acknowledge-host-tcb-writes", action="store_true",
                        help="allow GDB to overwrite two FS slots in the test inferior")
    args = parser.parse_args()
    if not args.acknowledge_host_tcb_writes:
        parser.error("this diagnostic writes to host TCB slots; explicitly acknowledge the risk")
    if args.compiler == "clang" and not args.resource_dir:
        parser.error("--resource-dir is required for Clang")
    root = args.result.resolve(strict=True)
    report = json.loads((root / "result.json").read_text())
    slots = report["runtime_slots"]
    output = root / "native-smoke"
    output.mkdir(exist_ok=False)
    source = output / "fixture.c"
    source.write_text(C_SOURCE)
    cpp = output / "fixture.cpp"
    cpp.write_text(CPP_SOURCE)
    preprocessed = output / "fixture.i"
    if args.compiler == "cc1":
        subprocess.run(["gcc", "-E", "-P", source, "-o", preprocessed], check=True)
    results = []
    for optimization in ("-O0", "-O2"):
        cases = [("c", "s"), ("c", "o"), ("c++", "o")] if args.compiler == "clang" else [("c", "s")]
        for language, extension in cases:
            label = f"{language}-{optimization}.{extension}"
            baseline = output / f"baseline-{label}"
            rewritten = output / f"rewritten-{label}"
            if args.compiler == "clang":
                compiler_args = ["-resource-dir", str(args.resource_dir.resolve()), "-fintegrated-cc1",
                                 optimization, "-S" if extension == "s" else "-c",
                                 str(cpp if language == "c++" else source)]
                if language == "c++":
                    compiler_args.insert(0, "-std=c++20")
            else:
                compiler_args = [str(preprocessed), optimization, "-quiet"]
            subprocess.run([root / "baseline", *compiler_args, "-o", baseline], check=True)
            gdb = ["gdb", "-q", "-batch", "-ex", "break *&_start", "-ex", "run",
                   "-ex", f"set *(unsigned long *)($fs_base+{slots['sandbox_offset']})=0",
                   "-ex", f"set *(unsigned long *)($fs_base+{slots['scratch_rax']})=0",
                   "-ex", "disable 1", "-ex", "continue", "--args", str(root / "rewritten"),
                   *compiler_args, "-o", str(rewritten)]
            result = subprocess.run(gdb, check=True, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, text=True)
            (output / f"gdb-{label}.log").write_text(result.stdout)
            if "exited normally" not in result.stdout:
                raise RuntimeError(f"rewritten compiler failed: {output / f'gdb-{label}.log'}")
            if baseline.read_bytes() != rewritten.read_bytes():
                raise RuntimeError(f"compiler output differs: {label}")
            if extension == "o" or args.compiler == "cc1":
                executable = output / f"run-{label}"
                subprocess.run(["g++" if language == "c++" else "gcc", "-no-pie",
                                rewritten, "-o", executable], check=True)
                subprocess.run([executable], check=True)
            results.append({"language": language, "optimization": optimization,
                            "emission": extension, "identical": True})
    (output / "result.json").write_text(json.dumps({
        "results": results, "gdb_writes_host_tcb": True,
        "gs_fork_runtime_verified": False}, indent=2) + "\n")
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"compiler-smoke: {error}", file=sys.stderr)
        sys.exit(1)
