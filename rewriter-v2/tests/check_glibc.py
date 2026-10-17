"""Opt-in behavioral acceptance against an existing glibc build and rewritten outputs."""

import argparse
import hashlib
import json
import resource
import subprocess
import tempfile
from pathlib import Path

from gsfork_elf.validator import validate_artifact


def run(arguments):
    result = subprocess.run([str(a) for a in arguments], capture_output=True, text=True, timeout=120,
                            preexec_fn=lambda: resource.setrlimit(resource.RLIMIT_CORE, (0, 0)))
    if result.returncode:
        raise RuntimeError(f"{arguments}: exit {result.returncode}\n{result.stdout}\n{result.stderr}")
    return result.stdout


def check(build, loader, libc, cxx_runtime=None):
    originals = (build / "elf/ld.so", build / "libc.so")
    controls = []
    validations = []
    for original, rewritten in zip(originals, (loader, libc)):
        report_dir = Path(str(rewritten) + ".gsfork")
        report = json.loads((report_dir / "report.json").read_text())
        if report["input_sha256"] != hashlib.sha256(original.read_bytes()).hexdigest():
            raise RuntimeError(f"{rewritten}: provenance does not match selected glibc build")
        if report["runtime"] != {"scratch_rax": -16, "sandbox_offset": -8}:
            raise RuntimeError("this fixture reserves FS scratch at -16 and GS offset at -8")
        validations.append(validate_artifact(rewritten, report))
        control = report_dir / "baseline"
        if hashlib.sha256(control.read_bytes()).hexdigest() != report["baseline_sha256"]:
            raise RuntimeError(f"{control}: altered native reassembly control")
        controls.append(control)
    with tempfile.TemporaryDirectory(prefix="gsfork-glibc-check-") as temporary:
        work = Path(temporary)
        smoke = work / "smoke"
        fixture = Path(__file__).parent / "fixtures/glibc_smoke.c"
        run(["gcc", "-O2", "-fno-omit-frame-pointer", "-Wall", "-Wextra", "-Werror",
             fixture, "-pthread", "-o", smoke])
        workloads = [("C", smoke, "glibc-smoke-ok\n")]
        if cxx_runtime is not None:
            cpp = work / "cpp-smoke"
            run(["g++", "-O2", "-fno-omit-frame-pointer", fixture.parent / "glibc_exceptions.cpp",
                 fixture.parent / "glibc_control.S", "-L" + str(cxx_runtime), "-o", cpp])
            workloads.append(("C++", cpp, "catch-cleanup-unwind-ok\nfini-ok\n"))
        libraries = []
        for name, candidate in zip(("original", "native", "gs"), (originals[1], controls[1], libc)):
            directory = work / name
            directory.mkdir()
            (directory / "libc.so.6").symlink_to(candidate.resolve())
            libraries.append(directory)
        executions = []
        for loader_name, candidate in zip(("original", "native", "gs"), (originals[0], controls[0], loader)):
            for library in libraries:
                paths = [library, build / "math"]
                if cxx_runtime is not None:
                    paths.append(cxx_runtime)
                for name, executable, expected in workloads:
                    output = run([candidate, "--library-path", ":".join(map(str, paths)), executable])
                    if output != expected:
                        raise RuntimeError(f"unexpected output: {output!r}")
                    executions.append({"loader": loader_name, "libc": library.name,
                                       "workload": name, "result": "passed"})
        expected_help = None
        for candidate in (originals[0], controls[0], loader):
            help_text = run([candidate, "--help"]).replace(str(candidate), "<loader>")
            if "Usage:" not in help_text or expected_help is not None and help_text != expected_help:
                raise RuntimeError(f"{candidate}: loader help failed")
            expected_help = help_text
    return {"loader": validations[0], "libc": validations[1], "executions": executions}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--loader", type=Path, required=True)
    parser.add_argument("--libc", type=Path, required=True)
    parser.add_argument("--cxx-runtime", type=Path, help="compatible libstdc++/libgcc directory for C++ tests")
    arguments = parser.parse_args()
    print(json.dumps(check(arguments.build.resolve(), arguments.loader.resolve(), arguments.libc.resolve(),
                           arguments.cxx_runtime.resolve() if arguments.cxx_runtime else None),
                     indent=2))
