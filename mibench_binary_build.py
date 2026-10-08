#!/usr/bin/env python3
"""Build MiBench variants from unchanged upstream source and binary rewriting."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

from mibench_build import COMMIT, REPOSITORY, source_tree
from mibench_rewrite import rewrite


ROOT = Path(__file__).resolve().parent


def run(command, **kwargs):
    return subprocess.run(command, check=True, text=True, **kwargs)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def compile_object(cc, source, output, standard, includes, extra=None):
    command = [
        cc,
        "-O3",
        "-Wall",
        "-Wextra",
        "-fno-pie",
        "-fno-stack-protector",
        "-fcf-protection=none",
        "-fno-asynchronous-unwind-tables",
        "-fno-unwind-tables",
        "-ffunction-sections",
        "-fdata-sections",
        f"-std={standard}",
        *[flag for directory in includes for flag in ("-I", str(directory))],
        *(extra or []),
        "-c",
        str(source),
        "-o",
        str(output),
    ]
    run(command)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "build/mibench-binary")
    parser.add_argument("--source", help="existing pinned ekut-es/mibench checkout")
    parser.add_argument("--cc", default="clang")
    parser.add_argument("--objcopy", default="objcopy")
    args = parser.parse_args()

    output = args.output.resolve()
    objects = output / "objects"
    objects.mkdir(parents=True, exist_ok=True)
    source = source_tree(output, args.source)
    upstream = {
        "crc_32.c": source / "telecomm/CRC32/crc_32.c",
        "crc.h": source / "telecomm/CRC32/crc.h",
        "sniptype.h": source / "telecomm/CRC32/sniptype.h",
        "fourierf.c": source / "telecomm/FFT/fourierf.c",
        "fftmisc.c": source / "telecomm/FFT/fftmisc.c",
        "fourier.h": source / "telecomm/FFT/fourier.h",
        "ddcmath.h": source / "telecomm/FFT/ddcmath.h",
        "adpcm.c": source / "telecomm/adpcm/src/adpcm.c",
        "adpcm.h": source / "telecomm/adpcm/src/adpcm.h",
    }
    source_hashes = {name: digest(path) for name, path in upstream.items()}
    includes = [
        ROOT / "mibench",
        source / "telecomm/CRC32",
        source / "telecomm/FFT",
        source / "telecomm/adpcm/src",
    ]
    units = [
        (
            ROOT / "mibench/driver.c",
            "driver.o",
            "gnu11",
            ["-DGS_INSTRUMENTED=0", "-DMIBENCH_BINARY_REWRITE=1"],
        ),
        (
            upstream["crc_32.c"],
            "crc_32.o",
            "gnu89",
            [],
        ),
        (upstream["fourierf.c"], "fourierf.o", "gnu11", []),
        (upstream["fftmisc.c"], "fftmisc.o", "gnu11", []),
        (upstream["adpcm.c"], "adpcm.o", "gnu89", []),
    ]
    object_paths = []
    for source_path, name, standard, extra in units:
        object_path = objects / name
        compile_object(
            args.cc, source_path, object_path, standard, includes, extra
        )
        if name == "crc_32.o":
            run([
                args.objcopy,
                "--redefine-sym",
                "main=mibench_crc_upstream_main",
                str(object_path),
            ])
        object_paths.append(object_path)
    if {name: digest(path) for name, path in upstream.items()} != source_hashes:
        raise RuntimeError("upstream source changed during the build")

    baseline = output / "mibench-baseline"
    run([
        args.cc,
        "-no-pie",
        "-Wl,--build-id=none",
        "-Wl,--gc-sections",
        f"-Wl,-T,{ROOT / 'mibench_binary_slots.ld'}",
        *map(str, object_paths),
        "-lm",
        "-o",
        str(baseline),
    ])
    instrumented = output / "mibench-instrumented"
    rewrite(baseline, instrumented, output / "rewrite.json")
    binaries = {"baseline": baseline}
    for name in ("gs0", "gsshift"):
        target = output / f"mibench-{name}"
        shutil.copy2(instrumented, target)
        binaries[name] = target

    disassembly = {
        name: run(
            ["objdump", "-d", "-Mintel", str(path)], capture_output=True
        ).stdout
        for name, path in binaries.items()
    }
    report = {
        "method": "binary-rewrite",
        "repository": REPOSITORY,
        "commit": COMMIT,
        "compiler": run(
            [args.cc, "--version"], capture_output=True
        ).stdout.splitlines()[0],
        "objcopy": run(
            [args.objcopy, "--version"], capture_output=True
        ).stdout.splitlines()[0],
        "source": str(source),
        "upstream_source_sha256": source_hashes,
        "binaries": {
            name: {"path": str(path), "sha256": digest(path)}
            for name, path in binaries.items()
        },
        "gs_operand_count": {
            name: text.count("gs:") for name, text in disassembly.items()
        },
        "rewrite_report": str(output / "rewrite.json"),
    }
    if report["binaries"]["gs0"]["sha256"] != report["binaries"]["gsshift"]["sha256"]:
        raise RuntimeError("GS=0 and shifted-GS binaries differ")
    if report["gs_operand_count"]["baseline"] != 0:
        raise RuntimeError("baseline unexpectedly contains GS operands")
    if report["gs_operand_count"]["gs0"] != 42:
        raise RuntimeError(
            f"expected 42 rewritten GS operands, got {report['gs_operand_count']['gs0']}"
        )
    (output / "build.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
