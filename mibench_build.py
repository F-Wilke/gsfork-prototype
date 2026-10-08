#!/usr/bin/env python3
"""Build reproducible baseline, GS=0, and shifted-GS MiBench kernel binaries."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parent
REPOSITORY = "https://github.com/ekut-es/mibench.git"
COMMIT = "54cdff6764b231fdb0a6e45c36c0cb8e7acf74ee"


def run(command, **kwargs):
    return subprocess.run(command, check=True, text=True, **kwargs)


def replace_once(text, old, new, path):
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{path}: expected one occurrence of {old!r}, found {count}")
    return text.replace(old, new)


def replace_first(text, old, new, path):
    if old not in text:
        raise RuntimeError(f"{path}: missing {old!r}")
    return text.replace(old, new, 1)


def source_tree(output, requested):
    if requested:
        source = Path(requested).resolve()
        actual = run(["git", "-C", str(source), "rev-parse", "HEAD"],
                     capture_output=True).stdout.strip()
        if actual != COMMIT:
            raise RuntimeError(f"MiBench source must be pinned at {COMMIT}, got {actual}")
        return source
    source = output / "upstream"
    if not (source / ".git").is_dir():
        run(["git", "clone", "--quiet", REPOSITORY, str(source)])
    run(["git", "-C", str(source), "fetch", "--quiet", "origin", COMMIT])
    run(["git", "-C", str(source), "checkout", "--quiet", "--detach", COMMIT])
    return source


def prepare_sources(source, destination):
    if destination.exists():
        shutil.rmtree(destination)
    destination.mkdir(parents=True)
    files = {
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
    for name, path in files.items():
        shutil.copy2(path, destination / name)

    path = destination / "crc.h"
    text = path.read_text()
    text = replace_once(text, '#include "sniptype.h"', '#include "sniptype.h"\n#include "gs_types.h"', path)
    text = replace_once(text, "DWORD crc32buf(char *buf, size_t len);",
                        "DWORD crc32buf(gs_char *buf, size_t len);", path)
    path.write_text(text)

    path = destination / "crc_32.c"
    text = path.read_text()
    text = replace_once(text, "DWORD crc32buf(char *buf, size_t len)",
                        "DWORD crc32buf(gs_char *buf, size_t len)", path)
    path.write_text(text)

    path = destination / "fourier.h"
    text = path.read_text()
    text = replace_first(text, '#ifdef __cplusplus', '#include "gs_types.h"\n\n#ifdef __cplusplus', path)
    for name in ("RealIn", "ImaginaryIn", "RealOut", "ImaginaryOut"):
        text = replace_once(text, f"float    *{name}", f"gs_float *{name}", path)
    path.write_text(text)

    path = destination / "fourierf.c"
    text = path.read_text()
    text = replace_once(text, "#include <math.h>", "#include <math.h>\n#include <stdint.h>", path)
    text = replace_once(text, "#define CHECKPOINTER(p)  CheckPointer(p,#p)",
                        "#define CHECKPOINTER(p)  CheckPointer((void *)(uintptr_t)(p),#p)", path)
    for name in ("RealIn", "ImagIn", "RealOut", "ImagOut"):
        text = replace_once(text, f"float    *{name}", f"gs_float *{name}", path)
    path.write_text(text)

    path = destination / "adpcm.h"
    text = path.read_text()
    text = replace_once(text, "struct adpcm_state {", '#include "gs_types.h"\n\nstruct adpcm_state {', path)
    text = replace_once(text, "void adpcm_coder ARGS((short [], char [], int, struct adpcm_state *));",
                        "void adpcm_coder ARGS((gs_short *, gs_char *, int, struct adpcm_state *));", path)
    text = replace_once(text, "void adpcm_decoder ARGS((char [], short [], int, struct adpcm_state *));",
                        "void adpcm_decoder ARGS((gs_char *, gs_short *, int, struct adpcm_state *));", path)
    path.write_text(text)

    path = destination / "adpcm.c"
    text = path.read_text()
    replacements = [
        ("    short indata[];", "    gs_short *indata;"),
        ("    char outdata[];", "    gs_char *outdata;"),
        ("    short *inp;", "    gs_short *inp;"),
        ("    signed char *outp;", "    gs_schar *outp;"),
        ("    outp = (signed char *)outdata;", "    outp = (gs_schar *)outdata;"),
        ("    char indata[];", "    gs_char *indata;"),
        ("    short outdata[];", "    gs_short *outdata;"),
        ("    signed char *inp;", "    gs_schar *inp;"),
        ("    short *outp;", "    gs_short *outp;"),
        ("    inp = (signed char *)indata;", "    inp = (gs_schar *)indata;"),
    ]
    for old, new in replacements:
        text = replace_once(text, old, new, path)
    path.write_text(text)
    return files


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_variant(cc, source_dir, output, name, instrumented):
    variant_dir = output / name
    variant_dir.mkdir(parents=True, exist_ok=True)
    defines = [
        f"-DGS_INSTRUMENTED={int(instrumented)}",
    ]
    common = [
        cc, "-O3", "-Wall", "-Wextra", "-fno-pie", "-fno-stack-protector",
        "-fcf-protection=none", "-fno-asynchronous-unwind-tables",
        "-fno-unwind-tables", "-I", str(source_dir), "-I", str(ROOT / "mibench"),
        *defines,
    ]
    units = [
        (ROOT / "mibench/driver.c", "driver.o", "gnu11", []),
        (source_dir / "crc_32.c", "crc_32.o", "gnu89", ["-Dmain=mibench_crc_upstream_main"]),
        (source_dir / "fourierf.c", "fourierf.o", "gnu11", []),
        (source_dir / "fftmisc.c", "fftmisc.o", "gnu11", []),
        (source_dir / "adpcm.c", "adpcm.o", "gnu89", []),
    ]
    objects = []
    for source, object_name, standard, extra in units:
        object_path = variant_dir / object_name
        run([*common, f"-std={standard}", *extra, "-c", str(source), "-o", str(object_path)])
        objects.append(object_path)
    binary = output / f"mibench-{name}"
    run([cc, "-no-pie", "-Wl,--build-id=none", *map(str, objects), "-lm", "-o", str(binary)])
    return binary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "build/mibench")
    parser.add_argument("--source", help="existing pinned ekut-es/mibench checkout")
    parser.add_argument("--cc", default="clang")
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    source = source_tree(output, args.source)
    originals = prepare_sources(source, output / "src")
    baseline = build_variant(args.cc, output / "src", output, "baseline", False)
    instrumented = build_variant(args.cc, output / "src", output, "instrumented", True)
    binaries = {"baseline": baseline}
    for name in ("gs0", "gsshift"):
        target = output / f"mibench-{name}"
        shutil.copy2(instrumented, target)
        binaries[name] = target
    disassembly = run(["objdump", "-d", "-Mintel", str(binaries["gs0"])],
                      capture_output=True).stdout
    if "gs:" not in disassembly:
        raise RuntimeError("instrumented binary contains no GS-relative operands")
    baseline_disassembly = run(["objdump", "-d", "-Mintel", str(binaries["baseline"])],
                               capture_output=True).stdout
    report = {
        "repository": REPOSITORY,
        "commit": COMMIT,
        "source": str(source),
        "source_sha256": {name: digest(path) for name, path in originals.items()},
        "binaries": {name: {"path": str(path), "sha256": digest(path)}
                     for name, path in binaries.items()},
        "gs_operand_count": {
            "baseline": baseline_disassembly.count("gs:"),
            "gs0": disassembly.count("gs:"),
            "gsshift": run(["objdump", "-d", "-Mintel", str(binaries["gsshift"])],
                           capture_output=True).stdout.count("gs:"),
        },
    }
    (output / "build.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
