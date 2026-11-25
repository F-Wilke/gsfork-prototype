#!/usr/bin/env python3
"""Reproduce a GNU link from instrumented selected objects and patch its PLT."""
import argparse
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import time

from elftools.elf.elffile import ELFFile
from elftools.common.exceptions import ELFError, DWARFError

from gsfork_elf.elf import tcb_field_offset
from gsfork_elf.errors import RewriteError
from gsfork_elf.objects import transform_object
from gsfork_elf.pipeline import rewrite
from gsfork_elf.policy import Runtime


def command_from_file(path, target):
    text = path.read_text().replace("\\\n", " ")
    candidates = []
    for line in text.splitlines():
        try:
            args = shlex.split(line)
        except ValueError:
            continue
        if "-o" in args and args.index("-o") + 1 < len(args):
            output = args[args.index("-o") + 1]
            if target is None or output == target:
                candidates.append(args)
    if len(candidates) != 1:
        raise ValueError(f"expected exactly one link command, found {len(candidates)}; "
                         "select the exact -o value with --link-target")
    args = candidates[0]
    if any(arg in ("&&", "||", ";", "|", ">", ">>", "<") for arg in args):
        raise ValueError("link command must be a direct compiler invocation without shell operators")
    return args


def trace_inputs(log, cwd):
    inputs = []
    archives = {}
    for line in log.splitlines():
        match = re.fullmatch(r"\((.+\.a)\)([^()]+)", line)
        if not match:
            match = re.fullmatch(r"(.+\.a)\(([^()]+)\)", line)
        if match:
            archive, member = match.groups()
            path = (cwd / archive).resolve()
            if path not in archives:
                archives[path] = subprocess.check_output(["ar", "t", path], text=True).splitlines()
            if archives[path].count(member) != 1:
                raise ValueError(f"archive member is missing or ambiguous: {path}({member})")
            inputs.append({"path": str(path), "member": member})
        elif line and not line.startswith(" ") and Path(line).suffix in (".o", ".oS"):
            path = (cwd / line).resolve()
            if not path.is_file():
                raise ValueError(f"traced object not found: {path}")
            inputs.append({"path": str(path), "member": None})
        elif line and not line.startswith(" "):
            if re.fullmatch(r"\(.+\)[^()]+", line):
                raise ValueError(f"unrecognized archive member in linker trace: {line}")
            path = cwd / line
            if path.is_file():
                with path.open("rb") as stream:
                    magic = stream.read(8)
                    if magic.startswith(b"\x7fELF"):
                        stream.seek(0)
                        if ELFFile(stream)['e_type'] == "ET_REL":
                            raise ValueError(f"unrecognized relocatable object in linker trace: {line}")
                    elif magic in (b"!<arch>\n", b"!<thin>\n") and path.suffix != ".a":
                        raise ValueError(f"unrecognized archive in linker trace: {line}")
    if not inputs:
        raise ValueError("linker trace contained no object inputs")
    return inputs


def probe(item):
    index, spec, root, runtime = item
    directory = root / "inputs" / f"{index:05d}"
    directory.mkdir(parents=True)
    source = directory / "original.o"
    stripped = directory / "nodebug.o"
    start = time.monotonic()
    if spec["member"] is None:
        source.symlink_to(spec["path"])
    else:
        with source.open("wb") as stream:
            subprocess.run(["ar", "p", spec["path"], spec["member"]], stdout=stream, check=True)
    subprocess.run(["objcopy", "--strip-debug", source, stripped], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    result = dict(spec, original_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
                  directory=str(directory))
    try:
        payload, counts = transform_object(stripped, runtime)
        (directory / "rewritten.o").write_bytes(payload)
        result.update(status="accepted", gs_prefixes=sum(counts.values()))
    except RewriteError as error:
        result.update(status="rejected", error=str(error))
    result["seconds"] = round(time.monotonic()-start, 3)
    return result


def elf_info(path):
    with path.open("rb") as stream:
        elf = ELFFile(stream)
        dynamic = elf.get_section_by_name(".dynamic")
        needed = [tag.needed for tag in dynamic.iter_tags() if tag.entry.d_tag == "DT_NEEDED"] if dynamic else []
        interpreter = next((segment.get_interp_name() for segment in elf.iter_segments()
                            if segment['p_type'] == "PT_INTERP"), None)
        return {"type": elf['e_type'], "needed": needed, "interpreter": interpreter}


def run(args):
    cwd = args.link_directory.resolve(strict=True)
    link = command_from_file(args.link_command, args.link_target)
    runtime = Runtime(
        tcb_field_offset(args.tcb_layout, "pthread", args.scratch_field)
        if args.tcb_layout else args.scratch_rax,
        tcb_field_offset(args.tcb_layout, "pthread", args.sandbox_field)
        if args.tcb_layout else args.sandbox_offset,
    )
    runtime.check()
    if runtime.scratch_rax is None or runtime.sandbox_offset is None:
        raise ValueError("both runtime slots are required")
    shared = [path.resolve(strict=True) for path in args.shared]
    if not shared:
        raise ValueError("explicit --shared link inputs are required")
    for path in shared:
        if elf_info(path)["type"] != "ET_DYN":
            raise ValueError(f"shared link input is not an ELF shared object: {path}")
    root = args.output.resolve()
    root.mkdir(parents=True, exist_ok=False)
    link[link.index("-o")+1] = str(root / "baseline")
    link.extend(["-Wl,-z,now,--no-relax,-t,-t", f"-Wl,-Map,{root / 'baseline.map'}"])
    (root / "baseline-command.json").write_text(json.dumps(link, indent=2) + "\n")
    start = time.monotonic()
    with (root / "baseline-link.log").open("w") as log:
        subprocess.run(link, cwd=cwd, stdout=log, stderr=subprocess.STDOUT, check=True)
    inputs = trace_inputs((root / "baseline-link.log").read_text(), cwd)
    baseline = elf_info(root / "baseline")
    if baseline["type"] != "ET_DYN" or not baseline["interpreter"]:
        raise ValueError("baseline must be a dynamically linked PIE")
    (root / "inputs.json").write_text(json.dumps(inputs, indent=2) + "\n")
    baseline_time = time.monotonic()-start
    start = time.monotonic()
    with concurrent.futures.ProcessPoolExecutor(max_workers=args.jobs) as executor:
        results = list(executor.map(probe, ((i, spec, root, runtime)
                                            for i, spec in enumerate(inputs))))
    (root / "audit.json").write_text(json.dumps(results, indent=2) + "\n")
    rejected = [item for item in results if item["status"] != "accepted"]
    if rejected:
        for item in rejected:
            print(f"{item['path']}({item['member']}): {item['error']}", file=sys.stderr)
        raise RewriteError(f"{len(rejected)}/{len(results)} objects rejected; refusing to link")
    rewrite_time = time.monotonic()-start
    command = [args.linker, "-nostdlib", "-pie", "-Wl,-e,_start,-z,now,--no-relax,--eh-frame-hdr"]
    if args.gc_sections:
        command.append("-Wl,--gc-sections")
    command += [f"-Wl,-Map,{root / 'rewritten.map'}", "-o", str(root / "linked")]
    command += [str(Path(item["directory"]) / "rewritten.o") for item in results]
    command += [str(path) for path in shared]
    (root / "rewritten-command.json").write_text(json.dumps(command, indent=2) + "\n")
    start = time.monotonic()
    with (root / "rewritten-link.log").open("w") as log:
        subprocess.run(command, cwd=cwd, stdout=log, stderr=subprocess.STDOUT, check=True)
    linked_time = time.monotonic()-start
    linked = elf_info(root / "linked")
    if (linked["type"] != baseline["type"] or linked["interpreter"] != baseline["interpreter"]
            or set(linked["needed"]) != set(baseline["needed"])):
        raise RewriteError(f"linked ELF runtime dependencies differ: baseline={baseline}, rewritten={linked}")
    if linked["needed"] != baseline["needed"] and not args.allow_needed_reordering:
        raise RewriteError("DT_NEEDED order changed; review interposition and pass "
                           "--allow-needed-reordering to acknowledge the difference")
    start = time.monotonic()
    plt = rewrite(root / "linked", root / "rewritten", plt_only=True)
    report = {
        "baseline_seconds": baseline_time, "object_rewrite_seconds": rewrite_time,
        "link_seconds": linked_time, "plt_seconds": time.monotonic()-start,
        "instrumented_inputs": len(results), "runtime_slots": {
            "scratch_rax": runtime.scratch_rax, "sandbox_offset": runtime.sandbox_offset,
            "tcb_layout": str(args.tcb_layout.resolve()) if args.tcb_layout else None,
            "tcb_layout_sha256": hashlib.sha256(args.tcb_layout.read_bytes()).hexdigest()
            if args.tcb_layout else None},
        "baseline_elf": baseline, "rewritten_elf": linked,
        "shared_link_inputs": [str(path) for path in shared],
        "plt_validation": plt["validation"], "gs_fork_runtime_verified": False,
    }
    (root / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--link-directory", required=True, type=Path)
    parser.add_argument("--link-command", required=True, type=Path)
    parser.add_argument("--link-target", help="exact -o value to select from a make dry-run log")
    parser.add_argument("--output", required=True, type=Path, help="new directory for all artifacts")
    parser.add_argument("--shared", action="append", type=Path, default=[],
                        help="explicit shared link input; repeat in link order")
    parser.add_argument("--linker", default="gcc", help="compiler driver for the rewritten link")
    parser.add_argument("--gc-sections", action="store_true")
    parser.add_argument("--allow-needed-reordering", action="store_true",
                        help="acknowledge changed dynamic symbol lookup order")
    parser.add_argument("--jobs", type=int, default=min(32, os.cpu_count() or 1))
    parser.add_argument("--tcb-layout", type=Path, help="runtime libc with struct pthread DWARF")
    parser.add_argument("--scratch-field", default="sandbox_scratch")
    parser.add_argument("--sandbox-field", default="sandbox_offset")
    parser.add_argument("--scratch-rax", type=lambda value: int(value, 0))
    parser.add_argument("--sandbox-offset", type=lambda value: int(value, 0))
    args = parser.parse_args()
    if args.jobs < 1:
        parser.error("--jobs must be positive")
    if args.tcb_layout and (args.scratch_rax is not None or args.sandbox_offset is not None):
        parser.error("use either --tcb-layout or numeric runtime slots")
    if not args.tcb_layout and (args.scratch_rax is None or args.sandbox_offset is None):
        parser.error("provide --tcb-layout or both --scratch-rax and --sandbox-offset")
    try:
        run(args)
    except (OSError, ValueError, RewriteError, ELFError, DWARFError, subprocess.SubprocessError) as error:
        print(f"rewrite-link-inputs: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
