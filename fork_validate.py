#!/usr/bin/env python3
"""Build and validate the broad fork-oriented GS rewrite policy."""
import argparse
import io
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess

from elftools.elf.elffile import ELFFile
from iced_x86 import Decoder, Mnemonic, Register

from rewrite import (
    RSP_BASES,
    load_fork_manifest,
    memory_operand_count,
    rewrite_fork,
)


ROOT = Path(__file__).resolve().parent


def run(command, **kwargs):
    return subprocess.run(command, check=True, text=True, **kwargs)


def audit_rewritten_operands(binary, manifest):
    data = Path(binary).read_bytes()
    elf = ELFFile(io.BytesIO(data))
    symtab = elf.get_section_by_name(".symtab")
    audited = 0
    for name in load_fork_manifest(manifest):
        symbol = symtab.get_symbol_by_name(name)[0]
        section = elf.get_section(symbol["st_shndx"])
        offset = section["sh_offset"] + symbol["st_value"] - section["sh_addr"]
        code = data[offset:offset + symbol["st_size"]]
        for instruction in Decoder(64, code, ip=symbol["st_value"]):
            if (
                memory_operand_count(instruction) != 1
                or instruction.mnemonic in (Mnemonic.LEA, Mnemonic.NOP)
            ):
                continue
            excluded = (
                instruction.is_ip_rel_memory_operand
                or instruction.memory_base in RSP_BASES
            )
            expected = Register.NONE if excluded else Register.GS
            if instruction.segment_prefix != expected:
                raise RuntimeError(
                    f"{name}: unexpected segment on instruction "
                    f"at 0x{instruction.ip:x}"
                )
            audited += 1
    return audited


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cc", default="clang")
    parser.add_argument("--output", type=Path, default=ROOT / "build/fork")
    parser.add_argument("--repeat", type=int, default=16)
    args = parser.parse_args()
    if args.repeat <= 0:
        parser.error("repeat must be positive")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)

    common = [
        args.cc, "-O2", "-Wall", "-Wextra", "-Werror", "-fno-pie",
        "-fno-stack-protector", "-fcf-protection=none",
        "-fno-asynchronous-unwind-tables", "-fno-unwind-tables",
    ]
    c_object = output / "fork_runtime.o"
    asm_object = output / "fork_runtime_asm.o"
    run([*common, "-std=gnu11", "-c", str(ROOT / "tests/fork_runtime.c"),
         "-o", str(c_object)])
    run([*common, "-c", str(ROOT / "tests/fork_runtime.S"),
         "-o", str(asm_object)])
    baseline = output / "fork-baseline"
    run([
        args.cc, "-no-pie", "-Wl,--build-id=none",
        f"-Wl,-T,{ROOT / 'fork_slots.ld'}",
        str(c_object), str(asm_object), "-o", str(baseline),
    ])
    rewritten = output / "fork-rewritten"
    report_path = output / "rewrite.json"
    manifest = ROOT / "tests/fork_manifest.json"
    report = rewrite_fork(baseline, rewritten, manifest)
    report_path.write_text(json.dumps(report, indent=2) + "\n")
    audited_operands = audit_rewritten_operands(rewritten, manifest)
    negative = output / "fork-unrewritten-shift"
    shutil.copy2(baseline, negative)

    records = {"baseline": [], "rewritten": []}
    for _ in range(args.repeat):
        for name, binary in (("baseline", baseline), ("rewritten", rewritten)):
            completed = run([str(binary)], capture_output=True)
            record = json.loads(completed.stdout)
            if not record["verified"]:
                raise RuntimeError(f"{name} fork runtime verification failed")
            records[name].append(record)
    baseline_record = records["baseline"][0]
    rewritten_record = records["rewritten"][0]
    for name, values in records.items():
        signatures = {
            (
                item["memory"],
                item["indirect_call"],
                item["indirect_jump"],
                item["rip"],
                item["observed_rsp"],
                item["parent_rsp_at_fork"],
                item["parent_stack_start"],
                item["parent_stack_end"],
                item["child_stack_start"],
                item["child_stack_end"],
                item["child_alias_matches"],
                item["parent_alias_matches"],
            )
            for item in values
        }
        if len(signatures) != 1:
            raise RuntimeError(f"{name} fork results were not deterministic")

    failed = subprocess.run(
        [str(negative)], capture_output=True, text=True
    )
    if failed.returncode != -signal.SIGSEGV:
        raise RuntimeError(
            "unrewritten shifted negative control did not SIGSEGV: "
            f"{failed.returncode}\n{failed.stderr}"
        )

    functions = {
        item["function"]: item["memory_instructions"]
        for item in report["functions"]
    }
    expected = {
        "fork_memory_probe": 4,
        "fork_indirect_call": 1,
        "fork_indirect_jump": 1,
        "fork_rip_probe": 0,
    }
    if functions != expected:
        raise RuntimeError(f"unexpected rewrite selection: {functions}")

    summary = {
        "baseline": baseline_record,
        "rewritten": rewritten_record,
        "negative_control_signal": signal.SIGSEGV,
        "repeat": args.repeat,
        "rewritten_operands": functions,
        "audited_explicit_memory_operands": audited_operands,
        "rewrite_report": str(report_path),
    }
    (output / "validation.json").write_text(
        json.dumps(summary, indent=2) + "\n"
    )
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
