#!/usr/bin/env python3
"""Rewrite selected data-buffer operands in unchanged MiBench machine code."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import struct

from elftools.elf.elffile import ELFFile
from iced_x86 import (
    BlockEncoder,
    Decoder,
    Formatter,
    FormatterSyntax,
    Instruction,
    Mnemonic,
    OpKind,
    Register,
)


FORMAT = Formatter(FormatterSyntax.INTEL)
MEMORY_KINDS = {
    OpKind.MEMORY,
    OpKind.MEMORY_SEG_SI,
    OpKind.MEMORY_SEG_ESI,
    OpKind.MEMORY_SEG_RSI,
    OpKind.MEMORY_SEG_DI,
    OpKind.MEMORY_SEG_EDI,
    OpKind.MEMORY_SEG_RDI,
    OpKind.MEMORY_ESDI,
    OpKind.MEMORY_ESEDI,
    OpKind.MEMORY_ESRDI,
}
FUNCTIONS = {
    "crc32buf": {
        "section": ".gsfork_mibench_crc",
        "bases": {Register.RDI},
        "offsets": set(),
        "expected": 3,
        "sha256": "10e64859a66bc03073c5811f0470c945fd6f18c385d59c9eb3fc04b5f4a380ea",
    },
    "fft_float": {
        "section": ".gsfork_mibench_fft",
        "bases": {Register.R15, Register.R14, Register.RBX},
        # ImagIn is spilled across ReverseBits() and reloaded into RCX.
        "offsets": {0x9F},
        "expected": 35,
        "sha256": "07cc366d9132514ac4792df073289ab431abfa9483bd00f471e5aa2eb42817dd",
    },
    "adpcm_coder": {
        "section": ".gsfork_mibench_adpcm",
        "bases": {Register.RDI, Register.RSI},
        "offsets": set(),
        "expected": 4,
        "sha256": "e5fa5d99baf30ebca3546ea64a548d60d23be5d192674a584070b42be28425d6",
    },
}


class Unsupported(ValueError):
    pass


def is_explicit_memory(instruction):
    return any(
        instruction.op_kind(index) in MEMORY_KINDS
        for index in range(instruction.op_count)
    )


def transform(code, base, rule, gs=True):
    expected_hash = rule.get("sha256")
    actual_hash = hashlib.sha256(code).hexdigest()
    if expected_hash is not None and actual_hash != expected_hash:
        raise Unsupported(
            f"function bytes do not match reviewed build: {actual_hash}"
        )
    instructions = list(Decoder(64, code, ip=base))
    if not instructions or sum(item.len for item in instructions) != len(code):
        raise Unsupported("incomplete function decoding")
    boundaries = {item.ip for item in instructions}
    edits = []
    selected_offsets = set()
    encoded = []
    for instruction in instructions:
        offset = instruction.ip - base
        selected = (
            instruction.mnemonic not in (Mnemonic.LEA, Mnemonic.NOP)
            and is_explicit_memory(instruction)
            and (
                instruction.memory_base in rule["bases"]
                or offset in rule["offsets"]
            )
        )
        if offset in rule["offsets"] and not is_explicit_memory(instruction):
            raise Unsupported(f"0x{offset:x}: expected an explicit memory operand")
        if selected:
            if instruction.has_segment_prefix:
                raise Unsupported(f"0x{offset:x}: selected operand already has a segment")
            before = FORMAT.format(instruction)
            if gs:
                instruction.segment_prefix = Register.GS
            edits.append({
                "old_offset": hex(offset),
                "before": before,
                "after": FORMAT.format(instruction),
                "memory_base": str(instruction.memory_base),
            })
            selected_offsets.add(offset)
        if instruction.is_ip_rel_memory_operand:
            target = instruction.ip_rel_memory_address
            if base <= target < base + len(code) and target not in boundaries:
                raise Unsupported(f"0x{offset:x}: RIP-relative target is not an instruction boundary")
        if instruction.mnemonic == Mnemonic.NOP:
            raw = Instruction.create_declare_byte(
                code[offset:offset + instruction.len]
            )
            raw.ip = instruction.ip
            encoded.append(raw)
        else:
            encoded.append(instruction)
    missing = rule["offsets"] - selected_offsets
    if missing:
        raise Unsupported(f"missing selected offsets: {sorted(hex(item) for item in missing)}")
    if len(edits) != rule["expected"]:
        raise Unsupported(f"expected {rule['expected']} selected operands, found {len(edits)}")
    encoder = BlockEncoder(64)
    encoder.add_many(encoded)
    return encoder.encode(base), edits


def rewrite(source, destination, report_path):
    source = Path(source)
    destination = Path(destination)
    data = bytearray(source.read_bytes())
    elf = ELFFile(io.BytesIO(data))
    if (
        elf.elfclass != 64
        or not elf.little_endian
        or elf["e_machine"] != "EM_X86_64"
        or elf["e_type"] != "ET_EXEC"
    ):
        raise Unsupported("expected a little-endian x86-64 ET_EXEC ELF")
    symtab = elf.get_section_by_name(".symtab")
    if symtab is None:
        raise Unsupported("unstripped function symbols are required")

    reports = []
    for name, rule in FUNCTIONS.items():
        candidates = symtab.get_symbol_by_name(name)
        section = elf.get_section_by_name(rule["section"])
        if not candidates or len(candidates) != 1 or section is None:
            raise Unsupported(f"missing unique symbol/reserved section for {name}")
        symbol = candidates[0]
        base = symbol["st_value"]
        size = symbol["st_size"]
        if base != section["sh_addr"] or size <= 0 or size > section["sh_size"]:
            raise Unsupported(f"invalid dedicated slot for {name}")
        offset = section["sh_offset"]
        original = bytes(data[offset:offset + size])
        rewritten, edits = transform(original, base, rule)
        if len(rewritten) > section["sh_size"]:
            raise Unsupported(f"insufficient reserved room for {name}")
        data[offset:offset + section["sh_size"]] = (
            rewritten + b"\xcc" * (section["sh_size"] - len(rewritten))
        )
        for index, candidate in enumerate(symtab.iter_symbols()):
            if candidate.name == name:
                struct.pack_into(
                    "<Q",
                    data,
                    symtab["sh_offset"] + index * symtab["sh_entsize"] + 16,
                    len(rewritten),
                )
                break
        reports.append({
            "function": name,
            "entry": hex(base),
            "original_bytes": size,
            "rewritten_bytes": len(rewritten),
            "memory_instructions": len(edits),
            "original_sha256": hashlib.sha256(original).hexdigest(),
            "edits": edits,
        })

    destination.write_bytes(data)
    destination.chmod(source.stat().st_mode & 0o777)
    report = {
        "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "output_sha256": hashlib.sha256(data).hexdigest(),
        "functions": reports,
    }
    Path(report_path).write_text(json.dumps(report, indent=2) + "\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source")
    parser.add_argument("destination")
    parser.add_argument("--report", required=True)
    args = parser.parse_args()
    if Path(args.source).resolve() == Path(args.destination).resolve():
        parser.error("input and output must differ")
    try:
        report = rewrite(args.source, args.destination, args.report)
    except (Unsupported, ValueError) as error:
        parser.exit(1, f"Rewrite rejected: {error}\n")
    for item in report["functions"]:
        print(
            f"{item['function']}: {item['original_bytes']} -> "
            f"{item['rewritten_bytes']} bytes, "
            f"{item['memory_instructions']} data-buffer accesses"
        )


if __name__ == "__main__":
    main()
