#!/usr/bin/env python3
"""Offline, restricted x86-64 ELF rewriter for explicitly reserved function slots."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import struct
from elftools.elf.elffile import ELFFile
from iced_x86 import (BlockEncoder, Decoder, FlowControl, Formatter, FormatterSyntax,
                      Instruction, InstructionInfoFactory, Mnemonic, OpKind, Register)

FUNCTIONS = {f"kernel_{s}": f".gsfork_{s}" for s in ("sum", "update", "avx2", "chase")}
# Deliberately small supported instruction family, not an x86 security validator.
ALLOWED = {getattr(Mnemonic, n) for n in (
    "MOV MOVZX MOVSX MOVSXD LEA ADD SUB XOR AND OR TEST CMP INC DEC IMUL SHL SHR SAR "
    "NEG NOT NOP RET JMP JE JNE JB JAE JA JBE JL JLE JG JGE CMOVE CMOVNE "
    "VPBROADCASTQ VMOVQ VMOVDQU VPADDQ VPXOR VZEROUPPER"
).split()}
STACK_REGS = {Register.RSP, Register.ESP, Register.SP, Register.SPL,
              Register.RBP, Register.EBP, Register.BP, Register.BPL}
RSP_BASES = {Register.RSP, Register.ESP, Register.SP}
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
FORMAT = Formatter(FormatterSyntax.INTEL)

class Unsupported(ValueError):
    pass


def memory_operand_count(instruction):
    return sum(
        instruction.op_kind(index) in MEMORY_KINDS
        for index in range(instruction.op_count)
    )


def transform(code, base, gs=True):
    insns = list(Decoder(64, code, ip=base))
    if not insns or sum(i.len for i in insns) != len(code):
        raise Unsupported("Incomplete function decoding")
    addresses = {i.ip for i in insns}
    factory = InstructionInfoFactory()
    edits = []
    for i in insns:
        def reject(reason):
            raise Unsupported(f"0x{i.ip:x}: {FORMAT.format(i)}: {reason}")
        if i.is_invalid or i.mnemonic not in ALLOWED:
            reject("outside supported instruction subset")
        if (i.has_segment_prefix or i.has_rep_prefix or i.has_repne_prefix) and i.mnemonic != Mnemonic.NOP:
            reject("existing segment or REP prefix")
        if i.mnemonic == Mnemonic.RET:
            if i.op_count != 0:
                reject("only plain native-stack RET is supported")
            continue
        if i.is_stack_instruction:
            reject("implicit stack access")
        if i.flow_control not in (FlowControl.NEXT, FlowControl.CONDITIONAL_BRANCH,
                                   FlowControl.UNCONDITIONAL_BRANCH):
            reject("calls and indirect control flow need a separate ABI")
        if i.flow_control in (FlowControl.CONDITIONAL_BRANCH, FlowControl.UNCONDITIONAL_BRANCH):
            if i.near_branch_target not in addresses:
                reject("branch outside the function or into an instruction")
        info = factory.info(i)
        if any(r.register in STACK_REGS for r in info.used_registers()):
            reject("stack/frame register use requires stack virtualization")
        explicit = any(i.op_kind(k) == OpKind.MEMORY for k in range(i.op_count))
        if i.is_ip_rel_memory_operand:
            reject("RIP-relative code/data classification is not implemented")
        if i.mnemonic in (Mnemonic.LEA, Mnemonic.NOP):
            continue  # Address computation/alignment padding: no data access.
        used = info.used_memory()
        if used and (not explicit or len(used) != 1):
            reject("implicit or multiple memory operands")
        if explicit:
            if not used:
                reject("memory operand with unclassified semantics")
            before = FORMAT.format(i)
            if gs:
                i.segment_prefix = Register.GS
            edits.append({"old_ip": hex(i.ip), "before": before, "after": FORMAT.format(i)})
    encoded_insns = []
    for i in insns:
        if i.mnemonic == Mnemonic.NOP:
            raw = Instruction.create_declare_byte(code[i.ip - base:i.ip - base + i.len])
            raw.ip = i.ip
            encoded_insns.append(raw)
        else:
            encoded_insns.append(i)
    encoder = BlockEncoder(64)
    encoder.add_many(encoded_insns)
    encoded = encoder.encode(base)
    # Verify all emitted direct branch targets remain instruction boundaries.
    out = list(Decoder(64, encoded, ip=base))
    targets = {i.ip for i in out}
    for i in out:
        if i.is_invalid:
            raise Unsupported("Encoder produced invalid bytes")
        if i.flow_control in (FlowControl.CONDITIONAL_BRANCH, FlowControl.UNCONDITIONAL_BRANCH):
            if i.near_branch_target not in targets:
                raise Unsupported("Encoded branch escaped its function")
    return encoded, edits


def transform_fork(code, base, gs=True):
    """Translate explicit memory operands except RIP/RSP-based accesses.

    Native implicit stack traffic remains untouched. Memory-indirect CALL/JMP
    operands are translated, while direct and register-indirect control flow
    has no address calculation to modify.
    """
    instructions = list(Decoder(64, code, ip=base))
    if not instructions or sum(item.len for item in instructions) != len(code):
        raise Unsupported("Incomplete function decoding")
    factory = InstructionInfoFactory()
    edits = []
    encoded_instructions = []
    for instruction in instructions:
        def reject(reason):
            raise Unsupported(
                f"0x{instruction.ip:x}: {FORMAT.format(instruction)}: {reason}"
            )

        if instruction.is_invalid:
            reject("invalid instruction")
        count = memory_operand_count(instruction)
        used_memory = factory.info(instruction).used_memory()
        if count > 1:
            reject("multiple explicit memory operands need separate translation")
        allowed_implicit_bases = set(RSP_BASES)
        if count:
            allowed_implicit_bases.add(instruction.memory_base)
            if instruction.is_ip_rel_memory_operand:
                allowed_implicit_bases.add(Register.NONE)
        if any(
            memory.base not in allowed_implicit_bases
            for memory in used_memory
        ):
            reject("implicit non-RSP memory access is not supported")

        selected = (
            count == 1
            and instruction.mnemonic not in (Mnemonic.LEA, Mnemonic.NOP)
            and not instruction.is_ip_rel_memory_operand
            and instruction.memory_base not in RSP_BASES
        )
        if selected:
            if instruction.has_segment_prefix:
                reject("selected operand already has a segment override")
            before = FORMAT.format(instruction)
            if gs:
                instruction.segment_prefix = Register.GS
            edits.append({
                "old_ip": hex(instruction.ip),
                "before": before,
                "after": FORMAT.format(instruction),
                "memory_base": str(instruction.memory_base),
                "flow_control": str(instruction.flow_control),
            })

        offset = instruction.ip - base
        if instruction.mnemonic == Mnemonic.NOP:
            raw = Instruction.create_declare_byte(
                code[offset:offset + instruction.len]
            )
            raw.ip = instruction.ip
            encoded_instructions.append(raw)
        else:
            encoded_instructions.append(instruction)

    encoder = BlockEncoder(64)
    encoder.add_many(encoded_instructions)
    encoded = encoder.encode(base)
    if any(item.is_invalid for item in Decoder(64, encoded, ip=base)):
        raise Unsupported("Encoder produced invalid bytes")
    return encoded, edits


def rewrite_slots(source, destination, functions, transformer, gs=True, mode="restricted"):
    data = bytearray(Path(source).read_bytes())
    elf = ELFFile(io.BytesIO(data))
    if elf.elfclass != 64 or not elf.little_endian or elf['e_machine'] != 'EM_X86_64' or elf['e_type'] != 'ET_EXEC':
        raise Unsupported("Expected a little-endian x86-64 ET_EXEC ELF")
    symtab = elf.get_section_by_name('.symtab')
    if symtab is None:
        raise Unsupported("Unstripped function symbols are required")
    reports = []
    for name, section_name in functions.items():
        candidates = symtab.get_symbol_by_name(name)
        section = elf.get_section_by_name(section_name)
        if not candidates or len(candidates) != 1 or section is None:
            raise Unsupported(f"Missing unique symbol/reserved section: {name}")
        sym = candidates[0]
        base, size = sym['st_value'], sym['st_size']
        if base != section['sh_addr'] or size <= 0 or size > section['sh_size']:
            raise Unsupported(f"Invalid dedicated slot for {name}")
        if not section['sh_flags'] & 4 or section['sh_type'] != 'SHT_PROGBITS':
            raise Unsupported(f"Non-executable or non-file-backed slot for {name}")
        for other in symtab.iter_symbols():
            if other.name != name and base <= other['st_value'] < base + section['sh_size'] and other['st_size']:
                raise Unsupported(f"Slot also contains symbol {other.name}")
        off = section['sh_offset']
        old = bytes(data[off:off+size])
        new, edits = transformer(old, base, gs)
        if len(new) > section['sh_size']:
            raise Unsupported(f"Insufficient reserved room for {name}")
        data[off:off+section['sh_size']] = new + b'\xcc' * (section['sh_size'] - len(new))
        # Keep ELF disassembly symbol extents accurate; DWARF/unwind are not supported.
        for index, candidate in enumerate(symtab.iter_symbols()):
            if candidate.name == name:
                struct.pack_into('<Q', data, symtab['sh_offset'] + index * symtab['sh_entsize'] + 16, len(new))
        reports.append({"function": name, "entry": hex(base), "original_bytes": size,
                        "rewritten_bytes": len(new), "memory_instructions": len(edits),
                        "original_hex": old.hex(), "rewritten_hex": new.hex(), "edits": edits})
    Path(destination).write_bytes(data)
    Path(destination).chmod(Path(source).stat().st_mode & 0o777)
    return {"gs": gs, "mode": mode,
            "source_sha256": hashlib.sha256(Path(source).read_bytes()).hexdigest(),
            "output_sha256": hashlib.sha256(data).hexdigest(), "functions": reports}


def rewrite(source, destination, gs=True):
    return rewrite_slots(source, destination, FUNCTIONS, transform, gs)


def load_fork_manifest(path):
    document = json.loads(Path(path).read_text())
    entries = document.get("functions")
    if not isinstance(entries, list) or not entries:
        raise Unsupported("Fork manifest requires a non-empty functions list")
    functions = {}
    for entry in entries:
        if not isinstance(entry, dict):
            raise Unsupported("Fork manifest entries must be objects")
        symbol = entry.get("symbol")
        section = entry.get("section")
        if not isinstance(symbol, str) or not symbol:
            raise Unsupported("Fork manifest function symbol is missing")
        if not isinstance(section, str) or not section:
            raise Unsupported(f"Fork manifest section is missing for {symbol}")
        if symbol in functions:
            raise Unsupported(f"Duplicate fork manifest symbol: {symbol}")
        functions[symbol] = section
    return functions


def rewrite_fork(source, destination, manifest, gs=True):
    functions = load_fork_manifest(manifest)
    return rewrite_slots(
        source, destination, functions, transform_fork, gs, mode="fork"
    )


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('source'); p.add_argument('destination')
    p.add_argument('--no-gs', action='store_true', help='Re-encoding-only control')
    p.add_argument('--fork-manifest',
                   help='rewrite listed functions with the broad fork policy')
    p.add_argument('--report', required=True)
    a = p.parse_args()
    if Path(a.source).resolve() == Path(a.destination).resolve():
        p.error('input and output must differ')
    try:
        if a.fork_manifest:
            report = rewrite_fork(
                a.source, a.destination, a.fork_manifest, not a.no_gs
            )
        else:
            report = rewrite(a.source, a.destination, not a.no_gs)
    except (Unsupported, ValueError) as e:
        p.exit(1, f'Rewrite rejected: {e}\n')
    Path(a.report).write_text(json.dumps(report, indent=2) + '\n')
    for f in report['functions']:
        print(f"{f['function']}: {f['original_bytes']} -> {f['rewritten_bytes']} bytes, {f['memory_instructions']} data accesses")
