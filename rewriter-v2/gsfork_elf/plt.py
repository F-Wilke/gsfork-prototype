from iced_x86 import Mnemonic, Register

from .errors import RewriteError, fail
from .policy import decode


PLT_SECTIONS = {".plt", ".plt.got", ".plt.sec", ".iplt"}


def indirect(data, address):
    ins = decode(data[:6], address)[0]
    if (len(data[:6]) != 6 or data[:2] != b"\xff\x25"
            or ins.mnemonic != Mnemonic.JMP or not ins.is_ip_rel_memory_operand):
        raise RewriteError(f"unrecognized RIP-indirect PLT jump at 0x{address:x}")
    return ins.ip_rel_memory_address


def translated_jump(address, target):
    disp = target - (address + 7)
    if not -(1 << 31) <= disp < (1 << 31):
        raise RewriteError("PLT displacement overflow")
    return b"\x65\xff\x25" + disp.to_bytes(4, "little", signed=True)


def pointer_identity(image, target):
    reloc = image.relocations.get(target)
    if reloc and reloc["type"] in (6, 7) and reloc["symbol"]:
        return reloc["symbol"]
    if reloc and reloc["type"] == 37 and not reloc["symbol"]:
        return reloc["addend"]
    raise RewriteError(f"{image.path}: PLT target 0x{target:x} is not GLOB_DAT/JUMP_SLOT/IRELATIVE")


def slot_bytes(record):
    prefix = bytes.fromhex(record.get("prefix", ""))
    address, size, target = record["address"], record["size"], record["target"]
    body = (translated_jump(address + len(prefix), target) if target is not None else b"\x0f\x0b")
    if len(prefix) + len(body) > size:
        raise RewriteError("GS jump cannot fit in generated PLT slot")
    return prefix + body + b"\x90" * (size - len(prefix) - len(body))


def patch_plt(image, *, require_now=True):
    """Replace only recognized GNU ld eager-binding slots without moving any bytes."""
    result = bytearray(image.data)
    records = []
    for section in image.executable:
        if not section.name.startswith((".plt", ".iplt")):
            continue
        if section.name not in PLT_SECTIONS:
            fail(image.path, section.name, section["sh_addr"], "unsupported generated PLT layout")
        if require_now and not image.now:
            raise RewriteError(f"{image.path}: PLT rewriting requires DT_BIND_NOW/DF_BIND_NOW")
        data, base = section.data(), section["sh_addr"]
        cet = image.elf.get_section_by_name(".plt.sec") is not None
        stride = 8 if section.name == ".plt.got" and not cet else 16
        if len(data) % stride:
            fail(image.path, section.name, base, "invalid generated PLT slot size")
        for offset in range(0, len(data), stride):
            address = base + offset
            slot = data[offset:offset + stride]
            prefix = b""
            if section.name == ".plt" and offset == 0:
                ins = decode(slot, address)
                if (len(ins) != 3 or slot[:2] != b"\xff\x35"
                        or slot[6:8] != b"\xff\x25" and slot[6:9] != b"\xf2\xff\x25"
                        or ins[2].mnemonic != Mnemonic.NOP
                        or not ins[0].is_ip_rel_memory_operand
                        or not ins[1].is_ip_rel_memory_operand
                        or ins[1].ip_rel_memory_address != ins[0].ip_rel_memory_address + 8):
                    fail(image.path, section.name, address, "unrecognized lazy resolver header")
                target = None
            elif section.name == ".plt" and cet:
                ins = decode(slot, address)
                if (len(ins) != 4 or slot[:4] != b"\xf3\x0f\x1e\xfa"
                        or ins[1].mnemonic != Mnemonic.PUSH or ins[2].mnemonic != Mnemonic.JMP
                        or ins[2].near_branch_target != base or ins[3].mnemonic != Mnemonic.NOP):
                    fail(image.path, section.name, address, "unrecognized CET lazy PLT tail")
                prefix, target = slot[:4], None
            else:
                jump_offset = 0
                if slot.startswith(b"\xf3\x0f\x1e\xfa"):
                    prefix = slot[:4]
                    jump_offset = 4
                if slot[jump_offset:jump_offset + 1] == b"\xf2":
                    prefix += b"\xf2"
                    jump_offset += 1
                target = indirect(slot[jump_offset:], address + jump_offset)
                pointer_identity(image, target)
                tail = decode(slot[jump_offset + 6:], address + jump_offset + 6)
                if section.name == ".plt":
                    if (len(tail) != 2 or tail[0].mnemonic != Mnemonic.PUSH
                            or tail[1].mnemonic != Mnemonic.JMP
                            or tail[1].near_branch_target != base):
                        fail(image.path, section.name, address, "unrecognized lazy PLT tail")
                elif any(i.mnemonic != Mnemonic.NOP
                         and not (i.mnemonic == Mnemonic.XCHG and i.op0_register == Register.AX
                                  and i.op1_register == Register.AX) for i in tail):
                    fail(image.path, section.name, address, "unrecognized PLT.got padding")
            record = {"section": section.name, "address": address, "size": stride,
                      "target": target, "prefix": prefix.hex(),
                      "strategy": "eager-gs-jump" if target is not None else "retired-lazy-resolver"}
            patched = slot_bytes(record)
            start = section["sh_offset"] + offset
            result[start:start + stride] = patched
            records.append({**record, "bytes": patched.hex()})
    return bytes(result), records


def validate_plt(image, records):
    seen = set()
    entries = {}
    for record in records:
        address, size = record["address"], record["size"]
        section = image.section_at(address, size)
        if section is None or section.name != record["section"] or section.name not in PLT_SECTIONS:
            raise RewriteError(f"{image.path}: PLT record outside supported section")
        if record.get("prefix", "") not in ("", "f2", "f30f1efa", "f30f1efaf2"):
            raise RewriteError(f"{image.path}: unsupported PLT control prefix")
        expected = slot_bytes(record)
        if image.read(address, size) != expected or expected.hex() != record["bytes"]:
            fail(image.path, section.name, address, "linker-generated code does not match GS PLT contract")
        if record["target"] is not None:
            instructions = decode(expected, address)
            ins = instructions[1] if instructions[0].mnemonic == Mnemonic.ENDBR64 else instructions[0]
            if ins.segment_prefix != Register.GS:
                fail(image.path, section.name, address, "uncovered/generated PLT pointer load")
            entries[address] = pointer_identity(image, ins.ip_rel_memory_address)
        seen.update(range(address, address + size))
    for section in image.executable:
        if section.name.startswith((".plt", ".iplt")):
            expected = set(range(section["sh_addr"], section["sh_addr"] + section["sh_size"]))
            if not expected <= seen or not image.now:
                fail(image.path, section.name, section["sh_addr"], "unaccounted PLT region or lazy binding")
    return entries, seen
