import hashlib

from iced_x86 import MemorySizeExt, Mnemonic, OpKind, Register

from .elf import Image
from .errors import RewriteError, fail
from .metadata import Metadata
from .plt import patch_plt, pointer_identity, validate_plt
from .policy import Runtime, classify, decode, string_form


BRANCH_KINDS = {OpKind.NEAR_BRANCH16, OpKind.NEAR_BRANCH32, OpKind.NEAR_BRANCH64}


def padding(data, address):
    try:
        return all(i.mnemonic == Mnemonic.NOP
                   or (i.mnemonic == Mnemonic.XCHG and i.op0_register == Register.AX
                       and i.op1_register == Register.AX)
                   for i in decode(data, address))
    except RewriteError:
        return False


def shape(ins, symbolic):
    if ins.mnemonic == Mnemonic.NOP:
        return ("nop",)
    mnemonic = ins.mnemonic
    count = ins.op_count
    comparisons = {Mnemonic.VPCMPB: Mnemonic.VPCMPEQB, Mnemonic.VPCMPD: Mnemonic.VPCMPEQD,
                   Mnemonic.VPCMPQ: Mnemonic.VPCMPEQQ, Mnemonic.VPCMPW: Mnemonic.VPCMPEQW}
    if mnemonic in comparisons and ins.immediate(ins.op_count - 1) == 0:
        mnemonic = comparisons[mnemonic]
        count -= 1
    compare = mnemonic in comparisons.values()
    operands = []
    for index in range(count):
        kind = ins.op_kind(index)
        if kind == OpKind.REGISTER:
            operands.append(("register", ins.op_register(index)))
        elif kind in BRANCH_KINDS:
            operands.append(("branch",))
        elif kind == OpKind.MEMORY:
            operands.append(("memory", ins.memory_base, ins.memory_index, ins.memory_index_scale,
                             MemorySizeExt.size(ins.memory_size) if compare else ins.memory_size,
                             None if symbolic and symbolic["field"] == "displacement"
                             else ins.memory_displacement))
        elif kind >= OpKind.IMMEDIATE8 and kind <= OpKind.IMMEDIATE32TO64:
            operands.append(("immediate", None if symbolic and symbolic["field"] == "immediate"
                             else ins.immediate(index)))
        else:
            operands.append(("implicit", kind))
    return (mnemonic, operands, ins.has_lock_prefix, ins.has_rep_prefix, ins.has_repne_prefix,
            ins.segment_prefix == Register.DS, ins.op_mask, ins.zeroing_masking,
            ins.rounding_control, ins.suppress_all_exceptions, ins.is_broadcast,
            ins.stack_pointer_increment)


def value(image, expr):
    if expr["attributes"]:
        raise RewriteError(f"{image.path}: unsupported data expression attributes {expr['attributes']}")
    result = image.symbol(expr.get("value_symbol", expr["symbol"]))
    if expr["kind"] == "difference":
        delta = result - image.symbol(expr.get("value_symbol2", expr["symbol2"]))
        if not expr["scale"] or delta % expr["scale"]:
            raise RewriteError("invalid symbolic difference scale")
        result = delta // expr["scale"]
    return result + expr["offset"]


def check_reference(image, ins, expr, plt_entries):
    if expr is None:
        return
    attributes = expr["attributes"]
    if expr["field"] == "displacement":
        target = ins.ip_rel_memory_address if ins.is_ip_rel_memory_operand else ins.memory_displacement
    elif ins.is_ip_rel_memory_operand:
        raise RewriteError("RIP-relative displacement has no symbolic expression")
    elif any(ins.op_kind(n) in BRANCH_KINDS for n in range(ins.op_count)):
        target = ins.near_branch_target
    else:
        immediate = [n for n in range(ins.op_count)
                     if OpKind.IMMEDIATE8 <= ins.op_kind(n) <= OpKind.IMMEDIATE32TO64]
        if len(immediate) == 1:
            target = ins.immediate(immediate[0])
        elif any(ins.op_kind(n) == OpKind.MEMORY for n in range(ins.op_count)):
            target = ins.memory_displacement
        else:
            raise RewriteError(f"unhandled symbolic instruction form: {ins}")
    if attributes == ["PLT"]:
        expected = plt_entries.get(target)
        resolver_match = (expr.get("ifunc_resolver") is not None
                          and expected == image.symbol(expr["ifunc_resolver"]))
        if (expected != expr["symbol"] and not resolver_match) or expr["offset"]:
            raise RewriteError(f"PLT reference does not resolve to {expr['symbol']}")
        if not resolver_match and "version" in expr:
            section = image.section_at(target)
            slot = decode(image.read(target, min(16, section["sh_addr"] + section["sh_size"] - target)), target)
            jump = next(i for i in slot if i.mnemonic == Mnemonic.JMP and i.is_ip_rel_memory_operand)
            if image.relocations[jump.ip_rel_memory_address]["version"] != expr["version"]:
                raise RewriteError(f"PLT symbol version changed for {expr['symbol']}")
    elif attributes == ["GOT", "PCREL"]:
        reloc = image.relocations.get(target)
        resolver_match = (reloc and reloc["type"] == 37 and expr.get("ifunc_resolver") is not None
                          and reloc["addend"] == image.symbol(expr["ifunc_resolver"]))
        if not reloc or (reloc["symbol"] != expr["symbol"] and not resolver_match) or expr["offset"]:
            raise RewriteError(f"GOT reference does not resolve to {expr['symbol']}")
        if not resolver_match and "version" in expr and reloc["version"] != expr["version"]:
            raise RewriteError(f"GOT symbol version changed for {expr['symbol']}")
    elif attributes == ["GOT", "TPOFF"]:
        relocation = image.relocations.get(target)
        if not relocation or relocation["type"] != 18:
            raise RewriteError(f"TLS GOT reference has no TPOFF64 relocation for {expr['symbol']}")
        if relocation["symbol"]:
            if relocation["symbol"] != expr["symbol"] or relocation["addend"] != expr["offset"]:
                raise RewriteError("named TLS GOT reference changed")
            if "version" in expr and relocation["version"] != expr["version"]:
                raise RewriteError("TLS GOT symbol version changed")
        elif relocation["addend"] != image.symbol(expr.get("value_symbol", expr["symbol"])) + expr["offset"]:
            raise RewriteError("local TLS GOT reference changed")
    elif (target - value(image, expr)) & ((1 << 64) - 1):
        raise RewriteError(f"stale symbolic reference to {expr['symbol']}: got 0x{target:x}")
    if ins.is_ip_rel_memory_operand and ins.mnemonic != Mnemonic.LEA and image.section_at(target) is None:
        if (expr["symbol"] != "__ehdr_start" or image.symbol("__ehdr_start") != 0
                or not 0 <= target < image.elf["e_ehsize"]):
            raise RewriteError(f"RIP-relative reference leaves allocated image: 0x{target:x}")


def check_wrapper(instructions, runtime, original):
    family, _ = string_form(original)
    stos = family == "stos"
    if len(instructions) != (13 if stos else 11):
        raise RewriteError("incorrect dedicated string wrapper length")
    mnemonics = ([Mnemonic.MOV, Mnemonic.MOV, Mnemonic.LAHF, Mnemonic.SETO, Mnemonic.XCHG,
                  Mnemonic.ADD, original.mnemonic, Mnemonic.SUB, Mnemonic.XCHG, Mnemonic.ADD,
                  Mnemonic.SAHF, Mnemonic.MOV, Mnemonic.MOV] if stos else
                 [Mnemonic.MOV, Mnemonic.LAHF, Mnemonic.SETO, Mnemonic.ADD, Mnemonic.ADD,
                  original.mnemonic, Mnemonic.SUB, Mnemonic.SUB, Mnemonic.ADD, Mnemonic.SAHF, Mnemonic.MOV])
    if [i.mnemonic for i in instructions] != mnemonics:
        raise RewriteError("REP wrapper instruction sequence changed")
    scratch, offset = runtime.scratch_rax, runtime.sandbox_offset
    if scratch is None or offset is None:
        raise RewriteError("REP wrapper runtime slots missing")
    slots = ((0, 0, Register.RDX, scratch), (5, 1, Register.RDI, offset),
             (7, 1, Register.RDI, offset), (12, 1, Register.RDX, scratch)) if stos else (
        (0, 0, Register.RAX, scratch), (3, 1, Register.RDI, offset),
        (4, 1, Register.RSI, offset), (6, 1, Register.RDI, offset),
        (7, 1, Register.RSI, offset), (10, 1, Register.RAX, scratch),
    )
    for index, mem_index, reg, address in slots:
        ins = instructions[index]
        if (ins.segment_prefix != Register.FS or ins.op_kind(mem_index) != OpKind.MEMORY
                or ins.op_register(1 - mem_index) != reg
                or ins.memory_base != Register.NONE or ins.memory_index != Register.NONE
                or ins.memory_displacement != address & ((1 << 64) - 1)):
            raise RewriteError("REP wrapper FS slot or pointer register changed")
    if instructions[3 if stos else 2].op0_register != Register.AL:
        raise RewriteError("REP wrapper must save OF in AL")
    add = instructions[9 if stos else 8]
    if add.op0_register != Register.AL or add.immediate(1) != 0x7F:
        raise RewriteError("REP wrapper must restore OF with addb $0x7f,%al")
    string_index = 6 if stos else 5
    if shape(instructions[string_index], None) != shape(original, None):
        raise RewriteError("string wrapper changed the native string form")
    if stos:
        for index in (4, 8):
            ins = instructions[index]
            if {ins.op0_register, ins.op1_register} != {Register.RAX, Register.RDX}:
                raise RewriteError("STOS wrapper changed its flag/data register exchange")
        for index, dest, source in ((1, Register.RDX, Register.RAX), (11, Register.RAX, Register.RDX)):
            if instructions[index].op0_register != dest or instructions[index].op1_register != source:
                raise RewriteError("STOS wrapper changed its accumulator save/restore")
    for index, ins in enumerate(instructions):
        if ins.has_lock_prefix or (index != string_index and (ins.has_rep_prefix or ins.has_repne_prefix)):
            raise RewriteError("unexpected prefix in REP wrapper")


def validate_artifact(path, report):
    image = Image(path)
    if report["schema"] != 1 or report["mode"] not in ("baseline", "gs"):
        raise RewriteError("unsupported provenance report schema/mode")
    baseline = report["mode"] == "baseline"
    original_tls = report.get("input_tls")
    if bool(original_tls) != bool(image.tls):
        raise RewriteError(f"{path}: PT_TLS was introduced or lost")
    if original_tls and any(original_tls[k] != image.tls[k]
                            for k in ("memory_size", "file_size", "alignment")):
        raise RewriteError(f"{path}: TLS layout changed, invalidating resolved thread-pointer offsets")
    runtime = Runtime(**report["runtime"])
    runtime.check()
    if any(s.name.startswith((".debug", ".zdebug", ".gnu_debug")) for s in image.sections):
        raise RewriteError(f"{path}: stale debug information was not removed")
    if image.libraries != report["libraries"]:
        raise RewriteError(f"{path}: relinking changed DT_NEEDED dependencies/order")
    if not baseline and set(image.libraries) - set(report["trusted_libraries"]):
        raise RewriteError(f"{path}: undeclared dynamic-library trust boundary")
    if not set(map(tuple, report["input_dynamic_symbols"])) <= set(image.dynamic_symbols):
        raise RewriteError(f"{path}: relinking lost a dynamic symbol/type")
    if not set(map(tuple, report["input_symbol_versions"])) <= set(image.symbol_versions):
        raise RewriteError(f"{path}: relinking changed symbol binding, visibility, or version")
    if sorted(report["input_version_definitions"]) != sorted(image.version_definitions):
        raise RewriteError(f"{path}: relinking changed version definitions")
    if report["input_dynamic_paths"] != image.dynamic_paths:
        raise RewriteError(f"{path}: relinking changed SONAME/RPATH/RUNPATH")
    if baseline:
        _, generated = patch_plt(image)
        plt_entries = {r["address"]: pointer_identity(image, r["target"])
                       for r in generated if r["target"] is not None}
        covered = {a for r in generated for a in range(r["address"], r["address"] + r["size"])}
    else:
        plt_entries, covered = validate_plt(image, report["generated"])
    boundaries, starts, allowed_targets = set(), set(), set(plt_entries)
    for section in image.executable:
        if section.name.startswith((".plt", ".iplt")):
            for ins in decode(section.data(), section["sh_addr"]):
                boundaries.update((ins.ip, ins.next_ip))
                starts.add(ins.ip)
    final_metadata = Metadata(image)
    old_starts, old_ends = {}, {}
    final_records, wrappers, direct = [], [], []
    instruction_count = 0
    for block in report["blocks"]:
        begin, end = image.symbol(block["begin"]), image.symbol(block["end"])
        section = image.section_at(begin, max(end - begin, 1))
        if section is None or section.name != block["section"] or end <= begin:
            fail(path, block["section"], begin, "invalid relocated block range")
        byte_range = set(range(begin, end))
        if byte_range & covered:
            fail(path, block["section"], begin, "overlapping provenance ranges")
        covered.update(byte_range)
        instructions = decode(image.read(begin, end - begin), begin)
        cursor = 0
        for item_index, item in enumerate(block["instructions"]):
            is_wrapper = item["rule"] in ("rep-movsb", "movs", "stos") and not baseline
            count = (13 if item["rule"] == "stos" else 11) if is_wrapper else 1
            if item["rule"] == "padding":
                available = 0
                for candidate in instructions[cursor:]:
                    if candidate.mnemonic != Mnemonic.NOP:
                        break
                    available += 1
                remaining = 0
                for following in block["instructions"][item_index + 1:]:
                    if following["rule"] != "padding":
                        break
                    remaining += 1
                count = max(1, available - remaining)
            sequence = instructions[cursor:cursor + count]
            if len(sequence) != count:
                fail(path, block["section"], begin, "missing recovered instruction")
            ins, last = sequence[0], sequence[-1]
            original = decode(bytes.fromhex(item["bytes"]), item["original"])[0]
            try:
                if is_wrapper:
                    check_wrapper(sequence, runtime, original)
                    stos = item["rule"] == "stos"
                    wrappers.append({"original": item["original"], "begin": ins.ip,
                                     "end": last.next_ip, "family": "stos" if stos else "movs",
                                     "phases": [{"address": i.ip, "instruction_index": n,
                                                 "rdi_translated": 6 <= n <= 7 if stos else 4 <= n <= 6,
                                                 "rsi_translated": not stos and 5 <= n <= 7,
                                                 "rax_in_scratch": not stos and 1 <= n <= 10,
                                                 "rdx_in_scratch": stos and 1 <= n <= 12}
                                                for n, i in enumerate(sequence)]})
                else:
                    if not block["trusted"] and not baseline:
                        rule = classify(ins, runtime, output=True)
                        expected = item["rule"]
                        if rule != expected:
                            raise RewriteError(f"instruction rule changed from {expected} to {rule}")
                    elif block["trusted"] and block["section"] not in report["trusted_sections"]:
                        raise RewriteError("instruction marked trusted outside declared boundary")
                    if shape(original, item["expression"]) != shape(ins, item["expression"]):
                        raise RewriteError(f"instruction semantics changed: {original} -> {ins}")
                    if (baseline and original.mnemonic != Mnemonic.NOP
                            and original.segment_prefix != ins.segment_prefix):
                        raise RewriteError("native baseline changed a segment override")
                    check_reference(image, ins, item["expression"], plt_entries)
                for instruction in sequence:
                    boundaries.update((instruction.ip, instruction.next_ip))
                    starts.add(instruction.ip)
                    if item["rule"] == "padding":
                        allowed_targets.add(instruction.ip)
                    if item["unwind"] is not None and final_metadata.state(instruction.ip) != item["unwind"]:
                        raise RewriteError("original unwind state was lost or changed")
                    if any(instruction.op_kind(n) in BRANCH_KINDS for n in range(instruction.op_count)):
                        direct.append((instruction.ip, instruction.near_branch_target, block["section"]))
            except RewriteError as error:
                fail(path, block["section"], ins.ip, f"original=0x{item['original']:x}: {error}")
            old_starts[item["original"]] = ins.ip
            old_ends[original.next_ip] = last.next_ip
            allowed_targets.add(ins.ip)
            if item.get("lock_suffix_entry"):
                raw = image.read(ins.ip, ins.len)
                if raw[0] != 0xF0:
                    raise RewriteError(f"{path}: original LOCK-skipping entry no longer skips only LOCK")
                suffix = decode(raw[1:], ins.ip + 1)
                if len(suffix) != 1 or suffix[0].has_lock_prefix:
                    raise RewriteError(f"{path}: invalid LOCK-skipping instruction suffix")
                if not baseline and suffix[0].segment_prefix != Register.GS:
                    raise RewriteError(f"{path}: LOCK-skipping entry bypasses GS instrumentation")
                allowed_targets.add(ins.ip + 1)
            final_records.append({"original": item["original"], "address": ins.ip,
                                  "end": last.next_ip, "section": block["section"], "rule": item["rule"]})
            instruction_count += 1
            cursor += count
        if cursor != len(instructions):
            fail(path, block["section"], instructions[cursor].ip, "unaccounted instructions in recovered block")
    for record in report["data"]:
        begin, end = image.symbol(record["begin"]), image.symbol(record["end"])
        if "tls_offset" in record:
            if begin != record["tls_offset"] or end != begin + record["size"]:
                fail(path, record["section"], begin, "TLS block changed its module-relative offset")
            begin += image.tls["address"]
            end += image.tls["address"]
        section = (image.elf.get_section_by_name(record["section"]) if "tls_offset" in record
                   else image.section_at(begin, max(end - begin, 1)))
        if (section is None or section.name != record["section"] or end - begin != record["size"]
                or begin < section["sh_addr"] or end > section["sh_addr"] + section["sh_size"]):
            fail(path, record["section"], begin, "relocated data block has wrong location/size")
        if section["sh_type"] == "SHT_NOBITS":
            continue
        actual = bytearray(image.read(begin, end - begin))
        expected = bytearray.fromhex(record["bytes"])
        if record["executable"]:
            if not padding(actual, begin):
                fail(path, record["section"], begin, "uncovered code in recovered executable padding")
            for ins in decode(actual, begin):
                boundaries.update((ins.ip, ins.next_ip))
                starts.add(ins.ip)
                allowed_targets.add(ins.ip)
            covered.update(range(begin, end))
            continue
        for entry in record["expressions"]:
            offset, size, expr = entry["offset"], entry["size"], entry["expression"]
            reloc = image.relocations.get(begin + offset)
            if reloc and reloc["symbol"] == expr["symbol"] and expr["kind"] == "constant":
                if reloc["addend"] != expr["offset"]:
                    fail(path, record["section"], begin + offset, "dynamic data relocation addend changed")
                if "version" in expr and reloc["version"] != expr["version"]:
                    fail(path, record["section"], begin + offset, "dynamic data relocation version changed")
            elif reloc and reloc["type"] == 37:
                if (size != 8 or not expr.get("ifunc_resolver") or expr["offset"]
                        or reloc["addend"] != image.symbol(expr["ifunc_resolver"])):
                    fail(path, record["section"], begin + offset, "stale IRELATIVE data-pointer resolver")
            else:
                expected_value = value(image, expr) & ((1 << (size * 8)) - 1)
                actual_value = (reloc["addend"] if reloc and reloc["type"] == 8
                                else int.from_bytes(actual[offset:offset + size], "little"))
                if actual_value != expected_value:
                    fail(path, record["section"], begin + offset, "stale symbolic data/code pointer")
            expected[offset:offset + size] = actual[offset:offset + size]
        if actual != expected:
            fail(path, record["section"], begin, "non-symbolic data bytes changed during relinking")
    for section in image.executable:
        base, end = section["sh_addr"], section["sh_addr"] + section["sh_size"]
        cursor = base
        while cursor < end:
            if cursor in covered:
                cursor += 1
                continue
            low = cursor
            while cursor < end and cursor not in covered:
                cursor += 1
            data = image.read(low, cursor - low)
            if not padding(data, low):
                fail(path, section.name, low,
                     f"unaccounted generated code or uncovered memory access: {data[:32].hex()}")
            for ins in decode(data, low):
                boundaries.update((ins.ip, ins.next_ip))
                starts.add(ins.ip)
                allowed_targets.add(ins.ip)
            covered.update(range(low, cursor))
    for address, target, section in direct:
        if target not in allowed_targets:
            fail(path, section, address, f"direct target 0x{target:x} is not a covered instruction/PLT entry")
    if image.elf["e_entry"] and image.elf["e_entry"] not in allowed_targets:
        raise RewriteError(f"{path}: entry point is not a covered instruction")
    if image.elf["e_entry"] != old_starts.get(report["input_entry"], 0):
        raise RewriteError(f"{path}: original entry-point reference was not preserved")
    for tag, original in report["input_init_fini"].items():
        if image.init_fini.get(tag) != old_starts.get(original):
            raise RewriteError(f"{path}: {tag} no longer points to the original covered routine")
    if set(image.init_fini) != set(report["input_init_fini"]):
        raise RewriteError(f"{path}: linker introduced or removed initialization/finalization code")
    resolver_entries = set()
    for resolver in report.get("input_resolvers", ()):
        address = image.symbol(resolver["symbol"])
        if old_starts.get(resolver["original"]) != address:
            raise RewriteError(f"{path}: IFUNC resolver does not point to its covered original code")
        resolver_entries.add(address)
    for reloc in image.relocations.values():
        if reloc["type"] == 37 and reloc["addend"] not in resolver_entries:
            raise RewriteError(f"{path}: IRELATIVE relocation points to an unaccounted resolver")
    for name, address, _ in image.ifuncs:
        if address not in resolver_entries:
            raise RewriteError(f"{path}: IFUNC symbol {name} points to an unaccounted resolver")
    for name, start, size in image.function_ranges:
        if start not in allowed_targets or start + size not in boundaries:
            raise RewriteError(f"{path}: function symbol {name} has stale code boundaries")
    mapped_sites = []
    def map_action(action):
        if not isinstance(action, int) or action == 0:
            return action
        for record in report["data"]:
            original = record["original"]
            if original is not None and original <= action < original + record["size"]:
                return image.symbol(record["begin"]) + action - original
        raise RewriteError(f"{path}: LSDA type pointer 0x{action:x} has no data provenance")

    for site in report["exception_sites"]:
        try:
            mapped_sites.append({"start": old_starts[site["start"]],
                                 "end": old_ends.get(site["end"], old_starts.get(site["end"])),
                                 "landing": old_starts[site["landing"]] if site["landing"] else 0,
                                 "actions": [map_action(a) for a in site["actions"]]})
        except KeyError as error:
            raise RewriteError(f"{path}: exception reference lacks input provenance: {error}") from error
    if mapped_sites != final_metadata.sites:
        difference = next(((a, b) for a, b in zip(mapped_sites, final_metadata.sites) if a != b),
                          (len(mapped_sites), len(final_metadata.sites)))
        raise RewriteError(f"{path}: exception call sites, landing pads, or action/type references changed: {difference}")
    metadata_summary = final_metadata.validate(boundaries, starts)
    if hashlib.sha256(image.data).hexdigest() != report["output_sha256"]:
        raise RewriteError(f"{path}: artifact hash does not match provenance report")
    report["locations"] = final_records
    report["wrappers"] = wrappers
    report["retired_plt_locations"] = [
        {"original": item["original"], "symbol": item["symbol"],
         "final_entries": [address for address, name in plt_entries.items()
                           if name == (old_starts.get(item["symbol"])
                                       if isinstance(item["symbol"], int) else item["symbol"])],
         "disposition": "retired-lazy-resolver" if item["symbol"] is None else "replaced-by-eager-entry"}
        for item in report["retired_plt"]
    ]
    no_unwind = sum(item["unwind"] is None for block in report["blocks"] for item in block["instructions"])
    return {"recovered_instructions": instruction_count, "retired_plt_instructions": len(report["retired_plt"]),
            "generated_plt_slots": len(report["generated"]), "covered_executable_bytes": len(covered),
            "rep_wrappers": len(wrappers), "instructions_without_input_unwind": no_unwind,
            **metadata_summary}
