"""Length-changing rewrite for compiler-generated x86-64 ELF64 RELA objects."""
import io
import struct
import subprocess
import tempfile
from functools import lru_cache
from pathlib import Path

from elftools.elf.elffile import ELFFile
from elftools.dwarf.callframe import FDE
from iced_x86 import Decoder, Mnemonic, OpKind, Register

from .errors import RewriteError
from .policy import classify
from .metadata import Reader


def require(condition, message):
    if not condition:
        raise RewriteError(message)


# Only data whose internal layout is independent of code growth is copied.
DATA = (".data", ".rodata", ".bss", ".tdata", ".tbss", ".init_array", ".fini_array")
TABLES = {"SHT_NULL", "SHT_SYMTAB", "SHT_STRTAB", "SHT_RELA", "SHT_GROUP"}
SPECIAL = {".comment", ".note.GNU-stack", ".note.gnu.property", ".eh_frame",
           ".note.ABI-tag", ".note.stapsdt", ".stapsdt.base"}


@lru_cache(maxsize=32)
def assemble_string_wrapper(assembly):
    with tempfile.TemporaryDirectory(prefix="gsfork-object-string-") as directory:
        obj = Path(directory) / "wrapper.o"
        subprocess.run(["as", "--64", "-o", str(obj), "-"], input=assembly,
                       text=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        elf = ELFFile(io.BytesIO(obj.read_bytes()))
        require(not any(sec['sh_type'] in ('SHT_RELA', 'SHT_REL')
                        for sec in elf.iter_sections()), "string wrapper contains relocations")
        return elf.get_section_by_name(".text").data()


def code_section(sec, relocs, functions, runtime, trusted, baseline):
    widened = set()
    while True:
        output, positions, ends, fields, count, overflows = layout_code_section(
            sec, relocs, functions, runtime, trusted, baseline, widened)
        if not overflows:
            return output, positions, ends, fields, count
        widened.update(overflows)


def widen_branch(raw):
    opcode = raw[-2]
    prefixes = raw[:-2]
    if opcode == 0xeb:
        require(len(prefixes) + 5 <= 15, "widened branch exceeds instruction length limit")
        return prefixes + b'\xe9' + bytes(4)
    if 0x70 <= opcode <= 0x7f:
        require(len(prefixes) + 6 <= 15, "widened branch exceeds instruction length limit")
        return prefixes + bytes((0x0f, opcode + 0x10)) + bytes(4)
    if 0xe0 <= opcode <= 0xe3:
        # LOOP/JCXZ have no near form. Preserve their flags/count behavior and
        # branch over a fall-through skip to a rel32 jump.
        return prefixes + bytes((opcode, 2, 0xeb, 5, 0xe9)) + bytes(4)
    raise RewriteError("unsupported short branch widening")


def layout_code_section(sec, relocs, functions, runtime, trusted, baseline, widened):
    original = sec.data()
    output = bytearray()
    positions = {}
    fields = {}
    fixups = []
    count = 0
    boundaries = sorted({sym['st_value'] for sym in functions} | {len(original)})
    ranges = sorted({(sym['st_value'], sym['st_value'] + sym['st_size']
                      if sym['st_size'] else next(
                          (boundary for boundary in boundaries if boundary > sym['st_value']),
                          len(original))) for sym in functions})
    if not ranges and sec.name in (".init", ".fini"):
        ranges = [(0, len(original))]
    require(ranges and all(0 <= start < end <= len(original) for start, end in ranges)
            and all(a[1] <= b[0] for a, b in zip(ranges, ranges[1:])),
            f"{sec.name}: expected nonoverlapping function boundaries")
    starts = {start for start, _ in ranges}
    ends = {}
    range_idx = 0
    decoder = Decoder(64, original)
    for ins in decoder:
        start, end = ins.ip, ins.next_ip
        require(not ins.is_invalid, f"{sec.name}+{start:#x}: invalid instruction")
        if start in starts:
            # Retain the original function alignment after earlier code grows.
            output.extend(b'\x90' * ((start - len(output)) % max(1, sec['sh_addralign'])))
        positions[start] = len(output)
        while range_idx < len(ranges) and start >= ranges[range_idx][1]:
            range_idx += 1
        if range_idx == len(ranges) or start < ranges[range_idx][0]:
            require(ins.mnemonic == Mnemonic.NOP or original[start:end] == b'\x66\x90',
                    f"{sec.name}+{start:#x}: bytes outside sized functions are not NOPs")
        rule = 'trusted' if trusted else classify(ins, runtime)
        raw = original[start:end]
        constants = decoder.get_constant_offsets(ins)
        branch = ins.op0_kind in (OpKind.NEAR_BRANCH64, OpKind.NEAR_BRANCH32, OpKind.NEAR_BRANCH16)
        if start in widened:
            require(branch and constants.immediate_size == 1,
                    f"{sec.name}+{start:#x}: unsupported branch widening")
            raw = widen_branch(raw)
        if rule == 'gs' and not baseline:
            require(ins.segment_prefix == Register.NONE, "unsupported object segment substitution")
            raw = b'\x65' + raw
            require(classify(Decoder(64, raw).decode(), runtime, output=True) == 'gs',
                    "could not encode GS memory operand")
            count += 1
        elif rule in ('rep-movsb', 'movs', 'stos') and not baseline:
            from .validator import check_wrapper
            raw = assemble_string_wrapper(runtime.string(ins))
            check_wrapper(list(Decoder(64, raw)), runtime, ins)
        elif rule == 'leave' and not baseline:
            raise RewriteError(f"{sec.name}+{start:#x}: object leave expansion unsupported")
        output.extend(raw)
        ends[end] = len(output)
        shift = len(output) - end
        for offset, size, relative, target in (
                (constants.displacement_offset, constants.displacement_size,
                 ins.is_ip_rel_memory_operand, ins.ip_rel_memory_address),
                (constants.immediate_offset, constants.immediate_size, branch, ins.near_branch_target)):
            if not size:
                continue
            field = start + offset
            if field in relocs:
                kind = relocs[field]
                supported = relative and kind in (2, 4, 9, 19, 20, 22, 41, 42)
                supported |= not relative and kind in (21, 23) and ins.op_kind(0) != OpKind.NEAR_BRANCH64
                require(size == 4 and supported,
                        f"{sec.name}+{field:#x}: unsupported instruction relocation {kind}")
                fields[field] = (field + shift, end - field if relative else 0)
            elif relative:
                if start in widened:
                    fixups.append((len(output) - 4, 4, target, len(output), start))
                else:
                    fixups.append((field + shift, size, target, len(output), start))
    positions[len(original)] = len(output)
    require(all(start in positions and end in ends for start, end in ranges),
            f"{sec.name}: function boundary inside instruction")
    require(fields.keys() == relocs.keys(), f"{sec.name}: relocation outside operand")
    overflows = set()
    for offset, width, target, end, start in fixups:
        require(target in positions, f"{sec.name}: unresolved internal reference {target:#x}")
        delta = positions[target] - end
        if not -(1 << (8*width-1)) <= delta < 1 << (8*width-1):
            require(width == 1 and start not in widened,
                    f"{sec.name}: internal displacement overflow")
            overflows.add(start)
            continue
        output[offset:offset+width] = delta.to_bytes(width, 'little', signed=True)
    return output, positions, ends, fields, count, overflows


def update_frames(data, references):
    """Rebuild GNU as zR FDEs, widening advances and relocating record offsets."""
    cursor = 0
    cies = {}
    used = set()
    output = bytearray()
    locations = {}
    while cursor < len(data):
        require(cursor + 4 <= len(data), "truncated .eh_frame entry")
        if data[cursor:cursor+4] == bytes(4):
            require(not any(data[cursor:]), "data after .eh_frame terminator")
            locations[cursor] = len(output)
            output.extend(data[cursor:])
            break
        require(cursor + 8 <= len(data), "truncated .eh_frame entry")
        size, cie = struct.unpack_from('<II', data, cursor)
        end = cursor + 4 + size
        require(size >= 4 and end <= len(data), "invalid .eh_frame entry")
        locations[cursor] = len(output)
        if not cie:
            # v1, zR, code alignment 1, data alignment -8, RIP, pcrel sdata4.
            personality = data[cursor+8:cursor+19] == b'\x01zPLR\0\x01\x78\x10\x07\x9b'
            if personality:
                require(data[cursor+23:cursor+25] == b'\x1b\x1b',
                        "unsupported .eh_frame personality encodings")
                initial = cursor + 25
                locations[cursor+19] = len(output) + 19
            else:
                require(data[cursor+8:cursor+17] == b'\x01zR\0\x01\x78\x10\x01\x1b',
                        "unsupported .eh_frame CIE")
                initial = cursor + 17
            # Accept the standard x86-64 initial state and trailing DW_CFA_nop.
            require(data[initial:end].rstrip(b'\0') == bytes.fromhex('0c07089001'),
                    "unsupported CIE initial instructions")
            cies[cursor] = len(output), personality
            output.extend(data[cursor:end])
        else:
            loc = cursor + 8
            require(cursor + 4 - cie in cies and loc in references and loc+9 <= end,
                    "unsupported .eh_frame FDE")
            cie_offset, personality = cies[cursor + 4 - cie]
            augmentation = 4 if personality else 0
            require(data[loc+8] == augmentation and loc+9+augmentation <= end,
                    "unsupported .eh_frame FDE augmentation")
            used.add(loc)
            positions, ends, start = references[loc]
            finish = start + struct.unpack_from('<I', data, loc+4)[0]
            require(start in positions and finish in ends, "invalid FDE range")
            record = bytearray(data[cursor:loc+9+augmentation])
            struct.pack_into('<I', record, 4, len(output) + 4 - cie_offset)
            struct.pack_into('<I', record, 12, ends[finish] - positions[start])
            locations[loc] = len(output) + 8
            if personality:
                locations[loc+9] = len(output) + 17
            pc = start
            i = loc + 9 + augmentation
            while i < end:
                instruction_start = i
                op = data[i]
                i += 1
                if op >> 6 == 1 or op in (2, 3, 4):
                    width = 0 if op >> 6 else 1 << (op-2)
                    require(i+width <= end, "truncated CFI advance")
                    advance = int.from_bytes(data[i:i+width], 'little') if width else op & 63
                    new = pc + advance
                    require(new in positions and new <= finish, "invalid CFI PC")
                    delta = (ends[new] if new == finish else positions[new]) - (
                        ends[pc] if pc == finish else positions[pc])
                    require(0 <= delta < 1 << 32, "CFI advance overflow")
                    if delta < 64 and not width:
                        record.append(0x40 + delta)
                    else:
                        new_width = max(width, 1 if delta < 256 else 2 if delta < 65536 else 4)
                        record.append({1: 2, 2: 3, 4: 4}[new_width])
                        record.extend(delta.to_bytes(new_width, 'little'))
                    i += width
                    pc = new
                    continue
                if op >> 6 == 2 or op in (6, 7, 8, 13, 14, 0x2e):
                    operands = 1
                elif op in (5, 9, 12, 17, 18, 20, 21):
                    operands = 2
                elif op >> 6 == 3 or op in (0, 10, 11):
                    operands = 0
                else:
                    raise RewriteError(f"unsupported CFI opcode {op:#x}")
                for _ in range(operands):
                    while i < end and data[i] & 128:
                        i += 1
                    require(i < end, "truncated CFI operand")
                    i += 1
                record.extend(data[instruction_start:i])
            record.extend(bytes(-len(record) % 8))
            struct.pack_into('<I', record, 0, len(record) - 4)
            output.extend(record)
        cursor = end
    require(used == references.keys(), "unexpected relocation in .eh_frame")
    locations[len(data)] = len(output)
    return output, locations


class ObjectMetadataBytes:
    def __init__(self, data):
        self.data = data

    def read(self, address, size):
        require(0 <= address <= address + size <= len(self.data), "truncated object exception metadata")
        return self.data[address:address+size]


def update_exception_tables(elf, sections, rela, symbols, maps, ends):
    contexts = {}
    frame_idx = next(idx for idx, sec in enumerate(sections) if sec.name == ".eh_frame")
    entries = {r['r_offset']: r for r in rela.get(frame_idx, (None, []))[1]}
    for fde in elf.get_dwarf_info().EH_CFI_entries():
        if not isinstance(fde, FDE):
            continue
        lsda = entries.get(fde.offset + 17)
        if lsda is None:
            continue
        code = entries.get(fde.offset + 8)
        require(code is not None and lsda['r_info_type'] == 2, "unsupported object LSDA reference")
        symbol = symbols[lsda['r_info_sym']]
        section = symbol['st_shndx']
        require(isinstance(section, int) and sections[section].name.startswith(".gcc_except_table"),
                "LSDA reference outside exception table")
        symbol_code = symbols[code['r_info_sym']]
        start = symbol_code['st_value'] + code['r_addend']
        key = section, symbol['st_value'] + lsda['r_addend']
        require(key not in contexts, "shared object LSDA needs distinct code mappings")
        contexts[key] = symbol_code['st_shndx'], start
    changed = {}
    for (idx, offset), (code, start) in contexts.items():
        data = changed.setdefault(idx, bytearray(sections[idx].data()))
        reader = Reader(ObjectMetadataBytes(data), offset)
        require(reader.byte() == 0xff, "unsupported object LSDA LPStart")
        encoding = reader.byte()
        if encoding != 0xff:
            require(encoding == 0x9b, "unsupported object LSDA type encoding")
            type_base = reader.leb() + reader.address
            require(type_base <= len(data), "object LSDA type table outside section")
        require(reader.byte() == 1, "unsupported object LSDA call-site encoding")
        length = reader.leb()
        finish = reader.address + length
        require(finish <= len(data) and code in maps, "invalid object LSDA call-site table")
        while reader.address < finish:
            fields = []
            values = []
            for _ in range(4):
                position = reader.address
                values.append(reader.leb())
                fields.append((position, reader.address - position))
            low, size, landing, action = values
            require(start + low in maps[code] and start + low + size in maps[code]
                    and (not landing or start + landing in maps[code]),
                    "object LSDA code reference outside instruction boundary")
            new_low = maps[code][start+low] - maps[code][start]
            boundary = start + low + size
            new_end = ends[code].get(boundary, maps[code][boundary])
            new_size = new_end - maps[code][start+low]
            new_landing = maps[code][start+landing] - maps[code][start] if landing else 0
            for (position, width), value in zip(fields, (new_low, new_size, new_landing, action)):
                require(0 <= value < 1 << (width*7), "object LSDA advance overflow")
                for i in range(width):
                    data[position+i] = (value >> (7*i) & 127) | (128 if i+1 < width else 0)
        require(reader.address == finish, "partial object LSDA call-site record")
    for idx, sec in enumerate(sections):
        if sec.name.startswith(".gcc_except_table"):
            require(idx in changed or not sec['sh_size'], "unreferenced object exception table")
    return changed


def transform_object(source, runtime, trusted_sections=(), baseline=False):
    raw = source.read_bytes()
    elf = ELFFile(io.BytesIO(raw))
    require(elf.elfclass == 64 and elf.little_endian and elf['e_machine'] == 'EM_X86_64'
            and elf['e_type'] == 'ET_REL' and not elf.num_segments()
            and elf['e_shentsize'] == 64, "expected x86-64 ELF64 relocatable object")
    sections = list(elf.iter_sections())
    code = {}
    rela = {}
    symtabs = []
    frames = []
    for idx, sec in enumerate(sections):
        kind = sec['sh_type']
        if sec['sh_flags'] & 4 and sec['sh_size']:
            require(kind == 'SHT_PROGBITS' and sec['sh_flags'] & 3 == 2,
                    f"{sec.name}: unsupported executable section")
            code[idx] = sec
        elif kind == 'SHT_RELA':
            target = sec['sh_info']
            require(target not in rela and sec['sh_entsize'] == 24, "unsupported RELA layout")
            rela[target] = (idx, list(sec.iter_relocations()))
        elif kind == 'SHT_SYMTAB':
            symtabs.append(idx)
        elif sec.name == '.eh_frame':
            frames.append(idx)
        elif sec.name == '.note.GNU-stack':
            require(not sec['sh_flags'] & 4, "executable stack unsupported")
        elif sec['sh_size'] and kind not in TABLES:
            require(kind in ('SHT_PROGBITS', 'SHT_NOBITS', 'SHT_NOTE', 'SHT_INIT_ARRAY',
                             'SHT_FINI_ARRAY') and (sec.name in SPECIAL or any(
                sec.name == name or sec.name.startswith(name + '.') for name in (*DATA, ".gcc_except_table"))),
                f"{sec.name}: unsupported object metadata")
    require(len(symtabs) <= 1 and (symtabs or not rela and all(
        sec.name in (".init", ".fini") for sec in code.values())),
        "object requires one symbol table")
    require(set(trusted_sections) <= {sec.name for sec in code.values()}, "unknown trusted section")
    table = sections[symtabs[0]] if symtabs else None
    require(table is None or table['sh_entsize'] == 24, "invalid symbol entry size")
    symbols = list(table.iter_symbols()) if table is not None else []
    if not baseline:
        validate_string_unwind(elf, sections, code, rela, symbols, trusted_sections)
    changed = {}
    maps = {}
    ends = {}
    operands = {}
    counts = {}
    functions_by_section = {}
    for symbol in symbols:
        if symbol['st_info']['type'] == 'STT_FUNC':
            functions_by_section.setdefault(symbol['st_shndx'], []).append(symbol)
    table_bases = {}
    for idx, sec in code.items():
        entries = {r['r_offset']: r for r in rela.get(idx, (None, []))[1]}
        decoder = Decoder(64, sec.data())
        for ins in decoder:
            if ins.mnemonic != Mnemonic.LEA or not ins.is_ip_rel_memory_operand:
                continue
            field = ins.ip + decoder.get_constant_offsets(ins).displacement_offset
            r = entries.get(field)
            if r is not None and r['r_info_type'] == 2:
                sym = symbols[r['r_info_sym']]
                dest = sym['st_shndx']
                if isinstance(dest, int) and sections[dest].name.startswith(".rodata"):
                    base = sym['st_value'] + r['r_addend'] + ins.next_ip - field
                    table_bases.setdefault(dest, set()).add(base)
    for idx, sec in code.items():
        require(sec.name not in counts, f"{sec.name}: duplicate executable section name")
        functions = functions_by_section.get(idx, [])
        entries = rela.get(idx, (None, []))[1]
        types = {r['r_offset']: r['r_info_type'] for r in entries}
        require(len(types) == len(entries), "overlapping instruction relocations")
        changed[idx], maps[idx], ends[idx], operands[idx], counts[sec.name] = code_section(
            sec, types, functions, runtime, sec.name in trusted_sections, baseline)
    if any(sec.name.startswith(".gcc_except_table") and sec['sh_size'] for sec in sections):
        require(len(frames) == 1, "exception tables require one .eh_frame section")
        changed.update(update_exception_tables(elf, sections, rela, symbols, maps, ends))
    syms = bytearray(table.data()) if table is not None else bytearray()
    if symtabs:
        changed[symtabs[0]] = syms
    for i, sym in enumerate(symbols):
        idx, start, size = sym['st_shndx'], sym['st_value'], sym['st_size']
        if idx in maps:
            require(sym['st_info']['type'] in ('STT_FUNC', 'STT_SECTION', 'STT_NOTYPE')
                    and start in maps[idx] and (not size or start+size in ends[idx]), "unsupported code symbol")
            new_start = maps[idx][start]
            new_size = ends[idx][start + size] - new_start if size else 0
            struct.pack_into('<QQ', syms, 24 * i + 8, new_start, new_size)
    frame_refs = {idx: {} for idx in frames}
    for target, (idx, entries) in rela.items():
        sec = sections[idx]
        require(sec['sh_link'] == symtabs[0], "unexpected relocation symbol table")
        changed[idx] = out = bytearray(sec.data())
        table_start = None
        previous_table_offset = None
        for i, r in enumerate(entries):
            offset, addend, kind = r['r_offset'], r['r_addend'], r['r_info_type']
            require(r['r_info_sym'] < len(symbols), "invalid relocation symbol index")
            sym = symbols[r['r_info_sym']]
            dest = sym['st_shndx']
            bias = 0
            if target in maps:
                offset, bias = operands[target][offset]
                # GOTPCRELX relaxations may change the instruction at final link.
                if kind in (41, 42) and not baseline:
                    kind = 9
            if target in frames:
                require(kind == 2, "unsupported FDE relocation")
                if dest in maps:
                    frame_refs[target][offset] = maps[dest], ends[dest], sym['st_value'] + addend
                else:
                    require(isinstance(dest, int) and (sections[dest].name.startswith(".data")
                            or sections[dest].name.startswith(".gcc_except_table")),
                            "unsupported FDE augmentation relocation")
            if dest in maps:
                if kind in (9, 41, 42, 4):
                    require(addend == -bias, "unsupported indirect code-symbol addend")
                else:
                    table_bias = 0
                    if target not in maps and target not in frames and kind == 2:
                        if offset in table_bases.get(target, ()):
                            table_start = offset
                        else:
                            require(previous_table_offset is not None
                                    and offset == previous_table_offset + 4,
                                    "unsupported relative data-to-code relocation")
                        require(table_start is not None
                                and sections[target].data()[offset:offset+4] == bytes(4),
                                "unsupported relative data-to-code relocation")
                        table_bias = offset - table_start
                        previous_table_offset = offset
                    require((target in frames or target in maps and kind == 2 or kind == 1
                             or kind == 2 and table_bases.get(target)),
                            "unsupported data-to-code relocation")
                    start = sym['st_value']
                    logical = start + addend + bias - table_bias
                    require(logical in maps[dest], "code relocation target outside instruction boundary")
                    addend = maps[dest][logical] - maps[dest][start] - bias + table_bias
            struct.pack_into('<QQq', out, 24*i, offset, r['r_info_sym'] << 32 | kind, addend)
    for idx in frames:
        changed[idx], locations = update_frames(sections[idx].data(), frame_refs[idx])
        if idx in rela:
            reloc_idx, entries = rela[idx]
            for i, entry in enumerate(entries):
                require(entry['r_offset'] in locations, "unmapped .eh_frame relocation")
                struct.pack_into('<Q', changed[reloc_idx], 24*i, locations[entry['r_offset']])
        for i, sym in enumerate(symbols):
            if sym['st_shndx'] == idx:
                start, size = sym['st_value'], sym['st_size']
                require(start in locations and (not size or start + size in locations),
                        "unmapped .eh_frame symbol")
                struct.pack_into('<QQ', syms, 24*i + 8, locations[start],
                                 locations[start+size] - locations[start] if size else 0)
    # Retain all section indices, flags, links and group memberships. Move only
    # growing payloads, at their original alignment, and update their headers.
    result = bytearray(raw)
    for idx, payload in changed.items():
        sec = sections[idx]
        offset = sec['sh_offset']
        if len(payload) > sec['sh_size']:
            alignment = max(1, sec['sh_addralign'])
            result.extend(bytes(-len(result) % alignment))
            offset = len(result)
        struct.pack_into('<QQ', result, elf['e_shoff'] + 64*idx + 24, offset, len(payload))
        result[offset:offset+len(payload)] = payload
    return result, counts


def validate_string_unwind(elf, sections, code, rela, symbols, trusted_sections):
    wrappers = {}
    for idx, sec in code.items():
        if sec.name in trusted_sections:
            continue
        for ins in Decoder(64, sec.data()):
            if (ins.mnemonic in (Mnemonic.MOVSB, Mnemonic.MOVSW, Mnemonic.MOVSD,
                                 Mnemonic.MOVSQ, Mnemonic.STOSB, Mnemonic.STOSW,
                                 Mnemonic.STOSD, Mnemonic.STOSQ)
                    and ins.op0_kind == OpKind.MEMORY_ESRDI):
                temporary = {0, 1, 5} if ins.mnemonic in (
                    Mnemonic.STOSB, Mnemonic.STOSW, Mnemonic.STOSD, Mnemonic.STOSQ) else {0, 4, 5}
                wrappers.setdefault(idx, []).append((ins.ip, temporary))
    if not wrappers:
        return
    for frame_idx, sec in enumerate(sections):
        if sec.name != ".eh_frame":
            continue
        entries = {r['r_offset']: r for r in rela.get(frame_idx, (None, []))[1]}
        for fde in elf.get_dwarf_info().EH_CFI_entries():
            if not isinstance(fde, FDE):
                continue
            relocation = entries.get(fde.offset + 8)
            if relocation is None:
                continue
            symbol = symbols[relocation['r_info_sym']]
            dest = symbol['st_shndx']
            start = symbol['st_value'] + relocation['r_addend']
            finish = start + fde['address_range']
            rows = fde.get_decoded().table
            for address, temporary in wrappers.get(dest, ()):
                if not start <= address < finish:
                    continue
                row = next(row for row in reversed(rows)
                           if row['pc'] - fde['initial_location'] <= address - start)
                cfa = row['cfa']
                require(cfa.expr is None and cfa.reg not in temporary,
                        "string wrapper needs CFI rules for temporary register locations")
                for register, rule in row.items():
                    if not isinstance(register, int):
                        continue
                    require(rule.type not in ('EXPRESSION', 'VAL_EXPRESSION')
                            and not (rule.type == 'REGISTER' and rule.arg in temporary),
                            "string wrapper needs CFI rules for temporary register locations")
