"""Length-changing rewrite for compiler-generated x86-64 ELF64 RELA objects."""
import io
import struct

from elftools.elf.elffile import ELFFile
from iced_x86 import Decoder, Mnemonic, OpKind, Register

from .errors import RewriteError
from .policy import classify


def require(condition, message):
    if not condition:
        raise RewriteError(message)


# Only data whose internal layout is independent of code growth is copied.
DATA = (".data", ".rodata", ".bss", ".tdata", ".tbss", ".init_array", ".fini_array")
TABLES = {"SHT_NULL", "SHT_SYMTAB", "SHT_STRTAB", "SHT_RELA", "SHT_GROUP"}
SPECIAL = {".comment", ".note.GNU-stack", ".note.gnu.property", ".eh_frame"}


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
    ranges = sorted({(sym['st_value'], sym['st_value'] + sym['st_size']) for sym in functions})
    require(ranges and all(0 <= start < end <= len(original) for start, end in ranges)
            and all(a[1] <= b[0] for a, b in zip(ranges, ranges[1:])),
            f"{sec.name}: expected sized, nonoverlapping functions")
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
        elif rule in ('rep-movsb', 'movs', 'stos', 'leave') and not baseline:
            raise RewriteError(f"{sec.name}+{start:#x}: object wrapper expansion unsupported")
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
                require(size == 4 and relative and kind in (2, 4, 9, 41, 42),
                        f"{sec.name}+{field:#x}: unsupported instruction relocation {kind}")
                fields[field] = (field + shift, end - field)
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
    """GNU as zR/pcrel-sdata4 FDEs. Keep record sizes and reject CFI growth overflow."""
    cursor = 0
    cies = set()
    used = set()
    while cursor < len(data):
        require(cursor + 8 <= len(data), "truncated .eh_frame entry")
        size, cie = struct.unpack_from('<II', data, cursor)
        end = cursor + 4 + size
        require(size >= 4 and end <= len(data), "invalid .eh_frame entry")
        if not cie:
            # v1, zR, code alignment 1, data alignment -8, RIP, pcrel sdata4.
            require(data[cursor+8:cursor+17] == b'\x01zR\0\x01\x78\x10\x01\x1b',
                    "unsupported .eh_frame CIE")
            # Accept the standard x86-64 initial state and trailing DW_CFA_nop.
            require(data[cursor+17:end].rstrip(b'\0') == bytes.fromhex('0c07089001'),
                    "unsupported CIE initial instructions")
            cies.add(cursor)
        else:
            loc = cursor + 8
            require(cursor + 4 - cie in cies and loc in references and loc+9 <= end
                    and data[loc+8] == 0, "unsupported .eh_frame FDE")
            used.add(loc)
            positions, ends, start = references[loc]
            finish = start + struct.unpack_from('<I', data, loc+4)[0]
            require(start in positions and finish in ends, "invalid FDE range")
            struct.pack_into('<I', data, loc+4, ends[finish] - positions[start])
            pc = start
            i = loc + 9
            while i < end:
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
                    require(delta < (1 << (8*width) if width else 64), "CFI advance overflow")
                    if width:
                        data[i:i+width] = delta.to_bytes(width, 'little')
                    else:
                        data[i-1] = 0x40 + delta
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
        cursor = end
    require(used == references.keys(), "unexpected relocation in .eh_frame")


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
                sec.name == name or sec.name.startswith(name + '.') for name in DATA)),
                f"{sec.name}: unsupported object metadata")
    require(len(symtabs) == 1, "object requires one symbol table")
    require(set(trusted_sections) <= {sec.name for sec in code.values()}, "unknown trusted section")
    table = sections[symtabs[0]]
    require(table['sh_entsize'] == 24, "invalid symbol entry size")
    symbols = list(table.iter_symbols())
    changed = {}
    maps = {}
    ends = {}
    operands = {}
    counts = {}
    functions_by_section = {}
    for symbol in symbols:
        if symbol['st_info']['type'] == 'STT_FUNC':
            functions_by_section.setdefault(symbol['st_shndx'], []).append(symbol)
    for idx, sec in code.items():
        require(sec.name not in counts, f"{sec.name}: duplicate executable section name")
        functions = functions_by_section.get(idx, [])
        entries = rela.get(idx, (None, []))[1]
        types = {r['r_offset']: r['r_info_type'] for r in entries}
        require(len(types) == len(entries), "overlapping instruction relocations")
        changed[idx], maps[idx], ends[idx], operands[idx], counts[sec.name] = code_section(
            sec, types, functions, runtime, sec.name in trusted_sections, baseline)
    changed[symtabs[0]] = syms = bytearray(table.data())
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
                require(kind == 2 and dest in maps, "unsupported FDE relocation")
                frame_refs[target][offset] = maps[dest], ends[dest], sym['st_value'] + addend
            if dest in maps:
                if kind in (9, 41, 42, 4):
                    require(addend == -bias, "unsupported indirect code-symbol addend")
                else:
                    require((target in frames or target in maps and kind == 2 or kind == 1),
                            "unsupported data-to-code relocation")
                    start = sym['st_value']
                    logical = start + addend + bias
                    require(logical in maps[dest], "code relocation target outside instruction boundary")
                    addend = maps[dest][logical] - maps[dest][start] - bias
            struct.pack_into('<QQq', out, 24*i, offset, r['r_info_sym'] << 32 | kind, addend)
    for idx in frames:
        changed[idx] = data = bytearray(sections[idx].data())
        update_frames(data, frame_refs[idx])
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
