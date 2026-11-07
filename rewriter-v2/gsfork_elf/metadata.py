import bisect

from elftools.dwarf.callframe import FDE

from .errors import RewriteError, fail


class Reader:
    def __init__(self, image, address):
        self.image, self.address = image, address

    def byte(self):
        value = self.image.read(self.address, 1)[0]
        self.address += 1
        return value

    def leb(self, signed=False):
        value = 0
        for shift in range(0, 70, 7):
            byte = self.byte()
            value |= (byte & 127) << shift
            if not byte & 128:
                return value - (1 << (shift + 7)) if signed and byte & 64 else value
        raise RewriteError("overlong LEB128 in exception metadata")


_FIXED_OPERAND = {0x06: 0, 0x12: 0, 0x1a: 0, 0x1c: 0, 0x1e: 0, 0x22: 0, 0x96: 0,
                  0x08: 1, 0x09: 1, 0x0a: 2, 0x0b: 2, 0x0c: 4, 0x0d: 4, 0x0e: 8, 0x0f: 8}


def expression_registers(expression):
    """Registers a DWARF expression reads, or None if it uses an unrecognized operation."""
    data, position, registers = bytes(expression), 0, set()

    def leb():
        nonlocal position
        value = shift = 0
        while position < len(data):
            byte = data[position]
            position += 1
            value |= (byte & 127) << shift
            shift += 7
            if not byte & 128:
                return value
        raise IndexError

    try:
        while position < len(data):
            opcode = data[position]
            position += 1
            if opcode in _FIXED_OPERAND:
                position += _FIXED_OPERAND[opcode]
            elif opcode in (0x10, 0x11, 0x23) or 0x30 <= opcode <= 0x4f:
                if opcode < 0x30:
                    leb()
            elif 0x50 <= opcode <= 0x8f:
                registers.add((opcode - 0x50) % 32)
                if opcode >= 0x70:
                    leb()
            elif opcode in (0x90, 0x92):
                registers.add(leb())
                if opcode == 0x92:
                    leb()
            else:
                return None
        if position > len(data):
            return None
    except IndexError:
        return None
    return registers


def cfi_state(row):
    cfa = row["cfa"]
    return {"cfa": [cfa.reg, cfa.offset, cfa.expr],
            "registers": {str(k): [v.type, v.arg] for k, v in row.items() if isinstance(k, int)}}


class Metadata:
    def __init__(self, image):
        self.image = image
        eh = image.elf.get_section_by_name(".eh_frame")
        if eh is None or not eh["sh_size"]:
            raise RewriteError(f"{image.path}: required .eh_frame unwind metadata is absent")
        self.frames = sorted(
            (f for f in image.elf.get_dwarf_info().EH_CFI_entries() if isinstance(f, FDE)),
            key=lambda f: f["initial_location"])
        if not self.frames:
            raise RewriteError(f"{image.path}: no recovered FDEs")
        self.starts = [f["initial_location"] for f in self.frames]
        self.rows = [f.get_decoded().table for f in self.frames]
        self.row_starts = [[row["pc"] for row in rows] for rows in self.rows]
        self.states = [{} for _ in self.rows]
        self.sites = []
        # LSDA type-table slot address -> PC-relative target, for repairing
        # entries the disassembler left unsymbolized.
        self.type_slots = {}
        for fde in self.frames:
            if fde.lsda_pointer:
                self.sites.extend(self._lsda(fde))

    def state(self, address):
        """Return the shared unwind state at an address; callers must not mutate it."""
        index = bisect.bisect_right(self.starts, address) - 1
        if index < 0:
            return None
        fde = self.frames[index]
        if address >= fde["initial_location"] + fde["address_range"]:
            return None
        row = bisect.bisect_right(self.row_starts[index], address) - 1
        if row < 0:
            return None
        if row not in self.states[index]:
            self.states[index][row] = cfi_state(self.rows[index][row])
        return self.states[index][row]

    def _lsda(self, fde):
        image = self.image
        start = fde["initial_location"]
        reader = Reader(image, fde.lsda_pointer)
        section = image.section_at(reader.address)
        if section is None or section.name != ".gcc_except_table":
            raise RewriteError(f"{image.path}: LSDA does not point into .gcc_except_table")
        if reader.byte() != 0xFF:
            raise RewriteError(f"{image.path}: only implicit function-relative LSDA LPStart is supported")
        type_encoding = reader.byte()
        type_base = None
        if type_encoding != 0xFF:
            if type_encoding != 0x9B:
                raise RewriteError(f"{image.path}: unsupported LSDA type encoding 0x{type_encoding:x}")
            offset = reader.leb()
            type_base = reader.address + offset
        if reader.byte() != 1:
            raise RewriteError(f"{image.path}: only ULEB128 LSDA call-site encoding is supported")
        length = reader.leb()
        end = reader.address + length
        if end > section["sh_addr"] + section["sh_size"]:
            raise RewriteError(f"{image.path}: LSDA call-site table extends outside its section")
        sites = []
        while reader.address < end:
            low, size, landing, action = (reader.leb() for _ in range(4))
            actions = []
            visited = set()
            current = end + action - 1 if action else None
            while current is not None:
                if current in visited or not end <= current < section["sh_addr"] + section["sh_size"]:
                    raise RewriteError(f"{image.path}: invalid/cyclic LSDA action chain")
                visited.add(current)
                ar = Reader(image, current)
                filter_value = ar.leb(signed=True)
                displacement_address = ar.address
                next_action = ar.leb(signed=True)
                if filter_value and type_base is None:
                    raise RewriteError(f"{image.path}: LSDA action requires a missing type table")
                if filter_value < 0:
                    # Exception specification: a zero-terminated ULEB128 list of
                    # type indices at TTBase + (-filter - 1).
                    spec = Reader(image, type_base - filter_value - 1)
                    identities = []
                    while True:
                        if not spec.address < section["sh_addr"] + section["sh_size"]:
                            raise RewriteError(f"{image.path}: unterminated LSDA exception specification")
                        index = spec.leb()
                        if not index:
                            break
                        identities.append(self._type(type_base, end, index))
                    actions.append(["spec", identities])
                else:
                    actions.append(self._type(type_base, end, filter_value) if filter_value else None)
                current = displacement_address + next_action if next_action else None
            sites.append({"start": start + low, "end": start + low + size,
                          "landing": start + landing if landing else 0, "actions": actions})
        if reader.address != end:
            raise RewriteError(f"{image.path}: LSDA call-site table has a partial record")
        return sites

    def _type(self, type_base, table_start, index):
        slot = type_base - index * 4
        if not table_start <= slot < type_base:
            raise RewriteError(f"{self.image.path}: invalid LSDA type index")
        delta = int.from_bytes(self.image.read(slot, 4), "little", signed=True)
        if not delta:
            return 0
        self.type_slots[slot] = slot + delta
        return self.image.pointer_identity(slot + delta)

    def validate(self, boundaries, code_starts):
        image = self.image
        eh = image.elf.get_section_by_name(".eh_frame")
        previous_end = 0
        for fde, rows in zip(self.frames, self.rows):
            start, end = fde["initial_location"], fde["initial_location"] + fde["address_range"]
            if start not in boundaries or end not in boundaries or start >= end or start < previous_end:
                fail(image.path, ".eh_frame", start, "invalid/overlapping FDE code range")
            if image.section_at(start, end - start) is None:
                fail(image.path, ".eh_frame", start, "FDE range crosses section boundaries")
            previous_end = end
            for row in rows:
                if row["pc"] not in boundaries or not start <= row["pc"] <= end:
                    fail(image.path, ".eh_frame", row["pc"], "CFI row is not on an instruction boundary")
        for site in self.sites:
            if (site["start"] not in boundaries or site["end"] not in boundaries
                    or site["start"] > site["end"]
                    or (site["landing"] and site["landing"] not in code_starts)):
                fail(image.path, ".gcc_except_table", site["start"], "invalid exception range/landing pad")
        header = image.elf.get_section_by_name(".eh_frame_hdr")
        if header is None:
            raise RewriteError(f"{image.path}: required .eh_frame_hdr is absent")
        data, base = header.data(), header["sh_addr"]
        if data[:4] != b"\x01\x1b\x03\x3b" or len(data) < 12:
            raise RewriteError(f"{image.path}: unsupported .eh_frame_hdr encoding")
        if base + 4 + int.from_bytes(data[4:8], "little", signed=True) != eh["sh_addr"]:
            raise RewriteError(f"{image.path}: .eh_frame_hdr points to the wrong frame section")
        count = int.from_bytes(data[8:12], "little")
        if count != len(self.frames) or len(data) != 12 + count * 8:
            raise RewriteError(f"{image.path}: inconsistent .eh_frame_hdr count")
        actual = [(base + int.from_bytes(data[o:o + 4], "little", signed=True),
                   base + int.from_bytes(data[o + 4:o + 8], "little", signed=True))
                  for o in range(12, len(data), 8)]
        expected = [(f["initial_location"], eh["sh_addr"] + f.offset) for f in self.frames]
        if actual != expected:
            raise RewriteError(f"{image.path}: stale/unsorted .eh_frame_hdr index")
        return {"fdes": len(self.frames), "exception_call_sites": len(self.sites)}
