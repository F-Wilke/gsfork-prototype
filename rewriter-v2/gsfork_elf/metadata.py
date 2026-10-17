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
        self.sites = []
        for fde in self.frames:
            if fde.lsda_pointer:
                self.sites.extend(self._lsda(fde))

    def state(self, address):
        index = bisect.bisect_right(self.starts, address) - 1
        if index < 0:
            return None
        fde = self.frames[index]
        if address >= fde["initial_location"] + fde["address_range"]:
            return None
        rows = self.rows[index]
        row = next((r for r in reversed(rows) if r["pc"] <= address), None)
        return cfi_state(row) if row else None

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
                if filter_value < 0:
                    raise RewriteError(f"{image.path}: LSDA exception-specification filters are unsupported")
                identity = None
                if filter_value:
                    if type_base is None:
                        raise RewriteError(f"{image.path}: LSDA action requires a missing type table")
                    slot = type_base - filter_value * 4
                    if not end <= slot < type_base:
                        raise RewriteError(f"{image.path}: invalid LSDA type index")
                    delta = int.from_bytes(image.read(slot, 4), "little", signed=True)
                    identity = image.pointer_identity(slot + delta) if delta else 0
                actions.append(identity)
                current = displacement_address + next_action if next_action else None
            sites.append({"start": start + low, "end": start + low + size,
                          "landing": start + landing if landing else 0, "actions": actions})
        if reader.address != end:
            raise RewriteError(f"{image.path}: LSDA call-site table has a partial record")
        return sites

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
