import io
import struct
from collections import defaultdict
from pathlib import Path

from elftools.elf.elffile import ELFFile
from elftools.elf.enums import (ENUM_ST_INFO_BIND, ENUM_ST_INFO_TYPE, ENUM_ST_SHNDX,
                                ENUM_ST_VISIBILITY, ENUM_VERSYM)
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import SymbolTableSection

from .errors import RewriteError, fail


def _decoder(enum):
    return {value: name for name, value in enum.items() if name != "_default_"}


_BIND, _TYPE, _VISIBILITY, _SHNDX, _VERSYM = map(
    _decoder, (ENUM_ST_INFO_BIND, ENUM_ST_INFO_TYPE, ENUM_ST_VISIBILITY, ENUM_ST_SHNDX, ENUM_VERSYM))
_SYMBOL = struct.Struct("<IBBHQQ")
_RELA, _REL = struct.Struct("<QQq"), struct.Struct("<QQ")


class _Symbol:
    """The pyelftools symbol fields this module reads, decoded without construct."""
    __slots__ = ("name", "value", "size", "type", "bind", "visibility", "shndx")


def _symbols(data, section, strings):
    # Equivalent to pyelftools' iter_symbols() for ELF64 little-endian, whose
    # construct-based parsing is the dominant cost for large symbol tables.
    entry_size = section["sh_entsize"]
    if entry_size < _SYMBOL.size:
        raise RewriteError(f"{section.name}: invalid symbol entry size {entry_size}")
    base, string_base = section["sh_offset"], strings["sh_offset"]
    result = []
    for index in range(section["sh_size"] // entry_size):
        st_name, info, other, shndx, value, size = _SYMBOL.unpack_from(data, base + index * entry_size)
        start = string_base + st_name
        end = data.find(b"\0", start)
        raw = data[start:end if end >= 0 else len(data)]
        symbol = _Symbol()
        symbol.name = raw.decode("utf-8", errors="replace") if raw else ""
        symbol.value, symbol.size = value, size
        symbol.bind, symbol.type = _BIND.get(info >> 4, info >> 4), _TYPE.get(info & 0xF, info & 0xF)
        symbol.visibility = _VISIBILITY.get(other & 7, other & 7)
        symbol.shndx = _SHNDX.get(shndx, shndx)
        result.append(symbol)
    return result


def _relocations(data, section):
    rela = section.is_RELA()
    layout = _RELA if rela else _REL
    base = section["sh_offset"]
    for index in range(section["sh_size"] // layout.size):
        fields = layout.unpack_from(data, base + index * layout.size)
        yield fields[0], fields[1] >> 32, fields[1] & 0xFFFFFFFF, fields[2] if rela else 0


class Image:
    def __init__(self, path):
        self.path = str(path)
        self.data = Path(path).read_bytes()
        self.elf = ELFFile(io.BytesIO(self.data))
        if (self.elf.elfclass != 64 or not self.elf.little_endian
                or self.elf["e_machine"] != "EM_X86_64"
                or self.elf["e_type"] not in ("ET_EXEC", "ET_DYN")):
            raise RewriteError(f"{path}: expected linked little-endian x86-64 ET_EXEC or ET_DYN")
        self.sections = list(self.elf.iter_sections())
        tls_segments = [s for s in self.elf.iter_segments() if s["p_type"] == "PT_TLS"]
        if len(tls_segments) > 1:
            raise RewriteError(f"{path}: multiple PT_TLS segments")
        self.tls = None
        if tls_segments:
            tls = tls_segments[0]
            self.tls = {"address": tls["p_vaddr"], "file_size": tls["p_filesz"],
                        "memory_size": tls["p_memsz"], "alignment": tls["p_align"],
                        "template": tls.data().hex()}
        if not self.sections:
            raise RewriteError(f"{path}: sectionless ELF recovery is not supported")
        self.executable = [s for s in self.sections if s["sh_flags"] & 4 and s["sh_size"]]
        if not self.executable:
            raise RewriteError(f"{path}: no executable sections")
        for segment in self.elf.iter_segments():
            if segment["p_type"] == "PT_GNU_STACK" and segment["p_flags"] & 1:
                raise RewriteError(f"{path}: executable stack is outside the static rewriting contract")
            if segment["p_type"] == "PT_LOAD" and segment["p_flags"] & 1:
                if segment["p_flags"] & 2:
                    raise RewriteError(f"{path}: writable executable PT_LOAD is unsupported")
                start, end = segment["p_vaddr"], segment["p_vaddr"] + segment["p_filesz"]
                covered = sorted((s["sh_addr"], s["sh_addr"] + s["sh_size"])
                                 for s in self.executable if start <= s["sh_addr"] < end)
                cursor = start
                for lo, hi in covered + [(end, end)]:
                    if lo < cursor or hi > end:
                        raise RewriteError(f"{path}: overlapping/out-of-segment executable sections")
                    gap = self.data[segment["p_offset"] + cursor - start:
                                    segment["p_offset"] + lo - start]
                    if any(gap):
                        fail(path, "PT_LOAD", cursor, "nonzero executable bytes outside code sections")
                    cursor = hi
        self.symbol_addresses = defaultdict(set)
        self.ifuncs = []
        self.local_ifunc_names = set()
        self.local_tls_names = set()
        self.tls_symbols = {}
        self.dynamic_symbols = []
        self.strong_imports = []
        self.function_ranges = []
        self.symbol_versions = []
        self.dynamic_versions = {}
        versions = {}
        version_needs = self.elf.get_section_by_name(".gnu.version_r")
        if version_needs:
            for version, auxiliaries in version_needs.iter_versions():
                for auxiliary in auxiliaries:
                    versions[auxiliary["vna_other"]] = version.name + ":" + auxiliary.name
        self.version_definitions = []
        version_defs = self.elf.get_section_by_name(".gnu.version_d")
        if version_defs:
            for version, auxiliaries in version_defs.iter_versions():
                names = [auxiliary.name for auxiliary in auxiliaries]
                versions[version["vd_ndx"]] = names[0]
                if not version["vd_flags"] & 1:
                    self.version_definitions.append(names)
        versym = self.elf.get_section_by_name(".gnu.version")
        table_symbols = {}
        for section_index, section in enumerate(self.sections):
            if isinstance(section, SymbolTableSection):
                symbols = _symbols(self.data, section, self.elf.get_section(section["sh_link"]))
                table_symbols[section_index] = symbols
                for index, symbol in enumerate(symbols):
                    if symbol.type == "STT_TLS" and symbol.shndx != "SHN_UNDEF":
                        self.tls_symbols[symbol.name] = (symbol.value, symbol.size)
                        if symbol.bind == "STB_LOCAL":
                            self.local_tls_names.add(symbol.name)
                    if symbol.shndx != "SHN_UNDEF" and symbol.name:
                        self.symbol_addresses[symbol.name].add(symbol.value)
                    if section.name == ".dynsym" and symbol.name:
                        self.dynamic_symbols.append((symbol.name, symbol.type))
                        if symbol.shndx == "SHN_UNDEF" and symbol.bind == "STB_GLOBAL":
                            self.strong_imports.append(symbol.name)
                        if versym:
                            entry = versym["sh_offset"] + index * versym["sh_entsize"]
                            raw = int.from_bytes(self.data[entry:entry + 2], "little")
                            ndx = _VERSYM.get(raw, raw)
                        else:
                            ndx = "VER_NDX_GLOBAL"
                        version = versions.get(ndx & 0x7FFF, "") if isinstance(ndx, int) else ""
                        hidden = bool(ndx & 0x8000) if isinstance(ndx, int) else False
                        self.dynamic_versions[index] = version
                        self.symbol_versions.append((symbol.name, symbol.type, symbol.bind,
                                                     symbol.visibility, version, hidden))
                    if symbol.type in ("STT_GNU_IFUNC", "STT_LOOS"):
                        if symbol.shndx != "SHN_UNDEF":
                            self.ifuncs.append((symbol.name, symbol.value, symbol.size))
                            if symbol.bind == "STB_LOCAL":
                                self.local_ifunc_names.add(symbol.name)
                    if (symbol.type in ("STT_FUNC", "STT_GNU_IFUNC", "STT_LOOS")
                            and symbol.shndx != "SHN_UNDEF"
                            and symbol.size):
                        self.function_ranges.append((symbol.name, symbol.value, symbol.size))
        self.symbols = {name: next(iter(addresses)) for name, addresses in self.symbol_addresses.items()
                        if len(addresses) == 1}
        executable_ranges = [(s["sh_addr"], s["sh_addr"] + s["sh_size"]) for s in self.executable]
        for name, address, _ in self.ifuncs:
            if not any(low <= address < high for low, high in executable_ranges):
                fail(path, ".dynsym/.symtab", address, f"IFUNC resolver {name} is outside executable code")
        self.relocations = {}
        for section in self.sections:
            if isinstance(section, RelocationSection) and section["sh_flags"] & 2:
                link = section["sh_link"]
                if link not in table_symbols:
                    linked = self.elf.get_section(link)
                    table_symbols[link] = _symbols(self.data, linked, self.elf.get_section(linked["sh_link"]))
                symbols = table_symbols[link]
                for offset, symbol_index, kind, addend in _relocations(self.data, section):
                    if kind == 0:
                        if offset or symbol_index or addend:
                            fail(path, section.name, offset, "noncanonical R_X86_64_NONE entry")
                        continue
                    if kind not in (1, 5, 6, 7, 8, 18, 37):
                        raise RewriteError(f"{path}: unsupported dynamic relocation {kind} (TLS requires layout validation)")
                    if any(low <= offset < high for low, high in executable_ranges):
                        fail(path, section.name, offset, "dynamic text relocation")
                    if symbol_index >= len(symbols):
                        raise RewriteError(f"{path}: relocation at 0x{offset:x} names a missing symbol")
                    symbol = symbols[symbol_index]
                    name = symbol.name
                    width = symbol.size if kind == 5 else 8
                    if self.section_at(offset, width) is None:
                        fail(path, section.name, offset, "dynamic relocation outside allocated memory")
                    self.relocations[offset] = {
                        "symbol": name, "type": kind, "addend": addend,
                        "version": self.dynamic_versions.get(symbol_index, ""),
                    }
                    if kind == 18:
                        if name and symbol.type != "STT_TLS":
                            fail(path, section.name, offset, "TPOFF64 references a non-TLS symbol")
                        if not name and (self.tls is None or not 0 <= addend < self.tls["memory_size"]):
                            fail(path, section.name, offset, "TPOFF64 offset is outside the module TLS image")
                    if kind == 37:
                        resolver = self.relocations[offset]["addend"]
                        if name or not any(low <= resolver < high for low, high in executable_ranges):
                            fail(path, section.name, offset, "invalid IRELATIVE resolver reference")
        dynamic = self.elf.get_section_by_name(".dynamic")
        tags = list(dynamic.iter_tags()) if dynamic else []
        self.libraries = [t.needed for t in tags if t.entry.d_tag == "DT_NEEDED"]
        self.dynamic_paths = {t.entry.d_tag: getattr(t, field)
                              for t in tags for tag, field in (("DT_SONAME", "soname"),
                                                               ("DT_RPATH", "rpath"),
                                                               ("DT_RUNPATH", "runpath"))
                              if t.entry.d_tag == tag}
        self.init_fini = {t.entry.d_tag: t.entry.d_ptr for t in tags
                          if t.entry.d_tag in ("DT_INIT", "DT_FINI")}
        self.now = any(t.entry.d_tag == "DT_BIND_NOW"
                       or (t.entry.d_tag == "DT_FLAGS" and t.entry.d_val & 8)
                       or (t.entry.d_tag == "DT_FLAGS_1" and t.entry.d_val & 1) for t in tags)
        # Local-exec TLS is only valid in the executable, whose TLS block sits at a
        # static thread-pointer offset; shared objects must use the GOT/TLSDESC.
        self.executable_tls = (self.elf["e_type"] == "ET_EXEC"
                               or any(t.entry.d_tag == "DT_FLAGS_1" and t.entry.d_val & 0x08000000
                                      for t in tags)
                               or any(s["p_type"] == "PT_INTERP" for s in self.elf.iter_segments()))
        if any(t.entry.d_tag in ("DT_TEXTREL", "DT_RELR", "DT_AUDIT", "DT_DEPAUDIT")
               for t in tags):
            raise RewriteError(f"{path}: unsupported dynamic relocation/audit feature")

    def section_at(self, address, size=1):
        if not hasattr(self, "_allocated"):
            self._allocated = [(s["sh_addr"], s["sh_addr"] + s["sh_size"], s) for s in self.sections
                               if s["sh_flags"] & 2
                               and not (s["sh_flags"] & 0x400 and s["sh_type"] == "SHT_NOBITS")]
        return next((s for low, high, s in self._allocated
                     if low <= address and address + size <= high), None)

    def read(self, address, size):
        section = self.section_at(address, size)
        if section is None or section["sh_type"] == "SHT_NOBITS":
            raise RewriteError(f"{self.path}: address 0x{address:x}+{size} is not file-backed")
        offset = section["sh_offset"] + address - section["sh_addr"]
        return self.data[offset:offset + size]

    def symbol(self, name):
        if len(self.symbol_addresses.get(name, ())) > 1:
            raise RewriteError(f"{self.path}: reference to ambiguous symbol {name}; a unique identity is required")
        if name not in self.symbols:
            raise RewriteError(f"{self.path}: required provenance/reference symbol {name} is missing")
        return self.symbols[name]

    def pointer_identity(self, address):
        reloc = self.relocations.get(address)
        if reloc and reloc["symbol"]:
            return reloc["symbol"]
        value = reloc["addend"] if reloc and reloc["type"] == 8 else int.from_bytes(self.read(address, 8), "little")
        if value and self.section_at(value) is None:
            raise RewriteError(f"{self.path}: dangling pointer at 0x{address:x}")
        if value:
            for name, _ in self.dynamic_symbols:
                if self.symbols.get(name) == value:
                    return name
        return value


def tcb_field_offset(path, struct, field):
    """Resolve offsetof(struct, field) from an ELF's DWARF debug info.

    On x86-64 the thread pointer (and thus FS base) is the address of the TCB,
    which is `struct pthread` itself, so a member's FS-relative displacement is
    exactly its struct offset. Letting the compiler-generated DWARF supply the
    offset keeps the runtime slots free of hand-written magic numbers.
    """
    elf = ELFFile(io.BytesIO(Path(path).read_bytes()))
    if not elf.has_dwarf_info():
        raise RewriteError(f"{path}: no DWARF debug info to resolve struct {struct} offsets")
    want = struct.encode()
    member = field.encode()
    for unit in elf.get_dwarf_info().iter_CUs():
        for die in unit.iter_DIEs():
            if (die.tag != "DW_TAG_structure_type"
                    or die.attributes.get("DW_AT_name") is None
                    or die.attributes["DW_AT_name"].value != want):
                continue
            for child in die.iter_children():
                if child.tag != "DW_TAG_member" or child.attributes.get("DW_AT_name") is None:
                    continue
                if child.attributes["DW_AT_name"].value == member:
                    location = child.attributes.get("DW_AT_data_member_location")
                    if location is None or not isinstance(location.value, int):
                        raise RewriteError(f"{path}: {struct}.{field} has no constant offset")
                    return location.value
    raise RewriteError(f"{path}: struct {struct} member {field} not found in DWARF")
