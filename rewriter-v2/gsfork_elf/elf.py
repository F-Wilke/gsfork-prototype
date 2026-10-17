import io
from collections import defaultdict
from pathlib import Path

from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import SymbolTableSection

from .errors import RewriteError, fail


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
        for section in self.sections:
            if isinstance(section, SymbolTableSection):
                for index, symbol in enumerate(section.iter_symbols()):
                    if symbol["st_info"]["type"] == "STT_TLS" and symbol["st_shndx"] != "SHN_UNDEF":
                        self.tls_symbols[symbol.name] = (symbol["st_value"], symbol["st_size"])
                        if symbol["st_info"]["bind"] == "STB_LOCAL":
                            self.local_tls_names.add(symbol.name)
                    if symbol["st_shndx"] != "SHN_UNDEF" and symbol.name:
                        self.symbol_addresses[symbol.name].add(symbol["st_value"])
                    if section.name == ".dynsym" and symbol.name:
                        self.dynamic_symbols.append((symbol.name, symbol["st_info"]["type"]))
                        ndx = versym.get_symbol(index)["ndx"] if versym else "VER_NDX_GLOBAL"
                        version = versions.get(ndx & 0x7FFF, "") if isinstance(ndx, int) else ""
                        hidden = bool(ndx & 0x8000) if isinstance(ndx, int) else False
                        self.dynamic_versions[index] = version
                        self.symbol_versions.append((symbol.name, symbol["st_info"]["type"],
                                                     symbol["st_info"]["bind"], symbol["st_other"]["visibility"],
                                                     version, hidden))
                    if symbol["st_info"]["type"] in ("STT_GNU_IFUNC", "STT_LOOS"):
                        if symbol["st_shndx"] != "SHN_UNDEF":
                            self.ifuncs.append((symbol.name, symbol["st_value"], symbol["st_size"]))
                            if symbol["st_info"]["bind"] == "STB_LOCAL":
                                self.local_ifunc_names.add(symbol.name)
                    if (symbol["st_info"]["type"] in ("STT_FUNC", "STT_GNU_IFUNC", "STT_LOOS")
                            and symbol["st_shndx"] != "SHN_UNDEF"
                            and symbol["st_size"]):
                        self.function_ranges.append((symbol.name, symbol["st_value"], symbol["st_size"]))
        self.symbols = {name: next(iter(addresses)) for name, addresses in self.symbol_addresses.items()
                        if len(addresses) == 1}
        for name, address, _ in self.ifuncs:
            if not any(s["sh_addr"] <= address < s["sh_addr"] + s["sh_size"] for s in self.executable):
                fail(path, ".dynsym/.symtab", address, f"IFUNC resolver {name} is outside executable code")
        self.relocations = {}
        for section in self.sections:
            if isinstance(section, RelocationSection) and section["sh_flags"] & 2:
                symbols = self.elf.get_section(section["sh_link"])
                for reloc in section.iter_relocations():
                    kind = reloc["r_info_type"]
                    if kind == 0:
                        if (reloc["r_offset"] or reloc["r_info_sym"]
                                or (reloc.is_RELA() and reloc["r_addend"])):
                            fail(path, section.name, reloc["r_offset"], "noncanonical R_X86_64_NONE entry")
                        continue
                    if kind not in (1, 5, 6, 7, 8, 18, 37):
                        raise RewriteError(f"{path}: unsupported dynamic relocation {kind} (TLS requires layout validation)")
                    if any(s["sh_addr"] <= reloc["r_offset"] < s["sh_addr"] + s["sh_size"]
                           for s in self.executable):
                        fail(path, section.name, reloc["r_offset"], "dynamic text relocation")
                    symbol = symbols.get_symbol(reloc["r_info_sym"])
                    name = symbol.name
                    width = symbol["st_size"] if kind == 5 else 8
                    if self.section_at(reloc["r_offset"], width) is None:
                        fail(path, section.name, reloc["r_offset"], "dynamic relocation outside allocated memory")
                    self.relocations[reloc["r_offset"]] = {
                        "symbol": name, "type": kind, "addend": reloc["r_addend"] if reloc.is_RELA() else 0,
                        "version": self.dynamic_versions.get(reloc["r_info_sym"], ""),
                    }
                    if kind == 18:
                        if name and symbol["st_info"]["type"] != "STT_TLS":
                            fail(path, section.name, reloc["r_offset"], "TPOFF64 references a non-TLS symbol")
                        if not name and (self.tls is None or not 0 <= reloc["r_addend"] < self.tls["memory_size"]):
                            fail(path, section.name, reloc["r_offset"], "TPOFF64 offset is outside the module TLS image")
                    if kind == 37:
                        resolver = self.relocations[reloc["r_offset"]]["addend"]
                        if name or not any(s["sh_addr"] <= resolver < s["sh_addr"] + s["sh_size"]
                                           for s in self.executable):
                            fail(path, section.name, reloc["r_offset"], "invalid IRELATIVE resolver reference")
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
        if any(t.entry.d_tag in ("DT_TEXTREL", "DT_RELR", "DT_AUDIT", "DT_DEPAUDIT")
               for t in tags):
            raise RewriteError(f"{path}: unsupported dynamic relocation/audit feature")

    def section_at(self, address, size=1):
        return next((s for s in self.sections if s["sh_flags"] & 2
                     and not (s["sh_flags"] & 0x400 and s["sh_type"] == "SHT_NOBITS")
                     and s["sh_addr"] <= address
                     and address + size <= s["sh_addr"] + s["sh_size"]), None)

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
