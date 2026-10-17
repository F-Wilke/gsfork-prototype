from collections import defaultdict

import gtirb
from iced_x86 import Decoder, Register

from .errors import RewriteError


def uniquify_locals(module):
    """Keep symbol objects/aux-data keys intact while disambiguating assembler names."""
    groups = defaultdict(list)
    for symbol in module.symbols:
        groups[symbol.name].append(symbol)
    info = module.aux_data["elfSymbolInfo"].data
    indices = module.aux_data["elfSymbolTabIdxInfo"].data
    occupied = set(groups)
    renames = []
    for name, group in sorted(groups.items()):
        if not name or len(group) < 2:
            continue
        for symbol in sorted(group, key=lambda s: (sorted(indices.get(s, ())), str(s.uuid))):
            if info[symbol][2] != "LOCAL":
                continue
            suffix = len(renames)
            unique = f"{name}__gsfork_local_{suffix}"
            while unique in occupied:
                suffix += 1
                unique = f"{name}__gsfork_local_{suffix}"
            occupied.add(unique)
            renames.append({"original": name, "unique": unique,
                            "symbol_uuid": str(symbol.uuid),
                            "table_indices": sorted(indices.get(symbol, ()))})
            symbol.name = unique
    return renames


def resolver_symbols(module, image):
    """Name code entry points, not the IFUNC symbols whose values resolve to implementations."""
    addresses = {address for _, address, _ in image.ifuncs}
    addresses.update(r["addend"] for r in image.relocations.values() if r["type"] == 37)
    blocks = {b.address: b for b in module.code_blocks}
    result = {}
    expressions = {bi.address + offset: expr for bi in module.byte_intervals
                   for offset, expr in bi.symbolic_expressions.items() if bi.address is not None}
    for address, reloc in image.relocations.items():
        if reloc["type"] != 37:
            continue
        expr = expressions.get(address)
        if (not isinstance(expr, gtirb.SymAddrConst) or expr.offset or expr.attributes
                or not isinstance(expr.symbol.referent, gtirb.CodeBlock)
                or expr.symbol.referent.address != reloc["addend"]
                or module.aux_data["elfSymbolInfo"].data[expr.symbol][1] != "GNU_IFUNC"):
            raise RewriteError(f"{image.path}: IRELATIVE at 0x{address:x} did not recover its IFUNC symbol")
    for address in sorted(addresses):
        block = blocks.get(address)
        if block is None:
            raise RewriteError(f"{image.path}: IFUNC/IRELATIVE resolver 0x{address:x} was not recovered as code")
        name = f"__gsfork_resolver_{address:x}"
        if any(s.name == name for s in module.symbols):
            raise RewriteError(f"input uses reserved resolver symbol {name}")
        gtirb.Symbol(name, payload=block, module=module)
        result[address] = name
    aliases = {s.name: s for s in module.symbols if s.name in result.values()}
    for block in module.code_blocks:
        for offset in range(block.offset, block.offset + block.size):
            expr = block.byte_interval.symbolic_expressions.get(offset)
            if not isinstance(expr, gtirb.SymAddrConst) or expr.attributes:
                continue
            info = module.aux_data["elfSymbolInfo"].data.get(expr.symbol)
            if not info or info[1] != "GNU_IFUNC":
                continue
            referent = expr.symbol.referent
            if not isinstance(referent, gtirb.CodeBlock) or referent.address not in result:
                raise RewriteError(f"{image.path}: direct resolver reference lacks recovered code")
            # A direct encoded code reference calls the resolver itself. An
            # IFUNC-typed assembly reference would instead call its selected
            # implementation through a PLT, silently changing the semantics.
            block.byte_interval.symbolic_expressions[offset] = gtirb.SymAddrConst(
                expr.offset, aliases[result[referent.address]])
    return result


def restore_linker_symbols(module, image):
    """These symbols refer to output ELF structures, not recovered input data blocks."""
    names = {"_DYNAMIC", "__ehdr_start", "_GLOBAL_OFFSET_TABLE_"}
    restored = []
    info = module.aux_data["elfSymbolInfo"].data
    for symbol in module.symbols:
        if symbol.name not in names or symbol.name not in image.symbol_addresses:
            continue
        if len(image.symbol_addresses[symbol.name]) != 1:
            raise RewriteError(f"{image.path}: ambiguous linker-owned symbol {symbol.name}")
        symbol.referent = gtirb.ProxyBlock(module=module)
        symbol.at_end = False
        info[symbol] = (0, "NOTYPE", "GLOBAL", "HIDDEN", 0)
        restored.append(symbol.name)
    header = next((s for s in module.symbols if s.name == "__ehdr_start"), None)
    if header is not None:
        # Ddisasm can choose an absolute version-node symbol at address zero
        # instead of the ELF header for a loader's load-bias computation.
        for block in module.code_blocks:
            decoder = Decoder(64, bytes(block.contents), ip=block.address)
            for instruction in decoder:
                if (not instruction.is_ip_rel_memory_operand
                        or not 0 <= instruction.ip_rel_memory_address < image.elf["e_ehsize"]):
                    continue
                offsets = decoder.get_constant_offsets(instruction)
                position = instruction.ip - block.byte_interval.address + offsets.displacement_offset
                expr = block.byte_interval.symbolic_expressions.get(position)
                if not isinstance(expr, gtirb.SymAddrConst) or expr.attributes:
                    raise RewriteError(f"{image.path}: unsupported ELF-header reference at 0x{instruction.ip:x}")
                base = expr.symbol.value
                if isinstance(expr.symbol.referent, gtirb.ByteBlock):
                    base = expr.symbol.referent.address
                    if expr.symbol.at_end:
                        base += expr.symbol.referent.size
                if expr.symbol is header:
                    base = 0
                if base is None or base + expr.offset != instruction.ip_rel_memory_address:
                    raise RewriteError(f"{image.path}: conflicting recovered ELF-header symbol")
                block.byte_interval.symbolic_expressions[position] = gtirb.SymAddrConst(
                    instruction.ip_rel_memory_address, header)
    return restored


def verify_tls(module, image):
    if image.tls is None:
        return
    sections = [s for s in module.sections if s.name in (".tdata", ".tbss")]
    if not sections:
        raise RewriteError(f"{image.path}: PT_TLS was not recovered")
    base = min(s.address for s in sections)
    info = module.aux_data["elfSymbolInfo"].data
    for name, (offset, size) in image.tls_symbols.items():
        candidates = [s for s in module.symbols if s.name == name and info.get(s, (0, ""))[1] == "TLS"]
        if not candidates or any(not isinstance(s.referent, gtirb.DataBlock)
                                 or s.referent.address - base != offset for s in candidates):
            raise RewriteError(f"{image.path}: TLS symbol {name} lost its module-relative offset")
    for bi in module.byte_intervals:
        for offset, expr in bi.symbolic_expressions.items():
            relocation = image.relocations.get(bi.address + offset) if bi.address is not None else None
            if not relocation or relocation["type"] != 18:
                continue
            if not isinstance(expr, gtirb.SymAddrConst) or expr.attributes:
                raise RewriteError(f"{image.path}: unrecovered TPOFF64 expression")
            if relocation["symbol"]:
                if expr.symbol.name != relocation["symbol"] or expr.offset != relocation["addend"]:
                    raise RewriteError(f"{image.path}: wrong named TPOFF64 expression")
            else:
                if (not isinstance(expr.symbol.referent, gtirb.DataBlock)
                        or expr.symbol.referent.address - base + expr.offset != relocation["addend"]):
                    raise RewriteError(f"{image.path}: wrong local TPOFF64 expression")
                size, _, binding, visibility, index = info.get(expr.symbol, (0, "", "LOCAL", "DEFAULT", 0))
                info[expr.symbol] = (size, "TLS", binding, visibility, index)


def preserve_resolved_fs_offsets(module):
    records = []
    for block in module.code_blocks:
        decoder = Decoder(64, bytes(block.contents), ip=block.address)
        for instruction in decoder:
            if (instruction.segment_prefix != Register.FS
                    or instruction.memory_base != Register.NONE or instruction.memory_index != Register.NONE):
                continue
            offsets = decoder.get_constant_offsets(instruction)
            if not offsets.has_displacement:
                continue
            offset = instruction.ip - block.byte_interval.address + offsets.displacement_offset
            expr = block.byte_interval.symbolic_expressions.get(offset)
            if expr is None or expr.attributes != {gtirb.SymbolicExpression.Attribute.TPOFF}:
                continue
            # An already-linked absolute FS offset belongs to the runtime TLS
            # contract; it is not a request for a new local-exec relocation.
            del block.byte_interval.symbolic_expressions[offset]
            module.aux_data["symbolicExpressionSizes"].data.pop(gtirb.Offset(block.byte_interval, offset), None)
            records.append({"instruction": instruction.ip, "offset": instruction.memory_displacement})
    return records


def add_reference_aliases(module):
    groups = defaultdict(list)
    for symbol in module.symbols:
        groups[symbol.name].append(symbol)
    aliases = {}
    for name, symbols in sorted(groups.items()):
        if not name or len({(s.referent, s.at_end, s.value) for s in symbols}) <= 1:
            continue
        for symbol in sorted(symbols, key=lambda s: str(s.uuid)):
            if isinstance(symbol.referent, gtirb.ByteBlock):
                aliases[symbol] = gtirb.Symbol(f"__gsfork_value_{len(aliases)}",
                                               payload=symbol.referent, at_end=symbol.at_end, module=module)
    module.aux_data["gsforkReferenceAliases"] = gtirb.AuxData(aliases, "mapping<UUID,UUID>")
