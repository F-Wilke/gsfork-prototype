import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import asdict
from contextlib import contextmanager
from pathlib import Path

import gtirb
from gtirb_rewriting import Constraints, Pass, PassManager, Patch
from iced_x86 import Decoder, Mnemonic, OpKind, Register

from .elf import Image
from .compiler import normalize_assembly
from .errors import RewriteError, fail
from .metadata import Metadata
from .plt import PLT_SECTIONS, patch_plt, pointer_identity
from .policy import Runtime, classify, decode
from .recovery import repair_masked_table_bases
from .symbols import (add_reference_aliases, preserve_resolved_fs_offsets, resolver_symbols, restore_linker_symbols,
                      uniquify_locals, verify_tls)


GENERATED_DATA = {
    ".interp", ".dynamic", ".dynsym", ".dynstr", ".hash", ".gnu.hash",
    ".gnu.version", ".gnu.version_r", ".gnu.version_d", ".got", ".got.plt",
    ".eh_frame", ".eh_frame_hdr", ".gcc_except_table",
}


def tool(name):
    sibling = Path(sys.executable).parent / name
    value = str(sibling) if sibling.exists() else shutil.which(name)
    if not value:
        raise RewriteError(f"missing tool {name}; install rewriter-v2 and GNU gcc/binutils")
    return value


def run(command, log, *, allow_absent_entry=False, repair_header_symbol=False, local_ifunc_names=(),
        recovery_image=None):
    try:
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, timeout=300, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise RewriteError(f"tool execution failed: {command[0]}: {error}") from error
    Path(log).write_text("COMMAND: " + repr(command) + "\n" + result.stdout)
    diagnostics = result.stdout
    local_tls_names = set()
    if not result.returncode and recovery_image is not None and recovery_image.tls is not None:
        recovered = gtirb.IR.load_protobuf(command[command.index("--ir") + 1])
        if len(recovered.modules) != 1:
            raise RewriteError("TLS recovery returned multiple modules")
        verify_tls(recovered.modules[0], recovery_image)
        local_tls_names = {s.name for s, info in recovered.modules[0].aux_data["elfSymbolInfo"].data.items()
                           if info[1] == "TLS"}
    if allow_absent_entry:
        diagnostics = diagnostics.replace("WARNING: Failed to set module entry point.", "")
    if repair_header_symbol:
        diagnostics = diagnostics.replace("WARNING: Moving symbol to first block of section: __ehdr_start", "")
    for name in set(local_ifunc_names) | set(local_tls_names):
        diagnostic = "WARNING: Could not find GLOBAL/WEAK symbol for "
        diagnostics = diagnostics.replace(f"{diagnostic}\n{diagnostic}{name}\n", "")
    if result.returncode or re.search(r"\b(?:warning|error|failed)\b", diagnostics, re.I):
        raise RewriteError(f"{command[0]} failed or reported recovery/link diagnostics:\n{result.stdout}")


def expression(expr, module, resolvers):
    attributes = sorted(a.name for a in expr.attributes)
    forward = module.aux_data["symbolForwarding"].data
    aliases = module.aux_data["gsforkReferenceAliases"].data

    def resolve(symbol):
        seen = set()
        while symbol in forward:
            if symbol in seen:
                raise RewriteError("cyclic GTIRB symbol forwarding")
            seen.add(symbol)
            symbol = forward[symbol]
        return symbol

    def version(symbol):
        table = module.aux_data.get("elfSymbolVersions")
        if table is None:
            return ""
        definitions, requirements, indices = table.data
        if symbol not in indices:
            return ""
        index = indices[symbol][0] & 0x7FFF
        if index in definitions:
            return definitions[index][0][0]
        for library, versions in requirements.items():
            if index in versions:
                return library + ":" + versions[index]
        return ""

    if isinstance(expr, gtirb.SymAddrConst):
        symbol = resolve(expr.symbol)
        info = module.aux_data["elfSymbolInfo"].data.get(symbol)
        resolver = None
        if info and info[1] == "GNU_IFUNC" and isinstance(symbol.referent, gtirb.CodeBlock):
            resolver = resolvers[symbol.referent.address]
        return {"kind": "constant", "symbol": symbol.name, "value_symbol": aliases.get(symbol, symbol).name,
                "tls": bool(info and info[1] == "TLS"), "version": version(symbol),
                "offset": expr.offset, "attributes": attributes, "ifunc_resolver": resolver}
    if isinstance(expr, gtirb.SymAddrAddr):
        first, second = resolve(expr.symbol1), resolve(expr.symbol2)
        return {"kind": "difference", "symbol": first.name, "symbol2": second.name,
                "value_symbol": aliases.get(first, first).name,
                "value_symbol2": aliases.get(second, second).name, "scale": expr.scale,
                "offset": expr.offset, "attributes": attributes}
    raise RewriteError(f"unsupported GTIRB symbolic expression {expr}")


def marker(module, block, number):
    begin, end = f"__gsfork_b_{number}", f"__gsfork_e_{number}"
    gtirb.Symbol(begin, payload=block, module=module)
    gtirb.Symbol(end, payload=block, at_end=True, module=module)
    return begin, end


class Transform(Pass):
    def __init__(self, image, metadata, runtime, trusted_sections, baseline, resolvers=None):
        self.image, self.metadata, self.runtime = image, metadata, runtime
        self.trusted_sections, self.baseline = set(trusted_sections), baseline
        self.blocks, self.data, self.retired = [], [], []
        self.input_data_ids = set()
        self.resolvers = resolvers or {}
        _, self.plt_slots = patch_plt(image, require_now=False)

    def begin_module(self, module, functions, context):
        if "cfiDirectives" not in module.aux_data or not module.aux_data["cfiDirectives"].data:
            raise RewriteError("Ddisasm did not recover required CFI directives")
        section_names = {s.name for s in module.sections}
        if self.trusted_sections - section_names:
            raise RewriteError(f"trusted sections absent from input: {sorted(self.trusted_sections - section_names)}")
        index = 0
        for section in sorted(module.sections, key=lambda s: s.address or 0):
            executable = gtirb.Section.Flag.Executable in section.flags
            if not executable and (section.name in GENERATED_DATA
                                   or section.name.startswith((".note", ".rela", ".rel.", ".debug"))):
                continue
            blocks = sorted(section.byte_blocks, key=lambda b: b.address)
            self.input_data_ids.update(b.uuid for b in blocks if isinstance(b, gtirb.DataBlock))
            if executable:
                self.check_recovery(section, blocks)
            for block in blocks:
                if not block.size:
                    continue
                if executable and section.name in PLT_SECTIONS:
                    if isinstance(block, gtirb.CodeBlock):
                        for ins in decode(bytes(block.contents), block.address):
                            slot = next(s for s in self.plt_slots
                                        if s["address"] <= ins.ip < s["address"] + s["size"])
                            self.retired.append({"section": section.name, "original": ins.ip,
                                                 "slot": slot["address"],
                                                 "symbol": (pointer_identity(self.image, slot["target"])
                                                            if slot["target"] is not None else None),
                                                 "bytes": bytes(block.contents)[
                                                     ins.ip - block.address:ins.next_ip - block.address].hex()})
                    continue
                begin, end = marker(module, block, index)
                index += 1
                record = {"section": section.name, "original": block.address,
                          "original_size": block.size, "begin": begin, "end": end}
                if isinstance(block, gtirb.DataBlock):
                    self.record_data(module, block, record, executable)
                    continue
                record["trusted"] = section.name in self.trusted_sections
                record["instructions"] = []
                instructions = decode(bytes(block.contents), block.address)
                for ins in instructions:
                    try:
                        if self.baseline:
                            rule = "padding" if ins.mnemonic == Mnemonic.NOP else "native-baseline"
                        else:
                            rule = "trusted" if record["trusted"] else classify(ins, self.runtime)
                    except RewriteError as error:
                        fail(self.image.path, section.name, ins.ip, f"{ins}: {error}")
                    low = ins.ip - block.byte_interval.address
                    fields = [(off, block.byte_interval.symbolic_expressions[off])
                              for off in range(low, low + ins.len)
                              if off in block.byte_interval.symbolic_expressions]
                    exprs = [expression(expr, module, self.resolvers) for off, expr in fields]
                    if len(exprs) > 1:
                        fail(self.image.path, section.name, ins.ip, "multiple symbolic instruction fields unsupported")
                    if exprs:
                        decoder = Decoder(64, bytes(block.contents)[ins.ip - block.address:], ip=ins.ip)
                        decoded = decoder.decode()
                        offsets = decoder.get_constant_offsets(decoded)
                        location = fields[0][0] - low
                        if offsets.has_displacement and location == offsets.displacement_offset:
                            exprs[0]["field"] = "displacement"
                        elif offsets.has_immediate and location == offsets.immediate_offset:
                            exprs[0]["field"] = "immediate"
                        else:
                            fail(self.image.path, section.name, ins.ip, "symbolic expression not on an encoded field")
                    relative = ins.is_ip_rel_memory_operand or any(
                        ins.op_kind(n) in (OpKind.NEAR_BRANCH16, OpKind.NEAR_BRANCH32, OpKind.NEAR_BRANCH64)
                        for n in range(ins.op_count))
                    if relative and not exprs:
                        fail(self.image.path, section.name, ins.ip, "unrecovered layout-dependent symbolic reference")
                    if any(e["attributes"] not in ([], ["PLT"], ["GOT", "PCREL"], ["GOT", "TPOFF"])
                           for e in exprs):
                        fail(self.image.path, section.name, ins.ip, "unsupported symbolic instruction attributes")
                    item = {"original": ins.ip, "bytes": bytes(block.contents)[
                        ins.ip - block.address:ins.next_ip - block.address].hex(),
                        "rule": rule, "expression": exprs[0] if exprs else None,
                        "unwind": self.metadata.state(ins.ip)}
                    item["lock_suffix_entry"] = (ins.has_lock_prefix
                                                 and bytes(block.contents)[ins.ip - block.address] == 0xF0)
                    record["instructions"].append(item)
                    if self.baseline or record["trusted"]:
                        continue
                    if rule == "gs":
                        # The assembler's `gs` prefix is a code fragment, not a DataBlock.
                        # Inserting it preserves the original symbolic operand and CFI.
                        context.insert_at(block, ins.ip - block.address,
                                          Patch.from_function(lambda _: "gs", Constraints()))
                    elif rule in ("rep-movsb", "movs", "stos"):
                        unwind = item["unwind"]
                        temporary_registers = {0, 1, 5} if rule == "stos" else {0, 4, 5}
                        if unwind and (unwind["cfa"][0] in temporary_registers or unwind["cfa"][2] is not None
                                       or any(kind == "REGISTER" and argument in temporary_registers
                                              or kind in ("EXPRESSION", "VAL_EXPRESSION")
                                              for kind, argument in unwind["registers"].values())):
                            fail(self.image.path, section.name, ins.ip,
                                 "string wrapper needs CFI rules for temporary register locations")
                        asm = self.runtime.string(ins)
                        context.replace_at(block, ins.ip - block.address, ins.len,
                                           Patch.from_function(lambda _, asm=asm: asm, Constraints()))
                self.blocks.append(record)

    def check_recovery(self, section, blocks):
        source = self.image.elf.get_section_by_name(section.name)
        if source is None:
            raise RewriteError(f"recovered executable section {section.name} absent in ELF")
        cursor = source["sh_addr"]
        for block in blocks:
            if block.address < cursor:
                fail(self.image.path, section.name, block.address, "overlapping recovered blocks")
            if block.address != cursor:
                fail(self.image.path, section.name, cursor, "unrecovered executable bytes")
            cursor = block.address + block.size
        if cursor != source["sh_addr"] + source["sh_size"]:
            fail(self.image.path, section.name, cursor, "unrecovered executable tail")

    def record_data(self, module, block, record, executable):
        if block.section.name in (".tdata", ".tbss"):
            tls_base = min(s.address for s in module.sections if s.name in (".tdata", ".tbss"))
            record["tls_offset"] = block.address - tls_base
        record["bytes"] = bytes(block.contents).hex()
        record["size"] = block.size
        record["expressions"] = []
        for offset, expr in block.byte_interval.symbolic_expressions.items():
            if block.offset <= offset < block.offset + block.size:
                sizes = module.aux_data["symbolicExpressionSizes"].data
                size = sizes.get(gtirb.Offset(block.byte_interval, offset))
                if size not in (1, 2, 4, 8):
                    fail(self.image.path, block.section.name, block.address,
                         "unsupported data symbolic-expression width")
                record["expressions"].append({"offset": offset - block.offset,
                                               "size": size, "expression": expression(expr, module, self.resolvers)})
        record["executable"] = executable
        if executable:
            from .validator import padding
            if not padding(bytes(block.contents), block.address):
                fail(self.image.path, block.section.name, block.address,
                     "non-padding data embedded in executable sections is not yet supported")
            if any(i.segment_prefix == Register.GS for i in decode(bytes(block.contents), block.address)):
                fail(self.image.path, block.section.name, block.address, "pre-existing GS in executable padding")
        self.data.append(record)


class NormalizePadding(Pass):
    def __init__(self, transform):
        self.transform = transform

    def begin_module(self, module, functions, context):
        for block in sorted(module.data_blocks, key=lambda b: b.address):
            if (gtirb.Section.Flag.Executable not in block.section.flags
                    or block.uuid in self.transform.input_data_ids):
                continue
            if (any(block.contents) or list(block.references)
                    or any(block.offset <= off < block.offset + block.size
                           for off in block.byte_interval.symbolic_expressions)):
                raise RewriteError("framework generated non-padding executable data")
            begin, end = marker(module, block, f"padding_{len(self.transform.data)}")
            self.transform.data.append({
                "section": block.section.name, "original": None, "original_size": 0,
                "begin": begin, "end": end, "bytes": (b"\x90" * block.size).hex(),
                "size": block.size, "expressions": [], "executable": True,
                "generated": "framework-alignment",
            })
            context.replace_at(block, 0, block.size, b"\x90" * block.size)


def print_ir(ir_path, binary, assembly, log, library_paths, *, image=None, entry_symbol=None,
             initializers=()):
    command = [tool("gtirb-pprinter"), str(ir_path), "--policy=complete", "--syntax=intel", "--layout",
               "--use-gcc", tool("gsfork-cc"),
               "--keep-all-functions", "--keep-all-array-sections",
               "--keep-symbol", "_DYNAMIC", "--keep-symbol", "__ehdr_start",
               "--keep-symbol", "_GLOBAL_OFFSET_TABLE_",
               "--skip-section", ".dynamic",
               "--binary", str(binary), "--asm", str(assembly),
               "--compiler-args=-Wl,-z,now", "--compiler-args=-Wl,--eh-frame-hdr",
               "--compiler-args=-Wl,--build-id=none", "--compiler-args=-Wa,-L"]
    if entry_symbol is not None:
        command.append(f"--compiler-args=-Wl,-e,{entry_symbol}")
    for flag, name in initializers:
        command.append(f"--compiler-args=-Wl,-{flag}={name}")
    if image is not None and image.elf.get_section_by_name(".plt.sec") is not None:
        command.append("--compiler-args=-Wl,-z,ibtplt")
    for section in (".dynsym", ".dynstr", ".gnu.hash", ".hash",
                    ".gnu.version", ".gnu.version_r", ".gnu.version_d"):
        command.extend(["--skip-section", section])
    for directory in library_paths:
        command.extend(["-L", str(Path(directory).resolve())])
    run(command, log)
    assembly.write_text(normalize_assembly(assembly.read_text()))


@contextmanager
def workspace(output):
    with tempfile.TemporaryDirectory(prefix=".gsfork-", dir=output.parent) as temporary:
        work = Path(temporary)
        try:
            yield work
        except RewriteError as error:
            diagnostics = Path(tempfile.mkdtemp(prefix=output.name + ".failed-", dir=output.parent))
            for path in work.iterdir():
                if path.suffix in (".log", ".S", ".gtirb", ".json"):
                    shutil.copy2(path, diagnostics / path.name)
            raise RewriteError(f"{error}\nDiagnostics retained in {diagnostics}") from error


def rewrite(input_path, output_path, *, baseline=False, runtime=Runtime(),
            trusted_sections=(), trusted_libraries=(), library_paths=()):
    from .validator import validate_artifact

    runtime.check()
    source, output = Path(input_path).resolve(), Path(output_path).absolute()
    artifacts = output.with_name(output.name + ".gsfork")
    if output.exists() or artifacts.exists():
        raise RewriteError(f"output or artifact directory already exists: {output}")
    if not output.parent.is_dir():
        raise RewriteError(f"output parent does not exist: {output.parent}")
    image = Image(source)
    missing = set(image.libraries) - set(trusted_libraries)
    if missing and not baseline:
        raise RewriteError(f"dependencies must be explicitly declared trusted (--trust-library): {sorted(missing)}")
    metadata = Metadata(image)
    patch_plt(image, require_now=False)
    with workspace(output) as work:
        original_ir = work / "original.gtirb"
        no_entry = (image.elf["e_type"] == "ET_DYN" and not image.elf["e_entry"]
                    and not any(s["p_type"] == "PT_INTERP" for s in image.elf.iter_segments()))
        run([tool("ddisasm"), str(source), "--ir", str(original_ir), "-j", "1"], work / "recovery.log",
            allow_absent_entry=no_entry, repair_header_symbol=image.symbols.get("__ehdr_start") == 0,
            local_ifunc_names=image.local_ifunc_names, recovery_image=image)
        ir = gtirb.IR.load_protobuf(original_ir)
        if (len(ir.modules) != 1 or ir.modules[0].isa != gtirb.Module.ISA.X64
                or ir.modules[0].file_format != gtirb.Module.FileFormat.ELF):
            raise RewriteError("Ddisasm returned an unexpected module/ISA/file format")
        module = ir.modules[0]
        if any(s.name.startswith("__gsfork_") for s in module.symbols):
            raise RewriteError("input already contains reserved __gsfork_ provenance symbols")
        verify_tls(module, image)
        fs_offsets = preserve_resolved_fs_offsets(module)
        local_renames = uniquify_locals(module)
        linker_symbols = restore_linker_symbols(module, image)
        resolvers = resolver_symbols(module, image)
        reference_repairs = repair_masked_table_bases(module)
        add_reference_aliases(module)
        entry_symbol = None
        initializers = []
        for tag, address in image.init_fini.items():
            flag = "init" if tag == "DT_INIT" else "fini"
            block = next((b for b in module.code_blocks if b.address == address), None)
            if block is None:
                raise RewriteError(f"{source}: {tag} entry was not recovered")
            name = "__gsfork_" + flag
            symbol = gtirb.Symbol(name, payload=block, module=module)
            module.aux_data["elfSymbolInfo"].data[symbol] = (0, "NOTYPE", "GLOBAL", "HIDDEN", 0)
            initializers.append((flag, name))
        if image.elf["e_entry"]:
            if module.entry_point is None or module.entry_point.address != image.elf["e_entry"]:
                raise RewriteError(f"{source}: Ddisasm did not preserve the ELF entry point")
            entry_symbol = "__gsfork_entry"
            entry = gtirb.Symbol(entry_symbol, payload=module.entry_point, module=module)
            module.aux_data["elfSymbolInfo"].data[entry] = (0, "NOTYPE", "GLOBAL", "HIDDEN", 0)
        ir.save_protobuf(original_ir)
        # Establish a native relinking control before touching instruction semantics.
        print_ir(original_ir, work / "baseline", work / "baseline.S",
                 work / "baseline.log", library_paths, image=image, entry_symbol=entry_symbol,
                 initializers=initializers)
        transform = Transform(image, metadata, runtime, trusted_sections, baseline, resolvers)
        passes = PassManager()
        passes.add(transform)
        passes.run(ir)
        padding_passes = PassManager()
        padding_passes.add(NormalizePadding(transform))
        padding_passes.run(ir)
        rewritten_ir = work / "rewritten.gtirb"
        ir.save_protobuf(rewritten_ir)
        staged = work / "output"
        print_ir(rewritten_ir, staged, work / "output.S", work / "link.log", library_paths,
                 image=image, entry_symbol=entry_symbol, initializers=initializers)
        linked = Image(staged)
        generated = []
        if not baseline:
            data, generated = patch_plt(linked)
            staged.write_bytes(data)
            ordered, lock_orders = order_lock_prefixes(Image(staged))
            staged.write_bytes(ordered)
        else:
            lock_orders = []
        report = {
            "schema": 1, "mode": "baseline" if baseline else "gs",
            "input": str(source), "output": str(output),
            "input_sha256": hashlib.sha256(image.data).hexdigest(),
            "input_entry": image.elf["e_entry"],
            "output_sha256": hashlib.sha256(staged.read_bytes()).hexdigest(),
            "baseline_sha256": hashlib.sha256((work / "baseline").read_bytes()).hexdigest(),
            "runtime": asdict(runtime), "trusted_sections": sorted(set(trusted_sections)),
            "trusted_libraries": sorted(set(trusted_libraries)), "libraries": image.libraries,
            "blocks": transform.blocks, "data": transform.data, "retired_plt": transform.retired,
            "generated": generated, "exception_sites": metadata.sites,
            "input_dynamic_symbols": image.dynamic_symbols,
            "input_symbol_versions": image.symbol_versions,
            "input_version_definitions": image.version_definitions,
            "input_dynamic_paths": image.dynamic_paths, "input_init_fini": image.init_fini,
            "input_tls": image.tls,
            "resolved_fs_offsets": fs_offsets,
            "lock_prefix_ordering": lock_orders,
            "reference_repairs": reference_repairs,
            "local_symbol_renames": local_renames,
            "linker_symbols": linker_symbols,
            "input_resolvers": [{"original": address, "symbol": name} for address, name in resolvers.items()],
            "toolchain": {"ddisasm": "1.9.5", "gtirb-rewriting": "0.4.1", "gtirb-pprinter": "2.2.5"},
        }
        pending_report = work / "unvalidated-report.json"
        pending_report.write_text(json.dumps(report, indent=2) + "\n")
        report["validation"] = validate_artifact(staged, report)
        pending_report.unlink()
        (work / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        staged.chmod(source.stat().st_mode & 0o777 & ~0o022)
        os.rename(work, artifacts)
        os.rename(artifacts / "output", output)
    return report


def order_lock_prefixes(image):
    result = bytearray(image.data)
    records = []
    for section in image.executable:
        for ins in decode(section.data(), section["sh_addr"]):
            if not ins.has_lock_prefix or ins.segment_prefix != Register.GS:
                continue
            offset = section["sh_offset"] + ins.ip - section["sh_addr"]
            raw = bytes(result[offset:offset + ins.len])
            end = 0
            while end < len(raw) and raw[end] in (0xF0, 0x65, 0x66, 0x67):
                end += 1
            prefix = raw[:end]
            if 0xF0 not in prefix:
                raise RewriteError(f"{image.path}: unsupported GS/LOCK prefix ordering at 0x{ins.ip:x}")
            ordered = b"\xf0" + prefix.replace(b"\xf0", b"") + raw[end:]
            if ordered == raw:
                continue
            candidate = decode(ordered, ins.ip)
            if len(candidate) != 1 or candidate[0] != ins:
                raise RewriteError("LOCK prefix reordering changed instruction semantics")
            result[offset:offset + ins.len] = ordered
            records.append({"address": ins.ip, "before": raw.hex(), "after": ordered.hex()})
    return bytes(result), records
