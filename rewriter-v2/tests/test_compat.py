import struct
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import gtirb

from gsfork_elf.compiler import restore_raw_bytes, restore_symbol_names
from gsfork_elf.elf import x86_feature_properties
from gsfork_elf.errors import RewriteError
from gsfork_elf.metadata import expression_registers
from gsfork_elf.pipeline import drop_ibt_property, expression, notrack_prefix_offset, run
from gsfork_elf.policy import classify, decode
from gsfork_elf.symbols import printer_name_restorations, printer_renames, uniquify_locals
from gsfork_elf.validator import check_reference, shape


def module_with_aux():
    module = gtirb.Module(name="compat")
    for name, schema in (
            ("elfSymbolInfo", "mapping<UUID,tuple<uint64_t,string,string,string,uint64_t>>"),
            ("elfSymbolTabIdxInfo", "mapping<UUID,sequence<tuple<string,uint64_t>>>"),
            ("symbolForwarding", "mapping<UUID,UUID>"),
            ("gsforkReferenceAliases", "mapping<UUID,UUID>")):
        module.aux_data[name] = gtirb.AuxData({}, schema)
    return module


def property_note(features):
    descriptor = struct.pack("<III", 0xC0000002, 4, features) + bytes(4)
    return struct.pack("<III", 4, len(descriptor), 5) + b"GNU\0" + descriptor


class CompatibilityTests(unittest.TestCase):
    def test_printer_renamed_names(self):
        for name in ("d", "d2", "def", "de85", "ah", "R15D", "rip", "0xBEEF", "DEADh", "shr"):
            self.assertTrue(printer_renames(name), name)
        for name in ("compute", "gitdiff", "h", "x1", "d_renamed", "main", "0x"):
            self.assertFalse(printer_renames(name), name)

    def test_printer_renamed_locals_get_reported_unique_names(self):
        module = module_with_aux()
        info = module.aux_data["elfSymbolInfo"].data
        local = gtirb.Symbol("d", payload=0x10, module=module)
        exported = gtirb.Symbol("add", payload=0x20, module=module)
        plain = gtirb.Symbol("table", payload=0x30, module=module)
        info[local] = (8, "OBJECT", "LOCAL", "DEFAULT", 0)
        info[exported] = (8, "FUNC", "GLOBAL", "DEFAULT", 0)
        info[plain] = (8, "OBJECT", "LOCAL", "DEFAULT", 0)
        renames = uniquify_locals(module)
        self.assertEqual([(r["original"], r["unique"]) for r in renames], [("d", "d__gsfork_local_0")])
        self.assertEqual((local.name, exported.name, plain.name), ("d__gsfork_local_0", "add", "table"))
        self.assertFalse(printer_renames(local.name))

    def test_nonlocal_printer_names_are_restored(self):
        module = module_with_aux()
        data = gtirb.DataBlock(size=8)
        gtirb.Symbol("BC", payload=data, module=module)
        gtirb.Symbol("ah", payload=data, module=module)
        gtirb.Symbol("main", payload=data, module=module)
        self.assertEqual(printer_name_restorations(module, True), (["BC"], ["ah"]))
        with self.assertRaisesRegex(RewriteError, "register/keyword"):
            printer_name_restorations(module, False)
        gtirb.Symbol("BC_renamed", payload=data, module=module)
        with self.assertRaisesRegex(RewriteError, "collides"):
            printer_name_restorations(module, True)

    def test_got_slot_to_unique_local_is_not_a_recovery_diagnostic(self):
        missing = "WARNING: Could not find GLOBAL/WEAK symbol for "
        image = SimpleNamespace(tls=None, unique_local_names={"Curl_sha256it"})
        command = ["ddisasm", "input", "--ir", "input.gtirb"]
        with tempfile.TemporaryDirectory() as temporary:
            log = Path(temporary) / "recovery.log"
            for output in (f"transform {missing}Curl_sha256it\n", f"{missing}\n{missing}Curl_sha256it\n"):
                with patch("gsfork_elf.pipeline.execute",
                           return_value=subprocess.CompletedProcess(command, 0, output)):
                    run(command, log, recovery_image=image)
            with patch("gsfork_elf.pipeline.execute",
                       return_value=subprocess.CompletedProcess(command, 0, f"{missing}duplicated\n")):
                with self.assertRaisesRegex(RewriteError, "diagnostics"):
                    run(command, log, recovery_image=image)

    def test_cfi_expression_registers(self):
        self.assertEqual(expression_registers([0x76, 0x78, 0x06]), {6})  # *(rbp - 8)
        self.assertEqual(expression_registers([0x76, 0]), {6})
        self.assertEqual(expression_registers([0x92, 0x11, 0x08, 0x23, 0x10]), {17})
        self.assertEqual(expression_registers([0x75, 0x00, 0x30, 0x22]), {5})
        self.assertIsNone(expression_registers([0x2f, 0x00, 0x00]))  # skip
        self.assertIsNone(expression_registers([0x76]))  # truncated

    def test_gsfork_cc_restores_raw_instruction_bytes(self):
        printed = "\n".join(["__gsfork_raw_3_650f38caca:", "            nop", "            nop",
                             "__gsfork_raw_3_650f38caca_end:", "            sha1nexte XMM9,XMM2"])
        self.assertEqual(restore_raw_bytes(printed).split("\n"), [
            "__gsfork_raw_3_650f38caca:", "            .byte 0x65,0x0f,0x38,0xca,0xca",
            "__gsfork_raw_3_650f38caca_end:", "            sha1nexte XMM9,XMM2"])
        with self.assertRaisesRegex(ValueError, "CFI"):
            restore_raw_bytes(printed.replace("nop\n", ".cfi_def_cfa_offset 16\n", 1))

    def test_gsfork_cc_restores_printed_names(self):
        printed = "\n".join([
            ".globl BC_renamed", ".type BC_renamed, @object", ".size BC_renamed, 8", "BC_renamed:",
            "    mov RAX,QWORD PTR [RIP+BC_renamed@GOTPCREL]", "    lea RDX,[RIP+BC_renamed2]",
            ".globl ah_renamed", ".hidden ah_renamed", ".type ah_renamed, @object", ".size ah_renamed, 8",
            "ah_renamed:", "    lea RAX,[RIP+ah_renamed+8]"])
        text = restore_symbol_names(printed, ["BC"], ["ah"])
        self.assertIn('[RIP+"BC"@GOTPCREL]', text)
        self.assertIn('"BC":', text)
        self.assertIn("BC_renamed2", text)
        self.assertIn("[RIP+ah_renamed+8]", text)
        self.assertNotIn(".globl ah_renamed", text)
        for line in ('.set "ah", ah_renamed', '.globl "ah"', '.hidden "ah"', '.type "ah", @object',
                     '.size "ah", 8', ".size ah_renamed, 8"):
            self.assertIn(line, text.split("\n"))

    def test_got_reference_to_nonpreemptible_definition_uses_relative_slot(self):
        ins = decode(bytes.fromhex("488b0500000000"), 0x1000)[0]  # mov rax, [rip+0] -> slot 0x1007
        expr = {"symbol": "table", "value_symbol": "table", "offset": 0, "attributes": ["GOT", "PCREL"],
                "version": "", "ifunc_resolver": None, "field": "displacement"}
        image = SimpleNamespace(symbol={"table": 0x2000}.__getitem__, section_at=lambda *a: object(),
                                relocations={0x1007: {"symbol": "", "type": 8, "addend": 0x2000, "version": ""}})
        check_reference(image, ins, expr, {})
        for relocation in ({"symbol": "", "type": 8, "addend": 0x2008, "version": ""},
                           {"symbol": "", "type": 37, "addend": 0x2000, "version": ""},
                           {"symbol": "other", "type": 6, "addend": 0, "version": ""}):
            image.relocations[0x1007] = relocation
            with self.assertRaisesRegex(RewriteError, "GOT reference does not resolve"):
                check_reference(image, ins, expr, {})

    def test_self_forwarded_canonical_plt_import_resolves_to_itself(self):
        module = module_with_aux()
        forward = module.aux_data["symbolForwarding"].data
        strcmp = gtirb.Symbol("strcmp", payload=gtirb.ProxyBlock(module=module), module=module)
        forward[strcmp] = strcmp
        self.assertEqual(expression(gtirb.SymAddrConst(0, strcmp), module, {})["symbol"], "strcmp")
        first = gtirb.Symbol("a", payload=0x10, module=module)
        second = gtirb.Symbol("b", payload=0x20, module=module)
        forward[first], forward[second] = second, first
        with self.assertRaisesRegex(RewriteError, "cyclic GTIRB symbol forwarding"):
            expression(gtirb.SymAddrConst(0, first), module, {})

    def test_two_symbolic_fields_are_both_masked(self):
        # mov QWORD PTR [rip+disp], imm32 in a non-PIE executable.
        original = decode(bytes.fromhex("48c7059e4d1f00c0c45f00"), 0x408487)[0]
        moved = decode(bytes.fromhex("6548c70500100000c0d45f00"), 0x500000)[0]
        displacement = {"field": "displacement"}
        immediate = {"field": "immediate"}
        self.assertEqual(shape(original, [displacement, immediate])[:2],
                         shape(moved, [displacement, immediate])[:2])
        self.assertNotEqual(shape(original, [displacement])[:2], shape(moved, [displacement])[:2])

    def test_memory_indirect_notrack_branch_becomes_gs(self):
        ins = decode(bytes.fromhex("3eff24cd402a4e00"), 0x1000)[0]
        self.assertEqual(classify(ins), "gs")
        with self.assertRaisesRegex(RewriteError, "segment override"):
            classify(ins, output=True)
        self.assertEqual(notrack_prefix_offset(bytes.fromhex("3eff24cd402a4e00")), 0)
        self.assertEqual(notrack_prefix_offset(bytes.fromhex("663eff24cd402a4e00")), 1)
        with self.assertRaisesRegex(RewriteError, "exactly one DS"):
            notrack_prefix_offset(bytes.fromhex("653eff24cd402a4e00"))
        converted = decode(bytes.fromhex("65ff24cd402a4e00"), 0x1000)[0]
        self.assertEqual(classify(converted, output=True), "gs")

    def test_ibt_property_is_dropped_but_shadow_stack_is_kept(self):
        module = gtirb.Module(name="note")
        section = gtirb.Section(name=".note.gnu.property", module=module)
        interval = gtirb.ByteInterval(address=0x400, contents=property_note(3), section=section)
        self.assertEqual([v for _, v in x86_feature_properties(interval.contents)], [3])
        drop_ibt_property(module)
        self.assertEqual([v for _, v in x86_feature_properties(interval.contents)], [2])

    def test_register_and_explicit_memory_extensions(self):
        self.assertEqual(classify(decode(bytes.fromhex("f20f38f107"), 0)[0]), "gs")  # crc32 eax, dword [rdi]
        self.assertEqual(classify(decode(bytes.fromhex("0fc7f0"), 0)[0]), "native")  # rdrand eax
        self.assertEqual(classify(decode(bytes.fromhex("660f3a220701"), 0)[0]), "gs")  # pinsrd xmm0, [rdi], 1


if __name__ == "__main__":
    unittest.main()
