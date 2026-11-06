import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import gtirb
from gtirb_layout import layout_module

from gsfork_elf.errors import RewriteError
from gsfork_elf.pipeline import run
from gsfork_elf.symbols import complete_elf_symbol_info, preserve_integral_symbols


class SymbolLayoutTests(unittest.TestCase):
    def setUp(self):
        self.module = gtirb.Module(name="layout", isa=gtirb.Module.ISA.X64,
                                   file_format=gtirb.Module.FileFormat.ELF)
        section = gtirb.Section(name=".data", module=self.module)
        self.interval = gtirb.ByteInterval(address=0x1000, contents=bytes(128), section=section)
        self.block = gtirb.DataBlock(size=128, byte_interval=self.interval)
        self.module.aux_data["elfSymbolInfo"] = gtirb.AuxData(
            {}, "mapping<UUID,tuple<uint64_t,string,string,string,uint64_t>>")

    def symbol(self, name, value, section_index):
        symbol = gtirb.Symbol(name, payload=value, module=self.module)
        self.module.aux_data["elfSymbolInfo"].data[symbol] = (
            0, "OBJECT", "LOCAL", "DEFAULT", section_index)
        return symbol

    def test_generated_labels_get_metadata_without_changing_existing_symbols(self):
        existing = self.symbol("exported", 0x1000, 1)
        original_info = self.module.aux_data["elfSymbolInfo"].data[existing]
        labels = [
            gtirb.Symbol("__gsfork_begin", payload=self.block, module=self.module),
            gtirb.Symbol("__gsfork_end", payload=self.block, at_end=True, module=self.module),
        ]
        complete_elf_symbol_info(self.module)
        complete_elf_symbol_info(self.module)
        info = self.module.aux_data["elfSymbolInfo"].data
        self.assertEqual(info[existing], original_info)
        for label in labels:
            self.assertEqual(info[label], (0, "NOTYPE", "LOCAL", "DEFAULT", 0))
            self.assertIs(label.referent, self.block)
        self.assertTrue(labels[1].at_end)

    def test_constants_do_not_bind_to_synthetic_layout_addresses(self):
        absolute = self.symbol("absolute", 0x1000, 0xFFF1)
        version = self.symbol("version", 0, 0xFFF1)
        discarded = self.symbol("discarded_warning", 64, 48)
        address = self.symbol("data_address", 0x1000, 1)
        with preserve_integral_symbols(self.module):
            layout_module(self.module)
            self.assertEqual(self.interval.address, 0)
            layout_module(self.module)
        for symbol, value in ((absolute, 0x1000), (version, 0), (discarded, 64)):
            self.assertEqual(symbol.value, value)
            self.assertIsNone(symbol.referent)
        self.assertIs(address.referent, self.block)
        self.assertEqual(set(self.interval.blocks), {self.block})
        self.assertEqual(self.interval.address, 0x200000)

    def test_final_layout_does_not_cover_integral_values(self):
        # libc: gtirb-rewriting placed .data at 0 and the printer bound .L_40 inside it.
        self.symbol(".L_40", 0x40, 0)
        self.symbol("next_candidate", 0x200040, 0xFFF1)
        with preserve_integral_symbols(self.module):
            self.interval.address = 0
        self.assertEqual(self.interval.address, 0x400000)

    def test_existing_clear_layout_is_not_moved(self):
        self.symbol("version", 0, 0xFFF1)
        with preserve_integral_symbols(self.module):
            pass
        self.assertEqual(self.interval.address, 0x1000)

    def test_restores_constants_after_failure(self):
        absolute = self.symbol("absolute", 64, 0xFFF1)
        with self.assertRaisesRegex(RewriteError, "test failure"):
            with preserve_integral_symbols(self.module):
                layout_module(self.module)
                raise RewriteError("test failure")
        self.assertEqual(absolute.value, 64)
        self.assertIsNone(absolute.referent)

    def test_overlap_diagnostics_still_fail_and_are_logged(self):
        warning = ("WARNING: found overlapping element at address 40\n"
                   "The --layout option to gtirb-pprinter can fix overlapping elements.\n")
        with tempfile.TemporaryDirectory() as temporary:
            log = Path(temporary) / "printer.log"
            result = subprocess.CompletedProcess(["gtirb-pprinter"], 0, warning)
            with patch("gsfork_elf.pipeline.execute", return_value=result):
                with self.assertRaisesRegex(RewriteError, "overlapping element"):
                    run(["gtirb-pprinter"], log)
            self.assertIn(warning, log.read_text())


if __name__ == "__main__":
    unittest.main()
