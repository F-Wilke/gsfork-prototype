import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import gtirb

from gsfork_elf.errors import RewriteError
from gsfork_elf.metadata import Metadata
from gsfork_elf.pipeline import (ToolMemoryExceeded, Transform, execute, linear_interval_split, normalize_padding,
                                 recovery_threads, run, tool, tool_memory_limit, write_report)
from gsfork_elf.policy import Runtime


class ScalingTests(unittest.TestCase):
    def setUp(self):
        self.module = gtirb.Module(name="scaling")
        self.section = gtirb.Section(name=".data", module=self.module)
        self.interval = gtirb.ByteInterval(address=0x1000, contents=bytes(32768),
                                           section=self.section)
        self.symbol = gtirb.Symbol("target", payload=0x1000, module=self.module)
        for name, data, schema in (
                ("elfSymbolInfo", {}, "mapping<UUID,tuple<uint64_t,string,string,string,uint64_t>>"),
                ("symbolForwarding", {}, "mapping<UUID,UUID>"),
                ("gsforkReferenceAliases", {}, "mapping<UUID,UUID>"),
                ("symbolicExpressionSizes", {}, "mapping<Offset,uint64_t>")):
            self.module.aux_data[name] = gtirb.AuxData(data, schema)
        for offset in range(0, 32768, 8):
            self.interval.symbolic_expressions[offset] = gtirb.SymAddrConst(0, self.symbol)
            self.module.aux_data["symbolicExpressionSizes"].data[
                gtirb.Offset(self.interval, offset)] = 8
        with patch("gsfork_elf.pipeline.patch_plt", return_value=(None, [])):
            self.transform = Transform(SimpleNamespace(path="scaling"), None, Runtime(), (), False)

    def test_data_expressions_use_half_open_indexed_range(self):
        block = gtirb.DataBlock(offset=16384, size=16, byte_interval=self.interval)
        record = {}
        expressions = self.interval.symbolic_expressions
        getitem = type(expressions).__getitem__
        with patch.object(expressions, "items", side_effect=AssertionError("full interval scan")):
            with patch.object(type(expressions), "__getitem__", autospec=True,
                              side_effect=getitem) as lookup:
                self.transform.record_data(self.module, block, record, False)
        self.assertEqual([(entry["offset"], entry["size"]) for entry in record["expressions"]],
                         [(0, 8), (8, 8)])
        self.assertEqual(lookup.call_count, 2)

    def test_indexed_data_still_rejects_unknown_width(self):
        block = gtirb.DataBlock(offset=16384, size=8, byte_interval=self.interval)
        del self.module.aux_data["symbolicExpressionSizes"].data[
            gtirb.Offset(self.interval, block.offset)]
        with self.assertRaisesRegex(RewriteError, "symbolic-expression width"):
            self.transform.record_data(self.module, block, {}, False)

    def test_data_without_expressions_needs_no_size_table(self):
        block = gtirb.DataBlock(offset=16385, size=1, byte_interval=self.interval)
        del self.module.aux_data["symbolicExpressionSizes"]
        record = {}
        self.transform.record_data(self.module, block, record, False)
        self.assertEqual(record["expressions"], [])

    def test_cfi_lookup_boundaries_and_shared_states(self):
        metadata = Metadata.__new__(Metadata)
        metadata.frames = [
            {"initial_location": 100, "address_range": 20},
            {"initial_location": 130, "address_range": 10},
        ]
        metadata.starts = [100, 130]
        rows = [
            [{"pc": pc, "cfa": SimpleNamespace(reg=7, offset=offset, expr=None)}
             for pc, offset in ((100, 8), (105, 16), (105, 24), (115, 8))],
            [],
        ]
        metadata.rows = rows
        metadata.row_starts = [[row["pc"] for row in frame] for frame in rows]
        metadata.states = [{} for _ in rows]
        for address, offset in ((100, 8), (104, 8), (105, 24), (114, 24), (115, 8), (119, 8)):
            with self.subTest(address=address):
                self.assertEqual(metadata.state(address)["cfa"], [7, offset, None])
        for address in (99, 120, 129, 130, 140):
            with self.subTest(address=address):
                self.assertIsNone(metadata.state(address))
        self.assertIs(metadata.state(105), metadata.state(114))

    def test_tls_recovery_returns_verified_ir_for_reuse(self):
        ir = gtirb.IR(modules=[self.module])
        image = SimpleNamespace(tls={})
        command = ["ddisasm", "input", "--ir", "input.gtirb"]
        result = subprocess.CompletedProcess(command, 0, "")
        with tempfile.TemporaryDirectory() as temporary:
            with patch("gsfork_elf.pipeline.execute", return_value=result):
                with patch("gsfork_elf.pipeline.gtirb.IR.load_protobuf", return_value=ir) as load:
                    with patch("gsfork_elf.pipeline.verify_tls") as verify:
                        self.assertIs(run(command, Path(temporary) / "recovery.log",
                                          recovery_image=image), ir)
        load.assert_called_once_with("input.gtirb")
        verify.assert_called_once_with(self.module, image)

    def test_padding_normalization_preserves_layout_and_original_data(self):
        self.section.flags.add(gtirb.Section.Flag.Executable)
        original = gtirb.DataBlock(offset=0, size=8, byte_interval=self.interval)
        self.transform.input_data_ids.add(original.uuid)
        first = gtirb.DataBlock(offset=8, size=8, byte_interval=self.interval)
        second = gtirb.DataBlock(offset=16, size=8, byte_interval=self.interval)
        self.interval.symbolic_expressions.clear()
        before = (self.interval.address, self.interval.size,
                  {b: (b.offset, b.size) for b in self.interval.blocks})
        normalize_padding(self.module, self.transform)
        self.assertEqual(self.interval.contents[:24], bytes(8) + b"\x90" * 16)
        self.assertEqual(before, (self.interval.address, self.interval.size,
                                 {b: (b.offset, b.size) for b in self.interval.blocks}))
        self.assertEqual(len(self.transform.data), 2)
        for block in (first, second):
            self.assertEqual(len(list(block.references)), 2)

    def test_padding_normalization_rejects_references_and_nonzero_bytes(self):
        self.section.flags.add(gtirb.Section.Flag.Executable)
        block = gtirb.DataBlock(offset=8, size=8, byte_interval=self.interval)
        with self.assertRaisesRegex(RewriteError, "non-padding"):
            normalize_padding(self.module, self.transform)
        self.interval.symbolic_expressions.clear()
        symbol = gtirb.Symbol("referenced_padding", payload=block, module=self.module)
        with self.assertRaisesRegex(RewriteError, "non-padding"):
            normalize_padding(self.module, self.transform)
        symbol.module = None
        self.interval.contents = bytes(8) + b"\x01" + bytes(32759)
        with self.assertRaisesRegex(RewriteError, "non-padding"):
            normalize_padding(self.module, self.transform)

    def test_tool_timeout_kills_wrapped_grandchild(self):
        # Mirrors the pip ddisasm wrapper: the real tool is a grandchild that
        # inherits the output pipe.
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "pid"
            child = ("import os, subprocess, sys; p = subprocess.Popen([sys.executable, '-c', "
                     "'import time; time.sleep(60)']); open(sys.argv[1], 'w').write(str(p.pid)); p.wait()")
            started = time.monotonic()
            with self.assertRaises(subprocess.TimeoutExpired):
                execute([sys.executable, "-c", child, str(marker)], 2)
            self.assertLess(time.monotonic() - started, 20)
            grandchild = int(marker.read_text())
            for _ in range(100):
                try:
                    stat = Path(f"/proc/{grandchild}/stat").read_text()
                except OSError:
                    break
                if stat[stat.rindex(")") + 2] == "Z":
                    break
                time.sleep(0.05)
            else:
                self.fail("grandchild survived the tool timeout")

    def test_recovery_threads_environment(self):
        with patch.dict(os.environ, {"GSFORK_DDISASM_THREADS": "3"}):
            self.assertEqual(recovery_threads(), 3)
        for value in ("0", "-1", "many"):
            with patch.dict(os.environ, {"GSFORK_DDISASM_THREADS": value}):
                with self.assertRaisesRegex(RewriteError, "GSFORK_DDISASM_THREADS"):
                    recovery_threads()
        with patch.dict(os.environ):
            os.environ.pop("GSFORK_DDISASM_THREADS", None)
            self.assertEqual(recovery_threads(), len(os.sched_getaffinity(0)))

    def test_report_writer_round_trips(self):
        report = {"input": "a\u00e9\"b", "empty": [], "records": [{"address": 1, "kind": ["x", None]}, 2.5],
                  "nested": {"k": [1, 2]}, "flag": True}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            write_report(path, report)
            self.assertEqual(json.loads(path.read_text()), report)
            self.assertEqual(path.read_text().count("\n"), 10)

    def test_fast_elf_decoding_matches_pyelftools(self):
        from elftools.elf.elffile import ELFFile
        from elftools.elf.relocation import RelocationSection
        from elftools.elf.sections import SymbolTableSection
        from gsfork_elf.elf import _relocations, _symbols
        path = os.path.realpath(sys.executable)
        data = Path(path).read_bytes()
        with open(path, "rb") as stream:
            elf = ELFFile(stream)
            checked = 0
            for section in elf.iter_sections():
                if isinstance(section, SymbolTableSection):
                    strings = elf.get_section(section["sh_link"])
                    fast = _symbols(data, section, strings)
                    slow = list(section.iter_symbols())
                    self.assertEqual(len(fast), len(slow))
                    for a, b in zip(fast, slow):
                        self.assertEqual((a.name, a.value, a.size, a.type, a.bind, a.visibility, a.shndx),
                                         (b.name, b["st_value"], b["st_size"], b["st_info"]["type"],
                                          b["st_info"]["bind"], b["st_other"]["visibility"], b["st_shndx"]))
                    checked += len(fast)
                elif isinstance(section, RelocationSection):
                    fast = list(_relocations(data, section))
                    slow = [(r["r_offset"], r["r_info_sym"], r["r_info_type"],
                             r["r_addend"] if section.is_RELA() else 0) for r in section.iter_relocations()]
                    self.assertEqual(fast, slow)
                    checked += len(fast)
        self.assertGreater(checked, 0)

    def test_linear_interval_split_matches_upstream_and_is_scoped(self):
        import gtirb_rewriting.prepare as prepare

        def split(linear):
            module = gtirb.Module(name="split")
            section = gtirb.Section(name=".text", module=module)
            # initialized_size < size exercises the copying fallback as well.
            interval = gtirb.ByteInterval(address=0x2000, size=96, initialized_size=80,
                                          contents=bytes(range(80)), section=section)
            for offset, size in ((0, 4), (4, 8), (10, 2), (11, 5), (32, 16), (70, 20)):
                gtirb.CodeBlock(offset=offset, size=size, byte_interval=interval)
            symbol = gtirb.Symbol("target", payload=0x2000, module=module)
            for offset in (2, 12, 40, 72):
                interval.symbolic_expressions[offset] = gtirb.SymAddrConst(offset, symbol)
            if linear:
                with linear_interval_split():
                    parts = prepare.split_byte_interval(interval, {})
            else:
                parts = prepare.split_byte_interval(interval, {})
            return [(part.address, part.size, part.initialized_size, bytes(part.contents),
                     sorted((b.offset, b.size) for b in part.blocks),
                     sorted((o, e.offset) for o, e in part.symbolic_expressions.items())) for part in parts]

        property_before = gtirb.ByteInterval.initialized_size
        self.assertEqual(split(True), split(False))
        self.assertEqual(len(split(True)), 4)
        self.assertIs(gtirb.ByteInterval.initialized_size, property_before)
        with linear_interval_split():
            pass
        self.assertEqual(prepare.split_byte_interval.__module__, "gtirb_rewriting.intervalutils")
        interval = gtirb.ByteInterval(contents=b"abcd")
        alias = interval.contents
        interval.initialized_size = 2
        self.assertEqual(bytes(alias), b"abcd")

    def _wait_gone(self, pid):
        for _ in range(200):
            try:
                stat = Path(f"/proc/{pid}/stat").read_text()
            except OSError:
                return True
            if stat[stat.rindex(")") + 2] == "Z":
                return True
            time.sleep(0.05)
        return False

    def test_tool_memory_budget_kills_tool(self):
        hog = "import time; data = bytearray(400 << 20); time.sleep(60)"
        started = time.monotonic()
        with self.assertRaisesRegex(ToolMemoryExceeded, "GSFORK_TOOL_MEMORY=100 MiB"):
            execute([sys.executable, "-c", hog], 60, memory_limit=100)
        self.assertLess(time.monotonic() - started, 20)
        with patch.dict(os.environ, {"GSFORK_TOOL_MEMORY": "2048"}):
            self.assertEqual(tool_memory_limit(), 2048)
        for value in ("0", "8G", "-5"):
            with patch.dict(os.environ, {"GSFORK_TOOL_MEMORY": value}):
                with self.assertRaisesRegex(RewriteError, "GSFORK_TOOL_MEMORY"):
                    tool_memory_limit()

    def test_tool_dies_when_rewriter_is_killed(self):
        # A harness timeout SIGKILLs the rewriter itself; its tool must not
        # survive as an orphan.
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "pid"
            rewriter = ("import sys; sys.path.insert(0, sys.argv[2]); from gsfork_elf.pipeline import execute; "
                        "execute(['sh', '-c', 'echo $$ > ' + sys.argv[1] + '; exec sleep 60'], 60)")
            process = subprocess.Popen([sys.executable, "-c", rewriter, str(marker),
                                        str(Path(__file__).resolve().parents[1])])
            for _ in range(200):
                if marker.exists() and marker.read_text().strip():
                    break
                time.sleep(0.05)
            tool_pid = int(marker.read_text())
            process.kill()
            process.wait()
            self.assertTrue(self._wait_gone(tool_pid), "tool survived its killed parent")

    def test_bundled_tools_run_without_python_wrapper(self):
        for name in ("ddisasm", "gtirb-pprinter"):
            path = tool(name)
            with open(path, "rb") as stream:
                self.assertEqual(stream.read(4), b"\x7fELF", f"{name} resolved to wrapper {path}")


if __name__ == "__main__":
    unittest.main()
