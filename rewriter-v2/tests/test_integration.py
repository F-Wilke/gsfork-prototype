import copy
import hashlib
import json
import resource
import signal
import subprocess
import tempfile
import unittest
from pathlib import Path

from iced_x86 import Decoder

from gsfork_elf.elf import Image
from gsfork_elf.benchmark import compare
from gsfork_elf.errors import RewriteError
from gsfork_elf.metadata import Metadata, Reader
from gsfork_elf.pipeline import rewrite
from gsfork_elf.policy import Runtime
from gsfork_elf.validator import validate_artifact


FIXTURES = Path(__file__).parent / "fixtures"
TRUST = ("libstdc++.so.6", "libgcc_s.so.1", "libc.so.6")


def command(args, *, success=True):
    result = subprocess.run(list(map(str, args)), capture_output=True, text=True, timeout=120,
                            preexec_fn=lambda: resource.setrlimit(resource.RLIMIT_CORE, (0, 0)))
    if success and result.returncode:
        raise AssertionError(f"{args}: exit {result.returncode}\n{result.stdout}\n{result.stderr}")
    return result


class IntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="gsfork-tests-")
        cls.work = Path(cls.temp.name)
        cls.exceptions = cls.work / "exceptions"
        command(["g++", "-O2", "-g", "-fno-omit-frame-pointer",
                 FIXTURES / "exceptions.cpp", "-o", cls.exceptions])
        cls.output = cls.work / "exceptions.gs"
        cls.report = rewrite(cls.exceptions, cls.output, trusted_libraries=TRUST)
        cls.kernels = cls.work / "kernels.so"
        command(["gcc", "-shared", "-fPIC", "-O2", "-ftls-model=initial-exec", "-Wl,-z,now",
                 FIXTURES / "kernels.S", FIXTURES / "ifunc.c", FIXTURES / "tls.c", "-o", cls.kernels])
        cls.kernel_output = cls.work / "kernels.gs.so"
        cls.kernel_report = rewrite(cls.kernels, cls.kernel_output, runtime=Runtime(-16, -8),
                                    trusted_libraries=TRUST)
        cls.runtime = cls.work / "runtime"
        command(["gcc", "-O2", "-g", "-Wall", "-Wextra", "-Werror", "-fno-stack-protector",
                 FIXTURES / "runtime.c", FIXTURES / "invoke.S", "-ldl", "-o", cls.runtime])

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_linked_cpp_roundtrip_and_rewrite(self):
        original = command([self.exceptions]).stdout
        self.assertEqual(original, "catch-cleanup-unwind-ok\nfini-ok\n")
        for binary in (Path(str(self.output) + ".gsfork") / "baseline", self.output):
            self.assertEqual(command([binary]).stdout, original)
        image = Image(self.exceptions)
        self.assertIsNone(image.elf.get_section_by_name(".rela.text"))
        self.assertGreater(self.report["validation"]["exception_call_sites"], 0)
        self.assertGreater(self.report["validation"]["generated_plt_slots"], 0)
        persisted = json.loads(Path(str(self.output) + ".gsfork/report.json").read_text())
        self.assertEqual(validate_artifact(self.output, persisted), self.report["validation"])

    def test_exec_and_stripped_pie(self):
        for pie, stripped in ((False, False), (True, True)):
            with self.subTest(pie=pie, stripped=stripped):
                source = self.work / f"variant-{pie}"
                command(["g++", "-O2", "-fno-omit-frame-pointer",
                         "-pie" if pie else "-no-pie", FIXTURES / "exceptions.cpp", "-o", source])
                if stripped:
                    command(["strip", "--strip-all", source])
                    self.assertIsNone(Image(source).elf.get_section_by_name(".symtab"))
                baseline = self.work / f"baseline-{pie}"
                rewrite(source, baseline, baseline=True)
                rewritten = self.work / f"gs-{pie}"
                report = rewrite(source, rewritten, trusted_libraries=TRUST)
                for binary in (baseline, rewritten):
                    self.assertEqual(command([binary]).stdout, command([source]).stdout)
                self.assertEqual(report["mode"], "gs")

    def test_versioned_shared_library_initialization(self):
        source, loader = self.work / "versioned.so", self.work / "loader"
        command(["gcc", "-O2", "-fPIC", "-shared", "-Wl,-soname,libgsfixture.so",
                 "-Wl,--version-script=" + str(FIXTURES / "shared.map"),
                 FIXTURES / "shared.c", "-o", source])
        command(["gcc", "-O2", FIXTURES / "loader.c", "-ldl", "-o", loader])
        rewritten = self.work / "versioned.gs.so"
        report = rewrite(source, rewritten, trusted_libraries=TRUST)
        self.assertTrue(report["input_version_definitions"])
        for binary in (source, Path(str(rewritten) + ".gsfork") / "baseline", rewritten):
            self.assertEqual(command([loader, binary]).stdout, "shared-fini-ok\n")

    def test_distinct_versioned_symbol_addresses(self):
        source, output, loader = self.work / "versions.so", self.work / "versions.gs.so", self.work / "version-loader"
        command(["gcc", "-shared", "-fPIC", "-O2", FIXTURES / "version_alias.c",
                 "-Wl,--version-script=" + str(FIXTURES / "version_alias.map"), "-o", source])
        command(["gcc", "-O2", FIXTURES / "version_alias_loader.c", "-ldl", "-o", loader])
        self.assertEqual(len(Image(source).symbol_addresses["version_api"]), 2)
        rewrite(source, output)
        for binary in (source, Path(str(output) + ".gsfork") / "baseline", output):
            command([loader, binary])

    def test_symbolic_jump_table(self):
        source, rewritten = self.work / "switch", self.work / "switch.gs"
        command(["gcc", "-O2", FIXTURES / "switch.c", "-o", source])
        report = rewrite(source, rewritten, trusted_libraries=TRUST)
        self.assertTrue(any(e["expression"]["kind"] == "difference"
                            for block in report["data"] for e in block["expressions"]))
        self.assertEqual(command([source]).stdout, command([rewritten]).stdout)

    def test_initial_exec_tls_threads_and_layout(self):
        source, output, loader = self.work / "tls.so", self.work / "tls.gs.so", self.work / "tls-loader"
        command(["gcc", "-O2", "-fPIC", "-shared", "-ftls-model=initial-exec",
                 FIXTURES / "tls.c", "-o", source])
        command(["gcc", "-O2", "-Wall", "-Wextra", "-Werror", FIXTURES / "tls_loader.c",
                 "-pthread", "-ldl", "-o", loader])
        report = rewrite(source, output)
        self.assertTrue(report["input_tls"])
        for binary in (source, Path(str(output) + ".gsfork") / "baseline", output):
            self.assertEqual(command([loader, binary]).stdout, "tls-thread-ok\n")
        image = Image(output)
        data = bytearray(image.data)
        index = next(i for i, s in enumerate(image.elf.iter_segments()) if s["p_type"] == "PT_TLS")
        offset = image.elf["e_phoff"] + index * image.elf["e_phentsize"] + 40
        data[offset:offset + 8] = (image.tls["memory_size"] + 8).to_bytes(8, "little")
        tampered = self.work / "tls-bad-layout"
        tampered.write_bytes(data)
        report["output_sha256"] = hashlib.sha256(data).hexdigest()
        with self.assertRaisesRegex(RewriteError, "TLS layout"):
            validate_artifact(tampered, report)

    def test_duplicate_local_symbol_identity(self):
        source, rewritten = self.work / "duplicate", self.work / "duplicate.gs"
        command(["gcc", "-O0", FIXTURES / "duplicate_a.c", FIXTURES / "duplicate_b.c",
                 FIXTURES / "duplicate_main.c", "-o", source])
        image = Image(source)
        self.assertEqual(len(image.symbol_addresses["repeated"]), 2)
        with self.assertRaisesRegex(RewriteError, "ambiguous"):
            image.symbol("repeated")
        report = rewrite(source, rewritten, trusted_libraries=TRUST)
        self.assertEqual(len([s for s in report["local_symbol_renames"] if s["original"] == "repeated"]), 2)
        for binary in (source, Path(str(rewritten) + ".gsfork") / "baseline", rewritten):
            command([binary])

    def test_entryless_crt_loader_header_reference(self):
        source, baseline = self.work / "loader-entry", self.work / "loader-entry.native"
        command(["gcc", "-nostdlib", "-shared", "-Wl,-e,_start", "-Wl,--eh-frame-hdr",
                 "-Wl,--version-script=" + str(FIXTURES / "loader_entry.map"),
                 FIXTURES / "loader_entry.S", "-o", source])
        report = rewrite(source, baseline, baseline=True)
        self.assertEqual(report["mode"], "baseline")
        self.assertIn("__ehdr_start", report["linker_symbols"])
        self.assertTrue(Image(baseline).elf["e_entry"])
        command([source])
        command([baseline])
        gs = self.work / "loader-entry.gs"
        report = rewrite(source, gs)
        self.assertTrue(any(i["rule"] == "runtime-control" for i in report["locations"]))
        command([gs])

    def test_ifunc_resolvers_and_irelative_pointers(self):
        loader = self.work / "ifunc-loader"
        command(["gcc", "-Wall", "-Wextra", "-Werror", FIXTURES / "ifunc_loader.c", "-ldl", "-o", loader])
        for cet in (False, True):
            with self.subTest(cet=cet):
                source, rewritten = self.work / f"ifunc-{cet}.so", self.work / f"ifunc-{cet}.gs.so"
                flags = (["-fcf-protection=branch", "-Wl,-z,ibtplt",
                          "-Wl,--version-script=" + str(FIXTURES / "ifunc.map")] if cet else [])
                command(["gcc", "-O2", "-fPIC", "-shared", *flags, FIXTURES / "ifunc.c", "-o", source])
                report = rewrite(source, rewritten, trusted_libraries=TRUST)
                if cet:
                    self.assertIsNotNone(Image(rewritten).elf.get_section_by_name(".plt.sec"))
                self.assertTrue(report["input_resolvers"])
                addresses = {r["original"] for r in report["input_resolvers"]}
                self.assertTrue(any(i["original"] in addresses for i in report["locations"]))
                self.assertGreaterEqual(sum(r["type"] == 37 for r in Image(rewritten).relocations.values()), 2)
                for binary in (source, Path(str(rewritten) + ".gsfork") / "baseline", rewritten):
                    self.assertEqual(command([loader, binary]).stdout, "ifunc-ok\n")
                image = Image(rewritten)
                reloc_section = next(s for s in image.sections if s["sh_type"] == "SHT_RELA"
                                     and any(r["r_info_type"] == 37 for r in s.iter_relocations()))
                index = next(i for i, r in enumerate(reloc_section.iter_relocations()) if r["r_info_type"] == 37)
                offset = reloc_section["sh_offset"] + index * reloc_section["sh_entsize"] + 16
                data = bytearray(image.data)
                resolver = int.from_bytes(data[offset:offset + 8], "little")
                data[offset:offset + 8] = (resolver + 1).to_bytes(8, "little")
                tampered = self.work / f"ifunc-{cet}.tampered"
                tampered.write_bytes(data)
                report["output_sha256"] = hashlib.sha256(data).hexdigest()
                with self.assertRaisesRegex(RewriteError, "IRELATIVE|resolver|PLT reference"):
                    validate_artifact(tampered, report)

    def test_shared_nonzero_stack_strings_signals(self):
        wrapper = self.kernel_report["wrappers"][0]
        rep_offset = wrapper["phases"][5]["address"] - wrapper["begin"]
        for binary in (self.kernels, Path(str(self.kernel_output) + ".gsfork") / "baseline",
                       self.kernel_output):
            result = command([self.runtime, binary, "zero", 0])
            self.assertEqual(result.stdout, "runtime-ok cases=6144 faults=0 nested=0\n")
        shifted = command([self.runtime, self.kernel_output, "shift", rep_offset])
        self.assertEqual(shifted.stdout, "runtime-ok cases=6144 faults=1 nested=1\n")
        control = command([self.runtime, self.kernels, "shift", 0], success=False)
        self.assertEqual(control.returncode, -signal.SIGSEGV)

    def mutate(self, address, replacement, *, source=None, provenance=None):
        image = Image(source or self.output)
        section = image.section_at(address, len(replacement))
        data = bytearray(image.data)
        offset = section["sh_offset"] + address - section["sh_addr"]
        data[offset:offset + len(replacement)] = replacement
        destination = self.work / "tampered"
        destination.write_bytes(data)
        report = copy.deepcopy(provenance or self.report)
        report["output_sha256"] = hashlib.sha256(data).hexdigest()
        return destination, report

    def test_validator_rejects_uncovered_original_access(self):
        location = next(r for r in self.report["locations"] if r["rule"] == "gs")
        destination, report = self.mutate(location["address"], b"\x3e")
        with self.assertRaisesRegex(RewriteError, "segment override|uncovered"):
            validate_artifact(destination, report)

    def test_validator_rejects_uninstrumented_generated_plt(self):
        slot = next(r for r in self.report["generated"] if r["target"] is not None)
        destination, report = self.mutate(slot["address"], b"\x3e")
        with self.assertRaisesRegex(RewriteError, "GS PLT contract"):
            validate_artifact(destination, report)

    def test_validator_rejects_lock_suffix_bypass(self):
        source = Image(self.kernel_output)
        item = next(i for b in self.kernel_report["blocks"] for i in b["instructions"]
                    if i.get("lock_suffix_entry") and i["rule"] == "gs")
        address = next(i["address"] for i in self.kernel_report["locations"] if i["original"] == item["original"])
        self.assertEqual(source.read(address, 2), b"\xf0\x65")
        destination, report = self.mutate(address, b"\x65\xf0", source=self.kernel_output,
                                          provenance=self.kernel_report)
        with self.assertRaisesRegex(RewriteError, "LOCK-skipping"):
            validate_artifact(destination, report)

    def test_validator_rejects_uncovered_generated_padding(self):
        record = next(r for r in self.report["data"] if r.get("generated") and r["size"] >= 3)
        address = Image(self.output).symbol(record["begin"])
        destination, report = self.mutate(address, b"\x48\x8b\x07")
        with self.assertRaisesRegex(RewriteError, "uncovered code"):
            validate_artifact(destination, report)

    def test_validator_rejects_stale_frame_index(self):
        header = Image(self.output).elf.get_section_by_name(".eh_frame_hdr")
        destination, report = self.mutate(header["sh_addr"] + 4, b"\x00\x00\x00\x00")
        with self.assertRaisesRegex(RewriteError, "wrong frame section"):
            validate_artifact(destination, report)

    def test_validator_rejects_stale_rip_reference(self):
        image = Image(self.output)
        for location in self.report["locations"]:
            decoder = Decoder(64, image.read(location["address"], location["end"] - location["address"]),
                              ip=location["address"])
            ins = decoder.decode()
            if ins.is_ip_rel_memory_operand:
                offset = decoder.get_constant_offsets(ins).displacement_offset
                address = location["address"] + offset
                old = int.from_bytes(image.read(address, 4), "little")
                destination, report = self.mutate(address, ((old + 1) & 0xffffffff).to_bytes(4, "little"))
                with self.assertRaisesRegex(RewriteError, "reference"):
                    validate_artifact(destination, report)
                return
        self.fail("fixture did not exercise RIP-relative references")

    def test_validator_checks_immediate_beside_symbolic_memory(self):
        image = Image(self.output)
        for location in self.report["locations"]:
            decoder = Decoder(64, image.read(location["address"], location["end"] - location["address"]),
                              ip=location["address"])
            ins = decoder.decode()
            offsets = decoder.get_constant_offsets(ins)
            if ins.is_ip_rel_memory_operand and offsets.has_immediate:
                address = location["address"] + offsets.immediate_offset
                destination, report = self.mutate(address, bytes([image.read(address, 1)[0] ^ 1]))
                with self.assertRaisesRegex(RewriteError, "semantics changed"):
                    validate_artifact(destination, report)
                return
        self.fail("fixture did not exercise symbolic-memory immediates")

    def test_validator_rejects_stale_exception_landing_pad(self):
        image = Image(self.output)
        fde = next(f for f in Metadata(image).frames if f.lsda_pointer)
        reader = Reader(image, fde.lsda_pointer)
        self.assertEqual(reader.byte(), 0xff)
        if reader.byte() != 0xff:
            reader.leb()
        self.assertEqual(reader.byte(), 1)
        reader.leb()
        reader.leb()
        reader.leb()
        address = reader.address
        destination, report = self.mutate(address, bytes([image.read(address, 1)[0] ^ 1]))
        with self.assertRaisesRegex(RewriteError, "exception call sites"):
            validate_artifact(destination, report)

    def test_no_success_artifact_on_failure(self):
        output = self.work / "must-not-exist"
        with self.assertRaisesRegex(RewriteError, "explicitly declared trusted"):
            rewrite(self.exceptions, output)
        self.assertFalse(output.exists())
        with self.assertRaisesRegex(RewriteError, "requires explicit"):
            rewrite(self.kernels, output, trusted_libraries=TRUST)
        self.assertFalse(output.exists())
        self.assertFalse(Path(str(output) + ".gsfork").exists())
        with self.assertRaisesRegex(RewriteError, "already exists"):
            rewrite(self.exceptions, self.output, trusted_libraries=TRUST)

    def test_performance_controls(self):
        results = compare(self.exceptions, Path(str(self.output) + ".gsfork") / "baseline",
                          self.output, samples=3)
        self.assertEqual(results["samples"], 3)
        self.assertTrue(all(results[name]["median_ns"] > 0 for name in ("original", "baseline", "gs")))


if __name__ == "__main__":
    unittest.main()
