import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from gsfork_elf.cli import runtime_slots
from gsfork_elf.errors import RewriteError

LAYOUT = r"""
#include <stddef.h>
struct pthread { char header[704]; void *sandbox_offset; unsigned long sandbox_scratch; };
struct pthread layout_anchor;
"""


class RuntimeSlotTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        work = Path(cls.temporary.name)
        (work / "layout.c").write_text(LAYOUT)
        (work / "program.c").write_text("int main(void) { return 0; }\n")
        cls.layout = work / "layout.so"
        cls.program = work / "program"
        subprocess.run(["gcc", "-g", "-shared", "-fPIC", work / "layout.c", "-o", cls.layout], check=True)
        subprocess.run(["gcc", "-g", work / "program.c", "-o", cls.program], check=True)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def args(self, **overrides):
        values = {"input": self.program, "scratch_rax": None, "sandbox_offset": None,
                  "scratch_field": "sandbox_scratch", "sandbox_field": "sandbox_offset",
                  "tcb_layout": self.layout}
        return SimpleNamespace(**{**values, **overrides})

    def test_layout_from_separate_glibc(self):
        runtime, layout = runtime_slots(self.args())
        self.assertEqual((runtime.scratch_rax, runtime.sandbox_offset), (712, 704))
        self.assertEqual(layout["source"], str(self.layout.resolve()))
        self.assertEqual(len(layout["source_sha256"]), 64)

    def test_program_without_layout_explains_tcb_layout(self):
        with self.assertRaisesRegex(RewriteError, "--tcb-layout"):
            runtime_slots(self.args(tcb_layout=None))

    def test_numeric_slots_have_no_layout(self):
        runtime, layout = runtime_slots(self.args(scratch_field=None, sandbox_field=None, tcb_layout=None,
                                                  scratch_rax=-16, sandbox_offset=-8))
        self.assertEqual((runtime.scratch_rax, runtime.sandbox_offset, layout), (-16, -8, None))

    def test_rejects_ambiguous_or_unused_options(self):
        for overrides in ({"scratch_rax": -16}, {"scratch_field": None, "sandbox_field": None},
                          {"sandbox_field": "missing"}):
            with self.subTest(overrides=overrides), self.assertRaises(RewriteError):
                runtime_slots(self.args(**overrides))


if __name__ == "__main__":
    unittest.main()
