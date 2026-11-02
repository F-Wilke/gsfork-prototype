import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from gsfork_elf.cli import runtime_slots
from gsfork_elf.errors import RewriteError

LAYOUT = r"""
#include <stddef.h>
struct pthread {
    char header[704];
    void *sandbox_offset;
    unsigned long sandbox_scratch;
    void *parent_stack_offset;
};
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
                  "parent_stack_field": None, "parent_stack_offset": None, "tcb_layout": self.layout}
        return SimpleNamespace(**{**values, **overrides})

    def test_layout_from_separate_glibc(self):
        runtime, layout = runtime_slots(self.args())
        self.assertEqual((runtime.scratch_rax, runtime.sandbox_offset), (712, 704))
        self.assertEqual(layout["source"], str(self.layout.resolve()))
        self.assertEqual(len(layout["source_sha256"]), 64)

    def test_program_without_layout_explains_tcb_layout(self):
        with self.assertRaisesRegex(RewriteError, "--tcb-layout"):
            runtime_slots(self.args(tcb_layout=None))

    def test_parent_stack_field(self):
        runtime, layout = runtime_slots(self.args(parent_stack_field="parent_stack_offset"))
        self.assertEqual(runtime.parent_stack_offset, 720)
        self.assertEqual(layout["parent_stack_field"], "parent_stack_offset")
        runtime.check()
        runtime, _ = runtime_slots(self.args(scratch_field=None, sandbox_field=None,
                                             parent_stack_field="parent_stack_offset"))
        self.assertEqual(runtime.parent_stack_offset, 720)
        runtime.check()

    def test_numeric_parent_stack_slot(self):
        runtime, layout = runtime_slots(self.args(scratch_field=None, sandbox_field=None,
                                                  tcb_layout=None, parent_stack_offset=-24))
        self.assertEqual(runtime.parent_stack_offset, -24)
        self.assertIsNone(layout)
        runtime.check()

    def test_numeric_slots_have_no_layout(self):
        runtime, layout = runtime_slots(self.args(scratch_field=None, sandbox_field=None, tcb_layout=None,
                                                  scratch_rax=-16, sandbox_offset=-8))
        self.assertEqual((runtime.scratch_rax, runtime.sandbox_offset, layout), (-16, -8, None))

    def test_rejects_ambiguous_or_unused_options(self):
        for overrides in ({"scratch_rax": -16}, {"scratch_field": None, "sandbox_field": None},
                          {"sandbox_field": "missing"},
                          {"parent_stack_field": "missing"},
                          {"parent_stack_field": "parent_stack_offset", "parent_stack_offset": 720}):
            with self.subTest(overrides=overrides), self.assertRaises(RewriteError):
                runtime_slots(self.args(**overrides))


if __name__ == "__main__":
    unittest.main()
