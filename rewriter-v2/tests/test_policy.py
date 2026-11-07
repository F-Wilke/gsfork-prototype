import unittest

from gsfork_elf.errors import RewriteError
from gsfork_elf.policy import Runtime, classify, decode


class PolicyTests(unittest.TestCase):
    def rule(self, hex_bytes, **kwargs):
        ins = decode(bytes.fromhex(hex_bytes), 0x1000)
        self.assertEqual(len(ins), 1)
        return classify(ins[0], Runtime(-16, -8), **kwargs)

    def test_explicit_memory(self):
        for code in ("488b07", "488907", "f048830701", "488b442408",
                     "488b4508", "488b0500000000", "ff10", "ff20",
                     "ff30", "8f0424", "67488b00", "0f1007"):
            with self.subTest(code=code):
                self.assertEqual(self.rule(code), "gs")
                with self.assertRaisesRegex(RewriteError, "uncovered"):
                    self.rule(code, output=True)
                self.assertEqual(self.rule("65" + code, output=True), "gs")

    def test_native_alias_and_logical_address(self):
        for code in ("50", "58", "9c", "9d", "c3", "c9", "ffd0", "ffe0",
                     "e800000000", "eb00", "fc", "fd", "3effe0", "3effd0"):
            with self.subTest(code=code):
                self.assertEqual(self.rule(code), "native")
        self.assertEqual(self.rule("488d0500000000"), "logical")
        self.assertEqual(self.rule("2e0f1f840000000000"), "padding")
        self.assertEqual(self.rule("64488b042500000000"), "fs")
        self.assertEqual(self.rule("f3a4"), "rep-movsb")
        for code in ("a4", "66a5", "a5", "48a5", "f366a5", "f3a5", "f348a5"):
            self.assertEqual(self.rule(code), "movs")
        for code in ("aa", "66ab", "ab", "48ab", "f3aa", "f366ab", "f3ab", "f348ab"):
            self.assertEqual(self.rule(code), "stos")
        self.assertEqual(self.rule("0f05"), "runtime-control")

    def test_rejections(self):
        for code in ("65488b07", "2e488b07", "f3ac",
                     "f3a6", "f2ae", "67f3a4", "64f3a4", "d7", "c8000000",
                     "66c9", "6650", "6658", "c20800", "0f01f8",
                     "0f0117", "0fa9", "8ee0", "ff18", "f2ff10", "0f20c0"):
            with self.subTest(code=code), self.assertRaises(RewriteError):
                self.rule(code)
        # Memory-indirect NOTRACK is converted to GS (IBT dropped); never valid output.
        self.assertEqual(self.rule("3eff10"), "gs")
        with self.assertRaises(RewriteError):
            self.rule("3eff10", output=True)

    def test_scratch_validation(self):
        for runtime in (Runtime(0, None), Runtime(0, 4), Runtime(1 << 32, 16),
                        Runtime(parent_stack_offset=1 << 31),
                        Runtime(parent_stack_offset=-(1 << 31) - 1),
                        Runtime(-16, -8, -12), Runtime(-16, -8, -4)):
            with self.subTest(runtime=runtime), self.assertRaises(RewriteError):
                runtime.check()
        with self.assertRaisesRegex(RewriteError, "requires explicit"):
            classify(decode(b"\xf3\xa4", 0)[0])
        for code in (b"\x0f", b"\x65" * 15 + b"\x90"):
            with self.assertRaises(RewriteError):
                decode(code, 0)

    def test_leave_runtime_mode(self):
        runtime = Runtime(-16, -8, 720)
        self.assertEqual(classify(decode(b"\xc9", 0)[0], runtime), "leave")
        self.assertEqual(classify(decode(b"\xc9", 0)[0]), "native")
        self.assertIn("movq %fs:720, %rax", runtime.leave())
        self.assertIn("leaq (%rbp,%rax), %rsp", runtime.leave())
        with self.assertRaisesRegex(RewriteError, "scratch-rax"):
            classify(decode(b"\xc9", 0)[0], Runtime(parent_stack_offset=720))
        for code in ("66c9", "67c9", "48c9", "64c9", "f3c9"):
            with self.subTest(code=code), self.assertRaises(RewriteError):
                classify(decode(bytes.fromhex(code), 0)[0], runtime)


if __name__ == "__main__":
    unittest.main()
