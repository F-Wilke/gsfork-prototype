import unittest

from iced_x86 import Decoder, Register

from mibench_rewrite import Unsupported, transform


class MiBenchRewriteTests(unittest.TestCase):
    def test_rewrites_only_selected_data_memory(self):
        code = bytes.fromhex(
            "8b07"              # mov eax,[rdi]
            "8b01"              # mov eax,[rcx]
            "488d4704"          # lea rax,[rdi+4]
            "8b0500000000"      # mov eax,[rip]
            "c3"
        )
        rule = {
            "bases": {Register.RDI},
            "offsets": set(),
            "expected": 1,
        }
        rewritten, edits = transform(code, 0x1000, rule)
        instructions = list(Decoder(64, rewritten, ip=0x1000))
        self.assertEqual(len(edits), 1)
        self.assertEqual(instructions[0].segment_prefix, Register.GS)
        self.assertTrue(all(
            instruction.segment_prefix == Register.NONE
            for instruction in instructions[1:]
        ))

    def test_requires_expected_operand_count(self):
        rule = {
            "bases": {Register.RDI},
            "offsets": set(),
            "expected": 2,
        }
        with self.assertRaises(Unsupported):
            transform(bytes.fromhex("8b07c3"), 0x1000, rule)

    def test_rejects_unreviewed_function_bytes(self):
        rule = {
            "bases": {Register.RDI},
            "offsets": set(),
            "expected": 1,
            "sha256": "0" * 64,
        }
        with self.assertRaises(Unsupported):
            transform(bytes.fromhex("8b07c3"), 0x1000, rule)

    def test_reencodes_external_call_and_selected_load(self):
        code = bytes.fromhex("e8fb0f00008b07c3")
        rule = {
            "bases": {Register.RDI},
            "offsets": set(),
            "expected": 1,
        }
        rewritten, _ = transform(code, 0x1000, rule)
        instructions = list(Decoder(64, rewritten, ip=0x1000))
        self.assertEqual(instructions[0].near_branch_target, 0x2000)
        self.assertEqual(instructions[1].segment_prefix, Register.GS)


if __name__ == "__main__":
    unittest.main()
