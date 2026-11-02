import unittest

from iced_x86 import Decoder

from gsfork_elf.compiler import normalize_assembly
from gsfork_elf.errors import RewriteError
from gsfork_elf.policy import Runtime, decode
from gsfork_elf.validator import check_leave, shape


class EncodingTests(unittest.TestCase):
    def test_exact_leave_expansion(self):
        original = decode(b"\xc9", 0)[0]
        for offset in (16, -24, -(1 << 31), (1 << 31) - 8):
            with self.subTest(offset=offset):
                scratch = (-64 & 0xFFFFFFFF).to_bytes(4, "little")
                data = (bytes.fromhex("6448890425") + scratch + bytes.fromhex("64488b0425")
                        + (offset & 0xFFFFFFFF).to_bytes(4, "little")
                        + bytes.fromhex("488d64050064488b0425") + scratch + b"\x5d")
                runtime = Runtime(-64, -56, offset)
                check_leave(decode(data, 0), runtime, original)
                with self.assertRaisesRegex(RewriteError, "leave expansion"):
                    check_leave(decode(data[:-1] + b"\x58", 0), runtime, original)
                old = (bytes.fromhex("4889ec6448032425")
                       + (offset & 0xFFFFFFFF).to_bytes(4, "little") + b"\x5d")
                with self.assertRaisesRegex(RewriteError, "leave expansion"):
                    check_leave(decode(old, 0), runtime, original)

    def test_exact_printer_syntax_fixes(self):
        self.assertEqual(normalize_assembly(" rstorssp DWORD PTR [RSI-8]\n xabort -1\n"),
                         " rstorssp QWORD PTR [RSI-8]\n xabort 255")
        self.assertEqual(normalize_assembly("xabort -256\n"), "xabort -256\n")
        self.assertEqual(normalize_assembly("mov eax,-1\n"), "mov eax,-1\n")

    def test_equivalent_evex_compare_encodings(self):
        general = Decoder(64, bytes.fromhex("62f37d203f0700")).decode()
        dedicated = Decoder(64, bytes.fromhex("62f17d207407")).decode()
        unequal = Decoder(64, bytes.fromhex("62f37d203f0704")).decode()
        self.assertEqual(str(general), str(dedicated))
        self.assertEqual(shape(general, None), shape(dedicated, None))
        self.assertNotEqual(shape(general, None), shape(unequal, None))


if __name__ == "__main__":
    unittest.main()
