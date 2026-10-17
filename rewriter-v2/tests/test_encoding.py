import unittest

from iced_x86 import Decoder

from gsfork_elf.compiler import normalize_assembly
from gsfork_elf.validator import shape


class EncodingTests(unittest.TestCase):
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
