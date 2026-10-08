import unittest
from iced_x86 import Decoder, Register, FlowControl, Mnemonic
from rewrite import transform, Unsupported

class RewriteTests(unittest.TestCase):
    def test_load_store_and_lea(self):
        code=bytes.fromhex('488b07488907488d4708c3')
        out, edits=transform(code,0x1000)
        ins=list(Decoder(64,out,ip=0x1000))
        self.assertEqual(len(edits),2)
        self.assertEqual([i.segment_prefix for i in ins], [Register.GS,Register.GS,Register.NONE,Register.NONE])
        self.assertEqual(len(out),len(code)+2)
    def test_short_branch_expands_and_retargets(self):
        code=b'\x74\x7e'+bytes.fromhex('488b07')*42+b'\xc3'
        out,_=transform(code,0x1000)
        ins=list(Decoder(64,out,ip=0x1000))
        self.assertEqual(ins[0].len,6)
        self.assertEqual(ins[0].near_branch_target,ins[-1].ip)
        self.assertEqual(ins[-1].mnemonic,Mnemonic.RET)
    def test_reencoding_control(self):
        code=bytes.fromhex('488b074883c708c3')
        out,_=transform(code,0x1000,False)
        self.assertEqual(code,out)
    def test_prefixed_alignment_nop(self):
        code=bytes.fromhex('66662e0f1f840000000000c3')
        out,edits=transform(code,0x1000)
        self.assertEqual(code,out)
        self.assertEqual(edits,[])
    def test_unsupported_patterns(self):
        patterns = {
            'push':'50c3', 'pop':'58c3', 'stack_load':'488b0424c3',
            'stack_pointer_copy':'4889e0c3', 'frame_pointer':'488b4500c3',
            'string':'f3a4c3', 'tls':'64488b042500000000c3',
            'already_gs':'65488b07c3', 'rip':'488b0500000000c3',
            'call':'e800000000c3', 'indirect_jump':'ffe0',
            'syscall':'0f05c3', 'gs_write':'f3480faed8c3',
            'outside_branch':'eb7fc3', 'middle_branch':'ebff',
            'invalid':'0f', 'ret_imm':'c20800'}
        for name,code in patterns.items():
            with self.subTest(name=name), self.assertRaises(Unsupported):
                transform(bytes.fromhex(code),0x1000)
