from dataclasses import dataclass

from iced_x86 import (
    Code, Decoder, FlowControl, InstructionInfoFactory, Mnemonic, OpKind,
    Register,
)

from .errors import RewriteError


MNEMONICS = {value: name.lower() for name, value in vars(Mnemonic).items()
             if name.isupper() and isinstance(value, int)}
ORDINARY = set("""
adc add and andn bsf bsr bswap bt btc btr bts bzhi clc cld clflush clflushopt
cmc cmp cmpxchg cmpxchg8b cmpxchg16b cpuid cwd cdq cqo cwde cdqe cbw
dec div endbr64 hlt idiv imul inc int3 lahf lfence lzcnt mfence mov movabs movbe
movsx movsxd movzx mul mulx neg nop not or pause popcnt rcl rcr ror rol rorx
sahf sal sar sarx sbb sfence shl shld shlx shr shrd shrx stc std sub test
tzcnt ud2 xadd xchg xor
addpd addps addsd addss andpd andps andnpd andnps comisd comiss cvtdq2pd
cvtdq2ps cvtpd2ps cvtps2pd cvtsd2si cvtsd2ss cvtsi2sd cvtsi2ss cvtss2sd
cvtss2si cvttsd2si cvttss2si divpd divps divsd divss ldmxcsr stmxcsr
maxpd maxps maxsd maxss minpd minps minsd minss movapd movaps movd movdqa
movdqu movhpd movhps movlpd movlps movmskpd movmskps movntdq movnti
movntpd movntps movq movsd movss movupd movups mulpd mulps mulsd mulss
orpd orps packssdw packsswb packuswb paddb paddd paddq paddw pand pandn
pcmpeqb pcmpeqd pcmpeqw pcmpgtb pcmpgtd pcmpgtw pextrw pinsrw pmovmskb
pmulhuw pmulhw pmullw pmuludq por pshufd pshufhw pshuflw pshufw pslld
pslldq psllq psllw psrad psraw psrld psrldq psrlq psrlw psubb psubd psubq
psubw punpckhbw punpckhdq punpckhqdq punpckhwd punpcklbw punpckldq
punpcklqdq punpcklwd pxor shufpd shufps sqrtpd sqrtps sqrtsd sqrtss
subpd subps subsd subss ucomisd ucomiss unpckhpd unpckhps unpcklpd
unpcklps xorpd xorps vzeroupper vzeroall
""".split())
ORDINARY |= {"cmov" + suffix for suffix in
             "a ae b be e g ge l le ne no np ns o p s".split()}
ORDINARY |= {"set" + suffix for suffix in
             "a ae b be e g ge l le ne no np ns o p s".split()}
ORDINARY |= set("""
palignr pminub pmaxub pminud pcmpistri pshufb lddqu cmpsd
prefetcht0 prefetcht1 prefetchnta
vpxor vmovdqu vpcmpeqb vpminub vpmovmskb vmovdqa vmovq vmovd
vpbroadcastb vpor vmovdqa64 vpxorq vpcmpb kmovd vmovdqu64 kord
kortestd vptestmb vporq kmovb vpand kunpckdq kmovq ktestd vpcmpgtb
vpandn vpsubb vpcmpistri vpslldq vpalignr vpsrldq vpbroadcastd
vpminud vpcmpd vptestmd kunpckbw vmovaps vpcmpeqd vpternlogd vmovdqu32
vmovntdq vmovups vpshufb vbroadcastss vmovdqu8 vpcmpub vpcmpeqq
fld fstp fldz fcomip fchs fnstenv fldenv fnstcw fucomi fabs fxch
fucomip fxam fnstsw fild fsubp fcomi fdiv fsubrp fld1 fmulp fscale
fmul fadd fldcw faddp fcmovbe fdivp wait
fxsave fxrstor xsave xsavec xrstor xgetbv rdtsc rdtscp
xbegin xabort xend xtest
""".split())
RUNTIME_CONTROL = {"rdfsbase", "wrfsbase", "syscall", "rdpkru", "wrpkru",
                   "rdsspq", "incsspq", "rstorssp", "saveprevssp"}
BRANCHES = {"j" + suffix for suffix in
            "a ae b be e g ge l le ne no np ns o p s rcxz ecxz".split()}
BRANCHES |= {"jmp", "call", "loop", "loope", "loopne"}
STRINGS = {getattr(Mnemonic, name) for name in
           ("MOVSB", "MOVSW", "MOVSD", "MOVSQ", "STOSB", "STOSW", "STOSD",
            "STOSQ", "LODSB", "LODSW", "LODSD", "LODSQ", "CMPSB", "CMPSW",
            "CMPSD", "CMPSQ", "SCASB", "SCASW", "SCASD", "SCASQ")}
STRING_KINDS = {OpKind.MEMORY_SEG_SI, OpKind.MEMORY_SEG_ESI,
                OpKind.MEMORY_SEG_RSI, OpKind.MEMORY_SEG_DI,
                OpKind.MEMORY_SEG_EDI, OpKind.MEMORY_SEG_RDI,
                OpKind.MEMORY_ESDI, OpKind.MEMORY_ESEDI, OpKind.MEMORY_ESRDI}
INFO = InstructionInfoFactory()


@dataclass(frozen=True)
class Runtime:
    scratch_rax: int | None = None
    sandbox_offset: int | None = None

    def check(self):
        values = (self.scratch_rax, self.sandbox_offset)
        if values == (None, None):
            return
        if any(v is None or not -(1 << 31) <= v <= (1 << 31) - 8 for v in values):
            raise RewriteError("scratch-rax and sandbox-offset must both be signed disp32 slots")
        if abs(self.scratch_rax - self.sandbox_offset) < 8:
            raise RewriteError("FS scratch and sandbox-offset slots must not overlap")

    def movsb(self):
        self.check()
        if self.scratch_rax is None:
            raise RewriteError("string instrumentation requires explicit FS scratch-rax and sandbox-offset slots")
        return f"""
movq %rax, %fs:{self.scratch_rax}
lahf
seto %al
addq %fs:{self.sandbox_offset}, %rdi
addq %fs:{self.sandbox_offset}, %rsi
rep movsb
subq %fs:{self.sandbox_offset}, %rdi
subq %fs:{self.sandbox_offset}, %rsi
addb $0x7f, %al
sahf
movq %fs:{self.scratch_rax}, %rax
"""

    def string(self, instruction):
        family, opcode = string_form(instruction)
        opcode = opcode.replace("movsd", "movsl").replace("stosd", "stosl")
        if family == "movs":
            return self.movsb().replace("rep movsb", opcode)
        self.movsb()
        return f"""
movq %rdx, %fs:{self.scratch_rax}
movq %rax, %rdx
lahf
seto %al
xchgq %rax, %rdx
addq %fs:{self.sandbox_offset}, %rdi
{opcode}
subq %fs:{self.sandbox_offset}, %rdi
xchgq %rax, %rdx
addb $0x7f, %al
sahf
movq %rdx, %rax
movq %fs:{self.scratch_rax}, %rdx
"""


def string_form(ins):
    name = MNEMONICS[ins.mnemonic]
    family = name[:4]
    if (family not in ("movs", "stos") or ins.has_repne_prefix
            or ins.segment_prefix != Register.NONE or ins.op0_kind != OpKind.MEMORY_ESRDI
            or family == "movs" and ins.op1_kind != OpKind.MEMORY_SEG_RSI):
        raise RewriteError("unsupported exact string form (only 64-bit-address MOVS/STOS)")
    return family, ("rep " if ins.has_rep_prefix else "") + name


def decode(data, address):
    instructions = list(Decoder(64, data, ip=address))
    if any(i.is_invalid for i in instructions) or sum(i.len for i in instructions) != len(data):
        raise RewriteError(f"invalid or truncated x86-64 instruction at 0x{address:x}")
    return instructions


def classify(ins, runtime=Runtime(), *, output=False):
    name = MNEMONICS[ins.mnemonic]
    if ins.segment_prefix == Register.GS and not output:
        raise RewriteError("pre-existing GS segment override")
    explicit = any(ins.op_kind(n) == OpKind.MEMORY for n in range(ins.op_count))
    string = (ins.mnemonic in STRINGS
              and any(ins.op_kind(n) in STRING_KINDS for n in range(ins.op_count)))
    if string:
        family, opcode = string_form(ins)
        runtime.string(ins)
        return "rep-movsb" if opcode == "rep movsb" else family
    if ins.is_privileged and name != "hlt":
        raise RewriteError("unsupported privileged instruction")
    if any(ins.op_kind(n) == OpKind.REGISTER
           and ins.op_register(n) in (Register.CS, Register.DS, Register.ES,
                                      Register.FS, Register.GS, Register.SS)
           for n in range(ins.op_count)):
        raise RewriteError("explicit segment-register manipulation is unsupported")
    if ins.has_repne_prefix or (ins.has_rep_prefix and name not in ("pause", "ret")):
        raise RewriteError("unsupported repetition/BND prefix on non-string instruction")
    if name == "call" and ins.code not in (Code.CALL_REL32_64, Code.CALL_RM64):
        raise RewriteError("unsupported nonstandard call form")
    if name == "jmp" and ins.code not in (Code.JMP_REL8_64, Code.JMP_REL32_64, Code.JMP_RM64):
        raise RewriteError("unsupported nonstandard jump form")
    if ins.segment_prefix not in (Register.NONE, Register.FS, Register.GS):
        # GNU alignment NOPs conventionally carry an ignored CS override.
        notrack_register = (ins.segment_prefix == Register.DS and name in ("call", "jmp")
                            and ins.op0_kind == OpKind.REGISTER)
        if not notrack_register and (name != "nop" or ins.segment_prefix != Register.CS):
            raise RewriteError("unsupported explicit segment override")
    if name in ("lea", "nop"):
        return "logical" if name == "lea" else "padding"
    if name in ("push", "pop", "pushfq", "popfq", "ret", "leave"):
        if ins.stack_pointer_increment not in (-8, 8) and name != "leave":
            raise RewriteError("unsupported nonstandard stack form")
        if name == "leave" and ins.code != Code.LEAVEQ:
            raise RewriteError("unsupported leave form")
    elif name not in ORDINARY and name not in BRANCHES and name not in RUNTIME_CONTROL:
        raise RewriteError(f"unsupported instruction {name}")
    if ins.flow_control in (FlowControl.INTERRUPT, FlowControl.EXCEPTION):
        if name not in ("int3", "ud2"):
            raise RewriteError(f"unsupported control transfer {name}")
    implicit = list(INFO.info(ins).used_memory())
    if not explicit and implicit and name not in (
            "push", "pop", "pushfq", "popfq", "call", "ret", "leave", "incsspq", "saveprevssp"):
        raise RewriteError(f"unsupported implicit memory access {name}")
    if not explicit:
        return "runtime-control" if name in RUNTIME_CONTROL else "native"
    if ins.segment_prefix == Register.FS:
        return "fs"
    if ins.segment_prefix == Register.GS:
        return "gs"
    if output:
        raise RewriteError("uncovered explicit data-memory access")
    if ins.len == 15:
        raise RewriteError("GS prefix would exceed the 15-byte instruction limit")
    return "gs"
