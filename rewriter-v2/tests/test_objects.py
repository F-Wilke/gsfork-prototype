import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from elftools.elf.elffile import ELFFile

from gsfork_elf.elf import Image
from gsfork_elf.errors import RewriteError
from gsfork_elf.pipeline import rewrite
from gsfork_elf.policy import Runtime
from gsfork_elf.validator import validate_artifact


DRIVER = Path(__file__).parent / "fixtures/object_plt_driver.c"


class ObjectRewriteTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.work = Path(tmp.name)
        self.obj = self.work / "input.o"
        self.out = self.work / "output.o"

    def gcc(self, *args, source=None):
        subprocess.run(["gcc", *args], input=source, text=True, check=True, cwd=self.work)

    def compile(self, source, *args):
        self.gcc("-c", "-O2", "-fPIC", "-ffunction-sections", *args,
                 "-x", "c", "-", "-o", self.obj, source=source)

    def test_link_and_call_with_translated_got(self):
        self.compile("extern int ext(int); int entry(int *p){return ext(*p)+*p;}")
        report = rewrite(self.obj, self.out)
        self.assertEqual(report["validation"]["gs_prefixes"], 2)
        self.gcc("-shared", "-fPIC", "-xc", "-", "-o", "libext.so",
                 source="int ext(int n){return n+1;}")
        for cet in (False, True):
            with self.subTest(cet=cet):
                linked = self.work / ("cet" if cet else "classic")
                self.gcc("-no-pie", DRIVER, self.out, "-L.", "-lext", "-Wl,-rpath,$ORIGIN",
                         "-Wl,-z,now,--no-relax", *(["-Wl,-z,ibtplt"] if cet else []), "-o", linked)
                image = Image(linked)
                slot, = [addr for addr, reloc in image.relocations.items() if reloc["symbol"] == "ext"]
                patched = linked.with_suffix(".gs")
                plt = rewrite(linked, patched, plt_only=True)
                self.assertTrue(any(r["target"] == slot for r in plt["generated"]))
                self.assertEqual(len(patched.read_bytes()), len(image.data))
                subprocess.run([patched, hex(slot)], check=True)
                self.assertEqual(validate_artifact(patched, plt), plt["validation"])
        self.gcc("-no-pie", DRIVER, self.out, "-L.", "-lext", "-Wl,-z,lazy", "-o", "lazy")
        with self.assertRaisesRegex(RewriteError, "BIND_NOW"):
            rewrite(self.work / "lazy", self.work / "failed", plt_only=True)
        self.assertFalse((self.work / "failed").exists())

    def test_got_only_plt(self):
        self.gcc("-shared", "-fPIC", "-xc", "-", "-o", "libext.so",
                 source="int ext(int n){return n+1;}")
        caller = ("extern int ext(int); int (*address)(int);"
                  "int main(void){address=ext; return ext(4)!=5;}")
        for ibt in (False, True):
            with self.subTest(ibt=ibt):
                linked = self.work / f"got-{ibt}"
                self.gcc("-fPIC", "-pie", "-Wl,-z,now,--no-relax", "-xc", "-",
                         "-L.", "-lext", "-Wl,-rpath,$ORIGIN",
                         *(["-Wl,-z,ibtplt"] if ibt else []), "-o", linked, source=caller)
                image = Image(linked)
                self.assertIsNone(image.elf.get_section_by_name(".plt.sec"))
                slot, = [addr for addr, r in image.relocations.items() if r["symbol"] == "ext"]
                patched = linked.with_suffix(".gs")
                report = rewrite(linked, patched, plt_only=True)
                entry, = [r for r in report["generated"] if r["target"] == slot]
                self.assertEqual((entry["section"], entry["size"]), (".plt.got", 16 if ibt else 8))
                subprocess.run([patched], check=True)

    def test_symbols_branches_got_and_unwind(self):
        self.compile("extern int g; int f(int *p, int n){"
                     "for(int i=0;i<n;i++) g+=p[i]; return g;} int (*fp)(int*,int)=f;")
        rewrite(self.obj, self.out)
        self.gcc("-no-pie", "-Wl,--no-relax", self.out, "-xc", "-", "-o", "run",
                 source="extern int (*fp)(int*,int); int g=1;"
                        "int main(void){int a[]={2,5,7};return fp(a,3)!=15;}")
        subprocess.run([self.work/"run"], check=True)
        with self.out.open("rb") as stream:
            elf = ELFFile(stream)
            func, = elf.get_section_by_name(".symtab").get_symbol_by_name("f")
            _, fde = elf.get_dwarf_info().EH_CFI_entries()
            self.assertEqual(fde["address_range"], func["st_size"])
        # Re-validation detects changes made after publication.
        self.out.write_bytes(self.obj.read_bytes())
        report = json.loads(Path(str(self.out)+".gsfork/report.json").read_text())
        with self.assertRaisesRegex(RewriteError, "hash"):
            validate_artifact(self.out, report)

    def test_multiple_functions_in_default_text(self):
        self.compile("int first(int *p){return *p+1;}"
                     "__attribute__((aligned(32))) int second(int *p){return *p+2;}",
                     "-fno-function-sections")
        rewrite(self.obj, self.out)
        with self.out.open("rb") as stream:
            elf = ELFFile(stream)
            symbols = elf.get_section_by_name(".symtab")
            second, = symbols.get_symbol_by_name("second")
            self.assertEqual(second["st_value"] % 32, 0)
            first, = symbols.get_symbol_by_name("first")
            _, a, b = elf.get_dwarf_info().EH_CFI_entries()
            self.assertEqual([a["address_range"], b["address_range"]],
                             [first["st_size"], second["st_size"]])
        self.gcc(self.out, "-xc", "-", "-o", "run",
                 source="int first(int*),second(int*);"
                        "int main(){int n=4;return first(&n)!=5 || second(&n)!=6;}")
        subprocess.run([self.work / "run"], check=True)

    def test_short_branch_overflow(self):
        for branch in ("jmp", "jz", "jrcxz", "jecxz"):
            with self.subTest(branch=branch):
                source = f"""
            .globl f
            .type f,@function
            f:
            .cfi_startproc
            xor %eax,%eax
            xor %ecx,%ecx
            {branch} 1f
            .rept 59
            mov (%rdi),%eax
            .endr
            1: mov g(%rip),%eax
            ret
            .cfi_endproc
            .size f,.-f
        """
                self.gcc("-c", "-x", "assembler", "-", "-o", self.obj, source=source)
                output = self.work / f"{branch}.o"
                rewrite(self.obj, output)
                self.gcc(output, "-xc", "-", "-o", branch,
                         source="int g=7; int f(int*); int main(){int n=3;return f(&n)!=7;}")
                subprocess.run([self.work / branch], check=True)
                with output.open("rb") as stream:
                    elf = ELFFile(stream)
                    func, = elf.get_section_by_name(".symtab").get_symbol_by_name("f")
                    _, fde = elf.get_dwarf_info().EH_CFI_entries()
                    self.assertEqual(fde["address_range"], func["st_size"])

    def test_branch_widening_reaches_fixed_point(self):
        self.gcc("-c", "-x", "assembler", "-", "-o", self.obj, source="""
            .globl f
            .type f,@function
            f: jmp 1f
            .rept 3
            nop
            .endr
            jmp 2f
            .rept 120
            nop
            .endr
            1:
            .rept 3
            mov (%rdi),%eax
            .endr
            2: ret
            .size f,.-f
        """)
        rewrite(self.obj, self.out)
        with self.out.open("rb") as stream:
            elf = ELFFile(stream)
            code = elf.get_section_by_name(".text").data()
            self.assertEqual(code[0], 0xe9)
            self.assertEqual(code[8], 0xe9)
        self.gcc(self.out, "-xc", "-", "-o", "run",
                 source="int f(int*); int main(){int n=9;return f(&n)!=9;}")
        subprocess.run([self.work / "run"], check=True)

    def test_backward_short_branches_preserve_flags_and_count(self):
        for branch in ("jnz", "loop", "loope", "loopne", "jrcxz"):
            with self.subTest(branch=branch):
                if branch == "jnz":
                    control = "dec %ecx"
                elif branch == "jrcxz":
                    control = "mov $1,%ecx; cmp %ecx,%ecx"
                else:
                    control = "test %eax,%eax" if branch == "loopne" else "cmp %ecx,%ecx"
                self.gcc("-c", "-x", "assembler", "-", "-o", self.obj, source=f"""
                    .globl f
                    .type f,@function
                    f: mov $2,%ecx
                    1:
                    .rept 59
                    mov (%rdi),%eax
                    .endr
                    {control}
                    {branch} 1b
                    setz %dl
                    movzbl %dl,%edx
                    shl $8,%edx
                    mov %ecx,%eax
                    or %edx,%eax
                    ret
                    .size f,.-f
                """)
                output = self.work / f"{branch}.o"
                rewrite(self.obj, output)
                expected = 257 if branch == "jrcxz" else 0 if branch == "loopne" else 256
                self.gcc(output, "-xc", "-", "-o", branch,
                         source=f"int f(int*); int main(){{int n=9;return f(&n)!={expected};}}")
                subprocess.run([self.work / branch], check=True, timeout=5)

    def test_debug_rejected_before_publication(self):
        self.compile("int f(int *p){return *p;}", "-g")
        with self.assertRaisesRegex(RewriteError, "unsupported object metadata"):
            rewrite(self.obj, self.out)
        self.assertFalse(self.out.exists())

    def test_cfi_advance_growth_moves_following_fdes(self):
        for count in (30, 120, 22000):
            with self.subTest(count=count):
                output = self.work / f"cfi-{count}.o"
                self.gcc("-c", "-x", "assembler", "-", "-o", self.obj, source=f"""
                    .globl f,g
                    .type f,@function
                    f:
                    .cfi_startproc
                    .rept {count}
                    mov (%rdi),%eax
                    .endr
                    push %rbx
                    .cfi_def_cfa_offset 16
                    .cfi_offset %rbx,-16
                    pop %rbx
                    .cfi_def_cfa_offset 8
                    ret
                    .cfi_endproc
                    .size f,.-f
                    .type g,@function
                    g:
                    .cfi_startproc
                    mov (%rdi),%eax
                    ret
                    .cfi_endproc
                    .size g,.-g
                """)
                rewrite(self.obj, output)
                with output.open("rb") as stream:
                    elf = ELFFile(stream)
                    _, first, second = elf.get_dwarf_info().EH_CFI_entries()
                    rows = first.get_decoded().table
                    self.assertEqual(rows[1]['pc'], count * 3 + 1)
                    self.assertEqual(rows[1]['cfa'].offset, 16)
                    symbol, = elf.get_section_by_name(".symtab").get_symbol_by_name("g")
                    self.assertEqual(second['initial_location'], symbol['st_value'])
                self.gcc(output, "-xc", "-", "-o", "run",
                         source="int f(int*),g(int*); int main(){int n=17;"
                                "return f(&n)!=17 || g(&n)!=17;}")
                subprocess.run([self.work / "run"], check=True)

    def test_relative_jump_tables_with_distinct_bases(self):
        self.gcc("-c", "-x", "assembler", "-", "-o", self.obj, source="""
            .globl f
            .type f,@function
            f:
            lea table(%rip),%rdx
            test %edi,%edi
            jz 1f
            lea table2(%rip),%rdx
            1: movslq (%rdx,%rsi,4),%rax
            add %rdx,%rax
            jmp *%rax
            a: mov (%rcx),%eax
            ret
            b: mov (%rcx),%eax
            add $1,%eax
            ret
            .size f,.-f
            .section .rodata
            table: .long a-table,b-table
            table2: .long b-table2,a-table2
        """)
        rewrite(self.obj, self.out)
        self.gcc(self.out, "-xc", "-", "-o", "run",
                 source="int f(int,int,int,int*); int main(){int n=9;"
                        "return f(0,0,0,&n)!=9 || f(0,1,0,&n)!=10 ||"
                        "f(1,0,0,&n)!=10 || f(1,1,0,&n)!=9;}")
        subprocess.run([self.work / "run"], check=True)

    def test_dynamic_tls_relocations(self):
        for model, kind in (("global-dynamic", 19), ("local-dynamic", 20)):
            with self.subTest(model=model):
                output = self.work / f"tls-{model}.o"
                self.compile("__thread int value=7; int f(void){return ++value;}",
                             f"-ftls-model={model}")
                with self.obj.open("rb") as stream:
                    elf = ELFFile(stream)
                    self.assertIn(kind, [r['r_info_type'] for sec in elf.iter_sections()
                                         if sec['sh_type'] == 'SHT_RELA'
                                         for r in sec.iter_relocations()])
                rewrite(self.obj, output)
                self.gcc("-shared", output, "-Wl,-z,now,--no-relax", "-o", "libtls.so")
                self.gcc("-xc", "-", "-L.", "-ltls", "-Wl,-rpath,$ORIGIN", "-o", "run",
                         source="int f(void); int main(){return f()!=8 || f()!=9;}")
                subprocess.run([self.work / "run"], check=True)

    def test_string_wrappers_with_nonzero_sandbox_offset(self):
        for opcode in ("rep movsb", "movsq", "rep stosb", "stosq"):
            with self.subTest(opcode=opcode):
                output = self.work / f"{opcode.replace(' ', '-')}.o"
                stos = "stos" in opcode
                self.gcc("-c", "-x", "assembler", "-", "-o", self.obj, source=f"""
                    .globl f
                    .type f,@function
                    f:
                    .cfi_startproc
                    {opcode}
                    ret
                    .cfi_endproc
                    .size f,.-f
                """)
                rewrite(self.obj, output, runtime=Runtime(0, 8))
                self.gcc("-nostdlib", "-no-pie", output, "-x", "assembler", "-",
                         "-o", "run", source=f"""
                    .globl _start
                    _start:
                    mov $158,%eax
                    mov $0x1002,%edi
                    lea tls(%rip),%rsi
                    syscall
                    test %eax,%eax
                    jnz failed
                    mov $128,%edi
                    mov $64,%esi
                    mov $1,%ecx
                    mov $0x1234,%eax
                    mov $0x5678,%edx
                    cmp %eax,%eax
                    call f
                    jnz failed
                    cmp $0x1234,%eax
                    jne failed
                    cmp $0x5678,%edx
                    jne failed
                    cmp ${129 if "rep" in opcode else 136},%edi
                    jne failed
                    cmp ${64 if stos else 65 if "rep" in opcode else 72},%esi
                    jne failed
                    cmpb ${0x34 if stos else 0x5a},buffer+128(%rip)
                    jne failed
                    xor %edi,%edi
                    jmp exit
                    failed: mov $1,%edi
                    exit: mov $60,%eax
                    syscall
                    .data
                    .align 8
                    tls: .quad 0,buffer
                    buffer: .zero 64
                    .quad 0x5a
                    .zero 128
                """)
                subprocess.run([self.work / "run"], check=True)

    def test_string_wrapper_rejects_temporary_cfa_register(self):
        self.gcc("-c", "-x", "assembler", "-", "-o", self.obj, source="""
            .globl f
            .type f,@function
            f:
            .cfi_startproc
            .cfi_def_cfa %rdi,8
            rep movsb
            ret
            .cfi_endproc
            .size f,.-f
        """)
        with self.assertRaisesRegex(RewriteError, "temporary register"):
            rewrite(self.obj, self.out, runtime=Runtime(0, 8))
        self.assertFalse(self.out.exists())

    def test_exception_ranges_and_landing_pads_follow_growth(self):
        subprocess.run(["g++", "-c", "-O2", "-fPIC", "-x", "c++", "-", "-o", self.obj],
                       input="""
            extern void throwing();
            struct Guard { int *p; ~Guard(){++*p;} };
            int f(int *p) {
                Guard g{p};
                *p += 2;
                try { throwing(); }
                catch (int n) { *p += n; }
                return *p;
            }
        """, text=True, check=True)
        rewrite(self.obj, self.out)
        subprocess.run(["g++", self.out, "-Wl,-z,now,--no-relax", "-xc++", "-",
                        "-o", self.work / "run"], input="""
            void throwing(){throw 3;}
            int f(int*);
            int main(){int n=4; int r=f(&n);return r!=9 || n!=10;}
        """, text=True, check=True)
        subprocess.run([self.work / "run"], check=True)

    def test_lsda_growth_overflow_rejected_before_publication(self):
        self.gcc("-c", "-x", "assembler", "-", "-o", self.obj, source="""
            .globl f
            .type f,@function
            f:
            .cfi_startproc
            .cfi_personality 0x9b,DW.ref.personality
            .cfi_lsda 0x1b,lsda
            .rept 50
            mov (%rdi),%eax
            .endr
            call throwing
            landing: ret
            .cfi_endproc
            .size f,.-f
            .section .data.rel.local
            DW.ref.personality: .quad personality
            .section .gcc_except_table
            lsda: .byte 0xff,0xff,1,4,100,5,105,0
        """)
        with self.assertRaisesRegex(RewriteError, "LSDA advance overflow"):
            rewrite(self.obj, self.out)
        self.assertFalse(self.out.exists())

    def test_unsized_function_markers(self):
        self.gcc("-c", "-x", "assembler", "-", "-o", self.obj, source="""
            .globl f,g
            .type f,@function
            f: mov (%rdi),%eax
            ret
            .align 16
            .type g,@function
            g: call f
            add $1,%eax
            ret
        """)
        rewrite(self.obj, self.out)
        self.gcc(self.out, "-xc", "-", "-o", "run",
                 source="int f(int*),g(int*);int main(){int n=4;"
                        "return f(&n)!=4 || g(&n)!=5;}")
        subprocess.run([self.work / "run"], check=True)
        with self.out.open("rb") as stream:
            elf = ELFFile(stream)
            g, = elf.get_section_by_name(".symtab").get_symbol_by_name("g")
            self.assertEqual(g['st_size'], 0)
            self.assertEqual(g['st_value'] % 16, 0)

    def test_symbol_less_init_epilogue_and_unsized_prologue(self):
        self.gcc("-c", "-x", "assembler", "-", "-o", self.obj, source="""
            .section .init
            .globl _init
            .type _init,@function
            _init: sub $8,%rsp
            mov (%rdi),%eax
        """)
        rewrite(self.obj, self.out)
        tail = self.work / "tail.o"
        self.gcc("-c", "-x", "assembler", "-", "-o", tail, source="""
            .section .init
            add $8,%rsp
            ret
        """)
        with tail.open("rb") as stream:
            self.assertIsNone(ELFFile(stream).get_section_by_name(".symtab"))
        rewritten_tail = self.work / "tail.gs.o"
        rewrite(tail, rewritten_tail)
        self.gcc("-nostdlib", "-no-pie", self.out, rewritten_tail, "-x", "assembler", "-",
                 "-o", "run", source="""
            .globl _start
            _start:
            lea value(%rip),%rdi
            call _init
            cmp $7,%eax
            setne %dil
            movzbl %dil,%edi
            mov $60,%eax
            syscall
            .data
            value: .long 7
        """)
        subprocess.run([self.work / "run"], check=True)
