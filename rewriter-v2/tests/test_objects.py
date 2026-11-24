import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from elftools.elf.elffile import ELFFile

from gsfork_elf.elf import Image
from gsfork_elf.errors import RewriteError
from gsfork_elf.pipeline import rewrite
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
        self.gcc("-c", "-x", "assembler", "-", "-o", self.obj, source="""
            .globl f
            .type f,@function
            f: jmp 1f
            .rept 60
            mov (%rdi),%eax
            .endr
            1: ret
            .size f,.-f
        """)
        with self.assertRaisesRegex(RewriteError, "internal displacement overflow"):
            rewrite(self.obj, self.out)
        self.assertFalse(self.out.exists())

    def test_debug_rejected_before_publication(self):
        self.compile("int f(int *p){return *p;}", "-g")
        with self.assertRaisesRegex(RewriteError, "unsupported object metadata"):
            rewrite(self.obj, self.out)
        self.assertFalse(self.out.exists())
