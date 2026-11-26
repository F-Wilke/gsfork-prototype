import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "tools/rewrite_link_inputs.py"


class LinkInputsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.work = Path(self.tmp.name)
        self.main = self.work / "main.o"
        self.library = self.work / "libfixture.a"
        self.output = self.work / "result"
        subprocess.run(["gcc", "-c", "-fPIC", "-xc", "-", "-o", self.main],
                       input="int f(int*);int main(){int n=41;return f(&n)!=42;}",
                       text=True, check=True)
        subprocess.run(["gcc", "-c", "-fPIC", "-xc", "-", "-o", self.work / "lib.o"],
                       input="int f(int *p){return *p+1;}", text=True, check=True)
        subprocess.run(["ar", "rcs", self.library, self.work / "lib.o"], check=True)
        (self.work / "link.txt").write_text("gcc -pie main.o libfixture.a -o original\n")
        trace = subprocess.check_output(["gcc", "-print-file-name=libc.so.6"], text=True).strip()
        self.libc = Path(trace).resolve(strict=True)

    def invoke(self, *extra):
        return subprocess.run([sys.executable, SCRIPT, "--link-directory", self.work,
                               "--link-command", self.work / "link.txt", "--output", self.output,
                               "--scratch-rax", "0", "--sandbox-offset", "8",
                               "--shared", self.libc, "--jobs", "2", *extra],
                              text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def test_rewrites_selected_archive_members_and_runs(self):
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        audit = json.loads((self.output / "audit.json").read_text())
        self.assertTrue(any(item["member"] == "lib.o" for item in audit))
        self.assertTrue(all(item["status"] == "accepted" for item in audit))
        report = json.loads((self.output / "result.json").read_text())
        self.assertFalse(report["gs_fork_runtime_verified"])
        self.assertEqual(report["instrumented_inputs"], len(audit))
        subprocess.run([self.output / "baseline"], check=True)
        subprocess.run([self.output / "rewritten"], check=True)

    def test_rejected_object_never_linked(self):
        subprocess.run(["gcc", "-c", "-x", "assembler", "-", "-o", self.work / "lib.o"],
                       input=".globl f\n.type f,@function\nf: mov %gs:(%rdi),%eax\nret\n"
                             ".size f,.-f\n", text=True, check=True)
        subprocess.run(["ar", "rcs", self.library, self.work / "lib.o"], check=True)
        result = self.invoke()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("refusing to link", result.stderr)
        self.assertFalse((self.output / "linked").exists())
        self.assertFalse((self.output / "rewritten").exists())

    def test_shared_archive_is_never_passed_uninstrumented(self):
        result = self.invoke("--shared", str(self.library))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("rewrite-link-inputs:", result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertFalse((self.output / "rewritten").exists())

    def test_duplicate_archive_member_rejected(self):
        subprocess.run(["ar", "q", self.library, self.work / "lib.o"], check=True)
        result = self.invoke()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("ambiguous", result.stderr)
        self.assertFalse((self.output / "rewritten").exists())

    def test_existing_output_directory_is_not_overwritten(self):
        self.output.mkdir()
        marker = self.output / "keep"
        marker.write_text("untouched")
        result = self.invoke()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(marker.read_text(), "untouched")

    def test_dependency_reordering_requires_explicit_acknowledgement(self):
        subprocess.run(["gcc", "-c", "-fPIC", "-fno-builtin", "-xc", "-", "-o", self.main],
                       input="double sqrt(double);int f(int*);"
                             "int main(){int n=41;return f(&n)!=42 || sqrt(4)!=2;}",
                       text=True, check=True)
        (self.work / "link.txt").write_text("gcc -pie main.o libfixture.a -lm -o original\n")
        libm = Path(subprocess.check_output(["gcc", "-print-file-name=libm.so.6"],
                                            text=True).strip()).resolve(strict=True)
        result = self.invoke("--shared", str(libm))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("DT_NEEDED order changed", result.stderr)
        self.assertFalse((self.output / "rewritten").exists())
        self.output = self.work / "accepted"
        result = self.invoke("--shared", str(libm), "--allow-needed-reordering")
        self.assertEqual(result.returncode, 0, result.stderr)
        subprocess.run([self.output / "rewritten"], check=True)

    def test_unrecognized_object_suffix_is_rejected(self):
        other = self.work / "input.obj"
        self.main.rename(other)
        (self.work / "link.txt").write_text("gcc -pie input.obj libfixture.a -o original\n")
        result = self.invoke()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unrecognized relocatable object", result.stderr)
        self.assertFalse((self.output / "rewritten").exists())


if __name__ == "__main__":
    unittest.main()
