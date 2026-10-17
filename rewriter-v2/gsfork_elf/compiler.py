"""GNU compiler adapter for two verified gtirb-pprinter 2.2.5 syntax defects."""

import re
import subprocess
import sys
from pathlib import Path


def normalize_assembly(text):
    text = re.sub(r"(?im)^(\s*rstorssp\s+)DWORD PTR\b", r"\1QWORD PTR", text)

    def abort(match):
        immediate = int(match[2])
        if not -128 <= immediate < 0:
            return match[0]
        return match[1] + str(immediate & 255)

    return re.sub(r"(?im)^(\s*xabort\s+)(-\d+)\s*$", abort, text)


def main(argv=None):
    arguments = sys.argv[1:] if argv is None else argv
    try:
        for argument in arguments:
            path = Path(argument)
            if path.suffix in (".s", ".S") and path.is_file():
                original = path.read_text()
                normalized = normalize_assembly(original)
                if normalized != original:
                    path.write_text(normalized)
                    print("gsfork-cc: corrected known printer RSTORSSP/XABORT syntax", file=sys.stderr)
        # The printer can select an at-end provenance alias for init/fini.
        # Put our explicit original-entry aliases after its generated options.
        boundaries = [a for a in arguments if a.startswith(("-Wl,-init=__gsfork_", "-Wl,-fini=__gsfork_"))]
        return subprocess.run(["gcc", *arguments, *boundaries], check=False).returncode
    except OSError as error:
        print(f"gsfork-cc: {error}", file=sys.stderr)
        return 1
