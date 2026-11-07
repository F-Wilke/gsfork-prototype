"""GNU compiler adapter for verified gtirb-pprinter 2.2.5 syntax and symbol-name defects."""

import re
import subprocess
import sys
from pathlib import Path


RAW_LABEL = "__gsfork_raw_"
RAW_END = "_end"
_RAW = re.compile(rf"^({RAW_LABEL}\d+_([0-9a-f]+)):\n(.*?)^\1{RAW_END}:$", re.M | re.S)


def restore_raw_bytes(text):
    """Replace the printer's rendering between raw-byte labels with the exact bytes."""
    def raw(match):
        if ".cfi" in match[3]:
            raise ValueError(f"CFI inside raw-byte instruction {match[1]}")
        encoding = ",".join(f"0x{b:02x}" for b in bytes.fromhex(match[2]))
        return f"{match[1]}:\n            .byte {encoding}\n{match[1]}{RAW_END}:"
    return _RAW.sub(raw, text)


def normalize_assembly(text):
    text = restore_raw_bytes(text)
    text = re.sub(r"(?im)^(\s*rstorssp\s+)DWORD PTR\b", r"\1QWORD PTR", text)

    def abort(match):
        immediate = int(match[2])
        if not -128 <= immediate < 0:
            return match[0]
        return match[1] + str(immediate & 255)

    return re.sub(r"(?im)^(\s*xabort\s+)(-\d+)\s*$", abort, text)


QUOTE_OPTION = "--gsfork-quote="
ALIAS_OPTION = "--gsfork-alias="
_LINKAGE = re.compile(r"^(\s*\.(?:globl|weak|hidden|protected|internal)\s+)(\S+)\s*$")
_TYPE_SIZE = re.compile(r"^(\s*\.(?:type|size)\s+)(\S+)(\s*,.*)$")


def restore_symbol_names(text, quoted=(), aliased=()):
    """Undo gtirb-pprinter's "_renamed" suffix for non-local symbol names.

    Hex-literal look-alikes are written as quoted names, which GAS accepts in
    Intel operands. Register/keyword names stay quoted-invalid in operands, so
    references keep the local printer name and the original name is defined as
    an alias with the same linkage, type, and size (definitions in executables
    only; the rewriter rejects other cases).
    """
    for name in quoted:
        text = re.sub(rf'(?<![\w.$"]){re.escape(name)}_renamed(?![\w.$])', f'"{name}"', text)
    for name in aliased:
        printed, lines, extra = f"{name}_renamed", [], []
        for line in text.split("\n"):
            linkage, sized = _LINKAGE.match(line), _TYPE_SIZE.match(line)
            if linkage and linkage[2] == printed:
                extra.append(f'{linkage[1]}"{name}"')
                continue
            if sized and sized[2] == printed:
                extra.append(f'{sized[1]}"{name}"{sized[3]}')
            lines.append(line)
        text = "\n".join(lines) + f'\n.set "{name}", {printed}\n' + "\n".join(extra) + "\n"
    return text


def main(argv=None):
    arguments = sys.argv[1:] if argv is None else argv
    quoted = [a[len(QUOTE_OPTION):] for a in arguments if a.startswith(QUOTE_OPTION)]
    aliased = [a[len(ALIAS_OPTION):] for a in arguments if a.startswith(ALIAS_OPTION)]
    arguments = [a for a in arguments if not a.startswith((QUOTE_OPTION, ALIAS_OPTION))]
    try:
        for argument in arguments:
            path = Path(argument)
            if path.suffix in (".s", ".S") and path.is_file():
                original = path.read_text()
                normalized = restore_symbol_names(normalize_assembly(original), quoted, aliased)
                if normalized != original:
                    path.write_text(normalized)
                    print("gsfork-cc: corrected known printer syntax/symbol names", file=sys.stderr)
        # The printer can select an at-end provenance alias for init/fini.
        # Put our explicit original-entry aliases after its generated options.
        boundaries = [a for a in arguments if a.startswith(("-Wl,-init=__gsfork_", "-Wl,-fini=__gsfork_"))]
        return subprocess.run(["gcc", *arguments, *boundaries], check=False).returncode
    except (OSError, ValueError) as error:
        print(f"gsfork-cc: {error}", file=sys.stderr)
        return 1
