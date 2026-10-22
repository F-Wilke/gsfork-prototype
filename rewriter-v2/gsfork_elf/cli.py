import argparse
import hashlib
import json
import sys
import subprocess
from pathlib import Path

from elftools.common.exceptions import ELFError, DWARFError

from .errors import RewriteError
from .elf import tcb_field_offset
from .pipeline import rewrite
from .policy import Runtime
from .validator import validate_artifact


def runtime_slots(args):
    """Build the FS slots, resolving struct pthread field names via DWARF when given.

    The thread pointer is the TCB base on x86-64, so a member's FS displacement is
    its struct offset. The layout comes from --tcb-layout (the libc/ld.so the
    program will run with) or, by default, from the input itself, which only works
    when the input is that glibc. Returns the slots and the layout provenance.
    """
    fields = (args.scratch_field, args.sandbox_field)
    if args.tcb_layout is not None and fields == (None, None):
        raise RewriteError("--tcb-layout is only meaningful with --scratch-field/--sandbox-field")
    source = Path(args.tcb_layout if args.tcb_layout is not None else args.input).resolve()

    def slot(number, field, numeric_flag, name):
        if number is not None and field is not None:
            raise RewriteError(f"pass either --{numeric_flag} or --{name}-field, not both")
        if field is not None:
            try:
                return tcb_field_offset(source, "pthread", field)
            except RewriteError as error:
                if args.tcb_layout is None:
                    raise RewriteError(f"{error}; pass --tcb-layout with the glibc ld.so/libc.so "
                                       "whose struct pthread the program will run with") from None
                raise
        return number

    runtime = Runtime(slot(args.scratch_rax, args.scratch_field, "scratch-rax", "scratch"),
                      slot(args.sandbox_offset, args.sandbox_field, "sandbox-offset", "sandbox"))
    layout = None
    if fields != (None, None):
        layout = {"source": str(source), "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                  "struct": "pthread", "scratch_field": args.scratch_field,
                  "sandbox_field": args.sandbox_field}
    return runtime, layout


def parser():
    result = argparse.ArgumentParser(description="GS-Fork linked x86-64 ELF rewriter")
    commands = result.add_subparsers(dest="command", required=True)
    for name in ("rewrite", "baseline"):
        command = commands.add_parser(name)
        command.add_argument("input", type=Path)
        command.add_argument("output", type=Path)
        command.add_argument("--scratch-rax", type=lambda s: int(s, 0))
        command.add_argument("--sandbox-offset", type=lambda s: int(s, 0))
        command.add_argument("--scratch-field",
                             help="struct pthread member holding FS scratch; offset read from input DWARF")
        command.add_argument("--sandbox-field",
                             help="struct pthread member holding the sandbox delta; offset read from input DWARF")
        command.add_argument("--tcb-layout", type=Path,
                             help="ELF with DWARF for struct pthread (the glibc ld.so/libc.so the program "
                                  "runs with); defaults to the input, which only suits glibc itself")
        command.add_argument("--trust-section", action="append", default=[])
        command.add_argument("--trust-library", action="append", default=[])
        command.add_argument("-L", "--library-path", action="append", default=[])
    validate = commands.add_parser("validate")
    validate.add_argument("input", type=Path)
    validate.add_argument("--report", type=Path)
    compare = commands.add_parser("compare", help="compare verified original/native-reassembly/GS=0 controls")
    compare.add_argument("original", type=Path)
    compare.add_argument("baseline", type=Path)
    compare.add_argument("rewritten", type=Path)
    compare.add_argument("--samples", type=int, default=31)
    compare.add_argument("--arg", action="append", default=[], help="argument passed to each program")
    return result


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        if args.command == "validate":
            report_path = args.report or Path(str(args.input) + ".gsfork/report.json")
            report = json.loads(report_path.read_text())
            result = {"mode": report["mode"], **validate_artifact(args.input, report)}
        elif args.command == "compare":
            from .benchmark import compare
            result = compare(args.original, args.baseline, args.rewritten, args.samples, args.arg)
        else:
            runtime, layout = runtime_slots(args)
            report = rewrite(args.input, args.output, baseline=args.command == "baseline",
                             runtime=runtime, trusted_sections=args.trust_section,
                             trusted_libraries=args.trust_library, library_paths=args.library_path,
                             runtime_layout=layout)
            result = {"output": report["output"], "mode": report["mode"], **report["validation"]}
        print(json.dumps(result, sort_keys=True))
        return 0
    except (RewriteError, OSError, ValueError, KeyError, ELFError, DWARFError,
            subprocess.TimeoutExpired) as error:
        print(f"gsfork-elf: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
