import argparse
import json
import sys
import subprocess
from pathlib import Path

from elftools.common.exceptions import ELFError, DWARFError

from .errors import RewriteError
from .pipeline import rewrite
from .policy import Runtime
from .validator import validate_artifact


def parser():
    result = argparse.ArgumentParser(description="GS-Fork linked x86-64 ELF rewriter")
    commands = result.add_subparsers(dest="command", required=True)
    for name in ("rewrite", "baseline"):
        command = commands.add_parser(name)
        command.add_argument("input", type=Path)
        command.add_argument("output", type=Path)
        command.add_argument("--scratch-rax", type=lambda s: int(s, 0))
        command.add_argument("--sandbox-offset", type=lambda s: int(s, 0))
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
            report = rewrite(args.input, args.output, baseline=args.command == "baseline",
                             runtime=Runtime(args.scratch_rax, args.sandbox_offset),
                             trusted_sections=args.trust_section, trusted_libraries=args.trust_library,
                             library_paths=args.library_path)
            result = {"output": report["output"], "mode": report["mode"], **report["validation"]}
        print(json.dumps(result, sort_keys=True))
        return 0
    except (RewriteError, OSError, ValueError, KeyError, ELFError, DWARFError,
            subprocess.TimeoutExpired) as error:
        print(f"gsfork-elf: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
