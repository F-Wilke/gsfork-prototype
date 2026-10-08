#!/usr/bin/env python3
"""Data-driven instruction test framework for GS rewrite policies."""
import argparse
import json
from pathlib import Path

from iced_x86 import Decoder, Register

from rewrite import Unsupported, transform, transform_fork


ROOT = Path(__file__).resolve().parent
POLICIES = {
    "restricted": transform,
    "fork": transform_fork,
}
SEGMENTS = {
    "NONE": Register.NONE,
    "CS": Register.CS,
    "GS": Register.GS,
}


def load_cases(path):
    document = json.loads(Path(path).read_text())
    cases = document.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ValueError("rewrite case file requires a non-empty cases list")
    names = set()
    for case in cases:
        name = case.get("name")
        if not isinstance(name, str) or not name:
            raise ValueError("every rewrite case needs a name")
        if name in names:
            raise ValueError(f"duplicate rewrite case: {name}")
        names.add(name)
        if case.get("policy") not in POLICIES:
            raise ValueError(f"{name}: unknown rewrite policy")
        if not isinstance(case.get("hex"), str):
            raise ValueError(f"{name}: hex machine code is required")
        if ("expected" in case) == ("error" in case):
            raise ValueError(f"{name}: specify exactly one of expected or error")
    return cases


def run_case(case):
    policy = POLICIES[case["policy"]]
    code = bytes.fromhex(case["hex"])
    base = int(case.get("base", 0x1000))
    gs = case.get("gs", True)
    expected_error = case.get("error")
    try:
        output, edits = policy(code, base, gs)
    except Unsupported as error:
        if expected_error is None:
            raise AssertionError(f"unexpected rejection: {error}") from error
        if expected_error not in str(error):
            raise AssertionError(
                f"rejection did not contain {expected_error!r}: {error}"
            ) from error
        return {"name": case["name"], "status": "rejected"}
    if expected_error is not None:
        raise AssertionError("case was accepted but rejection was expected")

    expected = case["expected"]
    instructions = list(Decoder(64, output, ip=base))
    if len(edits) != expected["edits"]:
        raise AssertionError(
            f"expected {expected['edits']} edits, found {len(edits)}"
        )
    expected_segments = expected.get("segments")
    if expected_segments is not None:
        actual = [instruction.segment_prefix for instruction in instructions]
        wanted = [SEGMENTS[name] for name in expected_segments]
        if actual != wanted:
            raise AssertionError(
                f"segment sequence mismatch: expected {expected_segments}, "
                f"found {actual}"
            )
    if "length_delta" in expected:
        actual_delta = len(output) - len(code)
        if actual_delta != expected["length_delta"]:
            raise AssertionError(
                f"expected length delta {expected['length_delta']}, "
                f"found {actual_delta}"
            )
    if "output_hex" in expected and output.hex() != expected["output_hex"]:
        raise AssertionError(
            f"expected output {expected['output_hex']}, found {output.hex()}"
        )
    for raw_index, target in expected.get("branch_targets", {}).items():
        index = int(raw_index)
        if instructions[index].near_branch_target != int(target, 0):
            raise AssertionError(
                f"instruction {index} target mismatch: "
                f"0x{instructions[index].near_branch_target:x}"
            )
    return {
        "name": case["name"],
        "status": "accepted",
        "instructions": len(instructions),
        "edits": len(edits),
        "bytes": len(output),
    }


def run_matrix(path):
    results = []
    for case in load_cases(path):
        try:
            results.append(run_case(case))
        except (AssertionError, ValueError) as error:
            raise AssertionError(f"{case['name']}: {error}") from error
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--cases",
        type=Path,
        default=ROOT / "tests/rewrite_cases.json",
    )
    args = parser.parse_args()
    results = run_matrix(args.cases)
    summary = {
        "cases": len(results),
        "accepted": sum(item["status"] == "accepted" for item in results),
        "rejected": sum(item["status"] == "rejected" for item in results),
        "results": results,
    }
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
