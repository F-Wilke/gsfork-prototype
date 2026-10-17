import hashlib
import json
import statistics
import subprocess
import time
from pathlib import Path

from .errors import RewriteError
from .validator import validate_artifact


def compare(original, baseline, rewritten, samples=31, arguments=()):
    if samples < 3:
        raise RewriteError("comparison requires at least three samples")
    paths = [Path(p).resolve() for p in (original, baseline, rewritten)]
    report = json.loads(Path(str(paths[2]) + ".gsfork/report.json").read_text())
    if report["mode"] != "gs":
        raise RewriteError("comparison requires a GS artifact, not another native baseline")
    validate_artifact(paths[2], report)
    for path, expected in zip(paths[:2], (report["input_sha256"], report["baseline_sha256"])):
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise RewriteError(f"{path}: comparison control is not from this rewrite")
    timings = [[], [], []]
    expected_output = None
    for trial in range(samples + 3):
        for index in ((trial + offset) % 3 for offset in range(3)):
            start = time.perf_counter_ns()
            process = subprocess.run([str(paths[index]), *arguments], capture_output=True, timeout=300)
            elapsed = time.perf_counter_ns() - start
            if process.returncode:
                raise RewriteError(f"{paths[index]} exited with {process.returncode}: {process.stderr!r}")
            output = process.stdout, process.stderr
            if expected_output is None:
                expected_output = output
            elif output != expected_output:
                raise RewriteError(f"{paths[index]} output differs between comparison controls")
            if trial >= 3:
                timings[index].append(elapsed)
    result = {"metric": "whole-process wall-clock nanoseconds (includes startup)",
              "samples": samples, "warmups": 3, "order": "rotating"}
    for name, path, values in zip(("original", "baseline", "gs"), paths, timings):
        values.sort()
        result[name] = {"path": str(path), "bytes": path.stat().st_size,
                        "median_ns": statistics.median(values), "minimum_ns": min(values),
                        "p95_ns": values[min(len(values) - 1, (len(values) * 95 + 99) // 100 - 1)]}
    result["baseline_over_original"] = result["baseline"]["median_ns"] / result["original"]["median_ns"]
    result["gs_over_baseline"] = result["gs"]["median_ns"] / result["baseline"]["median_ns"]
    return result
