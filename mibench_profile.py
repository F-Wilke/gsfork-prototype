#!/usr/bin/env python3
"""Run paired perf/timing comparisons for GS-instrumented MiBench kernels."""
import argparse
import csv
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import random
import shutil
import statistics
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent
DEFAULT_WORK = {
    "crc": 16 * 1024 * 1024,
    "fft": 65536,
    "adpcm": 4 * 1024 * 1024,
}


def parse_csv(path, work_items):
    counters = {}
    with Path(path).open(newline="") as stream:
        for row in csv.reader(stream, delimiter=";"):
            if len(row) < 3 or row[0].lstrip().startswith("#"):
                continue
            count, unit, event = [value.strip() for value in row[:3]]
            if not event:
                continue
            try:
                value = float(count)
            except ValueError:
                value = None

            def number(index):
                try:
                    return float(row[index].strip().strip("%"))
                except (ValueError, IndexError):
                    return None

            counters[event] = {
                "raw_count": count,
                "count": value,
                "unit": unit,
                "per_work_item": value / work_items if value is not None else None,
                "runtime_ns": number(3),
                "running_percent": number(4),
                "raw_columns": row,
            }
    return counters


def checked_run(command, timeout):
    result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(
            f"command failed ({result.returncode}): {' '.join(map(str, command))}\n"
            f"{result.stderr.strip()}"
        )
    record = json.loads(result.stdout)
    if not record["verified"]:
        raise RuntimeError("MiBench driver reported failed verification")
    return record


def one_perf(perf, command, stem, events, seconds):
    environment = dict(os.environ, LC_ALL="C")
    environment.pop("GSFORK_PERF_CTL", None)
    environment.pop("GSFORK_PERF_ACK", None)
    with tempfile.TemporaryDirectory(prefix="mibench-gs-perf-") as temp:
        control = Path(temp) / "control.fifo"
        ack = Path(temp) / "ack.fifo"
        os.mkfifo(control, 0o600)
        os.mkfifo(ack, 0o600)
        environment.update(GSFORK_PERF_CTL=str(control), GSFORK_PERF_ACK=str(ack))
        output = stem.with_suffix(".perf.csv")
        full = [
            perf, "stat", "-e", events, "-x", ";", "--no-big-num",
            "-o", str(output), "--delay=-1",
            f"--control=fifo:{control},{ack}", "--", *map(str, command),
        ]
        process = subprocess.run(
            full, capture_output=True, text=True, env=environment,
            timeout=max(60, seconds * 10 + 30),
        )
        stem.with_suffix(".command.json").write_text(json.dumps({"argv": full}, indent=2) + "\n")
        stem.with_suffix(".stdout").write_text(process.stdout)
        stem.with_suffix(".stderr").write_text(process.stderr)
        if process.returncode:
            raise RuntimeError(
                f"perf failed ({process.returncode}); see {stem.with_suffix('.stderr')}\n"
                f"{process.stderr.strip()}"
            )
        record = json.loads(process.stdout)
        if not record["verified"] or not record["perf_gated"]:
            raise RuntimeError("MiBench driver verification or perf gating failed")
        return record, parse_csv(output, record["work_items"])


def parse_work(value):
    result = dict(DEFAULT_WORK)
    if not value:
        return result
    for item in value.split(","):
        benchmark, raw = item.split("=", 1)
        if benchmark not in result:
            raise argparse.ArgumentTypeError(f"unknown benchmark {benchmark}")
        result[benchmark] = int(raw, 0)
    return result


def calibrate(binary, benchmark, work, cpu, seconds):
    sample = checked_run([binary, benchmark, str(work), "1", str(cpu)], 120)
    duration = max(sample["wall_ns"], 1)
    return max(1, round(seconds * 1e9 / duration))


def event_value(summary, prefix):
    for event, value in summary["counters"].items():
        if event.split(":")[0] == prefix:
            measured = value["median_per_work_item"]
            return "—" if measured is None else f"{measured:.3f}"
    return "—"


def summarize(rows, output):
    summaries = []
    for benchmark in dict.fromkeys(row["benchmark"] for row in rows):
        case = [row for row in rows if row["benchmark"] == benchmark]
        references = {row["sample"]: row for row in case if row["variant"] == "baseline"}
        for variant in dict.fromkeys(row["variant"] for row in case):
            values = [row for row in case if row["variant"] == variant]
            event_names = {event for row in values for event in row["counters"]}
            counters = {}
            for event in sorted(event_names):
                measurements = [row["counters"][event] for row in values if event in row["counters"]]
                valid = [item["per_work_item"] for item in measurements if item["count"] is not None]
                running = [item["running_percent"] for item in measurements
                           if item["running_percent"] is not None]
                counters[event] = {
                    "median_per_work_item": statistics.median(valid) if valid else None,
                    "valid_samples": len(valid),
                    "samples": len(values),
                    "minimum_running_percent": min(running) if running else None,
                    "statuses": sorted({item["raw_count"] for item in measurements
                                       if item["count"] is None}),
                }
            ratios = [
                row["wall_ns"] / references[row["sample"]]["wall_ns"]
                for row in values if row["sample"] in references
            ]
            summaries.append({
                "benchmark": benchmark,
                "variant": variant,
                "work": values[0]["work"],
                "iterations": values[0]["iterations"],
                "samples": len(values),
                "median_ns_per_work_item": statistics.median(
                    row["wall_ns"] / row["work_items"] for row in values
                ),
                "median_paired_wall_ratio": statistics.median(ratios) if ratios else None,
                "counters": counters,
            })
    (output / "summary.json").write_text(json.dumps(summaries, indent=2) + "\n")
    lines = [
        "| Benchmark | Variant | Work | Iterations | ns/item | cycles/item | instructions/item | Wall ratio |",
        "|---|---|---:|---:|---:|---:|---:|---:|",
    ]
    for item in summaries:
        ratio = item["median_paired_wall_ratio"]
        lines.append(
            f"| {item['benchmark']} | {item['variant']} | {item['work']:,} | "
            f"{item['iterations']:,} | {item['median_ns_per_work_item']:.3f} | "
            f"{event_value(item, 'cycles')} | {event_value(item, 'instructions')} | "
            f"{'—' if ratio is None else f'{ratio:.3f}x'} |"
        )
    text = "\n".join(lines) + "\n"
    (output / "summary.md").write_text(text)
    print(text, end="")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--benchmarks", default="crc,fft,adpcm")
    parser.add_argument("--variants", default="baseline,gs0,gsshift")
    parser.add_argument("--work", help="comma-separated overrides, e.g. crc=1048576,fft=4096")
    parser.add_argument("--seconds", type=float, default=2.0)
    parser.add_argument("--repeat", type=int, default=3)
    parser.add_argument("--cpu", type=int)
    parser.add_argument(
        "--events",
        default="cycles:u,instructions:u,branches:u,branch-misses:u",
    )
    parser.add_argument("--perf", default=shutil.which("perf"))
    parser.add_argument("--timing-only", action="store_true")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--binary-dir", type=Path, default=ROOT / "build/mibench")
    args = parser.parse_args()
    binary_dir = args.binary_dir.resolve()
    binaries = {
        variant: binary_dir / f"mibench-{variant}"
        for variant in ("baseline", "gs0", "gsshift")
    }
    if args.seconds <= 0 or args.repeat <= 0:
        parser.error("seconds and repeat must be positive")
    benchmarks = args.benchmarks.split(",")
    variants = args.variants.split(",")
    if any(name not in DEFAULT_WORK for name in benchmarks):
        parser.error("unknown benchmark")
    if any(name not in binaries for name in variants) or "baseline" not in variants:
        parser.error("variants must be selected from baseline,gs0,gsshift and include baseline")
    if not args.timing_only and not args.perf:
        parser.error("perf is required unless --timing-only is selected")
    for variant in variants:
        if not binaries[variant].is_file():
            parser.error("build MiBench variants first with make mibench-build")

    cpu = args.cpu
    if cpu is None:
        cpu = min(os.sched_getaffinity(0))
    if cpu not in os.sched_getaffinity(0):
        parser.error(f"CPU {cpu} is outside the process affinity mask")
    work = parse_work(args.work)
    iterations = {
        benchmark: calibrate(binaries["baseline"], benchmark, work[benchmark], cpu, args.seconds)
        for benchmark in benchmarks
    }
    output = args.output or ROOT / "mibench-results" / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    output = output.resolve()
    if output.exists() and any(output.iterdir()):
        parser.error(f"output directory is not empty: {output}")
    output.mkdir(parents=True, exist_ok=True)
    snapshot_dir = output / "binaries"
    snapshot_dir.mkdir()
    snapshots = {}
    for variant in variants:
        target = snapshot_dir / binaries[variant].name
        shutil.copy2(binaries[variant], target)
        snapshots[variant] = {
            "path": str(target),
            "sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
        }
    metadata = {
        "date_utc": datetime.now(timezone.utc).isoformat(),
        "platform": platform.platform(),
        "cpu": cpu,
        "benchmarks": benchmarks,
        "variants": variants,
        "work": {name: work[name] for name in benchmarks},
        "iterations": iterations,
        "seconds": args.seconds,
        "repeat": args.repeat,
        "events": args.events,
        "timing_only": args.timing_only,
        "perf": args.perf,
        "binary_dir": str(args.binary_dir.resolve()),
        "binaries": snapshots,
    }
    if args.perf:
        version = subprocess.run([args.perf, "--version"], capture_output=True, text=True, timeout=5)
        metadata["perf_version"] = version.stdout.strip() or version.stderr.strip()
    (output / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")

    rows = []
    randomizer = random.Random(20261007)
    for benchmark in benchmarks:
        expected_checksum = None
        for sample in range(args.repeat):
            order = list(variants)
            randomizer.shuffle(order)
            for sequence, variant in enumerate(order):
                binary = snapshot_dir / binaries[variant].name
                command = [
                    str(binary), benchmark, str(work[benchmark]),
                    str(iterations[benchmark]), str(cpu),
                ]
                stem = output / f"{benchmark}-{variant}-{sample}"
                if args.timing_only:
                    record = checked_run(command, max(120, args.seconds * 10 + 30))
                    counters = {}
                    stem.with_suffix(".command.json").write_text(
                        json.dumps({"argv": command, "timing_only": True}, indent=2) + "\n"
                    )
                else:
                    record, counters = one_perf(
                        args.perf, command, stem, args.events, args.seconds
                    )
                if expected_checksum is None:
                    expected_checksum = record["checksum"]
                elif record["checksum"] != expected_checksum:
                    raise RuntimeError(f"{benchmark}: checksum differs across variants")
                record.update(
                    sample=sample,
                    sequence=sequence,
                    counters=counters,
                )
                rows.append(record)
                with (output / "runs.jsonl").open("a") as stream:
                    stream.write(json.dumps(record) + "\n")
                print(
                    f"{benchmark} {variant}: {record['wall_ns'] / 1e9:.3f}s, verified",
                    flush=True,
                )
    summarize(rows, output)
    print(f"Results: {output}")


if __name__ == "__main__":
    main()
