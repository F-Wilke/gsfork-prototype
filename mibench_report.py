#!/usr/bin/env python3
"""Combine MiBench perf summaries into a long-form metric table."""
import argparse
import csv
import json
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inputs", nargs="+", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    rows = []
    for directory in args.inputs:
        summary = json.loads((directory / "summary.json").read_text())
        for item in summary:
            common = {
                "pass": directory.name,
                "benchmark": item["benchmark"],
                "variant": item["variant"],
                "work": item["work"],
                "iterations": item["iterations"],
                "samples": item["samples"],
                "median_ns_per_work_item": item["median_ns_per_work_item"],
                "median_paired_wall_ratio": item["median_paired_wall_ratio"],
            }
            for event, counter in item["counters"].items():
                rows.append({
                    **common,
                    "event": event,
                    "median_per_work_item": counter["median_per_work_item"],
                    "valid_samples": counter["valid_samples"],
                    "minimum_running_percent": counter["minimum_running_percent"],
                    "statuses": ",".join(counter["statuses"]),
                })

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=rows[0])
        writer.writeheader()
        writer.writerows(rows)
    print(f"Wrote {len(rows)} metric rows to {args.output}")


if __name__ == "__main__":
    main()
