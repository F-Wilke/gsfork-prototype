import json
from pathlib import Path
import tempfile
import unittest

import mibench_profile


class MiBenchProfileTests(unittest.TestCase):
    def test_parse_perf_csv(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "perf.csv"
            path.write_text(
                "200;;cycles:u;1000000;100.00;;\n"
                "<not counted>;;cache-misses:u;1000000;0.00;;\n"
            )
            counters = mibench_profile.parse_csv(path, 100)
        self.assertEqual(counters["cycles:u"]["count"], 200)
        self.assertEqual(counters["cycles:u"]["per_work_item"], 2)
        self.assertEqual(counters["cycles:u"]["running_percent"], 100)
        self.assertIsNone(counters["cache-misses:u"]["count"])

    def test_summary_uses_paired_ratios_and_counter_medians(self):
        rows = []
        for sample, baseline_ns, shifted_ns, baseline_cycles, shifted_cycles in [
            (0, 100, 120, 200, 240),
            (1, 200, 220, 400, 440),
        ]:
            for variant, wall_ns, cycles in [
                ("baseline", baseline_ns, baseline_cycles),
                ("gsshift", shifted_ns, shifted_cycles),
            ]:
                rows.append({
                    "benchmark": "fft",
                    "variant": variant,
                    "work": 10,
                    "iterations": 1,
                    "work_items": 10,
                    "sample": sample,
                    "wall_ns": wall_ns,
                    "counters": {
                        "cycles:u": {
                            "count": cycles,
                            "per_work_item": cycles / 10,
                            "running_percent": 100,
                            "raw_count": str(cycles),
                        }
                    },
                })
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp)
            mibench_profile.summarize(rows, output)
            summary = {
                item["variant"]: item
                for item in json.loads((output / "summary.json").read_text())
            }
        self.assertEqual(
            summary["gsshift"]["counters"]["cycles:u"]["median_per_work_item"],
            34,
        )
        self.assertAlmostEqual(
            summary["gsshift"]["median_paired_wall_ratio"],
            (1.2 + 1.1) / 2,
        )


if __name__ == "__main__":
    unittest.main()
