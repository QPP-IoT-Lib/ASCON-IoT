#!/usr/bin/env python3

import csv
import statistics
import sys
from pathlib import Path


def load_run(path):
    rows = {}

    with open(path, newline="") as f:
        for row in csv.reader(f):
            if not row:
                continue

            if row[0] not in ("encrypt", "decrypt"):
                continue

            op = row[0]
            size = int(row[1])
            iterations = int(row[2])
            ns_op = float(row[3])
            mib_s = float(row[4])

            rows[(op, size)] = {
                "iterations": iterations,
                "ns_op": ns_op,
                "mib_s": mib_s,
            }

    return rows


def main():
    if len(sys.argv) < 3:
        raise SystemExit(
            "usage: summarize_host.py OUTPUT.csv RUN1.txt RUN2.txt ..."
        )

    output = Path(sys.argv[1])
    run_paths = [Path(p) for p in sys.argv[2:]]

    runs = [load_run(p) for p in run_paths]

    keys = sorted(
        runs[0].keys(),
        key=lambda k: (k[1], k[0]),
    )

    with output.open("w", newline="") as f:
        writer = csv.writer(f)

        writer.writerow([
            "operation",
            "size_bytes",
            "iterations",
            "runs",
            "median_ns_op",
            "min_ns_op",
            "max_ns_op",
            "spread_percent",
            "median_MiB_s",
        ])

        for key in keys:
            op, size = key

            ns_values = [
                run[key]["ns_op"]
                for run in runs
            ]

            mib_values = [
                run[key]["mib_s"]
                for run in runs
            ]

            iterations = runs[0][key]["iterations"]

            median_ns = statistics.median(ns_values)
            min_ns = min(ns_values)
            max_ns = max(ns_values)

            spread = (
                (max_ns - min_ns)
                / median_ns
                * 100.0
            )

            median_mib = statistics.median(mib_values)

            writer.writerow([
                op,
                size,
                iterations,
                len(runs),
                f"{median_ns:.2f}",
                f"{min_ns:.2f}",
                f"{max_ns:.2f}",
                f"{spread:.2f}",
                f"{median_mib:.3f}",
            ])

    print(f"wrote {output}")


if __name__ == "__main__":
    main()
