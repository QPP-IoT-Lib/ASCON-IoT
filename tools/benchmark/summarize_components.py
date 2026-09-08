#!/usr/bin/env python3

import csv
import statistics
import sys
from pathlib import Path


def load_run(path: Path):
    rows = {}
    cipher_construction = None

    with path.open(newline="") as f:
        for raw in f:
            line = raw.strip()

            if not line:
                continue

            if line.startswith("cipher_construction,"):
                parts = line.split(",")

                if len(parts) != 5:
                    raise RuntimeError(
                        f"{path}: malformed cipher_construction row: {line}"
                    )

                cipher_construction = {
                    "iterations": int(parts[3]),
                    "ns_op": float(parts[4]),
                }

                continue

            if not (
                line.startswith("encrypt,")
                or line.startswith("decrypt,")
            ):
                continue

            parts = line.split(",")

            if len(parts) != 5:
                raise RuntimeError(
                    f"{path}: malformed benchmark row: {line}"
                )

            operation = parts[0]
            pt_bytes = int(parts[1])
            ad_bytes = int(parts[2])
            iterations = int(parts[3])
            ns_op = float(parts[4])

            rows[(operation, pt_bytes, ad_bytes)] = {
                "iterations": iterations,
                "ns_op": ns_op,
            }

    if cipher_construction is None:
        raise RuntimeError(
            f"{path}: cipher_construction result not found"
        )

    return cipher_construction, rows


def spread_percent(values, median_value):
    if median_value == 0.0:
        return 0.0

    return (
        (max(values) - min(values))
        / median_value
        * 100.0
    )


def main():
    if len(sys.argv) < 3:
        raise SystemExit(
            "usage: summarize_components.py "
            "OUTPUT.csv RUN1.txt RUN2.txt ..."
        )

    output = Path(sys.argv[1])
    run_paths = [Path(p) for p in sys.argv[2:]]

    loaded = [
        load_run(path)
        for path in run_paths
    ]

    construction_results = [
        item[0]
        for item in loaded
    ]

    runs = [
        item[1]
        for item in loaded
    ]

    reference_keys = set(runs[0])

    for index, run in enumerate(runs[1:], start=2):
        if set(run) != reference_keys:
            raise RuntimeError(
                f"run {index} does not contain "
                "the same measurement matrix"
            )

    for key in reference_keys:
        expected_iterations = runs[0][key]["iterations"]

        for index, run in enumerate(runs[1:], start=2):
            if run[key]["iterations"] != expected_iterations:
                raise RuntimeError(
                    f"run {index}: iteration count mismatch for {key}"
                )

    construction_iterations = (
        construction_results[0]["iterations"]
    )

    for index, result in enumerate(
        construction_results[1:],
        start=2,
    ):
        if result["iterations"] != construction_iterations:
            raise RuntimeError(
                f"run {index}: cipher construction "
                "iteration count mismatch"
            )

    medians = {}

    for key in reference_keys:
        values = [
            run[key]["ns_op"]
            for run in runs
        ]

        medians[key] = statistics.median(values)

    with output.open("w", newline="") as f:
        writer = csv.writer(f)

        writer.writerow([
            "operation",
            "pt_bytes",
            "ad_bytes",
            "iterations",
            "runs",
            "median_ns_op",
            "min_ns_op",
            "max_ns_op",
            "spread_percent",
            "delta_vs_ad0_ns",
            "delta_vs_previous_ad_ns",
        ])

        construction_values = [
            result["ns_op"]
            for result in construction_results
        ]

        construction_median = statistics.median(
            construction_values
        )

        writer.writerow([
            "cipher_construction",
            0,
            0,
            construction_iterations,
            len(construction_values),
            f"{construction_median:.2f}",
            f"{min(construction_values):.2f}",
            f"{max(construction_values):.2f}",
            f"{spread_percent(construction_values, construction_median):.2f}",
            "",
            "",
        ])

        for operation in ("encrypt", "decrypt"):
            pt_values = sorted(
                {
                    pt
                    for op, pt, _ in reference_keys
                    if op == operation
                }
            )

            for pt_bytes in pt_values:
                ad_values = sorted(
                    {
                        ad
                        for op, pt, ad in reference_keys
                        if (
                            op == operation
                            and pt == pt_bytes
                        )
                    }
                )

                baseline_key = (
                    operation,
                    pt_bytes,
                    0,
                )

                baseline = medians[baseline_key]

                previous_median = None

                for ad_bytes in ad_values:
                    key = (
                        operation,
                        pt_bytes,
                        ad_bytes,
                    )

                    values = [
                        run[key]["ns_op"]
                        for run in runs
                    ]

                    median_ns = medians[key]

                    delta_vs_ad0 = (
                        median_ns - baseline
                    )

                    if previous_median is None:
                        delta_vs_previous = 0.0
                    else:
                        delta_vs_previous = (
                            median_ns
                            - previous_median
                        )

                    writer.writerow([
                        operation,
                        pt_bytes,
                        ad_bytes,
                        runs[0][key]["iterations"],
                        len(runs),
                        f"{median_ns:.2f}",
                        f"{min(values):.2f}",
                        f"{max(values):.2f}",
                        f"{spread_percent(values, median_ns):.2f}",
                        f"{delta_vs_ad0:.2f}",
                        f"{delta_vs_previous:.2f}",
                    ])

                    previous_median = median_ns

    print(f"wrote {output}")


if __name__ == "__main__":
    main()
