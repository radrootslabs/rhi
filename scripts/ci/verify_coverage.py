#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import pathlib
import sys
import tomllib


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="verify coverage thresholds")
    parser.add_argument("--thresholds", required=True, type=pathlib.Path)
    parser.add_argument("--summary", required=True, type=pathlib.Path)
    parser.add_argument("--lcov", required=True, type=pathlib.Path)
    return parser.parse_args()


def read_thresholds(path: pathlib.Path) -> dict[str, float | bool]:
    payload = tomllib.loads(path.read_text(encoding="utf-8"))
    coverage = payload.get("coverage")
    if not isinstance(coverage, dict):
        raise ValueError("missing [coverage] table")
    return {
        "line_percent": float(coverage["line_percent"]),
        "function_percent": float(coverage["function_percent"]),
        "branch_percent": float(coverage["branch_percent"]),
        "require_branch_records": bool(coverage["require_branch_records"]),
    }


def read_totals(path: pathlib.Path) -> dict[str, object]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    data = payload.get("data")
    if not isinstance(data, list) or not data:
        raise ValueError("coverage summary missing data entries")
    totals = data[0].get("totals")
    if not isinstance(totals, dict):
        raise ValueError("coverage summary missing totals")
    return totals


def metric_percent(totals: dict[str, object], metric: str) -> float:
    metric_obj = totals.get(metric)
    if not isinstance(metric_obj, dict):
        raise ValueError(f"missing totals metric: {metric}")
    percent = metric_obj.get("percent")
    if not isinstance(percent, (int, float)):
        raise ValueError(f"missing percent for metric: {metric}")
    return float(percent)


def metric_count(totals: dict[str, object], metric: str) -> int:
    metric_obj = totals.get(metric)
    if not isinstance(metric_obj, dict):
        raise ValueError(f"missing totals metric: {metric}")
    count = metric_obj.get("count")
    if not isinstance(count, int):
        raise ValueError(f"missing count for metric: {metric}")
    return count


def lcov_branch_record_count(path: pathlib.Path) -> int:
    total = 0
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        if not raw_line.startswith("BRF:"):
            continue
        value = raw_line[4:].strip()
        if not value:
            continue
        total += int(value)
    return total


def main() -> int:
    args = parse_args()
    thresholds = read_thresholds(args.thresholds)
    totals = read_totals(args.summary)

    checks = [
        ("lines", metric_percent(totals, "lines"), thresholds["line_percent"]),
        (
            "functions",
            metric_percent(totals, "functions"),
            thresholds["function_percent"],
        ),
        (
            "branches",
            metric_percent(totals, "branches"),
            thresholds["branch_percent"],
        ),
    ]

    errors: list[str] = []
    for name, actual, required in checks:
        if actual < float(required):
            errors.append(f"{name} coverage {actual:.4f}% is below {required:.4f}%")

    if thresholds["require_branch_records"]:
        branch_total = metric_count(totals, "branches")
        if branch_total <= 0:
            errors.append("summary has no branch records")
        lcov_branches = lcov_branch_record_count(args.lcov)
        if lcov_branches <= 0:
            errors.append("lcov report has no branch records")

    print(
        "coverage totals: "
        f"lines={metric_percent(totals, 'lines'):.4f}% "
        f"functions={metric_percent(totals, 'functions'):.4f}% "
        f"branches={metric_percent(totals, 'branches'):.4f}%"
    )
    if errors:
        for error in errors:
            print(f"coverage gate error: {error}", file=sys.stderr)
        return 1
    print("coverage gate passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
