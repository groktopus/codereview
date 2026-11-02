#!/usr/bin/env python3
"""Enforce measured line-coverage floors and publish a per-module table.

Coverage is a floor, not a quality claim: this gate only refuses a run whose
measured line coverage fell below the recorded ratchet. It never substitutes
for behavioural assertions. The ``TARGET`` values below document the issue
target (VD-1) and the remaining gap; the ``FLOORS`` values are the enforced
ratchet. Raising a floor is a deliberate change made after new tests land.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Iterable, Mapping

# VD-1 issue target. Enforced floors are a strict ratchet below these values
# until the corresponding module actually reaches the target.
TARGET_OVERALL = 85.0
TARGET_CRITICAL = 90.0

# Enforced ratchet. These are updated only together with new tests; a floor is
# never lowered to accommodate a coverage drop. Values are the measured level
# (full suite, Python 3.14, see docs/COVERAGE-GATES.md) with a small tolerance
# for runner variation.
FLOORS: dict[str, float] = {
    "overall": 85.0,
    "github.py": 98.0,
    "publisher.py": 99.5,
    "checks.py": 99.5,
    "actions_publication.py": 98.5,
    "cli.py": 97.0,
}

CRITICAL_MODULES: tuple[str, ...] = (
    "github.py",
    "publisher.py",
    "checks.py",
    "actions_publication.py",
    "cli.py",
)


def module_name(path: str) -> str:
    """Return the package module name for a coverage JSON file path."""
    return Path(path).name


def collect_measurements(report: Mapping[str, object]) -> dict[str, dict[str, float]]:
    """Extract overall and per-module coverage from a coverage.py JSON report."""
    totals = report.get("totals")
    if not isinstance(totals, dict):
        raise ValueError("coverage report is missing totals")
    files = report.get("files")
    if not isinstance(files, dict):
        raise ValueError("coverage report is missing files")
    measured: dict[str, dict[str, float]] = {}
    measured["overall"] = {
        "percent": float(totals.get("percent_covered", 0.0)),
        "covered": float(totals.get("covered_lines", 0)),
        "statements": float(totals.get("num_statements", 0)),
    }
    for path, entry in files.items():
        if not isinstance(entry, dict):
            continue
        summary = entry.get("summary")
        if not isinstance(summary, dict):
            continue
        measured[module_name(str(path))] = {
            "percent": float(summary.get("percent_covered", 0.0)),
            "covered": float(summary.get("covered_lines", 0)),
            "statements": float(summary.get("num_statements", 0)),
        }
    return measured


def evaluate(measured: Mapping[str, Mapping[str, float]], floors: Mapping[str, float]) -> list[dict[str, object]]:
    """Build one row per enforced floor and mark whether it passed."""
    rows: list[dict[str, object]] = []
    for name, floor in floors.items():
        if name not in measured:
            rows.append(
                {
                    "module": name,
                    "percent": None,
                    "covered": 0,
                    "statements": 0,
                    "floor": floor,
                    "target": TARGET_OVERALL if name == "overall" else TARGET_CRITICAL,
                    "passed": False,
                    "missing": True,
                }
            )
            continue
        value = measured[name]
        rows.append(
            {
                "module": name,
                "percent": value["percent"],
                "covered": int(value["covered"]),
                "statements": int(value["statements"]),
                "floor": floor,
                "target": TARGET_OVERALL if name == "overall" else TARGET_CRITICAL,
                "passed": value["percent"] >= floor,
                "missing": False,
            }
        )
    return rows


def render_markdown(rows: Iterable[Mapping[str, object]]) -> str:
    """Render the per-module table appended to the CI job summary."""
    lines = [
        "## Coverage floors",
        "",
        "Coverage is measured with `pytest --cov` and enforced as a floor. "
        f"Issue target: overall ≥{TARGET_OVERALL:.0f}%, critical modules "
        f"≥{TARGET_CRITICAL:.0f}%; floors are a ratchet at the currently "
        "achieved level.",
        "",
        "| Module | Covered | Statements | Coverage | Floor | Target | Status |",
        "| --- | ---: | ---: | ---: | ---: | ---: | --- |",
    ]
    for row in rows:
        percent = "n/a" if row["percent"] is None else f"{float(row['percent']):.2f}%"
        status = "PASS" if row["passed"] else "FAIL"
        if row["missing"]:
            status = "MISSING"
        lines.append(
            f"| `{row['module']}` | {row['covered']} | {row['statements']} | {percent} | "
            f"{float(row['floor']):.2f}% | {float(row['target']):.0f}% | {status} |"
        )
    failed = [row["module"] for row in rows if not row["passed"]]
    lines.append("")
    if failed:
        lines.append("**Coverage gate failed:** " + ", ".join(f"`{name}`" for name in failed))
    else:
        lines.append("**Coverage gate passed.**")
    return "\n".join(lines)


def write_summary(text: str, summary_path: str | None = None) -> None:
    """Append the table to the GitHub job summary when the runner provides one."""
    destination = summary_path or os.environ.get("GITHUB_STEP_SUMMARY")
    if not destination:
        return
    with open(destination, "a", encoding="utf-8") as handle:
        handle.write(text + "\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--coverage-json", default="coverage.json", help="coverage.py JSON report path")
    parser.add_argument("--summary", default=None, help="markdown output path (defaults to stdout only)")
    parser.add_argument("--no-summary-env", action="store_true", help="do not append to GITHUB_STEP_SUMMARY")
    args = parser.parse_args(argv)

    report_path = Path(args.coverage_json)
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
        measured = collect_measurements(report)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"coverage gate: cannot read {report_path}: {exc}", file=sys.stderr)
        return 2

    rows = evaluate(measured, FLOORS)
    table = render_markdown(rows)
    print(table)
    if args.summary:
        Path(args.summary).write_text(table + "\n", encoding="utf-8")
    if not args.no_summary_env:
        write_summary(table)

    failed = [row for row in rows if not row["passed"]]
    if failed:
        for row in failed:
            measured_text = "missing" if row["missing"] else f"{float(row['percent']):.2f}%"
            print(
                f"coverage gate: {row['module']} measured {measured_text} below floor {float(row['floor']):.2f}%",
                file=sys.stderr,
            )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
