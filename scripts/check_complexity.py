#!/usr/bin/env python3
"""Fail new or grown functions that exceed the function-length budget.

The guard is deliberately narrow: it measures one physical span per function
and compares it with an explicit, checked-in baseline of historical offenders.
It is a ratchet, not a refactoring claim. A function already listed in the
baseline may not grow past its recorded length. If it shrinks to the threshold
or below, it is no longer an offender, so its baseline entry fails as stale
until the entry is removed or the baseline is deliberately regenerated; a
function that is not listed may not exceed the threshold at all.

Two modes are supported:

``manifest`` (the default)
    Scan every maintained Python file and enforce the baseline repository-wide.
    This is the deterministic CI mode; it does not need a base revision.

``diff`` (``--diff-base REF``)
    Parse ``git diff --unified=0 REF -- <paths>`` and check only functions that
    contain a changed line. Untouched historical offenders stay out of the way
    of a focused change, while a changed function still gets the growth check.

The default scan excludes the sha256-pinned historical compatibility fixtures
under ``tests/fixtures`` (see ``tests/fixtures/frozen-runtime-7d550b6/pins.json``).
Those files are immutable evidence (VD-3): they are not maintained code and
reformatting or refactoring them would invalidate the pins.

Exit codes: 0 clear, 1 violations, 2 usage or environment error.
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

REPORT_SCHEMA = "pr-review-complexity-report.v1"
BASELINE_SCHEMA = "pr-review-complexity-baseline.v1"
DEFAULT_THRESHOLD = 150
DEFAULT_PATHS = ("src", "scripts", "experiments", "tests")
DEFAULT_BASELINE = "scripts/complexity-baseline.v1.json"

# Historical compatibility evidence is sha256-pinned and immutable. It is
# intentionally outside the format and complexity ratchets.
EXCLUDED_PREFIXES = ("tests/fixtures/frozen-runtime-7d550b6/",)
EXCLUDED_GLOBS = ("tests/fixtures/*-base.py",)
SKIP_DIRECTORIES = frozenset({".git", ".venv", "venv", "__pycache__", "build", "dist", "node_modules"})

HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


@dataclass(frozen=True)
class FunctionRecord:
    """One function definition and its measured physical span."""

    path: str
    qualname: str
    start_line: int
    end_line: int
    lines: int


@dataclass(frozen=True)
class Finding:
    """One baseline or threshold violation."""

    code: str
    path: str
    qualname: str
    line: int
    lines: int
    message: str

    def as_dict(self) -> dict[str, object]:
        return {
            "code": self.code,
            "path": self.path,
            "qualname": self.qualname,
            "line": self.line,
            "lines": self.lines,
            "message": self.message,
        }


def _relative_posix(path: Path, root: Path) -> str:
    return path.resolve().relative_to(root.resolve()).as_posix()


def _is_excluded(relative: str) -> bool:
    if relative.startswith(EXCLUDED_PREFIXES):
        return True
    return any(Path(relative).match(pattern) for pattern in EXCLUDED_GLOBS)


def _iter_python_files(root: Path, paths: tuple[str, ...]) -> list[Path]:
    """Return sorted, deduplicated maintained Python files under ``paths``."""

    found: set[Path] = set()
    for raw in paths:
        candidate = (root / raw).resolve()
        try:
            candidate.relative_to(root.resolve())
        except ValueError:
            raise ValueError(f"scan path escapes the repository root: {raw}") from None
        if candidate.is_file():
            if candidate.suffix == ".py":
                found.add(candidate)
            continue
        if not candidate.exists():
            raise ValueError(f"scan path does not exist: {raw}")
        for file_path in candidate.rglob("*.py"):
            if any(part in SKIP_DIRECTORIES for part in file_path.parts):
                continue
            if file_path.is_file():
                found.add(file_path.resolve())
    kept = [path for path in found if not _is_excluded(_relative_posix(path, root))]
    return sorted(kept, key=lambda path: _relative_posix(path, root))


def _qualname(node: ast.AST, parents: dict[ast.AST, ast.AST]) -> str:
    parts: list[str] = []
    current: ast.AST | None = node
    while current is not None:
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            parts.append(current.name)
        current = parents.get(current)
    return ".".join(reversed(parts))


def functions_in_source(path: str, source: str) -> list[FunctionRecord]:
    """Parse ``source`` and return every function definition with its span."""

    tree = ast.parse(source, filename=path)
    parents: dict[ast.AST, ast.AST] = {}
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            parents[child] = parent
    records: list[FunctionRecord] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        end_line = node.end_lineno or node.lineno
        records.append(
            FunctionRecord(
                path=path,
                qualname=_qualname(node, parents),
                start_line=node.lineno,
                end_line=end_line,
                lines=end_line - node.lineno + 1,
            )
        )
    return sorted(records, key=lambda record: (record.start_line, record.qualname))


def scan(root: Path, paths: tuple[str, ...]) -> tuple[list[FunctionRecord], list[str]]:
    """Return ``(functions, scanned_file_paths)`` for the maintained tree."""

    files = _iter_python_files(root, paths)
    records: list[FunctionRecord] = []
    scanned: list[str] = []
    for file_path in files:
        relative = _relative_posix(file_path, root)
        scanned.append(relative)
        records.extend(functions_in_source(relative, file_path.read_text(encoding="utf-8")))
    return records, scanned


def changed_lines(root: Path, base: str, paths: tuple[str, ...]) -> dict[str, list[tuple[int, int]]]:
    """Return changed new-side line ranges per repository-relative path."""

    command = [
        "git",
        "-C",
        str(root),
        "diff",
        "--unified=0",
        "--no-color",
        "--no-ext-diff",
        "--diff-filter=AMR",
        "--relative",
        base,
        "--",
        *paths,
    ]
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise ValueError(f"git diff against {base!r} failed: {result.stderr.strip()}")
    ranges: dict[str, list[tuple[int, int]]] = {}
    current: str | None = None
    for line in result.stdout.splitlines():
        if line.startswith("+++ "):
            target = line[4:].strip()
            current = None if target == "/dev/null" else target.removeprefix("b/")
            if current is not None:
                ranges.setdefault(current, [])
            continue
        if current is None:
            continue
        match = HUNK_RE.match(line)
        if not match:
            continue
        start = int(match.group(1))
        count = int(match.group(2)) if match.group(2) is not None else 1
        # A deletion-only hunk reports count 0; treat the insertion point as
        # changed so a function that lost lines is still reviewed.
        end = start + max(count, 1) - 1
        ranges[current].append((start, end))
    return ranges


def _overlaps(record: FunctionRecord, ranges: list[tuple[int, int]]) -> bool:
    return any(record.start_line <= end and start <= record.end_line for start, end in ranges)


def load_baseline(path: Path) -> dict[str, int]:
    """Load the baseline as ``{"path::qualname": recorded_lines}``."""

    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("schema") != BASELINE_SCHEMA:
        raise ValueError(f"baseline schema must be {BASELINE_SCHEMA!r}")
    entries = data.get("entries")
    if not isinstance(entries, list):
        raise ValueError("baseline entries must be a list")
    baseline: dict[str, int] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("each baseline entry must be an object")
        entry_path = entry.get("path")
        qualname = entry.get("qualname")
        lines = entry.get("lines")
        if not isinstance(entry_path, str) or not isinstance(qualname, str):
            raise ValueError("baseline entry path and qualname must be strings")
        if not isinstance(lines, int) or lines <= 0:
            raise ValueError("baseline entry lines must be a positive integer")
        if Path(entry_path).is_absolute() or ".." in Path(entry_path).parts:
            raise ValueError(f"baseline path must be repository-relative: {entry_path!r}")
        key = f"{entry_path}::{qualname}"
        if key in baseline:
            raise ValueError(f"duplicate baseline entry: {key}")
        baseline[key] = lines
    threshold = data.get("threshold")
    if threshold is not None and not isinstance(threshold, int):
        raise ValueError("baseline threshold must be an integer when present")
    return baseline


def evaluate(
    records: list[FunctionRecord],
    baseline: dict[str, int],
    threshold: int,
    *,
    ranges: dict[str, list[tuple[int, int]]] | None = None,
    scanned_paths: set[str] | None = None,
    root: Path | None = None,
) -> list[Finding]:
    """Apply the baseline and threshold, optionally scoped to diff ranges.

    ``scanned_paths`` keeps a partial ``--paths`` scan from reporting every
    baseline entry outside the requested scope as stale. A baseline path that
    no longer exists on disk is still stale.
    """

    findings: list[Finding] = []
    for record in records:
        if ranges is not None and not _overlaps(record, ranges.get(record.path, [])):
            continue
        key = f"{record.path}::{record.qualname}"
        recorded = baseline.get(key)
        if recorded is None:
            if record.lines > threshold:
                findings.append(
                    Finding(
                        code="NEW_OVER_THRESHOLD",
                        path=record.path,
                        qualname=record.qualname,
                        line=record.start_line,
                        lines=record.lines,
                        message=(
                            f"function is {record.lines} lines, over the {threshold}-line budget; "
                            "split it or add an explicit reviewed baseline entry"
                        ),
                    )
                )
            continue
        if record.lines > recorded:
            findings.append(
                Finding(
                    code="BASELINE_GROWTH",
                    path=record.path,
                    qualname=record.qualname,
                    line=record.start_line,
                    lines=record.lines,
                    message=(
                        f"baselined function grew from {recorded} to {record.lines} lines; "
                        "shrink it, split it, or record a reviewed baseline increase"
                    ),
                )
            )
    if ranges is not None:
        return findings

    known_offenders = {f"{record.path}::{record.qualname}": record for record in records if record.lines > threshold}
    for key, recorded in baseline.items():
        if key in known_offenders:
            continue
        entry_path, _, qualname = key.partition("::")
        if scanned_paths is not None and entry_path not in scanned_paths:
            if root is not None and (root / entry_path).exists():
                continue
        findings.append(
            Finding(
                code="BASELINE_STALE",
                path=entry_path,
                qualname=qualname,
                line=0,
                lines=recorded,
                message=(
                    "baseline entry no longer matches a function over the threshold; "
                    "remove it or regenerate the baseline deliberately"
                ),
            )
        )
    return sorted(findings, key=lambda finding: (finding.path, finding.line, finding.qualname, finding.code))


def write_baseline(path: Path, records: list[FunctionRecord], threshold: int) -> None:
    """Write the current offenders as the explicit baseline."""

    entries = [
        {"path": record.path, "qualname": record.qualname, "lines": record.lines}
        for record in records
        if record.lines > threshold
    ]
    entries.sort(key=lambda entry: (str(entry["path"]), str(entry["qualname"])))
    payload = {
        "schema": BASELINE_SCHEMA,
        "threshold": threshold,
        "entries": entries,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=False) + "\n", encoding="utf-8")


def _summary_markdown(report: dict[str, object]) -> str:
    findings = report["findings"]
    assert isinstance(findings, list)
    lines = [
        "# Complexity guard",
        "",
        f"- Status: **{report['status']}**",
        f"- Mode: `{report['mode']}`",
        f"- Threshold: {report['threshold']} physical lines per function",
        f"- Scanned files: {report['scanned_files']}",
        f"- Functions inspected: {report['functions_checked']}",
        f"- Baseline entries: {report['baseline_entries']}",
        f"- Findings: {len(findings)}",
        "",
    ]
    if findings:
        lines.extend(["## Findings", "", "| Code | Location | Lines | Message |", "|---|---|---|---|"])
        for finding in findings:
            assert isinstance(finding, dict)
            lines.append(
                f"| `{finding['code']}` | `{finding['path']}`:{finding['line']} "
                f"`{finding['qualname']}` | {finding['lines']} | {finding['message']} |"
            )
        lines.append("")
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--threshold", type=int, default=DEFAULT_THRESHOLD)
    parser.add_argument("--baseline", type=Path, default=None)
    parser.add_argument("--paths", nargs="+", default=list(DEFAULT_PATHS))
    parser.add_argument("--diff-base", default=None, help="check only functions touched since this Git revision")
    parser.add_argument("--json", action="store_true", help="emit the report as JSON")
    parser.add_argument("--summary", type=Path, default=None, help="write a Markdown summary")
    parser.add_argument(
        "--update-baseline",
        action="store_true",
        help="rewrite the baseline with every current offender (deliberate maintenance action)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    root: Path = args.root.resolve()
    baseline_path = args.baseline if args.baseline is not None else root / DEFAULT_BASELINE
    if not baseline_path.is_absolute():
        baseline_path = root / baseline_path
    if args.threshold <= 0:
        parser.error("--threshold must be a positive integer")
    paths = tuple(args.paths)

    try:
        if args.diff_base is not None and args.update_baseline:
            parser.error("--update-baseline cannot be combined with --diff-base")
        records, scanned_files = scan(root, paths)
        if args.update_baseline:
            offenders = [record for record in records if record.lines > args.threshold]
            write_baseline(baseline_path, records, args.threshold)
            print(
                f"complexity baseline rewritten: {baseline_path} "
                f"({len(offenders)} offenders, {len(records)} functions inspected)"
            )
            return 0
        baseline = load_baseline(baseline_path)
        ranges = changed_lines(root, args.diff_base, paths) if args.diff_base is not None else None
    except (OSError, ValueError, SyntaxError) as error:
        print(f"complexity guard error: {error}", file=sys.stderr)
        return 2

    findings = evaluate(
        records,
        baseline,
        args.threshold,
        ranges=ranges,
        scanned_paths=set(scanned_files),
        root=root,
    )
    report: dict[str, object] = {
        "schema": REPORT_SCHEMA,
        "status": "FAIL" if findings else "PASS",
        "mode": "diff" if args.diff_base is not None else "manifest",
        "diff_base": args.diff_base,
        "threshold": args.threshold,
        "scanned_files": len(scanned_files),
        "functions_checked": len(records),
        "baseline_entries": len(baseline),
        "findings": [finding.as_dict() for finding in findings],
    }
    if args.summary is not None:
        summary_path: Path = args.summary
        if not summary_path.is_absolute():
            summary_path = root / summary_path
        summary_path.parent.mkdir(parents=True, exist_ok=True)
        summary_path.write_text(_summary_markdown(report), encoding="utf-8")
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        for finding in findings:
            print(f"{finding.code}: {finding.path}:{finding.line} {finding.qualname} ({finding.lines} lines)")
            print(f"  {finding.message}")
        print(
            f"complexity guard {report['status']}: {len(findings)} finding(s), "
            f"{len(records)} functions in {len(scanned_files)} files, threshold {args.threshold}"
        )
    return 0 if not findings else 1


if __name__ == "__main__":
    raise SystemExit(main())
