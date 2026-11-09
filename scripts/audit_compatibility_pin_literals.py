#!/usr/bin/env python3
"""Inventory hash-shaped literals without deciding whether they are pins.

This is a read-only diagnostic for VD-3. It scans explicitly enumerated source,
script, test, and workflow roots. It emits occurrences with a bounded line-context
hash and a conservative structural class; it never rewrites or migrates pins.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
TOKEN = re.compile(r"(?<![0-9a-fA-F])(?:[0-9a-fA-F]{40}|[0-9a-f]{64})(?![0-9a-fA-F])")
TEXT_SUFFIXES = {".py", ".md", ".json", ".yml", ".yaml", ".toml", ".ini", ".cfg"}
EXCLUDED_PARTS = {".git", ".venv", "venv", "__pycache__", ".mypy_cache", ".pytest_cache"}
GENERATED_CENSUS_RE = re.compile(r"docs/evidence/vd3-pin-census-[^/]+\.json$")
ROOTS = ("src", "scripts", "tests", "experiments", "docs", "examples", ".github")
MAX_CONTEXT_CHARS = 240


def _category(path: str, line: str, token: str) -> tuple[str, str]:
    """Classify only strong structural signals; ambiguous literals stay unknown."""
    lowered = line.lower()
    if path.startswith(".github/") and re.search(r"uses\s*:\s*[^\s@]+@" + re.escape(token), line):
        return "action_commit_pin", "GitHub workflow action reference uses @<revision> syntax."
    if len(token) == 40 and re.search(r"(?:historical|source)_revision|\b(?:base|head)_sha\b|commit(?:_sha)?", lowered):
        return "git_revision_candidate", "40-hex value occurs in a source/revision identity field."
    if len(token) == 64 and re.search(r"(?:sha256|digest|content_hash|artifact_hash|fixture_hash)", lowered):
        return "content_digest_candidate", "64-hex value occurs in a digest/hash field."
    if len(token) == 64 and re.search(r"(?:pinned|historical|compatibility|value_pin)", lowered):
        return "compatibility_pin_candidate", "64-hex value is named as a pin or historical compatibility value."
    return "unknown", "Hash-shaped token has no sufficiently strong local structural signal."


def audit(root: Path = ROOT, *, source_revision: str | None = None) -> dict[str, Any]:
    occurrences: list[dict[str, Any]] = []
    scanned_files = 0
    for root_name in ROOTS:
        directory = root / root_name
        if not directory.exists():
            continue
        for path in sorted(directory.rglob("*")):
            if not path.is_file() or path.suffix.lower() not in TEXT_SUFFIXES:
                continue
            relative_path = path.relative_to(root).as_posix()
            relative_parts = path.relative_to(root).parts
            if GENERATED_CENSUS_RE.fullmatch(relative_path):
                continue
            if any(part in EXCLUDED_PARTS for part in relative_parts):
                continue
            try:
                raw = path.read_bytes()
                text = raw.decode("utf-8")
            except (OSError, UnicodeError):
                continue
            scanned_files += 1
            for line_number, line in enumerate(text.splitlines(), 1):
                for match in TOKEN.finditer(line):
                    token = match.group(0)
                    category, rationale = _category(path.relative_to(root).as_posix(), line, token)
                    context = line.strip()[:MAX_CONTEXT_CHARS]
                    occurrences.append(
                        {
                            "path": path.relative_to(root).as_posix(),
                            "line": line_number,
                            "token": token,
                            "width": len(token),
                            "category": category,
                            "rationale": rationale,
                            "context_sha256": hashlib.sha256(context.encode("utf-8")).hexdigest(),
                        }
                    )
    occurrences.sort(key=lambda row: (row["path"], row["line"], row["token"]))
    counts: dict[str, int] = {}
    for row in occurrences:
        counts[row["category"]] = counts.get(row["category"], 0) + 1
    return {
        "schema": "vd3-compatibility-pin-census.v1",
        "source_revision": source_revision,
        "scope_roots": list(ROOTS),
        "scanned_file_count": scanned_files,
        "occurrence_count": len(occurrences),
        "category_counts": dict(sorted(counts.items())),
        "classification_note": "Candidate inventory only; hash shape and heuristic category do not prove a compatibility pin. Unknowns require review; no migration or enforcement is implied.",
        "occurrences": occurrences,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT, help="repository tree to inventory")
    parser.add_argument("--output", type=Path, help="write JSON to this path; stdout by default")
    parser.add_argument("--source-revision", help="record the exact Git revision being inventoried")
    parser.add_argument(
        "--evidence-output",
        action="store_true",
        help="allow writing into docs/evidence/ (the generated census excludes itself)",
    )
    args = parser.parse_args(argv)
    result = audit(args.root.resolve(), source_revision=args.source_revision)
    rendered = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        destination = args.output.resolve()
        evidence_root = (ROOT / "docs" / "evidence").resolve()
        if evidence_root in destination.parents and not args.evidence_output:
            parser.error("refusing to write docs/evidence without --evidence-output")
        if args.evidence_output and evidence_root not in destination.parents:
            parser.error("--evidence-output is only valid for destinations under docs/evidence")
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
