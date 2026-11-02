"""Tests for the decision-record index, metadata, and safety-invariant links."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import check_decision_records as records  # noqa: E402

RECORD = """# 0001 — Test record

- **Status:** {status}
- **Date:** 2026-11-01
- **Owner:** Test owner
- **Decision authority:** Test authority
- **Scope:** Test scope
- **Evidence:** Test evidence
- **Reversal/expiry:** Never

## Context

Test context.

## Decision

Test decision.

## Consequences

Test consequences.

## Alternatives considered

Test alternative.
"""

INDEX = """# Decision records

| ID | Record | Status | Owner | Date | Evidence |
|---|---|---|---|---|---|
| 0001 | [Test record](0001-test-record.md) | {status} | Test owner | 2026-11-01 | Test evidence |
"""

MANIFEST = {
    "schema": records.MANIFEST_SCHEMA,
    "invariants": [
        {
            "id": "test-invariant",
            "statement": "A test safety invariant.",
            "paths": ["src/example.py"],
            "records": ["0001"],
        }
    ],
}


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def make_repo(tmp_path: Path, status: str = "Accepted") -> Path:
    write(tmp_path / "docs" / "adr" / "0001-test-record.md", RECORD.format(status=status))
    write(tmp_path / "docs" / "adr" / "README.md", INDEX.format(status=status))
    write(tmp_path / "docs" / "adr" / "safety-invariants.json", json.dumps(MANIFEST))
    write(tmp_path / "src" / "example.py", "# example\n")
    write(
        tmp_path / "CONTRIBUTING.md",
        "A safety invariant change needs a decision record. See docs/adr/README.md.\n",
    )
    write(
        tmp_path / ".github" / "pull_request_template.md",
        "A safety invariant change needs a decision record. See docs/adr/README.md.\n",
    )
    return tmp_path


def test_repository_decision_log_passes() -> None:
    result = records.check(ROOT)
    assert result["errors"] == []
    assert result["records"] == 8
    assert result["legacy"] == 4
    assert result["invariants"] == 7


def test_missing_required_field_fails(tmp_path: Path) -> None:
    root = make_repo(tmp_path)
    path = root / "docs" / "adr" / "0001-test-record.md"
    path.write_text(path.read_text(encoding="utf-8").replace("- **Owner:** Test owner\n", ""), encoding="utf-8")
    result = records.check(root)
    assert any("missing or empty required field: Owner" in error for error in result["errors"])


def test_invalid_status_fails(tmp_path: Path) -> None:
    root = make_repo(tmp_path, status="Approved")
    result = records.check(root)
    assert any("invalid status 'Approved'" in error for error in result["errors"])


def test_missing_index_row_fails(tmp_path: Path) -> None:
    root = make_repo(tmp_path)
    write(root / "docs" / "adr" / "README.md", "# Decision records\n")
    result = records.check(root)
    assert any("record 0001 is not listed" in error for error in result["errors"])


def test_safety_invariant_must_link_accepted_record(tmp_path: Path) -> None:
    root = make_repo(tmp_path, status="Proposed")
    result = records.check(root)
    assert any("must link an accepted record" in error for error in result["errors"])


def test_safety_invariant_missing_path_fails(tmp_path: Path) -> None:
    root = make_repo(tmp_path)
    manifest = dict(MANIFEST)
    manifest["invariants"] = [dict(MANIFEST["invariants"][0], paths=["src/missing.py"])]
    write(root / "docs" / "adr" / "safety-invariants.json", json.dumps(manifest))
    result = records.check(root)
    assert any("names missing path 'src/missing.py'" in error for error in result["errors"])


def test_legacy_adr_must_be_reconciled(tmp_path: Path) -> None:
    root = make_repo(tmp_path)
    write(root / "docs" / "design" / "adrs" / "001-legacy.md", "# ADR-001\n")
    result = records.check(root)
    assert any("001-legacy.md must be reconciled" in error for error in result["errors"])
