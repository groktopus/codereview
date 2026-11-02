#!/usr/bin/env python3
"""Verify decision-record index, fields, statuses, and safety-invariant links.

The check is deliberately structural. It proves that records exist and are
indexed, that the required metadata is present and valid, and that every
safety-invariant surface names an accepted record. It does not judge whether the
cited evidence is sufficient or whether the decision was wise.
"""

from __future__ import annotations

import argparse
import datetime
import json
import re
from pathlib import Path

VALID_STATUSES = ("Proposed", "Accepted", "Rejected", "Deprecated", "Superseded")
REQUIRED_FIELDS = (
    "Status",
    "Date",
    "Owner",
    "Decision authority",
    "Scope",
    "Evidence",
    "Reversal/expiry",
)
REQUIRED_SECTIONS = ("Context", "Decision", "Consequences", "Alternatives considered")
RECORD_RE = re.compile(r"^(?P<id>\d{4})-[a-z0-9][a-z0-9-]*\.md$")
LEGACY_RE = re.compile(r"^\d{3}-[a-z0-9][a-z0-9-]*\.md$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}\b")
FIELD_RE = re.compile(r"^-\s+\*\*(?P<name>[^*]+):\*\*\s*(?P<value>.*?)\s*$")
HEADING_RE = re.compile(r"^##\s+(?P<name>.+?)\s*$")
TABLE_ID_RE = re.compile(r"^\d{4}$")
LINK_RE = re.compile(r"\[[^\]]*\]\((?P<target>[^)]+)\)")
MANIFEST_SCHEMA = "decision-record-safety-invariants.v1"


def _field_value(fields: dict[str, str], name: str) -> str:
    return fields.get(name, "").strip()


def parse_record(path: Path) -> dict[str, object]:
    """Parse header fields and section headings from one ADR."""

    text = path.read_text(encoding="utf-8")
    fields: dict[str, str] = {}
    sections: set[str] = set()
    title = ""
    for number, raw_line in enumerate(text.splitlines(), 1):
        line = raw_line.strip()
        if number == 1:
            title = line
        field = FIELD_RE.match(line)
        if field:
            fields.setdefault(field.group("name").strip(), field.group("value").strip())
            continue
        heading = HEADING_RE.match(raw_line)
        if heading:
            sections.add(heading.group("name").strip().lower())
    return {"path": path, "title": title, "fields": fields, "sections": sections, "text": text}


def parse_index_rows(text: str) -> dict[str, list[str]]:
    """Return table rows whose first cell is a four-digit record id."""

    rows: dict[str, list[str]] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line.startswith("|"):
            continue
        cells = [cell.strip() for cell in line.strip("|").split("|")]
        if not cells or not TABLE_ID_RE.match(cells[0]):
            continue
        rows[cells[0]] = cells
    return rows


def _check_record(record: dict[str, object], errors: list[str]) -> None:
    path = record["path"]
    assert isinstance(path, Path)
    label = path.name
    fields = record["fields"]
    sections = record["sections"]
    assert isinstance(fields, dict)
    assert isinstance(sections, set)

    for name in REQUIRED_FIELDS:
        if not _field_value(fields, name):
            errors.append(f"{label}: missing or empty required field: {name}")

    status = _field_value(fields, "Status")
    if status not in VALID_STATUSES:
        errors.append(f"{label}: invalid status {status!r}; expected one of {', '.join(VALID_STATUSES)}")

    date = _field_value(fields, "Date")
    if date and not DATE_RE.match(date):
        errors.append(f"{label}: Date must start with YYYY-MM-DD, got {date!r}")
    elif date:
        try:
            datetime.date.fromisoformat(date[:10])
        except ValueError:
            errors.append(f"{label}: Date is not a real calendar date: {date!r}")
    for name in ("Owner", "Evidence"):
        value = _field_value(fields, name).strip().lower()
        if value in {"tbd", "todo", "unknown", "n/a", "-"}:
            errors.append(f"{label}: {name} is a placeholder, not evidence")

    if status == "Accepted":
        authority = _field_value(fields, "Decision authority").lower()
        if "unresolved" in authority or "not recorded" in authority or not authority:
            errors.append(f"{label}: accepted record needs a recorded decision authority")

    for name in REQUIRED_SECTIONS:
        if name.lower() not in sections:
            errors.append(f"{label}: missing required section: ## {name}")

    title = record["title"]
    assert isinstance(title, str)
    record_id = label[:4]
    if not title.startswith(f"# {record_id}"):
        errors.append(f"{label}: title must start with '# {record_id}'")


def _check_index(
    records: dict[str, dict[str, object]],
    rows: dict[str, list[str]],
    errors: list[str],
) -> None:
    record_ids = set(records)
    for record_id in sorted(set(rows) - record_ids):
        errors.append(f"docs/adr/README.md: row {record_id} has no record file")
    for record_id in sorted(record_ids):
        if record_id not in rows:
            errors.append(f"docs/adr/README.md: record {record_id} is not listed in the decisions table")
            continue
        cells = rows[record_id]
        if len(cells) < 6:
            errors.append(f"docs/adr/README.md: row {record_id} needs Record, Status, Owner, Date, and Evidence")
            continue
        if not cells[1] or not cells[1].startswith("["):
            errors.append(f"docs/adr/README.md: row {record_id} needs a linked record title")
        if not cells[2]:
            errors.append(f"docs/adr/README.md: row {record_id} has no status")
        if not cells[3]:
            errors.append(f"docs/adr/README.md: row {record_id} has no owner")
        if not DATE_RE.match(cells[4]):
            errors.append(f"docs/adr/README.md: row {record_id} has no YYYY-MM-DD date")
        if not cells[5]:
            errors.append(f"docs/adr/README.md: row {record_id} has no evidence")
        targets = [
            Path(match.group("target")).name
            for match in LINK_RE.finditer(cells[1])
            if RECORD_RE.match(Path(match.group("target")).name)
        ]
        if not any(name.startswith(f"{record_id}-") for name in targets):
            errors.append(f"docs/adr/README.md: row {record_id} has no link to its record file")
        fields = records[record_id]["fields"]
        assert isinstance(fields, dict)
        expected = {
            "status": _field_value(fields, "Status"),
            "owner": _field_value(fields, "Owner"),
            "date": _field_value(fields, "Date")[:10],
            "evidence": _field_value(fields, "Evidence"),
        }
        if cells[2] != expected["status"]:
            errors.append(f"docs/adr/README.md: row {record_id} status does not match the record")
        if not cells[3] or cells[3].strip().lower() in {"tbd", "todo", "unknown"}:
            errors.append(f"docs/adr/README.md: row {record_id} has no real owner")
        if cells[4] != expected["date"]:
            errors.append(f"docs/adr/README.md: row {record_id} date does not match the record")
        if not cells[5] or cells[5].strip().lower() in {"tbd", "todo", "unknown"}:
            errors.append(f"docs/adr/README.md: row {record_id} has no real evidence")


def _check_legacy(root: Path, index_text: str, errors: list[str]) -> int:
    legacy_dir = root / "docs" / "design" / "adrs"
    if not legacy_dir.is_dir():
        return 0
    legacy = sorted(path for path in legacy_dir.glob("*.md") if LEGACY_RE.match(path.name))
    for path in legacy:
        if path.name not in index_text:
            errors.append(
                f"docs/adr/README.md: legacy design ADR {path.name} must be reconciled by reference"
            )
    return len(legacy)


def _check_manifest(
    root: Path,
    manifest_path: Path,
    records: dict[str, dict[str, object]],
    errors: list[str],
) -> int:
    if not manifest_path.is_file():
        errors.append(f"missing safety-invariant manifest: {manifest_path.relative_to(root)}")
        return 0
    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        errors.append(f"{manifest_path.relative_to(root)}: invalid JSON: {exc}")
        return 0
    if data.get("schema") != MANIFEST_SCHEMA:
        errors.append(f"{manifest_path.relative_to(root)}: schema must be {MANIFEST_SCHEMA!r}")
    invariants = data.get("invariants")
    if not isinstance(invariants, list) or not invariants:
        errors.append(f"{manifest_path.relative_to(root)}: invariants must be a non-empty list")
        return 0

    seen: set[str] = set()
    for invariant in invariants:
        if not isinstance(invariant, dict):
            errors.append(f"{manifest_path.relative_to(root)}: each invariant must be an object")
            continue
        invariant_id = invariant.get("id")
        if not isinstance(invariant_id, str) or not invariant_id:
            errors.append(f"{manifest_path.relative_to(root)}: invariant is missing an id")
            continue
        if invariant_id in seen:
            errors.append(f"{manifest_path.relative_to(root)}: duplicate invariant id {invariant_id!r}")
        seen.add(invariant_id)
        if not isinstance(invariant.get("statement"), str) or not invariant["statement"].strip():
            errors.append(f"{manifest_path.relative_to(root)}: invariant {invariant_id} has no statement")

        paths = invariant.get("paths")
        if not isinstance(paths, list) or not paths:
            errors.append(f"{manifest_path.relative_to(root)}: invariant {invariant_id} has no paths")
        else:
            for relative in paths:
                if not isinstance(relative, str) or not (root / relative).exists():
                    errors.append(
                        f"{manifest_path.relative_to(root)}: invariant {invariant_id} names missing path {relative!r}"
                    )

        record_ids = invariant.get("records")
        if not isinstance(record_ids, list) or not record_ids:
            errors.append(f"{manifest_path.relative_to(root)}: invariant {invariant_id} has no records")
            continue
        for record_id in record_ids:
            if not isinstance(record_id, str) or record_id not in records:
                errors.append(
                    f"{manifest_path.relative_to(root)}: invariant {invariant_id} names unknown record {record_id!r}"
                )
                continue
            record = records[record_id]
            fields = record["fields"]
            assert isinstance(fields, dict)
            if _field_value(fields, "Status") != "Accepted":
                errors.append(
                    f"{manifest_path.relative_to(root)}: invariant {invariant_id} must link an accepted record; "
                    f"{record_id} is {_field_value(fields, 'Status') or 'unstated'}"
                )
    return len(invariants)


def _check_process_docs(root: Path, errors: list[str]) -> None:
    required = {
        "CONTRIBUTING.md": ("decision record", "safety invariant", "docs/adr/README.md"),
        ".github/pull_request_template.md": ("decision record", "safety invariant", "docs/adr/README.md"),
    }
    for relative, needles in required.items():
        path = root / relative
        if not path.is_file():
            errors.append(f"{relative}: required process document is missing")
            continue
        text = path.read_text(encoding="utf-8").lower()
        for needle in needles:
            if needle.lower() not in text:
                errors.append(f"{relative}: must document {needle!r} for safety-invariant changes")


def check(root: Path) -> dict[str, object]:
    root = root.resolve()
    adr_dir = root / "docs" / "adr"
    index_path = adr_dir / "README.md"
    manifest_path = adr_dir / "safety-invariants.json"
    errors: list[str] = []
    if not index_path.is_file():
        return {
            "schema": MANIFEST_SCHEMA,
            "records": 0,
            "legacy": 0,
            "invariants": 0,
            "errors": [f"decision-record index not found: {index_path}"],
        }

    index_text = index_path.read_text(encoding="utf-8")
    rows = parse_index_rows(index_text)

    records: dict[str, dict[str, object]] = {}
    for path in sorted(adr_dir.glob("*.md")):
        if path.name != "README.md" and not RECORD_RE.match(path.name):
            errors.append(f"docs/adr/{path.name}: record filename must be NNNN-lowercase-name.md")
    paths = sorted(path for path in adr_dir.glob("*.md") if RECORD_RE.match(path.name))
    if not paths:
        errors.append("docs/adr: no decision records found")
    for path in paths:
        record_id = path.name[:4]
        records[record_id] = parse_record(path)
        _check_record(records[record_id], errors)

    for record_id, record in records.items():
        fields = record["fields"]
        assert isinstance(fields, dict)
        if record_id in rows and rows[record_id][2] != _field_value(fields, "Status"):
            errors.append(
                f"docs/adr/README.md: row {record_id} status {rows[record_id][2]!r} does not match "
                f"record status {_field_value(fields, 'Status')!r}"
            )

    _check_index(records, rows, errors)
    legacy_count = _check_legacy(root, index_text, errors)
    invariant_count = _check_manifest(root, manifest_path, records, errors)
    _check_process_docs(root, errors)

    return {
        "schema": "decision-record-check.v1",
        "records": len(records),
        "legacy": legacy_count,
        "invariants": invariant_count,
        "errors": errors,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    result = check(args.root)
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    elif result["errors"]:
        print(
            f"Decision records: {result['records']} record(s), {result['legacy']} legacy, "
            f"{result['invariants']} safety-invariant group(s)"
        )
        for error in result["errors"]:
            print(f"  ERROR: {error}")
    else:
        print(
            f"Decision records OK: {result['records']} records indexed, "
            f"{result['legacy']} legacy proposals reconciled, "
            f"{result['invariants']} safety-invariant groups linked"
        )
    return 1 if result["errors"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
