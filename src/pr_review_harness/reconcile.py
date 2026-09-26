"""Deterministic candidate validation and cross-task finding consolidation."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _norm(value: Any) -> str:
    return re.sub(r"\s+", " ", str(value or "").strip()).casefold()


def stable_candidate_id(snapshot_id: str, candidate: dict) -> str:
    location = candidate.get("location") if isinstance(candidate.get("location"), dict) else {}
    basis = {
        "snapshot_id": snapshot_id,
        "unit_id": candidate.get("unit_id"),
        "path": location.get("path", candidate.get("path")),
        "side": location.get("side", "HEAD"),
        "line": location.get("line", candidate.get("line")),
        "kind": location.get("kind", "line"),
        "observation": _norm(candidate.get("observation")),
        "consequence": _norm(candidate.get("consequence")),
        "rule": _norm(candidate.get("rule_or_contract")),
    }
    return "finding-" + hashlib.sha256(_canonical(basis)).hexdigest()[:20]


def validate_location(
    candidate: dict, unit: dict | None, task_units: set[str], unit_map: dict
) -> tuple[bool, dict, int | None, str | None]:
    """Validate HEAD/BASE line or explicit file-level anchors against snapshot inventory."""
    raw = candidate.get("location", {})
    location = dict(raw) if isinstance(raw, dict) else {}
    path = location.get("path") or candidate.get("path")
    line = location.get("line") if location.get("line") is not None else candidate.get("line")
    side = location.get("side", "HEAD")
    explicit_uid = candidate.get("unit_id")
    path_units = [
        uid
        for uid in task_units
        if unit_map.get(uid, {}).get("path") == path or unit_map.get(uid, {}).get("old_path") == path
    ]
    uid = explicit_uid if explicit_uid in task_units else path_units[0] if len(path_units) == 1 else None
    unit = unit if unit is not None else unit_map.get(uid)
    if not unit or uid not in task_units:
        return False, location, None, uid
    paths = {unit.get("path")}
    change_type = {"added": "add", "deleted": "delete", "modified": "modify", "renamed": "rename"}.get(
        unit.get("change_type"), unit.get("change_type")
    )
    if change_type == "rename":
        paths.add(unit.get("old_path"))
    if path not in paths or side not in {"HEAD", "BASE"}:
        return False, location, None, uid
    kind = location.get("kind", "line" if line is not None else None)
    if kind == "file":
        expected = unit.get("file_level_location")
        ok = bool(
            isinstance(expected, dict)
            and expected.get("kind") == "file"
            and expected.get("path") == path
            and expected.get("side") == side
        )
        location.update({"path": path, "side": side, "kind": "file"})
        return ok, location, None, uid
    if isinstance(line, bool) or not isinstance(line, int) or line < 1:
        return False, location, None, uid
    if side == "BASE":
        ranges = unit.get("old_line_ranges", [])
        expected_path = unit.get("old_path") if change_type == "rename" else unit.get("path")
        ok = path == expected_path and any(
            isinstance(r, (list, tuple)) and len(r) >= 2 and int(r[0]) <= line <= int(r[1]) for r in ranges
        )
    else:
        ranges = unit.get("changed_lines", unit.get("line_ranges", []))
        ok = path == unit.get("path") and any(
            isinstance(r, (list, tuple)) and len(r) >= 2 and int(r[0]) <= line <= int(r[1]) for r in ranges
        )
    location.update({"path": path, "side": side, "line": line, "kind": "line"})
    return bool(ok), location, line, uid


def consolidate_findings(findings: list[dict]) -> list[dict]:
    """Merge exact duplicates; conflicting assessments become unresolved, never votes."""
    groups: dict[str, list[dict]] = {}
    for finding in findings:
        loc = finding.get("location", {}) if isinstance(finding.get("location"), dict) else {}
        basis = {
            "snapshot_id": finding.get("snapshot_id"),
            "unit_id": finding.get("unit_id"),
            "path": loc.get("path", finding.get("path")),
            "side": loc.get("side", "HEAD"),
            "kind": loc.get("kind", "line" if loc.get("line") else "file"),
            "line": loc.get("line"),
            "observation": _norm(finding.get("observation")),
            "consequence": _norm(finding.get("consequence")),
            "rule": _norm(finding.get("rule_or_contract")),
        }
        key = hashlib.sha256(_canonical(basis)).hexdigest()
        groups.setdefault(key, []).append(finding)

    result = []
    for key, members in groups.items():
        canonical = dict(sorted(members, key=lambda item: item.get("finding_id", ""))[0])
        assessments = [m.get("semantic_assessment") for m in members if isinstance(m.get("semantic_assessment"), dict)]
        outcomes = {a.get("outcome") for a in assessments}
        support_shapes = {
            tuple(
                a.get(k)
                for k in (
                    "outcome",
                    "observation_support",
                    "consequence_support",
                    "rule_connection_support",
                    "introducedness",
                    "material_consequence",
                )
            )
            for a in assessments
        }
        conflict = (
            "CONTRADICTED" in outcomes
            or len({shape for shape in support_shapes if shape}) > 1
            and ("SUPPORTED" in outcomes or "CONTRADICTED" in outcomes)
        )
        canonical["candidate_ids"] = sorted(
            {m.get("candidate_id", m.get("finding_id")) for m in members if m.get("candidate_id", m.get("finding_id"))}
        )
        canonical["task_ids"] = sorted({m.get("task_id") for m in members if m.get("task_id")})
        canonical["evidence_refs"] = sorted({ref for m in members for ref in m.get("evidence_refs", [])})
        canonical["assessment_records"] = [
            {
                "candidate_id": m.get("candidate_id", m.get("finding_id")),
                "task_id": m.get("task_id"),
                "semantic_assessment": m.get("semantic_assessment"),
                "semantic_usage": m.get("semantic_usage", {}),
                "semantic_provenance": m.get("semantic_provenance", {}),
            }
            for m in sorted(
                members,
                key=lambda item: (
                    str(item.get("task_id", "")),
                    str(item.get("candidate_id", item.get("finding_id", ""))),
                ),
            )
        ]
        canonical["duplicate_count"] = len(members) - 1
        canonical["correlation_group_id"] = "correlation-" + key[:16] if len(members) > 1 or conflict else None
        if conflict:
            canonical["status"] = "CONTRADICTED"
            canonical["blocking_class"] = "UNRESOLVED"
            canonical["blocking_rationale"] = (
                "Conflicting bounded assessments were preserved; no provider count or vote selects a result."
            )
            canonical["reconciliation_conflict"] = True
        result.append(canonical)
    return sorted(result, key=lambda finding: finding.get("finding_id", ""))
