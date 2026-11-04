"""Bounded, deterministic coverage-note repair for specialist reports.

A specialist report can omit a required unit note, or report ``PARTIAL`` /
``NOT_COVERED`` even though the original task supplied evidence local to that
unit.  This module computes a bounded repair request for those units and
validates/merges exactly one response.  It never invents evidence and never
promotes a note to ``COVERED`` without a reference that was actually supplied
for that unit.

The repair pass is deliberately separate from completeness validation.  A
failed, malformed, duplicate, or unsupported repair changes nothing; the
original notes remain and the obligation stays incomplete.
"""

from __future__ import annotations

from typing import Any

from . import contracts

COVERAGE_REPAIR_VERSION = "coverage-repair.v1"
MAX_REPAIRS_PER_CHUNK = 1
MAX_REPAIRS_PER_RUN = 128
_REPAIR_STATES = frozenset({"COVERED", "PARTIAL", "NOT_COVERED"})
_REPAIR_FIELDS = frozenset({"unit_id", "state", "reason_code", "evidence_refs", "coverage_basis"})
_POLICY_FIELDS = frozenset({"max_calls_per_chunk", "max_calls_per_run"})


class CoverageRepairError(ValueError):
    """A bounded repair contract failure suitable for a public reason code."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _text(value: Any, limit: int = 256) -> bool:
    if not isinstance(value, str) or not value.strip():
        return False
    try:
        return len(value.encode("utf-8")) <= limit
    except UnicodeEncodeError:
        return False


def _string_set(value: Any) -> set[str]:
    return {item for item in value if isinstance(item, str) and item} if isinstance(value, list) else set()


def coverage_repair_policy(profile: dict[str, Any]) -> tuple[int, int]:
    """Return ``(max_calls_per_chunk, max_calls_per_run)`` from trusted profile.

    The per-chunk bound is at most one because a chunk's report is repaired in
    at most one additional provider call.  The run bound is capped at the
    module's hard ceiling; over-cap configuration fails closed rather than
    being silently weakened.
    """
    value = profile.get("coverage_repair", {})
    if value is None:
        value = {}
    if not isinstance(value, dict) or not set(value).issubset(_POLICY_FIELDS):
        raise ValueError("invalid coverage_repair profile setting")
    per_chunk = value.get("max_calls_per_chunk", MAX_REPAIRS_PER_CHUNK)
    per_run = value.get("max_calls_per_run", MAX_REPAIRS_PER_RUN)
    if isinstance(per_chunk, bool) or not isinstance(per_chunk, int) or per_chunk not in {0, 1}:
        raise ValueError("invalid coverage_repair.max_calls_per_chunk")
    if isinstance(per_run, bool) or not isinstance(per_run, int) or per_run < 0 or per_run > MAX_REPAIRS_PER_RUN:
        raise ValueError("invalid coverage_repair.max_calls_per_run")
    return per_chunk, per_run


def _unit_evidence(task: dict[str, Any], result: dict[str, Any], snapshot: dict[str, Any]) -> dict[str, set[str]]:
    """Return supplied evidence local to each unit, using the canonical inventory."""
    supplied = _string_set(task.get("evidence_ids")) & _string_set(result.get("input_evidence_ids"))
    inventory = snapshot.get("inventory") if isinstance(snapshot, dict) else None
    if not supplied or not isinstance(inventory, list):
        return {}
    unit_evidence: dict[str, set[str]] = {}
    for unit in inventory:
        if not isinstance(unit, dict):
            continue
        unit_id = unit.get("unit_id")
        if not _text(unit_id):
            continue
        unit_evidence[unit_id] = _string_set(unit.get("evidence_ids")) & supplied
    return unit_evidence


def _covered_units(
    notes: list[Any],
    unit_ids: list[str],
    supplied: set[str],
    unit_evidence: dict[str, set[str]],
) -> set[str]:
    covered: set[str] = set()
    for note in notes:
        if not isinstance(note, dict):
            continue
        unit_id = note.get("unit_id")
        refs = note.get("evidence_refs")
        if (
            unit_id in unit_ids
            and note.get("state") == "COVERED"
            and note.get("coverage_basis") == "STATIC_REVIEW"
            and isinstance(refs, list)
            and refs
            and set(refs).issubset(supplied)
            and set(refs) & unit_evidence.get(unit_id, set())
        ):
            covered.add(unit_id)
    return covered


def build_repair_request(
    task: dict[str, Any], result: dict[str, Any], snapshot: dict[str, Any]
) -> dict[str, Any] | None:
    """Return one bounded request for missing/partial unit notes, or ``None``."""
    if not isinstance(task, dict) or not isinstance(result, dict) or result.get("status") != "SUCCEEDED":
        return None
    payload = result.get("payload")
    if not isinstance(payload, dict):
        return None
    notes = payload.get("coverage_notes")
    if not isinstance(notes, list):
        return None
    raw_unit_ids = task.get("unit_ids")
    if (
        not isinstance(raw_unit_ids, list)
        or not raw_unit_ids
        or any(not _text(unit_id) for unit_id in raw_unit_ids)
        or len(raw_unit_ids) != len(set(raw_unit_ids))
    ):
        return None
    unit_ids = list(raw_unit_ids)
    supplied = _string_set(task.get("evidence_ids")) & _string_set(result.get("input_evidence_ids"))
    unit_evidence = _unit_evidence(task, result, snapshot)
    covered = _covered_units(notes, unit_ids, supplied, unit_evidence)
    notes_by_unit: dict[str, list[dict[str, Any]]] = {unit_id: [] for unit_id in unit_ids}
    for note in notes:
        if isinstance(note, dict) and note.get("unit_id") in notes_by_unit:
            notes_by_unit[note["unit_id"]].append(note)
    requested: list[dict[str, Any]] = []
    for unit_id in unit_ids:
        local_evidence = unit_evidence.get(unit_id, set())
        if unit_id in covered or not local_evidence:
            # Never request repair for a covered unit or a unit with no supplied
            # evidence reference; either would invite invented coverage.
            continue
        prior_notes = notes_by_unit.get(unit_id, [])
        states = {note.get("state") for note in prior_notes}
        if prior_notes and not states.intersection({"PARTIAL", "NOT_COVERED"}):
            continue
        last = prior_notes[-1] if prior_notes else None
        requested.append(
            {
                "unit_id": unit_id,
                "evidence_ids": sorted(local_evidence),
                "prior_state": last.get("state") if isinstance(last, dict) else None,
                "prior_reason_code": last.get("reason_code") if isinstance(last, dict) else None,
            }
        )
    if not requested:
        return None
    return {"contract_version": COVERAGE_REPAIR_VERSION, "requested_units": requested}


def requested_units(request: dict[str, Any]) -> dict[str, dict[str, Any]]:
    if not isinstance(request, dict) or set(request) != {"contract_version", "requested_units"}:
        raise CoverageRepairError("coverage_repair_request_invalid")
    if request.get("contract_version") != COVERAGE_REPAIR_VERSION:
        raise CoverageRepairError("coverage_repair_request_invalid")
    rows = request.get("requested_units")
    if not isinstance(rows, list) or not 1 <= len(rows) <= contracts.MAX_ITEMS:
        raise CoverageRepairError("coverage_repair_request_invalid")
    units: dict[str, dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict) or set(row) != {
            "unit_id",
            "evidence_ids",
            "prior_state",
            "prior_reason_code",
        }:
            raise CoverageRepairError("coverage_repair_request_invalid")
        unit_id = row.get("unit_id")
        evidence_ids = row.get("evidence_ids")
        if (
            not _text(unit_id)
            or unit_id in units
            or not isinstance(evidence_ids, list)
            or not evidence_ids
            or any(not _text(ref) for ref in evidence_ids)
            or len(evidence_ids) != len(set(evidence_ids))
        ):
            raise CoverageRepairError("coverage_repair_request_invalid")
        units[unit_id] = row
    return units


def validate_repair_payload(
    payload: Any, request: dict[str, Any], supplied_evidence_ids: set[str]
) -> list[dict[str, Any]]:
    """Validate exactly one note per requested unit; reject the whole response."""
    requested = requested_units(request)
    if not isinstance(payload, dict) or set(payload) != {"contract_version", "coverage_notes"}:
        raise CoverageRepairError("coverage_repair_invalid_fields")
    if payload.get("contract_version") != COVERAGE_REPAIR_VERSION:
        raise CoverageRepairError("coverage_repair_unsupported_contract")
    notes = payload.get("coverage_notes")
    if not isinstance(notes, list) or len(notes) != len(requested):
        raise CoverageRepairError("coverage_repair_count_mismatch")
    supplied = set(supplied_evidence_ids) if isinstance(supplied_evidence_ids, set) else set()
    normalized: list[dict[str, Any]] = []
    seen: set[str] = set()
    for note in notes:
        if not isinstance(note, dict) or set(note) != _REPAIR_FIELDS:
            raise CoverageRepairError("coverage_repair_invalid_fields")
        unit_id = note.get("unit_id")
        if not _text(unit_id) or unit_id not in requested:
            raise CoverageRepairError("coverage_repair_unknown_unit")
        if unit_id in seen:
            raise CoverageRepairError("coverage_repair_duplicate_unit")
        state = note.get("state")
        if state not in _REPAIR_STATES:
            raise CoverageRepairError("coverage_repair_invalid_state")
        if note.get("coverage_basis") != "STATIC_REVIEW":
            raise CoverageRepairError("coverage_repair_invalid_basis")
        if not _text(note.get("reason_code")):
            raise CoverageRepairError("coverage_repair_invalid_reason_code")
        refs = note.get("evidence_refs")
        if (
            not isinstance(refs, list)
            or len(refs) > contracts.MAX_REF_COUNT
            or any(not _text(ref) for ref in refs)
            or len(refs) != len(set(refs))
            or not set(refs).issubset(supplied)
        ):
            raise CoverageRepairError("coverage_repair_unsupplied_evidence")
        local = set(requested[unit_id]["evidence_ids"])
        if refs and not set(refs) & local:
            raise CoverageRepairError("coverage_repair_cross_unit_evidence")
        if state == "COVERED" and not refs:
            raise CoverageRepairError("coverage_repair_evidence_required")
        seen.add(unit_id)
        normalized.append(
            {
                "unit_id": unit_id,
                "state": state,
                "reason_code": note["reason_code"],
                "evidence_refs": list(refs),
                "coverage_basis": "STATIC_REVIEW",
            }
        )
    if seen != set(requested):
        raise CoverageRepairError("coverage_repair_count_mismatch")
    order = {unit_id: index for index, unit_id in enumerate(requested)}
    return sorted(normalized, key=lambda note: order[note["unit_id"]])


def merge_coverage_notes(
    original_notes: list[Any], repair_notes: list[dict[str, Any]], requested_unit_ids: list[str]
) -> list[Any]:
    """Merge repairs by unit; original covered notes win any conflict."""
    requested = set(requested_unit_ids)
    protected = {
        note.get("unit_id") for note in original_notes if isinstance(note, dict) and note.get("state") == "COVERED"
    }
    replace = requested - protected
    kept = [note for note in original_notes if not (isinstance(note, dict) and note.get("unit_id") in replace)]
    return kept + [note for note in repair_notes if note["unit_id"] in replace]
