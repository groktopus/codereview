"""Bounded coverage-note repair regression tests.

These tests exercise the optional repair stage through the real entry point.
They never dispatch a network call: the fake provider implements the same
method shape as the OpenAI-compatible adapter and returns already-structured
payloads.
"""

from __future__ import annotations

import copy

from pr_review_harness.engine import run_review
from pr_review_harness.planner import plan_review

LIMITS = {
    "deadline_seconds": 5,
    "max_concurrent_scopes": 2,
    "max_provider_calls": 8,
    "max_retries_per_task": 0,
    "max_context_bytes": 120_000,
    "max_input_bytes_per_task": 45_000,
    "max_output_bytes_per_task": 16_000,
    "max_output_bytes": 192_000,
    "max_context_retrievals": 2,
    "max_followup_tasks": 0,
}


def make_snapshot(unit_evidence=None):
    unit_evidence = unit_evidence or {"u0": ["diff:u0"], "u1": ["diff:u1"]}
    inventory = []
    evidence = {}
    for unit_id, evidence_ids in unit_evidence.items():
        inventory.append(
            {
                "unit_id": unit_id,
                "path": f"src/{unit_id}.py",
                "kind": "human_code",
                "change": "modified",
                "diff": "-old\n+new",
                "changed_lines": [[1, 2]],
                "evidence_ids": list(evidence_ids),
            }
        )
        for evidence_id in evidence_ids:
            evidence[evidence_id] = {
                "evidence_id": evidence_id,
                "snapshot_id": "snap",
                "path": f"src/{unit_id}.py",
                "line_start": 1,
                "line_end": 2,
                "content": "-old\n+new",
                "content_hash": "a" * 64,
                "source_kind": "diff",
                "trust": "untrusted_pr_content",
            }
    return {
        "snapshot_id": "snap",
        "base_sha": "b" * 40,
        "head_sha": "c" * 40,
        "profile_version": "p1",
        "snapshot_hash": "d" * 64,
        "freshness_basis": "HISTORICAL_SNAPSHOT",
        "inventory": inventory,
        "evidence": evidence,
        "gaps": [],
    }


def profile(repair=None):
    value = {"version": "p1", "required_lenses": ["correctness"], "allow_empty_approval": True}
    if repair is not None:
        value["coverage_repair"] = repair
    return value


class RepairProvider:
    """Emit configured initial notes, then answer one repair call if asked."""

    identity = {"kind": "test", "model": "coverage-repair"}

    def __init__(self, initial, repair=None, repair_error=None, duplicate=False):
        self.initial = initial
        self.repair = repair or {}
        self.repair_error = repair_error
        self.duplicate = duplicate
        self.review_calls = 0
        self.repair_calls = 0
        self.requested_units = []

    def review(self, task, evidence, limits):
        self.review_calls += 1
        notes = []
        for unit_id in task["unit_ids"]:
            spec = self.initial.get(unit_id)
            if spec is None:
                continue
            state, refs = spec
            notes.append(
                {
                    "unit_id": unit_id,
                    "state": state,
                    "reason_code": "TEST_INITIAL_STATE",
                    "evidence_refs": list(refs),
                    "coverage_basis": "STATIC_REVIEW",
                }
            )
        return {
            "payload": {
                "finding_candidates": [],
                "context_gap_proposals": [],
                "coverage_notes": notes,
            },
            "usage": {},
            "provenance": {
                "provider_contract_version": "specialist-findings.v4",
                "provenance": {"provider": "test"},
            },
        }

    def repair_coverage(self, task, evidence, limits):
        self.repair_calls += 1
        requested = task["coverage_repair"]["requested_units"]
        self.requested_units.append([row["unit_id"] for row in requested])
        if self.repair_error is not None:
            raise self.repair_error
        notes = []
        for row in requested:
            spec = self.repair.get(row["unit_id"])
            if spec is None:
                continue
            state, refs = spec
            notes.append(
                {
                    "unit_id": row["unit_id"],
                    "state": state,
                    "reason_code": "TEST_REPAIR_STATE",
                    "evidence_refs": list(refs),
                    "coverage_basis": "STATIC_REVIEW",
                }
            )
        if self.duplicate and notes:
            notes.append(copy.deepcopy(notes[0]))
        return {
            "payload": {"contract_version": "coverage-repair.v1", "coverage_notes": notes},
            "usage": {},
            "provenance": {"provider_contract_version": "coverage-repair.v1"},
        }


def run(tmp_path, provider, snapshot=None, repair_profile=None, limits=None):
    snapshot = snapshot or make_snapshot()
    profile_value = profile(repair_profile)
    plan = plan_review(snapshot, profile_value)
    return run_review(
        snapshot,
        plan,
        profile_value,
        provider,
        None,
        limits or dict(LIMITS),
        str(tmp_path / "out"),
        "coverage-repair-run",
    )


def notes_by_unit(result, task_id):
    output = result["ledger"]["outputs"][task_id]
    return {note["unit_id"]: note for note in output["payload"]["coverage_notes"]}


def test_missing_unit_note_is_repaired_once_and_coverage_completes(tmp_path):
    provider = RepairProvider(
        initial={"u0": ("COVERED", ["diff:u0"])},
        repair={"u1": ("COVERED", ["diff:u1"])},
    )
    result = run(tmp_path, provider)

    assert result["coverage_state"] == "COMPLETE"
    assert result["disposition"] == "APPROVE"
    task_id = next(iter(result["task_results"]))
    assert notes_by_unit(result, task_id)["u1"]["state"] == "COVERED"
    repair = result["ledger"]["coverage_repairs"][task_id]
    assert repair["status"] == "REPAIRED"
    assert repair["requested_unit_ids"] == ["u1"]
    assert repair["repaired_unit_ids"] == ["u1"]
    assert result["budget"]["provider_calls_reserved"] == 2


def test_partial_note_is_repaired_and_replaces_the_original(tmp_path):
    provider = RepairProvider(
        initial={"u0": ("PARTIAL", ["diff:u0"]), "u1": ("COVERED", ["diff:u1"])},
        repair={"u0": ("COVERED", ["diff:u0"])},
    )
    result = run(tmp_path, provider)

    assert result["coverage_state"] == "COMPLETE"
    task_id = next(iter(result["task_results"]))
    assert notes_by_unit(result, task_id)["u0"]["state"] == "COVERED"
    repair = result["ledger"]["coverage_repairs"][task_id]
    assert repair["status"] == "REPAIRED"
    assert repair["requested_unit_ids"] == ["u0"]
    assert repair["original_coverage_notes"][0]["state"] == "PARTIAL"


def test_repair_that_remains_partial_keeps_the_obligation_incomplete(tmp_path):
    provider = RepairProvider(
        initial={"u0": ("PARTIAL", ["diff:u0"]), "u1": ("PARTIAL", ["diff:u1"])},
        repair={"u0": ("COVERED", ["diff:u0"]), "u1": ("PARTIAL", ["diff:u1"])},
    )
    result = run(tmp_path, provider)

    assert result["coverage_state"] == "PARTIAL"
    assert result["disposition"] == "INCOMPLETE"
    task_id = next(iter(result["task_results"]))
    assert notes_by_unit(result, task_id)["u1"]["state"] == "PARTIAL"
    assert result["ledger"]["coverage_repairs"][task_id]["status"] == "REPAIRED"


def test_unit_without_supplied_evidence_is_never_repaired(tmp_path):
    snapshot = make_snapshot({"u0": ["diff:u0"], "u1": []})
    provider = RepairProvider(
        initial={"u0": ("COVERED", ["diff:u0"])},
        repair={"u1": ("COVERED", ["diff:u1"])},
    )
    result = run(tmp_path, provider, snapshot=snapshot)

    assert result["coverage_state"] == "PARTIAL"
    assert result["disposition"] == "INCOMPLETE"
    assert result["ledger"].get("coverage_repairs", {}) == {}
    assert result["budget"]["provider_calls_reserved"] == 1


def test_run_level_repair_cap_allows_only_one_additional_call(tmp_path):
    snapshot = make_snapshot()
    base_plan = plan_review(snapshot, profile())
    first = copy.deepcopy(base_plan["tasks"][0])
    second = copy.deepcopy(base_plan["tasks"][0])
    first["task_id"] = "repair-task-a"
    second["task_id"] = "repair-task-b"
    base_plan["tasks"] = [first, second]
    provider = RepairProvider(
        initial={},
        repair={"u0": ("COVERED", ["diff:u0"]), "u1": ("COVERED", ["diff:u1"])},
    )
    result = run_review(
        snapshot,
        base_plan,
        profile({"max_calls_per_run": 1}),
        provider,
        None,
        dict(LIMITS),
        str(tmp_path / "out"),
        "coverage-repair-cap",
    )

    repairs = result["ledger"]["coverage_repairs"]
    statuses = {row["status"] for row in repairs.values()}
    assert statuses == {"REPAIRED", "SKIPPED"}
    assert sum(1 for row in repairs.values() if row.get("provider_call") is True) == 1
    assert any(row.get("reason_code") == "COVERAGE_REPAIR_CAP" for row in repairs.values())
    assert result["budget"]["provider_calls_reserved"] == 3
    assert result["coverage_state"] == "PARTIAL"
    assert result["disposition"] == "INCOMPLETE"


def test_provider_failure_is_not_retried_and_stays_incomplete(tmp_path):
    provider = RepairProvider(initial={}, repair_error=RuntimeError("offline repair failure"))
    result = run(tmp_path, provider, limits={**LIMITS, "max_retries_per_task": 2})

    assert result["coverage_state"] == "PARTIAL"
    assert result["disposition"] == "INCOMPLETE"
    task_id = next(iter(result["task_results"]))
    repair = result["ledger"]["coverage_repairs"][task_id]
    assert repair["status"] == "FAILED"
    assert repair["provider_call"] is True
    assert result["budget"]["provider_calls_reserved"] == 2


def test_repair_claiming_coverage_with_unsupplied_evidence_is_rejected(tmp_path):
    provider = RepairProvider(
        initial={},
        repair={"u0": ("COVERED", ["invented"]), "u1": ("COVERED", ["diff:u1"])},
    )
    result = run(tmp_path, provider)

    assert result["coverage_state"] == "PARTIAL"
    assert result["disposition"] == "INCOMPLETE"
    task_id = next(iter(result["task_results"]))
    repair = result["ledger"]["coverage_repairs"][task_id]
    assert repair["status"] == "REJECTED"
    assert result["ledger"]["outputs"][task_id]["payload"]["coverage_notes"] == []


def test_duplicate_repair_units_are_rejected_without_changing_original_notes(tmp_path):
    provider = RepairProvider(
        initial={},
        repair={"u0": ("COVERED", ["diff:u0"]), "u1": ("COVERED", ["diff:u1"])},
        duplicate=True,
    )
    result = run(tmp_path, provider)

    assert result["coverage_state"] == "PARTIAL"
    task_id = next(iter(result["task_results"]))
    repair = result["ledger"]["coverage_repairs"][task_id]
    assert repair["status"] == "REJECTED"
    assert repair["provider_call"] is True
    assert result["ledger"]["outputs"][task_id]["payload"]["coverage_notes"] == []
