from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

from scripts.multipass_plan import (
    PlanError,
    aggregate,
    build_plan,
    new_ledger,
    record_check_result,
    record_context_result,
    record_external_check_result,
    record_task_result,
    reserve_task,
    validate_plan,
)

FIXTURE = Path(__file__).parent / "fixtures" / "pr305_prepare_only_manifest.json"


def prepared_manifest() -> dict:
    return json.loads(FIXTURE.read_text())


def make_plan():
    return build_plan(prepared_manifest())


def recompute_fingerprint(plan):
    payload = {key: value for key, value in plan.items() if key != "plan_fingerprint"}
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    plan["plan_fingerprint"] = hashlib.sha256(encoded).hexdigest()


def complete_primary_tasks(plan, ledger):
    for task in plan["task_manifest"]:
        reserve_task(plan, ledger, task["task_id"])
        record_task_result(
            plan,
            ledger,
            {
                "task_id": task["task_id"],
                "input_sha256": task["input_sha256"],
                "obligation_ids": task["obligation_ids"],
                "status": "SUCCEEDED",
            },
        )


def complete_checks(plan, ledger, status="PASS"):
    for task in plan["check_tasks"]:
        record_check_result(
            plan,
            ledger,
            task_id=task["task_id"],
            status=status,
            check_evidence_hash=plan["identity"]["check_evidence_hash"],
        )
    for check in plan["external_checks"]:
        record_external_check_result(
            plan,
            ledger,
            check_id=check["check_id"],
            status=status,
            check_evidence_hash=plan["identity"]["check_evidence_hash"],
        )


def test_frozen_pr305_assigns_every_primary_task_once_within_seven_pass_caps():
    prepared = prepared_manifest()
    plan = build_plan(prepared)

    provenance = prepared["fixture_metadata"]
    assert len(provenance["source_artifact_sha256"]) == 64
    assert "source text" in provenance["stripped_fields"]
    assert "prompts" in provenance["stripped_fields"]
    assert plan["identity"]["repository"] == "magnus919/SlopSearX"
    assert plan["identity"]["pull_request_number"] == 305
    assert len(plan["passes"]) == 7
    assert len(plan["task_manifest"]) == 38
    assert plan["limits"]["primary_input_bytes_total"] == 1_945_925
    assert plan["limits"]["primary_calls_total"] == 38

    assigned = [task["task_id"] for pass_data in plan["passes"] for task in pass_data["tasks"]]
    assert len(assigned) == len(set(assigned)) == 38
    assert set(assigned) == {task["task_id"] for task in plan["task_manifest"]}
    for pass_data in plan["passes"]:
        assert pass_data["calls"] <= 12
        assert pass_data["input_bytes"] <= 300_000
        assert all(task["input_bytes"] <= 64_000 for task in pass_data["tasks"])

    obligation_ids = [oid for task in plan["task_manifest"] for oid in task["obligation_ids"]]
    assert len(obligation_ids) == len(set(obligation_ids)) == 84
    assert len(plan["check_tasks"]) == 2
    assert len(plan["external_checks"]) == 2
    assert len(plan["context_tasks"]) == 2
    assert build_plan(prepared) == plan


def test_fixture_contains_no_raw_source_prompts_or_provider_endpoints():
    prepared = prepared_manifest()
    assert len(prepared["fixture_metadata"]["source_artifact_sha256"]) == 64
    forbidden_keys = {
        "prompt",
        "content",
        "credential",
        "endpoint",
        "provider_endpoint",
        "api_key",
        "authorization",
    }

    def walk(value):
        if isinstance(value, dict):
            for key, item in value.items():
                assert key.lower() not in forbidden_keys
                walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)

    walk(prepared)
    assert "evidence_index" not in prepared["snapshot"]
    assert all("evidence_bindings" not in row for row in prepared["scope"]["planned_task_scopes"])


def test_plan_fingerprint_rejects_request_hash_tampering_after_freeze():
    plan = make_plan()
    tampered = copy.deepcopy(plan)
    tampered["task_manifest"][0]["input_sha256"] = "0" * 64
    with pytest.raises(PlanError, match="plan_fingerprint_mismatch"):
        validate_plan(tampered)


def test_plan_rejects_pass_row_tampering_even_if_fingerprint_is_recomputed():
    plan = make_plan()
    tampered = copy.deepcopy(plan)
    tampered["passes"][0]["tasks"][0]["input_sha256"] = "0" * 64
    recompute_fingerprint(tampered)
    with pytest.raises(PlanError, match="pass_task_manifest_mismatch"):
        validate_plan(tampered)


def test_plan_rejects_required_obligation_omission_even_if_fingerprint_is_recomputed():
    plan = make_plan()
    tampered = copy.deepcopy(plan)
    task_id = tampered["passes"][0]["tasks"][0]["task_id"]
    replacement = "unit:invented:lens:correctness"
    for task in tampered["passes"][0]["tasks"]:
        if task["task_id"] == task_id:
            task["obligation_ids"][0] = replacement
    for task in tampered["task_manifest"]:
        if task["task_id"] == task_id:
            task["obligation_ids"][0] = replacement
    recompute_fingerprint(tampered)
    with pytest.raises(PlanError, match="primary_obligation_coverage_mismatch"):
        validate_plan(tampered)


@pytest.mark.parametrize(
    ("mutate", "error_code"),
    [
        (lambda plan: plan["required_obligations"].append(copy.deepcopy(plan["required_obligations"][0])), "duplicate_required_obligation_id"),
        (lambda plan: plan["task_manifest"].append(copy.deepcopy(plan["task_manifest"][0])), "duplicate_task_manifest_id"),
        (lambda plan: plan["check_tasks"].__setitem__(1, {**plan["check_tasks"][1], "task_id": plan["check_tasks"][0]["task_id"]}), "duplicate_check_task_id"),
        (lambda plan: plan["context_tasks"].__setitem__(1, {**plan["context_tasks"][1], "task_id": plan["context_tasks"][0]["task_id"]}), "duplicate_context_task_id"),
        (
            lambda plan: plan["check_tasks"][1].__setitem__("obligation_ids", plan["check_tasks"][0]["obligation_ids"][:]),
            "duplicate_assigned_check_obligation_id",
        ),
        (
            lambda plan: plan["context_tasks"].__setitem__(1, {**plan["context_tasks"][1], "obligation_id": plan["context_tasks"][0]["obligation_id"]}),
            "duplicate_assigned_context_obligation_id",
        ),
    ],
)
def test_plan_rejects_duplicate_inventory_and_assignment_ids_after_refingerprinting(mutate, error_code):
    plan = copy.deepcopy(make_plan())
    mutate(plan)
    recompute_fingerprint(plan)
    with pytest.raises(PlanError, match=error_code):
        validate_plan(plan)


def test_duplicate_obligation_in_request_is_rejected_before_assignment():
    prepared = prepared_manifest()
    prepared["primary_requests"][0]["obligation_ids"].append(prepared["primary_requests"][0]["obligation_ids"][0])
    with pytest.raises(PlanError, match="duplicate_or_invalid_task_obligation"):
        build_plan(prepared)


def test_unknown_reservation_survives_resume_and_is_never_retried():
    plan = make_plan()
    ledger = new_ledger(plan)
    task = plan["task_manifest"][0]
    reserve_task(plan, ledger, task["task_id"])

    resumed = json.loads(json.dumps(ledger))
    assert resumed["task_states"][task["task_id"]] == "RESERVED_UNKNOWN"
    assert resumed["reserved_calls"] == 1
    with pytest.raises(PlanError, match="task_already_reserved_or_terminal"):
        reserve_task(plan, resumed, task["task_id"])
    assert aggregate(plan, resumed)["prototype_state"] == "INCOMPLETE"


def test_unknown_or_mismatched_task_result_consumes_reservation_without_retry():
    plan = make_plan()
    ledger = new_ledger(plan)
    task = plan["task_manifest"][0]
    reserve_task(plan, ledger, task["task_id"])
    record_task_result(
        plan,
        ledger,
        {
            "task_id": task["task_id"],
            "input_sha256": "f" * 64,
            "obligation_ids": task["obligation_ids"],
            "status": "SUCCEEDED",
        },
    )
    assert ledger["task_states"][task["task_id"]] == "INVALID"
    with pytest.raises(PlanError, match="task_already_reserved_or_terminal"):
        reserve_task(plan, ledger, task["task_id"])


def test_pr305_remains_prototype_incomplete_until_required_context_is_resolved():
    plan = make_plan()
    ledger = new_ledger(plan)
    complete_primary_tasks(plan, ledger)
    complete_checks(plan, ledger)

    result = aggregate(plan, ledger)
    assert result["prototype_state"] == "INCOMPLETE"
    assert result["disposition"] == "NOT_EVALUATED"
    assert result["publication_eligible"] is False
    assert len(result["pending_ids"]) == 2

    for context in plan["context_tasks"]:
        record_context_result(
            plan,
            ledger,
            obligation_id=context["obligation_id"],
            status="RESOLVED",
            snapshot_id=plan["identity"]["snapshot_id"],
            evidence_sha256="a" * 64,
        )
    result = aggregate(plan, ledger)
    assert result["prototype_state"] == "ALL_REQUIRED_RESULTS_RECORDED"
    assert result["disposition"] == "NOT_EVALUATED"
    assert result["publication_eligible"] is False


def test_missing_or_unknown_required_check_keeps_aggregate_incomplete():
    plan = make_plan()
    ledger = new_ledger(plan)
    complete_primary_tasks(plan, ledger)
    for task in plan["check_tasks"][:1]:
        record_check_result(
            plan,
            ledger,
            task_id=task["task_id"],
            status="UNKNOWN",
            check_evidence_hash=plan["identity"]["check_evidence_hash"],
        )
    assert aggregate(plan, ledger)["prototype_state"] == "INCOMPLETE"


def test_failed_check_is_only_recorded_and_never_becomes_disposition():
    plan = make_plan()
    ledger = new_ledger(plan)
    complete_primary_tasks(plan, ledger)
    for task in plan["check_tasks"]:
        record_check_result(
            plan,
            ledger,
            task_id=task["task_id"],
            status="PASS",
            check_evidence_hash=plan["identity"]["check_evidence_hash"],
        )
    for check in plan["external_checks"]:
        record_external_check_result(
            plan,
            ledger,
            check_id=check["check_id"],
            status="FAIL" if check == plan["external_checks"][0] else "PASS",
            check_evidence_hash=plan["identity"]["check_evidence_hash"],
        )
    for context in plan["context_tasks"]:
        record_context_result(
            plan,
            ledger,
            obligation_id=context["obligation_id"],
            status="RESOLVED",
            snapshot_id=plan["identity"]["snapshot_id"],
            evidence_sha256="a" * 64,
        )
    result = aggregate(plan, ledger)
    assert result["prototype_state"] == "ALL_REQUIRED_RESULTS_RECORDED"
    assert result["disposition"] == "NOT_EVALUATED"
    assert result["recorded_failing_check_ids"]
    assert result["publication_eligible"] is False


def test_ledger_rejects_unknown_state_on_resume():
    plan = make_plan()
    ledger = new_ledger(plan)
    ledger["task_states"][plan["task_manifest"][0]["task_id"]] = "RETRY_ALLOWED"
    with pytest.raises(PlanError, match="invalid_task_state"):
        aggregate(plan, ledger)
