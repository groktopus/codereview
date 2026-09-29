"""Offline-only multi-pass planning and exact-once ledger prototype.

This module consumes a sanitized PREPARED_ONLY manifest. It never dispatches
providers, runs target code, or establishes semantic review correctness. The
ledger is a local coordination contract, not authenticated provenance: callers
must persist each reservation before any future external dispatch.
"""
from __future__ import annotations

import hashlib
import json
import re
from copy import deepcopy
from typing import Any

PLAN_VERSION = "codereview-multipass-plan.v1"
LEDGER_VERSION = "codereview-multipass-ledger.v1"
MAX_CALLS_PER_PASS = 12
MAX_BYTES_PER_PASS = 300_000
MAX_BYTES_PER_TASK = 64_000
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class PlanError(ValueError):
    """The sanitized prepared manifest or its derived plan is invalid."""


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _is_sha256(value: Any) -> bool:
    return isinstance(value, str) and _SHA256_RE.fullmatch(value) is not None


def _required_obligations(scope: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rows = scope.get("coverage_obligations")
    if not isinstance(rows, list):
        raise PlanError("coverage_obligations_missing")
    result: dict[str, dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict) or row.get("required") is not True:
            raise PlanError("invalid_required_obligation")
        obligation_id = row.get("obligation_id")
        if not isinstance(obligation_id, str) or not obligation_id or obligation_id in result:
            raise PlanError("duplicate_or_invalid_obligation_id")
        result[obligation_id] = row
    return result


def _target_identity(prepared: dict[str, Any]) -> dict[str, Any]:
    checks = prepared.get("checks")
    identity = checks.get("historical_check_identity") if isinstance(checks, dict) else None
    snapshot = prepared.get("snapshot")
    if not isinstance(identity, dict) or not isinstance(snapshot, dict):
        raise PlanError("target_identity_missing")
    required = ("repository", "pull_request_number", "base_sha", "head_sha")
    if any(identity.get(key) in (None, "") for key in required):
        raise PlanError("target_identity_incomplete")
    if not _is_sha256(checks.get("check_evidence_hash")):
        raise PlanError("check_evidence_identity_incomplete")
    for key in ("snapshot_hash", "profile_file_sha256", "provider_identity_sha256"):
        if not _is_sha256(snapshot.get(key)):
            raise PlanError("snapshot_identity_incomplete")
    return {
        "repository": identity["repository"],
        "pull_request_number": identity["pull_request_number"],
        "base_sha": identity["base_sha"],
        "head_sha": identity["head_sha"],
        "snapshot_id": snapshot.get("snapshot_id"),
        "snapshot_hash": snapshot["snapshot_hash"],
        "profile_version": snapshot.get("profile_version"),
        "profile_file_sha256": snapshot["profile_file_sha256"],
        "provider_identity_sha256": snapshot["provider_identity_sha256"],
        "check_evidence_hash": checks.get("check_evidence_hash"),
        "check_results": checks.get("check_results"),
    }


def build_plan(prepared: dict[str, Any]) -> dict[str, Any]:
    """Build an immutable, deterministic plan from a provider-free manifest."""
    if not isinstance(prepared, dict) or prepared.get("status") != "PREPARED_ONLY":
        raise PlanError("prepared_only_manifest_required")
    if prepared.get("no_provider_calls") is not True or prepared.get("no_target_code_execution") is not True:
        raise PlanError("provider_free_fixture_required")
    scope = prepared.get("scope")
    if not isinstance(scope, dict):
        raise PlanError("scope_missing")
    obligations = _required_obligations(scope)
    requests = prepared.get("primary_requests")
    if not isinstance(requests, list) or not requests:
        raise PlanError("primary_requests_missing")

    request_ids: set[str] = set()
    request_obligations: set[str] = set()
    specialist_tasks = []
    for request in requests:
        if not isinstance(request, dict) or request.get("admitted") is not True:
            raise PlanError("unadmitted_primary_request")
        task_id = request.get("task_id")
        input_bytes = request.get("input_bytes")
        request_hash = request.get("input_sha256")
        obligation_ids = request.get("obligation_ids")
        if not isinstance(task_id, str) or not task_id or task_id in request_ids:
            raise PlanError("duplicate_or_invalid_task_id")
        if isinstance(input_bytes, bool) or not isinstance(input_bytes, int) or input_bytes <= 0:
            raise PlanError("invalid_task_input_bytes")
        if input_bytes > MAX_BYTES_PER_TASK:
            raise PlanError("task_exceeds_per_task_limit")
        if not _is_sha256(request_hash):
            raise PlanError("invalid_request_hash")
        if (
            not isinstance(obligation_ids, list)
            or not obligation_ids
            or any(not isinstance(item, str) or not item for item in obligation_ids)
            or len(obligation_ids) != len(set(obligation_ids))
        ):
            raise PlanError("duplicate_or_invalid_task_obligation")
        for obligation_id in obligation_ids:
            obligation = obligations.get(obligation_id)
            if obligation is None or obligation.get("obligation_kind") != "CHANGED_UNIT_LENS":
                raise PlanError("primary_task_obligation_mismatch")
            if obligation_id in request_obligations:
                raise PlanError("obligation_assigned_more_than_once")
            request_obligations.add(obligation_id)
        request_ids.add(task_id)
        specialist_tasks.append(
            {
                "task_id": task_id,
                "input_bytes": input_bytes,
                "input_sha256": request_hash,
                "lens": request.get("lens"),
                "unit_ids": request.get("unit_ids"),
                "obligation_ids": list(obligation_ids),
                "request_input_contract": request.get("request_input_contract"),
                "required_context_ids": request.get("required_context_ids", []),
            }
        )

    task_scopes = scope.get("planned_task_scopes")
    if not isinstance(task_scopes, list):
        raise PlanError("planned_task_scopes_missing")
    check_tasks = []
    check_obligations: set[str] = set()
    check_task_ids: set[str] = set()
    for task in task_scopes:
        if not isinstance(task, dict):
            raise PlanError("invalid_planned_task_scope")
        if task.get("task_kind") != "DETERMINISTIC_CHECK":
            continue
        task_id = task.get("task_id")
        ids = task.get("obligation_ids")
        if not isinstance(task_id, str) or not task_id or task_id in request_ids or task_id in check_task_ids:
            raise PlanError("duplicate_or_invalid_check_task_id")
        if not isinstance(ids, list) or not ids or len(ids) != len(set(ids)):
            raise PlanError("invalid_check_obligations")
        for obligation_id in ids:
            obligation = obligations.get(obligation_id)
            if obligation is None or obligation.get("obligation_kind") != "PROJECT_CHECK":
                raise PlanError("check_task_obligation_mismatch")
            if obligation_id in check_obligations or obligation_id in request_obligations:
                raise PlanError("obligation_assigned_more_than_once")
            check_obligations.add(obligation_id)
        check_task_ids.add(task_id)
        check_tasks.append({"task_id": task_id, "obligation_ids": list(ids)})

    context_obligations = {
        obligation_id
        for obligation_id, row in obligations.items()
        if row.get("obligation_kind") == "REQUIRED_CONTEXT"
    }
    classified = request_obligations | check_obligations | context_obligations
    if classified != set(obligations):
        raise PlanError("required_obligation_unclassified")
    if request_obligations & check_obligations or request_obligations & context_obligations:
        raise PlanError("obligation_classification_conflict")
    if check_obligations & context_obligations:
        raise PlanError("obligation_classification_conflict")

    declared_unadmitted = scope.get("required_unadmitted_obligation_ids", [])
    if (
        not isinstance(declared_unadmitted, list)
        or any(not isinstance(item, str) or not item for item in declared_unadmitted)
        or len(declared_unadmitted) != len(set(declared_unadmitted))
        or set(declared_unadmitted) != context_obligations
    ):
        raise PlanError("required_context_admission_mismatch")
    gaps = scope.get("required_context_gaps", [])
    if not isinstance(gaps, list) or len(gaps) != len(context_obligations):
        raise PlanError("required_context_gap_inventory_mismatch")
    context_tasks = [
        {
            "task_id": f"context-task-{index + 1:02d}",
            "obligation_id": obligation_id,
            "gap_index": index,
            "gap_sha256": _sha256(gaps[index]),
        }
        for index, obligation_id in enumerate(declared_unadmitted)
    ]
    external_check_results = prepared["checks"].get("check_results")
    if not isinstance(external_check_results, dict):
        raise PlanError("external_check_results_missing")
    external_checks = []
    for check_id, check_result in sorted(external_check_results.items()):
        if not isinstance(check_id, str) or not check_id or not isinstance(check_result, dict):
            raise PlanError("invalid_external_check_result")
        external_checks.append({"check_id": check_id, "result_sha256": _sha256(check_result)})

    # First-fit decreasing is deterministic and avoids filling one pass with
    # small requests while stranding larger tasks. This is packing only, not
    # a priority policy; every required request remains assigned exactly once.
    packed: list[list[dict[str, Any]]] = []
    packed_bytes: list[int] = []
    for task in sorted(specialist_tasks, key=lambda row: (-row["input_bytes"], row["task_id"])):
        if task["input_bytes"] > MAX_BYTES_PER_PASS:
            raise PlanError("task_exceeds_pass_limit")
        destination = next(
            (
                index
                for index, rows in enumerate(packed)
                if len(rows) < MAX_CALLS_PER_PASS and packed_bytes[index] + task["input_bytes"] <= MAX_BYTES_PER_PASS
            ),
            None,
        )
        if destination is None:
            packed.append([task])
            packed_bytes.append(task["input_bytes"])
        else:
            packed[destination].append(task)
            packed_bytes[destination] += task["input_bytes"]
    passes = [
        {
            "pass_id": f"pass-{index + 1:02d}",
            "tasks": deepcopy(rows),
            "calls": len(rows),
            "input_bytes": packed_bytes[index],
        }
        for index, rows in enumerate(packed)
    ]

    plan = {
        "schema_version": PLAN_VERSION,
        "identity": _target_identity(prepared),
        "limits": {
            "calls_per_pass": MAX_CALLS_PER_PASS,
            "input_bytes_per_pass": MAX_BYTES_PER_PASS,
            "input_bytes_per_task": MAX_BYTES_PER_TASK,
            # These are exact mandatory-stage ceilings. Optional stages are not
            # admitted by this offline prototype.
            "primary_calls_total": len(specialist_tasks),
            "primary_input_bytes_total": sum(task["input_bytes"] for task in specialist_tasks),
        },
        "required_obligations": [obligations[key] for key in sorted(obligations)],
        "passes": passes,
        "check_tasks": check_tasks,
        "external_checks": external_checks,
        "context_tasks": context_tasks,
        "task_manifest": deepcopy(specialist_tasks),
        "disposition": "NOT_EVALUATED",
    }
    plan["plan_fingerprint"] = _sha256(plan)
    validate_plan(plan)
    return plan


def validate_plan(plan: dict[str, Any]) -> None:
    if not isinstance(plan, dict) or plan.get("schema_version") != PLAN_VERSION:
        raise PlanError("unsupported_plan")
    claimed = plan.get("plan_fingerprint")
    payload = {key: value for key, value in plan.items() if key != "plan_fingerprint"}
    if not _is_sha256(claimed) or _sha256(payload) != claimed:
        raise PlanError("plan_fingerprint_mismatch")
    required_rows = plan.get("required_obligations")
    if not isinstance(required_rows, list) or any(not isinstance(row, dict) for row in required_rows):
        raise PlanError("invalid_required_obligation_inventory")
    required_ids = [row.get("obligation_id") for row in required_rows]
    if any(not isinstance(value, str) or not value for value in required_ids):
        raise PlanError("invalid_required_obligation_id")
    if len(required_ids) != len(set(required_ids)):
        raise PlanError("duplicate_required_obligation_id")
    task_manifest = plan.get("task_manifest")
    if not isinstance(task_manifest, list) or any(not isinstance(task, dict) for task in task_manifest):
        raise PlanError("invalid_task_manifest")
    manifest_ids = [task.get("task_id") for task in task_manifest]
    if any(not isinstance(value, str) or not value for value in manifest_ids):
        raise PlanError("invalid_task_manifest_id")
    if len(manifest_ids) != len(set(manifest_ids)):
        raise PlanError("duplicate_task_manifest_id")
    check_tasks = plan.get("check_tasks")
    if not isinstance(check_tasks, list) or any(not isinstance(task, dict) for task in check_tasks):
        raise PlanError("invalid_check_task_inventory")
    check_task_ids = [task.get("task_id") for task in check_tasks]
    if any(not isinstance(value, str) or not value for value in check_task_ids):
        raise PlanError("invalid_check_task_id")
    if len(check_task_ids) != len(set(check_task_ids)) or set(check_task_ids) & set(manifest_ids):
        raise PlanError("duplicate_check_task_id")
    for task in check_tasks:
        ids = task.get("obligation_ids")
        if (
            not isinstance(ids, list)
            or not ids
            or any(not isinstance(value, str) or not value for value in ids)
        ):
            raise PlanError("invalid_check_task_obligations")
    context_tasks = plan.get("context_tasks")
    if not isinstance(context_tasks, list) or any(not isinstance(task, dict) for task in context_tasks):
        raise PlanError("invalid_context_task_inventory")
    context_task_ids = [task.get("task_id") for task in context_tasks]
    if any(not isinstance(value, str) or not value for value in context_task_ids):
        raise PlanError("invalid_context_task_id")
    if len(context_task_ids) != len(set(context_task_ids)):
        raise PlanError("duplicate_context_task_id")
    context_obligation_ids = [task.get("obligation_id") for task in context_tasks]
    if any(not isinstance(value, str) or not value for value in context_obligation_ids):
        raise PlanError("invalid_context_obligation_id")
    external_checks = plan.get("external_checks")
    if not isinstance(external_checks, list) or any(not isinstance(item, dict) for item in external_checks):
        raise PlanError("invalid_external_check_inventory")
    external_check_ids = [item.get("check_id") for item in external_checks]
    if any(not isinstance(value, str) or not value for value in external_check_ids):
        raise PlanError("invalid_external_check_id")
    if len(external_check_ids) != len(set(external_check_ids)):
        raise PlanError("duplicate_external_check_id")
    limits = plan.get("limits", {})
    if limits.get("calls_per_pass") != MAX_CALLS_PER_PASS or limits.get("input_bytes_per_pass") != MAX_BYTES_PER_PASS or limits.get("input_bytes_per_task") != MAX_BYTES_PER_TASK:
        raise PlanError("plan_limits_mismatch")
    seen_tasks: set[str] = set()
    seen_obligations: set[str] = set()
    total_bytes = total_calls = 0
    flattened_tasks = []
    for expected_index, pass_data in enumerate(plan.get("passes", []), 1):
        tasks = pass_data.get("tasks")
        if pass_data.get("pass_id") != f"pass-{expected_index:02d}" or not isinstance(tasks, list):
            raise PlanError("invalid_pass_assignment")
        size = 0
        for task in tasks:
            task_id = task.get("task_id")
            if task_id in seen_tasks:
                raise PlanError("task_assigned_more_than_once")
            seen_tasks.add(task_id)
            flattened_tasks.append(task)
            size += task.get("input_bytes", 0)
            for obligation_id in task.get("obligation_ids", []):
                if obligation_id in seen_obligations:
                    raise PlanError("obligation_assigned_more_than_once")
                seen_obligations.add(obligation_id)
        if len(tasks) > MAX_CALLS_PER_PASS or size > MAX_BYTES_PER_PASS:
            raise PlanError("pass_exceeds_limit")
        if pass_data.get("calls") != len(tasks) or pass_data.get("input_bytes") != size:
            raise PlanError("pass_accounting_mismatch")
        total_calls += len(tasks)
        total_bytes += size
    if seen_tasks != set(manifest_ids):
        raise PlanError("task_manifest_assignment_mismatch")
    flattened_by_id = {task["task_id"]: task for task in flattened_tasks}
    manifest_by_id = {task["task_id"]: task for task in task_manifest}
    if flattened_by_id != manifest_by_id:
        raise PlanError("pass_task_manifest_mismatch")
    if total_calls != limits.get("primary_calls_total") or total_bytes != limits.get("primary_input_bytes_total"):
        raise PlanError("global_accounting_mismatch")
    required_primary = {
        row.get("obligation_id")
        for row in required_rows
        if isinstance(row, dict) and row.get("obligation_kind") == "CHANGED_UNIT_LENS"
    }
    if seen_obligations != required_primary:
        raise PlanError("primary_obligation_coverage_mismatch")
    required_check = {
        row.get("obligation_id")
        for row in required_rows
        if isinstance(row, dict) and row.get("obligation_kind") == "PROJECT_CHECK"
    }
    assigned_check_rows = [
        obligation_id
        for task in check_tasks
        for obligation_id in task.get("obligation_ids", [])
    ]
    if len(assigned_check_rows) != len(set(assigned_check_rows)):
        raise PlanError("duplicate_assigned_check_obligation_id")
    assigned_check = set(assigned_check_rows)
    if assigned_check != required_check:
        raise PlanError("check_obligation_coverage_mismatch")
    required_context = {
        row.get("obligation_id")
        for row in required_rows
        if isinstance(row, dict) and row.get("obligation_kind") == "REQUIRED_CONTEXT"
    }
    if len(context_obligation_ids) != len(set(context_obligation_ids)):
        raise PlanError("duplicate_assigned_context_obligation_id")
    assigned_context = set(context_obligation_ids)
    if assigned_context != required_context:
        raise PlanError("context_obligation_coverage_mismatch")


def new_ledger(plan: dict[str, Any]) -> dict[str, Any]:
    validate_plan(plan)
    return {
        "schema_version": LEDGER_VERSION,
        "plan_fingerprint": plan["plan_fingerprint"],
        "task_states": {task["task_id"]: "PENDING" for task in plan["task_manifest"]},
        "check_states": {task["task_id"]: "PENDING" for task in plan["check_tasks"]},
        "external_check_states": {task["check_id"]: "PENDING" for task in plan["external_checks"]},
        "context_states": {task["obligation_id"]: "PENDING" for task in plan["context_tasks"]},
        "reserved_calls": 0,
        "reserved_input_bytes": 0,
        "pass_usage": {pass_data["pass_id"]: {"calls": 0, "input_bytes": 0} for pass_data in plan["passes"]},
    }


def _validate_ledger(plan: dict[str, Any], ledger: dict[str, Any]) -> None:
    validate_plan(plan)
    if not isinstance(ledger, dict) or ledger.get("schema_version") != LEDGER_VERSION:
        raise PlanError("invalid_ledger")
    if ledger.get("plan_fingerprint") != plan["plan_fingerprint"]:
        raise PlanError("ledger_plan_mismatch")
    expected_tasks = {task["task_id"] for task in plan["task_manifest"]}
    expected_checks = {task["task_id"] for task in plan["check_tasks"]}
    expected_external_checks = {task["check_id"] for task in plan["external_checks"]}
    expected_context = {task["obligation_id"] for task in plan["context_tasks"]}
    if (
        set(ledger.get("task_states", {})) != expected_tasks
        or set(ledger.get("check_states", {})) != expected_checks
        or set(ledger.get("external_check_states", {})) != expected_external_checks
        or set(ledger.get("context_states", {})) != expected_context
    ):
        raise PlanError("ledger_inventory_mismatch")
    if not set(ledger["task_states"].values()).issubset(
        {"PENDING", "RESERVED_UNKNOWN", "SUCCEEDED", "FAILED", "INVALID", "UNKNOWN"}
    ):
        raise PlanError("invalid_task_state")
    if not set(ledger["check_states"].values()).issubset({"PENDING", "PASS", "FAIL", "UNKNOWN", "INVALID"}):
        raise PlanError("invalid_check_state")
    if not set(ledger["external_check_states"].values()).issubset(
        {"PENDING", "PASS", "FAIL", "UNKNOWN", "INVALID"}
    ):
        raise PlanError("invalid_external_check_state")
    if not set(ledger["context_states"].values()).issubset({"PENDING", "RESOLVED", "UNKNOWN"}):
        raise PlanError("invalid_context_state")
    reserved = {"RESERVED_UNKNOWN", "SUCCEEDED", "FAILED", "INVALID", "UNKNOWN"}
    tasks_by_id = {task["task_id"]: task for task in plan["task_manifest"]}
    calls = sum(state in reserved for state in ledger["task_states"].values())
    byte_count = sum(tasks_by_id[task_id]["input_bytes"] for task_id, state in ledger["task_states"].items() if state in reserved)
    if ledger.get("reserved_calls") != calls or ledger.get("reserved_input_bytes") != byte_count:
        raise PlanError("ledger_accounting_mismatch")
    usage = {pass_data["pass_id"]: {"calls": 0, "input_bytes": 0} for pass_data in plan["passes"]}
    for pass_data in plan["passes"]:
        for task in pass_data["tasks"]:
            if ledger["task_states"][task["task_id"]] in reserved:
                usage[pass_data["pass_id"]]["calls"] += 1
                usage[pass_data["pass_id"]]["input_bytes"] += task["input_bytes"]
    if ledger.get("pass_usage") != usage:
        raise PlanError("ledger_pass_accounting_mismatch")


def reserve_task(plan: dict[str, Any], ledger: dict[str, Any], task_id: str) -> dict[str, Any]:
    """Reserve before dispatch; a reservation is spent even if outcome is lost."""
    _validate_ledger(plan, ledger)
    task = next((row for row in plan["task_manifest"] if row["task_id"] == task_id), None)
    if task is None:
        raise PlanError("unknown_task")
    if ledger["task_states"][task_id] != "PENDING":
        raise PlanError("task_already_reserved_or_terminal")
    pass_data = next(row for row in plan["passes"] if any(item["task_id"] == task_id for item in row["tasks"]))
    usage = ledger["pass_usage"][pass_data["pass_id"]]
    if usage["calls"] + 1 > MAX_CALLS_PER_PASS or usage["input_bytes"] + task["input_bytes"] > MAX_BYTES_PER_PASS:
        raise PlanError("pass_budget_exceeded")
    if ledger["reserved_calls"] + 1 > plan["limits"]["primary_calls_total"] or ledger["reserved_input_bytes"] + task["input_bytes"] > plan["limits"]["primary_input_bytes_total"]:
        raise PlanError("global_budget_exceeded")
    ledger["task_states"][task_id] = "RESERVED_UNKNOWN"
    ledger["reserved_calls"] += 1
    ledger["reserved_input_bytes"] += task["input_bytes"]
    usage["calls"] += 1
    usage["input_bytes"] += task["input_bytes"]
    _validate_ledger(plan, ledger)
    return {"task_id": task_id, "request_sha256": task["input_sha256"], "pass_id": pass_data["pass_id"], "input_bytes": task["input_bytes"]}


def record_task_result(plan: dict[str, Any], ledger: dict[str, Any], result: dict[str, Any]) -> None:
    _validate_ledger(plan, ledger)
    if not isinstance(result, dict):
        raise PlanError("invalid_task_result")
    task_id = result.get("task_id")
    state = ledger["task_states"].get(task_id)
    if state != "RESERVED_UNKNOWN":
        raise PlanError("task_result_without_reservation")
    task = next(row for row in plan["task_manifest"] if row["task_id"] == task_id)
    if result.get("input_sha256") != task["input_sha256"] or result.get("obligation_ids") != task["obligation_ids"]:
        ledger["task_states"][task_id] = "INVALID"
        _validate_ledger(plan, ledger)
        return
    status = result.get("status")
    if not isinstance(status, str) or status not in {"SUCCEEDED", "FAILED", "INVALID", "UNKNOWN"}:
        ledger["task_states"][task_id] = "INVALID"
    else:
        ledger["task_states"][task_id] = status
    _validate_ledger(plan, ledger)


def record_check_result(
    plan: dict[str, Any], ledger: dict[str, Any], *, task_id: str, status: str, check_evidence_hash: str
) -> None:
    _validate_ledger(plan, ledger)
    task = next((row for row in plan["check_tasks"] if row["task_id"] == task_id), None)
    if task is None or ledger["check_states"].get(task_id) != "PENDING":
        raise PlanError("check_result_without_pending_task")
    if (
        check_evidence_hash != plan["identity"].get("check_evidence_hash")
        or not isinstance(status, str)
        or status not in {"PASS", "FAIL", "UNKNOWN"}
    ):
        ledger["check_states"][task_id] = "INVALID"
    else:
        ledger["check_states"][task_id] = status


def record_external_check_result(
    plan: dict[str, Any], ledger: dict[str, Any], *, check_id: str, status: str, check_evidence_hash: str
) -> None:
    _validate_ledger(plan, ledger)
    if check_id not in ledger["external_check_states"] or ledger["external_check_states"][check_id] != "PENDING":
        raise PlanError("external_check_result_without_pending_check")
    if (
        check_evidence_hash != plan["identity"].get("check_evidence_hash")
        or not isinstance(status, str)
        or status not in {"PASS", "FAIL", "UNKNOWN"}
    ):
        ledger["external_check_states"][check_id] = "INVALID"
    else:
        ledger["external_check_states"][check_id] = status


def record_context_result(
    plan: dict[str, Any], ledger: dict[str, Any], *, obligation_id: str, status: str, snapshot_id: str, evidence_sha256: str | None
) -> None:
    _validate_ledger(plan, ledger)
    if obligation_id not in ledger["context_states"] or ledger["context_states"][obligation_id] != "PENDING":
        raise PlanError("context_result_without_pending_obligation")
    if status != "RESOLVED" or snapshot_id != plan["identity"].get("snapshot_id") or not _is_sha256(evidence_sha256):
        ledger["context_states"][obligation_id] = "UNKNOWN"
    else:
        ledger["context_states"][obligation_id] = "RESOLVED"


def aggregate(plan: dict[str, Any], ledger: dict[str, Any]) -> dict[str, Any]:
    """Return prototype record completeness only; never produce an audit or approval."""
    _validate_ledger(plan, ledger)
    pending = []
    blockers = []
    for task_id, state in ledger["task_states"].items():
        if state != "SUCCEEDED":
            pending.append(task_id)
    for task_id, state in ledger["check_states"].items():
        if state in {"PENDING", "UNKNOWN", "INVALID"}:
            pending.append(task_id)
        elif state == "FAIL":
            blockers.append(task_id)
    for check_id, state in ledger["external_check_states"].items():
        if state in {"PENDING", "UNKNOWN", "INVALID"}:
            pending.append(check_id)
        elif state == "FAIL":
            blockers.append(check_id)
    for obligation_id, state in ledger["context_states"].items():
        if state != "RESOLVED":
            pending.append(obligation_id)
    return {
        "prototype_state": "INCOMPLETE" if pending else "ALL_REQUIRED_RESULTS_RECORDED",
        "disposition": "NOT_EVALUATED",
        "publication_eligible": False,
        "pending_ids": sorted(set(pending)),
        "recorded_failing_check_ids": sorted(blockers),
        "provider_requests_reserved": ledger["reserved_calls"],
        "provider_input_bytes_reserved": ledger["reserved_input_bytes"],
        "required_specialist_tasks": len(plan["task_manifest"]),
        "required_check_tasks": len(plan["check_tasks"]),
        "required_external_checks": len(plan["external_checks"]),
        "required_context_obligations": len(plan["context_tasks"]),
    }
