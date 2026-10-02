"""Closed, current-source request pins for the opt-in PR-457 shadow lane.

This contract supplements the historical frozen plans. It is deliberately
limited to one fixed public case and the existing writer/audit budgets.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from pathlib import Path
from typing import Any

PLAN_SCHEMA = "pr457-current-source-capture-plan.v2"
RECEIPT_SCHEMA = "pr457-current-source-capture-receipt.v2"
SOURCE_WORKFLOW_REF = (
    "groktopus/codereview/.github/workflows/pr457-role-accounted-shadow.yml@refs/heads/main"
)
PLAN_FILENAME = "pr457-current-source-plan.json"
RECEIPT_FILENAME = "pr457-current-source-receipt.json"
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
SHA40 = re.compile(r"[0-9a-f]{40}\Z")
MAX_RUNTIME_FILES = 256
MAX_RUNTIME_ENTRIES = 1_024
MAX_RUNTIME_FILE_BYTES = 2_000_000
MAX_RUNTIME_TOTAL_BYTES = 8_000_000

TARGET = {
    "case_id": "PR-457",
    "repository": "magnus919/SlopSearX",
    "base_sha": "53dbafd9207eed175228c594058af85ed8e9bd0e",
    "head_sha": "595f143607961d21d162efe76518d86e416d2548",
    "snapshot_id": "snap-24293f430e4f8006a52bac18",
    "snapshot_sha256": "14bd673c2c77ffc59875c957c095b32e262d534fb581f3ec38aaf94898a19fea",
    "evidence_index_sha256": "10badb5f0c9325e55aa093788cfe6d2d45eaf8e66aef6c207a2dddc8a6bace95",
    "profile_version": "slopsearx-realcase-eval-v2-pr457-context240-window16k",
    "profile_file_sha256": "c3b5f82b0d2d38e3173f836a06af1b39afd8b47b81609caab5bae0e842435918",
    "historical_checks_sha256": "187bb52d825d1fa08872e4ef0b278fd0e6d9257721a459a6b6890ea8230a5977",
    "check_evidence_sha256": "7daee7f1c2e89a49c37cda4b5b204d636cf6219720df436c300d778f9fab3311",
    "scope_obligations": 14,
}
LIMITS = {
    "writer_exact_call_count": 6,
    "writer_max_provider_calls": 10,
    "writer_max_retries_per_task": 0,
    "writer_max_request_bytes": 128_000,
    "writer_max_response_bytes": 32_768,
    "writer_max_output_tokens": 1_800,
    "writer_deadline_seconds": 600,
    "audit_max_provider_calls": 3,
    "audit_max_input_bytes_per_call": 120_000,
    "audit_max_response_bytes_per_call": 64_000,
    "audit_max_output_tokens_per_llm_call": 1_800,
    "audit_max_deadline_seconds_per_call": 90,
    "audit_max_retries": 0,
    "total_provider_calls_max": 13,
    "total_provider_deadline_seconds_max": 870,
    "target_code_execution": False,
    "publication_enabled": False,
}
TASK_LENSES = {
    "task-623f302f40eb1872:chunk-1": "correctness",
    "task-c74db8e0a80307d3:chunk-1": "tests",
    "task-f10edd3dcc43dac7:chunk-1": "maintainability",
    "task-501271d8089f3137:chunk-1": "correctness",
    "task-3564cf4456fc5138:chunk-1": "tests",
    "task-338809eec73565aa:chunk-1": "maintainability",
}
CHECK_BINDINGS = {
    "check:portal-impact-evidence": ("portal-impact-evidence", "external:portal-contract"),
    "check:portal-browser-evidence": ("portal-browser-evidence", "external:portal-browser"),
}
CHECK_SCOPE_UNITS = ("unit-98ecf75f7878cd37c560",)


class CurrentSourceCaptureError(ValueError):
    """A current-source request plan failed its closed PR-457 contract."""


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise CurrentSourceCaptureError("prepared_input_invalid")
        value[key] = item
    return value


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _read_static_tasks() -> dict[str, str]:
    rows = dict(TASK_LENSES)
    if len(rows) != 6 or any(not isinstance(k, str) or not isinstance(v, str) for k, v in rows.items()):
        raise CurrentSourceCaptureError("static_task_inventory_invalid")
    return rows


def installed_module_inventory() -> dict[str, str]:
    package = Path(__file__).resolve().parent
    inventory: dict[str, str] = {}
    total_bytes = 0
    visited_entries = 0
    pending = [package]
    try:
        while pending:
            directory = pending.pop()
            with os.scandir(directory) as entries:
                for entry in entries:
                    visited_entries += 1
                    if visited_entries > MAX_RUNTIME_ENTRIES:
                        raise CurrentSourceCaptureError("runtime_inventory_limit_exceeded")
                    path = Path(entry.path)
                    relative = path.relative_to(package)
                    if "__pycache__" in relative.parts or path.suffix == ".pyc":
                        continue
                    info = entry.stat(follow_symlinks=False)
                    if stat.S_ISLNK(info.st_mode):
                        raise CurrentSourceCaptureError("runtime_inventory_symlink")
                    if stat.S_ISDIR(info.st_mode):
                        pending.append(path)
                        continue
                    if not stat.S_ISREG(info.st_mode):
                        continue
                    if len(inventory) >= MAX_RUNTIME_FILES or info.st_size > MAX_RUNTIME_FILE_BYTES:
                        raise CurrentSourceCaptureError("runtime_inventory_limit_exceeded")
                    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
                    descriptor = os.open(path, flags)
                    try:
                        opened = os.fstat(descriptor)
                        if (not stat.S_ISREG(opened.st_mode)
                                or (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino)
                                or opened.st_size != info.st_size):
                            raise CurrentSourceCaptureError("runtime_inventory_changed")
                        raw = bytearray()
                        while len(raw) <= MAX_RUNTIME_FILE_BYTES:
                            chunk = os.read(descriptor, min(65_536, MAX_RUNTIME_FILE_BYTES + 1 - len(raw)))
                            if not chunk:
                                break
                            raw.extend(chunk)
                    finally:
                        os.close(descriptor)
                    if len(raw) != opened.st_size or len(raw) > MAX_RUNTIME_FILE_BYTES:
                        raise CurrentSourceCaptureError("runtime_inventory_changed")
                    total_bytes += len(raw)
                    if total_bytes > MAX_RUNTIME_TOTAL_BYTES:
                        raise CurrentSourceCaptureError("runtime_inventory_limit_exceeded")
                    inventory[f"pr_review_harness/{relative.as_posix()}"] = _sha(bytes(raw))
    except CurrentSourceCaptureError:
        raise
    except OSError:
        raise CurrentSourceCaptureError("runtime_inventory_unavailable") from None
    if not inventory:
        raise CurrentSourceCaptureError("runtime_inventory_empty")
    return inventory


def module_inventory_sha256(inventory: dict[str, str]) -> str:
    return _sha(_canonical(inventory))


def _validate_inventory_shape(inventory: Any) -> None:
    if (not isinstance(inventory, dict) or not inventory or len(inventory) > MAX_RUNTIME_FILES
            or any(not isinstance(path, str) or not path.startswith("pr_review_harness/")
                   or len(path) > 240 or ".." in Path(path).parts
                   or not isinstance(digest, str) or not SHA256.fullmatch(digest)
                   for path, digest in inventory.items())):
        raise CurrentSourceCaptureError("runtime_inventory_invalid")
    if len(_canonical(inventory)) > 100_000:
        raise CurrentSourceCaptureError("runtime_inventory_limit_exceeded")


def _requests(prepared: dict[str, Any]) -> list[dict[str, Any]]:
    rows = prepared.get("primary_requests")
    expected = _read_static_tasks()
    if not isinstance(rows, list) or len(rows) != LIMITS["writer_exact_call_count"]:
        raise CurrentSourceCaptureError("prepared_request_count_invalid")
    result = []
    seen: set[str] = set()
    fields = {
        "admitted", "context_omissions", "evidence_bindings", "evidence_ids", "input_bytes", "input_sha256",
        "lens", "obligation_ids", "output_bytes_cap", "output_tokens_cap", "request_input_contract",
        "required_context_ids", "required_context_omissions", "task_id", "unit_evidence_bindings", "unit_ids",
    }
    for row in rows:
        if not isinstance(row, dict) or set(row) != fields:
            raise CurrentSourceCaptureError("prepared_request_shape_invalid")
        task_id = row["task_id"]
        size = row["input_bytes"]
        if (not isinstance(task_id, str) or task_id in seen or task_id not in expected
                or row.get("lens") != expected[task_id]
                or isinstance(size, bool) or not isinstance(size, int) or not 1 <= size <= LIMITS["writer_max_request_bytes"]
                or not isinstance(row.get("input_sha256"), str) or not SHA256.fullmatch(row["input_sha256"])
                or row.get("admitted") is not True
                or row.get("output_bytes_cap") != LIMITS["writer_max_response_bytes"]
                or row.get("output_tokens_cap") != LIMITS["writer_max_output_tokens"]):
            raise CurrentSourceCaptureError("prepared_request_invalid")
        seen.add(task_id)
        result.append({
            "task_id": task_id, "lens": row["lens"], "input_bytes": size,
            "input_sha256": row["input_sha256"],
            "output_bytes_cap": row["output_bytes_cap"], "output_tokens_cap": row["output_tokens_cap"],
        })
    if seen != set(expected):
        raise CurrentSourceCaptureError("prepared_task_inventory_mismatch")
    return sorted(result, key=lambda row: list(expected).index(row["task_id"]))


def _source_audit_requests(prepared: dict[str, Any]) -> list[dict[str, Any]]:
    capacity = prepared.get("capacity")
    preflight = capacity.get("source_audit_preflight") if isinstance(capacity, dict) else None
    rows = preflight.get("requests") if isinstance(preflight, dict) else None
    expected = _read_static_tasks()
    if (not isinstance(preflight, dict) or preflight.get("active_input_limit_bytes") != LIMITS["audit_max_input_bytes_per_call"]
            or preflight.get("status") != "ADMITTED" or preflight.get("request_count") != len(expected)
            or not isinstance(rows, list) or len(rows) != len(expected)):
        raise CurrentSourceCaptureError("source_audit_preflight_missing")
    result = []
    seen: set[str] = set()
    for row in rows:
        size = row.get("input_bytes") if isinstance(row, dict) else None
        task_id = row.get("task_id") if isinstance(row, dict) else None
        digest = row.get("input_sha256") if isinstance(row, dict) else None
        if (not isinstance(row, dict) or set(row) != {"task_id", "input_bytes", "input_sha256", "admitted"}
                or not isinstance(task_id, str) or task_id not in expected or task_id in seen
                or isinstance(size, bool) or not isinstance(size, int) or not 1 <= size <= LIMITS["audit_max_input_bytes_per_call"]
                or not isinstance(digest, str) or not SHA256.fullmatch(digest) or row.get("admitted") is not True):
            raise CurrentSourceCaptureError("source_audit_request_invalid")
        seen.add(task_id)
        result.append({"task_id": task_id, "input_bytes": size, "input_sha256": digest})
    if seen != set(expected):
        raise CurrentSourceCaptureError("source_audit_task_inventory_mismatch")
    if preflight.get("request_bytes_max") != max(row["input_bytes"] for row in result):
        raise CurrentSourceCaptureError("source_audit_request_totals_invalid")
    return sorted(result, key=lambda row: list(expected).index(row["task_id"]))


def _deterministic_check_tasks(prepared: dict[str, Any]) -> list[dict[str, Any]]:
    """Pin the fixed target's deterministic checks from trusted prepare output."""
    snapshot = prepared.get("snapshot")
    checks = prepared.get("checks")
    scope = prepared.get("scope")
    scopes = scope.get("planned_task_scopes") if isinstance(scope, dict) else None
    obligations = scope.get("coverage_obligations") if isinstance(scope, dict) else None
    check_results = checks.get("check_results") if isinstance(checks, dict) else None
    evidence_index = snapshot.get("evidence_index") if isinstance(snapshot, dict) else None
    if (not isinstance(scopes, list) or not isinstance(obligations, list)
            or not isinstance(check_results, dict) or not isinstance(evidence_index, list)):
        raise CurrentSourceCaptureError("prepared_check_scope_missing")
    obligation_by_id = {}
    for row in obligations:
        if not isinstance(row, dict) or not isinstance(row.get("obligation_id"), str):
            raise CurrentSourceCaptureError("prepared_check_obligation_invalid")
        if row["obligation_id"] in obligation_by_id:
            raise CurrentSourceCaptureError("prepared_check_obligation_invalid")
        obligation_by_id[row["obligation_id"]] = row
    evidence_by_id = {}
    for row in evidence_index:
        if not isinstance(row, dict) or not isinstance(row.get("evidence_id"), str):
            raise CurrentSourceCaptureError("prepared_check_evidence_invalid")
        if row["evidence_id"] in evidence_by_id:
            raise CurrentSourceCaptureError("prepared_check_evidence_invalid")
        evidence_by_id[row["evidence_id"]] = row
    expected_ids = {binding for _check_id, binding in CHECK_BINDINGS.values()}
    if set(check_results) != expected_ids:
        raise CurrentSourceCaptureError("prepared_check_inventory_mismatch")
    rows = [row for row in scopes if isinstance(row, dict) and row.get("task_kind") == "DETERMINISTIC_CHECK"]
    if len(scopes) != len(TASK_LENSES) + len(CHECK_BINDINGS) or len(rows) != len(CHECK_BINDINGS):
        raise CurrentSourceCaptureError("prepared_check_task_inventory_mismatch")
    scope_ids = [row.get("task_id") if isinstance(row, dict) else None for row in scopes]
    if (any(not isinstance(task_id, str) for task_id in scope_ids)
            or len(set(scope_ids)) != len(scope_ids)):
        raise CurrentSourceCaptureError("prepared_task_scope_inventory_invalid")
    # The planner records logical specialist task IDs in scope, while request
    # serialization pins the engine's chunk-qualified IDs. Bind only the
    # known single-chunk form; do not accept arbitrary suffixes or extra tasks.
    specialist_scopes = {
        row.get("task_id"): row for row in scopes
        if isinstance(row, dict) and row.get("task_kind") == "SPECIALIST_FINDINGS"
    }
    request_to_scope = {}
    for task_id in TASK_LENSES:
        match = re.fullmatch(r"(.+):chunk-1", task_id)
        if not match:
            raise CurrentSourceCaptureError("static_task_inventory_invalid")
        request_to_scope[task_id] = match.group(1)
    expected_scope_ids = set(request_to_scope.values())
    if (len(specialist_scopes) != len(TASK_LENSES)
            or set(specialist_scopes) != expected_scope_ids
            or any(specialist_scopes[request_to_scope[task_id]].get("lens") != lens
                   for task_id, lens in TASK_LENSES.items())):
        raise CurrentSourceCaptureError("prepared_primary_task_scope_mismatch")
    request_by_id = {
        row.get("task_id"): row for row in prepared.get("primary_requests", [])
        if isinstance(row, dict)
    }
    for request_id, scope_id in request_to_scope.items():
        request = request_by_id.get(request_id)
        planned_scope = specialist_scopes[scope_id]
        if (not isinstance(request, dict)
                or request.get("unit_ids") != planned_scope.get("unit_ids")
                or request.get("obligation_ids") != planned_scope.get("obligation_ids")
                or not isinstance(request.get("evidence_ids"), list)
                or not isinstance(planned_scope.get("evidence_ids"), list)
                or sorted(request["evidence_ids"]) != sorted(planned_scope["evidence_ids"])):
            raise CurrentSourceCaptureError("prepared_primary_scope_binding_mismatch")
    result = []
    seen: set[str] = set()
    for row in rows:
        task_id = row.get("task_id")
        obligation_ids = row.get("obligation_ids")
        if (not isinstance(task_id, str) or task_id in seen or not isinstance(obligation_ids, list)
                or len(obligation_ids) != 1 or not isinstance(obligation_ids[0], str)):
            raise CurrentSourceCaptureError("prepared_check_task_invalid")
        obligation_id = obligation_ids[0]
        configured = CHECK_BINDINGS.get(obligation_id)
        obligation = obligation_by_id.get(obligation_id)
        if configured is None or not isinstance(obligation, dict):
            raise CurrentSourceCaptureError("prepared_check_obligation_mismatch")
        check_id, binding_id = configured
        if (obligation.get("obligation_kind") != "PROJECT_CHECK" or obligation.get("required") is not True
                or obligation.get("check_binding_id") != binding_id
                or row.get("lens") != "project_specific"
                or row.get("unit_ids") != obligation.get("scope_unit_ids")
                or row.get("evidence_ids") != [] or row.get("required_context_ids") != []):
            raise CurrentSourceCaptureError("prepared_check_scope_mismatch")
        current_source_input_hash = row.get("current_source_input_hash")
        if not isinstance(current_source_input_hash, str) or not SHA256.fullmatch(current_source_input_hash):
            raise CurrentSourceCaptureError("prepared_check_input_hash_missing")
        expected_task_id = "task-" + hashlib.sha256(
            _canonical({"snapshot": snapshot["snapshot_id"], "obligation": obligation_id})
        ).hexdigest()[:16]
        if task_id != expected_task_id:
            raise CurrentSourceCaptureError("prepared_check_task_identity_mismatch")
        check_result = check_results.get(binding_id)
        if not isinstance(check_result, dict) or check_result.get("outcome") not in {"PASS", "FINDINGS", "UNKNOWN", "ERROR"}:
            raise CurrentSourceCaptureError("prepared_check_result_invalid")
        evidence_id = check_result.get("evidence_id")
        if evidence_id is not None:
            evidence = evidence_by_id.get(evidence_id)
            if (not isinstance(evidence_id, str) or not isinstance(evidence, dict)
                    or evidence.get("source_kind") != "github_check_run"
                    or evidence.get("trust") != "generated_result"
                    or not isinstance(evidence.get("content_hash"), str)
                    or not SHA256.fullmatch(evidence["content_hash"])
                    or evidence_id != "check-" + evidence["content_hash"][:24]):
                raise CurrentSourceCaptureError("prepared_check_evidence_mismatch")
        elif check_result.get("outcome") in {"PASS", "FINDINGS"}:
            raise CurrentSourceCaptureError("prepared_check_evidence_missing")
        result.append({
            "task_id": task_id, "task_kind": "DETERMINISTIC_CHECK", "lens": "project_specific",
            "obligation_id": obligation_id, "check_id": check_id, "check_binding_id": binding_id,
            "unit_ids": list(row["unit_ids"]), "evidence_ids": [],
            "expected_outcome": check_result["outcome"], "expected_evidence_id": evidence_id,
            "expected_input_hash": current_source_input_hash,
        })
        seen.add(task_id)
    if {row["obligation_id"] for row in result} != set(CHECK_BINDINGS):
        raise CurrentSourceCaptureError("prepared_check_task_inventory_mismatch")
    return sorted(result, key=lambda row: row["obligation_id"])


def create_plan(prepared: dict[str, Any], *, source_sha: str, module_inventory: dict[str, str], prepared_raw: bytes) -> tuple[dict[str, Any], dict[str, Any]]:
    if not isinstance(source_sha, str) or not SHA40.fullmatch(source_sha):
        raise CurrentSourceCaptureError("source_revision_invalid")
    if (not isinstance(prepared, dict) or prepared.get("status") != "PREPARED_ONLY"
            or prepared.get("no_provider_calls") is not True
            or prepared.get("no_target_code_execution") is not True
            or prepared.get("disposition") is not None):
        raise CurrentSourceCaptureError("prepared_state_invalid")
    try:
        parsed_raw = json.loads(prepared_raw.decode("utf-8"), object_pairs_hook=_unique_pairs,
                                parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("invalid_constant")))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError):
        raise CurrentSourceCaptureError("prepared_input_invalid") from None
    if parsed_raw != prepared:
        raise CurrentSourceCaptureError("prepared_input_binding_invalid")
    snapshot = prepared.get("snapshot")
    checks = prepared.get("checks")
    scope = prepared.get("scope")
    if not isinstance(snapshot, dict) or not isinstance(checks, dict) or not isinstance(scope, dict):
        raise CurrentSourceCaptureError("prepared_identity_missing")
    expected_snapshot = {
        "base_sha": TARGET["base_sha"], "head_sha": TARGET["head_sha"],
        "snapshot_id": TARGET["snapshot_id"], "snapshot_hash": TARGET["snapshot_sha256"],
        "evidence_index_sha256": TARGET["evidence_index_sha256"],
        "profile_version": TARGET["profile_version"], "profile_file_sha256": TARGET["profile_file_sha256"],
        "provider_identity_sha256": None,
    }
    identity_sha = snapshot.get("provider_identity_sha256")
    if not isinstance(identity_sha, str) or not SHA256.fullmatch(identity_sha):
        raise CurrentSourceCaptureError("prepared_provider_identity_invalid")
    expected_snapshot["provider_identity_sha256"] = identity_sha
    if any(snapshot.get(k) != v for k, v in expected_snapshot.items()):
        raise CurrentSourceCaptureError("prepared_snapshot_mismatch")
    hist = checks.get("historical_check_identity")
    obligations = scope.get("coverage_obligations")
    if (checks.get("check_evidence_hash") != TARGET["check_evidence_sha256"]
            or not isinstance(hist, dict) or hist.get("check_document_sha256") != TARGET["historical_checks_sha256"]
            or not isinstance(obligations, list) or len(obligations) != TARGET["scope_obligations"]):
        raise CurrentSourceCaptureError("prepared_checks_or_scope_mismatch")
    requests = _requests(prepared)
    source_requests = _source_audit_requests(prepared)
    check_tasks = _deterministic_check_tasks(prepared)
    capacity = prepared["capacity"]
    if (capacity.get("exact_primary_call_demand") != len(requests)
            or capacity.get("exact_primary_serialized_input_bytes") != sum(row["input_bytes"] for row in requests)
            or capacity.get("configured_max_provider_calls") != LIMITS["writer_max_provider_calls"]
            or capacity.get("configured_max_input_bytes_per_task") != LIMITS["writer_max_request_bytes"]):
        raise CurrentSourceCaptureError("prepared_capacity_mismatch")
    _validate_inventory_shape(module_inventory)
    plan = {
        "schema": PLAN_SCHEMA, "source_sha": source_sha, "target": TARGET,
        "provider_identity_sha256": identity_sha,
        "runtime": {"fingerprint_kind": "installed_source_resource_files.v1",
                    "module_count": len(module_inventory), "module_inventory_sha256": module_inventory_sha256(module_inventory),
                    "module_sha256": module_inventory},
        "limits": LIMITS, "writer_requests": requests, "source_audit_requests": source_requests,
        "deterministic_check_tasks": check_tasks,
    }
    receipt = {
        "schema": RECEIPT_SCHEMA, "source_sha": source_sha,
        "plan_sha256": _sha(_canonical(plan)), "prepared_sha256": _sha(prepared_raw),
        "provider_identity_sha256": expected_snapshot["provider_identity_sha256"],
        "provider_calls": 0, "target_code_execution": False, "publication_enabled": False,
    }
    return plan, receipt


def validate_plan(plan: Any, receipt: Any, *, source_sha: str, module_inventory: dict[str, str]) -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    if not isinstance(plan, dict) or set(plan) != {
        "schema", "source_sha", "target", "provider_identity_sha256", "runtime", "limits", "writer_requests",
        "source_audit_requests", "deterministic_check_tasks",
    }:
        raise CurrentSourceCaptureError("plan_shape_invalid")
    if plan.get("schema") != PLAN_SCHEMA or plan.get("source_sha") != source_sha or not SHA40.fullmatch(source_sha):
        raise CurrentSourceCaptureError("plan_source_invalid")
    if plan.get("target") != TARGET or plan.get("limits") != LIMITS:
        raise CurrentSourceCaptureError("plan_contract_mismatch")
    expected_identity = plan.get("provider_identity_sha256")
    if not isinstance(expected_identity, str) or not SHA256.fullmatch(expected_identity):
        raise CurrentSourceCaptureError("plan_provider_identity_mismatch")
    if plan.get("provider_identity_sha256") != expected_identity:
        raise CurrentSourceCaptureError("plan_provider_identity_mismatch")
    runtime = plan.get("runtime")
    if (not isinstance(runtime, dict) or set(runtime) != {"fingerprint_kind", "module_count", "module_inventory_sha256", "module_sha256"}
            or runtime.get("fingerprint_kind") != "installed_source_resource_files.v1"
            or runtime.get("module_sha256") != module_inventory
            or runtime.get("module_count") != len(module_inventory)
            or runtime.get("module_inventory_sha256") != module_inventory_sha256(module_inventory)):
        raise CurrentSourceCaptureError("plan_runtime_mismatch")
    request_rows = plan.get("writer_requests")
    if not isinstance(request_rows, list) or len(request_rows) != LIMITS["writer_exact_call_count"]:
        raise CurrentSourceCaptureError("plan_request_count_invalid")
    pins: dict[str, dict[str, Any]] = {}
    expected = _read_static_tasks()
    for row in request_rows:
        if not isinstance(row, dict) or set(row) != {
            "task_id", "lens", "input_bytes", "input_sha256", "output_bytes_cap", "output_tokens_cap",
        }:
            raise CurrentSourceCaptureError("plan_request_shape_invalid")
        task_id = row.get("task_id")
        size = row.get("input_bytes")
        if (not isinstance(task_id, str) or task_id in pins or task_id not in expected
                or row.get("lens") != expected[task_id]
                or isinstance(size, bool) or not isinstance(size, int) or not 1 <= size <= LIMITS["writer_max_request_bytes"]
                or not isinstance(row.get("input_sha256"), str) or not SHA256.fullmatch(row["input_sha256"])
                or row.get("output_bytes_cap") != LIMITS["writer_max_response_bytes"]
                or row.get("output_tokens_cap") != LIMITS["writer_max_output_tokens"]):
            raise CurrentSourceCaptureError("plan_request_invalid")
        pins[task_id] = dict(row)
    if set(pins) != set(expected):
        raise CurrentSourceCaptureError("plan_task_inventory_mismatch")
    source_rows = plan.get("source_audit_requests")
    if not isinstance(source_rows, list) or len(source_rows) != len(expected):
        raise CurrentSourceCaptureError("plan_source_audit_count_invalid")
    source_pins = {}
    for row in source_rows:
        if not isinstance(row, dict) or set(row) != {"task_id", "input_bytes", "input_sha256"}:
            raise CurrentSourceCaptureError("plan_source_audit_shape_invalid")
        task_id, size, digest = row["task_id"], row["input_bytes"], row["input_sha256"]
        if (not isinstance(task_id, str) or task_id not in expected or task_id in source_pins
                or isinstance(size, bool) or not isinstance(size, int) or not 1 <= size <= LIMITS["audit_max_input_bytes_per_call"]
                or not isinstance(digest, str) or not SHA256.fullmatch(digest)):
            raise CurrentSourceCaptureError("plan_source_audit_invalid")
        source_pins[task_id] = dict(row)
    if set(source_pins) != set(expected):
        raise CurrentSourceCaptureError("plan_source_audit_inventory_mismatch")
    check_tasks = plan.get("deterministic_check_tasks")
    if (not isinstance(check_tasks, list) or len(check_tasks) != len(CHECK_BINDINGS)
            or any(not isinstance(row, dict) or set(row) != {
                "task_id", "task_kind", "lens", "obligation_id", "check_id", "check_binding_id",
                "unit_ids", "evidence_ids", "expected_outcome", "expected_evidence_id", "expected_input_hash",
            } for row in check_tasks)):
        raise CurrentSourceCaptureError("plan_check_task_inventory_invalid")
    check_ids = set()
    for row in check_tasks:
        task_id = row.get("task_id")
        obligation_id = row.get("obligation_id")
        if not isinstance(task_id, str) or not isinstance(obligation_id, str):
            raise CurrentSourceCaptureError("plan_check_task_invalid")
        configured = CHECK_BINDINGS.get(obligation_id)
        expected_task_id = "task-" + hashlib.sha256(
            _canonical({"snapshot": TARGET["snapshot_id"], "obligation": obligation_id})
        ).hexdigest()[:16]
        if (configured is None or row.get("task_kind") != "DETERMINISTIC_CHECK"
                or task_id != expected_task_id or task_id in pins
                or row.get("check_id") != configured[0] or row.get("check_binding_id") != configured[1]
                or row.get("lens") != "project_specific" or row.get("evidence_ids") != []
                or row.get("unit_ids") != list(CHECK_SCOPE_UNITS)
                or any(not isinstance(unit, str) for unit in row["unit_ids"])
                or len(set(row["unit_ids"])) != len(row["unit_ids"])
                or row.get("expected_outcome") not in {"PASS", "FINDINGS", "UNKNOWN", "ERROR"}
                or not isinstance(row.get("expected_input_hash"), str)
                or not SHA256.fullmatch(row["expected_input_hash"])
                or (row.get("expected_evidence_id") is not None and
                    (not isinstance(row["expected_evidence_id"], str)
                     or not re.fullmatch(r"check-[0-9a-f]{24}", row["expected_evidence_id"])))):
            raise CurrentSourceCaptureError("plan_check_task_invalid")
        if row["expected_outcome"] in {"PASS", "FINDINGS"} and row["expected_evidence_id"] is None:
            raise CurrentSourceCaptureError("plan_check_evidence_missing")
        check_ids.add(obligation_id)
    if len({row["task_id"] for row in check_tasks}) != len(check_tasks):
        raise CurrentSourceCaptureError("plan_check_task_inventory_mismatch")
    if check_ids != set(CHECK_BINDINGS):
        raise CurrentSourceCaptureError("plan_check_task_inventory_mismatch")
    if not isinstance(receipt, dict) or set(receipt) != {
        "schema", "source_sha", "plan_sha256", "prepared_sha256", "provider_identity_sha256",
        "provider_calls", "target_code_execution", "publication_enabled",
    }:
        raise CurrentSourceCaptureError("receipt_shape_invalid")
    provider_calls = receipt.get("provider_calls")
    if (receipt.get("schema") != RECEIPT_SCHEMA or receipt.get("source_sha") != source_sha
            or receipt.get("plan_sha256") != _sha(_canonical(plan))
            or not isinstance(receipt.get("prepared_sha256"), str) or not SHA256.fullmatch(receipt["prepared_sha256"])
            or receipt.get("provider_identity_sha256") != expected_identity
            or isinstance(provider_calls, bool) or not isinstance(provider_calls, int) or provider_calls != 0
            or receipt.get("target_code_execution") is not False
            or receipt.get("publication_enabled") is not False):
        raise CurrentSourceCaptureError("receipt_binding_invalid")
    return pins, {"case_id": "PR-457", "snapshot_id": TARGET["snapshot_id"],
                  "snapshot_sha256": TARGET["snapshot_sha256"],
                  "audit_max_input_bytes_per_call": LIMITS["audit_max_input_bytes_per_call"],
                  "provider_identity_sha256": expected_identity,
                  "source_audit_requests": source_pins,
                  "deterministic_check_tasks": {row["task_id"]: row for row in check_tasks}}
