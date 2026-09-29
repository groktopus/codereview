#!/usr/bin/env python3
"""Fail-closed verification for the pinned PR-457 and PR-464 writer plans.

This verifier consumes provider-free CLI preparation JSON and a committed plan.
It emits a hash/count-only receipt; it never reads credentials or dispatches a
provider request.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from shadow_case_policy import CASE_POLICY  # noqa: E402

PLAN_MAX_BYTES = 128_000
PREPARE_MAX_BYTES = 4_000_000
SHA256 = re.compile(r"^[0-9a-f]{64}$")
EXPECTED_MODULE_COUNT = 35
EXPECTED_MODULE_TREE_SHA256 = "18fff15521a047add0cf4b89341e5117eb73ad959caaab664e0ee9a283bf29aa"
EXPECTED_PLAN_SHA256 = {case_id: policy["plan_sha256"] for case_id, policy in CASE_POLICY.items()}
CASE_CONTRACTS = {
    "PR-457": {"repository": "magnus919/SlopSearX", "base_sha": "53dbafd9207eed175228c594058af85ed8e9bd0e", "head_sha": "595f143607961d21d162efe76518d86e416d2548", "snapshot_id": "snap-24293f430e4f8006a52bac18", "snapshot_sha256": "14bd673c2c77ffc59875c957c095b32e262d534fb581f3ec38aaf94898a19fea", "evidence_index_sha256": "10badb5f0c9325e55aa093788cfe6d2d45eaf8e66aef6c207a2dddc8a6bace95", "profile_version": "slopsearx-realcase-eval-v2-pr457-context240-window16k", "profile_file_sha256": "c3b5f82b0d2d38e3173f836a06af1b39afd8b47b81609caab5bae0e842435918", "historical_checks_sha256": "187bb52d825d1fa08872e4ef0b278fd0e6d9257721a459a6b6890ea8230a5977", "check_evidence_sha256": "7daee7f1c2e89a49c37cda4b5b204d636cf6219720df436c300d778f9fab3311", "scope_obligations": 14, "request_count": 6, "request_bytes_total": 469539, "request_bytes_max": 118490, "remaining_call_slots": 4},
    "PR-464": {"repository": "magnus919/SlopSearX", "base_sha": "20a743f0434a1843aa00068483f608f1e213b2af", "head_sha": "bffc26f9e4bf95aca0c252e88a2396d03ece854c", "snapshot_id": "snap-e20deb18f2ac6cb39c6ebafd", "snapshot_sha256": "e45e9327fcb1ad37d6c37155fb40499f3179fc8dfd73d16a8d261f3a18691868", "evidence_index_sha256": "0b75fca3258bd3d75ed3d260467ec130f639f2afc59519e5f603f4d4a176e30c", "profile_version": "slopsearx-realcase-eval-v2-pr464-context240-window16k", "profile_file_sha256": "66e65ad3eec3e9311ff9df820ec4eba85baea236a1d56256781475455c6e0ea8", "historical_checks_sha256": "7198ac6bf02d3887fb065205e4ffbd48d435657027d4d5fa73168bdc900c359f", "check_evidence_sha256": "7187d1097d94930be5b3faf1a584cd409ecaae3f9f33789bfd6df78f5a451e7b", "scope_obligations": 22, "request_count": 10, "request_bytes_total": 893359, "request_bytes_max": 96462, "remaining_call_slots": 0},
}
LIMITS_PATH = ROOT / "experiments" / "model-only-shadow-live-writer-limits-v1.json"
PROVIDER_PATH = ROOT / "experiments" / "model-only-shadow-live-writer-provider-v1.json"


class PreflightError(ValueError):
    """Input does not match the fixed provider-free plan."""


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PreflightError("duplicate_json_key")
        result[key] = value
    return result


def _read_json(path: Path, limit: int) -> tuple[dict[str, Any], bytes]:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
            raise PreflightError("input_unavailable")
        fd = os.open(path, flags)
        try:
            opened = os.fstat(fd)
            if (not stat.S_ISREG(opened.st_mode) or opened.st_dev != before.st_dev
                    or opened.st_ino != before.st_ino or opened.st_size > limit):
                raise PreflightError("input_unavailable")
            chunks = bytearray()
            while len(chunks) <= limit:
                chunk = os.read(fd, min(64 * 1024, limit + 1 - len(chunks)))
                if not chunk:
                    break
                chunks.extend(chunk)
            raw = bytes(chunks)
        finally:
            os.close(fd)
    except OSError:
        raise PreflightError("input_unavailable") from None
    if len(raw) > limit:
        raise PreflightError("input_exceeds_limit")
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_pairs,
            parse_constant=lambda _value: (_ for _ in ()).throw(PreflightError("invalid_json_constant")),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, PreflightError):
        raise PreflightError("input_invalid_json") from None
    if not isinstance(value, dict):
        raise PreflightError("input_invalid_shape")
    return value, raw


def _integer(value: Any, *, minimum: int = 0) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= minimum


def _plan_requests(plan: dict[str, Any]) -> list[dict[str, Any]]:
    case_id = plan.get("case", {}).get("case_id") if isinstance(plan.get("case"), dict) else None
    contract = CASE_CONTRACTS.get(case_id)
    if contract is None:
        raise PreflightError("plan_case_identity_invalid")
    if set(plan) != {
        "schema", "status", "case", "runtime", "provider_identity", "budget", "writer_requests",
        "prepare_contract",
    }:
        raise PreflightError("plan_schema_invalid")
    if plan.get("schema") != "model-only-shadow-live-writer-plan.v2":
        raise PreflightError("plan_contract_invalid")
    if plan.get("status") != "PREPARE_ONLY_PINNED_PLAN_NO_PROVIDER_DISPATCH":
        raise PreflightError("plan_status_invalid")
    if plan.get("prepare_contract") != {
        "profile_path": f"docs/real-case-trial-v1/profiles/{case_id}.json",
        "historical_checks_path": f"docs/real-case-trial-v1/checks/{case_id}.json",
        "limits_path": "experiments/model-only-shadow-live-writer-limits-v1.json",
        "provider_config_path": "experiments/model-only-shadow-live-writer-provider-v1.json",
        "mode": "AUTO", "effect_policy": "READ_ONLY", "prepare_only": True,
        "json_output": True, "capture_case_id": case_id, "provider_calls_before_preflight": 0,
    }:
        raise PreflightError("plan_prepare_contract_invalid")
    case = plan.get("case")
    if not isinstance(case, dict) or set(case) != {
        "case_id", "repository", "base_sha", "head_sha", "snapshot_id", "snapshot_sha256",
        "evidence_index_sha256", "profile_version", "profile_file_sha256",
        "historical_checks_sha256", "check_evidence_sha256", "scope_obligations",
    }:
        raise PreflightError("plan_case_invalid")
    case_contract_fields = {
        "repository", "base_sha", "head_sha", "snapshot_id", "snapshot_sha256",
        "evidence_index_sha256", "profile_version", "profile_file_sha256",
        "historical_checks_sha256", "check_evidence_sha256", "scope_obligations",
    }
    if case != {key: contract[key] for key in case_contract_fields} | {"case_id": case_id}:
        raise PreflightError("plan_case_identity_invalid")
    for field in (
        "snapshot_sha256", "evidence_index_sha256", "profile_file_sha256",
        "historical_checks_sha256", "check_evidence_sha256",
    ):
        if not isinstance(case.get(field), str) or not SHA256.fullmatch(case[field]):
            raise PreflightError("plan_case_hash_invalid")
    runtime = plan.get("runtime")
    if not isinstance(runtime, dict) or set(runtime) != {
        "plan_generated_from_revision", "module_count", "module_tree_sha256", "limits_sha256",
        "provider_identity_sha256", "writer_provider_config_sha256",
    }:
        raise PreflightError("plan_runtime_invalid")
    if (runtime.get("module_count") != EXPECTED_MODULE_COUNT
            or runtime.get("module_tree_sha256") != EXPECTED_MODULE_TREE_SHA256):
        raise PreflightError("plan_runtime_invalid")
    for field in (
        "module_tree_sha256", "limits_sha256", "provider_identity_sha256", "writer_provider_config_sha256"
    ):
        if not isinstance(runtime.get(field), str) or not SHA256.fullmatch(runtime[field]):
            raise PreflightError("plan_runtime_hash_invalid")
    if runtime.get("plan_generated_from_revision") != "b8f159dd8dbae28f3dc44f5771681b958ff904c3":
        raise PreflightError("plan_runtime_revision_invalid")
    identity = plan.get("provider_identity")
    if not isinstance(identity, dict) or identity != {
        "status": "PLANNED_NOT_OBSERVED_SECRET_VALUES_OPAQUE",
        "writer_provider_id": "operator_openai_compatible",
        "writer_base_url": "https://inference-api.nousresearch.com/v1",
        "writer_model": "openai/gpt-6-luna",
        "writer_credential_env": "LLM_API_KEY",
    }:
        raise PreflightError("plan_provider_identity_invalid")
    budget = plan.get("budget")
    expected_budget = {
        "writer_exact_call_count": contract["request_count"], "writer_max_provider_calls": 10,
        "writer_max_retries_per_task": 0, "writer_max_request_bytes": 128000,
        "writer_max_response_bytes": 32768, "writer_max_output_tokens": 1800,
        "writer_deadline_seconds": 600, "writer_max_concurrent_scopes": 4,
        "writer_followup_slots": 0, "writer_claim_assessment_slots": 0,
        "writer_summary_slots": 0, "writer_optional_stage_slots": 0,
        "audit_max_provider_calls": 3,
        "audit_max_input_bytes_per_call": 120000 if case_id == "PR-457" else 96000,
        "audit_max_response_bytes_per_call": 64000, "audit_max_output_tokens_per_llm_call": 1800,
        "audit_max_deadline_seconds_per_call": 90, "audit_max_retries": 0,
        "total_provider_calls_max": 13, "total_provider_deadline_seconds_max": 870,
        "target_code_execution": False, "publication_enabled": False,
    }
    if budget != expected_budget:
        raise PreflightError("plan_budget_invalid")
    rows = plan.get("writer_requests")
    expected_fields = {"task_id", "lens", "input_bytes", "input_sha256", "output_bytes_cap", "output_tokens_cap"}
    if not isinstance(rows, list) or len(rows) != contract["request_count"]:
        raise PreflightError("plan_request_count_invalid")
    seen: set[str] = set()
    for row in rows:
        if not isinstance(row, dict) or set(row) != expected_fields:
            raise PreflightError("plan_request_invalid")
        task_id = row.get("task_id")
        if not isinstance(task_id, str) or not task_id or task_id in seen:
            raise PreflightError("plan_request_task_invalid")
        seen.add(task_id)
        if row.get("lens") not in {"correctness", "tests", "maintainability", "security"}:
            raise PreflightError("plan_request_lens_invalid")
        if not _integer(row.get("input_bytes"), minimum=1) or row["input_bytes"] > 128000:
            raise PreflightError("plan_request_size_invalid")
        if not isinstance(row.get("input_sha256"), str) or not SHA256.fullmatch(row["input_sha256"]):
            raise PreflightError("plan_request_hash_invalid")
        if row.get("output_bytes_cap") != 32768 or row.get("output_tokens_cap") != 1800:
            raise PreflightError("plan_request_output_budget_invalid")
    if (sum(row["input_bytes"] for row in rows) != contract["request_bytes_total"]
            or max(row["input_bytes"] for row in rows) != contract["request_bytes_max"]):
        raise PreflightError("plan_request_totals_invalid")
    return rows


def verify(plan: dict[str, Any], prepared: dict[str, Any], *, plan_bytes: bytes) -> dict[str, Any]:
    case_id = plan.get("case", {}).get("case_id") if isinstance(plan.get("case"), dict) else None
    contract = CASE_CONTRACTS.get(case_id)
    if contract is None or hashlib.sha256(plan_bytes).hexdigest() != EXPECTED_PLAN_SHA256[case_id]:
        raise PreflightError("plan_hash_mismatch")
    requests = _plan_requests(plan)
    limits, limits_bytes = _read_json(LIMITS_PATH, 16_000)
    provider_config, provider_bytes = _read_json(PROVIDER_PATH, 16_000)
    if hashlib.sha256(limits_bytes).hexdigest() != plan["runtime"]["limits_sha256"]:
        raise PreflightError("limits_file_hash_mismatch")
    if hashlib.sha256(provider_bytes).hexdigest() != plan["runtime"]["writer_provider_config_sha256"]:
        raise PreflightError("provider_config_hash_mismatch")
    if set(limits) != {
        "schema_version", "deadline_seconds", "max_concurrent_scopes", "max_provider_calls",
        "max_retries_per_task", "max_context_bytes", "max_snapshot_context_bytes",
        "max_input_bytes_per_task", "max_output_bytes_per_task", "max_output_bytes",
        "max_output_tokens", "max_context_retrievals", "max_followup_tasks",
    } or limits != {
        "schema_version": "1.0", "deadline_seconds": 600, "max_concurrent_scopes": 4,
        "max_provider_calls": 10, "max_retries_per_task": 0, "max_context_bytes": 8_000_000,
        "max_snapshot_context_bytes": 300_000, "max_input_bytes_per_task": 128_000,
        "max_output_bytes_per_task": 32_768, "max_output_bytes": 2_097_152,
        "max_output_tokens": 1800, "max_context_retrievals": 8, "max_followup_tasks": 0,
    }:
        raise PreflightError("limits_file_contract_invalid")
    if provider_config != {
        "kind": "openai_compatible", "provider_id": "operator_openai_compatible",
        "base_url": "https://inference-api.nousresearch.com/v1", "model": "openai/gpt-6-luna",
        "api_key_env": "LLM_API_KEY", "timeout_seconds": 90, "max_request_bytes": 128_000,
        "max_response_bytes": 32_768, "max_output_tokens": 1800, "max_output_items": 100,
    }:
        raise PreflightError("provider_config_contract_invalid")
    source_dir = ROOT / "src" / "pr_review_harness"
    module_files = {
        f"pr_review_harness/{path.name}": hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(source_dir.glob("*.py")) if path.is_file()
    }
    module_tree = hashlib.sha256(
        json.dumps(module_files, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()
    if len(module_files) != EXPECTED_MODULE_COUNT or module_tree != plan["runtime"]["module_tree_sha256"]:
        raise PreflightError("runtime_module_tree_mismatch")
    if set(prepared) != {
        "capacity", "checks", "command", "disposition", "no_provider_calls", "no_target_code_execution",
        "primary_requests", "scope", "snapshot", "status",
    }:
        raise PreflightError("prepare_schema_invalid")
    if (
        prepared.get("command") != "review" or prepared.get("status") != "PREPARED_ONLY"
        or prepared.get("no_provider_calls") is not True
        or prepared.get("no_target_code_execution") is not True
        or prepared.get("disposition") is not None
    ):
        raise PreflightError("prepare_state_invalid")
    case = plan["case"]
    snapshot = prepared.get("snapshot")
    if not isinstance(snapshot, dict) or any(
        snapshot.get(field) != expected for field, expected in {
            "base_sha": case["base_sha"], "head_sha": case["head_sha"],
            "snapshot_id": case["snapshot_id"], "snapshot_hash": case["snapshot_sha256"],
            "evidence_index_sha256": case["evidence_index_sha256"],
            "profile_version": case["profile_version"],
            "profile_file_sha256": case["profile_file_sha256"],
            "limits_sha256": plan["runtime"]["limits_sha256"],
            "provider_identity_sha256": plan["runtime"]["provider_identity_sha256"],
        }.items()
    ):
        raise PreflightError("prepare_snapshot_mismatch")
    checks = prepared.get("checks")
    if not isinstance(checks, dict) or checks.get("check_evidence_hash") != case["check_evidence_sha256"]:
        raise PreflightError("prepare_checks_mismatch")
    historical = checks.get("historical_check_identity")
    if not isinstance(historical, dict) or historical.get("check_document_sha256") != case["historical_checks_sha256"]:
        raise PreflightError("prepare_checks_mismatch")
    scope = prepared.get("scope")
    if (not isinstance(scope, dict) or not isinstance(scope.get("coverage_obligations"), list)
            or len(scope["coverage_obligations"]) != case["scope_obligations"]):
        raise PreflightError("prepare_scope_mismatch")
    capacity = prepared.get("capacity")
    if not isinstance(capacity, dict) or any(
        capacity.get(key) != expected for key, expected in {
            "configured_max_provider_calls": 10,
            "configured_max_input_bytes_per_task": 128000,
            "exact_primary_call_demand": contract["request_count"],
            "exact_primary_serialized_input_bytes": contract["request_bytes_total"],
            "remaining_global_call_slots_after_primary": contract["remaining_call_slots"],
        }.items()
    ):
        raise PreflightError("prepare_capacity_mismatch")
    actual = prepared.get("primary_requests")
    if not isinstance(actual, list) or len(actual) != len(requests):
        raise PreflightError("prepare_request_count_mismatch")
    actual_fields = {
        "admitted", "context_omissions", "evidence_bindings", "evidence_ids", "input_bytes", "input_sha256",
        "lens", "obligation_ids", "output_bytes_cap", "output_tokens_cap", "request_input_contract",
        "required_context_ids", "required_context_omissions", "task_id", "unit_evidence_bindings", "unit_ids",
    }
    request_fields = ("task_id", "lens", "input_bytes", "input_sha256", "output_bytes_cap", "output_tokens_cap")
    actual_by_id: dict[str, dict[str, Any]] = {}
    for row in actual:
        if (not isinstance(row, dict) or set(row) != actual_fields
                or not isinstance(row.get("task_id"), str) or row.get("task_id") in actual_by_id):
            raise PreflightError("prepare_request_invalid")
        if row.get("admitted") is not True:
            raise PreflightError("prepare_request_not_admitted")
        actual_by_id[row.get("task_id")] = row
    for expected in requests:
        observed = actual_by_id.get(expected["task_id"])
        if not isinstance(observed, dict) or any(observed.get(key) != expected[key] for key in request_fields):
            raise PreflightError("prepare_request_descriptor_mismatch")
    return {
        "schema": "model-only-shadow-live-preflight-receipt.v1",
        "status": "PLAN_MATCHED_PROVIDER_FREE",
        "case_id": case["case_id"],
        "snapshot_sha256": case["snapshot_sha256"],
        "plan_sha256": hashlib.sha256(plan_bytes).hexdigest(),
        "writer_calls_planned": len(requests),
        "writer_request_bytes_total": sum(row["input_bytes"] for row in requests),
        "writer_request_bytes_max": max(row["input_bytes"] for row in requests),
        "audit_request_cap_bytes": plan["budget"]["audit_max_input_bytes_per_call"],
        "provider_calls": 0,
        "target_code_execution": False,
        "publication_enabled": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--prepared", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        plan, plan_bytes = _read_json(args.plan, PLAN_MAX_BYTES)
        prepared, _prepared_bytes = _read_json(args.prepared, PREPARE_MAX_BYTES)
        receipt = verify(plan, prepared, plan_bytes=plan_bytes)
    except (OSError, PreflightError) as exc:
        code = str(exc) if isinstance(exc, PreflightError) else "input_unavailable"
        print(json.dumps({"ok": False, "error_code": code}, separators=(",", ":")), file=sys.stderr)
        return 2
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
