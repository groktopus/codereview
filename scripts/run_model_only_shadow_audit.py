#!/usr/bin/env python3
"""Run one bounded model-only audit from a same-job private writer capture.

Only a single deterministically selected candidate packet is sent to the three
audit roles. Raw requests and responses stay beneath the private output root;
the receipt contains statuses and hashes only.
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
# The current-source workflow installs the exact wheel built from its trusted
# dispatch revision. Keep its installed package authoritative; legacy frozen
# workflows retain their historical source-tree import behavior.
if os.environ.get("PR457_CURRENT_SOURCE_RUNTIME") != "1":
    sys.path.insert(0, str(ROOT / "src"))

import source_dispatch_accounting  # noqa: E402
from shadow_case_policy import CASE_POLICY, case_for_plan_path, validate_plan_binding  # noqa: E402

from pr_review_harness.claim_transport import ClaimTransport  # noqa: E402
from pr_review_harness.providers import OpenAIProvider, ProviderError  # noqa: E402
from pr_review_harness.shadow_audit import (  # noqa: E402
    MAX_CASE_BYTES,
    SOURCE_AUDIT_SERIALIZER_CANONICAL,
    SOURCE_AUDIT_SERIALIZER_LEGACY,
    run_shadow_audit,
)
from pr_review_harness.shadow_preflight import AuditDispatchGuard  # noqa: E402

MAX_CAPTURE_MANIFEST_BYTES = 256_000
MAX_RECEIPT_BYTES = 64_000
AUDIT_ROLES = ("source_auditor", "jev", "claim_auditor")
DISPATCH_STATES = {"guard_rejected", "post_guard_pretransport", "http_attempted", "unknown"}
DEFAULT_PLAN = ROOT / CASE_POLICY["PR-464"]["plan_relative_path"]
DEFAULT_LIMITS = ROOT / "experiments/model-only-shadow-audit-limits-v2.json"
PROFILE_RELATIVE_PATH = CASE_POLICY["PR-464"]["profile_path"]
EXPECTED_LLM = ("https://inference-api.nousresearch.com/v1", "openai/gpt-6-luna")
EXPECTED_JEV = ("https://api.typesafe.ai/v1/systemone", "jev-latest")


class PreDispatchFailure(ValueError):
    """A bounded failure receipt for validation/setup failures before audit calls."""

    def __init__(self, stage: str, code: str):
        super().__init__("audit pre-dispatch validation failed")
        self.stage = stage
        self.code = code


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_json_key")
        result[key] = value
    return result


def _read_json(path: Path, limit: int) -> tuple[dict[str, Any], bytes]:
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
        raise ValueError("input_unavailable")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise ValueError("input_unavailable")
        chunks = bytearray()
        while len(chunks) <= limit:
            block = os.read(fd, min(64 * 1024, limit + 1 - len(chunks)))
            if not block:
                break
            chunks.extend(block)
    finally:
        os.close(fd)
    if len(chunks) > limit:
        raise ValueError("input_too_large")
    try:
        value = json.loads(chunks.decode("utf-8"), object_pairs_hook=_unique,
                           parse_constant=lambda _v: (_ for _ in ()).throw(ValueError("invalid_constant")))
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError):
        raise ValueError("input_invalid_json") from None
    if not isinstance(value, dict):
        raise ValueError("input_invalid_shape")
    return value, bytes(chunks)


def _write_receipt(path: Path, value: dict[str, Any]) -> None:
    if path.exists() or path.is_symlink():
        raise ValueError("receipt_already_exists")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    raw = (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()
    if len(raw) > MAX_RECEIPT_BYTES:
        raise ValueError("receipt_too_large")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(fd)


def _packet_candidates(capture_root: Path) -> tuple[dict[str, Any], bytes, list[tuple[str, Path, dict[str, Any], bytes]]]:
    root = capture_root.absolute()
    info = root.lstat()
    if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError("private_capture_permissions_invalid")
    manifest, manifest_raw = _read_json(root / "manifest.json", MAX_CAPTURE_MANIFEST_BYTES)
    if manifest.get("contract_version") != "model-only-shadow-case.v1" or manifest.get("private_artifacts") is not True:
        raise ValueError("capture_manifest_invalid")
    run_identity = manifest.get("case_id")
    if (not isinstance(run_identity, str)
            or not re.fullmatch(r"writer-live-[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", run_identity)):
        raise ValueError("capture_run_identity_invalid")
    inventory = manifest.get("case_packet_inventory")
    if (not isinstance(inventory, dict) or set(inventory) != {"schema", "packets"}
            or inventory.get("schema") != "model-only-shadow-packet-inventory.v1"
            or not isinstance(inventory.get("packets"), list)
            or not 1 <= len(inventory["packets"]) <= 128):
        raise ValueError("capture_packet_inventory_missing_or_invalid")
    packet_dir = root / "case-packets"
    if packet_dir.is_symlink() or not packet_dir.is_dir() or stat.S_IMODE(packet_dir.stat().st_mode) != 0o700:
        raise ValueError("case_packet_directory_invalid")
    rows = []
    inventory_by_path: dict[str, str] = {}
    for item in inventory["packets"]:
        if (not isinstance(item, dict) or set(item) != {"path", "sha256"}
                or not isinstance(item.get("path"), str) or Path(item["path"]).name != item["path"]
                or not item["path"].endswith(".json") or not isinstance(item.get("sha256"), str)
                or not re.fullmatch(r"[0-9a-f]{64}", item["sha256"]) or item["path"] in inventory_by_path):
            raise ValueError("capture_packet_inventory_invalid")
        inventory_by_path[item["path"]] = item["sha256"]
    try:
        entries = list(packet_dir.iterdir())
    except OSError:
        raise ValueError("case_packet_directory_invalid") from None
    if {path.name for path in entries} != set(inventory_by_path):
        raise ValueError("capture_packet_inventory_mismatch")
    for path in sorted(entries):
        if path.is_symlink() or not path.is_file():
            raise ValueError("case_packet_file_invalid")
        if len(rows) >= 128:
            raise ValueError("case_packet_count_exceeds_limit")
        packet, raw = _read_json(path, MAX_CASE_BYTES)
        if hashlib.sha256(raw).hexdigest() != inventory_by_path[path.name]:
            raise ValueError("capture_packet_inventory_mismatch")
        if packet.get("contract_version") != "model-only-shadow-case.v1":
            raise ValueError("case_packet_contract_invalid")
        # The manifest case_id identifies this writer execution (for example,
        # writer-live-<run>-<attempt>); packets identify the frozen corpus case.
        # Bind packet case IDs to the trusted plan in _task_order instead.
        candidate = packet.get("writer_candidate")
        if candidate is None:
            candidate_id = ""
        elif (not isinstance(candidate, dict) or not isinstance(candidate.get("candidate_id"), str)
              or not candidate["candidate_id"]):
            raise ValueError("case_packet_candidate_invalid")
        else:
            candidate_id = candidate["candidate_id"]
        rows.append((candidate_id, path, packet, raw))
    if not rows:
        raise ValueError("case_packet_missing")
    return manifest, manifest_raw, rows


def _select_packet(rows: list[tuple[str, Path, dict[str, Any], bytes]]) -> tuple[str, Path, dict[str, Any], bytes] | None:
    candidates = [row for row in rows if row[0]]
    if not candidates:
        return None
    # Caller supplies trusted plan order with packet digest as the tie breaker.
    return candidates[0]


def _load_limits(path: Path) -> dict[str, Any]:
    limits, _ = _read_json(path, 16_000)
    common = {
        "schema": "model-only-shadow-audit-limits.v1", "max_packets": 1,
        "max_provider_calls": 3, "max_retries": 0,
        "max_request_bytes_per_call": 64_000, "max_response_bytes_per_call": 64_000,
        "max_output_tokens_per_llm_call": 1_800, "deadline_seconds_per_call": 90,
        "total_provider_deadline_seconds": 270, "target_code_execution": False,
        "publication_enabled": False,
        "preflight_boundary": "static_caps_before_dispatch_stage_local_request_checks_before_each_call",
    }
    expected = common
    if limits.get("schema") in {"model-only-shadow-audit-limits.v2", "model-only-shadow-audit-limits.v3"}:
        expected = {
            **common,
            "schema": limits["schema"],
            "max_request_bytes_per_call": (
                96_000 if limits["schema"] == "model-only-shadow-audit-limits.v2" else 120_000
            ),
            "preflight_boundary": (
                "exact_source_task_requests_admitted_before_writer_dispatch_then_stage_local_checks"
            ),
        }
    if limits != expected:
        raise ValueError("audit_limits_contract_mismatch")
    return {
        "max_input_bytes_per_task": expected["max_request_bytes_per_call"],
        "max_output_bytes_per_task": expected["max_response_bytes_per_call"],
        "max_output_tokens": expected["max_output_tokens_per_llm_call"],
        "deadline_seconds": expected["deadline_seconds_per_call"],
        "max_provider_calls": expected["max_provider_calls"],
        "max_retries": expected["max_retries"],
        "total_provider_deadline_seconds": expected["total_provider_deadline_seconds"],
    }


def _plan_budget(plan: dict[str, Any]) -> dict[str, int]:
    budget = plan.get("budget")
    required = (
        "audit_max_deadline_seconds_per_call", "audit_max_input_bytes_per_call",
        "audit_max_output_tokens_per_llm_call", "audit_max_provider_calls",
        "audit_max_response_bytes_per_call", "audit_max_retries",
        "total_provider_deadline_seconds_max", "writer_deadline_seconds",
    )
    if not isinstance(budget, dict) or any(
        type(budget.get(key)) is not int or budget[key] < 0 for key in required
    ):
        raise ValueError("writer_plan_budget_invalid")
    return {key: budget[key] for key in required}


def _validate_plan_budget(plan_budget: dict[str, int], limits: dict[str, Any]) -> None:
    """Refuse audit limits that exceed the selected plan before provider setup."""
    comparisons = (
        ("deadline_seconds", "audit_max_deadline_seconds_per_call"),
        ("max_input_bytes_per_task", "audit_max_input_bytes_per_call"),
        ("max_output_bytes_per_task", "audit_max_response_bytes_per_call"),
        ("max_output_tokens", "audit_max_output_tokens_per_llm_call"),
        ("max_provider_calls", "audit_max_provider_calls"),
        ("max_retries", "audit_max_retries"),
    )
    if any(limits[actual] > plan_budget[cap] for actual, cap in comparisons):
        raise ValueError("audit_limits_exceed_plan_budget")
    combined_deadline = plan_budget["writer_deadline_seconds"] + limits["total_provider_deadline_seconds"]
    if combined_deadline > plan_budget["total_provider_deadline_seconds_max"]:
        raise ValueError("combined_deadline_exceeds_plan_budget")


def _validate_provider_identity(provider: dict[str, Any], jev: dict[str, Any]) -> None:
    _validate_llm_identity(provider)
    _validate_jev_identity(jev)


def _validate_llm_identity(provider: dict[str, Any]) -> None:
    if (provider.get("kind") != "openai_compatible"
            or (provider.get("base_url"), provider.get("model")) != EXPECTED_LLM
            or provider.get("api_key_env") != "LLM_API_KEY"):
        raise ValueError("llm_identity_mismatch")


def _validate_jev_identity(jev: dict[str, Any]) -> None:
    if (jev.get("kind") != "typesafe"
            or (jev.get("endpoint"), jev.get("model")) != EXPECTED_JEV
            or jev.get("api_key_env") != "JEV_API_KEY"):
        raise ValueError("jev_identity_mismatch")


def _load_current_source_plan(path: Path) -> dict[str, Any]:
    """Validate the closed PR-457 request pins against the installed runtime."""
    try:
        from pr_review_harness.current_source_capture import (
            installed_module_inventory,
            validate_plan,
        )
        module_path = Path(__import__("pr_review_harness.current_source_capture", fromlist=["__file__"]).__file__).resolve()
        if module_path.is_relative_to((ROOT / "src").resolve()):
            raise ValueError("installed_runtime_required")
        plan_path = path.absolute()
        if plan_path.name != "pr457-current-source-plan.json":
            raise ValueError("current_source_plan_path_invalid")
        if os.environ.get("GITHUB_ACTIONS", "").lower() == "true":
            runner_temp = Path(os.environ.get("RUNNER_TEMP", "")).resolve(strict=True)
            expected = runner_temp / "pr457-current-source-plan.json"
            if (os.environ.get("GITHUB_REPOSITORY") != "groktopus/codereview"
                    or os.environ.get("GITHUB_EVENT_NAME") != "workflow_dispatch"
                    or os.environ.get("GITHUB_REF") != "refs/heads/main"
                    or os.environ.get("GITHUB_WORKFLOW_REF") != (
                        "groktopus/codereview/.github/workflows/pr457-role-accounted-shadow.yml@refs/heads/main"
                    )
                    or plan_path != expected):
                raise ValueError("current_source_workflow_context_invalid")
        receipt_path = plan_path.with_name("pr457-current-source-receipt.json")
        plan, _plan_raw = _read_json(plan_path, 256_000)
        receipt, _receipt_raw = _read_json(receipt_path, 64_000)
        _writer_pins, audit_snapshot = validate_plan(
            plan, receipt, source_sha=os.environ.get("GITHUB_SHA", ""),
            module_inventory=installed_module_inventory(),
        )
        return audit_snapshot
    except (OSError, TypeError, ValueError, RecursionError):
        raise ValueError("current_source_plan_invalid") from None


def _check_source_request_pin(snapshot: dict[str, Any] | None, packet: dict[str, Any], request: bytes) -> None:
    if snapshot is None:
        return
    if snapshot.get("source_audit_serializer") != SOURCE_AUDIT_SERIALIZER_CANONICAL:
        raise ProviderError("current_source_serializer_mismatch")
    task = packet.get("source_task")
    task_id = task.get("task_id") if isinstance(task, dict) else None
    pins = snapshot.get("source_audit_requests")
    pin = pins.get(task_id) if isinstance(pins, dict) and isinstance(task_id, str) else None
    digest = hashlib.sha256(request).hexdigest()
    if (not isinstance(pin, dict) or pin.get("task_id") != task_id
            or pin.get("input_bytes") != len(request) or pin.get("input_sha256") != digest
            or len(request) > snapshot.get("audit_max_input_bytes_per_call", 0)):
        raise ProviderError("current_source_request_pin_mismatch")


def _predispatch_failure(receipt_path: Path, case_id: str, stage: str, code: str) -> PreDispatchFailure:
    # Deliberately omit exception text, packet content, candidate IDs, and paths.
    receipt = {
        "schema": "model-only-shadow-audit-predispatch-failure.v1",
        "case_id": case_id,
        "terminal_state": "failed_before_dispatch",
        "failure_stage": stage,
        "failure_code": code,
        "audit_provider_calls": 0,
    }
    _write_receipt(receipt_path, receipt)
    return PreDispatchFailure(stage, code)


def _dispatch_accounting(roles: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Separate captured request attempts from evidence of an HTTP attempt."""
    output: dict[str, dict[str, Any]] = {}
    for role in AUDIT_ROLES:
        run = roles.get(role, {})
        calls = run.get("calls", []) if isinstance(run, dict) else []
        if not isinstance(calls, list):
            calls = []
        states = [call.get("dispatch_state") if isinstance(call, dict) else None for call in calls]
        hashes = [call.get("request_sha256") for call in calls if isinstance(call, dict)
                  and isinstance(call.get("request_sha256"), str)]
        counts = {state: sum(value == state for value in states) for state in DISPATCH_STATES}
        output[role] = {
            "attempted": len(calls),
            "dispatched": counts["http_attempted"],
            "guard_rejected": counts["guard_rejected"],
            "post_guard_pretransport": counts["post_guard_pretransport"],
            "unknown": counts["unknown"],
            "request_sha256": hashes[0] if len(hashes) == 1 else None,
        }
    return output


def _task_order(plan_path: Path, packets: list[tuple[str, Path, dict[str, Any], bytes]],
                manifest: dict[str, Any] | None = None, *,
                include_budget: bool = False) -> list[tuple[str, Path, dict[str, Any], bytes]] | tuple[list[tuple[str, Path, dict[str, Any], bytes]], dict[str, int]]:
    case_id, policy = case_for_plan_path(plan_path, ROOT)
    plan, plan_bytes = _read_json(plan_path, 256_000)
    bound_case_id, _ = validate_plan_binding(plan, plan_bytes)
    if bound_case_id != case_id:
        raise ValueError("writer_plan_binding_invalid")
    case = plan.get("case")
    requests = plan.get("writer_requests")
    if plan.get("schema") != "model-only-shadow-live-writer-plan.v2" or not isinstance(case, dict) or not isinstance(requests, list):
        raise ValueError("writer_plan_invalid")
    plan_case_id = case.get("case_id")
    packet_case_ids = [row[2].get("case_id") for row in packets]
    if (not isinstance(plan_case_id, str) or not plan_case_id
            or any(not isinstance(value, str) or not value for value in packet_case_ids)):
        raise ValueError("writer_plan_case_invalid")
    if set(packet_case_ids) != {plan_case_id}:
        raise ValueError("writer_plan_case_mismatch")
    prepare_contract = plan.get("prepare_contract")
    if (not isinstance(prepare_contract, dict)
            or prepare_contract.get("profile_path") != policy["profile_path"]):
        raise ValueError("writer_plan_profile_path_invalid")
    profile, profile_raw = _read_json(ROOT / policy["profile_path"], 256_000)
    if hashlib.sha256(profile_raw).hexdigest() != policy["profile_sha256"]:
        raise ValueError("profile_file_hash_mismatch")
    canonical_profile = json.dumps(
        profile, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("utf-8")
    snapshot_profile_hash = hashlib.sha256(canonical_profile).hexdigest()
    expected_identity = {
        "case_id": case.get("case_id"), "snapshot_id": case.get("snapshot_id"),
        "snapshot_hash": case.get("snapshot_sha256"), "base_sha": case.get("base_sha"),
        "head_sha": case.get("head_sha"), "profile_version": case.get("profile_version"),
        "profile_hash": snapshot_profile_hash,
    }
    if manifest is not None and any(manifest.get(key) != value for key, value in {
        "snapshot_id": expected_identity["snapshot_id"],
        "snapshot_hash": expected_identity["snapshot_hash"],
    }.items()):
        raise ValueError("capture_plan_identity_mismatch")
    task_ids = [item.get("task_id") for item in requests if isinstance(item, dict)]
    if (len(task_ids) != len(requests) or not task_ids
            or any(not isinstance(task_id, str) or not task_id for task_id in task_ids)
            or len(task_ids) != len(set(task_ids))):
        raise ValueError("writer_plan_tasks_invalid")
    rank = {task_id: index for index, task_id in enumerate(task_ids)}
    packet_task_ids: set[str] = set()
    for _candidate_id, _path, packet, _raw in packets:
        task = packet.get("source_task")
        task_id = task.get("task_id") if isinstance(task, dict) else None
        if not isinstance(task_id, str) or not task_id or task_id not in rank:
            raise ValueError("packet_task_not_in_plan")
        packet_task_ids.add(task_id)
        snapshot = packet.get("snapshot")
        if not isinstance(snapshot, dict) or any(snapshot.get(key) != value for key, value in {
            "snapshot_id": expected_identity["snapshot_id"], "snapshot_hash": expected_identity["snapshot_hash"],
            "base_sha": expected_identity["base_sha"], "head_sha": expected_identity["head_sha"],
            "profile_version": expected_identity["profile_version"], "profile_hash": expected_identity["profile_hash"],
        }.items()):
            raise ValueError("packet_plan_identity_mismatch")
    if packet_task_ids != set(task_ids):
        raise ValueError("case_packet_task_coverage_mismatch")
    ordered = sorted(packets, key=lambda row: (
        rank[row[2]["source_task"]["task_id"]], hashlib.sha256(row[3]).hexdigest()
    ))
    if include_budget:
        return ordered, _plan_budget(plan)
    return ordered


def run(capture_root: Path, provider_config_path: Path, jev_config_path: Path | None,
        output_root: Path, receipt_path: Path, plan_path: Path = DEFAULT_PLAN,
        limits_path: Path = DEFAULT_LIMITS, *, source_only_no_candidate: bool = False,
        selection_receipt_path: Path | None = None,
        source_dispatch_receipt_path: Path | None = None,
        current_source_plan_path: Path | None = None) -> dict[str, Any]:
    # Do not perform any validation that might later dispatch providers when
    # the caller's final receipt path is already occupied.  _write_receipt
    # also uses an exclusive create so a later collision cannot overwrite it.
    if receipt_path.exists() or receipt_path.is_symlink():
        raise ValueError("receipt_already_exists")
    try:
        selected_case_id, _selected_policy = case_for_plan_path(plan_path, ROOT)
    except ValueError:
        raise ValueError("audit_plan_path_invalid") from None
    try:
        manifest, manifest_raw, packets = _packet_candidates(capture_root)
    except (OSError, ValueError, RecursionError):
        raise _predispatch_failure(receipt_path, selected_case_id, "capture_validation", "capture_invalid") from None
    try:
        packets, plan_budget = _task_order(plan_path, packets, manifest, include_budget=True)
    except (OSError, TypeError, ValueError, RecursionError):
        raise _predispatch_failure(receipt_path, selected_case_id, "plan_binding", "plan_binding_invalid") from None
    current_source_snapshot = None
    if current_source_plan_path is not None:
        if selected_case_id != "PR-457":
            raise _predispatch_failure(receipt_path, selected_case_id, "plan_binding", "plan_binding_invalid")
        try:
            current_source_snapshot = _load_current_source_plan(current_source_plan_path)
        except (OSError, TypeError, ValueError, RecursionError):
            raise _predispatch_failure(receipt_path, selected_case_id, "plan_binding", "plan_binding_invalid") from None
    try:
        limits = _load_limits(limits_path)
    except (OSError, ValueError, RecursionError):
        raise _predispatch_failure(receipt_path, selected_case_id, "limits_validation", "limits_invalid") from None
    try:
        _validate_plan_budget(plan_budget, limits)
    except (KeyError, TypeError, ValueError):
        raise _predispatch_failure(receipt_path, selected_case_id, "budget_validation", "audit_budget_exceeded") from None
    capture_hash = hashlib.sha256(manifest_raw).hexdigest()
    candidates = [row for row in packets if row[0]]
    current_source_no_candidate = current_source_snapshot is not None and not candidates
    source_only_dispatch = source_only_no_candidate or current_source_no_candidate
    selected = _select_packet(packets)
    if selected is None:
        if not current_source_no_candidate and not source_only_no_candidate:
            _packet_id, _packet_path, packet, packet_raw = packets[0]
            zero_counts = {role: 0 for role in AUDIT_ROLES}
            receipt = {
                "schema": "model-only-shadow-audit-receipt.v1",
                "case_id": packet["case_id"], "terminal_state": "incomplete",
                "reason": "no_writer_candidate", "audit_provider_calls": 0,
                "candidate_packet_count": 0, "selected_packet_sha256": hashlib.sha256(packet_raw).hexdigest(),
                "capture_manifest_sha256": capture_hash,
                "roles": {role: "not_run" for role in AUDIT_ROLES},
                "role_call_counts": dict(zero_counts),
                "role_dispatched_call_counts": dict(zero_counts),
                "role_guard_rejected_counts": dict(zero_counts),
                "role_post_guard_pretransport_counts": dict(zero_counts),
                "role_unknown_dispatch_counts": dict(zero_counts),
                "role_request_sha256": {role: None for role in AUDIT_ROLES},
            }
            _write_receipt(receipt_path, receipt)
            return receipt
        if selected_case_id == "PR-457" and current_source_no_candidate:
            if selection_receipt_path is not None:
                raise _predispatch_failure(receipt_path, selected_case_id, "capture_validation", "capture_invalid")
            selected = packets[0]
            task = selected[2].get("source_task")
            task_id = task.get("task_id") if isinstance(task, dict) else None
            if not isinstance(task_id, str) or task_id not in current_source_snapshot["source_audit_requests"]:
                raise _predispatch_failure(receipt_path, selected_case_id, "plan_binding", "plan_binding_invalid")
        elif selected_case_id != "PR-464":
            raise _predispatch_failure(receipt_path, selected_case_id, "plan_binding", "plan_binding_invalid")
        elif selection_receipt_path is None:
            raise _predispatch_failure(receipt_path, selected_case_id, "capture_validation", "capture_invalid")
        else:
            try:
                selection, _ = _read_json(selection_receipt_path, 16_000)
                plan, plan_raw = _read_json(plan_path, 256_000)
                selection_fields = {
                    "schema", "case_id", "packet_path", "selected_packet_sha256", "capture_manifest_sha256",
                    "plan_sha256", "snapshot_sha256", "selected_task_sha256", "writer_calls",
                    "audit_provider_calls", "publication_enabled", "target_code_execution",
                }
                if (set(selection) != selection_fields
                        or selection.get("schema") != "frozen-pr464-no-candidate-selection.v1"
                        or selection.get("case_id") != "PR-464"
                        or selection.get("writer_calls") != 10 or selection.get("audit_provider_calls") != 0
                        or selection.get("publication_enabled") is not False
                        or selection.get("target_code_execution") is not False
                        or selection.get("capture_manifest_sha256") != capture_hash
                        or selection.get("plan_sha256") != hashlib.sha256(plan_raw).hexdigest()
                        or selection.get("snapshot_sha256") != plan.get("case", {}).get("snapshot_sha256")):
                    raise ValueError("selection_receipt_invalid")
                selected_path = selection.get("packet_path")
                if (not isinstance(selected_path, str) or not re.fullmatch(r"case-packets/[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.json", selected_path)
                        or not isinstance(selection.get("selected_packet_sha256"), str)
                        or not re.fullmatch(r"[0-9a-f]{64}", selection["selected_packet_sha256"])
                        or not isinstance(selection.get("selected_task_sha256"), str)
                        or not re.fullmatch(r"[0-9a-f]{64}", selection["selected_task_sha256"])):
                    raise ValueError("selection_receipt_invalid")
                matches = [row for row in packets if row[1].relative_to(capture_root).as_posix() == selected_path]
                if (len(matches) != 1 or matches[0][0] or hashlib.sha256(matches[0][3]).hexdigest() != selection["selected_packet_sha256"]
                        or hashlib.sha256(matches[0][2]["source_task"]["task_id"].encode("utf-8")).hexdigest()
                        != selection["selected_task_sha256"]):
                    raise ValueError("selection_receipt_invalid")
                selected = matches[0]
            except (OSError, KeyError, TypeError, ValueError, RecursionError):
                raise _predispatch_failure(receipt_path, selected_case_id, "capture_validation", "capture_invalid") from None
        # The frozen PR464 path runs one source-only audit here. Its no-candidate
        # result is sealed locally, then run_sealed_source_record_jev.py may make
        # one distinct Jev call. The normal three-role path remains unchanged.
    elif source_only_no_candidate:
        raise _predispatch_failure(receipt_path, selected_case_id, "capture_validation", "capture_invalid")

    # Plan task order is trusted and fixed; packet digest breaks ties within one task.
    candidate_id, _packet_path, packet, packet_raw = selected
    if source_only_dispatch and source_dispatch_receipt_path is not None:
        source_dispatch_accounting.write(source_dispatch_receipt_path, selected_case_id, "unknown", create=True)
    try:
        if output_root.exists() or output_root.is_symlink():
            raise ValueError("private_output_exists")
        source_config, _ = _read_json(provider_config_path, 16_000)
        _validate_llm_identity(source_config)
        jev_config: dict[str, Any] = {}
        if not current_source_no_candidate:
            if jev_config_path is None:
                raise ValueError("jev_config_required")
            jev_config, _ = _read_json(jev_config_path, 16_000)
            _validate_jev_identity(jev_config)
        source_config["timeout_seconds"] = limits["deadline_seconds"]
        source_config["max_request_bytes"] = limits["max_input_bytes_per_task"]
        source_config["max_response_bytes"] = limits["max_output_bytes_per_task"]
        source_config["max_output_tokens"] = limits["max_output_tokens"]
        claim_config = dict(source_config)
        source_provider = OpenAIProvider(source_config)
        if current_source_no_candidate:
            claim_provider = source_provider

            def jev_transport(*_args):
                raise ProviderError("jev_not_applicable")
        else:
            claim_provider = OpenAIProvider(claim_config)
            jev_transport = ClaimTransport.from_decision_config(jev_config)
            jev_transport.timeout_seconds = limits["deadline_seconds"]
            jev_transport.max_request_bytes = limits["max_input_bytes_per_task"]
            jev_transport.max_response_bytes = limits["max_output_bytes_per_task"]
        dispatch_guard = AuditDispatchGuard(limits)
    except (OSError, ValueError, ProviderError, RecursionError):
        if source_only_dispatch and source_dispatch_receipt_path is not None:
            source_dispatch_accounting.write(source_dispatch_receipt_path, selected_case_id, "0")
        raise _predispatch_failure(receipt_path, selected_case_id, "provider_setup", "provider_setup_invalid") from None

    guard_passed_roles: set[str] = set()

    def before_dispatch(role: str, request_bytes: bytes) -> None:
        dispatch_guard.check(role, request_bytes)
        if role == "source_auditor":
            _check_source_request_pin(current_source_snapshot, packet, request_bytes)
        guard_passed_roles.add(role)

    try:
        result = run_shadow_audit(
            packet, source_provider=source_provider, jev_transport=jev_transport,
            claim_provider=claim_provider, limits=limits, output_dir=output_root,
            before_dispatch=before_dispatch,
            source_request_serializer=(
                current_source_snapshot["source_audit_serializer"]
                if current_source_snapshot is not None
                else SOURCE_AUDIT_SERIALIZER_LEGACY
            ),
            on_source_http_attempt=(
                lambda: source_dispatch_accounting.write(source_dispatch_receipt_path, selected_case_id, "1")
                if source_only_dispatch and source_dispatch_receipt_path is not None else None
            ),
        )
    except (OSError, ValueError, ProviderError, RecursionError):
        # This records budget reservation only; HTTP-attempt evidence is
        # collected from the provider transports.
        if not guard_passed_roles:
            if source_only_dispatch and source_dispatch_receipt_path is not None:
                source_dispatch_accounting.write(source_dispatch_receipt_path, selected_case_id, "0")
            raise _predispatch_failure(
                receipt_path, selected_case_id, "audit_validation", "audit_input_invalid"
            ) from None
        raise
    audit_manifest = result["manifest"]
    roles = audit_manifest.get("roles", {})
    terminal = audit_manifest.get("terminal_state", "incomplete")
    if source_only_dispatch and not candidates:
        # The private audit manifest keeps the source stage's raw terminal
        # state (for example, missing_writer_candidate or source_audit_failed).
        # The hash-only public receipt uses the zero-candidate contract, whose
        # terminal state is always incomplete regardless of source outcome.
        terminal = "incomplete"
    if source_only_dispatch and source_dispatch_receipt_path is not None:
        source_dispatch_accounting.write(source_dispatch_receipt_path, selected_case_id,
                                         source_dispatch_accounting.classify_source_call(roles))
    dispatch = _dispatch_accounting(roles)
    receipt = {
        "schema": "model-only-shadow-audit-receipt.v1",
        "case_id": packet["case_id"], "terminal_state": terminal,
        "reason": ("no_writer_candidate" if not candidates else "one_candidate_selected"
                   if len(candidates) == 1 else "bounded_single_candidate_selection"),
        "audit_provider_calls": sum(row["dispatched"] for row in dispatch.values()),
        "candidate_packet_count": len(candidates),
        "selected_packet_sha256": hashlib.sha256(packet_raw).hexdigest(),
        "capture_manifest_sha256": capture_hash,
        "roles": {role: roles.get(role, {}).get("status", "not_run") for role in AUDIT_ROLES},
        "role_call_counts": {role: row["attempted"] for role, row in dispatch.items()},
        "role_dispatched_call_counts": {role: row["dispatched"] for role, row in dispatch.items()},
        "role_guard_rejected_counts": {role: row["guard_rejected"] for role, row in dispatch.items()},
        "role_post_guard_pretransport_counts": {
            role: row["post_guard_pretransport"] for role, row in dispatch.items()
        },
        "role_unknown_dispatch_counts": {role: row["unknown"] for role, row in dispatch.items()},
        "role_request_sha256": {role: row["request_sha256"] for role, row in dispatch.items()},
    }
    if candidates:
        receipt["selected_candidate_sha256"] = hashlib.sha256(candidate_id.encode("utf-8")).hexdigest()
        receipt["shadow_manifest_sha256"] = hashlib.sha256(
            (output_root / "shadow-audit-manifest.json").read_bytes()
        ).hexdigest()
    _write_receipt(receipt_path, receipt)
    return receipt


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture-root", type=Path, required=True)
    parser.add_argument("--provider-config", type=Path, required=True)
    parser.add_argument("--jev-config", type=Path)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--plan", type=Path, default=DEFAULT_PLAN)
    parser.add_argument("--limits", type=Path, default=DEFAULT_LIMITS)
    parser.add_argument("--source-only-no-candidate", action="store_true",
                        help="for frozen PR464 no-candidate captures, run only one source auditor before sealed Jev")
    parser.add_argument("--selection-receipt", type=Path,
                        help="hash-only frozen PR464 packet selector receipt required with source-only mode")
    parser.add_argument("--current-source-plan", type=Path,
                        help="closed PR457 current-source plan in RUNNER_TEMP; required for its bounded audit path")
    parser.add_argument("--source-dispatch-receipt", type=Path,
                        help="private durable source HTTP-attempt accounting receipt")
    parser.add_argument("--live", action="store_true", help="dispatch at most three bounded provider calls")
    args = parser.parse_args(argv)
    if not args.live:
        parser.error("provider dispatch requires --live after reviewing private capture and limits")
    try:
        receipt = run(args.capture_root, args.provider_config, args.jev_config, args.output_root,
                      args.receipt, args.plan, args.limits,
                      source_only_no_candidate=args.source_only_no_candidate,
                      selection_receipt_path=args.selection_receipt,
                      source_dispatch_receipt_path=args.source_dispatch_receipt,
                      current_source_plan_path=args.current_source_plan)
    except (OSError, ValueError, ProviderError) as exc:
        code = getattr(exc, "code", None)
        if not isinstance(code, str) or not code.isidentifier():
            code = "shadow_audit_failed"
        print(json.dumps({"ok": False, "error_code": code}, separators=(",", ":")), file=sys.stderr)
        return 2
    print(json.dumps({"ok": True, "terminal_state": receipt["terminal_state"],
                      "audit_provider_calls": receipt["audit_provider_calls"]},
                     sort_keys=True, separators=(",", ":")))
    return 0 if receipt["terminal_state"] in {"completed", "claim_audit_abstained", "incomplete"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
