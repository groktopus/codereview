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
sys.path.insert(0, str(ROOT / "src"))

from pr_review_harness.claim_transport import ClaimTransport  # noqa: E402
from pr_review_harness.providers import OpenAIProvider, ProviderError  # noqa: E402
from pr_review_harness.shadow_audit import MAX_CASE_BYTES, run_shadow_audit  # noqa: E402
from pr_review_harness.shadow_preflight import AuditDispatchGuard  # noqa: E402

MAX_CAPTURE_MANIFEST_BYTES = 256_000
MAX_RECEIPT_BYTES = 64_000
DEFAULT_PLAN = ROOT / "experiments/model-only-shadow-live-pr464-plan-v1.json"
DEFAULT_LIMITS = ROOT / "experiments/model-only-shadow-audit-limits-v1.json"
PROFILE_RELATIVE_PATH = "docs/real-case-trial-v1/profiles/PR-464.json"
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
    expected = {
        "schema": "model-only-shadow-audit-limits.v1", "max_packets": 1,
        "max_provider_calls": 3, "max_retries": 0,
        "max_request_bytes_per_call": 64_000, "max_response_bytes_per_call": 64_000,
        "max_output_tokens_per_llm_call": 1_800, "deadline_seconds_per_call": 90,
        "total_provider_deadline_seconds": 270, "target_code_execution": False,
        "publication_enabled": False,
        "preflight_boundary": "static_caps_before_dispatch_stage_local_request_checks_before_each_call",
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


def _validate_provider_identity(provider: dict[str, Any], jev: dict[str, Any]) -> None:
    if (provider.get("kind") != "openai_compatible"
            or (provider.get("base_url"), provider.get("model")) != EXPECTED_LLM
            or provider.get("api_key_env") != "LLM_API_KEY"):
        raise ValueError("llm_identity_mismatch")
    if (jev.get("kind") != "typesafe"
            or (jev.get("endpoint"), jev.get("model")) != EXPECTED_JEV
            or jev.get("api_key_env") != "JEV_API_KEY"):
        raise ValueError("jev_identity_mismatch")


def _predispatch_failure(receipt_path: Path, stage: str, code: str) -> PreDispatchFailure:
    # Deliberately omit exception text, packet content, candidate IDs, and paths.
    receipt = {
        "schema": "model-only-shadow-audit-predispatch-failure.v1",
        "case_id": "PR-464",
        "terminal_state": "failed_before_dispatch",
        "failure_stage": stage,
        "failure_code": code,
        "audit_provider_calls": 0,
    }
    _write_receipt(receipt_path, receipt)
    return PreDispatchFailure(stage, code)


def _task_order(plan_path: Path, packets: list[tuple[str, Path, dict[str, Any], bytes]],
                manifest: dict[str, Any] | None = None) -> list[tuple[str, Path, dict[str, Any], bytes]]:
    plan, _ = _read_json(plan_path, 256_000)
    case = plan.get("case")
    requests = plan.get("writer_requests")
    if plan.get("schema") != "model-only-shadow-live-writer-plan.v1" or not isinstance(case, dict) or not isinstance(requests, list):
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
            or prepare_contract.get("profile_path") != PROFILE_RELATIVE_PATH):
        raise ValueError("writer_plan_profile_path_invalid")
    profile, profile_raw = _read_json(ROOT / PROFILE_RELATIVE_PATH, 256_000)
    if hashlib.sha256(profile_raw).hexdigest() != case.get("profile_file_sha256"):
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
    return sorted(packets, key=lambda row: (
        rank[row[2]["source_task"]["task_id"]], hashlib.sha256(row[3]).hexdigest()
    ))


def run(capture_root: Path, provider_config_path: Path, jev_config_path: Path,
        output_root: Path, receipt_path: Path, plan_path: Path = DEFAULT_PLAN,
        limits_path: Path = DEFAULT_LIMITS) -> dict[str, Any]:
    try:
        manifest, manifest_raw, packets = _packet_candidates(capture_root)
    except (OSError, ValueError, RecursionError):
        raise _predispatch_failure(receipt_path, "capture_validation", "capture_invalid") from None
    try:
        packets = _task_order(plan_path, packets, manifest)
    except (OSError, TypeError, ValueError, RecursionError):
        raise _predispatch_failure(receipt_path, "plan_binding", "plan_binding_invalid") from None
    try:
        limits = _load_limits(limits_path)
    except (OSError, ValueError, RecursionError):
        raise _predispatch_failure(receipt_path, "limits_validation", "limits_invalid") from None
    capture_hash = hashlib.sha256(manifest_raw).hexdigest()
    candidates = [row for row in packets if row[0]]
    selected = _select_packet(packets)
    if selected is None:
        _packet_id, _packet_path, packet, packet_raw = packets[0]
        receipt = {
            "schema": "model-only-shadow-audit-receipt.v1",
            "case_id": packet["case_id"], "terminal_state": "incomplete",
            "reason": "no_writer_candidate", "audit_provider_calls": 0,
            "candidate_packet_count": 0, "selected_packet_sha256": hashlib.sha256(packet_raw).hexdigest(),
            "capture_manifest_sha256": capture_hash,
            "roles": {role: "not_run" for role in ("source_auditor", "jev", "claim_auditor")},
            "role_call_counts": {role: 0 for role in ("source_auditor", "jev", "claim_auditor")},
        }
        _write_receipt(receipt_path, receipt)
        return receipt

    # Plan task order is trusted and fixed; packet digest breaks ties within one task.
    candidate_id, _packet_path, packet, packet_raw = selected
    try:
        if output_root.exists() or output_root.is_symlink():
            raise ValueError("private_output_exists")
        source_config, _ = _read_json(provider_config_path, 16_000)
        jev_config, _ = _read_json(jev_config_path, 16_000)
        _validate_provider_identity(source_config, jev_config)
        source_config["timeout_seconds"] = limits["deadline_seconds"]
        source_config["max_request_bytes"] = limits["max_input_bytes_per_task"]
        source_config["max_response_bytes"] = limits["max_output_bytes_per_task"]
        source_config["max_output_tokens"] = limits["max_output_tokens"]
        claim_config = dict(source_config)
        source_provider = OpenAIProvider(source_config)
        claim_provider = OpenAIProvider(claim_config)
        jev_transport = ClaimTransport.from_decision_config(jev_config)
        jev_transport.timeout_seconds = limits["deadline_seconds"]
        jev_transport.max_request_bytes = limits["max_input_bytes_per_task"]
        jev_transport.max_response_bytes = limits["max_output_bytes_per_task"]
        dispatch_guard = AuditDispatchGuard(limits)
    except (OSError, ValueError, ProviderError, RecursionError):
        raise _predispatch_failure(receipt_path, "provider_setup", "provider_setup_invalid") from None

    dispatched_roles: set[str] = set()

    def before_dispatch(role: str, request_bytes: bytes) -> None:
        dispatch_guard.check(role, request_bytes)
        dispatched_roles.add(role)

    try:
        result = run_shadow_audit(
            packet, source_provider=source_provider, jev_transport=jev_transport,
            claim_provider=claim_provider, limits=limits, output_dir=output_root,
            before_dispatch=before_dispatch,
        )
    except (OSError, ValueError, ProviderError, RecursionError):
        # This hook records a role only after deterministic checks pass,
        # immediately before control returns to the provider transport.
        if not dispatched_roles:
            raise _predispatch_failure(
                receipt_path, "audit_validation", "audit_input_invalid"
            ) from None
        raise
    audit_manifest = result["manifest"]
    roles = audit_manifest.get("roles", {})
    terminal = audit_manifest.get("terminal_state", "incomplete")
    receipt = {
        "schema": "model-only-shadow-audit-receipt.v1",
        "case_id": packet["case_id"], "terminal_state": terminal,
        "reason": "one_candidate_selected" if len(candidates) == 1 else "bounded_single_candidate_selection",
        "audit_provider_calls": sum(len(roles.get(role, {}).get("calls", [])) for role in
                                     ("source_auditor", "jev", "claim_auditor")
                                     if isinstance(roles.get(role), dict)),
        "candidate_packet_count": len(candidates),
        "selected_candidate_sha256": hashlib.sha256(candidate_id.encode("utf-8")).hexdigest(),
        "selected_packet_sha256": hashlib.sha256(packet_raw).hexdigest(),
        "capture_manifest_sha256": capture_hash,
        "shadow_manifest_sha256": hashlib.sha256(
            (output_root / "shadow-audit-manifest.json").read_bytes()
        ).hexdigest(),
        "roles": {role: roles.get(role, {}).get("status", "not_run") for role in
                  ("source_auditor", "jev", "claim_auditor")},
        "role_call_counts": {role: len(roles.get(role, {}).get("calls", [])) for role in
                              ("source_auditor", "jev", "claim_auditor")
                              if isinstance(roles.get(role), dict)},
    }
    _write_receipt(receipt_path, receipt)
    return receipt


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture-root", type=Path, required=True)
    parser.add_argument("--provider-config", type=Path, required=True)
    parser.add_argument("--jev-config", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--plan", type=Path, default=DEFAULT_PLAN)
    parser.add_argument("--limits", type=Path, default=DEFAULT_LIMITS)
    parser.add_argument("--live", action="store_true", help="dispatch at most three bounded provider calls")
    args = parser.parse_args(argv)
    if not args.live:
        parser.error("provider dispatch requires --live after reviewing private capture and limits")
    try:
        receipt = run(args.capture_root, args.provider_config, args.jev_config, args.output_root,
                      args.receipt, args.plan, args.limits)
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
