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
import stat
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from pr_review_harness.claim_transport import ClaimTransport  # noqa: E402
from pr_review_harness.providers import OpenAIProvider, ProviderError  # noqa: E402
from pr_review_harness.shadow_audit import MAX_CASE_BYTES, run_shadow_audit  # noqa: E402

MAX_CAPTURE_MANIFEST_BYTES = 256_000
MAX_RECEIPT_BYTES = 64_000
DEFAULT_PLAN = ROOT / "experiments/model-only-shadow-live-pr464-plan-v1.json"
DEFAULT_LIMITS = ROOT / "experiments/model-only-shadow-audit-limits-v1.json"
EXPECTED_LLM = ("https://inference-api.nousresearch.com/v1", "openai/gpt-6-luna")
EXPECTED_JEV = ("https://api.typesafe.ai/v1/systemone", "jev-latest")


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
    packet_dir = root / "case-packets"
    if packet_dir.is_symlink() or not packet_dir.is_dir() or stat.S_IMODE(packet_dir.stat().st_mode) != 0o700:
        raise ValueError("case_packet_directory_invalid")
    rows = []
    for path in sorted(packet_dir.glob("*.json")):
        if len(rows) >= 128:
            raise ValueError("case_packet_count_exceeds_limit")
        packet, raw = _read_json(path, MAX_CASE_BYTES)
        if packet.get("contract_version") != "model-only-shadow-case.v1":
            raise ValueError("case_packet_contract_invalid")
        if packet.get("case_id") != manifest.get("case_id"):
            raise ValueError("case_packet_identity_mismatch")
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
def _task_order(plan_path: Path, packets: list[tuple[str, Path, dict[str, Any], bytes]],
                manifest: dict[str, Any] | None = None) -> list[tuple[str, Path, dict[str, Any], bytes]]:
    plan, _ = _read_json(plan_path, 256_000)
    case = plan.get("case")
    requests = plan.get("writer_requests")
    if plan.get("schema") != "model-only-shadow-live-writer-plan.v1" or not isinstance(case, dict) or not isinstance(requests, list):
        raise ValueError("writer_plan_invalid")
    case_ids = {row[2].get("case_id") for row in packets}
    if case_ids != {case.get("case_id")}:
        raise ValueError("writer_plan_case_mismatch")
    expected_identity = {
        "case_id": case.get("case_id"), "snapshot_id": case.get("snapshot_id"),
        "snapshot_hash": case.get("snapshot_sha256"), "base_sha": case.get("base_sha"),
        "head_sha": case.get("head_sha"), "profile_version": case.get("profile_version"),
        "profile_hash": case.get("profile_file_sha256"),
    }
    if manifest is not None and any(manifest.get(key) != value for key, value in {
        "case_id": expected_identity["case_id"], "snapshot_id": expected_identity["snapshot_id"],
        "snapshot_hash": expected_identity["snapshot_hash"],
    }.items()):
        raise ValueError("capture_plan_identity_mismatch")
    task_ids = [item.get("task_id") for item in requests if isinstance(item, dict)]
    if len(task_ids) != len(requests) or len(task_ids) != len(set(task_ids)) or not task_ids:
        raise ValueError("writer_plan_tasks_invalid")
    rank = {task_id: index for index, task_id in enumerate(task_ids)}
    for _candidate_id, _path, packet, _raw in packets:
        task = packet.get("source_task")
        task_id = task.get("task_id") if isinstance(task, dict) else None
        if task_id not in rank:
            raise ValueError("packet_task_not_in_plan")
        snapshot = packet.get("snapshot")
        if not isinstance(snapshot, dict) or any(snapshot.get(key) != value for key, value in {
            "snapshot_id": expected_identity["snapshot_id"], "snapshot_hash": expected_identity["snapshot_hash"],
            "base_sha": expected_identity["base_sha"], "head_sha": expected_identity["head_sha"],
            "profile_version": expected_identity["profile_version"], "profile_hash": expected_identity["profile_hash"],
        }.items()):
            raise ValueError("packet_plan_identity_mismatch")
    return sorted(packets, key=lambda row: (
        rank[row[2]["source_task"]["task_id"]], hashlib.sha256(row[3]).hexdigest()
    ))


def run(capture_root: Path, provider_config_path: Path, jev_config_path: Path,
        output_root: Path, receipt_path: Path, plan_path: Path = DEFAULT_PLAN,
        limits_path: Path = DEFAULT_LIMITS) -> dict[str, Any]:
    manifest, manifest_raw, packets = _packet_candidates(capture_root)
    packets = _task_order(plan_path, packets, manifest)
    limits = _load_limits(limits_path)
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
        }
        _write_receipt(receipt_path, receipt)
        return receipt

    # Plan task order is trusted and fixed; packet digest breaks ties within one task.
    candidate_id, _packet_path, packet, packet_raw = selected
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
    jev_config["timeout_seconds"] = limits["deadline_seconds"]
    jev_config["max_response_bytes"] = limits["max_output_bytes_per_task"]
    jev_transport = ClaimTransport.from_decision_config(jev_config)
    result = run_shadow_audit(
        packet, source_provider=source_provider, jev_transport=jev_transport,
        claim_provider=claim_provider, limits=limits, output_dir=output_root,
    )
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
