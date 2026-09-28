#!/usr/bin/env python3
"""Validate and emit a hash-only allowlisted receipt for shadow preflight."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
from pathlib import Path
from typing import Any

SUMMARY_KEYS = {"cases", "schema", "status"}
CASE_KEYS = {
    "case_id", "checks_sha256", "evidence_index_sha256", "immutable_patch_sha256",
    "primary_calls", "primary_descriptor_sha256", "primary_serialized_input_bytes",
    "profile_sha256", "scope_count", "scope_sha256", "snapshot_hash", "status",
}
MANIFEST_KEYS = {
    "baseline_plan_sha256", "call_cap_per_case", "call_cap_total_selected_cases",
    "candidate_adjudication_followup_summary_and_jev_demand", "case_cleanup_reserve_seconds",
    "case_wall_seconds_including_setup", "cases", "cost", "current_pr_state_checked",
    "elapsed_seconds", "engine_deadline_seconds", "fixed_case_manifest_sha256",
    "frozen_plan_manifest_sha256", "historical_only", "input_contract", "limits_version",
    "matrix_elapsed_seconds", "matrix_finalization_reserve_seconds",
    "matrix_wall_seconds_including_workflow_setup", "max_claim_assessments_per_case",
    "max_input_bytes_per_primary_task", "max_primary_concurrent_scopes", "max_retries_per_task",
    "max_snapshot_context_bytes", "mode", "output_byte_cap_per_case", "planned_scope_obligation_count",
    "primary_output_token_cap_per_call", "primary_request_demand", "primary_response_byte_cap_per_call",
    "provider_calls", "provider_execution_state", "publication_enabled", "runner_revision",
    "runtime_module_proof", "runtime_module_tree_sha256", "runtime_provenance_version",
    "runtime_revision", "runtime_wheel_sha256", "schema", "serialized_artifact_caps",
    "serialized_bytes_per_case_total", "serialized_primary_context_cap_per_case",
    "shared_task_response_reservation_cap_per_call", "status", "target_code_execution",
    "workflow_matrix_started_epoch",
}
MANIFEST_CASE_KEYS = CASE_KEYS | {"primary_request_receipts"}
SHA256 = re.compile(r"^[0-9a-f]{64}$")
SHA40 = re.compile(r"^[0-9a-f]{40}$")


class ReceiptError(ValueError):
    """Input is incomplete or outside the fixed sanitized receipt contract."""


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ReceiptError("duplicate_json_key")
        result[key] = value
    return result


def _read_json(path: Path, limit: int) -> tuple[dict[str, Any], bytes]:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
            raise ReceiptError("input_unavailable")
        fd = os.open(path, flags)
        try:
            opened = os.fstat(fd)
            if (not stat.S_ISREG(opened.st_mode) or opened.st_dev != before.st_dev
                    or opened.st_ino != before.st_ino or opened.st_size > limit):
                raise ReceiptError("input_unavailable")
            chunks = bytearray()
            while len(chunks) <= limit:
                chunk = os.read(fd, min(65536, limit + 1 - len(chunks)))
                if not chunk:
                    break
                chunks.extend(chunk)
            raw = bytes(chunks)
        finally:
            os.close(fd)
    except OSError:
        raise ReceiptError("input_unavailable") from None
    if len(raw) > limit:
        raise ReceiptError("input_exceeds_limit")
    try:
        value = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_pairs,
            parse_constant=lambda _value: (_ for _ in ()).throw(ReceiptError("invalid_constant")),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ReceiptError):
        raise ReceiptError("input_invalid_json") from None
    if not isinstance(value, dict):
        raise ReceiptError("input_invalid_shape")
    return value, raw


def _hash(value: Any, field: str) -> str:
    if not isinstance(value, str) or not SHA256.fullmatch(value):
        raise ReceiptError(field)
    return value


def _case_summary(row: dict[str, Any]) -> dict[str, Any]:
    if set(row) != CASE_KEYS or row.get("case_id") != "PR-464" or row.get("status") != "PREPARED_NOT_RUN":
        raise ReceiptError("case_receipt_invalid")
    if row.get("primary_calls") != 10 or row.get("primary_serialized_input_bytes") != 893359:
        raise ReceiptError("case_request_plan_mismatch")
    if row.get("snapshot_hash") != "3fcb39bbe80bbc10d02fbfef98abc6f73f9f46b829776515a6c9f9df69787663":
        raise ReceiptError("case_snapshot_mismatch")
    for field in (
        "checks_sha256", "evidence_index_sha256", "immutable_patch_sha256",
        "primary_descriptor_sha256", "profile_sha256", "scope_sha256", "snapshot_hash",
    ):
        _hash(row.get(field), "case_hash_invalid")
    for field in ("primary_calls", "primary_serialized_input_bytes", "scope_count"):
        value = row.get(field)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ReceiptError("case_count_invalid")
    return {key: row[key] for key in sorted(CASE_KEYS)}


def sanitize(summary_path: Path, manifest_path: Path, output_dir: Path) -> dict[str, Any]:
    summary, summary_bytes = _read_json(summary_path, 128_000)
    manifest, manifest_bytes = _read_json(manifest_path, 4_000_000)
    if set(summary) != SUMMARY_KEYS or summary.get("status") != "PREPARED_NOT_RUN":
        raise ReceiptError("summary_schema_invalid")
    if summary.get("schema") != "historical-real-case-trial-manifest.v2":
        raise ReceiptError("summary_contract_invalid")
    if set(manifest) != MANIFEST_KEYS or manifest.get("schema") != "historical-real-case-trial-manifest.v2":
        raise ReceiptError("manifest_schema_invalid")
    if manifest.get("status") != "PREPARED_NOT_RUN" or manifest.get("mode") != "staged-pr464":
        raise ReceiptError("manifest_status_invalid")
    if manifest.get("input_contract") != "specialist-input-v2" or manifest.get("provider_calls") != 0:
        raise ReceiptError("manifest_provider_state_invalid")
    if manifest.get("provider_execution_state") != "ZERO_PROVIDER_CALLS_PREPARE_ONLY":
        raise ReceiptError("manifest_provider_state_invalid")
    if manifest.get("publication_enabled") is not False or manifest.get("target_code_execution") is not False:
        raise ReceiptError("manifest_effect_state_invalid")
    if manifest.get("max_retries_per_task") != 0 or manifest.get("primary_response_byte_cap_per_call") != 16000:
        raise ReceiptError("manifest_budget_invalid")
    if manifest.get("runtime_revision") != "5873c3f1b297a96c49b78cbcb7be674ab70b3cea":
        raise ReceiptError("manifest_runtime_invalid")
    if manifest.get("runtime_module_tree_sha256") != "d8bdb53517abb7d85fff59805224f457f296832e7e0074b1485c50691dae1ad4":
        raise ReceiptError("manifest_runtime_hash_invalid")
    if not SHA40.fullmatch(str(manifest.get("runner_revision", ""))):
        raise ReceiptError("manifest_runner_revision_invalid")
    summary_cases = summary.get("cases")
    manifest_cases = manifest.get("cases")
    if not isinstance(summary_cases, list) or len(summary_cases) != 1 or not isinstance(summary_cases[0], dict):
        raise ReceiptError("summary_cases_invalid")
    if not isinstance(manifest_cases, list) or len(manifest_cases) != 1 or not isinstance(manifest_cases[0], dict):
        raise ReceiptError("manifest_cases_invalid")
    summary_case = _case_summary(summary_cases[0])
    manifest_case = manifest_cases[0]
    if set(manifest_case) != MANIFEST_CASE_KEYS or manifest_case.get("case_id") != "PR-464":
        raise ReceiptError("manifest_case_invalid")
    if manifest_case.get("status") != "PREPARED_NOT_RUN":
        raise ReceiptError("manifest_case_status_invalid")
    for key in CASE_KEYS:
        if manifest_case.get(key) != summary_case[key]:
            raise ReceiptError("summary_manifest_case_mismatch")
    summary_output = {
        "schema": "model-only-shadow-preflight-receipt.v1",
        "status": "PREPARED_NOT_RUN",
        "case": summary_case,
    }
    manifest_output = {
        **summary_output,
        "runner_revision": manifest["runner_revision"],
        "runtime_revision": manifest["runtime_revision"],
        "runtime_module_tree_sha256": manifest["runtime_module_tree_sha256"],
        "runtime_wheel_sha256": manifest["runtime_wheel_sha256"],
        "provider_execution_state": "ZERO_PROVIDER_CALLS_PREPARE_ONLY",
        "provider_calls": 0,
        "max_retries_per_task": 0,
        "publication_enabled": False,
        "target_code_execution": False,
        "source_summary_sha256": hashlib.sha256(summary_bytes).hexdigest(),
        "source_manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
    }
    output_dir.mkdir(mode=0o700, parents=False, exist_ok=False)
    os.chmod(output_dir, 0o700)
    for name, value in (("summary.json", summary_output), ("manifest.json", manifest_output)):
        encoded = (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode()
        target = output_dir / name
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
    return manifest_output


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--summary", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        output = sanitize(args.summary, args.manifest, args.output_dir)
    except (OSError, ReceiptError) as exc:
        error = str(exc) if isinstance(exc, ReceiptError) else "receipt_write_failed"
        print(json.dumps({"ok": False, "error_code": error}, separators=(",", ":")))
        return 2
    print(json.dumps({"ok": True, "case_id": output["case"]["case_id"], "status": output["status"]}, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
