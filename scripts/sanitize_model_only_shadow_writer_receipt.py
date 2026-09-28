#!/usr/bin/env python3
"""Emit a hash-only receipt from one complete private writer capture.

The script deliberately discards every raw prompt, source excerpt, candidate,
and model response. It accepts only a full successful execution of the fixed
PR-464 request plan and writes one allowlisted JSON receipt.
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
SHA256 = re.compile(r"^[0-9a-f]{64}$")
CALL_ID = re.compile(r"^call-[0-9a-f]{24}$")
EXPECTED_PLAN_SHA256 = "218da5b8011e0d9e391721a6e96114e9aa80f738c49eef2deb0f3c41f47d8db2"


class ReceiptError(ValueError):
    """Capture is incomplete or does not match the reviewed plan."""


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ReceiptError("duplicate_json_key")
        value[key] = item
    return value


def _read_regular(path: Path, limit: int, *, private: bool = False) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        before = path.lstat()
        if (not stat.S_ISREG(before.st_mode) or before.st_size > limit
                or (private and stat.S_IMODE(before.st_mode) != 0o600)):
            raise ReceiptError("input_unavailable")
        fd = os.open(path, flags)
        try:
            opened = os.fstat(fd)
            if (not stat.S_ISREG(opened.st_mode) or opened.st_dev != before.st_dev
                    or opened.st_ino != before.st_ino or opened.st_size > limit):
                raise ReceiptError("input_unavailable")
            if private and stat.S_IMODE(opened.st_mode) != 0o600:
                raise ReceiptError("input_unavailable")
            data = bytearray()
            while len(data) <= limit:
                block = os.read(fd, min(65536, limit + 1 - len(data)))
                if not block:
                    break
                data.extend(block)
            after = os.fstat(fd)
        finally:
            os.close(fd)
    except OSError:
        raise ReceiptError("input_unavailable") from None
    if len(data) > limit or before.st_size != after.st_size or after.st_size != len(data):
        raise ReceiptError("input_changed_or_oversize")
    return bytes(data)


def _read_json(path: Path, limit: int) -> tuple[dict[str, Any], bytes]:
    raw = _read_regular(path, limit)
    try:
        value = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_pairs,
            parse_constant=lambda _v: (_ for _ in ()).throw(ReceiptError("invalid_json_constant")),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ReceiptError):
        raise ReceiptError("input_invalid_json") from None
    if not isinstance(value, dict):
        raise ReceiptError("input_invalid_shape")
    return value, raw


def _write_private(path: Path, data: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ReceiptError("output_not_regular")
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(fd)


def sanitize(capture_root: Path, plan_path: Path, preflight_path: Path, output_dir: Path) -> dict[str, Any]:
    runner_temp_value = os.environ.get("RUNNER_TEMP")
    if not runner_temp_value:
        raise ReceiptError("runner_temp_unavailable")
    runner_temp = Path(runner_temp_value).resolve(strict=True)
    root = capture_root.absolute()
    output_path = output_dir.absolute()
    if (
        root.parent != runner_temp or output_path.parent != runner_temp or root == output_path
        or not root.exists() or output_path.exists() or root.is_symlink() or output_path.is_symlink()
    ):
        raise ReceiptError("private_paths_invalid")
    root_info = root.lstat()
    if not stat.S_ISDIR(root_info.st_mode) or stat.S_IMODE(root_info.st_mode) != 0o700:
        raise ReceiptError("private_capture_permissions_invalid")

    plan, plan_bytes = _read_json(plan_path, 128_000)
    preflight, _preflight_bytes = _read_json(preflight_path, 16_384)
    plan_hash = hashlib.sha256(plan_bytes).hexdigest()
    if plan_hash != EXPECTED_PLAN_SHA256:
        raise ReceiptError("plan_hash_mismatch")
    case = plan.get("case")
    budget = plan.get("budget")
    requests = plan.get("writer_requests")
    if (
        plan.get("schema") != "model-only-shadow-live-writer-plan.v1"
        or not isinstance(case, dict) or case.get("case_id") != "PR-464"
        or not isinstance(budget, dict) or budget.get("writer_exact_call_count") != 10
        or budget.get("writer_max_retries_per_task") != 0
        or not isinstance(requests, list) or len(requests) != 10
        or preflight.get("schema") != "model-only-shadow-live-preflight-receipt.v1"
        or preflight.get("status") != "PLAN_MATCHED_PROVIDER_FREE"
        or preflight.get("plan_sha256") != plan_hash
        or preflight.get("case_id") != case.get("case_id")
        or preflight.get("snapshot_sha256") != case.get("snapshot_sha256")
        or preflight.get("provider_calls") != 0
        or preflight.get("target_code_execution") is not False
        or preflight.get("publication_enabled") is not False
    ):
        raise ReceiptError("preflight_binding_invalid")
    expected = {}
    for row in requests:
        if (not isinstance(row, dict) or not isinstance(row.get("task_id"), str)
                or row["task_id"] in expected or not SHA256.fullmatch(str(row.get("input_sha256")))
                or isinstance(row.get("input_bytes"), bool) or not isinstance(row.get("input_bytes"), int)
                or not 1 <= row["input_bytes"] <= 128_000):
            raise ReceiptError("plan_request_invalid")
        expected[row["task_id"]] = row

    manifest, _manifest_bytes = _read_json(root / "manifest.json", 256_000)
    allowed_manifest_keys = {"contract_version", "case_id", "snapshot_id", "snapshot_hash", "source_task", "provider", "calls", "private_artifacts"}
    if set(manifest) != allowed_manifest_keys or manifest.get("contract_version") != "model-only-shadow-case.v1":
        raise ReceiptError("capture_manifest_invalid")
    if (
        manifest.get("snapshot_id") != case.get("snapshot_id")
        or manifest.get("snapshot_hash") != case.get("snapshot_sha256")
        or manifest.get("private_artifacts") is not True
        or not isinstance(manifest.get("case_id"), str)
        or not isinstance(manifest.get("calls"), list)
    ):
        raise ReceiptError("capture_identity_mismatch")
    provider = manifest.get("provider")
    expected_provider = {
        "provider_id": "operator_openai_compatible", "model_id": "openai/gpt-6-luna", "adapter_version": "0.2",
    }
    if provider != expected_provider:
        raise ReceiptError("provider_identity_mismatch")

    calls = manifest["calls"]
    if len(calls) != 10:
        raise ReceiptError("capture_call_count_mismatch")
    seen: set[str] = set()
    receipts = []
    total_request_bytes = 0
    total_response_bytes = 0
    run_id = manifest["case_id"]
    if manifest.get("source_task") != run_id:
        raise ReceiptError("capture_run_identity_mismatch")
    for call in calls:
        required_call_fields = {
            "call_id", "case_id", "run_id", "snapshot_id", "snapshot_hash", "task_id", "attempt",
            "provider", "status", "request_artifact_id", "request_sha256", "response_artifact_id",
            "response_sha256", "response_envelope_sha256", "content_transform",
        }
        if not isinstance(call, dict) or set(call) != required_call_fields:
            raise ReceiptError("capture_call_invalid")
        task_id = call.get("task_id")
        descriptor = expected.get(task_id)
        call_id = call.get("call_id")
        if (
            descriptor is None or task_id in seen or not isinstance(call_id, str) or not CALL_ID.fullmatch(call_id)
            or call.get("case_id") != run_id or call.get("run_id") != run_id
            or call.get("snapshot_id") != case["snapshot_id"] or call.get("snapshot_hash") != case["snapshot_sha256"]
            or call.get("attempt") != 0 or call.get("status") != "completed"
            or call.get("provider") != expected_provider
            or call.get("request_artifact_id") != "request-" + call_id
            or call.get("response_artifact_id") != "response-" + call_id
            or call.get("request_sha256") != descriptor["input_sha256"]
            or not isinstance(call.get("response_sha256"), str)
            or not SHA256.fullmatch(call["response_sha256"])
            or call.get("content_transform") != "openai-chat-completions.message-content.utf8.v1"
        ):
            raise ReceiptError("capture_call_binding_invalid")
        request_dir = root / "requests"
        response_dir = root / "responses"
        for child in (request_dir, response_dir):
            child_info = child.lstat()
            if not stat.S_ISDIR(child_info.st_mode) or stat.S_IMODE(child_info.st_mode) != 0o700:
                raise ReceiptError("capture_permissions_invalid")
        request = _read_regular(request_dir / f"{call_id}.bin", 128_000, private=True)
        response = _read_regular(response_dir / f"{call_id}.bin", 32_768, private=True)
        if (
            len(request) != descriptor["input_bytes"] or hashlib.sha256(request).hexdigest() != call["request_sha256"]
            or len(response) > 32_768 or hashlib.sha256(response).hexdigest() != call["response_sha256"]
        ):
            raise ReceiptError("capture_bytes_mismatch")
        try:
            parsed = json.loads(response.decode("utf-8"), object_pairs_hook=_pairs)
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ReceiptError):
            raise ReceiptError("structured_response_invalid") from None
        if not isinstance(parsed, dict):
            raise ReceiptError("structured_response_invalid")
        seen.add(task_id)
        total_request_bytes += len(request)
        total_response_bytes += len(response)
        receipts.append({
            "task_id": task_id,
            "request_sha256": call["request_sha256"], "request_bytes": len(request),
            "response_sha256": call["response_sha256"], "response_bytes": len(response),
        })
    if seen != set(expected):
        raise ReceiptError("capture_task_set_mismatch")
    output = {
        "schema": "model-only-shadow-live-writer-receipt.v1",
        "status": "WRITER_TRANSPORT_CAPTURED",
        "case_id": case["case_id"], "snapshot_id": case["snapshot_id"],
        "snapshot_sha256": case["snapshot_sha256"], "plan_sha256": plan_hash,
        "provider_id": expected_provider["provider_id"], "model_id": expected_provider["model_id"],
        "writer_call_count": len(receipts), "writer_request_bytes_total": total_request_bytes,
        "writer_response_bytes_total": total_response_bytes,
        "calls": sorted(receipts, key=lambda item: item["task_id"]),
        "target_code_execution": False, "publication_enabled": False,
        "audit_or_jev_dispatched": False,
    }
    output_path.mkdir(mode=0o700)
    os.chmod(output_path, 0o700)
    _write_private(output_path / "writer-receipt.json", json.dumps(
        output, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8") + b"\n")
    return output


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture-root", type=Path, required=True)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--preflight", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        sanitize(args.capture_root, args.plan, args.preflight, args.output_dir)
    except (OSError, ReceiptError) as exc:
        code = str(exc) if isinstance(exc, ReceiptError) else "input_unavailable"
        print(json.dumps({"ok": False, "error_code": code}, separators=(",", ":")), file=sys.stderr)
        return 2
    print('{"ok":true,"status":"WRITER_RECEIPT_SANITIZED"}')
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
