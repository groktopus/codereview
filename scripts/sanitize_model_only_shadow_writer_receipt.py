#!/usr/bin/env python3
"""Emit allowlisted content-free diagnostics from one complete private writer capture.

The script deliberately discards every raw prompt, source excerpt, candidate,
and model response. It accepts only a full successful execution of a pinned
writer plan and writes private allowlisted JSON artifacts.
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
if os.environ.get("PR457_CURRENT_SOURCE_RUNTIME") != "1":
    sys.path.insert(0, str(ROOT / "src"))
from shadow_case_policy import case_for_plan_path, validate_plan_binding  # noqa: E402

SHA256 = re.compile(r"^[0-9a-f]{64}$")
CALL_ID = re.compile(r"^call-[0-9a-f]{24}$")


class ReceiptError(ValueError):
    """Capture is incomplete or does not match the reviewed plan."""


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


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


def _validate_packet_inventory(root: Path, manifest: dict[str, Any]) -> None:
    inventory = manifest.get("case_packet_inventory")
    if (not isinstance(inventory, dict) or set(inventory) != {"schema", "packets"}
            or inventory.get("schema") != "model-only-shadow-packet-inventory.v1"
            or not isinstance(inventory.get("packets"), list)
            or not 1 <= len(inventory["packets"]) <= 128):
        raise ReceiptError("capture_packet_inventory_invalid")
    expected: dict[str, str] = {}
    for row in inventory["packets"]:
        if (not isinstance(row, dict) or set(row) != {"path", "sha256"}
                or not isinstance(row.get("path"), str)
                or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\.json", row["path"])
                or not isinstance(row.get("sha256"), str) or not SHA256.fullmatch(row["sha256"])
                or row["path"] in expected):
            raise ReceiptError("capture_packet_inventory_invalid")
        expected[row["path"]] = row["sha256"]
    packet_dir = root / "case-packets"
    try:
        info = packet_dir.lstat()
    except OSError:
        raise ReceiptError("capture_packet_inventory_invalid") from None
    if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700:
        raise ReceiptError("capture_packet_inventory_invalid")
    try:
        entries = list(packet_dir.iterdir())
    except OSError:
        raise ReceiptError("capture_packet_inventory_invalid") from None
    if {path.name for path in entries} != set(expected):
        raise ReceiptError("capture_packet_inventory_mismatch")
    for path in entries:
        raw = _read_regular(path, 4_000_000, private=True)
        if hashlib.sha256(raw).hexdigest() != expected[path.name]:
            raise ReceiptError("capture_packet_inventory_mismatch")


def _writer_outcome_accounting(root: Path, manifest: dict[str, Any], plan_hash: str,
                              response_rows: dict[str, dict[str, Any]],
                              request_rows: dict[str, dict[str, Any]]) -> tuple[dict[str, Any], dict[str, Any]]:
    """Summarize the model-output to packet boundary without retaining content."""
    inventory = manifest["case_packet_inventory"]["packets"]
    if len(inventory) > 128:
        raise ReceiptError("capture_packet_inventory_invalid")
    packet_candidates: dict[str, int] = {}
    packet_counts: dict[str, int] = {}
    packet_diagnostics: dict[str, dict[str, Any]] = {}
    for item in inventory:
        packet, _raw = _read_json(root / "case-packets" / item["path"], 4_000_000)
        source_task = packet.get("source_task")
        task_id = source_task.get("task_id") if isinstance(source_task, dict) else None
        if not isinstance(task_id, str) or task_id not in response_rows:
            raise ReceiptError("capture_packet_task_invalid")
        packet_counts[task_id] = packet_counts.get(task_id, 0) + 1
        candidate = packet.get("writer_candidate")
        if candidate is not None and not isinstance(candidate, dict):
            raise ReceiptError("capture_packet_candidate_invalid")
        if candidate is not None:
            packet_candidates[task_id] = packet_candidates.get(task_id, 0) + 1
        source_task = packet.get("source_task")
        source_evidence = packet.get("source_evidence")
        if not isinstance(source_task, dict) or not isinstance(source_evidence, list):
            raise ReceiptError("capture_packet_source_invalid")
        unit_ids = source_task.get("unit_ids", [])
        evidence_ids = source_task.get("evidence_ids", [])
        if (not isinstance(unit_ids, list) or len(unit_ids) > 128
                or any(not isinstance(value, str) or not value for value in unit_ids)
                or not isinstance(evidence_ids, list) or len(evidence_ids) > 512
                or any(not isinstance(value, str) or not value for value in evidence_ids)
                or len(source_evidence) > 512
                or any(not isinstance(item, dict) or not isinstance(item.get("evidence_id"), str)
                       for item in source_evidence)):
            raise ReceiptError("capture_packet_source_invalid")
        if evidence_ids != [item["evidence_id"] for item in source_evidence]:
            raise ReceiptError("capture_packet_source_invalid")
        # Keep only hashes, counts, and byte lengths. Never copy task/evidence
        # names, excerpts, or model output text into the diagnostic artifact.
        source_evidence_bytes = sum(len(_canonical_bytes(item)) for item in source_evidence)
        source = {
            "unit_hashes": sorted(hashlib.sha256(value.encode("utf-8")).hexdigest() for value in set(unit_ids)),
            "evidence_count": len(source_evidence),
            "evidence_ids_sha256": hashlib.sha256(_canonical_bytes(evidence_ids)).hexdigest(),
            "evidence_bytes": source_evidence_bytes,
        }
        existing = packet_diagnostics.get(task_id)
        if existing is not None and existing != source:
            raise ReceiptError("capture_packet_source_mismatch")
        packet_diagnostics[task_id] = source

    rows = []
    if set(packet_counts) != set(response_rows):
        raise ReceiptError("capture_packet_task_coverage_mismatch")
    for task_id in sorted(response_rows):
        response = response_rows[task_id]
        returned = response["returned_candidate_count"]
        packet_count = packet_candidates.get(task_id, 0)
        if packet_count > returned:
            raise ReceiptError("capture_packet_candidate_count_exceeds_returned")
        if response["response_parse_status"] != "valid_specialist_report":
            outcome = "parse_failure"
        elif returned == 0:
            outcome = "zero_findings_returned"
        elif packet_count == 0:
            outcome = "candidate_reconciliation_or_filtering"
        elif packet_count < returned:
            outcome = "candidate_reconciliation_or_filtering"
        else:
            outcome = "candidates_preserved_in_packets"
        rows.append({
            "task_id_sha256": hashlib.sha256(task_id.encode("utf-8")).hexdigest(),
            "response_sha256": response["response_sha256"],
            "response_parse_status": response["response_parse_status"],
            "returned_candidate_count": returned,
            "packet_candidate_count": packet_count,
            "candidate_packet_count": packet_counts.get(task_id, 0),
            "outcome": outcome,
        })
    diagnostic_rows = []
    for task_id in sorted(response_rows):
        response = response_rows[task_id]
        request = request_rows[task_id]
        source = packet_diagnostics[task_id]
        diagnostic_rows.append({
            "task_id_sha256": hashlib.sha256(task_id.encode("utf-8")).hexdigest(),
            "lens": request["lens"],
            "unit_hashes": source["unit_hashes"],
            "evidence_count": source["evidence_count"],
            "evidence_ids_sha256": source["evidence_ids_sha256"],
            "evidence_bytes": source["evidence_bytes"],
            "request_bytes": request["input_bytes"],
            "response_bytes": response["response_bytes"],
            "response_parse_status": response["response_parse_status"],
            "returned_candidate_count": response["returned_candidate_count"],
            "context_gap_count": response["context_gap_count"],
            "coverage_note_count": response["coverage_note_count"],
            "attempt": response["attempt"],
            "completion_state": response["completion_state"],
            "provider_completion_metadata": "not_captured",
        })
    diagnostics = {
        "schema": "model-only-shadow-live-task-diagnostics.v1",
        "plan_sha256": plan_hash,
        "capture_manifest_sha256": hashlib.sha256(
            (root / "manifest.json").read_bytes()
        ).hexdigest(),
        "tasks": diagnostic_rows,
    }
    outcomes = {
        "schema": "model-only-shadow-live-writer-outcomes.v1",
        "plan_sha256": plan_hash,
        "capture_manifest_sha256": hashlib.sha256(
            (root / "manifest.json").read_bytes()
        ).hexdigest(),
        "tasks": rows,
        "returned_candidate_count_total": sum(row["returned_candidate_count"] for row in rows),
        "packet_candidate_count_total": sum(row["packet_candidate_count"] for row in rows),
        "outcome_counts": {
            status: sum(row["outcome"] == status for row in rows)
            for status in (
                "zero_findings_returned", "parse_failure",
                "candidate_reconciliation_or_filtering", "candidates_preserved_in_packets",
            )
        },
    }
    return outcomes, diagnostics


def _current_source_plan(plan: dict[str, Any], preflight: dict[str, Any], plan_path: Path,
                         preflight_path: Path) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    try:
        from pr_review_harness.current_source_capture import installed_module_inventory, validate_plan
        module = __import__("pr_review_harness.current_source_capture", fromlist=["__file__"])
        module_path = Path(module.__file__).resolve()
        if module_path.is_relative_to((ROOT / "src").resolve()):
            raise ValueError("installed_runtime_required")
        if os.environ.get("GITHUB_ACTIONS", "").lower() == "true":
            runner_temp = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
            if (plan_path.absolute() != runner_temp / "pr457-current-source-plan.json"
                    or preflight_path.absolute() != runner_temp / "pr457-current-source-receipt.json"
                    or os.environ.get("GITHUB_REPOSITORY") != "groktopus/codereview"
                    or os.environ.get("GITHUB_EVENT_NAME") != "workflow_dispatch"
                    or os.environ.get("GITHUB_REF") != "refs/heads/main"
                    or os.environ.get("GITHUB_WORKFLOW_REF") != (
                        "groktopus/codereview/.github/workflows/pr457-role-accounted-shadow.yml@refs/heads/main"
                    )):
                raise ValueError("current_source_context_invalid")
        writer_pins, snapshot = validate_plan(
            plan, preflight, source_sha=os.environ.get("GITHUB_SHA", ""),
            module_inventory=installed_module_inventory(),
        )
    except (OSError, KeyError, TypeError, ValueError, RecursionError):
        raise ReceiptError("current_source_plan_invalid") from None
    target = plan.get("target")
    if not isinstance(target, dict):
        raise ReceiptError("current_source_plan_invalid")
    projected_case = {"case_id": "PR-457", "snapshot_id": target.get("snapshot_id"),
                      "snapshot_sha256": target.get("snapshot_sha256")}
    projected_plan = {
        "case": projected_case,
        "writer_requests": list(writer_pins.values()),
        "deterministic_check_tasks": snapshot.get("deterministic_check_tasks", {}),
    }
    return projected_plan, {"writer_calls": 6}, snapshot


def sanitize(capture_root: Path, plan_path: Path, preflight_path: Path, output_dir: Path, *,
             current_source: bool = False) -> dict[str, Any]:
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
    if current_source:
        projection_plan, case_policy, current_snapshot = _current_source_plan(
            plan, preflight, plan_path, preflight_path,
        )
        case = projection_plan["case"]
        requests = projection_plan["writer_requests"]
        case_id = "PR-457"
        if (current_snapshot.get("case_id") != case_id
                or current_snapshot.get("snapshot_id") != case.get("snapshot_id")
                or current_snapshot.get("snapshot_sha256") != case.get("snapshot_sha256")):
            raise ReceiptError("current_source_plan_invalid")
    else:
        try:
            case_id, case_policy = case_for_plan_path(plan_path, ROOT)
            validated_case_id, _ = validate_plan_binding(plan, plan_bytes)
        except ValueError:
            raise ReceiptError("plan_hash_mismatch") from None
        if plan_hash != case_policy["plan_sha256"] or validated_case_id != case_id:
            raise ReceiptError("plan_hash_mismatch")
        case = plan.get("case")
        budget = plan.get("budget")
        requests = plan.get("writer_requests")
        if (
            plan.get("schema") != case_policy["plan_schema"]
            or not isinstance(case, dict) or case.get("case_id") != case_id
            or not isinstance(budget, dict) or budget.get("writer_exact_call_count") != case_policy["writer_calls"]
            or budget.get("writer_max_retries_per_task") != 0
            or not isinstance(requests, list) or len(requests) != case_policy["writer_calls"]
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
    allowed_manifest_keys = {"contract_version", "case_id", "snapshot_id", "snapshot_hash", "source_task", "provider", "calls", "private_artifacts", "case_packet_inventory"}
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
    _validate_packet_inventory(root, manifest)

    calls = manifest["calls"]
    if len(calls) != case_policy["writer_calls"]:
        raise ReceiptError("capture_call_count_mismatch")
    seen: set[str] = set()
    receipts = []
    total_request_bytes = 0
    total_response_bytes = 0
    response_rows: dict[str, dict[str, Any]] = {}
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
        parse_status = "valid_specialist_report"
        returned_candidate_count = 0
        if (set(parsed) != {
                "contract_version", "finding_candidates", "context_gap_proposals", "coverage_notes",
                "specific_strengths", "future_guidance",
        } or parsed.get("contract_version") != "specialist-findings.v4"
                or any(not isinstance(parsed.get(field), list) for field in (
                    "finding_candidates", "context_gap_proposals", "coverage_notes",
                    "specific_strengths", "future_guidance",
                ))):
            parse_status = "invalid_specialist_report"
        if isinstance(parsed.get("finding_candidates"), list):
            returned_candidate_count = len(parsed["finding_candidates"])
        seen.add(task_id)
        total_request_bytes += len(request)
        total_response_bytes += len(response)
        response_rows[task_id] = {
            "response_sha256": call["response_sha256"],
            "response_parse_status": parse_status,
            "returned_candidate_count": returned_candidate_count,
            "context_gap_count": len(parsed["context_gap_proposals"])
            if isinstance(parsed.get("context_gap_proposals"), list) else None,
            "coverage_note_count": len(parsed["coverage_notes"])
            if isinstance(parsed.get("coverage_notes"), list) else None,
            "response_bytes": len(response),
            "attempt": call["attempt"],
            "completion_state": call["status"],
        }
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
    outcomes, diagnostics = _writer_outcome_accounting(root, manifest, plan_hash, response_rows, expected)
    _write_private(output_path / "writer-receipt.json", json.dumps(
        output, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8") + b"\n")
    _write_private(output_path / "writer-outcomes.json", json.dumps(
        outcomes, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8") + b"\n")
    _write_private(output_path / "writer-task-diagnostics.json", json.dumps(
        diagnostics, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8") + b"\n")
    return output


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture-root", type=Path, required=True)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--preflight", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--current-source", action="store_true",
                        help="validate the closed per-run PR-457 plan and receipt")
    args = parser.parse_args(argv)
    try:
        sanitize(args.capture_root, args.plan, args.preflight, args.output_dir,
                 current_source=args.current_source)
    except (OSError, ReceiptError) as exc:
        code = str(exc) if isinstance(exc, ReceiptError) else "input_unavailable"
        print(json.dumps({"ok": False, "error_code": code}, separators=(",", ":")), file=sys.stderr)
        return 2
    print('{"ok":true,"status":"WRITER_RECEIPT_SANITIZED"}')
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
