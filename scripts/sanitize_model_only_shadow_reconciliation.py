#!/usr/bin/env python3
"""Project validated writer/engine candidate reconciliation into private hash-only evidence."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
if os.environ.get("PR457_CURRENT_SOURCE_RUNTIME") != "1":
    sys.path.insert(0, str(ROOT / "src"))
from sanitize_model_only_shadow_writer_receipt import _current_source_plan  # noqa: E402
from sanitize_model_only_shadow_writer_receipt import sanitize as sanitize_writer_capture  # noqa: E402
from shadow_case_policy import case_for_plan_path  # noqa: E402

from pr_review_harness.contracts import ContractIssue, validate_candidate  # noqa: E402

FIELDS = ("title", "observation", "consequence", "rule_or_contract", "evidence_refs")
SHA = re.compile(r"^[0-9a-f]{64}$")


class ReconciliationError(ValueError):
    pass


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_json(path: Path, limit: int, private: bool = False) -> tuple[Any, bytes]:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        before = path.lstat()
        if (not stat.S_ISREG(before.st_mode) or before.st_size > limit
                or (private and stat.S_IMODE(before.st_mode) != 0o600)):
            raise ReconciliationError("input_unavailable")
        fd = os.open(path, flags)
        try:
            opened = os.fstat(fd)
            if (not stat.S_ISREG(opened.st_mode) or (before.st_dev, before.st_ino) !=
                    (opened.st_dev, opened.st_ino) or opened.st_size > limit):
                raise ReconciliationError("input_unavailable")
            data = bytearray()
            while len(data) <= limit:
                chunk = os.read(fd, min(65536, limit + 1 - len(data)))
                if not chunk:
                    break
                data.extend(chunk)
        finally:
            os.close(fd)
    except OSError:
        raise ReconciliationError("input_unavailable") from None
    if len(data) > limit or len(data) != before.st_size:
        raise ReconciliationError("input_changed_or_oversize")
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=unique_pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError):
        raise ReconciliationError("input_invalid_json") from None
    return value, bytes(data)


def unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def candidate_id(task_id: str, index: int, raw: Any) -> str:
    return digest(canonical({"task_id": task_id, "index": index, "raw": raw}))[:24]


def raw_item_hash(value: Any) -> str:
    return digest(json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8"))


def finding_pairs(findings: Any) -> set[tuple[str, str]]:
    pairs: set[tuple[str, str]] = set()
    if not isinstance(findings, list):
        return pairs
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        rows = finding.get("assessment_records")
        if isinstance(rows, list):
            pairs.update((row["candidate_id"], row["task_id"]) for row in rows
                         if isinstance(row, dict) and isinstance(row.get("candidate_id"), str)
                         and isinstance(row.get("task_id"), str))
        elif isinstance(finding.get("candidate_id"), str) and isinstance(finding.get("task_id"), str):
            pairs.add((finding["candidate_id"], finding["task_id"]))
    return pairs


def validate_deterministic_check_rows(tasks: dict[str, Any], ledger_outputs: dict[str, Any],
                                      check_tasks: dict[str, dict[str, Any]], snapshot_hash: str) -> None:
    """Validate the exact prepared checks without removing them from the ledger."""
    for task_id, binding in check_tasks.items():
        output = tasks.get(task_id)
        if not isinstance(output, dict) or ledger_outputs.get(task_id) != output:
            raise ReconciliationError("check_task_binding_invalid")
        evidence_id = binding["expected_evidence_id"]
        expected_refs = [evidence_id] if evidence_id is not None else []
        expected_payload = {
            "check_id": binding["check_id"],
            "outcome": binding["expected_outcome"],
            "finding_candidates": [],
            "evidence_refs": expected_refs,
            "diagnostics": [] if evidence_id is not None else ["authoritative_check_run_evidence_unavailable"],
        }
        expected_hash = digest(canonical(expected_payload))
        expected_input_hash = binding["expected_input_hash"]
        if (output.get("task_id") != task_id or output.get("task_kind") != "DETERMINISTIC_CHECK"
                or output.get("lens") != binding["lens"] or output.get("unit_ids") != binding["unit_ids"]
                or output.get("status") != "SUCCEEDED" or output.get("input_evidence_ids") != expected_refs
                or output.get("input_hash") != expected_input_hash
                or output.get("payload") != expected_payload or output.get("output_hash") != expected_hash
                or isinstance(output.get("attempts"), bool) or output.get("attempts") != 1
                or ledger_outputs[task_id].get("output_hash") != expected_hash):
            raise ReconciliationError("check_task_output_invalid")


def build_receipt(result: dict[str, Any], ledger: dict[str, Any], outcomes: dict[str, Any],
                  manifest: dict[str, Any], response_payloads: dict[str, tuple[str, dict]],
                  packet_pairs: set[tuple[str, str]], plan: dict[str, Any], writer_receipt: dict[str, Any],
                  result_sha: str, plan_sha: str, manifest_sha: str, writer_receipt_sha: str) -> dict[str, Any]:
    tasks = result.get("task_results")
    requests = plan.get("writer_requests")
    outcome_rows = outcomes.get("tasks")
    calls = manifest.get("calls")
    if not isinstance(ledger, dict) or not isinstance(tasks, dict) or not isinstance(requests, list):
        raise ReconciliationError("result_shape_invalid")
    if (result.get("result_hash") != result_sha
            or digest(canonical({key: value for key, value in result.items() if key != "result_hash"})) != result_sha
            or ledger.get("request_hash") != result.get("request_hash")):
        raise ReconciliationError("result_ledger_hash_invalid")
    if not all(isinstance(rows, list) for rows in (outcome_rows, calls)):
        raise ReconciliationError("provenance_missing")
    expected_count = len(requests)
    if not expected_count or len(outcome_rows) != expected_count or len(calls) != expected_count:
        raise ReconciliationError("task_coverage_invalid")
    task_ids = [row.get("task_id") if isinstance(row, dict) else None for row in requests]
    if any(not isinstance(task_id, str) for task_id in task_ids) or len(set(task_ids)) != expected_count:
        raise ReconciliationError("task_coverage_invalid")
    check_tasks = plan.get("deterministic_check_tasks", {})
    if (not isinstance(check_tasks, dict) or set(check_tasks).intersection(task_ids)
            or set(tasks) != set(task_ids).union(check_tasks) or ledger.get("outputs") != tasks):
        raise ReconciliationError("result_task_binding_invalid")
    validate_deterministic_check_rows(
        tasks, ledger["outputs"], check_tasks, plan.get("case", {}).get("snapshot_sha256"),
    )
    if (result.get("run_id") != manifest.get("case_id")
            or result.get("snapshot_id") != manifest.get("snapshot_id")
            or plan.get("case", {}).get("snapshot_id") != result.get("snapshot_id")
            or plan.get("case", {}).get("snapshot_sha256") != manifest.get("snapshot_hash")):
        raise ReconciliationError("result_capture_identity_mismatch")
    call_by_task = {row.get("task_id"): row for row in calls if isinstance(row, dict)}
    outcomes_by_hash = {row.get("task_id_sha256"): row for row in outcome_rows if isinstance(row, dict)}
    if set(call_by_task) != set(task_ids) or len(outcomes_by_hash) != expected_count:
        raise ReconciliationError("capture_task_binding_invalid")
    receipt_calls = writer_receipt.get("calls")
    if (writer_receipt.get("plan_sha256") != plan_sha
            or writer_receipt.get("snapshot_id") != plan.get("case", {}).get("snapshot_id")
            or writer_receipt.get("snapshot_sha256") != plan.get("case", {}).get("snapshot_sha256")
            or writer_receipt.get("writer_call_count") != expected_count
            or writer_receipt.get("publication_enabled") is not False
            or writer_receipt.get("target_code_execution") is not False
            or not isinstance(receipt_calls, list) or len(receipt_calls) != expected_count):
        raise ReconciliationError("writer_receipt_binding_invalid")
    receipt_by_task = {row.get("task_id"): row for row in receipt_calls if isinstance(row, dict)}
    if set(receipt_by_task) != set(task_ids):
        raise ReconciliationError("writer_receipt_task_binding_invalid")
    if outcomes.get("capture_manifest_sha256") not in (None, manifest_sha):
        raise ReconciliationError("outcomes_manifest_binding_invalid")
    records = ledger.get("candidate_records")
    records_by_key: dict[tuple[str, str], dict] = {}
    if isinstance(records, list):
        for row in records:
            if not isinstance(row, dict) or not isinstance(row.get("task_id"), str) or not isinstance(row.get("candidate_id"), str):
                raise ReconciliationError("candidate_record_invalid")
            key = (row["task_id"], row["candidate_id"])
            if key in records_by_key or key[0] not in task_ids:
                raise ReconciliationError("candidate_record_mismatch")
            records_by_key[key] = row
    elif records is not None:
        raise ReconciliationError("candidate_record_invalid")
    # This projection accounts only for the selected writer tasks. Findings
    # from separate check task types remain outside its candidate inventory.
    found = {pair for pair in finding_pairs(result.get("findings")) if pair[1] in set(task_ids)}
    projected_tasks = []
    accounted: set[tuple[str, str]] = set()
    expected_pairs: set[tuple[str, str]] = set()
    for task_id in task_ids:
        output = tasks[task_id]
        payload = output.get("payload") if isinstance(output, dict) else None
        if not isinstance(payload, dict) or not isinstance(payload.get("finding_candidates"), list):
            raise ReconciliationError("engine_payload_invalid")
        ledger_output = ledger["outputs"].get(task_id)
        if (not isinstance(ledger_output, dict)
                or ledger_output.get("output_hash") != digest(canonical(payload))):
            raise ReconciliationError("task_output_hash_invalid")
        call = call_by_task[task_id]
        outcome = outcomes_by_hash.get(digest(task_id.encode()))
        captured_sha, captured_payload = response_payloads[task_id]
        raw_candidates = captured_payload.get("finding_candidates")
        if not isinstance(raw_candidates, list) or not isinstance(outcome, dict):
            raise ReconciliationError("engine_capture_binding_invalid")
        if outcome.get("response_sha256") != call.get("response_sha256") or captured_sha != call.get("response_sha256"):
            raise ReconciliationError("response_hash_binding_invalid")
        request = next(row for row in requests if row["task_id"] == task_id)
        if (call.get("request_sha256") != request.get("input_sha256")
                or receipt_by_task[task_id].get("request_sha256") != request.get("input_sha256")
                or receipt_by_task[task_id].get("response_sha256") != captured_sha):
            raise ReconciliationError("request_response_binding_invalid")
        if outcome.get("returned_candidate_count") != len(raw_candidates):
            raise ReconciliationError("response_candidate_count_invalid")
        quarantined = payload.get("quarantined_items", [])
        if not isinstance(quarantined, list):
            raise ReconciliationError("normalization_ledger_invalid")
        rejected: dict[int, dict] = {}
        for item in quarantined:
            if not isinstance(item, dict) or item.get("kind") != "finding_candidates":
                continue
            ordinal = item.get("index")
            if isinstance(ordinal, bool) or not isinstance(ordinal, int) or ordinal in rejected:
                raise ReconciliationError("normalization_ledger_invalid")
            rejected[ordinal] = item
        if len(payload["finding_candidates"]) + len(rejected) != len(raw_candidates):
            raise ReconciliationError("normalization_candidate_count_invalid")
        projected = []
        accepted_index = 0
        for index, raw in enumerate(raw_candidates):
            rejected_item = rejected.get(index)
            if rejected_item is not None:
                if rejected_item.get("item_hash") != raw_item_hash(raw) or rejected_item.get("reason_code") not in {
                    "invalid_candidate_fields", "invalid_candidate_line", "invalid_candidate_text",
                    "invalid_candidate_severity", "invalid_candidate_reasoning_kind",
                    "invalid_candidate_introducedness", "invalid_candidate_evidence_refs",
                    "invalid_candidate_location", "invalid_candidate_unit_id",
                    "candidate_references_unknown_scope", "candidate_references_unknown_evidence",
                    "candidate_text_exceeds_limit", "output_item_limit_exceeded",
                }:
                    raise ReconciliationError("normalization_quarantine_binding_invalid")
                projected.append({"candidate_ordinal": index, "candidate_id_sha256": None,
                                  "raw_candidate_sha256": raw_item_hash(raw),
                                  "record_provenance": "VERIFIED", "validation_state": "NOT_APPLICABLE",
                                  "validation_reason": "NORMALIZATION_QUARANTINE", "in_reconciled_findings": False,
                                  "in_case_packet": False, "export_disposition": "NORMALIZATION_QUARANTINED",
                                  "normalization_reason_code": rejected_item["reason_code"],
                                  "missing_required_fields": []})
                continue
            if accepted_index >= len(payload["finding_candidates"]):
                raise ReconciliationError("normalization_candidate_count_invalid")
            engine_raw = payload["finding_candidates"][accepted_index]
            accepted_index += 1
            if not isinstance(engine_raw, dict):
                raise ReconciliationError("engine_candidate_invalid")
            if not isinstance(raw, dict):
                raise ReconciliationError("normalization_provenance_missing")
            try:
                normalized = validate_candidate(raw, captured_payload.get("contract_version"), None)
            except ContractIssue:
                raise ReconciliationError("normalization_provenance_invalid") from None
            for field, value in normalized.items():
                if field == "location":
                    if not isinstance(engine_raw.get(field), dict) or any(
                        engine_raw[field].get(name) != value.get(name)
                        for name in ("kind", "path", "side", "line")
                    ):
                        raise ReconciliationError("engine_candidate_source_mismatch")
                elif engine_raw.get(field) != value:
                    raise ReconciliationError("engine_candidate_source_mismatch")
            cid = candidate_id(task_id, accepted_index - 1, engine_raw)
            key = (task_id, cid)
            expected_pairs.add((cid, task_id))
            record = records_by_key.get(key)
            if record is not None:
                accounted.add(key)
                if isinstance(engine_raw, dict):
                    stored = record.get("raw")
                    if not isinstance(stored, dict) or any(stored.get(k) != v for k, v in engine_raw.items()):
                        raise ReconciliationError("candidate_record_binding_invalid")
                    if stored.get("candidate_id") != cid or stored.get("task_id") != task_id:
                        raise ReconciliationError("candidate_record_binding_invalid")
                elif record.get("raw_hash") != digest(canonical(raw)):
                    raise ReconciliationError("candidate_record_binding_invalid")
                state = record.get("validation_state")
                reason = record.get("validation_reason")
                if state not in {"VALID", "NEEDS_CONTEXT", "INVALID"} or reason not in {
                    "candidate_not_object", "location_or_evidence_not_validated",
                    "snapshot_location_and_evidence_validated",
                }:
                    raise ReconciliationError("candidate_validation_value_invalid")
                provenance = "VERIFIED"
            else:
                state = reason = "UNKNOWN"
                provenance = "UNKNOWN"
            pair = (cid, task_id)
            in_findings = pair in found
            in_packet = pair in packet_pairs
            if in_packet:
                disposition, missing = "EXPORTED", []
            elif provenance == "UNKNOWN":
                disposition, missing = "UNKNOWN", []
            elif not in_findings:
                disposition, missing = "NOT_IN_RECONCILED_FINDINGS", []
            elif not isinstance(raw, dict):
                disposition, missing = "CANDIDATE_NOT_OBJECT", []
            else:
                missing = [field for field in FIELDS if field not in raw]
                disposition = "MISSING_REQUIRED_FIELDS" if missing else "UNKNOWN"
            projected.append({"candidate_ordinal": index, "candidate_id_sha256": digest(cid.encode()),
                              "raw_candidate_sha256": raw_item_hash(raw),
                              "record_provenance": provenance, "validation_state": state,
                              "validation_reason": reason, "in_reconciled_findings": in_findings,
                              "in_case_packet": in_packet, "export_disposition": disposition,
                              "normalization_reason_code": None,
                              "missing_required_fields": missing})
        projected_tasks.append({"task_id_sha256": digest(task_id.encode()),
                                "response_sha256": call["response_sha256"],
                                "returned_candidate_count": len(projected),
                                "packet_candidate_count": sum(row["in_case_packet"] is True for row in projected),
                                "candidates": projected})
    if accounted != set(records_by_key):
        raise ReconciliationError("candidate_record_unmatched")
    if not found.issubset(expected_pairs):
        raise ReconciliationError("finding_candidate_unmatched")
    if not packet_pairs.issubset(expected_pairs):
        raise ReconciliationError("packet_candidate_unmatched")
    return {"schema": "model-only-shadow-writer-reconciliation.v1", "status": "PROJECTION_COMPLETE",
            "case_id": plan.get("case", {}).get("case_id", "unknown"), "run_id_sha256": digest(str(result.get("run_id")).encode()),
            "snapshot_id": result.get("snapshot_id"), "snapshot_sha256": plan["case"]["snapshot_sha256"],
            "plan_sha256": plan_sha, "capture_manifest_sha256": manifest_sha,
            "writer_receipt_sha256": writer_receipt_sha, "result_sha256": result_sha,
            "returned_candidate_count_total": sum(t["returned_candidate_count"] for t in projected_tasks),
            "packet_candidate_count_total": sum(t["packet_candidate_count"] for t in projected_tasks),
            "normalization_quarantined_count_total": sum(
                c["export_disposition"] == "NORMALIZATION_QUARANTINED"
                for t in projected_tasks for c in t["candidates"]
            ),
            "unknown_candidate_provenance_count": sum(c["record_provenance"] == "UNKNOWN"
                for t in projected_tasks for c in t["candidates"]), "tasks": projected_tasks}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ("result", "capture-root", "plan", "preflight", "writer-receipt", "writer-outcomes", "output"):
        parser.add_argument("--" + option, type=Path, required=True)
    parser.add_argument("--current-source", action="store_true",
                        help="validate the closed per-run PR-457 plan and receipt")
    args = parser.parse_args(argv)
    try:
        plan, plan_raw = read_json(args.plan, 128_000)
        if args.current_source:
            preflight, _ = read_json(args.preflight, 16_384)
            projection_plan, policy, _snapshot = _current_source_plan(
                plan, preflight, args.plan, args.preflight,
            )
            case_id = "PR-457"
        else:
            case_id, policy = case_for_plan_path(args.plan, ROOT)
            if case_id != "PR-464" or policy["writer_calls"] != 10:
                raise ReconciliationError("plan_identity_invalid")
            projection_plan = plan
        # Reuse the authoritative capture validator; supplied sanitized artifacts must match its output.
        runner_temp = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
        generated_dir = Path(tempfile.mkdtemp(prefix="reconcile-generated-", dir=runner_temp))
        generated_dir.rmdir()
        try:
            if args.current_source:
                generated_receipt = sanitize_writer_capture(
                    args.capture_root, args.plan, args.preflight, generated_dir,
                    current_source=True,
                )
            else:
                generated_receipt = sanitize_writer_capture(
                    args.capture_root, args.plan, args.preflight, generated_dir,
                )
            receipt_file, _ = read_json(args.writer_receipt, 128_000)
            outcomes_file, _ = read_json(args.writer_outcomes, 128_000)
            generated_outcomes, _ = read_json(generated_dir / "writer-outcomes.json", 128_000, True)
            if receipt_file != generated_receipt or outcomes_file != generated_outcomes:
                raise ReconciliationError("sanitized_capture_mismatch")
        finally:
            if generated_dir.exists():
                import shutil
                shutil.rmtree(generated_dir)
        result, result_raw = read_json(args.result, 8_000_000, True)
        manifest, manifest_raw = read_json(args.capture_root / "manifest.json", 256_000, True)
        if not isinstance(result, dict) or not isinstance(manifest, dict):
            raise ReconciliationError("result_shape_invalid")
        expected_hash = result.get("result_hash")
        if not isinstance(expected_hash, str) or digest(canonical({k: v for k, v in result.items() if k != "result_hash"})) != expected_hash:
            raise ReconciliationError("result_hash_mismatch")
        receipt, _ = read_json(args.writer_receipt, 128_000)
        outcomes, _ = read_json(args.writer_outcomes, 128_000)
        response_payloads: dict[str, tuple[str, dict]] = {}
        for call in manifest["calls"]:
            call_id = call["call_id"]
            if not isinstance(call_id, str) or call.get("response_artifact_id") != "response-" + call_id:
                raise ReconciliationError("capture_response_artifact_invalid")
            response, response_raw = read_json(args.capture_root / "responses" / f"{call_id}.bin", 32_768, True)
            response_payloads[call["task_id"]] = (digest(response_raw), response)
        packet_pairs: set[tuple[str, str]] = set()
        for item in manifest["case_packet_inventory"]["packets"]:
            packet, _ = read_json(args.capture_root / "case-packets" / item["path"], 4_000_000, True)
            candidate, source_task = packet.get("writer_candidate"), packet.get("source_task")
            if isinstance(candidate, dict) and isinstance(source_task, dict):
                packet_pairs.add((candidate["candidate_id"], source_task["task_id"]))
        projection = build_receipt(
            result, result.get("ledger"), outcomes, manifest, response_payloads, packet_pairs,
            projection_plan, receipt, expected_hash, digest(plan_raw), digest(manifest_raw), digest(canonical(receipt)),
        )
        out = canonical(projection) + b"\n"
        fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(out)
            stream.flush()
            os.fsync(stream.fileno())
        print(json.dumps({"ok": True, "status": projection["status"]}, separators=(",", ":")))
        return 0
    except (OSError, KeyError, TypeError, ValueError, RecursionError):
        exc = sys.exc_info()[1]
        code = str(exc) if isinstance(exc, ReconciliationError) else "reconciliation_input_invalid"
        print(json.dumps({"ok": False, "error_code": code}, separators=(",", ":")), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
