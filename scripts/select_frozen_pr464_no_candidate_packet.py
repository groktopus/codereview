#!/usr/bin/env python3
"""Select one manifest-bound PR-464 no-candidate packet without provider calls."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "src"))

import run_model_only_shadow_audit as shadow_runner  # noqa: E402
from sealed_source_record_integration import _validate_frozen_pr464  # noqa: E402

from pr_review_harness.shadow_audit import _validate_packet  # noqa: E402

SHA256 = re.compile(r"^[0-9a-f]{64}$")


class SelectionError(ValueError):
    """Capture does not prove one frozen PR-464 no-candidate packet."""


def _read_json(path: Path, limit: int = 64_000) -> dict[str, Any]:
    try:
        value, _raw = shadow_runner._read_json(path, limit)
    except (OSError, ValueError, UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        raise SelectionError("selection_input_invalid") from None
    if not isinstance(value, dict):
        raise SelectionError("selection_input_invalid")
    return value


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise SelectionError(code)


def select(
    capture_root: Path,
    plan_path: Path,
    preflight_path: Path,
    writer_receipt_path: Path,
    writer_outcomes_path: Path,
) -> dict[str, Any]:
    """Validate a completed private capture and return a hash-only packet selector."""
    case_id, _policy = shadow_runner.case_for_plan_path(plan_path, ROOT)
    _require(case_id == "PR-464", "selection_case_invalid")
    plan, plan_raw = shadow_runner._read_json(plan_path, 256_000)
    bound_case_id, _ = shadow_runner.validate_plan_binding(plan, plan_raw)
    _require(bound_case_id == "PR-464", "selection_plan_invalid")

    preflight = _read_json(preflight_path)
    plan_sha = hashlib.sha256(plan_raw).hexdigest()
    _require(
        preflight.get("schema") == "model-only-shadow-live-preflight-receipt.v1"
        and preflight.get("status") == "PLAN_MATCHED_PROVIDER_FREE"
        and preflight.get("case_id") == "PR-464"
        and preflight.get("plan_sha256") == plan_sha
        and preflight.get("snapshot_sha256") == plan["case"].get("snapshot_sha256")
        and preflight.get("provider_calls") == 0
        and preflight.get("target_code_execution") is False
        and preflight.get("publication_enabled") is False,
        "selection_preflight_invalid",
    )

    manifest, manifest_raw, packets = shadow_runner._packet_candidates(capture_root)
    _require(manifest.get("snapshot_id") == plan["case"].get("snapshot_id")
             and manifest.get("snapshot_hash") == plan["case"].get("snapshot_sha256"),
             "selection_capture_identity_invalid")
    ordered, _budget = shadow_runner._task_order(
        plan_path, packets, manifest=manifest, include_budget=True
    )
    packet_rows = []
    for row in ordered:
        _candidate_id, _path, packet, packet_raw = row
        try:
            _validate_packet(packet)
            _validate_frozen_pr464(packet)
        except Exception:
            raise SelectionError("selection_packet_identity_invalid") from None
        _require(packet.get("writer_candidate") is None, "selection_candidate_present")
        _require(packet.get("writer_run", {}).get("status") == "completed",
                 "selection_writer_run_incomplete")
        packet_rows.append((row, hashlib.sha256(packet_raw).hexdigest()))

    writer = _read_json(writer_receipt_path)
    outcomes = _read_json(writer_outcomes_path)
    manifest_sha = hashlib.sha256(manifest_raw).hexdigest()
    requests = plan.get("writer_requests")
    _require(isinstance(requests, list) and len(requests) == 10, "selection_plan_requests_invalid")
    expected_tasks = {row["task_id"]: row for row in requests if isinstance(row, dict)}
    expected_task_hashes = {hashlib.sha256(task.encode()).hexdigest() for task in expected_tasks}

    writer_calls = writer.get("calls")
    _require(
        writer.get("schema") == "model-only-shadow-live-writer-receipt.v1"
        and writer.get("status") == "WRITER_TRANSPORT_CAPTURED"
        and writer.get("case_id") == "PR-464"
        and writer.get("plan_sha256") == plan_sha
        and writer.get("snapshot_id") == plan["case"].get("snapshot_id")
        and writer.get("snapshot_sha256") == plan["case"].get("snapshot_sha256")
        and writer.get("writer_call_count") == 10
        and writer.get("audit_or_jev_dispatched") is False
        and writer.get("target_code_execution") is False
        and writer.get("publication_enabled") is False
        and isinstance(writer_calls, list)
        and len(writer_calls) == 10,
        "selection_writer_receipt_invalid",
    )
    observed_calls = {row.get("task_id"): row for row in writer_calls if isinstance(row, dict)}
    _require(set(observed_calls) == set(expected_tasks), "selection_writer_tasks_invalid")
    for task_id, request in expected_tasks.items():
        call = observed_calls[task_id]
        _require(call.get("request_sha256") == request.get("input_sha256")
                 and call.get("request_bytes") == request.get("input_bytes")
                 and isinstance(call.get("response_sha256"), str)
                 and SHA256.fullmatch(call["response_sha256"]) is not None,
                 "selection_writer_request_mismatch")

    outcome_rows = outcomes.get("tasks")
    _require(
        outcomes.get("schema") == "model-only-shadow-live-writer-outcomes.v1"
        and outcomes.get("plan_sha256") == plan_sha
        and outcomes.get("capture_manifest_sha256") == manifest_sha
        and outcomes.get("returned_candidate_count_total") == 0
        and outcomes.get("packet_candidate_count_total") == 0
        and outcomes.get("outcome_counts") == {
            "zero_findings_returned": 10,
            "parse_failure": 0,
            "candidate_reconciliation_or_filtering": 0,
            "candidates_preserved_in_packets": 0,
        }
        and isinstance(outcome_rows, list) and len(outcome_rows) == 10,
        "selection_writer_outcomes_invalid",
    )
    observed_task_hashes = set()
    outcome_by_task_hash = {}
    for row in outcome_rows:
        _require(
            isinstance(row, dict)
            and row.get("outcome") == "zero_findings_returned"
            and row.get("returned_candidate_count") == 0
            and row.get("packet_candidate_count") == 0
            and row.get("candidate_packet_count") == 1,
            "selection_writer_outcome_not_empty",
        )
        observed_task_hashes.add(row.get("task_id_sha256"))
        outcome_by_task_hash[row["task_id_sha256"]] = row
    _require(observed_task_hashes == expected_task_hashes, "selection_outcome_tasks_invalid")

    by_task: dict[str, list[tuple[tuple[str, Path, dict[str, Any], bytes], str]]] = {}
    for row, digest in packet_rows:
        task_id = row[2]["source_task"]["task_id"]
        writer_calls_for_packet = row[2]["writer_run"].get("calls")
        receipt_call = observed_calls[task_id]
        _require(
            isinstance(writer_calls_for_packet, list) and len(writer_calls_for_packet) == 1
            and writer_calls_for_packet[0].get("request_sha256") == receipt_call["request_sha256"]
            and writer_calls_for_packet[0].get("response_sha256") == receipt_call["response_sha256"],
            "selection_packet_writer_call_mismatch",
        )
        task_hash = hashlib.sha256(task_id.encode("utf-8")).hexdigest()
        _require(
            outcome_by_task_hash[task_hash].get("response_sha256") == receipt_call["response_sha256"],
            "selection_outcome_response_mismatch",
        )
        by_task.setdefault(task_id, []).append((row, digest))
    _require(set(by_task) == set(expected_tasks), "selection_packet_task_coverage_invalid")
    _require(all(len(rows) == 1 for rows in by_task.values()), "selection_packet_cardinality_invalid")

    selected, selected_sha = packet_rows[0]
    selected_path = selected[1]
    return {
        "schema": "frozen-pr464-no-candidate-selection.v1",
        "case_id": "PR-464",
        "packet_path": f"case-packets/{selected_path.name}",
        "selected_packet_sha256": selected_sha,
        "capture_manifest_sha256": manifest_sha,
        "plan_sha256": plan_sha,
        "snapshot_sha256": plan["case"]["snapshot_sha256"],
        "selected_task_sha256": hashlib.sha256(
            selected[2]["source_task"]["task_id"].encode("utf-8")
        ).hexdigest(),
        "writer_calls": 10,
        "audit_provider_calls": 0,
        "publication_enabled": False,
        "target_code_execution": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture-root", type=Path, required=True)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--preflight", type=Path, required=True)
    parser.add_argument("--writer-receipt", type=Path, required=True)
    parser.add_argument("--writer-outcomes", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = select(args.capture_root, args.plan, args.preflight,
                        args.writer_receipt, args.writer_outcomes)
    except (OSError, KeyError, TypeError, ValueError, RecursionError) as exc:
        code = str(exc) if isinstance(exc, SelectionError) else "selection_input_invalid"
        print(json.dumps({"ok": False, "error_code": code}, separators=(",", ":")), file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
