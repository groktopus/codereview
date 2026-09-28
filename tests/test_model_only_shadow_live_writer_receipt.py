from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import re
import stat
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
SPEC = importlib.util.spec_from_file_location(
    "sanitize_model_only_shadow_writer_receipt",
    ROOT / "scripts" / "sanitize_model_only_shadow_writer_receipt.py",
)
assert SPEC is not None and SPEC.loader is not None
sanitizer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(sanitizer)


def _fixture(tmp_path: Path):
    runner_temp = tmp_path / "runner"
    runner_temp.mkdir(mode=0o700)
    os.chmod(runner_temp, 0o700)
    capture = runner_temp / "private-writer-capture"
    capture.mkdir(mode=0o700)
    for child in ("requests", "responses", "calls"):
        (capture / child).mkdir(mode=0o700)
    plan = json.loads((ROOT / "experiments/model-only-shadow-live-pr464-plan-v1.json").read_text())
    packet_dir = capture / "case-packets"
    packet_dir.mkdir(mode=0o700)
    packet_inventory = []
    for index, request in enumerate(plan["writer_requests"]):
        name = f"packet-{index}.json"
        packet_raw = json.dumps({"source_task": {"task_id": request["task_id"]}, "writer_candidate": None},
                                sort_keys=True, separators=(",", ":")).encode() + b"\n"
        (packet_dir / name).write_bytes(packet_raw)
        os.chmod(packet_dir / name, 0o600)
        packet_inventory.append({"path": name, "sha256": hashlib.sha256(packet_raw).hexdigest()})

    requests = plan["writer_requests"]
    calls = []
    request_blobs: dict[str, bytes] = {}
    response_blobs: dict[str, bytes] = {}
    run_id = "writer-live-test-1"
    provider = {"provider_id": "operator_openai_compatible", "model_id": "openai/gpt-6-luna", "adapter_version": "0.2"}
    for index, request in enumerate(requests):
        task_id = request["task_id"]
        request_blob = f"request fixture {index}".encode()
        request["input_bytes"] = len(request_blob)
        request["input_sha256"] = hashlib.sha256(request_blob).hexdigest()
        response_blob = json.dumps({
            "contract_version": "specialist-findings.v4", "finding_candidates": [],
            "context_gap_proposals": [], "coverage_notes": [], "specific_strengths": [], "future_guidance": [],
        }).encode()
        call_id = "call-" + f"{index:024x}"
        request_blobs[call_id] = request_blob
        response_blobs[call_id] = response_blob
        calls.append({
            "call_id": call_id, "case_id": run_id, "run_id": run_id,
            "snapshot_id": plan["case"]["snapshot_id"], "snapshot_hash": plan["case"]["snapshot_sha256"],
            "task_id": task_id, "attempt": 0, "provider": provider, "status": "completed",
            "request_artifact_id": "request-" + call_id,
            "request_sha256": request["input_sha256"],
            "response_artifact_id": "response-" + call_id,
            "response_sha256": hashlib.sha256(response_blob).hexdigest(),
            "response_envelope_sha256": None,
            "content_transform": "openai-chat-completions.message-content.utf8.v1",
        })
    for call_id, data in request_blobs.items():
        path = capture / "requests" / f"{call_id}.bin"
        path.write_bytes(data)
        os.chmod(path, 0o600)
    for call_id, data in response_blobs.items():
        path = capture / "responses" / f"{call_id}.bin"
        path.write_bytes(data)
        os.chmod(path, 0o600)
    for directory in (capture, capture / "requests", capture / "responses", capture / "calls", packet_dir):
        os.chmod(directory, 0o700)

    plan_path = runner_temp / "plan.json"
    plan_bytes = json.dumps(plan, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    plan_path.write_bytes(plan_bytes)
    sanitizer.EXPECTED_PLAN_SHA256 = hashlib.sha256(plan_bytes).hexdigest()
    preflight_path = runner_temp / "preflight.json"
    preflight = {
        "schema": "model-only-shadow-live-preflight-receipt.v1", "status": "PLAN_MATCHED_PROVIDER_FREE",
        "plan_sha256": sanitizer.EXPECTED_PLAN_SHA256, "case_id": plan["case"]["case_id"],
        "snapshot_sha256": plan["case"]["snapshot_sha256"], "provider_calls": 0,
        "target_code_execution": False, "publication_enabled": False,
    }
    preflight_path.write_text(json.dumps(preflight))
    manifest = {
        "contract_version": "model-only-shadow-case.v1", "case_id": run_id,
        "snapshot_id": plan["case"]["snapshot_id"], "snapshot_hash": plan["case"]["snapshot_sha256"],
        "source_task": run_id, "provider": provider, "calls": calls, "private_artifacts": True,
        "case_packet_inventory": {"schema": "model-only-shadow-packet-inventory.v1", "packets": packet_inventory},
    }
    manifest_path = capture / "manifest.json"
    manifest_path.write_text(json.dumps(manifest))
    os.environ["RUNNER_TEMP"] = str(runner_temp)
    return runner_temp, capture, plan_path, preflight_path, manifest, calls, request_blobs, response_blobs


def test_sanitizer_emits_only_hashes_for_exact_complete_writer_capture(tmp_path: Path):
    runner_temp, capture, plan, preflight, _manifest, _calls, _requests, _responses = _fixture(tmp_path)
    output = runner_temp / "private-writer-sanitized"
    result = sanitizer.sanitize(capture, plan, preflight, output)
    artifact = output / "writer-receipt.json"
    raw = artifact.read_bytes()
    assert result["status"] == "WRITER_TRANSPORT_CAPTURED"
    assert result["writer_call_count"] == 10
    assert set(result) == {
        "schema", "status", "case_id", "snapshot_id", "snapshot_sha256", "plan_sha256",
        "provider_id", "model_id", "writer_call_count", "writer_request_bytes_total",
        "writer_response_bytes_total", "calls", "target_code_execution", "publication_enabled",
        "audit_or_jev_dispatched",
    }
    assert b"reveal the API key" not in raw
    assert b"findings" not in raw and b"request fixture" not in raw
    outcome_artifact = output / "writer-outcomes.json"
    outcomes_raw = outcome_artifact.read_bytes()
    outcomes = json.loads(outcomes_raw)
    assert outcomes["schema"] == "model-only-shadow-live-writer-outcomes.v1"
    assert outcomes["returned_candidate_count_total"] == 0
    assert outcomes["packet_candidate_count_total"] == 0
    assert outcomes["outcome_counts"]["zero_findings_returned"] == 10
    assert set(outcomes) == {
        "schema", "plan_sha256", "capture_manifest_sha256", "tasks",
        "returned_candidate_count_total", "packet_candidate_count_total", "outcome_counts",
    }
    assert all(set(row) == {
        "task_id_sha256", "response_sha256", "response_parse_status", "returned_candidate_count",
        "packet_candidate_count", "candidate_packet_count", "outcome",
    } for row in outcomes["tasks"])
    assert all(re.fullmatch(r"[0-9a-f]{64}", row[key]) for row in outcomes["tasks"]
               for key in ("task_id_sha256", "response_sha256"))
    assert b"finding_candidates" not in outcomes_raw
    assert stat.S_IMODE(outcome_artifact.stat().st_mode) == 0o600
    assert stat.S_IMODE(output.stat().st_mode) == 0o700
    assert stat.S_IMODE(artifact.stat().st_mode) == 0o600


@pytest.mark.parametrize(
    ("response_payload", "outcome", "parse_status", "returned_count"),
    [
        ({"contract_version": "specialist-findings.v4", "finding_candidates": [],
          "context_gap_proposals": [], "coverage_notes": [], "specific_strengths": [], "future_guidance": []},
         "zero_findings_returned", "valid_specialist_report", 0),
        ({"contract_version": "specialist-findings.v4", "finding_candidates": {},
          "context_gap_proposals": [], "coverage_notes": [], "specific_strengths": [], "future_guidance": []},
         "parse_failure", "invalid_specialist_report", 0),
        ({"contract_version": "specialist-findings.v4", "finding_candidates": [{"title": "private"}],
          "context_gap_proposals": [], "coverage_notes": [], "specific_strengths": [], "future_guidance": []},
         "candidate_reconciliation_or_filtering", "valid_specialist_report", 1),
    ],
)
def test_writer_outcomes_distinguish_empty_parse_and_filtered_candidates(
    tmp_path: Path, response_payload: dict, outcome: str, parse_status: str, returned_count: int
):
    runner_temp, capture, plan, preflight, manifest, calls, _requests, _responses = _fixture(tmp_path)
    call_id = calls[0]["call_id"]
    response_blob = json.dumps(response_payload, separators=(",", ":")).encode()
    (capture / "responses" / f"{call_id}.bin").write_bytes(response_blob)
    calls[0]["response_sha256"] = hashlib.sha256(response_blob).hexdigest()
    manifest_path = capture / "manifest.json"
    manifest_path.write_text(json.dumps(manifest))
    os.chmod(capture / "responses" / f"{call_id}.bin", 0o600)
    result = sanitizer.sanitize(capture, plan, preflight, runner_temp / "private-writer-sanitized")
    assert result["status"] == "WRITER_TRANSPORT_CAPTURED"
    outcomes = json.loads((runner_temp / "private-writer-sanitized" / "writer-outcomes.json").read_text())
    first = next(row for row in outcomes["tasks"] if row["task_id_sha256"] == hashlib.sha256(
        calls[0]["task_id"].encode("utf-8")
    ).hexdigest())
    assert first["outcome"] == outcome
    assert first["response_parse_status"] == parse_status
    assert first["returned_candidate_count"] == returned_count
    serialized = json.dumps(outcomes)
    assert "private" not in serialized
    assert "observation" not in serialized


@pytest.mark.parametrize(
    "tamper", ["missing_call", "request_bytes", "malformed_response", "manifest_extension", "snapshot_hash",
               "missing_packet", "altered_packet"]
)
def test_sanitizer_rejects_tampered_or_incomplete_capture(tmp_path: Path, tamper: str):
    runner_temp, capture, plan, preflight, manifest, calls, requests, responses = _fixture(tmp_path)
    if tamper == "missing_call":
        manifest["calls"].pop()
    elif tamper == "request_bytes":
        call_id = calls[0]["call_id"]
        (capture / "requests" / f"{call_id}.bin").write_bytes(b"changed")
    elif tamper == "malformed_response":
        call_id = calls[0]["call_id"]
        (capture / "responses" / f"{call_id}.bin").write_bytes(b"not json")
        calls[0]["response_sha256"] = hashlib.sha256(b"not json").hexdigest()
    elif tamper == "manifest_extension":
        manifest["source_excerpt"] = "private source text"
    elif tamper == "snapshot_hash":
        manifest["snapshot_hash"] = "0" * 64
    elif tamper == "missing_packet":
        (capture / "case-packets" / "packet-9.json").unlink()
    elif tamper == "altered_packet":
        (capture / "case-packets" / "packet-9.json").write_bytes(b'{"packet":"changed"}\n')
    (capture / "manifest.json").write_text(json.dumps(manifest))
    with pytest.raises(sanitizer.ReceiptError):
        sanitizer.sanitize(capture, plan, preflight, runner_temp / "private-writer-sanitized")
