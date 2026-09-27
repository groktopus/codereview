from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import validate_selected_control_transport_receipt as receipt_validator  # noqa: E402


def _retained_cardinality_arm(transport: str, state: str = "COMPLETE"):
    """Rebuild receipt-only six-exchange data from retained HTTP cardinality evidence.

    Trace metrics are actual from HTTP loopback run 36337385207. Body hashes are
    synthetic repeated-byte bodies at the retained stage lengths. This tests the
    receipt shape and matching logic; it does not establish a TLS comparison.
    """
    if state.startswith("NOT_RUN_"):
        return {"configured_transport": transport, "state": state}
    retained = json.loads(
        (ROOT / "tests/fixtures/retained-cardinality-http-arm-36337385207.json").read_text(encoding="utf-8")
    )
    source = retained["arm"]
    path = source["file_path_attribution"]
    payload_hashes = {}
    for stage in sorted(source["request_body_bytes_by_stage"]):
        req_size = source["request_body_bytes_by_stage"][stage]
        resp_size = source["response_body_bytes_by_stage"][stage]
        req_prefix = b"synthetic-request-" + stage.encode()
        resp_prefix = b"synthetic-response-" + stage.encode()
        payload_hashes[stage] = {
            "request_bytes": req_size,
            "request_sha256": hashlib.sha256(req_prefix + b"x" * (req_size - len(req_prefix))).hexdigest(),
            "response_bytes": resp_size,
            "response_sha256": hashlib.sha256(resp_prefix + b"x" * (resp_size - len(resp_prefix))).hexdigest(),
        }
    task_ids = ["synthetic-task-1", "synthetic-task-2", "synthetic-task-3"]
    trace_path = {
        **path,
        "state_meaning": "numeric_line_and_byte_accounting_complete_unknown_classes_are_valid",
        "path_argument_visibility": {
            "openat": "path_visible_and_lexically_classified",
            "newfstatat": "raw_hex_arguments_path_unavailable",
        },
        "line_bytes": "decoded_utf8_line_bytes_plus_observed_newline_byte",
    }
    return {
        "configured_transport": transport,
        "state": state,
        "trace_attribution": {
            "state": source["state"], "trace_bytes": source["trace_bytes"],
            "newline_terminated_line_bytes": source["trace_newline_terminated_line_bytes"],
            "unattributed_or_partial_bytes": source["trace_unattributed_or_partial_bytes"],
            "parsed_line_count": source["trace_parsed_line_count"],
            "parse_failure_count": source["trace_parse_failure_count"],
            "bytes_by_syscall": source["trace_bytes_by_syscall"],
            "lines_by_syscall": source["trace_lines_by_syscall"],
            "file_path_attribution": trace_path,
        },
        "observer_mode": "LINUX_STRACE",
        "observer_coverage": source["observer_coverage"],
        "observer_reason": source["observer_reason"],
        "protocol_exchange_state": "SERVER_WRITES_SETTLED",
        "protocol_stage_counts": source["protocol_stage_counts"],
        "http_requests_received": source["http_requests_received"],
        "server_response_writes_completed": source["server_response_writes_completed"],
        "fake_server_handlers_settled": True,
        "fake_server_active_handlers_at_snapshot": 0,
        "synthetic_protocol_path_state": "COMPLETE",
        "primary_task_statuses": [
            {"task_id": task_id, **item}
            for task_id, item in zip(task_ids, source["primary_task_statuses"], strict=True)
        ],
        "cli_invocation_status": "CLI_COMPLETED",
        "cli_exit_code": 0,
        "cli_result_present": True,
        "coverage_state": "COMPLETE",
        "claim_assessment_statuses": ["COMPLETE"],
        "native_advisory_status": "RECEIVED",
        "candidate_count": source["candidate_count"],
        "unexpected_task_result_count": 0,
        "transport_payload_hashes": payload_hashes,
        "provider_config_sha256": "a" * 64,
        "decision_config_sha256": "b" * 64,
        "normalized_transport_config_sha256": "c" * 64,
        "run_id": "r1-control",
        "event_mode": "LOCAL_EXPLICIT_BASE_HEAD_NO_GITHUB_EVENT",
        "event_identity": None,
        "task_ids": task_ids,
        "snapshot_id": "snapshot-fixed",
        "snapshot_hash": "f" * 64,
    }


_arm = _retained_cardinality_arm


def _valid_receipt():
    source_modules = {
        "pr_review_harness/" + path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted((ROOT / "src/pr_review_harness").glob("*.py")) if path.is_file()
    }
    return {
        "contract_version": "selected-control-transport-pair.v1",
        "pair_state": "INCOMPLETE",
        "reason": "PAIR_DEADLINE_EXHAUSTED",
        "diagnostic_head_sha": "a" * 40,
        "diagnostic_script_sha256": hashlib.sha256((ROOT / "scripts/selected_control_trace_attribution.py").read_bytes()).hexdigest(),
        "diagnostic_script_differs_from_head": False,
        "runtime_source_commit": "a" * 40,
        "runtime_tree_sha256": "1" * 64,
        "runtime_module_count": 28,
        "runtime_module_hashes": source_modules,
        "fixture_suite_sha256": "2" * 64,
        "generated_profile_sha256": "3" * 64,
        "base_sha": "4" * 40,
        "head_sha": "5" * 40,
        "run_id": "r1-control",
        "event_mode": "LOCAL_EXPLICIT_BASE_HEAD_NO_GITHUB_EVENT",
        "snapshot_id": "snapshot-fixed",
        "snapshot_hash": "f" * 64,
        "task_ids": ["synthetic-task-1", "synthetic-task-2", "synthetic-task-3"],
        "task_lenses": ["correctness", "security", "tests"],
        "observer_id": "linux-strace-syscall-observer.v3",
        "observer_source_sha256": "6" * 64,
        "syscall_scope": ["%process", "%file", "socket", "connect", "bind", "listen", "accept", "accept4", "shutdown"],
        "trace_cap_bytes": 1_048_576,
        "limits": {
            "max_provider_calls": 9, "max_retries_per_task": 0, "max_input_bytes_per_task": 64_000,
            "max_output_bytes_per_task": 32_768, "deadline_seconds": 270, "max_claim_assessments_per_run": 4,
        },
        "observer_timeout_seconds_per_arm": 300,
        "pair_deadline_seconds": 660,
        "primary_response_delay_seconds": 0,
        "tls_ca_sha256": "7" * 64,
        "tls_private_material_in_receipt": False,
        "tls_verification_disabled": False,
        "arms": [_arm("HTTP_LOOPBACK_FAKE"), _arm("HTTPS_LOOPBACK_FAKE", "NOT_RUN_PAIR_DEADLINE")],
        "comparison": None,
        "external_provider_dispatch_requested": False,
        "target_execution_requested": False,
        "quality_or_https_trace_parity_claim": False,
        "live_failure_cause_claim": False,
    }


def _validate(tmp_path, value):
    path = tmp_path / "receipt.json"
    path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")
    return receipt_validator.validate_receipt(path, ROOT, "a" * 40)


def test_receipt_validator_accepts_source_bound_http_trace_and_deadline_skipped_tls(tmp_path):
    assert _validate(tmp_path, _valid_receipt())["pair_state"] == "INCOMPLETE"


def test_receipt_validator_accepts_source_bound_complete_pair(tmp_path):
    row = _valid_receipt()
    row["pair_state"] = "COMPLETE"
    row["reason"] = None
    row["arms"] = [_arm("HTTP_LOOPBACK_FAKE", "COMPLETE"), _arm("HTTPS_LOOPBACK_FAKE", "COMPLETE")]
    row["task_ids"] = row["arms"][0]["task_ids"]
    row["arms"][0]["normalized_transport_config_sha256"] = "c" * 64
    row["arms"][1]["normalized_transport_config_sha256"] = "c" * 64
    trace_bytes = row["arms"][0]["trace_attribution"]["trace_bytes"]
    row["comparison"] = {
        "input_identity_match": True,
        "request_response_body_hashes_match": True,
        "normalized_endpoint_config_match": True,
        "http_trace_bytes": trace_bytes,
        "https_trace_bytes": trace_bytes,
        "trace_bytes_delta_https_minus_http": 0,
        "trace_bytes_by_syscall_delta_https_minus_http": {
            key: 0
            for key in row["arms"][0]["trace_attribution"]["bytes_by_syscall"]
        },
    }
    assert _validate(tmp_path, row)["pair_state"] == "COMPLETE"


@pytest.mark.parametrize("mutation", [
    lambda arm: arm.update(observer_coverage="INCOMPLETE", observer_reason="trace_byte_cap_exceeded"),
    lambda arm: arm.update(primary_task_statuses=[{**task, "status": "INCOMPLETE"} for task in arm["primary_task_statuses"]]),
    lambda arm: arm.update(coverage_state="PARTIAL"),
    lambda arm: arm.update(claim_assessment_statuses=["PARTIAL"]),
    lambda arm: arm.update(native_advisory_status="FAILED"),
    lambda arm: arm.update(cli_result_present=False),
])
def test_complete_pair_rejected_when_actual_completion_criteria_are_incomplete(tmp_path, mutation):
    row = _valid_receipt()
    row["pair_state"] = "COMPLETE"
    row["reason"] = None
    row["arms"] = [_arm("HTTP_LOOPBACK_FAKE", "COMPLETE"), _arm("HTTPS_LOOPBACK_FAKE", "COMPLETE")]
    row["task_ids"] = row["arms"][0]["task_ids"]
    for arm in row["arms"]:
        arm["normalized_transport_config_sha256"] = "c" * 64
    trace_bytes = row["arms"][0]["trace_attribution"]["trace_bytes"]
    row["comparison"] = {
        "input_identity_match": True,
        "request_response_body_hashes_match": True,
        "normalized_endpoint_config_match": True,
        "http_trace_bytes": trace_bytes,
        "https_trace_bytes": trace_bytes,
        "trace_bytes_delta_https_minus_http": 0,
        "trace_bytes_by_syscall_delta_https_minus_http": {
            key: 0 for key in row["arms"][0]["trace_attribution"]["bytes_by_syscall"]
        },
    }
    mutation(row["arms"][0])
    with pytest.raises(ValueError, match="complete_arm_actual_criteria_mismatch"):
        _validate(tmp_path, row)


@pytest.mark.parametrize("mutation", [
    lambda row: row["comparison"].update(request_response_body_hashes_match=False),
    lambda row: row["comparison"].update(input_identity_match=False),
    lambda row: row["comparison"].update(trace_bytes_delta_https_minus_http=1),
    lambda row: row["arms"][1]["transport_payload_hashes"]["native_claim"].update(request_sha256="0" * 64),
    lambda row: row["arms"][1].update(snapshot_hash="0" * 64),
])
def test_receipt_validator_never_accepts_complete_claim_with_mismatched_pair_evidence(tmp_path, mutation):
    row = _valid_receipt()
    row["pair_state"] = "COMPLETE"
    row["reason"] = None
    row["arms"] = [_arm("HTTP_LOOPBACK_FAKE", "COMPLETE"), _arm("HTTPS_LOOPBACK_FAKE", "COMPLETE")]
    row["task_ids"] = row["arms"][0]["task_ids"]
    for arm in row["arms"]:
        arm["normalized_transport_config_sha256"] = "c" * 64
    trace_bytes = row["arms"][0]["trace_attribution"]["trace_bytes"]
    syscall_bytes = row["arms"][0]["trace_attribution"]["bytes_by_syscall"]
    row["comparison"] = {
        "input_identity_match": True,
        "request_response_body_hashes_match": True,
        "normalized_endpoint_config_match": True,
        "http_trace_bytes": trace_bytes,
        "https_trace_bytes": trace_bytes,
        "trace_bytes_delta_https_minus_http": 0,
        "trace_bytes_by_syscall_delta_https_minus_http": {key: 0 for key in syscall_bytes},
    }
    mutation(row)
    with pytest.raises(ValueError):
        _validate(tmp_path, row)


@pytest.mark.parametrize("mutation", [
    lambda row: row.update(unreviewed_field="could contain arbitrary data"),
    lambda row: row.update(runtime_source_commit="b" * 40),
    lambda row: row.update(diagnostic_script_differs_from_head=True),
    lambda row: row["arms"][1].update(secret="unexpected"),
    lambda row: (row["arms"][0].update(state="INCOMPLETE"), row["arms"].__setitem__(1, _arm("HTTPS_LOOPBACK_FAKE", "COMPLETE"))),
])
def test_receipt_validator_rejects_unknown_fields_and_source_or_pair_mismatch(tmp_path, mutation):
    row = _valid_receipt()
    mutation(row)
    with pytest.raises(ValueError):
        _validate(tmp_path, row)


def test_transport_workflow_is_manual_main_only_secretless_and_uploads_one_bounded_receipt():
    workflow = (ROOT / ".github/workflows/selected-control-transport-pair.yml").read_text(encoding="utf-8")
    assert "on:\n  workflow_dispatch:" in workflow
    assert "github.repository == 'groktopus/codereview'" in workflow
    assert "github.ref == 'refs/heads/main'" in workflow
    assert "ARTIFACT_DIR: ${{ runner.temp }}/selected-control-transport-pair" in workflow
    assert 'echo "ARTIFACT_DIR=$ARTIFACT_DIR" >> "$GITHUB_ENV"' in workflow
    assert "secrets." not in workflow and "GITHUB_TOKEN" not in workflow
    assert "--transport-pair" in workflow
    assert "sudo unshare --net --fork" in workflow and "/usr/bin/env -i" in workflow
    assert "validate_selected_control_transport_receipt.py" in workflow
    assert "selected-control-transport-not-observed.v1" in workflow
    assert '"expected_source_sha": expected' in workflow
    assert '"checkout_source_sha": checkout_sha' in workflow
    assert '"installed_runtime_source_sha": expected if' in workflow
    assert '"actual_provider_calls": "UNKNOWN"' in workflow
    assert "PAIR_RECEIPT_MISSING_OR_REJECTED" in workflow
    assert "len(encoded) > 2048" in workflow
    assert "selected-control-transport-pair-${{ github.run_id }}" in workflow
    assert "retention-days: 3" in workflow


def test_not_observed_failure_receipt_is_bounded_and_does_not_infer_provider_calls(tmp_path):
    workflow = (ROOT / ".github/workflows/selected-control-transport-pair.yml").read_text(encoding="utf-8")
    safe_step = workflow.split("      - name: Validate the exact bounded receipt and source identity", 1)[1]
    block = re.search(r"(?ms)python3 - <<'PY'\n(?P<body>.*?)^\s+PY\s*$", safe_step)
    assert block is not None
    source = textwrap.dedent(block.group("body"))
    artifact_dir = tmp_path / "artifact"
    artifact_dir.mkdir(mode=0o700)
    env = {
        **os.environ,
        "SOURCE_SHA": "a" * 40,
        "SOURCE_ROOT": str(tmp_path / "checkout-not-created"),
        "ARTIFACT_DIR": str(artifact_dir),
        "CHECKOUT_OUTCOME": "failure",
        "PYTHON_OUTCOME": "skipped",
        "OBSERVER_OUTCOME": "skipped",
        "RUNTIME_OUTCOME": "skipped",
        "PROBE_OUTCOME": "skipped",
    }
    subprocess.run([sys.executable, "-c", source], check=True, env=env, timeout=5)
    receipt_path = artifact_dir / "transport-pair.json"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    assert receipt == {
        "contract_version": "selected-control-transport-not-observed.v1",
        "state": "NOT_OBSERVED",
        "reason_code": "CHECKOUT_FAILED",
        "expected_source_sha": "a" * 40,
        "checkout_source_sha": None,
        "checkout_source_matches_expected": None,
        "installed_runtime_source_sha": None,
        "probe_step_outcome": "skipped",
        "execution_state": "NOT_STARTED",
        "actual_provider_calls": "UNKNOWN",
    }
    assert receipt_path.stat().st_size <= 2048
