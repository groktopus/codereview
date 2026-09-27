from __future__ import annotations

import ast
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
    assert "selected-control-transport-not-observed.v2" in workflow
    assert '"expected_source_sha": expected' in workflow
    assert '"checkout_source_sha": checkout_sha' in workflow
    assert '"installed_runtime_source_sha": expected if' in workflow
    assert '"actual_provider_calls": "UNKNOWN"' in workflow
    assert "PAIR_RECEIPT_REJECTED" in workflow
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
        "GITHUB_OUTPUT": str(tmp_path / "github-output"),
        "CHECKOUT_OUTCOME": "failure",
        "PYTHON_OUTCOME": "skipped",
        "OBSERVER_OUTCOME": "skipped",
        "RUNTIME_OUTCOME": "skipped",
        "PROBE_OUTCOME": "skipped",
        "VALIDATION_EXIT_CODE": "1",
    }
    (artifact_dir / "validation-status.json").write_text(json.dumps({
        "contract_version": "transport-receipt-validation.v1",
        "status": "REJECTED",
        "rejection_code": "receipt_file_invalid",
    }), encoding="utf-8")
    subprocess.run([sys.executable, "-c", source], check=True, env=env, timeout=5)
    receipt_path = artifact_dir / "transport-pair.json"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    assert receipt == {
        "contract_version": "selected-control-transport-not-observed.v2",
        "state": "NOT_OBSERVED",
        "reason_code": "CHECKOUT_FAILED",
        "validator_rejection_code": None,
        "expected_source_sha": "a" * 40,
        "checkout_source_sha": None,
        "checkout_source_matches_expected": None,
        "installed_runtime_source_sha": None,
        "probe_step_outcome": "skipped",
        "execution_state": "NOT_STARTED",
        "actual_provider_calls": "UNKNOWN",
    }
    assert receipt_path.stat().st_size <= 2048


def _run_safe_step(tmp_path, status_bytes, *, validation_exit="1", probe_outcome="success"):
    workflow = (ROOT / ".github/workflows/selected-control-transport-pair.yml").read_text(encoding="utf-8")
    safe_step = workflow.split("      - name: Validate the exact bounded receipt and source identity", 1)[1]
    block = re.search(r"(?ms)python3 - <<'PY'\n(?P<body>.*?)^\s+PY\s*$", safe_step)
    assert block is not None
    source = textwrap.dedent(block.group("body"))
    artifact_dir = tmp_path / "artifact"
    artifact_dir.mkdir(mode=0o700)
    (artifact_dir / "validation-status.json").write_bytes(status_bytes)
    output_file = tmp_path / "github-output"
    env = {
        **os.environ,
        "SOURCE_SHA": "a" * 40,
        "SOURCE_ROOT": str(tmp_path / "checkout-not-created"),
        "ARTIFACT_DIR": str(artifact_dir),
        "GITHUB_OUTPUT": str(output_file),
        "CHECKOUT_OUTCOME": "success",
        "PYTHON_OUTCOME": "success",
        "OBSERVER_OUTCOME": "success",
        "RUNTIME_OUTCOME": "success",
        "PROBE_OUTCOME": probe_outcome,
        "VALIDATION_EXIT_CODE": validation_exit,
    }
    completed = subprocess.run([sys.executable, "-c", source], env=env, capture_output=True, timeout=5)
    output = output_file.read_text(encoding="utf-8") if output_file.exists() else ""
    receipt_path = artifact_dir / "transport-pair.json"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8")) if receipt_path.exists() else None
    return completed, output, receipt, artifact_dir


def test_successful_probe_with_typed_validator_rejection_writes_safe_fallback_and_denies_acceptance(tmp_path):
    status = {
        "contract_version": "transport-receipt-validation.v1",
        "status": "REJECTED",
        "rejection_code": "receipt_source_identity_mismatch",
    }
    completed, outputs, receipt, artifact_dir = _run_safe_step(
        tmp_path, json.dumps(status).encode(), validation_exit="1"
    )
    assert completed.returncode == 0
    assert outputs.splitlines() == ["safe=true", "accepted=false"]
    assert receipt["contract_version"] == "selected-control-transport-not-observed.v2"
    assert receipt["state"] == "NOT_OBSERVED"
    assert receipt["reason_code"] == "PAIR_RECEIPT_REJECTED"
    assert receipt["validator_rejection_code"] == "receipt_source_identity_mismatch"
    assert receipt["actual_provider_calls"] == "UNKNOWN"
    assert len(list(artifact_dir.glob("transport-pair.json"))) == 1


def test_arbitrary_validator_output_is_unknown_and_never_copied_into_fallback(tmp_path):
    secretish = "raw-provider-or-secret-value-must-not-survive"
    completed, outputs, receipt, artifact_dir = _run_safe_step(
        tmp_path, f"validator said {secretish}".encode(), validation_exit="1"
    )
    assert completed.returncode == 0
    assert outputs.splitlines() == ["safe=true", "accepted=false"]
    assert receipt["reason_code"] == "VALIDATOR_OUTPUT_UNKNOWN"
    assert receipt["validator_rejection_code"] is None
    assert secretish.encode() not in (artifact_dir / "transport-pair.json").read_bytes()


def test_only_accepted_diagnostic_and_successful_probe_can_mark_receipt_accepted(tmp_path):
    status = {
        "contract_version": "transport-receipt-validation.v1",
        "status": "ACCEPTED",
        "rejection_code": None,
    }
    completed, outputs, receipt, _ = _run_safe_step(
        tmp_path, json.dumps(status).encode(), validation_exit="0"
    )
    assert completed.returncode == 0
    assert outputs.splitlines() == ["safe=true", "accepted=true"]
    assert receipt is None


def test_validator_machine_diagnostic_is_finite_and_legacy_stdout_stays_generic(tmp_path, capsys):
    row = _valid_receipt()
    row["diagnostic_head_sha"] = "b" * 40
    path = tmp_path / "receipt.json"
    path.write_text(json.dumps(row), encoding="utf-8")
    args = [str(path), "--source-root", str(ROOT), "--expected-sha", "a" * 40, "--diagnostic-json"]
    assert receipt_validator.main(args) == 1
    assert json.loads(capsys.readouterr().out) == {
        "contract_version": "transport-receipt-validation.v1",
        "status": "REJECTED",
        "rejection_code": "receipt_source_identity_mismatch",
    }
    assert receipt_validator.main(args[:-1]) == 1
    assert capsys.readouterr().out.strip() == "transport_receipt_rejected"


def test_unknown_validator_exception_is_sanitized_in_machine_diagnostic(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(
        receipt_validator, "validate_receipt",
        lambda *_args: (_ for _ in ()).throw(ValueError("sensitive exception payload")),
    )
    assert receipt_validator.main([
        str(tmp_path / "unused"), "--source-root", str(ROOT), "--expected-sha", "a" * 40,
        "--diagnostic-json",
    ]) == 1
    emitted = capsys.readouterr().out
    assert "sensitive" not in emitted
    assert json.loads(emitted)["rejection_code"] == "validator_internal_unknown"


@pytest.mark.parametrize(
    "code",
    [
        "trace_fields_invalid",
        "arm_stage_fields_invalid",
        "arm_task_fields_invalid",
        "arm_payload_stages_invalid",
    ],
)
def test_fixed_validator_codes_survive_bounded_diagnostic(monkeypatch, tmp_path, code):
    monkeypatch.setattr(
        receipt_validator,
        "validate_receipt",
        lambda *_args: (_ for _ in ()).throw(ValueError(code)),
    )

    result = receipt_validator._validation_diagnostic(tmp_path / "unused", ROOT, "a" * 40)

    assert result == {
        "contract_version": "transport-receipt-validation.v1",
        "status": "REJECTED",
        "rejection_code": code,
    }


def test_every_literal_validator_rejection_code_is_in_the_closed_diagnostic_allowlist():
    source = (ROOT / "scripts/validate_selected_control_transport_receipt.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    fixed_codes = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Raise) and isinstance(node.exc, ast.Call):
            if (
                isinstance(node.exc.func, ast.Name)
                and node.exc.func.id == "ValueError"
                and node.exc.args
                and isinstance(node.exc.args[0], ast.Constant)
                and isinstance(node.exc.args[0].value, str)
            ):
                fixed_codes.add(node.exc.args[0].value)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            code_arg = 2 if node.func.id == "_keys" else 1 if node.func.id == "_hash" else None
            if (
                code_arg is not None
                and len(node.args) > code_arg
                and isinstance(node.args[code_arg], ast.Constant)
                and isinstance(node.args[code_arg].value, str)
            ):
                fixed_codes.add(node.args[code_arg].value)

    assert fixed_codes <= receipt_validator.VALIDATION_DIAGNOSTIC_CODES


@pytest.mark.skipif(
    os.environ.get("RUN_INSTALLED_LOOPBACK_TRANSPORT_VALIDATOR_TEST") != "1",
    reason="requires a separately opted-in Linux installed-CLI loopback pair run",
)
def test_actual_installed_cli_transport_emitter_roundtrips_through_strict_validator(tmp_path):
    import shutil

    assert sys.platform.startswith("linux"), "opt-in transport roundtrip must run on Linux"
    assert shutil.which("strace"), "opt-in transport roundtrip requires the installed Linux observer"
    cli = shutil.which("pr-review")
    assert cli, "opt-in transport roundtrip requires the installed wheel entrypoint"
    venv_bin = Path(os.environ["ROUNDTRIP_ENV"]) / "bin"
    assert Path(cli).resolve().parent == venv_bin.resolve(), "transport probe must use the built-wheel CLI"
    script = ROOT / "scripts/selected_control_trace_attribution.py"
    completed = subprocess.run(
        [sys.executable, str(script), "--cli", cli, "--workdir", str(tmp_path), "--transport-pair"],
        capture_output=True, timeout=660, check=False,
    )
    emitted = json.loads(completed.stdout)
    assert emitted.get("contract_version") == "selected-control-transport-pair.v1"
    assert emitted.get("pair_state") in {"COMPLETE", "INCOMPLETE"}
    source_identity = subprocess.run(
        ["git", "-C", str(ROOT), "rev-parse", "HEAD"],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        timeout=3, check=True,
    ).stdout.decode("ascii").strip()
    assert re.fullmatch(r"[0-9a-f]{40}", source_identity)
    assert emitted.get("diagnostic_head_sha") == source_identity
    receipt_path = tmp_path / "transport-pair.json"
    receipt_path.write_bytes(completed.stdout)
    validation = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/validate_selected_control_transport_receipt.py"),
            str(receipt_path), "--source-root", str(ROOT), "--expected-sha",
            source_identity, "--diagnostic-json",
        ],
        capture_output=True, timeout=5, check=False,
    )
    assert len(validation.stdout) <= 512
    result = json.loads(validation.stdout)
    assert result == {
        "contract_version": "transport-receipt-validation.v1",
        "status": "ACCEPTED",
        "rejection_code": None,
    }, result.get("rejection_code")
    assert validation.returncode == 0
    assert completed.returncode == (0 if emitted["pair_state"] == "COMPLETE" else 2)


def test_workflow_always_uploads_safe_fallback_then_fails_when_receipt_was_rejected():
    workflow = (ROOT / ".github/workflows/selected-control-transport-pair.yml").read_text(encoding="utf-8")
    upload_index = workflow.index("- name: Upload only the source-bound bounded receipt")
    gate_index = workflow.index("- name: Require a strictly accepted transport receipt")
    upload_block = workflow[upload_index:gate_index]
    gate_block = workflow[gate_index:]
    assert "if: always() && steps.safe.outputs.safe == 'true'" in upload_block
    assert "if: always()" in gate_block
    assert "RECEIPT_ACCEPTED" in gate_block and 'exit 1' in gate_block
    assert "PAIR_RECEIPT_REJECTED" in workflow and "VALIDATOR_OUTPUT_UNKNOWN" in workflow
    script = re.search(r"(?ms)        run: \|\n(?P<body>.*)$", gate_block)
    assert script is not None
    completed = subprocess.run(
        ["bash", "-c", textwrap.dedent(script.group("body"))],
        env={**os.environ, "RECEIPT_ACCEPTED": "false"}, capture_output=True, timeout=5,
    )
    assert completed.returncode == 1


def test_workflow_reason_codes_match_the_validator_closed_allowlist():
    workflow = (ROOT / ".github/workflows/selected-control-transport-pair.yml").read_text(encoding="utf-8")
    safe_step = workflow.split("      - name: Validate the exact bounded receipt and source identity", 1)[1]
    block = re.search(r"(?ms)python3 - <<'PY'\n(?P<body>.*?)^\s+PY\s*$", safe_step)
    assert block is not None
    tree = ast.parse(textwrap.dedent(block.group("body")))
    assignment = next(
        node for node in tree.body
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == "validation_codes" for target in node.targets
        )
    )
    workflow_codes = ast.literal_eval(assignment.value)
    assert workflow_codes == receipt_validator.VALIDATION_DIAGNOSTIC_CODES | {
        "receipt_json_invalid", "receipt_encoding_invalid", "receipt_io_error",
        "validator_internal_unknown",
    }


def test_secretless_ci_runs_opt_in_roundtrip_against_the_built_wheel():
    workflow = (ROOT / ".github/workflows/test.yml").read_text(encoding="utf-8")
    job = workflow.split("  transport-receipt-roundtrip:", 1)[1]
    assert "needs: build" in job
    assert "runs-on: ubuntu-latest" in job
    assert "sudo apt-get install --yes strace" in job
    assert "actions/download-artifact" in job and "pr-review-distributions" in job
    assert 'pip install "$ROUNDTRIP_DIST"/*.whl pytest' in job
    assert "RUN_INSTALLED_LOOPBACK_TRANSPORT_VALIDATOR_TEST: '1'" in job
    assert "tests/test_selected_control_transport_receipt.py::test_actual_installed_cli_transport_emitter_roundtrips_through_strict_validator" in job
    assert "secrets." not in job and "GITHUB_TOKEN" not in job
