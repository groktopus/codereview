from __future__ import annotations

import importlib.util
import json
import os
import stat
import subprocess
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
WORKFLOW = ROOT / ".github/workflows/private-shadow-capture.yml"
_SPEC = importlib.util.spec_from_file_location(
    "shadow_workflow_status", ROOT / "scripts/sanitize_model_only_shadow_workflow_status.py"
)
assert _SPEC is not None and _SPEC.loader is not None
STATUS = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(STATUS)
EXPECTED_STAGES = {
    "trusted_checkout", "trusted_identity", "case_selection", "exact_preflight",
    "provider_identity", "writer", "writer_sanitize", "audit_config", "shadow_audit",
    "audit_sanitize", "writer_artifact_upload", "audit_artifact_upload",
}


def _env(**values: str) -> dict[str, str]:
    env = {
        "STATUS_CASE_ID": "PR-457", "STATUS_RUN_ID": "12345",
        "STATUS_RUN_ATTEMPT": "2", "STATUS_JOB": "failure",
    }
    env.update({f"STATUS_{key.upper()}": value for key, value in values.items()})
    return env


def test_status_projection_handles_missing_and_unrecognized_values_fail_closed():
    receipt = STATUS.build_receipt({})
    assert receipt["case_id"] == "unknown"
    assert receipt["run_id"] == receipt["run_attempt"] == "unknown"
    assert receipt["job_status_at_projection"] == "unknown"
    assert set(receipt["stages"]) == EXPECTED_STAGES
    assert set(receipt["stages"].values()) == {"unknown"}
    assert receipt["writer_call_state"] == receipt["audit_call_state"] == "unknown"

    hostile = STATUS.build_receipt(_env(case_id="PR-999", writer="success", writer_sanitize="", job="secret"))
    assert hostile["case_id"] == "unknown"
    assert hostile["stages"]["writer"] == "success"
    assert hostile["stages"]["writer_sanitize"] == "unknown"
    assert hostile["job_status_at_projection"] == "unknown"
    assert hostile["writer_call_state"] == "unknown"


@pytest.mark.parametrize(("writer", "writer_sanitize", "upload", "expected"), [
    ("skipped", "skipped", "skipped", "not_started"),
    ("failure", "skipped", "skipped", "unknown"),
    ("success", "unknown", "skipped", "unknown"),
    ("success", "success", "failure", "unknown"),
    ("success", "success", "skipped", "unknown"),
    ("success", "success", "success", "accounted_by_sanitized_receipt"),
])
def test_writer_call_state_requires_sanitization_and_successful_upload(writer, writer_sanitize, upload, expected):
    receipt = STATUS.build_receipt(_env(
        writer=writer, writer_sanitize=writer_sanitize, writer_artifact_upload=upload,
    ))
    assert receipt["writer_call_state"] == expected


def test_audit_call_state_requires_a_sanitized_receipt_or_proves_it_never_started():
    skipped = STATUS.build_receipt(_env(shadow_audit="skipped", audit_sanitize="skipped"))
    assert skipped["audit_call_state"] == "not_started"
    failed = STATUS.build_receipt(_env(shadow_audit="failure", audit_sanitize="skipped"))
    assert failed["audit_call_state"] == "unknown"
    missing_upload = STATUS.build_receipt(_env(
        shadow_audit="failure", audit_sanitize="success", audit_artifact_upload="skipped",
    ))
    assert missing_upload["audit_call_state"] == "unknown"
    recorded = STATUS.build_receipt(_env(
        shadow_audit="failure", audit_sanitize="success", audit_artifact_upload="success",
    ))
    assert recorded["audit_call_state"] == "accounted_by_sanitized_receipt"


def test_trusted_projection_records_every_stage_when_outcomes_are_present():
    env = _env(**{name: "success" for name in (
        "trusted_checkout", "trusted_identity", "case_selection", "exact_preflight",
        "provider_identity", "writer", "writer_sanitize", "audit_config", "shadow_audit",
        "audit_sanitize", "writer_artifact_upload", "audit_artifact_upload",
    )})
    receipt = STATUS.build_receipt(env)
    assert receipt["projection_mode"] == "trusted_projector"
    assert set(receipt["stages"]) == EXPECTED_STAGES
    assert set(receipt["stages"].values()) == {"success"}
    assert receipt["writer_call_state"] == receipt["audit_call_state"] == "accounted_by_sanitized_receipt"


def test_status_case_binding_uses_the_selected_case_and_real_selection_step():
    text = WORKFLOW.read_text(encoding="utf-8")
    status = text.split("- name: Record bounded workflow status for incomplete runs", 1)[1].split(
        "- name: Upload only the bounded workflow status receipt", 1
    )[0]
    live = text.split("  live_writer:", 1)[1]
    assert "STATUS_CASE_ID: ${{ steps.case.outputs.case_id }}" in status
    assert "STATUS_CASE_SELECTION: ${{ steps.case.outcome }}" in status
    assert "id: case" in live
    assert "case_selection" in STATUS.STAGE_ENV
    for case_id in ("PR-457", "PR-464"):
        receipt = STATUS.build_receipt({
            "STATUS_CASE_ID": case_id, "STATUS_CASE_SELECTION": "success",
        })
        assert receipt["case_id"] == case_id
        assert receipt["stages"]["case_selection"] == "success"


def test_trusted_step_ids_belong_to_live_writer_status_scope():
    text = WORKFLOW.read_text(encoding="utf-8")
    prepare = text.split("  prepare:", 1)[1].split("  live_writer:", 1)[0]
    live = text.split("  live_writer:", 1)[1]
    assert "id: trusted-checkout" not in prepare
    assert "id: trusted-identity" not in prepare
    assert "id: trusted-checkout" in live
    assert "id: trusted-identity" in live


def test_status_file_is_private_and_written_only_to_the_fixed_runner_temp_location(tmp_path, monkeypatch):
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    output = tmp_path / "private-shadow-status" / "workflow-status.json"
    assert STATUS.main(["--output", str(output)]) == 0
    assert stat.S_IMODE(output.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    receipt = json.loads(output.read_text(encoding="utf-8"))
    assert receipt["schema"] == STATUS.SCHEMA
    assert STATUS.main(["--output", str(output)]) == 2

    bad = tmp_path / "elsewhere" / "workflow-status.json"
    assert STATUS.main(["--output", str(bad)]) == 2


def test_status_projector_refuses_preexisting_symlink_directory(tmp_path, monkeypatch):
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    external = tmp_path / "external"
    external.mkdir()
    (tmp_path / "private-shadow-status").symlink_to(external, target_is_directory=True)
    output = tmp_path / "private-shadow-status" / "workflow-status.json"
    assert STATUS.main(["--output", str(output)]) == 2
    assert not (external / "workflow-status.json").exists()


def test_workflow_status_is_a_separate_always_artifact_and_preserves_receipt_gates():
    text = WORKFLOW.read_text(encoding="utf-8")
    status = text.split("- name: Record bounded workflow status for incomplete runs", 1)[1].split(
        "- name: Upload only the bounded workflow status receipt", 1
    )[0]
    upload = text.split("- name: Upload only the bounded workflow status receipt", 1)[1].split(
        "- name: Remove private live-writer workspace", 1
    )[0]
    assert "if: always()" in status
    assert "sanitize_model_only_shadow_workflow_status.py" in status
    assert "projection_mode\": \"conservative_fallback\"" in status
    assert '"writer_call_state": "unknown"' in status
    assert '"audit_call_state": "unknown"' in status
    assert "if: always() && steps.workflow-status.outputs.validated == 'true'" in upload
    assert "private-shadow-workflow-status-${{ github.run_id }}-${{ github.run_attempt }}" in upload
    assert "writer-sanitize.outputs.validated == 'true'" in text
    assert "audit-sanitize.outputs.validated == 'true'" in text
    assert '"private-shadow-status"' in text.split("Remove private live-writer workspace", 1)[1]
    assert "${{ secrets." not in status and "writer-result.json" not in upload
    assert '"job_status_at_projection"' in status


def test_checkout_failure_uses_conservative_inline_fallback(tmp_path):
    text = WORKFLOW.read_text(encoding="utf-8")
    status_step = text.split("- name: Record bounded workflow status for incomplete runs", 1)[1].split(
        "- name: Upload only the bounded workflow status receipt", 1
    )[0]
    run_block = status_step.split("        run: |\n", 1)[1]
    run_block = run_block.split("\n      - name:", 1)[0]
    script = textwrap.dedent(run_block)
    env = {
        **os.environ,
        "RUNNER_TEMP": str(tmp_path),
        "GITHUB_OUTPUT": str(tmp_path / "github-output"),
        "STATUS_CASE_ID": "PR-457", "STATUS_RUN_ID": "9", "STATUS_RUN_ATTEMPT": "1",
        "STATUS_JOB": "failure", "STATUS_TRUSTED_CHECKOUT": "failure",
        "STATUS_TRUSTED_IDENTITY": "skipped", "STATUS_WRITER": "",
    }
    result = subprocess.run(["bash", "-e", "-u", "-o", "pipefail", "-c", script], env=env, check=False)
    assert result.returncode == 0
    receipt_path = tmp_path / "private-shadow-status" / "workflow-status.json"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    assert receipt["projection_mode"] == "conservative_fallback"
    assert receipt["case_id"] == "PR-457"
    assert receipt["stages"]["trusted_checkout"] == "failure"
    assert receipt["stages"]["writer"] == "unknown"
    assert receipt["writer_call_state"] == receipt["audit_call_state"] == "unknown"
    assert stat.S_IMODE(receipt_path.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(receipt_path.stat().st_mode) == 0o600


def test_inline_fallback_refuses_preexisting_symlink_directory(tmp_path):
    text = WORKFLOW.read_text(encoding="utf-8")
    status_step = text.split("- name: Record bounded workflow status for incomplete runs", 1)[1].split(
        "- name: Upload only the bounded workflow status receipt", 1
    )[0]
    run_block = status_step.split("        run: |\n", 1)[1].split("\n      - name:", 1)[0]
    script = textwrap.dedent(run_block)
    external = tmp_path / "external"
    external.mkdir()
    (tmp_path / "private-shadow-status").symlink_to(external, target_is_directory=True)
    env = {
        **os.environ,
        "RUNNER_TEMP": str(tmp_path), "GITHUB_OUTPUT": str(tmp_path / "github-output"),
        "STATUS_CASE_ID": "PR-457", "STATUS_RUN_ID": "9", "STATUS_RUN_ATTEMPT": "1",
        "STATUS_JOB": "failure", "STATUS_TRUSTED_CHECKOUT": "failure",
        "STATUS_TRUSTED_IDENTITY": "skipped",
    }
    result = subprocess.run(["bash", "-e", "-u", "-o", "pipefail", "-c", script], env=env, check=False)
    assert result.returncode != 0
    assert not (external / "workflow-status.json").exists()
