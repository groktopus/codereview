from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "scripts" / "extract_pr_review_failure_code.py"
SPEC = importlib.util.spec_from_file_location("extract_pr_review_failure_code", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
extractor = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(extractor)


def test_extractor_returns_only_whitelisted_cli_error_fields(tmp_path: Path):
    path = tmp_path / "cli-output.json"
    path.write_text('{"error":"preflight_rejected","exit_code":2}', encoding="utf-8")
    os.chmod(path, 0o600)
    assert extractor.extract(path, 2) == {"error": "preflight_rejected", "exit_code": 2}


@pytest.mark.parametrize(
    "payload,exit_code",
    [
        ('{"error":"preflight_rejected","exit_code":2,"source":"private text"}', 2),
        ('{"error":"private source: prompt injection","exit_code":2}', 2),
        ('{"error":"preflight_rejected","exit_code":1}', 2),
        ('{"error":"preflight_rejected","error":"run_id_already_exists","exit_code":2}', 2),
        ('{"error":"preflight_rejected","exit_code":NaN}', 2),
        ('not json', 2),
    ],
)
def test_extractor_rejects_unexpected_or_malformed_payload_without_echoing_it(
    tmp_path: Path, payload: str, exit_code: int,
):
    path = tmp_path / "cli-output.json"
    path.write_text(payload, encoding="utf-8")
    os.chmod(path, 0o600)
    with pytest.raises(extractor.DiagnosticError):
        extractor.extract(path, exit_code)
    completed = subprocess.run(
        [sys.executable, str(SCRIPT), "--input", str(path), "--exit-code", str(exit_code)],
        check=False, capture_output=True, text=True, timeout=10,
    )
    assert completed.returncode == 0
    assert json.loads(completed.stdout) == {
        "error": "prepare_failure_diagnostic_unavailable", "exit_code": exit_code,
    }
    assert "private" not in completed.stdout and "injection" not in completed.stdout


def test_extractor_refuses_symlink_and_non_regular_inputs(tmp_path: Path):
    target = tmp_path / "target.json"
    target.write_text('{"error":"preflight_rejected","exit_code":2}', encoding="utf-8")
    os.chmod(target, 0o600)
    link = tmp_path / "link.json"
    link.symlink_to(target)
    with pytest.raises(extractor.DiagnosticError):
        extractor.extract(link, 2)
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    with pytest.raises(extractor.DiagnosticError):
        extractor.extract(fifo, 2)


def test_extractor_accepts_only_fixed_stage_receipt_and_matching_exit_code(tmp_path: Path):
    path = tmp_path / "stage.json"
    path.write_text(json.dumps({
        "schema": "pr-review-prepare-stage-diagnostic.v1", "stage": "snapshot_collection", "exit_code": 2,
    }))
    os.chmod(path, 0o600)
    assert extractor.extract_stage(path, 2) == "snapshot_collection"
    for value in (
        {"schema": "pr-review-prepare-stage-diagnostic.v1", "stage": "source_text", "exit_code": 2},
        {"schema": "pr-review-prepare-stage-diagnostic.v1", "stage": "planning", "exit_code": 1},
        {"schema": "pr-review-prepare-stage-diagnostic.v1", "stage": "planning", "exit_code": 2, "detail": "secret"},
    ):
        path.write_text(json.dumps(value))
        os.chmod(path, 0o600)
        with pytest.raises(extractor.DiagnosticError):
            extractor.extract_stage(path, 2)


def test_live_prepare_uses_sanitized_failure_extractor_before_any_secrets():
    workflow = (ROOT / ".github/workflows/private-shadow-capture.yml").read_text(encoding="utf-8")
    live = workflow.split("  live_writer:", 1)[1]
    prepare = live.split("- name: Prepare the selected exact writer requests without credentials", 1)[1].split(
        "- name: Verify the exact plan", 1
    )[0]
    assert "2>/dev/null" in prepare
    assert "run_pr_review_stage_diagnostic.py" in prepare
    assert "extract_pr_review_failure_code.py" in prepare
    assert "--stage-input \"$RUNNER_TEMP/private-shadow-preparation/stage-diagnostic.json\"" in prepare
    assert "--input \"$RUNNER_TEMP/private-shadow-preparation/prepared.json\"" in prepare
    assert "exit \"$cli_exit_code\"" in prepare
    assert live.index("run_pr_review_stage_diagnostic.py") < live.index(
        "Check writer secret names and exact configured identity"
    )
    identity_step = live.split("- name: Check writer secret names and exact configured identity", 1)[1].split(
        "- name: Run only the selected pinned read-only writer calls", 1
    )[0]
    writer_step = live.split("- name: Run only the selected pinned read-only writer calls", 1)[1].split(
        "- name: Sanitize the completed writer capture", 1
    )[0]
    assert "if: steps.exact-preflight.outputs.verified == 'true'" in identity_step
    assert (
        "if: steps.exact-preflight.outputs.verified == 'true' && "
        "steps.provider-identity.outputs.validated == 'true'"
    ) in writer_step
