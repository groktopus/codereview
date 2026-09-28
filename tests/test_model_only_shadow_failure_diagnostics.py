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
    link = tmp_path / "link.json"
    link.symlink_to(target)
    with pytest.raises(extractor.DiagnosticError):
        extractor.extract(link, 2)
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    with pytest.raises(extractor.DiagnosticError):
        extractor.extract(fifo, 2)


def test_live_prepare_uses_sanitized_failure_extractor_before_any_secrets():
    workflow = (ROOT / ".github/workflows/private-shadow-capture.yml").read_text(encoding="utf-8")
    live = workflow.split("  live_writer:", 1)[1]
    prepare = live.split("- name: Prepare the exact current-runtime writer requests without credentials", 1)[1].split(
        "- name: Verify the exact plan", 1
    )[0]
    assert "2>/dev/null" in prepare
    assert "extract_pr_review_failure_code.py" in prepare
    assert "--input \"$RUNNER_TEMP/private-shadow-preparation/prepared.json\"" in prepare
    assert "exit \"$cli_exit_code\"" in prepare
    assert live.index("extract_pr_review_failure_code.py") < live.index("Check writer secret names and exact configured identity")
