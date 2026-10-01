from __future__ import annotations

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/configured-jev-injection-classifier-trial.yml"
LEGACY = ROOT / ".github/workflows/prepared-selected-model-provider-trial.yml"


def test_configured_jev_workflow_is_main_only_read_only_and_prepare_by_default():
    source = WORKFLOW.read_text(encoding="utf-8")
    assert "workflow_dispatch:" in source
    assert "default: false" in source
    assert "type: boolean" in source
    assert "github.repository == 'groktopus/codereview'" in source
    assert "github.ref == 'refs/heads/main'" in source
    assert "permissions:\n  contents: read" in source
    live = source.split("- name: Run the two configured Jev calls", 1)[1].split(
        "- name: Upload only", 1
    )[0]
    assert "if: inputs.run_live_trial == true" in live
    assert all(f"{name}: ${{{{ secrets.{name} }}}}" in live for name in ("JEV_BASE_URL", "JEV_MODEL", "JEV_API_KEY"))
    assert all(name not in live for name in ("LLM_BASE_URL", "LLM_MODEL", "LLM_API_KEY"))
    assert "permissions:" not in live
    assert "--run-provider-trial" in live
    assert "contents: write" not in source
    assert "pull_request:" not in source


def test_historical_classifier_workflow_remains_byte_identical_to_base():
    original = subprocess.run(
        ["git", "show", "HEAD:.github/workflows/prepared-selected-model-provider-trial.yml"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        timeout=10,
    ).stdout
    assert LEGACY.read_bytes() == original

