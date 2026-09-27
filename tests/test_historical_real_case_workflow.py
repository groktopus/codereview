from pathlib import Path

from scripts import run_real_case_trial as trial

WORKFLOW = Path(__file__).parents[1] / ".github" / "workflows" / "historical-real-case-provider-trial.yml"


def test_historical_trial_workflow_is_manual_read_only_and_has_fixed_modes():
    text = WORKFLOW.read_text()
    assert "workflow_dispatch:" in text
    assert "pull_request:" not in text
    assert "permissions:\n  contents: read" in text
    assert "contents: write" not in text
    assert "checks: read" not in text
    assert "pull-requests: read" not in text
    assert "default: prepare-only" in text
    assert "default: staged-pr464" in text
    assert "provider-trial" in text
    assert "full-three-case" in text
    assert "github.ref == 'refs/heads/main'" in text
    assert f"ref: {trial.RUNTIME_SHA}" in text
    assert trial.RUNTIME_MODULE_TREE_SHA256 == "86b4f0c82bbf3e4c01f38dff07d3dd93de31d14d6791683b95988c4c5ca04f5d"


def test_provider_secrets_are_only_mapped_to_the_explicit_run_step():
    text = WORKFLOW.read_text()
    names = ("LLM_BASE_URL", "LLM_MODEL", "LLM_API_KEY", "JEV_BASE_URL", "JEV_MODEL", "JEV_API_KEY")
    run_marker = "- name: Run the frozen provider trial"
    before, after = text.split(run_marker, maxsplit=1)
    assert "secrets." not in before
    for name in names:
        assert after.count(f"{name}: ${{{{ secrets.{name} }}}}") == 1
    assert "--prepare-only" in before
    assert "--run-provider-trial" in after


def test_only_sanitized_outputs_are_uploaded_and_trial_time_is_bounded():
    text = WORKFLOW.read_text()
    upload = text.split("- name: Upload only the sanitized summary and manifest", maxsplit=1)[1]
    assert "summary.json" in upload
    assert "manifest.json" in upload
    assert "private/" not in upload
    assert "55" in text
    assert '--mode "$TRIAL_SCOPE"' in text
