from pathlib import Path

from scripts import run_real_case_trial as trial

WORKFLOW = Path(__file__).parents[1] / ".github" / "workflows" / "context-followup-v3-prepare.yml"


def test_context_followup_v3_workflow_is_manual_read_only_provider_free_prepare():
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "workflow_dispatch:" in text
    assert "pull_request:" not in text
    assert "push:" not in text
    assert "permissions:\n  contents: read" in text
    assert "contents: write" not in text
    assert "secrets." not in text
    assert "--prepare-only" in text
    assert "--run-provider-trial" not in text
    assert "provider-trial" not in text
    assert trial.CONTEXT_FOLLOWUP_V3_SELECTOR in text
    assert "--mode full-three-case" in text
    assert "github.ref == 'refs/heads/main'" in text


def test_context_followup_v3_workflow_pins_dispatch_runner_and_unchanged_runtime():
    text = WORKFLOW.read_text(encoding="utf-8")
    clock_start = text.index("- name: Start the matrix clock before checkout and setup")
    runner_checkout = text.index("- name: Check out the runner at the immutable dispatch revision")
    assert clock_start < runner_checkout
    assert "TRIAL_STARTED_EPOCH={int(time.time())}" in text
    assert "ref: ${{ github.sha }}" in text
    assert "EXPECTED_SHA: ${{ github.sha }}" in text
    assert "GITHUB_SHA: ${{ github.sha }}" in text
    assert "persist-credentials: false" in text
    assert "ref: 7c89ad17327b8f0ed4fc381bf5c93255fd4e548e" in text
    assert trial.runtime_identity(trial.CONTEXT_FOLLOWUP_V3_SELECTOR) == (
        "7c89ad17327b8f0ed4fc381bf5c93255fd4e548e",
        trial.CONTEXT_FOLLOWUP_V2_MODULE_TREE_SHA256,
    )
    assert 'stream.write("sha256="' in text
    assert "runner_revision" in text


def test_context_followup_v3_workflow_upload_is_bounded_and_sanitized():
    text = WORKFLOW.read_text(encoding="utf-8")
    cleanup_start = text.index("- name: Remove only private preparation workspace data")
    upload_start = text.index("- name: Upload only the sanitized summary and manifest")
    assert cleanup_start < upload_start
    cleanup = text[cleanup_start:upload_start]
    assert "private = path / \"private\"" in cleanup
    assert "shutil.rmtree(private)" in cleanup
    assert "shutil.rmtree(path)" not in cleanup
    upload = text.split("- name: Upload only the sanitized summary and manifest", maxsplit=1)[1]
    assert "summary.json" in upload
    assert "manifest.json" in upload
    assert "private/" not in upload
    assert "retention-days: 7" in upload
    assert "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02" in upload
