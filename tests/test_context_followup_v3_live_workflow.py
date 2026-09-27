import json
import re
from pathlib import Path

from scripts import run_real_case_trial as trial

ROOT = Path(__file__).parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "context-followup-v3-live-trial.yml"
PLAN = ROOT / "docs" / "real-case-trial-context-followup-v3" / "manifest.json"
RUNTIME_SHA = "7c89ad17327b8f0ed4fc381bf5c93255fd4e548e"
RUNTIME_TREE_SHA256 = "c5b7c4e43aeddfad55bbcfdcb9e07c4a89fd0b6a3a263a31f046c8852dd8838a"
PROVIDER_SECRETS = {
    "LLM_BASE_URL",
    "LLM_MODEL",
    "LLM_API_KEY",
    "JEV_BASE_URL",
    "JEV_MODEL",
    "JEV_API_KEY",
}


def test_live_workflow_is_fixed_manual_main_only_read_only_provider_trial():
    text = WORKFLOW.read_text(encoding="utf-8")
    plan = json.loads(PLAN.read_text(encoding="utf-8"))

    assert text.count("workflow_dispatch:") == 1
    assert "pull_request:" not in text
    assert "push:" not in text
    assert "schedule:" not in text
    assert "workflow_call:" not in text
    assert "inputs." not in text
    assert "github.event_name == 'workflow_dispatch'" in text
    assert "github.repository == 'groktopus/codereview'" in text
    assert "github.ref == 'refs/heads/main'" in text
    assert "permissions:\n  contents: read" in text
    assert "contents: write" not in text
    assert "pull-requests: write" not in text

    invocation = text.split("- name: Run the fixed three-case v3 provider trial", maxsplit=1)[1]
    invocation = invocation.split("- name: Remove only private trial workspace data", maxsplit=1)[0]
    assert invocation.count("scripts/run_real_case_trial.py") == 1
    assert "--mode full-three-case --run-provider-trial" in invocation
    assert f"--input-contract {trial.CONTEXT_FOLLOWUP_V3_SELECTOR}" in invocation
    assert "--prepare-only" not in invocation
    assert "--case-id" not in invocation
    assert "specialist-input-v2-context-followup-v2" not in text
    assert plan["schema"] == "historical-real-case-context-followup-input-plan.v3"
    assert plan["input_contract"] == "specialist-input.v2"
    assert plan["dynamic_followup_projection"] == "context-followup-observation.v3"
    assert plan["selectors"] == ["staged-pr464", "full-three-case"]
    assert [case["case_id"] for case in plan["cases"]] == ["PR-457", "PR-463", "PR-464"]
    assert plan["max_retries_per_task"] == 0
    assert plan["limits"]["max_retries_per_task"] == 0
    assert plan["limits"]["max_provider_calls"] == 64
    actual_limits = trial.limits_for(plan["limits"]["max_provider_calls"])
    assert {key: actual_limits[key] for key in plan["limits"]} == plan["limits"]
    assert "download-artifact" not in text
    assert "workflow_run:" not in text


def test_live_workflow_binds_dispatch_runner_and_fixed_runtime_sources():
    text = WORKFLOW.read_text(encoding="utf-8")
    plan = json.loads(PLAN.read_text(encoding="utf-8"))

    assert trial._uses_v2_primary(trial.CONTEXT_FOLLOWUP_V3_SELECTOR)
    assert trial._is_context_followup_v3(trial.CONTEXT_FOLLOWUP_V3_SELECTOR)
    clock_start = text.index("- name: Start the bounded matrix clock before checkout and setup")
    runner_checkout = text.index("- name: Check out the runner at the immutable dispatch revision")
    runner_check = text.index("- name: Verify dispatch source identity")
    runtime_checkout = text.index("- name: Check out the fixed v3 runtime source")
    runtime_check = text.index("- name: Verify fixed runtime source identity")
    provider_run = text.index("- name: Run the fixed three-case v3 provider trial")
    assert clock_start < runner_checkout < runner_check < runtime_checkout < runtime_check < provider_run
    assert "TRIAL_STARTED_EPOCH={int(time.time())}" in text
    assert "ref: ${{ github.sha }}" in text
    assert "EXPECTED_SHA: ${{ github.sha }}" in text
    assert "GITHUB_SHA: ${{ github.sha }}" in text
    assert "persist-credentials: false" in text
    assert f"ref: {RUNTIME_SHA}" in text
    assert f"EXPECTED_RUNTIME_SHA: {RUNTIME_SHA}" in text
    assert plan["runtime_revision"] == RUNTIME_SHA
    assert plan["runtime_module_tree_sha256"] == RUNTIME_TREE_SHA256
    assert trial.runtime_identity(trial.CONTEXT_FOLLOWUP_V3_SELECTOR) == (RUNTIME_SHA, RUNTIME_TREE_SHA256)
    assert 'stream.write("sha256="' in text
    assert "runner_revision_mismatch" in text
    assert "runtime_revision_mismatch" in text
    assert "--runtime-source \"$GITHUB_WORKSPACE/trusted-runtime\"" in text


def test_live_workflow_scopes_provider_secrets_and_does_not_log_them():
    text = WORKFLOW.read_text(encoding="utf-8")
    invocation_start = text.index("- name: Run the fixed three-case v3 provider trial")
    cleanup_start = text.index("- name: Remove only private trial workspace data")
    provider_step = text[invocation_start:cleanup_start]
    references = set(re.findall(r"\$\{\{ secrets\.([A-Z0-9_]+) \}\}", text))

    assert references == PROVIDER_SECRETS
    assert all(f"${{{{ secrets.{name} }}}}" in provider_step for name in PROVIDER_SECRETS)
    assert all(f"${{{{ secrets.{name} }}}}" not in text[:invocation_start] for name in PROVIDER_SECRETS)
    assert "required_provider_configuration_missing" in provider_step
    assert "print(" not in provider_step
    assert "echo " not in provider_step
    assert "contents: read" in text
    assert "gh " not in text


def test_live_workflow_cleans_only_private_data_before_sanitized_upload():
    text = WORKFLOW.read_text(encoding="utf-8")
    cleanup_start = text.index("- name: Remove only private trial workspace data")
    upload_start = text.index("- name: Upload only the sanitized summary and manifest")
    cleanup = text[cleanup_start:upload_start]
    upload = text[upload_start:]

    assert cleanup_start < upload_start
    assert "if: always()" in cleanup
    assert 'private = path / "private"' in cleanup
    assert "shutil.rmtree(private)" in cleanup
    assert "shutil.rmtree(path)" not in cleanup
    assert "lstat()" in cleanup
    assert "S_ISLNK" in cleanup
    assert "if: always()" in upload
    assert "summary.json" in upload
    assert "manifest.json" in upload
    assert "private/" not in upload
    assert "retention-days: 7" in upload
    assert "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02" in upload
    assert "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683" in text
    assert "actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065" in text
