from __future__ import annotations

import re
from pathlib import Path

WORKFLOW = Path(__file__).parents[1] / ".github/workflows/selected-model-claim-trial.yml"
PIN = "69a848b651faf6deddd777ed1b83187b7b8adfbf"
CHECKOUT_ACTION = "11bd71901bbe5b1630ceea73d27597364c9af683"
SETUP_PYTHON_ACTION = "a26af69be951a213d495a4c3e4e4022e16d87065"
UPLOAD_ARTIFACT_ACTION = "ea165f8d65b6e75b540449e92b4886f43607fa02"


def _source() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


def _step(source: str, name: str) -> str:
    marker = f"      - name: {name}\n"
    start = source.find(marker)
    if start < 0:
        raise AssertionError(f"workflow_step_missing:{name}")
    end = source.find("\n      - name:", start + len(marker))
    return source[start:] if end < 0 else source[start:end]


def test_workflow_is_manual_only_main_guarded_and_read_only():
    source = _source()
    trigger = source.split("on:\n", 1)[1].split("\npermissions:\n", 1)[0]
    assert trigger.strip() == "workflow_dispatch:"
    assert "inputs:" not in trigger
    assert "permissions:\n  contents: read\n\njobs:" in source
    assert "contents: write" not in source
    assert "actions: write" not in source
    assert "pull-requests: write" not in source
    assert "if: github.event_name == 'workflow_dispatch' && github.repository == 'groktopus/codereview' && github.ref == 'refs/heads/main'" in source
    assert "timeout-minutes: 20" in source


def test_trusted_runner_checkout_uses_the_full_placeholder_sha_without_persisted_credentials():
    source = _source()
    checkout = _step(source, "Check out the trusted runner at a full immutable revision")
    assert f"uses: actions/checkout@{CHECKOUT_ACTION}" in checkout
    assert "repository: groktopus/codereview" in checkout
    assert f"ref: {PIN}" in checkout
    assert "path: trusted-runner" in checkout
    assert "persist-credentials: false" in checkout
    assert "Reviewed immutable runner commit; keep in sync with EXPECTED_RUNNER_SHA below." in checkout
    assert len(re.findall(r"(?m)^\s+(?:ref|EXPECTED_RUNNER_SHA): ([0-9a-f]+)$", source)) == 2


def test_full_sha_is_verified_before_any_project_install_or_import():
    source = _source()
    verify = _step(source, "Verify the exact trusted source revision before build or import")
    build = _step(source, "Build the wheel from the verified trusted source")
    install = _step(source, "Install the verified wheel")
    run = _step(source, "Prepare the fixed synthetic cases using the installed CLI")
    assert f"EXPECTED_RUNNER_SHA: {PIN}" in verify
    assert "[\"git\", \"-C\", source, \"rev-parse\", \"HEAD\"]" in verify
    assert "result.stdout.strip() != expected" in verify
    assert "pip wheel --no-deps" in build
    assert "pip\", \"install\", \"--no-deps\"" in install
    assert source.index("Verify the exact trusted source revision") < source.index("Build the wheel from the verified trusted source")
    assert source.index("Build the wheel from the verified trusted source") < source.index("Install the verified wheel")
    assert source.index("Install the verified wheel") < source.index("Prepare the fixed synthetic cases")
    assert "--prepare-only" in run
    assert "--cli-executable \"$(command -v pr-review)\"" in run
    assert "--run-provider-trial" not in source


def test_prepare_path_has_no_provider_secrets_or_runtime_selection_inputs():
    source = _source()
    for forbidden in (
        "secrets.", "LLM_BASE_URL", "LLM_MODEL", "LLM_API_KEY", "JEV_BASE_URL", "JEV_MODEL", "JEV_API_KEY",
        "NOUS_API_KEY", "TYPESAFE_API_KEY", "--provider-config", "--decision-config", "provider_config_from_env.py",
    ):
        assert forbidden not in source
    assert "workflow_dispatch:\n    inputs:" not in source
    assert "test_model:" not in source
    assert "test_case:" not in source
    assert "max_provider_calls:" not in source
    assert "--prepare-only" in source


def test_uploaded_artifact_contains_only_runner_approved_summary_and_manifest():
    source = _source()
    upload = _step(source, "Upload only the sanitized summary and manifest")
    assert f"uses: actions/upload-artifact@{UPLOAD_ARTIFACT_ACTION}" in upload
    assert "if: always()" in upload
    assert "name: selected-model-trial-preflight-${{ github.run_id }}" in upload
    assert "${{ runner.temp }}/selected-model-trial/summary.json" in upload
    assert "${{ runner.temp }}/selected-model-trial/manifest.json" in upload
    assert "artifacts/" not in upload
    assert "raw" not in upload.lower()
    assert "retention-days: 7" in upload
    assert "if-no-files-found: warn" in upload


def test_all_action_pins_match_existing_repository_pins():
    source = _source()
    assert f"actions/checkout@{CHECKOUT_ACTION}" in source
    assert f"actions/setup-python@{SETUP_PYTHON_ACTION}" in source
    assert f"actions/upload-artifact@{UPLOAD_ARTIFACT_ACTION}" in source
    for match in re.finditer(r"(?m)^\s+uses: ([^\s]+)$", source):
        action = match.group(1).split("@", 1)
        assert len(action) == 2 and re.fullmatch(r"[0-9a-f]{40}", action[1]), match.group(1)


def test_workflow_never_checks_out_or_executes_target_code_or_publishes_reviews():
    source = _source()
    assert "SlopSearX" not in source
    assert "git clone" not in source
    assert "pull_request_number" not in source
    assert "pr-analysis.yml" not in source
    assert "pr-publish.yml" not in source
    assert "gh api" not in source
    assert "PUBLISH_REVIEW" not in source
