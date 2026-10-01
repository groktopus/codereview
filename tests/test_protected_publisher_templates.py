"""Safety checks for inert protected-publication templates."""

import json
import re
from pathlib import Path

import pytest

from pr_review_harness.actions_runtime import OfficialActionsArtifactUploader
from pr_review_harness.protected_publication_runtime import ProtectedPublicationPolicy, ProtectedRuntimeError

ROOT = Path(__file__).resolve().parents[1]


def test_policy_template_is_explicitly_inert_and_rejected_until_real_identity_values_are_added():
    path = ROOT / "templates/protected-publisher-policy.json"
    document = json.loads(path.read_text(encoding="utf-8"))

    assert document["enabled"] is False
    assert document["schema"] == "pr-review-protected-publication-policy.v1"
    assert "REPLACE_WITH_" in path.read_text(encoding="utf-8")
    with pytest.raises(ProtectedRuntimeError, match="protected_policy_repository_invalid"):
        ProtectedPublicationPolicy.parse(document)


def test_workflow_template_stays_disabled_and_uses_existing_protected_runtime_and_pinned_bridge():
    workflow = (ROOT / "templates/protected-pr-review-publisher.yml").read_text(encoding="utf-8")

    assert re.search(r"(?m)^\s*if:\s*\$\{\{\s*false\s*\}\}\s*$", workflow)
    assert "workflow_run:" in workflow
    assert re.search(
        r"(?m)^concurrency:\n  group: pr-review-publish-\$\{\{ github\.repository_id \}\}\n"
        r"  queue: max\n  cancel-in-progress: false$",
        workflow,
    )
    publisher_job = re.search(r"(?ms)^  publisher-disabled:\n(?P<body>(?:    .*\n|\n)+)", workflow)
    assert publisher_job is not None
    publisher_body = publisher_job.group("body")
    assert re.search(r"(?m)^    environment:\n      name: code-review-publication$", publisher_body)
    assert re.search(r"(?m)^    permissions:\n      actions: read\n      contents: read\n      pull-requests: read$", publisher_body)
    assert "pull-requests: write" not in publisher_body
    assert "contents: write" not in publisher_body
    assert "${{ github.event.workflow_run.id }}" not in workflow.split("concurrency:", 1)[1].split("permissions:", 1)[0]
    assert "persist-credentials: false" in workflow
    assert "python -m pr_review_harness.protected_publication_runtime" in workflow
    assert "npm ci --ignore-scripts --no-audit --no-fund" in workflow
    assert "trusted-review-harness/src" in workflow
    assert '"git", "clone", "--no-checkout", "--filter=blob:none"' in workflow
    assert '"RUNNER_TEMP"' in workflow
    assert "timeout=120" in workflow
    assert "timeout=30" in workflow
    assert "timeout=10" in workflow
    assert "python -m pip install \"${RUNNER_TEMP}/trusted-review-harness[github-app]\"" in workflow
    assert "working-directory: ${{ runner.temp }}/trusted-review-harness/scripts/actions-artifact-uploader" in workflow
    assert "ACTIONS_RUNTIME_TOKEN: ''" in workflow
    assert "default-branch tip and keeps the reviewed PR base/head separate" in workflow
    assert "target repository's reviewed environment" in workflow


def test_artifact_bridge_working_directory_matches_runtime_default_script_location():
    workflow = (ROOT / "templates/protected-pr-review-publisher.yml").read_text(encoding="utf-8")
    expected = "${{ runner.temp }}/trusted-review-harness/scripts/actions-artifact-uploader"
    step_start = workflow.index("- name: Install only the lockfile-pinned official artifact client")
    step_end = workflow.index("- name: Run the protected publication runtime", step_start)
    install_step = workflow[step_start:step_end]
    assert f"working-directory: {expected}" in install_step

    uploader = OfficialActionsArtifactUploader(environ={"PATH": "/usr/bin:/bin"})
    assert uploader._script == ROOT / "scripts/actions-artifact-uploader/upload.mjs"
    assert uploader._script.is_file()
    assert "uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683" in workflow
    assert "uses: actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065" in workflow
    assert "uses: actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020" in workflow
    assert "node-version: '24'" in workflow
    assert workflow.index("- name: Set up Python") < workflow.index(
        "- name: Install the trusted harness's optional GitHub App signer dependency"
    )
    assert workflow.count("Configure the named `code-review-publication` environment") == 1
    assert "hash-locked exact version" not in workflow


def test_installed_wheel_workflow_binds_runtime_smoke_to_one_downloaded_wheel():
    workflow = (ROOT / ".github/workflows/test.yml").read_text(encoding="utf-8")

    assert "PR_REVIEW_PROTECTED_PUBLICATION_WHEEL" in workflow
    assert "tests/test_protected_publication_installed.py" in workflow
    assert "mapfile -t WHEELS" in workflow
    assert 'test "${#WHEELS[@]}" -eq 1' in workflow
