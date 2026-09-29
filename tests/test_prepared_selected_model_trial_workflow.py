from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).parents[1]
WORKFLOW = ROOT / ".github/workflows/prepared-selected-model-provider-trial.yml"
RUNNER_SHA = "896b9211ffaa1e888538d29184c23c76cb3c2863"
OPERATOR_SECRETS = {
    "LLM_BASE_URL",
    "LLM_MODEL",
    "LLM_API_KEY",
    "JEV_BASE_URL",
    "JEV_MODEL",
    "JEV_API_KEY",
}


def _workflow() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


def _steps(source: str) -> list[str]:
    marker = "      - name: "
    return [marker + step for step in source.split(marker)[1:]]


def _step(source: str, name: str) -> str:
    marker = f"      - name: {name}\n"
    start = source.find(marker)
    assert start >= 0, f"workflow_step_missing:{name}"
    end = source.find("\n      - name:", start + len(marker))
    return source[start:] if end < 0 else source[start:end]


def test_workflow_requires_manual_main_only_read_only_execution():
    source = _workflow()
    assert "on:\n  workflow_dispatch:\n" in source
    assert "permissions:\n  contents: read\n" in source
    assert (
        "if: github.event_name == 'workflow_dispatch' && "
        "github.repository == 'groktopus/codereview' && "
        "github.ref == 'refs/heads/main'"
    ) in source
    assert not re.search(r"(?m)^\s*(?:checks|contents|actions|pull-requests):\s*write\s*$", source)


def test_trusted_runner_pin_is_identical_and_checkout_does_not_persist_credentials():
    source = _workflow()
    checkout = _step(source, "Check out the trusted runner at a full immutable revision")
    verify = _step(source, "Verify the exact trusted source revision before build or import")
    assert "uses: actions/checkout@" in checkout
    assert "repository: groktopus/codereview" in checkout
    assert f"ref: {RUNNER_SHA}" in checkout
    assert "persist-credentials: false" in checkout
    assert f"EXPECTED_RUNNER_SHA: {RUNNER_SHA}" in verify
    assert 'result.stdout.strip() != expected' in verify


def test_secretless_fixed_case_preparation_precedes_the_credentialed_trial():
    source = _workflow()
    steps = _steps(source)
    prepare_index = next(
        index
        for index, step in enumerate(steps)
        if "prepare_selected_pair_clean_control_trial.py" in step
    )
    trial_index = next(index for index, step in enumerate(steps) if "--run-provider-trial" in step)
    prepare = steps[prepare_index]
    trial = steps[trial_index]
    assert prepare_index < trial_index
    assert not re.search(r"\bsecrets\.[A-Z0-9_]+", prepare)
    assert "--output" in prepare
    assert "--prepared-plan" in trial
    assert "--observe-effects" in trial

    refs_by_step = {
        index: set(re.findall(r"\bsecrets\.([A-Z0-9_]+)", step))
        for index, step in enumerate(steps)
    }
    assert set().union(*refs_by_step.values()) == OPERATOR_SECRETS
    assert refs_by_step[trial_index] == OPERATOR_SECRETS
    assert all(not refs for index, refs in refs_by_step.items() if index != trial_index)


def test_workflow_has_no_classifier_or_publication_side_effect_and_uploads_only_sanitized_outputs():
    source = _workflow()
    steps = _steps(source)
    serialized_steps = "\n".join(steps).lower()
    for forbidden in (
        "pull_request_target",
        "repository_dispatch",
        "classifier",
        "publish",
        "contents: write",
        "actions: write",
        "pull-requests: write",
    ):
        assert forbidden not in serialized_steps

    uploads = [step for step in steps if "uses: actions/upload-artifact@" in step]
    assert len(uploads) == 1
    upload = uploads[0]
    artifact_paths = re.search(r"(?ms)^          path: \|\n(?P<paths>.*?)(?=^          [a-z-]+:)", upload)
    assert artifact_paths is not None
    paths = [line.strip() for line in artifact_paths.group("paths").splitlines() if line.strip()]
    assert len(paths) == 2
    assert {Path(path).name for path in paths} == {"summary.json", "manifest.json"}
    assert all("prepared-selected-model-provider-result" in path for path in paths)
    assert "raw" not in upload.lower()

    cleanup = _step(source, "Remove only the private configs created for this run").lower()
    assert "prepared-selected-model-provider-config" in cleanup
    assert "prepared-selected-model-provider-trial" in cleanup
    assert "rmtree" in cleanup
    assert "relative_to(runner_temp)" in cleanup
    assert "stat.s_islnk" in cleanup
    assert "rm -rf" not in cleanup
    assert "rm -rf" not in source.lower()
