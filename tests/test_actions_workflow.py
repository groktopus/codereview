import json
import os
import re
import subprocess
import textwrap
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from pr_review_harness.cli import _limits, _read_limits

WORKFLOW = Path(__file__).parents[1] / ".github/workflows/pr-publish.yml"
ANALYSIS_WORKFLOW = Path(__file__).parents[1] / ".github/workflows/pr-analysis.yml"
TEST_WORKFLOW = Path(__file__).parents[1] / ".github/workflows/review-commits.yml"
RECOVERY_WORKFLOW = Path(__file__).parents[1] / ".github/workflows/hosted-recovery-rehearsal.yml"
PILOT_WORKFLOW = Path(__file__).parents[1] / ".github/workflows/slopsearx-pilot.yml"
SETUP_NODE_V4_PIN = "actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020"
OPERATIONS = Path(__file__).parents[1] / "docs/OPERATIONS.md"


def _caller_template() -> str:
    operations = OPERATIONS.read_text(encoding="utf-8")
    return operations.split("```yaml", 1)[1].split("```", 1)[0]


def _top_level_yaml_scalar(source: str, key: str) -> str:
    pattern = re.compile(rf"^{re.escape(key)}:\s*(.*?)\s*$", re.MULTILINE)
    match = pattern.search(source)
    if match is None or not match.group(1):
        raise ValueError(f"missing_top_level_{key}")
    value = match.group(1)
    if value[:1] in {"'", '"'} and value[-1:] == value[:1]:
        value = value[1:-1]
    return value


def _workflow_run_names(source: str) -> tuple[str, ...]:
    lines = source.splitlines()
    try:
        workflow_run = lines.index("  workflow_run:")
        workflows = lines.index("    workflows:", workflow_run + 1)
    except ValueError as exc:
        raise ValueError("workflow_run_filter_missing") from exc

    names = []
    for line in lines[workflows + 1 :]:
        if line.startswith("      - "):
            names.append(line.removeprefix("      - ").strip().strip("'\""))
        elif line.startswith("    types:"):
            break
        elif names and line.strip():
            break
    if not names:
        raise ValueError("workflow_run_names_missing")
    return tuple(names)


def _step(source: str, name: str) -> str:
    marker = f"      - name: {name}\n"
    start = source.index(marker)
    following = source.find("\n      - ", start + len(marker))
    return source[start:] if following < 0 else source[start:following] + "\n"


def _python_script(step: str) -> str:
    block = step.split("        run: |\n", 1)[1]
    block = re.sub(r"\A          python3? - <<'PY'\n", "", block)
    lines = block.splitlines()
    script = []
    for line in lines:
        if line.strip() == "PY":
            break
        if line.strip() and not line.startswith("          "):
            break
        script.append(line[10:] if line else "")
    if not script:
        raise AssertionError("embedded_python_missing")
    return textwrap.dedent("\n".join(script))


BASE_SHA = "c355830512fa5bffc167926a6a167bace93d96c6"
HEAD_SHA = "c8496b74d8e1da05a2ed654772fc4b1b1fcff56b"
TARGET_REPOSITORY = "magnus919/SlopSearX"


def _pull_request_event(number=477):
    return {
        "number": number,
        "pull_request": {"base": {"sha": BASE_SHA}, "head": {"sha": HEAD_SHA}},
    }


def _run_event_validator(tmp_path: Path, raw: bytes):
    source = ANALYSIS_WORKFLOW.read_text(encoding="utf-8")
    step = _step(source, "Validate generated PR event against the pinned analysis identity")
    namespace = {"__name__": "test_reusable_analysis_event_validation"}
    exec(compile(_python_script(step), "reusable analysis event validation", "exec"), namespace)
    event_path = tmp_path / "pr-event.json"
    event_path.write_bytes(raw)
    with patch.dict(
        os.environ,
        {
            "PR_EVENT_PATH": str(event_path),
            "EXPECTED_PR_NUMBER": "477",
            "EXPECTED_BASE_SHA": BASE_SHA,
            "EXPECTED_HEAD_SHA": HEAD_SHA,
        },
    ):
        namespace["main"]()


def _run_repository_identity_preflight(
    caller_repository: str,
    target_repository: str,
    *,
    emit_publication_bundle: bool = False,
    caller_event: str = "pull_request",
    caller_ref: str = "refs/heads/main",
    caller_workflow_ref: str = "groktopus/codereview/.github/workflows/slopsearx-pilot.yml@refs/heads/main",
    caller_sha: str = BASE_SHA,
    caller_workflow_sha: str = BASE_SHA,
    default_branch: str = "main",
    base_ref: str = "main",
):
    source = ANALYSIS_WORKFLOW.read_text(encoding="utf-8")
    step = _step(source, "Reject mutable or malformed harness and target identities before checkout")
    namespace = {"__name__": "test_reusable_analysis_repository_identity"}
    script = _python_script(step)
    with (
        patch.dict(
            os.environ,
            {
                "HARNESS_REPOSITORY": "groktopus/codereview",
                "HARNESS_SHA": "a" * 40,
                "CALLER_REPOSITORY": caller_repository,
                "CALLER_REF": caller_ref,
                "CALLER_WORKFLOW_REF": caller_workflow_ref,
                "CALLER_EVENT": caller_event,
                "CALLER_DEFAULT_BRANCH": default_branch,
                "CALLER_SHA": caller_sha,
                "CALLER_WORKFLOW_SHA": caller_workflow_sha,
                "EMIT_PUBLICATION_BUNDLE": "true" if emit_publication_bundle else "false",
                "TARGET_REPOSITORY": target_repository,
                "PR_NUMBER": "477",
                "BASE_REF": base_ref,
                "BASE_SHA": BASE_SHA,
                "HEAD_SHA": HEAD_SHA,
            },
        ),
        patch("subprocess.run") as run,
    ):
        run.return_value.returncode = 0
        exec(compile(script, "reusable analysis repository identity", "exec"), namespace)
        return run


def test_reusable_analysis_rejects_a_different_caller_before_git_or_checkout():
    source = ANALYSIS_WORKFLOW.read_text(encoding="utf-8")
    step = _step(source, "Reject mutable or malformed harness and target identities before checkout")
    namespace = {"__name__": "test_reusable_analysis_repository_identity"}
    script = _python_script(step)
    with (
        patch.dict(
            os.environ,
            {
                "HARNESS_REPOSITORY": "groktopus/codereview",
                "HARNESS_SHA": "a" * 40,
                "CALLER_REPOSITORY": "attacker/untrusted",
                "TARGET_REPOSITORY": TARGET_REPOSITORY,
                "PR_NUMBER": "477",
                "BASE_REF": "main",
                "BASE_SHA": BASE_SHA,
                "HEAD_SHA": HEAD_SHA,
            },
        ),
        patch("subprocess.run") as run,
    ):
        with pytest.raises(SystemExit, match="caller_target_repository_mismatch"):
            exec(compile(script, "reusable analysis repository identity", "exec"), namespace)
        run.assert_not_called()


def test_reusable_analysis_accepts_the_exact_caller_target_repository():
    run = _run_repository_identity_preflight(TARGET_REPOSITORY, TARGET_REPOSITORY)
    run.assert_called_once()
    assert run.call_args.args[0] == ["git", "check-ref-format", "refs/heads/main"]


def test_publication_opt_in_accepts_same_repo_protected_target_context():
    run = _run_repository_identity_preflight(
        TARGET_REPOSITORY,
        TARGET_REPOSITORY,
        emit_publication_bundle=True,
        caller_event="pull_request_target",
        caller_workflow_ref=f"{TARGET_REPOSITORY}/.github/workflows/review.yml@refs/heads/main",
    )
    run.assert_called_once_with(
        ["git", "check-ref-format", "refs/heads/main"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=3,
        check=False,
    )


@pytest.mark.parametrize(
    "changes",
    [
        {"caller_event": "pull_request"},
        {"caller_ref": "refs/heads/feature"},
        {"caller_workflow_ref": f"{TARGET_REPOSITORY}/.github/workflows/review.yml@refs/heads/feature"},
        {"caller_sha": "9" * 40},
        {"caller_workflow_sha": "9" * 40},
        {"base_ref": "release"},
    ],
)
def test_publication_opt_in_rejects_unprotected_target_context_before_git(changes):
    kwargs = {
        "caller_event": "pull_request_target",
        "caller_workflow_ref": f"{TARGET_REPOSITORY}/.github/workflows/review.yml@refs/heads/main",
    }
    kwargs.update(changes)
    source = ANALYSIS_WORKFLOW.read_text(encoding="utf-8")
    step = _step(source, "Reject mutable or malformed harness and target identities before checkout")
    script = _python_script(step)
    with (
        patch.dict(
            os.environ,
            {
                "HARNESS_REPOSITORY": "groktopus/codereview",
                "HARNESS_SHA": "a" * 40,
                "CALLER_REPOSITORY": TARGET_REPOSITORY,
                "CALLER_REF": kwargs.get("caller_ref", "refs/heads/main"),
                "CALLER_WORKFLOW_REF": kwargs["caller_workflow_ref"],
                "CALLER_EVENT": kwargs["caller_event"],
                "CALLER_DEFAULT_BRANCH": "main",
                "CALLER_SHA": kwargs.get("caller_sha", BASE_SHA),
                "CALLER_WORKFLOW_SHA": kwargs.get("caller_workflow_sha", BASE_SHA),
                "EMIT_PUBLICATION_BUNDLE": "true",
                "TARGET_REPOSITORY": TARGET_REPOSITORY,
                "PR_NUMBER": "477",
                "BASE_REF": kwargs.get("base_ref", "main"),
                "BASE_SHA": BASE_SHA,
                "HEAD_SHA": HEAD_SHA,
            },
        ),
        patch("subprocess.run") as run,
    ):
        with pytest.raises(SystemExit, match="publication_source_context_mismatch"):
            exec(compile(script, "reusable analysis publication source", "exec"), {})
        run.assert_not_called()


def test_reusable_analysis_accepts_only_the_pinned_central_pilot_pair_on_main():
    run = _run_repository_identity_preflight("groktopus/codereview", TARGET_REPOSITORY)
    run.assert_called_once()
    assert run.call_args.args[0] == ["git", "check-ref-format", "refs/heads/main"]


def test_publication_preflight_separates_current_workflow_sha_from_older_pr_base():
    caller_sha = "f" * 40
    run = _run_repository_identity_preflight(
        TARGET_REPOSITORY,
        TARGET_REPOSITORY,
        emit_publication_bundle=True,
        caller_event="pull_request_target",
        caller_ref="refs/heads/main",
        caller_workflow_ref=f"{TARGET_REPOSITORY}/.github/workflows/review.yml@refs/heads/main",
        caller_sha=caller_sha,
        caller_workflow_sha=caller_sha,
        base_ref="main",
    )
    run.assert_called_once()
    assert run.call_args.args[0] == ["git", "check-ref-format", "refs/heads/main"]


def test_publication_preflight_rejects_disagreeing_workflow_context_shas():
    with pytest.raises(SystemExit, match="publication_source_context_mismatch"):
        _run_repository_identity_preflight(
            TARGET_REPOSITORY,
            TARGET_REPOSITORY,
            emit_publication_bundle=True,
            caller_event="pull_request_target",
            caller_ref="refs/heads/main",
            caller_workflow_ref=f"{TARGET_REPOSITORY}/.github/workflows/review.yml@refs/heads/main",
            caller_sha="f" * 40,
            caller_workflow_sha="e" * 40,
            base_ref="main",
        )


@pytest.mark.parametrize(
    ("caller", "target", "caller_ref"),
    [
        ("attacker/untrusted", TARGET_REPOSITORY, "refs/heads/main"),
        ("groktopus/codereview", "attacker/target", "refs/heads/main"),
        ("groktopus/codereview", TARGET_REPOSITORY, "refs/heads/feature"),
    ],
)
def test_reusable_analysis_rejects_other_cross_repository_pairs(caller, target, caller_ref):
    source = ANALYSIS_WORKFLOW.read_text(encoding="utf-8")
    step = _step(source, "Reject mutable or malformed harness and target identities before checkout")
    script = _python_script(step)
    with (
        patch.dict(
            os.environ,
            {
                "HARNESS_REPOSITORY": "groktopus/codereview",
                "HARNESS_SHA": "a" * 40,
                "CALLER_REPOSITORY": caller,
                "CALLER_REF": caller_ref,
                "CALLER_WORKFLOW_REF": "groktopus/codereview/.github/workflows/slopsearx-pilot.yml@refs/heads/main",
                "TARGET_REPOSITORY": target,
                "PR_NUMBER": "477",
                "BASE_REF": "main",
                "BASE_SHA": BASE_SHA,
                "HEAD_SHA": HEAD_SHA,
            },
        ),
        patch("subprocess.run") as run,
    ):
        with pytest.raises(SystemExit, match="caller_target_repository_mismatch"):
            exec(compile(script, "reusable analysis repository identity", "exec"), {})
        run.assert_not_called()


def test_reusable_analysis_rejects_other_central_workflows():
    source = ANALYSIS_WORKFLOW.read_text(encoding="utf-8")
    step = _step(source, "Reject mutable or malformed harness and target identities before checkout")
    script = _python_script(step)
    with (
        patch.dict(
            os.environ,
            {
                "HARNESS_REPOSITORY": "groktopus/codereview",
                "HARNESS_SHA": "a" * 40,
                "CALLER_REPOSITORY": "groktopus/codereview",
                "CALLER_REF": "refs/heads/main",
                "CALLER_WORKFLOW_REF": "groktopus/codereview/.github/workflows/other.yml@refs/heads/main",
                "TARGET_REPOSITORY": TARGET_REPOSITORY,
                "PR_NUMBER": "477",
                "BASE_REF": "main",
                "BASE_SHA": BASE_SHA,
                "HEAD_SHA": HEAD_SHA,
            },
        ),
        patch("subprocess.run") as run,
    ):
        with pytest.raises(SystemExit, match="caller_target_repository_mismatch"):
            exec(compile(script, "reusable analysis repository identity", "exec"), {})
        run.assert_not_called()


def _caller_triggers_canary(caller: str, publisher: str) -> bool:
    try:
        caller_name = _top_level_yaml_scalar(caller, "name")
        return caller_name in _workflow_run_names(publisher)
    except ValueError:
        return False


def test_documented_caller_name_matches_the_actual_workflow_run_filter():
    caller = _caller_template()
    publisher = WORKFLOW.read_text(encoding="utf-8")
    pilot = PILOT_WORKFLOW.read_text(encoding="utf-8")

    # The operations snippet is a hypothetical caller whose name matches the
    # publisher filter. The repository's real pilot caller has a different
    # workflow_run name, so it cannot currently trigger this publisher.
    assert _top_level_yaml_scalar(caller, "name") == "PR Review Analysis"
    assert _caller_triggers_canary(caller, publisher)
    assert _top_level_yaml_scalar(pilot, "name") == "SlopSearX read-only review pilot"
    assert not _caller_triggers_canary(pilot, publisher)
    assert "  workflow_dispatch:" in pilot
    assert "target_repository: magnus919/SlopSearX" in pilot
    assert "PR_REVIEW_ANALYSIS_WORKFLOW_NAME: PR Review Analysis" in publisher
    assert not _caller_triggers_canary(caller.replace("name: PR Review Analysis\n", "", 1), publisher)
    assert not _caller_triggers_canary(
        caller.replace("name: PR Review Analysis", "name: Unrelated Workflow", 1), publisher
    )


def test_publication_workflow_is_hard_disabled_read_only_and_uses_protected_revision():
    source = WORKFLOW.read_text(encoding="utf-8")
    assert "workflow_run:" in source
    assert "types:\n      - completed" in source
    assert "queue: max" in source
    assert "cancel-in-progress: true" not in source
    assert "github.event.repository.default_branch" in source
    assert "ref: ${{ github.sha }}" in source
    assert "persist-credentials: false" in source
    assert "pull-requests: read" in source
    assert "actions: read" in source
    assert "contents: read" in source
    assert "if: ${{ false && vars.PR_REVIEW_PUBLICATION_ENABLED == 'true' }}" in source
    assert "pull-requests: write" not in source
    assert "pull_request:" not in source
    assert "NOUS_API_KEY" not in source
    assert "HARNESS_READ_TOKEN" not in source
    assert "GITHUB_ACTOR" not in source
    assert "checkout@" in source
    assert "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683" in source
    assert "actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065" in source
    assert SETUP_NODE_V4_PIN in source


def test_hosted_recovery_uses_verified_setup_node_v4_pin_and_keeps_node24():
    source = RECOVERY_WORKFLOW.read_text(encoding="utf-8")
    setup_step = source.split("- name: Set up the pinned readiness artifact bridge runtime", 1)[1].split(
        "- name: Install only the locked official artifact client", 1
    )[0]
    assert SETUP_NODE_V4_PIN in setup_step
    assert "node-version: '24'" in setup_step
    assert "actions/setup-node@1e60f620b9541d83c2a0d7bbbd10743a27a4e3d6" not in source


def test_runtime_secret_is_not_exposed_to_package_install_step():
    source = WORKFLOW.read_text(encoding="utf-8")
    install_step = source.split("- name: Install only the locked official artifact client", 1)[1].split(
        "- name: Verify platform-reported", 1
    )[0]
    assert "ACTIONS_RUNTIME_TOKEN: ''" in install_step
    assert "ACTIONS_RESULTS_URL: ''" in install_step
    assert "ACTIONS_RUNTIME_URL: ''" in install_step
    assert "GITHUB_TOKEN:" not in install_step
    assert "NOUS_API_KEY" not in install_step
    assert "npm ci --ignore-scripts" in install_step


def test_workflow_does_not_checkout_or_execute_upstream_pr_code():
    source = WORKFLOW.read_text(encoding="utf-8")
    assert "github.event.workflow_run.head_sha" not in source
    assert "refs/pull/" not in source
    assert "pull_request.head" not in source
    assert "git fetch" not in source
    assert "npm ci --ignore-scripts --no-audit --no-fund" in source
    assert "uses: ./scripts/actions-artifact-uploader" in source
    assert "python -m pr_review_harness.actions_runtime" not in source


def test_production_analysis_binds_all_six_provider_values_from_trusted_secrets():
    source = ANALYSIS_WORKFLOW.read_text(encoding="utf-8")
    secret_block = source.split("    secrets:", 1)[1].split("\npermissions:", 1)[0]
    names = (
        "LLM_BASE_URL",
        "LLM_MODEL",
        "LLM_API_KEY",
        "JEV_BASE_URL",
        "JEV_MODEL",
        "JEV_API_KEY",
    )

    for name in names:
        assert f"      {name}:\n        required: true" in secret_block
        assert f"{name}: ${{{{ secrets.{name} }}}}" in source
    assert "inputs.llm_" not in source
    assert "inputs.jev_" not in source
    materialization_step = source.split("- name: Materialize private provider configuration", 1)[1].split(
        "- name: Produce a bounded read-only report", 1
    )[0]
    assert "github.event." not in materialization_step
    assert "PR_NUMBER:" not in materialization_step
    assert "BASE_SHA:" not in materialization_step
    assert "HEAD_SHA:" not in materialization_step


def test_production_analysis_uses_generated_configs_without_catalog_or_target_execution():
    source = ANALYSIS_WORKFLOW.read_text(encoding="utf-8")
    config_step = source.split("- name: Materialize private provider configuration", 1)[1].split(
        "- name: Produce a bounded read-only report", 1
    )[0]
    review_step = source.split("- name: Produce a bounded read-only report", 1)[1]

    assert "scripts/provider_config_from_env.py" in config_step
    assert '"$RUNNER_TEMP/pr-review-provider-config"' in config_step
    assert '--provider-config "$RUNNER_TEMP/pr-review-provider-config/provider.json"' in review_step
    assert '--decision-config "$RUNNER_TEMP/pr-review-provider-config/decision.json"' in review_step
    assert "NOUS_API_KEY" not in source
    assert "model-catalog" not in source
    assert "examples/provider.nous-test" not in source
    assert "pull-requests: read" in source
    assert "pull-requests: write" not in source
    assert "pull_request:" not in source
    assert "refs/pull/" in source
    assert "fetched_target_head_mismatch" in source
    assert "fetched_target_base_mismatch" in source


def test_production_analysis_uses_fixed_bounded_claim_assessment_and_preserves_recovery_capture():
    source = ANALYSIS_WORKFLOW.read_text(encoding="utf-8")
    review_step = _step(source, "Produce a bounded read-only report from the bare target object store")
    review_command = review_step.split("        run: |\n", 1)[1].split("      - uses:", 1)[0]
    manifest_step = _step(source, "Record recovery identity and artifact digests")

    claim_lines = [line.strip() for line in review_command.splitlines() if "--max-claim-assessments" in line]
    assert claim_lines == ["--max-claim-assessments 1 \\"]
    assert "inputs.max_claim_assessments" not in source
    assert '--decision-config "$RUNNER_TEMP/pr-review-provider-config/decision.json"' in review_command
    assert "--capture-recovery-inputs artifacts/recovery-inputs.json" in review_command
    assert "--artifact-root artifacts" in manifest_step
    assert "DECISION_CONFIG: ${{ runner.temp }}/pr-review-provider-config/decision.json" in manifest_step


def test_ordinary_context_budget_is_a_trusted_single_override_and_fixed_in_workflow():
    limits_path = Path(__file__).parents[1] / "profiles/ordinary-review-limits-v2.json"
    policy = json.loads(limits_path.read_text(encoding="utf-8"))
    assert policy == {
        "schema_version": "1.0",
        "max_context_bytes": 600000,
        "max_input_bytes_per_task": 96000,
    }

    historical_limits = Path(__file__).parents[1] / "profiles/ordinary-review-limits-v1.json"
    assert json.loads(historical_limits.read_text(encoding="utf-8")) == {
        "schema_version": "1.0",
        "max_context_bytes": 600000,
    }

    baseline = _limits()
    resolved = _read_limits(SimpleNamespace(limits=str(limits_path)))
    changed = {key for key in baseline if baseline[key] != resolved[key]}
    assert changed == {"max_context_bytes", "max_input_bytes_per_task"}
    assert resolved["max_context_bytes"] == 600000
    assert resolved["max_input_bytes_per_task"] == 96000
    assert baseline["max_context_bytes"] == 300000
    assert baseline["max_input_bytes_per_task"] == 64000
    assert baseline["max_provider_calls"] == 12

    source = ANALYSIS_WORKFLOW.read_text(encoding="utf-8")
    review_step = _step(source, "Produce a bounded read-only report from the bare target object store")
    review_command = review_step.split("        run: |\n", 1)[1].split("      - uses:", 1)[0]
    assert "--limits profiles/ordinary-review-limits-v2.json \\" in review_command
    assert "inputs.limits" not in source
    assert "--capture-recovery-inputs artifacts/recovery-inputs.json" in review_command


def test_production_analysis_creates_redirect_parent_before_cli_starts():
    source = ANALYSIS_WORKFLOW.read_text(encoding="utf-8")
    review_step = source.split("- name: Produce a bounded read-only report", 1)[1]
    commands = review_step.split("        run: |", 1)[1].split("      - uses:", 1)[0]

    assert "mkdir -p artifacts" in commands
    assert commands.index("mkdir -p artifacts") < commands.index("pr-review review")
    assert commands.index("mkdir -p artifacts") < commands.index("> artifacts/review-result.json")


def test_reusable_analysis_validates_bounded_generated_event_before_provider_secrets(tmp_path):
    source = ANALYSIS_WORKFLOW.read_text(encoding="utf-8")
    validator = _step(source, "Validate generated PR event against the pinned analysis identity")
    config = _step(source, "Materialize private provider configuration from trusted secrets")
    script = _python_script(validator)

    assert source.index(validator) < source.index(config)
    assert "PR_EVENT_PATH: ${{ runner.temp }}/pr-event.json" in validator
    assert "EXPECTED_PR_NUMBER: ${{ inputs.pull_request_number }}" in validator
    assert "EXPECTED_BASE_SHA: ${{ inputs.base_sha }}" in validator
    assert "EXPECTED_HEAD_SHA: ${{ inputs.head_sha }}" in validator
    assert "MAX_EVENT_BYTES = 16_384" in script
    assert "stream.read(MAX_EVENT_BYTES + 1)" in script
    assert "object_pairs_hook=reject_duplicates" in script
    assert "parse_constant=reject_constant" in script
    assert "isinstance(number, bool) or not isinstance(number, int)" in script
    assert 'base.get("sha") != base_sha or head.get("sha") != head_sha' in script
    assert "print(" not in script
    _run_event_validator(tmp_path, json.dumps(_pull_request_event()).encode("utf-8"))


@pytest.mark.parametrize(
    "raw",
    [
        b"{malformed",
        b"{" + b" " * 16_384 + b"}",
        b'{"number":477,"number":477,"pull_request":{}}',
        b'{"number":477,"ignored":NaN,"pull_request":{}}',
        b'{"number":477,"ignored":Infinity,"pull_request":{}}',
        b'{"number":4.77e2,"pull_request":{"base":{"sha":"c355830512fa5bffc167926a6a167bace93d96c6"},"head":{"sha":"c8496b74d8e1da05a2ed654772fc4b1b1fcff56b"}}}',
        json.dumps({**_pull_request_event(), "number": True}).encode("utf-8"),
        json.dumps({**_pull_request_event(), "number": 478}).encode("utf-8"),
        json.dumps({"number": 477, "pull_request": {"base": {"sha": "d" * 40}, "head": {"sha": HEAD_SHA}}}).encode(
            "utf-8"
        ),
        json.dumps({"number": 477, "pull_request": {"base": {"sha": BASE_SHA}, "head": {"sha": "e" * 40}}}).encode(
            "utf-8"
        ),
    ],
)
def test_reusable_analysis_event_preflight_fails_closed_on_malformed_or_mismatched_event(tmp_path, raw):
    with pytest.raises(SystemExit, match="generated_pull_request_event_invalid"):
        _run_event_validator(tmp_path, raw)


def test_reusable_cli_uses_explicit_resolved_event_and_child_target_repository(monkeypatch, tmp_path, capsys):
    source = ANALYSIS_WORKFLOW.read_text(encoding="utf-8")
    review = _step(source, "Produce a bounded read-only report from the bare target object store")
    command = review.split("        run: |\n", 1)[1].split("      - uses:", 1)[0]

    assert "PR_EVENT_PATH: ${{ runner.temp }}/pr-event.json" in review
    assert "TARGET_REPOSITORY: ${{ inputs.target_repository }}" in review
    assert "GITHUB_EVENT_PATH:" not in review
    assert "GITHUB_REPOSITORY:" not in review
    assert "GITHUB_RUN_ID:" not in review
    assert "GITHUB_SERVER_URL:" not in review
    assert 'env GITHUB_REPOSITORY="$TARGET_REPOSITORY" pr-review review' in command
    assert '--event-file "$PR_EVENT_PATH"' in command

    monkeypatch.syspath_prepend(str(Path(__file__).parents[1] / "src"))
    from pr_review_harness import cli, github

    dispatch_path = tmp_path / "workflow-dispatch-event.json"
    dispatch_path.write_text(json.dumps({"workflow": "workflow_dispatch", "inputs": {"pull_request_number": "477"}}))
    resolved_path = tmp_path / "pr-event.json"
    resolved_path.write_text(json.dumps(_pull_request_event()))
    profile = tmp_path / "profile.json"
    profile.write_text(
        json.dumps({"version": "reusable-event-boundary-v1", "repository": TARGET_REPOSITORY, "context_paths": []}),
        encoding="utf-8",
    )
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(dispatch_path))
    monkeypatch.setenv("GITHUB_REPOSITORY", "trusted-harness/repository")
    monkeypatch.setenv("GITHUB_RUN_ID", "reusable-run-42")
    calls = []

    monkeypatch.setattr(github.GitHubPRAdapter, "check_runs", lambda *_args: {"runs": [], "complete": False})
    monkeypatch.setattr(cli, "_run_one", lambda *args: calls.append(args) or {"disposition": "INCOMPLETE"})
    with patch.dict(os.environ, {"GITHUB_REPOSITORY": TARGET_REPOSITORY}):
        result = cli.main(
            [
                "review",
                "--repo",
                str(tmp_path),
                "--event-file",
                str(resolved_path),
                "--profile",
                str(profile),
                "--output",
                str(tmp_path / "reports"),
                "--run-id",
                "pr-477-reusable-run-42",
                "--mode",
                "AUTO",
                "--json",
            ]
        )

    assert result == 0
    assert len(calls) == 1
    event = calls[0][8]
    assert event["repository"] == TARGET_REPOSITORY
    assert event["pull_request_number"] == 477
    assert event["base_sha"] == BASE_SHA
    assert event["head_sha"] == HEAD_SHA
    assert json.loads(capsys.readouterr().out)["disposition"] == "INCOMPLETE"


def test_production_analysis_fetches_immutable_pr_base_after_api_identity_check(tmp_path):
    source = ANALYSIS_WORKFLOW.read_text(encoding="utf-8")
    step = source.split("- name: Validate pinned source and PR identity, then acquire bare target objects", 1)[1]
    script = step.split("        run: |", 1)[1].split("      - name:", 1)[0]

    assert "if current['base_sha'] != base_sha or current['head_sha'] != head_sha:" in script
    assert script.index("if current['base_sha'] != base_sha or current['head_sha'] != head_sha:") < script.index(
        "git('git', 'init', '--bare', store)"
    )
    assert "f'+{base_sha}:refs/pr/base'" in script
    assert "f'+{base_ref_full}:refs/pr/base'" not in script

    def git(*args):
        return subprocess.run(
            ["git", *map(str, args)], check=True, capture_output=True, text=True, timeout=10
        ).stdout.strip()

    work = tmp_path / "work"
    remote = tmp_path / "target.git"
    store = tmp_path / "review.git"
    work.mkdir()
    git("init", work)
    git("-C", work, "config", "user.email", "review-fixture@example.invalid")
    git("-C", work, "config", "user.name", "Review fixture")
    (work / "source.txt").write_text("PR base\n", encoding="utf-8")
    git("-C", work, "add", "source.txt")
    git("-C", work, "commit", "-m", "PR base")
    base_sha = git("-C", work, "rev-parse", "HEAD")

    git("init", "--bare", remote)
    git("init", "--bare", store)
    git("-C", work, "push", remote, "HEAD:refs/heads/main")
    (work / "source.txt").write_text("advanced main\n", encoding="utf-8")
    git("-C", work, "commit", "-am", "Advance main")
    git("-C", work, "push", remote, "HEAD:refs/heads/main")
    advanced_main = git("--git-dir", remote, "rev-parse", "refs/heads/main")
    assert advanced_main != base_sha

    git(
        "-C",
        store,
        "fetch",
        "--no-tags",
        "--depth=1",
        remote.as_uri(),
        f"+{base_sha}:refs/pr/base",
    )
    assert git("--git-dir", store, "rev-parse", "refs/pr/base") == base_sha
    assert git("--git-dir", remote, "rev-parse", "refs/heads/main") == advanced_main


@pytest.mark.parametrize(
    ("current", "reason"),
    [
        (
            {"state": "open", "draft": True, "base_sha": BASE_SHA, "head_sha": HEAD_SHA},
            "target_pull_request_not_open_ready",
        ),
        (
            {"state": "open", "draft": False, "base_sha": "d" * 40, "head_sha": HEAD_SHA},
            "target_pull_request_revision_mismatch",
        ),
        (
            {"state": "open", "draft": False, "base_sha": BASE_SHA, "head_sha": "e" * 40},
            "target_pull_request_revision_mismatch",
        ),
    ],
)
def test_production_analysis_stops_before_object_fetch_for_draft_or_stale_identity(
    monkeypatch, tmp_path, current, reason
):
    source = ANALYSIS_WORKFLOW.read_text(encoding="utf-8")
    step = _step(source, "Validate pinned source and PR identity, then acquire bare target objects")
    script = _python_script(step)
    monkeypatch.setenv("HARNESS_SHA", "a" * 40)
    monkeypatch.setenv("TARGET_REPOSITORY", TARGET_REPOSITORY)
    monkeypatch.setenv("PR_NUMBER", "477")
    monkeypatch.setenv("BASE_REF", "main")
    monkeypatch.setenv("BASE_SHA", BASE_SHA)
    monkeypatch.setenv("HEAD_SHA", HEAD_SHA)
    monkeypatch.setenv("GITHUB_REPOSITORY", "groktopus/codereview")
    monkeypatch.setenv("OBJECT_STORE", str(tmp_path / "target.git"))
    monkeypatch.setenv("EVENT_OUTPUT", str(tmp_path / "event.json"))

    with patch("pr_review_harness.github.GitHubPRAdapter") as adapter, patch("subprocess.run") as run:
        adapter.return_value.pull_request.return_value = current
        run.return_value = SimpleNamespace(stdout="a" * 40 + "\n")
        with pytest.raises(SystemExit, match=reason):
            exec(compile(script, "reusable analysis source preflight", "exec"), {"__name__": "__main__"})

    adapter.return_value.pull_request.assert_called_once_with(TARGET_REPOSITORY, 477)
    assert run.call_count == 1
    assert run.call_args.args[0] == ("git", "rev-parse", "HEAD")


def test_historical_free_model_workflow_remains_separate_from_production_provider_config():
    source = TEST_WORKFLOW.read_text(encoding="utf-8")
    assert "NOUS_API_KEY" in source
    assert "model-catalog.json" in source
    assert "provider.nous-test" not in source
