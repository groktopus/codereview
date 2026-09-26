import re
from pathlib import Path

WORKFLOW = Path(__file__).parents[1] / ".github/workflows/pr-publish.yml"
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


def _caller_triggers_canary(caller: str, publisher: str) -> bool:
    try:
        caller_name = _top_level_yaml_scalar(caller, "name")
        return caller_name in _workflow_run_names(publisher)
    except ValueError:
        return False


def test_documented_caller_name_matches_the_actual_workflow_run_filter():
    caller = _caller_template()
    publisher = WORKFLOW.read_text(encoding="utf-8")

    assert _top_level_yaml_scalar(caller, "name") == "PR Review Analysis"
    assert _caller_triggers_canary(caller, publisher)
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
    assert "actions/setup-node@1e60f620b9541d83c2a0d7bbbd10743a27a4e3d6" in source


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
