import json
import re
import subprocess
import textwrap
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

WORKFLOW = Path(__file__).parents[1] / ".github/workflows/slopsearx-pilot.yml"
PIN = "c09321f2e963098c3ce665f3db144e22d37dd382"
SECRETS = (
    "LLM_BASE_URL",
    "LLM_MODEL",
    "LLM_API_KEY",
    "JEV_BASE_URL",
    "JEV_MODEL",
    "JEV_API_KEY",
)


def _source() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


def _metadata_script(source: str) -> str:
    resolve_job = source.split("  resolve-target:\n", 1)[1].split("\n  analyze:\n", 1)[0]
    block = resolve_job.split("        run: |\n", 1)[1]
    block = block.removeprefix("          python3 - <<'PY'\n")
    lines = []
    for line in block.splitlines():
        if line.strip() == "PY":
            break
        if line.strip() and not line.startswith("          "):
            break
        lines.append(line[10:] if line else "")
    if not lines:
        raise AssertionError("embedded_metadata_script_missing")
    return textwrap.dedent("\n".join(lines))


def _record(**overrides):
    record = {
        "number": 477,
        "state": "open",
        "draft": False,
        "base": {
            "ref": "main",
            "sha": "c355830512fa5bffc167926a6a167bace93d96c6",
            "repo": {"full_name": "magnus919/SlopSearX"},
        },
        "head": {"sha": "c8496b74d8e1da05a2ed654772fc4b1b1fcff56b"},
    }
    record.update(overrides)
    return record


def _run_metadata(monkeypatch, tmp_path, response):
    source = _source()
    namespace = {"__name__": "test_workflow_metadata"}
    exec(compile(_metadata_script(source), "slopsearx-pilot metadata", "exec"), namespace)
    output = tmp_path / "github-output"
    output.write_text("", encoding="utf-8")
    monkeypatch.setenv("PR_NUMBER", "477")
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))

    def fake_run(command, **kwargs):
        assert command[:4] == ["gh", "api", "repos/magnus919/SlopSearX/pulls/477", "--jq"]
        assert kwargs["timeout"] == 15
        return SimpleNamespace(returncode=0, stdout=response)

    with patch.object(subprocess, "run", side_effect=fake_run):
        namespace["main"]()
    return output.read_text(encoding="utf-8")


def test_pilot_dispatch_has_closed_contract_choice_and_runs_dispatcher_on_default_branch():
    source = _source()
    dispatch = source.split("on:\n", 1)[1].split("\npermissions:\n", 1)[0]
    assert "workflow_dispatch:" in dispatch
    assert "pull_request_number:" in dispatch
    assert "type: number" in dispatch
    assert "review_contract:" in dispatch
    assert "type: choice" in dispatch
    assert "default: legacy-v14" in dispatch
    assert "          - legacy-v14\n          - bounded-production-v16\n          - bounded-production-v17" in dispatch
    assert "target_repository:" not in dispatch
    assert "harness_sha:" not in dispatch
    assert "LLM_BASE_URL:" not in dispatch
    assert "JEV_BASE_URL:" not in dispatch
    assert "if: github.ref == 'refs/heads/main'" in source


def test_pilot_calls_immutable_harness_and_passes_only_named_provider_secrets():
    source = _source()
    call = source.split("  analyze:\n", 1)[1]
    uses_match = re.search(r"uses: groktopus/codereview/.github/workflows/pr-analysis.yml@([0-9a-f]{40})", call)
    sha_match = re.search(r"harness_sha: ([0-9a-f]{40})", call)
    assert uses_match is not None and sha_match is not None
    assert uses_match.group(1) == sha_match.group(1) == PIN
    assert "harness_repository: groktopus/codereview" in call
    assert "target_repository: magnus919/SlopSearX" in call
    assert "pull_request_number: ${{ fromJSON(inputs.pull_request_number) }}" in call
    assert "review_contract: ${{ inputs.review_contract }}" in call
    assert "profile_path:" not in call
    assert "limits_path:" not in call
    secret_block = call.split("    secrets:\n", 1)[1]
    for name in SECRETS:
        assert f"      {name}: ${{{{ secrets.{name} }}}}" in secret_block
    assert "secrets: inherit" not in source
    assert "pull-requests: write" not in source
    assert "contents: write" not in source
    assert "actions: write" not in source
    assert "pr-publish.yml" not in source
    assert "--effect-policy" not in call
    assert "--max-claim-assessments" not in call


def test_metadata_job_is_read_only_and_does_not_receive_provider_secrets():
    source = _source()
    resolve = source.split("  resolve-target:\n", 1)[1].split("\n  analyze:\n", 1)[0]
    assert "GH_TOKEN: ${{ github.token }}" in resolve
    assert "repos/magnus919/SlopSearX/pulls/" in resolve
    assert "LLM_API_KEY" not in resolve
    assert "JEV_API_KEY" not in resolve
    assert "checkout@" not in resolve
    assert "pull-requests: write" not in resolve
    assert "contents: write" not in resolve


def test_actions_read_is_granted_only_where_reusable_workflow_requires_it():
    source = _source()
    global_permissions = source.split("permissions:\n", 1)[1].split("\n\nconcurrency:", 1)[0]
    resolve = source.split("  resolve-target:\n", 1)[1].split("\n  analyze:\n", 1)[0]
    analyze = source.split("  analyze:\n", 1)[1]
    analyze_permissions = analyze.split("    permissions:\n", 1)[1].split("\n    uses:", 1)[0]

    assert "actions: read" in global_permissions
    assert "actions: read" in analyze_permissions
    assert "actions:" not in resolve


def test_metadata_validator_emits_only_current_open_main_pr_identity(monkeypatch, tmp_path):
    metadata = json.dumps(_record(), separators=(",", ":"))
    output = _run_metadata(monkeypatch, tmp_path, metadata)
    assert output == (
        "base_ref=main\n"
        "base_sha=c355830512fa5bffc167926a6a167bace93d96c6\n"
        "head_sha=c8496b74d8e1da05a2ed654772fc4b1b1fcff56b\n"
    )


@pytest.mark.parametrize(
    ("record", "reason"),
    [
        ({"state": "closed"}, "target_pull_request_not_open_ready"),
        ({"draft": True}, "target_pull_request_not_open_ready"),
        ({"base": {"repo": {"full_name": "someone/else"}}}, "target_base_repository_mismatch"),
        ({"base": {"ref": "release"}}, "target_base_ref_mismatch"),
        ({"head": {"sha": "not-a-commit"}}, "target_head_sha_invalid"),
    ],
)
def test_metadata_validator_fails_closed_for_unready_or_mismatched_pr(monkeypatch, tmp_path, record, reason):
    current = _record()
    for key, value in record.items():
        if isinstance(value, dict) and isinstance(current.get(key), dict):
            current[key].update(value)
        else:
            current[key] = value
    source = _source()
    namespace = {"__name__": "test_workflow_metadata"}
    exec(compile(_metadata_script(source), "slopsearx-pilot metadata", "exec"), namespace)
    monkeypatch.setenv("PR_NUMBER", "477")
    monkeypatch.setenv("GITHUB_OUTPUT", str(tmp_path / "github-output"))
    result = SimpleNamespace(returncode=0, stdout=json.dumps(current))
    with patch.object(subprocess, "run", return_value=result):
        with pytest.raises(SystemExit, match=reason):
            namespace["main"]()
    assert not (tmp_path / "github-output").exists()


def test_metadata_validator_rejects_invalid_dispatch_number_before_api_call(monkeypatch, tmp_path):
    source = _source()
    namespace = {"__name__": "test_workflow_metadata"}
    exec(compile(_metadata_script(source), "slopsearx-pilot metadata", "exec"), namespace)
    monkeypatch.setenv("PR_NUMBER", "477; echo unsafe")
    monkeypatch.setenv("GITHUB_OUTPUT", str(tmp_path / "github-output"))
    with patch.object(subprocess, "run") as run:
        with pytest.raises(SystemExit, match="pull_request_number_invalid"):
            namespace["main"]()
    run.assert_not_called()
