from __future__ import annotations

import json
import subprocess
import textwrap
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

WORKFLOW = Path(__file__).parents[1] / ".github/workflows/codereview-self-pilot.yml"
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
    job = source.split("  resolve-target:\n", 1)[1].split("\n  analyze:\n", 1)[0]
    block = job.split("        run: |\n", 1)[1]
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
        "number": 219,
        "state": "open",
        "draft": False,
        "base": {
            "ref": "main",
            "sha": "1d4903dab34b0c51e8f3805803872c3b98e2a96c",
            "repo": {"full_name": "groktopus/codereview"},
        },
        "head": {
            "sha": "8e6ef508df6fff36ac681ea96b2cc01f749b67d8",
            "repo": {"full_name": "groktopus/codereview"},
        },
    }
    record.update(overrides)
    return record


def _run_metadata(monkeypatch, tmp_path, response):
    namespace = {"__name__": "test_codereview_workflow_metadata"}
    exec(compile(_metadata_script(_source()), "codereview-self-pilot metadata", "exec"), namespace)
    output = tmp_path / "github-output"
    output.write_text("", encoding="utf-8")
    monkeypatch.setenv("PR_NUMBER", "219")
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))

    def fake_run(command, **kwargs):
        assert command[:4] == ["gh", "api", "repos/groktopus/codereview/pulls/219", "--jq"]
        assert kwargs["timeout"] == 15
        assert kwargs["check"] is False
        return SimpleNamespace(returncode=0, stdout=response)

    with patch.object(subprocess, "run", side_effect=fake_run):
        namespace["main"]()
    return output.read_text(encoding="utf-8")


def test_self_pilot_accepts_only_a_pr_number_and_keeps_analysis_hard_disabled():
    source = _source()
    dispatch = source.split("on:\n", 1)[1].split("\npermissions:\n", 1)[0]
    analysis = source.split("  analyze:\n", 1)[1]

    assert "workflow_dispatch:" in dispatch
    assert "pull_request_number:" in dispatch
    assert "type: number" in dispatch
    assert "target_repository:" not in dispatch
    assert "review_contract:" not in dispatch
    assert "profile_path:" not in dispatch
    assert "limits_path:" not in dispatch
    assert "if: github.ref == 'refs/heads/main'" in source
    assert "if: false" in analysis
    assert "uses: ./.github/workflows/pr-analysis.yml" in analysis
    assert "harness_repository: groktopus/codereview" in analysis
    assert "harness_sha: ${{ github.sha }}" in analysis
    assert "target_repository: groktopus/codereview" in analysis
    assert "review_contract: codereview-native-v1" in analysis
    assert "emit_publication_bundle:" not in analysis
    assert "pull-requests: write" not in source
    assert "contents: write" not in source
    assert "actions: write" not in source
    assert "pr-publish.yml" not in source
    secret_block = analysis.split("    secrets:\n", 1)[1]
    for name in SECRETS:
        assert f"      {name}: ${{{{ secrets.{name} }}}}" in secret_block
    assert "secrets: inherit" not in source


def test_metadata_job_binds_exact_open_pr_base_and_head_without_provider_secrets(monkeypatch, tmp_path):
    source = _source()
    resolve_job = source.split("  resolve-target:\n", 1)[1].split("\n  analyze:\n", 1)[0]
    for name in SECRETS:
        assert name not in resolve_job
    result = _run_metadata(monkeypatch, tmp_path, json.dumps(_record()))
    assert result == (
        "base_ref=main\n"
        "base_sha=1d4903dab34b0c51e8f3805803872c3b98e2a96c\n"
        "head_sha=8e6ef508df6fff36ac681ea96b2cc01f749b67d8\n"
    )


@pytest.mark.parametrize(
    ("overrides", "expected"),
    [
        ({"state": "closed"}, "target_pull_request_not_open_ready"),
        ({"draft": True}, "target_pull_request_not_open_ready"),
        ({"base": {"ref": "release", "sha": "1d4903dab34b0c51e8f3805803872c3b98e2a96c", "repo": {"full_name": "groktopus/codereview"}}}, "target_pull_request_repository_or_base_mismatch"),
        ({"head": {"sha": "8e6ef508df6fff36ac681ea96b2cc01f749b67d8", "repo": {"full_name": "attacker/codereview"}}}, "target_pull_request_repository_or_base_mismatch"),
    ],
)
def test_metadata_job_rejects_closed_draft_or_cross_repository_prs(
    monkeypatch, tmp_path, overrides, expected
):
    namespace = {"__name__": "test_codereview_workflow_metadata"}
    exec(compile(_metadata_script(_source()), "codereview-self-pilot metadata", "exec"), namespace)
    output = tmp_path / "github-output"
    output.write_text("", encoding="utf-8")
    monkeypatch.setenv("PR_NUMBER", "219")
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))
    response = json.dumps(_record(**overrides))

    def fake_run(*_args, **_kwargs):
        return SimpleNamespace(returncode=0, stdout=response)

    with patch.object(subprocess, "run", side_effect=fake_run), pytest.raises(SystemExit, match=expected):
        namespace["main"]()
    assert output.read_text(encoding="utf-8") == ""
