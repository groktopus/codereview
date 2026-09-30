from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

import run_model_only_shadow_audit as audit_runner  # noqa: E402
from frozen_pr464_provider_prompt import install_historical_review_parts  # noqa: E402

from pr_review_harness import cli  # noqa: E402
from pr_review_harness.providers import OpenAIProvider  # noqa: E402
from pr_review_harness.shadow_preflight import AuditDispatchGuard, AuditPreflightError  # noqa: E402


class NoDispatchProvider(OpenAIProvider):
    def _call(self, **_kwargs):
        raise AssertionError("prepare-only must not call a provider")


def _source_repo() -> Path:
    value = os.environ.get("PR464_SOURCE_REPO")
    if not value:
        pytest.skip("set PR464_SOURCE_REPO to a checkout containing the frozen PR464 commits")
    repo = Path(value).resolve()
    for revision in (
        "20a743f0434a1843aa00068483f608f1e213b2af",
        "bffc26f9e4bf95aca0c252e88a2396d03ece854c",
    ):
        subprocess.run(
            ["git", "-C", str(repo), "cat-file", "-e", f"{revision}^{{commit}}"],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
    return repo


def test_frozen_pr464_exact_source_audit_capacity_is_visible_before_dispatch(
    tmp_path, monkeypatch, capsys
):
    repo = _source_repo()
    plan = json.loads((ROOT / "experiments/model-only-shadow-live-pr464-plan-v3.json").read_text())
    profile_path = ROOT / "docs/real-case-trial-v1/profiles/PR-464.json"
    profile = json.loads(profile_path.read_text())
    limits = json.loads((ROOT / "experiments/model-only-shadow-live-writer-limits-v1.json").read_text())
    provider_config = json.loads((ROOT / "experiments/model-only-shadow-live-writer-provider-v1.json").read_text())
    install_historical_review_parts(monkeypatch)
    provider = NoDispatchProvider(provider_config)
    monkeypatch.setattr(cli, "_configs", lambda _args: (profile, limits, provider, None, None))
    monkeypatch.delenv("LLM_API_KEY", raising=False)
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))

    args = [
        "review", "--repo", str(repo), "--base", plan["case"]["base_sha"], "--head", plan["case"]["head_sha"],
        "--profile", str(profile_path), "--provider-config",
        str(ROOT / "experiments/model-only-shadow-live-writer-provider-v1.json"),
        "--limits", str(ROOT / "experiments/model-only-shadow-live-writer-limits-v1.json"),
        "--historical-checks-json", str(ROOT / "docs/real-case-trial-v1/checks/PR-464.json"),
        "--output", str(tmp_path / "prepare-output"), "--run-id", "pr464-source-preflight",
        "--prepare-only", "--private-shadow-preflight-case-id", "PR-464", "--json",
    ]
    assert cli.main(args) == 0
    prepared = json.loads(capsys.readouterr().out)
    source = prepared["capacity"]["source_audit_preflight"]

    assert prepared["no_provider_calls"] is True
    assert source["active_input_limit_bytes"] == 96_000
    assert source["request_count"] == 10
    assert source["status"] == "ADMITTED"
    assert source["request_bytes_max"] == 91_832
    assert source["requests"][0]["input_bytes"] == 74_521
    assert all(len(row["input_sha256"]) == 64 for row in source["requests"])
    assert all(row["input_bytes"] <= 96_000 for row in source["requests"])
    proposal = json.loads((ROOT / "experiments/model-only-shadow-live-pr464-plan-v3-proposal.json").read_text())
    proposed_rows = proposal["source_audit_preflight"]["requests"]
    assert [
        {key: row[key] for key in ("task_id", "input_bytes", "input_sha256")}
        for row in source["requests"]
    ] == proposed_rows
    v3_limits = audit_runner._load_limits(ROOT / "experiments/model-only-shadow-audit-limits-v2.json")
    assert v3_limits["max_input_bytes_per_task"] == 96_000
    serialized = (b'{"max_completion_tokens":1800,"pad":"'
                  + b"x" * (91_832 - len(b'{"max_completion_tokens":1800,"pad":"') - 2) + b'"}')
    AuditDispatchGuard(v3_limits).check("source_auditor", serialized)
    with pytest.raises(AuditPreflightError, match="audit_request_exceeds_limit"):
        AuditDispatchGuard(v3_limits).check("source_auditor", b"x" * 96_001)
    assert not (tmp_path / "prepare-output").exists()
