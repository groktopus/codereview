"""Offline contract tests for the fixed historical PR466 wrapper."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/run_historical_functional_review.py"
SPEC = importlib.util.spec_from_file_location("historical_functional_review", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
review = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(review)


@pytest.fixture(autouse=True)
def isolate_github_actions_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep local test outcomes independent of the runner's event context."""
    for name in (
        "GITHUB_ACTIONS",
        "GITHUB_EVENT_NAME",
        "GITHUB_REF",
        "GITHUB_SHA",
        "GITHUB_WORKFLOW_REF",
    ):
        monkeypatch.delenv(name, raising=False)


def _bare_repo(path: Path) -> tuple[str, str]:
    path.mkdir()
    subprocess.run(["git", "init", "--bare", str(path)], check=True, capture_output=True)
    seed = path.parent / "seed"
    seed.mkdir()
    subprocess.run(["git", "init", str(seed)], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(seed), "config", "user.name", "Test"], check=True)
    subprocess.run(["git", "-C", str(seed), "config", "user.email", "test@example.invalid"], check=True)
    (seed / "case.txt").write_text("base\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(seed), "add", "case.txt"], check=True)
    subprocess.run(["git", "-C", str(seed), "commit", "-m", "base"], check=True, capture_output=True)
    base = subprocess.run(
        ["git", "-C", str(seed), "rev-parse", "HEAD"], check=True, capture_output=True, text=True
    ).stdout.strip()
    (seed / "case.txt").write_text("head\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(seed), "commit", "-am", "head"], check=True, capture_output=True)
    head = subprocess.run(
        ["git", "-C", str(seed), "rev-parse", "HEAD"], check=True, capture_output=True, text=True
    ).stdout.strip()
    subprocess.run(["git", "-C", str(seed), "push", str(path), "HEAD"], check=True, capture_output=True)
    return base, head


def test_target_preflight_requires_bare_repo_and_both_exact_objects(tmp_path: Path, monkeypatch) -> None:
    bare = tmp_path / "target.git"
    base, head = _bare_repo(bare)
    monkeypatch.setattr(review, "BASE", base)
    monkeypatch.setattr(review, "HEAD", head)

    review._validate_target(bare)
    with pytest.raises(review.SafeFailure, match="target_bare_repository_unavailable"):
        review._validate_target(tmp_path / "missing.git")
    with pytest.raises(review.SafeFailure, match="target_bare_repository_unavailable"):
        review._validate_target(bare / "not-a-repository")


def test_actual_prepare_main_uses_only_prepare_boundary_and_no_live_config(tmp_path: Path, monkeypatch, capsys) -> None:
    bare = tmp_path / "target.git"
    base, head = _bare_repo(bare)
    monkeypatch.setattr(review, "BASE", base)
    monkeypatch.setattr(review, "HEAD", head)
    monkeypatch.setattr(review, "_validate_source_and_inputs", lambda: {})
    monkeypatch.setattr(review, "_limits_valid", lambda: None)

    config_calls: list[bool] = []

    def configs(directory: Path, *, live: bool) -> tuple[Path, Path]:
        config_calls.append(live)
        assert live is False
        return directory / "provider.json", directory / "decision.json"

    cli_calls: list[dict] = []

    def cli(target: Path, output: Path, provider: Path, decision: Path, *, prepare: bool) -> dict:
        cli_calls.append({"target": target, "prepare": prepare})
        assert prepare is True
        return {
            "no_provider_calls": True,
            "no_target_code_execution": True,
            "scope": {"primary_scope_admission_complete": True},
            "capacity": {"exact_primary_call_demand": 7, "exact_primary_serialized_input_bytes": 353_963},
            "primary_requests": [
                {"input_bytes": value} for value in (49_595, 50_084, 49_564, 55_674, 56_175, 36_640, 56_231)
            ],
        }

    monkeypatch.setattr(review, "_configs", configs)
    monkeypatch.setattr(review, "_cli", cli)
    out = tmp_path / "result"
    monkeypatch.setattr(sys, "argv", [str(SCRIPT), "prepare", "--target-bare", str(bare), "--output-dir", str(out)])
    for name in ("LLM_BASE_URL", "LLM_MODEL", "LLM_API_KEY", "JEV_BASE_URL", "JEV_MODEL", "JEV_API_KEY"):
        monkeypatch.setenv(name, "sentinel-must-not-be-used")

    assert review.main() == 0
    assert config_calls == [False]
    assert len(cli_calls) == 1 and cli_calls[0]["prepare"] is True
    assert cli_calls[0]["target"] == bare.resolve()
    emitted = json.loads(capsys.readouterr().out)
    assert emitted["status"] == "PREPARED_ONLY"
    observation = json.loads((out / "prepare-observation.json").read_text(encoding="utf-8"))
    assert observation["provider_calls"] == 0
    assert observation["target_code_executed"] is False
    assert observation["capacity"]["exact_primary_call_demand"] == 7


@pytest.mark.parametrize(
    "capacity,requests",
    [
        ({"exact_primary_call_demand": 11, "exact_primary_serialized_input_bytes": 1}, [{"input_bytes": 1}]),
        ({"exact_primary_call_demand": 1, "exact_primary_serialized_input_bytes": 600_001}, [{"input_bytes": 1}]),
        ({"exact_primary_call_demand": 1, "exact_primary_serialized_input_bytes": 1}, [{"input_bytes": 64_001}]),
        ({"exact_primary_call_demand": True, "exact_primary_serialized_input_bytes": 1}, [{"input_bytes": 1}]),
    ],
)
def test_prepare_rejects_out_of_contract_demand_before_review(capacity: dict, requests: list[dict]) -> None:
    with pytest.raises(review.SafeFailure):
        review._validate_prepare(
            {
                "no_provider_calls": True,
                "no_target_code_execution": True,
                "scope": {"primary_scope_admission_complete": True},
                "capacity": capacity,
                "primary_requests": requests,
            }
        )


def test_prepare_rejects_missing_execution_invariants() -> None:
    with pytest.raises(review.SafeFailure, match="prepare_invariant_failed"):
        review._validate_prepare(
            {
                "no_provider_calls": False,
                "no_target_code_execution": True,
                "capacity": {"exact_primary_call_demand": 1, "exact_primary_serialized_input_bytes": 1},
                "primary_requests": [{"input_bytes": 1}],
            }
        )


@pytest.mark.parametrize("scope", [None, {}, {"primary_scope_admission_complete": False}])
def test_prepare_rejects_missing_primary_scope_admission(scope: dict | None) -> None:
    result = {
        "no_provider_calls": True,
        "no_target_code_execution": True,
        "capacity": {"exact_primary_call_demand": 1, "exact_primary_serialized_input_bytes": 1},
        "primary_requests": [{"input_bytes": 1}],
    }
    if scope is not None:
        result["scope"] = scope
    with pytest.raises(review.SafeFailure, match="primary_request_capacity_exceeded"):
        review._validate_prepare(result)


def test_bad_fixed_input_hash_fails_before_configuration_or_cli(tmp_path: Path, monkeypatch, capsys) -> None:
    bad_checks = tmp_path / "bad-checks.json"
    bad_checks.write_text("{}\n", encoding="utf-8")
    monkeypatch.setattr(review, "CHECKS", bad_checks)
    monkeypatch.setattr(review, "_configs", lambda *args, **kwargs: pytest.fail("config reached before input hash"))
    monkeypatch.setattr(review, "_cli", lambda *args, **kwargs: pytest.fail("CLI reached before input hash"))
    monkeypatch.setattr(
        sys,
        "argv",
        [str(SCRIPT), "prepare", "--target-bare", str(tmp_path), "--output-dir", str(tmp_path / "out")],
    )

    assert review.main() == 2
    assert "case_input_hash_mismatch" in capsys.readouterr().err
    assert not (tmp_path / "out").exists()


def test_run_with_untrusted_dispatch_context_fails_before_configuration(tmp_path: Path, monkeypatch, capsys) -> None:
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_EVENT_NAME", "workflow_dispatch")
    monkeypatch.setenv("GITHUB_REF", "refs/heads/attacker-branch")
    monkeypatch.setattr(review, "_configs", lambda *args, **kwargs: pytest.fail("config reached before source gate"))
    monkeypatch.setattr(review, "_cli", lambda *args, **kwargs: pytest.fail("CLI reached before source gate"))
    monkeypatch.setattr(
        sys,
        "argv",
        [str(SCRIPT), "run", "--target-bare", str(tmp_path), "--output-dir", str(tmp_path / "out")],
    )

    assert review.main() == 2
    assert "live_mode_requires_trusted_workflow_dispatch" in capsys.readouterr().err
    assert not (tmp_path / "out").exists()


def test_non_object_manifest_fails_with_sanitized_reason(tmp_path: Path, monkeypatch) -> None:
    malformed = tmp_path / "manifest.json"
    malformed.write_text("[]\n", encoding="utf-8")
    monkeypatch.setattr(review, "MANIFEST", malformed)

    with pytest.raises(review.SafeFailure, match="case_manifest_invalid"):
        review._validate_source_and_inputs()


def test_cli_child_has_explicit_case_and_strips_ambient_event_and_auth(tmp_path: Path, monkeypatch) -> None:
    seen: dict = {}

    class Completed:
        returncode = 0
        stdout = '{"no_provider_calls":true,"no_target_code_execution":true}'

    def run(command: list[str], **kwargs) -> Completed:
        seen["command"] = command
        seen["env"] = kwargs["env"]
        seen["timeout"] = kwargs["timeout"]
        return Completed()

    monkeypatch.setattr(review.subprocess, "run", run)
    for name in (
        "GITHUB_EVENT_PATH",
        "GITHUB_TOKEN",
        "GH_TOKEN",
        "ACTIONS_RUNTIME_TOKEN",
        "ACTIONS_RUNTIME_URL",
        "ACTIONS_RESULTS_URL",
    ):
        monkeypatch.setenv(name, "ambient-sentinel")

    result = review._cli(
        tmp_path / "target.git", tmp_path / "out", tmp_path / "provider", tmp_path / "decision", prepare=True
    )
    assert result["no_provider_calls"] is True
    assert "--historical-checks-json" in seen["command"]
    assert "--prepare-only" in seen["command"]
    assert "--max-claim-assessments" in seen["command"]
    assert "--github-pr" not in seen["command"]
    assert seen["timeout"] == 630
    assert all(
        name not in seen["env"]
        for name in (
            "GITHUB_EVENT_PATH",
            "GITHUB_TOKEN",
            "GH_TOKEN",
            "ACTIONS_RUNTIME_TOKEN",
            "ACTIONS_RUNTIME_URL",
            "ACTIONS_RESULTS_URL",
        )
    )


def test_workflow_uses_trusted_checkout_and_exact_artifact_allowlists() -> None:
    workflow = yaml.load(
        (ROOT / ".github/workflows/historical-functional-review.yml").read_text(encoding="utf-8"),
        Loader=yaml.BaseLoader,
    )
    jobs = workflow["jobs"]
    prepare = jobs["prepare"]
    live = jobs["live-diagnostic"]

    for job in (prepare, live):
        checkout = next(step for step in job["steps"] if step.get("uses", "").startswith("actions/checkout@"))
        assert checkout["with"]["ref"] == "${{ github.sha }}"
        assert checkout["with"]["persist-credentials"] == "false"

    prepare_upload = next(
        step for step in prepare["steps"] if step.get("uses", "").startswith("actions/upload-artifact@")
    )
    live_upload = next(step for step in live["steps"] if step.get("uses", "").startswith("actions/upload-artifact@"))
    assert prepare_upload["with"]["path"] == "${{ runner.temp }}/pr466-prepare/prepare-observation.json"
    assert live_upload["with"]["path"].splitlines() == [
        "${{ runner.temp }}/pr466-review/review-result.json",
        "${{ runner.temp }}/pr466-review/review-report.md",
    ]
    assert live["if"].startswith("inputs.execute_live == true")
