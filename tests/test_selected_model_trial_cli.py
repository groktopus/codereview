from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import run_selected_model_trial as cli  # noqa: E402


def _base_args(tmp_path: Path) -> list[str]:
    return [
        "--run-provider-trial",
        "--output", str(tmp_path / "output"),
        "--cli-executable", str(tmp_path / "pr-review"),
        "--provider-config", str(tmp_path / "provider.json"),
        "--decision-config", str(tmp_path / "decision.json"),
    ]


def test_prepared_plan_is_forwarded_only_when_supplied_to_provider_trial(tmp_path, monkeypatch, capsys):
    calls: list[dict] = []
    monkeypatch.setattr(cli, "run_provider_trial", lambda **kwargs: calls.append(kwargs) or {"status": "PROCESS_COMPLETED"})

    assert cli.main(_base_args(tmp_path)) == 0
    assert "prepared_plan" not in calls[-1]

    prepared_plan = tmp_path / "prepared-plan.json"
    assert cli.main(_base_args(tmp_path) + ["--prepared-plan", str(prepared_plan)]) == 0
    assert calls[-1]["prepared_plan"] == prepared_plan
    assert json.loads(capsys.readouterr().out.splitlines()[-1]) == {"status": "PROCESS_COMPLETED"}


def test_prepare_only_rejects_prepared_plan_before_any_runner_call(tmp_path, monkeypatch, capsys):
    def unexpected_call(**_kwargs):
        pytest.fail("prepare-only must reject before invoking a runner")

    monkeypatch.setattr(cli, "run_provider_trial", unexpected_call)
    monkeypatch.setattr(cli, "prepare_only", unexpected_call)
    args = [
        "--prepare-only",
        "--output", str(tmp_path / "output"),
        "--cli-executable", str(tmp_path / "pr-review"),
        "--prepared-plan", str(tmp_path / "prepared-plan.json"),
    ]

    assert cli.main(args) == 2
    assert json.loads(capsys.readouterr().out) == {
        "status": "FAILED", "error": "prepare_only_rejects_prepared_plan"
    }
