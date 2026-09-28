from __future__ import annotations

import importlib.util
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "src"))
SPEC = importlib.util.spec_from_file_location(
    "run_pr_review_stage_diagnostic", ROOT / "scripts" / "run_pr_review_stage_diagnostic.py"
)
assert SPEC is not None and SPEC.loader is not None
diagnostic = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(diagnostic)


def _private_paths(tmp_path: Path) -> tuple[Path, Path, Path]:
    runner = tmp_path / "runner"
    runner.mkdir(mode=0o700)
    os.chmod(runner, 0o700)
    preparation = runner / "private-shadow-preparation"
    preparation.mkdir(mode=0o700)
    os.chmod(preparation, 0o700)
    output = runner / "prepare-output"
    output.mkdir(mode=0o700)
    return runner, preparation / "stage-diagnostic.json", output


def _cli_args(profile: Path, output: Path) -> list[str]:
    return [
        "review", "--repo", str(ROOT), "--base", "a" * 40, "--head", "b" * 40,
        "--profile", str(profile), "--provider-config",
        str(ROOT / "experiments/model-only-shadow-live-writer-provider-v1.json"),
        "--limits", str(ROOT / "experiments/model-only-shadow-live-writer-limits-v1.json"),
        "--historical-checks-json", str(ROOT / "docs/real-case-trial-v1/checks/PR-464.json"),
        "--mode", "AUTO", "--effect-policy", "READ_ONLY", "--run-id", "diagnostic-test",
        "--output", str(output), "--prepare-only", "--json",
    ]


def test_wrapper_records_profile_failure_stage_without_details(tmp_path: Path, monkeypatch, capsys):
    runner, stage_path, output = _private_paths(tmp_path)
    monkeypatch.setenv("RUNNER_TEMP", str(runner))
    monkeypatch.setenv("GITHUB_EVENT_PATH", "")
    code = diagnostic.main(["--stage-output", str(stage_path), "--", *_cli_args(tmp_path / "missing-profile.json", output)])
    captured = capsys.readouterr().out
    assert code == 2
    assert json.loads(captured) == {"error": "cannot read profile JSON", "exit_code": 2}
    stage = json.loads(stage_path.read_text())
    assert stage == {
        "schema": "pr-review-prepare-stage-diagnostic.v1", "stage": "profile_configuration", "exit_code": 2,
    }
    assert stat_mode(stage_path) == 0o600
    assert "missing-profile" not in stage_path.read_text()
    private_output = stage_path.parent / "cli-error.json"
    private_output.write_text(captured.strip())
    os.chmod(private_output, 0o600)
    from scripts.extract_pr_review_failure_code import extract, extract_stage

    assert {"stage": extract_stage(stage_path, 2), **extract(private_output, 2)} == {
        "stage": "profile_configuration", "error": "cannot read profile JSON", "exit_code": 2,
    }


def test_untrusted_exception_text_is_not_retained_or_logged(tmp_path: Path, monkeypatch, capsys):
    import pr_review_harness.cli as cli

    runner, stage_path, output = _private_paths(tmp_path)
    profile = tmp_path / "profile.json"
    profile.write_text("{}")
    monkeypatch.setenv("RUNNER_TEMP", str(runner))
    monkeypatch.setenv("GITHUB_EVENT_PATH", "")
    original = cli._load_json

    def malicious(*_args, **_kwargs):
        raise ValueError("hostile source says leak-secret-marker")

    monkeypatch.setattr(cli, "_load_json", malicious)
    code = diagnostic.main(["--stage-output", str(stage_path), "--", *_cli_args(profile, output)])
    captured = capsys.readouterr()
    assert code == 2
    assert json.loads(captured.out) == {"error": "preflight_rejected", "exit_code": 2}
    assert "leak-secret-marker" not in captured.out and "leak-secret-marker" not in captured.err
    assert json.loads(stage_path.read_text())["stage"] == "profile_configuration"
    assert "leak-secret-marker" not in stage_path.read_text()
    monkeypatch.setattr(cli, "_load_json", original)


def stat_mode(path: Path) -> int:
    import stat

    return stat.S_IMODE(path.stat().st_mode)
