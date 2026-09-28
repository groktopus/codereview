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


def test_run_pipeline_fallback_is_bounded_and_keeps_specific_stage(tmp_path: Path, monkeypatch):
    import pr_review_harness.cli as cli
    import pr_review_harness.planner as planner

    tracker = diagnostic.StageTracker()
    original_run_one = cli._run_one
    original_plan_review = planner.plan_review

    def failing_run_one(*_args, **_kwargs):
        planner.plan_review({}, {}, "AUTO")

    def failing_plan(*_args, **_kwargs):
        raise ValueError("untrusted diagnostic marker")

    monkeypatch.setattr(cli, "_run_one", failing_run_one)
    monkeypatch.setattr(planner, "plan_review", failing_plan)
    _cli, _emit, restore = diagnostic._install_tracking(tracker)
    try:
        try:
            cli._run_one(None, "", "", {}, {}, None, None, "run")
        except ValueError:
            pass
        else:
            raise AssertionError("expected the injected pipeline failure")
        assert tracker.failed_stage == "planning"
        assert "untrusted diagnostic marker" not in repr(tracker.__dict__)
    finally:
        restore()
        monkeypatch.setattr(cli, "_run_one", original_run_one)
        monkeypatch.setattr(planner, "plan_review", original_plan_review)


def test_run_pipeline_fallback_classifies_untracked_failure(tmp_path: Path, monkeypatch):
    import pr_review_harness.cli as cli

    tracker = diagnostic.StageTracker()
    original_run_one = cli._run_one

    def fail(*_args, **_kwargs):
        raise ValueError("source-controlled text must not escape")

    monkeypatch.setattr(cli, "_run_one", fail)
    _cli, _emit, restore = diagnostic._install_tracking(tracker)
    try:
        try:
            cli._run_one(None, "", "", {}, {}, None, None, "run")
        except ValueError:
            pass
        else:
            raise AssertionError("expected the injected pipeline failure")
        assert tracker.failed_stage == "review_pipeline_unclassified"
        assert "source-controlled text" not in repr(tracker.__dict__)
    finally:
        restore()
        monkeypatch.setattr(cli, "_run_one", original_run_one)


def test_check_ingestion_failure_is_classified_by_call_site(monkeypatch):
    import pr_review_harness.checks as checks

    tracker = diagnostic.StageTracker()
    original_ingest = checks.ingest_check_runs

    def fail(*_args, **_kwargs):
        raise ValueError("untrusted check payload")

    monkeypatch.setattr(checks, "ingest_check_runs", fail)
    _cli, _emit, restore = diagnostic._install_tracking(tracker)
    try:
        try:
            import pr_review_harness.cli as cli

            cli._validate_historical_checks(
                {"repository": "owner/repo", "required_checks": []},
                {
                    "repository": "owner/repo", "head_sha": "a" * 40,
                    "pull_request_number": 1, "runs": [],
                },
                "b" * 40,
                "a" * 40,
            )
        except ValueError:
            pass
        else:
            raise AssertionError("expected the injected check-ingestion failure")
        assert tracker.failed_stage == "historical_checks_validation"
        assert "untrusted check payload" not in repr(tracker.__dict__)
    finally:
        restore()
        monkeypatch.setattr(checks, "ingest_check_runs", original_ingest)


def stat_mode(path: Path) -> int:
    import stat

    return stat.S_IMODE(path.stat().st_mode)
