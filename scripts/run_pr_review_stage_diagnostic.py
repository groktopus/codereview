#!/usr/bin/env python3
"""Run pr-review unchanged while recording only a fixed failed preflight stage."""

from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path
from typing import Any, Callable

STAGES = {
    "profile_configuration", "limits_validation", "provider_configuration",
    "historical_checks_load", "historical_checks_validation", "snapshot_collection",
    "planning", "task_preparation", "request_evidence_selection", "request_serialization",
    "historical_snapshot_binding", "review_option_validation", "run_identity_validation",
    "review_pipeline_unclassified", "configuration_setup", "cli_preflight_unclassified",
}


class StageReceiptError(RuntimeError):
    """The private stage-only receipt cannot be written safely."""


class StageTracker:
    def __init__(self) -> None:
        self.failed_stage: str | None = None
        self.active_stage: str | None = None

    def wrap(self, stage: str, function: Callable[..., Any]) -> Callable[..., Any]:
        def tracked(*args: Any, **kwargs: Any) -> Any:
            try:
                return function(*args, **kwargs)
            except BaseException:
                if self.failed_stage is None and stage in STAGES:
                    self.failed_stage = stage
                raise
        return tracked


def _write_stage(path: Path, exit_code: int, stage: str) -> None:
    runner_temp_value = os.environ.get("RUNNER_TEMP")
    if not runner_temp_value or stage not in STAGES or exit_code not in (1, 2):
        raise StageReceiptError("stage_receipt_invalid")
    runner_temp = Path(runner_temp_value).resolve(strict=True)
    target = path.absolute()
    parent = target.parent
    parent_info = parent.lstat()
    if (
        parent.parent != runner_temp
        or not stat.S_ISDIR(parent_info.st_mode) or stat.S_IMODE(parent_info.st_mode) != 0o700
        or parent.is_symlink() or target.exists() or target.is_symlink()
    ):
        raise StageReceiptError("stage_receipt_path_invalid")
    payload = json.dumps(
        {"schema": "pr-review-prepare-stage-diagnostic.v1", "stage": stage, "exit_code": exit_code},
        sort_keys=True, separators=(",", ":"),
    ).encode("ascii") + b"\n"
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise StageReceiptError("stage_receipt_output_invalid")
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(fd)


def _install_tracking(tracker: StageTracker) -> tuple[Any, Any, Callable[[], None]]:
    from pr_review_harness import checks, cli, engine, planner, providers

    original_load_json = cli._load_json

    def tracked_load_json(path: str, label: str) -> Any:
        stage = {"profile": "profile_configuration", "limits": "limits_validation"}.get(
            label, "configuration_setup"
        )
        try:
            return original_load_json(path, label)
        except BaseException:
            if tracker.failed_stage is None:
                tracker.failed_stage = stage
            raise

    original_ingest = checks.ingest_check_runs
    original_validate_checks = cli._validate_historical_checks

    def tracked_validate_checks(*args: Any, **kwargs: Any) -> Any:
        previous_stage = tracker.active_stage
        tracker.active_stage = "historical_checks_validation"
        try:
            return original_validate_checks(*args, **kwargs)
        except BaseException:
            if tracker.failed_stage is None:
                tracker.failed_stage = "historical_checks_validation"
            raise
        finally:
            tracker.active_stage = previous_stage

    def tracked_ingest(*args: Any, **kwargs: Any) -> Any:
        stage = tracker.active_stage or "historical_snapshot_binding"
        try:
            return original_ingest(*args, **kwargs)
        except BaseException:
            if tracker.failed_stage is None:
                tracker.failed_stage = stage
            raise

    patches = [
        (cli, "_load_json", tracked_load_json),
        (cli, "_read_limits", tracker.wrap("limits_validation", cli._read_limits)),
        (providers, "load_provider_config", tracker.wrap("provider_configuration", providers.load_provider_config)),
        (cli, "_load_historical_checks", tracker.wrap("historical_checks_load", cli._load_historical_checks)),
        (cli, "_validate_historical_checks", tracked_validate_checks),
        (cli, "collect_snapshot", tracker.wrap("snapshot_collection", cli.collect_snapshot)),
        (cli, "_rebind_snapshot_evidence_references", tracker.wrap(
            "historical_snapshot_binding", cli._rebind_snapshot_evidence_references
        )),
        (checks, "ingest_check_runs", tracked_ingest),
        (planner, "plan_review", tracker.wrap("planning", planner.plan_review)),
        (engine, "prepare_plan_tasks", tracker.wrap("task_preparation", engine.prepare_plan_tasks)),
        (engine, "_evidence_for", tracker.wrap("request_evidence_selection", engine._evidence_for)),
        (providers.OpenAIProvider, "serialize_review_request", tracker.wrap(
            "request_serialization", providers.OpenAIProvider.serialize_review_request
        )),
        (cli, "_claim_assessment_cap", tracker.wrap("review_option_validation", cli._claim_assessment_cap)),
        (cli, "_validate_run_id", tracker.wrap("run_identity_validation", cli._validate_run_id)),
        (cli, "_run_one", tracker.wrap("review_pipeline_unclassified", cli._run_one)),
        (cli, "_configs", tracker.wrap("configuration_setup", cli._configs)),
    ]
    originals = [(owner, name, getattr(owner, name)) for owner, name, _replacement in patches]
    for owner, name, replacement in patches:
        setattr(owner, name, replacement)
    original_emit = cli._emit_error

    def restore() -> None:
        for owner, name, original in originals:
            setattr(owner, name, original)

    return cli, original_emit, restore


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    try:
        separator = arguments.index("--")
        stage_path = Path(arguments[1]) if arguments[0] == "--stage-output" else None
        if stage_path is None or separator != 2 or len(arguments) <= separator + 1:
            raise StageReceiptError("stage_arguments_invalid")
        cli_argv = arguments[separator + 1:]
    except (ValueError, IndexError):
        print('{"error":"diagnostic_wrapper_invalid_arguments","exit_code":2}')
        return 2

    tracker = StageTracker()
    try:
        cli, original_emit, restore_tracking = _install_tracking(tracker)
    except Exception:
        print('{"error":"diagnostic_wrapper_unavailable","exit_code":2}')
        return 2

    def emit_error(args: Any, code: int, message: str, *, diagnostic_artifact_path: str | None = None) -> None:
        stage = tracker.failed_stage or "cli_preflight_unclassified"
        try:
            _write_stage(stage_path, code, stage)
        except Exception:
            pass
        original_emit(args, code, message, diagnostic_artifact_path=diagnostic_artifact_path)

    cli._emit_error = emit_error
    try:
        return cli.main(cli_argv)
    except Exception:
        try:
            _write_stage(stage_path, 1, tracker.failed_stage or "cli_preflight_unclassified")
        except Exception:
            pass
        print('{"error":"review_runtime_failed","exit_code":1}')
        return 1
    finally:
        cli._emit_error = original_emit
        restore_tracking()


if __name__ == "__main__":
    raise SystemExit(main())
