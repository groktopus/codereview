#!/usr/bin/env python3
"""Measure installed review preparation through the bounded Linux observer."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import sysconfig
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from pr_review_harness.external_effect_observer import observe_cli, preflight  # noqa: E402

_RUN_STATUSES = {
    "CLI_COMPLETED",
    "CLI_FAILED",
    "INVALID_CLI_OUTPUT",
    "OBSERVER_TRACE_INCOMPLETE",
    "OBSERVER_UNAVAILABLE",
    "OBSERVER_SPAWN_FAILED",
    "OBSERVER_PROCESS_CAP_EXCEEDED",
    "RUN_TIMEOUT",
    "OUTPUT_LIMIT_EXCEEDED",
}
_CLI_ERRORS = {
    "invalid_arguments",
    "snapshot_preflight_failed",
    "preflight_rejected",
    "review_runtime_failed",
    "provider_configuration_invalid",
    "provider_adapter_unavailable",
    "profile_unavailable",
    "limits_unavailable",
    "other",
}
_OBSERVER_REASONS = {
    "linux_required",
    "strace_unavailable",
    "observer_identity_unavailable",
    "strace_version_probe_failed",
    "kill_on_exit_unavailable",
    "strace_version_invalid",
    "observer_deadline_exhausted",
    "timeout_invalid",
    "observer_unavailable",
    "command_invalid",
    "strace_spawn_failed",
    "trace_read_failed",
    "cli_output_read_failed",
    "trace_byte_cap_exceeded",
    "cli_output_cap_exceeded",
    "trace_line_cap_exceeded",
    "trace_parse_failed",
    "root_exec_launch_not_proven",
    "trace_resume_without_unfinished",
    "process_creation_cap_exceeded",
    "trace_aggregate_bucket_cap_exceeded",
    "run_timeout",
    "tracee_cleanup_unconfirmed",
    "trace_unfinished_syscall",
    "root_exec_or_trace_incomplete",
    "trace_trailing_bytes",
}


def _failure_summary(result: dict, failure: str) -> dict[str, object]:
    """Emit only allowlisted status codes and numeric observer counters."""
    observed = result.get("observer", {})
    invocation = result.get("invocation", {})
    cli_result = result.get("cli_result") or {}
    reason = observed.get("reason")
    cli_error = invocation.get("cli_error_code")
    return {
        "smoke": "INSTALLED_CLI_PREPARE_ONLY_FAILED",
        "failure": failure,
        "observer_id": "linux-strace-syscall-observer.v2"
        if observed.get("observer_id") == "linux-strace-syscall-observer.v2"
        else "unknown",
        "observer_reason": reason if isinstance(reason, str) and reason in _OBSERVER_REASONS else "other",
        "coverage": observed.get("coverage") if isinstance(observed.get("coverage"), str) and observed.get("coverage") in {"SCOPED_COMPLETE", "INCOMPLETE", "UNKNOWN"} else "UNKNOWN",
        "event_count": observed.get("event_count") if isinstance(observed.get("event_count"), int) else None,
        "event_aggregates_complete": observed.get("event_aggregates_complete") if isinstance(observed.get("event_aggregates_complete"), bool) else None,
        "trace_bytes": observed.get("trace_bytes") if isinstance(observed.get("trace_bytes"), int) else None,
        "invocation_status": invocation.get("run_status") if isinstance(invocation.get("run_status"), str) and invocation.get("run_status") in _RUN_STATUSES else "UNKNOWN",
        "cli_exit_code": invocation.get("exit_code") if isinstance(invocation.get("exit_code"), int) else None,
        "cli_status": cli_result.get("status") if cli_result.get("status") == "PREPARED_ONLY" else "UNKNOWN",
        "cli_error_code": cli_error if isinstance(cli_error, str) and cli_error in _CLI_ERRORS else "other" if cli_error else None,
        "no_provider_calls": cli_result.get("no_provider_calls") if isinstance(cli_result.get("no_provider_calls"), bool) else None,
        "no_target_code_execution": cli_result.get("no_target_code_execution") if isinstance(cli_result.get("no_target_code_execution"), bool) else None,
    }


def _git(repo: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repo), *args], check=True, capture_output=True, text=True
    )
    return completed.stdout.strip()


def main() -> int:
    identity = preflight()
    cli = Path(sysconfig.get_path("scripts")) / ("pr-review.exe" if os.name == "nt" else "pr-review")
    if identity.get("status") != "AVAILABLE" or not cli.is_file() or not os.access(cli, os.X_OK):
        raise SystemExit("effect_observer_preflight_unavailable")
    with tempfile.TemporaryDirectory(prefix="effect-observer-prepare-") as temporary:
        root = Path(temporary)
        repo = root / "repo"
        repo.mkdir()
        subprocess.run(["git", "init", str(repo)], check=True, capture_output=True)
        _git(repo, "config", "user.email", "observer-smoke@example.invalid")
        _git(repo, "config", "user.name", "Observer Smoke")
        target = repo / "src" / "example.py"
        target.parent.mkdir()
        target.write_text("def value():\n    return 1\n", encoding="utf-8")
        _git(repo, "add", "src/example.py")
        _git(repo, "-c", "core.hooksPath=/dev/null", "commit", "-m", "base")
        base = _git(repo, "rev-parse", "HEAD")
        target.write_text("def value():\n    return 2\n", encoding="utf-8")
        _git(repo, "add", "src/example.py")
        _git(repo, "-c", "core.hooksPath=/dev/null", "commit", "-m", "head")
        head = _git(repo, "rev-parse", "HEAD")

        profile = root / "profile.json"
        profile.write_text(
            json.dumps({"version": "effect-observer-smoke-v1", "required_lenses": ["correctness"]}),
            encoding="utf-8",
        )
        provider = root / "provider.json"
        provider.write_text(
            json.dumps(
                {
                    "kind": "openai_compatible",
                    "base_url": "https://provider.example.invalid/v1",
                    "model": "observer-smoke-model",
                    "api_key_env": "OBSERVER_SMOKE_PROVIDER_KEY",
                }
            ),
            encoding="utf-8",
        )
        env = dict(os.environ)
        env["OBSERVER_SMOKE_PROVIDER_KEY"] = "synthetic-canary-never-send"
        result = observe_cli(
            [
                str(cli),
                "review",
                "--repo",
                str(repo),
                "--base",
                base,
                "--head",
                head,
                "--profile",
                str(profile),
                "--provider-config",
                str(provider),
                "--output",
                str(root / "output"),
                "--prepare-only",
                "--json",
            ],
            cwd=root,
            env=env,
            timeout_seconds=30,
        )

    observed = result.get("observer", {})
    invocation = result.get("invocation", {})
    cli_result = result.get("cli_result") or {}
    if (
        observed.get("observer_id") != "linux-strace-syscall-observer.v2"
        or
        observed.get("coverage") != "SCOPED_COMPLETE"
        or invocation.get("run_status") != "CLI_COMPLETED"
        or cli_result.get("status") != "PREPARED_ONLY"
        or cli_result.get("no_provider_calls") is not True
        or cli_result.get("no_target_code_execution") is not True
    ):
        print(json.dumps(_failure_summary(result, "prepare_contract_failed"), sort_keys=True, separators=(",", ":")))
        return 1
    if "synthetic-canary-never-send" in json.dumps(result, sort_keys=True):
        print(json.dumps(_failure_summary(result, "redaction_check_failed"), sort_keys=True, separators=(",", ":")))
        return 1
    summary = {
        "smoke": "INSTALLED_CLI_PREPARE_ONLY_COMPLETED",
        "observer_id": observed.get("observer_id"),
        "overall_state": observed.get("overall_state"),
        "coverage": observed.get("coverage"),
        "channel_state": observed.get("channel_state"),
        "event_count": observed.get("event_count"),
        "event_sample_count": observed.get("event_sample_count"),
        "event_sample_truncated": observed.get("event_sample_truncated"),
        "event_aggregates_complete": observed.get("event_aggregates_complete"),
        "trace_bytes": observed.get("trace_bytes"),
        "strace_version": observed.get("strace_version"),
        "strace_executable_sha256": observed.get("strace_executable_sha256"),
        "observer_source_sha256": observed.get("source_sha256"),
        "no_provider_calls": cli_result["no_provider_calls"],
        "no_target_code_execution": cli_result["no_target_code_execution"],
    }
    print(json.dumps(summary, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
