#!/usr/bin/env python3
"""Measure installed review preparation through the bounded Linux observer."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import sysconfig
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from pr_review_harness.external_effect_observer import (  # noqa: E402
    TRACE_MAX_BYTES,
    observe_cli,
    preflight,
)

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
    "trace_duplicate_unfinished_syscall",
    "trace_pending_call_cap_exceeded",
    "process_creation_cap_exceeded",
    "trace_aggregate_bucket_cap_exceeded",
    "run_timeout",
    "tracee_cleanup_unconfirmed",
    "trace_unfinished_syscall",
    "root_exec_or_trace_incomplete",
    "trace_trailing_bytes",
}
_ACTION_EVENT_ENV = ("GITHUB_EVENT_PATH", "GITHUB_REPOSITORY", "GITHUB_RUN_ID")


def _prepare_environment(source: dict[str, str]) -> dict[str, str]:
    """Keep the smoke on its explicit synthetic revisions, outside Actions event selection."""
    env = dict(source)
    for key in _ACTION_EVENT_ENV:
        env.pop(key, None)
    env["OBSERVER_SMOKE_PROVIDER_KEY"] = "synthetic-canary-never-send"
    return env


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
        "observer_id": "linux-strace-syscall-observer.v3"
        if observed.get("observer_id") == "linux-strace-syscall-observer.v3"
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


def _validate_full_review(
    result: dict,
    observation: dict,
    invocation: dict,
    provider_calls: list[dict],
    *,
    target_marker_exists: bool,
) -> dict[str, object] | None:
    """Project only finite, typed evidence from one synthetic normal review."""
    required_lenses = {"correctness", "tests", "security", "maintainability"}
    tasks = result.get("task_results")
    if not isinstance(tasks, dict) or len(tasks) != len(required_lenses):
        return None
    if any(not isinstance(task, dict) for task in tasks.values()):
        return None
    if {task.get("lens") for task in tasks.values()} != required_lenses:
        return None
    if any(task.get("status") != "SUCCEEDED" or task.get("attempts") != 1 for task in tasks.values()):
        return None
    coverage = result.get("coverage_ledger")
    if (
        result.get("coverage_state") != "COMPLETE"
        or not isinstance(coverage, list)
        or not coverage
        or any(not isinstance(item, dict) or item.get("state") != "COMPLETE" for item in coverage)
        or any(not isinstance(item.get("lens"), str) for item in coverage if isinstance(item, dict))
        or {item.get("lens") for item in coverage} != required_lenses
        or any(item.get("required") is not True for item in coverage)
    ):
        return None
    disposition = result.get("disposition")
    if (
        not isinstance(disposition, str)
        or disposition not in {"COMMENT", "INCOMPLETE"}
        or result.get("allow_empty_approve") is not False
    ):
        return None
    freshness = result.get("freshness")
    if not isinstance(freshness, str) or freshness not in {"CURRENT", "STALE", "UNKNOWN"}:
        return None
    if (
        len(provider_calls) != len(required_lenses)
        or any(
            not isinstance(call, dict)
            or call.get("behavior") != "success"
            or call.get("path") != "/v1/chat/completions"
            for call in provider_calls
        )
        or observation.get("observer_id") != "linux-strace-syscall-observer.v3"
        or observation.get("coverage") != "SCOPED_COMPLETE"
        or observation.get("event_aggregates_complete") is not True
        or not isinstance(observation.get("event_count"), int)
        or observation.get("event_count", 0) <= 0
        or not isinstance(observation.get("trace_bytes"), int)
        or not 0 < observation["trace_bytes"] <= TRACE_MAX_BYTES
        or invocation.get("run_status") != "CLI_COMPLETED"
        or invocation.get("exit_code") != 0
        or target_marker_exists
    ):
        return None
    candidate_count = sum(
        len(task.get("payload", {}).get("finding_candidates", []))
        for task in tasks.values()
        if isinstance(task.get("payload"), dict)
        and isinstance(task.get("payload", {}).get("finding_candidates", []), list)
    )
    if candidate_count != 0:
        return None
    budget = result.get("budget")
    if (
        not isinstance(budget, dict)
        or budget.get("provider_calls_reserved") != len(required_lenses)
        or budget.get("provider_calls_limit") != 8
        or budget.get("output_bytes_reserved") != 32_000
        or budget.get("output_bytes_limit") != 32_000
        or budget.get("cost") != "UNKNOWN"
        or budget.get("cost_billing_known") is not False
        or budget.get("budget_breaches") != []
    ):
        return None
    return {
        "status": "NORMAL_REVIEW_COMPLETED",
        "coverage_state": "COMPLETE",
        "disposition": disposition,
        "freshness": freshness,
        "required_lenses": sorted(required_lenses),
        "completed_tasks": len(tasks),
        "provider_calls": len(provider_calls),
        "provider_call_limit": budget["provider_calls_limit"],
        "retries": 0,
        "output_bytes_reserved": budget["output_bytes_reserved"],
        "aggregate_output_byte_cap": budget["output_bytes_limit"],
        "cost_status": "UNKNOWN",
        "candidate_adjudication": "NOT_EXERCISED_NO_CANDIDATES",
        "jev": "NOT_CONFIGURED",
        "target_code_execution": False,
        "observer_coverage": observation["coverage"],
        "event_count": observation["event_count"],
        "trace_bytes": observation["trace_bytes"],
        "trace_byte_cap": TRACE_MAX_BYTES,
    }


def _full_review_smoke(cli: Path) -> dict[str, object] | None:
    """Run the installed CLI normally against the existing loopback fake."""
    sys.path.insert(0, str(ROOT))
    try:
        from scripts.run_recovery_rehearsal import (
            FAKE_API_KEY,
            _clean_env,
            _cli_args,
            _FakeProvider,
            _FakeProviderState,
            _limits,
            _write_fixture,
        )
        from scripts.run_recovery_rehearsal import (
            _git as fixture_git,
        )
    except ImportError:
        return None

    with tempfile.TemporaryDirectory(prefix="effect-observer-review-") as temporary:
        root = Path(temporary).resolve()
        home = root / "home"
        home.mkdir()
        deadline = time.monotonic() + 25
        state = _FakeProviderState()
        state.configure(["success"] * 8)
        server = None
        thread = None
        try:
            server = _FakeProvider(state)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            repo, base, _initial_head, profile, limits, provider_config = _write_fixture(
                root, server.endpoint, deadline
            )

            profile_value = json.loads(profile.read_text(encoding="utf-8"))
            profile_value["required_lenses"] = ["correctness", "tests", "security", "maintainability"]
            profile_value["allow_empty_approve"] = False
            profile.write_text(json.dumps(profile_value, sort_keys=True) + "\n", encoding="utf-8")
            limits_value = _limits()
            limits_value.update(
                {
                    "deadline_seconds": 20,
                    "max_concurrent_scopes": 4,
                    "max_provider_calls": 8,
                    "max_context_bytes": 128_000,
                    "max_input_bytes_per_task": 32_000,
                    "max_output_bytes_per_task": 8_000,
                    "max_output_bytes": 32_000,
                    "max_retries_per_task": 0,
                }
            )
            limits.write_text(json.dumps(limits_value, sort_keys=True) + "\n", encoding="utf-8")

            marker = root / "target-executed"
            source = repo / "sample.py"
            source.write_text(
                f"from pathlib import Path\nPath({str(marker)!r}).touch()\nVALUE = 3\n",
                encoding="utf-8",
            )
            fixture_git(["-C", str(repo), "add", "sample.py"], cwd=root, deadline_at=deadline)
            fixture_git(
                ["-C", str(repo), "-c", "core.hooksPath=/dev/null", "commit", "-m", "inert execution canary"],
                cwd=root,
                deadline_at=deadline,
            )
            head = fixture_git(["-C", str(repo), "rev-parse", "HEAD"], cwd=root, deadline_at=deadline)
            run_id = "observer-full-review-smoke"
            output = root / "output"
            env = _clean_env(home, provider_key=True)
            observed = observe_cli(
                [
                    str(cli),
                    *_cli_args(repo, base, head, profile, limits, provider_config, output, run_id),
                ],
                cwd=root,
                env=env,
                timeout_seconds=30,
            )
            result = observed.get("cli_result")
            if not isinstance(result, dict):
                return None
            durable_path = output / f"{run_id}.json"
            if not durable_path.is_file():
                return None
            durable = json.loads(durable_path.read_text(encoding="utf-8"))
            if FAKE_API_KEY in json.dumps([observed, durable], sort_keys=True):
                return None
            # The stdout projection and durable engine result must agree on the
            # core terminal fields; neither is printed from this temporary run.
            if any(result.get(key) != durable.get(key) for key in ("coverage_state", "disposition", "freshness")):
                return None
            return _validate_full_review(
                result,
                observed.get("observer", {}),
                observed.get("invocation", {}),
                state.calls,
                target_marker_exists=marker.exists(),
            )
        except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
            return None
        finally:
            if server is not None:
                server.shutdown()
                server.server_close()
            if thread is not None:
                thread.join(timeout=1)


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
        env = _prepare_environment(dict(os.environ))
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
        observed.get("observer_id") != "linux-strace-syscall-observer.v3"
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
    full_review = _full_review_smoke(cli)
    if full_review is None:
        print(
            json.dumps(
                {
                    "smoke": "INSTALLED_CLI_FULL_REVIEW_FAILED",
                    "failure": "full_review_contract_failed",
                    "prepare_smoke": "COMPLETED",
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 1
    summary["smoke"] = "INSTALLED_CLI_PREPARE_AND_FULL_REVIEW_COMPLETED"
    summary["normal_review"] = full_review
    print(json.dumps(summary, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
