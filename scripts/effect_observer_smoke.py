#!/usr/bin/env python3
"""Measure installed review preparation through the bounded Linux observer."""

from __future__ import annotations

import json
import os
import re
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
    "invalid_review_request",
    "run_id_already_exists",
    "resume_state_invalid",
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
_FULL_REVIEW_FAILURE_CODES = {
    "observer_scope_or_trace_incomplete",
    "cli_invocation_not_completed",
    "target_execution_marker_detected",
    "cli_result_unavailable",
    "required_task_count_mismatch",
    "task_result_schema_invalid",
    "task_lens_invalid",
    "required_lens_set_mismatch",
    "task_not_succeeded_once",
    "coverage_not_complete",
    "coverage_row_incomplete",
    "coverage_lens_invalid",
    "coverage_lens_set_mismatch",
    "coverage_required_flag_missing",
    "terminal_disposition_not_allowed",
    "freshness_status_invalid",
    "fake_provider_call_count_mismatch",
    "fake_provider_response_status_mismatch",
    "task_payload_schema_invalid",
    "candidate_adjudication_unexpectedly_exercised",
    "budget_or_cost_contract_mismatch",
    "recovery_fixture_import_failed",
    "fake_provider_key_exposed",
    "durable_result_missing_or_mismatched",
    "summary_projection_failed",
    "fixture_or_result_processing_failed",
}
_TASK_STATUS_VALUES = {
    "SUCCEEDED",
    "SKIPPED",
    "INVALID",
    "FAILED",
    "TIMED_OUT",
    "INTERRUPTED_UNKNOWN",
    "VALID_UNRESOLVED",
}
_TASK_ERROR_CODES = {
    "other",
    "CHECK_ADAPTER_UNAVAILABLE",
    "PROVIDER_UNAVAILABLE",
    "INPUT_BYTE_LIMIT_EXCEEDED",
    "INVALID_PROVIDER_ESTIMATE",
    "WORKER_START_FAILED",
    "INVALID_PROVIDER_RESULT",
    "INTERRUPTED_UNKNOWN",
    "RUN_CONTEXT_BUDGET_EXHAUSTED",
    "DEADLINE_EXCEEDED",
    "DEADLINE_EXHAUSTED",
    "request_exceeds_limit",
    "credential_unavailable",
    "provider_deadline_exceeded",
    "transport_failed",
    "malformed_provider_response",
    "malformed_native_response",
    "model_identity_missing",
    "model_identity_mismatch",
    "unsupported_primitive",
    "unsupported_task_kind",
    "invalid_specialist_result",
    "model_output_incomplete",
    "assessment_references_unknown_evidence",
    "response_exceeds_limit",
    "response_invalid",
    "http_status_4xx",
    "http_status_5xx",
}
_ACTION_EVENT_ENV = ("GITHUB_EVENT_PATH", "GITHUB_REPOSITORY", "GITHUB_RUN_ID")
FULL_REVIEW_FAKE_PROVIDER_TIMEOUT_SECONDS = 5.0
LONG_WAIT_PROVIDER_DELAY_SECONDS = 75.0
LONG_WAIT_PROVIDER_TIMEOUT_SECONDS = 120.0
LONG_WAIT_ENGINE_DEADLINE_SECONDS = 150
LONG_WAIT_OBSERVER_TIMEOUT_SECONDS = 180.0
_SAFE_TRACE_SYSCALLS = frozenset(
    {
        "access", "arch_prctl", "brk", "chdir", "chmod", "clone", "clone3", "close", "connect",
        "dup3", "execve", "exit_group", "fcntl", "fstat", "futex", "getcwd", "getdents64",
        "getegid", "geteuid", "getgid", "getrandom", "getuid", "ioctl", "lseek", "madvise",
        "mmap", "mprotect", "mkdirat", "nanosleep", "newfstatat", "openat", "pipe2", "poll",
        "ppoll", "prlimit64", "read", "readlink", "recvfrom", "renameat", "rt_sigaction",
        "rt_sigprocmask", "rt_sigreturn", "rseq", "sendto", "set_robust_list", "socket", "statx",
        "unlinkat", "uname", "vfork", "wait4", "waitid", "write",
    }
)


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


def _set_full_review_fake_provider_timeout(
    provider_config: Path, timeout_seconds: float = FULL_REVIEW_FAKE_PROVIDER_TIMEOUT_SECONDS
) -> None:
    """Keep the normal-review fake usable under tracing, below its engine deadline."""
    config = json.loads(provider_config.read_text(encoding="utf-8"))
    if not isinstance(config, dict):
        raise ValueError("provider_config_invalid")
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not 0 < timeout_seconds < float("inf")
    ):
        raise ValueError("provider_timeout_invalid")
    config["timeout_seconds"] = float(timeout_seconds)
    provider_config.write_text(json.dumps(config, sort_keys=True) + "\n", encoding="utf-8")


def _validate_full_review(
    result: dict,
    observation: dict,
    invocation: dict,
    provider_calls: list[dict],
    *,
    target_marker_exists: bool,
) -> dict[str, object] | None:
    """Project only finite, typed evidence from one synthetic normal review."""
    if _full_review_failure_code(
        result, observation, invocation, provider_calls, target_marker_exists=target_marker_exists
    ) is not None:
        return None
    tasks = result["task_results"]
    disposition = result["disposition"]
    freshness = result["freshness"]
    budget = result.get("budget")
    required_lenses = {"correctness", "tests", "security", "maintainability"}
    assert isinstance(budget, dict)
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
        "event_aggregates_complete": observation["event_aggregates_complete"],
        "event_counts_by_syscall": _safe_syscall_counts(
            observation.get("event_aggregates"),
            complete=observation.get("event_aggregates_complete") is True,
        ),
        "observer_source_sha256": observation.get("source_sha256")
        if isinstance(observation.get("source_sha256"), str)
        and re.fullmatch(r"[0-9a-f]{64}", observation["source_sha256"])
        else "UNKNOWN",
        "strace_version": observation.get("strace_version")
        if isinstance(observation.get("strace_version"), str)
        and re.fullmatch(r"[A-Za-z0-9 ._+-]{1,80}", observation["strace_version"])
        else "UNKNOWN",
        "strace_executable_sha256": observation.get("strace_executable_sha256")
        if isinstance(observation.get("strace_executable_sha256"), str)
        and re.fullmatch(r"[0-9a-f]{64}", observation["strace_executable_sha256"])
        else "UNKNOWN",
    }


def _safe_syscall_counts(aggregates: object, *, complete: bool) -> dict[str, object]:
    """Project aggregate counters without copying trace paths or arbitrary labels."""
    counts = {name: 0 for name in sorted(_SAFE_TRACE_SYSCALLS)}
    unknown_rows = 0
    if not isinstance(aggregates, list):
        return {"state": "UNKNOWN", "aggregates_complete": complete, "counts": counts, "unknown_rows": None}
    for row in aggregates:
        if not isinstance(row, dict):
            unknown_rows += 1
            continue
        syscall = row.get("syscall")
        count = row.get("count")
        if (
            isinstance(syscall, str)
            and syscall in counts
            and isinstance(count, int)
            and not isinstance(count, bool)
            and count >= 0
        ):
            counts[syscall] += count
        else:
            unknown_rows += 1
    return {
        "state": "SAFE_PROJECTION" if complete and unknown_rows == 0 else "PARTIAL_PROJECTION",
        "aggregates_complete": complete,
        "counts": counts,
        "unknown_rows": unknown_rows,
    }


def _full_review_failure_code(
    result: dict | None,
    observation: dict,
    invocation: dict,
    provider_calls: list[dict],
    *,
    target_marker_exists: bool,
) -> str | None:
    """Return the first stable failed stage without exposing payloads or logs."""
    observation = observation if isinstance(observation, dict) else {}
    invocation = invocation if isinstance(invocation, dict) else {}
    provider_calls = provider_calls if isinstance(provider_calls, list) else []
    if (
        observation.get("observer_id") != "linux-strace-syscall-observer.v3"
        or observation.get("coverage") != "SCOPED_COMPLETE"
        or observation.get("event_aggregates_complete") is not True
        or not isinstance(observation.get("event_count"), int)
        or isinstance(observation.get("event_count"), bool)
        or observation.get("event_count", 0) <= 0
        or not isinstance(observation.get("trace_bytes"), int)
        or isinstance(observation.get("trace_bytes"), bool)
        or not 0 < observation["trace_bytes"] <= TRACE_MAX_BYTES
    ):
        return "observer_scope_or_trace_incomplete"
    if invocation.get("run_status") != "CLI_COMPLETED" or invocation.get("exit_code") != 0:
        return "cli_invocation_not_completed"
    if target_marker_exists:
        return "target_execution_marker_detected"
    if not isinstance(result, dict):
        return "cli_result_unavailable"
    required_lenses = {"correctness", "tests", "security", "maintainability"}
    tasks = result.get("task_results")
    if not isinstance(tasks, dict) or len(tasks) != len(required_lenses):
        return "required_task_count_mismatch"
    if any(not isinstance(task, dict) for task in tasks.values()):
        return "task_result_schema_invalid"
    known_lenses = {"correctness", "tests", "security", "maintainability"}
    if any(not isinstance(task.get("lens"), str) for task in tasks.values()):
        return "task_lens_invalid"
    if {task.get("lens") for task in tasks.values()} != known_lenses:
        return "required_lens_set_mismatch"
    if any(task.get("status") != "SUCCEEDED" or task.get("attempts") != 1 for task in tasks.values()):
        return "task_not_succeeded_once"
    coverage = result.get("coverage_ledger")
    if result.get("coverage_state") != "COMPLETE" or not isinstance(coverage, list) or not coverage:
        return "coverage_not_complete"
    if any(not isinstance(item, dict) or item.get("state") != "COMPLETE" for item in coverage):
        return "coverage_row_incomplete"
    if any(not isinstance(item.get("lens"), str) for item in coverage if isinstance(item, dict)):
        return "coverage_lens_invalid"
    if {item.get("lens") for item in coverage} != required_lenses:
        return "coverage_lens_set_mismatch"
    if any(item.get("required") is not True for item in coverage):
        return "coverage_required_flag_missing"
    disposition = result.get("disposition")
    if (
        not isinstance(disposition, str)
        or disposition not in {"COMMENT", "INCOMPLETE"}
        or result.get("allow_empty_approve") is not False
    ):
        return "terminal_disposition_not_allowed"
    freshness = result.get("freshness")
    if not isinstance(freshness, str) or freshness not in {"CURRENT", "STALE", "UNKNOWN"}:
        return "freshness_status_invalid"
    if len(provider_calls) != len(required_lenses):
        return "fake_provider_call_count_mismatch"
    if any(
        not isinstance(call, dict)
        or call.get("behavior") != "success"
        or call.get("path") != "/v1/chat/completions"
        for call in provider_calls
    ):
        return "fake_provider_response_status_mismatch"
    candidate_count = 0
    for task in tasks.values():
        payload = task.get("payload")
        if not isinstance(payload, dict):
            return "task_payload_schema_invalid"
        candidates = payload.get("finding_candidates", [])
        if not isinstance(candidates, list):
            return "task_payload_schema_invalid"
        candidate_count += len(candidates)
    if candidate_count != 0:
        return "candidate_adjudication_unexpectedly_exercised"
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
        return "budget_or_cost_contract_mismatch"
    return None


def _safe_task_error_bucket(value: object) -> str:
    """Classify only known provider/engine codes; never echo an exception string."""
    if not isinstance(value, str):
        return "other"
    if value in _TASK_ERROR_CODES:
        return value
    if value.startswith("http_status_"):
        status = value[len("http_status_") :]
        if len(status) == 3 and status.isascii() and status.isdigit():
            number = int(status)
            if 400 <= number <= 499:
                return "http_status_4xx"
            if 500 <= number <= 599:
                return "http_status_5xx"
    return "other"


def _bounded_full_review_failure(
    failure_code: str,
    result: dict | None,
    observation: dict,
    invocation: dict,
    provider_calls: list[dict],
    *,
    target_marker_exists: bool,
) -> dict[str, object]:
    """Keep only stable enums, bounded counts, and byte counters for CI triage."""
    observation = observation if isinstance(observation, dict) else {}
    invocation = invocation if isinstance(invocation, dict) else {}
    provider_calls = provider_calls if isinstance(provider_calls, list) else []
    allowed_dispositions = {"APPROVE", "COMMENT", "REQUEST_CHANGES", "INCOMPLETE"}
    allowed_freshness = {"CURRENT", "STALE", "UNKNOWN"}
    tasks = result.get("task_results", {}) if isinstance(result, dict) else {}
    coverage = result.get("coverage_ledger", []) if isinstance(result, dict) else []
    budget = result.get("budget", {}) if isinstance(result, dict) else {}
    safe_task_rows = [item for item in tasks.values() if isinstance(item, dict)] if isinstance(tasks, dict) else []
    safe_coverage_rows = [item for item in coverage if isinstance(item, dict)] if isinstance(coverage, list) else []
    task_status_counts = {status: 0 for status in sorted(_TASK_STATUS_VALUES)}
    task_error_counts = {code: 0 for code in sorted(_TASK_ERROR_CODES)}
    unknown_task_status_count = 0
    unknown_task_error_count = 0
    total_task_attempts = 0
    unknown_task_attempt_count = 0
    for item in safe_task_rows:
        status = item.get("status")
        if isinstance(status, str) and status in task_status_counts:
            task_status_counts[status] += 1
        else:
            unknown_task_status_count += 1
        if status != "SUCCEEDED":
            error_code = _safe_task_error_bucket(item.get("error_code"))
            if error_code in task_error_counts:
                task_error_counts[error_code] += 1
            else:
                unknown_task_error_count += 1
        attempts = item.get("attempts")
        if isinstance(attempts, int) and not isinstance(attempts, bool) and 0 <= attempts <= 8:
            total_task_attempts += attempts
        else:
            unknown_task_attempt_count += 1
    observer_reason = observation.get("reason")
    invocation_status = invocation.get("run_status")
    return {
        "status": "NORMAL_REVIEW_FAILED",
        "failure_stage": failure_code if failure_code in _FULL_REVIEW_FAILURE_CODES else "unknown_failure",
        "observer_coverage": observation.get("coverage")
        if isinstance(observation.get("coverage"), str)
        and observation.get("coverage") in {"SCOPED_COMPLETE", "INCOMPLETE", "UNKNOWN"}
        else "UNKNOWN",
        "observer_reason": observer_reason if isinstance(observer_reason, str) and observer_reason in _OBSERVER_REASONS else "other",
        "observer_event_count": observation.get("event_count") if isinstance(observation.get("event_count"), int) and not isinstance(observation.get("event_count"), bool) else None,
        "observer_aggregates_complete": observation.get("event_aggregates_complete") if isinstance(observation.get("event_aggregates_complete"), bool) else None,
        "observer_trace_bytes": observation.get("trace_bytes") if isinstance(observation.get("trace_bytes"), int) and not isinstance(observation.get("trace_bytes"), bool) else None,
        "observer_source_sha256": observation.get("source_sha256")
        if isinstance(observation.get("source_sha256"), str)
        and re.fullmatch(r"[0-9a-f]{64}", observation["source_sha256"])
        else "UNKNOWN",
        "strace_version": observation.get("strace_version")
        if isinstance(observation.get("strace_version"), str)
        and re.fullmatch(r"[A-Za-z0-9 ._+-]{1,80}", observation["strace_version"])
        else "UNKNOWN",
        "strace_executable_sha256": observation.get("strace_executable_sha256")
        if isinstance(observation.get("strace_executable_sha256"), str)
        and re.fullmatch(r"[0-9a-f]{64}", observation["strace_executable_sha256"])
        else "UNKNOWN",
        "event_counts_by_syscall": _safe_syscall_counts(
            observation.get("event_aggregates"),
            complete=observation.get("event_aggregates_complete") is True,
        ),
        "invocation_status": invocation_status if isinstance(invocation_status, str) and invocation_status in _RUN_STATUSES else "UNKNOWN",
        "cli_exit_code": invocation.get("exit_code") if isinstance(invocation.get("exit_code"), int) and not isinstance(invocation.get("exit_code"), bool) else None,
        "cli_result_available": isinstance(result, dict),
        "task_result_rows": len(safe_task_rows),
        "succeeded_task_rows": sum(item.get("status") == "SUCCEEDED" for item in safe_task_rows),
        "task_status_counts": {key: value for key, value in task_status_counts.items() if value},
        "unknown_task_status_count": unknown_task_status_count,
        "task_error_code_counts": {key: value for key, value in task_error_counts.items() if value},
        "unknown_task_error_count": unknown_task_error_count,
        "task_attempts_total": total_task_attempts,
        "unknown_task_attempt_count": unknown_task_attempt_count,
        "observed_task_lenses": sorted(
            {
                item.get("lens")
                for item in safe_task_rows
                if isinstance(item.get("lens"), str)
                and item.get("lens") in {"correctness", "tests", "security", "maintainability"}
            }
        ),
        "unknown_task_lens_count": sum(
            not isinstance(item.get("lens"), str)
            or item.get("lens") not in {"correctness", "tests", "security", "maintainability"}
            for item in safe_task_rows
        ),
        "coverage_state": result.get("coverage_state") if isinstance(result, dict) and isinstance(result.get("coverage_state"), str) and result.get("coverage_state") in {"COMPLETE", "PARTIAL", "NOT_STARTED", "UNKNOWN"} else "UNKNOWN",
        "coverage_rows": len(safe_coverage_rows),
        "complete_coverage_rows": sum(item.get("state") == "COMPLETE" for item in safe_coverage_rows),
        "disposition": result.get("disposition")
        if isinstance(result, dict)
        and isinstance(result.get("disposition"), str)
        and result.get("disposition") in allowed_dispositions
        else "UNKNOWN",
        "freshness": result.get("freshness")
        if isinstance(result, dict)
        and isinstance(result.get("freshness"), str)
        and result.get("freshness") in allowed_freshness
        else "UNKNOWN",
        "fake_provider_calls": len(provider_calls),
        "successful_fake_calls": sum(isinstance(item, dict) and item.get("behavior") == "success" for item in provider_calls),
        "provider_calls_reserved": budget.get("provider_calls_reserved") if isinstance(budget, dict) and isinstance(budget.get("provider_calls_reserved"), int) and not isinstance(budget.get("provider_calls_reserved"), bool) else None,
        "output_bytes_reserved": budget.get("output_bytes_reserved") if isinstance(budget, dict) and isinstance(budget.get("output_bytes_reserved"), int) and not isinstance(budget.get("output_bytes_reserved"), bool) else None,
        "target_execution_marker_present": target_marker_exists,
    }


def _full_review_smoke(
    cli: Path,
    *,
    response_delay_seconds: float = 0.0,
    engine_deadline_seconds: int = 20,
    provider_timeout_seconds: float = FULL_REVIEW_FAKE_PROVIDER_TIMEOUT_SECONDS,
    observer_timeout_seconds: float = 30.0,
) -> dict[str, object]:
    """Run the installed CLI normally against the existing loopback fake."""
    if (
        isinstance(response_delay_seconds, bool)
        or not isinstance(response_delay_seconds, (int, float))
        or not 0 <= response_delay_seconds < float("inf")
        or isinstance(engine_deadline_seconds, bool)
        or not isinstance(engine_deadline_seconds, int)
        or engine_deadline_seconds < 1
        or isinstance(provider_timeout_seconds, bool)
        or not isinstance(provider_timeout_seconds, (int, float))
        or not 0 < provider_timeout_seconds < float("inf")
        or isinstance(observer_timeout_seconds, bool)
        or not isinstance(observer_timeout_seconds, (int, float))
        or not 0 < observer_timeout_seconds < float("inf")
        or not response_delay_seconds < provider_timeout_seconds < engine_deadline_seconds < observer_timeout_seconds
    ):
        return _bounded_full_review_failure("smoke_deadline_config_invalid", None, {}, {}, [], target_marker_exists=False)
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
        return _bounded_full_review_failure(
            "recovery_fixture_import_failed", None, {}, {}, [], target_marker_exists=False
        )

    with tempfile.TemporaryDirectory(prefix="effect-observer-review-") as temporary:
        root = Path(temporary).resolve()
        home = root / "home"
        home.mkdir()
        deadline = time.monotonic() + engine_deadline_seconds + 5
        state = _FakeProviderState()
        state.configure(["success"] * 8)
        server = None
        thread = None
        try:
            server = _FakeProvider(state, response_delay_seconds=response_delay_seconds)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            repo, base, _initial_head, profile, limits, provider_config = _write_fixture(
                root, server.endpoint, deadline
            )
            _set_full_review_fake_provider_timeout(provider_config, provider_timeout_seconds)

            profile_value = json.loads(profile.read_text(encoding="utf-8"))
            profile_value["required_lenses"] = ["correctness", "tests", "security", "maintainability"]
            profile_value["allow_empty_approve"] = False
            profile.write_text(json.dumps(profile_value, sort_keys=True) + "\n", encoding="utf-8")
            limits_value = _limits()
            limits_value.update(
                {
                    "deadline_seconds": engine_deadline_seconds,
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
                timeout_seconds=observer_timeout_seconds,
            )
            result = observed.get("cli_result")
            observation = observed.get("observer", {})
            invocation = observed.get("invocation", {})
            observation = observation if isinstance(observation, dict) else {}
            invocation = invocation if isinstance(invocation, dict) else {}
            durable = None
            durable_path = output / f"{run_id}.json"
            if durable_path.is_file():
                durable = json.loads(durable_path.read_text(encoding="utf-8"))
            if FAKE_API_KEY in json.dumps([observed, durable], sort_keys=True):
                return _bounded_full_review_failure(
                    "fake_provider_key_exposed", result if isinstance(result, dict) else None,
                    observation, invocation, state.calls,
                    target_marker_exists=marker.exists(),
                )
            if isinstance(result, dict) and (
                not isinstance(durable, dict)
                or any(result.get(key) != durable.get(key) for key in ("coverage_state", "disposition", "freshness"))
            ):
                return _bounded_full_review_failure(
                    "durable_result_missing_or_mismatched", result if isinstance(result, dict) else None,
                    observation, invocation, state.calls,
                    target_marker_exists=marker.exists(),
                )
            failure_code = _full_review_failure_code(
                result if isinstance(result, dict) else None,
                observation,
                invocation,
                state.calls,
                target_marker_exists=marker.exists(),
            )
            if failure_code is not None:
                return _bounded_full_review_failure(
                    failure_code,
                    result if isinstance(result, dict) else None,
                    observation,
                    invocation,
                    state.calls,
                    target_marker_exists=marker.exists(),
                )
            summary = _validate_full_review(
                result,
                observation,
                invocation,
                state.calls,
                target_marker_exists=marker.exists(),
            )
            if summary is not None:
                summary["fake_response_delay_seconds"] = float(response_delay_seconds)
                summary["engine_deadline_seconds"] = engine_deadline_seconds
                summary["provider_timeout_seconds"] = float(provider_timeout_seconds)
                summary["observer_timeout_seconds"] = float(observer_timeout_seconds)
            return summary or _bounded_full_review_failure(
                "summary_projection_failed", result, observation, invocation, state.calls,
                target_marker_exists=marker.exists(),
            )
        except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
            return _bounded_full_review_failure(
                "fixture_or_result_processing_failed", None, {}, {}, state.calls,
                target_marker_exists=(root / "target-executed").exists(),
            )
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
    if full_review.get("status") != "NORMAL_REVIEW_COMPLETED":
        print(
            json.dumps(
                {
                    "smoke": "INSTALLED_CLI_FULL_REVIEW_FAILED",
                    "failure": full_review,
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
