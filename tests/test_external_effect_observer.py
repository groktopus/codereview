from __future__ import annotations

import json
import os
import platform
import shutil
import socket
import sys
import threading
import time
import urllib.request
from pathlib import Path

import pytest

from pr_review_harness import external_effect_observer as observer
from scripts.effect_observer_smoke import (
    _SAFE_TRACE_SYSCALLS,
    FULL_REVIEW_FAKE_PROVIDER_TIMEOUT_SECONDS,
    LONG_WAIT_ENGINE_DEADLINE_SECONDS,
    LONG_WAIT_OBSERVER_TIMEOUT_SECONDS,
    LONG_WAIT_PROVIDER_DELAY_SECONDS,
    LONG_WAIT_PROVIDER_TIMEOUT_SECONDS,
    _bounded_full_review_failure,
    _failure_summary,
    _full_review_failure_code,
    _prepare_environment,
    _safe_syscall_counts,
    _set_full_review_fake_provider_timeout,
    _validate_full_review,
)
from scripts.run_recovery_rehearsal import FAKE_API_KEY, PROVIDER_TIMEOUT_SECONDS, _FakeProvider, _FakeProviderState


def _fake_strace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr(observer.platform, "system", lambda: "Linux")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    executable = bin_dir / "strace"
    executable.write_text(
        "#!/usr/bin/env python3\n"
        "import os, sys\n"
        "if '--version' in sys.argv:\n"
        " print('strace -- version 6.14')\n"
        " raise SystemExit(0)\n"
        "if '--help' in sys.argv:\n"
        " print('  --kill-on-exit       kill tracees when strace exits')\n"
        " raise SystemExit(0)\n"
        "if os.environ.get('OBSERVER_TEST_ARGV_FILE'):\n"
        " import json\n"
        " with open(os.environ['OBSERVER_TEST_ARGV_FILE'], 'w', encoding='utf-8') as stream:\n"
        "  json.dump(sys.argv, stream)\n"
        "if os.environ.get('OBSERVER_TEST_PID_FILE'):\n"
        " pid_path = os.environ['OBSERVER_TEST_PID_FILE']\n"
        " ready_path = pid_path + '.ready-tmp'\n"
        " with open(ready_path, 'w', encoding='ascii') as pid_stream:\n"
        "  pid_stream.write(str(os.getpid()))\n"
        "  pid_stream.flush()\n"
        "  os.fsync(pid_stream.fileno())\n"
        " os.replace(ready_path, pid_path)\n"
        "out = sys.argv[sys.argv.index('-o') + 1]\n"
        "fd = int(out.rsplit('/', 1)[1])\n"
        "root_event = b'' if os.environ.get('OBSERVER_TEST_NO_ROOT_EXEC') else b'[pid 4242] execve(0x0, 0x0, 0x0) = 0x0\\n'\n"
        "payload = root_event + bytes.fromhex(os.environ.get('OBSERVER_TEST_TRACE_HEX', ''))\n"
        "repeat = int(os.environ.get('OBSERVER_TEST_TRACE_REPEAT', '0'))\n"
        "if repeat:\n"
        " if os.environ.get('OBSERVER_TEST_TRACE_REPEAT_KIND') == 'file':\n"
        "  payload = b'[pid 4242] execve(0x0, 0x0, 0x0) = 0x0\\n' + b'[pid 5] openat(AT_FDCWD, \"' + b'x' * 550 + b'\", O_RDONLY) = 3\\n'\n"
        " elif os.environ.get('OBSERVER_TEST_TRACE_REPEAT_KIND') == 'metadata':\n"
        "  payload = b'[pid 5] newfstatat(AT_FDCWD, \"x\", {st_mode=S_IFREG}, 0) = 0\\n'\n"
        " else:\n"
        "  payload = b'[pid 4242] execve(0x0, 0x0, 0x0) = 0x0\\n' + b'[pid 5] clone(' + b'1' * 600 + b') = 6\\n'\n"
        " repeat -= 1\n"
        " while repeat:\n"
        "  n = os.write(fd, payload)\n"
        "  repeat -= 1\n"
        "if os.environ.get('OBSERVER_TEST_TRACE_REPEAT_KIND') == 'metadata':\n"
        " payload = b'[pid 5] newfstatat(AT_FDCWD, \"x\", {st_mode=S_IFREG}, 0) = 0\\n' + root_event + bytes.fromhex(os.environ.get('OBSERVER_TEST_TRACE_HEX', ''))\n"
        "elif not int(os.environ.get('OBSERVER_TEST_TRACE_REPEAT', '0')):\n"
        " payload = root_event + bytes.fromhex(os.environ.get('OBSERVER_TEST_TRACE_HEX', ''))\n"
        "view = memoryview(payload)\n"
        "while view:\n"
        " view = view[os.write(fd, view):]\n"
        "import time; time.sleep(0.05)\n"
        "command = sys.argv[sys.argv.index('--') + 1:]\n"
        "os.execvpe(command[0], command, os.environ)\n",
        encoding="utf-8",
    )
    executable.chmod(0o755)
    monkeypatch.setenv("PATH", str(bin_dir) + os.pathsep + os.environ.get("PATH", ""))
    return executable


def _fake_cli(tmp_path: Path) -> list[str]:
    script = tmp_path / "fake_cli.py"
    script.write_text("import json; print(json.dumps({'status': 'ok'}))\n", encoding="utf-8")
    return [sys.executable, str(script)]


def _wait_for_proc_child_stop(read_state, deadline: float) -> None:
    while time.monotonic() < deadline:
        try:
            state = read_state()
        except (FileNotFoundError, ProcessLookupError):
            return
        if state == "Z":
            return
        time.sleep(0.05)
    pytest.fail("strace_exit_left_a_running_setsid_tracee")


def test_observations_keep_only_typed_fields_and_hash_raw_paths(tmp_path, monkeypatch):
    _fake_strace(tmp_path, monkeypatch)
    raw_path = "/tmp/PRIVATE_OBSERVER_PATH_91f7"
    trace = (
        f'[pid 41] openat(AT_FDCWD, "{raw_path}", O_WRONLY|O_CREAT, 0600) = 3\n'
        f'[pid 41] rename("{raw_path}", "{raw_path}.new") = 0\n'
        '[pid 41] connect(3, {sa_family=AF_INET, sin_addr=inet_addr("127.0.0.1")}, 16) = -1 ECONNREFUSED (Connection refused)\n'
        '[pid 41] clone(0x123, 0, 0, 0, 0) = 42\n'
    )
    env = {**os.environ, "OBSERVER_TEST_TRACE_HEX": trace.encode().hex()}
    result = observer.observe_cli(_fake_cli(tmp_path), cwd=tmp_path, env=env, timeout_seconds=5)

    observation = result["observer"]
    assert observation["observer_id"] == "linux-strace-syscall-observer.v3"
    encoded = json.dumps(result, sort_keys=True)
    assert result["invocation"]["run_status"] == "CLI_COMPLETED", result
    assert observation["overall_state"] == "UNKNOWN"
    assert observation["coverage"] == "SCOPED_COMPLETE"
    assert observation["root_exec_evidence"] == "first_successful_execve_in_fresh_spawn_trace"
    assert observation["root_exec_pid"] == 4242
    assert any(item.get("syscall") == "openat" and item.get("outcome") == "SUCCESS" for item in observation["events"])
    assert any(item.get("syscall") == "rename" and item.get("outcome") == "SUCCESS" for item in observation["events"])
    assert any(item.get("destination_class") == "loopback" for item in observation["events"])
    assert all(item.get("operation") != "file_write" for item in observation["events"])
    assert raw_path not in encoded
    assert "PRIVATE_OBSERVER_PATH_91f7" not in encoded
    assert "cli_result" not in result["invocation"]
    assert result["cli_result"] == {"status": "ok"}


def test_platform_unavailable_does_not_run_cli(tmp_path, monkeypatch):
    marker = tmp_path / "should_not_exist"
    monkeypatch.setattr(observer.platform, "system", lambda: "Darwin")
    result = observer.observe_cli(
        [sys.executable, "-c", f"from pathlib import Path; Path({str(marker)!r}).touch()"],
        cwd=tmp_path,
        env=os.environ.copy(),
        timeout_seconds=2,
    )
    assert result["invocation"]["run_status"] == "OBSERVER_UNAVAILABLE"
    assert result["observer"]["overall_state"] == "UNKNOWN"
    assert not marker.exists()


@pytest.mark.parametrize(
    ("trace", "reason", "cli_may_start"),
    [
        (b"not a strace syscall line\n", "trace_parse_failed", False),
        (b"[pid 4] connect(3, {sa_family=AF_INET}, 16) <unfinished ...>\n", "trace_unfinished_syscall", True),
    ],
)
def test_unparseable_trace_is_unknown_and_bounds_cli_launch(tmp_path, monkeypatch, trace, reason, cli_may_start):
    _fake_strace(tmp_path, monkeypatch)
    marker = tmp_path / "should_not_exist"
    env = {**os.environ, "OBSERVER_TEST_TRACE_HEX": trace.hex()}
    result = observer.observe_cli(
        [sys.executable, "-c", f"from pathlib import Path; Path({str(marker)!r}).touch()"],
        cwd=tmp_path,
        env=env,
        timeout_seconds=3,
    )
    assert result["observer"]["coverage"] == "INCOMPLETE"
    assert result["observer"]["overall_state"] == "UNKNOWN"
    assert result["observer"]["reason"] == reason
    assert marker.exists() is cli_may_start


def test_trace_byte_cap_forces_unknown(tmp_path, monkeypatch):
    _fake_strace(tmp_path, monkeypatch)
    env = {
        **os.environ,
        "OBSERVER_TEST_TRACE_REPEAT": "5000",
        "OBSERVER_TEST_TRACE_REPEAT_KIND": "file",
    }
    result = observer.observe_cli(_fake_cli(tmp_path), cwd=tmp_path, env=env, timeout_seconds=5)
    assert result["observer"]["coverage"] == "INCOMPLETE"
    assert result["observer"]["overall_state"] == "UNKNOWN"
    assert result["observer"]["reason"] == "trace_byte_cap_exceeded"
    assert result["invocation"]["run_status"] == "OBSERVER_TRACE_INCOMPLETE", result
    assert result["cli_result"] is None


def test_noisy_prepare_volume_is_aggregated_with_late_effect_buckets(tmp_path, monkeypatch):
    _fake_strace(tmp_path, monkeypatch)
    late = (
        b'[pid 6] rename("/tmp/LATE_PRIVATE_PATH", "/tmp/LATE_PRIVATE_PATH.new") = 0\n'
        b'[pid 6] connect(3, {sa_family=AF_INET, sin_addr=inet_addr("203.0.113.8")}, 16) = 0\n'
        b'[pid 7] execve(0x0, 0x0, 0x0) = 0x0\n'
    )
    env = {
        **os.environ,
        "OBSERVER_TEST_TRACE_REPEAT": "2100",
        "OBSERVER_TEST_TRACE_REPEAT_KIND": "metadata",
        "OBSERVER_TEST_TRACE_HEX": late.hex(),
    }
    result = observer.observe_cli(_fake_cli(tmp_path), cwd=tmp_path, env=env, timeout_seconds=5)
    observed = result["observer"]
    assert result["invocation"]["run_status"] == "CLI_COMPLETED", result
    assert observed["coverage"] == "SCOPED_COMPLETE"
    assert observed["observer_id"] == "linux-strace-syscall-observer.v3"
    assert observed["overall_state"] == "UNKNOWN"
    assert observed["event_count"] == 2104
    assert observed["event_sample_count"] == observer.TRACE_MAX_EVENT_EXEMPLARS
    assert observed["event_sample_truncated"] is True
    assert observed["event_aggregates_complete"] is True
    counts = {(item["syscall"], item["outcome"]): item["count"] for item in observed["event_aggregates"]}
    assert sum(item["count"] for item in observed["event_aggregates"]) == observed["event_count"]
    assert counts[("newfstatat", "SUCCESS")] == 2100
    assert counts[("rename", "SUCCESS")] == 1
    assert counts[("connect", "SUCCESS")] == 1
    assert counts[("execve", "SUCCESS")] == 2
    serialized = json.dumps(result, sort_keys=True)
    assert "LATE_PRIVATE_PATH" not in serialized


def test_aggregate_bucket_cap_fails_closed(tmp_path, monkeypatch):
    _fake_strace(tmp_path, monkeypatch)
    trace = b"".join(
        f"[pid 8] syscall{index}() = 0\n".encode()
        for index in range(observer.TRACE_MAX_AGGREGATE_BUCKETS)
    )
    env = {**os.environ, "OBSERVER_TEST_TRACE_HEX": trace.hex()}
    result = observer.observe_cli(_fake_cli(tmp_path), cwd=tmp_path, env=env, timeout_seconds=5)
    assert result["observer"]["reason"] == "trace_aggregate_bucket_cap_exceeded"
    assert result["observer"]["coverage"] == "INCOMPLETE"
    assert result["observer"]["event_aggregates_complete"] is False
    assert result["observer"]["event_count"] == observer.TRACE_MAX_AGGREGATE_BUCKETS + 1
    assert sum(item["count"] for item in result["observer"]["event_aggregates"]) == observer.TRACE_MAX_AGGREGATE_BUCKETS
    assert result["invocation"]["run_status"] == "OBSERVER_TRACE_INCOMPLETE"
    assert result["cli_result"] is None


def test_resumed_socket_and_process_calls_keep_safe_pending_metadata(tmp_path, monkeypatch):
    _fake_strace(tmp_path, monkeypatch)
    trace = (
        b'[pid 51] connect(3, {sa_family=AF_INET, sin_addr=inet_addr("127.0.0.1")}, 16 <unfinished ...>\n'
        b'[pid 51] <... connect resumed>) = 0\n'
        b'[pid 52] clone(0x1, 0, 0, 0, 0 <unfinished ...>\n'
        b'[pid 52] <... clone resumed>) = 53\n'
    )
    env = {**os.environ, "OBSERVER_TEST_TRACE_HEX": trace.hex()}
    result = observer.observe_cli(_fake_cli(tmp_path), cwd=tmp_path, env=env, timeout_seconds=5)
    observed = result["observer"]
    aggregates = observed["event_aggregates"]
    assert result["invocation"]["run_status"] == "CLI_COMPLETED", result
    assert observed["coverage"] == "SCOPED_COMPLETE"
    assert observed["event_aggregates_complete"] is True
    assert sum(item["count"] for item in aggregates) == observed["event_count"]
    assert any(
        item["operation"] == "socket_endpoint_syscall"
        and item["syscall"] == "connect"
        and item["outcome"] == "SUCCESS"
        and item["destination_class"] == "loopback"
        and item["trace_state"] == "RESUMED"
        for item in aggregates
    )
    assert any(
        item["operation"] == "process_lifecycle_syscall"
        and item["syscall"] == "clone"
        and item["outcome"] == "SUCCESS"
        and item["result_class"] == "positive"
        and item["trace_state"] == "RESUMED"
        for item in aggregates
    )


def test_pending_call_metadata_has_a_finite_fail_closed_cap(tmp_path, monkeypatch):
    _fake_strace(tmp_path, monkeypatch)
    trace = b"".join(
        f'[pid {pid}] connect(3, {{sa_family=AF_INET, sin_addr=inet_addr("127.0.0.1")}}, 16 <unfinished ...>\n'.encode()
        for pid in range(1, observer.TRACE_MAX_PENDING_CALLS + 2)
    )
    env = {**os.environ, "OBSERVER_TEST_TRACE_HEX": trace.hex()}
    result = observer.observe_cli(_fake_cli(tmp_path), cwd=tmp_path, env=env, timeout_seconds=5)
    assert result["observer"]["reason"] == "trace_pending_call_cap_exceeded"
    assert result["observer"]["coverage"] == "INCOMPLETE"
    assert result["invocation"]["run_status"] == "OBSERVER_TRACE_INCOMPLETE"
    assert result["cli_result"] is None


def test_resumed_process_creation_counts_toward_cap(tmp_path, monkeypatch):
    _fake_strace(tmp_path, monkeypatch)
    calls = []
    for pid in range(10, 10 + observer.MAX_PROCESS_CREATIONS + 1):
        calls.append(f"[pid {pid}] clone(0x1 <unfinished ...>\n")
        calls.append(f"[pid {pid}] <... clone resumed>) = {pid + 1}\n")
    env = {**os.environ, "OBSERVER_TEST_TRACE_HEX": "".join(calls).encode().hex()}
    result = observer.observe_cli(_fake_cli(tmp_path), cwd=tmp_path, env=env, timeout_seconds=5)
    assert result["observer"]["reason"] == "process_creation_cap_exceeded"
    assert result["observer"]["coverage"] == "INCOMPLETE"
    assert result["invocation"]["run_status"] == "OBSERVER_PROCESS_CAP_EXCEEDED"
    assert result["cli_result"] is None


def test_prepare_smoke_failure_summary_is_code_only_and_bounded():
    sentinel = "synthetic-canary-never-send"
    summary = _failure_summary(
        {
            "observer": {"observer_id": observer.OBSERVER_ID, "reason": sentinel, "coverage": {sentinel: sentinel}, "event_count": 4, "trace_bytes": 128},
            "invocation": {"run_status": sentinel, "exit_code": 1, "cli_error_code": sentinel},
            "cli_result": {"status": sentinel, "error": sentinel, "no_provider_calls": False},
        },
        "prepare_contract_failed",
    )
    encoded = json.dumps(summary, sort_keys=True)
    assert sentinel not in encoded
    assert summary["observer_reason"] == "other"
    assert summary["coverage"] == "UNKNOWN"
    assert summary["invocation_status"] == "UNKNOWN"
    assert summary["cli_status"] == "UNKNOWN"
    assert summary["cli_error_code"] == "other"
    assert summary["event_count"] == 4 and summary["trace_bytes"] == 128


@pytest.mark.parametrize(
    "error_code",
    ["invalid_review_request", "run_id_already_exists", "resume_state_invalid"],
)
def test_prepare_smoke_retains_typed_preflight_diagnostic(error_code):
    summary = _failure_summary(
        {
            "observer": {"observer_id": observer.OBSERVER_ID, "reason": "observer_unavailable"},
            "invocation": {"run_status": "CLI_FAILED", "exit_code": 2, "cli_error_code": error_code},
            "cli_result": None,
        },
        "prepare_contract_failed",
    )
    assert summary["cli_error_code"] == error_code


def test_prepare_smoke_environment_ignores_enclosing_actions_event():
    source = {
        "GITHUB_EVENT_PATH": "/runner/work/_temp/event.json",
        "GITHUB_REPOSITORY": "owner/repository",
        "GITHUB_RUN_ID": "123456",
        "GITHUB_SERVER_URL": "https://github.com",
        "PATH": "/usr/bin",
    }
    env = _prepare_environment(source)
    assert "GITHUB_EVENT_PATH" not in env
    assert "GITHUB_REPOSITORY" not in env
    assert "GITHUB_RUN_ID" not in env
    assert env["GITHUB_SERVER_URL"] == source["GITHUB_SERVER_URL"]
    assert env["PATH"] == source["PATH"]
    assert env["OBSERVER_SMOKE_PROVIDER_KEY"] == "synthetic-canary-never-send"
    assert source["GITHUB_EVENT_PATH"] == "/runner/work/_temp/event.json"


def _full_review_contract_fixture():
    lenses = ("correctness", "tests", "security", "maintainability")
    result = {
        "task_results": {
            f"task-{lens}": {
                "lens": lens,
                "status": "SUCCEEDED",
                "attempts": 1,
                "payload": {"finding_candidates": []},
            }
            for lens in lenses
        },
        "coverage_state": "COMPLETE",
        "coverage_ledger": [{"state": "COMPLETE", "lens": lens, "required": True} for lens in lenses],
        "disposition": "COMMENT",
        "freshness": "UNKNOWN",
        "allow_empty_approve": False,
        "budget": {
            "provider_calls_reserved": 4,
            "provider_calls_limit": 8,
            "output_bytes_reserved": 32_000,
            "output_bytes_limit": 32_000,
            "cost": "UNKNOWN",
            "cost_billing_known": False,
            "budget_breaches": [],
        },
    }
    observation = {
        "observer_id": "linux-strace-syscall-observer.v3",
        "coverage": "SCOPED_COMPLETE",
        "event_aggregates_complete": True,
        "event_count": 42,
        "trace_bytes": 2048,
    }
    invocation = {"run_status": "CLI_COMPLETED", "exit_code": 0}
    calls = [{"path": "/v1/chat/completions", "behavior": "success"} for _ in lenses]
    return result, observation, invocation, calls


def test_full_review_smoke_requires_typed_complete_normal_path():
    result, observation, invocation, calls = _full_review_contract_fixture()
    summary = _validate_full_review(result, observation, invocation, calls, target_marker_exists=False)
    assert summary == {
        "status": "NORMAL_REVIEW_COMPLETED",
        "coverage_state": "COMPLETE",
        "disposition": "COMMENT",
        "freshness": "UNKNOWN",
        "required_lenses": ["correctness", "maintainability", "security", "tests"],
        "completed_tasks": 4,
        "provider_calls": 4,
        "provider_call_limit": 8,
        "retries": 0,
        "output_bytes_reserved": 32_000,
        "aggregate_output_byte_cap": 32_000,
        "cost_status": "UNKNOWN",
        "candidate_adjudication": "NOT_EXERCISED_NO_CANDIDATES",
        "jev": "NOT_CONFIGURED",
        "target_code_execution": False,
        "observer_coverage": "SCOPED_COMPLETE",
        "event_count": 42,
        "trace_bytes": 2048,
        "trace_byte_cap": observer.TRACE_MAX_BYTES,
        "event_aggregates_complete": True,
        "event_counts_by_syscall": {
            "state": "UNKNOWN",
            "aggregates_complete": True,
            "counts": {name: 0 for name in sorted(_SAFE_TRACE_SYSCALLS)},
            "unknown_rows": None,
        },
        "observer_source_sha256": "UNKNOWN",
        "strace_version": "UNKNOWN",
        "strace_executable_sha256": "UNKNOWN",
    }


def test_full_review_summary_retains_actual_strace_version_and_safe_counters():
    result, observation, invocation, calls = _full_review_contract_fixture()
    observation.update(
        {
            "strace_version": "strace -- version 6.8",
            "source_sha256": "a" * 64,
            "strace_executable_sha256": "b" * 64,
            "event_aggregates": [{"syscall": "wait4", "count": 7}],
        }
    )
    summary = _validate_full_review(result, observation, invocation, calls, target_marker_exists=False)
    assert summary is not None
    assert summary["strace_version"] == "strace -- version 6.8"
    assert summary["observer_source_sha256"] == "a" * 64
    assert summary["strace_executable_sha256"] == "b" * 64
    counters = summary["event_counts_by_syscall"]
    assert counters["state"] == "SAFE_PROJECTION"
    assert counters["counts"]["wait4"] == 7


@pytest.mark.parametrize("failure", ["calls", "lens", "coverage", "candidate", "executed", "trace_cap"])
def test_full_review_smoke_rejects_incomplete_or_unexercised_evidence(failure):
    result, observation, invocation, calls = _full_review_contract_fixture()
    if failure == "calls":
        calls.pop()
    elif failure == "lens":
        result["task_results"]["task-tests"]["lens"] = "performance"
    elif failure == "coverage":
        result["coverage_ledger"][0]["state"] = "PARTIAL"
    elif failure == "candidate":
        result["task_results"]["task-security"]["payload"]["finding_candidates"] = [{"id": "candidate"}]
    elif failure == "trace_cap":
        observation["trace_bytes"] = observer.TRACE_MAX_BYTES + 1
    summary = _validate_full_review(
        result,
        observation,
        invocation,
        calls,
        target_marker_exists=failure == "executed",
    )
    assert summary is None


def test_full_review_failure_diagnostic_uses_stable_codes_and_no_payload_fields():
    sentinel = "UNTRUSTED_PROVIDER_OR_SOURCE_CONTENT_5f8a"
    result, observation, invocation, calls = _full_review_contract_fixture()
    result["task_results"]["task-security"]["lens"] = sentinel
    result["task_results"]["task-security"].update(
        {"status": "FAILED", "attempts": 1, "error_code": "provider_deadline_exceeded"}
    )
    result["task_results"]["task-tests"].update(
        {"status": "INVALID", "attempts": 1, "error_code": sentinel}
    )
    result["task_results"]["task-correctness"].update(
        {"status": "FAILED", "attempts": 1, "error_code": "http_status_504"}
    )
    result["disposition"] = sentinel
    observation.update(
        {
            "reason": sentinel,
            "coverage": "INCOMPLETE",
            "trace_bytes": observer.TRACE_MAX_BYTES + 1,
            "event_count": True,
        }
    )
    code = _full_review_failure_code(
        result, observation, invocation, calls, target_marker_exists=False
    )
    assert code == "observer_scope_or_trace_incomplete"
    summary = _bounded_full_review_failure(
        code, result, observation, invocation, calls, target_marker_exists=False
    )
    encoded = json.dumps(summary, sort_keys=True)
    assert sentinel not in encoded
    assert summary["failure_stage"] == "observer_scope_or_trace_incomplete"
    assert summary["observer_reason"] == "other"
    assert summary["observer_event_count"] is None
    assert summary["observer_trace_bytes"] == observer.TRACE_MAX_BYTES + 1
    assert summary["observed_task_lenses"] == ["correctness", "maintainability", "tests"]
    assert summary["unknown_task_lens_count"] == 1
    assert summary["task_status_counts"] == {"FAILED": 2, "INVALID": 1, "SUCCEEDED": 1}
    assert summary["task_error_code_counts"] == {
        "http_status_5xx": 1,
        "provider_deadline_exceeded": 1,
        "other": 1,
    }
    assert summary["task_attempts_total"] == 4
    assert summary["unknown_task_error_count"] == 0


def test_full_review_diagnostic_fails_closed_on_malformed_payload_and_envelope():
    sentinel = "UNTRUSTED_PAYLOAD_62aa"
    result, observation, invocation, calls = _full_review_contract_fixture()
    result["task_results"]["task-security"]["payload"] = [sentinel]
    code = _full_review_failure_code(
        result, None, None, calls, target_marker_exists=False  # type: ignore[arg-type]
    )
    assert code == "observer_scope_or_trace_incomplete"

    result, observation, invocation, calls = _full_review_contract_fixture()
    result["task_results"]["task-security"]["payload"] = [sentinel]
    observation["coverage"] = "SCOPED_COMPLETE"
    summary = _bounded_full_review_failure(
        sentinel, result, observation, invocation, calls, target_marker_exists=False
    )
    encoded = json.dumps(summary, sort_keys=True)
    assert sentinel not in encoded
    assert summary["failure_stage"] == "unknown_failure"
    assert _full_review_failure_code(
        result, observation, invocation, calls, target_marker_exists=False
    ) == "task_payload_schema_invalid"


def test_full_review_smoke_uses_five_second_fake_timeout_without_changing_recovery_default(tmp_path):
    provider_config = tmp_path / "provider.json"
    provider_config.write_text(
        json.dumps({"timeout_seconds": PROVIDER_TIMEOUT_SECONDS, "kind": "openai_compatible"}),
        encoding="utf-8",
    )
    assert PROVIDER_TIMEOUT_SECONDS == 0.35

    _set_full_review_fake_provider_timeout(provider_config)

    configured = json.loads(provider_config.read_text(encoding="utf-8"))
    assert configured == {
        "kind": "openai_compatible",
        "timeout_seconds": FULL_REVIEW_FAKE_PROVIDER_TIMEOUT_SECONDS,
    }
    assert FULL_REVIEW_FAKE_PROVIDER_TIMEOUT_SECONDS == 5.0
    assert FULL_REVIEW_FAKE_PROVIDER_TIMEOUT_SECONDS < 20.0


def test_long_fake_wait_profile_keeps_caps_and_has_finite_deadline_headroom():
    assert LONG_WAIT_PROVIDER_DELAY_SECONDS == 75.0
    assert (
        LONG_WAIT_PROVIDER_DELAY_SECONDS
        < LONG_WAIT_PROVIDER_TIMEOUT_SECONDS
        < LONG_WAIT_ENGINE_DEADLINE_SECONDS
        < LONG_WAIT_OBSERVER_TIMEOUT_SECONDS
        <= 270
    )
    assert observer.TRACE_MAX_BYTES == 1_048_576


def test_safe_syscall_projection_handles_partial_aggregates_and_untrusted_labels():
    projected = _safe_syscall_counts(
        [
            {"syscall": "wait4", "count": 3},
            {"syscall": ["not", "hashable"], "count": 9},
            {"syscall": "future_syscall", "count": 4},
        ],
        complete=False,
    )
    assert projected["state"] == "PARTIAL_PROJECTION"
    assert projected["aggregates_complete"] is False
    assert projected["counts"]["wait4"] == 3
    assert projected["unknown_rows"] == 2
    assert "future_syscall" not in json.dumps(projected)


def test_fake_provider_supports_bounded_delayed_success_without_changing_default():
    state = _FakeProviderState()
    state.configure(["success"])
    try:
        server = _FakeProvider(state, response_delay_seconds=0.05)
    except PermissionError:
        pytest.skip("environment does not permit loopback listener")
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        request_body = json.dumps(
            {"messages": [{}, {"content": json.dumps({"task": {"unit_ids": []}, "evidence": []})}]}
        ).encode()
        request = urllib.request.Request(
            f"{server.endpoint}/chat/completions",
            data=request_body,
            headers={"Authorization": f"Bearer {FAKE_API_KEY}", "Content-Type": "application/json"},
            method="POST",
        )
        start = time.monotonic()
        with urllib.request.urlopen(request, timeout=2) as response:
            assert response.status == 200
            assert json.load(response)["model"] == "local-rehearsal-model"
        assert time.monotonic() - start >= 0.045
        assert state.calls == [{"path": "/v1/chat/completions", "behavior": "success"}]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)

    default_state = _FakeProviderState()
    default_state.configure(["success"])
    default_server = _FakeProvider(default_state)
    try:
        assert default_server.RequestHandlerClass.response_delay_seconds == 0.0
    finally:
        default_server.server_close()


@pytest.mark.parametrize(
    ("error_code", "expected_code"),
    [
        ("invalid_arguments", "invalid_arguments"),
        ("invalid_review_request", "invalid_review_request"),
        ("run_id_already_exists", "run_id_already_exists"),
        ("resume_state_invalid", "resume_state_invalid"),
        ("SENSITIVE_CLI_STDOUT_CANARY", "other"),
    ],
)
def test_failed_cli_exposes_only_stable_error_code(tmp_path, monkeypatch, error_code, expected_code):
    _fake_strace(tmp_path, monkeypatch)
    canary = "SENSITIVE_CLI_STDOUT_CANARY"
    script = tmp_path / "failed_cli.py"
    script.write_text(
        "import json, sys; "
        f"print(json.dumps({{'error':{error_code!r},'exit_code':2,'payload':{canary!r}}})); sys.exit(2)\n",
        encoding="utf-8",
    )
    result = observer.observe_cli([sys.executable, str(script)], cwd=tmp_path, env=os.environ.copy(), timeout_seconds=5)
    assert result["invocation"]["run_status"] == "CLI_FAILED"
    assert result["invocation"]["exit_code"] == 2
    assert result["invocation"]["cli_error_code"] == expected_code
    assert result["cli_result"] is None
    assert canary not in json.dumps(result, sort_keys=True)


def test_unterminated_trace_line_cap_fails_closed(tmp_path, monkeypatch):
    _fake_strace(tmp_path, monkeypatch)
    env = {**os.environ, "OBSERVER_TEST_TRACE_HEX": (b"x" * (observer.TRACE_MAX_LINE_BYTES + 1)).hex()}
    result = observer.observe_cli(_fake_cli(tmp_path), cwd=tmp_path, env=env, timeout_seconds=3)
    assert result["observer"]["reason"] == "trace_line_cap_exceeded"
    assert result["observer"]["coverage"] == "INCOMPLETE"
    assert result["invocation"]["run_status"] == "OBSERVER_TRACE_INCOMPLETE"
    assert result["cli_result"] is None


@pytest.mark.parametrize(
    ("env_additions", "trace"),
    [
        ({"OBSERVER_TEST_NO_ROOT_EXEC": "1"}, b""),
        ({}, b"openat(AT_FDCWD, \"trailing\", O_RDONLY)"),
    ],
)
def test_missing_root_exec_or_trailing_trace_bytes_fail_closed(tmp_path, monkeypatch, env_additions, trace):
    _fake_strace(tmp_path, monkeypatch)
    env = {**os.environ, **env_additions, "OBSERVER_TEST_TRACE_HEX": trace.hex()}
    result = observer.observe_cli(_fake_cli(tmp_path), cwd=tmp_path, env=env, timeout_seconds=3)
    assert result["observer"]["coverage"] == "INCOMPLETE"
    assert result["invocation"]["run_status"] == "OBSERVER_TRACE_INCOMPLETE"
    assert result["cli_result"] is None


def test_teardown_uses_at_most_the_reserved_grace_once(tmp_path, monkeypatch):
    _fake_strace(tmp_path, monkeypatch)
    real_popen = observer.subprocess.Popen
    wait_timeouts = []

    class TrackedProcess:
        def __init__(self, process):
            self._process = process

        def __getattr__(self, name):
            return getattr(self._process, name)

        def wait(self, timeout=None):
            wait_timeouts.append(timeout)
            if os.environ.get("OBSERVER_TEST_FORCE_WAIT_TIMEOUT"):
                raise observer.subprocess.TimeoutExpired(cmd="fake-strace", timeout=timeout)
            return self._process.wait(timeout=timeout)

    def track_trace_process(argv, *args, **kwargs):
        process = real_popen(argv, *args, **kwargs)
        return TrackedProcess(process) if "--" in argv else process

    monkeypatch.setattr(observer.subprocess, "Popen", track_trace_process)
    monkeypatch.setenv("OBSERVER_TEST_FORCE_WAIT_TIMEOUT", "1")
    command = [sys.executable, "-c", "import time; time.sleep(10)"]
    result = observer.observe_cli(command, cwd=tmp_path, env=os.environ.copy(), timeout_seconds=0.15)
    assert result["invocation"]["run_status"] == "RUN_TIMEOUT"
    assert result["invocation"]["cleanup_grace_ms"] == 1000
    assert result["invocation"]["cleanup_status"] == "UNCONFIRMED"
    assert wait_timeouts == [observer.CLEANUP_GRACE_SECONDS]


@pytest.mark.skipif(platform.system() != "Linux" or shutil.which("strace") is None, reason="Linux strace required")
def test_real_strace_observes_file_names_connect_and_child_after_parent_exit(tmp_path):
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    server.settimeout(5)
    accepted: list[socket.socket] = []

    def accept_one():
        connection, _ = server.accept()
        accepted.append(connection)

    accept_thread = threading.Thread(target=accept_one, daemon=True)
    accept_thread.start()
    created = tmp_path / "effect-before-rename.marker"
    renamed = tmp_path / "effect-after-rename.marker"
    child_file = tmp_path / "child-after-parent-exit.marker"
    port = server.getsockname()[1]
    script, _child_source = _effect_fixture_sources(created, renamed, child_file, port)
    try:
        result = observer.observe_cli([sys.executable, "-c", script], cwd=tmp_path, env=os.environ.copy(), timeout_seconds=8)
        accept_thread.join(timeout=5)
    finally:
        server.close()
        for connection in accepted:
            connection.close()
    observation = result["observer"]
    assert observation["overall_state"] == "UNKNOWN"
    assert observation["coverage"] == "SCOPED_COMPLETE"
    assert observation["event_aggregates_complete"] is True
    assert observation["event_sample_truncated"] is True
    assert result["invocation"]["run_status"] == "CLI_COMPLETED"
    aggregates = observation["event_aggregates"]
    assert sum(item["count"] for item in aggregates) == observation["event_count"]
    assert sum(
        item["count"]
        for item in aggregates
        if item["operation"] == "file_name_syscall"
        and item["syscall"] in {"open", "openat", "creat"}
        and item["outcome"] == "SUCCESS"
        and item["path_scope"] == "case_workdir"
    ) > 0
    assert sum(
        item["count"]
        for item in aggregates
        if item["operation"] == "file_name_syscall"
        and item["syscall"].startswith("rename")
        and item["outcome"] == "SUCCESS"
        and item["path_scope"] == "case_workdir"
    ) > 0
    assert sum(
        item["count"]
        for item in aggregates
        if item["syscall"] == "connect"
        and item["outcome"] == "SUCCESS"
        and item["destination_class"] == "loopback"
    ) > 0
    assert sum(
        item["count"]
        for item in aggregates
        if item["syscall"] in {"execve", "execveat"} and item["outcome"] == "SUCCESS"
    ) >= 2
    assert not created.exists() and renamed.is_file() and child_file.is_file()
    assert len(accepted) == 1


def test_process_creation_cap_terminates_owned_observer_tree(tmp_path, monkeypatch):
    _fake_strace(tmp_path, monkeypatch)
    marker = tmp_path / "cli_should_not_start"
    trace = b"[pid 5] clone(0x1, 0, 0, 0, 0) = 6\n" * (observer.MAX_PROCESS_CREATIONS + 1)
    env = {**os.environ, "OBSERVER_TEST_TRACE_HEX": trace.hex()}
    result = observer.observe_cli(
        [sys.executable, "-c", f"from pathlib import Path; Path({str(marker)!r}).touch()"],
        cwd=tmp_path,
        env=env,
        timeout_seconds=3,
    )
    assert result["invocation"]["run_status"] == "OBSERVER_PROCESS_CAP_EXCEEDED"
    assert result["observer"]["coverage"] == "INCOMPLETE"
    assert result["observer"]["overall_state"] == "UNKNOWN"
    assert result["observer"]["reason"] == "process_creation_cap_exceeded"
    assert not marker.exists()


def test_hash_file_rejects_symlink_and_fifo_without_opening_them(tmp_path):
    target = tmp_path / "target"
    target.write_bytes(b"safe")
    link = tmp_path / "link"
    link.symlink_to(target)
    fifo = tmp_path / "pipe"
    os.mkfifo(fifo)
    assert observer._hash_file(str(link)) is None
    assert observer._hash_file(str(fifo)) is None
    assert len(observer._hash_file(str(target)) or "") == 64


def _effect_fixture_sources(created: Path, renamed: Path, child_file: Path, port: int) -> tuple[str, str]:
    child_source = (
        "import pathlib, time\n"
        "time.sleep(0.2)\n"
        f"pathlib.Path({str(child_file)!r}).write_text('late')\n"
    )
    parent_source = (
        "import pathlib, socket, subprocess, sys\n"
        f"first = pathlib.Path({str(created)!r}); second = pathlib.Path({str(renamed)!r})\n"
        "first.write_text('fixture')\n"
        "first.rename(second)\n"
        # Keep the client socket in blocking mode so the traced connect itself
        # reports completion. The observer's outer deadline bounds this fixture.
        f"client = socket.socket(socket.AF_INET, socket.SOCK_STREAM); client.connect(('127.0.0.1', {port})); client.close()\n"
        f"child_source = {child_source!r}\n"
        "subprocess.Popen([sys.executable, '-c', child_source])\n"
        "print('{\"status\":\"ok\"}')\n"
    )
    return parent_source, child_source


def test_linux_effect_fixture_sources_compile_on_all_platforms(tmp_path):
    parent_source, child_source = _effect_fixture_sources(
        tmp_path / "created", tmp_path / "renamed", tmp_path / "child", 43123
    )
    compile(parent_source, "linux_effect_parent_fixture.py", "exec")
    compile(child_source, "linux_effect_child_fixture.py", "exec")


def test_parse_trace_paths_never_resolves_symlinks(tmp_path):
    loop = tmp_path / "loop"
    loop.symlink_to("loop")
    event = observer._parse_line(f'openat(AT_FDCWD, "{loop}", O_RDONLY) = 3', tmp_path)
    assert event and event["path_scope"] == "case_workdir"


def test_raw_exec_hex_zero_is_success_but_nonzero_is_not():
    assert observer._outcome("execve(0x0, 0x0, 0x0) = 0x0", "execve") == ("SUCCESS", 0)
    assert observer._outcome("execve(0x0, 0x0, 0x0) = 0xfffffffffffffff2", "execve") == ("ERROR", -1)


def test_raw_metadata_hex_args_keep_normalized_syscall_outcomes(tmp_path):
    decoded_stat = observer._parse_line(
        'newfstatat(AT_FDCWD, "private-name", {st_mode=S_IFREG|0600}, 0) = 0', tmp_path
    )
    raw_stat = observer._parse_line(
        "newfstatat(0xffffff9c, 0x7ffeaa001000, 0x7ffeaa000a00, 0) = 0", tmp_path
    )
    decoded_wait = observer._parse_line(
        "wait4(-1, [{WIFEXITED(s) && WEXITSTATUS(s) == 0}], 0, {ru_utime={tv_sec=0, tv_usec=0}}) = 4242",
        tmp_path,
    )
    raw_wait = observer._parse_line("wait4(0xffffffff, 0x7ffeaa000a00, 0, 0x0) = 0x1092", tmp_path)

    assert decoded_stat == raw_stat == {
        "syscall": "newfstatat",
        "operation": "other_scoped_syscall",
        "outcome": "SUCCESS",
    }
    assert decoded_wait == raw_wait == {
        "syscall": "wait4",
        "operation": "other_scoped_syscall",
        "outcome": "SUCCESS",
    }
    assert observer._parse_line("newfstatat(0x1, 0x2, 0x3, 0) = -1 ENOENT", tmp_path)["outcome"] == "ERROR"
    assert observer._outcome("wait4(0x1, 0x2, 0x0, 0x0) = 0xfffffffffffffff2", "wait4") == ("ERROR", -14)
    with pytest.raises(ValueError, match="trace_outcome_unavailable"):
        observer._parse_line("wait4(0x1, 0x2, 0x0, 0x0) = 0xzz", tmp_path)


def _completed_aggregate_projection(rows):
    counts = {}
    fields = ("operation", "syscall", "outcome", "destination_class", "path_scope")
    process_creation_calls = {"fork", "vfork", "clone", "clone3"}
    for row in rows:
        if row["outcome"] == "PENDING":
            continue
        # Resumed generic calls get a parser-inferred class that ordinary
        # records lack; only process-creation calls expose this in both forms.
        key = tuple((field, row.get(field)) for field in fields) + (
            ("result_class", row.get("result_class") if row.get("syscall") in process_creation_calls else None),
        )
        counts[key] = counts.get(key, 0) + row["count"]
    return counts


def _bounded_observer_count_summary(rows):
    selected = {"newfstatat", "wait4", "openat", "rename", "renameat", "renameat2", "connect"}
    counts = {}
    for row in rows:
        if row["syscall"] not in selected or row["outcome"] == "PENDING":
            continue
        key = ":".join(
            str(value or "-")
            for value in (row["syscall"], row["outcome"], row.get("destination_class"))
        )
        counts[key] = counts.get(key, 0) + row["count"]
    return dict(sorted(counts.items()))


def test_completed_projection_ignores_only_resumption_framing_metadata():
    normal = [
        {"operation": "other_scoped_syscall", "syscall": "newfstatat", "outcome": "SUCCESS", "count": 3},
        {"operation": "other_scoped_syscall", "syscall": "wait4", "outcome": "ERROR", "count": 1},
        {"operation": "file_name_syscall", "syscall": "openat", "outcome": "SUCCESS", "path_scope": "case_workdir", "count": 2},
        {"operation": "socket_endpoint_syscall", "syscall": "connect", "outcome": "SUCCESS", "destination_class": "loopback", "count": 1},
    ]
    resumed_equivalent = [
        {**normal[0], "result_class": "positive", "trace_state": "RESUMED"},
        {**normal[1], "result_class": "zero_or_nonpositive", "trace_state": "RESUMED"},
        {**normal[2], "result_class": "positive", "trace_state": "RESUMED"},
        {**normal[3], "result_class": "positive", "trace_state": "RESUMED"},
        {"operation": "other_scoped_syscall", "syscall": "newfstatat", "outcome": "PENDING", "trace_state": "UNFINISHED", "count": 900},
    ]
    assert _completed_aggregate_projection(normal) == _completed_aggregate_projection(resumed_equivalent)

    for changed_row in (
        {**resumed_equivalent[0], "outcome": "ERROR"},
        {**resumed_equivalent[2], "path_scope": "outside_case_workdir"},
        {**resumed_equivalent[3], "destination_class": "public"},
    ):
        changed = [*resumed_equivalent[:4]]
        changed[resumed_equivalent.index(next(row for row in resumed_equivalent[:4] if row["syscall"] == changed_row["syscall"]))] = changed_row
        assert _completed_aggregate_projection(normal) != _completed_aggregate_projection(changed)

    clone_zero = {"operation": "process_lifecycle_syscall", "syscall": "clone", "outcome": "SUCCESS", "result_class": "zero_or_nonpositive", "count": 1}
    clone_child = {**clone_zero, "result_class": "positive"}
    assert _completed_aggregate_projection([clone_zero]) != _completed_aggregate_projection([clone_child])


def test_strace_command_raw_formats_only_low_detail_metadata(tmp_path, monkeypatch):
    _fake_strace(tmp_path, monkeypatch)
    argv_file = tmp_path / "strace-argv.json"
    env = {**os.environ, "OBSERVER_TEST_ARGV_FILE": str(argv_file)}
    result = observer.observe_cli(_fake_cli(tmp_path), cwd=tmp_path, env=env, timeout_seconds=5)
    argv = json.loads(argv_file.read_text(encoding="utf-8"))

    assert result["invocation"]["run_status"] == "CLI_COMPLETED"
    assert argv[argv.index("-e") + 1] == "trace=" + ",".join(observer.SYSCALL_SCOPE)
    raw_arguments = [argv[index + 1] for index, item in enumerate(argv[:-1]) if item == "-e" and argv[index + 1].startswith("raw=")]
    assert raw_arguments == ["raw=execve,execveat,newfstatat,wait4"]


@pytest.mark.skipif(platform.system() != "Linux" or shutil.which("strace") is None, reason="requires Linux strace")
def test_linux_raw_metadata_format_reduces_bytes_without_changing_observed_events(tmp_path, monkeypatch):
    target = tmp_path / "workload-created.txt"
    child = "import os,sys; [os.stat(sys.argv[1]) for _ in range(20)]"
    workload = tmp_path / "metadata_workload.py"
    workload.write_text(
        "import json, os, pathlib, socket, subprocess, sys, threading\n"
        "for _ in range(600): os.stat(__file__)\n"
        "try: os.stat(__file__ + '.observer-missing')\n"
        "except FileNotFoundError: pass\n"
        f"subprocess.run([sys.executable, '-c', {child!r}, __file__], check=True)\n"
        "try: os.waitpid(-1, os.WNOHANG)\n"
        "except ChildProcessError: pass\n"
        "server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
        "server.bind(('127.0.0.1', 0)); server.listen(1)\n"
        "accepted = []\n"
        "thread = threading.Thread(target=lambda: accepted.append(server.accept()[0]))\n"
        "thread.start()\n"
        "client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
        "client.connect(server.getsockname()); client.close(); thread.join()\n"
        "accepted[0].close(); server.close()\n"
        f"target = pathlib.Path({str(target)!r})\n"
        "target.write_text('fixture', encoding='utf-8')\n"
        "target.rename(target.with_suffix('.renamed'))\n"
        "print(json.dumps({'status': 'ok'}))\n",
        encoding="utf-8",
    )
    command = [sys.executable, str(workload)]
    env = os.environ.copy()
    candidate_raw = observer.RAW_ARGUMENT_SYSCALLS

    monkeypatch.setattr(observer, "RAW_ARGUMENT_SYSCALLS", ("execve", "execveat"))
    baseline = observer.observe_cli(command, cwd=tmp_path, env=env, timeout_seconds=30)
    monkeypatch.setattr(observer, "RAW_ARGUMENT_SYSCALLS", candidate_raw)
    candidate = observer.observe_cli(command, cwd=tmp_path, env=env, timeout_seconds=30)

    assert baseline["invocation"]["run_status"] == candidate["invocation"]["run_status"] == "CLI_COMPLETED"
    assert baseline["cli_result"] == candidate["cli_result"] == {"status": "ok"}
    assert baseline["observer"]["coverage"] == candidate["observer"]["coverage"] == "SCOPED_COMPLETE"
    assert baseline["observer"]["event_aggregates_complete"] is candidate["observer"]["event_aggregates_complete"] is True
    assert sum(row["count"] for row in baseline["observer"]["event_aggregates"]) == baseline["observer"]["event_count"]
    assert sum(row["count"] for row in candidate["observer"]["event_aggregates"]) == candidate["observer"]["event_count"]
    baseline_completed = _completed_aggregate_projection(baseline["observer"]["event_aggregates"])
    candidate_completed = _completed_aggregate_projection(candidate["observer"]["event_aggregates"])
    assert baseline_completed == candidate_completed
    assert baseline["observer"]["trace_bytes"] > candidate["observer"]["trace_bytes"]
    counts = {(row["syscall"], row["outcome"]): row["count"] for row in candidate["observer"]["event_aggregates"]}
    assert counts[("newfstatat", "SUCCESS")] >= 600
    assert counts[("newfstatat", "ERROR")] >= 1
    assert counts[("wait4", "SUCCESS")] >= 1
    assert counts[("wait4", "ERROR")] >= 1
    assert counts[("openat", "SUCCESS")] >= 1
    assert counts[("connect", "SUCCESS")] >= 1
    assert sum(
        row["count"]
        for row in candidate["observer"]["event_aggregates"]
        if row["syscall"] in {"rename", "renameat", "renameat2"} and row["outcome"] == "SUCCESS"
    ) == 1
    print(
        "observer-v3-real-strace="
        + json.dumps(
            {
                "baseline_trace_bytes": baseline["observer"]["trace_bytes"],
                "candidate_trace_bytes": candidate["observer"]["trace_bytes"],
                "saved_trace_bytes": baseline["observer"]["trace_bytes"] - candidate["observer"]["trace_bytes"],
                "completed_event_count": sum(candidate_completed.values()),
                "completed_counts": _bounded_observer_count_summary(candidate["observer"]["event_aggregates"]),
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    assert any(
        row["syscall"] == "connect" and row.get("destination_class") == "loopback"
        for row in candidate["observer"]["event_aggregates"]
    )


def test_numeric_pid_parser_does_not_confuse_tracer_root_and_child(tmp_path):
    root = observer._parse_line("4242 execve(0x0, 0x0, 0x0) = 0x0", tmp_path)
    child = observer._parse_line("4243 clone(0x1, 0, 0, 0, 0) = 4244", tmp_path)
    assert root and root["pid"] == 4242 and root["outcome"] == "SUCCESS"
    assert child and child["pid"] == 4243 and child["result_class"] == "positive"


def test_keyboard_interrupt_kills_owned_tracer_and_closes_selector_fds(tmp_path, monkeypatch):
    _fake_strace(tmp_path, monkeypatch)
    pid_path = tmp_path / "strace-pid"
    monkeypatch.setenv("OBSERVER_TEST_PID_FILE", str(pid_path))
    original_selector = observer.selectors.DefaultSelector
    instances = []

    class InterruptingSelector:
        def __init__(self):
            self.inner = original_selector()
            self.registered_fds = []
            self.closed = False
            instances.append(self)

        def register(self, fileobj, events, data=None):
            self.registered_fds.append(fileobj if isinstance(fileobj, int) else fileobj.fileno())
            return self.inner.register(fileobj, events, data)

        def select(self, timeout=None):
            if len(self.registered_fds) < 3:
                return self.inner.select(timeout)
            deadline = time.monotonic() + 1
            while not pid_path.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            raise KeyboardInterrupt

        def get_map(self):
            return self.inner.get_map()

        def unregister(self, fileobj):
            return self.inner.unregister(fileobj)

        def close(self):
            self.closed = True
            return self.inner.close()

    monkeypatch.setattr(observer.selectors, "DefaultSelector", InterruptingSelector)
    with pytest.raises(KeyboardInterrupt):
        observer.observe_cli(_fake_cli(tmp_path), cwd=tmp_path, env=os.environ.copy(), timeout_seconds=5)
    assert instances and instances[0].closed
    for fd in instances[0].registered_fds:
        with pytest.raises(OSError):
            os.fstat(fd)
    assert pid_path.exists()
    pid_text = pid_path.read_text(encoding="ascii")
    assert pid_text.isdecimal(), "fake tracer readiness file must contain a complete PID"
    pid = int(pid_text)
    assert pid > 0
    assert not pid_path.with_name(pid_path.name + ".ready-tmp").exists()
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)


def test_cli_json_is_available_in_memory_but_excluded_from_persistable_projection(tmp_path, monkeypatch):
    _fake_strace(tmp_path, monkeypatch)
    secret = "CANARY_SECRET_DO_NOT_PERSIST"
    cli = tmp_path / "secret_cli.py"
    cli.write_text(f"import json; print(json.dumps({{'token': {secret!r}, 'path': '/private/secret'}}))\n", encoding="utf-8")
    result = observer.observe_cli([sys.executable, str(cli)], cwd=tmp_path, env=os.environ.copy(), timeout_seconds=5)
    assert result["cli_result"]["token"] == secret
    persisted = json.dumps({"invocation": result["invocation"], "observer": result["observer"]}, sort_keys=True)
    assert secret not in persisted
    assert "/private/secret" not in persisted


@pytest.mark.skipif(platform.system() != "Linux" or shutil.which("strace") is None, reason="Linux strace required")
def test_kill_on_exit_stops_setsid_descendant_on_trial_deadline(tmp_path):
    pid_file = tmp_path / "escaped_session_child.pid"
    script = (
        "import json, os, pathlib, time\n"
        "child = os.fork()\n"
        "if child == 0:\n"
        " os.setsid()\n"
        f" pathlib.Path({str(pid_file)!r}).write_text(str(os.getpid()))\n"
        " time.sleep(30)\n"
        " os._exit(0)\n"
        "print('{\"status\":\"parent-exited\"}', flush=True)\n"
    )
    result = observer.observe_cli([sys.executable, "-c", script], cwd=tmp_path, env=os.environ.copy(), timeout_seconds=0.8)
    assert result["observer"]["overall_state"] == "UNKNOWN"
    assert result["observer"]["coverage"] == "INCOMPLETE"
    assert result["invocation"]["run_status"] == "RUN_TIMEOUT"
    assert pid_file.exists()
    child_pid = int(pid_file.read_text(encoding="ascii"))
    _wait_for_proc_child_stop(
        lambda: Path(f"/proc/{child_pid}/stat").read_text(encoding="ascii").split()[2],
        time.monotonic() + 3,
    )


@pytest.mark.parametrize("disappearance", [FileNotFoundError, ProcessLookupError])
def test_proc_stat_disappearance_race_is_treated_as_stopped(tmp_path, disappearance):
    stat_file = tmp_path / "proc" / "4242" / "stat"
    reads = 0

    def read_state():
        nonlocal reads
        reads += 1
        if disappearance is ProcessLookupError:
            raise ProcessLookupError("process vanished during procfs read")
        return stat_file.read_text(encoding="ascii").split()[2]

    _wait_for_proc_child_stop(read_state, time.monotonic() + 3)
    assert reads == 1


def test_proc_stat_permission_and_malformed_data_fail_loudly(tmp_path):
    stat_file = tmp_path / "proc" / "4242" / "stat"
    stat_file.parent.mkdir(parents=True)
    stat_file.write_text("4242 (child)", encoding="ascii")

    def read_state():
        return stat_file.read_text(encoding="ascii").split()[2]

    with pytest.raises(IndexError):
        _wait_for_proc_child_stop(read_state, time.monotonic() + 3)

    def permission_denied():
        raise PermissionError("permission denied")

    with pytest.raises(PermissionError, match="permission denied"):
        _wait_for_proc_child_stop(permission_denied, time.monotonic() + 3)
