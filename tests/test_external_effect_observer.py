from __future__ import annotations

import json
import os
import platform
import shutil
import socket
import sys
import threading
import time
from pathlib import Path

import pytest

from pr_review_harness import external_effect_observer as observer
from scripts.effect_observer_smoke import _failure_summary, _prepare_environment


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
        "if os.environ.get('OBSERVER_TEST_PID_FILE'):\n"
        " open(os.environ['OBSERVER_TEST_PID_FILE'], 'w').write(str(os.getpid()))\n"
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
    assert observation["observer_id"] == "linux-strace-syscall-observer.v2"
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
    assert observed["observer_id"] == "linux-strace-syscall-observer.v2"
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


def test_failed_cli_exposes_only_stable_error_code(tmp_path, monkeypatch):
    _fake_strace(tmp_path, monkeypatch)
    canary = "SENSITIVE_CLI_STDOUT_CANARY"
    script = tmp_path / "failed_cli.py"
    script.write_text(
        "import json, sys; print(json.dumps({'error':'invalid_arguments','exit_code':2,'payload':'SENSITIVE_CLI_STDOUT_CANARY'})); sys.exit(2)\n",
        encoding="utf-8",
    )
    result = observer.observe_cli([sys.executable, str(script)], cwd=tmp_path, env=os.environ.copy(), timeout_seconds=5)
    assert result["invocation"]["run_status"] == "CLI_FAILED"
    assert result["invocation"]["exit_code"] == 2
    assert result["invocation"]["cli_error_code"] == "invalid_arguments"
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
        f"client = socket.create_connection(('127.0.0.1', {port}), timeout=2); client.close()\n"
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
    pid = int(pid_path.read_text(encoding="ascii"))
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
