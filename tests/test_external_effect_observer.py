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
        " else:\n"
        "  payload = b'[pid 4242] execve(0x0, 0x0, 0x0) = 0x0\\n' + b'[pid 5] clone(' + b'1' * 600 + b') = 6\\n'\n"
        " repeat -= 1\n"
        " while repeat:\n"
        "  n = os.write(fd, payload)\n"
        "  repeat -= 1\n"
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
    monkeypatch.setattr(observer, "TRACE_MAX_EVENTS", 10_000)
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
    script = (
        "import pathlib, socket, subprocess, sys\n"
        f"first = pathlib.Path({str(created)!r}); second = pathlib.Path({str(renamed)!r})\n"
        "first.write_text('fixture')\n"
        "first.rename(second)\n"
        f"client = socket.create_connection(('127.0.0.1', {port}), timeout=2); client.close()\n"
        f"subprocess.Popen([sys.executable, '-c', 'import pathlib,time; time.sleep(0.2); pathlib.Path({str(child_file)!r}).write_text(\"late\")'])\n"
        "print('{\"status\":\"ok\"}')\n"
    )
    try:
        result = observer.observe_cli([sys.executable, "-c", script], cwd=tmp_path, env=os.environ.copy(), timeout_seconds=8)
        accept_thread.join(timeout=5)
    finally:
        server.close()
        for connection in accepted:
            connection.close()
    events = result["observer"]["events"]
    assert result["observer"]["overall_state"] == "UNKNOWN"
    assert result["observer"]["coverage"] == "SCOPED_COMPLETE"
    assert result["invocation"]["run_status"] == "CLI_COMPLETED"
    assert any(item.get("syscall") in {"open", "openat", "creat"} and item.get("outcome") == "SUCCESS" for item in events)
    assert any(item.get("syscall", "").startswith("rename") and item.get("outcome") == "SUCCESS" for item in events)
    assert any(item.get("syscall") == "connect" and item.get("destination_class") == "loopback" for item in events)
    assert sum(item.get("syscall") in {"execve", "execveat"} for item in events) >= 2
    assert renamed.exists() and child_file.exists()


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
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        try:
            state = Path(f"/proc/{child_pid}/stat").read_text(encoding="ascii").split()[2]
        except FileNotFoundError:
            break
        if state == "Z":
            break
        time.sleep(0.05)
    else:
        pytest.fail("strace_exit_left_a_running_setsid_tracee")
