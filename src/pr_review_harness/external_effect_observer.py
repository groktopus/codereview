"""Bounded Linux syscall observations for an installed CLI process tree.

This is diagnostic instrumentation only. It does not contain the tracee or
establish that effects outside the listed syscall scope did not occur.
"""

from __future__ import annotations

import ast
import hashlib
import ipaddress
import json
import os
import platform
import re
import selectors
import shutil
import signal
import stat
import subprocess
import time
from collections import Counter
from pathlib import Path
from typing import Any

OBSERVER_ID = "linux-strace-syscall-observer.v2"
TRACE_MAX_BYTES = 1_048_576
TRACE_MAX_EVENT_EXEMPLARS = 256
TRACE_MAX_AGGREGATE_BUCKETS = 128
TRACE_MAX_LINE_BYTES = 8_192
MAX_PROCESS_CREATIONS = 128
TRACE_MAX_PENDING_CALLS = 256
CLI_STDOUT_MAX_BYTES = 256_000
CLI_STDERR_MAX_BYTES = 64_000
MAX_OBSERVER_TIMEOUT_SECONDS = 300
CLEANUP_GRACE_SECONDS = 1.0
PREFLIGHT_OUTPUT_BYTES = 65_536
STRACE_BINARY_MAX_BYTES = 32 * 1024 * 1024
SYSCALL_SCOPE = [
    "%process",
    "%file",
    "socket",
    "connect",
    "bind",
    "listen",
    "accept",
    "accept4",
    "shutdown",
]
_RETURN_RE = re.compile(r"\)\s+=\s+(-?\d+)(?:\s|$)")
_HEX_RETURN_RE = re.compile(r"\)\s+=\s+0x[0-9a-fA-F]+(?:\s|$)")
_PID_PREFIX = r"(?:(?:\[pid\s+(\d+)\]|\[(\d+)\]|(\d+))\s+)?"
_SYSCALL_RE = re.compile(r"^" + _PID_PREFIX + r"([A-Za-z_][A-Za-z0-9_]*)\((.*)$")
_RESUMED_RE = re.compile(r"^" + _PID_PREFIX + r"<\.\.\.\s+([A-Za-z_][A-Za-z0-9_]*)\s+resumed>(.*)$")
_UNFINISHED_RE = re.compile(r"\s+<unfinished \.\.\.>$")
_PROCESS_END_RE = re.compile(r"^" + _PID_PREFIX + r"\+\+\+ (exited with (\d+)|killed by (SIG[A-Z0-9]+)) \+\+\+$")
_SIGNAL_RE = re.compile(r"^" + _PID_PREFIX + r"--- (SIG[A-Z0-9]+) .*---$")
_QUOTED_RE = re.compile(r'"((?:\\.|[^"\\])*)"')
_ADDR_RE = re.compile(r'(?:inet_addr\(|inet_pton\([^,]+,\s*)\s*"([^"\n]{1,128})"')
_CLI_ERROR_CODES = {
    "invalid_arguments": "invalid_arguments",
    "snapshot_preflight_failed": "snapshot_preflight_failed",
    "preflight_rejected": "preflight_rejected",
    "review_runtime_failed": "review_runtime_failed",
    "provider configuration is invalid": "provider_configuration_invalid",
    "provider adapter is unavailable": "provider_adapter_unavailable",
    "cannot read profile JSON": "profile_unavailable",
    "cannot read limits JSON": "limits_unavailable",
}


def _source_sha256(*, deadline: float | None = None) -> str | None:
    return _hash_file(__file__, deadline=deadline)


def _bounded_process(argv: list[str], *, timeout: float, env: dict[str, str]) -> tuple[int, bytes, bytes] | None:
    """Run a trusted probe with bounded output and time."""
    if timeout <= 0:
        return None
    try:
        process = subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            start_new_session=(os.name == "posix"),
        )
    except OSError:
        return None
    assert process.stdout is not None and process.stderr is not None
    stdout_fd = process.stdout.fileno()
    stderr_fd = process.stderr.fileno()
    selector = selectors.DefaultSelector()
    streams = {stdout_fd: process.stdout, stderr_fd: process.stderr}
    buffers = {fd: bytearray() for fd in streams}
    for fd, stream in streams.items():
        os.set_blocking(fd, False)
        selector.register(stream, selectors.EVENT_READ, fd)
    deadline = time.monotonic() + timeout
    failed = False
    while selector.get_map() or process.poll() is None:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            failed = True
            break
        ready = selector.select(min(remaining, 0.1))
        if not ready and process.poll() is None:
            time.sleep(min(0.01, remaining))
        for key, _ in ready:
            fd = key.data
            try:
                block = os.read(fd, PREFLIGHT_OUTPUT_BYTES + 1 - len(buffers[fd]))
            except BlockingIOError:
                continue
            except OSError:
                failed = True
                break
            if not block:
                selector.unregister(key.fileobj)
                key.fileobj.close()
                continue
            buffers[fd].extend(block)
            if len(buffers[fd]) > PREFLIGHT_OUTPUT_BYTES:
                failed = True
                break
        if failed:
            break
    if failed:
        _terminate_group(process)
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        _terminate_group(process)
        try:
            process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            failed = True
        failed = True
    for key in list(selector.get_map().values()):
        try:
            selector.unregister(key.fileobj)
            key.fileobj.close()
        except OSError:
            pass
    selector.close()
    if failed:
        return None
    return process.returncode, bytes(buffers[stdout_fd]), bytes(buffers[stderr_fd])


def preflight(*, timeout_seconds: float = 15.0, deadline: float | None = None) -> dict[str, Any]:
    """Return a bounded Linux/strace identity; never installs or elevates anything."""
    if platform.system() != "Linux":
        return {"status": "UNSUPPORTED", "reason": "linux_required", "source_sha256": _source_sha256(deadline=deadline)}
    executable = shutil.which("strace")
    if not executable:
        return {"status": "UNSUPPORTED", "reason": "strace_unavailable", "source_sha256": _source_sha256(deadline=deadline)}
    source_hash = _source_sha256(deadline=deadline)
    binary_hash = _hash_file(executable, deadline=deadline)
    if source_hash is None or binary_hash is None:
        return {"status": "UNKNOWN", "reason": "observer_identity_unavailable"}
    def remaining() -> float:
        if deadline is None:
            return timeout_seconds
        return max(0.0, min(timeout_seconds, deadline - time.monotonic()))
    version_probe = _bounded_process([executable, "--version"], timeout=min(5, remaining()), env={"PATH": os.environ.get("PATH", "")})
    if version_probe is None or remaining() <= 0:
        return {"status": "UNKNOWN", "reason": "strace_version_probe_failed", "source_sha256": source_hash}
    help_probe = _bounded_process([executable, "--help"], timeout=min(5, remaining()), env={"PATH": os.environ.get("PATH", "")})
    if version_probe is None or help_probe is None:
        return {"status": "UNKNOWN", "reason": "strace_version_probe_failed", "source_sha256": source_hash}
    version_rc, version_stdout, _ = version_probe
    help_rc, help_stdout, help_stderr = help_probe
    output = version_stdout[:512].decode("ascii", "replace").splitlines()
    version = output[0] if output else ""
    help_output = (help_stdout + help_stderr).decode("utf-8", "replace")
    if version_rc or not version.startswith("strace -- version ") or len(version) > 256:
        return {"status": "UNKNOWN", "reason": "strace_version_invalid", "source_sha256": source_hash}
    if help_rc or "--kill-on-exit" not in help_output:
        return {"status": "UNSUPPORTED", "reason": "kill_on_exit_unavailable", "source_sha256": source_hash}
    return {
        "status": "AVAILABLE",
        "executable_sha256": binary_hash,
        "version": version,
        "kill_on_exit_supported": True,
        "source_sha256": source_hash,
    }


def _hash_file(path: str, *, deadline: float | None = None) -> str | None:
    digest = hashlib.sha256()
    fd = -1
    try:
        before = os.lstat(path)
        if not os.path.isfile(path) or os.path.islink(path) or before.st_size > STRACE_BINARY_MAX_BYTES:
            return None
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
        opened = os.fstat(fd)
        if not os.path.samestat(before, opened) or not stat.S_ISREG(opened.st_mode):
            return None
        total = 0
        while True:
            if deadline is not None and time.monotonic() >= deadline:
                return None
            block = os.read(fd, min(65_536, STRACE_BINARY_MAX_BYTES + 1 - total))
            if not block:
                break
            total += len(block)
            if total > STRACE_BINARY_MAX_BYTES:
                return None
            digest.update(block)
    except OSError:
        return None
    finally:
        if fd >= 0:
            os.close(fd)
    return digest.hexdigest()


def _outcome(line: str, syscall: str) -> tuple[str, int | None] | None:
    if syscall in {"execve", "execveat"}:
        hex_match = _HEX_RETURN_RE.search(line)
        if hex_match:
            value = hex_match.group(0).split("=")[-1].strip().lower()
            return ("SUCCESS", 0) if value == "0x0" else ("ERROR", -1)
    if syscall in {"exit", "exit_group"} and re.search(r"\)\s+=\s+\?(?:\s|$)", line):
        return "NONRETURNING", None
    match = _RETURN_RE.search(line)
    if not match:
        return None
    value = int(match.group(1))
    return ("SUCCESS" if value >= 0 else "ERROR"), value


def _path_evidence(args: str, cwd: Path) -> dict[str, Any] | None:
    match = _QUOTED_RE.search(args)
    if not match:
        return None
    encoded = match.group(1)
    raw = encoded.encode("utf-8", "replace")[:2_048]
    # Decode only as a literal string. If quoting cannot be decoded, hash the
    # trace representation and leave its path bucket unknown.
    try:
        decoded = ast.literal_eval('"' + encoded + '"')
        if encoded.endswith("..."):
            raise ValueError("strace_path_truncated")
        lexical = os.path.normpath(decoded if decoded.startswith("/") else str(cwd / decoded))
        cwd_text = os.path.normpath(str(cwd))
        scope = "case_workdir" if lexical == cwd_text or lexical.startswith(cwd_text.rstrip(os.sep) + os.sep) else "outside_case_workdir"
    except (OSError, ValueError, SyntaxError, RecursionError, TypeError, IndexError):
        scope = "unknown"
    return {
        "path_sha256": hashlib.sha256(raw).hexdigest(),
        "path_scope": scope,
        "path_hash_truncated": encoded.endswith("..."),
    }


def _destination_class(args: str) -> str | None:
    match = _ADDR_RE.search(args)
    if not match:
        return None
    try:
        address = ipaddress.ip_address(match.group(1))
    except ValueError:
        return "unparsed"
    if address.is_loopback:
        return "loopback"
    if address.is_private:
        return "private"
    if address.is_global:
        return "public"
    return "non_global"


def _parse_line(line: str, cwd: Path) -> dict[str, Any] | None:
    if not line:
        return None
    end_match = _PROCESS_END_RE.match(line)
    if end_match:
        pid = next((value for value in end_match.groups()[:3] if value is not None), None)
        if end_match.group(5):
            return {"pid": int(pid) if pid else None, "operation": "process_termination", "outcome": "EXITED", "exit_code": int(end_match.group(5))}
        return {"pid": int(pid) if pid else None, "operation": "process_termination", "outcome": "KILLED", "signal": end_match.group(6)}
    signal_match = _SIGNAL_RE.match(line)
    if signal_match:
        pid = next((value for value in signal_match.groups()[:3] if value is not None), None)
        return {"pid": int(pid) if pid else None, "operation": "signal_delivery", "signal": signal_match.group(4), "outcome": "OBSERVED"}
    resumed = _RESUMED_RE.match(line)
    if resumed:
        prefix_pid = next((value for value in resumed.groups()[:3] if value is not None), None)
        syscall = resumed.group(4)
        fragment = resumed.group(5)
        outcome = _outcome(fragment, syscall)
        if outcome is None:
            raise ValueError("trace_resumed_outcome_unavailable")
        return {"pid": int(prefix_pid) if prefix_pid else None, "syscall": syscall, "operation": "resumed_syscall", "trace_state": "RESUMED", "outcome": outcome[0], "result_class": "positive" if outcome[1] and outcome[1] > 0 else "zero_or_nonpositive" if outcome[1] is not None else "nonreturning"}
    match = _SYSCALL_RE.match(line)
    if not match:
        raise ValueError("trace_line_unrecognized")
    pid_text = next((value for value in match.groups()[:3] if value is not None), None)
    syscall, args = match.group(4), match.group(5)
    unfinished = _UNFINISHED_RE.search(args)
    if unfinished:
        args = args[: unfinished.start()]
        outcome = ("PENDING", None)
    else:
        outcome = _outcome(args, syscall)
    if outcome is None:
        # strace marks split/unfinished calls. Keep no raw line and treat the
        # observation channel as incomplete rather than guessing an outcome.
        raise ValueError("trace_outcome_unavailable")
    if syscall in {"execve", "execveat", "fork", "vfork", "clone", "clone3", "exit", "exit_group"}:
        operation = "process_lifecycle_syscall"
        safe_name = syscall
    elif syscall in {"open", "openat", "openat2", "creat", "rename", "renameat", "renameat2", "unlink", "unlinkat"}:
        operation = "file_name_syscall"
        safe_name = syscall
    elif syscall in {"socket", "connect", "bind", "listen", "accept", "accept4", "shutdown"}:
        operation = "socket_endpoint_syscall"
        safe_name = syscall
    else:
        # %file/%process expand by architecture and strace release. Keep only
        # the bounded syscall name/outcome for other calls in these classes.
        operation = "other_scoped_syscall"
        safe_name = syscall[:64]
    event: dict[str, Any] = {"syscall": safe_name, "operation": operation, "outcome": outcome[0]}
    if outcome[0] == "PENDING":
        event["trace_state"] = "UNFINISHED"
    if syscall in {"fork", "vfork", "clone", "clone3"} and outcome[1] is not None:
        event["result_class"] = "positive" if outcome[1] > 0 else "zero_or_nonpositive"
    if pid_text:
        event["pid"] = int(pid_text)
    if operation == "file_name_syscall":
        path = _path_evidence(args, cwd)
        if path:
            event.update(path)
    if operation == "socket_endpoint_syscall":
        destination = _destination_class(args)
        if destination:
            event["destination_class"] = destination
    return event


def _aggregate_key(event: dict[str, Any]) -> tuple[str, ...]:
    """Return a fixed-cardinality key containing only sanitized fields."""
    return tuple(
        str(event.get(field, ""))[:64]
        for field in (
            "operation",
            "syscall",
            "outcome",
            "result_class",
            "destination_class",
            "path_scope",
            "trace_state",
        )
    )


def _cli_error_code(stdout: bytes) -> str | None:
    """Extract a stable CLI error code without returning its output payload."""
    try:
        value = json.loads(stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        return None
    if not isinstance(value, dict) or not isinstance(value.get("error"), str):
        return None
    return _CLI_ERROR_CODES.get(value["error"], "other")


def observe_cli(
    command: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    timeout_seconds: float,
) -> dict[str, Any]:
    """Trace one CLI invocation while retaining only bounded sanitized events.

    The returned `overall_state` is always UNKNOWN because this syscall scope
    cannot establish absence of effects beyond the observed channels.
    """
    try:
        timeout = float(timeout_seconds)
    except (TypeError, ValueError):
        timeout = 0
    if not 0 < timeout <= MAX_OBSERVER_TIMEOUT_SECONDS:
        return {"invocation": {"run_status": "INVALID_TIMEOUT", "exit_code": None}, "observer": {"observer_id": OBSERVER_ID, "overall_state": "UNKNOWN", "coverage": "INCOMPLETE", "reason": "timeout_invalid", "events": []}, "cli_result": None}
    started = time.monotonic()
    deadline = started + timeout
    try:
        identity = preflight(timeout_seconds=timeout, deadline=deadline)
    except Exception:
        identity = {"status": "UNKNOWN", "reason": "preflight_failed"}
    base: dict[str, Any] = {
        "observer_id": OBSERVER_ID,
        "overall_state": "UNKNOWN",
        "channel_state": "UNKNOWN",
        "coverage": "INCOMPLETE",
        "scope": SYSCALL_SCOPE,
        "source_sha256": identity.get("source_sha256"),
        "events": [],
    }
    if identity.get("status") != "AVAILABLE":
        return {"invocation": {"run_status": "OBSERVER_UNAVAILABLE", "exit_code": None}, "observer": {**base, "reason": identity.get("reason", "observer_unavailable")}, "cli_result": None}
    if not command or len(command) > 256 or any(not isinstance(item, str) or "\x00" in item for item in command):
        return {"invocation": {"run_status": "INVALID_COMMAND", "exit_code": None}, "observer": {**base, "reason": "command_invalid"}, "cli_result": None}
    if time.monotonic() >= deadline:
        return {"invocation": {"run_status": "OBSERVER_UNAVAILABLE", "exit_code": None}, "observer": {**base, "reason": "observer_deadline_exhausted"}, "cli_result": None}

    trace_read, trace_write = os.pipe()
    os.set_blocking(trace_read, False)
    tracer = shutil.which("strace")
    assert tracer is not None
    trace_path = f"/dev/fd/{trace_write}"
    argv = [
        tracer,
        "--kill-on-exit",
        "-f",
        "-qq",
        "-s",
        "2048",
        "-e",
        "trace=" + ",".join(SYSCALL_SCOPE),
        "-e",
        "raw=execve,execveat",
        "-o",
        trace_path,
        "--",
        *command,
    ]
    try:
        process = subprocess.Popen(
            argv,
            cwd=cwd,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            pass_fds=(trace_write,),
            start_new_session=True,
        )
    except OSError:
        os.close(trace_read)
        os.close(trace_write)
        return {"invocation": {"run_status": "OBSERVER_SPAWN_FAILED", "exit_code": None}, "observer": {**base, "reason": "strace_spawn_failed"}}
    selector = None
    normal_exit = False
    try:
        os.close(trace_write)
        assert process.stdout is not None and process.stderr is not None
        stdout_fd = process.stdout.fileno()
        stderr_fd = process.stderr.fileno()
        selector = selectors.DefaultSelector()
        pipes = {
            stdout_fd: (process.stdout, CLI_STDOUT_MAX_BYTES),
            stderr_fd: (process.stderr, CLI_STDERR_MAX_BYTES),
            trace_read: (None, TRACE_MAX_BYTES),
        }
        captures = {fd: bytearray() for fd in pipes if fd != trace_read}
        byte_counts = {fd: 0 for fd in pipes}
        for fd, (stream, _) in pipes.items():
            selector.register(stream if stream is not None else fd, selectors.EVENT_READ, fd)
        trace_buffer = bytearray()
        events: list[dict[str, Any]] = []
        aggregates: Counter[tuple[str, ...]] = Counter()
        parsed_event_count = 0
        trace_bytes = 0
        incomplete: str | None = None
        parse_enabled = True
        cli_output_exceeded = False
        process_cap_exceeded = False
        process_creations = 0
        pending_call_evidence: dict[tuple[int | None, str], dict[str, Any]] = {}
        root_exec_seen = False
        root_exec_pid: int | None = None
        timed_out = False
        cwd_resolved = cwd
        root_exec_observed = False
        while selector.get_map() or process.poll() is None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                break
            ready = selector.select(min(remaining, 0.1))
            if not ready and process.poll() is None:
                time.sleep(min(0.01, remaining))
            for key, _ in ready:
                fd = key.data
                try:
                    read_limit = (
                        8_192
                        if fd == trace_read and not parse_enabled
                        else min(8_192, pipes[fd][1] + 1 - byte_counts[fd])
                    )
                    block = os.read(fd, read_limit)
                except BlockingIOError:
                    continue
                except OSError:
                    if fd == trace_read:
                        incomplete = incomplete or "trace_read_failed"
                        parse_enabled = False
                        selector.unregister(key.fileobj)
                        os.close(trace_read)
                        continue
                    incomplete = "cli_output_read_failed"
                    cli_output_exceeded = True
                    break
                if not block:
                    selector.unregister(key.fileobj)
                    if fd == trace_read:
                        os.close(trace_read)
                    else:
                        pipes[fd][0].close()  # type: ignore[union-attr]
                    continue
                byte_counts[fd] += len(block)
                if fd != trace_read:
                    captures[fd].extend(block)
                if byte_counts[fd] > pipes[fd][1]:
                    if fd == trace_read:
                        incomplete = incomplete or "trace_byte_cap_exceeded"
                        parse_enabled = False
                        trace_buffer.clear()
                        continue
                    incomplete = "cli_output_cap_exceeded"
                    cli_output_exceeded = True
                    break
                if fd == trace_read:
                    trace_bytes = byte_counts[fd]
                    if not parse_enabled:
                        continue
                    trace_buffer.extend(block)
                    while b"\n" in trace_buffer:
                        raw_line, _, rest = trace_buffer.partition(b"\n")
                        trace_buffer = bytearray(rest)
                        if len(raw_line) > TRACE_MAX_LINE_BYTES:
                            incomplete = incomplete or "trace_line_cap_exceeded"
                            parse_enabled = False
                            trace_buffer.clear()
                            break
                        try:
                            parsed = _parse_line(raw_line.decode("utf-8", "strict"), cwd_resolved)
                        except Exception:
                            incomplete = incomplete or "trace_parse_failed"
                            parse_enabled = False
                            trace_buffer.clear()
                            break
                        if incomplete is not None:
                            break
                        if parsed is not None:
                            parsed_event_count += 1
                            if not root_exec_seen and parsed.get("syscall") in {"execve", "execveat"}:
                                root_exec_seen = True
                                if parsed.get("outcome") == "SUCCESS" and parsed.get("pid") is not None:
                                    root_exec_pid = parsed.get("pid")
                                else:
                                    incomplete = "root_exec_launch_not_proven"
                                    parse_enabled = False
                                    break
                            pending_key = (parsed.get("pid"), parsed.get("syscall", ""))
                            if parsed.get("trace_state") == "UNFINISHED":
                                if pending_key in pending_call_evidence:
                                    incomplete = "trace_duplicate_unfinished_syscall"
                                    parse_enabled = False
                                    break
                                if len(pending_call_evidence) >= TRACE_MAX_PENDING_CALLS:
                                    incomplete = "trace_pending_call_cap_exceeded"
                                    parse_enabled = False
                                    break
                                pending_call_evidence[pending_key] = {
                                    field: parsed[field]
                                    for field in (
                                        "operation",
                                        "destination_class",
                                        "path_scope",
                                        "path_sha256",
                                        "path_hash_truncated",
                                    )
                                    if field in parsed
                                }
                            elif parsed.get("trace_state") == "RESUMED":
                                evidence = pending_call_evidence.pop(pending_key, None)
                                if evidence is None:
                                    incomplete = "trace_resume_without_unfinished"
                                    parse_enabled = False
                                    break
                                parsed.update(evidence)
                            if (
                                parsed.get("operation") == "process_lifecycle_syscall"
                                and parsed.get("syscall") in {"fork", "vfork", "clone", "clone3"}
                                and parsed.get("outcome") == "SUCCESS"
                            ):
                                process_creations += 1
                                if process_creations > MAX_PROCESS_CREATIONS:
                                    incomplete = "process_creation_cap_exceeded"
                                    process_cap_exceeded = True
                                    break
                            key = _aggregate_key(parsed)
                            if key not in aggregates and len(aggregates) >= TRACE_MAX_AGGREGATE_BUCKETS:
                                incomplete = "trace_aggregate_bucket_cap_exceeded"
                                parse_enabled = False
                                trace_buffer.clear()
                                break
                            aggregates[key] += 1
                            if len(events) < TRACE_MAX_EVENT_EXEMPLARS:
                                events.append(parsed)
                    if len(trace_buffer) > TRACE_MAX_LINE_BYTES:
                        incomplete = incomplete or "trace_line_cap_exceeded"
                        parse_enabled = False
                        trace_buffer.clear()
            if cli_output_exceeded or process_cap_exceeded or incomplete is not None:
                break
        needs_teardown = timed_out or cli_output_exceeded or process_cap_exceeded or incomplete is not None
        cleanup_confirmed = False
        if needs_teardown:
            _terminate_group(process)
            wait_seconds = CLEANUP_GRACE_SECONDS
        else:
            wait_seconds = max(0.001, deadline - time.monotonic())
        try:
            process.wait(timeout=wait_seconds)
            cleanup_confirmed = True
        except subprocess.TimeoutExpired:
            if needs_teardown:
                incomplete = incomplete or "tracee_cleanup_unconfirmed"
            else:
                _terminate_group(process)
                try:
                    process.wait(timeout=CLEANUP_GRACE_SECONDS)
                    cleanup_confirmed = True
                except subprocess.TimeoutExpired:
                    incomplete = incomplete or "tracee_cleanup_unconfirmed"
        for key in list(selector.get_map().values()):
            try:
                selector.unregister(key.fileobj)
                if isinstance(key.fileobj, int):
                    os.close(key.fileobj)
                else:
                    key.fileobj.close()
            except OSError:
                pass
        selector.close()

        if pending_call_evidence and incomplete is None:
            incomplete = "trace_unfinished_syscall"
        root_exec_observed = root_exec_seen and root_exec_pid is not None
        if incomplete is None and not root_exec_observed:
            incomplete = "root_exec_or_trace_incomplete"
        if incomplete is None and trace_buffer:
            incomplete = "trace_trailing_bytes"
        complete = not timed_out and incomplete is None and not trace_buffer and root_exec_observed
        cli_stdout = bytes(captures[stdout_fd])
        cli_stderr = bytes(captures[stderr_fd])
        invocation: dict[str, Any] = {
            "run_status": (
                "RUN_TIMEOUT"
                if timed_out
                else "OUTPUT_LIMIT_EXCEEDED"
                if cli_output_exceeded
                else "OBSERVER_PROCESS_CAP_EXCEEDED"
                if process_cap_exceeded
                else "OBSERVER_TRACE_INCOMPLETE"
                if not complete
                else "CLI_FAILED"
                if process.returncode
                else "CLI_COMPLETED"
            ),
            "exit_code": process.returncode,
            "elapsed_ms": round((time.monotonic() - started) * 1000, 2),
            "cleanup_grace_ms": round(CLEANUP_GRACE_SECONDS * 1000),
            "cleanup_status": "TRACER_EXITED" if cleanup_confirmed else "UNCONFIRMED",
            "stdout_bytes": len(cli_stdout),
            "stdout_sha256": hashlib.sha256(cli_stdout).hexdigest(),
            "stderr_bytes": len(cli_stderr),
            "stderr_sha256": hashlib.sha256(cli_stderr).hexdigest(),
            "cli_error_code": _cli_error_code(cli_stdout) if process.returncode else None,
        }
        cli_result = None
        if invocation["run_status"] == "CLI_COMPLETED" and complete:
            try:
                decoded = json.loads(cli_stdout)
                if isinstance(decoded, dict):
                    cli_result = decoded
                else:
                    invocation["run_status"] = "INVALID_CLI_OUTPUT"
            except (json.JSONDecodeError, UnicodeDecodeError):
                invocation["run_status"] = "INVALID_CLI_OUTPUT"
        observer = {
            **base,
            "strace_version": identity.get("version"),
            "strace_executable_sha256": identity.get("executable_sha256"),
            "trace_bytes": trace_bytes,
            "event_count": parsed_event_count,
            "event_sample_count": len(events),
            "event_sample_truncated": parsed_event_count > len(events),
            "event_aggregates": [
                {
                    "operation": key[0],
                    "syscall": key[1],
                    "outcome": key[2],
                    "result_class": key[3] or None,
                    "destination_class": key[4] or None,
                    "path_scope": key[5] or None,
                    "trace_state": key[6] or None,
                    "count": count,
                }
                for key, count in sorted(aggregates.items())
            ],
            "event_aggregates_complete": complete,
            "events": events,
            "root_exec_evidence": "first_successful_execve_in_fresh_spawn_trace" if root_exec_observed else None,
            "root_exec_pid": root_exec_pid,
            "coverage": "SCOPED_COMPLETE" if complete else "INCOMPLETE",
            "channel_state": "OBSERVED_SCOPED" if events else "NO_SYSCALL_EVENTS_IN_SCOPE" if complete else "UNKNOWN",
            "reason": None if complete else "run_timeout" if timed_out else incomplete or "root_exec_or_trace_incomplete",
        }
        normal_exit = True
        return {"invocation": invocation, "observer": observer, "cli_result": cli_result}
    finally:
        if not normal_exit:
            _terminate_group(process)
            try:
                process.wait(timeout=CLEANUP_GRACE_SECONDS)
            except subprocess.TimeoutExpired:
                pass
        if selector is not None:
            try:
                for key in list(selector.get_map().values()):
                    try:
                        selector.unregister(key.fileobj)
                        if isinstance(key.fileobj, int):
                            os.close(key.fileobj)
                        else:
                            key.fileobj.close()
                    except Exception:
                        pass
                selector.close()
            except Exception:
                pass
        for stream in (process.stdout, process.stderr):
            if stream is not None:
                try:
                    stream.close()
                except Exception:
                    pass
        for fd in (trace_read, trace_write):
            try:
                os.close(fd)
            except OSError:
                pass



def _terminate_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except OSError:
        try:
            process.kill()
        except OSError:
            pass


def main() -> int:
    """Print a sanitized tracer preflight identity for CI evidence."""
    identity = preflight()
    print(json.dumps(identity, sort_keys=True, separators=(",", ":")))
    return 0 if identity.get("status") == "AVAILABLE" else 1


if __name__ == "__main__":
    raise SystemExit(main())
