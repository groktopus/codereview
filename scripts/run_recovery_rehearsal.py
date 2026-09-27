#!/usr/bin/env python3
"""Exercise bounded recovery paths through an installed pr-review CLI offline.

The only HTTP endpoint is a loopback fake provider. Event-mode GitHub reads use
a temporary local ``gh`` shim. Reviewed Git source is read as immutable input;
the runner never checks it out or executes its hooks, tests, or build scripts.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import selectors
import signal
import stat
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

MAX_CLI_SECONDS = 12.0
MAX_REHEARSAL_SECONDS = 60.0
CLEANUP_GRACE_SECONDS = 3.0
MAX_CLI_OUTPUT_BYTES = 256_000
MAX_ARTIFACT_BYTES = 8_000_000
ENGINE_DEADLINE_SECONDS = 8
PROVIDER_TIMEOUT_SECONDS = 0.35
FAKE_API_KEY = "recovery-rehearsal-only"
FIXTURE_REPOSITORY = "owner/project"
FIXTURE_PR = 7
_REHEARSAL_ARTIFACT_NAMES = frozenset(
    f"recovery-{name}.{extension}"
    for name in (
        "http-failure",
        "provider-timeout",
        "interrupted",
        "historical",
        "freshness-stale",
        "freshness-unknown",
    )
    for extension in ("json", "md")
)
_FAILURE_CODE = re.compile(r"^[a-z][a-z0-9_]{0,79}$")


class RehearsalError(RuntimeError):
    """A stable, non-secret rehearsal failure."""


class _FakeProviderState:
    def __init__(self) -> None:
        self._condition = threading.Condition()
        self._behaviors: list[str] = []
        self._calls: list[dict[str, Any]] = []
        self._all_calls: list[dict[str, Any]] = []

    def configure(self, behaviors: list[str]) -> None:
        with self._condition:
            self._behaviors = list(behaviors)
            self._calls = []
            self._condition.notify_all()

    def record(self, path: str, behavior: str) -> int:
        with self._condition:
            self._calls.append({"path": path, "behavior": behavior})
            self._all_calls.append({"path": path, "behavior": behavior})
            self._condition.notify_all()
            return len(self._calls)

    def behavior_for(self, index: int) -> str:
        with self._condition:
            if index < len(self._behaviors):
                return self._behaviors[index]
            return "success"

    def wait_for_calls(self, count: int, timeout: float) -> bool:
        deadline = time.monotonic() + timeout
        with self._condition:
            while len(self._calls) < count:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._condition.wait(remaining)
            return True

    @property
    def calls(self) -> list[dict[str, Any]]:
        with self._condition:
            return list(self._calls)

    @property
    def all_calls(self) -> list[dict[str, Any]]:
        with self._condition:
            return list(self._all_calls)


def _specialist_payload(request: dict[str, Any]) -> dict[str, Any]:
    messages = request.get("messages")
    if not isinstance(messages, list) or len(messages) != 2 or not isinstance(messages[1], dict):
        raise ValueError("invalid synthetic request")
    user = json.loads(messages[1].get("content", "{}"))
    task = user.get("task", {})
    evidence = user.get("evidence", [])
    if not isinstance(task, dict) or not isinstance(evidence, list):
        raise ValueError("invalid synthetic request")
    refs = [
        item["evidence_id"] for item in evidence if isinstance(item, dict) and isinstance(item.get("evidence_id"), str)
    ]
    notes = [
        {
            "unit_id": unit_id,
            "state": "COVERED" if refs else "NOT_COVERED",
            "reason_code": "RECOVERY_REHEARSAL_SYNTHETIC_RESPONSE",
            "evidence_refs": refs,
            "coverage_basis": "STATIC_REVIEW",
        }
        for unit_id in task.get("unit_ids", [])
        if isinstance(unit_id, str)
    ]
    return {
        "contract_version": "specialist-findings.v4",
        "finding_candidates": [],
        "context_gap_proposals": [],
        "coverage_notes": notes,
        "specific_strengths": [],
        "future_guidance": [],
    }


class _ProviderHandler(BaseHTTPRequestHandler):
    state: _FakeProviderState
    api_key: str
    stall_seconds: float
    response_delay_seconds: float

    def do_POST(self) -> None:  # noqa: N802 - stdlib handler API
        length = int(self.headers.get("Content-Length", "0"))
        if length < 0 or length > 128_000 or self.path != "/v1/chat/completions":
            self.send_error(413)
            return
        raw = self.rfile.read(length)
        if self.headers.get("Authorization") != f"Bearer {self.api_key}":
            self.send_error(401)
            return
        try:
            request = json.loads(raw)
            payload = _specialist_payload(request)
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
            self.send_error(400)
            return
        behavior = self.state.behavior_for(len(self.state.calls))
        call_no = self.state.record(self.path, behavior)
        if behavior == "stall":
            time.sleep(self.stall_seconds)
            return
        if behavior == "http_503":
            body = b'{"error":"synthetic failure"}'
            self.send_response(503)
        elif behavior == "success":
            if self.response_delay_seconds:
                time.sleep(self.response_delay_seconds)
            body = json.dumps(
                {
                    "id": f"local-rehearsal-{call_no}",
                    "model": "local-rehearsal-model",
                    "choices": [{"finish_reason": "stop", "message": {"content": json.dumps(payload)}}],
                    "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
                },
                separators=(",", ":"),
            ).encode("utf-8")
            self.send_response(200)
        else:
            self.send_error(500)
            return
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def log_message(self, *_args: Any) -> None:
        return


class _FakeProvider(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, state: _FakeProviderState, *, response_delay_seconds: float = 0.0) -> None:
        if (
            isinstance(response_delay_seconds, bool)
            or not isinstance(response_delay_seconds, (int, float))
            or not 0 <= response_delay_seconds < float("inf")
        ):
            raise ValueError("invalid synthetic response delay")
        self.state = state
        handler = type(
            "RecoveryProviderHandler",
            (_ProviderHandler,),
            {
                "state": state,
                "api_key": FAKE_API_KEY,
                "stall_seconds": 4.0,
                "response_delay_seconds": float(response_delay_seconds),
            },
        )
        super().__init__(("127.0.0.1", 0), handler)

    @property
    def endpoint(self) -> str:
        return f"http://127.0.0.1:{self.server_port}/v1"


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(64 * 1024):
            digest.update(block)
    return digest.hexdigest()


def _collect_artifacts(source: Path, destination: Path) -> dict[str, Any]:
    """Copy only known, regular run artifacts while enforcing the aggregate cap."""
    copied: list[dict[str, Any]] = []
    omitted = 0
    total = 0
    if source.exists():
        try:
            source_mode = source.lstat().st_mode
        except OSError:
            return {"state": "UNKNOWN", "files": [], "omitted_count": 0}
        if stat.S_ISLNK(source_mode) or not stat.S_ISDIR(source_mode):
            return {"state": "UNKNOWN", "files": [], "omitted_count": 0}
        try:
            destination.mkdir(mode=0o700, exist_ok=True)
            dest_mode = destination.lstat().st_mode
            if stat.S_ISLNK(dest_mode) or not stat.S_ISDIR(dest_mode):
                return {"state": "UNKNOWN", "files": [], "omitted_count": 0}
        except OSError:
            return {"state": "UNKNOWN", "files": [], "omitted_count": 0}
        for path in sorted(source.iterdir(), key=lambda item: item.name):
            if path.name not in _REHEARSAL_ARTIFACT_NAMES:
                omitted += 1
                continue
            source_fd = None
            dest_fd = None
            dest_identity = None
            try:
                mode = path.lstat().st_mode
                if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
                    omitted += 1
                    continue
                source_fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
                source_stat = os.fstat(source_fd)
                if not stat.S_ISREG(source_stat.st_mode) or source_stat.st_size > MAX_ARTIFACT_BYTES:
                    os.close(source_fd)
                    omitted += 1
                    continue
                size = source_stat.st_size
                if total + size > MAX_ARTIFACT_BYTES:
                    os.close(source_fd)
                    omitted += 1
                    continue
                dest_path = destination / path.name
                if dest_path.exists() or dest_path.is_symlink():
                    os.close(source_fd)
                    omitted += 1
                    continue
                dest_fd = os.open(
                    dest_path,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                    0o600,
                )
                dest_stat = os.fstat(dest_fd)
                dest_identity = (dest_stat.st_dev, dest_stat.st_ino)
                digest = hashlib.sha256()
                remaining = size
                with os.fdopen(source_fd, "rb") as source_stream, os.fdopen(dest_fd, "wb") as dest_stream:
                    source_fd = None
                    dest_fd = None
                    while remaining:
                        block = source_stream.read(min(64 * 1024, remaining))
                        if not block:
                            raise OSError("artifact_short_read")
                        dest_stream.write(block)
                        digest.update(block)
                        remaining -= len(block)
                    if source_stream.read(1):
                        raise OSError("artifact_changed_during_copy")
                total += size
                copied.append({"name": path.name, "size_bytes": size, "sha256": digest.hexdigest()})
            except OSError:
                omitted += 1
                for descriptor in (source_fd, dest_fd):
                    if descriptor is not None:
                        try:
                            os.close(descriptor)
                        except OSError:
                            pass
                try:
                    dest_path = destination / path.name
                    current_stat = dest_path.lstat()
                    if (
                        dest_identity is not None
                        and stat.S_ISREG(current_stat.st_mode)
                        and (current_stat.st_dev, current_stat.st_ino) == dest_identity
                    ):
                        dest_path.unlink()
                except OSError:
                    pass
    state = "NONE" if omitted == 0 and not copied else "COMPLETE" if omitted == 0 else "PARTIAL"
    return {"state": state, "files": copied, "total_bytes": total, "omitted_count": omitted}


def _remove_known_artifacts(path: Path) -> None:
    """Remove only known regular files from a runner-created staging directory."""
    try:
        if stat.S_ISLNK(path.lstat().st_mode) or not path.is_dir():
            return
    except OSError:
        return
    for name in _REHEARSAL_ARTIFACT_NAMES:
        candidate = path / name
        try:
            if stat.S_ISREG(candidate.lstat().st_mode):
                candidate.unlink()
        except OSError:
            continue
    try:
        path.rmdir()
    except OSError:
        pass


def _failure_code(error: RehearsalError) -> str:
    code = str(error).split(":", 1)[0]
    return code if _FAILURE_CODE.fullmatch(code) else "rehearsal_failed"


def _persist_summary(output_dir: Path, summary: dict[str, Any]) -> None:
    encoded = json.dumps(summary, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
    if len(encoded) > 128_000:
        raise RehearsalError("summary_exceeds_limit")
    summary_path = output_dir / "recovery-rehearsal-summary.json"
    fd, temporary_name = tempfile.mkstemp(prefix=".summary-", suffix=".tmp", dir=output_dir)
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary_path, summary_path)
    finally:
        temporary_path.unlink(missing_ok=True)


def _remaining(deadline_at: float, cap: float) -> float:
    value = min(cap, deadline_at - time.monotonic())
    if value <= 0:
        raise RehearsalError("rehearsal_deadline_exceeded")
    return value


def _installed_cli(
    cli_path: Path, source_root: Path, cwd: Path, env: dict[str, str], deadline_at: float
) -> dict[str, str]:
    try:
        cli = cli_path.resolve(strict=True)
    except OSError:
        raise RehearsalError("installed_cli_not_found") from None
    if not cli.is_file() or not os.access(cli, os.X_OK):
        raise RehearsalError("installed_cli_not_executable")
    try:
        first_line = cli.open("rb").readline(512).decode("utf-8").strip()
    except (OSError, UnicodeDecodeError):
        raise RehearsalError("installed_cli_shebang_invalid") from None
    if not first_line.startswith("#!"):
        raise RehearsalError("installed_cli_shebang_invalid")
    interpreter = Path(first_line[2:].split()[0])
    if not interpreter.is_absolute() or not interpreter.is_file() or cli.parent != interpreter.parent.resolve():
        raise RehearsalError("installed_cli_interpreter_mismatch")
    provenance_program = """
import hashlib
import importlib.metadata
import json
from pathlib import Path
import pr_review_harness

package_dir = Path(pr_review_harness.__file__).resolve().parent
files = sorted(package_dir.glob('*.py'))
if len(files) > 128:
    raise SystemExit(2)
inventory = []
total = 0
for path in files:
    data = path.read_bytes()
    total += len(data)
    if len(data) > 2_000_000 or total > 8_000_000:
        raise SystemExit(2)
    inventory.append({'name': path.name, 'size_bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()})
canonical = json.dumps(inventory, sort_keys=True, separators=(',', ':')).encode()
print(json.dumps({
    'module': str(Path(pr_review_harness.__file__).resolve()),
    'version': importlib.metadata.version('pr-review-harness'),
    'source_modules': inventory,
    'source_inventory_sha256': hashlib.sha256(canonical).hexdigest(),
}, sort_keys=True, separators=(',', ':')))
"""
    result = subprocess.run(
        [str(interpreter), "-c", provenance_program],
        cwd=cwd,
        env=env,
        text=True,
        capture_output=True,
        timeout=_remaining(deadline_at, MAX_CLI_SECONDS),
        check=False,
    )
    if result.returncode != 0 or result.stderr or len(result.stdout.encode("utf-8")) > 32_000:
        raise RehearsalError("installed_module_import_failed")
    try:
        provenance = json.loads(result.stdout)
        module_path = Path(provenance["module"]).resolve(strict=True)
    except (KeyError, json.JSONDecodeError, OSError, TypeError, ValueError):
        raise RehearsalError("installed_module_import_failed") from None
    if module_path.is_relative_to(source_root.resolve()):
        raise RehearsalError("installed_module_resolved_to_source_checkout")
    if (
        not isinstance(provenance.get("version"), str)
        or not provenance["version"]
        or not isinstance(provenance.get("source_modules"), list)
        or len(provenance["source_modules"]) > 128
        or not isinstance(provenance.get("source_inventory_sha256"), str)
        or len(provenance["source_inventory_sha256"]) != 64
    ):
        raise RehearsalError("installed_module_provenance_invalid")
    help_result = subprocess.run(
        [str(cli), "--help"],
        cwd=cwd,
        env=env,
        text=True,
        capture_output=True,
        timeout=_remaining(deadline_at, MAX_CLI_SECONDS),
        check=False,
    )
    if help_result.returncode != 0 or "review" not in help_result.stdout or help_result.stderr:
        raise RehearsalError("installed_cli_help_failed")
    return {
        "cli": str(cli),
        "interpreter": str(interpreter),
        "module": str(module_path),
        "version": provenance["version"],
        "source_inventory_sha256": provenance["source_inventory_sha256"],
        "source_modules": provenance["source_modules"],
    }


def _clean_env(
    home: Path,
    *,
    fake_bin: Path | None = None,
    provider_key: bool = False,
    event_repo: bool = False,
    fake_gh_log: Path | None = None,
) -> dict[str, str]:
    path_entries = [str(fake_bin)] if fake_bin else []
    path_entries.extend(os.environ.get("PATH", "").split(os.pathsep))
    env = {
        "PATH": os.pathsep.join(item for item in path_entries if item),
        "HOME": str(home),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PYTHONNOUSERSITE": "1",
    }
    if os.name == "nt":
        for name in ("SYSTEMROOT", "WINDIR", "TEMP", "TMP"):
            if name in os.environ:
                env[name] = os.environ[name]
    if provider_key:
        env["RECOVERY_FAKE_PROVIDER_KEY"] = FAKE_API_KEY
    if event_repo:
        env["GITHUB_REPOSITORY"] = FIXTURE_REPOSITORY
    if fake_gh_log is not None:
        env["RECOVERY_FAKE_GH_LOG"] = str(fake_gh_log)
    return env


def _run_cli(
    cli: Path,
    argv: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    timeout_seconds: float = MAX_CLI_SECONDS,
    expected_exit: int = 0,
    deadline_at: float,
) -> dict[str, Any]:
    if timeout_seconds <= 0 or timeout_seconds > MAX_CLI_SECONDS:
        raise RehearsalError("cli_timeout_out_of_bounds")
    invocation_deadline = min(deadline_at, time.monotonic() + timeout_seconds)

    def invocation_remaining() -> float:
        now = time.monotonic()
        if now >= deadline_at:
            raise RehearsalError("rehearsal_deadline_exceeded")
        if now >= invocation_deadline:
            raise RehearsalError("cli_deadline_exceeded")
        return invocation_deadline - now

    process = None
    stdout = bytearray()
    stderr = bytearray()
    try:
        invocation_remaining()
        process = subprocess.Popen(
            [str(cli), *argv],
            cwd=cwd,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=(os.name == "posix"),
        )
        assert process.stdout is not None and process.stderr is not None
        buffers = {process.stdout.fileno(): stdout, process.stderr.fileno(): stderr}
        with selectors.DefaultSelector() as selector:
            for stream in (process.stdout, process.stderr):
                selector.register(stream, selectors.EVENT_READ)
            while selector.get_map():
                remaining = invocation_remaining()
                events = selector.select(min(remaining, 0.25))
                if not events and process.poll() is None:
                    continue
                for key, _mask in events:
                    block = os.read(key.fd, min(32_768, MAX_CLI_OUTPUT_BYTES + 1))
                    if not block:
                        selector.unregister(key.fileobj)
                        continue
                    target = buffers[key.fd]
                    target.extend(block)
                    if len(target) > MAX_CLI_OUTPUT_BYTES:
                        _terminate_group(process)
                        raise RehearsalError("cli_output_exceeds_limit")
        returncode = process.wait(timeout=invocation_remaining())
    except RehearsalError:
        if process is not None:
            _terminate_group(process)
        raise
    except subprocess.TimeoutExpired:
        if process is not None:
            _terminate_group(process)
        raise RehearsalError("cli_deadline_exceeded") from None
    except OSError:
        if process is not None:
            _terminate_group(process)
        raise RehearsalError("cli_invocation_failed") from None
    try:
        stdout_text = stdout.decode("utf-8")
        stderr_text = stderr.decode("utf-8")
    except UnicodeDecodeError:
        raise RehearsalError("cli_output_invalid_utf8") from None
    if returncode != expected_exit:
        raise RehearsalError("cli_exit_mismatch")
    if stderr_text:
        raise RehearsalError("cli_stderr_not_empty")
    try:
        value = json.loads(stdout_text)
    except json.JSONDecodeError:
        raise RehearsalError("cli_json_output_invalid") from None
    if not isinstance(value, dict):
        raise RehearsalError("cli_json_output_invalid")
    return value


def _terminate_group(process: subprocess.Popen[bytes]) -> None:
    if os.name == "posix":
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=0.2)
        except subprocess.TimeoutExpired:
            pass
        # A child may outlive the CLI parent while keeping stdout/stderr open.
        # Escalate against the isolated group even when the group leader exited.
        time.sleep(0.05)
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=0.5)
        except subprocess.TimeoutExpired:
            raise RehearsalError("owned_process_group_not_stopped") from None
    else:
        if process.poll() is not None:
            return
        process.terminate()
        try:
            process.wait(timeout=0.5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=0.5)


def _limits() -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "deadline_seconds": ENGINE_DEADLINE_SECONDS,
        "max_concurrent_scopes": 1,
        "max_provider_calls": 2,
        "max_retries_per_task": 0,
        "max_context_bytes": 32_000,
        "max_input_bytes_per_task": 32_000,
        "max_output_bytes_per_task": 8_000,
        "max_output_bytes": 16_000,
        "max_output_tokens": 256,
        "max_context_retrievals": 0,
        "max_followup_tasks": 0,
    }


def _write_fixture(root: Path, endpoint: str, deadline_at: float) -> tuple[Path, str, str, Path, Path, Path]:
    repo = root / "fixture.git"
    _git(["init", str(repo)], cwd=root, deadline_at=deadline_at)
    _git(["-C", str(repo), "config", "user.name", "Recovery Rehearsal"], cwd=root, deadline_at=deadline_at)
    _git(["-C", str(repo), "config", "user.email", "recovery@example.invalid"], cwd=root, deadline_at=deadline_at)
    source = repo / "sample.py"
    source.write_text("VALUE = 1\n", encoding="utf-8")
    _git(["-C", str(repo), "add", "sample.py"], cwd=root, deadline_at=deadline_at)
    _git(["-C", str(repo), "-c", "core.hooksPath=/dev/null", "commit", "-m", "base"], cwd=root, deadline_at=deadline_at)
    base = _git(["-C", str(repo), "rev-parse", "HEAD"], cwd=root, deadline_at=deadline_at)
    source.write_text("VALUE = 2\n", encoding="utf-8")
    _git(["-C", str(repo), "add", "sample.py"], cwd=root, deadline_at=deadline_at)
    _git(["-C", str(repo), "-c", "core.hooksPath=/dev/null", "commit", "-m", "head"], cwd=root, deadline_at=deadline_at)
    head = _git(["-C", str(repo), "rev-parse", "HEAD"], cwd=root, deadline_at=deadline_at)
    profile_path = root / "trusted-profile.json"
    profile_path.write_text(
        json.dumps(
            {
                "version": "recovery-rehearsal-profile-v1",
                "repository": FIXTURE_REPOSITORY,
                "allow_empty_approve": True,
                "required_lenses": ["correctness", "security"],
                "context_paths": [],
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    limits_path = root / "finite-limits.json"
    limits_path.write_text(json.dumps(_limits(), sort_keys=True) + "\n", encoding="utf-8")
    provider_config = root / "local-provider.json"
    provider_config.write_text(
        json.dumps(
            {
                "kind": "openai_compatible",
                "base_url": endpoint,
                "model": "local-rehearsal-model",
                "api_key_env": "RECOVERY_FAKE_PROVIDER_KEY",
                "timeout_seconds": PROVIDER_TIMEOUT_SECONDS,
                "max_request_bytes": 32_000,
                "max_response_bytes": 8_000,
                "max_output_tokens": 256,
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return repo, base, head, profile_path, limits_path, provider_config


def _git(argv: list[str], *, cwd: Path, deadline_at: float) -> str:
    try:
        result = subprocess.run(
            ["git", *argv],
            cwd=cwd,
            env={"PATH": os.environ.get("PATH", ""), "HOME": str(cwd), "GIT_CONFIG_NOSYSTEM": "1"},
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=_remaining(deadline_at, 5),
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise RehearsalError("fixture_git_failed") from None
    if result.returncode or len(result.stdout.encode("utf-8")) > 4096:
        raise RehearsalError("fixture_git_failed")
    return result.stdout.strip()


def _cli_args(
    repo: Path,
    base: str,
    head: str,
    profile: Path,
    limits: Path,
    provider_config: Path,
    output: Path,
    run_id: str,
    *,
    resume: bool = False,
    event_file: Path | None = None,
) -> list[str]:
    args = [
        "review",
        "--repo",
        str(repo),
        "--base",
        base,
        "--head",
        head,
        "--profile",
        str(profile),
        "--limits",
        str(limits),
        "--provider-config",
        str(provider_config),
        "--output",
        str(output),
        "--run-id",
        run_id,
        "--json",
    ]
    if resume:
        args.append("--resume")
    if event_file is not None:
        args.extend(["--event-file", str(event_file)])
    return args


def _summary_row(name: str, result_path: Path, result: dict[str, Any] | None, *, status: str) -> dict[str, Any]:
    row: dict[str, Any] = {"scenario": name, "status": status}
    if result is not None:
        task_results = result.get("task_results", {})
        task_outcomes = []
        if isinstance(task_results, dict):
            for task_id, value in sorted(task_results.items()):
                if not isinstance(value, dict):
                    continue
                task_status = value.get("status")
                outcome = {
                    "task_id": str(task_id)[:160],
                    "status": task_status
                    if isinstance(task_status, str) and task_status in {"SUCCEEDED", "FAILED", "INVALID", "TIMED_OUT"}
                    else "UNKNOWN",
                }
                error_code = value.get("error_code")
                if (
                    isinstance(error_code, str)
                    and 1 <= len(error_code) <= 100
                    and (
                        error_code in {"DEADLINE_EXCEEDED", "INTERRUPTED_UNKNOWN"}
                        or all(
                            char.isascii() and (char.islower() or char.isdigit() or char == "_") for char in error_code
                        )
                    )
                ):
                    outcome["error_code"] = error_code
                task_outcomes.append(outcome)
        budget = result.get("budget", {})
        ledger = result.get("ledger", {})
        ledger_budget = ledger.get("budget", {}) if isinstance(ledger, dict) else {}
        settlements = ledger_budget.get("settlements", {}) if isinstance(ledger_budget, dict) else {}
        settlement_statuses = (
            sorted(
                {
                    item.get("status")
                    for item in settlements.values()
                    if isinstance(item, dict)
                    and isinstance(item.get("status"), str)
                    and item.get("status") in {"SUCCEEDED", "FAILED", "TIMED_OUT", "INTERRUPTED_UNKNOWN", "UNKNOWN"}
                }
            )
            if isinstance(settlements, dict)
            else []
        )
        reservation_settlements = (
            [
                {"reservation_key": str(key)[:200], "status": item["status"]}
                for key, item in sorted(settlements.items())
                if isinstance(item, dict)
                and isinstance(item.get("status"), str)
                and item.get("status") in {"SUCCEEDED", "FAILED", "TIMED_OUT", "INTERRUPTED_UNKNOWN", "UNKNOWN"}
            ]
            if isinstance(settlements, dict)
            else []
        )
        row.update(
            {
                "disposition": result.get("disposition"),
                "coverage_state": result.get("coverage_state"),
                "freshness": result.get("freshness"),
                "provider_calls_reserved": budget.get("provider_calls_reserved") if isinstance(budget, dict) else None,
                "task_outcomes": task_outcomes,
                "settlement_statuses": settlement_statuses,
                "reservation_settlements": reservation_settlements,
                "result_sha256": _hash_file(result_path) if result_path.is_file() else None,
            }
        )
    return row


def _write_fake_gh(fake_bin: Path, mode: str, base: str, head: str, log_path: Path) -> None:
    fake_bin.mkdir(parents=True, exist_ok=True)
    path = fake_bin / "gh"
    script = f"""#!/usr/bin/env python3
import json, sys
args = sys.argv[1:]
endpoint = args[1] if len(args) > 1 and args[0] == "api" else ""
with open({str(log_path)!r}, "a", encoding="utf-8") as log:
    log.write("check-runs\\n" if "/check-runs?" in endpoint else "freshness\\n" if "/pulls/" in endpoint else "unknown\\n")
if "/check-runs?" in endpoint:
    print(json.dumps({{"total_count": 0, "check_runs": []}}))
elif endpoint.endswith("/pulls/{FIXTURE_PR}"):
    if {mode!r} == "UNKNOWN":
        raise SystemExit(1)
    print(json.dumps({{"number": {FIXTURE_PR}, "base": {{"sha": {base!r}, "repo": {{"full_name": {FIXTURE_REPOSITORY!r}, "html_url": "https://github.com/{FIXTURE_REPOSITORY}"}}}}, "head": {{"sha": {("0" * 40 if mode == "STALE" else head)!r}}}}}))
else:
    raise SystemExit(1)
"""
    path.write_text(script, encoding="utf-8")
    path.chmod(0o700)


def _event_file(root: Path, base: str, head: str) -> Path:
    path = root / "pull-request-event.json"
    path.write_text(
        json.dumps(
            {
                "number": FIXTURE_PR,
                "pull_request": {"base": {"sha": base}, "head": {"sha": head}},
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return path


def _run_rehearsal_body(
    cli_path: Path,
    output_dir: Path,
    source_root: Path,
    context: dict[str, Any],
    started: float,
) -> dict[str, Any]:
    try:
        with tempfile.TemporaryDirectory(prefix="pr-review-recovery-") as temporary:
            root = Path(temporary).resolve()
            home = root / "home"
            home.mkdir()
            clean_env = _clean_env(home)
            deadline_at = started + MAX_REHEARSAL_SECONDS - CLEANUP_GRACE_SECONDS
            installed = _installed_cli(cli_path, source_root, root, clean_env, deadline_at)
            context["installed_runtime"] = installed
            state = _FakeProviderState()
            context["provider_state"] = state
            try:
                server = _FakeProvider(state)
            except OSError:
                raise RehearsalError("loopback_fake_provider_unavailable") from None
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            context["provider_started"] = True
            rows = context["scenarios"]
            try:
                repo, base, head, profile, limits, provider_config = _write_fixture(root, server.endpoint, deadline_at)
                output = context["artifact_source"]
                context["fixture"] = {
                    "base_sha": base,
                    "head_sha": head,
                    "profile_sha256": _hash_file(profile),
                }
                provider_env = _clean_env(home, provider_key=True)

                # Provider failure is terminally represented as incomplete, with one reserved call.
                context["active_scenario"] = "provider_failure"
                state.configure(["http_503", "success"])
                failed_id = "recovery-http-failure"
                _run_cli(
                    Path(installed["cli"]),
                    _cli_args(repo, base, head, profile, limits, provider_config, output, failed_id),
                    cwd=root,
                    env=provider_env,
                    deadline_at=deadline_at,
                )
                fail_artifact = output / f"{failed_id}.json"
                fail_result = json.loads(fail_artifact.read_text(encoding="utf-8"))
                if fail_result.get("disposition") != "INCOMPLETE":
                    raise RehearsalError("provider_failure_not_incomplete")
                fail_outcomes = _summary_row("provider_failure", fail_artifact, fail_result, status="observed")[
                    "task_outcomes"
                ]
                if not any(
                    item.get("status") == "FAILED" and item.get("error_code") == "http_status_503"
                    for item in fail_outcomes
                ):
                    raise RehearsalError("provider_failure_outcome_missing")
                rows.append(
                    {
                        **_summary_row("provider_failure", fail_artifact, fail_result, status="observed"),
                        "fake_request_log": state.calls,
                    }
                )

                # Provider-level timeout must return before the CLI subprocess deadline.
                context["active_scenario"] = "provider_timeout"
                state.configure(["stall", "success"])
                timeout_id = "recovery-provider-timeout"
                _run_cli(
                    Path(installed["cli"]),
                    _cli_args(repo, base, head, profile, limits, provider_config, output, timeout_id),
                    cwd=root,
                    env=provider_env,
                    deadline_at=deadline_at,
                )
                timeout_artifact = output / f"{timeout_id}.json"
                timeout_review = json.loads(timeout_artifact.read_text(encoding="utf-8"))
                if timeout_review.get("disposition") != "INCOMPLETE":
                    raise RehearsalError("provider_timeout_not_incomplete")
                timeout_outcomes = _summary_row(
                    "provider_timeout", timeout_artifact, timeout_review, status="observed"
                )["task_outcomes"]
                if not any(
                    item.get("status") == "TIMED_OUT" and item.get("error_code") == "DEADLINE_EXCEEDED"
                    for item in timeout_outcomes
                ):
                    observed = json.dumps(timeout_outcomes, sort_keys=True, separators=(",", ":"))
                    raise RehearsalError(f"provider_timeout_outcome_missing:{observed[:1000]}")
                rows.append(
                    {
                        **_summary_row("provider_timeout", timeout_artifact, timeout_review, status="observed"),
                        "fake_request_log": state.calls,
                    }
                )

                # Let one task checkpoint, stall the next, and kill only this process group.
                context["active_scenario"] = "interruption_and_resume"
                state.configure(["success", "stall"])
                interrupted_id = "recovery-interrupted"
                command = [
                    str(installed["cli"]),
                    *_cli_args(repo, base, head, profile, limits, provider_config, output, interrupted_id),
                ]
                try:
                    process = subprocess.Popen(
                        command,
                        cwd=root,
                        env=provider_env,
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        start_new_session=(os.name == "posix"),
                    )
                except OSError:
                    raise RehearsalError("interrupt_cli_start_failed") from None
                deadline = _remaining(deadline_at, MAX_CLI_SECONDS) + time.monotonic()
                saw_two_calls = False
                while process.poll() is None and time.monotonic() < deadline:
                    if state.wait_for_calls(2, min(0.05, max(0.0, deadline_at - time.monotonic()))):
                        saw_two_calls = True
                        break
                killed = process.poll() is None and saw_two_calls
                if killed:
                    _terminate_group(process)
                else:
                    _terminate_group(process)
                partial_path = output / f"{interrupted_id}.json"
                if not partial_path.is_file():
                    raise RehearsalError("interrupted_checkpoint_missing")
                partial = json.loads(partial_path.read_text(encoding="utf-8"))
                reservations = partial.get("ledger", {}).get("budget", {}).get("reservations", {})
                settlements = partial.get("ledger", {}).get("budget", {}).get("settlements", {})
                interrupted_reservations = [key for key in reservations if key not in settlements]
                interrupted_request_log = state.calls
                if not killed or len(interrupted_request_log) != 2 or not interrupted_reservations:
                    raise RehearsalError("interrupted_checkpoint_not_proven")

                # Drift is rejected before another provider request; restore the exact profile to resume.
                original_profile = profile.read_bytes()
                changed_profile = json.loads(original_profile)
                changed_profile["review_criteria"] = {"correctness": "changed trusted profile"}
                profile.write_text(json.dumps(changed_profile, sort_keys=True) + "\n", encoding="utf-8")
                drift = _run_cli(
                    Path(installed["cli"]),
                    _cli_args(repo, base, head, profile, limits, provider_config, output, interrupted_id, resume=True),
                    cwd=root,
                    env=provider_env,
                    expected_exit=2,
                    deadline_at=deadline_at,
                )
                if not str(drift.get("error", "")).startswith("preflight_rejected"):
                    raise RehearsalError("profile_drift_not_rejected")
                if len(state.calls) != 2:
                    raise RehearsalError("profile_drift_dispatched_provider")
                profile.write_bytes(original_profile)
                state.configure(["success", "success"])
                resume_call_count = len(state.calls)
                resumed = _run_cli(
                    Path(installed["cli"]),
                    _cli_args(repo, base, head, profile, limits, provider_config, output, interrupted_id, resume=True),
                    cwd=root,
                    env=provider_env,
                    deadline_at=deadline_at,
                )
                final_interrupted = json.loads(partial_path.read_text(encoding="utf-8"))
                if resumed.get("disposition") != "INCOMPLETE" or final_interrupted.get("disposition") != "INCOMPLETE":
                    raise RehearsalError("interrupted_scope_not_retained_incomplete")
                final_row = _summary_row(
                    "resume_after_interrupted_call",
                    partial_path,
                    final_interrupted,
                    status="observed",
                )
                outcomes = final_row["task_outcomes"]
                if sorted(item["status"] for item in outcomes) != ["FAILED", "SUCCEEDED"]:
                    raise RehearsalError("interrupted_completed_task_not_retained")
                if not any(
                    item.get("status") == "FAILED" and item.get("error_code") == "INTERRUPTED_UNKNOWN"
                    for item in outcomes
                ):
                    raise RehearsalError("interrupted_task_unknown_outcome_missing")
                if sorted(item["status"] for item in final_row["reservation_settlements"]) != [
                    "INTERRUPTED_UNKNOWN",
                    "SUCCEEDED",
                ]:
                    raise RehearsalError("interrupted_reservation_settlement_missing")
                final_row["additional_provider_calls_after_resume"] = len(state.calls) - resume_call_count
                if len(state.calls) != resume_call_count:
                    raise RehearsalError("uncertain_provider_call_was_replayed")
                final_row["interrupted_fake_request_log"] = interrupted_request_log
                rows.append(final_row)
                rows.append(
                    {
                        "scenario": "profile_drift",
                        "status": "rejected_before_dispatch",
                        "error_code": "preflight_rejected",
                    }
                )

                # A terminal historical run can be safely re-opened; it makes no current GitHub claim.
                context["active_scenario"] = "historical_freshness"
                state.configure(["success", "success"])
                historical_id = "recovery-historical"
                _run_cli(
                    Path(installed["cli"]),
                    _cli_args(repo, base, head, profile, limits, provider_config, output, historical_id),
                    cwd=root,
                    env=provider_env,
                    deadline_at=deadline_at,
                )
                historical_artifact = output / f"{historical_id}.json"
                historical_review = json.loads(historical_artifact.read_text(encoding="utf-8"))
                if historical_review.get("freshness_details", {}).get("freshness_basis") != "HISTORICAL_SNAPSHOT":
                    raise RehearsalError("historical_freshness_basis_missing")
                rows.append(
                    {
                        **_summary_row(
                            "historical_freshness", historical_artifact, historical_review, status="observed"
                        ),
                        "fake_request_log": state.calls,
                    }
                )

                # Event-mode stale and unavailable reads are synthetic local gh results only.
                event = _event_file(root, base, head)
                for mode, expected_freshness in (("STALE", "STALE"), ("UNKNOWN", "UNKNOWN")):
                    context["active_scenario"] = f"freshness_{mode.lower()}"
                    fake_bin = root / f"fake-gh-{mode.lower()}"
                    gh_log = root / f"fake-gh-{mode.lower()}.log"
                    _write_fake_gh(fake_bin, mode, base, head, gh_log)
                    gh_env = _clean_env(
                        home,
                        fake_bin=fake_bin,
                        provider_key=True,
                        event_repo=True,
                        fake_gh_log=gh_log,
                    )
                    run_id = f"recovery-freshness-{mode.lower()}"
                    state.configure(["success", "success"])
                    _run_cli(
                        Path(installed["cli"]),
                        _cli_args(repo, base, head, profile, limits, provider_config, output, run_id, event_file=event),
                        cwd=root,
                        env=gh_env,
                        deadline_at=deadline_at,
                    )
                    artifact = output / f"{run_id}.json"
                    reviewed = json.loads(artifact.read_text(encoding="utf-8"))
                    if reviewed.get("freshness") != expected_freshness or reviewed.get("disposition") != "INCOMPLETE":
                        raise RehearsalError("freshness_fail_closed_behavior_missing")
                    rows.append(
                        {
                            **_summary_row(f"freshness_{mode.lower()}", artifact, reviewed, status="observed"),
                            "fake_request_log": state.calls,
                            "fake_gh_log": gh_log.read_text(encoding="utf-8").splitlines(),
                        }
                    )

                if time.monotonic() - started > MAX_REHEARSAL_SECONDS:
                    raise RehearsalError("rehearsal_deadline_exceeded")
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=min(1, CLEANUP_GRACE_SECONDS))
            summary = {
                "schema_version": "recovery-rehearsal.v1",
                "status": "completed",
                "provider_mode": "local_loopback_fake_only",
                "github_mode": "local_gh_shim_only",
                "target_execution": False,
                "freshness_claim_for_historical_case": "HISTORICAL_SNAPSHOT",
                "limits": {
                    "engine_deadline_seconds": ENGINE_DEADLINE_SECONDS,
                    "provider_timeout_seconds": PROVIDER_TIMEOUT_SECONDS,
                    "per_cli_timeout_seconds": MAX_CLI_SECONDS,
                    "overall_timeout_seconds": MAX_REHEARSAL_SECONDS,
                    "scenario_work_deadline_seconds": MAX_REHEARSAL_SECONDS - CLEANUP_GRACE_SECONDS,
                    "cleanup_grace_seconds": CLEANUP_GRACE_SECONDS,
                    "cli_output_bytes": MAX_CLI_OUTPUT_BYTES,
                    "artifact_bytes": MAX_ARTIFACT_BYTES,
                },
                "installed_runtime": installed,
                "fixture": {"base_sha": base, "head_sha": head, "profile_sha256": _hash_file(profile)},
                "provider_request_log": state.all_calls,
                "scenarios": rows,
                "elapsed_seconds": round(time.monotonic() - started, 3),
            }
            context["active_scenario"] = None
            return summary
    except json.JSONDecodeError:
        raise RehearsalError("result_artifact_json_invalid") from None
    except OSError:
        raise RehearsalError("rehearsal_io_failed") from None
    except ValueError:
        raise RehearsalError("rehearsal_value_invalid") from None


def run_rehearsal(cli_path: Path, output_dir: Path, *, source_root: Path) -> dict[str, Any]:
    started = time.monotonic()
    output_dir = output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    if any(output_dir.iterdir()):
        raise RehearsalError("output_directory_not_empty")

    context: dict[str, Any] = {
        "active_scenario": "setup",
        "scenarios": [],
        "installed_runtime": None,
        "provider_state": None,
        "provider_started": False,
        "fixture": None,
        "artifact_source": output_dir / ".working-artifacts",
    }
    try:
        source_root = source_root.resolve(strict=True)
        context["artifact_source"].mkdir(mode=0o700)
        summary = _run_rehearsal_body(cli_path, output_dir, source_root, context, started)
        artifact_summary = _collect_artifacts(context["artifact_source"], output_dir / "artifacts")
        context["artifact_summary"] = artifact_summary
        _remove_known_artifacts(context["artifact_source"])
        if artifact_summary["state"] != "COMPLETE":
            raise RehearsalError("artifact_retention_incomplete")
        summary["artifacts"] = artifact_summary
        _persist_summary(output_dir, summary)
        return summary
    except RehearsalError as exc:
        failure_code = _failure_code(exc)
    except (json.JSONDecodeError, UnicodeDecodeError):
        failure_code = "result_artifact_invalid"
    except OSError:
        failure_code = "rehearsal_io_failed"
    except Exception:
        failure_code = "rehearsal_unexpected_failure"

    if "artifact_summary" not in context:
        context["artifact_summary"] = _collect_artifacts(context["artifact_source"], output_dir / "artifacts")
    _remove_known_artifacts(context["artifact_source"])
    state = context.get("provider_state")
    provider_calls = state.all_calls if isinstance(state, _FakeProviderState) else []
    summary = {
        "schema_version": "recovery-rehearsal.v1",
        "status": "failed",
        "failure_reason_code": failure_code,
        "active_scenario": context.get("active_scenario") or "unknown",
        "active_scenario_outcome": "UNKNOWN",
        "provider_mode": "local_loopback_fake_only" if context.get("provider_started") else "NOT_STARTED",
        "github_mode": "local_gh_shim_only",
        "target_execution": False,
        "installed_runtime": context.get("installed_runtime"),
        "fixture": context.get("fixture"),
        "provider_request_log": provider_calls,
        "scenarios": context["scenarios"],
        "artifacts": context["artifact_summary"],
        "limits": {
            "overall_timeout_seconds": MAX_REHEARSAL_SECONDS,
            "scenario_work_deadline_seconds": MAX_REHEARSAL_SECONDS - CLEANUP_GRACE_SECONDS,
            "cleanup_grace_seconds": CLEANUP_GRACE_SECONDS,
            "artifact_bytes": MAX_ARTIFACT_BYTES,
        },
        "elapsed_seconds": round(time.monotonic() - started, 3),
    }
    try:
        _persist_summary(output_dir, summary)
    except (OSError, RehearsalError):
        return {
            "schema_version": "recovery-rehearsal.v1",
            "status": "failed",
            "failure_reason_code": "failure_summary_write_failed",
        }
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cli", required=True, type=Path, help="installed pr-review executable from its venv")
    parser.add_argument("--output-dir", required=True, type=Path, help="directory for bounded local artifacts")
    parser.add_argument("--source-root", type=Path, default=Path(__file__).resolve().parents[1], help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    try:
        summary = run_rehearsal(args.cli, args.output_dir, source_root=args.source_root)
    except RehearsalError as exc:
        print(json.dumps({"status": "failed", "error": str(exc)}, sort_keys=True, separators=(",", ":")))
        return 1
    print(json.dumps(summary, sort_keys=True, separators=(",", ":")))
    return 0 if summary.get("status") == "completed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
