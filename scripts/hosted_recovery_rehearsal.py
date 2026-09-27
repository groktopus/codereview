#!/usr/bin/env python3
"""Run one side of the bounded, secretless hosted cancellation recovery drill.

This command uses only a synthetic Git fixture and a loopback fake provider.
It never reads target repository code or real credentials.
"""

from __future__ import annotations

import argparse
import hashlib
import http.server
import json
import os
import re
import selectors
import shutil
import signal
import socketserver
import subprocess
import sys
import threading
import time
import traceback
import zipfile
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
import run_recovery_rehearsal as local  # noqa: E402

MAX_BYTES = 7_900_000
MAX_FILE_BYTES = 6_000_000
MAX_FILES = 8
RUN_ID = "hosted-cancel-recovery-v1"
PROVIDER_PORT = 18765
API_KEY = "hosted-recovery-fake-only"
MODEL = "hosted-recovery-fake-model-v1"
WHEEL_NAME = "pr_review_harness-0.1.0-py3-none-any.whl"
CANONICAL_REPOSITORY = "groktopus/codereview"
WORKFLOW_PATH = ".github/workflows/hosted-recovery-rehearsal.yml"
MAX_COMMAND_OUTPUT_BYTES = 65_536
MAX_ARCHIVE_SECONDS = 150
_PHASE_DEADLINE: float | None = None
NAMES = frozenset(
    {"manifest.json", "checkpoint.json", "fixture.bundle", "provider-ledger.json", WHEEL_NAME, "readiness.json"}
)
IDENTITY = {
    "repository": "owner/project",
    "pull_request": 7,
    "provider": "loopback-fake-v1",
    "model": MODEL,
    "mode": "AUTO",
}


class DrillError(RuntimeError):
    pass


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(65536):
            h.update(chunk)
    return h.hexdigest()


def canonical(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode()


def _regular_file(path: Path, *, limit: int = MAX_FILE_BYTES) -> int:
    info = path.lstat()
    if path.is_symlink() or not path.is_file() or info.st_size < 0 or info.st_size > limit:
        raise DrillError("artifact_file_type_or_size_invalid")
    return info.st_size


def validate_stage(stage: Path, *, require_manifest: bool = True) -> dict[str, Any]:
    """Validate the exact transfer allowlist, regular-file types, hashes and caps."""
    if stage.is_symlink() or not stage.is_dir():
        raise DrillError("artifact_directory_invalid")
    entries = list(stage.iterdir())
    if len(entries) > MAX_FILES or {path.name for path in entries} - NAMES:
        raise DrillError("artifact_allowlist_invalid")
    sizes = {path.name: _regular_file(path) for path in entries}
    if sum(sizes.values()) > MAX_BYTES:
        raise DrillError("artifact_total_size_exceeded")
    if require_manifest and "manifest.json" not in sizes:
        raise DrillError("artifact_manifest_missing")
    if "manifest.json" not in sizes:
        return {"sizes": sizes, "total_bytes": sum(sizes.values())}
    try:
        manifest = json.loads((stage / "manifest.json").read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        raise DrillError("artifact_manifest_invalid") from None
    if not isinstance(manifest, dict) or manifest.get("schema_version") != "hosted-recovery.v1":
        raise DrillError("artifact_manifest_invalid")
    expected = manifest.get("files")
    if not isinstance(expected, dict) or set(expected) != set(sizes) - {"manifest.json"}:
        raise DrillError("artifact_file_inventory_mismatch")
    for name, sha in expected.items():
        if not isinstance(sha, str) or digest(stage / name) != sha:
            raise DrillError("artifact_digest_mismatch")
    return {"manifest": manifest, "sizes": sizes, "total_bytes": sum(sizes.values())}


def source_inventory(root: Path) -> dict[str, str]:
    package = root / "src" / "pr_review_harness"
    return {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(package.glob("*.py"))
        if path.is_file() and not path.is_symlink()
    }


def _effective_deadline(timeout: float) -> float:
    deadline = time.monotonic() + timeout
    return min(deadline, _PHASE_DEADLINE) if _PHASE_DEADLINE is not None else deadline


def _terminate(proc: subprocess.Popen[bytes]) -> None:
    if proc.poll() is None:
        if os.name == "posix":
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        else:
            proc.kill()
    try:
        proc.wait(timeout=1)
    except subprocess.TimeoutExpired:
        pass


def _run(argv: list[str], *, cwd: Path, env: dict[str, str], timeout: float,
         output_limit: int = MAX_COMMAND_OUTPUT_BYTES) -> str:
    """Run with a shared wall deadline and bounded stdout memory."""
    deadline = _effective_deadline(timeout)
    output = bytearray()
    proc: subprocess.Popen[bytes] | None = None
    try:
        proc = subprocess.Popen(
            argv,
            cwd=cwd,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            start_new_session=(os.name == "posix"),
        )
        assert proc.stdout is not None
        with selectors.DefaultSelector() as selector:
            selector.register(proc.stdout, selectors.EVENT_READ)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise DrillError("command_deadline_exceeded")
                events = selector.select(min(remaining, 0.25))
                for key, _ in events:
                    chunk = os.read(key.fd, min(16_384, output_limit + 1))
                    if not chunk:
                        selector.unregister(key.fileobj)
                    else:
                        output.extend(chunk)
                        if len(output) > output_limit:
                            raise DrillError("command_output_limit_exceeded")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise DrillError("command_deadline_exceeded")
        code = proc.wait(timeout=remaining)
    except DrillError:
        if proc is not None:
            _terminate(proc)
        raise
    except (OSError, subprocess.TimeoutExpired):
        if proc is not None:
            _terminate(proc)
        raise DrillError("bounded_command_failed") from None
    if code:
        raise DrillError("bounded_command_failed")
    try:
        return output.decode("utf-8").strip()
    except UnicodeDecodeError:
        raise DrillError("bounded_command_output_invalid") from None


def _run_to_file(argv: list[str], *, cwd: Path, env: dict[str, str], timeout: float, destination: Path,
                 byte_limit: int) -> int:
    """Stream a bounded binary response to a new file without buffering it."""
    deadline = _effective_deadline(timeout)
    if destination.exists() or destination.is_symlink():
        raise DrillError("download_destination_exists")
    proc: subprocess.Popen[bytes] | None = None
    total = 0
    try:
        proc = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                start_new_session=(os.name == "posix"))
        assert proc.stdout is not None
        with destination.open("xb") as stream, selectors.DefaultSelector() as selector:
            selector.register(proc.stdout, selectors.EVENT_READ)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise DrillError("archive_download_deadline_exceeded")
                for key, _ in selector.select(min(remaining, 0.25)):
                    chunk = os.read(key.fd, 65_536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    total += len(chunk)
                    if total > byte_limit:
                        raise DrillError("archive_download_size_exceeded")
                    stream.write(chunk)
            stream.flush()
        remaining = deadline - time.monotonic()
        if remaining <= 0 or proc.wait(timeout=remaining):
            raise DrillError("archive_download_failed")
        return total
    except DrillError:
        if proc is not None:
            _terminate(proc)
        destination.unlink(missing_ok=True)
        raise
    except (OSError, subprocess.TimeoutExpired):
        if proc is not None:
            _terminate(proc)
        destination.unlink(missing_ok=True)
        raise DrillError("archive_download_failed") from None


def _extract_allowlisted_archive(archive: Path, destination: Path) -> None:
    if archive.is_symlink() or _regular_file(archive, limit=MAX_BYTES) > MAX_BYTES:
        raise DrillError("archive_file_invalid")
    try:
        with zipfile.ZipFile(archive) as bundle:
            entries = bundle.infolist()
            names = [item.filename for item in entries]
            if len(entries) > MAX_FILES or len(set(names)) != len(names) or set(names) - NAMES:
                raise DrillError("archive_inventory_invalid")
            if any("/" in name or "\\" in name or name in {".", ".."} for name in names):
                raise DrillError("archive_path_invalid")
            if any((item.external_attr >> 16) & 0o170000 == 0o120000 for item in entries):
                raise DrillError("archive_symlink_rejected")
            total = 0
            for item in entries:
                if item.is_dir() or item.file_size > MAX_FILE_BYTES:
                    raise DrillError("archive_entry_size_or_type_invalid")
                total += item.file_size
                if total > MAX_BYTES:
                    raise DrillError("artifact_total_size_exceeded")
            for item in entries:
                target = destination / item.filename
                count = 0
                with bundle.open(item) as source, target.open("xb") as output:
                    while chunk := source.read(65_536):
                        count += len(chunk)
                        if count > item.file_size or count > MAX_FILE_BYTES:
                            raise DrillError("archive_expansion_limit_exceeded")
                        output.write(chunk)
                if count != item.file_size:
                    raise DrillError("archive_entry_length_mismatch")
    except zipfile.BadZipFile:
        raise DrillError("artifact_archive_invalid") from None


def _download_canceled_run_artifact(source_run_id: str, expected_sha: str, destination: Path,
                                    *, repository: str, token: str) -> dict[str, Any]:
    """Authenticate the run metadata, then cap the archive before safe extraction."""
    if repository != CANONICAL_REPOSITORY or not re.fullmatch(r"[0-9]{1,20}", source_run_id):
        raise DrillError("source_run_identity_invalid")
    if not re.fullmatch(r"[0-9a-f]{40}", expected_sha) or not token:
        raise DrillError("source_run_identity_invalid")
    destination.mkdir(mode=0o700, parents=True)
    if list(destination.iterdir()):
        raise DrillError("download_directory_not_empty")
    env = {"PATH": os.environ.get("PATH", ""), "HOME": os.environ.get("HOME", "/tmp"), "GH_TOKEN": token}
    prefix = f"repos/{CANONICAL_REPOSITORY}"
    run_doc = json.loads(_run(["gh", "api", f"{prefix}/actions/runs/{source_run_id}"], cwd=destination, env=env,
                              timeout=30, output_limit=256_000))
    repo_info = run_doc.get("repository", {})
    path = run_doc.get("path", "")
    if (
        str(run_doc.get("id")) != source_run_id
        or repo_info.get("full_name", "").lower() != CANONICAL_REPOSITORY
        or run_doc.get("event") != "workflow_dispatch"
        or run_doc.get("status") != "completed"
        or run_doc.get("conclusion") != "cancelled"
        or run_doc.get("head_branch") != "main"
        or run_doc.get("head_sha") != expected_sha
        or path not in {
            WORKFLOW_PATH,
            WORKFLOW_PATH + "@main",
            WORKFLOW_PATH + "@refs/heads/main",
        }
    ):
        raise DrillError("source_run_not_expected_canceled_main_workflow")
    workflow_id = run_doc.get("workflow_id")
    if isinstance(workflow_id, bool) or not isinstance(workflow_id, int) or workflow_id < 1:
        raise DrillError("source_workflow_identity_invalid")
    workflow_doc = json.loads(_run(["gh", "api", f"{prefix}/actions/workflows/{workflow_id}"], cwd=destination, env=env,
                                   timeout=30, output_limit=128_000))
    if workflow_doc.get("path") != WORKFLOW_PATH:
        raise DrillError("source_workflow_identity_invalid")
    artifacts_doc = json.loads(_run(["gh", "api", f"{prefix}/actions/runs/{source_run_id}/artifacts?per_page=100"],
                                    cwd=destination, env=env, timeout=30, output_limit=256_000))
    artifacts = artifacts_doc.get("artifacts", [])
    matches = [item for item in artifacts if isinstance(item, dict)
               and item.get("name") == f"hosted-recovery-{source_run_id}"]
    if len(matches) != 1:
        raise DrillError("source_artifact_missing_or_ambiguous")
    item = matches[0]
    artifact_run = item.get("workflow_run")
    artifact_id = item.get("id")
    size = item.get("size_in_bytes")
    if (
        isinstance(artifact_id, bool) or not isinstance(artifact_id, int) or artifact_id < 1
        or not isinstance(artifact_run, dict) or str(artifact_run.get("id")) != source_run_id
        or item.get("expired") is not False
        or isinstance(size, bool) or not isinstance(size, int) or size < 1 or size > MAX_BYTES
    ):
        raise DrillError("source_artifact_metadata_invalid")
    archive = destination.parent / f".hosted-recovery-{source_run_id}.zip"
    downloaded = _run_to_file(
        ["gh", "api", f"repos/{CANONICAL_REPOSITORY}/actions/artifacts/{artifact_id}/zip"],
        cwd=destination, env=env, timeout=MAX_ARCHIVE_SECONDS, destination=archive, byte_limit=MAX_BYTES,
    )
    if downloaded != size:
        archive.unlink(missing_ok=True)
        raise DrillError("source_artifact_size_mismatch")
    try:
        _extract_allowlisted_archive(archive, destination)
    finally:
        archive.unlink(missing_ok=True)
    checked = validate_stage(destination)
    if checked["total_bytes"] > MAX_BYTES:
        raise DrillError("artifact_total_size_exceeded")
    return {"run_id": source_run_id, "workflow_id": workflow_id, "artifact_id": artifact_id,
            "artifact_name": item["name"], "artifact_bytes": size, "head_sha": expected_sha}


def _make_fixture(root: Path, stage: Path, source_root: Path, wheel: Path) -> tuple[Path, str, str, Path, Path, Path]:
    source_env = {"PATH": os.environ.get("PATH", ""), "HOME": os.environ.get("HOME", str(root))}
    source_sha = _run(["git", "rev-parse", "HEAD"], cwd=source_root, env=source_env, timeout=5)
    if not re.fullmatch(r"[0-9a-f]{40}", source_sha):
        raise DrillError("harness_revision_invalid")
    repo = Path("/tmp") / f"hosted-recovery-fixture-{source_sha}"
    try:
        repo.mkdir()
    except FileExistsError:
        raise DrillError("synthetic_fixture_path_already_exists") from None
    env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": os.environ.get("HOME", str(root)),
        "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_AUTHOR_NAME": "Recovery Fixture",
        "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
        "GIT_COMMITTER_NAME": "Recovery Fixture",
        "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
        "GIT_AUTHOR_DATE": "2000-01-01T00:00:00Z",
        "GIT_COMMITTER_DATE": "2000-01-01T00:00:00Z",
    }
    _run(["git", "init", "-b", "rehearsal", str(repo)], cwd=root, env=env, timeout=10)
    sample = repo / "sample.py"
    sample.write_text("VALUE = 1\n", encoding="utf-8")
    for content, message in (("VALUE = 1\n", "base"), ("VALUE = 2\n", "head")):
        sample.write_text(content, encoding="utf-8")
        _run(["git", "-C", str(repo), "add", "sample.py"], cwd=root, env=env, timeout=10)
        _run(["git", "-C", str(repo), "-c", "core.hooksPath=/dev/null", "commit", "-m", message], cwd=root, env=env, timeout=10)
        if message == "base":
            base = _run(["git", "-C", str(repo), "rev-parse", "HEAD"], cwd=root, env=env, timeout=10)
        else:
            head = _run(["git", "-C", str(repo), "rev-parse", "HEAD"], cwd=root, env=env, timeout=10)
    bundle = stage / "fixture.bundle"
    _run(["git", "-C", str(repo), "bundle", "create", str(bundle), "--all"], cwd=root, env=env, timeout=10)
    profile = root / "profile.json"
    profile.write_bytes(canonical({
        "version": "hosted-recovery-profile-v1",
        "repository": IDENTITY["repository"],
        "allow_empty_approve": True,
        "required_lenses": ["correctness", "security"],
        "context_paths": [],
    }))
    limits = root / "limits.json"
    limits.write_bytes(canonical({
        "schema_version": "1.0", "deadline_seconds": 540,
        "max_concurrent_scopes": 1, "max_provider_calls": 2,
        "max_retries_per_task": 0, "max_context_bytes": 32000,
        "max_input_bytes_per_task": 32000, "max_output_bytes_per_task": 8000,
        "max_output_bytes": 16000, "max_output_tokens": 256,
        "max_context_retrievals": 0, "max_followup_tasks": 0,
    }))
    config = root / "provider.json"
    config.write_bytes(canonical({
        "kind": "openai_compatible", "base_url": f"http://127.0.0.1:{PROVIDER_PORT}/v1",
        "model": MODEL, "api_key_env": "HOSTED_RECOVERY_FAKE_KEY",
        "timeout_seconds": 480, "max_request_bytes": 32000,
        "max_response_bytes": 8000, "max_output_tokens": 256,
    }))
    if wheel.name != WHEEL_NAME:
        raise DrillError("wheel_filename_invalid")
    shutil.copyfile(wheel, stage / WHEEL_NAME)
    if source_root.resolve() != Path.cwd().resolve():
        raise DrillError("source_root_mismatch")
    return repo, base, head, profile, limits, config


class _State:
    def __init__(self) -> None:
        self.lock = threading.Condition()
        self.events: list[dict[str, Any]] = []

    def add(self, event: dict[str, Any]) -> None:
        with self.lock:
            self.events.append(event)
            self.lock.notify_all()

    def wait(self, count: int, timeout: float) -> bool:
        deadline = time.monotonic() + timeout
        with self.lock:
            while len([e for e in self.events if e["event"] == "request_entered"]) < count:
                left = deadline - time.monotonic()
                if left <= 0:
                    return False
                self.lock.wait(left)
            return True


class _Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def _provider(state: _State) -> _Server:
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(min(max(length, 0), 128000))
            if self.path != "/v1/chat/completions" or self.headers.get("Authorization") != f"Bearer {API_KEY}" or length > 128000:
                self.send_error(401)
                return
            ordinal = 1 + sum(event["event"] == "request_entered" for event in state.events)
            state.add({"event": "request_entered", "ordinal": ordinal, "request_sha256": hashlib.sha256(raw).hexdigest()})
            if ordinal == 1:
                try:
                    local_payload = local._specialist_payload(json.loads(raw))
                except (ValueError, TypeError, json.JSONDecodeError):
                    self.send_error(400)
                    return
                body = json.dumps({
                    "id": "hosted-recovery-fake-1", "model": MODEL,
                    "choices": [{"finish_reason": "stop", "message": {"content": json.dumps(local_payload)}}],
                    "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
                }, separators=(",", ":")).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                state.add({"event": "response_sent", "ordinal": ordinal})
                return
            # The workflow is cancelled while this provider request is in flight.
            state.add({"event": "held_in_flight", "ordinal": ordinal})
            while True:
                time.sleep(30)

        def log_message(self, *_args: Any) -> None:
            return

    return _Server(("127.0.0.1", PROVIDER_PORT), Handler)


def _limits_identity(manifest: dict[str, Any]) -> dict[str, Any]:
    return {**IDENTITY, **manifest}


def run_a(*, root: Path, stage: Path, wheel: Path, source_root: Path) -> None:
    started = time.monotonic()
    global _PHASE_DEADLINE
    _PHASE_DEADLINE = started + 480  # Keep 30 seconds for cleanup; artifact upload has its own tail.
    if os.environ.get("GITHUB_REF") != "refs/heads/main":
        raise DrillError("canonical_main_ref_required")
    stage.mkdir(mode=0o700)
    if list(stage.iterdir()):
        raise DrillError("stage_not_empty")
    wheel = wheel.resolve(strict=True)
    _regular_file(wheel)
    source = source_inventory(source_root)
    work = root / "work"
    work.mkdir(mode=0o700)
    home = work / "home"
    home.mkdir(mode=0o700)
    venv = work / "venv"
    host_env = {"PATH": os.environ.get("PATH", ""), "HOME": str(home), "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}
    _run([sys.executable, "-m", "venv", str(venv)], cwd=work, env=host_env, timeout=60)
    cli = venv / "bin" / "pr-review"
    _run([str(venv / "bin" / "python"), "-m", "pip", "install", "--no-deps", str(wheel)], cwd=work, env=host_env, timeout=90)
    modules = sorted((venv / "lib").glob("python*/site-packages/pr_review_harness/*.py"))
    installed = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in modules if p.is_file()}
    if installed != source:
        raise DrillError("installed_wheel_source_identity_mismatch")
    repo, base, head, profile, limits, config = _make_fixture(work, stage, source_root, wheel)
    output = work / "output"
    output.mkdir()
    run_id = RUN_ID
    state = _State()
    try:
        server = _provider(state)
    except OSError:
        raise DrillError("loopback_fake_provider_unavailable") from None
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    env = {
        "PATH": f"{venv / 'bin'}:{os.environ.get('PATH', '')}",
        "HOME": str(home), "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
        "PYTHONNOUSERSITE": "1", "HOSTED_RECOVERY_FAKE_KEY": API_KEY,
    }
    cmd = [str(cli), "review", "--repo", str(repo), "--base", base, "--head", head,
           "--profile", str(profile), "--limits", str(limits), "--provider-config", str(config),
           "--output", str(output), "--run-id", run_id, "--json"]
    process = subprocess.Popen(cmd, cwd=work, env=env, stdin=subprocess.DEVNULL,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               start_new_session=True)
    try:
        deadline = started + 180
        if not state.wait(2, max(0, deadline - time.monotonic())):
            raise DrillError("provider_inflight_readiness_timeout")
        checkpoint = output / f"{run_id}.json"
        if not checkpoint.is_file() or checkpoint.is_symlink():
            raise DrillError("checkpoint_not_durable")
        payload = json.loads(checkpoint.read_text(encoding="utf-8"))
        budget = payload.get("ledger", {}).get("budget", {})
        reservations = budget.get("reservations", {})
        settlements = budget.get("settlements", {})
        prior = [key for key in reservations if key in settlements and settlements[key].get("status") == "SUCCEEDED"]
        uncertain = [key for key in reservations if key not in settlements]
        if process.poll() is not None or len(prior) != 1 or len(uncertain) != 1:
            raise DrillError("checkpoint_inflight_state_invalid")
        events = state.events
        if [event["event"] for event in events] != ["request_entered", "response_sent", "request_entered", "held_in_flight"]:
            raise DrillError("provider_readiness_ledger_invalid")
        shutil.copyfile(checkpoint, stage / "checkpoint.json")
        ledger = {"events": events, "completed_requests": 1, "historical_requests": 2, "new_resume_requests": 0}
        (stage / "provider-ledger.json").write_bytes(canonical(ledger))
        readiness = {
            "state": "READY_TO_CANCEL", "provider_ordinal": 2, "provider_in_flight": True,
            "completed_reservations": len(prior), "uncertain_reservations": len(uncertain),
            "checkpoint_sha256": digest(stage / "checkpoint.json"),
        }
        (stage / "readiness.json").write_bytes(canonical(readiness))
        hashes = {name: digest(stage / name) for name in (
            "checkpoint.json", "fixture.bundle", "provider-ledger.json", "readiness.json", WHEEL_NAME
        )}
        harness_sha = _run(["git", "rev-parse", "HEAD"], cwd=source_root, env=host_env, timeout=5)
        if os.environ.get("GITHUB_SHA") != harness_sha:
            raise DrillError("dispatched_source_sha_mismatch")
        manifest = {
            "schema_version": "hosted-recovery.v1", **IDENTITY,
            "run_id": os.environ.get("GITHUB_RUN_ID", "local-test"),
            "harness_sha": harness_sha, "workflow_ref": os.environ.get("GITHUB_REF"),
            "source_modules": source, "wheel_sha256": digest(stage / WHEEL_NAME),
            "profile_sha256": digest(profile), "limits_sha256": digest(limits),
            "base_sha": base, "head_sha": head, "run_identity": run_id,
            "snapshot_id": payload.get("ledger", {}).get("identity", {}).get("snapshot_id"),
            "request_hash": payload.get("request_hash"),
            "reservations": {"completed": len(prior), "uncertain": len(uncertain)},
            "historical_provider_requests": 2, "new_resume_requests_expected": 0,
            "files": hashes,
        }
        (stage / "manifest.json").write_bytes(canonical(manifest))
        checked = validate_stage(stage)
        if checked["total_bytes"] > MAX_BYTES:
            raise DrillError("artifact_total_size_exceeded")
        # The log notice is the externally polled readiness gate for the one allowed cancel.
        print(f"::notice::HOSTED_RECOVERY_READY run={manifest['run_id']} checkpoint_sha256={hashes['checkpoint.json']} provider_ordinal=2 in_flight=true completed=1 uncertain=1", flush=True)
        print(canonical({"status": "ready_to_cancel", "run_id": manifest["run_id"], "checkpoint_sha256": hashes["checkpoint.json"], "staged_bytes": checked["total_bytes"]}).decode().strip(), flush=True)
        deadline = started + 450
        while time.monotonic() < deadline and process.poll() is None:
            time.sleep(1)
        if process.poll() is None:
            raise DrillError("external_cancellation_deadline_exceeded")
        raise DrillError("cli_finished_before_external_cancel")
    except KeyboardInterrupt:
        return
    finally:
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGTERM)
                process.wait(timeout=2)
            except (ProcessLookupError, subprocess.TimeoutExpired):
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)


def run_b(*, root: Path, stage: Path, expected_run_id: str, expected_sha: str,
          repository: str, source_root: Path, output: Path) -> None:
    started = time.monotonic()
    global _PHASE_DEADLINE
    _PHASE_DEADLINE = started + 540  # Includes metadata, archive, install, resume and cleanup.
    if not expected_run_id.isascii() or not expected_run_id.isdigit() or len(expected_run_id) > 20:
        raise DrillError("source_run_id_invalid")
    if os.environ.get("GITHUB_REF") != "refs/heads/main" or os.environ.get("GITHUB_SHA") != expected_sha:
        raise DrillError("canonical_main_source_identity_mismatch")
    retrieval = _download_canceled_run_artifact(
        expected_run_id, expected_sha, stage, repository=repository, token=os.environ.get("GH_TOKEN", "")
    )
    checked = validate_stage(stage)
    manifest = checked["manifest"]
    if manifest.get("run_id") != expected_run_id:
        raise DrillError("source_run_identity_mismatch")
    source_sha = _run(["git", "rev-parse", "HEAD"], cwd=source_root,
                      env={"PATH": os.environ.get("PATH", ""), "HOME": os.environ.get("HOME", "/tmp")}, timeout=5)
    if manifest.get("harness_sha") != source_sha or source_sha != expected_sha:
        raise DrillError("harness_revision_identity_mismatch")
    if manifest.get("workflow_ref") != "refs/heads/main" or manifest.get("run_identity") != RUN_ID:
        raise DrillError("source_workflow_ref_invalid")
    if any(manifest.get(key) != value for key, value in IDENTITY.items()):
        raise DrillError("review_identity_mismatch")
    if (
        not re.fullmatch(r"[0-9a-f]{40}", str(manifest.get("base_sha", "")))
        or not re.fullmatch(r"[0-9a-f]{40}", str(manifest.get("head_sha", "")))
        or not isinstance(manifest.get("snapshot_id"), str)
        or not manifest["snapshot_id"]
        or not isinstance(manifest.get("request_hash"), str)
        or not re.fullmatch(r"[0-9a-f]{64}", manifest["request_hash"])
        or manifest.get("reservations") != {"completed": 1, "uncertain": 1}
        or manifest.get("historical_provider_requests") != 2
        or manifest.get("new_resume_requests_expected") != 0
    ):
        raise DrillError("resume_identity_manifest_invalid")
    if manifest.get("source_modules") != source_inventory(source_root):
        raise DrillError("source_module_identity_mismatch")
    try:
        readiness = json.loads((stage / "readiness.json").read_text(encoding="utf-8"))
        prior_ledger = json.loads((stage / "provider-ledger.json").read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        raise DrillError("readiness_or_provider_ledger_invalid") from None
    if (
        readiness.get("state") != "READY_TO_CANCEL"
        or readiness.get("provider_ordinal") != 2
        or readiness.get("provider_in_flight") is not True
        or readiness.get("completed_reservations") != 1
        or readiness.get("uncertain_reservations") != 1
        or readiness.get("checkpoint_sha256") != digest(stage / "checkpoint.json")
        or prior_ledger.get("completed_requests") != 1
        or prior_ledger.get("historical_requests") != 2
        or prior_ledger.get("new_resume_requests") != 0
        or [event.get("event") for event in prior_ledger.get("events", [])]
        != ["request_entered", "response_sent", "request_entered", "held_in_flight"]
    ):
        raise DrillError("readiness_or_provider_ledger_invalid")
    wheel = stage / WHEEL_NAME
    if digest(wheel) != manifest.get("wheel_sha256"):
        raise DrillError("wheel_identity_mismatch")
    work = root / "work"
    work.mkdir(mode=0o700)
    home = work / "home"
    home.mkdir(mode=0o700)
    venv = work / "venv"
    host_env = {"PATH": os.environ.get("PATH", ""), "HOME": str(home), "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}
    _run([sys.executable, "-m", "venv", str(venv)], cwd=work, env=host_env, timeout=60)
    _run([str(venv / "bin" / "python"), "-m", "pip", "install", "--no-deps", str(wheel)], cwd=work, env=host_env, timeout=90)
    cli = venv / "bin" / "pr-review"
    modules = sorted((venv / "lib").glob("python*/site-packages/pr_review_harness/*.py"))
    installed = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in modules if p.is_file()}
    if installed != manifest.get("source_modules"):
        raise DrillError("installed_wheel_source_identity_mismatch")
    repo = Path("/tmp") / f"hosted-recovery-fixture-{manifest['harness_sha']}"
    try:
        repo.mkdir()
    except FileExistsError:
        raise DrillError("synthetic_fixture_path_already_exists") from None
    env = host_env
    _run(["git", "init", "--bare", str(repo)], cwd=work, env=env, timeout=10)
    _run(["git", "-C", str(repo), "fetch", str(stage / "fixture.bundle"), "+refs/heads/rehearsal:refs/heads/rehearsal"], cwd=work, env=env, timeout=10)
    base, head = manifest["base_sha"], manifest["head_sha"]
    for ref, sha in (("refs/heads/rehearsal~1", base), ("refs/heads/rehearsal", head)):
        if _run(["git", "-C", str(repo), "rev-parse", ref], cwd=work, env=env, timeout=10) != sha:
            raise DrillError("fixture_revision_mismatch")
    profile = work / "profile.json"
    profile.write_bytes(canonical({
        "version": "hosted-recovery-profile-v1", "repository": IDENTITY["repository"],
        "allow_empty_approve": True, "required_lenses": ["correctness", "security"], "context_paths": [],
    }))
    limits = work / "limits.json"
    limits.write_bytes(canonical({
        "schema_version": "1.0", "deadline_seconds": 540, "max_concurrent_scopes": 1,
        "max_provider_calls": 2, "max_retries_per_task": 0, "max_context_bytes": 32000,
        "max_input_bytes_per_task": 32000, "max_output_bytes_per_task": 8000,
        "max_output_bytes": 16000, "max_output_tokens": 256,
        "max_context_retrievals": 0, "max_followup_tasks": 0,
    }))
    if digest(profile) != manifest.get("profile_sha256") or digest(limits) != manifest.get("limits_sha256"):
        raise DrillError("request_configuration_identity_mismatch")
    config = work / "provider.json"
    config.write_bytes(canonical({
        "kind": "openai_compatible", "base_url": f"http://127.0.0.1:{PROVIDER_PORT}/v1",
        "model": MODEL, "api_key_env": "HOSTED_RECOVERY_FAKE_KEY", "timeout_seconds": 480,
        "max_request_bytes": 32000, "max_response_bytes": 8000, "max_output_tokens": 256,
    }))
    output.mkdir(mode=0o700)
    checkpoint = stage / "checkpoint.json"
    (output / f"{RUN_ID}.json").write_bytes(checkpoint.read_bytes())
    state = _State()
    try:
        server = _provider(state)
    except OSError:
        raise DrillError("loopback_fake_provider_unavailable") from None
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    run_env = {**env, "PATH": f"{venv / 'bin'}:{env['PATH']}", "PYTHONNOUSERSITE": "1", "HOSTED_RECOVERY_FAKE_KEY": API_KEY}
    cmd = [str(cli), "review", "--repo", str(repo), "--base", base, "--head", head,
           "--profile", str(profile), "--limits", str(limits), "--provider-config", str(config),
           "--output", str(output), "--run-id", RUN_ID, "--resume", "--json"]
    try:
        result = local._run_cli(cli, cmd[1:], cwd=work, env=run_env, timeout_seconds=local.MAX_CLI_SECONDS,
                               deadline_at=time.monotonic() + 120)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)
    if state.events:
        raise DrillError("new_resume_provider_request_observed")
    if result.get("disposition") != "INCOMPLETE":
        raise DrillError("resume_disposition_not_incomplete")
    budget = result.get("budget", {})
    if budget.get("provider_calls_reserved") != 2:
        raise DrillError("historical_call_count_changed")
    outcomes = [item.get("status") for item in result.get("task_results", {}).values() if isinstance(item, dict)]
    errors = [item.get("error_code") for item in result.get("task_results", {}).values() if isinstance(item, dict)]
    if sorted(outcomes) != ["FAILED", "SUCCEEDED"] or "INTERRUPTED_UNKNOWN" not in errors:
        raise DrillError("uncertain_reservation_not_preserved")
    (output / "resume-evidence.json").write_bytes(canonical({
        "schema_version": "hosted-recovery-resume.v1", "source_run_id": expected_run_id,
        "artifact_retrieval": retrieval,
        "harness_sha": manifest["harness_sha"], "wheel_sha256": manifest["wheel_sha256"],
        "source_modules": manifest["source_modules"], "run_identity": RUN_ID,
        "base_sha": base, "head_sha": head, "snapshot_id": manifest["snapshot_id"],
        "request_hash": manifest["request_hash"], "disposition": result["disposition"],
        "manifest_sha256": digest(stage / "manifest.json"),
        "checkpoint_sha256": digest(stage / "checkpoint.json"),
        "prior_provider_ledger_sha256": digest(stage / "provider-ledger.json"),
        "readiness_sha256": digest(stage / "readiness.json"),
        "outcomes": sorted(outcomes), "interrupted_unknown_present": True,
        "historical_requests": 2, "new_resume_requests": len(state.events),
        "provider_events": state.events,
    }))
    print(canonical({"status": "resumed_incomplete", "historical_requests": 2, "new_resume_requests": 0,
                     "snapshot_id": manifest["snapshot_id"], "wheel_sha256": manifest["wheel_sha256"]}).decode().strip(), flush=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("run-a", "run-b"))
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--stage", required=True, type=Path)
    parser.add_argument("--source-root", required=True, type=Path)
    parser.add_argument("--wheel", type=Path)
    parser.add_argument("--source-run-id", default="")
    parser.add_argument("--expected-sha", default="")
    parser.add_argument("--repository", default="")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        args.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        if args.phase == "run-a":
            if args.wheel is None:
                raise DrillError("wheel_argument_required")
            run_a(root=args.root, stage=args.stage, wheel=args.wheel, source_root=args.source_root.resolve(strict=True))
        else:
            if args.output is None:
                raise DrillError("output_argument_required")
            run_b(root=args.root, stage=args.stage, expected_run_id=args.source_run_id,
                  expected_sha=args.expected_sha, repository=args.repository,
                  source_root=args.source_root.resolve(strict=True), output=args.output)
    except (DrillError, OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        code = str(exc) if isinstance(exc, DrillError) else "rehearsal_failed"
        if os.environ.get("HOSTED_RECOVERY_DEBUG") == "1" and not isinstance(exc, DrillError):
            traceback.print_exc()
        print(canonical({"status": "failed", "error_code": code}).decode().strip(), file=sys.stderr, flush=True)
        return 1
    except Exception:
        if os.environ.get("HOSTED_RECOVERY_DEBUG") == "1":
            traceback.print_exc()
        print(canonical({"status": "failed", "error_code": "rehearsal_unexpected_failure"}).decode().strip(), file=sys.stderr, flush=True)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
