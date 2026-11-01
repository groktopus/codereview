"""Bounded official Actions artifact upload bridge.

The bridge passes only the runner's artifact-runtime credentials to a
short-lived Node child running the pinned official ``@actions/artifact`` client.
It is the one Actions piece the installed protected-publication runtime needs;
the read-only identity canary that shares its history lives in
``experiments/harness/actions_canary.py``.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import shutil
import signal
import stat
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Callable, Mapping
from urllib.parse import urlsplit

from .actions_publication import ArtifactUploadResult

_ARTIFACT_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_MAX_UPLOAD_BYTES = 128 * 1024
_MAX_UPLOAD_SECONDS = 300.0
_MAX_BRIDGE_OUTPUT_BYTES = 4096


def _strict_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_json_key")
        result[key] = value
    return result


def _reject_json_constant(_value):
    raise ValueError("nonfinite_json_number")


class OfficialActionsArtifactUploader:
    """Bounded bridge to the pinned official ``@actions/artifact`` SDK."""

    def __init__(
        self,
        *,
        script_path: Path | None = None,
        node: str = "node",
        environ: Mapping[str, str] | None = None,
        popen: Callable = subprocess.Popen,
        clock: Callable[[], float] = time.monotonic,
    ):
        self._script = (
            script_path or Path(__file__).resolve().parents[2] / "scripts/actions-artifact-uploader/upload.mjs"
        )
        self._environ = dict(os.environ if environ is None else environ)
        self._search_path = self._environ.get("PATH", os.defpath)
        self._node = shutil.which(node, path=self._search_path) or node
        self._popen = popen
        self._clock = clock

    def upload(
        self,
        *,
        run_id: int,
        artifact_name: str,
        filename: str,
        content: bytes,
        timeout_seconds: float,
    ) -> ArtifactUploadResult:
        if (
            isinstance(run_id, bool)
            or not isinstance(run_id, int)
            or run_id < 1
            or not isinstance(artifact_name, str)
            or not _ARTIFACT_NAME.fullmatch(artifact_name)
            or not isinstance(filename, str)
            or not _ARTIFACT_NAME.fullmatch(filename)
            or not isinstance(content, bytes)
            or len(content) > _MAX_UPLOAD_BYTES
            or isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not math.isfinite(timeout_seconds)
            or not 0 < timeout_seconds <= _MAX_UPLOAD_SECONDS
        ):
            return ArtifactUploadResult("UNAVAILABLE", reason_code="artifact_upload_input_invalid")
        if self._environ.get("GITHUB_RUN_ID") != str(run_id):
            return ArtifactUploadResult("UNAVAILABLE", reason_code="artifact_run_binding_mismatch")
        runtime_token = self._environ.get("ACTIONS_RUNTIME_TOKEN")
        results_url = self._environ.get("ACTIONS_RESULTS_URL")
        if not runtime_token or not self._valid_results_url(results_url) or not Path(self._script).is_file():
            return ArtifactUploadResult("UNAVAILABLE", reason_code="artifact_runtime_unavailable")
        run_attempt = self._environ.get("GITHUB_RUN_ATTEMPT", "1")
        if not re.fullmatch(r"[1-9][0-9]{0,8}", run_attempt):
            return ArtifactUploadResult("UNAVAILABLE", reason_code="artifact_run_binding_invalid")

        started = self._clock()
        process = None
        with tempfile.TemporaryDirectory(prefix="pr-review-artifact-") as temp_dir:
            temp_path = Path(temp_dir)
            content_path = temp_path / filename
            content_path.write_bytes(content)
            try:
                content_path.chmod(0o600)
            except OSError:
                pass
            input_path = temp_path / "input.json"
            input_path.write_text(
                json.dumps(
                    {
                        "run_id": run_id,
                        "name": artifact_name,
                        "filename": filename,
                        "content_file": filename,
                        "content_sha256": hashlib.sha256(content).hexdigest(),
                        "content_bytes": len(content),
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ),
                encoding="utf-8",
            )
            try:
                input_path.chmod(0o600)
            except OSError:
                pass
            result_path = temp_path / "result.json"
            child_env = {
                "PATH": self._search_path,
                "HOME": str(temp_path),
                "TMPDIR": str(temp_path),
                "GITHUB_RUN_ID": str(run_id),
                "GITHUB_RUN_ATTEMPT": run_attempt,
                "GITHUB_SERVER_URL": "https://github.com",
                "GITHUB_WORKSPACE": str(temp_path),
                "ACTIONS_RUNTIME_TOKEN": runtime_token,
                "ACTIONS_RESULTS_URL": results_url,
                "ACTIONS_ARTIFACT_UPLOAD_TIMEOUT_MS": str(max(1, int(timeout_seconds * 1000))),
                "PR_REVIEW_UPLOAD_INPUT": str(input_path),
                "PR_REVIEW_UPLOAD_RESULT": str(result_path),
            }
            if self._environ.get("ACTIONS_RUNTIME_URL"):
                child_env["ACTIONS_RUNTIME_URL"] = self._environ["ACTIONS_RUNTIME_URL"]
            remaining = float(timeout_seconds) - (self._clock() - started)
            if remaining <= 0:
                return ArtifactUploadResult("UNAVAILABLE", reason_code="artifact_upload_deadline_exhausted")
            try:
                process = self._popen(
                    [self._node, str(self._script)],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    env=child_env,
                    start_new_session=(os.name == "posix"),
                )
            except (OSError, ValueError):
                return ArtifactUploadResult("UNAVAILABLE", reason_code="artifact_bridge_unavailable")

            deadline = started + float(timeout_seconds)
            try:
                while process.poll() is None:
                    remaining = deadline - self._clock()
                    if remaining <= 0:
                        raise subprocess.TimeoutExpired([self._node, str(self._script)], timeout_seconds)
                    time.sleep(min(0.025, remaining))
                if self._clock() >= deadline:
                    raise subprocess.TimeoutExpired([self._node, str(self._script)], timeout_seconds)
                process.wait(timeout=max(0.001, deadline - self._clock()))
            except (OSError, subprocess.TimeoutExpired):
                self._terminate_process_tree(process)
                reason = "artifact_upload_deadline_exhausted" if self._clock() >= deadline else "artifact_upload_failed"
                return ArtifactUploadResult("UNAVAILABLE", reason_code=reason)
            if process.returncode != 0:
                self._terminate_process_tree(process)
                return ArtifactUploadResult("UNAVAILABLE", reason_code="artifact_upload_failed")
            # The SDK should not leave descendants behind after its parent exits.
            self._terminate_process_tree(process)
            try:
                result_stat = result_path.lstat()
                if not stat.S_ISREG(result_stat.st_mode) or result_stat.st_size > _MAX_BRIDGE_OUTPUT_BYTES:
                    return ArtifactUploadResult("UNAVAILABLE", reason_code="artifact_bridge_output_exceeded")
                with result_path.open("rb") as result_file:
                    output = result_file.read(_MAX_BRIDGE_OUTPUT_BYTES + 1)
                if len(output) > _MAX_BRIDGE_OUTPUT_BYTES:
                    return ArtifactUploadResult("UNAVAILABLE", reason_code="artifact_bridge_output_exceeded")
                payload = json.loads(
                    output.decode("utf-8"),
                    object_pairs_hook=_strict_object,
                    parse_constant=_reject_json_constant,
                )
            except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError):
                return ArtifactUploadResult("UNAVAILABLE", reason_code="artifact_bridge_response_invalid")
        if (
            not isinstance(payload, dict)
            or set(payload) != {"status", "artifact_id", "size"}
            or payload.get("status") != "UPLOADED"
            or isinstance(payload.get("artifact_id"), bool)
            or not isinstance(payload.get("artifact_id"), int)
            or payload["artifact_id"] < 1
            or payload["artifact_id"] > 2**53 - 1
            or isinstance(payload.get("size"), bool)
            or not isinstance(payload.get("size"), int)
            or payload["size"] < 0
            or payload["size"] > 2**53 - 1
        ):
            return ArtifactUploadResult("UNAVAILABLE", reason_code="artifact_upload_unconfirmed")
        return ArtifactUploadResult("UPLOADED", artifact_id=payload["artifact_id"])

    @staticmethod
    def _valid_results_url(value: str | None) -> bool:
        if not isinstance(value, str) or len(value) > 2048:
            return False
        try:
            parsed = urlsplit(value)
            host = (parsed.hostname or "").lower()
            return (
                parsed.scheme == "https"
                and (host == "actions.githubusercontent.com" or host.endswith(".actions.githubusercontent.com"))
                and parsed.username is None
                and parsed.password is None
                and parsed.query == ""
                and parsed.fragment == ""
                and (parsed.port is None or parsed.port == 443)
            )
        except ValueError:
            return False

    @staticmethod
    def _terminate_process_tree(process) -> None:
        try:
            if os.name == "posix":
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    return
                try:
                    process.wait(timeout=0.25)
                except subprocess.TimeoutExpired:
                    pass
                # The parent may exit on SIGTERM while a descendant ignores it.
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            elif process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=0.25)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=1)
        except (OSError, ProcessLookupError, subprocess.TimeoutExpired):
            try:
                process.kill()
                process.wait(timeout=1)
            except (OSError, ProcessLookupError, subprocess.TimeoutExpired):
                pass


if __name__ == "__main__":
    import json

    from experiments.harness.actions_canary import run_actions_canary

    print(json.dumps(run_actions_canary(), sort_keys=True, separators=(",", ":")))
