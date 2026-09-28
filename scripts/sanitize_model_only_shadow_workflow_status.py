#!/usr/bin/env python3
"""Write a bounded workflow-status receipt without copying logs or model data."""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
from pathlib import Path
from typing import Any

SCHEMA = "model-only-shadow-workflow-status.v1"
CASES = {"PR-457", "PR-464"}
OUTCOMES = {"success", "failure", "cancelled", "skipped", "unknown"}
JOB_STATES = {"success", "failure", "cancelled", "unknown"}
STAGE_ENV = {
    "trusted_checkout": "STATUS_TRUSTED_CHECKOUT",
    "trusted_identity": "STATUS_TRUSTED_IDENTITY",
    "case_selection": "STATUS_CASE_SELECTION",
    "exact_preflight": "STATUS_EXACT_PREFLIGHT",
    "provider_identity": "STATUS_PROVIDER_IDENTITY",
    "writer": "STATUS_WRITER",
    "writer_sanitize": "STATUS_WRITER_SANITIZE",
    "audit_config": "STATUS_AUDIT_CONFIG",
    "shadow_audit": "STATUS_SHADOW_AUDIT",
    "audit_sanitize": "STATUS_AUDIT_SANITIZE",
    "writer_artifact_upload": "STATUS_WRITER_ARTIFACT_UPLOAD",
    "audit_artifact_upload": "STATUS_AUDIT_ARTIFACT_UPLOAD",
}


def _choice(value: Any, allowed: set[str]) -> str:
    return value if isinstance(value, str) and value in allowed else "unknown"


def _digits(value: Any) -> str:
    return value if isinstance(value, str) and re.fullmatch(r"[0-9]{1,20}", value) else "unknown"


def build_receipt(env: dict[str, str]) -> dict[str, Any]:
    stages = {
        name: _choice(env.get(variable, ""), OUTCOMES)
        for name, variable in STAGE_ENV.items()
    }
    writer = stages["writer"]
    writer_sanitize = stages["writer_sanitize"]
    audit = stages["shadow_audit"]
    audit_sanitize = stages["audit_sanitize"]
    writer_upload = stages["writer_artifact_upload"]
    audit_upload = stages["audit_artifact_upload"]
    writer_calls = (
        "not_started" if writer == "skipped"
        else "accounted_by_sanitized_receipt"
        if writer_sanitize == "success" and writer_upload == "success"
        else "unknown"
    )
    audit_calls = (
        "not_started" if audit == "skipped"
        else "accounted_by_sanitized_receipt"
        if audit_sanitize == "success" and audit_upload == "success"
        else "unknown"
    )
    return {
        "schema": SCHEMA,
        "case_id": env.get("STATUS_CASE_ID") if env.get("STATUS_CASE_ID") in CASES else "unknown",
        "run_id": _digits(env.get("STATUS_RUN_ID")),
        "run_attempt": _digits(env.get("STATUS_RUN_ATTEMPT")),
        "job_status_at_projection": _choice(env.get("STATUS_JOB", ""), JOB_STATES),
        "projection_mode": "trusted_projector",
        "stages": stages,
        "writer_call_state": writer_calls,
        "audit_call_state": audit_calls,
    }


def _output_path(path: Path) -> None:
    runner_temp_value = os.environ.get("RUNNER_TEMP")
    if not runner_temp_value:
        raise ValueError("runner_temp_unavailable")
    runner_temp = Path(runner_temp_value).resolve(strict=True)
    output = path.resolve(strict=False)
    expected_output = runner_temp / "private-shadow-status" / "workflow-status.json"
    if output != expected_output:
        raise ValueError("status_output_path_invalid")
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    temp_fd = os.open(runner_temp, directory_flags)
    try:
        os.mkdir("private-shadow-status", mode=0o700, dir_fd=temp_fd)
        status_fd = os.open("private-shadow-status", directory_flags, dir_fd=temp_fd)
        try:
            status_info = os.fstat(status_fd)
            if not stat.S_ISDIR(status_info.st_mode) or stat.S_IMODE(status_info.st_mode) != 0o700:
                raise ValueError("status_directory_invalid")
            fd = os.open(
                "workflow-status.json",
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o600, dir_fd=status_fd,
            )
            try:
                if not stat.S_ISREG(os.fstat(fd).st_mode):
                    raise ValueError("status_output_not_regular")
                os.fchmod(fd, 0o600)
                data = (json.dumps(build_receipt(dict(os.environ)), sort_keys=True,
                                   separators=(",", ":"), allow_nan=False) + "\n").encode("utf-8")
                with os.fdopen(fd, "wb", closefd=False) as stream:
                    stream.write(data)
                    stream.flush()
                    os.fsync(stream.fileno())
            finally:
                os.close(fd)
        finally:
            os.close(status_fd)
    finally:
        os.close(temp_fd)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        _output_path(args.output)
    except (OSError, ValueError):
        print('{"ok":false,"error_code":"workflow_status_invalid"}')
        return 2
    print('{"ok":true}')
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
