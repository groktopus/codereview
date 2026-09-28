#!/usr/bin/env python3
"""Print only a recognized pr-review JSON error code and process exit status."""

from __future__ import annotations

import argparse
import json
import os
import stat
from pathlib import Path
from typing import Any

MAX_BYTES = 8_192
SAFE_ERRORS = {
    "invalid_arguments", "invalid_review_request", "run_id_already_exists", "resume_state_invalid",
    "snapshot_preflight_failed", "preflight_rejected", "review_runtime_failed",
    "requested revisions do not match the GitHub event",
    "requested revisions do not match the GitHub PR",
    "--github-pr must use owner/repository#number",
    "--github-pr cannot be combined with a GitHub event",
    "explicit base and head revisions are required without a PR/event input",
    "GitHub event is not a pull_request event", "GITHUB_REPOSITORY is required for event mode",
    "PUBLISH_REVIEW is disabled", "stateless publication capability is unavailable",
    "provider adapter is unavailable", "provider configuration is invalid",
    "cannot read profile JSON", "cannot read limits JSON",
}


class DiagnosticError(ValueError):
    """CLI error output is unavailable or outside the tiny public contract."""


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise DiagnosticError("duplicate_key")
        value[key] = item
    return value


def _read_bounded_regular(path: Path) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        before = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode) or before.st_size > MAX_BYTES
            or stat.S_IMODE(before.st_mode) != 0o600
        ):
            raise DiagnosticError("input_unavailable")
        fd = os.open(path, flags)
        try:
            opened = os.fstat(fd)
            if (not stat.S_ISREG(opened.st_mode) or opened.st_dev != before.st_dev
                    or opened.st_ino != before.st_ino or opened.st_size > MAX_BYTES
                    or stat.S_IMODE(opened.st_mode) != 0o600):
                raise DiagnosticError("input_unavailable")
            chunks = bytearray()
            while len(chunks) <= MAX_BYTES:
                chunk = os.read(fd, min(2048, MAX_BYTES + 1 - len(chunks)))
                if not chunk:
                    break
                chunks.extend(chunk)
            after = os.fstat(fd)
        finally:
            os.close(fd)
    except OSError:
        raise DiagnosticError("input_unavailable") from None
    if len(chunks) > MAX_BYTES or before.st_size != after.st_size or len(chunks) != after.st_size:
        raise DiagnosticError("input_unavailable")
    return bytes(chunks)


def extract(path: Path, process_exit_code: int) -> dict[str, Any]:
    if isinstance(process_exit_code, bool) or process_exit_code not in (1, 2):
        raise DiagnosticError("exit_code_invalid")
    try:
        value = json.loads(
            _read_bounded_regular(path).decode("utf-8"),
            object_pairs_hook=_pairs,
            parse_constant=lambda _value: (_ for _ in ()).throw(DiagnosticError("invalid_constant")),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, DiagnosticError):
        raise DiagnosticError("cli_error_payload_invalid") from None
    if not isinstance(value, dict) or set(value) != {"error", "exit_code"}:
        raise DiagnosticError("cli_error_payload_invalid")
    error = value.get("error")
    exit_code = value.get("exit_code")
    if (
        not isinstance(error, str) or error not in SAFE_ERRORS
        or isinstance(exit_code, bool) or exit_code != process_exit_code
    ):
        raise DiagnosticError("cli_error_payload_invalid")
    return {"error": error, "exit_code": exit_code}


def extract_stage(path: Path, process_exit_code: int) -> str:
    try:
        value = json.loads(
            _read_bounded_regular(path).decode("utf-8"),
            object_pairs_hook=_pairs,
            parse_constant=lambda _value: (_ for _ in ()).throw(DiagnosticError("invalid_constant")),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, DiagnosticError):
        raise DiagnosticError("stage_payload_invalid") from None
    if (
        not isinstance(value, dict)
        or set(value) != {"schema", "stage", "exit_code"}
        or value.get("schema") != "pr-review-prepare-stage-diagnostic.v1"
        or value.get("stage") not in {
            "profile_configuration", "limits_validation", "provider_configuration",
            "historical_checks_load", "historical_checks_validation", "snapshot_collection",
            "planning", "task_preparation", "request_evidence_selection", "request_serialization",
            "cli_preflight_unclassified",
        }
        or isinstance(value.get("exit_code"), bool)
        or value.get("exit_code") != process_exit_code
    ):
        raise DiagnosticError("stage_payload_invalid")
    return value["stage"]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--exit-code", type=int, required=True)
    parser.add_argument("--stage-input", type=Path)
    args = parser.parse_args(argv)
    try:
        value = extract(args.input, args.exit_code)
        if args.stage_input is not None:
            value = {"stage": extract_stage(args.stage_input, args.exit_code), **value}
    except DiagnosticError:
        value = {"error": "prepare_failure_diagnostic_unavailable", "exit_code": args.exit_code}
    print(json.dumps(value, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
