#!/usr/bin/env python3
"""Pin exact provider-free PR-457 writer request bytes for one trusted run."""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from pathlib import Path

from pr_review_harness.current_source_capture import (  # noqa: E402
    CurrentSourceCaptureError,
    create_plan,
    installed_module_inventory,
)


def _read(path: Path, maximum: int) -> tuple[dict, bytes]:
    try:
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
            raise ValueError("prepared_input_invalid")
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        try:
            opened = os.fstat(fd)
            if (not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
                    or opened.st_size > maximum):
                raise ValueError("prepared_input_invalid")
            raw = bytearray()
            while len(raw) <= maximum:
                chunk = os.read(fd, min(65_536, maximum + 1 - len(raw)))
                if not chunk:
                    break
                raw.extend(chunk)
        finally:
            os.close(fd)
    except OSError:
        raise ValueError("prepared_input_invalid") from None
    if len(raw) > maximum:
        raise ValueError("prepared_input_invalid")
    try:
        value = json.loads(bytes(raw).decode("utf-8"), object_pairs_hook=_pairs,
                           parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("invalid_constant")))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError):
        raise ValueError("prepared_input_invalid") from None
    if not isinstance(value, dict):
        raise ValueError("prepared_input_invalid")
    return value, bytes(raw)


def _pairs(pairs: list[tuple[str, object]]) -> dict:
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate_json_key")
        value[key] = item
    return value


def _write_new(path: Path, value: dict) -> None:
    raw = (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def prepare(prepared_path: Path, output_dir: Path, source_sha: str) -> dict:
    if not output_dir.is_absolute() or output_dir.is_symlink() or not output_dir.is_dir():
        raise ValueError("runner_temp_unavailable")
    if output_dir.stat().st_mode & 0o077:
        raise ValueError("runner_temp_permissions_invalid")
    prepared, prepared_raw = _read(prepared_path, 4_000_000)
    plan, receipt = create_plan(
        prepared, source_sha=source_sha,
        module_inventory=installed_module_inventory(), prepared_raw=prepared_raw,
    )
    plan_path = output_dir / "pr457-current-source-plan.json"
    receipt_path = output_dir / "pr457-current-source-receipt.json"
    _write_new(plan_path, plan)
    _write_new(receipt_path, receipt)
    return {
        "schema": "pr457-current-source-prepare-observation.v1",
        "source_sha": source_sha,
        "plan_sha256": receipt["plan_sha256"],
        "prepared_sha256": receipt["prepared_sha256"],
        "writer_request_count": len(plan["writer_requests"]),
        "writer_request_bytes_total": sum(row["input_bytes"] for row in plan["writer_requests"]),
        "writer_request_bytes_max": max(row["input_bytes"] for row in plan["writer_requests"]),
        "provider_calls": 0,
        "target_code_execution": False,
        "publication_enabled": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prepared", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--source-sha", required=True)
    args = parser.parse_args(argv)
    try:
        print(json.dumps(prepare(args.prepared, args.output_dir, args.source_sha), sort_keys=True, separators=(",", ":")))
    except (OSError, ValueError, CurrentSourceCaptureError) as exc:
        code = str(exc) if isinstance(exc, CurrentSourceCaptureError) else "current_source_prepare_invalid"
        print(json.dumps({"ok": False, "error_code": code}, separators=(",", ":")), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
