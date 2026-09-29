"""Write a tiny crash-surviving receipt for the source HTTP-attempt count."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

SCHEMA = "source-dispatch-accounting.v1"
STATES = {"0", "1", "unknown"}


def _value(case_id: str, attempts: str) -> dict[str, str]:
    if case_id != "PR-464" or attempts not in STATES:
        raise ValueError("source_dispatch_accounting_invalid")
    return {"schema": SCHEMA, "case_id": case_id, "source_http_attempts": attempts}


def write(path: Path, case_id: str, attempts: str, *, create: bool = False) -> None:
    """Persist only bounded accounting fields; 1 is monotonic once observed."""
    value = _value(case_id, attempts)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    data = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    temp = path.with_name(path.name + ".next")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(temp, flags, 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(fd)
    try:
        if create:
            os.link(temp, path, follow_symlinks=False)
            temp.unlink()
        else:
            # Never replace a proven HTTP attempt with a weaker state.
            try:
                old = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError, TypeError):
                old = None
            if isinstance(old, dict) and old.get("source_http_attempts") == "1" and attempts != "1":
                value = old
                data = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
                temp.unlink()
                fd = os.open(temp, flags, 0o600)
                try:
                    with os.fdopen(fd, "wb", closefd=False) as stream:
                        stream.write(data)
                        stream.flush()
                        os.fsync(stream.fileno())
                finally:
                    os.close(fd)
            os.replace(temp, path)
        dir_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    finally:
        try:
            temp.unlink()
        except FileNotFoundError:
            pass


def classify_source_call(roles: Any) -> str:
    """Return 0/1 only from explicit single-call dispatch evidence."""
    if not isinstance(roles, dict):
        return "unknown"
    source = roles.get("source_auditor")
    if not isinstance(source, dict) or not isinstance(source.get("calls"), list):
        return "unknown"
    calls = source["calls"]
    if not calls:
        return "0"
    if len(calls) != 1 or not isinstance(calls[0], dict):
        return "unknown"
    state = calls[0].get("dispatch_state")
    if state == "http_attempted":
        return "1"
    if state in {"guard_rejected", "post_guard_pretransport"}:
        return "0"
    return "unknown"
