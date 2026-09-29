"""Bound and validate the exact non-secret inputs needed to resume a PR review."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from pathlib import Path
from typing import Any

SCHEMA = "pr-analysis-recovery-inputs.v1"
MAX_BYTES = 2_000_000
MAX_RUNS = 2_000
RUN_FIELDS = ("id", "name", "status", "conclusion", "head_sha", "app_id", "completed_at")
RAW_PROVIDER_FIELDS = {"external_id", "details_url"}
SHA = re.compile(r"^[0-9a-f]{40,64}$")
REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
EVENT_ID = re.compile(r"^[1-9][0-9]{0,19}$")


class RecoveryInputError(ValueError):
    """Recovery inputs do not match the bounded v1 contract."""


def canonical(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode()


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_json_key")
        result[key] = value
    return result


def _json(raw: bytes) -> dict[str, Any]:
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("invalid_json_constant")),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError):
        raise RecoveryInputError("recovery_inputs_invalid") from None
    if not isinstance(value, dict):
        raise RecoveryInputError("recovery_inputs_invalid")
    return value


def normalize_checks(document: dict[str, Any], *, repository: str, pull_request_number: int, head_sha: str) -> dict:
    """Project provider/API check data to only fields the review ingester consumes."""
    expected_top = {
        "schema_version", "repository", "pull_request_number", "head_sha", "captured_at", "complete", "runs"
    }
    if not isinstance(document, dict) or set(document) != expected_top:
        raise RecoveryInputError("recovery_check_document_invalid")
    if (
        document.get("schema_version") not in {"1.0", "2.0"}
        or document.get("repository") != repository
        or document.get("pull_request_number") != pull_request_number
        or isinstance(pull_request_number, bool)
        or not SHA.fullmatch(head_sha)
        or document.get("head_sha") != head_sha
        or not isinstance(document.get("captured_at"), str)
        or not document["captured_at"]
        or len(document["captured_at"]) > 64
        or not isinstance(document.get("complete"), bool)
        or not isinstance(document.get("runs"), list)
        or len(document["runs"]) > MAX_RUNS
    ):
        raise RecoveryInputError("recovery_check_document_invalid")
    try:
        if len(canonical(document)) > MAX_BYTES:
            raise RecoveryInputError("recovery_check_document_too_large")
    except (TypeError, ValueError):
        raise RecoveryInputError("recovery_check_document_invalid") from None
    rows = []
    for run in document["runs"]:
        if not isinstance(run, dict) or set(run) - (set(RUN_FIELDS) | RAW_PROVIDER_FIELDS):
            raise RecoveryInputError("recovery_check_run_invalid")
        row = {field: run.get(field) for field in RUN_FIELDS}
        run_id, app_id = row["id"], row["app_id"]
        if (run_id is not None and (isinstance(run_id, bool) or not isinstance(run_id, int) or run_id < 1)):
            raise RecoveryInputError("recovery_check_run_invalid")
        if (app_id is not None and (isinstance(app_id, bool) or not isinstance(app_id, int) or app_id < 1)):
            raise RecoveryInputError("recovery_check_run_invalid")
        for field in ("name", "status"):
            value = row[field]
            if value is not None and (not isinstance(value, str) or not value or len(value.encode()) > 256):
                raise RecoveryInputError("recovery_check_run_invalid")
        for field in ("conclusion", "completed_at"):
            value = row[field]
            if value is not None and (not isinstance(value, str) or len(value.encode()) > 256):
                raise RecoveryInputError("recovery_check_run_invalid")
        if row["head_sha"] is not None and (not isinstance(row["head_sha"], str) or not SHA.fullmatch(row["head_sha"])):
            raise RecoveryInputError("recovery_check_run_invalid")
        rows.append(row)
    normalized = {
        key: document[key]
        for key in ("schema_version", "repository", "pull_request_number", "head_sha", "captured_at", "complete")
    }
    normalized["schema_version"] = "2.0"
    normalized["runs"] = rows
    if len(canonical(normalized)) > MAX_BYTES:
        raise RecoveryInputError("recovery_check_document_too_large")
    return normalized


def make_packet(event: dict[str, Any], document: dict[str, Any], source_event_id: str) -> dict:
    if not isinstance(event, dict) or set(event) != {
        "repository", "pull_request_number", "event_id", "base_sha", "head_sha"
    }:
        raise RecoveryInputError("recovery_event_invalid")
    repository = event.get("repository")
    number = event.get("pull_request_number")
    base_sha, head_sha = event.get("base_sha"), event.get("head_sha")
    if (
        not isinstance(repository, str)
        or not REPOSITORY.fullmatch(repository)
        or isinstance(number, bool)
        or not isinstance(number, int)
        or number < 1
        or not isinstance(source_event_id, str)
        or not EVENT_ID.fullmatch(source_event_id)
        or event.get("event_id") != source_event_id
        or not isinstance(base_sha, str)
        or not SHA.fullmatch(base_sha)
        or not isinstance(head_sha, str)
        or not SHA.fullmatch(head_sha)
    ):
        raise RecoveryInputError("recovery_event_invalid")
    checks = normalize_checks(document, repository=repository, pull_request_number=number, head_sha=head_sha)
    return {
        "schema_version": SCHEMA,
        "source_event_id": source_event_id,
        "event": {key: event[key] for key in ("repository", "pull_request_number", "event_id", "base_sha", "head_sha")},
        "checks_document": checks,
    }


def validate_packet(packet: dict[str, Any], *, repository: str, run_id: str, base_sha: str | None = None, head_sha: str | None = None) -> dict:
    if not isinstance(packet, dict) or set(packet) != {"schema_version", "source_event_id", "event", "checks_document"}:
        raise RecoveryInputError("recovery_inputs_invalid")
    source_event_id = packet.get("source_event_id")
    event = packet.get("event")
    if (
        packet.get("schema_version") != SCHEMA
        or not isinstance(source_event_id, str)
        or not EVENT_ID.fullmatch(source_event_id)
        or not isinstance(event, dict)
        or event.get("event_id") != source_event_id
        or event.get("repository") != repository
        or run_id != f"pr-{event.get('pull_request_number')}-{source_event_id}"
        or (base_sha is not None and base_sha != event.get("base_sha"))
        or (head_sha is not None and head_sha != event.get("head_sha"))
    ):
        raise RecoveryInputError("recovery_inputs_identity_mismatch")
    canonical_event = {
        "repository": event.get("repository"),
        "pull_request_number": event.get("pull_request_number"),
        "event_id": event.get("event_id"),
        "base_sha": event.get("base_sha"),
        "head_sha": event.get("head_sha"),
    }
    try:
        rebuilt = make_packet(canonical_event, packet["checks_document"], source_event_id)
    except RecoveryInputError:
        raise
    if rebuilt != packet:
        raise RecoveryInputError("recovery_inputs_invalid")
    return rebuilt


def read_packet(path: str | Path, *, repository: str, run_id: str, base_sha: str | None = None, head_sha: str | None = None) -> tuple[dict, bytes]:
    source = Path(path)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        before = source.lstat()
        if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_BYTES:
            raise RecoveryInputError("recovery_inputs_invalid")
        fd = os.open(source, flags)
        try:
            opened = os.fstat(fd)
            if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                raise RecoveryInputError("recovery_inputs_invalid")
            raw = bytearray()
            while len(raw) <= MAX_BYTES:
                chunk = os.read(fd, min(65536, MAX_BYTES + 1 - len(raw)))
                if not chunk:
                    break
                raw.extend(chunk)
        finally:
            os.close(fd)
    except OSError:
        raise RecoveryInputError("recovery_inputs_unavailable") from None
    if len(raw) > MAX_BYTES:
        raise RecoveryInputError("recovery_inputs_invalid")
    packet = _json(bytes(raw))
    validate_packet(packet, repository=repository, run_id=run_id, base_sha=base_sha, head_sha=head_sha)
    return packet, bytes(raw)


def write_packet(path: str | Path, packet: dict) -> bytes:
    data = canonical(packet)
    if len(data) > MAX_BYTES:
        raise RecoveryInputError("recovery_inputs_invalid")
    destination = Path(path)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(destination, flags, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except OSError:
        raise RecoveryInputError("recovery_inputs_write_failed") from None
    return data
