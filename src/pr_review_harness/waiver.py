"""Bounded, expiring evidence waivers for review completeness.

A waiver is an explicitly named reviewer's exception for one exact missing
evidence obligation or one exact reason category.  It is not a blanket
"missing evidence is acceptable" switch:

* no waiver is the default, and missing evidence remains missing;
* the waiver file is bound to one repository and one exact base/head pair;
* the reviewer, reason, issue time, and expiry are required;
* every target is scoped to one of ``context_gap``, ``check``, or
  ``coverage_note`` and to an exact planned obligation id or an exact reason
  code in that category;
* an expired waiver is never applied, even if it was valid when the run
  started;
* a waived obligation becomes ``WAIVED``, never ``COMPLETE``.  Findings and
  any existing blocker remain untouched.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

from .completeness import classify_reason

WAIVER_SCHEMA = "review-evidence-waiver.v1"
RECEIPT_SCHEMA = "review-evidence-waiver-receipt.v1"
TARGET_KINDS = ("context_gap", "check", "coverage_note")
MAX_WAIVER_BYTES = 256_000
MAX_TARGETS = 64
MIN_REASON_LENGTH = 20
MIN_JUSTIFICATION_LENGTH = 10
_REPOSITORY_RE = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
_SHA_RE = re.compile(r"[0-9a-f]{40}")
_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}")
_REASON_RE = re.compile(r"[A-Za-z0-9_]{1,128}")
_WAIVER_KEYS = {
    "schema",
    "reviewer",
    "reason",
    "repository",
    "base_sha",
    "head_sha",
    "issued_at",
    "expires_at",
    "waivers",
}
_REASON_FAMILIES = {
    "context_gap": frozenset({"CONTEXT_GAP_UNRESOLVED"}),
    "check": frozenset({"CHECK_EVIDENCE_UNAVAILABLE", "CHECK_EVIDENCE_INVALID"}),
    "coverage_note": frozenset(
        {
            "COVERAGE_NOTE_MISSING",
            "COVERAGE_NOTE_INVALID",
            "SPECIALIST_COVERAGE_PARTIAL",
            "CONTEXT_NOT_COVERED",
        }
    ),
}


class WaiverError(ValueError):
    """A waiver failed validation or cannot be used for this review."""


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise WaiverError("review waiver is invalid")
        result[key] = value
    return result


def _reject_constant(_value: str) -> Any:
    raise WaiverError("review waiver is invalid")


def _bounded_text(value: Any, field: str, *, minimum: int, maximum: int) -> str:
    if not isinstance(value, str) or len(value.strip()) < minimum or len(value) > maximum:
        raise WaiverError(f"review waiver {field} is invalid")
    return value


def _parse_timestamp(value: Any, field: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise WaiverError(f"review waiver {field} is invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise WaiverError(f"review waiver {field} is invalid") from None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise WaiverError(f"review waiver {field} is invalid")
    return parsed.astimezone(timezone.utc)


def _validate_target(target: Any) -> dict[str, Any]:
    if not isinstance(target, dict):
        raise WaiverError("review waiver target is invalid")
    keys = set(target)
    if "id" in keys and "reason_code" in keys:
        raise WaiverError("review waiver target is overbroad")
    if keys not in (
        {"kind", "id", "justification"},
        {"kind", "reason_code", "justification"},
    ):
        raise WaiverError("review waiver target is invalid")
    kind = target.get("kind")
    if kind not in TARGET_KINDS:
        raise WaiverError("review waiver target kind is invalid")
    _bounded_text(target.get("justification"), "target justification", minimum=MIN_JUSTIFICATION_LENGTH, maximum=2_000)
    if "id" in target:
        identifier = target.get("id")
        if not isinstance(identifier, str) or _ID_RE.fullmatch(identifier) is None:
            raise WaiverError("review waiver target id is invalid")
        return {"kind": kind, "id": identifier, "justification": target["justification"]}
    reason_code = target.get("reason_code")
    if not isinstance(reason_code, str) or _REASON_RE.fullmatch(reason_code) is None:
        raise WaiverError("review waiver target reason_code is invalid")
    canonical = classify_reason(reason_code)
    if canonical not in _REASON_FAMILIES[kind]:
        raise WaiverError("review waiver target reason_code is outside its target kind")
    return {"kind": kind, "reason_code": reason_code, "justification": target["justification"]}


def _validate_shape(document: Any) -> dict[str, Any]:
    if not isinstance(document, dict) or set(document) != _WAIVER_KEYS:
        raise WaiverError("review waiver is invalid")
    if document.get("schema") != WAIVER_SCHEMA:
        raise WaiverError("review waiver schema is invalid")
    reviewer = _bounded_text(document.get("reviewer"), "reviewer", minimum=1, maximum=200)
    reason = _bounded_text(document.get("reason"), "reason", minimum=MIN_REASON_LENGTH, maximum=2_000)
    repository = document.get("repository")
    if not isinstance(repository, str) or _REPOSITORY_RE.fullmatch(repository) is None:
        raise WaiverError("review waiver repository is invalid")
    for field in ("base_sha", "head_sha"):
        value = document.get(field)
        if not isinstance(value, str) or _SHA_RE.fullmatch(value) is None:
            raise WaiverError(f"review waiver {field} is invalid")
    issued = _parse_timestamp(document.get("issued_at"), "issued_at")
    expires = _parse_timestamp(document.get("expires_at"), "expires_at")
    if expires <= issued:
        raise WaiverError("review waiver expires_at must be after issued_at")
    waivers = document.get("waivers")
    if not isinstance(waivers, list) or not 1 <= len(waivers) <= MAX_TARGETS:
        raise WaiverError("review waiver targets are invalid")
    targets = [_validate_target(target) for target in waivers]
    seen: set[tuple[str, str, str]] = set()
    for target in targets:
        key = (
            target["kind"],
            "id" if "id" in target else "reason_code",
            target.get("id", target.get("reason_code")),
        )
        if key in seen:
            raise WaiverError("review waiver target is duplicated")
        seen.add(key)
    return {
        "schema": WAIVER_SCHEMA,
        "reviewer": reviewer,
        "reason": reason,
        "repository": repository,
        "base_sha": document["base_sha"],
        "head_sha": document["head_sha"],
        "issued_at": document["issued_at"],
        "expires_at": document["expires_at"],
        "waivers": targets,
    }


def _read_bounded(path: str) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        source = Path(path)
        before = source.lstat()
        if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_WAIVER_BYTES:
            raise WaiverError("review waiver file is unavailable")
        descriptor = os.open(source, flags)
        try:
            opened = os.fstat(descriptor)
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_dev != before.st_dev
                or opened.st_ino != before.st_ino
                or opened.st_size > MAX_WAIVER_BYTES
            ):
                raise WaiverError("review waiver file is unavailable")
            data = bytearray()
            while len(data) <= MAX_WAIVER_BYTES:
                block = os.read(descriptor, min(65_536, MAX_WAIVER_BYTES + 1 - len(data)))
                if not block:
                    break
                data.extend(block)
        finally:
            os.close(descriptor)
    except WaiverError:
        raise
    except OSError:
        raise WaiverError("review waiver file is unavailable") from None
    if len(data) > MAX_WAIVER_BYTES:
        raise WaiverError("review waiver file is unavailable")
    return bytes(data)


def load_waiver(
    path: str,
    *,
    repository: str | None,
    base_sha: str | None,
    head_sha: str | None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Read, validate, and bind a waiver file before any provider dispatch."""

    data = _read_bounded(path)
    try:
        document = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        raise WaiverError("review waiver is invalid") from None
    normalized = _validate_shape(document)
    if repository is None or normalized["repository"] != repository:
        raise WaiverError("review waiver repository is out of scope")
    if normalized["base_sha"] != base_sha or normalized["head_sha"] != head_sha:
        raise WaiverError("review waiver revision is out of scope")
    issued = _parse_timestamp(normalized["issued_at"], "issued_at")
    expires = _parse_timestamp(normalized["expires_at"], "expires_at")
    current = _now(now)
    if expires <= current:
        raise WaiverError("review waiver is expired")
    if issued >= expires:
        raise WaiverError("review waiver expires_at must be after issued_at")
    normalized["source_sha256"] = hashlib.sha256(data).hexdigest()
    return normalized


def _now(value: datetime | None) -> datetime:
    if value is None:
        return datetime.now(timezone.utc)
    if value.tzinfo is None or value.utcoffset() is None:
        raise WaiverError("review waiver validation time is invalid")
    return value.astimezone(timezone.utc)


def _check_aliases(obligation: Mapping[str, Any]) -> set[str]:
    if obligation.get("obligation_kind") != "PROJECT_CHECK":
        return set()
    return {
        str(value)
        for value in (obligation.get("check_binding_id"), obligation.get("check_id"))
        if isinstance(value, str) and value
    }


def validate_waiver_targets(document: Mapping[str, Any], plan: Mapping[str, Any]) -> None:
    """Reject unknown, non-required, or wrong-kind targets before dispatch."""

    obligations = plan.get("coverage_obligations")
    if not isinstance(obligations, list):
        raise WaiverError("review waiver target is unknown")
    by_id: dict[str, Mapping[str, Any]] = {}
    aliases: dict[str, list[str]] = {}
    for obligation in obligations:
        if not isinstance(obligation, Mapping):
            continue
        obligation_id = obligation.get("obligation_id")
        if not isinstance(obligation_id, str) or not obligation_id:
            continue
        by_id[obligation_id] = obligation
        for alias in _check_aliases(obligation):
            aliases.setdefault(alias, []).append(obligation_id)
    resolved: set[str] = set()
    for target in document.get("waivers", []):
        if not isinstance(target, Mapping):
            raise WaiverError("review waiver target is invalid")
        kind = target.get("kind")
        if "id" not in target:
            allowed_kinds = {"PROJECT_CHECK"} if kind == "check" else {"CHANGED_UNIT_LENS", "REQUIRED_CONTEXT"}
            if not any(
                obligation.get("required") is True and obligation.get("obligation_kind") in allowed_kinds
                for obligation in by_id.values()
            ):
                raise WaiverError("review waiver target is unknown")
            continue
        identifier = target["id"]
        if kind == "check":
            candidates = [identifier] if identifier in by_id else aliases.get(identifier, [])
            if len(candidates) != 1:
                raise WaiverError("review waiver target is unknown")
            obligation_id = candidates[0]
        else:
            obligation_id = identifier
        obligation = by_id.get(obligation_id)
        if obligation is None or obligation.get("required") is not True:
            raise WaiverError("review waiver target is unknown")
        if kind == "check" and obligation.get("obligation_kind") != "PROJECT_CHECK":
            raise WaiverError("review waiver target kind is out of scope")
        if kind in {"context_gap", "coverage_note"} and obligation.get("obligation_kind") not in {
            "CHANGED_UNIT_LENS",
            "REQUIRED_CONTEXT",
        }:
            raise WaiverError("review waiver target kind is out of scope")
        if obligation_id in resolved:
            raise WaiverError("review waiver target is duplicated")
        resolved.add(obligation_id)


def _target_matches(row: Mapping[str, Any], target: Mapping[str, Any]) -> bool:
    if row.get("required", True) is not True or row.get("state") not in {"PARTIAL", "NOT_STARTED", "UNKNOWN"}:
        return False
    kind = target.get("kind")
    row_kind = row.get("obligation_kind")
    reason = row.get("reason_code")
    canonical = classify_reason(reason)
    if kind == "check":
        if row_kind != "PROJECT_CHECK" or canonical not in _REASON_FAMILIES[kind]:
            return False
        if "id" in target:
            return target["id"] in {
                row.get("obligation_id"),
                row.get("check_binding_id"),
                row.get("check_id"),
            }
        return classify_reason(target["reason_code"]) == canonical
    if kind == "context_gap":
        if row_kind not in {"CHANGED_UNIT_LENS", "REQUIRED_CONTEXT"} or canonical not in _REASON_FAMILIES[kind]:
            return False
        if "id" in target:
            return target["id"] == row.get("obligation_id")
        return classify_reason(target["reason_code"]) == canonical
    if kind == "coverage_note":
        if row_kind not in {"CHANGED_UNIT_LENS", "REQUIRED_CONTEXT"} or canonical not in _REASON_FAMILIES[kind]:
            return False
        if "id" in target:
            return target["id"] == row.get("obligation_id")
        return classify_reason(target["reason_code"]) == canonical
    return False


def _waiver_id(source_sha256: str, target: Mapping[str, Any], index: int) -> str:
    identity = json.dumps(
        {"source_sha256": source_sha256, "target": target, "index": index},
        sort_keys=True,
        separators=(",", ":"),
    )
    return "wvr-" + hashlib.sha256(identity.encode("utf-8")).hexdigest()[:24]


def apply_waivers(
    coverage_rows: Iterable[dict[str, Any]],
    document: Mapping[str, Any],
    *,
    now: datetime | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Apply valid targets to incomplete required rows.

    Expiry is checked again at use.  A waiver that expires after the run starts
    is reported as unapplied instead of being honored.  Rows are never turned
    into ``COMPLETE`` and findings are never inspected or changed here.
    """

    rows = [row for row in coverage_rows if isinstance(row, dict)]
    current = _now(now)
    expires = _parse_timestamp(document.get("expires_at"), "expires_at")
    if expires <= current:
        return [], [{"target": dict(target), "status": "EXPIRED_AT_USE"} for target in document.get("waivers", [])]
    source_sha256 = document.get("source_sha256")
    if not isinstance(source_sha256, str) or re.fullmatch(r"[0-9a-f]{64}", source_sha256) is None:
        raise WaiverError("review waiver source digest is invalid")
    applied: list[dict[str, Any]] = []
    unapplied: list[dict[str, Any]] = []
    for index, target in enumerate(document.get("waivers", [])):
        matches = [row for row in rows if _target_matches(row, target)]
        if not matches:
            unapplied.append({"target": dict(target), "status": "NO_MATCHING_INCOMPLETE_OBLIGATION"})
            continue
        record = {
            "waiver_id": _waiver_id(source_sha256, target, index),
            "target": dict(target),
            "reviewer": document["reviewer"],
            "reason": document["reason"],
            "justification": target["justification"],
            "issued_at": document["issued_at"],
            "expires_at": document["expires_at"],
            "source_sha256": source_sha256,
            "obligation_ids": [row.get("obligation_id") for row in matches],
        }
        for row in matches:
            row["waived_from_state"] = row.get("state")
            row["waived_from_reason_code"] = row.get("reason_code")
            row["state"] = "WAIVED"
            row["reason_code"] = "WAIVED"
            row["waiver"] = {
                "waiver_id": record["waiver_id"],
                "reviewer": record["reviewer"],
                "reason": record["reason"],
                "justification": record["justification"],
                "expires_at": record["expires_at"],
                "source_sha256": record["source_sha256"],
                "target": record["target"],
            }
        applied.append(record)
    return applied, unapplied


def build_waiver_receipt(
    document: Mapping[str, Any] | None,
    applied: Iterable[Mapping[str, Any]],
    unapplied: Iterable[Mapping[str, Any]],
) -> dict[str, Any] | None:
    """Build the bounded receipt embedded in the review result."""

    if document is None:
        return None
    applied_rows = [dict(item) for item in applied]
    unapplied_rows = [dict(item) for item in unapplied]
    return {
        "schema": RECEIPT_SCHEMA,
        "waiver_schema": WAIVER_SCHEMA,
        "source_sha256": document.get("source_sha256"),
        "reviewer": document.get("reviewer"),
        "reason": document.get("reason"),
        "repository": document.get("repository"),
        "base_sha": document.get("base_sha"),
        "head_sha": document.get("head_sha"),
        "issued_at": document.get("issued_at"),
        "expires_at": document.get("expires_at"),
        "applied_count": len(applied_rows),
        "waived_obligation_count": sum(len(item.get("obligation_ids", [])) for item in applied_rows),
        "unapplied_target_count": len(unapplied_rows),
    }
