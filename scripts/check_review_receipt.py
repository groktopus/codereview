#!/usr/bin/env python3
"""Validate the merge-review receipt carried in a pull request body.

This script is the CI half of the protocol documented in
``docs/REVIEW-EVIDENCE.md``. It reads only the pull request event JSON named by
``GITHUB_EVENT_PATH`` (or ``--event``), extracts the fenced ``review-receipt``
block from ``pull_request.body``, and validates it against the
``review-receipt.v1`` schema.

It does not execute pull request code, read the pull request checkout, contact
the network, post a review, or approve anything. The event path is the only
file it reads. Diagnostics are deterministic and every failure carries a stable
code.

``decision_records`` is optional here: GA-2 enforcement
(``scripts/check_decision_record_links.py``) is what requires it when a pull
request changes a path listed in ``docs/adr/safety-invariants.json``.

Exit codes
----------
0   receipt accepted (verdict CLEAR for the exact pull request head)
1   unexpected internal error
2   event unavailable or malformed (path, JSON, pull request identity)
3   receipt block missing, duplicated, unclosed, oversized, or not JSON
4   receipt schema or field validation failed (including unknown fields)
5   placeholder or template text was left in a required field
6   reviewed_sha does not equal the pull request head SHA
7   verdict is NOT CLEAR (or anything other than CLEAR)
8   self-review is undeclared or inconsistent with the recorded reviewer
9   agent reviewer is missing a recorded identity/protocol

Usage
-----
    python3 scripts/check_review_receipt.py --event pull_request.json
    python3 scripts/check_review_receipt.py --event pull_request.json --json
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

SCHEMA_ID = "review-receipt.v1"
RECEIPT_INFO = "review-receipt"
MAX_EVENT_BYTES = 2_000_000
MAX_RECEIPT_BYTES = 64_000
MAX_SCOPE_ITEMS = 50
MAX_EVIDENCE_ITEMS = 50
MAX_DECISION_RECORDS = 10
MIN_INDEPENDENCE_CHARS = 20
MIN_POST_MERGE_CHARS = 10

FENCE_RE = re.compile(r"^(?P<indent>[ \t]*)(?P<marker>`{3,}|~{3,})(?P<info>.*)$")
SHA_RE = re.compile(r"[0-9a-f]{40}\Z")
PLACEHOLDER_RE = re.compile(
    r"(?:<[^>\n]*>|\{\{[^}\n]*\}\}|\b(?:todo|tbd|fixme|placeholder|replace[-_ ]?me|your[-_ ](?:name|identity))\b)",
    re.IGNORECASE,
)

ROOT_FIELDS = {
    "schema",
    "reviewer",
    "reviewed_sha",
    "independence",
    "scope",
    "verdict",
    "evidence",
    "reviewed_at",
    "self_review",
    "post_merge_verification",
    "decision_records",
}
REVIEWER_FIELDS = {"identity", "kind", "protocol"}
EVIDENCE_FIELDS = {"kind", "value"}
REVIEWER_KINDS = {"human", "agent"}
VERDICTS = {"CLEAR", "NOT CLEAR"}
DECISION_RECORD_ID_RE = re.compile(r"\d{4}\Z")
DECISION_RECORD_PATH_RE = re.compile(r"docs/adr/\d{4}-[a-z0-9][a-z0-9-]*\.md\Z")
DECISION_RECORD_URL_RE = re.compile(
    r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/blob/\S+/docs/adr/\d{4}-[a-z0-9][a-z0-9-]*\.md\Z"
)

EXIT_INTERNAL = 1
EXIT_EVENT = 2
EXIT_RECEIPT = 3
EXIT_FIELD = 4
EXIT_PLACEHOLDER = 5
EXIT_SHA = 6
EXIT_VERDICT = 7
EXIT_SELF_REVIEW = 8
EXIT_AGENT = 9

CODE_EXITS = {
    "EVENT_PATH_MISSING": EXIT_EVENT,
    "EVENT_PATH_UNREADABLE": EXIT_EVENT,
    "EVENT_TOO_LARGE": EXIT_EVENT,
    "EVENT_INVALID_JSON": EXIT_EVENT,
    "EVENT_INVALID_SHAPE": EXIT_EVENT,
    "EVENT_HEAD_UNKNOWN": EXIT_EVENT,
    "EVENT_AUTHOR_UNKNOWN": EXIT_EVENT,
    "RECEIPT_MISSING": EXIT_RECEIPT,
    "RECEIPT_DUPLICATE": EXIT_RECEIPT,
    "RECEIPT_DUPLICATE_KEY": EXIT_RECEIPT,
    "RECEIPT_UNCLOSED": EXIT_RECEIPT,
    "RECEIPT_TOO_LARGE": EXIT_RECEIPT,
    "RECEIPT_NOT_JSON": EXIT_RECEIPT,
    "RECEIPT_NOT_OBJECT": EXIT_RECEIPT,
    "FIELD_MISSING": EXIT_FIELD,
    "FIELD_TYPE": EXIT_FIELD,
    "FIELD_EMPTY": EXIT_FIELD,
    "FIELD_INVALID": EXIT_FIELD,
    "FIELD_UNKNOWN": EXIT_FIELD,
    "PLACEHOLDER": EXIT_PLACEHOLDER,
    "SHA_MISMATCH": EXIT_SHA,
    "VERDICT_NOT_CLEAR": EXIT_VERDICT,
    "SELF_REVIEW_UNDECLARED": EXIT_SELF_REVIEW,
    "SELF_REVIEW_INCONSISTENT": EXIT_SELF_REVIEW,
    "AGENT_PROTOCOL_MISSING": EXIT_AGENT,
}


@dataclass(frozen=True)
class Failure:
    code: str
    message: str

    @property
    def exit_code(self) -> int:
        return CODE_EXITS.get(self.code, EXIT_INTERNAL)

    def as_dict(self) -> dict[str, str]:
        return {"code": self.code, "message": self.message}


@dataclass(frozen=True)
class Receipt:
    reviewer_identity: str
    reviewer_kind: str
    reviewer_protocol: str | None
    reviewed_sha: str
    independence: str
    scope: tuple[str, ...]
    verdict: str
    evidence: tuple[dict[str, str], ...]
    reviewed_at: str
    self_review: bool
    post_merge_verification: str
    decision_records: tuple[str, ...] | None = None


@dataclass(frozen=True)
class Report:
    failures: tuple[Failure, ...]
    head_sha: str | None
    reviewer_identity: str | None
    reviewed_sha: str | None
    verdict: str | None
    decision_records: tuple[str, ...] | None = None

    @property
    def ok(self) -> bool:
        return not self.failures

    @property
    def exit_code(self) -> int:
        return self.failures[0].exit_code if self.failures else 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA_ID,
            "status": "PASS" if self.ok else "FAIL",
            "exit_code": self.exit_code,
            "head_sha": self.head_sha,
            "reviewed_sha": self.reviewed_sha,
            "reviewer_identity": self.reviewer_identity,
            "verdict": self.verdict,
            "decision_records": list(self.decision_records) if self.decision_records is not None else None,
            "failures": [failure.as_dict() for failure in self.failures],
        }


def extract_receipt_blocks(body: str) -> tuple[list[str], bool]:
    """Return (receipt block bodies, unclosed flag) for fenced review-receipt blocks."""

    lines = body.splitlines()
    blocks: list[str] = []
    unclosed = False
    index = 0
    while index < len(lines):
        opening = FENCE_RE.match(lines[index])
        if opening is None:
            index += 1
            continue
        marker = opening.group("marker")
        info = opening.group("info").strip()
        fence_char = marker[0]
        fence_length = len(marker)
        closing = re.compile(rf"^[ \t]*{re.escape(fence_char)}{{{fence_length},}}[ \t]*$")
        cursor = index + 1
        content: list[str] = []
        closed = False
        while cursor < len(lines):
            if closing.match(lines[cursor]):
                closed = True
                break
            content.append(lines[cursor])
            cursor += 1
        is_receipt = info.split()[0] == RECEIPT_INFO if info else False
        if is_receipt:
            if closed:
                blocks.append("\n".join(content))
            else:
                unclosed = True
            index = cursor + 1 if closed else len(lines)
            continue
        index = cursor + 1 if closed else len(lines)
    return blocks, unclosed


def _failure(code: str, message: str) -> Failure:
    return Failure(code=code, message=message)


def _string(
    container: dict[str, Any],
    key: str,
    path: str,
    failures: list[Failure],
    *,
    minimum: int = 1,
    maximum: int = 4000,
) -> str | None:
    if key not in container:
        failures.append(_failure("FIELD_MISSING", f"{path}.{key} is required"))
        return None
    value = container[key]
    if not isinstance(value, str):
        failures.append(_failure("FIELD_TYPE", f"{path}.{key} must be a string"))
        return None
    text = value.strip()
    if len(text) < minimum:
        failures.append(_failure("FIELD_EMPTY", f"{path}.{key} is empty"))
        return None
    if len(text) > maximum:
        failures.append(_failure("FIELD_INVALID", f"{path}.{key} exceeds {maximum} characters"))
        return None
    return text


def _string_list(
    container: dict[str, Any],
    key: str,
    path: str,
    failures: list[Failure],
    *,
    maximum_items: int,
) -> tuple[str, ...] | None:
    if key not in container:
        failures.append(_failure("FIELD_MISSING", f"{path}.{key} is required"))
        return None
    value = container[key]
    if not isinstance(value, list):
        failures.append(_failure("FIELD_TYPE", f"{path}.{key} must be a list of strings"))
        return None
    if not value:
        failures.append(_failure("FIELD_EMPTY", f"{path}.{key} must list at least one item"))
        return None
    if len(value) > maximum_items:
        failures.append(_failure("FIELD_INVALID", f"{path}.{key} exceeds {maximum_items} items"))
        return None
    items: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item.strip():
            failures.append(_failure("FIELD_INVALID", f"{path}.{key}[{index}] must be a non-empty string"))
            return None
        items.append(item.strip())
    return tuple(items)


def _validate_evidence(
    container: dict[str, Any],
    path: str,
    failures: list[Failure],
) -> tuple[dict[str, str], ...] | None:
    if "evidence" not in container:
        failures.append(_failure("FIELD_MISSING", f"{path}.evidence is required"))
        return None
    value = container["evidence"]
    if not isinstance(value, list):
        failures.append(_failure("FIELD_TYPE", f"{path}.evidence must be a list"))
        return None
    if not value:
        failures.append(_failure("FIELD_EMPTY", f"{path}.evidence must list at least one link or command"))
        return None
    if len(value) > MAX_EVIDENCE_ITEMS:
        failures.append(_failure("FIELD_INVALID", f"{path}.evidence exceeds {MAX_EVIDENCE_ITEMS} items"))
        return None
    evidence: list[dict[str, str]] = []
    for index, item in enumerate(value):
        item_path = f"{path}.evidence[{index}]"
        if not isinstance(item, dict):
            failures.append(_failure("FIELD_TYPE", f"{item_path} must be an object"))
            return None
        unknown = sorted(set(item) - EVIDENCE_FIELDS)
        if unknown:
            failures.append(_failure("FIELD_UNKNOWN", f"{item_path} has unknown fields: {', '.join(unknown)}"))
            return None
        kind = item.get("kind")
        if kind not in {"link", "command"}:
            failures.append(_failure("FIELD_INVALID", f"{item_path}.kind must be 'link' or 'command'"))
            return None
        text = item.get("value")
        if not isinstance(text, str) or not text.strip():
            failures.append(_failure("FIELD_INVALID", f"{item_path}.value must be a non-empty string"))
            return None
        text = text.strip()
        if kind == "link" and not text.startswith(("https://", "http://")):
            failures.append(_failure("FIELD_INVALID", f"{item_path}.value must be an http(s) URL"))
            return None
        if "\n" in text:
            failures.append(_failure("FIELD_INVALID", f"{item_path}.value must be a single line"))
            return None
        evidence.append({"kind": kind, "value": text})
    return tuple(evidence)


def is_decision_record_reference(value: str) -> bool:
    """True when ``value`` names a decision record by ID, path, or repository link."""

    return bool(
        DECISION_RECORD_ID_RE.match(value)
        or DECISION_RECORD_PATH_RE.match(value)
        or DECISION_RECORD_URL_RE.match(value)
    )


def _validate_decision_records(
    container: dict[str, Any],
    path: str,
    failures: list[Failure],
) -> tuple[str, ...] | None:
    """Validate the optional ``decision_records`` list (GA-2).

    The field is optional here; ``scripts/check_decision_record_links.py``
    requires it when a pull request changes a safety-invariant path. When it is
    present it must be a non-empty list of single-line record references, so an
    empty list cannot stand in for "no decision record needed".
    """

    key = "decision_records"
    if key not in container:
        return None
    value = container[key]
    if not isinstance(value, list):
        failures.append(_failure("FIELD_TYPE", f"{path}.{key} must be a list of decision-record IDs or links"))
        return None
    if not value:
        failures.append(
            _failure("FIELD_EMPTY", f"{path}.{key} must not be empty; omit it when no decision record is required")
        )
        return None
    if len(value) > MAX_DECISION_RECORDS:
        failures.append(_failure("FIELD_INVALID", f"{path}.{key} exceeds {MAX_DECISION_RECORDS} items"))
        return None
    references: list[str] = []
    for index, item in enumerate(value):
        item_path = f"{path}.{key}[{index}]"
        if not isinstance(item, str) or not item.strip():
            failures.append(_failure("FIELD_INVALID", f"{item_path} must be a non-empty string"))
            return None
        text = item.strip()
        if len(text) > 300:
            failures.append(_failure("FIELD_INVALID", f"{item_path} exceeds 300 characters"))
            return None
        if "\n" in text or "\r" in text or "\t" in text:
            failures.append(_failure("FIELD_INVALID", f"{item_path} must be a single line"))
            return None
        if not is_decision_record_reference(text):
            failures.append(
                _failure(
                    "FIELD_INVALID",
                    f"{item_path} must be a four-digit record ID (for example 0002), a docs/adr/NNNN-*.md path, "
                    "or an https link to that file",
                )
            )
            return None
        references.append(text)
    return tuple(references)


def _validate_timestamp(value: str | None, failures: list[Failure]) -> str | None:
    if value is None:
        return None
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        failures.append(_failure("FIELD_INVALID", "reviewed_at must be an ISO 8601 timestamp"))
        return None
    if parsed.tzinfo is None:
        failures.append(_failure("FIELD_INVALID", "reviewed_at must include a time zone (for example Z)"))
        return None
    return value


def validate_receipt(receipt: Any) -> tuple[list[Failure], Receipt | None]:
    """Validate the decoded receipt object against review-receipt.v1."""

    failures: list[Failure] = []
    if not isinstance(receipt, dict):
        return [_failure("RECEIPT_NOT_OBJECT", "receipt must be a JSON object")], None

    unknown = sorted(set(receipt) - ROOT_FIELDS)
    if unknown:
        failures.append(_failure("FIELD_UNKNOWN", f"receipt has unknown fields: {', '.join(unknown)}"))

    schema = _string(receipt, "schema", "receipt", failures, maximum=64)
    if schema is not None and schema != SCHEMA_ID:
        failures.append(_failure("FIELD_INVALID", f"receipt.schema must be {SCHEMA_ID!r}"))

    reviewer = receipt.get("reviewer")
    reviewer_identity: str | None = None
    reviewer_kind: str | None = None
    reviewer_protocol: str | None = None
    if "reviewer" not in receipt:
        failures.append(_failure("FIELD_MISSING", "receipt.reviewer is required"))
    elif not isinstance(reviewer, dict):
        failures.append(_failure("FIELD_TYPE", "receipt.reviewer must be an object"))
    else:
        reviewer_unknown = sorted(set(reviewer) - REVIEWER_FIELDS)
        if reviewer_unknown:
            failures.append(
                _failure("FIELD_UNKNOWN", f"receipt.reviewer has unknown fields: {', '.join(reviewer_unknown)}")
            )
        reviewer_identity = _string(reviewer, "identity", "receipt.reviewer", failures, maximum=200)
        reviewer_kind = _string(reviewer, "kind", "receipt.reviewer", failures, maximum=16)
        if reviewer_kind is not None and reviewer_kind not in REVIEWER_KINDS:
            failures.append(_failure("FIELD_INVALID", "receipt.reviewer.kind must be 'human' or 'agent'"))
        if "protocol" in reviewer:
            if not isinstance(reviewer["protocol"], str):
                failures.append(_failure("FIELD_TYPE", "receipt.reviewer.protocol must be a string"))
            else:
                protocol_text = reviewer["protocol"].strip()
                reviewer_protocol = protocol_text or None

    reviewed_sha = _string(receipt, "reviewed_sha", "receipt", failures, maximum=64)
    if reviewed_sha is not None and not SHA_RE.match(reviewed_sha):
        failures.append(_failure("FIELD_INVALID", "receipt.reviewed_sha must be a full 40-character lowercase hex SHA"))

    independence = _string(receipt, "independence", "receipt", failures, minimum=MIN_INDEPENDENCE_CHARS, maximum=4000)
    scope = _string_list(receipt, "scope", "receipt", failures, maximum_items=MAX_SCOPE_ITEMS)

    verdict = _string(receipt, "verdict", "receipt", failures, maximum=16)
    if verdict is not None and verdict not in VERDICTS:
        failures.append(_failure("FIELD_INVALID", "receipt.verdict must be 'CLEAR' or 'NOT CLEAR'"))

    evidence = _validate_evidence(receipt, "receipt", failures)
    reviewed_at = _validate_timestamp(_string(receipt, "reviewed_at", "receipt", failures, maximum=64), failures)

    self_review_value = receipt.get("self_review")
    if "self_review" not in receipt:
        failures.append(_failure("FIELD_MISSING", "receipt.self_review is required"))
        self_review: bool | None = None
    elif not isinstance(self_review_value, bool):
        failures.append(_failure("FIELD_TYPE", "receipt.self_review must be true or false"))
        self_review = None
    else:
        self_review = self_review_value

    post_merge = _string(
        receipt,
        "post_merge_verification",
        "receipt",
        failures,
        minimum=MIN_POST_MERGE_CHARS,
        maximum=4000,
    )
    decision_records = _validate_decision_records(receipt, "receipt", failures)

    if failures:
        return failures, None

    assert reviewer_identity is not None
    assert reviewer_kind is not None
    assert reviewed_sha is not None
    assert independence is not None
    assert scope is not None
    assert verdict is not None
    assert evidence is not None
    assert reviewed_at is not None
    assert self_review is not None
    assert post_merge is not None
    return [], Receipt(
        reviewer_identity=reviewer_identity,
        reviewer_kind=reviewer_kind,
        reviewer_protocol=reviewer_protocol,
        reviewed_sha=reviewed_sha,
        independence=independence,
        scope=scope,
        verdict=verdict,
        evidence=evidence,
        reviewed_at=reviewed_at,
        self_review=self_review,
        post_merge_verification=post_merge,
        decision_records=decision_records,
    )


def _placeholder_failures(receipt: Receipt) -> list[Failure]:
    values: list[tuple[str, str]] = [
        ("receipt.reviewer.identity", receipt.reviewer_identity),
        ("receipt.independence", receipt.independence),
        ("receipt.post_merge_verification", receipt.post_merge_verification),
    ]
    if receipt.reviewer_protocol:
        values.append(("receipt.reviewer.protocol", receipt.reviewer_protocol))
    values.extend((f"receipt.scope[{index}]", item) for index, item in enumerate(receipt.scope))
    values.extend((f"receipt.evidence[{index}].value", item["value"]) for index, item in enumerate(receipt.evidence))
    if receipt.decision_records:
        values.extend(
            (f"receipt.decision_records[{index}]", item) for index, item in enumerate(receipt.decision_records)
        )
    failures: list[Failure] = []
    for path, value in values:
        if PLACEHOLDER_RE.search(value):
            failures.append(_failure("PLACEHOLDER", f"{path} still contains placeholder or template text"))
    return failures


class DuplicateKeyError(ValueError):
    """A JSON object contained the same key more than once."""


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKeyError(key)
        result[key] = value
    return result


def validate_event(event: Any) -> Report:
    """Validate a decoded pull request event. Pure function; reads nothing."""

    if not isinstance(event, dict):
        return Report((_failure("EVENT_INVALID_SHAPE", "event must be a JSON object"),), None, None, None, None)
    pull_request = event.get("pull_request")
    if not isinstance(pull_request, dict):
        return Report(
            (_failure("EVENT_INVALID_SHAPE", "event.pull_request must be an object"),), None, None, None, None
        )

    head = pull_request.get("head")
    head_sha = head.get("sha") if isinstance(head, dict) else None
    if not isinstance(head_sha, str) or not SHA_RE.match(head_sha):
        return Report(
            (_failure("EVENT_HEAD_UNKNOWN", "event.pull_request.head.sha must be a full 40-character hex SHA"),),
            None,
            None,
            None,
            None,
        )

    user = pull_request.get("user")
    author = user.get("login") if isinstance(user, dict) else None
    if not isinstance(author, str) or not author.strip():
        return Report(
            (_failure("EVENT_AUTHOR_UNKNOWN", "event.pull_request.user.login is required"),),
            head_sha,
            None,
            None,
            None,
        )

    body = pull_request.get("body")
    if body is None:
        body = ""
    if not isinstance(body, str):
        return Report(
            (_failure("EVENT_INVALID_SHAPE", "event.pull_request.body must be a string"),),
            head_sha,
            None,
            None,
            None,
        )
    if len(body.encode("utf-8")) > MAX_EVENT_BYTES:
        return Report(
            (_failure("EVENT_TOO_LARGE", "pull request body is too large to validate"),),
            head_sha,
            None,
            None,
            None,
        )

    blocks, unclosed = extract_receipt_blocks(body)
    if unclosed:
        return Report(
            (_failure("RECEIPT_UNCLOSED", "a review-receipt fence is not closed"),), head_sha, None, None, None
        )
    if not blocks:
        return Report(
            (
                _failure(
                    "RECEIPT_MISSING",
                    "pull request body has no fenced review-receipt block (see docs/REVIEW-EVIDENCE.md)",
                ),
            ),
            head_sha,
            None,
            None,
            None,
        )
    if len(blocks) > 1:
        return Report(
            (_failure("RECEIPT_DUPLICATE", "pull request body has more than one review-receipt block"),),
            head_sha,
            None,
            None,
            None,
        )

    raw = blocks[0]
    if len(raw.encode("utf-8")) > MAX_RECEIPT_BYTES:
        return Report((_failure("RECEIPT_TOO_LARGE", "review-receipt block is too large"),), head_sha, None, None, None)
    try:
        decoded = json.loads(raw, object_pairs_hook=_reject_duplicate_keys)
    except DuplicateKeyError:
        return Report(
            (_failure("RECEIPT_DUPLICATE_KEY", "review-receipt JSON repeats an object key"),),
            head_sha,
            None,
            None,
            None,
        )
    except json.JSONDecodeError as exc:
        return Report(
            (_failure("RECEIPT_NOT_JSON", f"review-receipt block is not valid JSON: {exc.msg}"),),
            head_sha,
            None,
            None,
            None,
        )

    failures, receipt = validate_receipt(decoded)
    if receipt is None:
        return Report(tuple(failures), head_sha, None, None, None)

    failures.extend(_placeholder_failures(receipt))
    if receipt.reviewed_sha != head_sha:
        failures.append(
            _failure(
                "SHA_MISMATCH",
                f"reviewed_sha {receipt.reviewed_sha} does not equal pull request head {head_sha}",
            )
        )
    if receipt.verdict != "CLEAR":
        failures.append(_failure("VERDICT_NOT_CLEAR", f"review verdict is {receipt.verdict!r}; only CLEAR can pass"))

    is_self_review = receipt.reviewer_identity.casefold() == author.strip().casefold()
    if is_self_review and not receipt.self_review:
        failures.append(
            _failure(
                "SELF_REVIEW_UNDECLARED",
                "reviewer matches the pull request author; record self_review=true and state the limitation",
            )
        )
    if not is_self_review and receipt.self_review:
        failures.append(
            _failure(
                "SELF_REVIEW_INCONSISTENT",
                "self_review=true but reviewer identity differs from the pull request author",
            )
        )

    if receipt.reviewer_kind == "agent" and not receipt.reviewer_protocol:
        failures.append(
            _failure(
                "AGENT_PROTOCOL_MISSING",
                "agent reviewers must record reviewer.protocol (identity, harness, model, and review protocol)",
            )
        )

    return Report(
        tuple(failures),
        head_sha,
        receipt.reviewer_identity,
        receipt.reviewed_sha,
        receipt.verdict,
        receipt.decision_records,
    )


def load_event(path: Path | None) -> tuple[Any, list[Failure]]:
    if path is None:
        return None, [_failure("EVENT_PATH_MISSING", "GITHUB_EVENT_PATH is not set; pass --event PATH")]
    if not path.is_file():
        return None, [_failure("EVENT_PATH_MISSING", f"event file not found: {path}")]
    try:
        raw = path.read_bytes()
    except OSError as exc:
        return None, [_failure("EVENT_PATH_UNREADABLE", f"cannot read event file: {exc}")]
    if len(raw) > MAX_EVENT_BYTES:
        return None, [_failure("EVENT_TOO_LARGE", "event file is too large to validate")]
    try:
        return json.loads(raw.decode("utf-8")), []
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        return None, [_failure("EVENT_INVALID_JSON", f"event file is not valid JSON: {exc}")]


def check(event_path: Path | None) -> Report:
    event, failures = load_event(event_path)
    if failures:
        return Report(tuple(failures), None, None, None, None)
    return validate_event(event)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate a pull request review receipt.")
    parser.add_argument(
        "--event",
        type=Path,
        default=None,
        help="Path to the pull request event JSON (defaults to GITHUB_EVENT_PATH).",
    )
    parser.add_argument("--json", action="store_true", help="Emit the machine-readable report on stdout.")
    args = parser.parse_args(argv)

    event_path = args.event
    if event_path is None:
        env_path = os.environ.get("GITHUB_EVENT_PATH")
        event_path = Path(env_path) if env_path else None

    report = check(event_path)

    if args.json:
        print(json.dumps(report.as_dict(), indent=2, sort_keys=True))
    elif report.ok:
        print(
            "review-receipt: PASS "
            f"reviewer={str(report.reviewer_identity).replace(chr(10), ' ').replace(chr(13), ' ')} reviewed_sha={report.reviewed_sha} verdict={report.verdict}"
        )
    else:
        for failure in report.failures:
            print(f"review-receipt: ERROR {failure.code}: {failure.message}", file=sys.stderr)
        print(f"review-receipt: FAIL ({len(report.failures)} problem(s))", file=sys.stderr)

    return report.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
