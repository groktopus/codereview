"""Typed, bounded contracts for GitHub-backed publication attempt receipts.

This module contains no HTTP client or persistence backend. A production adapter
must independently verify GitHub run/artifact metadata before returning a
complete history scan or acknowledging that a receipt artifact is durable.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
from typing import Protocol

_RECEIPT_VERSION = "1.0"
_SHA = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_HEX_64 = re.compile(r"[0-9a-f]{64}\Z")
_REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
_ACTOR = re.compile(r"[A-Za-z0-9-]{1,39}(?:\[bot\])?\Z")
_EFFECT = re.compile(r"effect-[0-9a-f]{64}\Z")
_SAFE_PATH = re.compile(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*\Z")
MAX_RECEIPT_BYTES = 16 * 1024


class HistoryStatus(StrEnum):
    COMPLETE = "COMPLETE"
    INCOMPLETE = "INCOMPLETE"
    UNAVAILABLE = "UNAVAILABLE"


class ReceiptPersistenceStatus(StrEnum):
    ACKNOWLEDGED = "ACKNOWLEDGED"
    REJECTED = "REJECTED"
    UNKNOWN = "UNKNOWN"


class ReviewState(StrEnum):
    APPROVED = "APPROVED"
    CHANGES_REQUESTED = "CHANGES_REQUESTED"
    COMMENTED = "COMMENTED"


class ReceiptContractError(ValueError):
    """A receipt or adapter result does not satisfy the versioned contract."""


def _positive_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _validate_sha(value: object, name: str) -> None:
    if not isinstance(value, str) or not _SHA.fullmatch(value):
        raise ReceiptContractError(f"{name} is invalid")


def _validate_hash(value: object, name: str) -> None:
    if not isinstance(value, str) or not _HEX_64.fullmatch(value):
        raise ReceiptContractError(f"{name} is invalid")


def validate_credential_provenance(value: object) -> dict:
    """Validate declaration provenance without implying effective permission."""
    expected_permissions = {"actions": "read", "contents": "read", "pull-requests": "write"}
    if (
        not isinstance(value, dict)
        or set(value)
        != {
            "schema",
            "credential_kind",
            "identity_state",
            "permission_basis",
            "write_capability",
            "publisher_workflow_sha256",
            "declared_job_permissions",
        }
        or value.get("schema") != "publisher-credential-provenance.v1"
        or value.get("credential_kind") != "ACTIONS_TOKEN"
        or value.get("identity_state") != "PLATFORM_BOUND"
        or value.get("permission_basis") != "WORKFLOW_DECLARATION"
        or value.get("write_capability") != "NOT_TESTED"
        or not isinstance(value.get("publisher_workflow_sha256"), str)
        or not _HEX_64.fullmatch(value["publisher_workflow_sha256"])
        or value.get("declared_job_permissions") != expected_permissions
    ):
        raise ReceiptContractError("credential provenance is invalid")
    return value


@dataclass(frozen=True)
class EffectSlot:
    """Immutable one-head target slot; result hashes are deliberately separate."""

    repository_id: int
    repository: str
    pull_request_number: int
    head_sha: str
    effect_type: str = "PULL_REQUEST_REVIEW"

    def __post_init__(self) -> None:
        if not _positive_int(self.repository_id):
            raise ReceiptContractError("repository_id is invalid")
        if not isinstance(self.repository, str) or not _REPOSITORY.fullmatch(self.repository):
            raise ReceiptContractError("repository is invalid")
        if not _positive_int(self.pull_request_number):
            raise ReceiptContractError("pull_request_number is invalid")
        _validate_sha(self.head_sha, "head_sha")
        if self.effect_type != "PULL_REQUEST_REVIEW":
            raise ReceiptContractError("effect_type is unsupported")

    @property
    def key(self) -> str:
        body = json.dumps(
            {
                "repository_id": self.repository_id,
                "pull_request_number": self.pull_request_number,
                "head_sha": self.head_sha,
                "effect_type": self.effect_type,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
        return "slot-" + hashlib.sha256(body).hexdigest()

    def to_dict(self) -> dict:
        return {
            "repository_id": self.repository_id,
            "repository": self.repository,
            "pull_request_number": self.pull_request_number,
            "head_sha": self.head_sha,
            "effect_type": self.effect_type,
        }


@dataclass(frozen=True)
class RunIdentity:
    """GitHub-derived run identity; adapters must source fields from API records."""

    repository_id: int
    workflow_id: int
    workflow_path: str
    workflow_ref: str
    workflow_sha: str
    run_id: int
    run_attempt: int

    def __post_init__(self) -> None:
        for field_name in ("repository_id", "workflow_id", "run_id", "run_attempt"):
            if not _positive_int(getattr(self, field_name)):
                raise ReceiptContractError(f"{field_name} is invalid")
        if not isinstance(self.workflow_path, str) or not _SAFE_PATH.fullmatch(self.workflow_path):
            raise ReceiptContractError("workflow_path is invalid")
        if not isinstance(self.workflow_ref, str) or not self.workflow_ref or len(self.workflow_ref) > 512:
            raise ReceiptContractError("workflow_ref is invalid")
        _validate_sha(self.workflow_sha, "workflow_sha")

    def to_dict(self) -> dict:
        return {
            "repository_id": self.repository_id,
            "workflow_id": self.workflow_id,
            "workflow_path": self.workflow_path,
            "workflow_ref": self.workflow_ref,
            "workflow_sha": self.workflow_sha,
            "run_id": self.run_id,
            "run_attempt": self.run_attempt,
        }


@dataclass(frozen=True)
class AttemptReceipt:
    """Pre-POST receipt. It records intent, never claims the review was submitted."""

    slot: EffectSlot
    effect_key: str
    result_hash: str
    review_body_hash: str
    disposition: str
    review_event: str
    actor_login: str
    profile_hash: str
    upstream_run: RunIdentity
    publisher_run: RunIdentity
    protocol_version: str = "actions-receipt-v1"
    schema_version: str = _RECEIPT_VERSION
    credential_provenance: dict | None = None

    def __post_init__(self) -> None:
        if self.schema_version != _RECEIPT_VERSION:
            raise ReceiptContractError("receipt schema_version is unsupported")
        if self.credential_provenance is None:
            if self.protocol_version != "actions-receipt-v1":
                raise ReceiptContractError("protocol_version is unsupported")
        else:
            validate_credential_provenance(self.credential_provenance)
            if self.protocol_version != "actions-receipt-v2":
                raise ReceiptContractError("protocol_version is unsupported")
        if not isinstance(self.effect_key, str) or not _EFFECT.fullmatch(self.effect_key):
            raise ReceiptContractError("effect_key is invalid")
        for field_name in ("result_hash", "review_body_hash", "profile_hash"):
            _validate_hash(getattr(self, field_name), field_name)
        if self.disposition not in {"APPROVE", "REQUEST_CHANGES", "COMMENT", "INCOMPLETE"}:
            raise ReceiptContractError("disposition is invalid")
        expected_event = "COMMENT" if self.disposition == "INCOMPLETE" else self.disposition
        if self.review_event != expected_event:
            raise ReceiptContractError("review_event is inconsistent with disposition")
        if not isinstance(self.actor_login, str) or not _ACTOR.fullmatch(self.actor_login):
            raise ReceiptContractError("actor_login is invalid")
        if self.upstream_run.repository_id != self.slot.repository_id:
            raise ReceiptContractError("upstream repository binding is invalid")
        if self.publisher_run.repository_id != self.slot.repository_id:
            raise ReceiptContractError("publisher repository binding is invalid")

    def to_dict(self) -> dict:
        value = {
            "schema_version": self.schema_version,
            "protocol_version": self.protocol_version,
            "slot": self.slot.to_dict(),
            "slot_key": self.slot.key,
            "effect_key": self.effect_key,
            "result_hash": self.result_hash,
            "review_body_hash": self.review_body_hash,
            "disposition": self.disposition,
            "review_event": self.review_event,
            "actor_login": self.actor_login,
            "profile_hash": self.profile_hash,
            "upstream_run": self.upstream_run.to_dict(),
            "publisher_run": self.publisher_run.to_dict(),
            "state": "SUBMISSION_STARTED",
        }
        if self.credential_provenance is not None:
            value["credential_provenance"] = self.credential_provenance
        return value

    def to_bytes(self) -> bytes:
        encoded = json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        if len(encoded) > MAX_RECEIPT_BYTES:
            raise ReceiptContractError("receipt exceeds byte limit")
        return encoded

    @classmethod
    def from_bytes(cls, raw: bytes) -> AttemptReceipt:
        if not isinstance(raw, bytes) or len(raw) > MAX_RECEIPT_BYTES:
            raise ReceiptContractError("receipt input exceeds byte limit")
        try:
            text = raw.decode("utf-8", errors="strict")
            data = json.loads(text, object_pairs_hook=_unique_pairs)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
            raise ReceiptContractError("receipt JSON is invalid") from None
        return _receipt_from_dict(data)


@dataclass(frozen=True)
class ReviewObservation:
    """One independently observed marker review, already bound by the API adapter."""

    slot: EffectSlot
    effect_key: str
    review_body_hash: str
    actor_login: str
    state: ReviewState
    review_id: int

    def __post_init__(self) -> None:
        if not isinstance(self.effect_key, str) or not _EFFECT.fullmatch(self.effect_key):
            raise ReceiptContractError("observed effect_key is invalid")
        _validate_hash(self.review_body_hash, "observed review_body_hash")
        if not isinstance(self.actor_login, str) or not _ACTOR.fullmatch(self.actor_login):
            raise ReceiptContractError("observed actor_login is invalid")
        if not isinstance(self.state, ReviewState):
            raise ReceiptContractError("observed review state is invalid")
        if not _positive_int(self.review_id):
            raise ReceiptContractError("observed review_id is invalid")


@dataclass(frozen=True)
class PublicationAdmission:
    """Capability value from a trusted API adapter after result/run validation.

    The API adapter must construct this only after it has cross-checked the
    result, artifact digest, upstream run, current publisher run and trusted
    publisher policy against GitHub API data. It is deliberately richer than
    a caller-supplied ``authorized=True`` flag.
    """

    slot: EffectSlot
    base_sha: str
    effect_key: str
    result_hash: str
    review_body_hash: str
    disposition: str
    review_event: str
    actor_login: str
    profile_hash: str
    policy_hash: str
    source_artifact_sha256: str
    admission_evidence_hash: str
    upstream_run: RunIdentity
    publisher_run: RunIdentity
    concurrency_group: str
    concurrency_contract_hash: str
    verification_kind: str = "GITHUB_API_RUN_ARTIFACT_V1"
    concurrency_scope: str = "pull_request"
    credential_provenance: dict | None = None

    def __post_init__(self) -> None:
        _validate_sha(self.base_sha, "base_sha")
        if not isinstance(self.effect_key, str) or not _EFFECT.fullmatch(self.effect_key):
            raise ReceiptContractError("admission effect_key is invalid")
        for field_name in (
            "result_hash",
            "review_body_hash",
            "profile_hash",
            "policy_hash",
            "source_artifact_sha256",
            "admission_evidence_hash",
            "concurrency_contract_hash",
        ):
            _validate_hash(getattr(self, field_name), field_name)
        if self.disposition not in {"APPROVE", "REQUEST_CHANGES", "COMMENT", "INCOMPLETE"}:
            raise ReceiptContractError("admission disposition is invalid")
        expected_event = "COMMENT" if self.disposition == "INCOMPLETE" else self.disposition
        if self.review_event != expected_event:
            raise ReceiptContractError("admission review_event is inconsistent")
        if not isinstance(self.actor_login, str) or not _ACTOR.fullmatch(self.actor_login):
            raise ReceiptContractError("admission actor_login is invalid")
        if self.verification_kind != "GITHUB_API_RUN_ARTIFACT_V1":
            raise ReceiptContractError("admission verification is unavailable")
        if self.concurrency_scope == "pull_request":
            expected_group = f"pr-review-publish-{self.slot.repository_id}-{self.slot.pull_request_number}"
        elif self.concurrency_scope == "repository":
            expected_group = f"pr-review-publish-{self.slot.repository_id}"
        else:
            raise ReceiptContractError("admission concurrency scope is invalid")
        if self.concurrency_group != expected_group:
            raise ReceiptContractError("admission concurrency binding is invalid")
        if self.credential_provenance is not None:
            validate_credential_provenance(self.credential_provenance)
        if self.upstream_run.repository_id != self.slot.repository_id:
            raise ReceiptContractError("admission upstream run binding is invalid")
        if self.publisher_run.repository_id != self.slot.repository_id:
            raise ReceiptContractError("admission publisher run binding is invalid")


class PublicationAdmissionProvider(Protocol):
    """Trusted implementation validates and returns exact immutable authority."""

    def admit(self, result: dict, config: dict, limits: ScanLimits) -> PublicationAdmission: ...


@dataclass(frozen=True)
class HistoryScan:
    """Bounded history result; only COMPLETE scans may authorize a new attempt."""

    status: HistoryStatus
    receipts: tuple[AttemptReceipt, ...] = ()
    reviews: tuple[ReviewObservation, ...] = ()
    reason_code: str | None = None
    scanned_runs: int = 0
    scanned_pages: int = 0

    def __post_init__(self) -> None:
        if not isinstance(self.status, HistoryStatus):
            raise ReceiptContractError("history status is invalid")
        if any(not isinstance(item, AttemptReceipt) for item in self.receipts):
            raise ReceiptContractError("history receipts are invalid")
        if any(not isinstance(item, ReviewObservation) for item in self.reviews):
            raise ReceiptContractError("history reviews are invalid")
        if any(
            isinstance(value, bool) or not isinstance(value, int) or value < 0
            for value in (self.scanned_runs, self.scanned_pages)
        ):
            raise ReceiptContractError("history scan counts are invalid")
        if self.status is not HistoryStatus.COMPLETE and not self.reason_code:
            raise ReceiptContractError("incomplete history requires a reason")
        if self.reason_code is not None and (
            not isinstance(self.reason_code, str) or not re.fullmatch(r"[a-z0-9_]{1,64}", self.reason_code)
        ):
            raise ReceiptContractError("history reason_code is invalid")


@dataclass(frozen=True)
class ReceiptAcknowledgement:
    """Proof metadata for a receipt artifact observed as durable on GitHub."""

    artifact_id: int
    publisher_run: RunIdentity
    archive_sha256: str
    receipt_sha256: str
    expires_at: str

    def __post_init__(self) -> None:
        if not _positive_int(self.artifact_id):
            raise ReceiptContractError("artifact_id is invalid")
        _validate_hash(self.archive_sha256, "archive_sha256")
        _validate_hash(self.receipt_sha256, "receipt_sha256")
        _parse_utc_timestamp(self.expires_at)
        if not isinstance(self.publisher_run, RunIdentity):
            raise ReceiptContractError("publisher_run is invalid")

    def is_unexpired(self, now: datetime | None = None) -> bool:
        """Check expiry against an injected UTC clock for deterministic adapters/tests."""
        current = now if now is not None else datetime.now(timezone.utc)
        if current.tzinfo is None or current.utcoffset() is None:
            raise ReceiptContractError("current time must be timezone-aware")
        return _parse_utc_timestamp(self.expires_at) > current.astimezone(timezone.utc)


@dataclass(frozen=True)
class ReceiptPersistence:
    """Typed upload outcome; an acknowledgement must match the exact receipt."""

    status: ReceiptPersistenceStatus
    acknowledgement: ReceiptAcknowledgement | None = None
    reason_code: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.status, ReceiptPersistenceStatus):
            raise ReceiptContractError("receipt persistence status is invalid")
        if self.status is ReceiptPersistenceStatus.ACKNOWLEDGED and not isinstance(
            self.acknowledgement, ReceiptAcknowledgement
        ):
            raise ReceiptContractError("acknowledged receipt requires artifact proof")
        if self.status is not ReceiptPersistenceStatus.ACKNOWLEDGED and self.acknowledgement is not None:
            raise ReceiptContractError("unacknowledged receipt cannot carry artifact proof")
        if self.reason_code is not None and not re.fullmatch(r"[a-z0-9_]{1,64}", self.reason_code):
            raise ReceiptContractError("receipt persistence reason is invalid")

    def acknowledges(self, receipt: AttemptReceipt) -> bool:
        """Return true only when the digest and publisher run bind this receipt."""
        acknowledgement = self.acknowledgement
        if self.status is not ReceiptPersistenceStatus.ACKNOWLEDGED or acknowledgement is None:
            return False
        try:
            receipt_digest = hashlib.sha256(receipt.to_bytes()).hexdigest()
        except ReceiptContractError:
            return False
        return (
            acknowledgement.publisher_run == receipt.publisher_run
            and acknowledgement.receipt_sha256 == receipt_digest
            and acknowledgement.is_unexpired()
        )


@dataclass(frozen=True)
class ScanLimits:
    """Hard read bound supplied by trusted publisher policy."""

    max_runs: int = 100
    max_pages: int = 10
    max_reviews: int = 1000
    deadline_seconds: float = 90.0

    def __post_init__(self) -> None:
        for name in ("max_runs", "max_pages", "max_reviews"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ReceiptContractError(f"{name} is invalid")
        if isinstance(self.deadline_seconds, bool) or not isinstance(self.deadline_seconds, (int, float)):
            raise ReceiptContractError("deadline_seconds is invalid")
        if not 0 < self.deadline_seconds <= 300:
            raise ReceiptContractError("deadline_seconds is invalid")


class PublicationHistoryReader(Protocol):
    """Reads verified GitHub records within the supplied remaining deadline.

    Implementations must pass the supplied deadline through every paginated
    API request and stop before it expires; treating each request as a fresh
    full timeout would violate the caller's end-to-end bound.
    """

    def scan(self, slot: EffectSlot, limits: ScanLimits) -> HistoryScan: ...


class AttemptReceiptWriter(Protocol):
    """Uploads a receipt using only the remaining end-to-end time budget."""

    def persist(self, receipt: AttemptReceipt, limits: ScanLimits) -> ReceiptPersistence: ...


class FreshHeadReader(Protocol):
    """Return the live head SHA, bounded by the supplied remaining seconds."""

    def __call__(self, timeout_seconds: float) -> str: ...


class ReviewSubmitter(Protocol):
    """Submit once with no hidden retries and a caller-bounded timeout."""

    def __call__(self, payload: dict, effect_key: str, timeout_seconds: float) -> ReviewObservation: ...


def _unique_pairs(pairs: list[tuple[str, object]]) -> dict:
    value = {}
    for key, child in pairs:
        if key in value:
            raise ValueError("duplicate key")
        value[key] = child
    return value


def _parse_utc_timestamp(value: object) -> datetime:
    """Parse a strict ISO-8601 UTC timestamp; reject local/naive timestamps."""
    if not isinstance(value, str) or not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)", value
    ):
        raise ReceiptContractError("expires_at is invalid")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
    except ValueError:
        raise ReceiptContractError("expires_at is invalid") from None
    if parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise ReceiptContractError("expires_at must be UTC")
    return parsed.astimezone(timezone.utc)


def _run_from_dict(value: object) -> RunIdentity:
    keys = {
        "repository_id",
        "workflow_id",
        "workflow_path",
        "workflow_ref",
        "workflow_sha",
        "run_id",
        "run_attempt",
    }
    if not isinstance(value, dict) or set(value) != keys:
        raise ReceiptContractError("run identity fields are invalid")
    try:
        return RunIdentity(**value)
    except TypeError:
        raise ReceiptContractError("run identity fields are invalid") from None


def _receipt_from_dict(data: object) -> AttemptReceipt:
    keys = {
        "schema_version",
        "protocol_version",
        "slot",
        "slot_key",
        "effect_key",
        "result_hash",
        "review_body_hash",
        "disposition",
        "review_event",
        "actor_login",
        "profile_hash",
        "upstream_run",
        "publisher_run",
        "state",
    }
    if not isinstance(data, dict) or data.get("state") != "SUBMISSION_STARTED":
        raise ReceiptContractError("receipt fields are invalid")
    protocol_version = data.get("protocol_version")
    if protocol_version == "actions-receipt-v2":
        keys.add("credential_provenance")
    elif protocol_version != "actions-receipt-v1":
        raise ReceiptContractError("receipt protocol is unsupported")
    if set(data) != keys:
        raise ReceiptContractError("receipt fields are invalid")
    slot_value = data.get("slot")
    if not isinstance(slot_value, dict) or set(slot_value) != {
        "repository_id",
        "repository",
        "pull_request_number",
        "head_sha",
        "effect_type",
    }:
        raise ReceiptContractError("receipt slot is invalid")
    try:
        slot = EffectSlot(**slot_value)
    except TypeError:
        raise ReceiptContractError("receipt slot is invalid") from None
    if data.get("slot_key") != slot.key:
        raise ReceiptContractError("receipt slot key is inconsistent")
    return AttemptReceipt(
        slot=slot,
        effect_key=data["effect_key"],
        result_hash=data["result_hash"],
        review_body_hash=data["review_body_hash"],
        disposition=data["disposition"],
        review_event=data["review_event"],
        actor_login=data["actor_login"],
        profile_hash=data["profile_hash"],
        upstream_run=_run_from_dict(data["upstream_run"]),
        publisher_run=_run_from_dict(data["publisher_run"]),
        protocol_version=data["protocol_version"],
        credential_provenance=data.get("credential_provenance"),
        schema_version=data["schema_version"],
    )
