import hashlib
import json
from datetime import datetime, timezone

import pytest

from pr_review_harness.publication_receipts import (
    AttemptReceipt,
    EffectSlot,
    HistoryScan,
    HistoryStatus,
    ReceiptAcknowledgement,
    ReceiptContractError,
    ReceiptPersistence,
    ReceiptPersistenceStatus,
    RunIdentity,
    ScanLimits,
)


def h(value):
    return hashlib.sha256(value.encode()).hexdigest()


def run(run_id, workflow_id):
    return RunIdentity(
        repository_id=1234,
        workflow_id=workflow_id,
        workflow_path=".github/workflows/pr-publish.yml",
        workflow_ref="refs/heads/main",
        workflow_sha="c" * 40,
        run_id=run_id,
        run_attempt=1,
    )


def receipt():
    return AttemptReceipt(
        slot=EffectSlot(1234, "owner/repo", 8, "a" * 40),
        effect_key="effect-" + "1" * 64,
        result_hash=h("result"),
        review_body_hash=h("body"),
        disposition="COMMENT",
        review_event="COMMENT",
        actor_login="review-bot[bot]",
        profile_hash=h("profile"),
        upstream_run=run(101, 10),
        publisher_run=run(202, 20),
    )


def test_receipt_round_trip_is_compact_and_binds_run_slot_and_state():
    original = receipt()
    parsed = AttemptReceipt.from_bytes(original.to_bytes())
    assert parsed == original
    value = json.loads(original.to_bytes())
    assert value["state"] == "SUBMISSION_STARTED"
    assert value["slot_key"] == original.slot.key
    assert value["publisher_run"]["run_id"] == 202
    assert "review body" not in original.to_bytes().decode()


def test_actions_receipt_v2_binds_declared_workflow_provenance_without_claiming_write_capability():
    provenance = {
        "schema": "publisher-credential-provenance.v1",
        "credential_kind": "ACTIONS_TOKEN",
        "identity_state": "PLATFORM_BOUND",
        "permission_basis": "WORKFLOW_DECLARATION",
        "write_capability": "NOT_TESTED",
        "publisher_workflow_sha256": h("workflow"),
        "declared_job_permissions": {"actions": "read", "contents": "read", "pull-requests": "write"},
    }
    original = AttemptReceipt(
        **{
            key: value
            for key, value in receipt().__dict__.items()
            if key not in {"protocol_version", "schema_version", "credential_provenance"}
        },
        credential_provenance=provenance,
        protocol_version="actions-receipt-v2",
    )
    encoded = original.to_bytes()
    parsed = AttemptReceipt.from_bytes(encoded)
    assert parsed == original
    assert json.loads(encoded)["credential_provenance"] == provenance
    assert json.loads(encoded)["credential_provenance"]["write_capability"] == "NOT_TESTED"

    value = json.loads(encoded)
    del value["credential_provenance"]
    with pytest.raises(ReceiptContractError, match="fields"):
        AttemptReceipt.from_bytes(json.dumps(value).encode())
    value = json.loads(encoded)
    value["credential_provenance"]["declared_job_permissions"]["contents"] = "write"
    with pytest.raises(ReceiptContractError, match="provenance"):
        AttemptReceipt.from_bytes(json.dumps(value).encode())


def test_slot_key_is_stable_per_numeric_repository_pr_head_not_result():
    slot = receipt().slot
    assert slot.key == EffectSlot(1234, "owner/repo", 8, "a" * 40).key
    assert slot.key != EffectSlot(9999, "owner/repo", 8, "a" * 40).key
    assert slot.key != EffectSlot(1234, "owner/repo", 8, "b" * 40).key


@pytest.mark.parametrize(
    "value",
    [
        {"repository_id": True, "repository": "owner/repo", "pull_request_number": 1, "head_sha": "a" * 40},
        {"repository_id": 1, "repository": "owner/repo", "pull_request_number": 1, "head_sha": "a" * 41},
    ],
)
def test_slot_rejects_bool_ids_and_non_git_sha_lengths(value):
    with pytest.raises(ReceiptContractError):
        EffectSlot(**value)


def test_receipt_parser_rejects_duplicate_unknown_or_tampered_fields():
    raw = receipt().to_bytes()
    with pytest.raises(ReceiptContractError, match="JSON"):
        AttemptReceipt.from_bytes(
            raw.replace(b'"state":"SUBMISSION_STARTED"', b'"state":"SUBMISSION_STARTED","state":"SUBMISSION_STARTED"')
        )
    value = json.loads(raw)
    value["slot_key"] = "slot-" + "0" * 64
    with pytest.raises(ReceiptContractError, match="inconsistent"):
        AttemptReceipt.from_bytes(json.dumps(value).encode())
    value = json.loads(raw)
    value["extra"] = "not allowed"
    with pytest.raises(ReceiptContractError, match="fields"):
        AttemptReceipt.from_bytes(json.dumps(value).encode())
    with pytest.raises(ReceiptContractError, match="byte limit"):
        AttemptReceipt.from_bytes(b" " * 16385)


def test_history_incomplete_is_explicit_and_has_safe_reason_code():
    scan = HistoryScan(HistoryStatus.INCOMPLETE, reason_code="pagination_limit", scanned_pages=10)
    assert scan.status is HistoryStatus.INCOMPLETE
    with pytest.raises(ReceiptContractError, match="reason"):
        HistoryScan(HistoryStatus.UNAVAILABLE)
    with pytest.raises(ReceiptContractError, match="reason_code"):
        HistoryScan(HistoryStatus.UNAVAILABLE, reason_code="response body contains token")


def test_limits_reject_bool_and_unbounded_deadline():
    with pytest.raises(ReceiptContractError, match="max_runs"):
        ScanLimits(max_runs=True)
    with pytest.raises(ReceiptContractError, match="deadline"):
        ScanLimits(deadline_seconds=float("inf"))
    with pytest.raises(ReceiptContractError, match="max_pages"):
        ScanLimits(max_pages=0)


def test_publication_admission_accepts_only_exact_bounded_concurrency_scopes():
    from pr_review_harness.publication_receipts import PublicationAdmission

    slot = receipt().slot
    values = {
        "slot": slot,
        "base_sha": "b" * 40,
        "effect_key": "effect-" + "1" * 64,
        "result_hash": h("result"),
        "review_body_hash": h("body"),
        "disposition": "COMMENT",
        "review_event": "COMMENT",
        "actor_login": "review-bot[bot]",
        "profile_hash": h("profile"),
        "policy_hash": h("policy"),
        "source_artifact_sha256": h("artifact"),
        "admission_evidence_hash": h("evidence"),
        "upstream_run": run(101, 10),
        "publisher_run": run(202, 20),
        "concurrency_contract_hash": h("concurrency"),
    }
    default = PublicationAdmission(**values, concurrency_group="pr-review-publish-1234-8")
    assert default.concurrency_scope == "pull_request"
    repository_scope = PublicationAdmission(
        **values,
        concurrency_scope="repository",
        concurrency_group="pr-review-publish-1234",
    )
    assert repository_scope.concurrency_group == "pr-review-publish-1234"

    for scope, group in (
        ("repository", "pr-review-publish-1234-8"),
        ("pull_request", "pr-review-publish-1234"),
        ("organization", "pr-review-publish-1234"),
    ):
        with pytest.raises(ReceiptContractError, match="concurrency"):
            PublicationAdmission(**values, concurrency_scope=scope, concurrency_group=group)


def test_receipt_ack_requires_exact_durable_bytes_and_publisher_run(monkeypatch):
    import pr_review_harness.publication_receipts as receipt_module

    class FixedDateTime(datetime):
        @classmethod
        def now(cls, tz=None):
            current = datetime(2026, 9, 30, 12, tzinfo=timezone.utc)
            return current if tz is not None else current.replace(tzinfo=None)

    monkeypatch.setattr(receipt_module, "datetime", FixedDateTime)
    item = receipt()
    ack = ReceiptAcknowledgement(
        artifact_id=7,
        publisher_run=item.publisher_run,
        archive_sha256=h("archive"),
        receipt_sha256=hashlib.sha256(item.to_bytes()).hexdigest(),
        expires_at="2026-10-01T00:00:00Z",
    )
    persisted = ReceiptPersistence(ReceiptPersistenceStatus.ACKNOWLEDGED, acknowledgement=ack)
    assert persisted.acknowledges(item)
    other_run = ReceiptAcknowledgement(
        artifact_id=7,
        publisher_run=run(203, 20),
        archive_sha256=h("archive"),
        receipt_sha256=hashlib.sha256(item.to_bytes()).hexdigest(),
        expires_at="2026-10-01T00:00:00Z",
    )
    assert not ReceiptPersistence(ReceiptPersistenceStatus.ACKNOWLEDGED, acknowledgement=other_run).acknowledges(item)
    assert not ReceiptPersistence(ReceiptPersistenceStatus.UNKNOWN, reason_code="upload_timeout").acknowledges(item)


def test_receipt_ack_expiry_requires_real_utc_timestamp_and_is_checked_against_now():
    item = receipt()
    ack = ReceiptAcknowledgement(
        artifact_id=8,
        publisher_run=item.publisher_run,
        archive_sha256=h("archive"),
        receipt_sha256=hashlib.sha256(item.to_bytes()).hexdigest(),
        expires_at="2026-10-01T00:00:00Z",
    )
    future = datetime(2026, 9, 26, tzinfo=timezone.utc)
    past = datetime(2026, 10, 2, tzinfo=timezone.utc)
    assert ack.is_unexpired(future)
    assert not ack.is_unexpired(past)
    for timestamp in (
        "2026-10-01",
        "2026-10-01T00:00:00",
        "2026-10-01T00:00:00+01:00",
        "2026-02-30T00:00:00Z",
    ):
        with pytest.raises(ReceiptContractError, match="expires_at"):
            ReceiptAcknowledgement(
                artifact_id=8,
                publisher_run=item.publisher_run,
                archive_sha256=h("archive"),
                receipt_sha256=hashlib.sha256(item.to_bytes()).hexdigest(),
                expires_at=timestamp,
            )
