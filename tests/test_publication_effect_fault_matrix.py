"""SE-4 deterministic fake-only matrix for publication effect boundaries."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml
from test_actions_publication import BASE, HEAD, WRITER, make_policy, make_valid_result

from pr_review_harness.publication_receipts import (
    EffectSlot,
    HistoryScan,
    HistoryStatus,
    PublicationAdmission,
    ReceiptAcknowledgement,
    ReceiptPersistence,
    ReceiptPersistenceStatus,
    ReviewObservation,
    ReviewState,
    RunIdentity,
    ScanLimits,
)
from pr_review_harness.publisher import (
    PublicationAdmissionUnavailable,
    _canonical_hash,
    _stateless_effect_key,
    preview_publication,
    publish_review_stateless,
)

ROOT = Path(__file__).resolve().parents[1]
CONFIG = {
    "schema_version": "1.0",
    "enabled": True,
    "allowed_repositories": ["owner/repo"],
    "allowed_dispositions": ["COMMENT"],
    "allowed_profile_versions": ["profile-v3"],
    "allowed_actors": [WRITER],
    "max_review_body_bytes": 60_000,
}


@dataclass(frozen=True)
class FaultCase:
    case_id: str
    fault: str
    terminal: str
    reason: str | None
    posts: int
    receipts: int
    owner: str
    reconciliation_step: str


FAULT_MATRIX = (
    FaultCase(
        "SE4-FM-01",
        "receipt acknowledged before POST",
        "CONFIRMED",
        None,
        1,
        1,
        "publisher operator",
        "verify durable receipt readback precedes the single review POST",
    ),
    FaultCase(
        "SE4-FM-02",
        "ambiguous submit without matching history",
        "UNKNOWN",
        "submit_response_ambiguous",
        1,
        1,
        "publication operator",
        "inspect bounded review history for the exact effect marker; never resubmit automatically",
    ),
    FaultCase(
        "SE4-FM-03",
        "duplicate reviews for the same slot",
        "CONFLICT",
        "multiple_reviews_for_slot",
        0,
        0,
        "publication operator",
        "compare both same-slot reviews and resolve duplicate/conflicting effects manually",
    ),
    FaultCase(
        "SE4-FM-04",
        "timeout after accepted POST",
        "CONFIRMED",
        "confirmed_after_ambiguous_response",
        1,
        1,
        "publication operator",
        "retain the exact matching review-history observation; do not retry",
    ),
    FaultCase(
        "SE4-FM-05",
        "history pagination unavailable",
        "UNKNOWN",
        "github_history_unavailable",
        0,
        0,
        "publication operator",
        "restore complete bounded history evidence before considering a new attempt",
    ),
    FaultCase(
        "SE4-FM-06",
        "stale head after receipt acknowledgement",
        "STALE",
        "head_sha_changed_after_receipt",
        0,
        1,
        "source reviewer",
        "reanalyze the current head and create a new review result; do not reuse this receipt",
    ),
    FaultCase(
        "SE4-FM-07",
        "tampered result artifact",
        "REJECTED",
        "review result hash is invalid",
        0,
        0,
        "source workflow owner",
        "preserve the rejected artifact and regenerate it from the trusted producer",
    ),
    FaultCase(
        "SE4-FM-08",
        "wrong publisher actor",
        "REJECTED",
        "publisher actor is outside authorization scope",
        0,
        0,
        "publisher policy owner",
        "verify the trusted actor identity and policy binding; do not broaden actor scope",
    ),
    FaultCase(
        "SE4-FM-09",
        "insufficient publisher scope",
        "UNKNOWN",
        "publisher_credential_invalid",
        0,
        0,
        "publisher workflow owner",
        "verify the declared minimum permissions and effective capability before any authorized retry",
    ),
)


def _admission(result, *, actor=WRITER):
    policy = make_policy()
    request = preview_publication(result, CONFIG)
    slot = EffectSlot(policy.repository_id, policy.repository, policy.pull_request_number, HEAD)
    effect_key = _stateless_effect_key(
        slot,
        request["result_hash"],
        request["review_body_hash"],
        request["disposition"],
    )
    publisher_run = RunIdentity(
        repository_id=policy.repository_id,
        workflow_id=policy.publisher_workflow_id,
        workflow_path=policy.publisher_workflow_path,
        workflow_ref=policy.publisher_workflow_ref,
        workflow_sha=policy.publisher_workflow_sha,
        run_id=policy.publisher_run_id,
        run_attempt=policy.publisher_run_attempt,
    )
    upstream_run = RunIdentity(
        repository_id=policy.repository_id,
        workflow_id=policy.caller_workflow_id,
        workflow_path=policy.caller_workflow_path,
        workflow_ref=policy.caller_workflow_ref,
        workflow_sha=policy.caller_workflow_sha,
        run_id=policy.upstream_run_id,
        run_attempt=policy.upstream_run_attempt,
    )
    group = f"pr-review-publish-{policy.repository_id}-{policy.pull_request_number}"
    return PublicationAdmission(
        slot=slot,
        base_sha=BASE,
        effect_key=effect_key,
        result_hash=request["result_hash"],
        review_body_hash=request["review_body_hash"],
        disposition=request["disposition"],
        review_event=request["review_event"],
        actor_login=actor,
        profile_hash=policy.profile_sha256,
        policy_hash=_canonical_hash(CONFIG),
        source_artifact_sha256="2" * 64,
        admission_evidence_hash="3" * 64,
        upstream_run=upstream_run,
        publisher_run=publisher_run,
        concurrency_group=group,
        concurrency_contract_hash="4" * 64,
    )


def _review(admission, *, review_id=123):
    return ReviewObservation(
        slot=admission.slot,
        effect_key=admission.effect_key,
        review_body_hash=admission.review_body_hash,
        actor_login=admission.actor_login,
        state=ReviewState.COMMENTED,
        review_id=review_id,
    )


def _matrix_table() -> str:
    lines = [
        "| Matrix ID | Injected fault | Terminal state / reason | Review POSTs | Receipt writes | Reconciliation owner | Required reconciliation step |",
        "|---|---|---|---:|---:|---|---|",
    ]
    for case in FAULT_MATRIX:
        terminal = f"`{case.terminal}`" + (f" / `{case.reason}`" if case.reason else "")
        lines.append(
            f"| {case.case_id} | {case.fault} | {terminal} | {case.posts} | {case.receipts} | "
            f"{case.owner} | {case.reconciliation_step} |"
        )
    return "\n".join(lines)


@pytest.mark.parametrize("case", FAULT_MATRIX, ids=lambda case: case.case_id)
def test_se4_publication_effect_fault_matrix(case: FaultCase):
    """Exercise every named failure using injected in-memory capabilities only."""
    result = make_valid_result()
    if case.case_id == "SE4-FM-07":
        result["report_sections"]["future_guidance"].append("tampered after hashing")

    admission = (
        None
        if case.case_id == "SE4-FM-07"
        else _admission(
            result,
            actor="unexpected-reviewer[bot]" if case.case_id == "SE4-FM-08" else WRITER,
        )
    )
    events: list[str] = []
    post_count = 0
    receipt_count = 0
    history_calls = 0
    submissions = []
    observed_reviews = []

    class FakeAdmission:
        def admit(self, *_args):
            if case.case_id == "SE4-FM-09":
                raise PublicationAdmissionUnavailable("publisher_credential_invalid")
            if case.case_id == "SE4-FM-07":
                raise AssertionError("tampered result must be rejected before admission")
            return admission

    class FakeHistory:
        def scan(self, *_args):
            nonlocal history_calls
            history_calls += 1
            events.append("history_scan")
            if case.case_id == "SE4-FM-05":
                return HistoryScan(
                    HistoryStatus.UNAVAILABLE,
                    reason_code="github_history_unavailable",
                )
            if case.case_id == "SE4-FM-03":
                return HistoryScan(
                    HistoryStatus.COMPLETE,
                    reviews=(_review(admission, review_id=120), _review(admission, review_id=121)),
                    scanned_pages=1,
                    reviews_complete=True,
                )
            if observed_reviews:
                return HistoryScan(
                    HistoryStatus.COMPLETE,
                    reviews=tuple(observed_reviews),
                    scanned_pages=1,
                    reviews_complete=True,
                )
            return HistoryScan(
                HistoryStatus.COMPLETE,
                scanned_pages=1,
                reviews_complete=True,
            )

    class FakeReceiptWriter:
        def persist(self, receipt, _limits):
            nonlocal receipt_count
            receipt_count += 1
            events.append("receipt_acknowledged")
            acknowledgement = ReceiptAcknowledgement(
                artifact_id=991,
                publisher_run=receipt.publisher_run,
                archive_sha256="5" * 64,
                receipt_sha256=hashlib.sha256(receipt.to_bytes()).hexdigest(),
                expires_at=(datetime.now(timezone.utc) + timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            )
            return ReceiptPersistence(ReceiptPersistenceStatus.ACKNOWLEDGED, acknowledgement)

    def fresh_head(_timeout):
        events.append("fresh_head")
        if case.case_id == "SE4-FM-06" and events.count("fresh_head") == 2:
            return "c" * 40
        return HEAD

    def submit_review(payload, effect_key, _timeout):
        nonlocal post_count
        post_count += 1
        submissions.append((payload, effect_key))
        events.append("review_post")
        if case.case_id == "SE4-FM-02":
            raise TimeoutError("simulated uncertain transport outcome; no acceptance observed")
        if case.case_id == "SE4-FM-04":
            observed_reviews.append(_review(admission))
            raise TimeoutError("simulated response timeout after fake server accepted POST")
        return _review(admission)

    outcome = publish_review_stateless(
        result,
        CONFIG,
        "PUBLISH_REVIEW",
        admission_provider=FakeAdmission(),
        history_reader=FakeHistory(),
        receipt_writer=FakeReceiptWriter(),
        fresh_head=fresh_head,
        submit_review=submit_review,
        limits=ScanLimits(max_runs=20, max_pages=3, max_reviews=100, deadline_seconds=20),
    )

    assert outcome["status"] == case.terminal, (case.case_id, outcome, events)
    assert outcome["reason"] == case.reason, (case.case_id, outcome, events)
    assert post_count == case.posts, (case.case_id, submissions, events)
    assert receipt_count == case.receipts, (case.case_id, events)
    assert post_count <= 1, "the effect boundary must never blindly retry a review POST"
    assert receipt_count <= 1, "one attempt may persist no more than one receipt"
    assert case.owner.strip() and case.reconciliation_step.strip()

    if case.case_id == "SE4-FM-01":
        assert events.index("receipt_acknowledged") < events.index("review_post")
    elif case.case_id in {"SE4-FM-02", "SE4-FM-04"}:
        assert events.index("receipt_acknowledged") < events.index("review_post")
        assert history_calls == 2, "ambiguous submissions get one bounded read-only reconciliation scan"
        assert post_count == 1
    elif case.case_id in {"SE4-FM-03", "SE4-FM-05", "SE4-FM-07", "SE4-FM-08", "SE4-FM-09"}:
        assert receipt_count == 0
        assert post_count == 0
    elif case.case_id == "SE4-FM-06":
        assert events.index("receipt_acknowledged") < len(events) - 1
        assert events[-1] == "fresh_head"
        assert post_count == 0


def test_se4_fault_matrix_ids_and_reconciliation_metadata_are_unique_and_complete():
    ids = [case.case_id for case in FAULT_MATRIX]
    assert ids == [f"SE4-FM-{index:02d}" for index in range(1, 10)]
    assert len(ids) == len(set(ids))
    assert len({case.fault for case in FAULT_MATRIX}) == 9
    assert all(case.owner and case.reconciliation_step for case in FAULT_MATRIX)
    operational_doc = (ROOT / "docs/protected-publication-runtime.md").read_text(encoding="utf-8")
    assert _matrix_table() in operational_doc


def test_se4_declared_permissions_are_read_only_by_default_and_writer_scope_is_minimal():
    active = yaml.load(
        (ROOT / ".github/workflows/pr-publish.yml").read_text(encoding="utf-8"),
        Loader=yaml.BaseLoader,
    )
    assert active["permissions"] == {
        "actions": "read",
        "contents": "read",
        "pull-requests": "read",
    }
    assert active["jobs"]["read-only-canary"]["permissions"] == {
        "actions": "read",
        "contents": "read",
        "pull-requests": "read",
    }
    assert (
        active["jobs"]["publication-disabled"]["if"] == "${{ false && vars.PR_REVIEW_PUBLICATION_ENABLED == 'true' }}"
    )
    assert active["jobs"]["publication-disabled"]["permissions"] == {}

    writer_template = yaml.load(
        (ROOT / "templates/protected-pr-review-publisher-github-token.yml").read_text(encoding="utf-8"),
        Loader=yaml.BaseLoader,
    )
    # Read is needed for protected code/artifact/history admission; write is
    # restricted to creating a pull-request review. The template remains inert.
    assert writer_template["jobs"]["publisher-disabled"]["permissions"] == {
        "actions": "read",
        "contents": "read",
        "pull-requests": "write",
    }
    assert writer_template["jobs"]["publisher-disabled"]["if"] == "${{ false }}"
    assert writer_template["permissions"] == {
        "actions": "read",
        "contents": "read",
        "pull-requests": "read",
    }
