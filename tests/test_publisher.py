import copy
import hashlib

import pytest

from pr_review_harness.engine import _hash, run_review
from pr_review_harness.planner import plan_review
from pr_review_harness.publisher import (
    PublicationRejected,
    SQLiteEffectStore,
    effect_idempotency_key,
    prepare_publication,
    publish_review,
)
from pr_review_harness.report import render_report


def seal(value):
    return _hash(value)


def result():
    value = {
        "run_id": "publisher-fixture",
        "snapshot_id": "snapshot-fixture",
        "repository": "owner/repo",
        "pull_request_number": 5,
        "base_sha": "b" * 40,
        "head_sha": "a" * 40,
        "freshness": "CURRENT",
        "disposition": "COMMENT",
        "merge_eligibility": "NOT_EVALUATED",
        "project_profile_version": "publisher-v1",
        "coverage_state": "COMPLETE",
        "coverage_ledger": [{"obligation_id": "obligation-fixture", "required": True, "state": "COMPLETE"}],
        "policy_valid": True,
        "allow_empty_approve": False,
        "task_results": {},
        "ledger": {"candidate_records": []},
        "evidence_index": {},
        "budget": {},
        "findings": [],
        "report_sections": {
            "blockers": [],
            "suggested_improvements": [],
            "specific_strengths": [],
            "future_guidance": [],
        },
    }
    value["rendered_review"] = render_report(value)
    value["result_hash"] = seal(value)
    return value


def accepted_blocker(value):
    from pr_review_harness.reconcile import stable_candidate_id

    task_id = "task-fixture"
    evidence_id = "ev-fixture"
    candidate = {
        "unit_id": "unit-fixture",
        "location": {"kind": "line", "path": "src/a.py", "side": "HEAD", "line": 4, "reason": None},
        "title": "Supported issue",
        "observation": "Unsafe input is accepted.",
        "consequence": "The boundary can be crossed.",
        "rule_or_contract": "Input validation contract",
        "severity": "high",
        "evidence_refs": [evidence_id],
    }
    candidate_id = _hash({"task_id": task_id, "index": 0, "raw": candidate})[:24]
    normalized = {
        **candidate,
        "candidate_id": candidate_id,
        "task_id": task_id,
        "snapshot_id": value["snapshot_id"],
        "validation_state": "VALID",
        "validation_reason": "snapshot_location_and_evidence_validated",
    }
    finding_id = stable_candidate_id(value["snapshot_id"], normalized)
    finding = {
        "finding_id": finding_id,
        "candidate_id": candidate_id,
        "candidate_ids": [candidate_id],
        "task_id": task_id,
        "task_ids": [task_id],
        "snapshot_id": value["snapshot_id"],
        "unit_id": "unit-fixture",
        "location": candidate["location"],
        "path": "src/a.py",
        "title": candidate["title"],
        "observation": candidate["observation"],
        "consequence": candidate["consequence"],
        "rule_or_contract": candidate["rule_or_contract"],
        "evidence_refs": [evidence_id],
        "status": "ACCEPTED",
        "severity": "high",
        "blocking_class": "BLOCKING",
        "blocking_rationale": "Supported by evidence.",
    }
    value["findings"] = [finding]
    value["disposition"] = "REQUEST_CHANGES"
    value["task_results"] = {
        task_id: {
            "status": "SUCCEEDED",
            "input_evidence_ids": [evidence_id],
            "payload": {"finding_candidates": [candidate]},
        }
    }
    value["ledger"] = {
        "candidate_records": [
            {
                "candidate_id": candidate_id,
                "finding_id": finding_id,
                "task_id": task_id,
                "snapshot_id": value["snapshot_id"],
                "validation_state": "VALID",
                "raw": normalized,
            }
        ]
    }
    value["evidence_index"] = {
        evidence_id: {
            "path": "src/a.py",
            "line_start": 1,
            "line_end": 10,
            "source_revision": value["head_sha"],
            "source_kind": "source_window",
            "content_hash": "c" * 64,
        }
    }
    value["report_sections"]["blockers"] = [
        {
            "finding_id": finding_id,
            "title": finding["title"],
            "path": finding["path"],
            "location": finding["location"],
            "observation": finding["observation"],
            "consequence": finding["consequence"],
            "rule_or_contract": finding["rule_or_contract"],
            "evidence_refs": [evidence_id],
        }
    ]
    return value


def config(**extra):
    return {
        "schema_version": "1.0",
        "enabled": True,
        "allowed_repositories": ["owner/repo"],
        "allowed_dispositions": ["COMMENT"],
        **extra,
    }


def test_publication_disabled_by_default_and_requires_effect_authority():
    with pytest.raises(PublicationRejected, match="disabled"):
        prepare_publication(result(), {"schema_version": "1.0", "enabled": False}, "PUBLISH_REVIEW", True)
    with pytest.raises(PublicationRejected, match="operator authorization"):
        prepare_publication(result(), config(), "PUBLISH_REVIEW", False)


def test_publication_request_hash_binds_review_and_never_merges():
    review = result()["rendered_review"]
    prepared = prepare_publication(result(), config(), "PUBLISH_REVIEW", True, rendered_review=review)
    assert prepared["idempotency_key"] == effect_idempotency_key(result(), rendered_review=review)
    assert prepared["review_payload"]["commit_id"] == "a" * 40
    assert prepared["review_payload"]["event"] == "COMMENT"
    assert prepared["review_payload"]["body"] == review
    assert prepared["idempotency_key"] == effect_idempotency_key(result())
    assert prepared["merge"] is False
    assert "merge" not in prepared["review_payload"]


def test_publication_rejects_noncanonical_body_that_could_omit_blockers():
    reviewed = result()
    reviewed = accepted_blocker(reviewed)
    reviewed.pop("result_hash")
    reviewed["rendered_review"] = render_report(reviewed)
    reviewed["result_hash"] = seal(reviewed)
    with pytest.raises(PublicationRejected, match="canonical result"):
        prepare_publication(
            reviewed,
            config(allowed_dispositions=["REQUEST_CHANGES"]),
            "PUBLISH_REVIEW",
            True,
            rendered_review="A clean review; no blockers.",
        )


def test_resume_timestamp_refresh_keeps_idempotency_but_changed_body_does_not():
    original = result()
    refreshed = copy.deepcopy(original)
    refreshed["completed_at"] = "2099-01-01T00:00:00Z"
    refreshed.pop("result_hash")
    refreshed["result_hash"] = seal(refreshed)
    assert effect_idempotency_key(original) == effect_idempotency_key(refreshed)

    changed = copy.deepcopy(refreshed)
    changed["report_sections"]["suggested_improvements"] = [{"finding_id": "finding-new", "title": "New"}]
    changed["rendered_review"] = render_report(changed)
    changed.pop("result_hash")
    changed["result_hash"] = seal(changed)
    assert effect_idempotency_key(changed) != effect_idempotency_key(refreshed)


class EmptyProvider:
    identity = {"kind": "publisher-test"}

    def review(self, task, evidence, limits):
        return {
            "payload": {
                "finding_candidates": [],
                "context_gap_proposals": [],
                "coverage_notes": [
                    {
                        "unit_id": unit,
                        "state": "COVERED",
                        "reason_code": "REVIEWED",
                        "evidence_refs": list(task["evidence_ids"]),
                        "coverage_basis": "STATIC_REVIEW",
                    }
                    for unit in task["unit_ids"]
                ],
            }
        }


def test_engine_durable_result_accepts_its_canonical_external_review_body(tmp_path):
    evidence_id = "evidence-1"
    snapshot = {
        "snapshot_id": "engine-publisher-snapshot",
        "snapshot_hash": "d" * 64,
        "base_sha": "b" * 40,
        "head_sha": "a" * 40,
        "repository": "owner/repo",
        "pull_request_number": 5,
        "freshness_basis": "HISTORICAL_SNAPSHOT",
        "profile_version": "publisher-v1",
        "inventory": [
            {
                "unit_id": "unit-1",
                "path": "src/a.py",
                "kind": "human_code",
                "change_type": "modify",
                "diff": "+value = 2",
                "changed_lines": [[1, 1]],
                "evidence_ids": [evidence_id],
            }
        ],
        "evidence": {
            evidence_id: {
                "evidence_id": evidence_id,
                "snapshot_id": "engine-publisher-snapshot",
                "path": "src/a.py",
                "source_kind": "diff",
                "content": "+value = 2",
                "content_hash": "c" * 64,
                "trust": "untrusted_pr_content",
            }
        },
        "gaps": [],
    }
    profile_value = {"version": "publisher-v1", "required_lenses": ["correctness"], "allow_empty_approval": False}
    plan = plan_review(snapshot, profile_value)
    limits = {
        "deadline_seconds": 3,
        "max_concurrent_scopes": 1,
        "max_provider_calls": 2,
        "max_retries_per_task": 0,
        "max_context_bytes": 5000,
        "max_input_bytes_per_task": 3000,
        "max_output_bytes_per_task": 1000,
        "max_output_bytes": 2000,
        "max_output_tokens": 100,
        "max_context_retrievals": 0,
        "max_followup_tasks": 0,
    }
    durable = run_review(
        snapshot, plan, profile_value, EmptyProvider(), None, limits, str(tmp_path), "engine-publication"
    )
    external_render = render_report(durable)
    prepared = prepare_publication(
        durable,
        config(allowed_dispositions=[durable["disposition"]]),
        "PUBLISH_REVIEW",
        True,
        rendered_review=external_render,
    )
    assert prepared["review_payload"]["body"] == external_render
    assert prepared["result_hash"] == durable["result_hash"]


def test_mutated_result_and_out_of_scope_repository_are_rejected():
    mutated = result()
    mutated["disposition"] = "APPROVE"
    with pytest.raises(PublicationRejected, match="hash"):
        prepare_publication(mutated, config(), "PUBLISH_REVIEW", True)
    with pytest.raises(PublicationRejected, match="authorization scope"):
        prepare_publication(result(), config(allowed_repositories=["elsewhere/repo"]), "PUBLISH_REVIEW", True)


def test_rehashed_but_reducer_inconsistent_disposition_is_rejected():
    inconsistent = result()
    inconsistent["disposition"] = "REQUEST_CHANGES"
    inconsistent.pop("result_hash")
    inconsistent["result_hash"] = seal(inconsistent)
    with pytest.raises(PublicationRejected, match="disposition is inconsistent"):
        prepare_publication(
            inconsistent,
            config(allowed_dispositions=["REQUEST_CHANGES"]),
            "PUBLISH_REVIEW",
            True,
        )


def test_rehashed_unaccepted_finding_cannot_be_smuggled_into_improvements():
    value = result()
    value["report_sections"]["suggested_improvements"] = [
        {"finding_id": "unsupported-finding", "title": "Unvalidated advice"}
    ]
    value["rendered_review"] = render_report(value)
    value.pop("result_hash")
    value["result_hash"] = seal(value)
    with pytest.raises(PublicationRejected, match="report findings"):
        prepare_publication(value, config(), "PUBLISH_REVIEW", True)


def test_review_submit_requires_final_sha_and_existing_effect_lookup():
    calls = []
    heads = iter(["a" * 40, "b" * 40])
    outcome = publish_review(
        result(),
        config(),
        "PUBLISH_REVIEW",
        True,
        fresh_head=lambda: next(heads),
        lookup_effect=lambda key: "not_found",
        claim_effect=lambda key: "acquired",
        submit_review=lambda payload, key: calls.append((payload, key)),
        confirm_effect=lambda key, detail: None,
    )
    assert outcome["status"] == "REJECTED"
    assert outcome["reason"] == "head_sha_changed_before_submit"
    assert calls == []


def test_fresh_sha_is_rechecked_after_claim_and_releases_stale_reservation():
    calls = []
    heads = iter(["a" * 40, "a" * 40, "b" * 40])
    outcome = publish_review(
        result(),
        config(),
        "PUBLISH_REVIEW",
        True,
        fresh_head=lambda: next(heads),
        lookup_effect=lambda key: "not_found",
        claim_effect=lambda key: "acquired",
        submit_review=lambda *args: calls.append(args),
        confirm_effect=lambda key, detail: None,
        release_effect=lambda key: calls.append(("released", key)),
    )
    assert outcome["status"] == "REJECTED"
    assert outcome["reason"] == "head_sha_changed_before_submit"
    assert calls == [("released", outcome["request"]["idempotency_key"])]


def test_ambiguous_submit_is_looked_up_and_never_blindly_retried():
    lookup_states = iter(["not_found", "unknown"])
    calls = []

    def submit(*args):
        calls.append(args)
        raise TimeoutError

    outcome = publish_review(
        result(),
        config(),
        "PUBLISH_REVIEW",
        True,
        fresh_head=lambda: "a" * 40,
        lookup_effect=lambda key: next(lookup_states),
        claim_effect=lambda key: "acquired",
        submit_review=submit,
        confirm_effect=lambda key, detail: None,
    )
    assert outcome["status"] == "UNKNOWN"
    assert outcome["reason"] == "submit_response_ambiguous"
    assert len(calls) == 1


def test_replay_uses_atomic_claim_and_does_not_submit_twice():
    calls = []
    result_value = result()
    outcome = publish_review(
        result_value,
        config(),
        "PUBLISH_REVIEW",
        True,
        fresh_head=lambda: "a" * 40,
        lookup_effect=lambda key: "not_found",
        claim_effect=lambda key: "confirmed",
        submit_review=lambda *args: calls.append(args),
        confirm_effect=lambda key, detail: None,
    )
    assert outcome["status"] == "CONFIRMED"
    assert calls == []


def test_sqlite_effect_store_claim_is_durable_and_serialized(tmp_path):
    store = SQLiteEffectStore(str(tmp_path / "state" / "effects.sqlite"))
    assert store.lookup("key") == "not_found"
    assert store.claim("key") == "acquired"
    assert store.claim("key") == "in_progress"
    assert store.lookup("key") == "unknown"
    store.confirm("key", "review 123")
    assert SQLiteEffectStore(str(tmp_path / "state" / "effects.sqlite")).lookup("key") == "confirmed"


class FakeAdmissionProvider:
    def __init__(self, config_value, review):
        import hashlib
        import json

        from pr_review_harness.publication_receipts import (
            EffectSlot,
            PublicationAdmission,
            RunIdentity,
        )
        from pr_review_harness.publisher import _stateless_effect_key

        def canonical(value):
            return hashlib.sha256(
                json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
            ).hexdigest()

        slot = EffectSlot(1234, review["repository"], review["pull_request_number"], review["head_sha"])
        self.value = PublicationAdmission(
            slot=slot,
            base_sha="b" * 40,
            effect_key=_stateless_effect_key(
                slot, review["result_hash"], review["review_body_hash"], review["disposition"]
            ),
            result_hash=review["result_hash"],
            review_body_hash=review["review_body_hash"],
            disposition=review["disposition"],
            review_event=review["review_event"],
            actor_login="review-bot[bot]",
            profile_hash=canonical({"profile": "publisher-v1"}),
            policy_hash=canonical(config_value),
            source_artifact_sha256=canonical({"artifact": "sha256"}),
            admission_evidence_hash=canonical({"api": "bound"}),
            upstream_run=RunIdentity(
                repository_id=1234,
                workflow_id=10,
                workflow_path=".github/workflows/pr-analysis.yml",
                workflow_ref="refs/heads/main",
                workflow_sha="c" * 40,
                run_id=101,
                run_attempt=1,
            ),
            publisher_run=RunIdentity(
                repository_id=1234,
                workflow_id=20,
                workflow_path=".github/workflows/pr-publish.yml",
                workflow_ref="refs/heads/main",
                workflow_sha="d" * 40,
                run_id=202,
                run_attempt=1,
            ),
            concurrency_group="pr-review-publish-1234-5",
            concurrency_contract_hash=canonical({"workflow": "serialized-v1"}),
        )

    def admit(self, _result, _config, _limits):
        return self.value


class FakeReceiptHistory:
    def __init__(self, scans=None):
        from pr_review_harness.publication_receipts import HistoryScan, HistoryStatus

        self.scans = list(scans or [HistoryScan(HistoryStatus.COMPLETE)])
        self.calls = 0

    def scan(self, _slot, _limits):
        self.calls += 1
        if len(self.scans) > 1:
            return self.scans.pop(0)
        return self.scans[0]


class FakeReceiptWriter:
    def __init__(self, status="ACKNOWLEDGED", mismatch=False):
        from pr_review_harness.publication_receipts import (
            ReceiptPersistenceStatus,
        )

        self.status = ReceiptPersistenceStatus(status)
        self.mismatch = mismatch
        self.receipts = []

    def persist(self, receipt, _limits):
        import hashlib

        from pr_review_harness.publication_receipts import ReceiptAcknowledgement, ReceiptPersistence

        self.receipts.append(receipt)
        digest = hashlib.sha256(receipt.to_bytes()).hexdigest()
        if self.mismatch:
            digest = "0" * 64
        ack = ReceiptAcknowledgement(
            artifact_id=77,
            publisher_run=receipt.publisher_run,
            archive_sha256=hashlib.sha256(b"archive").hexdigest(),
            receipt_sha256=digest,
            expires_at="2026-10-01T00:00:00Z",
        )
        if self.status.value != "ACKNOWLEDGED":
            return ReceiptPersistence(self.status, reason_code="receipt_upload_unknown")
        return ReceiptPersistence(self.status, acknowledgement=ack)


def _stateless_config():
    return config(
        allowed_profile_versions=["publisher-v1"],
        allowed_actors=["review-bot[bot]"],
    )


def _publish_stateless(review=None, *, history=None, writer=None, fresh=None, submit=None, admission=None):
    from pr_review_harness.publisher import publish_review_stateless

    value = review or result()
    policy = _stateless_config()
    writer = writer or FakeReceiptWriter()
    history = history or FakeReceiptHistory()
    heads = iter(fresh if fresh is not None else ["a" * 40, "a" * 40])
    calls = []

    def fake_submit(payload, key, _timeout):
        calls.append((payload, key))
        if submit is not None:
            return submit(payload, key)
        from pr_review_harness.publication_receipts import ReviewObservation, ReviewState

        state = {
            "APPROVE": ReviewState.APPROVED,
            "REQUEST_CHANGES": ReviewState.CHANGES_REQUESTED,
            "COMMENT": ReviewState.COMMENTED,
        }[payload["event"]]
        return ReviewObservation(
            slot=admission.value.slot
            if admission
            else FakeAdmissionProvider(policy, preview(value, policy)).value.slot,
            effect_key=key,
            review_body_hash=hashlib.sha256(
                payload["body"].rsplit("\n\n<!-- pr-review-harness:", 1)[0].encode()
            ).hexdigest(),
            actor_login="review-bot[bot]",
            state=state,
            review_id=900,
        )

    prepared = preview(value, policy)
    provider = admission or FakeAdmissionProvider(policy, prepared)
    outcome = publish_review_stateless(
        value,
        policy,
        "PUBLISH_REVIEW",
        admission_provider=provider,
        history_reader=history,
        receipt_writer=writer,
        fresh_head=lambda _timeout: next(heads),
        submit_review=fake_submit,
    )
    return outcome, writer, history, calls, provider


def preview(value, policy):
    from pr_review_harness.publisher import preview_publication

    return preview_publication(value, policy)


def test_stateless_publication_requires_durable_receipt_before_single_post():
    outcome, writer, history, calls, _ = _publish_stateless()
    assert outcome["status"] == "CONFIRMED"
    assert len(writer.receipts) == 1
    assert len(calls) == 1
    assert history.calls == 1
    assert outcome["request"]["idempotency_key"] == writer.receipts[0].effect_key
    sent_body = calls[0][0]["body"]
    assert sent_body.endswith(f"<!-- pr-review-harness:{calls[0][1]} -->")
    assert sent_body.count("<!-- pr-review-harness:") == 1
    canonical_body = sent_body.rsplit("\n\n<!-- pr-review-harness:", 1)[0]
    assert hashlib.sha256(canonical_body.encode()).hexdigest() == writer.receipts[0].review_body_hash


def test_stateless_publication_refuses_prior_unknown_receipt_without_post():
    from pr_review_harness.publication_receipts import HistoryScan, HistoryStatus

    policy = _stateless_config()
    prepared = preview(result(), policy)
    receipt_writer = FakeReceiptWriter()
    provider = FakeAdmissionProvider(policy, prepared)
    receipt_writer.persist(
        __import__("pr_review_harness.publication_receipts", fromlist=["AttemptReceipt"]).AttemptReceipt(
            slot=provider.value.slot,
            effect_key=provider.value.effect_key,
            result_hash=provider.value.result_hash,
            review_body_hash=provider.value.review_body_hash,
            disposition=provider.value.disposition,
            review_event=provider.value.review_event,
            actor_login=provider.value.actor_login,
            profile_hash=provider.value.profile_hash,
            upstream_run=provider.value.upstream_run,
            publisher_run=provider.value.publisher_run,
        ),
        __import__("pr_review_harness.publication_receipts", fromlist=["ScanLimits"]).ScanLimits(),
    )
    prior = receipt_writer.receipts[0]
    history = FakeReceiptHistory([HistoryScan(HistoryStatus.COMPLETE, receipts=(prior,))])
    outcome, writer, _, calls, _ = _publish_stateless(history=history)
    assert outcome["status"] == "UNKNOWN"
    assert outcome["reason"] == "prior_attempt_has_no_confirmed_review"
    assert calls == []
    assert writer.receipts == []


def test_stateless_publication_requires_complete_history_and_acknowledged_exact_receipt():
    from pr_review_harness.publication_receipts import HistoryScan, HistoryStatus

    outcome, writer, _, calls, _ = _publish_stateless(
        history=FakeReceiptHistory([HistoryScan(HistoryStatus.INCOMPLETE, reason_code="run_scan_limit")])
    )
    assert outcome["status"] == "UNKNOWN"
    assert calls == []
    assert writer.receipts == []

    outcome, writer, _, calls, _ = _publish_stateless(writer=FakeReceiptWriter("UNKNOWN"))
    assert outcome["status"] == "UNKNOWN"
    assert calls == []
    assert len(writer.receipts) == 1

    outcome, writer, _, calls, _ = _publish_stateless(writer=FakeReceiptWriter(mismatch=True))
    assert outcome["status"] == "UNKNOWN"
    assert outcome["reason"] == "receipt_acknowledgement_mismatch"
    assert calls == []


def test_stateless_publication_treats_marker_match_as_confirmed_and_other_result_as_conflict():
    from pr_review_harness.publication_receipts import HistoryScan, HistoryStatus, ReviewObservation, ReviewState

    policy = _stateless_config()
    value = result()
    prepared = preview(value, policy)
    provider = FakeAdmissionProvider(policy, prepared)
    match = ReviewObservation(
        slot=provider.value.slot,
        effect_key=provider.value.effect_key,
        review_body_hash=provider.value.review_body_hash,
        actor_login=provider.value.actor_login,
        state=ReviewState.COMMENTED,
        review_id=901,
    )
    outcome, writer, _, calls, _ = _publish_stateless(
        history=FakeReceiptHistory([HistoryScan(HistoryStatus.COMPLETE, reviews=(match,))])
    )
    assert outcome["status"] == "CONFIRMED"
    assert calls == []
    assert writer.receipts == []

    conflict = ReviewObservation(
        slot=provider.value.slot,
        effect_key="effect-" + "f" * 64,
        review_body_hash=provider.value.review_body_hash,
        actor_login=provider.value.actor_login,
        state=ReviewState.COMMENTED,
        review_id=902,
    )
    outcome, _, _, calls, _ = _publish_stateless(
        history=FakeReceiptHistory([HistoryScan(HistoryStatus.COMPLETE, reviews=(conflict,))])
    )
    assert outcome["status"] == "CONFLICT"
    assert calls == []


def test_stateless_publication_rechecks_head_after_receipt_and_never_posts_stale_result():
    outcome, writer, _, calls, _ = _publish_stateless(fresh=["a" * 40, "b" * 40])
    assert outcome["status"] == "STALE"
    assert outcome["reason"] == "head_sha_changed_after_receipt"
    assert len(writer.receipts) == 1
    assert calls == []


def test_incomplete_terminal_result_publishes_comment_event_and_preserves_semantic_state():
    value = result()
    value["coverage_state"] = "PARTIAL"
    value["coverage_ledger"][0]["state"] = "PARTIAL"
    value["disposition"] = "INCOMPLETE"
    value["rendered_review"] = render_report(value)
    value.pop("result_hash")
    value["result_hash"] = seal(value)
    outcome, writer, _, calls, _ = _publish_stateless(value)
    assert outcome["status"] == "CONFIRMED"
    assert outcome["request"]["disposition"] == "INCOMPLETE"
    assert outcome["request"]["review_event"] == "COMMENT"
    assert calls[0][0]["event"] == "COMMENT"
    assert writer.receipts[0].disposition == "INCOMPLETE"
    assert writer.receipts[0].review_event == "COMMENT"


def test_stateless_calls_share_one_decreasing_monotonic_deadline(monkeypatch):
    import pr_review_harness.publisher as publisher_module
    from pr_review_harness.publication_receipts import ScanLimits

    value = result()
    policy = _stateless_config()
    prepared = preview(value, policy)
    provider = FakeAdmissionProvider(policy, prepared)
    history = FakeReceiptHistory()
    writer = FakeReceiptWriter()
    remaining_seen = []
    original_admit = provider.admit
    original_scan = history.scan
    original_persist = writer.persist

    def admit(review, config_value, limits):
        remaining_seen.append(limits.deadline_seconds)
        return original_admit(review, config_value, limits)

    def scan(slot, limits):
        remaining_seen.append(limits.deadline_seconds)
        return original_scan(slot, limits)

    def persist(receipt_value, limits):
        remaining_seen.append(limits.deadline_seconds)
        return original_persist(receipt_value, limits)

    provider.admit = admit
    history.scan = scan
    writer.persist = persist

    def head(timeout_seconds):
        remaining_seen.append(timeout_seconds)
        return "a" * 40

    def submit(payload, key, timeout_seconds):
        remaining_seen.append(timeout_seconds)
        from pr_review_harness.publication_receipts import ReviewObservation, ReviewState

        canonical_body = payload["body"].rsplit("\n\n<!-- pr-review-harness:", 1)[0]
        return ReviewObservation(
            slot=provider.value.slot,
            effect_key=key,
            review_body_hash=hashlib.sha256(canonical_body.encode()).hexdigest(),
            actor_login="review-bot[bot]",
            state=ReviewState.COMMENTED,
            review_id=903,
        )

    ticks = iter(float(value) for value in range(100, 120))
    monkeypatch.setattr(publisher_module.time, "monotonic", lambda: next(ticks))
    outcome = publisher_module.publish_review_stateless(
        value,
        policy,
        "PUBLISH_REVIEW",
        admission_provider=provider,
        history_reader=history,
        receipt_writer=writer,
        fresh_head=head,
        submit_review=submit,
        limits=ScanLimits(deadline_seconds=8),
    )
    assert outcome["status"] == "CONFIRMED"
    assert remaining_seen == sorted(remaining_seen, reverse=True)
    assert min(remaining_seen) > 0


def test_stateless_publication_ambiguous_post_reconciles_once_then_stays_unknown():
    from pr_review_harness.publication_receipts import HistoryScan, HistoryStatus

    history = FakeReceiptHistory([HistoryScan(HistoryStatus.COMPLETE), HistoryScan(HistoryStatus.COMPLETE)])
    outcome, _, _, calls, _ = _publish_stateless(
        history=history, submit=lambda *_: (_ for _ in ()).throw(TimeoutError())
    )
    assert outcome["status"] == "UNKNOWN"
    assert outcome["reason"] == "submit_response_ambiguous"
    assert len(calls) == 1
    assert history.calls == 2


def test_stateless_publication_rejects_unverified_or_mismatched_admission():
    from dataclasses import replace

    policy = _stateless_config()
    prepared = preview(result(), policy)
    provider = FakeAdmissionProvider(policy, prepared)
    invalid = type("Admission", (), {"admit": lambda self, *_: replace(provider.value, policy_hash="0" * 64)})()
    outcome, writer, _, calls, _ = _publish_stateless(admission=invalid)
    assert outcome["status"] == "REJECTED"
    assert calls == []
    assert writer.receipts == []
