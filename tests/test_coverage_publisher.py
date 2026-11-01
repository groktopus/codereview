"""Coverage-focused negative-path tests for the guarded publisher.

Every refusal asserted here is checked for its typed reason *and* for the
absence of the remote effect (no review POST, no effect claim). Helpers come
from the existing publisher test modules so the valid baseline result stays
identical to the suite's canonical fixture.
"""

import copy
import hashlib
import sqlite3
import time
from dataclasses import replace

import pytest
from test_publisher import (
    FakeAdmissionProvider,
    FakeReceiptHistory,
    FakeReceiptWriter,
    _freeze_receipt_clock,
    _stateless_config,
    accepted_blocker,
    config,
    preview,
    result,
    seal,
)

import pr_review_harness.publisher as publisher_module
from pr_review_harness.publication_receipts import (
    AttemptReceipt,
    EffectSlot,
    HistoryScan,
    HistoryStatus,
    NoEffectReceipt,
    ReceiptPersistence,
    ReceiptPersistenceStatus,
    ReviewObservation,
    ReviewState,
    ScanLimits,
)
from pr_review_harness.publisher import (
    PublicationAdmissionUnavailable,
    PublicationRejected,
    SQLiteEffectStore,
    _marked_review_payload,
    _stateless_effect_key,
    _validate_result,
    effect_idempotency_key,
    prepare_publication,
    preview_publication,
    publish_review,
    publish_review_stateless,
    render_publication_body,
)


def reseal(value):
    value.pop("result_hash", None)
    value["result_hash"] = seal(value)
    return value


def assert_rejected(func, match):
    with pytest.raises(PublicationRejected, match=match):
        func()


# ---------------------------------------------------------------------------
# SQLite effect store: deadline, rollback, release
# ---------------------------------------------------------------------------


def test_effect_store_deadline_is_enforced_before_connecting(tmp_path):
    store = SQLiteEffectStore(str(tmp_path / "effects.sqlite"), deadline_at=time.monotonic() - 1)
    with pytest.raises(TimeoutError, match="deadline exceeded"):
        store.claim("effect-key")
    assert not (tmp_path / "effects.sqlite").exists()


def test_effect_store_claim_rolls_back_on_storage_failure(tmp_path, monkeypatch):
    class Rows:
        def fetchone(self):
            return None

    class FailingConnection:
        def __init__(self):
            self.rolled_back = False
            self.closed = False

        def execute(self, sql, params=()):
            if sql.lstrip().startswith("INSERT"):
                raise sqlite3.OperationalError("database is locked")
            return Rows()

        def commit(self):
            raise AssertionError("a failed claim must not commit")

        def rollback(self):
            self.rolled_back = True

        def close(self):
            self.closed = True

    connection = FailingConnection()
    store = SQLiteEffectStore(str(tmp_path / "effects.sqlite"))
    monkeypatch.setattr(store, "_connect", lambda: connection)
    with pytest.raises(sqlite3.OperationalError, match="database is locked"):
        store.claim("effect-key")
    assert connection.rolled_back is True
    assert connection.closed is True


def test_effect_store_release_only_drops_an_unconfirmed_claim(tmp_path):
    store = SQLiteEffectStore(str(tmp_path / "effects" / "effects.sqlite"))
    assert store.claim("claimed-key") == "acquired"
    assert store.claim("claimed-key") == "in_progress"
    store.release("claimed-key")
    assert store.lookup("claimed-key") == "not_found"

    assert store.claim("confirmed-key") == "acquired"
    store.confirm("confirmed-key", "review 1")
    assert store.claim("confirmed-key") == "confirmed"
    store.release("confirmed-key")
    assert store.lookup("confirmed-key") == "confirmed"


# ---------------------------------------------------------------------------
# effect key and render/prepare/preview refusals
# ---------------------------------------------------------------------------


def test_effect_key_rejects_unrenderable_result_and_unknown_publication_mode():
    assert_rejected(lambda: effect_idempotency_key({"repository": "owner/repo"}), "canonical review report")
    assert_rejected(
        lambda: effect_idempotency_key(result(), publication_mode="SILENT"),
        "publication_mode_invalid",
    )
    binding = effect_idempotency_key(result(), publication_mode="NON_BINDING_COMMENT")
    assert binding != effect_idempotency_key(result())


def test_effect_key_binds_the_non_binding_publication_mode():
    value = result()
    slot = EffectSlot(8123, "owner/repo", 5, value["head_sha"])
    disposition_key = _stateless_effect_key(slot, value["result_hash"], "a" * 64, "COMMENT")
    mode_key = _stateless_effect_key(
        slot, value["result_hash"], "a" * 64, "COMMENT", publication_mode="NON_BINDING_COMMENT"
    )
    assert mode_key != disposition_key


def test_render_publication_body_rejects_unknown_mode_and_invalid_result(monkeypatch):
    assert_rejected(lambda: render_publication_body(result(), "SILENT"), "publication_mode_invalid")

    def broken(_result):
        raise ValueError("cannot render")

    monkeypatch.setattr("pr_review_harness.report.render_report", broken)
    assert_rejected(lambda: render_publication_body(result()), "canonical review report is invalid")


def test_prepare_publication_refuses_unknown_effect_policy_and_bad_config():
    assert_rejected(
        lambda: prepare_publication(result(), config(), "READ_ONLY", True),
        "effect policy does not permit",
    )
    assert_rejected(
        lambda: prepare_publication(result(), {"schema_version": "2.0"}, "PUBLISH_REVIEW", True),
        "publisher configuration schema is invalid",
    )
    assert_rejected(
        lambda: prepare_publication(result(), config(enabled=False), "PUBLISH_REVIEW", True),
        "review publishing is disabled",
    )
    assert_rejected(
        lambda: prepare_publication(result(), config(), "PUBLISH_REVIEW", False),
        "explicit operator authorization is required",
    )


def test_render_publication_body_non_binding_mode_keeps_analysis_and_adds_notice():
    body = render_publication_body(result(), "NON_BINDING_COMMENT")
    assert body.startswith("## Non-binding review comment")
    assert "Underlying analysis disposition: `COMMENT`" in body
    assert result()["rendered_review"] in body


def test_preview_non_binding_mode_and_incomplete_policy_events():
    non_binding = preview_publication(
        result(),
        config(publication_mode="NON_BINDING_COMMENT", allowed_dispositions=["COMMENT"]),
    )
    assert non_binding["review_event"] == "COMMENT"
    assert non_binding["publication_mode"] == "NON_BINDING_COMMENT"

    incomplete = result()
    incomplete["coverage_state"] = "PARTIAL"
    incomplete["coverage_ledger"][0]["state"] = "PARTIAL"
    incomplete["disposition"] = "INCOMPLETE"
    reseal(incomplete)
    prepared = preview_publication(incomplete, config(allowed_dispositions=["COMMENT"]))
    assert prepared["review_event"] == "COMMENT"


def test_preview_refuses_disallowed_disposition_and_noncanonical_body():
    assert_rejected(
        lambda: preview_publication(result(), config(allowed_dispositions=["APPROVE"])),
        "disposition_not_allowed",
    )
    assert_rejected(
        lambda: preview_publication(result(), config(), rendered_review="different body"),
        "review body differs from canonical result",
    )


def test_preview_refuses_invalid_publisher_config_schema():
    assert_rejected(
        lambda: preview_publication(result(), {"schema_version": "2.0"}),
        "publisher configuration schema is invalid",
    )


def _preview_without_result_gate(monkeypatch):
    monkeypatch.setattr(publisher_module, "_validate_result", lambda _result: None)


def _preview_config(mutate, policy=None):
    value = result()
    mutate(value)
    preview_publication(value, policy or config())


@pytest.mark.parametrize(
    ("case", "match"),
    [
        ("repository", "pull request identity is invalid"),
        ("head", "review head SHA is invalid"),
        ("mode", "publication_mode_invalid"),
        ("policy", "review policy is invalid"),
        ("disposition", "review disposition cannot be published"),
        ("body_bool", "review body is invalid or exceeds its bound"),
        ("body_small", "review body is invalid or exceeds its bound"),
    ],
)
def test_preview_defensive_guards_refuse_without_side_effects(monkeypatch, case, match):
    _preview_without_result_gate(monkeypatch)

    def run():
        value = result()
        if case == "repository":
            value.update(repository="")
            preview_publication(value, config())
        elif case == "head":
            value.update(head_sha="not-a-sha")
            preview_publication(value, config())
        elif case == "mode":
            preview_publication(value, config(publication_mode="SILENT"))
        elif case == "policy":
            value.update(disposition="INCOMPLETE", policy_valid=False)
            preview_publication(value, config(allowed_dispositions=["COMMENT"]))
        elif case == "disposition":
            value.update(disposition="MERGE")
            preview_publication(value, config())
        elif case == "body_bool":
            preview_publication(value, config(max_review_body_bytes=True))
        else:
            preview_publication(value, config(max_review_body_bytes=10))

    assert_rejected(run, match)


def test_preview_rejects_render_failure_through_canonical_body(monkeypatch):
    _preview_without_result_gate(monkeypatch)

    monkeypatch.setattr("pr_review_harness.report.render_report", lambda _result: (_ for _ in ()).throw(TypeError()))

    def run():
        preview_publication(result(), config())

    assert_rejected(run, "canonical review report is invalid")


def test_marked_payload_refuses_body_that_already_contains_marker():
    assert_rejected(
        lambda: _marked_review_payload({"body": "ok <!-- pr-review-harness:effect-x -->"}, "effect-x"),
        "reserved marker",
    )


# ---------------------------------------------------------------------------
# _validate_result contract refusals
# ---------------------------------------------------------------------------


def _mutated(mutator):
    value = result()
    mutator(value)
    return reseal(value)


def _duplicate_obligations(value):
    value["coverage_ledger"] = [
        {"obligation_id": "dup", "required": True, "state": "COMPLETE"},
        {"obligation_id": "dup", "required": True, "state": "COMPLETE"},
    ]


@pytest.mark.parametrize(
    ("factory", "match"),
    [
        (lambda: [], "review result is invalid"),
        (
            lambda: _mutated(lambda value: value.update(repository="owner")),
            "review result contract is invalid",
        ),
        (
            lambda: _mutated(lambda value: value.update(disposition="MERGE")),
            "review disposition cannot be published",
        ),
        (
            lambda: _mutated(
                lambda value: value.update(
                    coverage_ledger=[{"required": True, "state": "COMPLETE"}]
                )
            ),
            "review coverage ledger is invalid",
        ),
        (lambda: _mutated(_duplicate_obligations), "review coverage ledger is invalid"),
        (
            lambda: _mutated(
                lambda value: value.update(
                    coverage_ledger=[{"obligation_id": "o", "required": False, "state": "COMPLETE"}]
                )
            ),
            "review has no required coverage obligations",
        ),
        (
            lambda: _mutated(
                lambda value: value.update(
                    coverage_ledger=[{"obligation_id": "o", "required": True, "state": "BOGUS"}]
                )
            ),
            "review coverage ledger is invalid",
        ),
        (
            lambda: _mutated(
                lambda value: value.update(
                    coverage_ledger=[{"obligation_id": "o", "required": True, "state": "COMPLETE"}],
                    coverage_state="PARTIAL",
                )
            ),
            "review coverage state is inconsistent",
        ),
        (
            lambda: _mutated(
                lambda value: value.update(findings=[{"status": "MAYBE", "blocking_class": "BLOCKING"}])
            ),
            "review findings are invalid",
        ),
        (
            lambda: _mutated(lambda value: value.update(report_sections=["not", "a", "dict"])),
            "review report sections are invalid",
        ),
        (
            lambda: _mutated(lambda value: value.update(freshness="STALE")),
            "review freshness is not current",
        ),
        (
            lambda: _mutated(lambda value: value.update(disposition="REQUEST_CHANGES")),
            "review disposition is inconsistent with deterministic policy",
        ),
        (lambda: _stale_hash_result(), "review result hash is invalid"),
        (
            lambda: _rehashed_blocker_without_rendered_section(),
            "canonical report findings do not match accepted findings",
        ),
    ],
)
def test_result_validation_refuses_contract_violations(factory, match):
    assert_rejected(lambda: _validate_result(factory()), match)


def _stale_hash_result():
    value = result()
    value["result_hash"] = "0" * 64
    return value


def _rehashed_blocker_without_rendered_section():
    value = accepted_blocker(result())
    value["report_sections"]["blockers"] = []
    reseal(value)
    return value


def test_result_validation_wraps_reducer_input_failures(monkeypatch):
    # The reducer is imported inside the validator, so the module attribute is
    # the seam a hardened reducer failure would surface through.
    monkeypatch.setattr(
        "pr_review_harness.engine._reduce",
        lambda *_args: (_ for _ in ()).throw(TypeError("reducer exploded")),
    )
    assert_rejected(lambda: _validate_result(result()), "review reducer inputs are invalid")


# ---------------------------------------------------------------------------
# accepted-finding rebinding refusals
# ---------------------------------------------------------------------------


def _accepted():
    return reseal(accepted_blocker(result()))


def _patch_record(value, **fields):
    record = value["ledger"]["candidate_records"][0]
    record.update(fields)


def _patch_finding(value, **fields):
    value["findings"][0].update(fields)


def _rename_finding(value, new_id):
    value["findings"][0]["finding_id"] = new_id
    value["ledger"]["candidate_records"][0]["finding_id"] = new_id
    value["report_sections"]["blockers"][0]["finding_id"] = new_id


@pytest.mark.parametrize(
    ("mutator", "match"),
    [
        (lambda value: value["ledger"].update(candidate_records="nope"), "review candidate ledger is invalid"),
        (
            lambda value: value["ledger"]["candidate_records"].append(
                copy.deepcopy(value["ledger"]["candidate_records"][0])
            ),
            "review candidate ledger is invalid",
        ),
        (
            lambda value: value["findings"].append(
                {
                    "finding_id": "finding-non-accepted",
                    "status": "NEEDS_EVIDENCE",
                    "blocking_class": "NON_BLOCKING",
                }
            ),
            None,  # this mutation is valid; it only exercises the skip branch
        ),
        (
            lambda value: _patch_finding(
                value, location={"kind": "line", "path": "src/a.py", "side": "HEAD", "line": 0}
            ),
            "accepted finding location is invalid",
        ),
        (lambda value: _patch_finding(value, candidate_ids=[]), "accepted finding evidence is invalid"),
        (
            lambda value: _patch_finding(value, task_ids=["missing-task"]),
            "accepted finding task binding is invalid",
        ),
        (
            lambda value: value["evidence_index"].update({"ev-fixture": "not-a-dict"}),
            "accepted finding evidence is invalid",
        ),
        (
            lambda value: value["evidence_index"]["ev-fixture"].update(content_hash="zz"),
            "accepted finding evidence integrity is invalid",
        ),
        (
            lambda value: value["evidence_index"]["ev-fixture"].update(path="src/other.py"),
            "accepted finding lacks source-bound evidence",
        ),
        (lambda value: _patch_record(value, validation_state="INVALID"), "candidate binding is invalid"),
        (
            lambda value: value["task_results"]["task-fixture"].update(status="FAILED"),
            "accepted finding task is incomplete",
        ),
        (
            lambda value: value["task_results"]["task-fixture"].update(payload=[]),
            "accepted finding was not supported by its task inputs",
        ),
        (lambda value: _patch_record(value, raw="not-a-dict"), "candidate record is invalid"),
        (
            lambda value: value["task_results"]["task-fixture"].update(payload={"finding_candidates": {}}),
            "accepted finding source candidate is missing",
        ),
        (
            lambda value: value["task_results"]["task-fixture"].update(payload={"finding_candidates": []}),
            "accepted finding source candidate is unbound",
        ),
        (
            lambda value: value["ledger"]["candidate_records"][0]["raw"].update(severity="low"),
            "accepted finding differs from its provider candidate",
        ),
        (lambda value: _rename_finding(value, "finding-unverifiable"), "accepted finding identity is inconsistent"),
        (
            lambda value: value["ledger"]["candidate_records"][0]["raw"].update(unit_id="unit-other"),
            "accepted finding differs from its provider candidate",
        ),
        (
            lambda value: value["ledger"]["candidate_records"][0]["raw"].update(evidence_refs=["ev-fixture", "ev-2"]),
            "accepted finding differs from its provider candidate",
        ),
        (
            lambda value: _add_extra_finding_ref(value),
            "accepted finding evidence references are inconsistent",
        ),
    ],
)
def test_accepted_finding_rebinding_refuses_invalid_provenance(mutator, match):
    value = _accepted()
    mutator(value)
    value["result_hash"] = seal({key: item for key, item in value.items() if key != "result_hash"})
    if match is None:
        assert _validate_result(value) is None
    else:
        assert_rejected(lambda: _validate_result(value), match)


def _add_extra_finding_ref(value):
    value["evidence_index"]["ev-2"] = {
        "path": "src/b.py",
        "line_start": 1,
        "line_end": 2,
        "source_revision": value["head_sha"],
        "source_kind": "source_window",
        "content_hash": "d" * 64,
    }
    value["findings"][0]["evidence_refs"] = ["ev-fixture", "ev-2"]


def test_accepted_finding_with_mismatched_unit_is_refused():
    """A candidate consistently rebound to a unit the finding does not claim."""
    from pr_review_harness.engine import _hash
    from pr_review_harness.reconcile import stable_candidate_id

    value = _accepted()
    raw = copy.deepcopy(value["ledger"]["candidate_records"][0]["raw"])
    raw["unit_id"] = "unit-other"
    candidate_id = _hash({"task_id": "task-fixture", "index": 0, "raw": raw})[:24]
    finding_id = stable_candidate_id(value["snapshot_id"], raw)
    value["task_results"]["task-fixture"]["payload"]["finding_candidates"] = [raw]
    record = value["ledger"]["candidate_records"][0]
    record.update(candidate_id=candidate_id, finding_id=finding_id, raw=raw)
    finding = value["findings"][0]
    finding.update(candidate_id=candidate_id, candidate_ids=[candidate_id], finding_id=finding_id)
    value["report_sections"]["blockers"][0]["finding_id"] = finding_id
    value["result_hash"] = seal({key: item for key, item in value.items() if key != "result_hash"})
    assert_rejected(lambda: _validate_result(value), "accepted finding source candidate differs from report")


# ---------------------------------------------------------------------------
# report-note provenance refusals
# ---------------------------------------------------------------------------


def _note_result(section="specific_strengths"):
    from pr_review_harness.engine import _hash

    detail_key = "why_it_matters" if section == "specific_strengths" else "guidance"
    unit_id = "unit-note"
    evidence_id = "ev-note"
    source_note = {
        "unit_id": unit_id,
        "title": "Note title",
        "observation": "Note observation",
        "detail": "Note detail",
        "evidence_refs": [evidence_id],
    }
    basis = {
        "unit_id": unit_id,
        "title": "Note title",
        "observation": "Note observation",
        "detail": "Note detail",
    }
    note_id = "note-" + _hash({"snapshot_id": "snapshot-fixture", "kind": section, **basis})[:20]
    note = {
        "unit_id": unit_id,
        "title": "Note title",
        "observation": "Note observation",
        detail_key: "Note detail",
        "finding_id": note_id,
        "note_id": note_id,
        "snapshot_id": "snapshot-fixture",
        "task_ids": ["task-note"],
        "evidence_refs": [evidence_id],
    }
    value = result()
    value["task_results"] = {
        "task-note": {
            "status": "SUCCEEDED",
            "unit_ids": [unit_id],
            "input_evidence_ids": [evidence_id],
            "payload": {section: [source_note]},
        }
    }
    value["evidence_index"] = {
        evidence_id: {
            "path": "src/a.py",
            "line_start": 1,
            "line_end": 3,
            "source_revision": value["head_sha"],
            "content_hash": "c" * 64,
        }
    }
    value["report_sections"][section] = [note]
    return reseal(value)


def _resign(value):
    value["result_hash"] = seal({key: item for key, item in value.items() if key != "result_hash"})
    return value


@pytest.mark.parametrize("section", ["specific_strengths", "future_guidance"])
def test_report_notes_accept_fully_bound_provenance(section):
    value = _note_result(section)
    assert _validate_result(value) is None


@pytest.mark.parametrize(
    ("mutator", "match"),
    [
        (
            lambda value: value["report_sections"].update(specific_strengths={}),
            "review report note section is invalid",
        ),
        (
            lambda value: value["report_sections"].update(specific_strengths=["not-a-note"]),
            "review report note is invalid",
        ),
        (
            lambda value: value["report_sections"]["specific_strengths"][0].pop("why_it_matters"),
            "review report note is invalid",
        ),
        (
            lambda value: value["report_sections"]["specific_strengths"][0].update(note_id="note-forged"),
            "review report note provenance is invalid",
        ),
        (
            lambda value: value["task_results"]["task-note"].update(status="FAILED"),
            "review report note task is incomplete",
        ),
        (
            lambda value: value["task_results"]["task-note"].update(unit_ids=[]),
            "review report note unit is outside task scope",
        ),
        (
            lambda value: value["task_results"]["task-note"].update(payload={}),
            "review report note source is missing",
        ),
        (
            lambda value: value["task_results"]["task-note"]["payload"]["specific_strengths"][0].update(
                title="Different title"
            ),
            "review report note is not bound to task evidence",
        ),
        (
            lambda value: value["report_sections"]["specific_strengths"][0].update(
                evidence_refs=["ev-note", "ev-extra"]
            ),
            "review report note evidence is inconsistent",
        ),
    ],
)
def test_report_note_provenance_refusals(mutator, match):
    value = _note_result()
    if "ev-extra" in str(mutator.__code__.co_consts):
        value["evidence_index"]["ev-extra"] = {
            "path": "src/a.py",
            "line_start": 1,
            "line_end": 3,
            "source_revision": value["head_sha"],
            "content_hash": "e" * 64,
        }
    mutator(value)
    _resign(value)
    assert_rejected(lambda: _validate_result(value), match)


# ---------------------------------------------------------------------------
# stateless publication pre-flight, history and persistence refusals
# ---------------------------------------------------------------------------


class BudgetClock:
    """Monotonic clock that expires the stage budget on the Nth read."""

    def __init__(self, fail_at=None):
        self.calls = 0
        self.fail_at = fail_at

    def __call__(self):
        self.calls += 1
        if self.fail_at is not None and self.calls >= self.fail_at:
            return 10_000.0
        return float(self.calls)


def _submission_observation(provider, payload, effect_key):
    canonical = payload["body"].rsplit("\n\n<!-- pr-review-harness:", 1)[0]
    return ReviewObservation(
        slot=provider.value.slot,
        effect_key=effect_key,
        review_body_hash=hashlib.sha256(canonical.encode()).hexdigest(),
        actor_login=provider.value.actor_login,
        state=ReviewState.COMMENTED,
        review_id=1001,
    )


def _run_stateless(
    review=None,
    *,
    policy=None,
    admission=None,
    history=None,
    writer=None,
    fresh=None,
    head=None,
    submit=None,
    limits=None,
):
    value = review or result()
    policy = policy or _stateless_config()
    provider = admission or FakeAdmissionProvider(policy, preview(value, policy))
    writer = writer if writer is not None else FakeReceiptWriter()
    history = history if history is not None else FakeReceiptHistory()
    heads = iter(fresh if fresh is not None else ["a" * 40] * 6)
    head_reader = head or (lambda _timeout: next(heads))
    calls = []

    def fake_submit(payload, effect_key, _timeout):
        calls.append((payload, effect_key))
        if submit is not None:
            return submit(payload, effect_key)
        return _submission_observation(provider, payload, effect_key)

    outcome = publish_review_stateless(
        value,
        policy,
        "PUBLISH_REVIEW",
        admission_provider=provider,
        history_reader=history,
        receipt_writer=writer,
        fresh_head=head_reader,
        submit_review=fake_submit,
        limits=limits,
    )
    return outcome, calls, writer, history


def _receipt(value, **overrides):
    fields = {
        "slot": value.slot,
        "effect_key": value.effect_key,
        "result_hash": value.result_hash,
        "review_body_hash": value.review_body_hash,
        "disposition": value.disposition,
        "review_event": value.review_event,
        "actor_login": value.actor_login,
        "profile_hash": value.profile_hash,
        "upstream_run": value.upstream_run,
        "publisher_run": value.publisher_run,
    }
    fields.update(overrides)
    return AttemptReceipt(**fields)


def _review(value, **overrides):
    fields = {
        "slot": value.slot,
        "effect_key": value.effect_key,
        "review_body_hash": value.review_body_hash,
        "actor_login": value.actor_login,
        "state": ReviewState.COMMENTED,
        "review_id": 7001,
    }
    fields.update(overrides)
    return ReviewObservation(**fields)


def _no_effect(value):
    return NoEffectReceipt(publisher_run=value.publisher_run, policy_hash=value.profile_hash)


@pytest.mark.parametrize(
    ("kwargs", "reason"),
    [
        ({"limits": object()}, "publication_limits_invalid"),
        ({"effect_policy": "READ_ONLY"}, "effect_policy_denied"),
        ({"policy": {"schema_version": "2.0"}}, "publisher_config_invalid"),
        ({"policy": {"schema_version": "1.0", "enabled": False}}, "publication_disabled"),
        ({"submit_review": None}, "publisher_capability_unavailable"),
        (
            {"policy": dict(_stateless_config(), allowed_profile_versions=["other-profile"])},
            "review profile is outside publisher authorization scope",
        ),
        ({"policy": dict(_stateless_config(), allowed_actors="review-bot[bot]")}, "publisher actor policy is invalid"),
        (
            {"policy": dict(_stateless_config(), allowed_actors=["someone-else"])},
            "publisher actor is outside authorization scope",
        ),
    ],
)
def test_stateless_preflight_refusals_have_no_side_effects(kwargs, reason):
    value = result()
    policy = kwargs.pop("policy", _stateless_config())
    try:
        provider = FakeAdmissionProvider(policy, preview(value, policy))
    except PublicationRejected:
        provider = FakeAdmissionProvider(_stateless_config(), preview(value, _stateless_config()))
    writer = FakeReceiptWriter()
    history = FakeReceiptHistory()
    calls = []
    submit = kwargs.pop("submit_review", lambda payload, key, _timeout: calls.append((payload, key)))
    effect_policy = kwargs.pop("effect_policy", "PUBLISH_REVIEW")
    limits = kwargs.pop("limits", None)

    outcome = publish_review_stateless(
        value,
        policy,
        effect_policy,
        admission_provider=provider,
        history_reader=history,
        receipt_writer=writer,
        fresh_head=lambda _timeout: "a" * 40,
        submit_review=submit,
        limits=limits,
    )
    assert outcome["status"] == "REJECTED"
    assert outcome["reason"] == reason
    assert calls == []
    assert writer.receipts == []
    assert history.calls == 0


def test_stateless_refuses_non_admission_value_without_posting():
    policy = _stateless_config()
    writer = FakeReceiptWriter()
    calls = []

    class WeakAdmission:
        def admit(self, *_args):
            return {"slot": "forged"}

    outcome = publish_review_stateless(
        result(),
        policy,
        "PUBLISH_REVIEW",
        admission_provider=WeakAdmission(),
        history_reader=FakeReceiptHistory(),
        receipt_writer=writer,
        fresh_head=lambda _timeout: "a" * 40,
        submit_review=lambda payload, key, _timeout: calls.append((payload, key)),
    )
    assert outcome["status"] == "REJECTED"
    assert outcome["reason"] == "publication_admission_invalid"
    assert calls == []
    assert writer.receipts == []


@pytest.mark.parametrize(
    ("fail_at", "reason"),
    [
        (2, "publication_deadline_exhausted"),
        (3, "publication_deadline_exhausted"),
        (4, "publication_deadline_exhausted"),
        (5, "publication_deadline_exhausted"),
        (6, "publication_deadline_exhausted"),
        (7, "publication_deadline_exhausted"),
    ],
)
def test_stateless_expired_stage_budget_never_posts(monkeypatch, fail_at, reason):
    monkeypatch.setattr(publisher_module.time, "monotonic", BudgetClock(fail_at=fail_at))
    _freeze_receipt_clock(monkeypatch)
    outcome, calls, writer, _ = _run_stateless()
    assert outcome["status"] == "UNKNOWN"
    assert outcome["reason"] == reason
    assert calls == []


@pytest.mark.parametrize(
    ("history_factory", "limits", "reason"),
    [
        (lambda value: (_ for _ in ()).throw(TimeoutError()), None, "publication_history_unavailable"),
        (lambda value: object(), None, "publication_history_contract_invalid"),
        (
            lambda value: _receipt_overflow(value),
            ScanLimits(max_runs=1),
            "publication_receipt_limit_exceeded",
        ),
        (
            lambda value: _no_effect_overflow(value),
            ScanLimits(max_runs=1),
            "publication_no_effect_limit_exceeded",
        ),
        (
            lambda value: _review_overflow(value),
            ScanLimits(max_reviews=1),
            "publication_review_limit_exceeded",
        ),
    ],
)
def test_stateless_history_refusals_never_post(history_factory, limits, reason):
    policy = _stateless_config()
    provider = FakeAdmissionProvider(policy, preview(result(), policy))

    class BadHistory:
        calls = 0

        def scan(self, _slot, _limits):
            type(self).calls += 1
            return history_factory(provider.value)

    writer = FakeReceiptWriter()
    calls = []
    outcome = publish_review_stateless(
        result(),
        policy,
        "PUBLISH_REVIEW",
        admission_provider=provider,
        history_reader=BadHistory(),
        receipt_writer=writer,
        fresh_head=lambda _timeout: "a" * 40,
        submit_review=lambda payload, key, _timeout: calls.append((payload, key)),
        limits=limits,
    )
    assert outcome["status"] == "UNKNOWN"
    assert outcome["reason"] == reason
    assert calls == []
    assert writer.receipts == []


def _receipt_overflow(value):
    return HistoryScan(HistoryStatus.COMPLETE, receipts=(_receipt(value), _receipt(value)))


def _no_effect_overflow(value):
    return HistoryScan(HistoryStatus.COMPLETE, no_effects=(_no_effect(value), _no_effect(value)))


def _review_overflow(value):
    other = _review(value, review_id=7002)
    return HistoryScan(HistoryStatus.COMPLETE, reviews=(_review(value), other))


@pytest.mark.parametrize(
    ("scan_factory", "status", "reason"),
    [
        (
            lambda value: HistoryScan(
                HistoryStatus.COMPLETE, receipts=(_receipt(value), _receipt(value))
            ),
            "UNKNOWN",
            "multiple_attempt_receipts_for_slot",
        ),
        (
            lambda value: HistoryScan(
                HistoryStatus.COMPLETE,
                receipts=(_receipt(value, effect_key="effect-" + "f" * 64),),
            ),
            "CONFLICT",
            "different_result_already_claimed_slot",
        ),
    ],
)
def test_stateless_prior_receipt_state_refusals(scan_factory, status, reason):
    policy = _stateless_config()
    provider = FakeAdmissionProvider(policy, preview(result(), policy))
    outcome, calls, writer, _ = _run_stateless(
        admission=provider, history=FakeReceiptHistory([scan_factory(provider.value)])
    )
    assert outcome["status"] == status
    assert outcome["reason"] == reason
    assert calls == []
    assert writer.receipts == []


def test_stateless_stale_head_before_receipt_never_posts():
    outcome, calls, writer, _ = _run_stateless(fresh=["b" * 40])
    assert outcome["status"] == "STALE"
    assert outcome["reason"] == "head_sha_changed_before_receipt"
    assert calls == []
    assert writer.receipts == []


@pytest.mark.parametrize(
    ("writer_factory", "reason"),
    [
        (lambda: (_ for _ in ()).throw(TimeoutError()), "receipt_persistence_unknown"),
        (lambda: object(), "receipt_persistence_contract_invalid"),
        (
            lambda: ReceiptPersistence(ReceiptPersistenceStatus.REJECTED, reason_code="receipt_rejected"),
            "receipt_rejected",
        ),
        (
            lambda: ReceiptPersistence(ReceiptPersistenceStatus.UNKNOWN),
            "receipt_not_acknowledged",
        ),
    ],
)
def test_stateless_persistence_refusals_never_post(writer_factory, reason):
    class BadWriter:
        receipts = []

        def persist(self, _receipt_value, _limits):
            return writer_factory()

    outcome, calls, _, _ = _run_stateless(writer=BadWriter())
    assert outcome["status"] in {"UNKNOWN", "REJECTED"}
    assert outcome["reason"] == reason
    assert calls == []


@pytest.mark.parametrize(
    ("submit_factory", "history", "status", "reason"),
    [
        (
            lambda: (_ for _ in ()).throw(TimeoutError()),
            lambda value: [
                HistoryScan(HistoryStatus.COMPLETE),
                HistoryScan(HistoryStatus.COMPLETE, reviews=(_review(value, effect_key="effect-" + "f" * 64),)),
            ],
            "CONFLICT",
            "existing_review_conflicts_with_slot",
        ),
        (
            lambda: object(),
            lambda value: [
                HistoryScan(HistoryStatus.COMPLETE),
                HistoryScan(HistoryStatus.COMPLETE, reviews=(_review(value),)),
            ],
            "CONFIRMED",
            "confirmed_after_response_validation",
        ),
        (
            lambda: object(),
            lambda value: [
                HistoryScan(HistoryStatus.COMPLETE),
                HistoryScan(HistoryStatus.COMPLETE, reviews=(_review(value, effect_key="effect-" + "f" * 64),)),
            ],
            "CONFLICT",
            "existing_review_conflicts_with_slot",
        ),
        (
            lambda: object(),
            lambda value: [HistoryScan(HistoryStatus.COMPLETE), HistoryScan(HistoryStatus.COMPLETE)],
            "UNKNOWN",
            "submit_response_invalid",
        ),
        (
            lambda: _review_mismatch,
            lambda value: [HistoryScan(HistoryStatus.COMPLETE)],
            "UNKNOWN",
            "submit_response_binding_invalid",
        ),
    ],
)
def test_stateless_ambiguous_or_unbound_submit_is_reconciled_once(
    monkeypatch, submit_factory, history, status, reason
):
    _freeze_receipt_clock(monkeypatch)
    policy = _stateless_config()
    provider = FakeAdmissionProvider(policy, preview(result(), policy))

    def submit(_payload, _key):
        outcome = submit_factory()
        if outcome is _review_mismatch:
            return _review(provider.value, effect_key="effect-" + "f" * 64)
        return outcome

    outcome, calls, _, _ = _run_stateless(
        admission=provider,
        history=FakeReceiptHistory(history(provider.value)),
        submit=submit,
    )
    assert outcome["status"] == status
    assert outcome["reason"] == reason
    # A single ambiguous POST is attempted; it is never retried blindly.
    assert len(calls) <= 1


_review_mismatch = object()


# ---------------------------------------------------------------------------
# legacy publish_review failure branches
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# stateless publication: admission, history and reconciliation branches
# ---------------------------------------------------------------------------


def test_stateless_admission_unavailable_returns_allowlisted_reason():
    policy = _stateless_config()

    class UnavailableAdmission:
        def admit(self, *_args):
            raise PublicationAdmissionUnavailable("deadline_exhausted")

    outcome = publish_review_stateless(
        result(),
        policy,
        "PUBLISH_REVIEW",
        admission_provider=UnavailableAdmission(),
        history_reader=FakeReceiptHistory(),
        receipt_writer=FakeReceiptWriter(),
        fresh_head=lambda _timeout: "a" * 40,
        submit_review=lambda *args: None,
    )
    assert outcome["status"] == "UNKNOWN"
    assert outcome["reason"] == "deadline_exhausted"


def test_stateless_unexpected_admission_error_is_generic_unknown():
    policy = _stateless_config()

    class ExplodingAdmission:
        def admit(self, *_args):
            raise RuntimeError("private provider response")

    outcome = publish_review_stateless(
        result(),
        policy,
        "PUBLISH_REVIEW",
        admission_provider=ExplodingAdmission(),
        history_reader=FakeReceiptHistory(),
        receipt_writer=FakeReceiptWriter(),
        fresh_head=lambda _timeout: "a" * 40,
        submit_review=lambda *args: None,
    )
    assert outcome["status"] == "UNKNOWN"
    assert outcome["reason"] == "publication_admission_unavailable"


def test_stateless_mismatched_admission_context_is_rejected_without_posting():
    policy = _stateless_config()
    provider = FakeAdmissionProvider(policy, preview(result(), policy))
    provider.value = replace(provider.value, policy_hash="0" * 64)
    outcome, calls, writer, history = _run_stateless(admission=provider)
    assert outcome["status"] == "REJECTED"
    assert outcome["reason"] == "verified publication context does not match the review"
    assert calls == []
    assert writer.receipts == []
    assert history.calls == 0


@pytest.mark.parametrize(
    ("scan", "status", "reason"),
    [
        (
            HistoryScan(HistoryStatus.INCOMPLETE, reason_code="run_scan_limit"),
            "UNKNOWN",
            "run_scan_limit",
        ),
        (
            HistoryScan(HistoryStatus.COMPLETE, scanned_runs=2),
            "UNKNOWN",
            "publication_history_limit_exceeded",
        ),
    ],
)
def test_stateless_incomplete_or_over_limit_history_never_posts(scan, status, reason):
    outcome, calls, writer, _ = _run_stateless(
        history=FakeReceiptHistory([scan]), limits=ScanLimits(max_runs=1)
    )
    assert outcome["status"] == status
    assert outcome["reason"] == reason
    assert calls == []
    assert writer.receipts == []


def test_stateless_multiple_reviews_for_slot_is_a_conflict():
    policy = _stateless_config()
    provider = FakeAdmissionProvider(policy, preview(result(), policy))
    scan = HistoryScan(
        HistoryStatus.COMPLETE, reviews=(_review(provider.value), _review(provider.value, review_id=7002))
    )
    outcome, calls, _, _ = _run_stateless(admission=provider, history=FakeReceiptHistory([scan]))
    assert outcome["status"] == "CONFLICT"
    assert outcome["reason"] == "multiple_reviews_for_slot"
    assert calls == []


def test_stateless_matching_prior_receipt_stays_unknown_without_posting():
    policy = _stateless_config()
    provider = FakeAdmissionProvider(policy, preview(result(), policy))
    scan = HistoryScan(HistoryStatus.COMPLETE, receipts=(_receipt(provider.value),))
    outcome, calls, writer, _ = _run_stateless(admission=provider, history=FakeReceiptHistory([scan]))
    assert outcome["status"] == "UNKNOWN"
    assert outcome["reason"] == "prior_attempt_has_no_confirmed_review"
    assert calls == []
    assert writer.receipts == []


def test_stateless_complete_history_with_matching_review_confirms_without_posting():
    policy = _stateless_config()
    provider = FakeAdmissionProvider(policy, preview(result(), policy))
    scan = HistoryScan(HistoryStatus.COMPLETE, reviews=(_review(provider.value),))
    outcome, calls, writer, _ = _run_stateless(admission=provider, history=FakeReceiptHistory([scan]))
    assert outcome["status"] == "CONFIRMED"
    assert outcome["reason"] is None
    assert outcome["effect_observation"]["review_id"] == 7001
    assert calls == []
    assert writer.receipts == []


def _incomplete_review_scan(provider, reviews):
    return HistoryScan(
        HistoryStatus.INCOMPLETE,
        reviews=reviews,
        reason_code="receipt_history_incomplete",
        scanned_pages=1,
        reviews_complete=True,
    )


@pytest.mark.parametrize(
    ("review_factory", "status", "reason"),
    [
        (lambda value: (_review(value),), "CONFIRMED", "confirmed_from_complete_review_history"),
        (
            lambda value: (_review(value, effect_key="effect-" + "f" * 64),),
            "CONFLICT",
            "existing_review_conflicts_with_slot",
        ),
        (lambda value: (), "UNKNOWN", "publication_history_incomplete"),
    ],
)
def test_stateless_incomplete_history_reconciles_review_only(review_factory, status, reason):
    policy = _stateless_config()
    provider = FakeAdmissionProvider(policy, preview(result(), policy))
    scan = _incomplete_review_scan(provider, review_factory(provider.value))
    outcome, calls, writer, _ = _run_stateless(admission=provider, history=FakeReceiptHistory([scan]))
    assert outcome["status"] == status
    assert outcome["reason"] == reason
    assert calls == []
    assert writer.receipts == []


def test_stateless_ambiguous_post_with_confirmed_rescan_is_confirmed_once(monkeypatch):
    _freeze_receipt_clock(monkeypatch)
    policy = _stateless_config()
    provider = FakeAdmissionProvider(policy, preview(result(), policy))
    history = FakeReceiptHistory(
        [HistoryScan(HistoryStatus.COMPLETE), HistoryScan(HistoryStatus.COMPLETE, reviews=(_review(provider.value),))]
    )
    outcome, calls, _, _ = _run_stateless(
        admission=provider,
        history=history,
        submit=lambda *_: (_ for _ in ()).throw(TimeoutError()),
    )
    assert outcome["status"] == "CONFIRMED"
    assert outcome["reason"] == "confirmed_after_ambiguous_response"
    assert len(calls) == 1


def test_stateless_ambiguous_post_with_ready_rescan_stays_unknown(monkeypatch):
    _freeze_receipt_clock(monkeypatch)
    policy = _stateless_config()
    provider = FakeAdmissionProvider(policy, preview(result(), policy))
    history = FakeReceiptHistory([HistoryScan(HistoryStatus.COMPLETE), HistoryScan(HistoryStatus.COMPLETE)])
    outcome, calls, _, _ = _run_stateless(
        admission=provider,
        history=history,
        submit=lambda *_: (_ for _ in ()).throw(TimeoutError()),
    )
    assert outcome["status"] == "UNKNOWN"
    assert outcome["reason"] == "submit_response_ambiguous"
    assert len(calls) == 1


def test_stateless_head_reader_failures_are_unknown_and_never_post(monkeypatch):
    _freeze_receipt_clock(monkeypatch)
    reader = _heads([TimeoutError])
    outcome, calls, _, _ = _run_stateless(head=lambda _timeout: reader())
    assert outcome["status"] == "UNKNOWN"
    assert outcome["reason"] == "pre_receipt_head_unavailable"
    assert calls == []


def test_stateless_post_receipt_head_failures_never_post(monkeypatch):
    _freeze_receipt_clock(monkeypatch)
    reader = _heads(["a" * 40, TimeoutError])
    outcome, calls, writer, _ = _run_stateless(head=lambda _timeout: reader())
    assert outcome["status"] == "UNKNOWN"
    assert outcome["reason"] == "post_receipt_head_unavailable"
    assert calls == []
    assert len(writer.receipts) == 1


def test_stateless_stale_after_receipt_never_posts(monkeypatch):
    _freeze_receipt_clock(monkeypatch)
    outcome, calls, _, _ = _run_stateless(fresh=["a" * 40, "b" * 40])
    assert outcome["status"] == "STALE"
    assert outcome["reason"] == "head_sha_changed_after_receipt"
    assert calls == []


def test_stateless_receipt_acknowledgement_mismatch_never_posts(monkeypatch):
    _freeze_receipt_clock(monkeypatch)
    outcome, calls, _, _ = _run_stateless(writer=FakeReceiptWriter(mismatch=True))
    assert outcome["status"] == "UNKNOWN"
    assert outcome["reason"] == "receipt_acknowledgement_mismatch"
    assert calls == []


CREDENTIAL_PROVENANCE = {
    "schema": "publisher-credential-provenance.v1",
    "credential_kind": "ACTIONS_TOKEN",
    "identity_state": "PLATFORM_BOUND",
    "permission_basis": "WORKFLOW_DECLARATION",
    "write_capability": "NOT_TESTED",
    "publisher_workflow_sha256": "d" * 64,
    "declared_job_permissions": {"actions": "read", "contents": "read", "pull-requests": "write"},
}


def test_stateless_confirmed_response_reports_observed_effect_when_credential_bound(monkeypatch):
    _freeze_receipt_clock(monkeypatch)
    policy = _stateless_config()
    provider = FakeAdmissionProvider(policy, preview(result(), policy))
    provider.value = replace(provider.value, credential_provenance=CREDENTIAL_PROVENANCE)
    outcome, calls, writer, _ = _run_stateless(admission=provider)
    assert outcome["status"] == "CONFIRMED"
    assert outcome["effect_observation"] == {
        "actor_login": "review-bot[bot]",
        "review_state": "COMMENTED",
        "review_id": 1001,
        "write_capability": "OBSERVED_SUCCESS",
    }
    assert len(calls) == 1
    assert len(writer.receipts) == 1



def _heads(sequence):
    iterator = iter(sequence)

    def next_head():
        value = next(iterator)
        if isinstance(value, type) and issubclass(value, BaseException):
            raise value("head reader failed")
        return value

    return next_head


def _lookups(sequence):
    iterator = iter(sequence)
    failure = TimeoutError

    def next_lookup(key):
        value = next(iterator)
        if value is failure:
            raise value("lookup failed")
        return value

    return next_lookup


def _legacy(**overrides):
    calls = []
    inner_submit = overrides.pop("submit_review", lambda payload, key: None)

    def submit_review(payload, key):
        calls.append(("submit", payload, key))
        return inner_submit(payload, key)

    values = {
        "fresh_head": lambda: "a" * 40,
        "lookup_effect": lambda key: "not_found",
        "claim_effect": lambda key: "acquired",
        "submit_review": submit_review,
        "confirm_effect": lambda key, detail: calls.append(("confirm", key)),
        "release_effect": lambda key: calls.append(("release", key)),
    }
    values.update(overrides)
    outcome = publish_review(result(), config(), "PUBLISH_REVIEW", True, **values)
    return outcome, calls


def test_legacy_publication_requires_capabilities():
    outcome = publish_review(result(), config(), "PUBLISH_REVIEW", True, fresh_head=lambda: "a" * 40)
    assert outcome["status"] == "REJECTED"
    assert outcome["reason"] == "publisher_capability_unavailable"


def test_legacy_publication_success_confirms_once():
    outcome, calls = _legacy()
    assert outcome["status"] == "CONFIRMED"
    assert outcome["reason"] is None
    assert [entry[0] for entry in calls] == ["submit", "confirm"]


@pytest.mark.parametrize(
    ("overrides", "status", "reason", "submit_calls"),
    [
        ({"fresh_head": lambda: (_ for _ in ()).throw(TimeoutError())}, "UNKNOWN", "fresh_head_unavailable", 0),
        ({"fresh_head": lambda: "b" * 40}, "REJECTED", "head_sha_changed", 0),
        (
            {"lookup_effect": lambda key: (_ for _ in ()).throw(TimeoutError())},
            "UNKNOWN",
            "existing_effect_state_unavailable",
            0,
        ),
        ({"lookup_effect": lambda key: "confirmed"}, "CONFIRMED", "idempotent_effect_already_exists", 0),
        ({"lookup_effect": lambda key: "unknown"}, "UNKNOWN", "existing_effect_state_ambiguous", 0),
        ({"lookup_effect": lambda key: "corrupt"}, "REJECTED", "existing_effect_state_invalid", 0),
        (
            {"fresh_head": _heads(["a" * 40, TimeoutError])},
            "UNKNOWN",
            "final_fresh_head_unavailable",
            0,
        ),
        (
            {"fresh_head": _heads(["a" * 40, "a" * 40, TimeoutError])},
            "UNKNOWN",
            "final_fresh_head_unavailable",
            0,
        ),
        ({"fresh_head": _heads(["a" * 40, "b" * 40])}, "REJECTED", "head_sha_changed_before_submit", 0),
        (
            {"fresh_head": _heads(["a" * 40, "a" * 40, "b" * 40])},
            "REJECTED",
            "head_sha_changed_before_submit",
            0,
        ),
        ({"claim_effect": lambda key: "confirmed"}, "CONFIRMED", "idempotent_effect_already_exists", 0),
        (
            {"claim_effect": lambda key: (_ for _ in ()).throw(TimeoutError())},
            "UNKNOWN",
            "effect_claim_unavailable",
            0,
        ),
        ({"claim_effect": lambda key: "in_progress"}, "UNKNOWN", "effect_claim_not_acquired", 0),
        (
            {"fresh_head": _heads(["a" * 40, TimeoutError])},
            "UNKNOWN",
            "final_fresh_head_unavailable",
            0,
        ),
        (
            {"fresh_head": _heads(["a" * 40, "a" * 40, TimeoutError])},
            "UNKNOWN",
            "final_fresh_head_unavailable",
            0,
        ),
        ({"fresh_head": _heads(["a" * 40, "b" * 40])}, "REJECTED", "head_sha_changed_before_submit", 0),
        (
            {"fresh_head": _heads(["a" * 40, "a" * 40, "b" * 40])},
            "REJECTED",
            "head_sha_changed_before_submit",
            0,
        ),
        ({"claim_effect": lambda key: "confirmed"}, "CONFIRMED", "idempotent_effect_already_exists", 0),
        (
            {
                "submit_review": lambda payload, key: (_ for _ in ()).throw(TimeoutError()),
                "lookup_effect": _lookups(["not_found", "confirmed"]),
                "confirm_effect": lambda key, detail: (_ for _ in ()).throw(TimeoutError()),
            },
            "CONFIRMED",
            "confirmed_after_ambiguous_response",
            1,
        ),
        (
            {
                "submit_review": lambda payload, key: (_ for _ in ()).throw(TimeoutError()),
                "lookup_effect": _lookups(["not_found", "not_found"]),
            },
            "UNKNOWN",
            "submit_response_ambiguous",
            1,
        ),
        (
            {
                "submit_review": lambda payload, key: (_ for _ in ()).throw(TimeoutError()),
                "lookup_effect": _lookups(["not_found", TimeoutError]),
            },
            "UNKNOWN",
            "submit_response_ambiguous",
            1,
        ),
        (
            {
                "confirm_effect": lambda key, detail: (_ for _ in ()).throw(TimeoutError()),
                "lookup_effect": _lookups(["not_found", "not_found"]),
            },
            "UNKNOWN",
            "effect_recording_failed",
            1,
        ),
        (
            {
                "confirm_effect": lambda key, detail: (_ for _ in ()).throw(TimeoutError()),
                "lookup_effect": _lookups(["not_found", TimeoutError]),
            },
            "UNKNOWN",
            "effect_recording_failed",
            1,
        ),
        (
            {
                "confirm_effect": lambda key, detail: (_ for _ in ()).throw(TimeoutError()),
                "lookup_effect": _lookups(["not_found", "confirmed"]),
            },
            "CONFIRMED",
            None,
            1,
        ),
    ],
)
def test_legacy_publication_failure_branches(overrides, status, reason, submit_calls):
    outcome, calls = _legacy(**overrides)
    assert outcome["status"] == status
    assert outcome["reason"] == reason
    assert sum(1 for entry in calls if entry[0] == "submit") == submit_calls

