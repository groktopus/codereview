import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from source_record_decision import (  # noqa: E402
    CHOICES,
    QUESTION_ID,
    SourceRecordDecisionError,
    _question_id,
    run_source_record_decision,
)


def _record(record_id="record-a", summary="Possible concern", evidence_refs=None):
    return {"record_id": record_id, "summary": summary, "evidence_refs": evidence_refs or ["ev-1"]}


def _source(records, status="completed"):
    return json.dumps({"contract_version": "shadow-source-audit.v1", "status": status, "records": records}).encode()


def _jev(request, *, choice="UNCERTAIN", subject_kind="source_auditor_record"):
    req = json.loads(request)
    return json.dumps({
        "contract_version": "source-record-jev.v1",
        "model_id": req["expected_model_id"],
        "subject_kind": subject_kind,
        "subject_id": req["subject_id"],
        "record_id": req["record_id"],
        "question_id": req["question"]["question_id"],
        "status": "completed",
        "choice": choice,
        "probabilities": {name: (1.0 if name == choice else 0.0) for name in CHOICES},
    }).encode()


def _run(source_bytes, *, jev=None, clock=lambda: 0.0):
    calls = {"source": [], "jev": []}

    def source_transport(raw, timeout, cap):
        calls["source"].append((raw, timeout, cap))
        parsed = json.loads(raw)
        assert parsed["subject_kind"] == "frozen_case"
        assert "writer_candidate" not in parsed and "jev_classification" not in parsed
        return source_bytes

    def jev_transport(raw, timeout, cap):
        calls["jev"].append((raw, timeout, cap))
        return jev(raw) if jev else _jev(raw)

    result = run_source_record_decision(
        subject_id="case-1", expected_model_id="jev-test-v1", source_task={"task_id": "task-1", "prompt": "inspect"},
        source_evidence=[{"evidence_id": "ev-1", "content": "frozen evidence"}],
        source_transport=source_transport, jev_transport=jev_transport, clock=clock,
    )
    return result, calls


def test_source_record_is_deterministically_selected_and_typed_as_advisory():
    records = [_record("record-z", "second"), _record("record-a", "first")]
    left, left_calls = _run(_source(records))
    right, _ = _run(_source(list(reversed(records))))

    request = json.loads(left_calls["jev"][0][0])
    assert left["contract_version"] == "source-record-decision-result.v1"
    assert left["subject_kind"] == "frozen_case"
    assert left["jev_subject_kind"] == "source_auditor_record"
    assert left["selected_count"] == 1 and left["unselected_count"] == 1
    assert left["selected_record_id_sha256"] == right["selected_record_id_sha256"]
    assert request["question"]["dimension"] == QUESTION_ID
    assert request["question"]["choices"] == list(CHOICES)
    assert request["evidence_refs"] == ["ev-1"]
    assert request["evidence"] == [{"evidence_id": "ev-1", "content": "frozen evidence"}]
    assert "untrusted data" in request["question"]["instruction"]
    assert left["advisory_choice"] == "UNCERTAIN"
    assert left["disposition"] == "not_set"
    assert left["writer_comparison"] == "not_applicable"
    assert left["transport_invocations"] == 2 and left["retries"] == 0
    assert "Possible concern" not in json.dumps(left)
    assert "record-a" not in json.dumps(left) and "record-z" not in json.dumps(left)


@pytest.mark.parametrize("raw,status", [
    (_source([], "abstained"), "abstained"),
])
def test_no_source_records_means_not_run_not_a_negative_decision(raw, status):
    result, calls = _run(raw)
    assert result["source_status"] == status
    assert result["source_record_count"] == 0
    assert result["selected_count"] == result["unselected_count"] == 0
    assert result["jev_status"] == "not_run"
    assert result["advisory_choice"] is None
    assert result["terminal_state"] == "incomplete"
    assert result["transport_invocations"] == 1 and result["retries"] == 0
    assert calls["jev"] == []


def test_source_contract_rejects_unbound_evidence_without_jev_or_retry():
    result, calls = _run(_source([_record(evidence_refs=["not-in-snapshot"])]))
    assert result["source_status"] == "failed"
    assert result["error_code"] == "source_record_evidence_invalid"
    assert result["jev_status"] == "not_run"
    assert result["transport_invocations"] == 1 and result["retries"] == 0
    assert calls["source"] and calls["jev"] == []


@pytest.mark.parametrize("raw", [
    b'{"contract_version":"shadow-source-audit.v1","contract_version":"shadow-source-audit.v1","status":"abstained","records":[]}',
    b'{"contract_version":"shadow-source-audit.v1","status":"abstained","records":[],"x":NaN}',
])
def test_source_response_rejects_duplicate_keys_and_nonfinite_constants(raw):
    result, calls = _run(raw)
    assert result["source_status"] == "failed"
    assert result["error_code"] == "source_response_invalid"
    assert result["jev_status"] == "not_run"
    assert len(calls["source"]) == 1 and calls["jev"] == []


def test_source_record_summary_uses_utf8_byte_limit():
    result, _ = _run(_source([_record(summary="é" * 2001)]))
    assert result["source_status"] == "failed"
    assert result["error_code"] == "source_record_invalid"


def test_transport_exception_code_is_never_echoed_into_receipt():
    class ProviderFailure(Exception):
        code = "private_provider_token_123"

    def fail(*_args):
        raise ProviderFailure()

    result = run_source_record_decision(
        subject_id="case-1", expected_model_id="jev-test-v1", source_task={}, source_evidence=[],
        source_transport=fail, jev_transport=lambda *_: b"{}",
    )
    assert result["error_code"] == "transport_or_contract_failed"
    assert "private_provider_token_123" not in json.dumps(result)


@pytest.mark.parametrize("raw", [
    lambda request: (b'{"contract_version":"source-record-jev.v1","contract_version":"source-record-jev.v1"}'),
    lambda request: b'{"contract_version":"source-record-jev.v1","subject_id":"x","value":NaN}',
])
def test_jev_response_rejects_duplicate_keys_and_nonfinite_constants(raw):
    result, _ = _run(_source([_record()]), jev=raw)
    assert result["jev_status"] == "failed"
    assert result["error_code"] == "jev_response_invalid"
    assert result["advisory_choice"] is None


def test_jev_subject_kind_mismatch_is_incomplete_and_never_compared_to_writer():
    result, calls = _run(_source([_record()]), jev=lambda raw: _jev(raw, subject_kind="writer_candidate"))
    assert len(calls["jev"]) == 1
    assert result["jev_status"] == "failed"
    assert result["error_code"] == "jev_subject_mismatch"
    assert result["terminal_state"] == "incomplete"
    assert result["writer_comparison"] == "not_applicable"
    assert result["advisory_choice"] is None


def test_jev_abstention_is_preserved_without_a_negative_choice():
    def abstain(raw):
        request = json.loads(raw)
        return json.dumps({
            "contract_version": "source-record-jev.v1",
            "model_id": request["expected_model_id"],
            "subject_kind": "source_auditor_record",
            "subject_id": request["subject_id"],
            "record_id": request["record_id"],
            "question_id": request["question"]["question_id"],
            "status": "abstained",
        }).encode()

    result, _ = _run(_source([_record()]), jev=abstain)
    assert result["jev_status"] == "abstained"
    assert result["terminal_state"] == "abstained"
    assert result["advisory_choice"] is None
    assert result["advisory_probabilities"] is None
    assert result["disposition"] == "not_set"


def test_shared_deadline_passes_only_remaining_budget_to_jev():
    ticks = iter((0.0, 80.0, 80.0, 90.0))
    result, calls = _run(_source([_record()]), clock=lambda: next(ticks))
    assert calls["jev"][0][1] == 10.0
    assert result["jev_status"] == "completed"
    assert result["transport_invocations"] == 2 and result["retries"] == 0


def test_late_source_suppresses_jev_including_for_empty_abstention():
    ticks = iter((0.0, 91.0))
    result, calls = _run(_source([], "abstained"), clock=lambda: next(ticks))
    assert result["jev_status"] == "not_run"
    assert result["error_code"] == "budget_exceeded"
    assert result["terminal_state"] == "incomplete"
    assert result["transport_invocations"] == 1 and result["retries"] == 0
    assert calls["jev"] == []


def test_late_jev_is_incomplete_even_when_transport_returns_valid_response():
    ticks = iter((0.0, 80.0, 80.0, 91.0))
    result, calls = _run(_source([_record()]), clock=lambda: next(ticks))
    assert calls["jev"][0][1] == 10.0
    assert result["jev_status"] == "failed"
    assert result["error_code"] == "budget_exceeded"
    assert result["terminal_state"] == "incomplete"
    assert result["advisory_choice"] is None
    assert result["transport_invocations"] == 2 and result["retries"] == 0


def test_jev_model_id_must_match_the_pinned_expected_id():
    def wrong_model(raw):
        value = json.loads(_jev(raw))
        value["model_id"] = "other-model"
        return json.dumps(value).encode()

    result, _ = _run(_source([_record()]), jev=wrong_model)
    assert result["jev_status"] == "failed"
    assert result["error_code"] == "jev_model_mismatch"
    assert result["advisory_choice"] is None


def test_stable_question_id_is_bound_to_record_id():
    assert _question_id("record-a") != _question_id("record-b")
    with pytest.raises(SourceRecordDecisionError):
        run_source_record_decision(
            subject_id="case-1", expected_model_id="jev-test-v1", source_task={}, source_evidence=[],
            source_transport=lambda *_: b"{}", jev_transport=lambda *_: b"{}", deadline_seconds=91,
        )
