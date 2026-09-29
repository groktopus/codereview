from __future__ import annotations

import hashlib
import json
import time
from dataclasses import replace

import pytest

from pr_review_harness.claim_assessment import (
    ClaimAssessmentAdapter,
    ClaimAssessmentError,
)

BASE_SHA = "a" * 40
HEAD_SHA = "b" * 40


def _candidate() -> dict:
    return {
        "candidate_id": "candidate-17",
        "title": "Missing validation",
        "observation": "The new handler forwards an unchecked value.",
        "consequence": "A malformed value may raise an exception.",
        "rule_or_contract": "The handler input contract requires validation.",
        "evidence_refs": ["ev-head"],
    }


def _evidence(evidence_id="ev-head", side="HEAD", content="handler forwards value") -> dict:
    return {
        "evidence_id": evidence_id,
        "source_kind": "repository_file",
        "content": content,
        "content_hash": hashlib.sha256(content.encode()).hexdigest(),
        "trust": "repository_evidence",
        "path": "src/handler.py",
        "source_revision": BASE_SHA if side == "BASE" else HEAD_SHA if side == "HEAD" else "c" * 40,
        "snapshot_id": "snapshot-1",
        "line": 12,
    }


def _identity() -> dict:
    return {
        "snapshot_id": "snapshot-1",
        "snapshot_hash": "1" * 64,
        "profile_id": "profile-v1",
        "profile_hash": "2" * 64,
        "base_sha": BASE_SHA,
        "head_sha": HEAD_SHA,
    }


def _limits(**changes) -> dict:
    return {
        "max_input_bytes_per_task": 60_000,
        "max_output_bytes_per_task": 50_000,
        "deadline_seconds": 2,
        **changes,
    }


def _primary_assessment() -> dict:
    refs = ["ev-head"]
    return {
        "contract_version": "semantic-adjudication.v3",
        "source_contract_version": "semantic-adjudication.v3",
        "outcome": "SUPPORTED",
        "observation_support": "SUPPORTED",
        "consequence_support": "NOT_ESTABLISHED",
        "rule_connection_support": "SUPPORTED",
        "introducedness": "INTRODUCED",
        "evidence_refs": refs,
        "assumptions": [],
        "uncertainties": [],
        "summary": "Primary model assessment summary.",
        "material_consequence": False,
        "causal_roles": {
            role: {
                "support": "SUPPORTED",
                "assessment": f"Primary {role} assessment.",
                "evidence_refs": refs,
            }
            for role in ("behavior", "consumer", "impact")
        },
    }


def _envelope(request_bytes: bytes, *, omit=(), invalid=(), model="jev-1.13.0") -> bytes:
    request = json.loads(request_bytes)
    answers = {}
    for question_id, question in request["questions"].items():
        if question_id in omit:
            continue
        options = question["criteria"]
        keys = list(options)
        if question_id in invalid:
            answers[question_id] = {"type": "choice", "choice": keys[0], "probabilities": {}, "confidence": 0.8}
            continue
        probabilities = {key: 0.0 for key in keys}
        probabilities[keys[0]] = 1.0
        answers[question_id] = {
            "type": "choice",
            "choice": keys[0],
            "probabilities": probabilities,
            "confidence": 1.0,
        }
    return json.dumps(
        {"model": model, "request_id": "req-1", "answers": answers, "usage": {"input_tokens": 10, "output_tokens": 5}}
    ).encode()


def _adapter(call):
    return ClaimAssessmentAdapter(call, "jev-latest")


def test_serialized_native_choice_request_binds_candidate_and_exact_evidence_refs():
    captured = {}

    def call(raw, deadline, cap):
        captured.update(request=json.loads(raw), deadline=deadline, cap=cap)
        return _envelope(raw)

    result = _adapter(call).assess(_candidate(), [_evidence()], _identity(), _limits())
    request = captured["request"]
    assert request["model"] == "jev-latest"
    assert request["state"]["assessment_identity"] == _identity()
    assert len(request["questions"]) == 5
    assert {q["type"] for q in request["questions"].values()} == {"choice"}
    assert set(request["state"]) == {"assessment_identity", "candidate", "cited_evidence"}
    assert [item["evidence_id"] for item in request["state"]["cited_evidence"]] == ["ev-head"]
    assert "jev-latest" == result["provenance"]["configured_model_id"]
    assert "jev-1.13.0" == result["provenance"]["provider_model_id"]
    assert result["status"] == "COMPLETE"
    assert result["assessments"]["introducedness"]["status"] == "NOT_SHOWN"
    assert result["assessments"]["observation_support"]["interpretation"] == "advisory_uncalibrated"
    assert result["usage"] == {"known": True, "input_tokens": 10, "output_tokens": 5}


def test_bound_transport_dispatch_state_is_retained_without_request_bytes():
    class Transport:
        last_dispatch_state = "post_guard_pretransport"

        def __call__(self, raw, _deadline, _cap):
            self.last_dispatch_state = "http_attempted"
            return _envelope(raw)

    result = ClaimAssessmentAdapter(Transport(), "jev-latest").assess(
        _candidate(), [_evidence()], _identity(), _limits()
    )

    assert result["provenance"]["dispatch_state"] == "http_attempted"
    assert "request_bytes" not in result["provenance"]
    assert result["usage"] == {"known": True, "input_tokens": 10, "output_tokens": 5}


def test_v2_binds_primary_generated_assessment_separately_and_preserves_v1_contract():
    captured = {}

    def call(raw, _deadline, _cap):
        captured["raw"] = raw
        return _envelope(raw)

    adapter = _adapter(call)
    primary = _primary_assessment()
    prepared = adapter.prepare(_candidate(), [_evidence()], _identity(), _limits(), primary_assessment=primary)
    request = json.loads(prepared.request_bytes)
    assert prepared.contract_version == "claim-assessment.2"
    assert request["state"]["assessment_contract_version"] == "claim-assessment.2"
    assert request["state"]["primary_assessment"] == primary
    assert request["state"]["candidate"] != request["state"]["primary_assessment"]
    assert len(request["questions"]) == 5
    assert (
        prepared.primary_assessment_hash
        == hashlib.sha256(
            json.dumps(primary, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
    )
    result = adapter.assess_prepared(prepared, _limits())
    assert result["contract_version"] == "claim-assessment.2"
    assert result["decision"] == "ADVISORY_ONLY"
    assert result["provenance"]["primary_assessment_hash"] == prepared.primary_assessment_hash
    assert captured["raw"] == prepared.request_bytes


def test_v2_rejects_primary_assessment_refs_without_delivered_source_records():
    primary = _primary_assessment()
    primary["causal_roles"]["consumer"]["evidence_refs"] = ["not-delivered"]
    with pytest.raises(ClaimAssessmentError, match="candidate_evidence_reference_missing"):
        _adapter(lambda *_args: b"").prepare(
            _candidate(), [_evidence()], _identity(), _limits(), primary_assessment=primary
        )


def test_v2_accepts_source_contract_array_counts_and_long_text_within_request_bound():
    primary = _primary_assessment()
    primary["assumptions"] = [f"assumption {index}" for index in range(33)]
    primary["uncertainties"] = ["u" * 11_900]
    primary["causal_roles"]["behavior"]["assessment"] = "role assessment " * 100

    prepared = _adapter(lambda *_args: b"").prepare(
        _candidate(), [_evidence()], _identity(), _limits(), primary_assessment=primary
    )
    serialized = json.loads(prepared.request_bytes)["state"]["primary_assessment"]

    assert serialized["assumptions"] == primary["assumptions"]
    assert serialized["uncertainties"] == primary["uncertainties"]
    assert serialized["causal_roles"]["behavior"]["assessment"] == primary["causal_roles"]["behavior"]["assessment"]
    assert len(prepared.request_bytes) < 64_000


def test_v2_rejects_whole_request_over_intrinsic_cap_before_transport_dispatch():
    calls = []
    primary = _primary_assessment()
    primary["assumptions"] = ["x" * 11_900 for _ in range(6)]

    with pytest.raises(ClaimAssessmentError, match="request_exceeds_intrinsic_limit"):
        _adapter(lambda *args: calls.append(args)).prepare(
            _candidate(), [_evidence()], _identity(), _limits(), primary_assessment=primary
        )

    assert calls == []


def test_v2_rejects_unhashable_primary_evidence_reference_as_contract_error():
    primary = _primary_assessment()
    primary["evidence_refs"] = [{"not": "a reference"}]

    with pytest.raises(ClaimAssessmentError, match="invalid_primary_assessment_evidence_refs"):
        _adapter(lambda *_args: b"").prepare(
            _candidate(), [_evidence()], _identity(), _limits(), primary_assessment=primary
        )


def test_v2_rejects_unhashable_candidate_ref_in_prepared_request_without_type_error():
    adapter = _adapter(lambda *_args: b"")
    prepared = adapter.prepare(
        _candidate(), [_evidence()], _identity(), _limits(), primary_assessment=_primary_assessment()
    )
    request = json.loads(prepared.request_bytes)
    request["state"]["candidate"]["evidence_refs"] = [{}]
    tampered_bytes = json.dumps(request, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode()

    with pytest.raises(ClaimAssessmentError, match="invalid_prepared_assessment"):
        adapter.assess_prepared(replace(prepared, request_bytes=tampered_bytes), _limits())


def test_v2_keeps_original_candidate_refs_separate_from_primary_source_union():
    primary = _primary_assessment()
    primary["causal_roles"]["impact"]["evidence_refs"] = ["ev-extra"]
    extra = _evidence("ev-extra", "HEAD", "caller verifies result")
    prepared = _adapter(lambda *_args: b"").prepare(
        _candidate(), [_evidence(), extra], _identity(), _limits(), primary_assessment=primary
    )
    request = json.loads(prepared.request_bytes)
    assert request["state"]["candidate"]["evidence_refs"] == ["ev-head"]
    assert request["state"]["primary_assessment"]["causal_roles"]["impact"]["evidence_refs"] == ["ev-extra"]
    assert [row["evidence_id"] for row in request["state"]["cited_evidence"]] == ["ev-head", "ev-extra"]
    assert prepared.evidence_refs == ("ev-head", "ev-extra")
    assert (
        _adapter(lambda *_args: _envelope(prepared.request_bytes)).assess_prepared(prepared, _limits())["status"]
        == "COMPLETE"
    )


def test_prepared_estimate_quotes_identical_bytes_and_separates_response_from_ipc_caps():
    class EstimatingTransport:
        def __init__(self):
            self.request = None

        def __call__(self, _raw, _deadline, _cap):
            return b""

        def estimate_call(self, request_bytes, limits):
            self.request = request_bytes
            return {
                "provider_calls": 1,
                "input_bytes": len(request_bytes),
                "max_output_bytes": min(8192, limits["max_output_bytes_per_task"]),
                "deadline_seconds": min(8, limits["deadline_seconds"]),
            }

    transport = EstimatingTransport()
    adapter = ClaimAssessmentAdapter(transport, "jev-latest")
    prepared = adapter.prepare(
        _candidate(), [_evidence()], _identity(), _limits(), primary_assessment=_primary_assessment()
    )

    quote = adapter.estimate_prepared(prepared, _limits(max_output_bytes_per_task=20_000))

    assert transport.request is prepared.request_bytes
    assert quote["input_bytes"] == len(prepared.request_bytes)
    assert quote["provider_response_bytes"] == 8192
    assert quote["max_output_bytes"] == 20_000


def test_prepared_estimate_rejects_quote_for_different_request_length():
    class BadEstimator:
        def __call__(self, _raw, _deadline, _cap):
            return b""

        def estimate_call(self, request_bytes, _limits):
            return {
                "provider_calls": 1,
                "input_bytes": len(request_bytes) + 1,
                "max_output_bytes": 8192,
                "deadline_seconds": 2,
            }

    adapter = ClaimAssessmentAdapter(BadEstimator(), "jev-latest")
    prepared = adapter.prepare(
        _candidate(), [_evidence()], _identity(), _limits(), primary_assessment=_primary_assessment()
    )

    with pytest.raises(ClaimAssessmentError, match="invalid_claim_transport_estimate"):
        adapter.estimate_prepared(prepared, _limits())


def test_prepared_estimate_accepts_shorter_transport_deadline():
    class ShortEstimator:
        def __call__(self, _raw, _deadline, _cap):
            return b""

        def estimate_call(self, request_bytes, _limits):
            return {
                "provider_calls": 1,
                "input_bytes": len(request_bytes),
                "max_output_bytes": 8192,
                "deadline_seconds": 0.5,
            }

    adapter = ClaimAssessmentAdapter(ShortEstimator(), "jev-latest")
    prepared = adapter.prepare(
        _candidate(), [_evidence()], _identity(), _limits(), primary_assessment=_primary_assessment()
    )

    assert adapter.estimate_prepared(prepared, _limits())["deadline_seconds"] == 0.5


@pytest.mark.parametrize("deadline", [2.01, float("inf"), float("nan")])
def test_prepared_estimate_rejects_deadline_over_caller_limit_or_nonfinite(deadline):
    class LongEstimator:
        def __call__(self, _raw, _deadline, _cap):
            return b""

        def estimate_call(self, request_bytes, _limits):
            return {
                "provider_calls": 1,
                "input_bytes": len(request_bytes),
                "max_output_bytes": 8192,
                "deadline_seconds": deadline,
            }

    adapter = ClaimAssessmentAdapter(LongEstimator(), "jev-latest")
    prepared = adapter.prepare(
        _candidate(), [_evidence()], _identity(), _limits(), primary_assessment=_primary_assessment()
    )

    with pytest.raises(ClaimAssessmentError, match="invalid_claim_transport_estimate"):
        adapter.estimate_prepared(prepared, _limits())


@pytest.mark.parametrize("malformation", ["tampered_request", "list_candidate", "unhashable_refs"])
def test_prepared_estimate_rejects_malformed_prepared_before_estimator(malformation):
    class CountingEstimator:
        called = False

        def __call__(self, _raw, _deadline, _cap):
            return b""

        def estimate_call(self, request_bytes, _limits):
            self.called = True
            return {
                "provider_calls": 1,
                "input_bytes": len(request_bytes),
                "max_output_bytes": 8192,
                "deadline_seconds": 1,
            }

    transport = CountingEstimator()
    adapter = ClaimAssessmentAdapter(transport, "jev-latest")
    prepared = adapter.prepare(
        _candidate(), [_evidence()], _identity(), _limits(), primary_assessment=_primary_assessment()
    )
    if malformation == "tampered_request":
        request = json.loads(prepared.request_bytes)
        request["state"]["assessment_identity"]["snapshot_id"] = "other-snapshot"
        tampered_bytes = json.dumps(request, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode()
        prepared = replace(prepared, request_bytes=tampered_bytes)
    elif malformation == "list_candidate":
        request = json.loads(prepared.request_bytes)
        request["state"]["candidate"] = []
        tampered_bytes = json.dumps(request, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode()
        prepared = replace(
            prepared, request_bytes=tampered_bytes, request_hash=hashlib.sha256(tampered_bytes).hexdigest()
        )
    else:
        prepared = replace(prepared, evidence_refs=({},))

    with pytest.raises(ClaimAssessmentError, match="invalid_prepared_assessment"):
        adapter.estimate_prepared(prepared, _limits())
    assert not transport.called


def test_v2_prepared_primary_hash_is_checked_before_dispatch():
    called = False

    def call(*_args):
        nonlocal called
        called = True
        return b"{}"

    adapter = _adapter(call)
    prepared = adapter.prepare(
        _candidate(), [_evidence()], _identity(), _limits(), primary_assessment=_primary_assessment()
    )
    tampered = replace(prepared, primary_assessment_hash="0" * 64)
    with pytest.raises(ClaimAssessmentError, match="invalid_prepared_assessment"):
        adapter.assess_prepared(tampered, _limits())
    assert not called


@pytest.mark.parametrize(
    ("response_model", "error_code"),
    [("jev-other", "model_identity_mismatch"), (None, "model_identity_missing")],
)
def test_v2_requires_validated_endpoint_model_identity(response_model, error_code):
    def call(raw, _deadline, _cap):
        body = _envelope(raw, model=response_model) if response_model is not None else _envelope(raw)
        if response_model is None:
            envelope = json.loads(body)
            envelope.pop("model")
            body = json.dumps(envelope).encode()
        return body

    adapter = _adapter(call)
    prepared = adapter.prepare(
        _candidate(), [_evidence()], _identity(), _limits(), primary_assessment=_primary_assessment()
    )
    result = adapter.assess_prepared(prepared, _limits())
    assert result["status"] == "FAILED"
    assert result["provenance"]["error_code"] == error_code
    assert all(item["status"] in {"FAILED", "NOT_SHOWN"} for item in result["assessments"].values())
    assert not any(item["status"] == "ANSWERED" for item in result["assessments"].values())
    if response_model is not None:
        assert "provider_model_id" not in result["provenance"]
        assert "invalid_provider_model_id_hash" in result["provenance"]


def test_v2_latest_alias_accepts_only_versioned_jev_reported_model():
    adapter = _adapter(lambda raw, _deadline, _cap: _envelope(raw, model="jev-1.13.0"))
    prepared = adapter.prepare(
        _candidate(), [_evidence()], _identity(), _limits(), primary_assessment=_primary_assessment()
    )
    result = adapter.assess_prepared(prepared, _limits())
    assert result["status"] == "COMPLETE"
    assert result["provenance"]["provider_model_id"] == "jev-1.13.0"
    assert result["provenance"]["model_identity_source"] == "endpoint_reported_validated"


def test_v2_pinned_model_requires_exact_endpoint_report():
    adapter = ClaimAssessmentAdapter(lambda raw, _deadline, _cap: _envelope(raw, model="jev-1.14.0"), "jev-1.13.0")
    prepared = adapter.prepare(
        _candidate(), [_evidence()], _identity(), _limits(), primary_assessment=_primary_assessment()
    )
    result = adapter.assess_prepared(prepared, _limits())
    assert result["status"] == "FAILED"
    assert result["provenance"]["error_code"] == "model_identity_mismatch"
    assert "provider_model_id" not in result["provenance"]


@pytest.mark.parametrize("source_kind", ["diff", "base_file", "head_file", "source_window", "profile_context"])
def test_native_claim_contract_preserves_snapshot_collector_source_kinds(source_kind):
    evidence = _evidence()
    evidence["source_kind"] = source_kind
    prepared = _adapter(lambda *_args: b"").prepare(_candidate(), [evidence], _identity(), _limits())
    request = json.loads(prepared.request_bytes)
    assert request["state"]["cited_evidence"][0]["source_kind"] == source_kind
    assert request["state"]["cited_evidence"][0]["evidence_id"] == "ev-head"


def test_native_claim_contract_rejects_unknown_source_kind_and_source_window_tampering():
    adapter = _adapter(lambda *_args: pytest.fail("invalid evidence must not reach transport"))
    unknown = _evidence()
    unknown["source_kind"] = "invented_window"
    with pytest.raises(ClaimAssessmentError, match="invalid_evidence_source_kind"):
        adapter.prepare(_candidate(), [unknown], _identity(), _limits())

    tampered = _evidence()
    tampered["source_kind"] = "source_window"
    tampered["content"] += "tampered"
    with pytest.raises(ClaimAssessmentError, match="evidence_content_hash_mismatch"):
        adapter.prepare(_candidate(), [tampered], _identity(), _limits())


def test_larger_caller_ceiling_is_applied_to_exact_prepared_body():
    calls = []

    def call(raw, _deadline, _cap):
        calls.append(raw)
        return _envelope(raw)

    adapter = _adapter(call)
    large_limits = _limits(max_input_bytes_per_task=128_000)
    prepared = adapter.prepare(_candidate(), [_evidence()], _identity(), large_limits)
    assert isinstance(prepared.request_bytes, bytes)
    assert len(prepared.request_bytes) <= 64_000
    assert prepared.question_hash
    smaller_limits = _limits(max_input_bytes_per_task=len(prepared.request_bytes) - 1)
    with pytest.raises(ClaimAssessmentError, match="request_exceeds_limit"):
        adapter.assess_prepared(prepared, smaller_limits)
    assert calls == []

    result = adapter.assess_prepared(prepared, large_limits)
    assert result["provenance"]["request_hash"] == hashlib.sha256(prepared.request_bytes).hexdigest()
    assert calls == [prepared.request_bytes]


def test_prepared_request_over_smaller_caller_ceiling_rejects_before_transport():
    calls = []
    adapter = _adapter(lambda raw, *_args: calls.append(raw) or _envelope(raw))
    with pytest.raises(ClaimAssessmentError, match="request_exceeds_limit"):
        adapter.prepare(_candidate(), [_evidence()], _identity(), _limits(max_input_bytes_per_task=64))
    assert calls == []


def test_estimate_rejects_exact_body_over_caller_ceiling_before_quote():
    class EstimatingTransport:
        def __init__(self):
            self.quoted = False

        def __call__(self, *_args):
            return b"{}"

        def estimate_call(self, request_bytes, limits):
            self.quoted = True
            return {
                "provider_calls": 1,
                "input_bytes": len(request_bytes),
                "max_output_bytes": min(8_192, limits["max_output_bytes_per_task"]),
                "deadline_seconds": 1,
            }

    transport = EstimatingTransport()
    adapter = ClaimAssessmentAdapter(transport, "jev-latest")
    prepared = adapter.prepare(
        _candidate(),
        [_evidence()],
        _identity(),
        _limits(max_input_bytes_per_task=128_000),
        primary_assessment=_primary_assessment(),
    )
    exact_cap = len(prepared.request_bytes) - 1

    with pytest.raises(ClaimAssessmentError, match="request_exceeds_limit"):
        adapter.estimate_prepared(prepared, _limits(max_input_bytes_per_task=exact_cap))
    assert transport.quoted is False


def test_actual_prepared_request_over_native_cap_fails_without_truncation_or_transport():
    calls = []
    candidate = _candidate()
    evidence = []
    refs = []
    for index in range(3):
        evidence_id = f"ev-large-{index}"
        content = (chr(ord("a") + index) * 23_000)
        evidence.append(_evidence(evidence_id, "HEAD", content))
        refs.append(evidence_id)
    candidate["evidence_refs"] = refs

    with pytest.raises(ClaimAssessmentError, match="request_exceeds_intrinsic_limit"):
        _adapter(lambda raw, *_args: calls.append(raw) or _envelope(raw)).prepare(
            candidate, evidence, _identity(), _limits(max_input_bytes_per_task=128_000)
        )
    assert calls == []


def test_tampered_prepared_bytes_are_rejected_before_dispatch():
    called = False

    def call(*_args):
        nonlocal called
        called = True
        return b"{}"

    adapter = _adapter(call)
    prepared = adapter.prepare(_candidate(), [_evidence()], _identity(), _limits())
    tampered = replace(prepared, request_bytes=prepared.request_bytes + b" ")
    with pytest.raises(ClaimAssessmentError, match="invalid_prepared_assessment"):
        adapter.assess_prepared(tampered, _limits())
    assert not called


def test_question_ids_are_bound_to_candidate_and_dimension():
    requests = []

    def call(raw, _deadline, _cap):
        requests.append(json.loads(raw))
        return _envelope(raw)

    adapter = _adapter(call)
    first = _candidate()
    second = {**first, "candidate_id": "candidate-18"}
    adapter.assess(first, [_evidence()], _identity(), _limits())
    adapter.assess(second, [_evidence()], _identity(), _limits())
    first_ids = set(requests[0]["questions"])
    second_ids = set(requests[1]["questions"])
    assert len(first_ids) == 5 and len(second_ids) == 5
    assert first_ids.isdisjoint(second_ids)


def test_introducedness_uses_separate_question_only_with_both_revision_sides():
    candidate = {**_candidate(), "evidence_refs": ["ev-base", "ev-head"]}
    seen = {}

    def call(raw, _deadline, _cap):
        seen["request"] = json.loads(raw)
        return _envelope(raw)

    result = _adapter(call).assess(
        candidate, [_evidence("ev-base", "BASE", "old value"), _evidence()], _identity(), _limits()
    )
    assert len(seen["request"]["questions"]) == 6
    assert result["assessments"]["introducedness"]["status"] == "ANSWERED"
    assert result["assessments"]["introducedness"]["question_id"] in seen["request"]["questions"]


def test_side_labels_without_exact_revision_and_snapshot_binding_do_not_enable_introducedness():
    candidate = {**_candidate(), "evidence_refs": ["ev-base", "ev-head"]}
    # `side` labels alone are untrusted; only exact immutable revisions count.
    evidence = [
        {**_evidence("ev-base", "OTHER", "old value"), "side": "BASE"},
        {**_evidence("ev-head", "OTHER"), "side": "HEAD"},
    ]
    called = {}

    def call(raw, _deadline, _cap):
        called["request"] = json.loads(raw)
        return _envelope(raw)

    result = _adapter(call).assess(candidate, evidence, _identity(), _limits())
    assert len(called["request"]["questions"]) == 5
    assert result["assessments"]["introducedness"]["status"] == "NOT_SHOWN"
    with pytest.raises(ClaimAssessmentError, match="evidence_snapshot_mismatch"):
        _adapter(call).assess(_candidate(), [_evidence() | {"snapshot_id": "other-snapshot"}], _identity(), _limits())


def test_invalid_question_is_quarantined_while_valid_siblings_survive():
    bad_id = None

    def call(raw, _deadline, _cap):
        nonlocal bad_id
        bad_id = next(iter(json.loads(raw)["questions"]))
        return _envelope(raw, invalid={bad_id})

    result = _adapter(call).assess(_candidate(), [_evidence()], _identity(), _limits())
    states = [item["status"] for item in result["assessments"].values()]
    assert states.count("INVALID") == 1
    assert states.count("ANSWERED") == 4
    invalid = next(item for item in result["assessments"].values() if item["status"] == "INVALID")
    assert invalid["invalid_answer_hash"]
    assert invalid["probabilities"] is None
    assert result["status"] == "PARTIAL"


def test_native_choice_distribution_accepts_a_top_probability_tie_but_not_a_lower_choice():
    def call_with_tie(raw, _deadline, _cap):
        envelope = json.loads(_envelope(raw))
        answer = next(iter(envelope["answers"].values()))
        keys = list(answer["probabilities"])
        answer["choice"] = keys[0]
        answer["probabilities"] = {key: 0.5 if key in keys[:2] else 0.0 for key in keys}
        answer["confidence"] = 0.5
        return json.dumps(envelope).encode()

    tied = _adapter(call_with_tie).assess(_candidate(), [_evidence()], _identity(), _limits())
    assert sum(item["status"] == "ANSWERED" for item in tied["assessments"].values()) == 5

    def call_lower_choice(raw, _deadline, _cap):
        envelope = json.loads(_envelope(raw))
        answer = next(iter(envelope["answers"].values()))
        keys = list(answer["probabilities"])
        answer["choice"] = keys[1]
        answer["probabilities"] = {key: 0.0 for key in keys}
        answer["probabilities"][keys[0]] = 1.0
        answer["confidence"] = 1.0
        return json.dumps(envelope).encode()

    lower = _adapter(call_lower_choice).assess(_candidate(), [_evidence()], _identity(), _limits())
    assert sum(item["status"] == "INVALID" for item in lower["assessments"].values()) == 1


def test_missing_question_is_explicitly_omitted_and_probability_shape_is_validated():
    omitted_id = None

    def call(raw, _deadline, _cap):
        nonlocal omitted_id
        omitted_id = next(iter(json.loads(raw)["questions"]))
        return _envelope(raw, omit={omitted_id})

    result = _adapter(call).assess(_candidate(), [_evidence()], _identity(), _limits())
    omitted = next(item for item in result["assessments"].values() if item["question_id"] == omitted_id)
    assert omitted["status"] == "OMITTED"
    assert omitted["error_code"] == "answer_omitted"
    assert result["status"] == "PARTIAL"


def test_unexpected_questions_are_hashed_not_retained():
    def call(raw, _deadline, _cap):
        envelope = json.loads(_envelope(raw))
        envelope["answers"]["extra"] = {"private": "discard this"}
        return json.dumps(envelope).encode()

    result = _adapter(call).assess(_candidate(), [_evidence()], _identity(), _limits())
    assert result["status"] == "COMPLETE"
    assert result["provenance"]["unexpected_answer_count"] == 1
    assert len(result["provenance"]["unexpected_answers"][0]["answer_hash"]) == 64
    assert "discard this" not in repr(result)


@pytest.mark.parametrize("raw", [b'{"answers":{"x":1,"x":2}}', b'{"answers":NaN}', b"not-json"])
def test_malformed_json_fails_with_response_hash_without_raw_body(raw):
    result = _adapter(lambda *_args: raw).assess(_candidate(), [_evidence()], _identity(), _limits())
    assert result["status"] == "FAILED"
    assert all(item["status"] == "FAILED" or item["status"] == "NOT_SHOWN" for item in result["assessments"].values())
    assert result["provenance"]["response_hash"] == hashlib.sha256(raw).hexdigest()
    assert "not-json" not in repr(result)


def test_excessively_nested_json_is_rejected_with_bounded_failure():
    raw = b'{"answers":{},"extra":' + b"[" * 1000 + b"0" + b"]" * 1000 + b"}"
    result = _adapter(lambda *_args: raw).assess(_candidate(), [_evidence()], _identity(), _limits())
    assert result["status"] == "FAILED"
    assert all(item["status"] == "FAILED" or item["status"] == "NOT_SHOWN" for item in result["assessments"].values())


@pytest.mark.parametrize("field", ["confidence", "probability"])
def test_huge_json_integer_in_native_answer_is_quarantined(field):
    def call(raw, _deadline, _cap):
        envelope = json.loads(_envelope(raw))
        question_id = next(iter(envelope["answers"]))
        answer = envelope["answers"][question_id]
        if field == "confidence":
            answer["confidence"] = 10**1000
        else:
            choice = answer["choice"]
            answer["probabilities"][choice] = 10**1000
        return json.dumps(envelope).encode()

    result = _adapter(call).assess(_candidate(), [_evidence()], _identity(), _limits())
    invalid = [item for item in result["assessments"].values() if item["status"] == "INVALID"]
    assert len(invalid) == 1
    assert invalid[0]["error_code"] == "invalid_choice_answer"
    assert invalid[0]["invalid_answer_hash"]


def test_evidence_closure_and_content_hash_are_checked_before_transport():
    called = False

    def call(*_args):
        nonlocal called
        called = True
        return b"{}"

    with pytest.raises(ClaimAssessmentError, match="candidate_evidence_reference_missing"):
        _adapter(call).assess(_candidate(), [], _identity(), _limits())
    with pytest.raises(ClaimAssessmentError, match="evidence_content_hash_mismatch"):
        _adapter(call).assess(_candidate(), [{**_evidence(), "content_hash": "0" * 64}], _identity(), _limits())
    assert not called


@pytest.mark.parametrize(
    ("field", "value", "code"),
    [
        ("max_input_bytes_per_task", True, "invalid_input_byte_limit"),
        ("max_input_bytes_per_task", 0, "invalid_input_byte_limit"),
        ("max_input_bytes_per_task", "128000", "invalid_input_byte_limit"),
        ("max_output_bytes_per_task", 0, "invalid_output_byte_limit"),
        ("deadline_seconds", float("inf"), "invalid_deadline"),
    ],
)
def test_finite_limits_reject_invalid_values(field, value, code):
    with pytest.raises(ClaimAssessmentError, match=code):
        _adapter(lambda *_args: b"{}").assess(_candidate(), [_evidence()], _identity(), _limits(**{field: value}))


def test_request_cap_is_enforced_before_transport():
    called = False

    def call(*_args):
        nonlocal called
        called = True
        return b"{}"

    with pytest.raises(ClaimAssessmentError, match="request_exceeds_limit"):
        _adapter(call).assess(_candidate(), [_evidence()], _identity(), _limits(max_input_bytes_per_task=64))
    assert not called


def test_slow_noncooperative_transport_is_reported_failed_after_deadline():
    def call(raw, _deadline, _cap):
        time.sleep(0.02)
        return _envelope(raw)

    result = _adapter(call).assess(_candidate(), [_evidence()], _identity(), _limits(deadline_seconds=0.005))
    assert result["status"] == "FAILED"
    assert all(item["status"] == "FAILED" or item["status"] == "NOT_SHOWN" for item in result["assessments"].values())
    assert result["elapsed_ms"] >= 5
