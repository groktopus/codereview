from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import replace

import pytest

from pr_review_harness.claim_triage import ClaimTriageError, ClaimTriagePolicy, triage_claim

_REQUIRED = {
    "observation_support": "SUPPORTED",
    "consequence_support": "SUPPORTED",
    "rule_connection_support": "SUPPORTED",
    "materiality": "MATERIAL",
    "missing_context": "NO_MISSING_CONTEXT_IDENTIFIED",
}


def _sha(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    ).hexdigest()


def _policy(**overrides) -> ClaimTriagePolicy:
    raw = {
        "contract_version": "claim-triage-policy.1",
        "policy_id": "test-policy-v1",
        "expected_provider_id": "typesafe",
        "configured_model_id": "jev-latest",
        "allowed_provider_model_ids": ["jev-1.13.0"],
        "required_dimensions": list(_REQUIRED),
        "required_choices": dict(_REQUIRED),
        "contradiction_choices": {"observation_support": ["CONTRADICTED"]},
        "disagreement_rules": [],
    }
    raw.update(overrides)
    return ClaimTriagePolicy.from_mapping(raw)


def _assessment(choices: dict[str, str] | None = None) -> dict:
    selections = dict(_REQUIRED)
    selections["introducedness"] = "INTRODUCED"
    if choices:
        selections.update(choices)
    answers = {}
    for dimension, choice in selections.items():
        options = {
            "observation_support": ["SUPPORTED", "NOT_ESTABLISHED", "CONTRADICTED", "UNCERTAIN"],
            "consequence_support": ["SUPPORTED", "NOT_ESTABLISHED", "CONTRADICTED", "UNCERTAIN"],
            "rule_connection_support": ["SUPPORTED", "NOT_ESTABLISHED", "CONTRADICTED", "UNCERTAIN"],
            "materiality": ["MATERIAL", "NOT_ESTABLISHED", "NOT_MATERIAL", "UNCERTAIN"],
            "missing_context": ["MISSING_CONTEXT_IDENTIFIED", "NO_MISSING_CONTEXT_IDENTIFIED", "UNCERTAIN"],
            "introducedness": ["INTRODUCED", "REEXPOSED", "PRE_EXISTING", "UNKNOWN"],
        }[dimension]
        probabilities = {option: 0.0 for option in options}
        probabilities[choice] = 1.0
        answers[dimension] = {
            "question_id": f"question-{dimension}",
            "status": "ANSWERED",
            "native_primitive": "Choice",
            "choice": choice,
            "probabilities": probabilities,
            "confidence": 0.01,
            "evidence_refs": ["evidence-1"],
            "interpretation": "advisory_uncalibrated",
            "invalid_answer_hash": None,
            "error_code": None,
        }
    provenance = {
        "contract_version": "claim-assessment.1",
        "native_contract": "system-one-choice-v1",
        "provider_id": "typesafe",
        "configured_model_id": "jev-latest",
        "provider_model_id": "jev-1.13.0",
        "model_identity_source": "endpoint_reported",
        "request_hash": "1" * 64,
        "response_hash": "2" * 64,
        "candidate_hash": "3" * 64,
        "evidence_hash": "4" * 64,
        "question_hash": "5" * 64,
        "snapshot_id": "synthetic-snapshot",
        "snapshot_hash": "6" * 64,
        "profile_id": "synthetic-profile",
        "profile_hash": "7" * 64,
        "base_sha": "a" * 40,
        "head_sha": "b" * 40,
    }
    return {
        "contract_version": "claim-assessment.1",
        "status": "COMPLETE",
        "assessments": answers,
        "usage": {"known": True, "input_tokens": 10, "output_tokens": 5},
        "provenance": provenance,
        "elapsed_ms": 12.5,
        "decision": "ADVISORY_ONLY",
    }


def test_all_required_trusted_policy_conditions_are_needed_for_support_state():
    assessment = _assessment()
    result = triage_claim(assessment, _policy())

    assert result["status"] == "SUPPORTED_FOR_REVIEW"
    assert result["decision"] == "ADVISORY_ONLY"
    assert result["policy"]["sha256"] == _policy().policy_hash
    assert result["assessment_hash"] == _sha(assessment)
    assert result["provenance"] == assessment["provenance"]
    assert result["dimensions"] == assessment["assessments"]
    assert result["conflicts"] == []


def test_materiality_without_established_consequence_is_needs_evidence_and_conflict():
    result = triage_claim(
        _assessment({"consequence_support": "NOT_ESTABLISHED"}),
        _policy(),
    )

    assert result["status"] == "NEEDS_EVIDENCE"
    assert result["conflicts"] == [
        {
            "conflict_id": "materiality_without_established_consequence",
            "dimensions": ["materiality", "consequence_support"],
            "choices": {"materiality": "MATERIAL", "consequence_support": "NOT_ESTABLISHED"},
            "kind": "requires_evidence",
        }
    ]


def test_required_context_gap_blocks_support_even_when_other_dimensions_pass():
    result = triage_claim(
        _assessment({"missing_context": "MISSING_CONTEXT_IDENTIFIED"}),
        _policy(),
    )
    assert result["status"] == "NEEDS_EVIDENCE"
    assert result["evidence_gaps"] == [{"reason_code": "required_choice_not_established", "detail": "missing_context"}]


def test_not_shown_required_dimension_is_a_gap_not_transport_unavailability():
    assessment = _assessment()
    assessment["assessments"]["rule_connection_support"].update(
        status="NOT_SHOWN", choice=None, probabilities=None, confidence=None, error_code="source_not_available"
    )
    result = triage_claim(assessment, _policy())

    assert result["status"] == "NEEDS_EVIDENCE"
    assert result["unavailable_reasons"] == []
    assert result["evidence_gaps"] == [
        {"reason_code": "required_dimension_not_shown", "detail": "rule_connection_support"}
    ]


def test_omitted_required_answer_is_unavailable_even_when_siblings_are_positive():
    assessment = _assessment()
    assessment["status"] = "PARTIAL"
    assessment["assessments"]["rule_connection_support"].update(
        status="OMITTED", choice=None, probabilities=None, confidence=None, error_code="answer_omitted"
    )
    result = triage_claim(assessment, _policy())

    assert result["status"] == "UNAVAILABLE"
    assert {item["reason_code"] for item in result["unavailable_reasons"]} >= {
        "assessment_not_complete",
        "required_answer_unavailable",
    }
    assert result["dimensions"]["observation_support"]["choice"] == "SUPPORTED"


def test_conflicts_are_retained_when_missing_required_answer_takes_status_precedence():
    assessment = _assessment({"consequence_support": "NOT_ESTABLISHED"})
    assessment["status"] = "PARTIAL"
    assessment["assessments"]["observation_support"].update(
        status="OMITTED", choice=None, probabilities=None, confidence=None, error_code="answer_omitted"
    )
    result = triage_claim(assessment, _policy())

    assert result["status"] == "UNAVAILABLE"
    assert any(item["conflict_id"] == "materiality_without_established_consequence" for item in result["conflicts"])


def test_policy_defined_exact_disagreement_is_visible_and_cannot_promote_support():
    raw_rules = [
        {
            "rule_id": "support-versus-rule-gap",
            "when": {"observation_support": "SUPPORTED", "rule_connection_support": "NOT_ESTABLISHED"},
        }
    ]
    policy = _policy(disagreement_rules=raw_rules)
    assessment = _assessment({"rule_connection_support": "NOT_ESTABLISHED"})
    result = triage_claim(assessment, policy)

    assert result["status"] == "DISAGREEMENT"
    assert any(item["conflict_id"] == "policy_disagreement:support-versus-rule-gap" for item in result["conflicts"])

    contradicted = triage_claim(_assessment({"observation_support": "CONTRADICTED"}), policy)
    assert contradicted["status"] == "CONTRADICTED"


def test_endpoint_identity_mismatch_is_unavailable_and_provenance_is_preserved():
    assessment = _assessment()
    assessment["provenance"]["provider_model_id"] = "unapproved-other-model"
    result = triage_claim(assessment, _policy())

    assert result["status"] == "UNAVAILABLE"
    assert {item["reason_code"] for item in result["unavailable_reasons"]} == {"provider_model_identity_mismatch"}
    assert result["provenance"] == assessment["provenance"]


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    [
        ("configured_model_id", "different-alias", "configured_model_mismatch"),
        ("model_identity_source", "not_reported_by_endpoint", "provider_model_identity_mismatch"),
        ("response_hash", None, "assessment_transport_or_source_hash_missing"),
    ],
)
def test_transport_or_model_identity_mismatch_is_unavailable(field, value, reason):
    assessment = _assessment()
    assessment["provenance"][field] = value
    result = triage_claim(assessment, _policy())
    assert result["status"] == "UNAVAILABLE"
    assert any(item["reason_code"] == reason for item in result["unavailable_reasons"])


@pytest.mark.parametrize("assessment", [None, {"status": "FAILED", "assessments": {}, "provenance": {}}])
def test_absent_or_failed_assessment_is_unavailable(assessment):
    result = triage_claim(assessment, _policy())
    assert result["status"] == "UNAVAILABLE"


def test_confidence_does_not_change_a_choice_based_triage_state():
    policy = _policy()
    low = _assessment()
    high = copy.deepcopy(low)
    for answer in low["assessments"].values():
        answer["confidence"] = 0.0
    for answer in high["assessments"].values():
        answer["confidence"] = 1.0

    assert triage_claim(low, policy)["status"] == "SUPPORTED_FOR_REVIEW"
    assert triage_claim(high, policy)["status"] == "SUPPORTED_FOR_REVIEW"


def test_policy_cannot_omit_required_factors_or_configure_a_support_promotion():
    with pytest.raises(ClaimTriageError, match="invalid_required_dimensions"):
        _policy(required_dimensions=["materiality"], required_choices={"materiality": "MATERIAL"})

    with pytest.raises(ClaimTriageError, match="invalid_disagreement_rule"):
        _policy(
            disagreement_rules=[
                {
                    "rule_id": "unsafe-promotion",
                    "when": {"observation_support": "SUPPORTED", "consequence_support": "SUPPORTED"},
                    "status": "SUPPORTED_FOR_REVIEW",
                }
            ]
        )


def test_policy_object_cannot_be_forged_with_replace_or_mutable_field_aliases():
    policy = _policy()
    with pytest.raises(ClaimTriageError, match="unsafe_base_required_choices|invalid_required_dimensions"):
        replace(policy, required_dimensions=("materiality",), required_choices=(("materiality", "MATERIAL"),))
    with pytest.raises(ClaimTriageError, match="policy_hash_mismatch"):
        replace(policy, policy_hash="0" * 64)

    shared_models = ["jev-1.13.0"]
    with pytest.raises(ClaimTriageError, match="invalid_allowed_provider_models"):
        replace(policy, allowed_provider_model_ids=shared_models)
    shared_models.append("unapproved-model")
    assert policy.allowed_provider_model_ids == ("jev-1.13.0",)
    with pytest.raises(ClaimTriageError, match="invalid_disagreement_rules"):
        replace(policy, disagreement_rules=[])


def test_unhashable_policy_choices_are_typed_policy_errors():
    with pytest.raises(ClaimTriageError, match="invalid_required_choices"):
        _policy(required_choices={**_REQUIRED, "materiality": ["MATERIAL"]})
    with pytest.raises(ClaimTriageError, match="invalid_disagreement_condition"):
        _policy(
            disagreement_rules=[
                {"rule_id": "bad-choice", "when": {"materiality": [], "observation_support": "SUPPORTED"}}
            ]
        )
    with pytest.raises(ClaimTriageError, match="invalid_contradiction_choices"):
        _policy(contradiction_choices={"observation_support": [["CONTRADICTED"]]})


def test_malformed_or_invalid_answer_is_unavailable_not_a_partial_support():
    assessment = _assessment()
    assessment["assessments"]["materiality"]["confidence"] = float("nan")
    result = triage_claim(assessment, _policy())
    assert result["status"] == "UNAVAILABLE"
    assert any(item["reason_code"] == "assessment_invalid_shape" for item in result["unavailable_reasons"])

    assessment = _assessment()
    assessment["assessments"]["materiality"]["confidence"] = 0.5
    assessment["assessments"]["materiality"]["probabilities"]["MATERIAL"] = 10**1000
    result = triage_claim(assessment, _policy())
    assert result["status"] == "UNAVAILABLE"
    assert any(item["reason_code"] == "assessment_invalid_shape" for item in result["unavailable_reasons"])

    assessment = _assessment()
    assessment["assessments"]["materiality"]["confidence"] = 0.5
    assessment["assessments"]["materiality"]["probabilities"]["MATERIAL"] = 2.0
    result = triage_claim(assessment, _policy())
    assert result["status"] == "UNAVAILABLE"
    assert any(item["reason_code"] == "required_answer_invalid" for item in result["unavailable_reasons"])


def test_assessment_bounds_and_unhashable_choices_fail_closed_without_raising():
    oversized = _assessment()
    oversized["extra"] = "x" * 130_000
    result = triage_claim(oversized, _policy())
    assert result["status"] == "UNAVAILABLE"
    assert result["assessment_hash"] is None

    deep = _assessment()
    nested = None
    for _ in range(70):
        nested = [nested]
    deep["extra"] = nested
    result = triage_claim(deep, _policy())
    assert result["status"] == "UNAVAILABLE"

    malformed = _assessment()
    malformed["assessments"]["observation_support"]["choice"] = []
    result = triage_claim(malformed, _policy())
    assert result["status"] == "UNAVAILABLE"
    assert any(item["reason_code"] == "required_answer_invalid" for item in result["unavailable_reasons"])
