"""Bounded deterministic VD-2 reducer and validation-boundary contracts.

No providers, subprocesses, network, or production-source copies are used here.
The decision-table oracle is fixed by the disposition contract, not confidence.
"""

from __future__ import annotations

import copy
import itertools

import pytest

from pr_review_harness.claim_assessment import ClaimAssessmentAdapter
from pr_review_harness.contracts import ContractIssue, validate_adjudication
from pr_review_harness.engine import _reduce, _validated_v3_causal_roles


def result(**overrides):
    return {"findings": [], "coverage_state": "COMPLETE", "freshness": "CURRENT", **overrides}


@pytest.mark.parametrize("coverage", ["COMPLETE", "COMPLETE_WITH_WAIVERS", "PARTIAL", "UNKNOWN", None])
@pytest.mark.parametrize("freshness", ["CURRENT", "STALE", "UNKNOWN", None])
@pytest.mark.parametrize("policy_valid,allow", list(itertools.product([False, True], repeat=2)))
def test_blocker_precedes_incompleteness_and_advisory_synthesis(coverage, freshness, policy_valid, allow):
    value = result(
        findings=[{"status": "ACCEPTED", "blocking_class": "BLOCKING", "finding_id": "known"}],
        coverage_state=coverage,
        freshness=freshness,
        budget={"budget_breaches": [{"reason": "OUTPUT_BYTE_LIMIT_EXCEEDED"}]},
        advisory_assessment={"status": "COMPLETE", "recommendation": "APPROVE", "confidence": 1.0},
        report_sections={"blockers": [], "summary": "No changes needed"},
    )
    before = copy.deepcopy(value)
    assert _reduce(value, allow, policy_valid) == "REQUEST_CHANGES"
    assert value == before
    assert _reduce(value, allow, policy_valid) == "REQUEST_CHANGES"
    assert value == before


@pytest.mark.parametrize("coverage", ["COMPLETE", "COMPLETE_WITH_WAIVERS", "PARTIAL", "UNKNOWN", "FUTURE", None])
@pytest.mark.parametrize("freshness", ["CURRENT", "STALE", "UNKNOWN", "FUTURE", None])
@pytest.mark.parametrize("policy_valid,allow", list(itertools.product([False, True], repeat=2)))
def test_empty_decision_table_and_replay(coverage, freshness, policy_valid, allow):
    value = result(coverage_state=coverage, freshness=freshness)
    if coverage == "COMPLETE_WITH_WAIVERS":
        # A valid waived state carries a receipt; a bare enum is not a contract input.
        value["waivers_applied"] = [{"waiver_id": "accepted"}]
    expected = "INCOMPLETE"
    if coverage in {"COMPLETE", "COMPLETE_WITH_WAIVERS"} and freshness == "CURRENT" and policy_valid:
        expected = "APPROVE" if allow and coverage == "COMPLETE" else "COMMENT"
    before = copy.deepcopy(value)
    for _ in range(3):
        assert _reduce(value, allow, policy_valid) == expected
        assert value == before


@pytest.mark.parametrize(
    "waiver_fields",
    [
        {"waivers_applied": [{"waiver_id": "accepted"}]},
        {"completeness_summary": {"waived": 1}},
        {"coverage_ledger": [{"state": "WAIVED"}]},
    ],
)
def test_each_waiver_receipt_independently_prevents_empty_approval(waiver_fields):
    assert _reduce(result(**waiver_fields), True, True) == "COMMENT"


@pytest.mark.parametrize(
    "neutral_fields",
    [
        {},
        {"waivers_applied": []},
        {"completeness_summary": None},
        {"completeness_summary": {}},
        {"completeness_summary": {"waived": 0}},
        {"coverage_ledger": [None, "WAIVED", {}, {"state": "COVERED"}]},
        {"budget": {}},
        {"budget": {"budget_breaches": []}},
    ],
)
def test_absent_or_nonwaived_optional_receipts_do_not_invent_a_waiver(neutral_fields):
    assert _reduce(result(**neutral_fields), True, True) == "APPROVE"


@pytest.mark.parametrize("status", ["ACCEPTED", "NEEDS_EVIDENCE", "CONTRADICTED", "UNSUPPORTED", None])
@pytest.mark.parametrize("blocking_class", ["BLOCKING", "UNRESOLVED", "NON_BLOCKING", None])
def test_finding_classification_decision_table(status, blocking_class):
    value = result(findings=[{"status": status, "blocking_class": blocking_class}])
    if status == "ACCEPTED" and blocking_class == "BLOCKING":
        expected = "REQUEST_CHANGES"
    elif status != "UNSUPPORTED" and blocking_class == "UNRESOLVED":
        expected = "INCOMPLETE"
    else:
        expected = "COMMENT"
    assert _reduce(value, True, True) == expected


def test_budget_breach_alone_prevents_approval():
    assert _reduce(result(budget={"budget_breaches": [{"reason": "ceiling"}]}), True, True) == "INCOMPLETE"


@pytest.mark.parametrize("confidence", [None, True, False, "1", -0.01, 1.01, float("nan"), float("inf")])
def test_invalid_confidence_is_not_an_accepted_native_choice(confidence):
    answer = {
        "type": "choice",
        "choice": "supported",
        "probabilities": {"supported": 1.0, "unknown": 0.0},
        "confidence": confidence,
    }
    assert ClaimAssessmentAdapter._valid_choice(answer, {"supported", "unknown"}) is False


@pytest.mark.parametrize("confidence", [0, 0.5, 1])
def test_valid_confidence_does_not_grant_approval_authority(confidence):
    answer = {
        "type": "choice",
        "choice": "supported",
        "probabilities": {"supported": 1.0, "unknown": 0.0},
        "confidence": confidence,
    }
    assert ClaimAssessmentAdapter._valid_choice(answer, {"supported", "unknown"}) is True
    value = result(
        findings=[{"status": "NEEDS_EVIDENCE", "blocking_class": "UNRESOLVED"}],
        advisory_assessment=answer,
    )
    assert _reduce(value, True, True) == "INCOMPLETE"


@pytest.mark.parametrize(
    "refs,code",
    [
        ([], "supported_claim_requires_evidence"),
        (None, "invalid_assessment_array"),
        ([False], "invalid_assessment_array"),
    ],
)
def test_invalid_adjudication_evidence_is_rejected_with_stable_reason(refs, code):
    payload = {
        "outcome": "SUPPORTED",
        "observation_support": "SUPPORTED",
        "consequence_support": "SUPPORTED",
        "rule_connection_support": "SUPPORTED",
        "introducedness": "INTRODUCED",
        "evidence_refs": refs,
        "assumptions": [],
        "uncertainties": [],
        "summary": "Supported claim requires bounded evidence.",
        "material_consequence": True,
    }
    with pytest.raises(ContractIssue) as raised:
        validate_adjudication(payload)
    assert raised.value.code == code


@pytest.mark.parametrize("fault", ["none", "undelivered", "foreign-snapshot", "identity-mismatch", "missing"])
def test_causal_role_refs_require_delivered_snapshot_bound_evidence(fault):
    assessment = {
        "contract_version": "semantic-adjudication.v3",
        "source_contract_version": "semantic-adjudication.v3",
        "causal_roles": {
            role: {"support": "SUPPORTED", "assessment": "Bounded causal link.", "evidence_refs": ["ev-1"]}
            for role in ("behavior", "consumer", "impact")
        },
    }
    evidence = {"ev-1": {"evidence_id": "ev-1", "snapshot_id": "snap-1"}}
    delivered = [evidence["ev-1"]]
    if fault == "undelivered":
        delivered = []
    elif fault == "foreign-snapshot":
        evidence["ev-1"]["snapshot_id"] = "snap-other"
    elif fault == "identity-mismatch":
        evidence["ev-1"]["evidence_id"] = "ev-other"
    elif fault == "missing":
        evidence = {}
    valid, refs = _validated_v3_causal_roles(
        assessment,
        delivered,
        evidence,
        "snap-1",
        {"provider": {"adjudication_rubric_version": "causal-roles.behavior-consumer-impact.v1"}},
        {"provider_rubric_version": "causal-roles.behavior-consumer-impact.v1"},
    )
    if fault == "none":
        assert valid is True
        assert refs == {"ev-1"}
    else:
        assert valid is False
        assert refs == set()
