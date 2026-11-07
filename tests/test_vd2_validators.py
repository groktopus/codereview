"""Mutation-guided boundary contracts; deterministic, provider-free and finite."""

from __future__ import annotations

import copy

import pytest

from pr_review_harness import contracts
from pr_review_harness.claim_assessment import ClaimAssessmentAdapter
from pr_review_harness.engine import _validated_v3_causal_roles


def causal_inputs():
    role = {"support": "SUPPORTED", "assessment": "Bounded causal step.", "evidence_refs": ["ev"]}
    return {
        "assessment": {
            "contract_version": contracts.ADJUDICATION_V3,
            "source_contract_version": contracts.ADJUDICATION_V3,
            "causal_roles": {name: copy.deepcopy(role) for name in contracts.CAUSAL_ROLE_NAMES},
        },
        "delivered_evidence": [{"evidence_id": "ev"}],
        "evidence_map": {"ev": {"evidence_id": "ev", "snapshot_id": "snap"}},
        "snapshot_id": "snap",
        "provider_identity": {"provider": {"adjudication_rubric_version": contracts.ADJUDICATION_RUBRIC_VERSION}},
        "semantic_provenance": {"provider_rubric_version": contracts.ADJUDICATION_RUBRIC_VERSION},
    }


@pytest.mark.parametrize(
    "field,value",
    [
        ("assessment", None),
        ("provider_identity", None),
        ("provider_identity", {}),
        ("provider_identity", {"provider": None}),
        ("semantic_provenance", None),
        ("semantic_provenance", {}),
    ],
)
def test_causal_rejects_missing_trusted_envelopes(field, value):
    args = causal_inputs()
    args[field] = value
    assert _validated_v3_causal_roles(**args) == (False, set())


@pytest.mark.parametrize("version_key", ["contract_version", "source_contract_version"])
def test_causal_rejects_one_stale_version_even_when_the_other_is_current(version_key):
    args = causal_inputs()
    args["assessment"][version_key] = contracts.ADJUDICATION_V2
    assert _validated_v3_causal_roles(**args) == (False, set())


@pytest.mark.parametrize("envelope", ["provider_identity", "semantic_provenance"])
def test_causal_rejects_one_mismatched_rubric(envelope):
    args = causal_inputs()
    if envelope == "provider_identity":
        args[envelope]["provider"]["adjudication_rubric_version"] = "stale"
    else:
        args[envelope]["provider_rubric_version"] = "stale"
    assert _validated_v3_causal_roles(**args) == (False, set())


@pytest.mark.parametrize("roles", [None, {}, {"unknown": {}}])
def test_causal_requires_exact_role_inventory(roles):
    args = causal_inputs()
    args["assessment"]["causal_roles"] = roles
    assert _validated_v3_causal_roles(**args) == (False, set())


@pytest.mark.parametrize(
    "changes",
    [
        {"extra": True},
        {"support": "unknown"},
        {"assessment": ""},
        {"assessment": "  "},
        {"assessment": None},
        {"assessment": "x" * (contracts.MAX_CAUSAL_ASSESSMENT_BYTES + 1)},
        {"assessment": "\ud800"},
        {"evidence_refs": "ev"},
        {"evidence_refs": ["ev"] * (contracts.MAX_CAUSAL_ROLE_EVIDENCE_REFS + 1)},
        {"evidence_refs": []},
        {"support": "CONTRADICTED", "evidence_refs": []},
    ],
)
def test_causal_rejects_malformed_role_without_losing_failed_validity(changes):
    args = causal_inputs()
    args["assessment"]["causal_roles"]["impact"].update(changes)
    assert _validated_v3_causal_roles(**args) == (False, set())


def test_causal_accepts_unestablished_role_without_citation():
    args = causal_inputs()
    args["assessment"]["causal_roles"]["impact"].update(support="NOT_ESTABLISHED", evidence_refs=[])
    assert _validated_v3_causal_roles(**args) == (True, {"ev"})


@pytest.mark.parametrize(
    "count", [contracts.MAX_CAUSAL_ROLE_EVIDENCE_REFS, contracts.MAX_CAUSAL_ROLE_EVIDENCE_REFS + 1]
)
def test_causal_reference_count_boundary(count):
    args = causal_inputs()
    args["assessment"]["causal_roles"]["impact"]["evidence_refs"] = ["ev"] * count
    expected = (True, {"ev"}) if count == contracts.MAX_CAUSAL_ROLE_EVIDENCE_REFS else (False, set())
    assert _validated_v3_causal_roles(**args) == expected


@pytest.mark.parametrize("length", [256, 257])
def test_causal_reference_utf8_byte_boundary(length):
    args = causal_inputs()
    ref = "a" * length
    args["delivered_evidence"] = [{"evidence_id": ref}]
    args["evidence_map"] = {ref: {"evidence_id": ref, "snapshot_id": "snap"}}
    for role in args["assessment"]["causal_roles"].values():
        role["evidence_refs"] = [ref]
    assert _validated_v3_causal_roles(**args) == ((True, {ref}) if length == 256 else (False, set()))


def test_causal_rejects_unencodable_reference_even_when_delivered():
    args = causal_inputs()
    ref = "\ud800"
    args["delivered_evidence"] = [{"evidence_id": ref}]
    args["evidence_map"] = {ref: {"evidence_id": ref, "snapshot_id": "snap"}}
    for role in args["assessment"]["causal_roles"].values():
        role["evidence_refs"] = [ref]
    assert _validated_v3_causal_roles(**args) == (False, set())


def choice(**changes):
    return {"type": "choice", "choice": "yes", "probabilities": {"yes": 0.6, "no": 0.4}, "confidence": 0.5, **changes}


@pytest.mark.parametrize(
    "answer",
    [
        None,
        {},
        choice(extra=True),
        choice(type="noul"),
        choice(choice="missing"),
        choice(probabilities={"yes": 1.0}),
        choice(probabilities={"yes": 0.6, "no": 0.4, "extra": 0.0}),
        choice(probabilities=None),
        choice(probabilities={"yes": 1.1, "no": -0.1}),
        choice(probabilities={"yes": True, "no": 0.0}),
        choice(probabilities={"yes": float("nan"), "no": 0.0}),
        choice(probabilities={"yes": 0.9, "no": 0.9}),
        choice(probabilities={"yes": 0.2, "no": 0.8}),
    ],
)
def test_choice_rejects_malformed_shapes_probabilities_and_nonmaximum_selection(answer):
    assert ClaimAssessmentAdapter._valid_choice(answer, {"yes", "no"}) is False


@pytest.mark.parametrize("probabilities", [{"yes": 0.5, "no": 0.5}, {"yes": 0.5000005, "no": 0.4999995}])
def test_choice_accepts_maximum_or_bounded_tie(probabilities):
    assert ClaimAssessmentAdapter._valid_choice(choice(probabilities=probabilities), {"yes", "no"}) is True


@pytest.mark.parametrize("size", [contracts.MAX_CAUSAL_ASSESSMENT_BYTES, contracts.MAX_CAUSAL_ASSESSMENT_BYTES + 1])
def test_causal_statement_utf8_byte_boundary(size):
    args = causal_inputs()
    args["assessment"]["causal_roles"]["impact"]["assessment"] = "x" * size
    assert _validated_v3_causal_roles(**args) == (
        (True, {"ev"}) if size == contracts.MAX_CAUSAL_ASSESSMENT_BYTES else (False, set())
    )
