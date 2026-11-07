"""Exact adjudication reason-code and positive-shape mutation oracles."""

import copy

import pytest

from pr_review_harness import contracts


def payload():
    role = {"support": "SUPPORTED", "assessment": "Bounded causal link.", "evidence_refs": ["ev"]}
    return {
        "contract_version": contracts.ADJUDICATION_V3,
        "outcome": "SUPPORTED",
        "observation_support": "SUPPORTED",
        "consequence_support": "SUPPORTED",
        "rule_connection_support": "SUPPORTED",
        "introducedness": "INTRODUCED",
        "evidence_refs": ["ev"],
        "assumptions": [],
        "uncertainties": [],
        "summary": "Bounded summary.",
        "material_consequence": True,
        "causal_roles": {name: copy.deepcopy(role) for name in contracts.CAUSAL_ROLE_NAMES},
    }


@pytest.mark.parametrize("outcome", ["SUPPORTED", "NOT_SUPPORTED", "UNCERTAIN", "CONTRADICTED"])
def test_normalized_outcomes_and_role_keys_are_exact(outcome):
    value = payload()
    value["outcome"] = outcome
    before = copy.deepcopy(value)
    assert contracts.validate_adjudication(value) == {**value, "source_contract_version": contracts.ADJUDICATION_V3}
    assert value == before


@pytest.mark.parametrize(
    "path,value,reason",
    [
        ([], None, "invalid_assessment"),
        (["extra"], True, "invalid_assessment_fields"),
        (["contract_version"], "future", "unsupported_assessment_contract"),
        (["contract_version"], contracts.ADJUDICATION_V2, "invalid_assessment_fields"),
        (["outcome"], "future", "invalid_assessment_outcome"),
        (["observation_support"], "future", "invalid_assessment_support"),
        (["introducedness"], "future", "invalid_assessment_semantics"),
        (["material_consequence"], 1, "invalid_assessment_semantics"),
        (["summary"], "", "invalid_assessment_summary"),
        (["causal_roles"], {}, "invalid_causal_roles"),
        (["causal_roles", "impact", "extra"], True, "invalid_causal_role_fields"),
        (["causal_roles", "impact", "support"], "future", "invalid_causal_role_support"),
        (["causal_roles", "impact", "assessment"], "", "invalid_causal_role_assessment"),
        (["causal_roles", "impact", "evidence_refs"], [], "invalid_causal_role_evidence_refs"),
    ],
)
def test_invalid_fields_expose_exact_reason_codes(path, value, reason):
    document = payload()
    if not path:
        document = value
    else:
        target = document
        for key in path[:-1]:
            target = target[key]
        target[path[-1]] = value
    with pytest.raises(contracts.ContractIssue) as raised:
        contracts.validate_adjudication(document)
    assert raised.value.code == reason


@pytest.mark.parametrize("key", ["observation_support", "consequence_support", "rule_connection_support", None])
def test_each_support_dimension_independently_requires_evidence(key):
    document = payload()
    document["evidence_refs"] = []
    for name in ("observation_support", "consequence_support", "rule_connection_support"):
        document[name] = "SUPPORTED" if name == key else "NOT_ESTABLISHED"
    if key is None:
        assert contracts.validate_adjudication(document)["evidence_refs"] == []
    else:
        with pytest.raises(contracts.ContractIssue) as raised:
            contracts.validate_adjudication(document)
        assert raised.value.code == "supported_claim_requires_evidence"


@pytest.mark.parametrize("size", [contracts.MAX_REF_COUNT, contracts.MAX_REF_COUNT + 1])
def test_array_count_boundary(size):
    document = payload()
    document["assumptions"] = ["Bounded assumption"] * size
    if size == contracts.MAX_REF_COUNT:
        assert len(contracts.validate_adjudication(document)["assumptions"]) == size
    else:
        with pytest.raises(contracts.ContractIssue) as raised:
            contracts.validate_adjudication(document)
        assert raised.value.code == "invalid_assessment_array"


@pytest.mark.parametrize(
    "count", [contracts.MAX_CAUSAL_ROLE_EVIDENCE_REFS, contracts.MAX_CAUSAL_ROLE_EVIDENCE_REFS + 1]
)
def test_role_reference_count_boundary(count):
    document = payload()
    document["causal_roles"]["impact"]["evidence_refs"] = ["ev"] * count
    if count == contracts.MAX_CAUSAL_ROLE_EVIDENCE_REFS:
        assert len(contracts.validate_adjudication(document)["causal_roles"]["impact"]["evidence_refs"]) == count
    else:
        with pytest.raises(contracts.ContractIssue) as raised:
            contracts.validate_adjudication(document)
        assert raised.value.code == "invalid_causal_role_evidence_refs"


@pytest.mark.parametrize("size", [256, 257])
def test_role_reference_byte_boundary(size):
    document = payload()
    document["causal_roles"]["impact"]["evidence_refs"] = ["x" * size]
    if size == 256:
        assert contracts.validate_adjudication(document)["causal_roles"]["impact"]["evidence_refs"] == ["x" * size]
    else:
        with pytest.raises(contracts.ContractIssue) as raised:
            contracts.validate_adjudication(document)
        assert raised.value.code == "invalid_causal_role_evidence_refs"
