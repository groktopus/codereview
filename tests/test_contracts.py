from __future__ import annotations

import hashlib
import json

import pytest

from pr_review_harness.contracts import (
    ADJUDICATION_V1,
    ADJUDICATION_V2,
    ADJUDICATION_V3,
    CAUSAL_ROLE_NAMES,
    MAX_CAUSAL_ASSESSMENT_BYTES,
    MAX_REF_COUNT,
    SPECIALIST_INTERNAL,
    SPECIALIST_V1,
    SPECIALIST_V2,
    SPECIALIST_V3,
    SPECIALIST_V4,
    ContractIssue,
    validate_adjudication,
    validate_gap,
    validate_specialist,
)


def _gap(target, *, legacy=False):
    row = {
        "evidence_kind": "implementation",
        "target": target,
        "rationale": "The caller contract is absent from this evidence set.",
        "related_evidence_ids": ["ev-1"],
        "required_lens": "correctness",
    }
    if not legacy:
        row["related_candidate_ids"] = []
    return row


def test_v2_tagged_target_normalizes_to_engine_contract():
    gap = validate_gap(_gap({"kind": "path", "value": "src/client.py"}), SPECIALIST_V2)
    assert gap["target"] == {"target_unit_id": None, "target_path": "src/client.py", "target_symbol": None}
    assert gap["related_candidate_ids"] == []


@pytest.mark.parametrize(
    "target",
    [
        {"target_unit_id": "u-1", "target_path": None, "target_symbol": None},
        {"target_unit_id": None, "target_path": "src/client.py", "target_symbol": None},
        {"target_unit_id": None, "target_path": None, "target_symbol": "Client.send"},
    ],
)
def test_v1_nested_targets_remain_migratable(target):
    assert validate_gap(_gap(target, legacy=True), SPECIALIST_V1)["target"] == target


@pytest.mark.parametrize(
    "target",
    [
        {"kind": "path", "value": ""},
        {"kind": "path", "value": "src/a.py", "extra": True},
        {"kind": "other", "value": "src/a.py"},
        {"target_unit_id": "u-1", "target_path": "src/a.py", "target_symbol": None},
    ],
)
def test_gap_target_rejects_ambiguous_or_unsupported_shapes(target):
    version = SPECIALIST_V2 if "kind" in target else SPECIALIST_V1
    with pytest.raises(ContractIssue, match="invalid_context_gap_target"):
        validate_gap(_gap(target, legacy=version == SPECIALIST_V1), version)


def test_specialist_contract_quarantines_invalid_items_with_hash_and_keeps_siblings():
    invalid = _gap({"kind": "path", "value": "src/unknown.py", "extra": "ambiguous"})
    payload = {
        "contract_version": SPECIALIST_V2,
        "finding_candidates": [],
        "context_gap_proposals": [
            _gap({"kind": "path", "value": "src/client.py"}),
            invalid,
        ],
        "coverage_notes": [],
    }
    result = validate_specialist(payload, valid_evidence_ids={"ev-1"})
    assert result["contract_version"] == SPECIALIST_INTERNAL
    assert result["source_contract_version"] == SPECIALIST_V2
    assert len(result["context_gap_proposals"]) == 1
    quarantined = result["quarantined_items"]
    assert quarantined == [
        {
            "kind": "context_gap_proposals",
            "index": 1,
            "reason_code": "invalid_context_gap_target",
            "item_hash": hashlib.sha256(
                json.dumps(invalid, ensure_ascii=False, separators=(",", ":")).encode()
            ).hexdigest(),
        }
    ]
    assert "src/unknown.py" not in repr(quarantined)


def test_static_review_coverage_is_tagged_and_does_not_claim_execution():
    note = {
        "unit_id": "u-1",
        "state": "COVERED",
        "reason_code": "reviewed",
        "evidence_refs": ["ev-1"],
        "coverage_basis": "STATIC_REVIEW",
    }
    payload = {
        "contract_version": SPECIALIST_V2,
        "finding_candidates": [],
        "context_gap_proposals": [],
        "coverage_notes": [note],
    }
    result = validate_specialist(payload, valid_evidence_ids={"ev-1"}, valid_unit_ids={"u-1"})
    assert result["coverage_notes"][0]["coverage_basis"] == "STATIC_REVIEW"
    assert "execution" not in result["coverage_notes"][0]


def _candidate_v3(location, unit_id="u-1"):
    return {
        "unit_id": unit_id,
        "location": location,
        "title": "Explicitly anchored candidate",
        "observation": "The changed behavior is visible in supplied evidence.",
        "consequence": "A caller can receive an inconsistent result.",
        "rule_or_contract": "The operation must preserve its declared contract.",
        "severity": "medium",
        "reasoning_kind": "observed",
        "evidence_refs": ["ev-1"],
        "introducedness": "INTRODUCED",
    }


@pytest.mark.parametrize(
    "location",
    [
        {"kind": "line", "path": "src/client.py", "side": "HEAD", "line": 12, "reason": None},
        {"kind": "line", "path": "src/client.py", "side": "BASE", "line": 9, "reason": None},
        {"kind": "file", "path": "gone.py", "side": "BASE", "line": None, "reason": "file_deleted"},
    ],
)
def test_v3_typed_locations_normalize_to_core_candidate_shape(location):
    result = validate_specialist(
        {
            "contract_version": SPECIALIST_V3,
            "finding_candidates": [_candidate_v3(location)],
            "context_gap_proposals": [],
            "coverage_notes": [],
        },
        valid_evidence_ids={"ev-1"},
        valid_unit_ids={"u-1"},
    )
    candidate = result["finding_candidates"][0]
    assert result["source_contract_version"] == SPECIALIST_V3
    assert candidate["unit_id"] == "u-1"
    assert candidate["location"] == location
    assert candidate["path"] == location["path"]
    assert candidate["line"] == location["line"]


@pytest.mark.parametrize(
    "location",
    [
        {"kind": "line", "path": "src/client.py", "side": "HEAD", "line": None, "reason": None},
        {"kind": "file", "path": "src/client.py", "side": "HEAD", "line": 7, "reason": "file-level"},
        {"kind": "file", "path": "src/client.py", "side": "OTHER", "line": None, "reason": "file-level"},
        {"kind": "file", "path": "src/client.py", "side": "HEAD", "line": None, "reason": None},
        {"kind": "line", "path": "src/client.py", "side": "BASE", "line": True, "reason": None},
    ],
)
def test_v3_rejects_inconsistent_location_as_quarantined_item(location):
    result = validate_specialist(
        {
            "contract_version": SPECIALIST_V3,
            "finding_candidates": [_candidate_v3(location)],
            "context_gap_proposals": [],
            "coverage_notes": [],
        },
        valid_evidence_ids={"ev-1"},
        valid_unit_ids={"u-1"},
    )
    assert result["finding_candidates"] == []
    assert result["quarantined_items"][0]["reason_code"] == "invalid_candidate_location"


@pytest.mark.parametrize("version", [SPECIALIST_V1, SPECIALIST_V2])
def test_legacy_null_line_is_quarantined_instead_of_becoming_file_location(version):
    legacy = {
        "path": "gone.py",
        "line": None,
        **{
            key: value
            for key, value in _candidate_v3(
                {"kind": "file", "path": "gone.py", "side": "BASE", "line": None, "reason": "file_deleted"}
            ).items()
            if key not in {"unit_id", "location"}
        },
    }
    payload = {
        "contract_version": version,
        "finding_candidates": [legacy],
        "context_gap_proposals": [],
        "coverage_notes": [],
    }
    result = validate_specialist(payload, valid_evidence_ids={"ev-1"})
    assert result["finding_candidates"] == []
    assert result["quarantined_items"][0]["reason_code"] == "invalid_candidate_line"


def test_v3_migration_adds_empty_optional_report_note_categories():
    result = validate_specialist(
        {
            "contract_version": SPECIALIST_V3,
            "finding_candidates": [],
            "context_gap_proposals": [],
            "coverage_notes": [],
        }
    )
    assert result["source_contract_version"] == SPECIALIST_V3
    assert result["specific_strengths"] == []
    assert result["future_guidance"] == []


def test_v4_allows_no_notes_when_evidence_does_not_support_them():
    result = validate_specialist(
        {
            "contract_version": SPECIALIST_V4,
            "finding_candidates": [],
            "context_gap_proposals": [],
            "coverage_notes": [],
            "specific_strengths": [],
            "future_guidance": [],
        }
    )
    assert result["specific_strengths"] == []
    assert result["future_guidance"] == []
    assert result["quarantined_items"] == []


def test_v4_unencodable_text_is_quarantined_instead_of_escaping_validation():
    note = {
        "unit_id": "u-1",
        "title": "Invalid text",
        "observation": "unpaired surrogate: \ud800",
        "why_it_matters": "This text cannot be encoded safely.",
        "evidence_refs": ["ev-1"],
    }
    result = validate_specialist(
        {
            "contract_version": SPECIALIST_V4,
            "finding_candidates": [],
            "context_gap_proposals": [],
            "coverage_notes": [],
            "specific_strengths": [note],
            "future_guidance": [],
        },
        valid_evidence_ids={"ev-1"},
        valid_unit_ids={"u-1"},
    )
    assert result["specific_strengths"] == []
    assert result["quarantined_items"][0]["reason_code"] == "invalid_report_note_text"


def test_coverage_note_schema_failures_are_quarantined_with_bounded_reasons():
    valid = {
        "unit_id": "u-1",
        "state": "COVERED",
        "reason_code": "STATIC_REVIEW",
        "evidence_refs": ["ev-1"],
        "coverage_basis": "STATIC_REVIEW",
    }
    wrong_unit = {**valid, "unit_id": "untrusted-unit", "reason_code": "private detail " * 10}
    excessive_reason = {**valid, "reason_code": "R" * 257}
    bad_state = {**valid, "state": "UNKNOWN"}
    unhashable_state = {**valid, "state": []}
    too_many_refs = {**valid, "evidence_refs": [f"ev-{index}" for index in range(MAX_REF_COUNT + 1)]}
    extra_field = {**valid, "private": "must not leak"}
    result = validate_specialist(
        {
            "contract_version": SPECIALIST_V4,
            "finding_candidates": [],
            "context_gap_proposals": [],
            "coverage_notes": [valid, wrong_unit, excessive_reason, bad_state, unhashable_state, too_many_refs, extra_field],
            "specific_strengths": [],
            "future_guidance": [],
        },
        valid_evidence_ids={"ev-1"},
        valid_unit_ids={"u-1"},
    )
    assert result["coverage_notes"] == [{**valid}]
    assert [row["reason_code"] for row in result["quarantined_items"]] == [
        "coverage_references_unknown_scope",
        "invalid_coverage_note_reason_code",
        "invalid_coverage_note_state",
        "invalid_coverage_note_state",
        "invalid_coverage_note_evidence_refs",
        "invalid_coverage_note_fields",
    ]
    assert all(len(row["reason_code"]) <= 256 and len(row["item_hash"]) == 64 for row in result["quarantined_items"])
    assert "private detail" not in repr(result["quarantined_items"])
    assert "must not leak" not in repr(result["quarantined_items"])


def test_v4_keeps_specific_evidence_backed_notes_and_quarantines_bad_siblings():
    strength = {
        "unit_id": "u-1",
        "title": "Bounded request handling",
        "observation": "The handler rejects requests above the documented byte ceiling.",
        "why_it_matters": "Large payloads cannot consume unbounded request memory.",
        "evidence_refs": ["ev-1"],
    }
    guidance = {
        "unit_id": "u-1",
        "title": "Retain cross-version compatibility tests",
        "observation": "The adapter has a migration path for the prior contract version.",
        "guidance": "Keep one fixture per supported version as schemas evolve.",
        "evidence_refs": ["ev-2"],
    }
    unsupported = {**strength, "evidence_refs": ["ev-not-delivered"]}
    malformed = {**guidance, "guidance": ""}
    result = validate_specialist(
        {
            "contract_version": SPECIALIST_V4,
            "finding_candidates": [],
            "context_gap_proposals": [],
            "coverage_notes": [],
            "specific_strengths": [strength, unsupported],
            "future_guidance": [guidance, malformed],
        },
        valid_evidence_ids={"ev-1", "ev-2"},
        valid_unit_ids={"u-1"},
    )
    assert result["source_contract_version"] == SPECIALIST_V4
    assert result["specific_strengths"] == [
        {
            "unit_id": "u-1",
            "title": strength["title"],
            "observation": strength["observation"],
            "detail": strength["why_it_matters"],
            "evidence_refs": ["ev-1"],
        }
    ]
    assert result["future_guidance"] == [
        {
            "unit_id": "u-1",
            "title": guidance["title"],
            "observation": guidance["observation"],
            "detail": guidance["guidance"],
            "evidence_refs": ["ev-2"],
        }
    ]
    assert result["finding_candidates"] == []
    assert [item["reason_code"] for item in result["quarantined_items"]] == [
        "report_note_references_unknown_evidence",
        "invalid_report_note_text",
    ]
    assert all(len(item["item_hash"]) == 64 for item in result["quarantined_items"])
    assert "ev-not-delivered" not in repr(result["quarantined_items"])


def test_v4_report_notes_reject_unknown_scope_and_oversized_lists():
    note = {
        "unit_id": "u-other",
        "title": "A claim",
        "observation": "An observation.",
        "why_it_matters": "A reason.",
        "evidence_refs": ["ev-1"],
    }
    payload = {
        "contract_version": SPECIALIST_V4,
        "finding_candidates": [],
        "context_gap_proposals": [],
        "coverage_notes": [],
        "specific_strengths": [note] * 11,
        "future_guidance": [],
    }
    result = validate_specialist(payload, valid_evidence_ids={"ev-1"}, valid_unit_ids={"u-1"})
    assert result["specific_strengths"] == []
    assert result["quarantined_items"][0]["reason_code"] == "report_note_references_unknown_scope"
    assert len(result["quarantined_items"]) == 11
    assert result["quarantined_items"][-1]["reason_code"] == "report_note_limit_exceeded"


def test_adjudication_v2_bounds_supported_claims_to_supplied_evidence():
    valid = {
        "contract_version": ADJUDICATION_V2,
        "outcome": "SUPPORTED",
        "observation_support": "SUPPORTED",
        "consequence_support": "NOT_ESTABLISHED",
        "rule_connection_support": "SUPPORTED",
        "introducedness": "UNKNOWN",
        "evidence_refs": ["ev-1"],
        "assumptions": [],
        "uncertainties": [],
        "summary": "The observation is supported; the consequence remains unestablished.",
        "material_consequence": False,
    }
    assert validate_adjudication(valid)["contract_version"] == ADJUDICATION_V2
    no_refs = {**valid, "evidence_refs": []}
    with pytest.raises(ContractIssue, match="supported_claim_requires_evidence"):
        validate_adjudication(no_refs)


def _adjudication_v3(**overrides):
    role = {
        "support": "SUPPORTED",
        "assessment": "The source and caller contract establish this causal step.",
        "evidence_refs": ["ev-1"],
    }
    payload = {
        "contract_version": ADJUDICATION_V3,
        "outcome": "SUPPORTED",
        "observation_support": "SUPPORTED",
        "consequence_support": "SUPPORTED",
        "rule_connection_support": "SUPPORTED",
        "introducedness": "INTRODUCED",
        "evidence_refs": ["ev-1"],
        "assumptions": [],
        "uncertainties": [],
        "summary": "Static source evidence connects the changed behavior to its consumer and impact.",
        "material_consequence": True,
        "causal_roles": {name: dict(role) for name in CAUSAL_ROLE_NAMES},
    }
    payload.update(overrides)
    return payload


def test_adjudication_v3_accepts_static_causal_chain_with_shared_evidence_id():
    payload = _adjudication_v3()
    normalized = validate_adjudication(payload)
    assert normalized["contract_version"] == ADJUDICATION_V3
    assert normalized["source_contract_version"] == ADJUDICATION_V3
    assert normalized["causal_roles"]["behavior"]["evidence_refs"] == ["ev-1"]
    assert normalized["causal_roles"]["consumer"]["evidence_refs"] == ["ev-1"]
    assert normalized["causal_roles"]["impact"]["evidence_refs"] == ["ev-1"]


def test_adjudication_v3_allows_unestablished_role_without_citation_but_not_supported_role():
    roles = _adjudication_v3()["causal_roles"]
    roles["consumer"] = {
        "support": "NOT_ESTABLISHED",
        "assessment": "The supplied source does not show which downstream caller consumes this behavior.",
        "evidence_refs": [],
    }
    result = validate_adjudication(_adjudication_v3(causal_roles=roles))
    assert result["causal_roles"]["consumer"]["support"] == "NOT_ESTABLISHED"
    assert result["causal_roles"]["consumer"]["evidence_refs"] == []

    roles["consumer"]["support"] = "SUPPORTED"
    with pytest.raises(ContractIssue, match="invalid_causal_role_evidence_refs"):
        validate_adjudication(_adjudication_v3(causal_roles=roles))


@pytest.mark.parametrize(
    ("mutation", "reason"),
    [
        (lambda value: value["causal_roles"].pop("consumer"), "invalid_causal_roles"),
        (
            lambda value: value["causal_roles"]["consumer"].update(evidence_refs=[]),
            "invalid_causal_role_evidence_refs",
        ),
        (
            lambda value: value["causal_roles"]["impact"].update(assessment="x" * (MAX_CAUSAL_ASSESSMENT_BYTES + 1)),
            "invalid_causal_role_assessment",
        ),
        (
            lambda value: value["causal_roles"]["behavior"].update(support="LIKELY"),
            "invalid_causal_role_support",
        ),
    ],
)
def test_adjudication_v3_rejects_missing_or_malformed_role_evidence(mutation, reason):
    payload = _adjudication_v3()
    mutation(payload)
    with pytest.raises(ContractIssue, match=reason):
        validate_adjudication(payload)


def test_adjudication_legacy_contracts_keep_source_version_and_unknown_roles():
    v2 = _adjudication_v3()
    v2.pop("causal_roles")
    v2["contract_version"] = ADJUDICATION_V2
    normalized_v2 = validate_adjudication(v2)
    assert normalized_v2["contract_version"] == ADJUDICATION_V2
    assert normalized_v2["source_contract_version"] == ADJUDICATION_V2
    assert normalized_v2["causal_roles"] is None

    v1 = dict(v2)
    v1.pop("contract_version")
    normalized_v1 = validate_adjudication(v1)
    assert normalized_v1["contract_version"] == ADJUDICATION_V1
    assert normalized_v1["source_contract_version"] == ADJUDICATION_V1
    assert normalized_v1["causal_roles"] is None


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    [
        ("contract_version", [], "unsupported_assessment_contract"),
        ("outcome", [], "invalid_assessment_outcome"),
        ("observation_support", [], "invalid_assessment_support"),
        ("introducedness", [], "invalid_assessment_semantics"),
    ],
)
def test_adjudication_rejects_unhashable_enum_values_as_contract_issues(field, value, reason):
    payload = _adjudication_v3()
    payload[field] = value
    with pytest.raises(ContractIssue, match=reason):
        validate_adjudication(payload)
