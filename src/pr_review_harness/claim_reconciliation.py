"""Deterministic reconciliation policy for optional typed claim assessments."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any

POLICY_VERSION = "claim-reconciliation.v1"
_POLICY_KEYS = {"version", "enabled", "required", "max_assessments"}
_CHOICES = {
    "observation_support": {"SUPPORTED", "NOT_ESTABLISHED", "CONTRADICTED", "UNCERTAIN"},
    "consequence_support": {"SUPPORTED", "NOT_ESTABLISHED", "CONTRADICTED", "UNCERTAIN"},
    "rule_connection_support": {"SUPPORTED", "NOT_ESTABLISHED", "CONTRADICTED", "UNCERTAIN"},
    "materiality": {"MATERIAL", "NOT_MATERIAL", "NOT_ESTABLISHED", "UNCERTAIN"},
    "missing_context": {"MISSING_CONTEXT_IDENTIFIED", "NO_MISSING_CONTEXT_IDENTIFIED", "UNCERTAIN"},
    "introducedness": {"INTRODUCED", "REEXPOSED", "PRE_EXISTING", "UNKNOWN"},
}


def validate_claim_reconciliation_policy(profile: Mapping[str, Any]) -> dict[str, Any] | None:
    """Validate an opt-in required classifier policy; absence preserves v1 behavior."""
    if not isinstance(profile, Mapping):
        raise ValueError("profile must be an object")
    if "claim_reconciliation" not in profile:
        return None
    value = profile["claim_reconciliation"]
    if not isinstance(value, dict) or set(value) != _POLICY_KEYS:
        raise ValueError("claim_reconciliation policy shape is invalid")
    cap = value.get("max_assessments")
    if (
        value.get("version") != POLICY_VERSION
        or value.get("enabled") is not True
        or value.get("required") is not True
        or isinstance(cap, bool)
        or not isinstance(cap, int)
        or not 1 <= cap <= 4
    ):
        raise ValueError("claim_reconciliation policy must be enabled, required, and finitely capped")
    return dict(value)


def _hash(value: Any) -> str:
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def classify_reconciliation(
    primary: Any,
    claim_row: Any,
    *,
    candidate_valid: bool,
    introducedness_available: bool = True,
) -> dict[str, Any]:
    """Compare validated typed answers with the exact primary semantic assessment.

    The result is descriptive policy input only: agreement does not promote a
    finding, and disagreement never changes an already accepted blocker.
    """
    primary_hash = _hash(primary) if isinstance(primary, dict) else None
    row = claim_row if isinstance(claim_row, dict) else {}
    assessments = row.get("assessments")
    assessment_hash = _hash(assessments) if isinstance(assessments, dict) else None
    base = {
        "version": POLICY_VERSION,
        "primary_assessment_hash": primary_hash,
        "claim_assessment_hash": assessment_hash,
        "candidate_hash": row.get("candidate_hash") if isinstance(row.get("candidate_hash"), str) else None,
        "evidence_hash": row.get("evidence_hash") if isinstance(row.get("evidence_hash"), str) else None,
        "request_hash": row.get("request_hash") if isinstance(row.get("request_hash"), str) else None,
        "disagreeing_dimensions": [],
    }
    if not candidate_valid:
        return {**base, "state": "PARTIAL", "reason_code": "PRIMARY_CANDIDATE_INVALID"}
    if not isinstance(primary, dict):
        return {**base, "state": "PARTIAL", "reason_code": "PRIMARY_ASSESSMENT_UNAVAILABLE"}
    if row.get("status") != "COMPLETE" or row.get("response_valid") is not True:
        return {**base, "state": "PARTIAL", "reason_code": "CLAIM_ASSESSMENT_INCOMPLETE"}
    if row.get("primary_assessment_hash") != primary_hash:
        return {**base, "state": "PARTIAL", "reason_code": "PRIMARY_ASSESSMENT_BINDING_MISMATCH"}
    if not isinstance(assessments, dict) or set(assessments) != set(_CHOICES):
        return {**base, "state": "PARTIAL", "reason_code": "CLAIM_ASSESSMENT_INVALID"}

    disagreements: list[str] = []
    unassessed: list[str] = []
    uncompared: list[str] = []
    qualifier_status = "SATISFIED"
    qualifier_reason = None
    for dimension, choices in _CHOICES.items():
        answer = assessments.get(dimension)
        if not isinstance(answer, dict) or not isinstance(answer.get("status"), str):
            return {**base, "state": "PARTIAL", "reason_code": "CLAIM_ASSESSMENT_INVALID"}
        if answer["status"] not in {"ANSWERED", "NOT_SHOWN"}:
            return {**base, "state": "PARTIAL", "reason_code": "CLAIM_ASSESSMENT_INVALID"}
        if dimension == "introducedness" and not introducedness_available:
            if answer.get("status") != "NOT_SHOWN":
                return {**base, "state": "PARTIAL", "reason_code": "CLAIM_ASSESSMENT_INVALID"}
            unassessed.append(dimension)
            continue
        choice = answer.get("choice")
        if answer.get("status") != "ANSWERED" or not isinstance(choice, str) or choice not in choices:
            return {**base, "state": "PARTIAL", "reason_code": "CLAIM_ASSESSMENT_INVALID"}
        if dimension == "materiality":
            expected = "MATERIAL" if primary.get("material_consequence") is True else (
                "NOT_MATERIAL" if primary.get("material_consequence") is False else None
            )
        elif dimension == "missing_context":
            uncompared.append(dimension)
            if choice == "MISSING_CONTEXT_IDENTIFIED":
                qualifier_status = "UNSATISFIED"
                qualifier_reason = "MISSING_CONTEXT_IDENTIFIED"
            elif choice == "UNCERTAIN":
                qualifier_status = "UNRESOLVED"
                qualifier_reason = "MISSING_CONTEXT_UNCERTAIN"
            continue
        else:
            expected = primary.get(dimension)
        if expected is None or choice != expected:
            disagreements.append(dimension)

    if unassessed:
        return {
            **base,
            "state": "PARTIAL",
            "reason_code": "CLAIM_ASSESSMENT_DIMENSION_UNAVAILABLE",
            "unassessed_dimensions": unassessed,
            "uncompared_dimensions": uncompared,
            "disagreeing_dimensions": disagreements,
            "qualifier_status": qualifier_status,
            "qualifier_reason": qualifier_reason,
        }
    if disagreements:
        return {
            **base,
            "state": "CONFLICT",
            "reason_code": "CLAIM_ASSESSMENT_DISAGREES",
            "uncompared_dimensions": uncompared,
            "disagreeing_dimensions": disagreements,
            "qualifier_status": qualifier_status,
            "qualifier_reason": qualifier_reason,
        }
    if qualifier_status != "SATISFIED":
        return {
            **base,
            "state": "PARTIAL",
            "reason_code": "RECONCILIATION_QUALIFIER_UNSATISFIED",
            "uncompared_dimensions": uncompared,
            "disagreeing_dimensions": disagreements,
            "qualifier_status": qualifier_status,
            "qualifier_reason": qualifier_reason,
        }
    return {
        **base,
        "state": "AGREES",
        "reason_code": "CLAIM_ASSESSMENT_AGREES",
        "uncompared_dimensions": uncompared,
        "qualifier_status": qualifier_status,
        "qualifier_reason": qualifier_reason,
    }
