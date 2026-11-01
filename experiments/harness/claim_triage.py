"""Pure, conservative mapping from native claim answers to reviewable advice.

The returned status is never a disposition or a permission to add, remove, or
publish a finding. Policy is explicit, versioned input supplied by the caller;
native model output cannot select or modify it.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

CONTRACT_VERSION = "claim-triage.1"
POLICY_VERSION = "claim-triage-policy.1"
_MAX_JSON_BYTES = 128_000
_MAX_JSON_NODES = 20_000
_MAX_JSON_DEPTH = 64
_SHA256 = re.compile(r"^[0-9a-f]{64}$")

_CHOICES: dict[str, frozenset[str]] = {
    "observation_support": frozenset({"SUPPORTED", "NOT_ESTABLISHED", "CONTRADICTED", "UNCERTAIN"}),
    "consequence_support": frozenset({"SUPPORTED", "NOT_ESTABLISHED", "CONTRADICTED", "UNCERTAIN"}),
    "rule_connection_support": frozenset({"SUPPORTED", "NOT_ESTABLISHED", "CONTRADICTED", "UNCERTAIN"}),
    "materiality": frozenset({"MATERIAL", "NOT_ESTABLISHED", "NOT_MATERIAL", "UNCERTAIN"}),
    "missing_context": frozenset({"MISSING_CONTEXT_IDENTIFIED", "NO_MISSING_CONTEXT_IDENTIFIED", "UNCERTAIN"}),
    "introducedness": frozenset({"INTRODUCED", "REEXPOSED", "PRE_EXISTING", "UNKNOWN"}),
}
_BASE_REQUIRED_CHOICES = {
    "observation_support": "SUPPORTED",
    "consequence_support": "SUPPORTED",
    "rule_connection_support": "SUPPORTED",
    "materiality": "MATERIAL",
    "missing_context": "NO_MISSING_CONTEXT_IDENTIFIED",
}
_ASSESSMENT_STATUSES = frozenset({"COMPLETE", "PARTIAL", "FAILED"})
_ANSWER_STATUSES = frozenset({"ANSWERED", "NOT_SHOWN", "OMITTED", "INVALID", "FAILED", "NOT_RUN"})
_TRIAGE_STATES = frozenset({"SUPPORTED_FOR_REVIEW", "CONTRADICTED", "NEEDS_EVIDENCE", "DISAGREEMENT", "UNAVAILABLE"})


class ClaimTriageError(ValueError):
    """A versioned trusted triage policy violates the local contract."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _bounded_json(value: Any, *, limit: int, error_code: str) -> tuple[dict[str, Any], bytes]:
    if not isinstance(value, dict):
        raise ClaimTriageError(error_code)
    stack = [(value, 0)]
    nodes = 0
    string_chars = 0
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if nodes > _MAX_JSON_NODES or depth > _MAX_JSON_DEPTH:
            raise ClaimTriageError(error_code)
        if isinstance(current, dict):
            for key, child in current.items():
                if not isinstance(key, str) or len(key) > limit:
                    raise ClaimTriageError(error_code)
                string_chars += len(key)
                stack.append((child, depth + 1))
        elif isinstance(current, list):
            stack.extend((child, depth + 1) for child in current)
        elif isinstance(current, str):
            if len(current) > limit:
                raise ClaimTriageError(error_code)
            string_chars += len(current)
        elif isinstance(current, int) and not isinstance(current, bool):
            if current.bit_length() > 256:
                raise ClaimTriageError(error_code)
        elif isinstance(current, float):
            if not math.isfinite(current):
                raise ClaimTriageError(error_code)
        elif current is None or isinstance(current, (str, int, bool)):
            continue
        else:
            raise ClaimTriageError(error_code)
        if string_chars > limit:
            raise ClaimTriageError(error_code)
    try:
        # Reject lone surrogates and avoid encoding strings until their character
        # lengths have already been bounded above.
        for text in _iter_strings(value):
            if len(text.encode("utf-8")) > limit:
                raise ClaimTriageError(error_code)
    except UnicodeEncodeError:
        raise ClaimTriageError(error_code) from None
    try:
        encoded = _canonical(value)
    except (TypeError, ValueError, RecursionError, OverflowError):
        raise ClaimTriageError(error_code) from None
    if len(encoded) > limit:
        raise ClaimTriageError(error_code)
    # round-trip provides a JSON-only detached copy; the structural walk above
    # bounds parser depth before this potentially recursive operation.
    try:
        detached = json.loads(encoded)
    except (json.JSONDecodeError, RecursionError):
        raise ClaimTriageError(error_code) from None
    return detached, encoded


def _positive_text(value: Any, limit: int = 128) -> bool:
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        return False
    try:
        return len(value.encode("utf-8")) <= limit
    except UnicodeEncodeError:
        return False


def _iter_strings(value: Any):
    stack = [value]
    while stack:
        current = stack.pop()
        if isinstance(current, str):
            yield current
        elif isinstance(current, dict):
            for key, child in current.items():
                yield key
                stack.append(child)
        elif isinstance(current, list):
            stack.extend(current)


@dataclass(frozen=True)
class DisagreementRule:
    rule_id: str
    when: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class ClaimTriagePolicy:
    """Validated exact-choice policy, constructed from trusted versioned config."""

    policy_id: str
    expected_provider_id: str
    configured_model_id: str
    allowed_provider_model_ids: tuple[str, ...]
    required_dimensions: tuple[str, ...]
    required_choices: tuple[tuple[str, str], ...]
    contradiction_choices: tuple[tuple[str, tuple[str, ...]], ...]
    disagreement_rules: tuple[DisagreementRule, ...]
    policy_hash: str

    def __post_init__(self) -> None:
        if not _positive_text(self.policy_id):
            raise ClaimTriageError("invalid_policy_id")
        if not _positive_text(self.expected_provider_id) or not _positive_text(self.configured_model_id, 256):
            raise ClaimTriageError("invalid_policy_identity")
        if (
            not self.allowed_provider_model_ids
            or not isinstance(self.allowed_provider_model_ids, tuple)
            or len(self.allowed_provider_model_ids) > 8
            or any(not _positive_text(model_id, 256) for model_id in self.allowed_provider_model_ids)
            or len(set(self.allowed_provider_model_ids)) != len(self.allowed_provider_model_ids)
        ):
            raise ClaimTriageError("invalid_allowed_provider_models")
        dimensions = self.required_dimensions
        if (
            not isinstance(dimensions, tuple)
            or not dimensions
            or len(dimensions) > len(_CHOICES)
            or any(not isinstance(dimension, str) or dimension not in _CHOICES for dimension in dimensions)
            or len(set(dimensions)) != len(dimensions)
            or not set(_BASE_REQUIRED_CHOICES).issubset(dimensions)
        ):
            raise ClaimTriageError("invalid_required_dimensions")
        if not isinstance(self.required_choices, tuple) or any(
            not isinstance(pair, tuple) or len(pair) != 2 or not isinstance(pair[0], str)
            for pair in self.required_choices
        ):
            raise ClaimTriageError("invalid_required_choices")
        required_choices = dict(self.required_choices)
        if len(required_choices) != len(self.required_choices) or set(required_choices) != set(dimensions):
            raise ClaimTriageError("invalid_required_choices")
        if any(not isinstance(choice, str) or choice not in _CHOICES[dim] for dim, choice in required_choices.items()):
            raise ClaimTriageError("invalid_required_choices")
        if any(required_choices.get(dim) != choice for dim, choice in _BASE_REQUIRED_CHOICES.items()):
            raise ClaimTriageError("unsafe_base_required_choices")
        if not isinstance(self.contradiction_choices, tuple) or any(
            not isinstance(pair, tuple)
            or len(pair) != 2
            or not isinstance(pair[0], str)
            or not isinstance(pair[1], tuple)
            for pair in self.contradiction_choices
        ):
            raise ClaimTriageError("invalid_contradiction_choices")
        contradictions = dict(self.contradiction_choices)
        if len(contradictions) != len(self.contradiction_choices) or not set(contradictions).issubset(dimensions):
            raise ClaimTriageError("invalid_contradiction_choices")
        for dim, choices in contradictions.items():
            if (
                not choices
                or any(not isinstance(choice, str) or choice not in _CHOICES[dim] for choice in choices)
                or len(set(choices)) != len(choices)
                or required_choices[dim] in choices
            ):
                raise ClaimTriageError("invalid_contradiction_choices")
        if not isinstance(self.disagreement_rules, tuple) or len(self.disagreement_rules) > 16:
            raise ClaimTriageError("invalid_disagreement_rules")
        ids: set[str] = set()
        conditions: set[tuple[tuple[str, str], ...]] = set()
        for rule in self.disagreement_rules:
            if not isinstance(rule, DisagreementRule) or not _positive_text(rule.rule_id):
                raise ClaimTriageError("invalid_disagreement_rule")
            if not isinstance(rule.when, tuple) or any(
                not isinstance(pair, tuple)
                or len(pair) != 2
                or not isinstance(pair[0], str)
                or not isinstance(pair[1], str)
                for pair in rule.when
            ):
                raise ClaimTriageError("invalid_disagreement_condition")
            when = tuple(sorted(rule.when))
            if (
                len(when) < 2
                or len(dict(when)) != len(when)
                or not set(dict(when)).issubset(dimensions)
                or any(not isinstance(choice, str) or choice not in _CHOICES[dim] for dim, choice in when)
                or rule.rule_id in ids
                or when in conditions
            ):
                raise ClaimTriageError("invalid_disagreement_condition")
            ids.add(rule.rule_id)
            conditions.add(when)
        mapping = {
            "contract_version": POLICY_VERSION,
            "policy_id": self.policy_id,
            "expected_provider_id": self.expected_provider_id,
            "configured_model_id": self.configured_model_id,
            "allowed_provider_model_ids": list(self.allowed_provider_model_ids),
            "required_dimensions": list(dimensions),
            "required_choices": required_choices,
            "contradiction_choices": {key: list(value) for key, value in contradictions.items()},
            "disagreement_rules": [
                {"rule_id": rule.rule_id, "when": dict(rule.when)} for rule in self.disagreement_rules
            ],
        }
        if not isinstance(self.policy_hash, str) or not _SHA256.fullmatch(self.policy_hash):
            raise ClaimTriageError("invalid_policy_hash")
        if _sha(_canonical(mapping)) != self.policy_hash:
            raise ClaimTriageError("policy_hash_mismatch")

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> ClaimTriagePolicy:
        if not isinstance(value, Mapping):
            raise ClaimTriageError("invalid_policy")
        detached, encoded = _bounded_json(dict(value), limit=16_000, error_code="invalid_policy")
        required_fields = {
            "contract_version",
            "policy_id",
            "expected_provider_id",
            "configured_model_id",
            "allowed_provider_model_ids",
            "required_dimensions",
            "required_choices",
            "contradiction_choices",
            "disagreement_rules",
        }
        if set(detached) != required_fields or detached.get("contract_version") != POLICY_VERSION:
            raise ClaimTriageError("invalid_policy_fields")
        if not _positive_text(detached.get("policy_id")):
            raise ClaimTriageError("invalid_policy_id")
        if not _positive_text(detached.get("expected_provider_id")):
            raise ClaimTriageError("invalid_expected_provider_id")
        if not _positive_text(detached.get("configured_model_id"), 256):
            raise ClaimTriageError("invalid_configured_model_id")
        allowed_models = detached.get("allowed_provider_model_ids")
        if (
            not isinstance(allowed_models, list)
            or not allowed_models
            or len(allowed_models) > 8
            or any(not _positive_text(item, 256) for item in allowed_models)
            or len(set(allowed_models)) != len(allowed_models)
        ):
            raise ClaimTriageError("invalid_allowed_provider_models")

        dimensions = detached.get("required_dimensions")
        if (
            not isinstance(dimensions, list)
            or not dimensions
            or len(dimensions) > len(_CHOICES)
            or any(not isinstance(item, str) or item not in _CHOICES for item in dimensions)
            or len(set(dimensions)) != len(dimensions)
            or not set(_BASE_REQUIRED_CHOICES).issubset(dimensions)
        ):
            raise ClaimTriageError("invalid_required_dimensions")

        expected_choices = detached.get("required_choices")
        if not isinstance(expected_choices, dict) or set(expected_choices) != set(dimensions):
            raise ClaimTriageError("invalid_required_choices")
        if any(
            not isinstance(expected_choices.get(dim), str) or expected_choices[dim] not in _CHOICES[dim]
            for dim in dimensions
        ):
            raise ClaimTriageError("invalid_required_choices")
        if any(expected_choices.get(dim) != choice for dim, choice in _BASE_REQUIRED_CHOICES.items()):
            raise ClaimTriageError("unsafe_base_required_choices")

        contradiction_choices = detached.get("contradiction_choices")
        if not isinstance(contradiction_choices, dict) or not set(contradiction_choices).issubset(dimensions):
            raise ClaimTriageError("invalid_contradiction_choices")
        normalized_contradictions: list[tuple[str, tuple[str, ...]]] = []
        for dimension, choices in contradiction_choices.items():
            if (
                not isinstance(choices, list)
                or not choices
                or any(not isinstance(choice, str) or choice not in _CHOICES[dimension] for choice in choices)
                or len(set(choices)) != len(choices)
                or expected_choices[dimension] in choices
            ):
                raise ClaimTriageError("invalid_contradiction_choices")
            normalized_contradictions.append((dimension, tuple(choices)))

        rules = detached.get("disagreement_rules")
        if not isinstance(rules, list) or len(rules) > 16:
            raise ClaimTriageError("invalid_disagreement_rules")
        normalized_rules: list[DisagreementRule] = []
        seen_ids: set[str] = set()
        seen_conditions: set[tuple[tuple[str, str], ...]] = set()
        for rule in rules:
            if not isinstance(rule, dict) or set(rule) != {"rule_id", "when"}:
                raise ClaimTriageError("invalid_disagreement_rule")
            rule_id = rule.get("rule_id")
            when = rule.get("when")
            if not _positive_text(rule_id) or rule_id in seen_ids:
                raise ClaimTriageError("invalid_disagreement_rule_id")
            if (
                not isinstance(when, dict)
                or len(when) < 2
                or not set(when).issubset(dimensions)
                or any(not isinstance(choice, str) or choice not in _CHOICES[dim] for dim, choice in when.items())
            ):
                raise ClaimTriageError("invalid_disagreement_condition")
            condition = tuple(sorted(when.items()))
            if condition in seen_conditions:
                raise ClaimTriageError("duplicate_disagreement_condition")
            seen_ids.add(rule_id)
            seen_conditions.add(condition)
            normalized_rules.append(DisagreementRule(rule_id=rule_id, when=condition))

        return cls(
            policy_id=detached["policy_id"],
            expected_provider_id=detached["expected_provider_id"],
            configured_model_id=detached["configured_model_id"],
            allowed_provider_model_ids=tuple(allowed_models),
            required_dimensions=tuple(dimensions),
            required_choices=tuple((dim, expected_choices[dim]) for dim in dimensions),
            contradiction_choices=tuple(normalized_contradictions),
            disagreement_rules=tuple(normalized_rules),
            policy_hash=_sha(encoded),
        )


def _valid_unit_number(value: Any) -> bool:
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return value in {0, 1}
    return isinstance(value, float) and math.isfinite(value) and 0 <= value <= 1


def _valid_answer(dimension: str, answer: Any) -> bool:
    if (
        not isinstance(answer, dict)
        or not isinstance(answer.get("status"), str)
        or answer.get("status") != "ANSWERED"
        or answer.get("native_primitive") != "Choice"
        or answer.get("interpretation") != "advisory_uncalibrated"
    ):
        return False
    choice = answer.get("choice")
    probabilities = answer.get("probabilities")
    if (
        not isinstance(choice, str)
        or choice not in _CHOICES[dimension]
        or not isinstance(probabilities, dict)
        or any(not isinstance(key, str) for key in probabilities)
        or set(probabilities) != set(_CHOICES[dimension])
    ):
        return False
    if any(not _valid_unit_number(item) for item in probabilities.values()):
        return False
    if abs(sum(float(item) for item in probabilities.values()) - 1.0) > 0.02:
        return False
    if probabilities[choice] < max(float(item) for item in probabilities.values()) - 1e-6:
        return False
    if not _valid_unit_number(answer.get("confidence")):
        return False
    question_id = answer.get("question_id")
    evidence_refs = answer.get("evidence_refs")
    return (
        _positive_text(question_id, 256)
        and isinstance(evidence_refs, list)
        and bool(evidence_refs)
        and all(_positive_text(ref, 256) for ref in evidence_refs)
        and len(evidence_refs) == len(set(evidence_refs))
    )


def _validate_provenance(provenance: Any, policy: ClaimTriagePolicy) -> list[dict[str, str]]:
    if not isinstance(provenance, dict):
        return [{"reason_code": "assessment_provenance_missing", "detail": "provenance"}]
    reasons: list[dict[str, str]] = []
    if (
        provenance.get("contract_version") != "claim-assessment.1"
        or provenance.get("native_contract") != "system-one-choice-v1"
    ):
        reasons.append({"reason_code": "assessment_contract_mismatch", "detail": "contract_version"})
    if provenance.get("provider_id") != policy.expected_provider_id:
        reasons.append({"reason_code": "provider_identity_mismatch", "detail": "provider_id"})
    if provenance.get("configured_model_id") != policy.configured_model_id:
        reasons.append({"reason_code": "configured_model_mismatch", "detail": "configured_model_id"})
    if (
        provenance.get("model_identity_source") != "endpoint_reported"
        or provenance.get("provider_model_id") not in policy.allowed_provider_model_ids
    ):
        reasons.append({"reason_code": "provider_model_identity_mismatch", "detail": "provider_model_id"})
    if not all(
        isinstance(provenance.get(key), str) and _SHA256.fullmatch(provenance[key])
        for key in (
            "request_hash",
            "response_hash",
            "candidate_hash",
            "evidence_hash",
            "question_hash",
            "snapshot_hash",
            "profile_hash",
        )
    ):
        reasons.append({"reason_code": "assessment_transport_or_source_hash_missing", "detail": "provenance_hash"})
    for key in ("snapshot_id", "profile_id", "base_sha", "head_sha"):
        if not _positive_text(provenance.get(key), 256):
            reasons.append({"reason_code": "assessment_identity_incomplete", "detail": key})
    return reasons


def triage_claim(assessment: Mapping[str, Any] | None, policy: ClaimTriagePolicy) -> dict[str, Any]:
    """Map validated per-dimension answers to a bounded advisory state.

    Required positive choices and contradiction/disagreement rules come only
    from the validated versioned policy. No probability or confidence threshold
    is applied. `SUPPORTED_FOR_REVIEW` is an advisory eligibility state only.
    """

    if not isinstance(policy, ClaimTriagePolicy):
        raise ClaimTriageError("validated_policy_required")

    detached_assessment: dict[str, Any] | None = None
    assessment_hash: str | None = None
    assessment_error: str | None = None
    if assessment is None:
        assessment_error = "assessment_absent"
    elif not isinstance(assessment, Mapping):
        assessment_error = "assessment_invalid_shape"
    else:
        try:
            detached_assessment, encoded = _bounded_json(
                dict(assessment), limit=_MAX_JSON_BYTES, error_code="assessment_invalid_shape"
            )
            assessment_hash = _sha(encoded)
        except ClaimTriageError as exc:
            assessment_error = exc.code

    raw_dimensions: dict[str, Any] = {}
    provenance: dict[str, Any] | None = None
    observed_choices: dict[str, str] = {}
    unavailable_reasons: list[dict[str, str]] = []
    evidence_gaps: list[dict[str, str]] = []
    conflicts: list[dict[str, Any]] = []

    if detached_assessment is not None:
        if detached_assessment.get("contract_version") != "claim-assessment.1":
            unavailable_reasons.append({"reason_code": "assessment_contract_mismatch", "detail": "contract_version"})
        if detached_assessment.get("decision") != "ADVISORY_ONLY":
            unavailable_reasons.append({"reason_code": "assessment_decision_unexpected", "detail": "decision"})
        provenance_value = detached_assessment.get("provenance")
        if isinstance(provenance_value, dict):
            provenance = provenance_value
        unavailable_reasons.extend(_validate_provenance(provenance_value, policy))
        raw_answers = detached_assessment.get("assessments")
        if isinstance(raw_answers, dict):
            raw_dimensions = raw_answers

        if detached_assessment.get("status") != "COMPLETE":
            status = detached_assessment.get("status")
            safe_status = status if isinstance(status, str) and status in _ASSESSMENT_STATUSES else "UNKNOWN"
            unavailable_reasons.append({"reason_code": "assessment_not_complete", "detail": safe_status})

        for dimension, answer in raw_dimensions.items():
            if dimension in _CHOICES and _valid_answer(dimension, answer):
                observed_choices[dimension] = answer["choice"]

        for dimension in policy.required_dimensions:
            answer = raw_dimensions.get(dimension)
            if not isinstance(answer, dict):
                unavailable_reasons.append({"reason_code": "required_answer_missing", "detail": dimension})
                continue
            state = answer.get("status")
            if not isinstance(state, str) or state not in _ANSWER_STATUSES:
                unavailable_reasons.append({"reason_code": "required_answer_state_invalid", "detail": dimension})
            elif state == "NOT_SHOWN":
                evidence_gaps.append({"reason_code": "required_dimension_not_shown", "detail": dimension})
            elif state != "ANSWERED":
                unavailable_reasons.append({"reason_code": "required_answer_unavailable", "detail": dimension})
            elif not _valid_answer(dimension, answer):
                unavailable_reasons.append({"reason_code": "required_answer_invalid", "detail": dimension})

    elif assessment_error is not None:
        unavailable_reasons.append({"reason_code": assessment_error, "detail": "assessment"})

    expected_choices = dict(policy.required_choices)
    contradictions = dict(policy.contradiction_choices)
    for dimension, selected in observed_choices.items():
        if selected in contradictions.get(dimension, ()):
            conflicts.append(
                {
                    "conflict_id": "policy_contradiction:" + dimension,
                    "dimension": dimension,
                    "selected_choice": selected,
                    "kind": "explicit_contradiction",
                }
            )

    consequence = observed_choices.get("consequence_support")
    materiality = observed_choices.get("materiality")
    if materiality == "MATERIAL" and consequence == "NOT_ESTABLISHED":
        conflicts.append(
            {
                "conflict_id": "materiality_without_established_consequence",
                "dimensions": ["materiality", "consequence_support"],
                "choices": {"materiality": materiality, "consequence_support": consequence},
                "kind": "requires_evidence",
            }
        )

    matched_disagreements: list[str] = []
    for rule in policy.disagreement_rules:
        if all(observed_choices.get(dimension) == choice for dimension, choice in rule.when):
            matched_disagreements.append(rule.rule_id)
            conflicts.append(
                {
                    "conflict_id": "policy_disagreement:" + rule.rule_id,
                    "dimensions": [dimension for dimension, _ in rule.when],
                    "choices": dict(rule.when),
                    "kind": "configured_disagreement",
                }
            )

    for dimension, expected in expected_choices.items():
        selected = observed_choices.get(dimension)
        if selected is not None and selected != expected and selected not in contradictions.get(dimension, ()):
            evidence_gaps.append({"reason_code": "required_choice_not_established", "detail": dimension})

    # A conflict remains in the output even if unavailability or an explicit
    # contradiction determines the top-level status.
    if unavailable_reasons:
        result_state = "UNAVAILABLE"
    elif any(item["kind"] == "explicit_contradiction" for item in conflicts):
        result_state = "CONTRADICTED"
    elif any(item["conflict_id"] == "materiality_without_established_consequence" for item in conflicts):
        result_state = "NEEDS_EVIDENCE"
    elif matched_disagreements:
        result_state = "DISAGREEMENT"
    elif evidence_gaps:
        result_state = "NEEDS_EVIDENCE"
    elif all(observed_choices.get(dim) == expected for dim, expected in expected_choices.items()):
        result_state = "SUPPORTED_FOR_REVIEW"
    else:
        result_state = "NEEDS_EVIDENCE"

    return {
        "contract_version": CONTRACT_VERSION,
        "status": result_state,
        "policy": {"contract_version": POLICY_VERSION, "policy_id": policy.policy_id, "sha256": policy.policy_hash},
        "assessment_hash": assessment_hash,
        "assessment_status": detached_assessment.get("status") if detached_assessment else None,
        "dimensions": raw_dimensions,
        "provenance": provenance,
        "unavailable_reasons": unavailable_reasons,
        "evidence_gaps": evidence_gaps,
        "conflicts": conflicts,
        "decision": "ADVISORY_ONLY",
    }
