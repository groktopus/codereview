"""Bounded advisory claim assessment over an injected System One transport.

This module builds and validates the documented TypeSafe Choice wire contract.
It deliberately does not provide transport credentials, thresholds, workflow
choices, or an interpretation that can authorize a review disposition.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from .contracts import MAX_REF_COUNT, ContractIssue, validate_adjudication

CONTRACT_VERSION = "claim-assessment.1"
PRIMARY_ASSESSMENT_CONTRACT_VERSION = "claim-assessment.2"
_PRIMARY_ASSESSMENT_SOURCE_CONTRACT = "semantic-adjudication.v3"
NATIVE_CONTRACT = "system-one-choice-v1"
_DIMENSIONS = {
    "observation_support": {
        "SUPPORTED": "The cited evidence supports the candidate's stated observation.",
        "NOT_ESTABLISHED": "The cited evidence does not establish the observation; this is not proof of its opposite.",
        "CONTRADICTED": "The cited evidence conflicts with the stated observation.",
        "UNCERTAIN": "The cited evidence is ambiguous, incomplete, or conflicting.",
    },
    "consequence_support": {
        "SUPPORTED": "The cited evidence supports the stated consequence.",
        "NOT_ESTABLISHED": "The cited evidence does not establish the consequence; this is not proof of no consequence.",
        "CONTRADICTED": "The cited evidence conflicts with the stated consequence.",
        "UNCERTAIN": "The cited evidence is ambiguous, incomplete, or conflicting.",
    },
    "rule_connection_support": {
        "SUPPORTED": "The cited evidence and supplied rule or contract support this connection.",
        "NOT_ESTABLISHED": "The supplied evidence does not establish the rule connection.",
        "CONTRADICTED": "The supplied rule or contract conflicts with this connection.",
        "UNCERTAIN": "The rule connection is ambiguous or the supplied evidence is insufficient.",
    },
    "materiality": {
        "MATERIAL": "The cited evidence establishes a concrete material consequence under the supplied context.",
        "NOT_MATERIAL": "The cited evidence supports that the consequence is not material under the supplied context.",
        "NOT_ESTABLISHED": "Materiality is not established by the cited evidence.",
        "UNCERTAIN": "The available evidence is insufficient or ambiguous about materiality.",
    },
    "missing_context": {
        "MISSING_CONTEXT_IDENTIFIED": "Specific additional evidence is needed to assess this claim.",
        "NO_MISSING_CONTEXT_IDENTIFIED": "No additional context need is apparent from the supplied evidence.",
        "UNCERTAIN": "Whether additional context is needed is unclear.",
    },
    "introducedness": {
        "INTRODUCED": "The evidence supports that the behavior was introduced by this change.",
        "REEXPOSED": "The behavior existed before but this change re-exposes or newly activates it.",
        "PRE_EXISTING": "The evidence supports that the behavior already existed and is not re-exposed by this change.",
        "UNKNOWN": "The evidence does not establish whether this behavior is introduced, re-exposed, or pre-existing.",
    },
}
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_VERSIONED_JEV_MODEL_ID = re.compile(r"jev-[0-9]+\.[0-9]+\.[0-9]+\Z")
_MAX_QUESTIONS = 6
_MAX_CANDIDATE_TEXT_BYTES = 16_000
_MAX_EVIDENCE_ITEMS = 32
_MAX_ONE_EVIDENCE_BYTES = 24_000
_MAX_RESPONSE_BYTES = 64_000
_MAX_REQUEST_BYTES = 64_000
_MAX_JSON_DEPTH = 64
_MAX_JSON_NODES = 20_000
_PRIMARY_FIELDS = {
    "contract_version",
    "source_contract_version",
    "outcome",
    "observation_support",
    "consequence_support",
    "rule_connection_support",
    "introducedness",
    "evidence_refs",
    "assumptions",
    "uncertainties",
    "summary",
    "material_consequence",
    "causal_roles",
}
_CAUSAL_ROLE_NAMES = {"behavior", "consumer", "impact"}
_CAUSAL_SUPPORT = {"SUPPORTED", "NOT_ESTABLISHED", "CONTRADICTED"}


class ClaimAssessmentError(ValueError):
    """A local input or finite-limit contract was violated."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


CLAIM_ASSESSMENT_ERROR_CODES = frozenset(
    {
        "candidate_evidence_reference_missing",
        "claim_transport_estimator_required",
        "configured_model_required",
        "duplicate_evidence_id",
        "evidence_content_hash_mismatch",
        "evidence_snapshot_mismatch",
        "invalid_assessment_identity",
        "invalid_assessment_identity_fields",
        "invalid_assessment_identity_hash",
        "invalid_assessment_input",
        "invalid_candidate_evidence_refs",
        "invalid_candidate_fields",
        "invalid_candidate_id",
        "invalid_candidate_text",
        "invalid_claim_transport_estimate",
        "invalid_deadline",
        "invalid_evidence_collection",
        "invalid_evidence_content",
        "invalid_evidence_item",
        "invalid_evidence_source_kind",
        "invalid_evidence_trust",
        "invalid_input_byte_limit",
        "invalid_output_byte_limit",
        "invalid_prepared_assessment",
        "invalid_primary_assessment_causal_roles",
        "invalid_primary_assessment_contract",
        "invalid_primary_assessment_evidence_refs",
        "invalid_primary_assessment_fields",
        "invalid_primary_assessment_value",
        "invalid_revision_identity",
        "malformed_native_response",
        "native_transport_required",
        "question_limit_exceeded",
        "request_exceeds_intrinsic_limit",
        "request_exceeds_limit",
    }
)


@dataclass(frozen=True)
class PreparedClaimAssessment:
    """Immutable exact serialized request and its precomputed identities."""

    contract_version: str
    request_bytes: bytes
    question_ids: tuple[tuple[str, str], ...]
    evidence_refs: tuple[str, ...]
    candidate_hash: str
    evidence_hash: str
    question_hash: str
    request_hash: str
    introducedness_available: bool
    primary_assessment_hash: str | None = None


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _is_positive_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _valid_text(value: Any, limit: int) -> bool:
    return isinstance(value, str) and bool(value.strip()) and len(value.encode("utf-8")) <= limit


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_json_key")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError(f"invalid_json_constant:{value}")


def _parse_json(raw: bytes) -> Any:
    try:
        result = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object, parse_constant=_reject_constant)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError):
        raise ClaimAssessmentError("malformed_native_response") from None
    # Some Python versions accept deeply nested JSON without RecursionError.
    # Walk iteratively so the validator itself never recurses on untrusted data.
    stack = [(result, 0)]
    nodes = 0
    while stack:
        value, depth = stack.pop()
        nodes += 1
        if nodes > _MAX_JSON_NODES or depth > _MAX_JSON_DEPTH:
            raise ClaimAssessmentError("malformed_native_response")
        if isinstance(value, dict):
            stack.extend((child, depth + 1) for child in value.values())
        elif isinstance(value, list):
            stack.extend((child, depth + 1) for child in value)
    return result


def _finite_number(value: Any) -> bool:
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return True  # The bounded range checks below reject out-of-range integers without float conversion.
    return isinstance(value, float) and math.isfinite(value)


def _limits(limits: Mapping[str, Any]) -> tuple[int, int, float]:
    input_bytes = limits.get("max_input_bytes_per_task")
    output_bytes = limits.get("max_output_bytes_per_task")
    deadline = limits.get("deadline_seconds")
    # This is the caller's per-task ceiling, not the native transport's hard
    # request limit. The exact prepared body is checked against both ceilings
    # after serialization so a larger overall workflow cap remains valid.
    if not _is_positive_int(input_bytes):
        raise ClaimAssessmentError("invalid_input_byte_limit")
    if not _is_positive_int(output_bytes) or output_bytes > _MAX_RESPONSE_BYTES:
        raise ClaimAssessmentError("invalid_output_byte_limit")
    if not _finite_number(deadline) or deadline <= 0 or deadline > 120:
        raise ClaimAssessmentError("invalid_deadline")
    return input_bytes, output_bytes, float(deadline)


def _question_id(candidate_id: str, dimension: str, contract_version: str = CONTRACT_VERSION) -> str:
    digest = _sha(f"{contract_version}\0{candidate_id}\0{dimension}".encode("utf-8"))[:24]
    return f"ca-{digest}"


def _validate_identity(identity: Mapping[str, Any]) -> None:
    required = {"snapshot_id", "snapshot_hash", "profile_id", "profile_hash", "base_sha", "head_sha"}
    if set(identity) != required:
        raise ClaimAssessmentError("invalid_assessment_identity_fields")
    for key in ("snapshot_id", "profile_id"):
        if not _valid_text(identity[key], 256):
            raise ClaimAssessmentError("invalid_assessment_identity")
    for key in ("snapshot_hash", "profile_hash"):
        if not isinstance(identity[key], str) or not _SHA256.fullmatch(identity[key]):
            raise ClaimAssessmentError("invalid_assessment_identity_hash")
    for key in ("base_sha", "head_sha"):
        if not isinstance(identity[key], str) or not re.fullmatch(r"[0-9a-f]{40,64}", identity[key]):
            raise ClaimAssessmentError("invalid_revision_identity")
    if identity["base_sha"] == identity["head_sha"]:
        raise ClaimAssessmentError("invalid_revision_identity")


def _candidate_state(
    candidate: Mapping[str, Any],
    evidence: Sequence[Mapping[str, Any]],
    identity: Mapping[str, Any],
    additional_refs: Sequence[str] = (),
) -> tuple[dict[str, Any], bool, tuple[str, ...]]:
    required = {"candidate_id", "title", "observation", "consequence", "rule_or_contract", "evidence_refs"}
    if not required.issubset(candidate):
        raise ClaimAssessmentError("invalid_candidate_fields")
    candidate_id = candidate["candidate_id"]
    if not _valid_text(candidate_id, 256):
        raise ClaimAssessmentError("invalid_candidate_id")
    for key in ("title", "observation", "consequence", "rule_or_contract"):
        if not _valid_text(candidate[key], _MAX_CANDIDATE_TEXT_BYTES):
            raise ClaimAssessmentError("invalid_candidate_text")
    refs = candidate["evidence_refs"]
    if not isinstance(refs, list) or not refs or len(refs) > _MAX_EVIDENCE_ITEMS:
        raise ClaimAssessmentError("invalid_candidate_evidence_refs")
    if any(not _valid_text(ref, 256) for ref in refs) or len(set(refs)) != len(refs):
        raise ClaimAssessmentError("invalid_candidate_evidence_refs")
    if not isinstance(evidence, Sequence) or isinstance(evidence, (str, bytes)) or len(evidence) > _MAX_EVIDENCE_ITEMS:
        raise ClaimAssessmentError("invalid_evidence_collection")

    by_id: dict[str, Mapping[str, Any]] = {}
    for item in evidence:
        if not isinstance(item, Mapping) or not _valid_text(item.get("evidence_id"), 256):
            raise ClaimAssessmentError("invalid_evidence_item")
        evidence_id = item["evidence_id"]
        if evidence_id in by_id:
            raise ClaimAssessmentError("duplicate_evidence_id")
        by_id[evidence_id] = item
    if any(ref not in by_id for ref in refs):
        raise ClaimAssessmentError("candidate_evidence_reference_missing")
    if (
        not isinstance(additional_refs, Sequence)
        or isinstance(additional_refs, (str, bytes))
        or any(not _valid_text(ref, 256) or ref not in by_id for ref in additional_refs)
    ):
        raise ClaimAssessmentError("candidate_evidence_reference_missing")
    all_refs = list(dict.fromkeys([*refs, *additional_refs]))

    cited: list[dict[str, Any]] = []
    sides: set[str] = set()
    for evidence_id in all_refs:
        item = by_id[evidence_id]
        if item.get("snapshot_id") is not None and item.get("snapshot_id") != identity["snapshot_id"]:
            raise ClaimAssessmentError("evidence_snapshot_mismatch")
        content = item.get("content")
        content_hash = item.get("content_hash")
        trust = item.get("trust")
        source_kind = item.get("source_kind")
        if not isinstance(content, str) or len(content.encode("utf-8")) > _MAX_ONE_EVIDENCE_BYTES:
            raise ClaimAssessmentError("invalid_evidence_content")
        if (
            not isinstance(content_hash, str)
            or not _SHA256.fullmatch(content_hash)
            or _sha(content.encode()) != content_hash
        ):
            raise ClaimAssessmentError("evidence_content_hash_mismatch")
        if not isinstance(trust, str) or trust not in {
            "trusted_policy",
            "repository_evidence",
            "untrusted_pr_content",
            "generated_result",
        }:
            raise ClaimAssessmentError("invalid_evidence_trust")
        if not isinstance(source_kind, str) or source_kind not in {
            "diff",
            "base_file",
            "head_file",
            "source_window",
            "profile_context",
            "repository_file",
            "test_result",
            "tool_result",
            "profile",
            "model_assessment",
            "human_note",
        }:
            raise ClaimAssessmentError("invalid_evidence_source_kind")
        source_revision = item.get("source_revision")
        if source_revision == identity["base_sha"]:
            side = "BASE"
            sides.add(side)
        elif source_revision == identity["head_sha"]:
            side = "HEAD"
            sides.add(side)
        else:
            side = None
        cited.append(
            {
                "evidence_id": evidence_id,
                "source_kind": source_kind,
                "content_hash": content_hash,
                "trust": trust,
                "path": item.get("path"),
                "side": side,
                "source_revision": source_revision if isinstance(source_revision, str) else None,
                "line": item.get("line"),
                "content": content,
            }
        )
    state = {
        "candidate": {
            key: candidate[key] for key in ("candidate_id", "title", "observation", "consequence", "rule_or_contract")
        },
        "cited_evidence": cited,
    }
    return state, sides == {"BASE", "HEAD"}, tuple(all_refs)


def _validate_primary_assessment(assessment: Mapping[str, Any], allowed_evidence_refs: set[str]) -> dict[str, Any]:
    """Validate/copy the normalized generated v3 judgment without rewriting it."""
    if not isinstance(assessment, Mapping) or set(assessment) != _PRIMARY_FIELDS:
        raise ClaimAssessmentError("invalid_primary_assessment_fields")
    if (
        assessment.get("contract_version") != _PRIMARY_ASSESSMENT_SOURCE_CONTRACT
        or assessment.get("source_contract_version") != _PRIMARY_ASSESSMENT_SOURCE_CONTRACT
    ):
        raise ClaimAssessmentError("invalid_primary_assessment_contract")
    values = {
        "outcome": {"SUPPORTED", "NOT_SUPPORTED", "UNCERTAIN", "CONTRADICTED"},
        "observation_support": {"SUPPORTED", "NOT_ESTABLISHED", "CONTRADICTED"},
        "consequence_support": {"SUPPORTED", "NOT_ESTABLISHED", "CONTRADICTED"},
        "rule_connection_support": {"SUPPORTED", "NOT_ESTABLISHED", "CONTRADICTED"},
        "introducedness": {"INTRODUCED", "REEXPOSED", "PRE_EXISTING", "UNKNOWN"},
    }
    if any(
        not isinstance(assessment.get(key), str) or assessment.get(key) not in choices
        for key, choices in values.items()
    ):
        raise ClaimAssessmentError("invalid_primary_assessment_value")
    if not isinstance(assessment.get("material_consequence"), bool):
        raise ClaimAssessmentError("invalid_primary_assessment_value")

    # The source v3 contract is authoritative for field-level shape and bounds.
    # The adapter applies its separate whole-request byte bound after exact
    # serialization; it must not silently narrow or truncate valid v3 fields.
    source_payload = dict(assessment)
    source_payload.pop("source_contract_version", None)
    try:
        normalized = validate_adjudication(source_payload)
    except ContractIssue:
        raise ClaimAssessmentError("invalid_primary_assessment_contract") from None

    def validate_refs(value: Any, allow_empty: bool) -> list[str]:
        if (
            not isinstance(value, list)
            or len(value) > MAX_REF_COUNT
            or (not allow_empty and not value)
            or any(not _valid_text(ref, 256) or ref not in allowed_evidence_refs for ref in value)
        ):
            raise ClaimAssessmentError("invalid_primary_assessment_evidence_refs")
        return list(value)

    normalized["evidence_refs"] = validate_refs(assessment.get("evidence_refs"), allow_empty=True)
    if (
        any(
            assessment.get(key) == "SUPPORTED"
            for key in ("observation_support", "consequence_support", "rule_connection_support")
        )
        and not normalized["evidence_refs"]
    ):
        raise ClaimAssessmentError("invalid_primary_assessment_evidence_refs")
    roles = normalized["causal_roles"]
    if not isinstance(roles, Mapping) or set(roles) != _CAUSAL_ROLE_NAMES:
        raise ClaimAssessmentError("invalid_primary_assessment_causal_roles")
    for role in roles.values():
        role["evidence_refs"] = validate_refs(role["evidence_refs"], allow_empty=role["support"] == "NOT_ESTABLISHED")
    return normalized


def _primary_reference_ids(assessment: Mapping[str, Any]) -> list[str]:
    """Read source IDs for collection; the full assessment validation follows."""
    if not isinstance(assessment, Mapping):
        raise ClaimAssessmentError("invalid_primary_assessment_fields")
    refs = assessment.get("evidence_refs")
    roles = assessment.get("causal_roles")
    if not isinstance(refs, list) or not isinstance(roles, Mapping):
        raise ClaimAssessmentError("invalid_primary_assessment_evidence_refs")
    collected = list(refs)
    for role in roles.values():
        if not isinstance(role, Mapping) or not isinstance(role.get("evidence_refs"), list):
            raise ClaimAssessmentError("invalid_primary_assessment_evidence_refs")
        collected.extend(role["evidence_refs"])
    if any(not _valid_text(ref, 256) for ref in collected):
        raise ClaimAssessmentError("invalid_primary_assessment_evidence_refs")
    return list(dict.fromkeys(collected))


def _questions(
    candidate_id: str,
    include_introducedness: bool,
    contract_version: str = CONTRACT_VERSION,
) -> tuple[dict[str, Any], dict[str, str]]:
    dimensions = [
        "observation_support",
        "consequence_support",
        "rule_connection_support",
        "materiality",
        "missing_context",
    ]
    dimensions.append("introducedness")
    questions: dict[str, Any] = {}
    ids: dict[str, str] = {}
    for dimension in dimensions:
        question_id = _question_id(candidate_id, dimension, contract_version)
        ids[dimension] = question_id
        if dimension == "introducedness" and not include_introducedness:
            continue
        options = _DIMENSIONS[dimension]
        instruction = (
            f"For candidate {candidate_id!r}, assess only the supplied candidate and its exact cited evidence. "
            f"Return the best category for {dimension}. Do not infer facts absent from the evidence. "
            "This is an advisory evidence judgment; do not choose an action, disposition, workflow, or retrieval request."
        )
        if contract_version == PRIMARY_ASSESSMENT_CONTRACT_VERSION:
            instruction = (
                f"For candidate {candidate_id!r}, independently assess only the supplied candidate and its exact cited "
                f"source evidence. A separately labeled prior model assessment is context about another model's judgment, "
                f"not evidence and not an answer to copy. Return the best category for {dimension}. Do not infer facts "
                "absent from source evidence. This is advisory, not a disposition or action."
            )
        questions[question_id] = {
            "type": "choice",
            "instructions": instruction,
            "criteria": options,
        }
    return questions, ids


class ClaimAssessmentAdapter:
    """Build one bounded native request and preserve per-question responses.

    `native_call` is a transport seam and must perform no caller-controlled
    actions. It receives serialized JSON, a relative deadline, and response
    byte cap, and returns the exact response body bytes. No built-in live
    transport or credential handling is provided here. The deadline is
    cooperative: late results are marked FAILED, but the adapter cannot stop
    a blocking callback. A production caller must provide a transport or
    killable process boundary that enforces the wall-clock timeout.
    """

    def __init__(self, native_call: Callable[[bytes, float, int], bytes], model: str):
        if not callable(native_call):
            raise ClaimAssessmentError("native_transport_required")
        if not _valid_text(model, 256):
            raise ClaimAssessmentError("configured_model_required")
        self.native_call = native_call
        self.configured_model = model

    @property
    def identity(self) -> dict[str, Any]:
        transport_identity = getattr(self.native_call, "identity", None)
        if callable(transport_identity):
            transport_identity = transport_identity()
        if not isinstance(transport_identity, (dict, list, str, int, float, bool, type(None))):
            transport_identity = {"type": type(self.native_call).__name__}
        return {
            "provider_id": "typesafe-claim-assessment",
            "configured_model_id": self.configured_model,
            "contract_version": PRIMARY_ASSESSMENT_CONTRACT_VERSION,
            "native_contract": NATIVE_CONTRACT,
            "transport": transport_identity,
        }

    def _validate_prepared(self, prepared: PreparedClaimAssessment) -> dict[str, Any]:
        """Validate exact prepared bytes and their metadata without transport use."""
        if (
            not isinstance(prepared, PreparedClaimAssessment)
            or prepared.contract_version not in {CONTRACT_VERSION, PRIMARY_ASSESSMENT_CONTRACT_VERSION}
            or not isinstance(prepared.request_bytes, bytes)
            or len(prepared.request_bytes) > _MAX_REQUEST_BYTES
            or not isinstance(prepared.request_hash, str)
            or not _SHA256.fullmatch(prepared.request_hash)
            or _sha(prepared.request_bytes) != prepared.request_hash
        ):
            raise ClaimAssessmentError("invalid_prepared_assessment")
        try:
            request = _parse_json(prepared.request_bytes)
        except ClaimAssessmentError:
            raise ClaimAssessmentError("invalid_prepared_assessment") from None
        if not isinstance(request, dict) or set(request) != {"model", "state", "questions"}:
            raise ClaimAssessmentError("invalid_prepared_assessment")
        if request["model"] != self.configured_model or _canonical(request) != prepared.request_bytes:
            raise ClaimAssessmentError("invalid_prepared_assessment")
        state = request.get("state")
        if not isinstance(state, dict) or not isinstance(state.get("candidate"), dict):
            raise ClaimAssessmentError("invalid_prepared_assessment")
        candidate = state["candidate"]
        if not _valid_text(candidate.get("candidate_id"), 256):
            raise ClaimAssessmentError("invalid_prepared_assessment")
        if (
            not isinstance(prepared.question_ids, tuple)
            or any(
                not isinstance(pair, tuple) or len(pair) != 2 or not all(isinstance(value, str) for value in pair)
                for pair in prepared.question_ids
            )
            or not isinstance(prepared.introducedness_available, bool)
        ):
            raise ClaimAssessmentError("invalid_prepared_assessment")
        dimensions = dict(prepared.question_ids)
        if (
            len(dimensions) != len(prepared.question_ids)
            or set(dimensions) != set(_DIMENSIONS)
            or not isinstance(prepared.evidence_refs, tuple)
            or not prepared.evidence_refs
            or any(not _valid_text(ref, 256) for ref in prepared.evidence_refs)
        ):
            raise ClaimAssessmentError("invalid_prepared_assessment")
        questions = request.get("questions")
        expected_questions, expected_ids = _questions(
            candidate["candidate_id"],
            prepared.introducedness_available,
            prepared.contract_version,
        )
        if (
            questions != expected_questions
            or dimensions != expected_ids
            or tuple(prepared.evidence_refs) != tuple(dict.fromkeys(prepared.evidence_refs))
            or not prepared.evidence_refs
        ):
            raise ClaimAssessmentError("invalid_prepared_assessment")
        expected_state_fields = {"assessment_identity", "candidate", "cited_evidence"}
        if prepared.contract_version == PRIMARY_ASSESSMENT_CONTRACT_VERSION:
            expected_state_fields |= {"assessment_contract_version", "primary_assessment"}
        if not isinstance(state, dict) or set(state) != expected_state_fields:
            raise ClaimAssessmentError("invalid_prepared_assessment")
        candidate_state = state.get("candidate")
        evidence_state = state.get("cited_evidence")
        identity_record = state.get("assessment_identity")
        if (
            not isinstance(candidate_state, dict)
            or not isinstance(evidence_state, list)
            or not isinstance(identity_record, dict)
        ):
            raise ClaimAssessmentError("invalid_prepared_assessment")
        if any(not isinstance(item, dict) or not _valid_text(item.get("evidence_id"), 256) for item in evidence_state):
            raise ClaimAssessmentError("invalid_prepared_assessment")
        try:
            _validate_identity(identity_record)
        except ClaimAssessmentError:
            raise ClaimAssessmentError("invalid_prepared_assessment") from None
        if prepared.contract_version == CONTRACT_VERSION:
            if prepared.primary_assessment_hash is not None:
                raise ClaimAssessmentError("invalid_prepared_assessment")
        else:
            primary = state.get("primary_assessment")
            cited_ids = (
                {
                    item.get("evidence_id")
                    for item in evidence_state
                    if isinstance(item, dict) and isinstance(item.get("evidence_id"), str)
                }
                if isinstance(evidence_state, list)
                else set()
            )
            if (
                set(state)
                != {
                    "assessment_identity",
                    "candidate",
                    "cited_evidence",
                    "assessment_contract_version",
                    "primary_assessment",
                }
                or state.get("assessment_contract_version") != PRIMARY_ASSESSMENT_CONTRACT_VERSION
                or set(candidate_state)
                != {"candidate_id", "title", "observation", "consequence", "rule_or_contract", "evidence_refs"}
                or not isinstance(primary, dict)
                or _sha(_canonical(primary)) != prepared.primary_assessment_hash
            ):
                raise ClaimAssessmentError("invalid_prepared_assessment")
            original_refs = candidate_state.get("evidence_refs")
            cited_order = [item.get("evidence_id") for item in evidence_state]
            if (
                not isinstance(original_refs, list)
                or not original_refs
                or any(not _valid_text(ref, 256) for ref in original_refs)
                or len(set(original_refs)) != len(original_refs)
                or any(ref not in cited_order for ref in original_refs)
                or tuple(prepared.evidence_refs) != tuple(cited_order)
            ):
                raise ClaimAssessmentError("invalid_prepared_assessment")
            try:
                normalized_primary = _validate_primary_assessment(primary, cited_ids)
            except ClaimAssessmentError:
                raise ClaimAssessmentError("invalid_prepared_assessment") from None
            if normalized_primary != primary:
                raise ClaimAssessmentError("invalid_prepared_assessment")
        if (
            _sha(_canonical(candidate_state)) != prepared.candidate_hash
            or _sha(_canonical(evidence_state)) != prepared.evidence_hash
            or _sha(_canonical(questions)) != prepared.question_hash
        ):
            raise ClaimAssessmentError("invalid_prepared_assessment")
        identity_fields = ("snapshot_id", "snapshot_hash", "profile_id", "profile_hash", "base_sha", "head_sha")
        if not isinstance(identity_record, dict) or set(identity_record) != set(identity_fields):
            raise ClaimAssessmentError("invalid_prepared_assessment")
        identity_record = {key: identity_record[key] for key in identity_fields}
        input_hash = _sha(prepared.request_bytes)
        provenance: dict[str, Any] = {
            "contract_version": prepared.contract_version,
            "native_contract": NATIVE_CONTRACT,
            "provider_id": "typesafe",
            "configured_model_id": self.configured_model,
            "provider_model_id": None,
            "model_identity_source": "not_reported_by_endpoint",
            "request_id": None,
            "request_hash": input_hash,
            "response_hash": None,
            "response_bytes": None,
            "candidate_hash": prepared.candidate_hash,
            "evidence_hash": prepared.evidence_hash,
            "question_hash": prepared.question_hash,
            **identity_record,
        }
        if prepared.primary_assessment_hash is not None:
            provenance["primary_assessment_hash"] = prepared.primary_assessment_hash
        assessments = {
            dimension: {
                "question_id": question_id,
                "status": "NOT_SHOWN"
                if dimension == "introducedness" and not prepared.introducedness_available
                else "NOT_RUN",
                "native_primitive": "Choice",
                "choice": None,
                "probabilities": None,
                "confidence": None,
                "evidence_refs": list(prepared.evidence_refs),
                "interpretation": "advisory_uncalibrated",
                "invalid_answer_hash": None,
                "error_code": "base_head_evidence_not_provided"
                if dimension == "introducedness" and not prepared.introducedness_available
                else None,
            }
            for dimension, question_id in dimensions.items()
        }
        return {
            "dimensions": dimensions,
            "provenance": provenance,
            "assessments": assessments,
        }

    def estimate_prepared(self, prepared: PreparedClaimAssessment, limits: Mapping[str, Any]) -> dict[str, Any]:
        """Quote the exact prepared request and separate wire response from IPC output bounds."""
        if (
            not isinstance(prepared, PreparedClaimAssessment)
            or prepared.contract_version != PRIMARY_ASSESSMENT_CONTRACT_VERSION
            or not isinstance(limits, Mapping)
        ):
            raise ClaimAssessmentError("invalid_prepared_assessment")
        input_cap, _output_cap, requested_deadline = _limits(limits)
        self._validate_prepared(prepared)
        if len(prepared.request_bytes) > input_cap:
            raise ClaimAssessmentError("request_exceeds_limit")
        estimator = getattr(self.native_call, "estimate_call", None)
        if not callable(estimator):
            raise ClaimAssessmentError("claim_transport_estimator_required")
        quote = estimator(prepared.request_bytes, dict(limits))
        if not isinstance(quote, dict):
            raise ClaimAssessmentError("invalid_claim_transport_estimate")
        response_cap = quote.get("max_output_bytes")
        if (
            quote.get("provider_calls") != 1
            or quote.get("input_bytes") != len(prepared.request_bytes)
            or not _is_positive_int(response_cap)
            or response_cap > int(limits["max_output_bytes_per_task"])
        ):
            raise ClaimAssessmentError("invalid_claim_transport_estimate")
        deadline = quote.get("deadline_seconds")
        if not _finite_number(deadline) or deadline <= 0 or deadline > requested_deadline:
            raise ClaimAssessmentError("invalid_claim_transport_estimate")
        return {
            **quote,
            "provider_calls": 1,
            "input_bytes": len(prepared.request_bytes),
            "provider_response_bytes": response_cap,
            # BudgetLedger and the process boundary cap the serialized result,
            # distinct from the transport's raw HTTP response-byte cap.
            "max_output_bytes": int(limits["max_output_bytes_per_task"]),
        }

    def assess(
        self,
        candidate: Mapping[str, Any],
        evidence: Sequence[Mapping[str, Any]],
        identity: Mapping[str, Any],
        limits: Mapping[str, Any],
    ) -> dict[str, Any]:
        prepared = self.prepare(candidate, evidence, identity, limits)
        return self.assess_prepared(prepared, limits)

    def prepare(
        self,
        candidate: Mapping[str, Any],
        evidence: Sequence[Mapping[str, Any]],
        identity: Mapping[str, Any],
        limits: Mapping[str, Any],
        primary_assessment: Mapping[str, Any] | None = None,
    ) -> PreparedClaimAssessment:
        """Build once so the same exact bytes can be measured, reserved, and dispatched."""
        if not isinstance(candidate, Mapping) or not isinstance(identity, Mapping) or not isinstance(limits, Mapping):
            raise ClaimAssessmentError("invalid_assessment_input")
        _validate_identity(identity)
        input_cap, _output_cap, _deadline_seconds = _limits(limits)
        extra_refs = _primary_reference_ids(primary_assessment) if primary_assessment is not None else []
        state, has_revision_pair, cited_refs = _candidate_state(candidate, evidence, identity, extra_refs)
        contract_version = CONTRACT_VERSION
        primary_hash = None
        if primary_assessment is not None:
            normalized = _validate_primary_assessment(primary_assessment, set(cited_refs))
            primary_hash = _sha(_canonical(normalized))
            state["assessment_contract_version"] = PRIMARY_ASSESSMENT_CONTRACT_VERSION
            state["candidate"]["evidence_refs"] = list(candidate["evidence_refs"])
            state["primary_assessment"] = normalized
            contract_version = PRIMARY_ASSESSMENT_CONTRACT_VERSION
        questions, dimension_ids = _questions(candidate["candidate_id"], has_revision_pair, contract_version)
        if len(questions) > _MAX_QUESTIONS:
            raise ClaimAssessmentError("question_limit_exceeded")
        identity_record = {
            key: identity[key]
            for key in ("snapshot_id", "snapshot_hash", "profile_id", "profile_hash", "base_sha", "head_sha")
        }
        state["assessment_identity"] = identity_record
        request: dict[str, Any] = {"model": self.configured_model, "state": state, "questions": questions}
        request_bytes = _canonical(request)
        if len(request_bytes) > _MAX_REQUEST_BYTES:
            raise ClaimAssessmentError("request_exceeds_intrinsic_limit")
        if len(request_bytes) > input_cap:
            raise ClaimAssessmentError("request_exceeds_limit")
        return PreparedClaimAssessment(
            contract_version=contract_version,
            request_bytes=request_bytes,
            question_ids=tuple(dimension_ids.items()),
            evidence_refs=cited_refs,
            candidate_hash=_sha(_canonical(state["candidate"])),
            evidence_hash=_sha(_canonical(state["cited_evidence"])),
            question_hash=_sha(_canonical(questions)),
            request_hash=_sha(request_bytes),
            introducedness_available=has_revision_pair,
            primary_assessment_hash=primary_hash,
        )

    def assess_prepared(self, prepared: PreparedClaimAssessment, limits: Mapping[str, Any]) -> dict[str, Any]:
        """Dispatch exactly the preflighted bytes once and validate bounded native answers."""
        if not isinstance(prepared, PreparedClaimAssessment):
            raise ClaimAssessmentError("invalid_prepared_assessment")
        if not isinstance(limits, Mapping):
            raise ClaimAssessmentError("invalid_assessment_input")
        input_cap, output_cap, deadline_seconds = _limits(limits)
        if not isinstance(prepared.request_bytes, bytes):
            raise ClaimAssessmentError("invalid_prepared_assessment")
        if len(prepared.request_bytes) > input_cap:
            raise ClaimAssessmentError("request_exceeds_limit")
        validated = self._validate_prepared(prepared)
        dimension_ids = validated["dimensions"]
        provenance = validated["provenance"]
        assessments = validated["assessments"]
        elapsed_ms: float | None = None
        provider_usage: dict[str, int] | None = None
        try:
            start = time.monotonic()
            raw = self.native_call(prepared.request_bytes, deadline_seconds, output_cap)
            elapsed_ms = round((time.monotonic() - start) * 1000, 2)
        except Exception as exc:
            for item in assessments.values():
                if item["status"] == "NOT_RUN":
                    item["status"] = "FAILED"
                    item["error_code"] = _safe_error_code(exc)
            provenance["error_class"] = type(exc).__name__[:80]
            error_code = _safe_error_code(exc)
            if error_code != "native_call_failed":
                provenance["error_code"] = error_code
            meta = getattr(exc, "meta", {})
            if isinstance(meta, dict):
                response_hash = meta.get("response_hash")
                response_bytes = meta.get("response_bytes")
                http_status = meta.get("http_status")
                if isinstance(response_hash, str) and _SHA256.fullmatch(response_hash):
                    provenance["response_hash"] = response_hash
                if isinstance(response_bytes, int) and not isinstance(response_bytes, bool) and response_bytes >= 0:
                    provenance["response_bytes"] = response_bytes
                if isinstance(http_status, int) and not isinstance(http_status, bool) and 100 <= http_status <= 599:
                    provenance["http_status"] = http_status
            return self._result(
                "FAILED", assessments, provenance, elapsed_ms, provider_usage, prepared.contract_version
            )

        provenance["elapsed_ms"] = elapsed_ms
        if isinstance(raw, bytes):
            provenance["response_hash"] = _sha(raw)
            provenance["response_bytes"] = len(raw)
        if elapsed_ms is not None and elapsed_ms > deadline_seconds * 1000:
            for item in assessments.values():
                if item["status"] == "NOT_RUN":
                    item["status"] = "FAILED"
                    item["error_code"] = "native_call_deadline_exceeded"
            return self._result(
                "FAILED", assessments, provenance, elapsed_ms, provider_usage, prepared.contract_version
            )

        if not isinstance(raw, bytes):
            for item in assessments.values():
                if item["status"] == "NOT_RUN":
                    item["status"] = "FAILED"
                    item["error_code"] = "native_response_not_bytes"
            return self._result(
                "FAILED", assessments, provenance, elapsed_ms, provider_usage, prepared.contract_version
            )
        if len(raw) > output_cap:
            for item in assessments.values():
                if item["status"] == "NOT_RUN":
                    item["status"] = "FAILED"
                    item["error_code"] = "native_response_exceeds_limit"
            return self._result(
                "FAILED", assessments, provenance, elapsed_ms, provider_usage, prepared.contract_version
            )
        try:
            envelope = _parse_json(raw)
        except ClaimAssessmentError:
            for item in assessments.values():
                if item["status"] == "NOT_RUN":
                    item["status"] = "FAILED"
                    item["error_code"] = "malformed_native_response"
            return self._result(
                "FAILED", assessments, provenance, elapsed_ms, provider_usage, prepared.contract_version
            )
        if not isinstance(envelope, dict) or not isinstance(envelope.get("answers"), dict):
            for item in assessments.values():
                if item["status"] == "NOT_RUN":
                    item["status"] = "FAILED"
                    item["error_code"] = "invalid_native_envelope"
            return self._result(
                "FAILED", assessments, provenance, elapsed_ms, provider_usage, prepared.contract_version
            )

        actual_model = envelope.get("model")
        model_valid = isinstance(actual_model, str) and bool(actual_model.strip()) and len(actual_model) <= 256
        if prepared.contract_version == PRIMARY_ASSESSMENT_CONTRACT_VERSION:
            provenance.pop("provider_model_id", None)
            model_valid = bool(
                model_valid
                and (
                    _VERSIONED_JEV_MODEL_ID.fullmatch(actual_model)
                    if self.configured_model == "jev-latest"
                    else actual_model == self.configured_model
                )
            )
            if model_valid:
                provenance["provider_model_id"] = actual_model
                provenance["model_identity_source"] = "endpoint_reported_validated"
            elif "model" in envelope:
                provenance["invalid_provider_model_id_hash"] = _sha(_safe_hash_bytes(actual_model))
            error = "model_identity_missing" if "model" not in envelope else "model_identity_mismatch"
            if not model_valid:
                for item in assessments.values():
                    if item["status"] == "NOT_RUN":
                        item.update(status="FAILED", error_code=error)
                provenance["error_code"] = error
                return self._result(
                    "FAILED", assessments, provenance, elapsed_ms, provider_usage, prepared.contract_version
                )
        elif model_valid:
            provenance["provider_model_id"] = actual_model
            provenance["model_identity_source"] = "endpoint_reported"
        elif "model" in envelope:
            provenance["invalid_provider_model_id_hash"] = _sha(_safe_hash_bytes(actual_model))
        request_id = envelope.get("request_id")
        if isinstance(request_id, str) and request_id.strip() and len(request_id) <= 256:
            provenance["request_id"] = request_id
        usage = envelope.get("usage")
        if isinstance(usage, dict):
            parsed: dict[str, int] = {}
            for key in ("input_tokens", "output_tokens"):
                value = usage.get(key)
                if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
                    parsed[key] = value
            if len(parsed) == 2:
                provider_usage = parsed

        expected_ids = {item["question_id"] for item in assessments.values() if item["status"] == "NOT_RUN"}
        answers = envelope["answers"]
        extra_ids = sorted(set(answers) - expected_ids)
        if extra_ids:
            provenance["unexpected_answer_count"] = len(extra_ids)
            provenance["unexpected_answers"] = [
                {
                    "question_id_hash": _sha(key.encode("utf-8")),
                    "answer_hash": _sha(_safe_hash_bytes(answers[key])),
                }
                for key in extra_ids
            ]
        option_sets = {dimension: set(_DIMENSIONS[dimension]) for dimension in dimension_ids}
        id_dimensions = {question_id: dimension for dimension, question_id in dimension_ids.items()}
        for question_id, dimension in id_dimensions.items():
            item = assessments[dimension]
            if item["status"] != "NOT_RUN":
                continue
            if question_id not in answers:
                item.update(status="OMITTED", error_code="answer_omitted")
                continue
            answer = answers[question_id]
            if not self._valid_choice(answer, option_sets[dimension]):
                item.update(
                    status="INVALID",
                    error_code="invalid_choice_answer",
                    invalid_answer_hash=_sha(_safe_hash_bytes(answer)),
                )
                continue
            item.update(
                status="ANSWERED",
                choice=answer["choice"],
                probabilities={key: float(value) for key, value in answer["probabilities"].items()},
                confidence=float(answer["confidence"]),
                error_code=None,
            )
        states = {item["status"] for item in assessments.values()}
        if states <= {"ANSWERED", "NOT_SHOWN"}:
            result_status = "COMPLETE"
        elif "ANSWERED" in states:
            result_status = "PARTIAL"
        else:
            result_status = "FAILED"
        return self._result(
            result_status, assessments, provenance, elapsed_ms, provider_usage, prepared.contract_version
        )

    @staticmethod
    def _valid_choice(answer: Any, allowed: set[str]) -> bool:
        if not isinstance(answer, dict) or set(answer) != {"type", "choice", "probabilities", "confidence"}:
            return False
        if answer.get("type") != "choice" or answer.get("choice") not in allowed:
            return False
        probabilities = answer.get("probabilities")
        confidence = answer.get("confidence")
        if not isinstance(probabilities, dict) or set(probabilities) != allowed or not _finite_number(confidence):
            return False
        if not 0 <= confidence <= 1:
            return False
        values = list(probabilities.values())
        if any(not _finite_number(value) or not 0 <= value <= 1 for value in values):
            return False
        if abs(sum(values) - 1.0) > 0.02:
            return False
        # The selected option must be among the maximum-probability options;
        # ties are valid. This validates the native answer shape only.
        return probabilities[answer["choice"]] >= max(values) - 1e-6

    @staticmethod
    def _result(
        status: str,
        assessments: dict[str, dict[str, Any]],
        provenance: dict[str, Any],
        elapsed_ms: float | None,
        usage: dict[str, int] | None,
        contract_version: str = CONTRACT_VERSION,
    ) -> dict[str, Any]:
        return {
            "contract_version": contract_version,
            "status": status,
            "assessments": assessments,
            "usage": {"known": usage is not None, **(usage or {"input_tokens": None, "output_tokens": None})},
            "provenance": provenance,
            "elapsed_ms": elapsed_ms,
            "decision": "ADVISORY_ONLY",
        }


def _safe_hash_bytes(value: Any) -> bytes:
    try:
        return _canonical(value)
    except (TypeError, ValueError, RecursionError):
        return repr(type(value).__name__).encode("ascii")


def _safe_error_code(exc: Exception) -> str:
    value = getattr(exc, "code", None)
    if isinstance(value, str) and re.fullmatch(r"[a-z][a-z0-9_]{0,79}", value):
        return value
    return "native_call_failed"
