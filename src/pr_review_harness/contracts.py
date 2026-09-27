"""Versioned, bounded contracts at the untrusted model boundary.

The provider emits Specialist V4 and Adjudication V3 records. The adapter
accepts historical contracts during migration without promoting their source
version or synthesizing missing causal-role evidence.
Validation failures for individual list items are returned as hash-only
quarantine records so valid siblings and provider metering survive.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

SPECIALIST_V1 = "specialist-findings.v1"
SPECIALIST_V2 = "specialist-findings.v2"
SPECIALIST_V3 = "specialist-findings.v3"
SPECIALIST_V4 = "specialist-findings.v4"
SPECIALIST_INPUT_V2 = "specialist-input.v2"
ADJUDICATION_V1 = "semantic-adjudication.v1"
ADJUDICATION_V2 = "semantic-adjudication.v2"
ADJUDICATION_V3 = "semantic-adjudication.v3"
ADJUDICATION_RUBRIC_VERSION = "causal-roles.behavior-consumer-impact.v1"
SPECIALIST_INTERNAL = "specialist-findings.engine-v2"

MAX_ITEMS = 100
MAX_TEXT_BYTES = 12_000
MAX_GAP_TEXT_BYTES = 4_000
MAX_REF_COUNT = 500
MAX_REPORT_NOTES = 10
MAX_NOTE_TEXT_BYTES = 2_000
CAUSAL_ROLE_NAMES = ("behavior", "consumer", "impact")
CAUSAL_SUPPORT_VALUES = ("SUPPORTED", "NOT_ESTABLISHED", "CONTRADICTED")
MAX_CAUSAL_ASSESSMENT_BYTES = 2_000
MAX_CAUSAL_ROLE_EVIDENCE_REFS = 50

_LENSES = {"correctness", "tests", "design", "security", "performance", "maintainability", "project_specific"}
_EVIDENCE_KINDS = {
    "caller",
    "implementation",
    "test",
    "configuration",
    "contract",
    "trust_boundary",
    "provenance",
    "other",
}
_SEVERITIES = {"critical", "high", "medium", "low", "informational", "unknown"}
_INTRODUCEDNESS = {"INTRODUCED", "REEXPOSED", "PRE_EXISTING", "UNKNOWN"}
_SUPPORT = {"SUPPORTED", "NOT_ESTABLISHED", "CONTRADICTED"}


class ContractIssue(ValueError):
    """A bounded validation error suitable for a public reason code."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _is_text(value: Any, limit: int = MAX_TEXT_BYTES) -> bool:
    if not isinstance(value, str) or not value.strip():
        return False
    try:
        return len(value.encode("utf-8")) <= limit
    except UnicodeEncodeError:
        return False


def _hash_item(item: Any) -> str:
    try:
        encoded = json.dumps(item, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError):
        encoded = repr(type(item).__name__).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def _require_fields(item: Any, fields: set[str], code: str) -> dict[str, Any]:
    if not isinstance(item, dict) or set(item) != fields:
        raise ContractIssue(code)
    return item


_CANDIDATE_COMMON = {
    "title",
    "observation",
    "consequence",
    "rule_or_contract",
    "severity",
    "reasoning_kind",
    "evidence_refs",
    "introducedness",
}


def validate_candidate(
    item: Any,
    source_version: str = SPECIALIST_V1,
    valid_unit_ids: set[str] | None = None,
) -> dict[str, Any]:
    legacy_required = _CANDIDATE_COMMON | {"path", "line"}
    v3_required = _CANDIDATE_COMMON | {"location", "unit_id"}
    if source_version in {SPECIALIST_V1, SPECIALIST_V2}:
        value = _require_fields(item, legacy_required, "invalid_candidate_fields")
        path = value["path"]
        line = value["line"]
        # Historical null lines are ambiguous. Never reinterpret them as file
        # locations; only V3's explicit tagged location can make that claim.
        if line is None:
            raise ContractIssue("invalid_candidate_line")
        location = {"kind": "line", "path": path, "side": "HEAD", "line": line, "reason": None}
        unit_id = None
    elif source_version in {SPECIALIST_V3, SPECIALIST_V4}:
        value = _require_fields(item, v3_required, "invalid_candidate_fields")
        unit_id = value["unit_id"]
        if not _is_text(unit_id, 256):
            raise ContractIssue("invalid_candidate_unit_id")
        if valid_unit_ids is not None and unit_id not in valid_unit_ids:
            raise ContractIssue("candidate_references_unknown_scope")
        location = value["location"]
        if not isinstance(location, dict) or set(location) != {"kind", "path", "side", "line", "reason"}:
            raise ContractIssue("invalid_candidate_location")
        if location["kind"] not in {"line", "file"} or location["side"] not in {"HEAD", "BASE"}:
            raise ContractIssue("invalid_candidate_location")
        if not _is_text(location["path"], 2_000):
            raise ContractIssue("invalid_candidate_location")
        if location["kind"] == "line":
            if (
                isinstance(location["line"], bool)
                or not isinstance(location["line"], int)
                or location["line"] < 1
                or location["reason"] is not None
            ):
                raise ContractIssue("invalid_candidate_location")
        elif location["line"] is not None or not _is_text(location["reason"], 256):
            raise ContractIssue("invalid_candidate_location")
        path, line = location["path"], location["line"]
    else:
        raise ContractIssue("unsupported_specialist_contract")
    for key in ("title", "observation", "consequence", "rule_or_contract"):
        if not _is_text(value[key]):
            raise ContractIssue("invalid_candidate_text")
    if not _is_text(path, 2_000):
        raise ContractIssue("invalid_candidate_text")
    if location["kind"] == "line" and (isinstance(line, bool) or not isinstance(line, int) or line < 1):
        raise ContractIssue("invalid_candidate_line")
    if value["severity"] not in _SEVERITIES:
        raise ContractIssue("invalid_candidate_severity")
    if value["reasoning_kind"] not in {"observed", "inferred"}:
        raise ContractIssue("invalid_candidate_reasoning_kind")
    if value["introducedness"] not in _INTRODUCEDNESS:
        raise ContractIssue("invalid_candidate_introducedness")
    refs = value["evidence_refs"]
    if not isinstance(refs, list) or not 0 < len(refs) <= MAX_REF_COUNT or any(not _is_text(ref, 256) for ref in refs):
        raise ContractIssue("invalid_candidate_evidence_refs")
    # Normalize legacy providers and V3 to the existing engine shape while
    # retaining the typed location and explicit V3 scope identifier.
    return {**value, "path": path, "line": line, "location": location, **({"unit_id": unit_id} if unit_id else {})}


def _normalize_gap_target(target: Any, source_version: str) -> dict[str, str]:
    """Return the legacy engine representation after enforcing one target."""
    if isinstance(target, dict) and set(target) == {"kind", "value"}:
        kind, value = target.get("kind"), target.get("value")
        if kind not in {"unit", "path", "symbol"} or not _is_text(value, 2_000):
            raise ContractIssue("invalid_context_gap_target")
        field = {"unit": "target_unit_id", "path": "target_path", "symbol": "target_symbol"}[kind]
        return {
            "target_unit_id": value if field == "target_unit_id" else None,
            "target_path": value if field == "target_path" else None,
            "target_symbol": value if field == "target_symbol" else None,
        }

    # V1 migration: historical nested target, or the original flat triplet.
    legacy_keys = {"target_unit_id", "target_path", "target_symbol"}
    if source_version == SPECIALIST_V1:
        if isinstance(target, dict) and set(target) == legacy_keys:
            values = target
        elif isinstance(target, dict) and set(target) == {"target_unit_id", "target_path", "target_symbol"}:
            values = target
        else:
            raise ContractIssue("invalid_context_gap_target")
        selected = [key for key, val in values.items() if _is_text(val, 2_000)]
        if len(selected) != 1 or any(val is not None and not _is_text(val, 2_000) for val in values.values()):
            raise ContractIssue("invalid_context_gap_target")
        return {key: values[key] for key in legacy_keys}
    raise ContractIssue("invalid_context_gap_target")


def validate_gap(item: Any, source_version: str) -> dict[str, Any]:
    if not isinstance(item, dict):
        raise ContractIssue("invalid_context_gap_fields")
    base = {"evidence_kind", "target", "rationale", "related_candidate_ids", "related_evidence_ids", "required_lens"}
    fields = set(item)
    # The V1 artifact schema predates related candidate IDs.
    if source_version == SPECIALIST_V1 and fields == base - {"related_candidate_ids"}:
        value = item
        candidate_ids = []
    elif source_version == SPECIALIST_V1 and fields == (base - {"target", "related_candidate_ids"}) | {
        "target_unit_id",
        "target_path",
        "target_symbol",
    }:
        value = {**item, "target": {key: item[key] for key in ("target_unit_id", "target_path", "target_symbol")}}
        candidate_ids = []
    elif fields == base:
        value = item
        candidate_ids = item["related_candidate_ids"]
    else:
        raise ContractIssue("invalid_context_gap_fields")
    if value["evidence_kind"] not in _EVIDENCE_KINDS:
        raise ContractIssue("invalid_context_gap_kind")
    target = _normalize_gap_target(value["target"], source_version)
    if not _is_text(value["rationale"], MAX_GAP_TEXT_BYTES):
        raise ContractIssue("invalid_context_gap_text")
    if value["required_lens"] not in _LENSES:
        raise ContractIssue("invalid_context_gap_lens")
    for key, refs in (
        ("related_candidate_ids", candidate_ids),
        ("related_evidence_ids", value["related_evidence_ids"]),
    ):
        if not isinstance(refs, list) or len(refs) > MAX_REF_COUNT or any(not _is_text(ref, 256) for ref in refs):
            raise ContractIssue(f"invalid_context_gap_{key}")
    # Engine-facing shape remains stable until its shared-contract migration.
    return {
        "evidence_kind": value["evidence_kind"],
        "target": target,
        "rationale": value["rationale"],
        "related_candidate_ids": list(candidate_ids),
        "related_evidence_ids": list(value["related_evidence_ids"]),
        "required_lens": value["required_lens"],
    }


def validate_coverage_note(item: Any, source_version: str) -> dict[str, Any]:
    required = {"unit_id", "state", "reason_code", "evidence_refs"}
    expected = required | (
        {"coverage_basis"} if source_version in {SPECIALIST_V2, SPECIALIST_V3, SPECIALIST_V4} else set()
    )
    if isinstance(item, dict) and source_version == SPECIALIST_V1 and set(item) == required | {"coverage_basis"}:
        expected = set(item)
    value = _require_fields(item, expected, "invalid_coverage_note")
    if not _is_text(value["unit_id"], 256) or not _is_text(value["reason_code"], 256):
        raise ContractIssue("invalid_coverage_note")
    if value["state"] not in {"COVERED", "PARTIAL", "NOT_COVERED"}:
        raise ContractIssue("invalid_coverage_note")
    refs = value["evidence_refs"]
    if not isinstance(refs, list) or len(refs) > MAX_REF_COUNT or any(not _is_text(ref, 256) for ref in refs):
        raise ContractIssue("invalid_coverage_note")
    if value["state"] == "COVERED" and not refs:
        raise ContractIssue("invalid_coverage_note")
    if "coverage_basis" in value and value["coverage_basis"] != "STATIC_REVIEW":
        raise ContractIssue("invalid_coverage_basis")
    # This is a claim about static evidence reviewed, never command execution.
    return {**value, "coverage_basis": "STATIC_REVIEW"}


def validate_report_note(
    item: Any,
    kind: str,
    *,
    valid_evidence_ids: set[str] | None = None,
    valid_unit_ids: set[str] | None = None,
) -> dict[str, Any]:
    """Validate one optional evidence-backed strength or guidance note."""
    if kind == "specific_strengths":
        detail_key = "why_it_matters"
    elif kind == "future_guidance":
        detail_key = "guidance"
    else:
        raise ContractIssue("invalid_report_note_kind")
    required = {"unit_id", "title", "observation", detail_key, "evidence_refs"}
    value = _require_fields(item, required, "invalid_report_note_fields")
    if not _is_text(value["unit_id"], 256):
        raise ContractIssue("invalid_report_note_unit_id")
    if valid_unit_ids is not None and value["unit_id"] not in valid_unit_ids:
        raise ContractIssue("report_note_references_unknown_scope")
    if not _is_text(value["title"], 256) or not _is_text(value["observation"], MAX_NOTE_TEXT_BYTES):
        raise ContractIssue("invalid_report_note_text")
    if not _is_text(value[detail_key], MAX_NOTE_TEXT_BYTES):
        raise ContractIssue("invalid_report_note_text")
    refs = value["evidence_refs"]
    if not isinstance(refs, list) or not 0 < len(refs) <= 20 or any(not _is_text(ref, 256) for ref in refs):
        raise ContractIssue("invalid_report_note_evidence_refs")
    if valid_evidence_ids is not None and not set(refs).issubset(valid_evidence_ids):
        raise ContractIssue("report_note_references_unknown_evidence")
    return value


def validate_specialist(
    payload: Any,
    *,
    valid_evidence_ids: set[str] | None = None,
    valid_unit_ids: set[str] | None = None,
    max_items: int = MAX_ITEMS,
    max_candidate_text_bytes: int = MAX_TEXT_BYTES,
) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ContractIssue("invalid_specialist_report")
    keys = set(payload)
    legacy_v1_keys = {"finding_candidates", "context_gap_proposals", "coverage_notes"}
    current_v3_keys = legacy_v1_keys | {"contract_version"}
    current_v4_keys = current_v3_keys | {"specific_strengths", "future_guidance"}
    if keys == current_v4_keys:
        version = payload["contract_version"]
        if version != SPECIALIST_V4:
            raise ContractIssue("unsupported_specialist_contract")
    elif keys == current_v3_keys:
        version = payload["contract_version"]
        if version not in {SPECIALIST_V1, SPECIALIST_V2, SPECIALIST_V3}:
            raise ContractIssue("unsupported_specialist_contract")
    elif keys == legacy_v1_keys:
        # Missing tag is accepted only as the unambiguous historical V1 shape.
        version = SPECIALIST_V1
    else:
        raise ContractIssue("invalid_specialist_fields")
    arrays = {key: payload[key] for key in ("finding_candidates", "context_gap_proposals", "coverage_notes")}
    if version == SPECIALIST_V4:
        arrays.update({key: payload[key] for key in ("specific_strengths", "future_guidance")})
    else:
        arrays.update({"specific_strengths": [], "future_guidance": []})
    if any(not isinstance(value, list) for value in arrays.values()):
        raise ContractIssue("invalid_specialist_array")
    if isinstance(max_items, bool) or not isinstance(max_items, int) or not 1 <= max_items <= MAX_ITEMS:
        raise ContractIssue("invalid_item_limit")
    valid: dict[str, list[dict[str, Any]]] = {key: [] for key in arrays}
    quarantined: list[dict[str, Any]] = []
    validators = {
        "finding_candidates": lambda item: validate_candidate(item, version, valid_unit_ids),
        "context_gap_proposals": lambda item: validate_gap(item, version),
        "coverage_notes": lambda item: validate_coverage_note(item, version),
        "specific_strengths": lambda item: validate_report_note(
            item,
            "specific_strengths",
            valid_evidence_ids=valid_evidence_ids,
            valid_unit_ids=valid_unit_ids,
        ),
        "future_guidance": lambda item: validate_report_note(
            item,
            "future_guidance",
            valid_evidence_ids=valid_evidence_ids,
            valid_unit_ids=valid_unit_ids,
        ),
    }
    accepted_count = 0
    for key, rows in arrays.items():
        for index, item in enumerate(rows):
            try:
                if key in {"specific_strengths", "future_guidance"} and index >= MAX_REPORT_NOTES:
                    raise ContractIssue("report_note_limit_exceeded")
                accepted = validators[key](item)
                if valid_evidence_ids is not None:
                    if key == "finding_candidates" and not set(accepted["evidence_refs"]).issubset(valid_evidence_ids):
                        raise ContractIssue("candidate_references_unknown_evidence")
                    if key == "context_gap_proposals" and not set(accepted["related_evidence_ids"]).issubset(
                        valid_evidence_ids
                    ):
                        raise ContractIssue("context_gap_references_unknown_evidence")
                    if key == "coverage_notes" and not set(accepted["evidence_refs"]).issubset(valid_evidence_ids):
                        raise ContractIssue("coverage_references_unknown_evidence")
                if key == "coverage_notes" and valid_unit_ids is not None and accepted["unit_id"] not in valid_unit_ids:
                    raise ContractIssue("coverage_references_unknown_scope")
                if (
                    key == "finding_candidates"
                    and max(
                        len(accepted[field].encode("utf-8"))
                        for field in ("title", "observation", "consequence", "rule_or_contract")
                    )
                    > max_candidate_text_bytes
                ):
                    raise ContractIssue("candidate_text_exceeds_limit")
                if accepted_count >= max_items:
                    raise ContractIssue("output_item_limit_exceeded")
            except ContractIssue as exc:
                quarantined.append(
                    {"kind": key, "index": index, "reason_code": exc.code, "item_hash": _hash_item(item)}
                )
            else:
                valid[key].append(accepted)
                accepted_count += 1
    return {
        "contract_version": SPECIALIST_INTERNAL,
        "source_contract_version": version,
        **valid,
        "quarantined_items": quarantined,
    }


def validate_adjudication(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ContractIssue("invalid_assessment")
    required = {
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
    }
    fields = set(payload)
    allowed_v3_fields = required | {"contract_version", "causal_roles"}
    if fields not in (required, required | {"contract_version"}) and fields != allowed_v3_fields:
        raise ContractIssue("invalid_assessment_fields")
    version = payload.get("contract_version", ADJUDICATION_V1)
    if not isinstance(version, str) or version not in {ADJUDICATION_V1, ADJUDICATION_V2, ADJUDICATION_V3}:
        raise ContractIssue("unsupported_assessment_contract")
    if (version == ADJUDICATION_V3) != (fields == allowed_v3_fields):
        raise ContractIssue("invalid_assessment_fields")
    if not isinstance(payload["outcome"], str) or payload["outcome"] not in {
        "SUPPORTED",
        "NOT_SUPPORTED",
        "UNCERTAIN",
        "CONTRADICTED",
    }:
        raise ContractIssue("invalid_assessment_outcome")
    for key in ("observation_support", "consequence_support", "rule_connection_support"):
        if not isinstance(payload[key], str) or payload[key] not in _SUPPORT:
            raise ContractIssue("invalid_assessment_support")
    if (
        not isinstance(payload["introducedness"], str)
        or payload["introducedness"] not in _INTRODUCEDNESS
        or not isinstance(payload["material_consequence"], bool)
    ):
        raise ContractIssue("invalid_assessment_semantics")
    for key in ("evidence_refs", "assumptions", "uncertainties"):
        rows = payload[key]
        if (
            not isinstance(rows, list)
            or len(rows) > MAX_REF_COUNT
            or any(not _is_text(row, MAX_TEXT_BYTES) for row in rows)
        ):
            raise ContractIssue("invalid_assessment_array")
    if (
        any(
            payload[k] == "SUPPORTED" for k in ("observation_support", "consequence_support", "rule_connection_support")
        )
        and not payload["evidence_refs"]
    ):
        raise ContractIssue("supported_claim_requires_evidence")
    if not _is_text(payload["summary"], MAX_TEXT_BYTES):
        raise ContractIssue("invalid_assessment_summary")
    causal_roles = None
    if version == ADJUDICATION_V3:
        causal_roles = payload["causal_roles"]
        if not isinstance(causal_roles, dict) or set(causal_roles) != set(CAUSAL_ROLE_NAMES):
            raise ContractIssue("invalid_causal_roles")
        normalized_roles = {}
        for role in CAUSAL_ROLE_NAMES:
            value = causal_roles[role]
            if not isinstance(value, dict) or set(value) != {"support", "assessment", "evidence_refs"}:
                raise ContractIssue("invalid_causal_role_fields")
            if not isinstance(value["support"], str) or value["support"] not in CAUSAL_SUPPORT_VALUES:
                raise ContractIssue("invalid_causal_role_support")
            if not _is_text(value["assessment"], MAX_CAUSAL_ASSESSMENT_BYTES):
                raise ContractIssue("invalid_causal_role_assessment")
            refs = value["evidence_refs"]
            if (
                not isinstance(refs, list)
                or len(refs) > MAX_CAUSAL_ROLE_EVIDENCE_REFS
                or (value["support"] != "NOT_ESTABLISHED" and not refs)
                or any(not _is_text(ref, 256) for ref in refs)
            ):
                raise ContractIssue("invalid_causal_role_evidence_refs")
            normalized_roles[role] = {**value, "evidence_refs": list(refs)}
        causal_roles = normalized_roles
    return {
        **payload,
        "contract_version": version,
        "source_contract_version": version,
        "causal_roles": causal_roles,
    }


def item_hash(item: Any) -> str:
    """Expose stable hash utility without retaining untrusted item text."""
    return _hash_item(item)
