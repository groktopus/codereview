"""Canonical completeness taxonomy, summary, and baseline comparison.

The review controller already records one coverage row per required
obligation.  That ledger explains *which* obligation is incomplete, but the
reason strings historically lived in several modules and several encodings
(``CONTEXT_GAP_UNRESOLVED``, ``ipc_envelope_truncated``,
``CHECK_RESULT_UNAVAILABLE``, provider error codes, ...).  This module gives
those strings one versioned meaning without renaming anything that is already
written to a result or a report.

Two derived artifacts are produced here:

``review-completeness-summary.v1``
    Machine-readable counts and reason distribution for a single run.

``review-completeness-baseline.v1``
    A comparison snapshot used by ``scripts/check_completeness.py`` to fail a
    change that makes required obligations less complete.

Completeness is not quality.  A complete review can still miss a defect and an
incomplete review is not evidence that the change is safe.  Missing and
partial obligations stay missing and partial; they are never promoted by the
summary, the report, or the gate.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

TAXONOMY_VERSION = "review-completeness-taxonomy.v1"
SUMMARY_SCHEMA = "review-completeness-summary.v1"
BASELINE_SCHEMA = "review-completeness-baseline.v1"
TAXONOMY_DOC = "docs/REVIEW-COMPLETENESS.md"

COMPLETE = "COMPLETE"
PARTIAL = "PARTIAL"
NOT_STARTED = "NOT_STARTED"
UNKNOWN_STATE = "UNKNOWN"

_STATES = (COMPLETE, PARTIAL, NOT_STARTED, UNKNOWN_STATE)

# Canonical reason definitions.  ``code`` is the stable machine value; the
# descriptions are the human contract.  ``legacy_codes`` contains every
# existing string this layer knows how to translate.  New strings that are not
# listed here remain visible as the passed-through ``reported_reason_code`` and
# are classified as ``UNCLASSIFIED_REASON`` so taxonomy drift is measurable
# instead of silent.
REASON_TAXONOMY: tuple[dict[str, Any], ...] = (
    {
        "code": "CONTEXT_EVIDENCE_MISSING",
        "description": "Required repository context could not be retrieved because the target was absent, unallowlisted, unbound, or otherwise unavailable.",
        "legacy_codes": (
            "context_target_not_in_trusted_manifest",
            "symbol_lookup_not_in_allowlist_contract",
            "target_unit_not_in_snapshot",
            "target_path_invalid",
            "target_path_not_allowlisted",
            "source_not_bound_by_exact_trusted_policy_path",
            "evidence_not_validated_as_trusted_policy",
            "source_inventory_incomplete",
            "source_content_unavailable",
            "validated_source_changed",
            "heading_occurrence_not_found",
            "binary_context_not_retrieved",
            "context_target_source_identity_mismatch",
            "retrieval_evidence_encoding_invalid",
            "required_context_missing",
            "REQUIRED_CONTEXT_MISSING",
            "UNIT_OUT_OF_SCOPE",
        ),
    },
    {
        "code": "CONTEXT_EVIDENCE_TRUNCATED",
        "description": "Required context was cut short by an input, output, retrieval, or IPC envelope limit, so the obligation was assessed without all of the requested evidence.",
        "legacy_codes": (
            "ipc_envelope_truncated",
            "retrieval_metadata_exceeds_ipc_limit",
            "OUTPUT_BYTE_LIMIT_EXCEEDED",
            "OUTPUT_BYTE_BUDGET_EXHAUSTED",
            "INPUT_BYTE_LIMIT_EXCEEDED",
            "REQUIRED_CONTEXT_OMITTED_BY_INPUT_LIMIT",
            "UNIT_REQUIRED_CONTEXT_EXCEEDS_INPUT_LIMIT",
            "UNIT_EVIDENCE_EXCEEDS_INPUT_LIMIT",
            "CONTEXT_RETRIEVAL_BYTE_LIMIT_EXCEEDED",
            "section_byte_limit_exceeded",
            "source_byte_limit_exceeded",
            "diff_truncated",
            "IPC_OUTPUT_LIMIT_EXCEEDED",
        ),
    },
    {
        "code": "CONTEXT_GAP_UNRESOLVED",
        "description": "A required evidence or follow-up gap linked to the obligation remained unresolved.",
        "legacy_codes": ("CONTEXT_GAP_UNRESOLVED",),
    },
    {
        "code": "CONTEXT_NOT_COVERED",
        "description": "A required-context obligation did not receive a covering static-review note.",
        "legacy_codes": ("REQUIRED_CONTEXT_NOT_COVERED",),
    },
    {
        "code": "CHECK_EVIDENCE_UNAVAILABLE",
        "description": "A required project check result could not be observed from bound, complete evidence.",
        "legacy_codes": (
            "CHECK_RESULT_UNAVAILABLE",
            "CHECK_ADAPTER_UNAVAILABLE",
            "github_check_name_not_configured",
            "app_identity_not_configured",
            "check_run_listing_incomplete",
            "check_run_missing_or_ambiguous",
            "check_run_identity_or_status_invalid",
            "check_run_not_complete_or_conclusion_unknown",
        ),
    },
    {
        "code": "CHECK_EVIDENCE_INVALID",
        "description": "A project check result was observed but its evidence was unbound, mismatched, or structurally invalid.",
        "legacy_codes": ("CHECK_RESULT_EVIDENCE_INVALID",),
    },
    {
        "code": "SPECIALIST_COVERAGE_PARTIAL",
        "description": "The specialist reported valid static-review coverage for only part of the changed unit scope.",
        "legacy_codes": ("PARTIAL_REVIEW_COVERAGE",),
    },
    {
        "code": "COVERAGE_NOTE_MISSING",
        "description": "The required coverage-note contract was absent from the specialist output.",
        "legacy_codes": ("COVERAGE_NOTE_MISSING",),
    },
    {
        "code": "COVERAGE_NOTE_INVALID",
        "description": "Coverage notes were present but their evidence references or states violated the contract.",
        "legacy_codes": ("COVERAGE_NOTE_EVIDENCE_INVALID",),
    },
    {
        "code": "REQUIRED_OUTPUT_QUARANTINED",
        "description": "Output needed for the obligation was quarantined as invalid or unsafe to use.",
        "legacy_codes": ("REQUIRED_OUTPUT_QUARANTINED",),
    },
    {
        "code": "PROVIDER_UNAVAILABLE",
        "description": "No configured provider was available to perform the required obligation.",
        "legacy_codes": ("PROVIDER_UNAVAILABLE", "NOT_SUPPORTED", "NOT_CONFIGURED"),
    },
    {
        "code": "BUDGET_EXHAUSTED",
        "description": "A bounded budget prevented the required obligation from running or completing.",
        "legacy_codes": (
            "RUN_CONTEXT_BUDGET_EXHAUSTED",
            "PROVIDER_CALL_BUDGET_EXHAUSTED",
            "CONTEXT_BYTE_BUDGET_EXHAUSTED",
            "CONTEXT_RETRIEVAL_BUDGET_EXHAUSTED",
            "FOLLOWUP_TASK_BUDGET_EXHAUSTED",
            "MONETARY_BUDGET_EXHAUSTED",
            "MONETARY_BOUND_UNAVAILABLE",
            "REQUIRED_CLAIM_ASSESSMENT_CAP_RESERVED",
            "REQUIRED_CLAIM_ASSESSMENT_DEADLINE_RESERVED",
            "CLAIM_ASSESSMENT_BUDGET_UNAVAILABLE",
            "CLAIM_ASSESSMENT_CAP_EXHAUSTED",
            "context_budget_exhausted",
        ),
    },
    {
        "code": "DEADLINE_EXHAUSTED",
        "description": "The run or call deadline expired before the required obligation completed.",
        "legacy_codes": (
            "DEADLINE_EXHAUSTED",
            "DEADLINE_EXCEEDED",
        ),
    },
    {
        "code": "TASK_FAILED",
        "description": "A dispatch, worker, transport, or provider failure ended the required task without a usable result.",
        "legacy_codes": (
            "WORKER_START_FAILED",
            "WORKER_CANCELLED",
            "WORKER_EXITED_WITHOUT_RESULT",
            "INVALID_PROVIDER_RESULT",
            "INVALID_PROVIDER_ESTIMATE",
            "RESPONSE_SCHEMA_INVALID",
            "INTERRUPTED_UNKNOWN",
            "TIMED_OUT",
            "SHADOW_DISPATCH_UNCERTAIN",
            "PRIOR_SHADOW_ATTEMPT_UNSETTLED",
            "PRIOR_SHADOW_RESERVATION_EXISTS",
            "TRANSPORT_FAILURE",
            "HTTP_ERROR_RESPONSE",
            "request_exceeds_limit",
        ),
    },
    {
        "code": "CLAIM_RECONCILIATION_INCOMPLETE",
        "description": "A required typed claim assessment was unavailable, invalid, mismatched, or incomplete, so reconciliation could not complete.",
        "legacy_codes": (
            "PRIMARY_CANDIDATE_INVALID",
            "PRIMARY_ASSESSMENT_UNAVAILABLE",
            "CLAIM_ASSESSMENT_INCOMPLETE",
            "PRIMARY_ASSESSMENT_BINDING_MISMATCH",
            "CLAIM_ASSESSMENT_INVALID",
            "CLAIM_ASSESSMENT_DIMENSION_UNAVAILABLE",
            "RECONCILIATION_QUALIFIER_UNSATISFIED",
            "CLAIM_ASSESSMENT_DISAGREES",
        ),
    },
    {
        "code": "MISSING_RESULT",
        "description": "No result row was produced for the required obligation.",
        "legacy_codes": ("MISSING_RESULT", "MISSING"),
    },
    {
        "code": "MISSING_REASON",
        "description": "The obligation is incomplete but no reason code was recorded.",
        "legacy_codes": (),
    },
    {
        "code": "UNCLASSIFIED_REASON",
        "description": "The obligation is incomplete and the reported reason is not yet in this taxonomy version. The original string is preserved unchanged.",
        "legacy_codes": (),
    },
)

# Reasons that belong to a successful/complete outcome.  They are deliberately
# not part of the incomplete-reason distribution.
COMPLETE_REASON_CODES = frozenset(
    {
        "VALID_RESULT",
        "CLAIM_ASSESSMENT_AGREES",
    }
)

_DEFINITION_BY_CODE = {entry["code"]: entry for entry in REASON_TAXONOMY}
_LEGACY_TO_CANONICAL: dict[str, str] = {}
for _entry in REASON_TAXONOMY:
    for _legacy in _entry["legacy_codes"]:
        if _legacy in _LEGACY_TO_CANONICAL and _LEGACY_TO_CANONICAL[_legacy] != _entry["code"]:
            raise RuntimeError(f"duplicate taxonomy mapping for {_legacy!r}")
        _LEGACY_TO_CANONICAL[_legacy] = _entry["code"]

PROVIDER_CODE_MAP: dict[str, str] = {
    # PROVIDER_UNAVAILABLE
    "credential_unavailable": "PROVIDER_UNAVAILABLE",
    "provider_call_failed": "PROVIDER_UNAVAILABLE",
    "provider_config_invalid_json": "PROVIDER_UNAVAILABLE",
    "provider_config_unavailable": "PROVIDER_UNAVAILABLE",
    # BUDGET_EXHAUSTED
    "candidate_text_exceeds_limit": "BUDGET_EXHAUSTED",
    "invalid_item_limit": "BUDGET_EXHAUSTED",
    "invalid_limits": "BUDGET_EXHAUSTED",
    "invalid_max_cost_microunits_per_call": "BUDGET_EXHAUSTED",
    "invalid_price_configuration": "BUDGET_EXHAUSTED",
    "invalid_transport_limit": "BUDGET_EXHAUSTED",
    "output_item_limit_exceeded": "BUDGET_EXHAUSTED",
    "provider_config_exceeds_limit": "BUDGET_EXHAUSTED",
    "report_note_limit_exceeded": "BUDGET_EXHAUSTED",
    "request_exceeds_limit": "BUDGET_EXHAUSTED",
    "response_exceeds_limit": "BUDGET_EXHAUSTED",
    # DEADLINE_EXHAUSTED
    "provider_deadline_exceeded": "DEADLINE_EXHAUSTED",
    # TASK_FAILED
    "assessment_references_unknown_evidence": "TASK_FAILED",
    "candidate_references_unknown_evidence": "TASK_FAILED",
    "candidate_references_unknown_scope": "TASK_FAILED",
    "capture_receipt_invalid": "TASK_FAILED",
    "capture_sink_failed": "TASK_FAILED",
    "capture_sink_required": "TASK_FAILED",
    "configured_model_mismatch": "TASK_FAILED",
    "context_followup_requires_specialist_input_v2": "TASK_FAILED",
    "context_gap_references_unknown_evidence": "TASK_FAILED",
    "coverage_note_evidence_required": "TASK_FAILED",
    "coverage_references_unknown_evidence": "TASK_FAILED",
    "coverage_references_unknown_scope": "TASK_FAILED",
    "endpoint_must_not_contain_credentials_or_query": "TASK_FAILED",
    "endpoint_required": "TASK_FAILED",
    "invalid_assessment": "TASK_FAILED",
    "invalid_assessment_array": "TASK_FAILED",
    "invalid_assessment_fields": "TASK_FAILED",
    "invalid_assessment_outcome": "TASK_FAILED",
    "invalid_assessment_request": "TASK_FAILED",
    "invalid_assessment_semantics": "TASK_FAILED",
    "invalid_assessment_summary": "TASK_FAILED",
    "invalid_assessment_support": "TASK_FAILED",
    "invalid_candidate_evidence_refs": "TASK_FAILED",
    "invalid_candidate_introducedness": "TASK_FAILED",
    "invalid_candidate_line": "TASK_FAILED",
    "invalid_candidate_location": "TASK_FAILED",
    "invalid_candidate_reasoning_kind": "TASK_FAILED",
    "invalid_candidate_severity": "TASK_FAILED",
    "invalid_candidate_text": "TASK_FAILED",
    "invalid_candidate_unit_id": "TASK_FAILED",
    "invalid_causal_role_assessment": "TASK_FAILED",
    "invalid_causal_role_evidence_refs": "TASK_FAILED",
    "invalid_causal_role_fields": "TASK_FAILED",
    "invalid_causal_role_support": "TASK_FAILED",
    "invalid_causal_roles": "TASK_FAILED",
    "invalid_claim_candidate": "TASK_FAILED",
    "invalid_claim_evidence": "TASK_FAILED",
    "invalid_claim_identity": "TASK_FAILED",
    "invalid_claim_transport_config": "TASK_FAILED",
    "invalid_context_followup_binding": "TASK_FAILED",
    "invalid_context_followup_evidence_binding": "TASK_FAILED",
    "invalid_context_followup_identity": "TASK_FAILED",
    "invalid_context_followup_rationale": "TASK_FAILED",
    "invalid_context_followup_references": "TASK_FAILED",
    "invalid_context_followup_scope": "TASK_FAILED",
    "invalid_context_followup_target": "TASK_FAILED",
    "invalid_context_followup_version": "TASK_FAILED",
    "invalid_context_gap_fields": "TASK_FAILED",
    "invalid_context_gap_kind": "TASK_FAILED",
    "invalid_context_gap_lens": "TASK_FAILED",
    "invalid_context_gap_target": "TASK_FAILED",
    "invalid_context_gap_text": "TASK_FAILED",
    "invalid_context_target_manifest": "TASK_FAILED",
    "invalid_coverage_basis": "TASK_FAILED",
    "invalid_coverage_note_evidence_refs": "TASK_FAILED",
    "invalid_coverage_note_reason_code": "TASK_FAILED",
    "invalid_coverage_note_state": "TASK_FAILED",
    "invalid_coverage_note_unit_id": "TASK_FAILED",
    "invalid_credential_reference": "TASK_FAILED",
    "invalid_decision_config": "TASK_FAILED",
    "invalid_endpoint": "TASK_FAILED",
    "invalid_endpoint_path": "TASK_FAILED",
    "invalid_endpoint_reference": "TASK_FAILED",
    "invalid_model": "TASK_FAILED",
    "invalid_native_request": "TASK_FAILED",
    "invalid_primary_assessment": "TASK_FAILED",
    "invalid_reasoning_effort": "TASK_FAILED",
    "invalid_report_note_evidence_refs": "TASK_FAILED",
    "invalid_report_note_kind": "TASK_FAILED",
    "invalid_report_note_text": "TASK_FAILED",
    "invalid_report_note_unit_id": "TASK_FAILED",
    "invalid_request_input_contract": "TASK_FAILED",
    "invalid_response_format": "TASK_FAILED",
    "invalid_specialist_array": "TASK_FAILED",
    "invalid_specialist_fields": "TASK_FAILED",
    "invalid_specialist_input": "TASK_FAILED",
    "invalid_specialist_report": "TASK_FAILED",
    "invalid_token_limit_parameter": "TASK_FAILED",
    "invalid_unit_evidence_bindings": "TASK_FAILED",
    "literal_credentials_forbidden": "TASK_FAILED",
    "malformed_native_response": "TASK_FAILED",
    "malformed_provider_response": "TASK_FAILED",
    "model_identity_mismatch": "TASK_FAILED",
    "model_identity_missing": "TASK_FAILED",
    "model_output_incomplete": "TASK_FAILED",
    "provider_response_contains_credential": "TASK_FAILED",
    "question_and_text_required": "TASK_FAILED",
    "remote_http_forbidden": "TASK_FAILED",
    "report_note_references_unknown_evidence": "TASK_FAILED",
    "report_note_references_unknown_scope": "TASK_FAILED",
    "request_pin_invalid": "TASK_FAILED",
    "request_pin_mismatch": "TASK_FAILED",
    "request_serialization_invalid": "TASK_FAILED",
    "request_task_binding_mismatch": "TASK_FAILED",
    "request_task_binding_missing": "TASK_FAILED",
    "response_read_failed": "TASK_FAILED",
    "supported_claim_requires_evidence": "TASK_FAILED",
    "unsupported_assessment_contract": "TASK_FAILED",
    "unsupported_claim_transport_config": "TASK_FAILED",
    "unsupported_decision_provider": "TASK_FAILED",
    "unsupported_native_endpoint": "TASK_FAILED",
    "unsupported_native_operation": "TASK_FAILED",
    "unsupported_primitive": "TASK_FAILED",
    "unsupported_provider_kind": "TASK_FAILED",
    "unsupported_specialist_contract": "TASK_FAILED",
    "unsupported_task_kind": "TASK_FAILED",
}

PROVIDER_CODE_MAP.update(
    {
        "invalid_candidate_fields": "TASK_FAILED",
        "invalid_context_followup": "TASK_FAILED",
        "invalid_coverage_note_fields": "TASK_FAILED",
        "invalid_report_note_fields": "TASK_FAILED",
        "invalid_context_gap_related_candidate_ids": "TASK_FAILED",
        "invalid_context_gap_related_evidence_ids": "TASK_FAILED",
        "invalid_provider_config": "TASK_FAILED",
        "invalid_timeout": "TASK_FAILED",
        "invalid_deadline": "TASK_FAILED",
        "invalid_request": "TASK_FAILED",
        "invalid_criteria": "TASK_FAILED",
        "invalid_max_response_bytes": "TASK_FAILED",
        "invalid_max_request_bytes": "TASK_FAILED",
        "invalid_max_output_tokens": "TASK_FAILED",
        "invalid_max_output_items": "TASK_FAILED",
        "invalid_max_item_text_bytes": "TASK_FAILED",
        "invalid_max_output_bytes_per_task": "TASK_FAILED",
        "invalid_max_input_bytes_per_task": "TASK_FAILED",
    }
)
PROVIDER_CODE_MAP.pop("request_exceeds_limit", None)

_PROVIDER_DYNAMIC_RULES: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"^http_status_[0-9]{3}$"), "PROVIDER_UNAVAILABLE"),
    (re.compile(r"^[a-z0-9_]+_exceeds_limit$"), "BUDGET_EXHAUSTED"),
)

_CANONICAL_CODES = frozenset(_DEFINITION_BY_CODE)


def taxonomy_document() -> dict[str, Any]:
    """Return the versioned taxonomy as a JSON-serializable document."""

    return {
        "version": TAXONOMY_VERSION,
        "documentation": TAXONOMY_DOC,
        "complete_reason_codes": sorted(COMPLETE_REASON_CODES),
        "provider_codes": dict(sorted(PROVIDER_CODE_MAP.items())),
        "provider_dynamic_rules": [
            {"pattern": pattern.pattern, "canonical_code": canonical} for pattern, canonical in _PROVIDER_DYNAMIC_RULES
        ],
        "reasons": [
            {
                "code": entry["code"],
                "description": entry["description"],
                "legacy_codes": list(entry["legacy_codes"]),
            }
            for entry in REASON_TAXONOMY
        ],
    }


def classify_reason(reason_code: Any) -> str:
    """Map one existing reason string to a stable canonical code.

    Complete-outcome reasons are returned unchanged as their own code so a
    caller can distinguish them from the incomplete taxonomy.  A missing code
    becomes ``MISSING_REASON``; an unknown code becomes
    ``UNCLASSIFIED_REASON``.  No input is ever modified.
    """

    if reason_code is None:
        return "MISSING_REASON"
    if not isinstance(reason_code, str) or not reason_code.strip():
        return "MISSING_REASON"
    if reason_code in COMPLETE_REASON_CODES:
        return reason_code
    if reason_code in _CANONICAL_CODES:
        return reason_code
    mapped = _LEGACY_TO_CANONICAL.get(reason_code)
    if mapped is not None:
        return mapped
    # Retrieval and provider codes are sometimes lower case; the documented
    # mapping is exact, so only fall back to a case-insensitive lookup when the
    # legacy table has a unique match.
    folded = reason_code.casefold()
    matches = {canonical for legacy, canonical in _LEGACY_TO_CANONICAL.items() if legacy.casefold() == folded}
    if len(matches) == 1:
        return matches.pop()
    return _classify_family(reason_code)


def _classify_family(reason_code: str) -> str:
    """Classify a provider/contract code from the versioned exact map.

    Codes that are not in the map or the two documented dynamic families stay
    ``UNCLASSIFIED_REASON`` so new strings remain visible as taxonomy drift.
    """

    mapped = PROVIDER_CODE_MAP.get(reason_code)
    if mapped is not None:
        return mapped
    for pattern, canonical in _PROVIDER_DYNAMIC_RULES:
        if pattern.fullmatch(reason_code):
            return canonical
    return "UNCLASSIFIED_REASON"


def _coverage_state(row: Mapping[str, Any]) -> str:
    state = row.get("state")
    return state if state in _STATES else UNKNOWN_STATE


def _required(row: Mapping[str, Any]) -> bool:
    return row.get("required", True) is not False


def _share(numerator: int, denominator: int) -> float | None:
    if denominator <= 0:
        return None
    return round(numerator / denominator, 6)


def build_completeness_summary(
    coverage_rows: Iterable[Mapping[str, Any]],
    not_applicable: Iterable[Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build the machine-readable completeness summary from a coverage ledger.

    ``required_total`` is the denominator for completion.  Non-required ledger
    rows and ``not_applicable`` obligations are reported separately and never
    inflate completion.  Zero required obligations is an explicit, valid case
    with ``None`` ratios rather than an implicit 100%.
    """

    rows = [row for row in coverage_rows if isinstance(row, Mapping)]
    ledger_total = len(rows)
    required_rows = [row for row in rows if _required(row)]
    counts = {state: 0 for state in _STATES}
    for row in required_rows:
        counts[_coverage_state(row)] += 1

    required_total = len(required_rows)
    incomplete_total = counts[PARTIAL] + counts[NOT_STARTED] + counts[UNKNOWN_STATE]

    reasons: dict[str, dict[str, Any]] = {}
    for row in required_rows:
        state = _coverage_state(row)
        if state == COMPLETE:
            continue
        reported = row.get("reason_code")
        canonical = classify_reason(reported)
        bucket = reasons.setdefault(
            canonical,
            {
                "canonical_code": canonical,
                "description": _DEFINITION_BY_CODE.get(canonical, {}).get("description", ""),
                "obligations": 0,
                "states": {state_name: 0 for state_name in _STATES},
                "legacy_codes": {},
            },
        )
        bucket["obligations"] += 1
        bucket["states"][state] += 1
        reported_key = reported if isinstance(reported, str) and reported else "<missing>"
        bucket["legacy_codes"][reported_key] = bucket["legacy_codes"].get(reported_key, 0) + 1

    distribution: list[dict[str, Any]] = []
    for bucket in reasons.values():
        distribution.append(
            {
                "canonical_code": bucket["canonical_code"],
                "description": bucket["description"],
                "obligations": bucket["obligations"],
                "share_of_incomplete": _share(bucket["obligations"], incomplete_total),
                "share_of_required": _share(bucket["obligations"], required_total),
                "states": dict(bucket["states"]),
                "legacy_codes": [
                    {"code": code, "obligations": count} for code, count in sorted(bucket["legacy_codes"].items())
                ],
            }
        )
    distribution.sort(key=lambda item: (-item["obligations"], item["canonical_code"]))

    not_applicable_rows = [row for row in (not_applicable or ()) if isinstance(row, Mapping)]
    return {
        "schema": SUMMARY_SCHEMA,
        "taxonomy_version": TAXONOMY_VERSION,
        "taxonomy_document": TAXONOMY_DOC,
        "ledger_total": ledger_total,
        "required_total": required_total,
        "complete": counts[COMPLETE],
        "partial": counts[PARTIAL],
        "not_started": counts[NOT_STARTED],
        "unknown_state": counts[UNKNOWN_STATE],
        "not_applicable": len(not_applicable_rows),
        "non_required": ledger_total - required_total,
        "incomplete_total": incomplete_total,
        "zero_obligations": required_total == 0,
        "complete_ratio": _share(counts[COMPLETE], required_total),
        "resolved_ratio": _share(counts[COMPLETE] + counts[PARTIAL], required_total),
        "reason_distribution": distribution,
        "reason_distribution_denominator": incomplete_total,
        "unclassified_obligations": sum(
            item["obligations"] for item in distribution if item["canonical_code"] == "UNCLASSIFIED_REASON"
        ),
    }


def summary_from_result(result: Mapping[str, Any]) -> dict[str, Any]:
    """Recompute a summary from the coverage ledger of a stored result.

    The gate and the report both recompute from the ledger so a stale or
    hand-edited summary cannot hide a regression.  When a stored summary is
    present the caller can compare it with :func:`summary_is_consistent`.
    """

    coverage = result.get("coverage_ledger")
    if not isinstance(coverage, list):
        raise ValueError("result must contain a coverage_ledger array")
    if any(not isinstance(row, Mapping) for row in coverage):
        raise ValueError("every coverage_ledger row must be an object")
    not_applicable = result.get("not_applicable")
    return build_completeness_summary(
        coverage,
        not_applicable if isinstance(not_applicable, list) else [],
    )


def summary_is_consistent(result: Mapping[str, Any], summary: Mapping[str, Any]) -> bool:
    """Return whether an embedded summary agrees with the ledger-derived one."""

    stored = result.get("completeness_summary")
    if not isinstance(stored, Mapping):
        return True
    keys = (
        "schema",
        "taxonomy_version",
        "required_total",
        "complete",
        "partial",
        "not_started",
        "unknown_state",
        "not_applicable",
        "incomplete_total",
        "reason_distribution_denominator",
        "unclassified_obligations",
        "complete_ratio",
        "resolved_ratio",
        "zero_obligations",
        "ledger_total",
        "non_required",
    )
    if not all(stored.get(key) == summary.get(key) for key in keys):
        return False
    stored_distribution = stored.get("reason_distribution")
    if not isinstance(stored_distribution, list):
        return False
    if any(not isinstance(item, Mapping) for item in stored_distribution):
        return False
    normalized = [(item.get("canonical_code"), item.get("obligations")) for item in stored_distribution]
    expected = [
        (item.get("canonical_code"), item.get("obligations")) for item in summary.get("reason_distribution", [])
    ]
    return normalized == expected


def _case_id(result: Mapping[str, Any], fallback: str | None = None) -> str:
    for key in ("case_id", "snapshot_id", "run_id"):
        value = result.get(key)
        if isinstance(value, str) and value:
            return value
    snapshot = result.get("snapshot")
    if isinstance(snapshot, Mapping):
        value = snapshot.get("snapshot_id")
        if isinstance(value, str) and value:
            return value
    return fallback or "unnamed-result"


def build_baseline(
    results: Sequence[Mapping[str, Any]],
    *,
    corpus: Mapping[str, Any] | None = None,
    thresholds: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a compact baseline from stored run results.

    Per-obligation states are retained so the gate can detect a
    known-complete obligation that later becomes partial or truncated, even if
    aggregate counts happen to stay flat.
    """

    cases: dict[str, Any] = {}
    for index, result in enumerate(results):
        summary = summary_from_result(result)
        case_id = _case_id(result, f"case-{index}")
        if case_id in cases:
            raise ValueError(f"duplicate case id in baseline: {case_id}")
        obligations = {
            str(row.get("obligation_id", f"obligation-{position}")): _coverage_state(row)
            for position, row in enumerate(result.get("coverage_ledger", []))
            if isinstance(row, Mapping) and _required(row)
        }
        cases[case_id] = {
            "required_total": summary["required_total"],
            "complete": summary["complete"],
            "partial": summary["partial"],
            "not_started": summary["not_started"],
            "unknown_state": summary["unknown_state"],
            "not_applicable": summary["not_applicable"],
            "zero_obligations": summary["zero_obligations"],
            "complete_ratio": summary["complete_ratio"],
            "incomplete_total": summary["incomplete_total"],
            "unclassified_obligations": summary["unclassified_obligations"],
            "obligations": obligations,
            "reason_distribution": [
                {
                    "canonical_code": item["canonical_code"],
                    "obligations": item["obligations"],
                }
                for item in summary["reason_distribution"]
            ],
        }
    return {
        "schema": BASELINE_SCHEMA,
        "taxonomy_version": TAXONOMY_VERSION,
        "summary_schema": SUMMARY_SCHEMA,
        "taxonomy_document": TAXONOMY_DOC,
        "corpus": dict(corpus or {}),
        "thresholds": {
            "min_completion_ratio": 0.0,
            "max_completion_drop": 0.0,
            "max_unclassified_increase": 0,
            **(dict(thresholds or {})),
        },
        "cases": cases,
    }


def _threshold(baseline: Mapping[str, Any], key: str, override: Any) -> Any:
    if override is not None:
        return override
    thresholds = baseline.get("thresholds")
    if isinstance(thresholds, Mapping):
        return thresholds.get(key)
    return None


def compare_to_baseline(
    result: Mapping[str, Any],
    baseline: Mapping[str, Any],
    *,
    case_id: str | None = None,
    min_completion_ratio: float | None = None,
    max_completion_drop: float | None = None,
    max_unclassified_increase: int | None = None,
) -> dict[str, Any]:
    """Compare one result to a stored baseline and return a gate verdict.

    The comparison fails closed on:

    * a baseline obligation that was complete and is no longer complete
      (this is the explicit "known-complete case regressed to truncated"
      condition);
    * a completion-ratio drop larger than the owner-set threshold;
    * completion below an absolute owner-set floor;
    * an obligation present in the baseline that disappeared from the result;
    * an embedded summary that disagrees with the ledger; or
    * an increase in unclassified reasons beyond the owner-set threshold.
    """

    if baseline.get("schema") != BASELINE_SCHEMA:
        raise ValueError("baseline schema is not review-completeness-baseline.v1")
    if baseline.get("taxonomy_version") != TAXONOMY_VERSION:
        raise ValueError("baseline taxonomy version is not the current taxonomy")

    current = summary_from_result(result)
    resolved_case_id = case_id or _case_id(result)
    cases = baseline.get("cases")
    if not isinstance(cases, Mapping):
        raise ValueError("baseline must contain a cases object")
    baseline_case = cases.get(resolved_case_id)
    if not isinstance(baseline_case, Mapping):
        return {
            "status": "FAIL",
            "schema": "review-completeness-gate.v1",
            "case_id": resolved_case_id,
            "taxonomy_version": TAXONOMY_VERSION,
            "findings": [
                {
                    "code": "CASE_NOT_IN_BASELINE",
                    "message": f"case {resolved_case_id!r} is not present in the baseline",
                }
            ],
            "current": current,
            "baseline": None,
        }

    findings: list[dict[str, Any]] = []
    warnings: list[dict[str, Any]] = []

    if not summary_is_consistent(result, current):
        findings.append(
            {
                "code": "SUMMARY_INCONSISTENT",
                "message": "embedded completeness_summary disagrees with the coverage ledger",
            }
        )

    current_states = {
        row.get("obligation_id"): _coverage_state(row)
        for row in result.get("coverage_ledger", [])
        if isinstance(row, Mapping)
    }
    baseline_obligations = baseline_case.get("obligations")
    if isinstance(baseline_obligations, Mapping):
        for obligation, prior in baseline_obligations.items():
            if prior == "PARTIAL" and current_states.get(obligation) in {"NOT_STARTED", "UNKNOWN"}:
                findings.append(
                    {
                        "code": "PARTIAL_OBLIGATION_REGRESSION",
                        "message": (
                            f"obligation {obligation!r} regressed from PARTIAL to {current_states.get(obligation)!r}"
                        ),
                    }
                )

    baseline_ratio = baseline_case.get("complete_ratio")
    current_ratio = current["complete_ratio"]
    drop_limit = _threshold(baseline, "max_completion_drop", max_completion_drop)
    drop_limit = 0.0 if drop_limit is None else float(drop_limit)
    if baseline_ratio is None and current_ratio is None:
        ratio_drop = 0.0
    elif baseline_ratio is None:
        ratio_drop = None
        warnings.append(
            {
                "code": "BASELINE_WAS_ZERO_OBLIGATION",
                "message": "baseline had zero required obligations; the current result now has obligations",
            }
        )
    elif current_ratio is None:
        ratio_drop = float(baseline_ratio)
    else:
        ratio_drop = float(baseline_ratio) - float(current_ratio)
    if ratio_drop is not None and ratio_drop > drop_limit:
        findings.append(
            {
                "code": "COMPLETION_RATIO_REGRESSION",
                "message": (
                    f"complete ratio dropped from {baseline_ratio} to {current_ratio} "
                    f"(drop {ratio_drop:.6f} > allowed {drop_limit:.6f})"
                ),
            }
        )

    floor = _threshold(baseline, "min_completion_ratio", min_completion_ratio)
    if floor is not None and current_ratio is not None and float(current_ratio) < float(floor):
        findings.append(
            {
                "code": "BELOW_MIN_COMPLETION_RATIO",
                "message": f"complete ratio {current_ratio} is below the owner-set floor {float(floor):.6f}",
            }
        )

    baseline_obligations = baseline_case.get("obligations")
    current_obligations = {
        str(row.get("obligation_id", f"obligation-{position}")): _coverage_state(row)
        for position, row in enumerate(result.get("coverage_ledger", []))
        if isinstance(row, Mapping) and _required(row)
    }
    if isinstance(baseline_obligations, Mapping):
        for obligation_id, previous_state in baseline_obligations.items():
            if obligation_id not in current_obligations:
                findings.append(
                    {
                        "code": "OBLIGATION_MISSING",
                        "message": f"required obligation {obligation_id!r} from the baseline is absent",
                    }
                )
                continue
            if previous_state == COMPLETE and current_obligations[obligation_id] != COMPLETE:
                row = next(
                    (
                        candidate
                        for candidate in result.get("coverage_ledger", [])
                        if isinstance(candidate, Mapping) and str(candidate.get("obligation_id", "")) == obligation_id
                    ),
                    {},
                )
                reason = row.get("reason_code")
                findings.append(
                    {
                        "code": "KNOWN_COMPLETE_REGRESSION",
                        "message": (
                            f"obligation {obligation_id!r} was COMPLETE and is now "
                            f"{current_obligations[obligation_id]} ({reason!r})"
                        ),
                    }
                )

    unclassified_limit = _threshold(baseline, "max_unclassified_increase", max_unclassified_increase)
    unclassified_limit = 0 if unclassified_limit is None else int(unclassified_limit)
    increase = current["unclassified_obligations"] - int(baseline_case.get("unclassified_obligations", 0))
    if increase > unclassified_limit:
        findings.append(
            {
                "code": "UNCLASSIFIED_REASON_INCREASE",
                "message": (
                    f"unclassified incomplete obligations increased by {increase} (allowed {unclassified_limit})"
                ),
            }
        )

    return {
        "status": "FAIL" if findings else "PASS",
        "schema": "review-completeness-gate.v1",
        "case_id": resolved_case_id,
        "taxonomy_version": TAXONOMY_VERSION,
        "thresholds": {
            "min_completion_ratio": floor,
            "max_completion_drop": drop_limit,
            "max_unclassified_increase": unclassified_limit,
        },
        "findings": findings,
        "warnings": warnings,
        "current": current,
        "baseline": {
            "required_total": baseline_case.get("required_total"),
            "complete": baseline_case.get("complete"),
            "partial": baseline_case.get("partial"),
            "not_started": baseline_case.get("not_started"),
            "unknown_state": baseline_case.get("unknown_state"),
            "not_applicable": baseline_case.get("not_applicable"),
            "complete_ratio": baseline_ratio,
            "incomplete_total": baseline_case.get("incomplete_total"),
            "reason_distribution": baseline_case.get("reason_distribution"),
        },
    }


def render_summary_text(summary: Mapping[str, Any]) -> str:
    """Render the short human summary used by the CLI and CI logs."""

    required = summary.get("required_total", 0)
    taxonomy = summary.get("taxonomy_version", TAXONOMY_VERSION)
    if summary.get("zero_obligations"):
        return (
            f"Completeness ({taxonomy}): zero required obligations "
            f"(zero-obligation run; not_applicable={summary.get('not_applicable', 0)})."
        )
    ratio = summary.get("complete_ratio")
    percent = f"{float(ratio) * 100:.1f}%" if isinstance(ratio, (int, float)) else "UNKNOWN"
    reasons = (
        "; ".join(
            f"{item['canonical_code']} {item['obligations']}" for item in summary.get("reason_distribution", [])[:8]
        )
        or "none"
    )
    return (
        f"Completeness ({taxonomy}): {summary.get('complete')}/{required} required complete "
        f"({percent}); {summary.get('partial')} partial, {summary.get('not_started')} not started, "
        f"{summary.get('unknown_state')} unknown; {summary.get('not_applicable')} not applicable; "
        f"incomplete reasons ({summary.get('reason_distribution_denominator')}/{required} required): {reasons}."
    )


def _read_json(path: str) -> Any:
    raw = Path(path).read_bytes()
    return json.loads(raw)


def _collect_results(args: argparse.Namespace) -> list[dict[str, Any]]:
    paths: list[str] = []
    if args.result:
        paths.extend(args.result)
    if args.results_dir:
        directory = Path(args.results_dir)
        if not directory.is_dir():
            raise ValueError(f"results directory does not exist: {directory}")
        paths.extend(sorted(str(path) for path in directory.glob("*.json")))
    if args.results_manifest:
        manifest = _read_json(args.results_manifest)
        entries = manifest.get("results") if isinstance(manifest, dict) else None
        if not isinstance(entries, list) or any(not isinstance(item, str) for item in entries):
            raise ValueError("results manifest must contain a results array of paths")
        base = Path(args.results_manifest).resolve().parent
        paths.extend(str((base / item).resolve()) if not Path(item).is_absolute() else item for item in entries)
    results: list[dict[str, Any]] = []
    for path in paths:
        value = _read_json(path)
        if not isinstance(value, dict):
            raise ValueError(f"result must be a JSON object: {path}")
        results.append(value)
    return results


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="check_completeness.py",
        description="Emit or gate the review-completeness summary of stored run results.",
    )
    parser.add_argument("--result", action="append", help="stored review result JSON (repeatable)")
    parser.add_argument("--results-dir", help="directory of stored review result JSON files")
    parser.add_argument("--results-manifest", help="JSON object with a relative 'results' path array")
    parser.add_argument("--baseline", help="baseline JSON produced by --write-baseline")
    parser.add_argument(
        "--summary-only",
        action="store_true",
        help="emit the canonical summary for the supplied results without a baseline comparison",
    )
    parser.add_argument("--write-baseline", metavar="PATH", help="write a new baseline from the supplied results")
    parser.add_argument("--case-id", help="baseline case id override for a single result")
    parser.add_argument("--corpus-name", default="unspecified", help="baseline corpus name")
    parser.add_argument("--corpus-provenance", default="", help="baseline corpus provenance note")
    parser.add_argument("--min-completion-ratio", type=float, default=None, help="override absolute completion floor")
    parser.add_argument("--max-completion-drop", type=float, default=None, help="override allowed ratio drop")
    parser.add_argument(
        "--max-unclassified-increase",
        type=int,
        default=None,
        help="override allowed increase in unclassified incomplete obligations",
    )
    parser.add_argument("--json", action="store_true", help="emit the full JSON verdict")
    parser.add_argument("--quiet", action="store_true", help="only emit failures")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
    except SystemExit as exc:
        return int(exc.code or 0)
    try:
        results = _collect_results(args)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"completeness gate: cannot read input: {exc}", file=sys.stderr)
        return 2
    if not results:
        print("completeness gate: no result inputs supplied", file=sys.stderr)
        return 2

    if args.summary_only:
        summaries: list[dict[str, Any]] = []
        try:
            for result in results:
                summaries.append(
                    {
                        "case_id": _case_id(result),
                        "completeness_summary": summary_from_result(result),
                    }
                )
        except (ValueError, KeyError, TypeError) as exc:
            print(f"completeness gate: cannot summarize result: {exc}", file=sys.stderr)
            return 2
        if args.json:
            print(
                json.dumps(
                    {
                        "status": "SUMMARY",
                        "schema": "review-completeness-summary-run.v1",
                        "taxonomy_version": TAXONOMY_VERSION,
                        "results": summaries,
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
        elif not args.quiet:
            for item in summaries:
                print(f"{item['case_id']}: {render_summary_text(item['completeness_summary'])}")
        return 0

    if args.write_baseline:
        try:
            baseline = build_baseline(
                results,
                corpus={"name": args.corpus_name, "provenance": args.corpus_provenance},
                thresholds={
                    "min_completion_ratio": args.min_completion_ratio if args.min_completion_ratio is not None else 0.0,
                    "max_completion_drop": args.max_completion_drop if args.max_completion_drop is not None else 0.0,
                    "max_unclassified_increase": args.max_unclassified_increase
                    if args.max_unclassified_increase is not None
                    else 0,
                },
            )
        except ValueError as exc:
            print(f"completeness gate: cannot build baseline: {exc}", file=sys.stderr)
            return 2
        Path(args.write_baseline).parent.mkdir(parents=True, exist_ok=True)
        Path(args.write_baseline).write_text(json.dumps(baseline, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        if args.json:
            print(
                json.dumps(
                    {"status": "BASELINE_WRITTEN", "path": args.write_baseline, "cases": sorted(baseline["cases"])}
                )
            )
        elif not args.quiet:
            print(f"completeness baseline written: {args.write_baseline} ({len(baseline['cases'])} case(s))")
        return 0

    if not args.baseline:
        print("completeness gate: --baseline is required unless --write-baseline is used", file=sys.stderr)
        return 2
    try:
        baseline = _read_json(args.baseline)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"completeness gate: cannot read baseline: {exc}", file=sys.stderr)
        return 2
    if not isinstance(baseline, dict):
        print("completeness gate: baseline must be a JSON object", file=sys.stderr)
        return 2

    verdicts: list[dict[str, Any]] = []
    for index, result in enumerate(results):
        try:
            verdict = compare_to_baseline(
                result,
                baseline,
                case_id=args.case_id if len(results) == 1 else None,
                min_completion_ratio=args.min_completion_ratio,
                max_completion_drop=args.max_completion_drop,
                max_unclassified_increase=args.max_unclassified_increase,
            )
        except (ValueError, KeyError, TypeError) as exc:
            print(f"completeness gate: cannot compare result {index}: {exc}", file=sys.stderr)
            return 2
        verdicts.append(verdict)

    failed = [verdict for verdict in verdicts if verdict["status"] != "PASS"]
    if args.json:
        print(
            json.dumps(
                {
                    "status": "FAIL" if failed else "PASS",
                    "schema": "review-completeness-gate-run.v1",
                    "baseline": args.baseline,
                    "taxonomy_version": TAXONOMY_VERSION,
                    "verdicts": verdicts,
                },
                indent=2,
                sort_keys=True,
            )
        )
    elif not args.quiet:
        for verdict in verdicts:
            print(f"[{verdict['status']}] {verdict['case_id']}: {render_summary_text(verdict['current'])}")
            for finding in verdict["findings"]:
                print(f"  - {finding['code']}: {finding['message']}")
            for warning in verdict.get("warnings", []):
                print(f"  - WARNING {warning['code']}: {warning['message']}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
