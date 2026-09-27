"""Bounded deterministic execution, reconciliation, ledgering, and reporting."""

from __future__ import annotations

import fnmatch
import hashlib
import json
import math
import os
import pickle
import re
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import contracts as review_contracts
from .budget import (
    BudgetExhausted,
    BudgetLedger,
    IsolatedCallError,
    IsolatedInvocation,
    isolated_call,
    wait_for_any,
)
from .claim_assessment import CLAIM_ASSESSMENT_ERROR_CODES, ClaimAssessmentError
from .planner import allow_empty_approve
from .reconcile import consolidate_findings, stable_candidate_id, validate_location
from .report import render_report as _render_report


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _hash(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


_REQUIRED_CONTEXT_NOTE_CODES = (
    "NOTE_NOT_OBJECT",
    "STATE_NOT_COVERED",
    "BASIS_NOT_STATIC_REVIEW",
    "UNIT_OUT_OF_SCOPE",
    "NO_RETRIEVED_EVIDENCE_REFERENCE",
    "REFERENCE_NOT_IN_TASK_INPUT",
    "MATCH",
    "NO_COVERAGE_NOTES",
    "UNKNOWN",
)
_REQUIRED_OUTPUT_QUARANTINE_KINDS = (
    "finding_candidates",
    "context_gap_proposals",
    "coverage_notes",
    "other_required_kind",
)


def _required_context_note_match(
    note: Any,
    *,
    scope_unit_ids: set[str],
    required_evidence_ids: set[str],
    task_input_evidence_ids: set[str],
    predicate_order: str,
) -> tuple[bool, str]:
    """Evaluate and classify one note in its caller's existing predicate order."""
    if not isinstance(note, dict):
        return False, "NOTE_NOT_OBJECT"
    checks = (
        (("UNIT_OUT_OF_SCOPE", lambda: note.get("unit_id") in scope_unit_ids),
         ("STATE_NOT_COVERED", lambda: note.get("state") == "COVERED"),
         ("BASIS_NOT_STATIC_REVIEW", lambda: note.get("coverage_basis") == "STATIC_REVIEW"))
        if predicate_order == "followup_resolution"
        else (("STATE_NOT_COVERED", lambda: note.get("state") == "COVERED"),
              ("BASIS_NOT_STATIC_REVIEW", lambda: note.get("coverage_basis") == "STATIC_REVIEW"),
              ("UNIT_OUT_OF_SCOPE", lambda: note.get("unit_id") in scope_unit_ids))
    )
    if predicate_order not in {"followup_resolution", "final_coverage"}:
        raise ValueError("required_context_predicate_order_invalid")
    for code, passes in checks:
        if not passes():
            return False, code
    refs = set(note.get("evidence_refs", []))
    if not refs.intersection(required_evidence_ids):
        return False, "NO_RETRIEVED_EVIDENCE_REFERENCE"
    if not refs.issubset(task_input_evidence_ids):
        return False, "REFERENCE_NOT_IN_TASK_INPUT"
    return True, "MATCH"


def _coverage_note_observation(
    notes: Any,
    *,
    notes_present: bool,
    scope_unit_ids: Any,
    required_evidence_ids: Any,
    task_input_evidence_ids: Any,
    predicate_order: str = "final_coverage",
) -> tuple[bool, dict[str, Any]]:
    """Return the existing any-match decision and a bounded typed explanation."""
    observable = (
        notes_present
        and isinstance(notes, list)
        and len(notes) <= review_contracts.MAX_ITEMS
        and isinstance(scope_unit_ids, (list, set, tuple))
        and all(isinstance(value, str) for value in scope_unit_ids)
        and isinstance(required_evidence_ids, (list, set, tuple))
        and all(isinstance(value, str) for value in required_evidence_ids)
        and isinstance(task_input_evidence_ids, (list, set, tuple))
        and all(isinstance(value, str) for value in task_input_evidence_ids)
    )
    scope = set(scope_unit_ids) if isinstance(scope_unit_ids, (list, set, tuple)) else set()
    required = set(required_evidence_ids) if isinstance(required_evidence_ids, (list, set, tuple)) else set()
    inputs = set(task_input_evidence_ids) if isinstance(task_input_evidence_ids, (list, set, tuple)) else set()
    matched = False
    examined = 0
    unexamined_after_match = 0
    counts = {code: 0 for code in _REQUIRED_CONTEXT_NOTE_CODES}
    if isinstance(notes, list):
        for note in notes:
            note_match, code = _required_context_note_match(
                note,
                scope_unit_ids=scope,
                required_evidence_ids=required,
                task_input_evidence_ids=inputs,
                predicate_order=predicate_order,
            )
            examined += 1
            matched = matched or note_match
            counts[code] += 1
            if note_match:
                unexamined_after_match = len(notes) - examined
                break
        if not notes:
            counts["NO_COVERAGE_NOTES"] = 1
    result = (
        "UNKNOWN"
        if not observable
        else "COVERED"
        if matched
        else "NO_COVERING_NOTE"
        if notes
        else "NO_NOTES"
    )
    return matched, {
        "state": "OBSERVED" if observable else "UNKNOWN",
        "result": result,
        "note_count": len(notes) if observable else "UNKNOWN",
        "notes_examined_count": examined if observable else "UNKNOWN",
        "notes_unexamined_after_match_count": unexamined_after_match if observable else "UNKNOWN",
        "failure_counts": counts if observable else "UNKNOWN",
    }


def _required_output_quarantine_observation(results: list[dict[str, Any]]) -> tuple[bool, dict[str, Any]]:
    """Mirror the reducer's existing required-vs-advisory quarantine rule."""
    counts = {kind: 0 for kind in _REQUIRED_OUTPUT_QUARANTINE_KINDS}
    total = 0
    observable = True
    required_found = False
    for result_index, result in enumerate(results):
        if "quarantined_items" not in result:
            observable = False
        items = result.get("quarantined_items", [])
        for index, item in enumerate(items):
            kind = item.get("kind")
            if kind in {"specific_strengths", "future_guidance"}:
                continue
            bucket = kind if isinstance(kind, str) and kind in counts else "other_required_kind"
            if not isinstance(kind, str):
                observable = False
            counts[bucket] += 1
            total += 1
            required_found = True
            if index + 1 < len(items) or result_index + 1 < len(results):
                observable = False
            break
        if required_found:
            break
    return required_found, {
        "state": "OBSERVED" if observable else "UNKNOWN",
        "count": total if observable else "UNKNOWN",
        "by_kind": counts if observable else "UNKNOWN",
    }


def _claim_adapter_bytes(value: Any) -> bytes:
    """Use the claim adapter's exact canonical JSON representation for bound hashes."""
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _claim_adapter_hash(value: Any) -> str:
    return hashlib.sha256(_claim_adapter_bytes(value)).hexdigest()


def _safe_claim_error_code(exc: Exception) -> str:
    """Return only a known local ClaimAssessmentError code, never raw text."""
    code = None
    if type(exc) is ClaimAssessmentError:
        code = getattr(exc, "code", None)
    elif isinstance(exc, IsolatedCallError) and exc.remote_type == "ClaimAssessmentError":
        code = str(exc)
    return code if isinstance(code, str) and code in CLAIM_ASSESSMENT_ERROR_CODES else "UNKNOWN"


_ADJUDICATION_V3 = review_contracts.ADJUDICATION_V3
_ADJUDICATION_RUBRIC = review_contracts.ADJUDICATION_RUBRIC_VERSION
_CAUSAL_ROLES = review_contracts.CAUSAL_ROLE_NAMES
_CAUSAL_SUPPORT = set(review_contracts.CAUSAL_SUPPORT_VALUES)
_MAX_CAUSAL_ASSESSMENT_BYTES = review_contracts.MAX_CAUSAL_ASSESSMENT_BYTES
_MAX_CAUSAL_ROLE_EVIDENCE_REFS = review_contracts.MAX_CAUSAL_ROLE_EVIDENCE_REFS
_MAX_CAUSAL_ROLE_EVIDENCE_REF_BYTES = 256


def _validated_v3_causal_roles(
    assessment: Any,
    delivered_evidence: list[dict],
    evidence_map: dict,
    snapshot_id: str,
    provider_identity: Any,
    semantic_provenance: Any,
) -> tuple[bool, set[str]]:
    """Check normalized v3 role claims against the exact adjudication input."""
    if (
        not isinstance(assessment, dict)
        or assessment.get("contract_version") != _ADJUDICATION_V3
        or assessment.get("source_contract_version") != _ADJUDICATION_V3
    ):
        return False, set()
    provider_details = provider_identity.get("provider") if isinstance(provider_identity, dict) else None
    if (
        not isinstance(provider_details, dict)
        or provider_details.get("adjudication_rubric_version") != _ADJUDICATION_RUBRIC
        or not isinstance(semantic_provenance, dict)
        or semantic_provenance.get("provider_rubric_version") != _ADJUDICATION_RUBRIC
    ):
        return False, set()
    roles = assessment.get("causal_roles")
    if not isinstance(roles, dict) or set(roles) != set(_CAUSAL_ROLES):
        return False, set()
    delivered_ids = {
        item.get("evidence_id")
        for item in delivered_evidence
        if isinstance(item, dict) and isinstance(item.get("evidence_id"), str)
    }
    referenced: set[str] = set()
    for role_name in _CAUSAL_ROLES:
        role = roles.get(role_name)
        if (
            not isinstance(role, dict)
            or set(role) != {"support", "assessment", "evidence_refs"}
            or role.get("support") not in _CAUSAL_SUPPORT
        ):
            return False, set()
        statement = role.get("assessment")
        if not isinstance(statement, str) or not statement.strip():
            return False, set()
        try:
            if len(statement.encode("utf-8")) > _MAX_CAUSAL_ASSESSMENT_BYTES:
                return False, set()
        except UnicodeEncodeError:
            return False, set()
        refs = role.get("evidence_refs")
        if not isinstance(refs, list) or len(refs) > _MAX_CAUSAL_ROLE_EVIDENCE_REFS:
            return False, set()
        if role["support"] in {"SUPPORTED", "CONTRADICTED"} and not refs:
            return False, set()
        for ref in refs:
            if not isinstance(ref, str) or ref not in delivered_ids:
                return False, set()
            try:
                if len(ref.encode("utf-8")) > _MAX_CAUSAL_ROLE_EVIDENCE_REF_BYTES:
                    return False, set()
            except UnicodeEncodeError:
                return False, set()
            record = evidence_map.get(ref)
            if (
                not isinstance(record, dict)
                or record.get("evidence_id") != ref
                or record.get("snapshot_id") != snapshot_id
            ):
                return False, set()
            referenced.add(ref)
    return True, referenced


def _core_contract_hash() -> str:
    """Fingerprint execution and normalization rules into every resume identity."""
    root = Path(__file__).resolve().parent
    names = ("engine.py", "planner.py", "providers.py", "contracts.py", "reconcile.py", "budget.py")
    return _hash({name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in names})


def _bounded_freshness(check: Any, timeout: float) -> dict:
    if timeout <= 0:
        raise TimeoutError("DEADLINE_EXHAUSTED")
    invocation = IsolatedInvocation(check, "__call__", (), deadline_seconds=timeout, output_limit=8192)
    while not invocation.poll():
        invocation.wait_for_ready()
    result = invocation.result()
    if not isinstance(result, dict):
        raise ValueError("invalid freshness result")
    return result


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def validate_limits(limits: dict) -> None:
    """Reject unbounded or malformed budgets before any provider call."""
    if not isinstance(limits, dict):
        raise ValueError("limits must be an object")
    required = {
        "deadline_seconds": (float, 0, None),
        "max_concurrent_scopes": (int, 1, None),
        "max_provider_calls": (int, 1, None),
        "max_retries_per_task": (int, 0, None),
        "max_context_bytes": (int, 1, None),
        "max_input_bytes_per_task": (int, 1, None),
        "max_output_bytes_per_task": (int, 1, None),
        "max_output_bytes": (int, 1, None),
        "max_context_retrievals": (int, 0, None),
        "max_followup_tasks": (int, 0, None),
    }
    optional_positive_ints = {"max_snapshot_context_bytes"}
    missing = [key for key in required if key not in limits]
    if missing:
        raise ValueError("missing finite limits: " + ", ".join(missing))
    for key, (kind, low, _) in required.items():
        value = limits[key]
        if isinstance(value, bool) or not isinstance(value, (int, float) if kind is float else int):
            raise ValueError(f"invalid limit: {key}")
        if key == "deadline_seconds":
            if not math.isfinite(value) or value <= 0:
                raise ValueError(f"invalid limit: {key}")
        elif value < low:
            raise ValueError(f"invalid limit: {key}")
    for key in optional_positive_ints:
        if key in limits:
            value = limits[key]
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"invalid limit: {key}")
    if limits.get("max_cost_microunits") is not None:
        if (
            isinstance(limits["max_cost_microunits"], bool)
            or not isinstance(limits["max_cost_microunits"], int)
            or limits["max_cost_microunits"] < 1
        ):
            raise ValueError("invalid limit: max_cost_microunits")


def _provider_identity(provider: Any, decision_provider: Any) -> Any:
    def identity(obj: Any) -> Any:
        if obj is None:
            return None
        value = getattr(obj, "identity", None)
        if callable(value):
            value = value()
        return (
            value
            if isinstance(value, (str, int, float, bool, dict, list, type(None)))
            else {"type": type(obj).__name__}
        )

    return {"provider": identity(provider), "decision_provider": identity(decision_provider)}


def _claim_assessor_binding(assessor: Any) -> tuple[str, str, str]:
    """Validate the opt-in shadow adapter and return a stable non-secret identity binding."""
    for name in ("prepare", "estimate_prepared", "assess_prepared"):
        if not callable(getattr(assessor, name, None)):
            raise ValueError("claim assessor does not implement the prepared-assessment interface")
    identity = getattr(assessor, "identity", None)
    if callable(identity):
        identity = identity()
    if not isinstance(identity, dict):
        raise ValueError("claim assessor identity must be an object")
    version = identity.get("contract_version")
    if not isinstance(version, str) or not version or len(version) > 128:
        raise ValueError("claim assessor contract identity is required")
    try:
        encoded_identity = _canonical(identity)
        serialized_assessor = pickle.dumps(assessor, protocol=pickle.HIGHEST_PROTOCOL)
    except Exception as exc:
        raise ValueError("claim assessor identity or adapter is not serializable") from exc
    if len(encoded_identity) > 16_384 or len(serialized_assessor) > 65_536:
        raise ValueError("claim assessor configuration exceeds its finite preflight bound")
    root = Path(__file__).resolve().parent
    implementation_hash = _hash(
        {
            name: hashlib.sha256((root / name).read_bytes()).hexdigest()
            for name in ("claim_assessment.py", "claim_transport.py")
        }
    )
    return _hash(identity), version, implementation_hash


def _evidence_for(task: dict, snapshot: dict, limit: int) -> list[dict]:
    evidence = snapshot.get("evidence", {})
    ids = list(task.get("evidence_ids", []))
    result = []
    total = 0
    for eid in ids:
        item = evidence.get(eid) if isinstance(evidence, dict) else None
        if not isinstance(item, dict):
            continue
        encoded = _canonical(item)
        total += len(encoded)
        result.append(dict(item))
    # Snapshot builders may embed evidence on each inventory item.
    if not result:
        wanted = set(task.get("unit_ids", task.get("scope_unit_ids", [])))
        for unit in snapshot.get("inventory", []):
            if unit.get("unit_id") in wanted:
                item = {
                    "evidence_id": f"unit:{unit['unit_id']}",
                    "path": unit.get("path"),
                    "content": unit.get("diff", ""),
                    "source_kind": "diff",
                    "trust": "untrusted_pr_content",
                    "snapshot_id": snapshot.get("snapshot_id"),
                }
                encoded = _canonical(item)
                total += len(encoded)
                result.append(item)
    return result


def _same_evidence_content(left: dict, right: dict) -> bool:
    bound_fields = (
        "evidence_id",
        "snapshot_id",
        "path",
        "source_revision",
        "content_hash",
        "source_kind",
        "source_side",
        "source_object_id",
        "line_start",
        "line_end",
        "trust",
    )
    return all(left.get(field) == right.get(field) for field in bound_fields) and (
        "content" not in left or "content" not in right or left.get("content") == right.get("content")
    )


def _merge_evidence_rows(rows: list[dict]) -> list[dict]:
    """Deduplicate repeated IDs only when their immutable content binding agrees."""
    merged = []
    by_id = {}
    for item in rows:
        evidence_id = item.get("evidence_id") if isinstance(item, dict) else None
        if not isinstance(evidence_id, str) or not evidence_id:
            raise ValueError("invalid_evidence_id")
        existing = by_id.get(evidence_id)
        if existing is not None:
            if not _same_evidence_content(existing, item):
                raise ValueError("evidence_identity_conflict")
            continue
        by_id[evidence_id] = item
        merged.append(item)
    return merged


def _bind_specialist_input(task: dict, snapshot: dict, profile: dict, evidence: list[dict]) -> dict:
    """Attach the trusted unit-local evidence relation to one measured request."""
    if task.get("task_kind", "SPECIALIST_FINDINGS") != "SPECIALIST_FINDINGS":
        return task
    unit_ids = task.get("unit_ids", task.get("scope_unit_ids", []))
    task_evidence_ids = task.get("evidence_ids", [])
    if (
        not isinstance(unit_ids, list)
        or not unit_ids
        or any(not isinstance(unit_id, str) or not unit_id for unit_id in unit_ids)
        or len(unit_ids) != len(set(unit_ids))
        or not isinstance(task_evidence_ids, list)
        or any(not isinstance(evidence_id, str) or not evidence_id for evidence_id in task_evidence_ids)
        or len(task_evidence_ids) != len(set(task_evidence_ids))
    ):
        raise ValueError("invalid_specialist_input_scope")
    delivered = {
        item.get("evidence_id")
        for item in evidence
        if isinstance(item, dict)
        and isinstance(item.get("evidence_id"), str)
        and item.get("snapshot_id") == snapshot.get("snapshot_id")
    }
    inventory = {
        row.get("unit_id"): row
        for row in snapshot.get("inventory", [])
        if isinstance(row, dict) and isinstance(row.get("unit_id"), str)
    }
    bindings = []
    for unit_id in unit_ids:
        row = inventory.get(unit_id)
        selected_ids = []
        binding_status = "UNKNOWN"
        if isinstance(row, dict):
            source_ids = row.get("evidence_ids", [])
            if not isinstance(source_ids, list) or any(not isinstance(value, str) for value in source_ids):
                raise ValueError("invalid_specialist_unit_evidence")
            selected_set = set(source_ids)
            selected_ids = [evidence_id for evidence_id in task_evidence_ids if evidence_id in selected_set and evidence_id in delivered]
            binding_status = "VERIFIED"
        bindings.append({"unit_id": unit_id, "binding_status": binding_status, "evidence_ids": selected_ids})
    return {
        **task,
        "request_input_contract": review_contracts.SPECIALIST_INPUT_V2,
        "unit_evidence_bindings": bindings,
    }


def _task_input_provenance(task: dict) -> dict[str, Any]:
    provenance = {
        "request_input_contract": task.get("request_input_contract"),
        "unit_evidence_bindings": task.get("unit_evidence_bindings"),
    }
    if "context_followup" in task:
        provenance["context_followup"] = task["context_followup"]
    return provenance


def _context_followup_metadata(
    *,
    task: dict,
    record: dict,
    obligation: dict,
    parent_task: dict,
    parent_result: dict,
    retrieved_entry: dict,
    snapshot_id: str,
) -> dict[str, Any]:
    """Reconstruct the exact authorized follow-up metadata from run state."""
    proposal_id = record.get("proposal_id")
    parent_task_id = record.get("task_id")
    proposal = record.get("proposal")
    if not isinstance(parent_task_id, str) or not parent_task_id:
        raise ValueError("invalid_context_followup_parent_binding")
    prefix = f"{parent_task_id}:gap:"
    if (
        record.get("status") not in {"VALID_UNRESOLVED", "RESOLVED_BY_FOLLOWUP"}
        or not isinstance(proposal_id, str)
        or not proposal_id.startswith(prefix)
        or not proposal_id[len(prefix) :].isdigit()
        or not isinstance(proposal, dict)
        or parent_task.get("task_id") != parent_task_id
        or parent_result.get("task_id") != parent_task_id
        or parent_result.get("status") != "SUCCEEDED"
    ):
        raise ValueError("invalid_context_followup_parent_binding")
    index = int(proposal_id[len(prefix) :])
    if proposal_id != f"{parent_task_id}:gap:{index}":
        raise ValueError("invalid_context_followup_proposal_binding")
    parent_payload = parent_result.get("payload")
    parent_proposals = parent_payload.get("context_gap_proposals", []) if isinstance(parent_payload, dict) else []
    if not isinstance(parent_proposals, list) or index >= len(parent_proposals) or parent_proposals[index] != proposal:
        raise ValueError("invalid_context_followup_proposal_binding")
    source_version = parent_result.get("source_contract_version")
    if source_version is None:
        source_version = review_contracts.SPECIALIST_V1
    if not isinstance(source_version, str) or source_version not in {
        review_contracts.SPECIALIST_V1,
        review_contracts.SPECIALIST_V2,
        review_contracts.SPECIALIST_V3,
        review_contracts.SPECIALIST_V4,
    }:
        raise ValueError("invalid_context_followup_parent_contract")
    target = proposal.get("target")
    if not isinstance(target, dict) or set(target) != {"target_unit_id", "target_path", "target_symbol"}:
        raise ValueError("invalid_context_followup_target")
    target_values = [target.get(key) for key in ("target_unit_id", "target_path", "target_symbol")]
    if any(
        value is not None
        and (not isinstance(value, str) or not value.strip() or len(value.encode("utf-8")) > 2_000)
        for value in target_values
    ):
        raise ValueError("invalid_context_followup_target")
    selected = [
        (key, target.get(key))
        for key in ("target_unit_id", "target_path", "target_symbol")
        if target.get(key) is not None
    ]
    if len(selected) != 1 or not isinstance(selected[0][1], str):
        raise ValueError("invalid_context_followup_target")
    target_kind = {"target_unit_id": "unit", "target_path": "path", "target_symbol": "symbol"}[selected[0][0]]
    # Provider adapters store the normalized engine-facing target triplet. Rebuild
    # the typed contract shape before revalidating with the declared source version.
    wire_proposal = {
        **proposal,
        "target": {"kind": target_kind, "value": selected[0][1]},
    }
    try:
        normalized_proposal = review_contracts.validate_gap(wire_proposal, source_version)
    except review_contracts.ContractIssue as exc:
        raise ValueError(exc.code) from None

    target = normalized_proposal.get("target")
    if not isinstance(target, dict) or set(target) != {"target_unit_id", "target_path", "target_symbol"}:
        raise ValueError("invalid_context_followup_target")

    retrieved = retrieved_entry.get("result")
    retrieved_evidence = retrieved_entry.get("evidence")
    retrieved_ids = record.get("retrieved_evidence_ids")
    if (
        not isinstance(retrieved, dict)
        or retrieved.get("status") != "RESOLVED"
        or not isinstance(retrieved_evidence, list)
        or any(not isinstance(item, dict) or not isinstance(item.get("evidence_id"), str) for item in retrieved_evidence)
        or not isinstance(retrieved_ids, list)
        or not retrieved_ids
        or any(not isinstance(evidence_id, str) for evidence_id in retrieved_ids)
        or len(retrieved_ids) != len(set(retrieved_ids))
        or [item.get("evidence_id") for item in retrieved_evidence if isinstance(item, dict)] != retrieved_ids
    ):
        raise ValueError("invalid_context_followup_retrieval_binding")

    parent_obligation_ids = record.get("affected_obligation_ids")
    if (
        not isinstance(parent_obligation_ids, list)
        or not parent_obligation_ids
        or any(not isinstance(oid, str) or not oid for oid in parent_obligation_ids)
        or len(parent_obligation_ids) != len(set(parent_obligation_ids))
        or not isinstance(parent_task.get("obligation_ids", [parent_task.get("obligation_id")]), list)
        or not set(parent_obligation_ids).issubset(
            set(parent_task.get("obligation_ids", [parent_task.get("obligation_id")]))
        )
    ):
        raise ValueError("invalid_context_followup_parent_obligations")
    scope_unit_ids = [record["resolved_unit_id"]] if record.get("resolved_unit_id") else list(parent_task.get("unit_ids", []))
    if not scope_unit_ids or any(not isinstance(uid, str) or not uid for uid in scope_unit_ids):
        raise ValueError("invalid_context_followup_scope")
    obligation_id = f"context:{proposal_id}"
    if (
        obligation.get("obligation_id") != obligation_id
        or obligation.get("obligation_kind") != "REQUIRED_CONTEXT"
        or obligation.get("required") is not True
        or obligation.get("scope_unit_ids") != scope_unit_ids
        or obligation.get("lens") != normalized_proposal.get("required_lens")
        or obligation.get("parent_obligation_ids") != parent_obligation_ids
        or obligation.get("context_gap_id") != proposal_id
        or obligation.get("retrieved_evidence_ids") != retrieved_ids
    ):
        raise ValueError("invalid_context_followup_obligation_binding")

    related_candidate_ids = normalized_proposal.get("related_candidate_ids")
    related_evidence_ids = normalized_proposal.get("related_evidence_ids")
    parent_evidence_ids = parent_task.get("evidence_ids")
    if (
        not isinstance(related_candidate_ids, list)
        or not isinstance(related_evidence_ids, list)
        or not isinstance(parent_evidence_ids, list)
        or any(not isinstance(value, str) or not value for value in parent_evidence_ids)
        or any(not isinstance(value, str) or not value for value in related_candidate_ids)
        or any(not isinstance(value, str) or not value for value in related_evidence_ids)
        or not set(related_evidence_ids).issubset(set(parent_evidence_ids))
    ):
        raise ValueError("invalid_context_followup_related_evidence")
    metadata = {
        "contract_version": review_contracts.CONTEXT_FOLLOWUP_V1,
        "snapshot_id": snapshot_id,
        "proposal_id": proposal_id,
        "parent_task_id": parent_task_id,
        "parent_obligation_ids": list(parent_obligation_ids),
        "followup_obligation_id": obligation_id,
        "required_lens": normalized_proposal.get("required_lens"),
        "scope_unit_ids": scope_unit_ids,
        "evidence_kind": normalized_proposal.get("evidence_kind"),
        "target": {"kind": target_kind, "value": selected[0][1]},
        "rationale": normalized_proposal.get("rationale"),
        "related_candidate_ids": list(related_candidate_ids),
        "related_evidence_ids": list(related_evidence_ids),
        "retrieved_evidence_ids": list(retrieved_ids),
    }
    try:
        review_contracts.validate_context_followup_metadata(metadata)
    except review_contracts.ContractIssue as exc:
        raise ValueError(exc.code) from None
    if (
        task.get("task_id") != f"{parent_task_id}:followup:{index}"
        or task.get("context_gap_followup_for") != proposal_id
        or task.get("obligation_id") != obligation_id
        or task.get("obligation_ids") != [obligation_id]
        or task.get("unit_ids") != scope_unit_ids
        or task.get("lens") != normalized_proposal.get("required_lens")
        or not isinstance(task.get("evidence_ids"), list)
        or any(not isinstance(value, str) or not value for value in task.get("evidence_ids", []))
        or not set(retrieved_ids).issubset(set(task["evidence_ids"]))
    ):
        raise ValueError("invalid_context_followup_task_binding")
    return metadata


def _validate_context_followup_task(
    task: dict,
    ledger: dict,
    snapshot: dict,
    obligation_by_id: dict,
    task_by_id: dict,
) -> None:
    marker = task.get("context_gap_followup_for")
    if marker is None and "context_followup" not in task:
        return
    if not isinstance(marker, str) or "context_followup" not in task:
        raise ValueError("invalid_context_followup_contract")
    records = [
        item
        for item in ledger.get("context_gaps", [])
        if isinstance(item, dict) and item.get("proposal_id") == marker
    ]
    if len(records) != 1:
        raise ValueError("invalid_context_followup_gap_record")
    record = records[0]
    parent_task = task_by_id.get(record.get("task_id"))
    parent_result = ledger.get("outputs", {}).get(record.get("task_id"), {})
    obligation = obligation_by_id.get(f"context:{marker}")
    retrieved_entry = ledger.get("retrieved_context", {}).get(marker)
    if not all(isinstance(value, dict) for value in (parent_task, parent_result, obligation, retrieved_entry)):
        raise ValueError("invalid_context_followup_run_binding")
    expected = _context_followup_metadata(
        task=task,
        record=record,
        obligation=obligation,
        parent_task=parent_task,
        parent_result=parent_result,
        retrieved_entry=retrieved_entry,
        snapshot_id=snapshot.get("snapshot_id"),
    )
    if task.get("context_followup") != expected:
        raise ValueError("invalid_context_followup_metadata_binding")


def _validate_bound_specialist_input(task: dict, snapshot: dict, profile: dict, evidence: list[dict]) -> None:
    """Reject persisted or caller-supplied mappings not derivable from trusted input."""
    if task.get("request_input_contract") != review_contracts.SPECIALIST_INPUT_V2:
        raise ValueError("invalid_specialist_input_contract")
    source_task = {key: value for key, value in task.items() if key not in {"request_input_contract", "unit_evidence_bindings"}}
    expected = _bind_specialist_input(source_task, snapshot, profile, evidence)
    if task.get("unit_evidence_bindings") != expected["unit_evidence_bindings"]:
        raise ValueError("invalid_specialist_unit_evidence_binding")


def effective_task_input_ceiling(limits: dict, provider: Any) -> int:
    """Return the shared runtime/adapter ceiling for one primary request.

    Providers without a declared request cap retain the historical runtime
    limit. A declared cap is trusted adapter configuration and must be a finite
    positive integer; malformed capabilities fail preflight before dispatch.
    """
    runtime_cap = limits["max_input_bytes_per_task"]
    adapter_cap = getattr(provider, "max_request_bytes", None)
    if adapter_cap is None:
        return runtime_cap
    if isinstance(adapter_cap, bool) or not isinstance(adapter_cap, int) or adapter_cap <= 0:
        raise ValueError("invalid provider input byte capability")
    return min(runtime_cap, adapter_cap)


def _unwrap(response: Any) -> tuple[dict, dict, dict]:
    if not isinstance(response, dict):
        raise ValueError("invalid_result")
    if "payload" in response:
        payload, usage, provenance = response["payload"], response.get("usage", {}), response.get("provenance", {})
    else:
        payload, usage, provenance = response, {}, {}
    if not isinstance(payload, dict) or not isinstance(usage, dict) or not isinstance(provenance, dict):
        raise ValueError("invalid_result")
    return payload, usage, provenance


def safe_provider_error(exc: Exception) -> str | None:
    from .providers import ProviderError

    if isinstance(exc, ProviderError) and re.fullmatch(r"[a-z0-9_]{1,100}", exc.code):
        return exc.code
    return None


def _stable_finding_id(run_id: str, candidate: dict) -> str:
    return "finding-" + _hash({"run_id": run_id, "candidate": candidate})[:16]


def _reduce(result: dict, allow_empty_approve: bool, policy_valid: bool) -> str:
    findings = result["findings"]
    blockers = [f for f in findings if f.get("status") == "ACCEPTED" and f.get("blocking_class") == "BLOCKING"]
    if blockers:
        return "REQUEST_CHANGES"
    required_incomplete = (
        result["coverage_state"] != "COMPLETE"
        or not policy_valid
        or any(f.get("blocking_class") == "UNRESOLVED" for f in findings)
        or bool(result.get("budget", {}).get("budget_breaches"))
    )
    if required_incomplete or result["freshness"] != "CURRENT":
        return "INCOMPLETE"
    if findings:
        return "COMMENT"
    return "APPROVE" if allow_empty_approve else "COMMENT"


def prepare_plan_tasks(snapshot: dict, plan: dict, profile: dict, limits: dict, provider: Any) -> tuple[list[dict], dict]:
    """Apply the same deterministic specialist chunking used by the runner.

    This is shared with provider-free prepare mode so admission and serialized
    request measurements cannot drift from normal dispatch behavior.
    """
    validate_limits(limits)
    tasks = plan.get("tasks")
    obligations = plan.get("coverage_obligations")
    if not isinstance(tasks, list) or not isinstance(obligations, list):
        raise ValueError("plan requires tasks and coverage_obligations")
    obligations = list(obligations)
    task_by_id = {}
    for task in tasks:
        if not isinstance(task, dict) or not task.get("task_id") or not task.get("obligation_id"):
            raise ValueError("invalid planned task")
        task_kind = task.get("task_kind", "SPECIALIST_FINDINGS")
        if not isinstance(task_kind, str) or task_kind not in ("SPECIALIST_FINDINGS", "DETERMINISTIC_CHECK"):
            raise ValueError("invalid planned task kind")
        if task["task_id"] in task_by_id:
            raise ValueError("duplicate task_id")
        if task.get("task_kind", "SPECIALIST_FINDINGS") == "SPECIALIST_FINDINGS" and (
            "request_input_contract" in task or "unit_evidence_bindings" in task
        ):
            raise ValueError("planned_specialist_input_metadata_is_engine_owned")
        task_by_id[task["task_id"]] = task
    obligation_by_id = {
        o.get("obligation_id"): o for o in obligations if isinstance(o, dict) and o.get("obligation_id")
    }
    if len(obligation_by_id) != len(obligations):
        raise ValueError("invalid or duplicate coverage obligation")
    for task in tasks:
        if not set(task.get("obligation_ids", [task["obligation_id"]])).issubset(obligation_by_id):
            raise ValueError("task references unknown obligation")

    # Split an oversized specialist batch deterministically by inventory order.
    # Each unit keeps its own required obligation IDs, so omitted units cannot
    # inherit another chunk's successful result.
    def review_input_size(task: dict, evidence: list[dict]) -> int:
        measure = getattr(provider, "review_input_bytes", None)
        if callable(measure) and task.get("task_kind", "SPECIALIST_FINDINGS") == "SPECIALIST_FINDINGS":
            # Reserve extra room for chunk metadata added after grouping.
            return measure(task, evidence, limits) + 1024
        return len(_canonical({"task": task, "evidence": evidence}))

    unit_order = {u.get("unit_id"): i for i, u in enumerate(snapshot.get("inventory", [])) if isinstance(u, dict)}
    split_tasks = []
    split_skips = {}
    input_ceiling = effective_task_input_ceiling(limits, provider)
    for task in tasks:
        unit_ids = list(task.get("unit_ids", task.get("scope_unit_ids", [])))
        if task.get("task_kind", "SPECIALIST_FINDINGS") != "SPECIALIST_FINDINGS":
            split_tasks.append(task)
            continue
        unit_obligations = {
            oid: list(obligation_by_id[oid].get("scope_unit_ids", []))
            for oid in task.get("obligation_ids", [task["obligation_id"]])
        }
        task_evidence_ids = set(task.get("evidence_ids", []))
        all_context_ids = list(task.get("base_context_ids") or snapshot.get("trusted_context_refs", []))
        required_context_ids = list(dict.fromkeys(task.get("required_context_ids", [])))
        # A required reference is authoritative even if an inconsistent task
        # omitted it from base_context_ids. Do not turn that inconsistency into
        # optional or silently absent context.
        all_context_ids = list(dict.fromkeys(all_context_ids + required_context_ids))
        context_ids = [eid for eid in all_context_ids if eid in task_evidence_ids]
        context_id_set = set(context_ids)
        task_evidence = snapshot.get("evidence", {})

        def skip_unit(uid: str, error_code: str, required_omissions: list[str] | None = None) -> None:
            obligation_ids = [oid for oid, units in unit_obligations.items() if uid in units]
            key = _hash({"task": task["task_id"], "unit": uid})[:20]
            existing = split_skips.get(key, {})
            split_skips[key] = {
                "task_id": task["task_id"],
                "unit_id": uid,
                "obligation_ids": list(dict.fromkeys(existing.get("obligation_ids", []) + obligation_ids)),
                "status": "SKIPPED",
                "error_code": error_code,
                "required_context_omissions": list(
                    dict.fromkeys(existing.get("required_context_omissions", []) + (required_omissions or []))
                ),
                "attempts": 0,
            }

        missing_required = [
            eid
            for eid in required_context_ids
            if eid not in task_evidence_ids
            or not isinstance(task_evidence, dict)
            or not isinstance(task_evidence.get(eid), dict)
            or task_evidence[eid].get("evidence_id") != eid
            or task_evidence[eid].get("snapshot_id") != snapshot.get("snapshot_id")
        ]
        if missing_required:
            for uid in unit_ids:
                skip_unit(uid, "REQUIRED_CONTEXT_MISSING", missing_required)
            continue

        batches, current, current_ids, current_obs, current_required = [], [], [], [], []

        def batch_task(units: list[str], ids: list[str], required: list[str]) -> dict:
            required = list(dict.fromkeys(required))
            candidate = {
                **task,
                "unit_ids": units,
                "scope_unit_ids": units,
                "evidence_ids": list(dict.fromkeys(ids + required)),
                "base_context_ids": required,
                "required_context_ids": required,
            }
            evidence = _evidence_for(candidate, snapshot, input_ceiling)
            return _bind_specialist_input(candidate, snapshot, profile, evidence)

        for uid in sorted(unit_ids, key=lambda u: unit_order.get(u, 10**9)):
            unit = next((u for u in snapshot.get("inventory", []) if u.get("unit_id") == uid), {})
            if profile.get("context_selection"):
                # The planner narrows each unit to its bound diff/window set.
                # Keep that exact set during batching; inventory.evidence_ids
                # also contains whole-file captures that the selector excludes.
                unit_review_ids = unit.get("review_context_evidence_ids", unit.get("evidence_ids", []))
            else:
                # Preserve historical profile behavior, including older
                # snapshots without the selector-specific inventory field.
                unit_review_ids = unit.get("evidence_ids", [])
            unit_evidence_ids = set(unit_review_ids)
            ids = [
                eid for eid in task.get("evidence_ids", []) if eid in unit_evidence_ids and eid not in context_id_set
            ]
            unit_task = batch_task([uid], ids, [])
            unit_evidence = _evidence_for(unit_task, snapshot, input_ceiling)
            unit_size = review_input_size(unit_task, unit_evidence)
            if unit_size > input_ceiling:
                skip_unit(uid, "UNIT_EVIDENCE_EXCEEDS_INPUT_LIMIT")
                continue

            unit_required = list(required_context_ids)
            required_task = batch_task([uid], ids, unit_required)
            required_size = review_input_size(required_task, _evidence_for(required_task, snapshot, input_ceiling))
            if required_size > input_ceiling:
                skip_unit(uid, "UNIT_REQUIRED_CONTEXT_EXCEEDS_INPUT_LIMIT", unit_required)
                continue

            candidate_units = current + [uid]
            candidate_ids = current_ids + ids
            candidate_required = list(dict.fromkeys(current_required + unit_required))
            candidate_task = batch_task(candidate_units, candidate_ids, candidate_required)
            cur_size = review_input_size(candidate_task, _evidence_for(candidate_task, snapshot, input_ceiling))
            if current and cur_size > input_ceiling:
                batches.append((current, current_ids, current_obs, current_required))
                current, current_ids, current_obs, current_required = [], [], [], []
            current.append(uid)
            current_ids.extend(ids)
            current_required.extend(unit_required)
            current_obs.extend(oid for oid, units in unit_obligations.items() if uid in units)
        if current:
            batches.append((current, current_ids, current_obs, current_required))
        for index, (units, ids, oids, mandatory_ids) in enumerate(batches, 1):
            chosen_context = list(dict.fromkeys(mandatory_ids))
            omitted_context = []

            def finalized_batch(selected_context: list[str], omitted_ids: list[str]) -> dict:
                candidate = {
                    **task,
                    "task_id": f"{task['task_id']}:chunk-{index}",
                    "unit_ids": units,
                    "scope_unit_ids": units,
                    "evidence_ids": list(dict.fromkeys(ids + selected_context)),
                    "base_context_ids": selected_context,
                    "required_context_ids": list(dict.fromkeys(mandatory_ids)),
                    "context_omissions": omitted_ids,
                    "required_context_omissions": [],
                    "obligation_id": oids[0],
                    "obligation_ids": list(dict.fromkeys(oids)),
                }
                evidence = _evidence_for(candidate, snapshot, input_ceiling)
                return _bind_specialist_input(candidate, snapshot, profile, evidence)

            for eid in context_ids:
                if eid in set(chosen_context):
                    continue
                optional_task = finalized_batch(chosen_context + [eid], omitted_context)
                size = review_input_size(optional_task, _evidence_for(optional_task, snapshot, input_ceiling))
                (chosen_context if size <= input_ceiling else omitted_context).append(eid)
            final_task = finalized_batch(chosen_context, omitted_context)
            final_size = review_input_size(final_task, _evidence_for(final_task, snapshot, input_ceiling))
            if final_size > input_ceiling:
                for uid in units:
                    skip_unit(uid, "UNIT_REQUIRED_CONTEXT_EXCEEDS_INPUT_LIMIT", list(dict.fromkeys(mandatory_ids)))
                continue
            split_tasks.append(final_task)
    tasks = split_tasks
    return tasks, split_skips


def run_review(
    snapshot: dict,
    plan: dict,
    profile: dict,
    provider: Any,
    decision_provider: Any,
    limits: dict,
    output_dir: str,
    run_id: str,
    resume: bool = False,
    freshness_check: Any = None,
    context_retriever: Any = None,
    check_adapter: Any = None,
    claim_assessor: Any = None,
    max_claim_assessments: int = 0,
) -> dict:
    """Run bounded provider tasks and persist an integrity-checked review result.

    This controller never executes reviewed code. A lack of provider capability
    yields explicit NOT_STARTED coverage; it cannot be interpreted as no findings.
    """
    validate_limits(limits)
    if (
        isinstance(max_claim_assessments, bool)
        or not isinstance(max_claim_assessments, int)
        or not 0 <= max_claim_assessments <= 4
    ):
        raise ValueError("max_claim_assessments must be an integer from 0 to 4")
    claim_assessor_identity_hash = None
    claim_assessor_contract = None
    claim_assessor_code_hash = None
    if max_claim_assessments > 0:
        if claim_assessor is None:
            raise ValueError("positive max_claim_assessments requires a claim assessor")
        claim_assessor_identity_hash, claim_assessor_contract, claim_assessor_code_hash = _claim_assessor_binding(
            claim_assessor
        )
    if (
        not run_id
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", run_id)
        or ".." in run_id
        or not isinstance(snapshot, dict)
        or not isinstance(plan, dict)
        or not isinstance(profile, dict)
    ):
        raise ValueError("run_id, snapshot, plan, and profile are required")
    approval_authority = allow_empty_approve(profile)
    if plan.get("snapshot_id") not in (None, snapshot.get("snapshot_id")):
        raise ValueError("plan snapshot mismatch")
    tasks = plan.get("tasks")
    obligations = plan.get("coverage_obligations")
    if not isinstance(tasks, list) or not isinstance(obligations, list):
        raise ValueError("plan requires tasks and coverage_obligations")
    obligations = list(obligations)
    input_ceiling = effective_task_input_ceiling(limits, provider)
    primary_tasks, split_skips = prepare_plan_tasks(
        snapshot, {"tasks": tasks, "coverage_obligations": obligations}, profile, limits, provider
    )
    primary_task_inputs = [
        {
            "task_id": task["task_id"],
            "task_kind": task.get("task_kind", "SPECIALIST_FINDINGS"),
            "unit_ids": list(task.get("unit_ids", [])),
            "evidence_ids": list(task.get("evidence_ids", [])),
            "request_input_contract": task.get("request_input_contract"),
            "unit_evidence_bindings": task.get("unit_evidence_bindings"),
        }
        for task in primary_tasks
    ]
    output_path = Path(output_dir).resolve() / f"{run_id}.json"
    provider_identity = _provider_identity(provider, decision_provider)
    request_basis = {
        "snapshot": snapshot,
        "plan": plan,
        "profile": profile,
        "limits": limits,
        "provider": provider_identity,
        "run_id": run_id,
        "primary_task_inputs": primary_task_inputs,
        "request_input_contract": review_contracts.SPECIALIST_INPUT_V2,
        "core_contract_hash": _core_contract_hash(),
    }
    if max_claim_assessments > 0:
        request_basis["claim_assessment"] = {
            "assessor_identity_hash": claim_assessor_identity_hash,
            "implementation_hash": claim_assessor_code_hash,
            "contract_version": claim_assessor_contract,
            "max_assessments": max_claim_assessments,
        }
    request_hash = _hash(request_basis)
    deadline_epoch = time.time() + float(limits["deadline_seconds"])
    ledger = {
        "ledger_version": "0.2",
        "request_hash": request_hash,
        "events": [],
        "outputs": {},
        "candidate_records": [],
        "budget": {"reservations": {}, "settlements": {}, "context_retrievals": 0, "followup_tasks": 0},
        "deadline_epoch": deadline_epoch,
        "identity": {
            "snapshot_id": snapshot.get("snapshot_id"),
            "profile_version": profile.get("version", profile.get("profile_version")),
            "question_versions": sorted({str(t.get("question_version", "0.1")) for t in tasks}),
            "provider_identity_hash": _hash(provider_identity),
            "plan_hash": _hash(plan),
            "primary_task_inputs_hash": _hash(primary_task_inputs),
            "request_input_contract": review_contracts.SPECIALIST_INPUT_V2,
            "core_contract_hash": _core_contract_hash(),
        },
    }
    if max_claim_assessments > 0:
        ledger["identity"]["claim_assessment"] = {
            "assessor_identity_hash": claim_assessor_identity_hash,
            "implementation_hash": claim_assessor_code_hash,
            "contract_version": claim_assessor_contract,
            "max_assessments": max_claim_assessments,
        }
    if output_path.exists():
        if not resume:
            raise ValueError("run_id already exists; resume explicitly")
        try:
            saved = json.loads(output_path.read_text(encoding="utf-8"))
            ledger = saved["ledger"]
            if saved.get("request_hash") != request_hash or ledger.get("request_hash") != request_hash:
                raise ValueError("resume request mismatch")
            if _hash({k: v for k, v in saved.items() if k != "result_hash"}) != saved.get("result_hash"):
                raise ValueError("resume result integrity mismatch")
            if any(
                _hash({k: v for k, v in event.items() if k != "event_hash"}) != event.get("event_hash")
                for event in ledger.get("events", [])
            ):
                raise ValueError("resume ledger integrity mismatch")
            saved_snapshot = {**snapshot, "evidence": dict(snapshot.get("evidence", {}))}
            saved_retrieved_context = ledger.get("retrieved_context", {})
            if isinstance(saved_retrieved_context, dict):
                for entry in saved_retrieved_context.values():
                    if isinstance(entry, dict):
                        for item in entry.get("evidence", []):
                            if isinstance(item, dict) and isinstance(item.get("evidence_id"), str):
                                existing = saved_snapshot["evidence"].get(item["evidence_id"])
                                if existing is not None and not _same_evidence_content(existing, item):
                                    raise ValueError("resume evidence identity mismatch")
                                saved_snapshot["evidence"].setdefault(item["evidence_id"], item)
            saved_dynamic_tasks = [t for t in ledger.get("dynamic_tasks", []) if isinstance(t, dict)]
            saved_task_by_id = {task["task_id"]: task for task in [*primary_tasks, *saved_dynamic_tasks]}
            saved_dynamic_obligations = ledger.get("dynamic_obligations", [])
            if not isinstance(saved_dynamic_obligations, list):
                raise ValueError("resume dynamic obligation ledger invalid")
            saved_obligation_by_id = {
                item.get("obligation_id"): item
                for item in [*obligations, *saved_dynamic_obligations]
                if isinstance(item, dict) and item.get("obligation_id")
            }
            for task in saved_dynamic_tasks:
                if task.get("task_kind", "SPECIALIST_FINDINGS") == "SPECIALIST_FINDINGS":
                    _validate_context_followup_task(
                        task, ledger, saved_snapshot, saved_obligation_by_id, saved_task_by_id
                    )
                    saved_evidence = _evidence_for(task, saved_snapshot, input_ceiling)
                    _validate_bound_specialist_input(task, saved_snapshot, profile, saved_evidence)
            saved_input_provenance = {
                task["task_id"]: _task_input_provenance(task)
                for task in [*primary_tasks, *saved_dynamic_tasks]
                if task.get("request_input_contract") == review_contracts.SPECIALIST_INPUT_V2
            }
            if ledger.get("planned_task_inputs") != saved_input_provenance:
                raise ValueError("resume planned input binding mismatch")
            saved_outputs = ledger.get("outputs", {})
            if isinstance(saved_outputs, dict):
                for task_id, provenance in saved_input_provenance.items():
                    output = saved_outputs.get(task_id)
                    if isinstance(output, dict) and _task_input_provenance(output) != provenance:
                        raise ValueError("resume task input binding mismatch")
            if ledger.get("identity", {}).get("snapshot_id") not in (None, snapshot.get("snapshot_id")):
                raise ValueError("resume snapshot identity mismatch")
            if saved.get("completed_at"):
                if callable(freshness_check):
                    try:
                        check = _bounded_freshness(freshness_check, 5.0)
                        if isinstance(check, dict) and check.get("freshness") in {"CURRENT", "STALE", "UNKNOWN"}:
                            saved["freshness"] = check["freshness"]
                            saved["freshness_details"] = {
                                "expected_head_sha": snapshot.get("head_sha"),
                                **{k: v for k, v in check.items() if k != "freshness"},
                            }
                        else:
                            saved["freshness"] = "UNKNOWN"
                            saved["freshness_details"] = {
                                "expected_head_sha": snapshot.get("head_sha"),
                                "observed_head_sha": None,
                            }
                        saved["disposition"] = _reduce(
                            saved,
                            saved.get("allow_empty_approve") is True,
                            saved.get("policy_valid", False),
                        )
                        saved["completed_at"] = _now()
                        saved["result_hash"] = _hash({k: v for k, v in saved.items() if k != "result_hash"})
                        _atomic_write(output_path, _canonical(saved) + b"\n")
                    except Exception:
                        saved["freshness"] = "UNKNOWN"
                        saved["freshness_details"] = {
                            "expected_head_sha": snapshot.get("head_sha"),
                            "observed_head_sha": None,
                            "freshness_check_error": True,
                        }
                        saved["disposition"] = _reduce(
                            saved,
                            saved.get("allow_empty_approve") is True,
                            saved.get("policy_valid", False),
                        )
                        saved["completed_at"] = _now()
                        saved["result_hash"] = _hash({k: v for k, v in saved.items() if k != "result_hash"})
                        _atomic_write(output_path, _canonical(saved) + b"\n")
                elif snapshot.get("freshness_basis") != "HISTORICAL_SNAPSHOT":
                    saved["freshness"] = "UNKNOWN"
                    saved["freshness_details"] = {
                        "expected_head_sha": snapshot.get("head_sha"),
                        "observed_head_sha": None,
                    }
                    saved["disposition"] = _reduce(
                        saved,
                        saved.get("allow_empty_approve") is True,
                        saved.get("policy_valid", False),
                    )
                    saved["completed_at"] = _now()
                    saved["result_hash"] = _hash({k: v for k, v in saved.items() if k != "result_hash"})
                    _atomic_write(output_path, _canonical(saved) + b"\n")
                return saved
        except (KeyError, OSError, json.JSONDecodeError) as exc:
            raise ValueError("resume ledger invalid") from exc
    else:
        event = {"event": "RUN_STARTED", "at": _now()}
        event["event_hash"] = _hash(event)
        ledger["events"].append(event)

    if max_claim_assessments > 0:
        ledger.setdefault("claim_assessments", {})

    # Dynamic follow-up requests and retrieved immutable evidence are part of
    # the durable run state, while request identity remains the original
    # snapshot+plan+profile contract.
    snapshot = {**snapshot, "evidence": dict(snapshot.get("evidence", {}))}
    retrieved_context = ledger.get("retrieved_context", {})
    if isinstance(retrieved_context, dict):
        for entry in retrieved_context.values():
            if isinstance(entry, dict):
                for evidence in entry.get("evidence", []):
                    if isinstance(evidence, dict) and isinstance(evidence.get("evidence_id"), str):
                        existing = snapshot["evidence"].get(evidence["evidence_id"])
                        if existing is not None and not _same_evidence_content(existing, evidence):
                            raise ValueError("resume evidence identity mismatch")
                        snapshot["evidence"].setdefault(evidence["evidence_id"], evidence)
    tasks = primary_tasks
    dynamic_tasks = [t for t in ledger.get("dynamic_tasks", []) if isinstance(t, dict)]
    if isinstance(ledger.get("dynamic_obligations"), list):
        obligations = list(obligations) + [o for o in ledger["dynamic_obligations"] if isinstance(o, dict)]

    deadline_epoch = float(ledger.get("deadline_epoch", deadline_epoch))
    state_lock = threading.RLock()

    def checkpoint(terminal: bool = False) -> None:
        with state_lock:
            payload = {
                "run_id": run_id,
                "request_hash": request_hash,
                "completed_at": _now() if terminal else None,
                "ledger": ledger,
                "task_results": ledger.get("outputs", {}),
            }
            payload["result_hash"] = _hash(payload)
            _atomic_write(output_path, _canonical(payload) + b"\n")

    budget = BudgetLedger(limits, ledger.setdefault("budget", {}), persist=checkpoint, deadline_epoch=deadline_epoch)
    # A process crash after reservation is an uncertain paid attempt. Settle it
    # as unknown and never reuse its idempotency key for another dispatch.
    for reservation_key, reservation in list(budget.state["reservations"].items()):
        if reservation.get("provider_calls", 0) > 0 and reservation_key not in budget.state["settlements"]:
            budget.settle(reservation_key, output_bytes=None, usage={}, status="INTERRUPTED_UNKNOWN")
            ledger.setdefault("invocations", []).append(
                {
                    "reservation_key": reservation_key,
                    "status": "INTERRUPTED_UNKNOWN",
                    "at": _now(),
                }
            )

    task_by_id = {}
    for task in tasks:
        if not isinstance(task, dict) or not task.get("task_id") or not task.get("obligation_id"):
            raise ValueError("invalid planned task")
        if task["task_id"] in task_by_id:
            raise ValueError("duplicate task_id")
        task_by_id[task["task_id"]] = task
    obligation_by_id = {
        o.get("obligation_id"): o for o in obligations if isinstance(o, dict) and o.get("obligation_id")
    }
    if len(obligation_by_id) != len(obligations):
        raise ValueError("invalid or duplicate coverage obligation")
    for task in tasks:
        if not set(task.get("obligation_ids", [task["obligation_id"]])).issubset(obligation_by_id):
            raise ValueError("task references unknown obligation")

    known_task_ids = {task["task_id"] for task in tasks}
    for task in dynamic_tasks:
        if not task.get("task_id") or not task.get("obligation_id") or task["task_id"] in known_task_ids:
            raise ValueError("invalid_or_duplicate_dynamic_task")
        if task.get("task_kind", "SPECIALIST_FINDINGS") == "SPECIALIST_FINDINGS":
            _validate_context_followup_task(task, ledger, snapshot, obligation_by_id, task_by_id)
            evidence = _evidence_for(task, snapshot, input_ceiling)
            _validate_bound_specialist_input(task, snapshot, profile, evidence)
        if not set(task.get("obligation_ids", [task["obligation_id"]])).issubset(obligation_by_id):
            raise ValueError("dynamic_task_references_unknown_obligation")
        known_task_ids.add(task["task_id"])
        task_by_id[task["task_id"]] = task
        tasks.append(task)
    planned_task_inputs = {
        task["task_id"]: _task_input_provenance(task)
        for task in tasks
        if task.get("request_input_contract") == review_contracts.SPECIALIST_INPUT_V2
    }
    if "planned_task_inputs" in ledger and ledger["planned_task_inputs"] != planned_task_inputs:
        raise ValueError("resume planned input binding mismatch")
    ledger["planned_task_inputs"] = planned_task_inputs

    def review_input_size(task: dict, evidence: list[dict]) -> int:
        measure = getattr(provider, "review_input_bytes", None)
        if callable(measure) and task.get("task_kind", "SPECIALIST_FINDINGS") == "SPECIALIST_FINDINGS":
            return measure(task, evidence, limits) + 1024
        return len(_canonical({"task": task, "evidence": evidence}))

    call_lock = threading.Lock()
    task_results = dict(ledger.get("outputs", {}))
    for key, value in split_skips.items():
        task_results[key] = value
    pending = [
        t for t in tasks if t["task_id"] not in task_results or task_results[t["task_id"]].get("status") != "SUCCEEDED"
    ]
    evidence_cache = {t["task_id"]: _evidence_for(t, snapshot, input_ceiling) for t in tasks}
    for task in tasks:
        if task.get("task_kind", "SPECIALIST_FINDINGS") == "SPECIALIST_FINDINGS":
            _validate_bound_specialist_input(task, snapshot, profile, evidence_cache[task["task_id"]])

    def remaining_call_limits() -> dict:
        return {**limits, "deadline_seconds": max(0.0, budget.remaining_seconds())}

    def call_estimate(target: Any, task_kind: str, task: dict, evidence: list[dict], fallback_size: int) -> dict:
        estimator = getattr(target, "estimate_call", None)
        if callable(estimator):
            estimate = estimator(task_kind, task, evidence, remaining_call_limits())
            if not isinstance(estimate, dict):
                raise ValueError("provider estimate_call must return an object")
            estimate = dict(estimate)
        else:
            estimate = {
                "provider_calls": 1,
                "input_bytes": fallback_size,
                "max_output_bytes": int(limits["max_output_bytes_per_task"]),
                "reservation_kind": "unknown",
            }
        estimate["provider_calls"] = estimate.get("provider_calls", 1)
        estimate["input_bytes"] = estimate.get("input_bytes", fallback_size)
        estimate["max_output_bytes"] = estimate.get("max_output_bytes", int(limits["max_output_bytes_per_task"]))
        estimate["deadline_seconds"] = min(
            float(estimate.get("deadline_seconds", remaining_call_limits()["deadline_seconds"])),
            remaining_call_limits()["deadline_seconds"],
        )
        if limits.get("max_cost_microunits") is not None and estimate.get("reservation_kind") != "operator_bound":
            raise ValueError(
                "configured monetary budget reservation is unsupported without an operator-bound per-call quote"
            )
        return estimate

    def reserve_provider_call(
        key: str, target: Any, task_kind: str, task: dict, evidence: list[dict], fallback_size: int
    ) -> dict:
        estimate = call_estimate(target, task_kind, task, evidence, fallback_size)
        return budget.reserve(key, estimate)

    def validated_check_evidence(task: dict, payload: dict) -> list[str]:
        """Bind deterministic-check outputs to the exact ingested evidence.

        Check adapters receive the immutable snapshot, but a task is authorized
        to consume only the evidence for its own configured binding. Preserve
        those validated references in the task and coverage ledgers; never let
        a check adapter claim evidence from another binding or snapshot.
        """
        binding_id = task.get("check_binding_id")
        if not isinstance(binding_id, str) or not binding_id:
            raise ValueError("check_binding_missing")
        if payload.get("check_id") != task.get("check_id"):
            raise ValueError("check_identity_mismatch")

        result_map = snapshot.get("external_check_results", {})
        evidence_map = snapshot.get("evidence", {})
        if not isinstance(result_map, dict) or not isinstance(evidence_map, dict):
            raise ValueError("check_evidence_index_invalid")
        external_result = result_map.get(binding_id)
        expected_refs: list[str] = []
        expected_outcome = "UNKNOWN"
        if isinstance(external_result, dict):
            outcome = external_result.get("outcome", "UNKNOWN")
            if outcome not in {"PASS", "FINDINGS", "UNKNOWN", "ERROR"}:
                raise ValueError("check_evidence_outcome_invalid")
            expected_outcome = outcome
            evidence_id = external_result.get("evidence_id")
            if evidence_id is not None:
                if not isinstance(evidence_id, str) or not evidence_id:
                    raise ValueError("check_evidence_reference_invalid")
                item = evidence_map.get(evidence_id)
                if not isinstance(item, dict):
                    raise ValueError("check_evidence_missing")
                content_hash = item.get("content_hash")
                unsigned_item = {
                    key: value
                    for key, value in item.items()
                    if key not in {"content_hash", "evidence_id", "source_kind", "trust"}
                }
                evidence_outcome = (
                    "PASS"
                    if item.get("status") == "completed" and item.get("conclusion") == "success"
                    else "FINDINGS"
                    if item.get("status") == "completed"
                    and item.get("conclusion")
                    in {"failure", "cancelled", "timed_out", "action_required", "startup_failure"}
                    else "UNKNOWN"
                )
                if (
                    item.get("evidence_id") != evidence_id
                    or item.get("binding_id") != binding_id
                    or item.get("source_kind") != "github_check_run"
                    or item.get("trust") != "generated_result"
                    or item.get("repository") != snapshot.get("repository")
                    or item.get("pull_request_number") != snapshot.get("pull_request_number")
                    or item.get("head_sha") != snapshot.get("head_sha")
                    or evidence_outcome != outcome
                    or not isinstance(content_hash, str)
                    or _hash(unsigned_item) != content_hash
                    or evidence_id != "check-" + content_hash[:24]
                ):
                    raise ValueError("check_evidence_binding_invalid")
                expected_refs = [evidence_id]
        if expected_outcome in {"PASS", "FINDINGS"} and not expected_refs:
            raise ValueError("conclusive_check_without_evidence")

        references = payload.get("evidence_refs")
        if (
            payload.get("outcome") != expected_outcome
            or not isinstance(references, list)
            or any(not isinstance(ref, str) for ref in references)
            or references != expected_refs
        ):
            raise ValueError("check_result_evidence_mismatch")
        return expected_refs

    if limits.get("max_cost_microunits") is not None:
        for planned_task in tasks:
            target = check_adapter if planned_task.get("task_kind") == "DETERMINISTIC_CHECK" else provider
            if target is None:
                continue
            evidence = evidence_cache[planned_task["task_id"]]
            quote = call_estimate(
                target,
                planned_task.get("task_kind", "SPECIALIST_FINDINGS"),
                planned_task,
                evidence,
                review_input_size(planned_task, evidence),
            )
            if quote.get("reservation_kind") != "operator_bound":
                raise ValueError("configured monetary budget requires operator-bound per-call reservations")
        if decision_provider is not None and callable(getattr(decision_provider, "assess", None)):
            quote = call_estimate(decision_provider, "SYSTEM_ONE_ASSESSMENT", {}, [], 0)
            if quote.get("reservation_kind") != "operator_bound":
                raise ValueError("configured monetary budget requires operator-bound per-call reservations")

    def start_attempt(task: dict, attempt_index: int) -> dict:
        task_id = task["task_id"]
        evidence = evidence_cache[task_id]
        kind = task.get("task_kind", "SPECIALIST_FINDINGS")
        is_check = kind == "DETERMINISTIC_CHECK"
        target = check_adapter if is_check else provider
        method = "__call__" if is_check else "review"
        if target is None or not callable(target if is_check else getattr(target, "review", None)):
            return {
                "task_id": task_id,
                "status": "SKIPPED",
                "error_code": "CHECK_ADAPTER_UNAVAILABLE" if is_check else "PROVIDER_UNAVAILABLE",
                "attempts": attempt_index,
            }
        if kind == "SPECIALIST_FINDINGS":
            _validate_context_followup_task(task, ledger, snapshot, obligation_by_id, task_by_id)
            _validate_bound_specialist_input(task, snapshot, profile, evidence)
        required_size = review_input_size(task, evidence)
        task_input_ceiling = int(limits["max_input_bytes_per_task"]) if is_check else input_ceiling
        if required_size > task_input_ceiling:
            return {
                "task_id": task_id,
                "status": "SKIPPED",
                "error_code": "INPUT_BYTE_LIMIT_EXCEEDED",
                "attempts": attempt_index,
            }
        reservation_key = f"{task_id}:{'check' if is_check else 'review'}:{attempt_index}"
        try:
            reservation = reserve_provider_call(
                reservation_key,
                target,
                kind,
                task,
                evidence,
                len(_canonical({"task": task, "evidence": evidence})) if is_check else required_size,
            )
        except BudgetExhausted as exc:
            return {
                "task_id": task_id,
                "status": "SKIPPED",
                "error_code": str(exc),
                "input_hash": _hash(evidence),
                "attempts": attempt_index,
            }
        except ValueError as exc:
            return {
                "task_id": task_id,
                "status": "INVALID",
                "error_code": "INVALID_PROVIDER_ESTIMATE",
                "error_summary": type(exc).__name__,
                "attempts": attempt_index,
            }
        invocation_limits = {**remaining_call_limits(), "attempt_index": attempt_index}
        args = (task, snapshot, profile, invocation_limits) if is_check else (task, evidence, invocation_limits)
        try:
            invocation = IsolatedInvocation(
                target,
                method,
                args,
                deadline_seconds=min(
                    float(reservation.get("deadline_seconds", remaining_call_limits()["deadline_seconds"])),
                    remaining_call_limits()["deadline_seconds"],
                ),
                output_limit=int(reservation["max_output_bytes"]),
            )
        except Exception as exc:
            try:
                budget.settle(reservation_key, output_bytes=None, usage={}, status="FAILED")
            except (ValueError, KeyError):
                pass
            return {
                "task_id": task_id,
                "status": "FAILED",
                "error_code": "WORKER_START_FAILED",
                "error_summary": type(exc).__name__,
                "attempts": attempt_index + 1,
                "input_hash": _hash(evidence),
            }
        return {
            "task": task,
            "task_id": task_id,
            "kind": kind,
            "is_check": is_check,
            "target": target,
            "reservation_key": reservation_key,
            "reservation": reservation,
            "invocation": invocation,
            "evidence": evidence,
            "attempt_index": attempt_index,
            "started_at": _now(),
        }

    def finish_attempt(prepared: dict) -> dict:
        task = prepared["task"]
        task_id = prepared["task_id"]
        evidence = prepared["evidence"]
        key = prepared["reservation_key"]
        invocation = prepared["invocation"]
        try:
            response = invocation.result()
            payload, usage, provenance = _unwrap(response)
            if len(_canonical(response)) > int(prepared["reservation"]["max_output_bytes"]):
                raise ValueError("output_limit")
            check_input_evidence_ids = None
            if prepared["is_check"]:
                if payload.get("outcome") not in {"PASS", "FINDINGS", "UNKNOWN", "ERROR"}:
                    raise ValueError("invalid_check")
                check_input_evidence_ids = validated_check_evidence(task, payload)
            elif not all(
                isinstance(payload.get(name), list)
                for name in ("finding_candidates", "context_gap_proposals", "coverage_notes")
            ):
                raise ValueError("invalid_specialist_result")
            else:
                quarantined = list(payload.get("quarantined_items", []))
                for field in ("specific_strengths", "future_guidance"):
                    rows = payload.get(field, [])
                    if not isinstance(rows, list):
                        raise ValueError("invalid_specialist_notes")
                    accepted = []
                    for index, note in enumerate(rows):
                        valid = (
                            isinstance(note, dict)
                            and set(note) == {"unit_id", "title", "observation", "detail", "evidence_refs"}
                            and note.get("unit_id") in set(task.get("unit_ids", []))
                            and all(
                                isinstance(note.get(name), str)
                                and note[name].strip()
                                and len(note[name].encode("utf-8")) <= (256 if name == "title" else 2000)
                                for name in ("title", "observation", "detail")
                            )
                            and isinstance(note.get("evidence_refs"), list)
                            and 1 <= len(note["evidence_refs"]) <= 20
                            and all(isinstance(ref, str) for ref in note["evidence_refs"])
                            and set(note["evidence_refs"]).issubset(
                                {item.get("evidence_id") for item in evidence if item.get("evidence_id")}
                            )
                        )
                        if valid:
                            accepted.append(note)
                        else:
                            quarantined.append(
                                {
                                    "kind": field,
                                    "index": index,
                                    "reason_code": "invalid_report_note",
                                    "item_hash": _hash(note),
                                }
                            )
                    payload[field] = accepted
                payload["quarantined_items"] = quarantined
            budget.settle(key, output_bytes=len(_canonical(response)), usage=usage, status="SUCCEEDED")
            return {
                "task_id": task_id,
                "task_kind": prepared["kind"],
                "lens": task.get("lens"),
                "unit_ids": list(task.get("unit_ids", [])),
                "status": "SUCCEEDED",
                "input_hash": _hash(
                    {
                        "evidence": _hash(evidence),
                        "snapshot_hash": snapshot.get("snapshot_hash"),
                        "check_binding_id": task.get("check_binding_id"),
                        "check_evidence_ids": check_input_evidence_ids,
                    }
                    if prepared["is_check"]
                    else evidence
                ),
                "input_evidence_ids": check_input_evidence_ids
                if prepared["is_check"]
                else [item.get("evidence_id") for item in evidence if item.get("evidence_id")],
                "output_hash": _hash(payload),
                "payload": payload,
                "quarantined_items": list(payload.get("quarantined_items", [])),
                "source_contract_version": payload.get("source_contract_version"),
                "usage": usage,
                "provenance": provenance,
                "attempts": prepared["attempt_index"] + 1,
                "context_omissions": list(task.get("context_omissions", [])),
                "required_context_omissions": list(task.get("required_context_omissions", [])),
                "started_at": prepared["started_at"],
                "finished_at": _now(),
            }
        except Exception as exc:
            meta = getattr(exc, "meta", {})
            usage = meta.get("usage", {}) if isinstance(meta, dict) else {}
            try:
                budget.settle(
                    key,
                    output_bytes=meta.get("actual_output_bytes") if isinstance(meta, dict) else None,
                    usage=usage,
                    status="INVALID" if isinstance(exc, ValueError) else "FAILED",
                )
            except (ValueError, KeyError):
                pass
            return {
                "task_id": task_id,
                "task_kind": task.get("task_kind"),
                "lens": task.get("lens"),
                "unit_ids": list(task.get("unit_ids", [])),
                "status": "INVALID"
                if isinstance(exc, ValueError) or getattr(exc, "remote_type", "") == "OutputLimitError"
                else "TIMED_OUT"
                if getattr(exc, "remote_type", "") == "TimeoutError"
                else "FAILED",
                "error_code": "INVALID_PROVIDER_RESULT" if isinstance(exc, ValueError) else str(exc)[:120],
                "error_summary": type(exc).__name__,
                "provider_error_meta": meta if isinstance(meta, dict) else {},
                "input_hash": _hash(evidence),
                "input_evidence_ids": []
                if prepared["is_check"]
                else [item.get("evidence_id") for item in evidence if item.get("evidence_id")],
                "attempts": prepared["attempt_index"] + 1,
                "started_at": prepared["started_at"],
                "finished_at": _now(),
            }

    max_workers = int(limits["max_concurrent_scopes"])
    max_context = int(limits["max_context_bytes"])
    used_context = 0
    ledger["outputs"] = task_results
    ledger["planned_tasks"] = [t["task_id"] for t in tasks]
    checkpoint()

    queue: list[tuple[dict, int]] = []
    for task in pending:
        old = task_results.get(task["task_id"], {})
        attempts_done = int(old.get("attempts", 0)) if isinstance(old, dict) else 0
        prefix = task["task_id"] + ":"
        reserved_attempts = [
            int(key.rsplit(":", 1)[-1]) + 1
            for key in budget.state["reservations"]
            if key.startswith(prefix)
            and key.rsplit(":", 1)[0].endswith((":review", ":check"))
            and key.rsplit(":", 1)[-1].isdigit()
        ]
        attempts_done = max([attempts_done, *reserved_attempts])
        if attempts_done < 1 + int(limits["max_retries_per_task"]):
            queue.append((task, attempts_done))
        elif attempts_done and task["task_id"] not in task_results:
            task_results[task["task_id"]] = {
                "task_id": task["task_id"],
                "task_kind": task.get("task_kind"),
                "lens": task.get("lens"),
                "unit_ids": list(task.get("unit_ids", [])),
                "status": "FAILED",
                "error_code": "INTERRUPTED_UNKNOWN",
                "input_evidence_ids": [],
                "attempts": attempts_done,
                **(
                    {
                        "request_input_contract": task["request_input_contract"],
                        "unit_evidence_bindings": task["unit_evidence_bindings"],
                    }
                    if task.get("request_input_contract") == review_contracts.SPECIALIST_INPUT_V2
                    else {}
                ),
                **({"context_followup": task["context_followup"]} if "context_followup" in task else {}),
            }
    active: dict[int, dict] = {}

    def record_task_outcome(task: dict, outcome: dict, reservation_key: str | None = None) -> None:
        with state_lock:
            if task.get("request_input_contract") == review_contracts.SPECIALIST_INPUT_V2:
                outcome = {
                    **outcome,
                    "request_input_contract": task["request_input_contract"],
                    "unit_evidence_bindings": task["unit_evidence_bindings"],
                }
            if "context_followup" in task:
                outcome = {**outcome, "context_followup": task["context_followup"]}
            task_results[task["task_id"]] = outcome
            ledger["outputs"] = task_results
            if reservation_key:
                ledger.setdefault("invocations", []).append(
                    {
                        "reservation_key": reservation_key,
                        "task_id": task["task_id"],
                        "status": outcome.get("status"),
                        "input_hash": outcome.get("input_hash"),
                        "output_hash": outcome.get("output_hash"),
                        "provider_error_meta": outcome.get("provider_error_meta", {}),
                        "attempt": outcome.get("attempts"),
                        "at": outcome.get("finished_at", _now()),
                    }
                )
            checkpoint()

    while queue or active:
        while queue and len(active) < max_workers and budget.remaining_seconds() > 0:
            task, attempt_index = queue.pop(0)
            evidence = evidence_cache[task["task_id"]]
            estimated_size = review_input_size(task, evidence)
            if used_context + estimated_size > max_context:
                record_task_outcome(
                    task,
                    {
                        "task_id": task["task_id"],
                        "status": "SKIPPED",
                        "error_code": "RUN_CONTEXT_BUDGET_EXHAUSTED",
                        "attempts": attempt_index,
                    },
                )
                continue
            prepared = start_attempt(task, attempt_index)
            if "invocation" not in prepared:
                record_task_outcome(task, prepared)
                continue
            used_context += int(prepared["reservation"].get("input_bytes", estimated_size))
            active[id(prepared["invocation"])] = prepared

        completed_ids = []
        for active_key, prepared in list(active.items()):
            invocation = prepared["invocation"]
            if invocation.poll():
                outcome = finish_attempt(prepared)
                completed_ids.append(active_key)
                attempt_index = prepared["attempt_index"]
                if (
                    outcome.get("status") in {"FAILED", "INVALID", "TIMED_OUT"}
                    and attempt_index < int(limits["max_retries_per_task"])
                    and budget.remaining_seconds() > 0
                ):
                    queue.append((prepared["task"], attempt_index + 1))
                    with state_lock:
                        ledger.setdefault("invocations", []).append(
                            {
                                "reservation_key": prepared["reservation_key"],
                                "task_id": prepared["task_id"],
                                "status": outcome.get("status"),
                                "provider_error_meta": outcome.get("provider_error_meta", {}),
                                "attempt": attempt_index + 1,
                                "at": _now(),
                            }
                        )
                        checkpoint()
                else:
                    record_task_outcome(prepared["task"], outcome, prepared["reservation_key"])
        for key in completed_ids:
            active.pop(key, None)

        if budget.remaining_seconds() <= 0:
            for prepared in active.values():
                prepared["invocation"].cancel()
                outcome = {
                    "task_id": prepared["task_id"],
                    "status": "TIMED_OUT",
                    "error_code": "DEADLINE_EXCEEDED",
                    "error_summary": "TimeoutError",
                    "input_hash": _hash(prepared["evidence"]),
                    "attempts": prepared["attempt_index"] + 1,
                    "finished_at": _now(),
                }
                try:
                    budget.settle(prepared["reservation_key"], output_bytes=None, usage={}, status="TIMED_OUT")
                except (ValueError, KeyError):
                    pass
                record_task_outcome(prepared["task"], outcome, prepared["reservation_key"])
            active.clear()
            for task, attempt_index in queue:
                record_task_outcome(
                    task,
                    {
                        "task_id": task["task_id"],
                        "status": "SKIPPED",
                        "error_code": "DEADLINE_EXHAUSTED",
                        "attempts": attempt_index,
                    },
                )
            queue.clear()
        elif not completed_ids and active:
            wait_for_any(
                [prepared["invocation"] for prepared in active.values()],
                timeout=budget.remaining_seconds(),
            )

    ledger["outputs"] = task_results
    checkpoint()

    findings: list[dict] = list(ledger.get("findings", []))
    context_gaps: list[dict] = list(ledger.get("context_gaps", []))
    existing_gap_ids = {gap.get("proposal_id") for gap in context_gaps if isinstance(gap, dict)}
    for task in tasks:
        for evidence_id in task.get("required_context_omissions", []):
            gap_id = f"{task['task_id']}:required-context-omission:{evidence_id}"
            if gap_id in existing_gap_ids:
                continue
            evidence_item = snapshot.get("evidence", {}).get(evidence_id, {})
            context_gaps.append(
                {
                    "task_id": task["task_id"],
                    "proposal_id": gap_id,
                    "status": "VALID_UNRESOLVED",
                    "reason_code": "REQUIRED_CONTEXT_OMITTED_BY_INPUT_LIMIT",
                    "path": evidence_item.get("path"),
                    "evidence_id": evidence_id,
                    "affected_obligation_ids": list(task.get("obligation_ids", [task.get("obligation_id")])),
                    "affected_unit_ids": list(task.get("unit_ids", [])),
                    "required_lens": task.get("lens"),
                }
            )
            existing_gap_ids.add(gap_id)
    gap_obligations: dict[str, list[str]] = {}
    for gap in context_gaps:
        if gap.get("status") == "RESOLVED_BY_FOLLOWUP":
            continue
        for oid in gap.get("affected_obligation_ids", []):
            gap_obligations.setdefault(oid, []).append(gap["proposal_id"])
    known_ids = {f.get("finding_id") for f in findings}
    evidence_map = snapshot.get("evidence", {}) if isinstance(snapshot.get("evidence", {}), dict) else {}
    unit_map = {u.get("unit_id"): u for u in snapshot.get("inventory", []) if isinstance(u, dict)}

    def run_followup(task: dict, evidence: list[dict]) -> dict:
        task_id = task["task_id"]
        evidence_cache[task_id] = evidence
        max_attempts = 1 + int(limits["max_retries_per_task"])
        outcome: dict = {"task_id": task_id, "status": "SKIPPED", "error_code": "DEADLINE_EXHAUSTED", "attempts": 0}
        attempt_prefix = task_id + ":review:"
        prior_attempts = [
            int(key[len(attempt_prefix) :]) + 1
            for key in budget.state["reservations"]
            if key.startswith(attempt_prefix) and key[len(attempt_prefix) :].isdigit()
        ]
        for attempt in range(max(prior_attempts, default=0), max_attempts):
            if budget.remaining_seconds() <= 0:
                break
            prepared = start_attempt(task, attempt)
            if "invocation" not in prepared:
                outcome = prepared
                break
            invocation = prepared["invocation"]
            while not invocation.poll() and budget.remaining_seconds() > 0:
                invocation.wait_for_ready(timeout=budget.remaining_seconds())
            if invocation.poll():
                outcome = finish_attempt(prepared)
            else:
                invocation.cancel()
                try:
                    budget.settle(prepared["reservation_key"], output_bytes=None, usage={}, status="TIMED_OUT")
                except (ValueError, KeyError):
                    pass
                outcome = {
                    "task_id": task_id,
                    "task_kind": task.get("task_kind"),
                    "status": "TIMED_OUT",
                    "error_code": "DEADLINE_EXHAUSTED",
                    "attempts": attempt + 1,
                    "input_evidence_ids": [item.get("evidence_id") for item in evidence if item.get("evidence_id")],
                    "input_hash": _hash(evidence),
                }
            record_task_outcome(task, outcome, prepared["reservation_key"])
            if outcome.get("status") == "SUCCEEDED" or attempt + 1 >= max_attempts:
                break
        return outcome

    for task in tasks:
        result = task_results.get(task["task_id"], {})
        if result.get("status") != "SUCCEEDED" or task["task_id"] in ledger.get("reconciled_tasks", []):
            continue
        payload = result.get("payload", {})
        task_units = set(task.get("unit_ids", task.get("scope_unit_ids", [])))
        for index, proposal in enumerate(payload.get("context_gap_proposals", [])):
            record = {"task_id": task["task_id"], "proposal_id": f"{task['task_id']}:gap:{index}", "proposal": proposal}
            valid = isinstance(proposal, dict) and proposal.get("evidence_kind") in {
                "caller",
                "implementation",
                "test",
                "configuration",
                "contract",
                "trust_boundary",
                "provenance",
                "other",
            }
            target = proposal.get("target", {}) if isinstance(proposal, dict) else {}
            if (
                not isinstance(target, dict)
                or set(target) != {"target_unit_id", "target_path", "target_symbol"}
                or sum(bool(target.get(k)) for k in target) != 1
            ):
                valid = False
            target_unit = (
                target.get("target_unit_id")
                if isinstance(target, dict) and isinstance(target.get("target_unit_id"), str)
                else None
            )
            if target_unit is None and isinstance(target, dict) and target.get("target_path"):
                candidates = [uid for uid in task_units if unit_map.get(uid, {}).get("path") == target["target_path"]]
                target_unit = candidates[0] if len(candidates) == 1 else None
            lens = (
                proposal.get("required_lens")
                if isinstance(proposal, dict) and isinstance(proposal.get("required_lens"), str)
                else None
            )
            refs = proposal.get("related_evidence_ids", []) if isinstance(proposal, dict) else []
            valid_target = bool(
                isinstance(target, dict)
                and all(target.get(k) is None or isinstance(target.get(k), str) for k in target)
                and (
                    target_unit
                    or target.get("target_symbol")
                    or (
                        isinstance(target.get("target_path"), str)
                        and target["target_path"]
                        and not target["target_path"].startswith("/")
                        and ".." not in target["target_path"].split("/")
                    )
                )
            )
            valid = bool(
                valid
                and valid_target
                and lens
                in {"correctness", "tests", "design", "security", "performance", "maintainability", "project_specific"}
                and isinstance(proposal.get("rationale"), str)
                and proposal.get("rationale")
                and isinstance(refs, list)
                and all(isinstance(ref, str) for ref in refs)
                and set(refs).issubset(set(task.get("evidence_ids", [])))
                and refs
            )
            record["status"] = "VALID_UNRESOLVED" if valid else "INVALID"
            record["resolved_unit_id"] = target_unit if valid else None
            target_obligations = [
                oid
                for oid in task.get("obligation_ids", [task["obligation_id"]])
                if lens is None or obligation_by_id[oid].get("lens") == lens
            ]
            record["affected_obligation_ids"] = target_obligations or task.get(
                "obligation_ids", [task["obligation_id"]]
            )
            prior_index = next(
                (i for i, existing in enumerate(context_gaps) if existing.get("proposal_id") == record["proposal_id"]),
                None,
            )
            if prior_index is None:
                context_gaps.append(record)
            else:
                context_gaps[prior_index].update(record)
            ledger["context_gaps"] = context_gaps
            checkpoint()
            if valid and callable(context_retriever) and ":followup:" not in task["task_id"]:
                retrieval_key = f"{record['proposal_id']}:context-retrieval"
                reserved_bytes = max(
                    0,
                    min(
                        int(limits["max_input_bytes_per_task"]),
                        int(limits["max_output_bytes_per_task"]),
                        int(limits["max_context_bytes"]) - budget.summary()["context_bytes_reserved"],
                    ),
                )
                retrieved = None
                try:
                    if reserved_bytes <= 0:
                        raise BudgetExhausted("CONTEXT_BYTE_BUDGET_EXHAUSTED")
                    budget.reserve_retrieval(retrieval_key, reserved_bytes)
                    cached = ledger.get("retrieved_context", {}).get(record["proposal_id"])
                    if isinstance(cached, dict):
                        retrieved = cached.get("result")
                        fetched = cached.get("evidence", [])
                    else:
                        retrieval_limits = {
                            **remaining_call_limits(),
                            "max_bytes": reserved_bytes,
                            "max_retrieval_bytes": reserved_bytes,
                            "context_bytes_remaining": reserved_bytes,
                            "max_result_bytes": int(limits["max_output_bytes_per_task"]),
                        }
                        invocation = IsolatedInvocation(
                            context_retriever,
                            "__call__",
                            (
                                snapshot,
                                profile,
                                {**proposal, "_proposal_id": record["proposal_id"], "_task_id": task["task_id"]},
                                retrieval_limits,
                            ),
                            deadline_seconds=budget.remaining_seconds(),
                            output_limit=int(limits["max_output_bytes_per_task"]),
                        )
                        while not invocation.poll() and budget.remaining_seconds() > 0:
                            invocation.wait_for_ready(timeout=budget.remaining_seconds())
                        if invocation.poll():
                            retrieved = invocation.result()
                        else:
                            invocation.cancel()
                            raise BudgetExhausted("DEADLINE_EXHAUSTED")
                        fetched = retrieved.get("evidence", []) if isinstance(retrieved, dict) else []
                        if isinstance(fetched, dict):
                            fetched = [fetched]
                        elif fetched is None:
                            fetched = []
                    retrieval_envelope_bytes = len(_canonical(retrieved))
                    if retrieval_envelope_bytes > int(limits["max_output_bytes_per_task"]):
                        raise BudgetExhausted("OUTPUT_BYTE_LIMIT_EXCEEDED")
                    if not isinstance(retrieved, dict) or retrieved.get("status") not in {
                        "RESOLVED",
                        "PARTIAL",
                        "UNRESOLVED",
                    }:
                        raise ValueError("invalid_context_retrieval_result")
                    if not isinstance(fetched, list):
                        raise ValueError("invalid_context_retrieval_evidence")
                    target_path = target.get("target_path") if isinstance(target, dict) else None
                    patterns = profile.get("retrieval_context_patterns") or profile.get("context_paths") or []
                    if not isinstance(patterns, list):
                        patterns = []
                    verified, byte_count = [], 0
                    for item in fetched:
                        if not isinstance(item, dict):
                            raise ValueError("invalid_context_retrieval_evidence")
                        content = item.get("content")
                        path = item.get("path")
                        if not isinstance(content, str) or not isinstance(path, str):
                            raise ValueError("invalid_context_retrieval_evidence")
                        raw_bytes = content.encode("utf-8")
                        byte_count += len(raw_bytes)
                        if (
                            item.get("snapshot_id") != snapshot.get("snapshot_id")
                            or item.get("trust") not in {"repository_evidence", "trusted_policy"}
                            or item.get("source_kind") != "repository_file"
                            or item.get("source_revision") not in {snapshot.get("base_sha"), snapshot.get("head_sha")}
                            or not isinstance(item.get("content_hash"), str)
                            or hashlib.sha256(raw_bytes).hexdigest() != item.get("content_hash")
                            or not isinstance(item.get("evidence_id"), str)
                            or item.get("evidence_id")
                            != "ev-"
                            + hashlib.sha256(
                                _canonical(
                                    {
                                        "snapshot_id": snapshot.get("snapshot_id"),
                                        "revision": item.get("source_revision"),
                                        "path": path,
                                        "hash": item.get("content_hash"),
                                    }
                                )
                            ).hexdigest()[:24]
                            or item.get("proposal_id") not in (None, record["proposal_id"])
                            or item.get("task_id") not in (None, task["task_id"])
                            or not any(fnmatch.fnmatchcase(path, pat) for pat in patterns if isinstance(pat, str))
                            or (target_path and path != target_path)
                        ):
                            raise ValueError("context_retrieval_evidence_binding_failed")
                        verified.append(item)
                    verified = _merge_evidence_rows(verified)
                    if byte_count > reserved_bytes:
                        raise BudgetExhausted("CONTEXT_RETRIEVAL_BYTE_LIMIT_EXCEEDED")
                    budget.settle(retrieval_key, output_bytes=byte_count, usage={}, status=retrieved["status"])
                    record["retrieval_status"] = retrieved["status"]
                    record["retrieval_reason"] = retrieved.get("reason")
                    record["retrieved_evidence_ids"] = [item["evidence_id"] for item in verified]
                    record["retrieved_bytes"] = byte_count
                    record["retrieval_envelope_bytes"] = retrieval_envelope_bytes
                    if not isinstance(cached, dict):
                        ledger.setdefault("retrieved_context", {})[record["proposal_id"]] = {
                            "result": retrieved,
                            "evidence": verified,
                        }
                    for item in verified:
                        existing = evidence_map.get(item["evidence_id"])
                        if existing is not None and not _same_evidence_content(existing, item):
                            raise ValueError("evidence_identity_conflict")
                        evidence_map.setdefault(item["evidence_id"], item)
                    checkpoint()
                except Exception as exc:
                    record["retrieval_status"] = "UNRESOLVED"
                    record["retrieval_reason"] = str(exc)[:120]
                    try:
                        if (
                            retrieval_key in ledger["budget"]["reservations"]
                            and retrieval_key not in ledger["budget"]["settlements"]
                        ):
                            budget.settle(retrieval_key, output_bytes=None, usage={}, status="FAILED")
                    except (ValueError, KeyError):
                        pass

                if retrieved and retrieved.get("status") == "RESOLVED" and record.get("retrieved_evidence_ids"):
                    followup_id = f"{task['task_id']}:followup:{index}"
                    followup_obligation_id = f"context:{record['proposal_id']}"
                    followup_task = {
                        **task,
                        "task_id": followup_id,
                        "obligation_id": followup_obligation_id,
                        "obligation_ids": [followup_obligation_id],
                        "unit_ids": [target_unit] if target_unit else list(task_units),
                        "scope_unit_ids": [target_unit] if target_unit else list(task_units),
                        "evidence_ids": list(
                            dict.fromkeys(list(task.get("evidence_ids", [])) + record["retrieved_evidence_ids"])
                        ),
                        "context_gap_followup_for": record["proposal_id"],
                        "lens": lens,
                    }
                    followup_evidence = _merge_evidence_rows([
                        *evidence_cache.get(task["task_id"], []),
                        *(evidence_map[eid] for eid in record["retrieved_evidence_ids"]),
                    ])
                    try:
                        obligation = {
                            "obligation_id": followup_obligation_id,
                            "obligation_kind": "REQUIRED_CONTEXT",
                            "required": True,
                            "scope_unit_ids": followup_task["unit_ids"],
                            "lens": lens,
                            "parent_obligation_ids": list(record["affected_obligation_ids"]),
                            "context_gap_id": record["proposal_id"],
                            "retrieved_evidence_ids": list(record["retrieved_evidence_ids"]),
                        }
                        followup_task["context_followup"] = _context_followup_metadata(
                            task=followup_task,
                            record=record,
                            obligation=obligation,
                            parent_task=task,
                            parent_result=task_results[task["task_id"]],
                            retrieved_entry=ledger.get("retrieved_context", {}).get(record["proposal_id"], {}),
                            snapshot_id=snapshot.get("snapshot_id"),
                        )
                        followup_task = _bind_specialist_input(
                            followup_task, snapshot, profile, followup_evidence
                        )
                        budget.reserve_followup(followup_id)
                        obligation_by_id[followup_obligation_id] = obligation
                        if not any(o.get("obligation_id") == followup_obligation_id for o in obligations):
                            obligations.append(obligation)
                        dynamic_obligations = ledger.setdefault("dynamic_obligations", [])
                        if not isinstance(dynamic_obligations, list):
                            raise ValueError("invalid_dynamic_obligation_ledger")
                        existing_obligation = next(
                            (item for item in dynamic_obligations if isinstance(item, dict) and item.get("obligation_id") == followup_obligation_id),
                            None,
                        )
                        if existing_obligation is None:
                            dynamic_obligations.append(obligation)
                        elif existing_obligation != obligation:
                            raise ValueError("resume context follow-up obligation mismatch")
                        prior_task = next((t for t in tasks if t.get("task_id") == followup_id), None)
                        if prior_task is None:
                            tasks.append(followup_task)
                            task_by_id[followup_id] = followup_task
                            ledger.setdefault("dynamic_tasks", []).append(followup_task)
                            ledger.setdefault("planned_task_inputs", {})[followup_id] = _task_input_provenance(
                                followup_task
                            )
                        else:
                            if prior_task != followup_task:
                                raise ValueError("resume followup task binding mismatch")
                            followup_task = prior_task
                        checkpoint()
                        followup_result = task_results.get(followup_id)
                        if not isinstance(followup_result, dict):
                            followup_result = run_followup(followup_task, followup_evidence)
                        followup_payload = followup_result.get("payload", {})
                        notes = followup_payload.get("coverage_notes", []) if isinstance(followup_payload, dict) else []
                        covered, note_observation = _coverage_note_observation(
                            notes,
                            notes_present=isinstance(followup_payload, dict) and "coverage_notes" in followup_payload,
                            scope_unit_ids=followup_task.get("unit_ids", []),
                            required_evidence_ids=record.get("retrieved_evidence_ids", []),
                            task_input_evidence_ids=followup_result.get("input_evidence_ids", []),
                            predicate_order="followup_resolution",
                        )
                        record["coverage_note_diagnostics"] = note_observation
                        if covered:
                            record["status"] = "RESOLVED_BY_FOLLOWUP"
                            record["followup_task_id"] = followup_id
                        else:
                            record["status"] = "VALID_UNRESOLVED"
                            record["followup_task_id"] = followup_id
                    except (BudgetExhausted, ValueError) as exc:
                        record["followup_error"] = str(exc)[:120]

            # The final gap map is rebuilt after all persisted/new proposals are reconciled.
        for index, raw in enumerate(payload.get("finding_candidates", [])):
            candidate_id = _hash({"task_id": task["task_id"], "index": index, "raw": raw})[:24]
            if not isinstance(raw, dict):
                ledger.setdefault("candidate_records", []).append(
                    {
                        "candidate_id": candidate_id,
                        "task_id": task["task_id"],
                        "validation_state": "INVALID",
                        "validation_reason": "candidate_not_object",
                        "raw_hash": _hash(raw),
                    }
                )
                continue
            candidate = dict(raw)
            candidate["candidate_id"] = candidate_id
            candidate["task_id"] = task["task_id"]
            candidate["snapshot_id"] = snapshot.get("snapshot_id")
            task_units = set(task.get("unit_ids", task.get("scope_unit_ids", [])))
            refs = candidate.get("evidence_refs", [])
            supplied_ids = set(task.get("evidence_ids", []))
            valid_refs = [ref for ref in refs if isinstance(ref, str) and ref in supplied_ids and ref in evidence_map]
            location_valid, location, line, uid = validate_location(candidate, None, task_units, unit_map)
            if location.get("kind") == "file" and unit_map.get(uid):
                anchor = unit_map[uid].get("file_level_location")
                anchor_id = anchor.get("evidence_id") if isinstance(anchor, dict) else None
                anchor_hash = anchor.get("evidence_hash") if isinstance(anchor, dict) else None
                anchor_record = evidence_map.get(anchor_id) if isinstance(anchor_id, str) else None
                anchor_side = anchor.get("side") if isinstance(anchor, dict) else None
                expected_revision = snapshot.get("base_sha") if anchor_side == "BASE" else snapshot.get("head_sha")
                expected_source_kind = "base_file" if anchor_side == "BASE" else "head_file"
                anchor_valid = bool(
                    isinstance(anchor, dict)
                    and anchor.get("kind") == "file"
                    and anchor_side in {"BASE", "HEAD"}
                    and isinstance(anchor_id, str)
                    and isinstance(anchor_hash, str)
                    and re.fullmatch(r"[0-9a-f]{64}", anchor_hash)
                    and anchor_id in set(unit_map[uid].get("evidence_ids", []))
                    and anchor_id in supplied_ids
                    and anchor_id in valid_refs
                    and isinstance(anchor_record, dict)
                    and anchor_record.get("evidence_id") == anchor_id
                    and anchor_record.get("path") == anchor.get("path")
                    and anchor_record.get("source_revision") == expected_revision
                    and anchor_record.get("source_kind") == expected_source_kind
                    and anchor_record.get("snapshot_id") == snapshot.get("snapshot_id")
                    and anchor_record.get("content_hash") == anchor_hash
                    and anchor_record.get("content_truncated") is False
                )
                location_valid = location_valid and anchor_valid
            candidate["location"] = location
            candidate["unit_id"] = uid
            unit = unit_map.get(uid)
            structurally_valid = bool(
                unit
                and uid in task_units
                and candidate.get("observation")
                and candidate.get("consequence")
                and candidate.get("rule_or_contract")
                and refs
                and len(valid_refs) == len(refs)
                and location_valid
            )
            candidate["validation_state"] = "VALID" if structurally_valid else "NEEDS_CONTEXT"
            candidate["validation_reason"] = (
                "snapshot_location_and_evidence_validated"
                if structurally_valid
                else "location_or_evidence_not_validated"
            )
            fid = stable_candidate_id(snapshot.get("snapshot_id", ""), candidate)
            ledger.setdefault("candidate_records", []).append(
                {
                    "candidate_id": candidate_id,
                    "finding_id": fid,
                    "task_id": task["task_id"],
                    "snapshot_id": snapshot.get("snapshot_id"),
                    "validation_state": candidate["validation_state"],
                    "validation_reason": candidate["validation_reason"],
                    "raw": candidate,
                }
            )
            known_ids.add(fid)
            assessment = None
            semantic_result = None
            reservation_key = None
            causal_roles_valid = False
            semantic_role_refs: set[str] = set()
            if structurally_valid and provider is not None and callable(getattr(provider, "adjudicate", None)):
                try:
                    adjudication_evidence = evidence_cache[task["task_id"]]
                    candidate_hash = _hash(candidate)
                    adjudication_input_hash = _hash(
                        {
                            "candidate": candidate,
                            "evidence": adjudication_evidence,
                            "semantic_contract_version": _ADJUDICATION_V3,
                            "semantic_rubric_version": _ADJUDICATION_RUBRIC,
                            "provider_identity_hash": _hash(provider_identity),
                        }
                    )
                    cached_assessment = ledger.get("adjudications", {}).get(candidate_id)
                    cached_payload = (
                        cached_assessment.get("assessment") if isinstance(cached_assessment, dict) else None
                    )
                    cached_provenance = (
                        cached_assessment.get("provenance") if isinstance(cached_assessment, dict) else None
                    )
                    reused_assessment = bool(
                        isinstance(cached_assessment, dict)
                        and cached_assessment.get("candidate_hash") == candidate_hash
                        and cached_assessment.get("input_hash") == adjudication_input_hash
                        and isinstance(cached_payload, dict)
                        and cached_payload.get("contract_version") == _ADJUDICATION_V3
                        and cached_payload.get("source_contract_version") == _ADJUDICATION_V3
                        and isinstance(cached_provenance, dict)
                        and cached_provenance.get("provider_rubric_version") == _ADJUDICATION_RUBRIC
                    )
                    if reused_assessment:
                        assessment = cached_assessment["assessment"]
                        semantic_usage = cached_assessment.get("usage", {})
                        semantic_provenance = cached_assessment.get("provenance", {})
                    else:
                        prefix = (
                            f"{task['task_id']}:adjudicate:{_ADJUDICATION_V3}:{_ADJUDICATION_RUBRIC}:"
                            f"{candidate_id}:attempt:"
                        )
                        attempts = [
                            int(key[len(prefix) :])
                            for key in budget.state["reservations"]
                            if key.startswith(prefix) and key[len(prefix) :].isdigit()
                        ]
                        adjudication_attempt = max(attempts, default=-1) + 1
                        reservation_key = f"{prefix}{adjudication_attempt}"
                        reservation = reserve_provider_call(
                            reservation_key,
                            provider,
                            "SEMANTIC_ADJUDICATION",
                            {**task, "candidate": candidate},
                            adjudication_evidence,
                            len(_canonical({"candidate": candidate, "evidence": adjudication_evidence})),
                        )
                        response = isolated_call(
                            provider,
                            "adjudicate",
                            (candidate, adjudication_evidence, remaining_call_limits()),
                            deadline_seconds=min(
                                float(reservation.get("deadline_seconds", remaining_call_limits()["deadline_seconds"])),
                                remaining_call_limits()["deadline_seconds"],
                            ),
                            output_limit=int(reservation["max_output_bytes"]),
                            lock=call_lock,
                        )
                        assessment, semantic_usage, semantic_provenance = _unwrap(response)
                    assessment_refs = assessment.get("evidence_refs", [])
                    delivered_ids = {
                        item.get("evidence_id")
                        for item in adjudication_evidence
                        if isinstance(item, dict) and isinstance(item.get("evidence_id"), str)
                    }
                    support_keys = ("observation_support", "consequence_support", "rule_connection_support")
                    if (
                        assessment.get("outcome") not in {"SUPPORTED", "NOT_SUPPORTED", "UNCERTAIN", "CONTRADICTED"}
                        or not isinstance(assessment_refs, list)
                        or any(not isinstance(ref, str) or ref not in delivered_ids for ref in assessment_refs)
                        or assessment.get("introducedness")
                        not in {"INTRODUCED", "REEXPOSED", "PRE_EXISTING", "UNKNOWN"}
                        or any(
                            assessment.get(k) not in {"SUPPORTED", "NOT_ESTABLISHED", "CONTRADICTED"}
                            for k in support_keys
                        )
                        or not isinstance(assessment.get("material_consequence"), bool)
                        or (assessment.get("outcome") == "SUPPORTED" and not assessment_refs)
                    ):
                        assessment = {"outcome": "UNCERTAIN"}
                    causal_roles_valid, semantic_role_refs = _validated_v3_causal_roles(
                        assessment,
                        adjudication_evidence,
                        evidence_map,
                        snapshot.get("snapshot_id"),
                        provider_identity,
                        semantic_provenance,
                    )
                    semantic_result = assessment
                    if not reused_assessment:
                        ledger.setdefault("adjudications", {})[candidate_id] = {
                            "candidate_hash": candidate_hash,
                            "input_hash": adjudication_input_hash,
                            "assessment": assessment,
                            "usage": semantic_usage,
                            "provenance": semantic_provenance,
                            "reservation_key": reservation_key,
                        }
                        checkpoint()
                        budget.settle(
                            reservation_key,
                            output_bytes=len(_canonical(response)),
                            usage=semantic_usage,
                            status="SUCCEEDED" if assessment.get("outcome") != "UNCERTAIN" else "INVALID",
                        )
                except Exception as exc:
                    if isinstance(exc, BudgetExhausted):
                        budget_code = str(exc)
                        safe_error_code = (
                            budget_code
                            if budget_code
                            in {
                                "CONTEXT_BYTE_BUDGET_EXHAUSTED",
                                "CONTEXT_RETRIEVAL_BUDGET_EXHAUSTED",
                                "CONTEXT_RETRIEVAL_BYTE_LIMIT_EXCEEDED",
                                "DEADLINE_EXHAUSTED",
                                "FOLLOWUP_TASK_BUDGET_EXHAUSTED",
                                "INPUT_BYTE_LIMIT_EXCEEDED",
                                "MONETARY_BOUND_UNAVAILABLE",
                                "MONETARY_BUDGET_EXHAUSTED",
                                "OUTPUT_BYTE_BUDGET_EXHAUSTED",
                                "OUTPUT_BYTE_LIMIT_EXCEEDED",
                                "PROVIDER_CALL_BUDGET_EXHAUSTED",
                            }
                            else type(exc).__name__
                        )
                    else:
                        safe_error_code = type(exc).__name__
                    assessment = {
                        "outcome": "UNCERTAIN",
                        "reason": type(exc).__name__,
                        "error_code": safe_error_code,
                    }
                    # Persist the failure on the finding even when reservation
                    # fails before a provider result or adjudication record exists.
                    # UNCERTAIN is deliberately unresolved and cannot support a blocker.
                    semantic_result = assessment
                    remote_meta = getattr(exc, "meta", {})
                    semantic_usage = remote_meta.get("usage", {}) if isinstance(remote_meta, dict) else {}
                    semantic_provenance = {"error_meta": remote_meta} if remote_meta else {}
                    if reservation_key is not None:
                        try:
                            budget.settle(
                                reservation_key,
                                output_bytes=remote_meta.get("actual_output_bytes")
                                if isinstance(remote_meta, dict)
                                else None,
                                usage=semantic_usage,
                                status="FAILED",
                            )
                        except (ValueError, KeyError):
                            pass
            else:
                semantic_usage, semantic_provenance = {}, {}
            introduced = (assessment or {}).get("introducedness", "UNKNOWN")
            causal_roles = (assessment or {}).get("causal_roles", {})
            causal_path_supported = bool(
                causal_roles_valid and all(causal_roles[role].get("support") == "SUPPORTED" for role in _CAUSAL_ROLES)
            )
            claim_supported = (
                structurally_valid
                and assessment
                and assessment.get("outcome") == "SUPPORTED"
                and causal_path_supported
                and all(
                    assessment.get(key) == "SUPPORTED" for key in ("observation_support", "rule_connection_support")
                )
            )
            claim_supported = bool(claim_supported and introduced in {"INTRODUCED", "REEXPOSED", "PRE_EXISTING"})
            supported = bool(claim_supported and introduced in {"INTRODUCED", "REEXPOSED"})
            materiality = (assessment or {}).get("material_consequence")
            blocking = bool(supported and materiality is True and assessment.get("consequence_support") == "SUPPORTED")
            unresolved = (
                not structurally_valid
                or assessment is None
                or not causal_roles_valid
                or not causal_path_supported
                or assessment.get("outcome") in {"UNCERTAIN", "CONTRADICTED"}
                or introduced == "UNKNOWN"
                or (assessment.get("outcome") == "SUPPORTED" and (not claim_supported or materiality is None))
            )
            status = (
                "ACCEPTED"
                if claim_supported
                else (
                    "NEEDS_EVIDENCE"
                    if not structurally_valid
                    else "CONTRADICTED"
                    if assessment and assessment.get("outcome") == "CONTRADICTED"
                    else "UNSUPPORTED"
                    if assessment and assessment.get("outcome") == "NOT_SUPPORTED"
                    else "NEEDS_EVIDENCE"
                )
            )
            location = dict(candidate.get("location", {})) if isinstance(candidate.get("location", {}), dict) else {}
            path = location.get("path") or candidate.get("path") or (unit.get("path") if unit else None)
            location["path"] = path
            location["side"] = location.get("side", "HEAD")
            if line is not None:
                location["line"] = line
            finding = {
                "finding_id": fid,
                "candidate_id": candidate_id,
                "task_id": task["task_id"],
                "snapshot_id": snapshot.get("snapshot_id"),
                "unit_id": uid,
                "location": location,
                "path": path,
                "title": str(candidate.get("title", "Unverified finding"))[:300],
                "observation": str(candidate.get("observation", ""))[:2000],
                "consequence": str(candidate.get("consequence", ""))[:2000],
                "rule_or_contract": str(candidate.get("rule_or_contract", ""))[:1000],
                "evidence_refs": sorted(set(valid_refs) | semantic_role_refs),
                "status": status,
                "severity": candidate.get("severity", "unknown"),
                "introducedness": introduced,
                "blocking_class": "BLOCKING" if blocking else "UNRESOLVED" if unresolved else "NON_BLOCKING",
                "blocking_rationale": "Evidence and semantic assessment support a material changed behavior or trusted policy consequence."
                if blocking
                else "Not established as a blocker by the bounded evidence and policy rules.",
                "semantic_assessment": semantic_result,
                "semantic_usage": semantic_usage,
                "semantic_provenance": semantic_provenance,
            }
            findings.append(finding)
        ledger.setdefault("reconciled_tasks", []).append(task["task_id"])

    # The per-candidate claim assessor is an optional, sequential shadow stage.
    # It runs after every primary adjudication has settled and before findings
    # are consolidated so it cannot consume primary call slots or affect the
    # deterministic reducer inputs.
    if max_claim_assessments > 0:
        claim_rows = ledger.setdefault("claim_assessments", {})
        if not isinstance(claim_rows, dict):
            raise ValueError("claim assessment ledger is invalid")
        finding_by_candidate = {
            item.get("candidate_id"): item
            for item in findings
            if isinstance(item, dict) and isinstance(item.get("candidate_id"), str)
        }
        record_by_candidate = {
            item.get("candidate_id"): item
            for item in ledger.get("candidate_records", [])
            if isinstance(item, dict) and isinstance(item.get("candidate_id"), str)
        }
        ordered_candidates = sorted(record_by_candidate)
        attempts_used = sum(
            1 for row in claim_rows.values() if isinstance(row, dict) and isinstance(row.get("reservation_key"), str)
        )

        def claim_not_run(candidate_id: str, reason: str, **details: Any) -> None:
            claim_rows[candidate_id] = {
                "contract_version": claim_assessor_contract,
                "candidate_id": candidate_id,
                "status": "NOT_RUN",
                "reason_code": reason,
                **details,
            }
            checkpoint()

        claim_identity = {
            "snapshot_id": snapshot.get("snapshot_id"),
            "snapshot_hash": snapshot.get("snapshot_hash"),
            "profile_id": profile.get("version", profile.get("profile_version")),
            "profile_hash": _hash(profile),
            "base_sha": snapshot.get("base_sha"),
            "head_sha": snapshot.get("head_sha"),
        }
        freshness_reserve_seconds = 16.0 if callable(freshness_check) else 0.0
        for candidate_id in ordered_candidates:
            prior = claim_rows.get(candidate_id)
            if isinstance(prior, dict):
                if prior.get("status") in {
                    "COMPLETE",
                    "PARTIAL",
                    "FAILED",
                    "NOT_RUN",
                    "INTERRUPTED_UNKNOWN",
                }:
                    continue
                # An unfinished row or reservation represents an uncertain
                # dispatch after a crash. Never reuse that paid-call key.
                prior_reservation = prior.get("reservation_key")
                if prior_reservation or prior.get("status") in {"RESERVED", "DISPATCHING", "PREPARING"}:
                    claim_rows[candidate_id] = {
                        **prior,
                        "status": "INTERRUPTED_UNKNOWN",
                        "reason_code": "PRIOR_SHADOW_ATTEMPT_UNSETTLED",
                    }
                    checkpoint()
                    continue

            candidate_record = record_by_candidate[candidate_id]
            finding = finding_by_candidate.get(candidate_id)
            primary = finding.get("semantic_assessment") if isinstance(finding, dict) else None
            if candidate_record.get("validation_state") != "VALID":
                claim_not_run(candidate_id, "PRIMARY_CANDIDATE_INVALID")
                continue
            if (
                not isinstance(finding, dict)
                or not isinstance(primary, dict)
                or primary.get("contract_version") != _ADJUDICATION_V3
                or primary.get("source_contract_version") != _ADJUDICATION_V3
            ):
                claim_not_run(candidate_id, "PRIMARY_ASSESSMENT_UNAVAILABLE")
                continue
            if attempts_used >= max_claim_assessments:
                claim_not_run(candidate_id, "CLAIM_ASSESSMENT_CAP_EXHAUSTED")
                continue

            raw_candidate = candidate_record.get("raw")
            if not isinstance(raw_candidate, dict):
                claim_not_run(candidate_id, "PRIMARY_CANDIDATE_INVALID")
                continue
            refs: list[str] = []
            original_refs = raw_candidate.get("evidence_refs")
            if not isinstance(original_refs, list):
                claim_not_run(candidate_id, "PRIMARY_CANDIDATE_INVALID")
                continue
            refs.extend(original_refs)
            refs.extend(primary.get("evidence_refs", []))
            role_records = primary.get("causal_roles", {})
            if isinstance(role_records, dict):
                for role_name in _CAUSAL_ROLES:
                    role = role_records.get(role_name)
                    if isinstance(role, dict) and isinstance(role.get("evidence_refs"), list):
                        refs.extend(role["evidence_refs"])
            refs = list(dict.fromkeys(ref for ref in refs if isinstance(ref, str)))
            cited_evidence = []
            invalid_binding = False
            for evidence_id in refs:
                item = evidence_map.get(evidence_id)
                if (
                    not isinstance(item, dict)
                    or item.get("evidence_id") != evidence_id
                    or item.get("snapshot_id") != snapshot.get("snapshot_id")
                ):
                    invalid_binding = True
                    break
                cited_evidence.append(item)
            if invalid_binding or not original_refs or any(ref not in refs for ref in original_refs):
                claim_not_run(candidate_id, "CANDIDATE_EVIDENCE_BINDING_INVALID")
                continue

            reservation_key = f"claim-assessment:{claim_assessor_contract}:{candidate_id}:attempt:0"
            if reservation_key in budget.state["reservations"]:
                # A reservation without a durable completed row is uncertain;
                # startup settlement above has already marked it unknown.
                attempts_used += 1
                claim_rows[candidate_id] = {
                    "contract_version": claim_assessor_contract,
                    "candidate_id": candidate_id,
                    "status": "INTERRUPTED_UNKNOWN",
                    "reason_code": "PRIOR_SHADOW_RESERVATION_EXISTS",
                    "attempt": 0,
                    "reservation_key": reservation_key,
                }
                checkpoint()
                continue

            remaining = budget.remaining_seconds() - freshness_reserve_seconds
            deadline_cap = min(8.0, remaining)
            if deadline_cap <= 0:
                claim_not_run(
                    candidate_id,
                    "FRESHNESS_BUDGET_RESERVED" if freshness_reserve_seconds else "DEADLINE_EXHAUSTED",
                    freshness_reserve_seconds=freshness_reserve_seconds,
                )
                continue

            primary_hash = _hash(primary)
            raw_refs = list(original_refs)
            claim_candidate = {
                key: raw_candidate.get(key)
                for key in ("candidate_id", "title", "observation", "consequence", "rule_or_contract")
            }
            claim_candidate["candidate_id"] = candidate_id
            claim_candidate["evidence_refs"] = raw_refs
            claim_rows[candidate_id] = {
                "contract_version": claim_assessor_contract,
                "candidate_id": candidate_id,
                "attempt": 0,
                "status": "PREPARING",
                "primary_assessment_hash": primary_hash,
                "candidate_hash": _hash(claim_candidate),
                "evidence_refs": refs,
                "implementation_hash": claim_assessor_code_hash,
            }
            checkpoint()
            prepared = None
            reservation = None
            try:
                call_limits = {
                    **limits,
                    "deadline_seconds": deadline_cap,
                }
                prepared = claim_assessor.prepare(
                    claim_candidate,
                    cited_evidence,
                    claim_identity,
                    call_limits,
                    primary_assessment=primary,
                )
                prepared_request = getattr(prepared, "request_bytes", None)
                prepared_hash = getattr(prepared, "request_hash", None)
                prepared_version = getattr(prepared, "contract_version", None)
                if (
                    not isinstance(prepared_request, bytes)
                    or not isinstance(prepared_hash, str)
                    or hashlib.sha256(prepared_request).hexdigest() != prepared_hash
                    or prepared_version != claim_assessor_contract
                    or prepared_version != "claim-assessment.2"
                ):
                    raise ValueError("invalid_prepared_claim_request")
                try:
                    prepared_body = json.loads(prepared_request.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
                    raise ValueError("invalid_prepared_claim_request") from None
                prepared_state = prepared_body.get("state") if isinstance(prepared_body, dict) else None
                prepared_candidate = prepared_state.get("candidate") if isinstance(prepared_state, dict) else None
                prepared_evidence = prepared_state.get("cited_evidence") if isinstance(prepared_state, dict) else None
                prepared_questions = prepared_body.get("questions") if isinstance(prepared_body, dict) else None
                prepared_primary = (
                    prepared_state.get("primary_assessment") if isinstance(prepared_state, dict) else None
                )
                question_pairs = getattr(prepared, "question_ids", None)
                introducedness_available = getattr(prepared, "introducedness_available", None)
                required_dimensions = {
                    "observation_support",
                    "consequence_support",
                    "rule_connection_support",
                    "materiality",
                    "missing_context",
                    "introducedness",
                }
                prepared_question_map = {}
                prepared_question_ids_valid = False
                if (
                    isinstance(question_pairs, tuple)
                    and isinstance(introducedness_available, bool)
                    and all(
                        isinstance(pair, tuple)
                        and len(pair) == 2
                        and all(isinstance(value, str) and value for value in pair)
                        for pair in question_pairs
                    )
                ):
                    prepared_question_map = dict(question_pairs)
                    expected_question_ids = {
                        question_id
                        for dimension, question_id in prepared_question_map.items()
                        if introducedness_available or dimension != "introducedness"
                    }
                    prepared_question_ids_valid = bool(
                        len(prepared_question_map) == len(question_pairs)
                        and len(set(prepared_question_map.values())) == len(prepared_question_map)
                        and set(prepared_question_map) == required_dimensions
                        and isinstance(prepared_questions, dict)
                        and bool(prepared_questions)
                        and all(isinstance(question, dict) for question in prepared_questions.values())
                        and set(prepared_questions) == expected_question_ids
                    )
                if (
                    not isinstance(prepared_state, dict)
                    or prepared_state.get("assessment_contract_version") != prepared_version
                    or prepared_state.get("assessment_identity") != claim_identity
                    or prepared_candidate != claim_candidate
                    or prepared_primary != primary
                    or not isinstance(prepared_evidence, list)
                    or [item.get("evidence_id") for item in prepared_evidence if isinstance(item, dict)] != refs
                    or not isinstance(prepared_questions, dict)
                    or not prepared_questions
                    or not prepared_question_ids_valid
                    or getattr(prepared, "candidate_hash", None) != _claim_adapter_hash(prepared_candidate)
                    or getattr(prepared, "evidence_hash", None) != _claim_adapter_hash(prepared_evidence)
                    or getattr(prepared, "question_hash", None) != _claim_adapter_hash(prepared_questions)
                    or getattr(prepared, "primary_assessment_hash", None) != _claim_adapter_hash(prepared_primary)
                ):
                    raise ValueError("invalid_prepared_claim_binding")
                # Preparation and quote are local but may consume wall time.
                remaining = budget.remaining_seconds() - freshness_reserve_seconds
                deadline_cap = min(8.0, remaining)
                if deadline_cap <= 0:
                    raise BudgetExhausted(
                        "FRESHNESS_BUDGET_RESERVED" if freshness_reserve_seconds else "DEADLINE_EXHAUSTED"
                    )
                call_limits = {**limits, "deadline_seconds": deadline_cap}
                estimate = claim_assessor.estimate_prepared(prepared, call_limits)
                if (
                    not isinstance(estimate, dict)
                    or estimate.get("provider_calls") != 1
                    or estimate.get("input_bytes") != len(prepared_request)
                    or estimate.get("max_output_bytes") != limits["max_output_bytes_per_task"]
                    or isinstance(estimate.get("provider_response_bytes"), bool)
                    or not isinstance(estimate.get("provider_response_bytes"), int)
                    or not 0 < estimate["provider_response_bytes"] <= limits["max_output_bytes_per_task"]
                    or isinstance(estimate.get("deadline_seconds"), bool)
                    or not isinstance(estimate.get("deadline_seconds"), (int, float))
                    or not math.isfinite(estimate["deadline_seconds"])
                    or not 0 < estimate["deadline_seconds"] <= deadline_cap
                ):
                    raise ValueError("invalid_claim_assessment_quote")
                estimate = {**estimate, "max_cost_microunits": None}
                # The process result has its own serialized IPC ceiling; the
                # transport's raw response ceiling remains separately recorded.
                raw_response_cap = estimate["provider_response_bytes"]
                ipc_cap = int(estimate["max_output_bytes"])
                claim_rows[candidate_id].update(
                    {
                        "status": "RESERVED",
                        "request_hash": prepared_hash,
                        "candidate_hash": getattr(prepared, "candidate_hash", None),
                        "question_hash": getattr(prepared, "question_hash", None),
                        "evidence_hash": getattr(prepared, "evidence_hash", None),
                        "primary_assessment_hash": getattr(prepared, "primary_assessment_hash", primary_hash),
                        "provider_response_bytes_reserved": raw_response_cap,
                        "ipc_output_bytes_reserved": ipc_cap,
                        "input_bytes_reserved": estimate["input_bytes"],
                        "reservation_key": reservation_key,
                        "quote_deadline_seconds": estimate["deadline_seconds"],
                    }
                )
                checkpoint()
                reservation = budget.reserve(reservation_key, estimate, kind="claim_assessment")
                claim_rows[candidate_id]["status"] = "DISPATCHING"
                checkpoint()
                # Retain a 16 second tail for the independent final freshness
                # check. A started shadow call cannot consume that opportunity.
                remaining = budget.remaining_seconds() - freshness_reserve_seconds
                dispatch_deadline = min(8.0, float(reservation["deadline_seconds"]), remaining)
                if dispatch_deadline <= 0:
                    raise BudgetExhausted(
                        "FRESHNESS_BUDGET_RESERVED" if freshness_reserve_seconds else "DEADLINE_EXHAUSTED"
                    )
                started = time.monotonic()
                response = isolated_call(
                    claim_assessor,
                    "assess_prepared",
                    (
                        prepared,
                        {
                            **limits,
                            "deadline_seconds": dispatch_deadline,
                            # The transport quote can impose a smaller raw
                            # HTTP response ceiling than the serialized IPC cap.
                            "max_output_bytes_per_task": raw_response_cap,
                        },
                    ),
                    deadline_seconds=dispatch_deadline,
                    output_limit=ipc_cap,
                    lock=call_lock,
                )
                elapsed_ms = round((time.monotonic() - started) * 1000, 2)
                if not isinstance(response, dict):
                    raise ValueError("invalid_claim_assessment_response")
                output_bytes = len(_canonical(response))
                usage = response.get("usage") if isinstance(response.get("usage"), dict) else {}
                status = response.get("status")
                if status not in {"COMPLETE", "PARTIAL", "FAILED"}:
                    status = "FAILED"
                provenance = response.get("provenance") if isinstance(response.get("provenance"), dict) else {}
                expected_provenance = {
                    "contract_version": prepared_version,
                    "request_hash": prepared_hash,
                    "candidate_hash": getattr(prepared, "candidate_hash", None),
                    "evidence_hash": getattr(prepared, "evidence_hash", None),
                    "question_hash": getattr(prepared, "question_hash", None),
                    **claim_identity,
                }
                expected_provenance["primary_assessment_hash"] = prepared.primary_assessment_hash
                provenance_valid = bool(
                    response.get("contract_version") == prepared_version
                    and all(provenance.get(key) == value for key, value in expected_provenance.items())
                )
                question_map = prepared_question_map
                response_assessments = response.get("assessments")
                assessments_valid = bool(
                    isinstance(response_assessments, dict)
                    and set(response_assessments) == set(question_map)
                    and response.get("decision") == "ADVISORY_ONLY"
                )
                for dimension, question_id in question_map.items():
                    item = response_assessments.get(dimension) if isinstance(response_assessments, dict) else None
                    if (
                        not isinstance(item, dict)
                        or item.get("question_id") != question_id
                        or item.get("native_primitive") != "Choice"
                        or item.get("interpretation") != "advisory_uncalibrated"
                        or item.get("evidence_refs") != list(getattr(prepared, "evidence_refs", ()))
                        or item.get("status") not in {"ANSWERED", "OMITTED", "INVALID", "FAILED", "NOT_SHOWN"}
                        or (
                            item.get("status") == "NOT_SHOWN"
                            and (dimension != "introducedness" or getattr(prepared, "introducedness_available", True))
                        )
                    ):
                        assessments_valid = False
                        break
                complete_assessment = bool(
                    assessments_valid
                    and all(
                        response_assessments[dimension]["status"]
                        == (
                            "NOT_SHOWN"
                            if dimension == "introducedness" and not prepared.introducedness_available
                            else "ANSWERED"
                        )
                        for dimension in question_map
                    )
                )
                response_valid = bool(
                    provenance_valid and assessments_valid and (status != "COMPLETE" or complete_assessment)
                )
                if not response_valid:
                    status = "FAILED"
                budget.settle(reservation_key, output_bytes=output_bytes, usage=usage, status=status)
                record_update = {
                    "status": status,
                    "normalized_result_hash": _hash(response),
                    "response_bytes": output_bytes,
                    "usage": usage,
                    "provenance_valid": provenance_valid,
                    "response_valid": response_valid,
                    "provenance": provenance if provenance_valid else {},
                    "elapsed_ms": elapsed_ms,
                    "settlement_key": reservation_key,
                }
                if response_valid:
                    record_update["assessments"] = response_assessments
                else:
                    record_update["reason_code"] = (
                        "RESPONSE_PROVENANCE_MISMATCH" if not provenance_valid else "RESPONSE_SCHEMA_INVALID"
                    )
                claim_rows[candidate_id].update(record_update)
                attempts_used += 1
                checkpoint()
            except BudgetExhausted as exc:
                budget_code = str(exc)
                allowed_budget_codes = {
                    "CLAIM_ASSESSMENT_CAP_EXHAUSTED",
                    "CONTEXT_BYTE_BUDGET_EXHAUSTED",
                    "DEADLINE_EXHAUSTED",
                    "FRESHNESS_BUDGET_RESERVED",
                    "INPUT_BYTE_LIMIT_EXCEEDED",
                    "MONETARY_BOUND_UNAVAILABLE",
                    "MONETARY_BUDGET_EXHAUSTED",
                    "OUTPUT_BYTE_BUDGET_EXHAUSTED",
                    "OUTPUT_BYTE_LIMIT_EXCEEDED",
                    "PROVIDER_CALL_BUDGET_EXHAUSTED",
                }
                error_code = (
                    budget_code if budget_code in allowed_budget_codes else "CLAIM_ASSESSMENT_BUDGET_UNAVAILABLE"
                )
                if reservation is not None:
                    try:
                        budget.settle(reservation_key, output_bytes=None, usage={}, status="NOT_RUN")
                    except (ValueError, KeyError):
                        pass
                claim_rows[candidate_id].update(
                    {
                        "status": "NOT_RUN",
                        "reason_code": error_code,
                        "attempt": 0,
                        "reservation_key": reservation_key if reservation is not None else None,
                    }
                )
                if reservation is not None:
                    attempts_used += 1
                checkpoint()
            except Exception as exc:
                meta = getattr(exc, "meta", {})
                meta = meta if isinstance(meta, dict) else {}
                remote_type = getattr(exc, "remote_type", None)
                uncertain = remote_type in {"TimeoutError", "Cancelled", "WorkerExit", "WorkerStartError"}
                raw_actual = meta.get("actual_output_bytes")
                actual_output = (
                    raw_actual
                    if isinstance(raw_actual, int) and not isinstance(raw_actual, bool) and raw_actual >= 0
                    else None
                )
                if reservation is not None:
                    # Preserve measured output so BudgetLedger records a real
                    # shared-resource overrun and the existing reducer fails closed.
                    settlement_bytes = actual_output
                    try:
                        budget.settle(
                            reservation_key,
                            output_bytes=settlement_bytes,
                            usage=meta.get("usage", {}) if isinstance(meta.get("usage"), dict) else {},
                            status="INTERRUPTED_UNKNOWN" if uncertain else "FAILED",
                        )
                    except (ValueError, KeyError):
                        pass
                    attempts_used += 1
                claim_rows[candidate_id].update(
                    {
                        "status": "INTERRUPTED_UNKNOWN" if uncertain else "FAILED",
                        "reason_code": "SHADOW_DISPATCH_UNCERTAIN"
                        if uncertain
                        else "IPC_OUTPUT_LIMIT_EXCEEDED"
                        if actual_output is not None and actual_output > ipc_cap
                        else type(exc).__name__,
                        "error_type": type(exc).__name__,
                        "error_code": _safe_claim_error_code(exc),
                        "actual_output_bytes_observed": actual_output,
                        "observed_output_limit_violation": (
                            {"actual_bytes": actual_output, "reserved_bytes": ipc_cap}
                            if actual_output is not None and actual_output > ipc_cap
                            else None
                        ),
                        "reservation_key": reservation_key if reservation is not None else None,
                    }
                )
                checkpoint()

    findings = consolidate_findings(findings)
    gap_obligations = {}
    for gap in context_gaps:
        if gap.get("status") != "RESOLVED_BY_FOLLOWUP":
            for oid in gap.get("affected_obligation_ids", []):
                gap_obligations.setdefault(oid, []).append(gap["proposal_id"])

    coverage = []
    for obligation_id, obligation in obligation_by_id.items():
        related = [t for t in tasks if obligation_id in t.get("obligation_ids", [t["obligation_id"]])]
        preflight_skips = [row for row in split_skips.values() if obligation_id in row.get("obligation_ids", [])]
        results = [task_results.get(t["task_id"], {}) for t in related]
        successful = bool(related) and not preflight_skips and all(r.get("status") == "SUCCEEDED" for r in results)
        check_evidence_refs: set[str] = set()
        check_result_evidence_invalid = False
        check_result_unavailable = False
        required_output_quarantined, quarantine_observation = _required_output_quarantine_observation(results)
        required_context_not_covered = False
        required_context_note_observations: list[dict[str, Any]] = []
        required_context_note_matches: list[bool] = []
        coverage_note_missing = False
        coverage_note_evidence_invalid = False
        partial_coverage_note = False
        if successful:
            # No-finding success is a completed result. A check UNKNOWN/ERROR remains partial.
            successful = all(r.get("payload", {}).get("outcome") not in {"UNKNOWN", "ERROR"} for r in results)
            check_result_unavailable = obligation.get("obligation_kind") == "PROJECT_CHECK" and any(
                r.get("payload", {}).get("outcome") in {"UNKNOWN", "ERROR"} for r in results
            )
            if required_output_quarantined:
                successful = False
            if obligation.get("obligation_kind") == "CHANGED_UNIT_LENS":
                scope_units = set(obligation.get("scope_unit_ids", []))
                for task, task_result in zip(related, results):
                    if task_result.get("status") != "SUCCEEDED":
                        successful = False
                        continue
                    notes = task_result.get("payload", {}).get("coverage_notes", [])
                    unit_evidence = {
                        u.get("unit_id"): set(u.get("evidence_ids", []))
                        for u in snapshot.get("inventory", [])
                        if isinstance(u, dict)
                    }
                    covered = {
                        n.get("unit_id")
                        for n in notes
                        if isinstance(n, dict)
                        and n.get("state") == "COVERED"
                        and n.get("coverage_basis") == "STATIC_REVIEW"
                        and n.get("evidence_refs")
                        and set(n.get("evidence_refs", [])).issubset(set(task_result.get("input_evidence_ids", [])))
                        and set(n.get("evidence_refs", [])) & unit_evidence.get(n.get("unit_id"), set())
                    }
                    missing_covered_units = (set(task.get("unit_ids", [])) & scope_units) - covered
                    if missing_covered_units:
                        successful = False
                        for unit_id in missing_covered_units:
                            unit_notes = [
                                note for note in notes if isinstance(note, dict) and note.get("unit_id") == unit_id
                            ]
                            if not unit_notes:
                                coverage_note_missing = True
                            else:
                                input_evidence_ids = set(task_result.get("input_evidence_ids", []))
                                unit_evidence_ids = unit_evidence.get(unit_id, set())
                                for note in unit_notes:
                                    refs = note.get("evidence_refs", [])
                                    if note.get("state") in {"PARTIAL", "NOT_COVERED"}:
                                        if refs and (
                                            not set(refs).issubset(input_evidence_ids)
                                            or not set(refs) & unit_evidence_ids
                                        ):
                                            coverage_note_evidence_invalid = True
                                        else:
                                            partial_coverage_note = True
                                    elif note.get("state") == "COVERED":
                                        coverage_note_evidence_invalid = True
                                    else:
                                        coverage_note_missing = True
                    task_has_required_quarantine, _ = _required_output_quarantine_observation([task_result])
                    if task_has_required_quarantine:
                        successful = False
            if obligation.get("obligation_kind") == "REQUIRED_CONTEXT":
                required_ids = set(obligation.get("retrieved_evidence_ids", []))
                for task_result in results:
                    payload = task_result.get("payload", {})
                    notes = payload.get("coverage_notes", []) if isinstance(payload, dict) else []
                    covered, note_observation = _coverage_note_observation(
                        notes,
                        notes_present=isinstance(payload, dict) and "coverage_notes" in payload,
                        scope_unit_ids=obligation.get("scope_unit_ids", []),
                        required_evidence_ids=required_ids,
                        task_input_evidence_ids=task_result.get("input_evidence_ids", []),
                        predicate_order="final_coverage",
                    )
                    required_context_note_observations.append(note_observation)
                    required_context_note_matches.append(covered)
                    if not covered:
                        required_context_not_covered = True
                    task_has_required_quarantine, _ = _required_output_quarantine_observation([task_result])
                    if not covered or task_has_required_quarantine:
                        successful = False
        if obligation.get("obligation_kind") == "PROJECT_CHECK":
            expected_binding = obligation.get("check_binding_id")
            for task, task_result in zip(related, results):
                if task_result.get("status") != "SUCCEEDED":
                    continue
                try:
                    refs = validated_check_evidence(task, task_result.get("payload", {}))
                except (AttributeError, TypeError, ValueError):
                    check_result_evidence_invalid = True
                    continue
                dispatched_refs = task_result.get("input_evidence_ids")
                if (
                    task.get("task_kind") != "DETERMINISTIC_CHECK"
                    or task.get("check_binding_id") != expected_binding
                    or not isinstance(dispatched_refs, list)
                    or dispatched_refs != refs
                ):
                    check_result_evidence_invalid = True
                    continue
                check_evidence_refs.update(refs)
            if check_result_evidence_invalid:
                successful = False
        state = (
            "PARTIAL"
            if gap_obligations.get(obligation_id)
            else "COMPLETE"
            if successful
            else "PARTIAL"
            if any(r.get("status") not in {None, "SKIPPED"} for r in results)
            else "NOT_STARTED"
        )
        failure_reason = next(
            (result.get("error_code", "MISSING_RESULT") for result in results if result.get("status") != "SUCCEEDED"),
            None,
        )
        skip_reason = next((row.get("error_code", "MISSING_RESULT") for row in preflight_skips), None)
        if gap_obligations.get(obligation_id):
            reason_code = "CONTEXT_GAP_UNRESOLVED"
        elif successful:
            reason_code = "VALID_RESULT"
        elif check_result_evidence_invalid:
            reason_code = "CHECK_RESULT_EVIDENCE_INVALID"
        elif failure_reason:
            reason_code = failure_reason
        elif skip_reason:
            reason_code = skip_reason
        elif required_output_quarantined:
            reason_code = "REQUIRED_OUTPUT_QUARANTINED"
        elif required_context_not_covered:
            reason_code = "REQUIRED_CONTEXT_NOT_COVERED"
        elif check_result_unavailable:
            reason_code = "CHECK_RESULT_UNAVAILABLE"
        elif coverage_note_evidence_invalid:
            reason_code = "COVERAGE_NOTE_EVIDENCE_INVALID"
        elif partial_coverage_note:
            reason_code = "PARTIAL_REVIEW_COVERAGE"
        elif coverage_note_missing:
            reason_code = "COVERAGE_NOTE_MISSING"
        else:
            reason_code = "MISSING_RESULT"
        coverage_row = {
                "coverage_id": _hash({"run_id": run_id, "obligation": obligation_id})[:20],
                "run_id": run_id,
                "snapshot_id": snapshot.get("snapshot_id"),
                **obligation,
                "state": state,
                "reason_code": reason_code,
                "context_gap_ids": gap_obligations.get(obligation_id, []),
                "task_ids": list(
                    dict.fromkeys(
                        [t["task_id"] for t in related]
                        + [row["task_id"] for row in preflight_skips if isinstance(row.get("task_id"), str)]
                    )
                ),
                "evidence_refs": sorted(check_evidence_refs)
                if obligation.get("obligation_kind") == "PROJECT_CHECK"
                else sorted({eid for t in related for eid in t.get("evidence_ids", [])}),
                "updated_at": _now(),
            }
        if obligation.get("obligation_kind") == "REQUIRED_CONTEXT":
            note_observed = bool(required_context_note_observations) and all(
                row.get("state") == "OBSERVED" for row in required_context_note_observations
            )
            note_counts: dict[str, int] | str = {code: 0 for code in _REQUIRED_CONTEXT_NOTE_CODES}
            note_count: int | str = 0
            notes_examined_count: int | str = 0
            notes_unexamined_after_match_count: int | str = 0
            if note_observed:
                for observation in required_context_note_observations:
                    counts = observation.get("failure_counts")
                    if not isinstance(counts, dict):
                        note_observed = False
                        break
                    note_count += observation["note_count"]
                    notes_examined_count += observation["notes_examined_count"]
                    notes_unexamined_after_match_count += observation["notes_unexamined_after_match_count"]
                    for code in _REQUIRED_CONTEXT_NOTE_CODES:
                        note_counts[code] += counts[code]
            if not note_observed:
                note_counts = "UNKNOWN"
                note_count = "UNKNOWN"
                notes_examined_count = "UNKNOWN"
                notes_unexamined_after_match_count = "UNKNOWN"
                coverage_note_result = "UNKNOWN"
            elif required_context_note_matches and all(required_context_note_matches):
                coverage_note_result = "COVERED"
            elif note_count == 0:
                coverage_note_result = "NO_NOTES"
            else:
                coverage_note_result = "NO_COVERING_NOTE"

            unresolved_ids = gap_obligations.get(obligation_id, [])
            unresolved_followup_count = 0
            gap_observation_known = True
            for gap_id in unresolved_ids:
                linked = [gap for gap in context_gaps if isinstance(gap, dict) and gap.get("proposal_id") == gap_id]
                if len(linked) != 1 or not isinstance(linked[0].get("task_id"), str):
                    gap_observation_known = False
                    continue
                if ":followup:" in linked[0]["task_id"]:
                    unresolved_followup_count += 1

            closure_state = (
                "OBSERVED"
                if note_observed and quarantine_observation["state"] == "OBSERVED" and gap_observation_known
                else "UNKNOWN"
            )
            coverage_row["closure_diagnostics"] = {
                "schema": "required-context-closure-diagnostics.v1",
                "state": closure_state,
                "coverage_note_result": coverage_note_result,
                "coverage_note_count": note_count,
                "coverage_note_notes_examined_count": notes_examined_count,
                "coverage_note_notes_unexamined_after_match_count": notes_unexamined_after_match_count,
                "coverage_note_failure_counts": note_counts,
                "required_output_quarantine_count": quarantine_observation["count"],
                "required_output_quarantine_by_kind": quarantine_observation["by_kind"],
                "unresolved_context_gap_count": len(unresolved_ids),
                "unresolved_followup_gap_count": (
                    unresolved_followup_count if gap_observation_known else "UNKNOWN"
                ),
            }
        coverage.append(coverage_row)
    required_cov = [c for c in coverage if c.get("required", True)]
    coverage_state = (
        "COMPLETE"
        if all(c["state"] == "COMPLETE" for c in required_cov)
        else "NOT_STARTED"
        if not any(c["state"] != "NOT_STARTED" for c in required_cov)
        else "PARTIAL"
    )
    freshness = "UNKNOWN"
    freshness_details = {"expected_head_sha": snapshot.get("head_sha"), "observed_head_sha": None}
    if callable(freshness_check):
        try:
            check = _bounded_freshness(freshness_check, budget.remaining_seconds())
            if isinstance(check, dict) and check.get("freshness") in {"CURRENT", "STALE", "UNKNOWN"}:
                freshness = check["freshness"]
                freshness_details.update({k: v for k, v in check.items() if k != "freshness"})
        except Exception:
            freshness = "UNKNOWN"
    elif snapshot.get("freshness_basis") == "HISTORICAL_SNAPSHOT" and snapshot.get("snapshot_hash"):
        freshness = "CURRENT"
        freshness_details["freshness_basis"] = "HISTORICAL_SNAPSHOT"

    blockers = [f for f in findings if f.get("status") == "ACCEPTED" and f.get("blocking_class") == "BLOCKING"]

    def report_notes(field: str, detail_name: str) -> list[dict]:
        notes: dict[str, dict] = {}
        for task in tasks:
            outcome = task_results.get(task["task_id"], {})
            if outcome.get("status") != "SUCCEEDED":
                continue
            for note in outcome.get("payload", {}).get(field, []):
                refs = list(note.get("evidence_refs", []))
                basis = {
                    "unit_id": note["unit_id"],
                    "title": note["title"],
                    "observation": note["observation"],
                    "detail": note["detail"],
                }
                note_id = "note-" + _hash({"snapshot_id": snapshot.get("snapshot_id"), "kind": field, **basis})[:20]
                item = notes.setdefault(
                    note_id,
                    {
                        "finding_id": note_id,
                        "note_id": note_id,
                        "snapshot_id": snapshot.get("snapshot_id"),
                        "unit_id": note["unit_id"],
                        "title": note["title"],
                        "observation": note["observation"],
                        detail_name: note["detail"],
                        "evidence_refs": [],
                        "task_ids": [],
                    },
                )
                item["evidence_refs"] = sorted(set(item["evidence_refs"]) | set(refs))
                item["task_ids"] = sorted(set(item["task_ids"]) | {task["task_id"]})
        return [notes[key] for key in sorted(notes)]

    accepted_improvements = [
        f for f in findings if f.get("status") == "ACCEPTED" and f.get("blocking_class") == "NON_BLOCKING"
    ]
    report_sections = {
        "blockers": [
            {
                "finding_id": f["finding_id"],
                "snapshot_id": f.get("snapshot_id"),
                "unit_id": f.get("unit_id"),
                "title": f["title"],
                "status": f["status"],
                "path": f["path"],
                "line": (f.get("location") or {}).get("line"),
                "location": f.get("location"),
                "observation": f["observation"],
                "consequence": f["consequence"],
                "rule_or_contract": f["rule_or_contract"],
                "rationale": f["blocking_rationale"],
                "evidence_refs": f["evidence_refs"],
            }
            for f in blockers
        ],
        "suggested_improvements": [
            {
                "finding_id": f["finding_id"],
                "snapshot_id": f.get("snapshot_id"),
                "unit_id": f.get("unit_id"),
                "title": f["title"],
                "status": f["status"],
                "path": f["path"],
                "line": (f.get("location") or {}).get("line"),
                "location": f.get("location"),
                "observation": f["observation"],
                "consequence": f["consequence"],
                "rule_or_contract": f["rule_or_contract"],
                "rationale": f["blocking_rationale"],
                "evidence_refs": f["evidence_refs"],
            }
            for f in accepted_improvements
        ],
        "specific_strengths": report_notes("specific_strengths", "why_it_matters"),
        "future_guidance": report_notes("future_guidance", "guidance"),
    }
    result = {
        "contract_version": "0.1",
        "run_id": run_id,
        "snapshot_id": snapshot.get("snapshot_id"),
        "base_sha": snapshot.get("base_sha"),
        "head_sha": snapshot.get("head_sha"),
        "project_profile_version": profile.get(
            "version",
            profile.get("profile_version", snapshot.get("profile_version", snapshot.get("project_profile_version"))),
        ),
        "coverage_state": coverage_state,
        "freshness": freshness,
        "freshness_details": freshness_details,
        "disposition": "INCOMPLETE",
        "merge_eligibility": "NOT_EVALUATED",
        "findings": findings,
        "coverage_ledger": coverage,
        "report_sections": report_sections,
        "created_at": ledger.get("created_at", _now()),
        "completed_at": _now(),
        "provider_identity": provider_identity,
        "repository": snapshot.get("repository"),
        "pull_request_number": snapshot.get("pull_request_number"),
        "repository_url": snapshot.get("repository_url"),
        "budget": budget.summary(),
        "task_results": task_results,
        "policy_valid": bool(plan.get("policy_valid", False)),
        "allow_empty_approve": approval_authority,
        "context_gaps": context_gaps,
        "snapshot_gaps": snapshot.get("gaps", []),
        "routing_reasons": plan.get("routing_reasons", []),
        "not_applicable": plan.get("not_applicable", []),
        "evidence_index": {
            eid: {
                k: ev.get(k)
                for k in (
                    "path",
                    "line_start",
                    "line_end",
                    "source_revision",
                    "source_object_id",
                    "source_object_format",
                    "source_object_size_bytes",
                    "content_truncated",
                    "source_side",
                    "source_kind",
                    "content_hash",
                    "trust",
                    "source_url",
                    "object_id",
                    "byte_count",
                )
                if ev.get(k) is not None
            }
            for eid, ev in evidence_map.items()
        },
        "context_omissions": [
            {"task_id": tid, "evidence_id": eid, "reason": "input_byte_limit"}
            for tid, tr in task_results.items()
            for eid in tr.get("context_omissions", [])
        ],
    }
    if max_claim_assessments > 0:
        result["claim_assessments"] = [
            ledger["claim_assessments"][candidate_id] for candidate_id in sorted(ledger["claim_assessments"])
        ]
    result["disposition"] = _reduce(
        result,
        approval_authority,
        result["policy_valid"],
    )
    advisory_assessment = {"status": "NOT_CONFIGURED"}
    if decision_provider is not None and callable(getattr(decision_provider, "assess", None)):
        advisory_attempt = (
            max(
                (
                    int(key.rsplit(":", 1)[-1])
                    for key in budget.state["reservations"]
                    if key.startswith("system-one:advisory:") and key.rsplit(":", 1)[-1].isdigit()
                ),
                default=-1,
            )
            + 1
        )
        reservation_key = f"system-one:advisory:{advisory_attempt}"
        try:
            advisory_text = json.dumps(
                {
                    "mode": plan.get("mode"),
                    "coverage_state": coverage_state,
                    "required_scopes": len(required_cov),
                    "finding_ids": [f["finding_id"] for f in findings],
                    "routing_reasons": plan.get("routing_reasons", []),
                },
                sort_keys=True,
            )
            reservation = reserve_provider_call(
                reservation_key,
                decision_provider,
                "SYSTEM_ONE_ASSESSMENT",
                {"task_id": reservation_key},
                [{"content": advisory_text}],
                len(advisory_text.encode("utf-8")),
            )
            response = isolated_call(
                decision_provider,
                "assess",
                (
                    "Provide an advisory risk/context assessment of this bounded deterministic review summary. Do not decide disposition or clear findings.",
                    advisory_text,
                    remaining_call_limits(),
                ),
                deadline_seconds=min(
                    float(reservation.get("deadline_seconds", remaining_call_limits()["deadline_seconds"])),
                    remaining_call_limits()["deadline_seconds"],
                ),
                output_limit=int(reservation["max_output_bytes"]),
                lock=call_lock,
            )
            payload, usage, provenance = _unwrap(response)
            budget.settle(reservation_key, output_bytes=len(_canonical(response)), usage=usage, status="SUCCEEDED")
            advisory_assessment = {
                "status": "RECEIVED",
                "result": payload,
                "usage": usage,
                "provenance": provenance,
            }
        except BudgetExhausted as exc:
            advisory_assessment = {"status": "NOT_RUN", "reason": str(exc)}
        except Exception as exc:
            meta = getattr(exc, "meta", {})
            usage = meta.get("usage", {}) if isinstance(meta, dict) else {}
            try:
                budget.settle(
                    reservation_key,
                    output_bytes=meta.get("actual_output_bytes") if isinstance(meta, dict) else None,
                    usage=usage,
                    status="FAILED",
                )
            except (ValueError, KeyError):
                pass
            advisory_assessment = {
                "status": "FAILED",
                "error_code": type(exc).__name__,
                "provider_error_meta": meta if isinstance(meta, dict) else {},
                "usage": usage,
            }
    result["advisory_assessment"] = advisory_assessment
    result["budget"] = budget.summary()
    ledger["outputs"] = task_results
    ledger["findings"] = findings
    ledger["context_gaps"] = context_gaps
    ledger["call_reservations"] = result["budget"]["provider_calls_reserved"]
    ledger["created_at"] = result["created_at"]
    for task_id, task_result in task_results.items():
        event = {
            "event": "TASK_RESULT",
            "task_id": task_id,
            "output_hash": task_result.get("output_hash"),
            "status": task_result.get("status"),
            "at": task_result.get("finished_at", _now()),
        }
        event["event_hash"] = _hash(event)
        ledger["events"].append(event)
    saved = {**result, "request_hash": request_hash, "ledger": ledger}
    saved["result_hash"] = _hash(saved)
    _atomic_write(output_path, _canonical(saved) + b"\n")
    return saved


def render_report(result: dict) -> str:
    """Render the deterministic four-category report."""
    return _render_report(result)
