"""Bounded deterministic execution, reconciliation, ledgering, and reporting."""

from __future__ import annotations

# The extracted review stages resolve their module globals through this module's
# namespace on every call (``from .engine import ...`` inside each stage), so
# the names below stay importable from ``engine`` exactly as they were when the
# controller body lived here.  They are re-exported deliberately.
import fnmatch  # noqa: F401
import hashlib
import json
import math
import os
import re
import tempfile
import threading  # noqa: F401
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import contracts as review_contracts
from .budget import (  # noqa: F401
    BudgetExhausted,
    BudgetLedger,
    IsolatedCallError,
    IsolatedInvocation,
    isolated_call,
    wait_for_any,
)
from .claim_assessment import CLAIM_ASSESSMENT_ERROR_CODES, ClaimAssessmentError
from .claim_reconciliation import (  # noqa: F401
    classify_reconciliation,
    validate_claim_reconciliation_policy,
)
from .context_targets import build_context_target_manifest, validate_context_target_choice  # noqa: F401
from .errors import BoundaryValueError
from .planner import allow_empty_approve as allow_empty_approve  # noqa: F401
from .private_capture import (  # noqa: F401
    MAX_CAPTURE_CALLS,
    MAX_REQUEST_BYTES,
    MAX_RESPONSE_BYTES,
    MAX_TOTAL_BYTES,
    PrivateShadowCapture,
    write_provider_exchange,
)
from .reconcile import (  # noqa: F401
    consolidate_findings,
    stable_candidate_id,
    validate_location,
)
from .report import render_report as _render_report
from .review_stages import (
    assess_claims,
    bind_run_state,
    build_and_persist_result,
    dispatch_tasks,
    install_attempt_lifecycle,
    install_budget_helpers,
    install_followup_runner,
    install_report_notes,
    install_review_input_size,
    preflight_review,
    prepare_dispatch,
    prepare_followups,
    quote_monetary_budget,
    reduce_coverage,
    resume_completed_review,
    run_followups,
)
from .review_state import PlanRecord, ReviewResult, RunState, SnapshotRecord, TaskRecord
from .source_audit import serialize_source_audit_request  # noqa: F401

_SYSTEM_ONE_ADVISORY_QUESTION = (
    "Provide an advisory risk/context assessment of this bounded deterministic review summary. "
    "Do not decide disposition or clear findings."
)


class EnginePreflightError(BoundaryValueError):
    """A closed, deterministic rejection found before provider dispatch or writes."""

    _PUBLIC_REASONS = {
        "invalid_review_request",
        "run_id_already_exists",
        "resume_state_invalid",
        "review_waiver_rejected",
    }

    _DETAILS = {
        "invalid_review_request": "review request is invalid",
        "run_id_already_exists": "run_id already exists; resume explicitly",
        "resume_state_invalid": "resume ledger invalid",
        "review_waiver_rejected": "review waiver rejected",
    }
    _RESUME_DETAILS = {
        "resume request mismatch",
        "resume result integrity mismatch",
        "resume ledger integrity mismatch",
        "resume evidence identity mismatch",
        "resume dynamic obligation ledger invalid",
        "resume planned input binding mismatch",
        "resume task input binding mismatch",
        "resume snapshot identity mismatch",
        "resume waiver binding mismatch",
        "invalid_context_followup_parent_binding",
        "invalid_context_followup_proposal_binding",
        "invalid_context_followup_parent_contract",
        "invalid_context_followup_target",
        "invalid_context_followup_retrieval_binding",
        "invalid_context_followup_parent_obligations",
        "invalid_context_followup_scope",
        "invalid_context_followup_obligation_binding",
        "invalid_context_followup_related_evidence",
        "invalid_context_followup_task_binding",
        "invalid_context_followup_contract",
        "invalid_context_followup_gap_record",
        "invalid_context_followup_run_binding",
        "invalid_context_followup_metadata_binding",
    }
    _REQUEST_DETAILS = {
        "plan requires tasks and coverage_obligations",
        "invalid planned task",
        "invalid planned task kind",
        "duplicate task_id",
        "planned_specialist_input_metadata_is_engine_owned",
        "invalid or duplicate coverage obligation",
        "task references unknown obligation",
        "positive max_claim_assessments requires a claim assessor",
        "max_claim_assessments must be an integer from 0 to 4",
        "claim assessor does not implement the prepared-assessment interface",
        "claim assessor identity must be an object",
        "claim assessor contract identity is required",
        "claim assessor identity or adapter is not serializable",
        "claim assessor configuration exceeds its finite preflight bound",
        "contract registry is unavailable",
        "contract registry is invalid",
        "contract registry has an invalid status",
        "contract registry has a duplicate entry",
        "contract registry references an unknown contract",
        "contract registry source digest does not match",
        "contract registry supported matrix is invalid",
        "archived contract combination rejected",
        "deprecated contract combination rejected",
        "contract limits do not match the registered combination",
        "contract version is not registered",
        "profile is not registered for a review contract",
        "contract invariants do not match the registry",
        "claim assessment cap does not match the registered combination",
    }
    _LIMIT_NAMES = {
        "deadline_seconds",
        "max_concurrent_scopes",
        "max_provider_calls",
        "max_retries_per_task",
        "max_context_bytes",
        "max_input_bytes_per_task",
        "max_output_bytes_per_task",
        "max_output_bytes",
        "max_context_retrievals",
        "max_followup_tasks",
        "max_snapshot_context_bytes",
        "max_cost_microunits",
        "max_retrieval_result_bytes",
    }

    def __init__(self, reason: str, detail: str | None = None):
        if reason not in self._PUBLIC_REASONS:
            raise ValueError("unknown engine preflight rejection")
        self.reason = reason
        safe_detail = None
        if reason == "resume_state_invalid" and detail in self._RESUME_DETAILS:
            safe_detail = detail
        elif reason == "invalid_review_request" and detail in self._REQUEST_DETAILS:
            safe_detail = detail
        elif reason == "invalid_review_request" and isinstance(detail, str):
            prefix, separator, key = detail.partition(": ")
            if prefix == "invalid limit" and separator and key in self._LIMIT_NAMES:
                safe_detail = detail
            elif prefix == "missing finite limits" and separator:
                missing = key.split(", ")
                if missing and all(item in self._LIMIT_NAMES for item in missing):
                    safe_detail = detail
        super().__init__(safe_detail or self._DETAILS[reason])


def _private_capture_profile_id(profile: dict[str, Any]) -> str:
    """Resolve a capture-local alias; repository and snapshot hashes bind provenance.

    A repository basename is intentionally compatible with frozen corpora, not
    globally unique across owners. The hashed profile and snapshot identities
    remain the binding when two repositories share a basename. ``unknown`` is
    retained only for legacy profiles with no identity fields or repository.
    """
    from .private_capture import _safe_id

    for key in ("profile_id", "id", "name"):
        if key in profile:
            try:
                return _safe_id(profile[key], "profile_id")
            except ValueError:
                raise ValueError("private capture profile identity is invalid") from None

    if "repository" not in profile:
        return "unknown"

    repository = profile["repository"]
    owner = repo = None
    if isinstance(repository, dict):
        owner = repository.get("owner")
        repo = repository.get("repo", repository.get("name"))
    elif isinstance(repository, str) and repository.count("/") == 1:
        owner, repo = repository.split("/", 1)
    component = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}")
    if (
        isinstance(owner, str)
        and isinstance(repo, str)
        and component.fullmatch(owner)
        and component.fullmatch(repo)
        and owner not in {".", ".."}
        and repo not in {".", ".."}
    ):
        return _safe_id(repo.lower(), "profile_id")
    raise ValueError("private capture repository identity is invalid")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _hash(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _check_evidence_hash(value: Any) -> str:
    """Match checks.py's historical ensure_ascii=True evidence identity contract."""
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    return hashlib.sha256(encoded).hexdigest()


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
        (
            ("UNIT_OUT_OF_SCOPE", lambda: note.get("unit_id") in scope_unit_ids),
            ("STATE_NOT_COVERED", lambda: note.get("state") == "COVERED"),
            ("BASIS_NOT_STATIC_REVIEW", lambda: note.get("coverage_basis") == "STATIC_REVIEW"),
        )
        if predicate_order == "followup_resolution"
        else (
            ("STATE_NOT_COVERED", lambda: note.get("state") == "COVERED"),
            ("BASIS_NOT_STATIC_REVIEW", lambda: note.get("coverage_basis") == "STATIC_REVIEW"),
            ("UNIT_OUT_OF_SCOPE", lambda: note.get("unit_id") in scope_unit_ids),
        )
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
    result = "UNKNOWN" if not observable else "COVERED" if matched else "NO_COVERING_NOTE" if notes else "NO_NOTES"
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
_CLAIM_ASSESSMENT_DISPATCH_SECONDS = 8.0
_CLAIM_FRESHNESS_TAIL_SECONDS = 16.0


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
    names = (
        "engine.py",
        "review_stages.py",
        "review_state.py",
        "planner.py",
        "providers.py",
        "contracts.py",
        "reconcile.py",
        "budget.py",
        "claim_reconciliation.py",
        "contract_registry.py",
        "contract_registry.json",
    )
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
    optional_positive_ints = {"max_snapshot_context_bytes", "max_retrieval_result_bytes"}
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
    if limits.get("max_retrieval_result_bytes", 0) > limits["max_input_bytes_per_task"]:
        raise ValueError("invalid limit: max_retrieval_result_bytes")
    if limits.get("max_cost_microunits") is not None:
        if (
            isinstance(limits["max_cost_microunits"], bool)
            or not isinstance(limits["max_cost_microunits"], int)
            or limits["max_cost_microunits"] < 1
        ):
            raise ValueError("invalid limit: max_cost_microunits")
    if limits.get("max_cost_currency") is not None:
        currency = limits["max_cost_currency"]
        if not isinstance(currency, str) or not re.fullmatch(r"[A-Z]{3}", currency):
            raise ValueError("invalid limit: max_cost_currency")
        if limits.get("max_cost_microunits") is None:
            raise ValueError("invalid limit: max_cost_currency")


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


_ASSESSOR_INTERFACE = ("prepare", "estimate_prepared", "assess_prepared")
_MAX_ASSESSOR_IDENTITY_BYTES = 16_384
_MAX_ASSESSOR_CONFIGURATION_BYTES = 65_536


def _declared_assessor_configuration(assessor: Any, identity: dict) -> dict:
    """Return a canonical, JSON-serializable declaration of the adapter.

    The historical object-serialization size proxy measured an arbitrary
    object graph. This replacement serializes only the declared identity, the
    optional adapter-declared ``configuration`` value, and a deterministic
    type/interface descriptor. It never serializes the adapter object, so the
    preflight bound is reproducible across Python versions.
    """
    configuration = getattr(assessor, "configuration", None)
    if callable(configuration):
        configuration = configuration()
    return {
        "identity": identity,
        "configuration": configuration if configuration is not None else {},
        "adapter": {
            "type": f"{type(assessor).__module__}.{type(assessor).__qualname__}",
            "interface": list(_ASSESSOR_INTERFACE),
        },
    }


def _claim_assessor_binding(assessor: Any, expected_contract_version: str) -> tuple[str, str, str]:
    """Validate the opt-in shadow adapter and return a stable non-secret identity binding."""
    for name in _ASSESSOR_INTERFACE:
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
    supported_versions = identity.get("supported_contract_versions", [version])
    if (
        not isinstance(supported_versions, list)
        or not supported_versions
        or any(not isinstance(item, str) or not item or len(item) > 128 for item in supported_versions)
        or len(set(supported_versions)) != len(supported_versions)
        or expected_contract_version not in supported_versions
    ):
        raise ValueError("claim assessor does not support the required contract version")
    try:
        encoded_identity = _canonical(identity)
        encoded_configuration = _canonical(_declared_assessor_configuration(assessor, identity))
    except (TypeError, ValueError, RecursionError) as exc:
        raise ValueError("claim assessor identity or adapter is not serializable") from exc
    if (
        len(encoded_identity) > _MAX_ASSESSOR_IDENTITY_BYTES
        or len(encoded_configuration) > _MAX_ASSESSOR_CONFIGURATION_BYTES
    ):
        raise ValueError("claim assessor configuration exceeds its finite preflight bound")
    root = Path(__file__).resolve().parent
    implementation_hash = _hash(
        {
            name: hashlib.sha256((root / name).read_bytes()).hexdigest()
            for name in ("claim_assessment.py", "claim_transport.py")
        }
    )
    return hashlib.sha256(encoded_configuration).hexdigest(), expected_contract_version, implementation_hash


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


def _complete_snapshot_context_evidence(
    snapshot: dict, binding: dict, captured_evidence: dict | None = None
) -> dict | None:
    """Return only a complete, exact HEAD file already captured in this snapshot.

    This is a reuse path, not a retrieval: the row retains its original
    ``head_file`` / ``untrusted_pr_content`` classification. Every immutable
    source binding and both content/object hashes are rechecked before reuse.
    """
    evidence_map = captured_evidence if isinstance(captured_evidence, dict) else snapshot.get("evidence")
    if not isinstance(evidence_map, dict):
        return None
    path = binding.get("path")
    revision = binding.get("source_sha")
    object_id = binding.get("source_object_id")
    object_format = binding.get("source_object_format")
    if (
        not isinstance(path, str)
        or not isinstance(revision, str)
        or revision != snapshot.get("head_sha")
        or not isinstance(object_id, str)
        or object_format not in {"sha1", "sha256"}
        or len(object_id) != (40 if object_format == "sha1" else 64)
        or binding.get("evidence_kind") not in {"implementation", "test"}
    ):
        return None
    matches = [
        item
        for indexed_evidence_id, item in evidence_map.items()
        if isinstance(item, dict)
        and item.get("evidence_id") == indexed_evidence_id
        and item.get("path") == path
        and item.get("source_revision") == revision
        and item.get("source_object_id") == object_id
        and item.get("source_object_format") == object_format
        and item.get("source_kind") == "head_file"
        and item.get("trust") == "untrusted_pr_content"
        and item.get("snapshot_id") == snapshot.get("snapshot_id")
        and item.get("content_truncated") is False
    ]
    if len(matches) != 1:
        return None
    item = matches[0]
    content = item.get("content")
    evidence_id = item.get("evidence_id")
    line_start = item.get("line_start")
    if not isinstance(content, str) or not isinstance(evidence_id, str) or not evidence_id or line_start != 1:
        return None
    try:
        raw = content.encode("utf-8")
    except UnicodeEncodeError:
        return None
    content_hash = hashlib.sha256(raw).hexdigest()
    if item.get("content_hash") != content_hash:
        return None
    git_header = f"blob {len(raw)}\0".encode("ascii")
    object_hash = hashlib.new(object_format, git_header + raw).hexdigest()
    if object_hash != object_id or item.get("source_object_size_bytes") != len(raw):
        return None
    return item


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
            selected_ids = [
                evidence_id
                for evidence_id in task_evidence_ids
                if evidence_id in selected_set and evidence_id in delivered
            ]
            binding_status = "VERIFIED"
        bindings.append({"unit_id": unit_id, "binding_status": binding_status, "evidence_ids": selected_ids})
    bound = {
        **task,
        "request_input_contract": review_contracts.SPECIALIST_INPUT_V2,
        "unit_evidence_bindings": bindings,
    }
    manifest = build_context_target_manifest(task, snapshot, profile)
    if manifest is not None:
        bound["context_target_manifest"] = manifest
    return bound


def _task_input_provenance(task: dict) -> dict[str, Any]:
    provenance = {
        "request_input_contract": task.get("request_input_contract"),
        "unit_evidence_bindings": task.get("unit_evidence_bindings"),
    }
    if "context_target_manifest" in task:
        provenance["context_target_manifest"] = task["context_target_manifest"]
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
        value is not None and (not isinstance(value, str) or not value.strip() or len(value.encode("utf-8")) > 2_000)
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
        or any(
            not isinstance(item, dict) or not isinstance(item.get("evidence_id"), str) for item in retrieved_evidence
        )
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
    scope_unit_ids = (
        [record["resolved_unit_id"]] if record.get("resolved_unit_id") else list(parent_task.get("unit_ids", []))
    )
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
        item for item in ledger.get("context_gaps", []) if isinstance(item, dict) and item.get("proposal_id") == marker
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
    source_task = {
        key: value
        for key, value in task.items()
        if key not in {"request_input_contract", "unit_evidence_bindings", "context_target_manifest"}
    }
    expected = _bind_specialist_input(source_task, snapshot, profile, evidence)
    if task.get("unit_evidence_bindings") != expected["unit_evidence_bindings"]:
        raise ValueError("invalid_specialist_unit_evidence_binding")
    if task.get("context_target_manifest") != expected.get("context_target_manifest"):
        raise ValueError("invalid_context_target_manifest_binding")


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


def _settlement_observation(
    stage: str,
    usage: Any,
    provenance: Any = None,
    *,
    call_elapsed_ms: float | None = None,
    error_meta: Any = None,
) -> dict:
    """Project provider metadata into bounded scalar settlement facts only."""
    exchange = None
    for container in (provenance, error_meta):
        if not isinstance(container, dict):
            continue
        candidate = container.get("local_http_exchange")
        if not isinstance(candidate, dict) and isinstance(container.get("provenance"), dict):
            candidate = container["provenance"].get("local_http_exchange")
        if isinstance(candidate, dict):
            exchange = candidate
            break
    exchange = exchange if isinstance(exchange, dict) else {}
    exchange_elapsed = exchange.get("elapsed_ms")
    safe_usage = usage if isinstance(usage, dict) else {}
    observation = {
        "stage": stage,
        # A missing receipt is deliberately UNKNOWN, never inferred from an
        # adapter return, exception, or worker launch.
        "request_attempted": exchange.get("request_attempted")
        if isinstance(exchange.get("request_attempted"), bool)
        else None,
        "http_status": exchange.get("http_status"),
        "call_elapsed_ms": call_elapsed_ms,
        "http_elapsed_ms": exchange_elapsed,
        "usage_known": safe_usage.get("known") is True,
    }
    for field in ("prompt_tokens", "completion_tokens", "input_tokens", "output_tokens", "total_tokens"):
        observation[field] = safe_usage.get(field)
    return observation


def _run_elapsed_ms(ledger: dict) -> float | None:
    started = ledger.get("run_started_at_epoch")
    if isinstance(started, bool) or not isinstance(started, (int, float)) or not math.isfinite(started):
        return None
    elapsed = (time.time() - started) * 1000
    return round(elapsed, 2) if math.isfinite(elapsed) and elapsed >= 0 else None


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
    completeness = result.get("completeness_summary")
    waived = bool(
        result.get("waivers_applied")
        or (isinstance(completeness, dict) and completeness.get("waived", 0))
        or any(isinstance(row, dict) and row.get("state") == "WAIVED" for row in result.get("coverage_ledger", []))
    )
    required_incomplete = (
        result["coverage_state"] not in {"COMPLETE", "COMPLETE_WITH_WAIVERS"}
        or not policy_valid
        or any(f.get("blocking_class") == "UNRESOLVED" for f in findings)
        or bool(result.get("budget", {}).get("budget_breaches"))
    )
    if required_incomplete or result["freshness"] != "CURRENT":
        return "INCOMPLETE"
    if waived or findings:
        return "COMMENT"
    return "APPROVE" if allow_empty_approve else "COMMENT"


def prepare_plan_tasks(
    snapshot: SnapshotRecord,
    plan: PlanRecord,
    profile: dict[str, Any],
    limits: dict[str, Any],
    provider: Any,
) -> tuple[list[TaskRecord], dict[str, dict[str, object]]]:
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


def _load_validated_resume_state(
    output_path: Path,
    request_hash: str,
    snapshot: dict,
    primary_tasks: list[dict],
    obligations: list[dict],
    input_ceiling: int,
    profile: dict,
    waiver_binding: dict,
) -> tuple[dict, dict]:
    """Validate immutable resume identity before freshness work or any write."""
    try:
        saved = json.loads(output_path.read_text(encoding="utf-8"))
        ledger = saved["ledger"]
        saved_waiver = saved.get("waiver_receipt")
        if waiver_binding.get("present") is True:
            if not isinstance(saved_waiver, dict) or saved_waiver.get("source_sha256") != waiver_binding.get(
                "source_sha256"
            ):
                raise ValueError("resume waiver binding mismatch")
        elif saved_waiver is not None:
            raise ValueError("resume waiver binding mismatch")
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
                _validate_context_followup_task(task, ledger, saved_snapshot, saved_obligation_by_id, saved_task_by_id)
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
        if "deadline_epoch" in ledger:
            float(ledger["deadline_epoch"])
    except OSError:
        # Storage failures are runtime failures; do not relabel them as bad input.
        raise
    except ValueError as exc:
        detail = str(exc) if str(exc) in EnginePreflightError._RESUME_DETAILS else None
        raise EnginePreflightError("resume_state_invalid", detail) from None
    except (KeyError, TypeError, AttributeError):
        raise EnginePreflightError("resume_state_invalid") from None
    return saved, ledger


def run_review(
    snapshot: SnapshotRecord,
    plan: PlanRecord,
    profile: dict[str, Any],
    provider: Any,
    decision_provider: Any,
    limits: dict[str, Any],
    output_dir: str,
    run_id: str,
    resume: bool = False,
    freshness_check: Any = None,
    context_retriever: Any = None,
    check_adapter: Any = None,
    claim_assessor: Any = None,
    max_claim_assessments: int = 0,
    private_capture_dir: str | None = None,
    private_capture_case_id: str | None = None,
    private_capture_request_pins: dict[str, dict] | None = None,
    private_capture_snapshot_pin: dict[str, Any] | None = None,
    private_capture_source_audit_max_bytes: int = 64_000,
    allow_archived_contracts: bool = False,
    price_table: Any = None,
    waiver_path: str | None = None,
) -> ReviewResult:
    """Run bounded provider tasks and persist an integrity-checked review result.

    This controller never executes reviewed code. A lack of provider capability
    yields explicit NOT_STARTED coverage; it cannot be interpreted as no findings.
    """

    state = RunState(
        snapshot=snapshot,
        plan=plan,
        profile=profile,
        provider=provider,
        decision_provider=decision_provider,
        limits=limits,
        output_dir=output_dir,
        run_id=run_id,
        resume=resume,
        freshness_check=freshness_check,
        context_retriever=context_retriever,
        check_adapter=check_adapter,
        claim_assessor=claim_assessor,
        max_claim_assessments=max_claim_assessments,
        private_capture_dir=private_capture_dir,
        private_capture_case_id=private_capture_case_id,
        private_capture_request_pins=private_capture_request_pins,
        private_capture_snapshot_pin=private_capture_snapshot_pin,
        private_capture_source_audit_max_bytes=private_capture_source_audit_max_bytes,
        allow_archived_contracts=allow_archived_contracts,
        price_table=price_table,
        waiver_path=waiver_path,
    )
    # Deterministic stage order; the coordinator makes no review decisions and
    # never dispatches on model output.  Invariants that hold across the whole
    # sequence: reserve-before-dispatch, fail-closed on unknown/partial evidence,
    # blocker preservation, and no model control flow.
    preflight_review(state)
    resumed = resume_completed_review(state)
    if resumed is not None:
        return resumed
    bind_run_state(state)
    install_review_input_size(state)
    prepare_dispatch(state)
    install_budget_helpers(state)
    quote_monetary_budget(state)
    install_attempt_lifecycle(state)
    dispatch_tasks(state)
    prepare_followups(state)
    install_followup_runner(state)
    run_followups(state)
    assess_claims(state)
    reduce_coverage(state)
    install_report_notes(state)
    return build_and_persist_result(state)


def render_report(result: ReviewResult) -> str:
    """Render the deterministic four-category report."""
    return _render_report(result)
