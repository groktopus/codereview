"""Explicit stages of the bounded review controller (CA-1).

Each stage takes the mutable :class:`~pr_review_harness.review_state.RunState`
and performs exactly one phase of the former monolithic ``run_review``.
Stages are independently importable and can be exercised with a constructed
state; they never hold closure state of their own.

Ordering contract (the coordinator enforces it): preflight, resume binding,
run-state binding, budget helpers, attempt lifecycle, dispatch, follow-ups,
required claim assessment, reduction, rendering.  Invariants that must hold
across every stage: reserve-before-dispatch, fail-closed on unknown or
partial evidence, blocker preservation, and no model control flow.
"""

from __future__ import annotations

import functools
from typing import Any

from .contract_registry import ContractRegistryError, effective_contract_set, load_registry
from .errors import defect_name, is_defect
from .review_state import RunState

_CONTRACT_REJECTION_DETAILS = {
    "registry_unavailable": "contract registry is unavailable",
    "registry_invalid": "contract registry is invalid",
    "registry_invalid_status": "contract registry has an invalid status",
    "registry_duplicate_entry": "contract registry has a duplicate entry",
    "registry_unknown_reference": "contract registry references an unknown contract",
    "registry_source_mismatch": "contract registry source digest does not match",
    "registry_supported_matrix": "contract registry supported matrix is invalid",
    "contract_archived": "archived contract combination rejected",
    "contract_deprecated": "deprecated contract combination rejected",
    "contract_limits_mismatch": "contract limits do not match the registered combination",
    "contract_unknown_component": "contract version is not registered",
    "contract_unregistered_profile": "profile is not registered for a review contract",
    "contract_invariant_mismatch": "contract invariants do not match the registry",
    "contract_claim_cap_mismatch": "claim assessment cap does not match the registered combination",
}


def checkpoint_stage(state: RunState, terminal: bool = False) -> None:
    from .engine import _atomic_write, _canonical, _hash, _now
    with state.state_lock:
        payload = {
            "run_id": state.run_id,
            "request_hash": state.request_hash,
            "completed_at": _now() if terminal else None,
            "ledger": state.ledger,
            "task_results": state.ledger.get("outputs", {}),
        }
        payload["result_hash"] = _hash(payload)
        _atomic_write(state.output_path, _canonical(payload) + b"\n")



def review_input_size_stage(state: RunState, task: dict, evidence: list[dict]) -> int:
    from .engine import _canonical
    measure = getattr(state.provider, "review_input_bytes", None)
    if callable(measure) and task.get("task_kind", "SPECIALIST_FINDINGS") == "SPECIALIST_FINDINGS":
        return measure(task, evidence, state.limits) + 1024
    return len(_canonical({"task": task, "evidence": evidence}))



def remaining_call_limits_stage(state: RunState, ) -> dict:
    return {**state.limits, "deadline_seconds": max(0.0, state.budget.remaining_seconds())}



def required_claim_calls_remaining_stage(state: RunState, ) -> int:
    """Return the outstanding required calls for currently validated candidates."""
    if state.reconciliation_policy is None:
        return 0
    if not callable(getattr(state.provider, "adjudicate", None)):
        return 0
    eligible_candidates = sum(
        1
        for record in state.ledger.get("candidate_records", [])
        if isinstance(record, dict) and record.get("validation_state") == "VALID"
    )
    demand = min(int(state.reconciliation_policy["max_assessments"]), eligible_candidates)
    used = sum(
        reservation.get("provider_calls", 0)
        for reservation in state.budget.state.get("reservations", {}).values()
        if isinstance(reservation, dict) and reservation.get("kind") == "claim_assessment"
    )
    return max(0, demand - used)



def required_claim_deadline_floor_stage(state: RunState, ) -> float:
    from .engine import _CLAIM_ASSESSMENT_DISPATCH_SECONDS, _CLAIM_FRESHNESS_TAIL_SECONDS
    calls = state.required_claim_calls_remaining()
    if not calls:
        return 0.0
    return calls * _CLAIM_ASSESSMENT_DISPATCH_SECONDS + (
        _CLAIM_FRESHNESS_TAIL_SECONDS if callable(state.freshness_check) else 0.0
    )



def call_estimate_stage(
        state: RunState,
    target: Any,
    task_kind: str,
    task: dict,
    evidence: list[dict],
    fallback_size: int,
    *,
    deadline_floor_seconds: float = 0.0,
) -> dict:
    from .engine import BudgetExhausted
    current_remaining = state.budget.remaining_seconds()
    quote_deadline = max(0.0, current_remaining - deadline_floor_seconds)
    if deadline_floor_seconds and quote_deadline <= 0:
        raise BudgetExhausted("REQUIRED_CLAIM_ASSESSMENT_DEADLINE_RESERVED")
    quote_limits = {**state.remaining_call_limits(), "deadline_seconds": quote_deadline}
    estimator = getattr(target, "estimate_call", None)
    if callable(estimator):
        estimate = estimator(task_kind, task, evidence, quote_limits)
        if not isinstance(estimate, dict):
            raise ValueError("provider estimate_call must return an object")
        estimate = dict(estimate)
    else:
        estimate = {
            "provider_calls": 1,
            "input_bytes": fallback_size,
            "max_output_bytes": int(state.limits["max_output_bytes_per_task"]),
            "reservation_kind": "unknown",
        }
    estimate["provider_calls"] = estimate.get("provider_calls", 1)
    estimate["input_bytes"] = estimate.get("input_bytes", fallback_size)
    estimate["max_output_bytes"] = estimate.get("max_output_bytes", int(state.limits["max_output_bytes_per_task"]))
    estimate["deadline_seconds"] = min(
        float(estimate.get("deadline_seconds", quote_deadline)),
        quote_deadline,
    )
    if state.limits.get("max_cost_microunits") is not None and estimate.get("reservation_kind") != "operator_bound":
        raise ValueError(
            "configured monetary budget reservation is unsupported without an operator-bound per-call quote"
        )
    if deadline_floor_seconds:
        after_quote_deadline = max(0.0, state.budget.remaining_seconds() - deadline_floor_seconds)
        if after_quote_deadline <= 0:
            raise BudgetExhausted("REQUIRED_CLAIM_ASSESSMENT_DEADLINE_RESERVED")
        estimate["deadline_seconds"] = min(float(estimate["deadline_seconds"]), after_quote_deadline)
    return estimate



def reserve_provider_call_stage(
        state: RunState,
    key: str, target: Any, task_kind: str, task: dict, evidence: list[dict], fallback_size: int
) -> dict:
    protect_required_claim_stage = task_kind in {"SEMANTIC_ADJUDICATION", "SYSTEM_ONE_ASSESSMENT"}
    protected_claim_calls = state.required_claim_calls_remaining() if protect_required_claim_stage else 0
    claim_deadline_floor = state.required_claim_deadline_floor() if protect_required_claim_stage else 0.0
    estimate = state.call_estimate(
        target,
        task_kind,
        task,
        evidence,
        fallback_size,
        deadline_floor_seconds=claim_deadline_floor,
    )
    if protected_claim_calls or claim_deadline_floor:
        return state.budget.reserve(
            key,
            estimate,
            provider_call_floor=protected_claim_calls,
            deadline_floor_seconds=claim_deadline_floor,
        )
    return state.budget.reserve(key, estimate)



def reserve_local_check_stage(state: RunState, key: str, input_bytes: int) -> dict:
    """Reserve bounded local check work without charging a provider call."""
    estimate = {
        "provider_calls": 0,
        "input_bytes": input_bytes,
        "max_output_bytes": int(state.limits["max_output_bytes_per_task"]),
        "max_cost_microunits": 0,
        "reservation_kind": "operator_bound",
        "deadline_seconds": state.remaining_call_limits()["deadline_seconds"],
    }
    return state.budget.reserve(key, estimate, kind="deterministic_check")



def validated_check_evidence_stage(state: RunState, task: dict, payload: dict) -> list[str]:
    """Bind deterministic-check outputs to the exact ingested evidence.

    Check adapters receive the immutable snapshot, but a task is authorized
    to consume only the evidence for its own configured binding. Preserve
    those validated references in the task and coverage ledgers; never let
    a check adapter claim evidence from another binding or snapshot.
    """
    from .engine import _check_evidence_hash
    binding_id = task.get("check_binding_id")
    if not isinstance(binding_id, str) or not binding_id:
        raise ValueError("check_binding_missing")
    if payload.get("check_id") != task.get("check_id"):
        raise ValueError("check_identity_mismatch")

    result_map = state.snapshot.get("external_check_results", {})
    evidence_map = state.snapshot.get("evidence", {})
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
                if key not in {"content_hash", "evidence_id", "source_kind", "trust", "snapshot_id"}
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
                or item.get("repository") != state.snapshot.get("repository")
                or item.get("pull_request_number") != state.snapshot.get("pull_request_number")
                or item.get("head_sha") != state.snapshot.get("head_sha")
                or ("snapshot_id" in item and item["snapshot_id"] != state.snapshot.get("snapshot_id"))
                or evidence_outcome != outcome
                or not isinstance(content_hash, str)
                or _check_evidence_hash(unsigned_item) != content_hash
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



def start_attempt_stage(state: RunState, task: dict, attempt_index: int) -> dict:
    from .engine import (
        BudgetExhausted,
        EnginePreflightError,
        IsolatedCallError,
        IsolatedInvocation,
        _canonical,
        _hash,
        _now,
        _settlement_observation,
        _validate_bound_specialist_input,
        _validate_context_followup_task,
        time,
        write_provider_exchange,
    )
    task_id = task["task_id"]
    evidence = state.evidence_cache[task_id]
    kind = task.get("task_kind", "SPECIALIST_FINDINGS")
    is_check = kind == "DETERMINISTIC_CHECK"
    target = state.check_adapter if is_check else state.provider
    capturing = state.private_capture is not None and not is_check and kind == "SPECIALIST_FINDINGS"
    method = "__call__" if is_check else "review_with_capture" if capturing else "review"
    expected_method = "__call__" if is_check else "review_with_capture" if capturing else "review"
    if target is None or not callable(target if is_check else getattr(target, expected_method, None)):
        return {
            "task_id": task_id,
            "status": "SKIPPED",
            "error_code": "CHECK_ADAPTER_UNAVAILABLE" if is_check else "PROVIDER_UNAVAILABLE",
            "attempts": attempt_index,
        }
    if kind == "SPECIALIST_FINDINGS":
        _validate_context_followup_task(task, state.ledger, state.snapshot, state.obligation_by_id, state.task_by_id)
        _validate_bound_specialist_input(task, state.snapshot, state.profile, evidence)
    required_size = state.review_input_size(task, evidence)
    invocation_limits = {**state.remaining_call_limits(), "attempt_index": attempt_index}
    if is_check:
        binding_id = task.get("check_binding_id")
        external_results = state.snapshot.get("external_check_results", {})
        evidence_map = state.snapshot.get("evidence", {})
        source_result = external_results.get(binding_id) if isinstance(external_results, dict) else None
        bound_result = (
            {key: source_result[key] for key in ("outcome", "evidence_id") if key in source_result}
            if isinstance(source_result, dict)
            else None
        )
        check_snapshot = {
            "repository": state.snapshot.get("repository"),
            "pull_request_number": state.snapshot.get("pull_request_number"),
            "head_sha": state.snapshot.get("head_sha"),
            "external_check_results": {binding_id: bound_result} if isinstance(bound_result, dict) else {},
            "evidence": {},
        }
        evidence_id = bound_result.get("evidence_id") if isinstance(bound_result, dict) else None
        if isinstance(evidence_id, str) and isinstance(evidence_map, dict):
            bound_evidence = evidence_map.get(evidence_id)
            if isinstance(bound_evidence, dict):
                check_snapshot["evidence"][evidence_id] = bound_evidence
        invocation_args = (task, check_snapshot, state.profile, invocation_limits)
        required_size = len(_canonical(invocation_args))
        task_input_ceiling = int(state.limits["max_input_bytes_per_task"])
    else:
        task_input_ceiling = state.input_ceiling
    if required_size > task_input_ceiling:
        return {
            "task_id": task_id,
            "status": "SKIPPED",
            "error_code": "INPUT_BYTE_LIMIT_EXCEEDED",
            "attempts": attempt_index,
        }
    reservation_key = f"{task_id}:{'check' if is_check else 'review'}:{attempt_index}"
    try:
        if is_check:
            reservation = state.reserve_local_check(reservation_key, required_size)
        else:
            reservation = state.reserve_provider_call(
                reservation_key,
                target,
                kind,
                task,
                evidence,
                required_size,
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
    capture_spec = None
    if capturing:
        capture_spec = state.private_capture.begin_call(run_id=state.run_id, task_id=task_id, attempt=attempt_index)
        capture_spec.update({
            "root": str(state.private_capture.root),
            "provider": state.private_capture.provider_identity,
        })
        if state.private_capture_request_pins is not None:
            pin = state.private_capture_request_pins.get(task_id)
            if not isinstance(pin, dict):
                state.private_capture.finalize_pending(capture_spec["call_id"], "failed")
                raise EnginePreflightError("invalid_review_request", "private capture task is not pinned")
            capture_spec.update({
                "strict_request_pin": True,
                "expected_task_id": task_id,
                "expected_request_sha256": pin["input_sha256"],
            })
    args = invocation_args if is_check else (
        (task, evidence, invocation_limits, capture_spec, write_provider_exchange)
        if capturing
        else (task, evidence, invocation_limits)
    )
    try:
        invocation = IsolatedInvocation(
            target,
            method,
            args,
            deadline_seconds=min(
                float(reservation.get("deadline_seconds", state.remaining_call_limits()["deadline_seconds"])),
                state.remaining_call_limits()["deadline_seconds"],
            ),
            output_limit=int(reservation["max_output_bytes"]),
        )
    except (IsolatedCallError, OSError, ValueError) as exc:
        # Expected spawn/argument boundary; a TypeError here is a harness
        # defect and propagates instead of becoming WORKER_START_FAILED.
        if capture_spec is not None:
            state.private_capture.finalize_pending(capture_spec["call_id"], "failed")
        try:
            state.budget.settle(
                reservation_key,
                output_bytes=None,
                usage={},
                status="FAILED",
                observation=_settlement_observation(
                    "deterministic_check"
                    if is_check
                    else "followup"
                    if ":followup:" in task_id
                    else "primary",
                    {},
                ),
            )
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
        "capture_spec": capture_spec,
        "started_at": _now(),
        "started_monotonic": time.monotonic(),
    }



def finish_attempt_stage(state: RunState, prepared: dict) -> dict:
    from .engine import (
        BudgetExhausted,
        IsolatedCallError,
        _canonical,
        _hash,
        _now,
        _settlement_observation,
        _unwrap,
        time,
    )
    task = prepared["task"]
    task_id = prepared["task_id"]
    evidence = prepared["evidence"]
    key = prepared["reservation_key"]
    invocation = prepared["invocation"]
    try:
        response = invocation.result()
        if prepared.get("capture_spec") is not None:
            capture_receipt = state.private_capture.reconcile(prepared["capture_spec"])
            if capture_receipt is None or capture_receipt.get("status") != "completed":
                state.private_capture.finalize_pending(prepared["capture_spec"]["call_id"], "failed")
                raise ValueError("provider capture receipt missing or incomplete")
        payload, usage, provenance = _unwrap(response)
        if len(_canonical(response)) > int(prepared["reservation"]["max_output_bytes"]):
            raise ValueError("output_limit")
        check_input_evidence_ids = None
        if prepared["is_check"]:
            if payload.get("outcome") not in {"PASS", "FINDINGS", "UNKNOWN", "ERROR"}:
                raise ValueError("invalid_check")
            check_input_evidence_ids = state.validated_check_evidence(task, payload)
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
        state.budget.settle(
            key,
            output_bytes=len(_canonical(response)),
            usage=usage,
            status="SUCCEEDED",
            observation=_settlement_observation(
                "deterministic_check"
                if prepared["is_check"]
                else "followup"
                if ":followup:" in prepared["task_id"]
                else "primary",
                usage,
                provenance,
                call_elapsed_ms=(time.monotonic() - prepared["started_monotonic"]) * 1000,
            ),
        )
        return {
            "task_id": task_id,
            "task_kind": prepared["kind"],
            "lens": task.get("lens"),
            "unit_ids": list(task.get("unit_ids", [])),
            "status": "SUCCEEDED",
            "input_hash": _hash(
                {
                    "evidence": _hash(evidence),
                    "snapshot_hash": state.snapshot.get("snapshot_hash"),
                    "check_binding_id": task.get("check_binding_id"),
                    "check_evidence_ids": check_input_evidence_ids,
                }
                if prepared["is_check"]
                else (
                    {"evidence": evidence, "context_target_manifest": task["context_target_manifest"]}
                    if isinstance(task.get("context_target_manifest"), dict)
                    else evidence
                )
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
    except (BudgetExhausted, IsolatedCallError, OSError, ValueError, KeyError) as exc:
        # Expected invocation/validation boundary. Defect types (TypeError,
        # AttributeError, ...) are deliberately absent and propagate.
        if prepared.get("capture_spec") is not None:
            try:
                if state.private_capture.reconcile(prepared["capture_spec"]) is None:
                    state.private_capture.finalize_pending(prepared["capture_spec"]["call_id"], "failed")
            except (OSError, TypeError, ValueError):
                state.private_capture.finalize_pending(prepared["capture_spec"]["call_id"], "failed")
        meta = getattr(exc, "meta", {})
        usage = meta.get("usage", {}) if isinstance(meta, dict) else {}
        try:
            state.budget.settle(
                key,
                output_bytes=meta.get("actual_output_bytes") if isinstance(meta, dict) else None,
                usage=usage,
                status="INVALID" if isinstance(exc, ValueError) else "FAILED",
                observation=_settlement_observation(
                    "deterministic_check"
                    if prepared["is_check"]
                    else "followup"
                    if ":followup:" in prepared["task_id"]
                    else "primary",
                    usage,
                    error_meta=meta,
                    call_elapsed_ms=(time.monotonic() - prepared["started_monotonic"]) * 1000,
                ),
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



def record_task_outcome_stage(state: RunState, task: dict, outcome: dict, reservation_key: str | None = None) -> None:
    from .engine import _now, review_contracts
    with state.state_lock:
        if task.get("request_input_contract") == review_contracts.SPECIALIST_INPUT_V2:
            outcome = {
                **outcome,
                "request_input_contract": task["request_input_contract"],
                "unit_evidence_bindings": task["unit_evidence_bindings"],
            }
        if "context_followup" in task:
            outcome = {**outcome, "context_followup": task["context_followup"]}
        if isinstance(task.get("context_target_manifest"), dict):
            outcome = {**outcome, "context_target_manifest": task["context_target_manifest"]}
        state.task_results[task["task_id"]] = outcome
        state.ledger["outputs"] = state.task_results
        if reservation_key:
            state.ledger.setdefault("invocations", []).append(
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
        state.checkpoint()



def run_followup_stage(state: RunState, task: dict, evidence: list[dict]) -> dict:
    from .engine import _hash
    task_id = task["task_id"]
    state.evidence_cache[task_id] = evidence
    max_attempts = 1 + int(state.limits["max_retries_per_task"])
    outcome: dict = {"task_id": task_id, "status": "SKIPPED", "error_code": "DEADLINE_EXHAUSTED", "attempts": 0}
    attempt_prefix = task_id + ":review:"
    prior_attempts = [
        int(key[len(attempt_prefix) :]) + 1
        for key in state.budget.state["reservations"]
        if key.startswith(attempt_prefix) and key[len(attempt_prefix) :].isdigit()
    ]
    for attempt in range(max(prior_attempts, default=0), max_attempts):
        if state.budget.remaining_seconds() <= 0:
            break
        prepared = state.start_attempt(task, attempt)
        if "invocation" not in prepared:
            outcome = prepared
            break
        invocation = prepared["invocation"]
        while not invocation.poll() and state.budget.remaining_seconds() > 0:
            invocation.wait_for_ready(timeout=state.budget.remaining_seconds())
        if invocation.poll():
            outcome = state.finish_attempt(prepared)
        else:
            invocation.cancel()
            try:
                state.budget.settle(prepared["reservation_key"], output_bytes=None, usage={}, status="TIMED_OUT")
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
        state.record_task_outcome(task, outcome, prepared["reservation_key"])
        if outcome.get("status") == "SUCCEEDED" or attempt + 1 >= max_attempts:
            break
    return outcome



def claim_not_run_stage(state: RunState, candidate_id: str, reason: str, **details: Any) -> None:
    state.claim_rows[candidate_id] = {
        "contract_version": state.claim_assessor_contract,
        "candidate_id": candidate_id,
        "status": "NOT_RUN",
        "reason_code": reason,
        **details,
    }
    state.checkpoint()



def report_notes_stage(state: RunState, field: str, detail_name: str) -> list[dict]:
    from .engine import _hash
    notes: dict[str, dict] = {}
    for task in state.tasks:
        outcome = state.task_results.get(task["task_id"], {})
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
            note_id = "note-" + _hash({"snapshot_id": state.snapshot.get("snapshot_id"), "kind": field, **basis})[:20]
            item = notes.setdefault(
                note_id,
                {
                    "finding_id": note_id,
                    "note_id": note_id,
                    "snapshot_id": state.snapshot.get("snapshot_id"),
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



def preflight_review(state: RunState) -> None:
    """Validate the review request and bind the trusted snapshot/plan/profile.

Contract: fail closed with ``EnginePreflightError`` before any provider
dispatch or result file creation.  No reservation is made here."""
    from .engine import (
        EnginePreflightError,
        _claim_assessor_binding,
        allow_empty_approve,
        effective_task_input_ceiling,
        prepare_plan_tasks,
        re,
        validate_claim_reconciliation_policy,
        validate_limits,
    )
    try:
        validate_limits(state.limits)
    except (TypeError, ValueError) as exc:
        raise EnginePreflightError("invalid_review_request", str(exc)) from None
    if (
        isinstance(state.max_claim_assessments, bool)
        or not isinstance(state.max_claim_assessments, int)
        or not 0 <= state.max_claim_assessments <= 4
    ):
        raise EnginePreflightError("invalid_review_request", "max_claim_assessments must be an integer from 0 to 4")
    try:
        state.reconciliation_policy = validate_claim_reconciliation_policy(state.profile)
    except (TypeError, ValueError) as exc:
        raise EnginePreflightError("invalid_review_request", str(exc)) from None
    if state.reconciliation_policy is not None and state.max_claim_assessments != state.reconciliation_policy["max_assessments"]:
        raise EnginePreflightError(
            "invalid_review_request",
            "required claim reconciliation cap must match the trusted profile",
        )
    state.claim_assessor_identity_hash = None
    state.claim_assessor_contract = None
    state.claim_assessor_code_hash = None
    state.expected_claim_contract = (
        "claim-assessment.3" if state.snapshot.get("comparison_mode") == "PR_MERGE_BASE" else "claim-assessment.2"
    )
    if state.max_claim_assessments > 0:
        if state.claim_assessor is None:
            raise EnginePreflightError("invalid_review_request", "positive max_claim_assessments requires a claim assessor")
        try:
            state.claim_assessor_identity_hash, state.claim_assessor_contract, state.claim_assessor_code_hash = _claim_assessor_binding(
                state.claim_assessor, state.expected_claim_contract
            )
        except (TypeError, ValueError) as exc:
            raise EnginePreflightError("invalid_review_request", str(exc)) from None
    if (
        not isinstance(state.run_id, str)
        or not state.run_id
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", state.run_id)
        or ".." in state.run_id
        or not isinstance(state.snapshot, dict)
        or not isinstance(state.plan, dict)
        or not isinstance(state.profile, dict)
    ):
        raise EnginePreflightError("invalid_review_request")
    try:
        state.contracts = effective_contract_set(
            load_registry(),
            state.profile,
            state.limits,
            comparison_mode=state.snapshot.get("comparison_mode"),
            claim_assessment_version=state.expected_claim_contract,
            max_claim_assessments=state.max_claim_assessments,
            allow_archived=getattr(state, "allow_archived_contracts", False),
        )
    except ContractRegistryError as exc:
        raise EnginePreflightError(
            "invalid_review_request", _CONTRACT_REJECTION_DETAILS.get(exc.code, "contract registry validation failed")
        ) from None
    try:
        state.approval_authority = allow_empty_approve(state.profile)
    except (TypeError, ValueError):
        raise EnginePreflightError("invalid_review_request") from None
    if state.plan.get("snapshot_id") not in (None, state.snapshot.get("snapshot_id")):
        raise EnginePreflightError("invalid_review_request")
    state.tasks = state.plan.get("tasks")
    state.obligations = state.plan.get("coverage_obligations")
    if not isinstance(state.tasks, list) or not isinstance(state.obligations, list):
        raise EnginePreflightError("invalid_review_request")
    state.obligations = list(state.obligations)
    try:
        state.input_ceiling = effective_task_input_ceiling(state.limits, state.provider)
        state.primary_tasks, state.split_skips = prepare_plan_tasks(
            state.snapshot, {"tasks": state.tasks, "coverage_obligations": state.obligations}, state.profile, state.limits, state.provider
        )
        state.primary_task_inputs = [
            {
                "task_id": task["task_id"],
                "task_kind": task.get("task_kind", "SPECIALIST_FINDINGS"),
                "unit_ids": list(task.get("unit_ids", [])),
                "evidence_ids": list(task.get("evidence_ids", [])),
                "request_input_contract": task.get("request_input_contract"),
                "unit_evidence_bindings": task.get("unit_evidence_bindings"),
            }
            for task in state.primary_tasks
        ]
    except EnginePreflightError:
        raise
    except (KeyError, TypeError, ValueError) as exc:
        raise EnginePreflightError("invalid_review_request", str(exc)) from None



def resume_completed_review(state: RunState) -> dict | None:
    """Build request identity, open the ledger, and load a prior result.

Contract: an existing result is returned only after resume validation;
a non-resume collision raises ``run_id_already_exists``.  Returns the
saved result (refreshed for freshness) or ``None`` to start a new run."""
    from .engine import (
        EnginePreflightError,
        IsolatedCallError,
        Path,
        _atomic_write,
        _bounded_freshness,
        _canonical,
        _core_contract_hash,
        _hash,
        _load_validated_resume_state,
        _now,
        _provider_identity,
        _reduce,
        review_contracts,
        time,
    )
    state.output_path = Path(state.output_dir).resolve() / f"{state.run_id}.json"
    state.provider_identity = _provider_identity(state.provider, state.decision_provider)
    state.request_basis = {
        "snapshot": state.snapshot,
        "plan": state.plan,
        "profile": state.profile,
        "limits": state.limits,
        "provider": state.provider_identity,
        "run_id": state.run_id,
        "primary_task_inputs": state.primary_task_inputs,
        "request_input_contract": review_contracts.SPECIALIST_INPUT_V2,
        "core_contract_hash": _core_contract_hash(),
    }
    if state.max_claim_assessments > 0:
        state.request_basis["claim_assessment"] = {
            "assessor_identity_hash": state.claim_assessor_identity_hash,
            "implementation_hash": state.claim_assessor_code_hash,
            "contract_version": state.claim_assessor_contract,
            "max_assessments": state.max_claim_assessments,
        }
    if state.reconciliation_policy is not None:
        state.request_basis["claim_reconciliation"] = state.reconciliation_policy
    state.request_hash = _hash(state.request_basis)
    state.deadline_epoch = time.time() + float(state.limits["deadline_seconds"])
    state.ledger = {
        "ledger_version": "0.2",
        "request_hash": state.request_hash,
        "run_started_at_epoch": time.time(),
        "events": [],
        "outputs": {},
        "candidate_records": [],
        "budget": {"reservations": {}, "settlements": {}, "context_retrievals": 0, "followup_tasks": 0},
        "deadline_epoch": state.deadline_epoch,
        "identity": {
            "snapshot_id": state.snapshot.get("snapshot_id"),
            "profile_version": state.profile.get("version", state.profile.get("profile_version")),
            "question_versions": sorted({str(t.get("question_version", "0.1")) for t in state.tasks}),
            "provider_identity_hash": _hash(state.provider_identity),
            "plan_hash": _hash(state.plan),
            "primary_task_inputs_hash": _hash(state.primary_task_inputs),
            "request_input_contract": review_contracts.SPECIALIST_INPUT_V2,
            "core_contract_hash": _core_contract_hash(),
            "effective_contracts": state.contracts,
        },
    }
    if state.max_claim_assessments > 0:
        state.ledger["identity"]["claim_assessment"] = {
            "assessor_identity_hash": state.claim_assessor_identity_hash,
            "implementation_hash": state.claim_assessor_code_hash,
            "contract_version": state.claim_assessor_contract,
            "max_assessments": state.max_claim_assessments,
        }
    if state.reconciliation_policy is not None:
        state.ledger["identity"]["claim_reconciliation"] = state.reconciliation_policy
    if state.output_path.exists():
        if not state.resume:
            raise EnginePreflightError("run_id_already_exists")
        state.saved, state.ledger = _load_validated_resume_state(
            state.output_path,
            state.request_hash,
            state.snapshot,
            state.primary_tasks,
            state.obligations,
            state.input_ceiling,
            state.profile,
        )
        if state.saved.get("completed_at"):
            if callable(state.freshness_check):
                try:
                    state.check = _bounded_freshness(state.freshness_check, 5.0)
                    if isinstance(state.check, dict) and state.check.get("freshness") in {"CURRENT", "STALE", "UNKNOWN"}:
                        state.saved["freshness"] = state.check["freshness"]
                        state.saved["freshness_details"] = {
                            "expected_head_sha": state.snapshot.get("head_sha"),
                            **{k: v for k, v in state.check.items() if k != "freshness"},
                        }
                    else:
                        state.saved["freshness"] = "UNKNOWN"
                        state.saved["freshness_details"] = {
                            "expected_head_sha": state.snapshot.get("head_sha"),
                            "observed_head_sha": None,
                        }
                    state.saved["disposition"] = _reduce(
                        state.saved,
                        state.saved.get("allow_empty_approve") is True,
                        state.saved.get("policy_valid", False),
                    )
                    state.saved["completed_at"] = _now()
                    state.saved["result_hash"] = _hash({k: v for k, v in state.saved.items() if k != "result_hash"})
                    _atomic_write(state.output_path, _canonical(state.saved) + b"\n")
                except (IsolatedCallError, OSError, TimeoutError, ValueError, KeyError) as exc:
                    if isinstance(exc, IsolatedCallError) and is_defect(exc):
                        raise
                    # Expected freshness/write boundary: the prior result is
                    # rewritten as UNKNOWN freshness, which cannot approve.
                    state.saved["freshness"] = "UNKNOWN"
                    state.saved["freshness_details"] = {
                        "expected_head_sha": state.snapshot.get("head_sha"),
                        "observed_head_sha": None,
                        "freshness_check_error": True,
                    }
                    state.saved["disposition"] = _reduce(
                        state.saved,
                        state.saved.get("allow_empty_approve") is True,
                        state.saved.get("policy_valid", False),
                    )
                    state.saved["completed_at"] = _now()
                    state.saved["result_hash"] = _hash({k: v for k, v in state.saved.items() if k != "result_hash"})
                    _atomic_write(state.output_path, _canonical(state.saved) + b"\n")
            elif state.snapshot.get("freshness_basis") != "HISTORICAL_SNAPSHOT":
                state.saved["freshness"] = "UNKNOWN"
                state.saved["freshness_details"] = {
                    "expected_head_sha": state.snapshot.get("head_sha"),
                    "observed_head_sha": None,
                }
                state.saved["disposition"] = _reduce(
                    state.saved,
                    state.saved.get("allow_empty_approve") is True,
                    state.saved.get("policy_valid", False),
                )
                state.saved["completed_at"] = _now()
                state.saved["result_hash"] = _hash({k: v for k, v in state.saved.items() if k != "result_hash"})
                _atomic_write(state.output_path, _canonical(state.saved) + b"\n")
            return state.saved
    else:
        state.event = {"event": "RUN_STARTED", "at": _now()}
        state.event["event_hash"] = _hash(state.event)
        state.ledger["events"].append(state.event)



def bind_run_state(state: RunState) -> None:
    """Bind resume-carried evidence, dynamic tasks, ledger, and call indexes.

Contract: reserve-before-dispatch and fail-closed resume.  A reservation
that outlived its process is settled INTERRUPTED_UNKNOWN and its key is
never dispatched again."""
    from .engine import (
        BudgetLedger,
        EnginePreflightError,
        _evidence_for,
        _now,
        _same_evidence_content,
        _task_input_provenance,
        _validate_bound_specialist_input,
        _validate_context_followup_task,
        review_contracts,
        threading,
    )
    if state.max_claim_assessments > 0:
        state.ledger.setdefault("claim_assessments", {})
    # Dynamic follow-up requests and retrieved immutable evidence are part of
    # the durable run state, while request identity remains the original
    # snapshot+plan+profile contract.
    state.snapshot_captured_evidence = dict(state.snapshot.get("evidence", {}))
    state.snapshot = {**state.snapshot, "evidence": dict(state.snapshot_captured_evidence)}
    state.retrieved_context = state.ledger.get("retrieved_context", {})
    if isinstance(state.retrieved_context, dict):
        for state.entry in state.retrieved_context.values():
            if isinstance(state.entry, dict):
                for state.evidence in state.entry.get("evidence", []):
                    if isinstance(state.evidence, dict) and isinstance(state.evidence.get("evidence_id"), str):
                        state.existing = state.snapshot["evidence"].get(state.evidence["evidence_id"])
                        if state.existing is not None and not _same_evidence_content(state.existing, state.evidence):
                            raise EnginePreflightError("resume_state_invalid", "resume evidence identity mismatch")
                        state.snapshot["evidence"].setdefault(state.evidence["evidence_id"], state.evidence)
    state.tasks = state.primary_tasks
    state.dynamic_tasks = [t for t in state.ledger.get("dynamic_tasks", []) if isinstance(t, dict)]
    if isinstance(state.ledger.get("dynamic_obligations"), list):
        state.obligations = list(state.obligations) + [o for o in state.ledger["dynamic_obligations"] if isinstance(o, dict)]
    state.deadline_epoch = float(state.ledger.get("deadline_epoch", state.deadline_epoch))
    state.state_lock = threading.RLock()
    state.checkpoint = functools.partial(checkpoint_stage, state)
    state.budget = BudgetLedger(state.limits, state.ledger.setdefault("budget", {}), persist=state.checkpoint, deadline_epoch=state.deadline_epoch)
    # A process crash after reservation is an uncertain paid attempt. Settle it
    # as unknown and never reuse its idempotency key for another dispatch.
    for state.reservation_key, state.reservation in list(state.budget.state["reservations"].items()):
        if state.reservation.get("provider_calls", 0) > 0 and state.reservation_key not in state.budget.state["settlements"]:
            state.budget.settle(state.reservation_key, output_bytes=None, usage={}, status="INTERRUPTED_UNKNOWN")
            state.ledger.setdefault("invocations", []).append(
                {
                    "reservation_key": state.reservation_key,
                    "status": "INTERRUPTED_UNKNOWN",
                    "at": _now(),
                }
            )
    state.task_by_id = {}
    for state.task in state.tasks:
        if not isinstance(state.task, dict) or not state.task.get("task_id") or not state.task.get("obligation_id"):
            raise ValueError("invalid planned task")
        if state.task["task_id"] in state.task_by_id:
            raise ValueError("duplicate task_id")
        state.task_by_id[state.task["task_id"]] = state.task
    state.obligation_by_id = {
        o.get("obligation_id"): o for o in state.obligations if isinstance(o, dict) and o.get("obligation_id")
    }
    if len(state.obligation_by_id) != len(state.obligations):
        raise ValueError("invalid or duplicate coverage obligation")
    for state.task in state.tasks:
        if not set(state.task.get("obligation_ids", [state.task["obligation_id"]])).issubset(state.obligation_by_id):
            raise ValueError("task references unknown obligation")
    state.known_task_ids = {task["task_id"] for task in state.tasks}
    for state.task in state.dynamic_tasks:
        if not state.task.get("task_id") or not state.task.get("obligation_id") or state.task["task_id"] in state.known_task_ids:
            raise ValueError("invalid_or_duplicate_dynamic_task")
        if state.task.get("task_kind", "SPECIALIST_FINDINGS") == "SPECIALIST_FINDINGS":
            _validate_context_followup_task(state.task, state.ledger, state.snapshot, state.obligation_by_id, state.task_by_id)
            state.evidence = _evidence_for(state.task, state.snapshot, state.input_ceiling)
            _validate_bound_specialist_input(state.task, state.snapshot, state.profile, state.evidence)
        if not set(state.task.get("obligation_ids", [state.task["obligation_id"]])).issubset(state.obligation_by_id):
            raise ValueError("dynamic_task_references_unknown_obligation")
        state.known_task_ids.add(state.task["task_id"])
        state.task_by_id[state.task["task_id"]] = state.task
        state.tasks.append(state.task)
    state.planned_task_inputs = {
        task["task_id"]: _task_input_provenance(task)
        for task in state.tasks
        if task.get("request_input_contract") == review_contracts.SPECIALIST_INPUT_V2
    }
    if "planned_task_inputs" in state.ledger and state.ledger["planned_task_inputs"] != state.planned_task_inputs:
        raise ValueError("resume planned input binding mismatch")
    state.ledger["planned_task_inputs"] = state.planned_task_inputs



def install_review_input_size(state: RunState) -> None:
    """Install the provider-aware request-size measure used for splits and quotes."""
    state.review_input_size = functools.partial(review_input_size_stage, state)



def prepare_dispatch(state: RunState) -> None:
    """Compute pending work, evidence bindings, and internal private capture.

Contract: every specialist task is validated against exactly its bound
evidence before dispatch; capture pins are verified byte-for-byte."""
    from .engine import (
        MAX_CAPTURE_CALLS,
        MAX_REQUEST_BYTES,
        MAX_RESPONSE_BYTES,
        MAX_TOTAL_BYTES,
        EnginePreflightError,
        PrivateShadowCapture,
        _evidence_for,
        _private_capture_profile_id,
        _validate_bound_specialist_input,
        hashlib,
        serialize_source_audit_request,
        threading,
    )
    state.call_lock = threading.Lock()
    state.task_results = dict(state.ledger.get("outputs", {}))
    for state.key, state.value in state.split_skips.items():
        state.task_results[state.key] = state.value
    state.pending = [
        t for t in state.tasks if t["task_id"] not in state.task_results or state.task_results[t["task_id"]].get("status") != "SUCCEEDED"
    ]
    state.evidence_cache = {t["task_id"]: _evidence_for(t, state.snapshot, state.input_ceiling) for t in state.tasks}
    for state.task in state.tasks:
        if state.task.get("task_kind", "SPECIALIST_FINDINGS") == "SPECIALIST_FINDINGS":
            _validate_bound_specialist_input(state.task, state.snapshot, state.profile, state.evidence_cache[state.task["task_id"]])
    state.private_capture = None
    if state.private_capture_dir is not None:
        if state.resume or not callable(getattr(state.provider, "review_with_capture", None)):
            raise EnginePreflightError("invalid_review_request", "private capture requires a fresh capture-capable provider")
        if (
            isinstance(state.private_capture_source_audit_max_bytes, bool)
            or not isinstance(state.private_capture_source_audit_max_bytes, int)
            or not 1 <= state.private_capture_source_audit_max_bytes <= MAX_REQUEST_BYTES
        ):
            raise EnginePreflightError("invalid_review_request", "source audit request limit invalid")
        if state.private_capture_case_id is not None:
            state.audit_limits = {
                "max_input_bytes_per_task": state.private_capture_source_audit_max_bytes,
                "max_output_bytes_per_task": 64_000,
                "max_output_tokens": 1_800,
            }
            try:
                state.profile_id = _private_capture_profile_id(state.profile)
            except (TypeError, ValueError) as exc:
                raise EnginePreflightError(
                    "invalid_review_request", "private capture profile identity is invalid"
                ) from exc
            for state.task in state.primary_tasks:
                if state.task.get("task_kind", "SPECIALIST_FINDINGS") != "SPECIALIST_FINDINGS":
                    continue
                try:
                    state.source_request = serialize_source_audit_request(
                        state.provider,
                        case_id=state.private_capture_case_id,
                        snapshot=state.snapshot,
                        profile_id=state.profile_id,
                        task=state.task,
                        evidence=state.evidence_cache[state.task["task_id"]],
                        limits=state.audit_limits,
                    )
                except (KeyError, TypeError, ValueError, RuntimeError) as exc:
                    raise EnginePreflightError(
                        "invalid_review_request", "source audit request serialization failed"
                    ) from exc
                if len(state.source_request) > state.private_capture_source_audit_max_bytes:
                    raise EnginePreflightError(
                        "invalid_review_request", "source audit request exceeds configured byte limit"
                    )
        if state.private_capture_request_pins is not None:
            state.planned = [
                task for task in state.primary_tasks
                if task.get("task_kind", "SPECIALIST_FINDINGS") == "SPECIALIST_FINDINGS"
            ]
            if (
                not isinstance(state.private_capture_request_pins, dict)
                or len(state.private_capture_request_pins) != len(state.planned)
                or {task.get("task_id") for task in state.planned} != set(state.private_capture_request_pins)
                or not isinstance(state.private_capture_snapshot_pin, dict)
                or state.snapshot.get("snapshot_id") != state.private_capture_snapshot_pin.get("snapshot_id")
                or state.snapshot.get("snapshot_hash") != state.private_capture_snapshot_pin.get("snapshot_sha256")
                or not callable(getattr(state.provider, "serialize_review_request", None))
                or state.limits.get("max_provider_calls") < len(state.private_capture_request_pins)
                or state.limits.get("max_retries_per_task") != 0
                or state.limits.get("max_followup_tasks") != 0
                or state.decision_provider is not None
                or state.max_claim_assessments != 0
            ):
                raise EnginePreflightError("invalid_review_request", "private capture plan binding mismatch")
            for state.task in state.planned:
                state.task_id = state.task.get("task_id")
                state.pin = state.private_capture_request_pins.get(state.task_id)
                if not isinstance(state.pin, dict):
                    raise EnginePreflightError("invalid_review_request", "private capture task is not pinned")
                state.request_bytes = state.provider.serialize_review_request(state.task, state.evidence_cache[state.task_id], state.limits)
                if (
                    hashlib.sha256(state.request_bytes).hexdigest() != state.pin.get("input_sha256")
                    or len(state.request_bytes) != state.pin.get("input_bytes")
                    or state.task.get("lens") != state.pin.get("lens")
                    or min(state.provider.max_response_bytes, state.limits["max_output_bytes_per_task"])
                    != state.pin.get("output_bytes_cap")
                    or min(state.provider.max_output_tokens, state.limits["max_output_tokens"])
                    != state.pin.get("output_tokens_cap")
                ):
                    raise EnginePreflightError("invalid_review_request", "private capture request bytes changed")
        state.call_cap = state.limits["max_provider_calls"]
        state.input_cap = min(state.limits["max_input_bytes_per_task"], state.input_ceiling)
        state.output_cap = state.limits["max_output_bytes_per_task"]
        if (
            state.call_cap > MAX_CAPTURE_CALLS
            or state.input_cap > MAX_REQUEST_BYTES
            or state.output_cap > MAX_RESPONSE_BYTES
            or state.call_cap * (state.input_cap + state.output_cap) > MAX_TOTAL_BYTES
        ):
            raise EnginePreflightError("invalid_review_request", "private capture capacity exceeds its fixed limits")
        try:
            state.capture_profile_id = _private_capture_profile_id(state.profile)
            state.private_capture = PrivateShadowCapture(
                state.private_capture_dir,
                case_id=state.run_id,
                snapshot=state.snapshot,
                source_task=state.run_id,
                provider=state.provider,
                request_byte_limit=state.input_cap,
                response_byte_limit=state.output_cap,
                corpus_case_id=state.private_capture_case_id,
            )
            state.private_capture.export_source_tasks(
                [
                    {"task": task, "evidence": state.evidence_cache[task["task_id"]]}
                    for task in state.primary_tasks
                    if task.get("task_kind", "SPECIALIST_FINDINGS") == "SPECIALIST_FINDINGS"
                ],
                profile_id=state.capture_profile_id,
            )
        except (OSError, TypeError, ValueError) as exc:
            raise EnginePreflightError("invalid_review_request", f"private capture unavailable: {type(exc).__name__}") from None



def install_budget_helpers(state: RunState) -> None:
    """Install estimate/reservation/check-validation helpers on the state.

Contract: reserve-before-dispatch.  Required claim-assessment capacity is
protected by a call floor and a deadline floor at every reservation."""
    state.remaining_call_limits = functools.partial(remaining_call_limits_stage, state)
    state.required_claim_calls_remaining = functools.partial(required_claim_calls_remaining_stage, state)
    state.required_claim_deadline_floor = functools.partial(required_claim_deadline_floor_stage, state)
    state.call_estimate = functools.partial(call_estimate_stage, state)
    state.reserve_provider_call = functools.partial(reserve_provider_call_stage, state)
    state.reserve_local_check = functools.partial(reserve_local_check_stage, state)
    state.validated_check_evidence = functools.partial(validated_check_evidence_stage, state)



def quote_monetary_budget(state: RunState) -> None:
    """Reject a configured monetary budget unless every call is operator-bound."""
    if state.limits.get("max_cost_microunits") is not None:
        for state.planned_task in state.tasks:
            if state.planned_task.get("task_kind") == "DETERMINISTIC_CHECK":
                # Deterministic checks are bounded local work, not provider
                # calls requiring a provider quote.
                continue
            state.target = state.check_adapter if state.planned_task.get("task_kind") == "DETERMINISTIC_CHECK" else state.provider
            if state.target is None:
                continue
            state.evidence = state.evidence_cache[state.planned_task["task_id"]]
            state.quote = state.call_estimate(
                state.target,
                state.planned_task.get("task_kind", "SPECIALIST_FINDINGS"),
                state.planned_task,
                state.evidence,
                state.review_input_size(state.planned_task, state.evidence),
            )
            if state.quote.get("reservation_kind") != "operator_bound":
                raise ValueError("configured monetary budget requires operator-bound per-call reservations")
        if state.decision_provider is not None and callable(getattr(state.decision_provider, "assess", None)):
            state.quote = state.call_estimate(state.decision_provider, "SYSTEM_ONE_ASSESSMENT", {}, [], 0)
            if state.quote.get("reservation_kind") != "operator_bound":
                raise ValueError("configured monetary budget requires operator-bound per-call reservations")



def install_attempt_lifecycle(state: RunState) -> None:
    """Install the per-attempt open/settle helpers on the state.

Contract: a task either holds a reservation or is terminally skipped; an
attempt is settled exactly once with its observed bytes and usage."""
    state.start_attempt = functools.partial(start_attempt_stage, state)
    state.finish_attempt = functools.partial(finish_attempt_stage, state)



def dispatch_tasks(state: RunState) -> None:
    """Dispatch reserved specialist/check work and record task outcomes.

Contract: deterministic scheduling only; each settlement records observed
output, and a failed or unavailable attempt stays explicitly unsuccessful."""
    from .engine import _hash, _now, _settlement_observation, review_contracts, time, wait_for_any
    state.max_workers = int(state.limits["max_concurrent_scopes"])
    state.max_context = int(state.limits["max_context_bytes"])
    state.used_context = 0
    state.ledger["outputs"] = state.task_results
    state.ledger["planned_tasks"] = [t["task_id"] for t in state.tasks]
    state.checkpoint()
    state.queue: list[tuple[dict, int]] = []
    for state.task in state.pending:
        state.old = state.task_results.get(state.task["task_id"], {})
        state.attempts_done = int(state.old.get("attempts", 0)) if isinstance(state.old, dict) else 0
        state.prefix = state.task["task_id"] + ":"
        state.reserved_attempts = [
            int(key.rsplit(":", 1)[-1]) + 1
            for key in state.budget.state["reservations"]
            if key.startswith(state.prefix)
            and key.rsplit(":", 1)[0].endswith((":review", ":check"))
            and key.rsplit(":", 1)[-1].isdigit()
        ]
        state.attempts_done = max([state.attempts_done, *state.reserved_attempts])
        if state.attempts_done < 1 + int(state.limits["max_retries_per_task"]):
            state.queue.append((state.task, state.attempts_done))
        elif state.attempts_done and state.task["task_id"] not in state.task_results:
            state.task_results[state.task["task_id"]] = {
                "task_id": state.task["task_id"],
                "task_kind": state.task.get("task_kind"),
                "lens": state.task.get("lens"),
                "unit_ids": list(state.task.get("unit_ids", [])),
                "status": "FAILED",
                "error_code": "INTERRUPTED_UNKNOWN",
                "input_evidence_ids": [],
                "attempts": state.attempts_done,
                **(
                    {
                        "request_input_contract": state.task["request_input_contract"],
                        "unit_evidence_bindings": state.task["unit_evidence_bindings"],
                    }
                    if state.task.get("request_input_contract") == review_contracts.SPECIALIST_INPUT_V2
                    else {}
                ),
                **({"context_followup": state.task["context_followup"]} if "context_followup" in state.task else {}),
                **(
                    {"context_target_manifest": state.task["context_target_manifest"]}
                    if isinstance(state.task.get("context_target_manifest"), dict)
                    else {}
                ),
            }
    state.active: dict[int, dict] = {}
    state.record_task_outcome = functools.partial(record_task_outcome_stage, state)
    while state.queue or state.active:
        while state.queue and len(state.active) < state.max_workers and state.budget.remaining_seconds() > 0:
            state.task, state.attempt_index = state.queue.pop(0)
            state.evidence = state.evidence_cache[state.task["task_id"]]
            state.estimated_size = state.review_input_size(state.task, state.evidence)
            if state.used_context + state.estimated_size > state.max_context:
                state.record_task_outcome(
                    state.task,
                    {
                        "task_id": state.task["task_id"],
                        "status": "SKIPPED",
                        "error_code": "RUN_CONTEXT_BUDGET_EXHAUSTED",
                        "attempts": state.attempt_index,
                    },
                )
                continue
            state.prepared = state.start_attempt(state.task, state.attempt_index)
            if "invocation" not in state.prepared:
                state.record_task_outcome(state.task, state.prepared)
                continue
            state.used_context += int(state.prepared["reservation"].get("input_bytes", state.estimated_size))
            state.active[id(state.prepared["invocation"])] = state.prepared
        state.completed_ids = []
        for state.active_key, state.prepared in list(state.active.items()):
            state.invocation = state.prepared["invocation"]
            if state.invocation.poll():
                state.outcome = state.finish_attempt(state.prepared)
                state.completed_ids.append(state.active_key)
                state.attempt_index = state.prepared["attempt_index"]
                if (
                    state.outcome.get("status") in {"FAILED", "INVALID", "TIMED_OUT"}
                    and state.attempt_index < int(state.limits["max_retries_per_task"])
                    and state.budget.remaining_seconds() > 0
                ):
                    state.queue.append((state.prepared["task"], state.attempt_index + 1))
                    with state.state_lock:
                        state.ledger.setdefault("invocations", []).append(
                            {
                                "reservation_key": state.prepared["reservation_key"],
                                "task_id": state.prepared["task_id"],
                                "status": state.outcome.get("status"),
                                "provider_error_meta": state.outcome.get("provider_error_meta", {}),
                                "attempt": state.attempt_index + 1,
                                "at": _now(),
                            }
                        )
                        state.checkpoint()
                else:
                    state.record_task_outcome(state.prepared["task"], state.outcome, state.prepared["reservation_key"])
        for state.key in state.completed_ids:
            state.active.pop(state.key, None)
        if state.budget.remaining_seconds() <= 0:
            for state.prepared in state.active.values():
                state.prepared["invocation"].cancel()
                state.outcome = {
                    "task_id": state.prepared["task_id"],
                    "status": "TIMED_OUT",
                    "error_code": "DEADLINE_EXCEEDED",
                    "error_summary": "TimeoutError",
                    "input_hash": _hash(state.prepared["evidence"]),
                    "attempts": state.prepared["attempt_index"] + 1,
                    "finished_at": _now(),
                }
                try:
                    state.budget.settle(
                        state.prepared["reservation_key"],
                        output_bytes=None,
                        usage={},
                        status="TIMED_OUT",
                        observation=_settlement_observation(
                            "deterministic_check"
                            if state.prepared["is_check"]
                            else "followup"
                            if ":followup:" in state.prepared["task_id"]
                            else "primary",
                            {},
                            call_elapsed_ms=(time.monotonic() - state.prepared["started_monotonic"]) * 1000,
                        ),
                    )
                except (ValueError, KeyError):
                    pass
                state.record_task_outcome(state.prepared["task"], state.outcome, state.prepared["reservation_key"])
            state.active.clear()
            for state.task, state.attempt_index in state.queue:
                state.record_task_outcome(
                    state.task,
                    {
                        "task_id": state.task["task_id"],
                        "status": "SKIPPED",
                        "error_code": "DEADLINE_EXHAUSTED",
                        "attempts": state.attempt_index,
                    },
                )
            state.queue.clear()
        elif not state.completed_ids and state.active:
            wait_for_any(
                [prepared["invocation"] for prepared in state.active.values()],
                timeout=state.budget.remaining_seconds(),
            )
    state.ledger["outputs"] = state.task_results



def prepare_followups(state: RunState) -> None:
    """Index existing results, evidence, and units for follow-up binding."""
    state.checkpoint()
    state.findings: list[dict] = list(state.ledger.get("findings", []))
    state.context_gaps: list[dict] = list(state.ledger.get("context_gaps", []))
    state.existing_gap_ids = {gap.get("proposal_id") for gap in state.context_gaps if isinstance(gap, dict)}
    for state.task in state.tasks:
        for state.evidence_id in state.task.get("required_context_omissions", []):
            state.gap_id = f"{state.task['task_id']}:required-context-omission:{state.evidence_id}"
            if state.gap_id in state.existing_gap_ids:
                continue
            state.evidence_item = state.snapshot.get("evidence", {}).get(state.evidence_id, {})
            state.context_gaps.append(
                {
                    "task_id": state.task["task_id"],
                    "proposal_id": state.gap_id,
                    "status": "VALID_UNRESOLVED",
                    "reason_code": "REQUIRED_CONTEXT_OMITTED_BY_INPUT_LIMIT",
                    "path": state.evidence_item.get("path"),
                    "evidence_id": state.evidence_id,
                    "affected_obligation_ids": list(state.task.get("obligation_ids", [state.task.get("obligation_id")])),
                    "affected_unit_ids": list(state.task.get("unit_ids", [])),
                    "required_lens": state.task.get("lens"),
                }
            )
            state.existing_gap_ids.add(state.gap_id)
    state.gap_obligations: dict[str, list[str]] = {}
    for state.gap in state.context_gaps:
        if state.gap.get("status") == "RESOLVED_BY_FOLLOWUP":
            continue
        for state.oid in state.gap.get("affected_obligation_ids", []):
            state.gap_obligations.setdefault(state.oid, []).append(state.gap["proposal_id"])
    state.known_ids = {f.get("finding_id") for f in state.findings}
    state.evidence_map = state.snapshot.get("evidence", {}) if isinstance(state.snapshot.get("evidence", {}), dict) else {}
    state.unit_map = {u.get("unit_id"): u for u in state.snapshot.get("inventory", []) if isinstance(u, dict)}



def install_followup_runner(state: RunState) -> None:
    """Install the bounded context follow-up runner on the state."""
    state.run_followup = functools.partial(run_followup_stage, state)



def run_followups(state: RunState) -> None:
    """Execute bounded retrieval/context follow-ups and bind their evidence."""
    from .engine import (
        _ADJUDICATION_RUBRIC,
        _ADJUDICATION_V3,
        _CAUSAL_ROLES,
        BudgetExhausted,
        IsolatedCallError,
        IsolatedInvocation,
        _bind_specialist_input,
        _canonical,
        _complete_snapshot_context_evidence,
        _context_followup_metadata,
        _coverage_note_observation,
        _hash,
        _merge_evidence_rows,
        _same_evidence_content,
        _settlement_observation,
        _task_input_provenance,
        _unwrap,
        _validated_v3_causal_roles,
        fnmatch,
        hashlib,
        isolated_call,
        re,
        stable_candidate_id,
        time,
        validate_context_target_choice,
        validate_location,
    )
    for state.task in state.tasks:
        state.result = state.task_results.get(state.task["task_id"], {})
        if state.result.get("status") != "SUCCEEDED" or state.task["task_id"] in state.ledger.get("reconciled_tasks", []):
            continue
        state.payload = state.result.get("payload", {})
        state.task_units = set(state.task.get("unit_ids", state.task.get("scope_unit_ids", [])))
        for state.index, state.proposal in enumerate(state.payload.get("context_gap_proposals", [])):
            state.record = {"task_id": state.task["task_id"], "proposal_id": f"{state.task['task_id']}:gap:{state.index}", "proposal": state.proposal}
            state.manifest = state.task.get("context_target_manifest")
            state.manifest_choice = (
                validate_context_target_choice(state.manifest, state.proposal)
                if isinstance(state.manifest, dict)
                else None
            )
            state.valid = isinstance(state.proposal, dict) and state.proposal.get("evidence_kind") in {
                "caller",
                "implementation",
                "test",
                "configuration",
                "contract",
                "trust_boundary",
                "provenance",
                "other",
            }
            state.target = state.proposal.get("target", {}) if isinstance(state.proposal, dict) else {}
            if (
                not isinstance(state.target, dict)
                or set(state.target) != {"target_unit_id", "target_path", "target_symbol"}
                or sum(bool(state.target.get(k)) for k in state.target) != 1
            ):
                state.valid = False
            state.target_unit = (
                state.target.get("target_unit_id")
                if isinstance(state.target, dict) and isinstance(state.target.get("target_unit_id"), str)
                else None
            )
            if state.target_unit is None and isinstance(state.target, dict) and state.target.get("target_path"):
                state.candidates = [uid for uid in state.task_units if state.unit_map.get(uid, {}).get("path") == state.target["target_path"]]
                state.target_unit = state.candidates[0] if len(state.candidates) == 1 else None
            state.lens = (
                state.proposal.get("required_lens")
                if isinstance(state.proposal, dict) and isinstance(state.proposal.get("required_lens"), str)
                else None
            )
            state.refs = state.proposal.get("related_evidence_ids", []) if isinstance(state.proposal, dict) else []
            state.valid_target = bool(
                isinstance(state.target, dict)
                and all(state.target.get(k) is None or isinstance(state.target.get(k), str) for k in state.target)
                and (
                    state.target_unit
                    or state.target.get("target_symbol")
                    or (
                        isinstance(state.target.get("target_path"), str)
                        and state.target["target_path"]
                        and not state.target["target_path"].startswith("/")
                        and ".." not in state.target["target_path"].split("/")
                    )
                )
            )
            state.valid = bool(
                state.valid
                and state.valid_target
                and state.lens
                in {"correctness", "tests", "design", "security", "performance", "maintainability", "project_specific"}
                and isinstance(state.proposal.get("rationale"), str)
                and state.proposal.get("rationale")
                and isinstance(state.refs, list)
                and all(isinstance(ref, str) for ref in state.refs)
                and set(state.refs).issubset(set(state.task.get("evidence_ids", [])))
                and state.refs
            )
            if isinstance(state.manifest, dict) and state.manifest_choice is None:
                state.valid = False
                state.record["reason_code"] = "context_target_not_in_trusted_manifest"
            state.record["status"] = "VALID_UNRESOLVED" if state.valid else "INVALID"
            state.record["resolved_unit_id"] = state.target_unit if state.valid else None
            if state.valid and state.manifest_choice is not None:
                state.selected_path = state.manifest_choice["value"] if state.manifest_choice["kind"] == "path" else state.unit_map.get(
                    state.manifest_choice["value"], {}
                ).get("path")
                state.record["context_target_binding"] = {
                    "choice_id": state.manifest_choice["choice_id"],
                    "target_kind": state.manifest_choice["kind"],
                    "target_value": state.manifest_choice["value"],
                    "evidence_kind": state.proposal["evidence_kind"],
                    "path": state.selected_path,
                    "source_sha": state.manifest_choice["source_sha"],
                    "source_object_id": state.manifest_choice["source_object_id"],
                    "source_object_format": state.manifest_choice["source_object_format"],
                    "snapshot_id": state.snapshot.get("snapshot_id"),
                }
            state.target_obligations = [
                oid
                for oid in state.task.get("obligation_ids", [state.task["obligation_id"]])
                if state.lens is None or state.obligation_by_id[oid].get("lens") == state.lens
            ]
            state.record["affected_obligation_ids"] = state.target_obligations or state.task.get(
                "obligation_ids", [state.task["obligation_id"]]
            )
            state.prior_index = next(
                (i for i, existing in enumerate(state.context_gaps) if existing.get("proposal_id") == state.record["proposal_id"]),
                None,
            )
            if state.prior_index is None:
                state.context_gaps.append(state.record)
            else:
                state.context_gaps[state.prior_index].update(state.record)
            state.ledger["context_gaps"] = state.context_gaps
            state.checkpoint()
            if state.valid and callable(state.context_retriever) and ":followup:" not in state.task["task_id"]:
                state.retrieval_key = f"{state.record['proposal_id']}:context-retrieval"
                state.target_binding = state.record.get("context_target_binding")
                state.snapshot_item = (
                    _complete_snapshot_context_evidence(state.snapshot, state.target_binding, state.snapshot_captured_evidence)
                    if isinstance(state.target_binding, dict)
                    and isinstance(state.profile.get("context_target_manifest"), dict)
                    else None
                )
                state.snapshot_reuse = state.snapshot_item is not None
                # Retrieval results are sized by a dedicated ceiling, not by the
                # provider output budget. It defaults to the per-task input
                # ceiling so a whole allowlisted file can fit in one result,
                # while the input ceiling still bounds the content any single
                # task may consume. Provider response caps are unchanged.
                state.retrieval_result_bytes = int(
                    state.limits.get("max_retrieval_result_bytes", state.limits["max_input_bytes_per_task"])
                )
                state.reserved_bytes = (
                    len(state.snapshot_item["content"].encode("utf-8"))
                    if state.snapshot_reuse
                    else max(
                        0,
                        min(
                            state.retrieval_result_bytes,
                            int(state.limits["max_input_bytes_per_task"]),
                            int(state.limits["max_context_bytes"]) - state.budget.summary()["context_bytes_reserved"],
                        ),
                    )
                )
                state.retrieved = None
                try:
                    state.cached = state.ledger.get("retrieved_context", {}).get(state.record["proposal_id"])
                    if state.snapshot_reuse:
                        state.retrieved = {
                            "status": "RESOLVED",
                            "reason": "reused_complete_snapshot_evidence",
                            "source": "SNAPSHOT_REUSE",
                        }
                        state.fetched = [{
                            **state.snapshot_item,
                            "proposal_id": state.record["proposal_id"],
                            "task_id": state.task["task_id"],
                            "required_lens": state.lens,
                        }]
                        state.cached = None
                    else:
                        if state.reserved_bytes <= 0:
                            raise BudgetExhausted("CONTEXT_BYTE_BUDGET_EXHAUSTED")
                        state.budget.reserve_retrieval(state.retrieval_key, state.reserved_bytes)
                        if isinstance(state.cached, dict):
                            state.retrieved = state.cached.get("result")
                            state.fetched = state.cached.get("evidence", [])
                        else:
                            state.retrieval_limits = {
                                **state.remaining_call_limits(),
                                "max_bytes": state.reserved_bytes,
                                "max_retrieval_bytes": state.reserved_bytes,
                                "context_bytes_remaining": state.reserved_bytes,
                                "max_retrieval_result_bytes": state.retrieval_result_bytes,
                            }
                            state.invocation = IsolatedInvocation(
                                state.context_retriever,
                                "__call__",
                                (
                                    state.snapshot,
                                    state.profile,
                                    {
                                        **state.proposal,
                                        "_proposal_id": state.record["proposal_id"],
                                        "_task_id": state.task["task_id"],
                                        **(
                                            {"_context_target_binding": state.record["context_target_binding"]}
                                            if "context_target_binding" in state.record
                                            else {}
                                        ),
                                    },
                                    state.retrieval_limits,
                                ),
                                deadline_seconds=state.budget.remaining_seconds(),
                                output_limit=state.retrieval_result_bytes,
                            )
                            while not state.invocation.poll() and state.budget.remaining_seconds() > 0:
                                state.invocation.wait_for_ready(timeout=state.budget.remaining_seconds())
                            if state.invocation.poll():
                                state.retrieved = state.invocation.result()
                            else:
                                state.invocation.cancel()
                                raise BudgetExhausted("DEADLINE_EXHAUSTED")
                            state.fetched = state.retrieved.get("evidence", []) if isinstance(state.retrieved, dict) else []
                            if isinstance(state.fetched, dict):
                                state.fetched = [state.fetched]
                            elif state.fetched is None:
                                state.fetched = []
                    state.retrieval_envelope_bytes = None if state.snapshot_reuse else len(_canonical(state.retrieved))
                    if not state.snapshot_reuse and state.retrieval_envelope_bytes > state.retrieval_result_bytes:
                        raise BudgetExhausted("OUTPUT_BYTE_LIMIT_EXCEEDED")
                    if not isinstance(state.retrieved, dict) or state.retrieved.get("status") not in {
                        "RESOLVED",
                        "PARTIAL",
                        "UNRESOLVED",
                    }:
                        raise ValueError("invalid_context_retrieval_result")
                    if not isinstance(state.fetched, list):
                        raise ValueError("invalid_context_retrieval_evidence")
                    state.target_path = state.target.get("target_path") if isinstance(state.target, dict) else None
                    state.target_binding = state.record.get("context_target_binding")
                    if isinstance(state.target_binding, dict):
                        state.target_path = state.target_binding.get("path")
                    state.patterns = state.profile.get("retrieval_context_patterns") or state.profile.get("context_paths") or []
                    if not isinstance(state.patterns, list):
                        state.patterns = []
                    state.verified, state.byte_count = [], 0
                    for state.item in state.fetched:
                        if not isinstance(state.item, dict):
                            raise ValueError("invalid_context_retrieval_evidence")
                        state.content = state.item.get("content")
                        state.path = state.item.get("path")
                        if not isinstance(state.content, str) or not isinstance(state.path, str):
                            raise ValueError("invalid_context_retrieval_evidence")
                        state.raw_bytes = state.content.encode("utf-8")
                        state.byte_count += len(state.raw_bytes)
                        if state.snapshot_reuse:
                            state.original = state.evidence_map.get(state.item.get("evidence_id"))
                            if (
                                not isinstance(state.original, dict)
                                or not _same_evidence_content(state.original, state.item)
                                or _complete_snapshot_context_evidence(
                                    state.snapshot, state.target_binding, state.snapshot_captured_evidence
                                ) is None
                            ):
                                raise ValueError("context_snapshot_reuse_binding_failed")
                            state.verified.append(state.item)
                            continue
                        if (
                            state.item.get("snapshot_id") != state.snapshot.get("snapshot_id")
                            or state.item.get("trust") not in {"repository_evidence", "trusted_policy"}
                            or state.item.get("source_kind") != "repository_file"
                            or state.item.get("source_revision") not in (
                                {state.snapshot.get("base_sha"), state.snapshot.get("head_sha")}
                                | (
                                    {state.snapshot["change_base_sha"]}
                                    if isinstance(state.snapshot.get("change_base_sha"), str)
                                    else set()
                                )
                            )
                            or not isinstance(state.item.get("content_hash"), str)
                            or hashlib.sha256(state.raw_bytes).hexdigest() != state.item.get("content_hash")
                            or not isinstance(state.item.get("evidence_id"), str)
                            or state.item.get("evidence_id")
                            != "ev-"
                            + hashlib.sha256(
                                _canonical(
                                    {
                                        "snapshot_id": state.snapshot.get("snapshot_id"),
                                        "revision": state.item.get("source_revision"),
                                        "path": state.path,
                                        "hash": state.item.get("content_hash"),
                                    }
                                )
                            ).hexdigest()[:24]
                            or state.item.get("proposal_id") not in (None, state.record["proposal_id"])
                            or state.item.get("task_id") not in (None, state.task["task_id"])
                            or (
                                isinstance(state.target_binding, dict)
                                and (
                                    state.item.get("source_revision") != state.target_binding.get("source_sha")
                                    or state.item.get("source_object_id") != state.target_binding.get("source_object_id")
                                )
                            )
                            or not any(fnmatch.fnmatchcase(state.path, pat) for pat in state.patterns if isinstance(pat, str))
                            or (state.target_path and state.path != state.target_path)
                        ):
                            raise ValueError("context_retrieval_evidence_binding_failed")
                        state.verified.append(state.item)
                    state.verified = _merge_evidence_rows(state.verified)
                    if not state.snapshot_reuse and state.byte_count > state.reserved_bytes:
                        raise BudgetExhausted("CONTEXT_RETRIEVAL_BYTE_LIMIT_EXCEEDED")
                    if not state.snapshot_reuse:
                        state.budget.settle(state.retrieval_key, output_bytes=state.byte_count, usage={}, status=state.retrieved["status"])
                    state.record["retrieval_status"] = state.retrieved["status"]
                    state.record["retrieval_reason"] = state.retrieved.get("reason")
                    if state.retrieved.get("source") == "SNAPSHOT_REUSE":
                        state.record["retrieval_source"] = "SNAPSHOT_REUSE"
                    state.record["retrieved_evidence_ids"] = [item["evidence_id"] for item in state.verified]
                    state.record["retrieved_bytes"] = state.byte_count
                    state.record["retrieval_envelope_bytes"] = state.retrieval_envelope_bytes
                    if not isinstance(state.cached, dict) or state.snapshot_reuse:
                        state.ledger.setdefault("retrieved_context", {})[state.record["proposal_id"]] = {
                            "result": state.retrieved,
                            "evidence": state.verified,
                        }
                    for state.item in state.verified:
                        state.existing = state.evidence_map.get(state.item["evidence_id"])
                        if state.existing is not None and not _same_evidence_content(state.existing, state.item):
                            raise ValueError("evidence_identity_conflict")
                        state.evidence_map.setdefault(state.item["evidence_id"], state.item)
                    state.checkpoint()
                except (BudgetExhausted, IsolatedCallError, OSError, ValueError, KeyError) as exc:
                    # Expected retrieval/validation boundary: the gap stays
                    # UNRESOLVED and the reason is a bounded safe code; a
                    # harness defect propagates instead of being recorded.
                    state.record["retrieval_status"] = "UNRESOLVED"
                    state.record["retrieval_reason"] = str(exc)[:120]
                    try:
                        if (
                            state.retrieval_key in state.ledger["budget"]["reservations"]
                            and state.retrieval_key not in state.ledger["budget"]["settlements"]
                        ):
                            state.budget.settle(state.retrieval_key, output_bytes=None, usage={}, status="FAILED")
                    except (ValueError, KeyError):
                        pass
                if state.retrieved and state.retrieved.get("status") == "RESOLVED" and state.record.get("retrieved_evidence_ids"):
                    state.followup_id = f"{state.task['task_id']}:followup:{state.index}"
                    state.followup_obligation_id = f"context:{state.record['proposal_id']}"
                    state.followup_unit_ids = (
                        [state.target_unit] if state.target_unit else list(state.task.get("unit_ids", state.task.get("scope_unit_ids", [])))
                    )
                    state.followup_task = {
                        **state.task,
                        "task_id": state.followup_id,
                        "obligation_id": state.followup_obligation_id,
                        "obligation_ids": [state.followup_obligation_id],
                        "unit_ids": state.followup_unit_ids,
                        "scope_unit_ids": state.followup_unit_ids,
                        "evidence_ids": list(
                            dict.fromkeys(list(state.task.get("evidence_ids", [])) + state.record["retrieved_evidence_ids"])
                        ),
                        "context_gap_followup_for": state.record["proposal_id"],
                        "lens": state.lens,
                    }
                    state.followup_evidence = _merge_evidence_rows([
                        *state.evidence_cache.get(state.task["task_id"], []),
                        *(state.evidence_map[eid] for eid in state.record["retrieved_evidence_ids"]),
                    ])
                    try:
                        state.obligation = {
                            "obligation_id": state.followup_obligation_id,
                            "obligation_kind": "REQUIRED_CONTEXT",
                            "required": True,
                            "scope_unit_ids": state.followup_task["unit_ids"],
                            "lens": state.lens,
                            "parent_obligation_ids": list(state.record["affected_obligation_ids"]),
                            "context_gap_id": state.record["proposal_id"],
                            "retrieved_evidence_ids": list(state.record["retrieved_evidence_ids"]),
                        }
                        state.followup_task["context_followup"] = _context_followup_metadata(
                            task=state.followup_task,
                            record=state.record,
                            obligation=state.obligation,
                            parent_task=state.task,
                            parent_result=state.task_results[state.task["task_id"]],
                            retrieved_entry=state.ledger.get("retrieved_context", {}).get(state.record["proposal_id"], {}),
                            snapshot_id=state.snapshot.get("snapshot_id"),
                        )
                        state.followup_task = _bind_specialist_input(
                            state.followup_task, state.snapshot, state.profile, state.followup_evidence
                        )
                        if state.record.get("retrieval_source") == "SNAPSHOT_REUSE":
                            state.quoted_input_bytes = state.review_input_size(state.followup_task, state.followup_evidence)
                            if state.quoted_input_bytes > state.input_ceiling:
                                raise BudgetExhausted("INPUT_BYTE_LIMIT_EXCEEDED")
                        state.budget.reserve_followup(state.followup_id)
                        state.obligation_by_id[state.followup_obligation_id] = state.obligation
                        if not any(o.get("obligation_id") == state.followup_obligation_id for o in state.obligations):
                            state.obligations.append(state.obligation)
                        state.dynamic_obligations = state.ledger.setdefault("dynamic_obligations", [])
                        if not isinstance(state.dynamic_obligations, list):
                            raise ValueError("invalid_dynamic_obligation_ledger")
                        state.existing_obligation = next(
                            (item for item in state.dynamic_obligations if isinstance(item, dict) and item.get("obligation_id") == state.followup_obligation_id),
                            None,
                        )
                        if state.existing_obligation is None:
                            state.dynamic_obligations.append(state.obligation)
                        elif state.existing_obligation != state.obligation:
                            raise ValueError("resume context follow-up obligation mismatch")
                        state.prior_task = next((t for t in state.tasks if t.get("task_id") == state.followup_id), None)
                        if state.prior_task is None:
                            state.tasks.append(state.followup_task)
                            state.task_by_id[state.followup_id] = state.followup_task
                            state.ledger.setdefault("dynamic_tasks", []).append(state.followup_task)
                            state.ledger.setdefault("planned_task_inputs", {})[state.followup_id] = _task_input_provenance(
                                state.followup_task
                            )
                        else:
                            if state.prior_task != state.followup_task:
                                raise ValueError("resume followup task binding mismatch")
                            state.followup_task = state.prior_task
                        state.checkpoint()
                        state.followup_result = state.task_results.get(state.followup_id)
                        if not isinstance(state.followup_result, dict):
                            state.followup_result = state.run_followup(state.followup_task, state.followup_evidence)
                        state.followup_payload = state.followup_result.get("payload", {})
                        state.notes = state.followup_payload.get("coverage_notes", []) if isinstance(state.followup_payload, dict) else []
                        state.covered, state.note_observation = _coverage_note_observation(
                            state.notes,
                            notes_present=isinstance(state.followup_payload, dict) and "coverage_notes" in state.followup_payload,
                            scope_unit_ids=state.followup_task.get("unit_ids", []),
                            required_evidence_ids=state.record.get("retrieved_evidence_ids", []),
                            task_input_evidence_ids=state.followup_result.get("input_evidence_ids", []),
                            predicate_order="followup_resolution",
                        )
                        state.record["coverage_note_diagnostics"] = state.note_observation
                        if state.covered:
                            state.record["status"] = "RESOLVED_BY_FOLLOWUP"
                            state.record["followup_task_id"] = state.followup_id
                        else:
                            state.record["status"] = "VALID_UNRESOLVED"
                            state.record["followup_task_id"] = state.followup_id
                    except (BudgetExhausted, ValueError) as exc:
                        state.record["followup_error"] = str(exc)[:120]
            # The final gap map is rebuilt after all persisted/new proposals are reconciled.
        for state.index, state.raw in enumerate(state.payload.get("finding_candidates", [])):
            state.candidate_id = _hash({"task_id": state.task["task_id"], "index": state.index, "raw": state.raw})[:24]
            if not isinstance(state.raw, dict):
                state.ledger.setdefault("candidate_records", []).append(
                    {
                        "candidate_id": state.candidate_id,
                        "task_id": state.task["task_id"],
                        "validation_state": "INVALID",
                        "validation_reason": "candidate_not_object",
                        "raw_hash": _hash(state.raw),
                    }
                )
                continue
            state.candidate = dict(state.raw)
            state.candidate["candidate_id"] = state.candidate_id
            state.candidate["task_id"] = state.task["task_id"]
            state.candidate["snapshot_id"] = state.snapshot.get("snapshot_id")
            state.task_units = set(state.task.get("unit_ids", state.task.get("scope_unit_ids", [])))
            state.refs = state.candidate.get("evidence_refs", [])
            state.supplied_ids = set(state.task.get("evidence_ids", []))
            state.valid_refs = [ref for ref in state.refs if isinstance(ref, str) and ref in state.supplied_ids and ref in state.evidence_map]
            state.location_valid, state.location, state.line, state.uid = validate_location(state.candidate, None, state.task_units, state.unit_map)
            if state.location.get("kind") == "file" and state.unit_map.get(state.uid):
                state.anchor = state.unit_map[state.uid].get("file_level_location")
                state.anchor_id = state.anchor.get("evidence_id") if isinstance(state.anchor, dict) else None
                state.anchor_hash = state.anchor.get("evidence_hash") if isinstance(state.anchor, dict) else None
                state.anchor_record = state.evidence_map.get(state.anchor_id) if isinstance(state.anchor_id, str) else None
                state.anchor_side = state.anchor.get("side") if isinstance(state.anchor, dict) else None
                state.expected_revision = (
                    state.snapshot.get("change_base_sha", state.snapshot.get("base_sha"))
                    if state.anchor_side == "BASE"
                    else state.snapshot.get("head_sha")
                )
                state.expected_source_kind = "base_file" if state.anchor_side == "BASE" else "head_file"
                state.anchor_valid = bool(
                    isinstance(state.anchor, dict)
                    and state.anchor.get("kind") == "file"
                    and state.anchor_side in {"BASE", "HEAD"}
                    and isinstance(state.anchor_id, str)
                    and isinstance(state.anchor_hash, str)
                    and re.fullmatch(r"[0-9a-f]{64}", state.anchor_hash)
                    and state.anchor_id in set(state.unit_map[state.uid].get("evidence_ids", []))
                    and state.anchor_id in state.supplied_ids
                    and state.anchor_id in state.valid_refs
                    and isinstance(state.anchor_record, dict)
                    and state.anchor_record.get("evidence_id") == state.anchor_id
                    and state.anchor_record.get("path") == state.anchor.get("path")
                    and state.anchor_record.get("source_revision") == state.expected_revision
                    and state.anchor_record.get("source_kind") == state.expected_source_kind
                    and state.anchor_record.get("snapshot_id") == state.snapshot.get("snapshot_id")
                    and state.anchor_record.get("content_hash") == state.anchor_hash
                    and state.anchor_record.get("content_truncated") is False
                )
                state.location_valid = state.location_valid and state.anchor_valid
            state.candidate["location"] = state.location
            state.candidate["unit_id"] = state.uid
            state.unit = state.unit_map.get(state.uid)
            state.structurally_valid = bool(
                state.unit
                and state.uid in state.task_units
                and state.candidate.get("observation")
                and state.candidate.get("consequence")
                and state.candidate.get("rule_or_contract")
                and state.refs
                and len(state.valid_refs) == len(state.refs)
                and state.location_valid
            )
            state.candidate["validation_state"] = "VALID" if state.structurally_valid else "NEEDS_CONTEXT"
            state.candidate["validation_reason"] = (
                "snapshot_location_and_evidence_validated"
                if state.structurally_valid
                else "location_or_evidence_not_validated"
            )
            state.fid = stable_candidate_id(state.snapshot.get("snapshot_id", ""), state.candidate)
            state.candidate_record = {
                "candidate_id": state.candidate_id,
                "finding_id": state.fid,
                "task_id": state.task["task_id"],
                "snapshot_id": state.snapshot.get("snapshot_id"),
                "validation_state": state.candidate["validation_state"],
                "validation_reason": state.candidate["validation_reason"],
                "raw": state.candidate,
            }
            state.ledger.setdefault("candidate_records", []).append(state.candidate_record)
            state.known_ids.add(state.fid)
            state.assessment = None
            state.semantic_result = None
            state.reservation_key = None
            state.adjudication_started_monotonic = None
            state.adjudication_dispatch_started = False
            state.causal_roles_valid = False
            state.semantic_role_refs: set[str] = set()
            if (
                state.private_capture is None and state.structurally_valid and state.provider is not None
                and callable(getattr(state.provider, "adjudicate", None))
            ):
                try:
                    state.adjudication_evidence = state.evidence_cache[state.task["task_id"]]
                    state.candidate_hash = _hash(state.candidate)
                    state.adjudication_input_hash = _hash(
                        {
                            "candidate": state.candidate,
                            "evidence": state.adjudication_evidence,
                            "semantic_contract_version": _ADJUDICATION_V3,
                            "semantic_rubric_version": _ADJUDICATION_RUBRIC,
                            "provider_identity_hash": _hash(state.provider_identity),
                        }
                    )
                    state.cached_assessment = state.ledger.get("adjudications", {}).get(state.candidate_id)
                    state.cached_payload = (
                        state.cached_assessment.get("assessment") if isinstance(state.cached_assessment, dict) else None
                    )
                    state.cached_provenance = (
                        state.cached_assessment.get("provenance") if isinstance(state.cached_assessment, dict) else None
                    )
                    state.reused_assessment = bool(
                        isinstance(state.cached_assessment, dict)
                        and state.cached_assessment.get("candidate_hash") == state.candidate_hash
                        and state.cached_assessment.get("input_hash") == state.adjudication_input_hash
                        and isinstance(state.cached_payload, dict)
                        and state.cached_payload.get("contract_version") == _ADJUDICATION_V3
                        and state.cached_payload.get("source_contract_version") == _ADJUDICATION_V3
                        and isinstance(state.cached_provenance, dict)
                        and state.cached_provenance.get("provider_rubric_version") == _ADJUDICATION_RUBRIC
                    )
                    if state.reused_assessment:
                        state.assessment = state.cached_assessment["assessment"]
                        state.semantic_usage = state.cached_assessment.get("usage", {})
                        state.semantic_provenance = state.cached_assessment.get("provenance", {})
                    else:
                        state.prefix = (
                            f"{state.task['task_id']}:adjudicate:{_ADJUDICATION_V3}:{_ADJUDICATION_RUBRIC}:"
                            f"{state.candidate_id}:attempt:"
                        )
                        state.attempts = [
                            int(key[len(state.prefix) :])
                            for key in state.budget.state["reservations"]
                            if key.startswith(state.prefix) and key[len(state.prefix) :].isdigit()
                        ]
                        state.adjudication_attempt = max(state.attempts, default=-1) + 1
                        state.reservation_key = f"{state.prefix}{state.adjudication_attempt}"
                        state.reservation = state.reserve_provider_call(
                            state.reservation_key,
                            state.provider,
                            "SEMANTIC_ADJUDICATION",
                            {**state.task, "candidate": state.candidate},
                            state.adjudication_evidence,
                            len(_canonical({"candidate": state.candidate, "evidence": state.adjudication_evidence})),
                        )
                        state.adjudication_deadline = min(
                            float(state.reservation.get("deadline_seconds", state.remaining_call_limits()["deadline_seconds"])),
                            max(0.0, state.budget.remaining_seconds() - state.required_claim_deadline_floor()),
                        )
                        if state.adjudication_deadline <= 0 and state.required_claim_deadline_floor() > 0:
                            raise BudgetExhausted("REQUIRED_CLAIM_ASSESSMENT_DEADLINE_RESERVED")
                        if state.adjudication_deadline <= 0:
                            raise BudgetExhausted("DEADLINE_EXHAUSTED")
                        state.adjudication_dispatch_started = True
                        state.adjudication_started_monotonic = time.monotonic()
                        state.response = isolated_call(
                            state.provider,
                            "adjudicate",
                            (state.candidate, state.adjudication_evidence, state.remaining_call_limits()),
                            deadline_seconds=state.adjudication_deadline,
                            output_limit=int(state.reservation["max_output_bytes"]),
                            lock=state.call_lock,
                        )
                        state.assessment, state.semantic_usage, state.semantic_provenance = _unwrap(state.response)
                    state.assessment_refs = state.assessment.get("evidence_refs", [])
                    state.delivered_ids = {
                        item.get("evidence_id")
                        for item in state.adjudication_evidence
                        if isinstance(item, dict) and isinstance(item.get("evidence_id"), str)
                    }
                    state.support_keys = ("observation_support", "consequence_support", "rule_connection_support")
                    if (
                        state.assessment.get("outcome") not in {"SUPPORTED", "NOT_SUPPORTED", "UNCERTAIN", "CONTRADICTED"}
                        or not isinstance(state.assessment_refs, list)
                        or any(not isinstance(ref, str) or ref not in state.delivered_ids for ref in state.assessment_refs)
                        or state.assessment.get("introducedness")
                        not in {"INTRODUCED", "REEXPOSED", "PRE_EXISTING", "UNKNOWN"}
                        or any(
                            state.assessment.get(k) not in {"SUPPORTED", "NOT_ESTABLISHED", "CONTRADICTED"}
                            for k in state.support_keys
                        )
                        or not isinstance(state.assessment.get("material_consequence"), bool)
                        or (state.assessment.get("outcome") == "SUPPORTED" and not state.assessment_refs)
                    ):
                        state.assessment = {"outcome": "UNCERTAIN"}
                    state.causal_roles_valid, state.semantic_role_refs = _validated_v3_causal_roles(
                        state.assessment,
                        state.adjudication_evidence,
                        state.evidence_map,
                        state.snapshot.get("snapshot_id"),
                        state.provider_identity,
                        state.semantic_provenance,
                    )
                    state.semantic_result = state.assessment
                    if not state.reused_assessment:
                        state.ledger.setdefault("adjudications", {})[state.candidate_id] = {
                            "candidate_hash": state.candidate_hash,
                            "input_hash": state.adjudication_input_hash,
                            "assessment": state.assessment,
                            "usage": state.semantic_usage,
                            "provenance": state.semantic_provenance,
                            "reservation_key": state.reservation_key,
                        }
                        state.checkpoint()
                        state.budget.settle(
                            state.reservation_key,
                            output_bytes=len(_canonical(state.response)),
                            usage=state.semantic_usage,
                            status="SUCCEEDED" if state.assessment.get("outcome") != "UNCERTAIN" else "INVALID",
                            observation=_settlement_observation(
                                "semantic_adjudication",
                                state.semantic_usage,
                                state.semantic_provenance,
                                call_elapsed_ms=(time.monotonic() - state.adjudication_started_monotonic) * 1000
                                if state.adjudication_started_monotonic is not None
                                else None,
                            ),
                        )
                except Exception as exc:
                    # Separate a programming defect from an expected boundary
                    # failure. The defect is recorded explicitly; it still
                    # yields an unresolved assessment and can never approve.
                    defect_kind = defect_name(exc)
                    if defect_kind is not None:
                        state.safe_error_code = "HARNESS_DEFECT"
                    elif isinstance(exc, BudgetExhausted):
                        state.budget_code = str(exc)
                        state.safe_error_code = (
                            state.budget_code
                            if state.budget_code
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
                                "REQUIRED_CLAIM_ASSESSMENT_CAP_RESERVED",
                                "REQUIRED_CLAIM_ASSESSMENT_DEADLINE_RESERVED",
                            }
                            else type(exc).__name__
                        )
                    else:
                        state.safe_error_code = type(exc).__name__
                    state.assessment = {
                        "outcome": "UNCERTAIN",
                        "reason": defect_kind or type(exc).__name__,
                        "error_code": state.safe_error_code,
                    }
                    if defect_kind is not None:
                        state.assessment["defect"] = True
                        state.assessment["defect_type"] = defect_kind
                        state.candidate_record["adjudication_defect"] = defect_kind
                    if state.safe_error_code in {
                        "REQUIRED_CLAIM_ASSESSMENT_CAP_RESERVED",
                        "REQUIRED_CLAIM_ASSESSMENT_DEADLINE_RESERVED",
                    }:
                        state.assessment["reason_code"] = state.safe_error_code
                        state.candidate_record["adjudication_state"] = "DEFERRED"
                        state.candidate_record["adjudication_reason_code"] = state.safe_error_code
                    # Persist the failure on the finding even when reservation
                    # fails before a provider result or adjudication record exists.
                    # UNCERTAIN is deliberately unresolved and cannot support a blocker.
                    state.semantic_result = state.assessment
                    state.remote_meta = getattr(exc, "meta", {})
                    state.semantic_usage = state.remote_meta.get("usage", {}) if isinstance(state.remote_meta, dict) else {}
                    state.semantic_provenance = {"error_meta": state.remote_meta} if state.remote_meta else {}
                    if state.reservation_key is not None:
                        try:
                            state.budget.settle(
                                state.reservation_key,
                                output_bytes=state.remote_meta.get("actual_output_bytes")
                                if isinstance(state.remote_meta, dict)
                                else None,
                                usage=state.semantic_usage,
                                status=(
                                    "NOT_RUN"
                                    if isinstance(exc, BudgetExhausted) and not state.adjudication_dispatch_started
                                    else "FAILED"
                                ),
                                observation=_settlement_observation(
                                    "semantic_adjudication",
                                    state.semantic_usage,
                                    error_meta=state.remote_meta,
                                    call_elapsed_ms=(time.monotonic() - state.adjudication_started_monotonic) * 1000
                                    if state.adjudication_started_monotonic is not None
                                    else None,
                                ),
                            )
                        except (ValueError, KeyError):
                            pass
            else:
                state.semantic_usage, state.semantic_provenance = {}, {}
            state.introduced = (state.assessment or {}).get("introducedness", "UNKNOWN")
            state.causal_roles = (state.assessment or {}).get("causal_roles", {})
            state.causal_path_supported = bool(
                state.causal_roles_valid and all(state.causal_roles[role].get("support") == "SUPPORTED" for role in _CAUSAL_ROLES)
            )
            state.claim_supported = (
                state.structurally_valid
                and state.assessment
                and state.assessment.get("outcome") == "SUPPORTED"
                and state.causal_path_supported
                and all(
                    state.assessment.get(key) == "SUPPORTED" for key in ("observation_support", "rule_connection_support")
                )
            )
            state.claim_supported = bool(state.claim_supported and state.introduced in {"INTRODUCED", "REEXPOSED", "PRE_EXISTING"})
            state.supported = bool(state.claim_supported and state.introduced in {"INTRODUCED", "REEXPOSED"})
            state.materiality = (state.assessment or {}).get("material_consequence")
            state.blocking = bool(state.supported and state.materiality is True and state.assessment.get("consequence_support") == "SUPPORTED")
            state.unresolved = (
                not state.structurally_valid
                or state.assessment is None
                or not state.causal_roles_valid
                or not state.causal_path_supported
                or state.assessment.get("outcome") in {"UNCERTAIN", "CONTRADICTED"}
                or state.introduced == "UNKNOWN"
                or (state.assessment.get("outcome") == "SUPPORTED" and (not state.claim_supported or state.materiality is None))
            )
            state.status = (
                "ACCEPTED"
                if state.claim_supported
                else (
                    "NEEDS_EVIDENCE"
                    if not state.structurally_valid
                    else "CONTRADICTED"
                    if state.assessment and state.assessment.get("outcome") == "CONTRADICTED"
                    else "UNSUPPORTED"
                    if state.assessment and state.assessment.get("outcome") == "NOT_SUPPORTED"
                    else "NEEDS_EVIDENCE"
                )
            )
            state.location = dict(state.candidate.get("location", {})) if isinstance(state.candidate.get("location", {}), dict) else {}
            state.path = state.location.get("path") or state.candidate.get("path") or (state.unit.get("path") if state.unit else None)
            state.location["path"] = state.path
            state.location["side"] = state.location.get("side", "HEAD")
            if state.line is not None:
                state.location["line"] = state.line
            state.finding = {
                "finding_id": state.fid,
                "candidate_id": state.candidate_id,
                "task_id": state.task["task_id"],
                "snapshot_id": state.snapshot.get("snapshot_id"),
                "unit_id": state.uid,
                "location": state.location,
                "path": state.path,
                "title": str(state.candidate.get("title", "Unverified finding"))[:300],
                "observation": str(state.candidate.get("observation", ""))[:2000],
                "consequence": str(state.candidate.get("consequence", ""))[:2000],
                "rule_or_contract": str(state.candidate.get("rule_or_contract", ""))[:1000],
                "evidence_refs": sorted(set(state.valid_refs) | state.semantic_role_refs),
                "status": state.status,
                "severity": state.candidate.get("severity", "unknown"),
                "introducedness": state.introduced,
                "blocking_class": "BLOCKING" if state.blocking else "UNRESOLVED" if state.unresolved else "NON_BLOCKING",
                "blocking_rationale": "Evidence and semantic assessment support a material changed behavior or trusted policy consequence."
                if state.blocking
                else "Not established as a blocker by the bounded evidence and policy rules.",
                "semantic_assessment": state.semantic_result,
                "semantic_usage": state.semantic_usage,
                "semantic_provenance": state.semantic_provenance,
            }
            state.findings.append(state.finding)
        state.ledger.setdefault("reconciled_tasks", []).append(state.task["task_id"])



def assess_claims(state: RunState) -> None:
    """Run required claim adjudication under the trusted reconciliation policy.

Contract: only validated candidates may consume a required assessment;
unknown or failed adjudication never becomes a clean approval."""
    from .engine import (
        _ADJUDICATION_V3,
        _CAUSAL_ROLES,
        BudgetExhausted,
        ClaimAssessmentError,
        IsolatedCallError,
        _canonical,
        _claim_adapter_hash,
        _hash,
        _safe_claim_error_code,
        _settlement_observation,
        hashlib,
        isolated_call,
        json,
        math,
        time,
    )
    # The per-candidate claim assessor is an optional, sequential shadow stage.
    # It runs after every primary adjudication has settled and before findings
    # are consolidated so it cannot consume primary call slots or affect the
    # deterministic reducer inputs.
    if state.max_claim_assessments > 0:
        state.claim_rows = state.ledger.setdefault("claim_assessments", {})
        if not isinstance(state.claim_rows, dict):
            raise ValueError("claim assessment ledger is invalid")
        state.finding_by_candidate = {
            item.get("candidate_id"): item
            for item in state.findings
            if isinstance(item, dict) and isinstance(item.get("candidate_id"), str)
        }
        state.record_by_candidate = {
            item.get("candidate_id"): item
            for item in state.ledger.get("candidate_records", [])
            if isinstance(item, dict) and isinstance(item.get("candidate_id"), str)
        }
        state.ordered_candidates = sorted(state.record_by_candidate)
        state.attempts_used = sum(
            1 for row in state.claim_rows.values() if isinstance(row, dict) and isinstance(row.get("reservation_key"), str)
        )
        state.claim_not_run = functools.partial(claim_not_run_stage, state)
        state.claim_identity = {
            "snapshot_id": state.snapshot.get("snapshot_id"),
            "snapshot_hash": state.snapshot.get("snapshot_hash"),
            "profile_id": state.profile.get("version", state.profile.get("profile_version")),
            "profile_hash": _hash(state.profile),
            "base_sha": state.snapshot.get("base_sha"),
            "head_sha": state.snapshot.get("head_sha"),
        }
        if state.snapshot.get("comparison_mode") == "PR_MERGE_BASE":
            state.claim_identity["change_base_sha"] = state.snapshot.get("change_base_sha")
        state.freshness_reserve_seconds = 16.0 if callable(state.freshness_check) else 0.0
        for state.candidate_id in state.ordered_candidates:
            state.prior = state.claim_rows.get(state.candidate_id)
            if isinstance(state.prior, dict):
                if state.prior.get("status") in {
                    "COMPLETE",
                    "PARTIAL",
                    "FAILED",
                    "NOT_RUN",
                    "INTERRUPTED_UNKNOWN",
                }:
                    continue
                # An unfinished row or reservation represents an uncertain
                # dispatch after a crash. Never reuse that paid-call key.
                state.prior_reservation = state.prior.get("reservation_key")
                if state.prior_reservation or state.prior.get("status") in {"RESERVED", "DISPATCHING", "PREPARING"}:
                    state.claim_rows[state.candidate_id] = {
                        **state.prior,
                        "status": "INTERRUPTED_UNKNOWN",
                        "reason_code": "PRIOR_SHADOW_ATTEMPT_UNSETTLED",
                    }
                    state.checkpoint()
                    continue
            state.candidate_record = state.record_by_candidate[state.candidate_id]
            state.finding = state.finding_by_candidate.get(state.candidate_id)
            state.primary = state.finding.get("semantic_assessment") if isinstance(state.finding, dict) else None
            if state.candidate_record.get("validation_state") != "VALID":
                state.claim_not_run(state.candidate_id, "PRIMARY_CANDIDATE_INVALID")
                continue
            if (
                not isinstance(state.finding, dict)
                or not isinstance(state.primary, dict)
                or state.primary.get("contract_version") != _ADJUDICATION_V3
                or state.primary.get("source_contract_version") != _ADJUDICATION_V3
            ):
                state.claim_not_run(state.candidate_id, "PRIMARY_ASSESSMENT_UNAVAILABLE")
                continue
            if state.attempts_used >= state.max_claim_assessments:
                state.claim_not_run(state.candidate_id, "CLAIM_ASSESSMENT_CAP_EXHAUSTED")
                continue
            state.raw_candidate = state.candidate_record.get("raw")
            if not isinstance(state.raw_candidate, dict):
                state.claim_not_run(state.candidate_id, "PRIMARY_CANDIDATE_INVALID")
                continue
            state.refs: list[str] = []
            state.original_refs = state.raw_candidate.get("evidence_refs")
            if not isinstance(state.original_refs, list):
                state.claim_not_run(state.candidate_id, "PRIMARY_CANDIDATE_INVALID")
                continue
            state.refs.extend(state.original_refs)
            state.refs.extend(state.primary.get("evidence_refs", []))
            state.role_records = state.primary.get("causal_roles", {})
            if isinstance(state.role_records, dict):
                for state.role_name in _CAUSAL_ROLES:
                    state.role = state.role_records.get(state.role_name)
                    if isinstance(state.role, dict) and isinstance(state.role.get("evidence_refs"), list):
                        state.refs.extend(state.role["evidence_refs"])
            state.refs = list(dict.fromkeys(ref for ref in state.refs if isinstance(ref, str)))
            state.cited_evidence = []
            state.invalid_binding = False
            for state.evidence_id in state.refs:
                state.item = state.evidence_map.get(state.evidence_id)
                if (
                    not isinstance(state.item, dict)
                    or state.item.get("evidence_id") != state.evidence_id
                    or state.item.get("snapshot_id") != state.snapshot.get("snapshot_id")
                ):
                    state.invalid_binding = True
                    break
                state.cited_evidence.append(state.item)
            if state.invalid_binding or not state.original_refs or any(ref not in state.refs for ref in state.original_refs):
                state.claim_not_run(state.candidate_id, "CANDIDATE_EVIDENCE_BINDING_INVALID")
                continue
            state.reservation_key = f"claim-assessment:{state.claim_assessor_contract}:{state.candidate_id}:attempt:0"
            if state.reservation_key in state.budget.state["reservations"]:
                # A reservation without a durable completed row is uncertain;
                # startup settlement above has already marked it unknown.
                state.attempts_used += 1
                state.claim_rows[state.candidate_id] = {
                    "contract_version": state.claim_assessor_contract,
                    "candidate_id": state.candidate_id,
                    "status": "INTERRUPTED_UNKNOWN",
                    "reason_code": "PRIOR_SHADOW_RESERVATION_EXISTS",
                    "attempt": 0,
                    "reservation_key": state.reservation_key,
                }
                state.checkpoint()
                continue
            state.remaining = state.budget.remaining_seconds() - state.freshness_reserve_seconds
            state.deadline_cap = min(8.0, state.remaining)
            if state.deadline_cap <= 0:
                state.claim_not_run(
                    state.candidate_id,
                    "FRESHNESS_BUDGET_RESERVED" if state.freshness_reserve_seconds else "DEADLINE_EXHAUSTED",
                    freshness_reserve_seconds=state.freshness_reserve_seconds,
                )
                continue
            state.primary_hash = _hash(state.primary)
            state.raw_refs = list(state.original_refs)
            state.claim_candidate = {
                key: state.raw_candidate.get(key)
                for key in ("candidate_id", "title", "observation", "consequence", "rule_or_contract")
            }
            state.claim_candidate["candidate_id"] = state.candidate_id
            state.claim_candidate["evidence_refs"] = state.raw_refs
            state.claim_rows[state.candidate_id] = {
                "contract_version": state.claim_assessor_contract,
                "candidate_id": state.candidate_id,
                "attempt": 0,
                "status": "PREPARING",
                "primary_assessment_hash": state.primary_hash,
                "candidate_hash": _hash(state.claim_candidate),
                "evidence_refs": state.refs,
                "implementation_hash": state.claim_assessor_code_hash,
            }
            state.checkpoint()
            state.prepared = None
            state.reservation = None
            state.claim_call_started = None
            try:
                state.call_limits = {
                    **state.limits,
                    "deadline_seconds": state.deadline_cap,
                }
                state.prepared = state.claim_assessor.prepare(
                    state.claim_candidate,
                    state.cited_evidence,
                    state.claim_identity,
                    state.call_limits,
                    primary_assessment=state.primary,
                )
                state.prepared_request = getattr(state.prepared, "request_bytes", None)
                state.prepared_hash = getattr(state.prepared, "request_hash", None)
                state.prepared_version = getattr(state.prepared, "contract_version", None)
                if (
                    not isinstance(state.prepared_request, bytes)
                    or not isinstance(state.prepared_hash, str)
                    or hashlib.sha256(state.prepared_request).hexdigest() != state.prepared_hash
                    or state.prepared_version != state.claim_assessor_contract
                ):
                    raise ValueError("invalid_prepared_claim_request")
                try:
                    state.prepared_body = json.loads(state.prepared_request.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
                    raise ValueError("invalid_prepared_claim_request") from None
                state.prepared_state = state.prepared_body.get("state") if isinstance(state.prepared_body, dict) else None
                state.prepared_candidate = state.prepared_state.get("candidate") if isinstance(state.prepared_state, dict) else None
                state.prepared_evidence = state.prepared_state.get("cited_evidence") if isinstance(state.prepared_state, dict) else None
                state.prepared_questions = state.prepared_body.get("questions") if isinstance(state.prepared_body, dict) else None
                state.prepared_primary = (
                    state.prepared_state.get("primary_assessment") if isinstance(state.prepared_state, dict) else None
                )
                state.question_pairs = getattr(state.prepared, "question_ids", None)
                state.introducedness_available = getattr(state.prepared, "introducedness_available", None)
                state.required_dimensions = {
                    "observation_support",
                    "consequence_support",
                    "rule_connection_support",
                    "materiality",
                    "missing_context",
                    "introducedness",
                }
                state.prepared_question_map = {}
                state.prepared_question_ids_valid = False
                if (
                    isinstance(state.question_pairs, tuple)
                    and isinstance(state.introducedness_available, bool)
                    and all(
                        isinstance(pair, tuple)
                        and len(pair) == 2
                        and all(isinstance(value, str) and value for value in pair)
                        for pair in state.question_pairs
                    )
                ):
                    state.prepared_question_map = dict(state.question_pairs)
                    state.expected_question_ids = {
                        question_id
                        for dimension, question_id in state.prepared_question_map.items()
                        if state.introducedness_available or dimension != "introducedness"
                    }
                    state.prepared_question_ids_valid = bool(
                        len(state.prepared_question_map) == len(state.question_pairs)
                        and len(set(state.prepared_question_map.values())) == len(state.prepared_question_map)
                        and set(state.prepared_question_map) == state.required_dimensions
                        and isinstance(state.prepared_questions, dict)
                        and bool(state.prepared_questions)
                        and all(isinstance(question, dict) for question in state.prepared_questions.values())
                        and set(state.prepared_questions) == state.expected_question_ids
                    )
                if (
                    not isinstance(state.prepared_state, dict)
                    or state.prepared_state.get("assessment_contract_version") != state.prepared_version
                    or state.prepared_state.get("assessment_identity") != state.claim_identity
                    or state.prepared_candidate != state.claim_candidate
                    or state.prepared_primary != state.primary
                    or not isinstance(state.prepared_evidence, list)
                    or [item.get("evidence_id") for item in state.prepared_evidence if isinstance(item, dict)] != state.refs
                    or not isinstance(state.prepared_questions, dict)
                    or not state.prepared_questions
                    or not state.prepared_question_ids_valid
                    or getattr(state.prepared, "candidate_hash", None) != _claim_adapter_hash(state.prepared_candidate)
                    or getattr(state.prepared, "evidence_hash", None) != _claim_adapter_hash(state.prepared_evidence)
                    or getattr(state.prepared, "question_hash", None) != _claim_adapter_hash(state.prepared_questions)
                    or getattr(state.prepared, "primary_assessment_hash", None) != _claim_adapter_hash(state.prepared_primary)
                ):
                    raise ValueError("invalid_prepared_claim_binding")
                # Preparation and quote are local but may consume wall time.
                state.remaining = state.budget.remaining_seconds() - state.freshness_reserve_seconds
                state.deadline_cap = min(8.0, state.remaining)
                if state.deadline_cap <= 0:
                    raise BudgetExhausted(
                        "FRESHNESS_BUDGET_RESERVED" if state.freshness_reserve_seconds else "DEADLINE_EXHAUSTED"
                    )
                state.call_limits = {**state.limits, "deadline_seconds": state.deadline_cap}
                state.estimate = state.claim_assessor.estimate_prepared(state.prepared, state.call_limits)
                if (
                    not isinstance(state.estimate, dict)
                    or state.estimate.get("provider_calls") != 1
                    or state.estimate.get("input_bytes") != len(state.prepared_request)
                    or state.estimate.get("max_output_bytes") != state.limits["max_output_bytes_per_task"]
                    or isinstance(state.estimate.get("provider_response_bytes"), bool)
                    or not isinstance(state.estimate.get("provider_response_bytes"), int)
                    or not 0 < state.estimate["provider_response_bytes"] <= state.limits["max_output_bytes_per_task"]
                    or isinstance(state.estimate.get("deadline_seconds"), bool)
                    or not isinstance(state.estimate.get("deadline_seconds"), (int, float))
                    or not math.isfinite(state.estimate["deadline_seconds"])
                    or not 0 < state.estimate["deadline_seconds"] <= state.deadline_cap
                ):
                    raise ValueError("invalid_claim_assessment_quote")
                state.estimate = {**state.estimate, "max_cost_microunits": None}
                # The process result has its own serialized IPC ceiling; the
                # transport's raw response ceiling remains separately recorded.
                state.raw_response_cap = state.estimate["provider_response_bytes"]
                state.ipc_cap = int(state.estimate["max_output_bytes"])
                state.claim_rows[state.candidate_id].update(
                    {
                        "status": "RESERVED",
                        "request_hash": state.prepared_hash,
                        "candidate_hash": getattr(state.prepared, "candidate_hash", None),
                        "question_hash": getattr(state.prepared, "question_hash", None),
                        "evidence_hash": getattr(state.prepared, "evidence_hash", None),
                        "primary_assessment_hash": getattr(state.prepared, "primary_assessment_hash", state.primary_hash),
                        "provider_response_bytes_reserved": state.raw_response_cap,
                        "ipc_output_bytes_reserved": state.ipc_cap,
                        "input_bytes_reserved": state.estimate["input_bytes"],
                        "reservation_key": state.reservation_key,
                        "quote_deadline_seconds": state.estimate["deadline_seconds"],
                    }
                )
                state.checkpoint()
                state.reservation = state.budget.reserve(state.reservation_key, state.estimate, kind="claim_assessment")
                state.claim_rows[state.candidate_id]["status"] = "DISPATCHING"
                state.checkpoint()
                # Retain a 16 second tail for the independent final freshness
                # check. A started shadow call cannot consume that opportunity.
                state.remaining = state.budget.remaining_seconds() - state.freshness_reserve_seconds
                state.dispatch_deadline = min(8.0, float(state.reservation["deadline_seconds"]), state.remaining)
                if state.dispatch_deadline <= 0:
                    raise BudgetExhausted(
                        "FRESHNESS_BUDGET_RESERVED" if state.freshness_reserve_seconds else "DEADLINE_EXHAUSTED"
                    )
                state.started = time.monotonic()
                state.claim_call_started = state.started
                state.response = isolated_call(
                    state.claim_assessor,
                    "assess_prepared",
                    (
                        state.prepared,
                        {
                            **state.limits,
                            "deadline_seconds": state.dispatch_deadline,
                            # The transport quote can impose a smaller raw
                            # HTTP response ceiling than the serialized IPC cap.
                            "max_output_bytes_per_task": state.raw_response_cap,
                        },
                    ),
                    deadline_seconds=state.dispatch_deadline,
                    output_limit=state.ipc_cap,
                    lock=state.call_lock,
                )
                state.elapsed_ms = round((time.monotonic() - state.started) * 1000, 2)
                if not isinstance(state.response, dict):
                    raise ValueError("invalid_claim_assessment_response")
                state.output_bytes = len(_canonical(state.response))
                state.usage = state.response.get("usage") if isinstance(state.response.get("usage"), dict) else {}
                state.status = state.response.get("status")
                if state.status not in {"COMPLETE", "PARTIAL", "FAILED"}:
                    state.status = "FAILED"
                state.provenance = state.response.get("provenance") if isinstance(state.response.get("provenance"), dict) else {}
                state.expected_provenance = {
                    "contract_version": state.prepared_version,
                    "request_hash": state.prepared_hash,
                    "candidate_hash": getattr(state.prepared, "candidate_hash", None),
                    "evidence_hash": getattr(state.prepared, "evidence_hash", None),
                    "question_hash": getattr(state.prepared, "question_hash", None),
                    **state.claim_identity,
                }
                state.expected_provenance["primary_assessment_hash"] = state.prepared.primary_assessment_hash
                state.provenance_valid = bool(
                    state.response.get("contract_version") == state.prepared_version
                    and all(state.provenance.get(key) == value for key, value in state.expected_provenance.items())
                )
                state.question_map = state.prepared_question_map
                state.response_assessments = state.response.get("assessments")
                state.assessments_valid = bool(
                    isinstance(state.response_assessments, dict)
                    and set(state.response_assessments) == set(state.question_map)
                    and state.response.get("decision") == "ADVISORY_ONLY"
                )
                for state.dimension, state.question_id in state.question_map.items():
                    state.item = state.response_assessments.get(state.dimension) if isinstance(state.response_assessments, dict) else None
                    if (
                        not isinstance(state.item, dict)
                        or state.item.get("question_id") != state.question_id
                        or state.item.get("native_primitive") != "Choice"
                        or state.item.get("interpretation") != "advisory_uncalibrated"
                        or state.item.get("evidence_refs") != list(getattr(state.prepared, "evidence_refs", ()))
                        or state.item.get("status") not in {"ANSWERED", "OMITTED", "INVALID", "FAILED", "NOT_SHOWN"}
                        or (
                            state.item.get("status") == "NOT_SHOWN"
                            and (state.dimension != "introducedness" or getattr(state.prepared, "introducedness_available", True))
                        )
                    ):
                        state.assessments_valid = False
                        break
                state.complete_assessment = bool(
                    state.assessments_valid
                    and all(
                        state.response_assessments[dimension]["status"]
                        == (
                            "NOT_SHOWN"
                            if dimension == "introducedness" and not state.prepared.introducedness_available
                            else "ANSWERED"
                        )
                        for dimension in state.question_map
                    )
                )
                state.response_valid = bool(
                    state.provenance_valid and state.assessments_valid and (state.status != "COMPLETE" or state.complete_assessment)
                )
                if not state.response_valid:
                    state.status = "FAILED"
                state.budget.settle(
                    state.reservation_key,
                    output_bytes=state.output_bytes,
                    usage=state.usage,
                    status=state.status,
                    observation=_settlement_observation(
                        "claim_assessment", state.usage, state.provenance, call_elapsed_ms=state.elapsed_ms
                    ),
                )
                state.record_update = {
                    "status": state.status,
                    "normalized_result_hash": _hash(state.response),
                    "response_bytes": state.output_bytes,
                    "usage": state.usage,
                    "provenance_valid": state.provenance_valid,
                    "response_valid": state.response_valid,
                    "provenance": state.provenance if state.provenance_valid else {},
                    "elapsed_ms": state.elapsed_ms,
                    "settlement_key": state.reservation_key,
                }
                if state.response_valid:
                    state.record_update["assessments"] = state.response_assessments
                else:
                    state.record_update["reason_code"] = (
                        "RESPONSE_PROVENANCE_MISMATCH" if not state.provenance_valid else "RESPONSE_SCHEMA_INVALID"
                    )
                state.claim_rows[state.candidate_id].update(state.record_update)
                state.attempts_used += 1
                state.checkpoint()
            except BudgetExhausted as exc:
                state.budget_code = str(exc)
                state.allowed_budget_codes = {
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
                state.error_code = (
                    state.budget_code if state.budget_code in state.allowed_budget_codes else "CLAIM_ASSESSMENT_BUDGET_UNAVAILABLE"
                )
                if state.reservation is not None:
                    try:
                        state.budget.settle(
                            state.reservation_key,
                            output_bytes=None,
                            usage={},
                            status="NOT_RUN",
                            observation=_settlement_observation("claim_assessment", {}),
                        )
                    except (ValueError, KeyError):
                        pass
                state.claim_rows[state.candidate_id].update(
                    {
                        "status": "NOT_RUN",
                        "reason_code": state.error_code,
                        "attempt": 0,
                        "reservation_key": state.reservation_key if state.reservation is not None else None,
                    }
                )
                if state.reservation is not None:
                    state.attempts_used += 1
                state.checkpoint()
            except (
                ClaimAssessmentError,
                IsolatedCallError,
                OSError,
                ValueError,
                KeyError,
            ) as exc:
                # Expected advisory/dispatch boundary. Local defect types are
                # absent here and propagate; a defect raised inside the spawned
                # assessor arrives as IsolatedCallError.remote_type and is
                # recorded explicitly below instead of looking like a normal
                # shadow miss.
                state.defect_kind = defect_name(exc)
                state.meta = getattr(exc, "meta", {})
                state.meta = state.meta if isinstance(state.meta, dict) else {}
                state.remote_type = getattr(exc, "remote_type", None)
                state.uncertain = state.remote_type in {"TimeoutError", "Cancelled", "WorkerExit", "WorkerStartError"}
                state.raw_actual = state.meta.get("actual_output_bytes")
                state.actual_output = (
                    state.raw_actual
                    if isinstance(state.raw_actual, int) and not isinstance(state.raw_actual, bool) and state.raw_actual >= 0
                    else None
                )
                if state.reservation is not None:
                    # Preserve measured output so BudgetLedger records a real
                    # shared-resource overrun and the existing reducer fails closed.
                    state.settlement_bytes = state.actual_output
                    try:
                        state.budget.settle(
                            state.reservation_key,
                            output_bytes=state.settlement_bytes,
                            usage=state.meta.get("usage", {}) if isinstance(state.meta.get("usage"), dict) else {},
                            status="INTERRUPTED_UNKNOWN" if state.uncertain else "FAILED",
                            observation=_settlement_observation(
                                "claim_assessment",
                                state.meta.get("usage", {}) if isinstance(state.meta.get("usage"), dict) else {},
                                error_meta=state.meta,
                                call_elapsed_ms=(time.monotonic() - state.claim_call_started) * 1000
                                if state.claim_call_started is not None
                                else None,
                            ),
                        )
                    except (ValueError, KeyError):
                        pass
                    state.attempts_used += 1
                state.claim_rows[state.candidate_id].update(
                    {
                        "status": "INTERRUPTED_UNKNOWN" if state.uncertain else "FAILED",
                        "reason_code": "SHADOW_ASSESSOR_DEFECT"
                        if state.defect_kind is not None
                        else "SHADOW_DISPATCH_UNCERTAIN"
                        if state.uncertain
                        else "IPC_OUTPUT_LIMIT_EXCEEDED"
                        if state.actual_output is not None and state.actual_output > state.ipc_cap
                        else type(exc).__name__,
                        "error_type": type(exc).__name__,
                        "error_code": _safe_claim_error_code(exc),
                        "defect": state.defect_kind is not None,
                        "defect_type": state.defect_kind,
                        "actual_output_bytes_observed": state.actual_output,
                        "observed_output_limit_violation": (
                            {"actual_bytes": state.actual_output, "reserved_bytes": state.ipc_cap}
                            if state.actual_output is not None and state.actual_output > state.ipc_cap
                            else None
                        ),
                        "reservation_key": state.reservation_key if state.reservation is not None else None,
                    }
                )
                state.checkpoint()



def reduce_coverage(state: RunState) -> None:
    """Reconcile findings, compute coverage and freshness, and preserve blockers.

Contract: blocker preservation - a known supported blocker survives
partial coverage; model agreement is never treated as truth."""
    from .engine import (
        _REQUIRED_CONTEXT_NOTE_CODES,
        IsolatedCallError,
        _bounded_freshness,
        _coverage_note_observation,
        _hash,
        _now,
        _required_output_quarantine_observation,
        classify_reconciliation,
        consolidate_findings,
    )
    state.claim_reconciliation_rows: list[dict[str, Any]] = []
    state.reconciliation_by_candidate: dict[str, dict[str, Any]] = {}
    if state.reconciliation_policy is not None:
        state.primary_finding_by_candidate = {
            item.get("candidate_id"): item
            for item in state.findings
            if isinstance(item, dict) and isinstance(item.get("candidate_id"), str)
        }
        state.claim_rows = state.ledger.get("claim_assessments", {})
        for state.candidate_record in state.ledger.get("candidate_records", []):
            if not isinstance(state.candidate_record, dict) or not isinstance(state.candidate_record.get("candidate_id"), str):
                continue
            state.candidate_id = state.candidate_record["candidate_id"]
            state.primary_finding = state.primary_finding_by_candidate.get(state.candidate_id)
            state.primary = state.primary_finding.get("semantic_assessment") if isinstance(state.primary_finding, dict) else None
            state.claim_row = state.claim_rows.get(state.candidate_id) if isinstance(state.claim_rows, dict) else None
            state.relation = classify_reconciliation(
                state.primary,
                state.claim_row,
                candidate_valid=state.candidate_record.get("validation_state") == "VALID",
                introducedness_available=(
                    isinstance(state.claim_row, dict)
                    and isinstance(state.claim_row.get("assessments"), dict)
                    and isinstance(state.claim_row["assessments"].get("introducedness"), dict)
                    and state.claim_row["assessments"]["introducedness"].get("status") == "ANSWERED"
                ),
            )
            state.relation["candidate_id"] = state.candidate_id
            state.reconciliation_by_candidate[state.candidate_id] = state.relation
            state.raw_candidate = state.candidate_record.get("raw")
            state.raw_candidate = state.raw_candidate if isinstance(state.raw_candidate, dict) else {}
            state.refs = set(state.raw_candidate.get("evidence_refs", [])) if isinstance(state.raw_candidate.get("evidence_refs"), list) else set()
            if isinstance(state.primary, dict) and isinstance(state.primary.get("evidence_refs"), list):
                state.refs.update(state.primary["evidence_refs"])
            state.claim_reconciliation_rows.append(
                {
                    "obligation_id": f"claim-reconciliation:{state.candidate_id}",
                    "obligation_kind": "CLAIM_RECONCILIATION",
                    "required": True,
                    "candidate_id": state.candidate_id,
                    "scope_unit_ids": [state.raw_candidate["unit_id"]]
                    if isinstance(state.raw_candidate.get("unit_id"), str)
                    else [],
                    "state": "COMPLETE" if state.relation["state"] == "AGREES" else "PARTIAL",
                    "reconciliation_state": state.relation["state"],
                    "reason_code": state.relation["reason_code"],
                    "task_ids": [state.candidate_record["task_id"]]
                    if isinstance(state.candidate_record.get("task_id"), str)
                    else [],
                    "evidence_refs": sorted(ref for ref in state.refs if isinstance(ref, str)),
                    "primary_assessment_hash": state.relation["primary_assessment_hash"],
                    "claim_assessment_hash": state.relation["claim_assessment_hash"],
                    "request_hash": state.relation["request_hash"],
                }
            )
    state.findings = consolidate_findings(state.findings)
    if state.reconciliation_policy is not None:
        for state.finding in state.findings:
            state.candidate_ids = state.finding.get("candidate_ids", [])
            state.linked = [
                state.reconciliation_by_candidate[candidate_id]
                for candidate_id in state.candidate_ids
                if candidate_id in state.reconciliation_by_candidate
            ]
            if state.linked:
                state.finding["claim_reconciliations"] = state.linked
    state.gap_obligations = {}
    for state.gap in state.context_gaps:
        if state.gap.get("status") != "RESOLVED_BY_FOLLOWUP":
            for state.oid in state.gap.get("affected_obligation_ids", []):
                state.gap_obligations.setdefault(state.oid, []).append(state.gap["proposal_id"])
    state.coverage = []
    for state.obligation_id, state.obligation in state.obligation_by_id.items():
        state.related = [t for t in state.tasks if state.obligation_id in t.get("obligation_ids", [t["obligation_id"]])]
        state.preflight_skips = [row for row in state.split_skips.values() if state.obligation_id in row.get("obligation_ids", [])]
        state.results = [state.task_results.get(t["task_id"], {}) for t in state.related]
        state.successful = bool(state.related) and not state.preflight_skips and all(r.get("status") == "SUCCEEDED" for r in state.results)
        state.check_evidence_refs: set[str] = set()
        state.check_result_evidence_invalid = False
        state.check_result_unavailable = False
        state.required_output_quarantined, state.quarantine_observation = _required_output_quarantine_observation(state.results)
        state.required_context_not_covered = False
        state.required_context_note_observations: list[dict[str, Any]] = []
        state.required_context_note_matches: list[bool] = []
        state.coverage_note_missing = False
        state.coverage_note_evidence_invalid = False
        state.partial_coverage_note = False
        if state.successful:
            # No-finding success is a completed result. A check UNKNOWN/ERROR remains partial.
            state.successful = all(r.get("payload", {}).get("outcome") not in {"UNKNOWN", "ERROR"} for r in state.results)
            state.check_result_unavailable = state.obligation.get("obligation_kind") == "PROJECT_CHECK" and any(
                r.get("payload", {}).get("outcome") in {"UNKNOWN", "ERROR"} for r in state.results
            )
            if state.required_output_quarantined:
                state.successful = False
            if state.obligation.get("obligation_kind") == "CHANGED_UNIT_LENS":
                state.scope_units = set(state.obligation.get("scope_unit_ids", []))
                for state.task, state.task_result in zip(state.related, state.results):
                    if state.task_result.get("status") != "SUCCEEDED":
                        state.successful = False
                        continue
                    state.notes = state.task_result.get("payload", {}).get("coverage_notes", [])
                    state.unit_evidence = {
                        u.get("unit_id"): set(u.get("evidence_ids", []))
                        for u in state.snapshot.get("inventory", [])
                        if isinstance(u, dict)
                    }
                    state.covered = {
                        n.get("unit_id")
                        for n in state.notes
                        if isinstance(n, dict)
                        and n.get("state") == "COVERED"
                        and n.get("coverage_basis") == "STATIC_REVIEW"
                        and n.get("evidence_refs")
                        and set(n.get("evidence_refs", [])).issubset(set(state.task_result.get("input_evidence_ids", [])))
                        and set(n.get("evidence_refs", [])) & state.unit_evidence.get(n.get("unit_id"), set())
                    }
                    state.missing_covered_units = (set(state.task.get("unit_ids", [])) & state.scope_units) - state.covered
                    if state.missing_covered_units:
                        state.successful = False
                        for state.unit_id in state.missing_covered_units:
                            state.unit_notes = [
                                note for note in state.notes if isinstance(note, dict) and note.get("unit_id") == state.unit_id
                            ]
                            if not state.unit_notes:
                                state.coverage_note_missing = True
                            else:
                                state.input_evidence_ids = set(state.task_result.get("input_evidence_ids", []))
                                state.unit_evidence_ids = state.unit_evidence.get(state.unit_id, set())
                                for state.note in state.unit_notes:
                                    state.refs = state.note.get("evidence_refs", [])
                                    if state.note.get("state") in {"PARTIAL", "NOT_COVERED"}:
                                        if state.refs and (
                                            not set(state.refs).issubset(state.input_evidence_ids)
                                            or not set(state.refs) & state.unit_evidence_ids
                                        ):
                                            state.coverage_note_evidence_invalid = True
                                        else:
                                            state.partial_coverage_note = True
                                    elif state.note.get("state") == "COVERED":
                                        state.coverage_note_evidence_invalid = True
                                    else:
                                        state.coverage_note_missing = True
                    state.task_has_required_quarantine, state._ = _required_output_quarantine_observation([state.task_result])
                    if state.task_has_required_quarantine:
                        state.successful = False
            if state.obligation.get("obligation_kind") == "REQUIRED_CONTEXT":
                state.required_ids = set(state.obligation.get("retrieved_evidence_ids", []))
                for state.task_result in state.results:
                    state.payload = state.task_result.get("payload", {})
                    state.notes = state.payload.get("coverage_notes", []) if isinstance(state.payload, dict) else []
                    state.covered, state.note_observation = _coverage_note_observation(
                        state.notes,
                        notes_present=isinstance(state.payload, dict) and "coverage_notes" in state.payload,
                        scope_unit_ids=state.obligation.get("scope_unit_ids", []),
                        required_evidence_ids=state.required_ids,
                        task_input_evidence_ids=state.task_result.get("input_evidence_ids", []),
                        predicate_order="final_coverage",
                    )
                    state.required_context_note_observations.append(state.note_observation)
                    state.required_context_note_matches.append(state.covered)
                    if not state.covered:
                        state.required_context_not_covered = True
                    state.task_has_required_quarantine, state._ = _required_output_quarantine_observation([state.task_result])
                    if not state.covered or state.task_has_required_quarantine:
                        state.successful = False
        if state.obligation.get("obligation_kind") == "PROJECT_CHECK":
            state.expected_binding = state.obligation.get("check_binding_id")
            for state.task, state.task_result in zip(state.related, state.results):
                if state.task_result.get("status") != "SUCCEEDED":
                    continue
                try:
                    state.refs = state.validated_check_evidence(state.task, state.task_result.get("payload", {}))
                except (AttributeError, TypeError, ValueError):
                    state.check_result_evidence_invalid = True
                    continue
                state.dispatched_refs = state.task_result.get("input_evidence_ids")
                if (
                    state.task.get("task_kind") != "DETERMINISTIC_CHECK"
                    or state.task.get("check_binding_id") != state.expected_binding
                    or not isinstance(state.dispatched_refs, list)
                    or state.dispatched_refs != state.refs
                ):
                    state.check_result_evidence_invalid = True
                    continue
                state.check_evidence_refs.update(state.refs)
            if state.check_result_evidence_invalid:
                state.successful = False
        state.state = (
            "PARTIAL"
            if state.gap_obligations.get(state.obligation_id)
            else "COMPLETE"
            if state.successful
            else "PARTIAL"
            if any(r.get("status") not in {None, "SKIPPED"} for r in state.results)
            else "NOT_STARTED"
        )
        state.failure_reason = next(
            (result.get("error_code", "MISSING_RESULT") for result in state.results if result.get("status") != "SUCCEEDED"),
            None,
        )
        state.skip_reason = next((row.get("error_code", "MISSING_RESULT") for row in state.preflight_skips), None)
        if state.gap_obligations.get(state.obligation_id):
            state.reason_code = "CONTEXT_GAP_UNRESOLVED"
        elif state.successful:
            state.reason_code = "VALID_RESULT"
        elif state.check_result_evidence_invalid:
            state.reason_code = "CHECK_RESULT_EVIDENCE_INVALID"
        elif state.failure_reason:
            state.reason_code = state.failure_reason
        elif state.skip_reason:
            state.reason_code = state.skip_reason
        elif state.required_output_quarantined:
            state.reason_code = "REQUIRED_OUTPUT_QUARANTINED"
        elif state.required_context_not_covered:
            state.reason_code = "REQUIRED_CONTEXT_NOT_COVERED"
        elif state.check_result_unavailable:
            state.reason_code = "CHECK_RESULT_UNAVAILABLE"
        elif state.coverage_note_evidence_invalid:
            state.reason_code = "COVERAGE_NOTE_EVIDENCE_INVALID"
        elif state.partial_coverage_note:
            state.reason_code = "PARTIAL_REVIEW_COVERAGE"
        elif state.coverage_note_missing:
            state.reason_code = "COVERAGE_NOTE_MISSING"
        else:
            state.reason_code = "MISSING_RESULT"
        state.coverage_row = {
                "coverage_id": _hash({"run_id": state.run_id, "obligation": state.obligation_id})[:20],
                "run_id": state.run_id,
                "snapshot_id": state.snapshot.get("snapshot_id"),
                **state.obligation,
                "state": state.state,
                "reason_code": state.reason_code,
                "context_gap_ids": state.gap_obligations.get(state.obligation_id, []),
                "task_ids": list(
                    dict.fromkeys(
                        [t["task_id"] for t in state.related]
                        + [row["task_id"] for row in state.preflight_skips if isinstance(row.get("task_id"), str)]
                    )
                ),
                "evidence_refs": sorted(state.check_evidence_refs)
                if state.obligation.get("obligation_kind") == "PROJECT_CHECK"
                else sorted({eid for t in state.related for eid in t.get("evidence_ids", [])}),
                "updated_at": _now(),
            }
        if state.obligation.get("obligation_kind") == "REQUIRED_CONTEXT":
            state.note_observed = bool(state.required_context_note_observations) and all(
                row.get("state") == "OBSERVED" for row in state.required_context_note_observations
            )
            state.note_counts: dict[str, int] | str = {code: 0 for code in _REQUIRED_CONTEXT_NOTE_CODES}
            state.note_count: int | str = 0
            state.notes_examined_count: int | str = 0
            state.notes_unexamined_after_match_count: int | str = 0
            if state.note_observed:
                for state.observation in state.required_context_note_observations:
                    state.counts = state.observation.get("failure_counts")
                    if not isinstance(state.counts, dict):
                        state.note_observed = False
                        break
                    state.note_count += state.observation["note_count"]
                    state.notes_examined_count += state.observation["notes_examined_count"]
                    state.notes_unexamined_after_match_count += state.observation["notes_unexamined_after_match_count"]
                    for state.code in _REQUIRED_CONTEXT_NOTE_CODES:
                        state.note_counts[state.code] += state.counts[state.code]
            if not state.note_observed:
                state.note_counts = "UNKNOWN"
                state.note_count = "UNKNOWN"
                state.notes_examined_count = "UNKNOWN"
                state.notes_unexamined_after_match_count = "UNKNOWN"
                state.coverage_note_result = "UNKNOWN"
            elif state.required_context_note_matches and all(state.required_context_note_matches):
                state.coverage_note_result = "COVERED"
            elif state.note_count == 0:
                state.coverage_note_result = "NO_NOTES"
            else:
                state.coverage_note_result = "NO_COVERING_NOTE"
            state.unresolved_ids = state.gap_obligations.get(state.obligation_id, [])
            state.unresolved_followup_count = 0
            state.gap_observation_known = True
            for state.gap_id in state.unresolved_ids:
                state.linked = [gap for gap in state.context_gaps if isinstance(gap, dict) and gap.get("proposal_id") == state.gap_id]
                if len(state.linked) != 1 or not isinstance(state.linked[0].get("task_id"), str):
                    state.gap_observation_known = False
                    continue
                if ":followup:" in state.linked[0]["task_id"]:
                    state.unresolved_followup_count += 1
            state.closure_state = (
                "OBSERVED"
                if state.note_observed and state.quarantine_observation["state"] == "OBSERVED" and state.gap_observation_known
                else "UNKNOWN"
            )
            state.coverage_row["closure_diagnostics"] = {
                "schema": "required-context-closure-diagnostics.v1",
                "state": state.closure_state,
                "coverage_note_result": state.coverage_note_result,
                "coverage_note_count": state.note_count,
                "coverage_note_notes_examined_count": state.notes_examined_count,
                "coverage_note_notes_unexamined_after_match_count": state.notes_unexamined_after_match_count,
                "coverage_note_failure_counts": state.note_counts,
                "required_output_quarantine_count": state.quarantine_observation["count"],
                "required_output_quarantine_by_kind": state.quarantine_observation["by_kind"],
                "unresolved_context_gap_count": len(state.unresolved_ids),
                "unresolved_followup_gap_count": (
                    state.unresolved_followup_count if state.gap_observation_known else "UNKNOWN"
                ),
            }
        state.coverage.append(state.coverage_row)
    for state.obligation in state.claim_reconciliation_rows:
        state.coverage.append(
            {
                "coverage_id": _hash({"run_id": state.run_id, "obligation": state.obligation["obligation_id"]})[:20],
                "run_id": state.run_id,
                "snapshot_id": state.snapshot.get("snapshot_id"),
                **state.obligation,
                "context_gap_ids": [],
                "updated_at": _now(),
            }
        )
    state.required_cov = [c for c in state.coverage if c.get("required", True)]
    state.coverage_state = (
        "COMPLETE"
        if all(c["state"] == "COMPLETE" for c in state.required_cov)
        else "NOT_STARTED"
        if not any(c["state"] != "NOT_STARTED" for c in state.required_cov)
        else "PARTIAL"
    )
    state.freshness = "UNKNOWN"
    state.freshness_details = {"expected_head_sha": state.snapshot.get("head_sha"), "observed_head_sha": None}
    if callable(state.freshness_check):
        try:
            state.check = _bounded_freshness(state.freshness_check, state.budget.remaining_seconds())
            if isinstance(state.check, dict) and state.check.get("freshness") in {"CURRENT", "STALE", "UNKNOWN"}:
                state.freshness = state.check["freshness"]
                state.freshness_details.update({k: v for k, v in state.check.items() if k != "freshness"})
        except (IsolatedCallError, OSError, TimeoutError, ValueError, KeyError) as exc:
            if isinstance(exc, IsolatedCallError) and is_defect(exc):
                raise
            # Expected freshness boundary: UNKNOWN freshness is conservative
            # and can never approve; defect types propagate.
            state.freshness = "UNKNOWN"
    elif state.snapshot.get("freshness_basis") == "HISTORICAL_SNAPSHOT" and state.snapshot.get("snapshot_hash"):
        state.freshness = "CURRENT"
        state.freshness_details["freshness_basis"] = "HISTORICAL_SNAPSHOT"
    state.blockers = [f for f in state.findings if f.get("status") == "ACCEPTED" and f.get("blocking_class") == "BLOCKING"]



def install_report_notes(state: RunState) -> None:
    """Install the deterministic report-note mapper on the state."""
    state.report_notes = functools.partial(report_notes_stage, state)



def build_and_persist_result(state: RunState) -> None:
    """Assemble result, disposition, and advisory assessment, then persist.

Contract: result hash and ledger are written atomically; disposition is
reduced deterministically from preserved findings and coverage."""
    from .completeness import build_completeness_summary
    from .engine import (
        _SYSTEM_ONE_ADVISORY_QUESTION,
        BudgetExhausted,
        _atomic_write,
        _canonical,
        _hash,
        _now,
        _reduce,
        _run_elapsed_ms,
        _settlement_observation,
        _unwrap,
        isolated_call,
        json,
        time,
    )
    state.accepted_improvements = [
        f for f in state.findings if f.get("status") == "ACCEPTED" and f.get("blocking_class") == "NON_BLOCKING"
    ]
    state.report_sections = {
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
            for f in state.blockers
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
            for f in state.accepted_improvements
        ],
        "specific_strengths": state.report_notes("specific_strengths", "why_it_matters"),
        "future_guidance": state.report_notes("future_guidance", "guidance"),
    }
    state.result = {
        "contract_version": "0.1",
        "run_id": state.run_id,
        "run_elapsed_ms": _run_elapsed_ms(state.ledger),
        "snapshot_id": state.snapshot.get("snapshot_id"),
        "base_sha": state.snapshot.get("base_sha"),
        "head_sha": state.snapshot.get("head_sha"),
        **(
            {"comparison_mode": state.snapshot["comparison_mode"], "change_base_sha": state.snapshot["change_base_sha"]}
            if state.snapshot.get("comparison_mode") == "PR_MERGE_BASE"
            else {}
        ),
        "effective_contracts": state.contracts,
        "project_profile_version": state.profile.get(
            "version",
            state.profile.get("profile_version", state.snapshot.get("profile_version", state.snapshot.get("project_profile_version"))),
        ),
        "coverage_state": state.coverage_state,
        "freshness": state.freshness,
        "freshness_details": state.freshness_details,
        "disposition": "INCOMPLETE",
        "merge_eligibility": "NOT_EVALUATED",
        "findings": state.findings,
        "coverage_ledger": state.coverage,
        "completeness_summary": build_completeness_summary(
            state.coverage,
            state.plan.get("not_applicable", []),
        ),
        "report_sections": state.report_sections,
        "created_at": state.ledger.get("created_at", _now()),
        "completed_at": _now(),
        "provider_identity": state.provider_identity,
        "repository": state.snapshot.get("repository"),
        "pull_request_number": state.snapshot.get("pull_request_number"),
        "repository_url": state.snapshot.get("repository_url"),
        "budget": state.budget.summary(),
        "task_results": state.task_results,
        "policy_valid": bool(state.plan.get("policy_valid", False)),
        "allow_empty_approve": state.approval_authority,
        "context_gaps": state.context_gaps,
        "snapshot_gaps": state.snapshot.get("gaps", []),
        "routing_reasons": state.plan.get("routing_reasons", []),
        "not_applicable": state.plan.get("not_applicable", []),
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
            for eid, ev in state.evidence_map.items()
        },
        "context_omissions": [
            {"task_id": tid, "evidence_id": eid, "reason": "input_byte_limit"}
            for tid, tr in state.task_results.items()
            for eid in tr.get("context_omissions", [])
        ],
    }
    if state.max_claim_assessments > 0:
        state.result["claim_assessments"] = [
            state.ledger["claim_assessments"][candidate_id] for candidate_id in sorted(state.ledger["claim_assessments"])
        ]
    state.result["disposition"] = _reduce(
        state.result,
        state.approval_authority,
        state.result["policy_valid"],
    )
    state.advisory_assessment = {"status": "NOT_CONFIGURED"}
    if state.decision_provider is not None and callable(getattr(state.decision_provider, "assess", None)):
        state.advisory_attempt = (
            max(
                (
                    int(key.rsplit(":", 1)[-1])
                    for key in state.budget.state["reservations"]
                    if key.startswith("system-one:advisory:") and key.rsplit(":", 1)[-1].isdigit()
                ),
                default=-1,
            )
            + 1
        )
        state.reservation_key = f"system-one:advisory:{state.advisory_attempt}"
        state.advisory_call_started = None
        try:
            state.advisory_text = json.dumps(
                {
                    "mode": state.plan.get("mode"),
                    "coverage_state": state.coverage_state,
                    "required_scopes": len(state.required_cov),
                    "finding_ids": [f["finding_id"] for f in state.findings],
                    "routing_reasons": state.plan.get("routing_reasons", []),
                },
                sort_keys=True,
            )
            state.reservation = state.reserve_provider_call(
                state.reservation_key,
                state.decision_provider,
                "SYSTEM_ONE_ASSESSMENT",
                {"task_id": state.reservation_key, "question": _SYSTEM_ONE_ADVISORY_QUESTION},
                [{"content": state.advisory_text}],
                len(state.advisory_text.encode("utf-8")),
            )
            state.advisory_deadline = min(
                float(state.reservation.get("deadline_seconds", state.remaining_call_limits()["deadline_seconds"])),
                max(0.0, state.budget.remaining_seconds() - state.required_claim_deadline_floor()),
            )
            if state.advisory_deadline <= 0:
                if state.required_claim_deadline_floor() > 0:
                    raise BudgetExhausted("REQUIRED_CLAIM_ASSESSMENT_DEADLINE_RESERVED")
                raise BudgetExhausted("DEADLINE_EXHAUSTED")
            state.advisory_call_started = time.monotonic()
            state.response = isolated_call(
                state.decision_provider,
                "assess",
                (
                    _SYSTEM_ONE_ADVISORY_QUESTION,
                    state.advisory_text,
                    {**state.limits, "deadline_seconds": state.advisory_deadline},
                ),
                deadline_seconds=state.advisory_deadline,
                output_limit=int(state.reservation["max_output_bytes"]),
                lock=state.call_lock,
            )
            state.payload, state.usage, state.provenance = _unwrap(state.response)
            state.budget.settle(
                state.reservation_key,
                output_bytes=len(_canonical(state.response)),
                usage=state.usage,
                status="SUCCEEDED",
                observation=_settlement_observation(
                    "advisory",
                    state.usage,
                    state.provenance,
                    call_elapsed_ms=(time.monotonic() - state.advisory_call_started) * 1000
                    if state.advisory_call_started is not None
                    else None,
                ),
            )
            state.advisory_assessment = {
                "status": "RECEIVED",
                "result": state.payload,
                "usage": state.usage,
                "provenance": state.provenance,
            }
        except BudgetExhausted as exc:
            if (
                state.reservation_key in state.budget.state.get("reservations", {})
                and state.reservation_key not in state.budget.state.get("settlements", {})
            ):
                try:
                    state.budget.settle(
                        state.reservation_key,
                        output_bytes=None,
                        usage={},
                        status="NOT_RUN",
                        observation=_settlement_observation("advisory", {}),
                    )
                except (ValueError, KeyError):
                    pass
            state.advisory_assessment = {"status": "NOT_RUN", "reason": str(exc)}
        except Exception as exc:
            # Intentional fail-closed advisory boundary: this runs after the
            # deterministic disposition and can never change it. A defect is
            # still labelled explicitly rather than reported as a normal miss.
            state.meta = getattr(exc, "meta", {})
            state.usage = state.meta.get("usage", {}) if isinstance(state.meta, dict) else {}
            try:
                state.budget.settle(
                    state.reservation_key,
                    output_bytes=state.meta.get("actual_output_bytes") if isinstance(state.meta, dict) else None,
                    usage=state.usage,
                    status="FAILED",
                    observation=_settlement_observation(
                        "advisory",
                        state.usage,
                        error_meta=state.meta,
                        call_elapsed_ms=(time.monotonic() - state.advisory_call_started) * 1000
                        if state.advisory_call_started is not None
                        else None,
                    ),
                )
            except (ValueError, KeyError):
                pass
            state.advisory_assessment = {
                "status": "FAILED",
                "error_code": "HARNESS_DEFECT" if is_defect(exc) else type(exc).__name__,
                "defect_type": defect_name(exc),
                "provider_error_meta": state.meta if isinstance(state.meta, dict) else {},
                "usage": state.usage,
            }
    state.result["advisory_assessment"] = state.advisory_assessment
    # The deterministic report is assembled before the optional System One
    # advisory call; finalize elapsed at the actual end of the run.
    state.result["run_elapsed_ms"] = _run_elapsed_ms(state.ledger)
    state.result["completed_at"] = _now()
    state.result["budget"] = state.budget.summary()
    state.ledger["outputs"] = state.task_results
    state.ledger["findings"] = state.findings
    state.ledger["context_gaps"] = state.context_gaps
    state.ledger["call_reservations"] = state.result["budget"]["provider_calls_reserved"]
    state.ledger["created_at"] = state.result["created_at"]
    for state.task_id, state.task_result in state.task_results.items():
        state.event = {
            "event": "TASK_RESULT",
            "task_id": state.task_id,
            "output_hash": state.task_result.get("output_hash"),
            "status": state.task_result.get("status"),
            "at": state.task_result.get("finished_at", _now()),
        }
        state.event["event_hash"] = _hash(state.event)
        state.ledger["events"].append(state.event)
    state.saved = {**state.result, "request_hash": state.request_hash, "ledger": state.ledger}
    state.saved["result_hash"] = _hash(state.saved)
    if state.private_capture is not None:
        state.private_capture.export_case_packets(state.result, profile=state.profile)
    _atomic_write(state.output_path, _canonical(state.saved) + b"\n")


