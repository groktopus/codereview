"""Durable, thread-safe reservations for every bounded review invocation."""

from __future__ import annotations

import hashlib
import json
import math
import multiprocessing
import os
import signal
import threading
import time
from multiprocessing.connection import wait as wait_connections
from typing import Any, Callable

from .contracts import (
    ADJUDICATION_V1,
    ADJUDICATION_V2,
    ADJUDICATION_V3,
    SPECIALIST_V1,
    SPECIALIST_V2,
    SPECIALIST_V3,
    SPECIALIST_V4,
)

_PROVIDER_CONTRACT_VERSIONS = frozenset(
    {
        ADJUDICATION_V1,
        ADJUDICATION_V2,
        ADJUDICATION_V3,
        SPECIALIST_V1,
        SPECIALIST_V2,
        SPECIALIST_V3,
        SPECIALIST_V4,
    }
)
_MAX_PROVIDER_RESPONSE_BYTES = 64 * 1024 * 1024 + 1
_MAX_PROVIDER_ELAPSED_MS = 24 * 60 * 60 * 1000
_LOCAL_HTTP_EXCHANGE_STATES = frozenset(
    {
        "REQUEST_SERIALIZED",
        "REQUEST_ATTEMPTED",
        "HTTP_RESPONSE_RECEIVED",
        "HTTP_ERROR_RESPONSE",
        "TRANSPORT_FAILURE",
        "UNKNOWN",
    }
)


def _safe_local_http_exchange(value: Any) -> dict | None:
    """Validate the versioned local observation while dropping unapproved fields."""
    if not isinstance(value, dict) or value.get("contract_version") != "local-http-exchange.v1":
        return None
    state = value.get("state")
    request_hash = value.get("request_sha256")
    endpoint_hash = value.get("endpoint_sha256")
    request_bytes = value.get("request_bytes")

    def valid_hash(item: Any) -> bool:
        return isinstance(item, str) and len(item) == 64 and all(c in "0123456789abcdef" for c in item)

    if (
        not isinstance(state, str)
        or state not in _LOCAL_HTTP_EXCHANGE_STATES
        or value.get("delivery_observation") != "UNKNOWN"
        or value.get("request_serialized") is not True
        or type(value.get("request_attempted")) is not bool
        or not valid_hash(request_hash)
        or (not valid_hash(endpoint_hash) and not (state == "REQUEST_SERIALIZED" and endpoint_hash is None))
        or type(request_bytes) is not int
        or not 0 <= request_bytes <= _MAX_PROVIDER_RESPONSE_BYTES
    ):
        return None
    attempted = value["request_attempted"]
    status = value.get("http_status")
    response_hash = value.get("response_sha256")
    response_bytes = value.get("response_bytes")
    response_complete = value.get("response_complete")
    has_response_bytes = response_hash is not None or response_bytes is not None
    if not has_response_bytes and response_complete is not None:
        return None
    if state in {"REQUEST_SERIALIZED", "REQUEST_ATTEMPTED", "TRANSPORT_FAILURE"} and (
        status is not None or has_response_bytes or response_complete is not None
    ):
        return None
    if state == "REQUEST_SERIALIZED" and attempted:
        return None
    if state in {"REQUEST_ATTEMPTED", "TRANSPORT_FAILURE"} and not attempted:
        return None
    if state in {"HTTP_RESPONSE_RECEIVED", "HTTP_ERROR_RESPONSE"} and (
        not attempted or type(status) is not int or not 100 <= status <= 599
    ):
        return None
    if state in {"HTTP_RESPONSE_RECEIVED", "HTTP_ERROR_RESPONSE"} and not has_response_bytes:
        return None
    if state == "UNKNOWN" and (status is not None or has_response_bytes or response_complete is not None):
        return None
    safe = {
        "contract_version": "local-http-exchange.v1",
        "state": state,
        "delivery_observation": "UNKNOWN",
        "request_serialized": True,
        "request_attempted": attempted,
        "request_sha256": request_hash,
        "request_bytes": request_bytes,
    }
    if valid_hash(endpoint_hash):
        safe["endpoint_sha256"] = endpoint_hash
    for name, limit in (("provider_id", 128), ("model_id", 256)):
        item = value.get(name)
        if isinstance(item, str) and item and len(item) <= limit and not any(ord(ch) < 32 for ch in item):
            safe[name] = item
    if status is not None and type(status) is int and 100 <= status <= 599:
        safe["http_status"] = status
    if response_hash is not None or response_bytes is not None:
        if (
            not valid_hash(response_hash)
            or type(response_bytes) is not int
            or not 0 <= response_bytes <= _MAX_PROVIDER_RESPONSE_BYTES
            or type(response_complete) is not bool
        ):
            return None
        safe.update(
            {
                "response_sha256": response_hash,
                "response_bytes": response_bytes,
                "response_complete": response_complete,
            }
        )
    elapsed = value.get("elapsed_ms")
    if type(elapsed) is int and 0 <= elapsed <= _MAX_PROVIDER_ELAPSED_MS:
        safe["elapsed_ms"] = elapsed
    elif type(elapsed) is float and math.isfinite(elapsed) and 0 <= elapsed <= _MAX_PROVIDER_ELAPSED_MS:
        safe["elapsed_ms"] = elapsed
    return safe


def _safe_provider_metadata(meta: dict, output_limit: int) -> dict:
    """Keep only bounded provider diagnostics across the isolated-process boundary."""
    approved = {
        "request_id",
        "elapsed_seconds",
        "usage",
        "actual_output_bytes",
    }
    safe = {key: value for key, value in meta.items() if key in approved}
    sources = [meta]
    provenance = meta.get("provenance")
    if isinstance(provenance, dict):
        sources.append(provenance)

    for source in sources:
        exchange = _safe_local_http_exchange(source.get("local_http_exchange"))
        if exchange is not None:
            safe["local_http_exchange"] = exchange
        for key in ("request_hash", "response_hash"):
            value = source.get(key)
            if isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value):
                safe[key] = value

        status = source.get("http_status")
        if type(status) is int and 100 <= status <= 599:
            safe["http_status"] = status

        response_bytes = source.get("response_bytes")
        if type(response_bytes) is int and 0 <= response_bytes <= _MAX_PROVIDER_RESPONSE_BYTES:
            safe["response_bytes"] = response_bytes

        truncated = source.get("output_truncated")
        if type(truncated) is bool:
            safe["output_truncated"] = truncated

        elapsed_ms = source.get("elapsed_ms")
        if type(elapsed_ms) is int and 0 <= elapsed_ms <= _MAX_PROVIDER_ELAPSED_MS:
            safe["elapsed_ms"] = elapsed_ms
        elif type(elapsed_ms) is float and math.isfinite(elapsed_ms) and 0 <= elapsed_ms <= _MAX_PROVIDER_ELAPSED_MS:
            safe["elapsed_ms"] = elapsed_ms

        contract_version = source.get("provider_contract_version")
        if isinstance(contract_version, str) and contract_version in _PROVIDER_CONTRACT_VERSIONS:
            safe["provider_contract_version"] = contract_version

    actual_output_bytes = safe.get("actual_output_bytes")
    if type(actual_output_bytes) is not int or not 0 <= actual_output_bytes <= _MAX_PROVIDER_RESPONSE_BYTES:
        safe.pop("actual_output_bytes", None)
    return safe


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


class BudgetExhausted(RuntimeError):
    """A reservation could not be made without exceeding a configured limit."""


class BudgetLedger:
    """Single authority for call, input, output, retrieval and money budgets.

    ``state`` is stored in the run ledger and every new reservation is persisted
    before work is started. Replaying an identical reservation key is a no-op;
    a key reused with different estimates is a hard integrity error.
    """

    def __init__(
        self,
        limits: dict,
        state: dict,
        persist: Callable[[], None] | None = None,
        deadline_epoch: float | None = None,
    ) -> None:
        self.limits = limits
        self.state = state
        self.state.setdefault("reservations", {})
        self.state.setdefault("settlements", {})
        self.state.setdefault("context_retrievals", 0)
        self.state.setdefault("followup_tasks", 0)
        self._persist = persist or (lambda: None)
        self._lock = threading.RLock()
        self.deadline_epoch = deadline_epoch
        self._deadline_monotonic = (
            time.monotonic() + max(0.0, deadline_epoch - time.time()) if deadline_epoch is not None else None
        )

    def remaining_seconds(self) -> float:
        if self._deadline_monotonic is None:
            return 0.0
        return max(0.0, self._deadline_monotonic - time.monotonic())

    def reserve(
        self,
        key: str,
        estimate: dict,
        *,
        kind: str = "provider",
        provider_call_floor: int = 0,
        deadline_floor_seconds: float = 0.0,
    ) -> dict:
        """Atomically reserve every resource before invocation starts."""
        if not isinstance(key, str) or not key or not isinstance(estimate, dict):
            raise ValueError("reservation key and estimate are required")
        if isinstance(provider_call_floor, bool) or not isinstance(provider_call_floor, int) or provider_call_floor < 0:
            raise ValueError("provider_call_floor must be a nonnegative integer")
        if (
            isinstance(deadline_floor_seconds, bool)
            or not isinstance(deadline_floor_seconds, (int, float))
            or not math.isfinite(deadline_floor_seconds)
            or deadline_floor_seconds < 0
        ):
            raise ValueError("deadline_floor_seconds must be a finite nonnegative number")
        cost = estimate.get("max_cost_microunits")
        reservation = {
            "key": key,
            "kind": kind,
            "provider_calls": _nonnegative_int(estimate.get("provider_calls", 1), "provider_calls"),
            "input_bytes": _nonnegative_int(estimate.get("input_bytes", 0), "input_bytes"),
            "max_output_bytes": _nonnegative_int(
                estimate.get("max_output_bytes", self.limits["max_output_bytes_per_task"]), "max_output_bytes"
            ),
            "max_cost_microunits": None if cost is None else _nonnegative_int(cost, "max_cost_microunits"),
            "reservation_kind": estimate.get("reservation_kind", "unknown"),
            "deadline_seconds": float(estimate.get("deadline_seconds", self.remaining_seconds())),
            # Remaining time is transient. A resumed identical request must
            # replay the original reservation instead of conflicting because
            # its wall-clock deadline is now closer.
            "estimate_hash": _digest({k: v for k, v in estimate.items() if k != "deadline_seconds"}),
            "status": "RESERVED",
        }
        if not math.isfinite(reservation["deadline_seconds"]) or reservation["deadline_seconds"] <= 0:
            raise ValueError("invalid reservation: deadline_seconds")
        with self._lock:
            existing = self.state["reservations"].get(key)
            if existing:
                if existing.get("estimate_hash") != reservation["estimate_hash"]:
                    raise ValueError("reservation key reused with different estimate")
                return existing
            current_remaining_seconds = self.remaining_seconds()
            if current_remaining_seconds <= 0:
                raise BudgetExhausted("DEADLINE_EXHAUSTED")
            if deadline_floor_seconds:
                available_deadline_seconds = current_remaining_seconds - deadline_floor_seconds
                if available_deadline_seconds <= 0:
                    raise BudgetExhausted("REQUIRED_CLAIM_ASSESSMENT_DEADLINE_RESERVED")
                reservation["deadline_seconds"] = min(
                    reservation["deadline_seconds"], available_deadline_seconds
                )
            reservations = list(self.state["reservations"].values())
            reserved_calls = sum(r.get("provider_calls", 0) for r in reservations)
            projected_calls = reserved_calls + reservation["provider_calls"]
            if projected_calls > int(self.limits["max_provider_calls"]):
                raise BudgetExhausted("PROVIDER_CALL_BUDGET_EXHAUSTED")
            if projected_calls + provider_call_floor > int(self.limits["max_provider_calls"]):
                raise BudgetExhausted("REQUIRED_CLAIM_ASSESSMENT_CAP_RESERVED")
            if sum(r.get("input_bytes", 0) for r in reservations) + reservation["input_bytes"] > int(
                self.limits["max_context_bytes"]
            ):
                raise BudgetExhausted("CONTEXT_BYTE_BUDGET_EXHAUSTED")
            if reservation["input_bytes"] > int(self.limits["max_input_bytes_per_task"]):
                raise BudgetExhausted("INPUT_BYTE_LIMIT_EXCEEDED")
            if reservation["max_output_bytes"] > int(self.limits["max_output_bytes_per_task"]):
                raise BudgetExhausted("OUTPUT_BYTE_LIMIT_EXCEEDED")
            output_reserved = sum(r.get("max_output_bytes", 0) for r in reservations)
            if output_reserved + reservation["max_output_bytes"] > int(self.limits["max_output_bytes"]):
                raise BudgetExhausted("OUTPUT_BYTE_BUDGET_EXHAUSTED")
            if self.limits.get("max_cost_microunits") is not None:
                if reservation["max_cost_microunits"] is None or reservation["reservation_kind"] != "operator_bound":
                    raise BudgetExhausted("MONETARY_BOUND_UNAVAILABLE")
                reserved_cost = sum(r.get("max_cost_microunits") or 0 for r in reservations)
                if reserved_cost + reservation["max_cost_microunits"] > int(self.limits["max_cost_microunits"]):
                    raise BudgetExhausted("MONETARY_BUDGET_EXHAUSTED")
            self.state["reservations"][key] = reservation
            self._persist()
            return reservation

    def reserve_retrieval(self, key: str, byte_ceiling: int) -> dict:
        """Reserve one allowlisted snapshot-context retrieval and its bytes."""
        with self._lock:
            existing = self.state["reservations"].get(key)
            if existing:
                if existing.get("kind") != "context_retrieval" or existing.get("input_bytes") != byte_ceiling:
                    raise ValueError("retrieval reservation key reused with different estimate")
                return existing
            if int(self.state.get("context_retrievals", 0)) >= int(self.limits["max_context_retrievals"]):
                raise BudgetExhausted("CONTEXT_RETRIEVAL_BUDGET_EXHAUSTED")
            record = self.reserve(
                key,
                {
                    "provider_calls": 0,
                    "input_bytes": byte_ceiling,
                    "max_output_bytes": 0,
                    "max_cost_microunits": 0,
                    "reservation_kind": "operator_bound",
                },
                kind="context_retrieval",
            )
            if record.get("kind") == "context_retrieval" and record.get("status") == "RESERVED":
                if not record.get("retrieval_counted"):
                    self.state["context_retrievals"] = int(self.state.get("context_retrievals", 0)) + 1
                    record["retrieval_counted"] = True
                    self._persist()
            return record

    def reserve_followup(self, task_key: str) -> None:
        with self._lock:
            existing = set(self.state.setdefault("followup_task_keys", []))
            if task_key in existing:
                return
            if len(existing) >= int(self.limits["max_followup_tasks"]):
                raise BudgetExhausted("FOLLOWUP_TASK_BUDGET_EXHAUSTED")
            existing.add(task_key)
            self.state["followup_task_keys"] = sorted(existing)
            self.state["followup_tasks"] = len(existing)
            self._persist()

    def settle(
        self,
        key: str,
        *,
        output_bytes: int | None,
        usage: dict,
        status: str,
        observation: dict | None = None,
    ) -> None:
        """Append actual usage while keeping unavailable billing explicitly unknown."""
        with self._lock:
            reservation = self.state["reservations"].get(key)
            if reservation is None:
                raise ValueError("settlement without reservation")
            settlement = {
                "status": status,
                "actual_output_bytes": output_bytes,
                "usage": usage if isinstance(usage, dict) else {},
                "billed_cost_microunits": (usage or {}).get("billed_cost_microunits"),
                "estimated_cost_microunits": (usage or {}).get("estimated_cost_microunits"),
                "settled_at_epoch": time.time(),
            }
            safe_observation = _safe_settlement_observation(observation)
            if safe_observation is not None:
                settlement["observation"] = safe_observation
            current = self.state["settlements"].get(key)
            if current is not None:
                comparable = {k: v for k, v in settlement.items() if k != "settled_at_epoch"}
                prior = {k: v for k, v in current.items() if k != "settled_at_epoch"}
                # Pre-observability checkpoints have no observation field. A
                # replay may add the optional argument now, but cannot invent
                # a receipt for work whose old checkpoint omitted one.
                if "observation" not in prior:
                    comparable.pop("observation", None)
                elif safe_observation is None:
                    prior.pop("observation", None)
                if prior != comparable:
                    raise ValueError("conflicting settlement replay")
                return
            if output_bytes is not None:
                if reservation.get("kind") == "context_retrieval":
                    retrieval_cap = reservation.get("input_bytes", 0)
                    if output_bytes > retrieval_cap:
                        self.state.setdefault("budget_breaches", []).append(
                            {
                                "key": key,
                                "reason": "CONTEXT_RETRIEVAL_RESERVATION_OVERRUN",
                                "actual": output_bytes,
                                "reserved": retrieval_cap,
                            }
                        )
                elif output_bytes > reservation.get("max_output_bytes", 0):
                    self.state.setdefault("budget_breaches", []).append(
                        {
                            "key": key,
                            "reason": "OUTPUT_RESERVATION_OVERRUN",
                            "actual": output_bytes,
                            "reserved": reservation.get("max_output_bytes", 0),
                        }
                    )
            billed_cost = settlement["billed_cost_microunits"]
            cap = reservation.get("max_cost_microunits")
            if (
                isinstance(billed_cost, int)
                and not isinstance(billed_cost, bool)
                and cap is not None
                and billed_cost > cap
            ):
                self.state.setdefault("budget_breaches", []).append(
                    {"key": key, "reason": "MONETARY_RESERVATION_OVERRUN", "actual": billed_cost, "reserved": cap}
                )
            run_cap = self.limits.get("max_cost_microunits")
            if isinstance(billed_cost, int) and not isinstance(billed_cost, bool) and run_cap is not None:
                known_cost = sum(
                    value
                    for settled in self.state["settlements"].values()
                    if isinstance((value := settled.get("billed_cost_microunits")), int)
                    and not isinstance(value, bool)
                    and value >= 0
                )
                if known_cost + billed_cost > run_cap:
                    self.state.setdefault("budget_breaches", []).append(
                        {"key": key, "reason": "MONETARY_RUN_BUDGET_OVERRUN", "actual": billed_cost, "limit": run_cap}
                    )
            reservation["status"] = "SETTLED"
            self.state["settlements"][key] = settlement
            self._persist()

    def summary(self) -> dict:
        with self._lock:
            reservations = list(self.state["reservations"].values())
            settlements = self.state["settlements"]
            provider_reservations = [r for r in reservations if r.get("provider_calls", 0) > 0]
            local_check_reservations = [r for r in reservations if r.get("kind") == "deterministic_check"]
            billed = [settlements.get(r["key"], {}).get("billed_cost_microunits") for r in provider_reservations]
            estimated = [settlements.get(r["key"], {}).get("estimated_cost_microunits") for r in provider_reservations]

            def valid_billed(value: Any) -> bool:
                return isinstance(value, int) and not isinstance(value, bool) and value >= 0

            def valid_estimate(value: Any) -> bool:
                return isinstance(value, int) and not isinstance(value, bool) and value >= 0

            provider_observability = _provider_observability(reservations, settlements)
            return {
                "provider_calls_reserved": sum(r.get("provider_calls", 0) for r in reservations),
                "provider_calls_limit": self.limits["max_provider_calls"],
                "local_check_reservations": len(local_check_reservations),
                "local_check_input_bytes_reserved": sum(r.get("input_bytes", 0) for r in local_check_reservations),
                "local_check_output_bytes_reserved": sum(
                    r.get("max_output_bytes", 0) for r in local_check_reservations
                ),
                "context_bytes_reserved": sum(r.get("input_bytes", 0) for r in reservations),
                "context_bytes_limit": self.limits["max_context_bytes"],
                "output_bytes_reserved": sum(r.get("max_output_bytes", 0) for r in reservations),
                "output_bytes_limit": self.limits["max_output_bytes"],
                "context_retrievals_reserved": self.state.get("context_retrievals", 0),
                "context_retrievals_limit": self.limits["max_context_retrievals"],
                "followup_tasks_reserved": self.state.get("followup_tasks", 0),
                "followup_tasks_limit": self.limits["max_followup_tasks"],
                "cost_reserved_microunits": sum(r.get("max_cost_microunits") or 0 for r in reservations),
                "cost_limit_microunits": self.limits.get("max_cost_microunits"),
                "cost_billed_microunits": sum(v for v in billed if valid_billed(v)),
                "cost_billing_known": bool(billed) and all(valid_billed(v) for v in billed),
                "cost_estimated_microunits": sum(v for v in estimated if valid_estimate(v)),
                "cost_estimate_known": bool(estimated) and all(valid_estimate(v) for v in estimated),
                "cost": sum(billed) if bool(billed) and all(valid_billed(v) for v in billed) else "UNKNOWN",
                "provider_observability": provider_observability,
                "budget_breaches": list(self.state.get("budget_breaches", [])),
            }


_OBSERVATION_STAGES = frozenset(
    {
        "primary",
        "followup",
        "semantic_adjudication",
        "claim_assessment",
        "advisory",
        "deterministic_check",
        "context_retrieval",
        "other",
    }
)
_TOKEN_FIELDS = ("prompt_tokens", "completion_tokens", "input_tokens", "output_tokens", "total_tokens")


def _valid_token_count(value: Any) -> bool:
    return type(value) is int and value >= 0


def _usage_state(usage: Any, known_flag: Any = None) -> str:
    if not isinstance(usage, dict):
        return "UNKNOWN"
    has_any = any(_valid_token_count(usage.get(field)) for field in _TOKEN_FIELDS)
    required = all(_valid_token_count(usage.get(field)) for field in ("prompt_tokens", "completion_tokens", "total_tokens"))
    if known_flag is True and required:
        return "KNOWN"
    return "PARTIAL" if has_any else "UNKNOWN"


def _safe_elapsed(value: Any) -> float | None:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return None
    try:
        elapsed = float(value)
    except (OverflowError, TypeError, ValueError):
        return None
    return round(elapsed, 2) if math.isfinite(elapsed) and elapsed >= 0 else None


def _safe_settlement_observation(value: Any) -> dict | None:
    """Keep only finite scalar counters; provider payloads and metadata stay out."""
    if not isinstance(value, dict):
        return None
    stage = value.get("stage")
    if not isinstance(stage, str) or stage not in _OBSERVATION_STAGES:
        stage = "other"
    result: dict[str, Any] = {"stage": stage}
    attempted = value.get("request_attempted")
    result["request_attempted"] = attempted if isinstance(attempted, bool) else None
    status = value.get("http_status")
    result["http_status"] = status if type(status) is int and 100 <= status <= 599 else None
    for field in ("call_elapsed_ms", "http_elapsed_ms"):
        result[field] = _safe_elapsed(value.get(field))
    token_values = {}
    for field in _TOKEN_FIELDS:
        token_count = value.get(field)
        token_values[field] = token_count if type(token_count) is int and token_count >= 0 else None
    result["usage"] = token_values
    result["usage_state"] = _usage_state(token_values, value.get("usage_known"))
    return result


def _stage_for_reservation(reservation: dict) -> str:
    key = reservation.get("key", "")
    kind = reservation.get("kind")
    if kind == "context_retrieval":
        return "context_retrieval"
    if kind == "deterministic_check":
        return "deterministic_check"
    if isinstance(key, str):
        if ":review:" in key:
            return "followup" if ":followup:" in key else "primary"
        if ":adjudicate:" in key:
            return "semantic_adjudication"
        if key.startswith("claim-assessment:"):
            return "claim_assessment"
        if key.startswith("system-one:advisory:"):
            return "advisory"
    return "other"


def _attempt_family(key: Any) -> str:
    if not isinstance(key, str):
        return "unknown"
    if ":review:" in key:
        prefix, _, suffix = key.rpartition(":")
        return prefix if suffix.isdigit() else key
    if ":attempt:" in key:
        prefix, _, suffix = key.rpartition(":")
        return prefix if suffix.isdigit() else key
    if key.startswith("system-one:advisory:"):
        prefix, _, suffix = key.rpartition(":")
        return prefix if suffix.isdigit() else key
    return key


def _provider_observability(reservations: list[dict], settlements: dict) -> dict:
    """Summarize actual scalar observations with explicit unknown denominators."""
    stages: dict[str, dict[str, Any]] = {}
    families: dict[str, dict[str, set[str]]] = {}
    for reservation in reservations:
        if not isinstance(reservation, dict):
            continue
        key = reservation.get("key")
        settlement = settlements.get(key, {}) if isinstance(key, str) else {}
        observation = settlement.get("observation", {}) if isinstance(settlement, dict) else {}
        stage = observation.get("stage") if isinstance(observation, dict) else None
        if stage not in _OBSERVATION_STAGES:
            stage = _stage_for_reservation(reservation)
        row = stages.setdefault(
            stage,
            {
                "provider_calls_reserved": 0,
                "tool_calls_reserved": 0,
                "retry_calls": 0,
                "settled_calls": 0,
                "settled_reservations": 0,
                "request_attempted": 0,
                "request_not_attempted": 0,
                "request_attempt_unknown": 0,
                "call_elapsed_ms_sum": 0.0,
                "call_elapsed_known": 0,
                "http_elapsed_ms_sum": 0.0,
                "http_elapsed_known": 0,
                "usage_known": 0,
                "usage_partial": 0,
                "usage_unknown": 0,
                "billed_cost_known": 0,
                "billed_cost_microunits": 0,
                "estimated_cost_known": 0,
                "estimated_cost_microunits": 0,
                "usage_fields": {field: {"reported_count": 0, "reported_sum": 0} for field in _TOKEN_FIELDS},
            },
        )
        provider_calls = reservation.get("provider_calls", 0)
        if type(provider_calls) is not int or provider_calls < 0:
            provider_calls = 0
        if isinstance(observation, dict):
            for field, counter in (("call_elapsed_ms", "call"), ("http_elapsed_ms", "http")):
                elapsed = _safe_elapsed(observation.get(field))
                if elapsed is not None:
                    row[f"{counter}_elapsed_ms_sum"] += elapsed
                    row[f"{counter}_elapsed_known"] += 1
        if provider_calls:
            row["provider_calls_reserved"] += provider_calls
            if isinstance(key, str):
                family = _attempt_family(key)
                families.setdefault(stage, {}).setdefault(family, set()).add(key)
            if key in settlements:
                row["settled_calls"] += provider_calls
            attempted = observation.get("request_attempted") if isinstance(observation, dict) else None
            if attempted is True:
                row["request_attempted"] += provider_calls
            elif attempted is False:
                row["request_not_attempted"] += provider_calls
            else:
                row["request_attempt_unknown"] += provider_calls
            if isinstance(observation, dict):
                usage_state = observation.get("usage_state")
                usage = observation.get("usage", {})
                if "usage_state" not in observation:
                    usage = settlement.get("usage", {}) if isinstance(settlement, dict) else {}
                    usage_state = _usage_state(usage, usage.get("known") if isinstance(usage, dict) else None)
                else:
                    usage_state = _usage_state(usage, usage_state == "KNOWN")
            else:
                usage = settlement.get("usage", {}) if isinstance(settlement, dict) else {}
                usage_state = _usage_state(usage, usage.get("known") if isinstance(usage, dict) else None)
            if not isinstance(usage_state, str) or usage_state not in {"KNOWN", "PARTIAL"}:
                usage_state = "UNKNOWN"
            row[f"usage_{usage_state.lower()}"] += provider_calls
            for field in _TOKEN_FIELDS:
                value = usage.get(field) if isinstance(usage, dict) else None
                if type(value) is int and value >= 0:
                    row["usage_fields"][field]["reported_count"] += provider_calls
                    row["usage_fields"][field]["reported_sum"] += value
            if isinstance(settlement, dict):
                for field, count_key, sum_key in (
                    ("billed_cost_microunits", "billed_cost_known", "billed_cost_microunits"),
                    ("estimated_cost_microunits", "estimated_cost_known", "estimated_cost_microunits"),
                ):
                    value = settlement.get(field)
                    if type(value) is int and value >= 0:
                        row[count_key] += provider_calls
                        row[sum_key] += value
        elif reservation.get("kind") in {"context_retrieval", "deterministic_check"}:
            row["tool_calls_reserved"] += 1
        if isinstance(key, str) and key in settlements:
            row["settled_reservations"] += 1
    for stage, row in stages.items():
        row["retry_calls"] = sum(max(0, len(keys) - 1) for keys in families.get(stage, {}).values())
        row["call_elapsed_ms_sum"] = round(row["call_elapsed_ms_sum"], 2)
        row["http_elapsed_ms_sum"] = round(row["http_elapsed_ms_sum"], 2)
    return {
        "provider_calls_reserved": sum(row["provider_calls_reserved"] for row in stages.values()),
        "tool_calls_reserved": sum(row["tool_calls_reserved"] for row in stages.values()),
        "retry_calls": sum(max(0, len(keys) - 1) for groups in families.values() for keys in groups.values()),
        "stages": stages,
    }


def _positive_int(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"invalid reservation: {name}")
    return value


def _nonnegative_int(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"invalid reservation: {name}")
    return value


class IsolatedCallError(RuntimeError):
    def __init__(self, remote_type: str, message: str, meta: dict | None = None) -> None:
        super().__init__(message)
        self.remote_type = remote_type
        self.meta = meta or {}


def _bounded_wait_timeout(value: float | None) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
        raise ValueError("invalid readiness wait timeout")
    return float(value)


class IsolatedInvocation:
    """One spawn-isolated, killable provider invocation managed by the controller."""

    def __init__(
        self,
        target: Any,
        method_name: str,
        args: tuple,
        *,
        deadline_seconds: float,
        output_limit: int,
    ) -> None:
        if deadline_seconds <= 0:
            raise IsolatedCallError("TimeoutError", "DEADLINE_EXHAUSTED")
        if os.name != "posix":
            raise IsolatedCallError("WorkerStartError", "UNSUPPORTED_PROCESS_TREE_ISOLATION")
        self._target = target
        self._deadline = time.monotonic() + deadline_seconds
        ctx = multiprocessing.get_context("spawn")
        self._recv, send_conn = ctx.Pipe(duplex=False)
        self._process = ctx.Process(
            target=_child_call, args=(send_conn, target, method_name, args, output_limit), daemon=True
        )
        try:
            self._process.start()
        except Exception as exc:
            send_conn.close()
            self._recv.close()
            raise IsolatedCallError("WorkerStartError", "WORKER_START_FAILED") from exc
        send_conn.close()
        self._response = None
        self._finished = False

    def poll(self) -> bool:
        if self._finished:
            return True
        if self._recv.poll(0):
            try:
                self._response = self._recv.recv()
            except EOFError:
                self._response = ("error", "WorkerExit", "WORKER_EXITED_WITHOUT_RESULT", {}, None)
            self._stop()
            self._finished = True
            return True
        if time.monotonic() >= self._deadline:
            self._response = ("error", "TimeoutError", "DEADLINE_EXCEEDED", {}, None)
            self._stop()
            self._finished = True
            return True
        if not self._process.is_alive():
            if self._recv.poll(0.01):
                return self.poll()
            self._response = ("error", "WorkerExit", "WORKER_EXITED_WITHOUT_RESULT", {}, None)
            self._stop()
            self._finished = True
            return True
        return False

    @property
    def remaining_seconds(self) -> float:
        """Return the remaining hard deadline for this child invocation."""
        return max(0.0, self._deadline - time.monotonic())

    def wait_handles(self) -> tuple[Any, ...]:
        """Return the result pipe and child sentinel used for readiness waits."""
        if self._finished:
            return ()
        return self._recv, self._process.sentinel

    def wait_for_ready(self, timeout: float | None = None) -> bool:
        """Block until this child sends/closes its pipe or exits, up to its deadline."""
        timeout = _bounded_wait_timeout(timeout)
        handles = self.wait_handles()
        if not handles:
            return True
        remaining = self.remaining_seconds
        wait_seconds = remaining if timeout is None else min(max(0.0, timeout), remaining)
        return bool(wait_connections(handles, timeout=wait_seconds))

    def _stop(self) -> None:
        # The worker calls setsid before invoking an adapter. Its subprocesses
        # inherit the private session, allowing cancellation of the full tree
        # without signalling the controller's process group.
        try:
            if (
                self._process.pid
                and os.getpgid(self._process.pid) == self._process.pid
                and os.getsid(self._process.pid) == self._process.pid
            ):
                os.killpg(self._process.pid, signal.SIGTERM)
                self._process.join(timeout=0.05)
                try:
                    os.killpg(self._process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            elif self._process.is_alive():
                self._process.terminate()
            self._process.join(timeout=0.05)
        except ProcessLookupError:
            self._process.join(timeout=0.05)
        except PermissionError:
            if self._process.is_alive():
                self._process.terminate()
            self._process.join(timeout=0.05)
        if self._process.is_alive():
            self._process.kill()
            self._process.join(timeout=0.05)
        self._recv.close()

    def cancel(self) -> None:
        if not self._finished:
            self._response = ("error", "Cancelled", "WORKER_CANCELLED", {}, None)
            self._stop()
            self._finished = True

    def result(self) -> Any:
        if not self.poll():
            raise RuntimeError("invocation is still running")
        response = self._response
        if response[0] == "ok":
            return response[1]
        _, remote_type, message, meta, _delta = response
        raise IsolatedCallError(remote_type, message, meta)


def _child_call(send_conn: Any, target: Any, method_name: str, args: tuple, output_limit: int) -> None:
    """Execute only trusted adapter code in a disposable child, never target code."""
    os.setsid()
    before = getattr(target, "calls", None)

    def call_delta() -> int | None:
        after = getattr(target, "calls", None)
        return after - before if isinstance(before, int) and isinstance(after, int) else None

    try:
        response = getattr(target, method_name)(*args)
        if len(_canonical(response)) > output_limit:
            actual_output_bytes = len(_canonical(response))
            response_meta = {
                "usage": response.get("usage", {}) if isinstance(response, dict) else {},
                "provenance": response.get("provenance", {}) if isinstance(response, dict) else {},
                "actual_output_bytes": actual_output_bytes,
            }
            send_conn.send(
                (
                    "error",
                    "OutputLimitError",
                    "OUTPUT_BYTE_LIMIT_EXCEEDED",
                    _safe_provider_metadata(response_meta, output_limit),
                    call_delta(),
                )
            )
        else:
            send_conn.send(("ok", response, call_delta()))
    except BaseException as exc:  # propagate only type and approved metadata
        meta = getattr(exc, "meta", {})
        if not isinstance(meta, dict):
            meta = {}
        send_conn.send(
            (
                "error",
                type(exc).__name__,
                str(getattr(exc, "code", type(exc).__name__))[:120],
                _safe_provider_metadata(meta, output_limit),
                call_delta(),
            )
        )
    finally:
        send_conn.close()


def isolated_call(
    target: Any,
    method_name: str,
    args: tuple,
    *,
    deadline_seconds: float,
    output_limit: int,
    lock: threading.Lock | None = None,
) -> Any:
    """Run a trusted adapter in a spawned process group with a hard deadline."""
    invocation = IsolatedInvocation(
        target, method_name, args, deadline_seconds=deadline_seconds, output_limit=output_limit
    )
    while not invocation.poll():
        invocation.wait_for_ready()
    return invocation.result()


def wait_for_any(invocations: list[IsolatedInvocation], timeout: float | None = None) -> list[IsolatedInvocation]:
    """Wait for any active child pipe/sentinel, bounded by the nearest deadline."""
    timeout = _bounded_wait_timeout(timeout)
    active = [invocation for invocation in invocations if invocation.wait_handles()]
    if not active:
        return []
    handles: list[Any] = []
    owners: dict[Any, IsolatedInvocation] = {}
    for invocation in active:
        for handle in invocation.wait_handles():
            handles.append(handle)
            owners[handle] = invocation
    now = time.monotonic()
    nearest_deadline_remaining = max(0.0, min(invocation._deadline for invocation in active) - now)
    wait_seconds = nearest_deadline_remaining if timeout is None else min(timeout, nearest_deadline_remaining)
    ready = set(wait_connections(handles, timeout=wait_seconds))
    ready_ids = {id(owners[handle]) for handle in ready if handle in owners}
    return [invocation for invocation in active if id(invocation) in ready_ids]
