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

    def reserve(self, key: str, estimate: dict, *, kind: str = "provider") -> dict:
        """Atomically reserve every resource before invocation starts."""
        if not isinstance(key, str) or not key or not isinstance(estimate, dict):
            raise ValueError("reservation key and estimate are required")
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
            if self.remaining_seconds() <= 0:
                raise BudgetExhausted("DEADLINE_EXHAUSTED")
            reservations = list(self.state["reservations"].values())
            if sum(r.get("provider_calls", 0) for r in reservations) + reservation["provider_calls"] > int(
                self.limits["max_provider_calls"]
            ):
                raise BudgetExhausted("PROVIDER_CALL_BUDGET_EXHAUSTED")
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

    def settle(self, key: str, *, output_bytes: int | None, usage: dict, status: str) -> None:
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
            current = self.state["settlements"].get(key)
            if current is not None:
                comparable = {k: v for k, v in settlement.items() if k != "settled_at_epoch"}
                prior = {k: v for k, v in current.items() if k != "settled_at_epoch"}
                if prior != comparable:
                    raise ValueError("conflicting settlement replay")
                return
            if output_bytes is not None and output_bytes > reservation.get("max_output_bytes", 0):
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
            billed = [settlements.get(r["key"], {}).get("billed_cost_microunits") for r in provider_reservations]
            estimated = [settlements.get(r["key"], {}).get("estimated_cost_microunits") for r in provider_reservations]

            def valid_billed(value: Any) -> bool:
                return isinstance(value, int) and not isinstance(value, bool) and value >= 0

            def valid_estimate(value: Any) -> bool:
                return isinstance(value, int) and not isinstance(value, bool) and value >= 0

            return {
                "provider_calls_reserved": sum(r.get("provider_calls", 0) for r in reservations),
                "provider_calls_limit": self.limits["max_provider_calls"],
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
                "budget_breaches": list(self.state.get("budget_breaches", [])),
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
        time.sleep(min(0.01, max(0.0, invocation._deadline - time.monotonic())))
    return invocation.result()
