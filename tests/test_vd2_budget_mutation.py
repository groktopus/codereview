import copy
import hashlib
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

import pr_review_harness.budget as budget_module
from pr_review_harness.budget import (
    BudgetExhausted,
    BudgetLedger,
    IsolatedCallError,
    IsolatedInvocation,
    isolated_call,
    wait_for_any,
)
from pr_review_harness.contracts import ADJUDICATION_V3, SPECIALIST_V4


class SpawnsDescendant:
    def __init__(self, pid_file: str, ready_file: str, heartbeat_file: str):
        self.pid_file = pid_file
        self.ready_file = ready_file
        self.heartbeat_file = heartbeat_file

    def __call__(self):
        script = (
            "import pathlib,signal,time; "
            "signal.signal(signal.SIGTERM,lambda *_:None); "
            f"pathlib.Path({self.ready_file!r}).write_text('ready'); "
            f"p=pathlib.Path({self.heartbeat_file!r}); "
            "exec('while True:\\n n=int(p.read_text())+1 if p.exists() else 1\\n p.write_text(str(n))\\n time.sleep(0.01)')"
        )
        child = subprocess.Popen([sys.executable, "-c", script])
        Path(self.pid_file).write_text(str(child.pid))
        deadline = time.monotonic() + 5
        while not Path(self.ready_file).exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        time.sleep(10)


def _process_state(pid: int) -> str:
    def recheck_liveness() -> str:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return "X"
        except PermissionError:
            return "UNKNOWN"
        return "UNKNOWN"

    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return "X"
    except PermissionError:
        return "UNKNOWN"
    proc_stat = Path(f"/proc/{pid}/stat")
    try:
        raw = proc_stat.read_text(encoding="ascii")
        return raw.rsplit(")", 1)[1].strip().split()[0]
    except OSError:
        pass
    try:
        result = subprocess.run(
            ["ps", "-o", "stat=", "-p", str(pid)],
            capture_output=True,
            check=False,
            text=True,
            timeout=1,
        )
    except (OSError, subprocess.SubprocessError):
        return recheck_liveness()
    if result.returncode != 0 or not result.stdout.strip():
        return recheck_liveness()
    return result.stdout.strip().split()[0][0]


def _hide_process_table_observations(monkeypatch, pid: int) -> None:
    original_read_text = Path.read_text

    def read_text(path, *args, **kwargs):
        if path == Path(f"/proc/{pid}/stat"):
            raise FileNotFoundError(path)
        return original_read_text(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", read_text)
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda command, **kwargs: subprocess.CompletedProcess(command, 1, "", ""),
    )


def test_process_state_rechecks_pid_after_process_table_disappears(monkeypatch):
    pid = 87654321
    _hide_process_table_observations(monkeypatch, pid)
    calls = 0

    def kill_probe(probed_pid, signal_number):
        nonlocal calls
        assert probed_pid == pid
        assert signal_number == 0
        calls += 1
        if calls == 2:
            raise ProcessLookupError

    monkeypatch.setattr(os, "kill", kill_probe)

    assert _process_state(pid) == "X"
    assert calls == 2


def test_process_state_keeps_live_unobservable_pid_unknown(monkeypatch):
    pid = 87654322
    _hide_process_table_observations(monkeypatch, pid)
    calls = 0

    def kill_probe(probed_pid, signal_number):
        nonlocal calls
        assert probed_pid == pid
        assert signal_number == 0
        calls += 1

    monkeypatch.setattr(os, "kill", kill_probe)

    assert _process_state(pid) == "UNKNOWN"
    assert calls == 2


def test_process_state_keeps_permission_limited_recheck_unknown(monkeypatch):
    pid = 87654323
    _hide_process_table_observations(monkeypatch, pid)
    calls = 0

    def kill_probe(probed_pid, signal_number):
        nonlocal calls
        assert probed_pid == pid
        assert signal_number == 0
        calls += 1
        if calls == 2:
            raise PermissionError

    monkeypatch.setattr(os, "kill", kill_probe)

    assert _process_state(pid) == "UNKNOWN"
    assert calls == 2


LIMITS = {
    "deadline_seconds": 10,
    "max_provider_calls": 3,
    "max_context_bytes": 10_000,
    "max_input_bytes_per_task": 5_000,
    "max_output_bytes_per_task": 1_000,
    "max_output_bytes": 2_000,
    "max_context_retrievals": 1,
    "max_followup_tasks": 1,
    "max_cost_microunits": 20,
}


class RaisesProviderMetadata:
    def __init__(self, meta):
        self.meta = meta

    def __call__(self):
        error = RuntimeError("provider call failed")
        error.code = "response_exceeds_limit"
        error.meta = self.meta
        raise error


class ReturnsOversizedProviderResponse:
    def __call__(self):
        return {
            "usage": {"prompt_tokens": 1},
            "provenance": {
                "provider_contract_version": SPECIALIST_V4,
                "elapsed_ms": 10,
            },
            "padding": "x" * 1000,
        }


class ReturnsAfterDelay:
    def __init__(self, delay: float):
        self.delay = delay

    def __call__(self):
        time.sleep(self.delay)
        return {"completed": True}


class ExitsWithoutResponse:
    def __call__(self):
        os._exit(0)


class WaitsForRelease:
    def __init__(self, started_file: str, release_file: str):
        self.started_file = started_file
        self.release_file = release_file

    def __call__(self):
        Path(self.started_file).write_text("started", encoding="ascii")
        deadline = time.monotonic() + 5
        while not Path(self.release_file).exists() and time.monotonic() < deadline:
            time.sleep(0.005)
        return {"slow": True}


def test_isolated_call_waits_for_ready_pipe_without_polling():
    calls = 0
    original_poll = IsolatedInvocation.poll

    def count_poll(invocation):
        nonlocal calls
        calls += 1
        return original_poll(invocation)

    IsolatedInvocation.poll = count_poll
    try:
        result = isolated_call(ReturnsAfterDelay(0.2), "__call__", (), deadline_seconds=2, output_limit=1024)
    finally:
        IsolatedInvocation.poll = original_poll

    assert result == {"completed": True}
    assert calls <= 3


def test_readiness_wakes_on_pipe_eof_when_worker_exits_without_result():
    invocation = IsolatedInvocation(ExitsWithoutResponse(), "__call__", (), deadline_seconds=2, output_limit=1024)
    try:
        assert invocation.wait_for_ready(timeout=2)
        with pytest.raises(IsolatedCallError) as caught:
            invocation.result()
        assert caught.value.remote_type == "WorkerExit"
    finally:
        invocation.cancel()


def test_readiness_timeout_marks_invocation_timed_out():
    invocation = IsolatedInvocation(ReturnsAfterDelay(10), "__call__", (), deadline_seconds=0.1, output_limit=1024)
    try:
        assert not invocation.wait_for_ready(timeout=1)
        with pytest.raises(IsolatedCallError) as caught:
            invocation.result()
        assert caught.value.remote_type == "TimeoutError"
        assert invocation.wait_handles() == ()
    finally:
        invocation.cancel()


def test_cancel_after_readiness_timeout_cleans_child_handles():
    invocation = IsolatedInvocation(ReturnsAfterDelay(10), "__call__", (), deadline_seconds=5, output_limit=1024)
    try:
        assert not invocation.wait_for_ready(timeout=0.02)
        invocation.cancel()
        with pytest.raises(IsolatedCallError) as caught:
            invocation.result()
        assert caught.value.remote_type == "Cancelled"
        assert invocation.wait_handles() == ()
    finally:
        invocation.cancel()


def test_wait_any_returns_the_fast_ready_worker_before_a_blocked_worker(tmp_path):
    started = tmp_path / "slow-started"
    release = tmp_path / "slow-release"
    slow = IsolatedInvocation(
        WaitsForRelease(str(started), str(release)), "__call__", (), deadline_seconds=5, output_limit=1024
    )
    startup_deadline = time.monotonic() + 3
    while not started.exists() and time.monotonic() < startup_deadline:
        time.sleep(0.01)
    fast = None
    try:
        assert started.exists(), "slow worker did not start"
        fast = IsolatedInvocation(ReturnsAfterDelay(0), "__call__", (), deadline_seconds=3, output_limit=1024)
        ready = wait_for_any([slow, fast], timeout=2)
        assert fast in ready
        assert slow not in ready
        assert fast.result() == {"completed": True}

        release.write_text("release", encoding="ascii")
        assert slow.wait_for_ready(timeout=2)
        assert slow.result() == {"slow": True}
    finally:
        release.write_text("release", encoding="ascii")
        slow.cancel()
        if fast is not None:
            fast.cancel()


@pytest.mark.parametrize("timeout", [True, -1, float("nan"), float("inf"), "1"])
def test_readiness_wait_rejects_invalid_timeout(timeout):
    with pytest.raises(ValueError, match="invalid readiness wait timeout"):
        wait_for_any([], timeout=timeout)


def test_finished_invocation_has_no_stale_wait_handles():
    invocation = IsolatedInvocation(ReturnsAfterDelay(0), "__call__", (), deadline_seconds=2, output_limit=1024)
    try:
        assert invocation.wait_for_ready(timeout=2)
        assert invocation.result() == {"completed": True}
        assert invocation.wait_handles() == ()
        assert invocation.wait_for_ready()
        assert wait_for_any([invocation], timeout=1) == []
    finally:
        invocation.cancel()


def _isolated_provider_error(meta):
    invocation = IsolatedInvocation(
        RaisesProviderMetadata(meta), "__call__", (), deadline_seconds=5, output_limit=100_000
    )
    deadline = time.monotonic() + 4
    while not invocation.poll() and time.monotonic() < deadline:
        time.sleep(0.005)
    with pytest.raises(IsolatedCallError) as caught:
        invocation.result()
    return caught.value.meta


def test_unsettled_call_prevents_billing_known_after_another_call_settles():
    state = {}
    budget = BudgetLedger(LIMITS, state, deadline_epoch=time.time() + 10)
    estimate = {
        "provider_calls": 1,
        "input_bytes": 100,
        "max_output_bytes": 500,
        "max_cost_microunits": 10,
        "reservation_kind": "operator_bound",
    }
    budget.reserve("call-1", estimate)
    budget.settle("call-1", output_bytes=12, usage={"billed_cost_microunits": 1}, status="SUCCEEDED")
    budget.reserve("call-2", {**estimate, "input_bytes": 120})

    summary = budget.summary()
    assert summary["cost_billing_known"] is False
    assert summary["cost"] == "UNKNOWN"


def test_context_retrieval_reservation_replay_is_idempotent_at_limit():
    state = {}
    budget = BudgetLedger(LIMITS, state, deadline_epoch=time.time() + 10)
    first = budget.reserve_retrieval("gap-1", 400)
    replay = budget.reserve_retrieval("gap-1", 400)

    assert first == replay
    assert budget.summary()["context_retrievals_reserved"] == 1
    with pytest.raises(BudgetExhausted, match="CONTEXT_RETRIEVAL_BUDGET_EXHAUSTED"):
        budget.reserve_retrieval("gap-2", 100)


def test_context_retrieval_reserves_input_but_not_provider_output_capacity():
    limits = {
        **LIMITS,
        "max_provider_calls": 5,
        "max_context_retrievals": 2,
        "max_context_bytes": 100_000,
        "max_input_bytes_per_task": 32_768,
        "max_output_bytes_per_task": 32_768,
        "max_output_bytes": 163_840,
        "max_cost_microunits": None,
    }
    budget = BudgetLedger(limits, {}, deadline_epoch=time.time() + 10)

    for key in ("gap-1", "gap-2"):
        retrieval = budget.reserve_retrieval(key, 32_768)
        assert retrieval["input_bytes"] == 32_768
        assert retrieval["max_output_bytes"] == 0
    for index in range(5):
        budget.reserve(
            f"specialist-{index}",
            {"provider_calls": 1, "input_bytes": 100, "max_output_bytes": 32_768},
        )

    summary = budget.summary()
    assert summary["context_retrievals_reserved"] == 2
    assert summary["context_bytes_reserved"] == 66_036
    assert summary["output_bytes_reserved"] == 163_840


def test_required_claim_assessment_floor_reserves_existing_calls_without_fake_reservations():
    limits = {**LIMITS, "max_provider_calls": 3}
    state = {}
    budget = BudgetLedger(limits, state, deadline_epoch=time.time() + 10)
    estimate = {
        "provider_calls": 1,
        "input_bytes": 10,
        "max_output_bytes": 100,
        "max_cost_microunits": 0,
        "reservation_kind": "operator_bound",
    }

    budget.reserve("primary", estimate)
    budget.reserve("adjudication-1", estimate, provider_call_floor=1)
    with pytest.raises(BudgetExhausted, match="REQUIRED_CLAIM_ASSESSMENT_CAP_RESERVED"):
        budget.reserve("adjudication-2", estimate, provider_call_floor=1)

    assert set(state["reservations"]) == {"primary", "adjudication-1"}
    budget.reserve("required-claim", estimate)
    assert budget.summary()["provider_calls_reserved"] == 3


def test_required_claim_deadline_floor_rejects_exact_remaining_time():
    budget = BudgetLedger({**LIMITS, "max_cost_microunits": None}, {}, deadline_epoch=time.time() + 20)
    budget.remaining_seconds = lambda: 10.0
    with pytest.raises(BudgetExhausted, match="REQUIRED_CLAIM_ASSESSMENT_DEADLINE_RESERVED"):
        budget.reserve(
            "adjudication",
            {"provider_calls": 1, "input_bytes": 10, "max_output_bytes": 100},
            deadline_floor_seconds=10,
        )
    assert budget.state["reservations"] == {}


def test_required_claim_deadline_floor_allows_dispatch_above_floor():
    budget = BudgetLedger({**LIMITS, "max_cost_microunits": None}, {}, deadline_epoch=time.time() + 20)
    budget.remaining_seconds = lambda: 10.01
    reservation = budget.reserve(
        "adjudication",
        {"provider_calls": 1, "input_bytes": 10, "max_output_bytes": 100},
        deadline_floor_seconds=10,
    )
    assert reservation["provider_calls"] == 1


def test_context_retrieval_settlement_uses_input_cap_while_provider_output_uses_output_cap():
    limits = {**LIMITS, "max_context_retrievals": 2}
    budget = BudgetLedger(limits, {}, deadline_epoch=time.time() + 10)
    budget.reserve_retrieval("gap-ok", 100)
    budget.settle("gap-ok", output_bytes=80, usage={}, status="SUCCEEDED")
    assert budget.summary()["budget_breaches"] == []

    budget.reserve_retrieval("gap-overrun", 100)
    budget.settle("gap-overrun", output_bytes=101, usage={}, status="SUCCEEDED")
    budget.reserve(
        "provider-call",
        {
            "provider_calls": 1,
            "input_bytes": 10,
            "max_output_bytes": 100,
            "reservation_kind": "operator_bound",
            "max_cost_microunits": 10,
        },
    )
    budget.settle("provider-call", output_bytes=101, usage={}, status="SUCCEEDED")

    breaches = budget.summary()["budget_breaches"]
    assert [(row["key"], row["reason"]) for row in breaches] == [
        ("gap-overrun", "CONTEXT_RETRIEVAL_RESERVATION_OVERRUN"),
        ("provider-call", "OUTPUT_RESERVATION_OVERRUN"),
    ]


def test_isolation_preserves_typed_provider_failure_diagnostics():
    metadata = _isolated_provider_error(
        {
            "request_hash": "a" * 64,
            "response_hash": "b" * 64,
            "response_bytes": 32_769,
            "output_truncated": True,
            "elapsed_ms": 12.5,
            "provider_contract_version": SPECIALIST_V4,
            "configured_model_alias": "private-alias",
        }
    )

    assert metadata["request_hash"] == "a" * 64
    assert metadata["response_hash"] == "b" * 64
    assert metadata["response_bytes"] == 32_769
    assert metadata["output_truncated"] is True
    assert metadata["elapsed_ms"] == 12.5
    assert metadata["provider_contract_version"] == SPECIALIST_V4
    assert "configured_model_alias" not in metadata


def test_isolation_flattens_only_allowlisted_nested_provider_provenance():
    metadata = _isolated_provider_error(
        {
            "usage": {"prompt_tokens": 100, "completion_tokens": 4096},
            "provenance": {
                "request_hash": "c" * 64,
                "response_hash": "d" * 64,
                "http_status": 200,
                "elapsed_ms": 20,
                "provider_contract_version": ADJUDICATION_V3,
                "provider_reported_model_id": "untrusted-raw-model-text",
                "response_body": "private-body",
            },
        }
    )

    assert metadata["usage"] == {"prompt_tokens": 100, "completion_tokens": 4096}
    assert metadata["request_hash"] == "c" * 64
    assert metadata["response_hash"] == "d" * 64
    assert metadata["http_status"] == 200
    assert metadata["elapsed_ms"] == 20
    assert metadata["provider_contract_version"] == ADJUDICATION_V3
    assert "provenance" not in metadata
    assert "provider_reported_model_id" not in metadata
    assert "response_body" not in metadata


def test_isolation_discards_malformed_or_unbounded_provider_diagnostics():
    metadata = _isolated_provider_error(
        {
            "request_hash": "not-a-hash",
            "response_hash": "secret=never-copy",
            "response_bytes": 64 * 1024 * 1024 + 2,
            "output_truncated": "false",
            "elapsed_ms": float("nan"),
            "actual_output_bytes": 10**1000,
            "http_status": True,
            "provider_contract_version": "api_key=must-not-escape",
            "raw_response": "secret body",
        }
    )

    assert (
        not {
            "request_hash",
            "response_hash",
            "response_bytes",
            "output_truncated",
            "elapsed_ms",
            "http_status",
            "provider_contract_version",
            "raw_response",
        }
        & metadata.keys()
    )


def test_isolation_retains_bounded_actual_size_above_output_cap():
    invocation = IsolatedInvocation(
        ReturnsOversizedProviderResponse(), "__call__", (), deadline_seconds=5, output_limit=100
    )
    deadline = time.monotonic() + 4
    while not invocation.poll() and time.monotonic() < deadline:
        time.sleep(0.005)
    with pytest.raises(IsolatedCallError) as caught:
        invocation.result()

    assert str(caught.value) == "OUTPUT_BYTE_LIMIT_EXCEEDED"
    assert caught.value.meta["actual_output_bytes"] > 101
    assert caught.value.meta["provider_contract_version"] == SPECIALIST_V4
    assert caught.value.meta["elapsed_ms"] == 10


def test_reservation_replay_ignores_transient_remaining_deadline():
    state = {}
    budget = BudgetLedger({**LIMITS, "max_cost_microunits": None}, state, deadline_epoch=time.time() + 10)
    first = budget.reserve(
        "task:review:0",
        {"provider_calls": 1, "input_bytes": 100, "max_output_bytes": 100, "deadline_seconds": 9},
    )
    replay = budget.reserve(
        "task:review:0",
        {"provider_calls": 1, "input_bytes": 100, "max_output_bytes": 100, "deadline_seconds": 2},
    )
    assert replay == first
    assert replay["deadline_seconds"] == 9


def test_money_cap_requires_operator_bound_and_not_price_estimate():
    budget = BudgetLedger(LIMITS, {}, deadline_epoch=time.time() + 10)
    with pytest.raises(BudgetExhausted, match="MONETARY_BOUND_UNAVAILABLE"):
        budget.reserve(
            "priced-only",
            {"input_bytes": 1, "max_output_bytes": 1, "max_cost_microunits": 10, "reservation_kind": "price_estimate"},
        )


def test_provider_billing_overrun_is_detected_against_reservation_and_run_cap():
    limits = {**LIMITS, "max_cost_microunits": 25}
    budget = BudgetLedger(limits, {}, deadline_epoch=time.time() + 10)
    for key in ("call-1", "call-2"):
        budget.reserve(
            key,
            {
                "provider_calls": 1,
                "input_bytes": 10,
                "max_output_bytes": 100,
                "max_cost_microunits": 10,
                "reservation_kind": "operator_bound",
            },
        )
    budget.settle("call-1", output_bytes=5, usage={"billed_cost_microunits": 13}, status="SUCCEEDED")
    budget.settle("call-2", output_bytes=5, usage={"billed_cost_microunits": 13}, status="SUCCEEDED")
    breaches = budget.summary()["budget_breaches"]
    assert any(row["reason"] == "MONETARY_RESERVATION_OVERRUN" for row in breaches)
    assert any(row["reason"] == "MONETARY_RUN_BUDGET_OVERRUN" for row in breaches)


def test_deadline_cancellation_terminates_adapter_descendant_process_group(tmp_path):
    pid_file = tmp_path / "child.pid"
    ready_file = tmp_path / "child.ready"
    heartbeat_file = tmp_path / "child.heartbeat"
    invocation = IsolatedInvocation(
        SpawnsDescendant(str(pid_file), str(ready_file), str(heartbeat_file)),
        "__call__",
        (),
        deadline_seconds=1.5,
        output_limit=1024,
    )
    deadline = time.monotonic() + 3
    while not invocation.poll() and time.monotonic() < deadline:
        time.sleep(0.005)
    with pytest.raises(IsolatedCallError):
        invocation.result()
    assert ready_file.exists(), "descendant never reached its ready state"
    child_pid = int(pid_file.read_text())
    process_deadline = time.monotonic() + 1
    while _process_state(child_pid) not in {"Z", "X"} and time.monotonic() < process_deadline:
        time.sleep(0.01)
    assert _process_state(child_pid) in {"Z", "X"}, "descendant remained alive after process-group cancellation"
    before = heartbeat_file.read_text()
    time.sleep(0.08)
    assert heartbeat_file.read_text() == before, "descendant continued running after cancellation"


# ---------------------------------------------------------------------------
# Focused deterministic unit tests for budget.py internals and arithmetic.
# Everything below is pure in-process work (no network, no wall-clock waits
# except the spawn-isolation tests above), so mutant verdicts are stable.

from pr_review_harness.budget import (  # noqa: E402 - appended focus tests preserve the original module imports
    _attempt_family,
    _bounded_wait_timeout,
    _canonical,
    _digest,
    _nonnegative_int,
    _positive_int,
    _provider_observability,
    _safe_elapsed,
    _safe_local_http_exchange,
    _safe_provider_metadata,
    _safe_settlement_observation,
    _stage_for_reservation,
    _usage_state,
)

_HEX_A = "a" * 64
_HEX_B = "b" * 64
_HEX_C = "c" * 64


def _base_exchange(**overrides):
    record = {
        "contract_version": "local-http-exchange.v1",
        "state": "HTTP_RESPONSE_RECEIVED",
        "delivery_observation": "UNKNOWN",
        "request_serialized": True,
        "request_attempted": True,
        "request_sha256": _HEX_A,
        "endpoint_sha256": _HEX_B,
        "request_bytes": 10,
        "http_status": 200,
        "response_sha256": _HEX_C,
        "response_bytes": 5,
        "response_complete": True,
        "elapsed_ms": 12,
        "provider_id": "provider",
        "model_id": "model",
        "unapproved": "drop-me",
    }
    record.update(overrides)
    return record


def test_safe_local_http_exchange_accepts_full_http_response():
    assert _safe_local_http_exchange(_base_exchange()) == {
        "contract_version": "local-http-exchange.v1",
        "state": "HTTP_RESPONSE_RECEIVED",
        "delivery_observation": "UNKNOWN",
        "request_serialized": True,
        "request_attempted": True,
        "request_sha256": _HEX_A,
        "endpoint_sha256": _HEX_B,
        "request_bytes": 10,
        "provider_id": "provider",
        "model_id": "model",
        "http_status": 200,
        "response_sha256": _HEX_C,
        "response_bytes": 5,
        "response_complete": True,
        "elapsed_ms": 12,
    }


def test_safe_local_http_exchange_minimal_serialized_record():
    record = {
        "contract_version": "local-http-exchange.v1",
        "state": "REQUEST_SERIALIZED",
        "delivery_observation": "UNKNOWN",
        "request_serialized": True,
        "request_attempted": False,
        "request_sha256": _HEX_A,
        "endpoint_sha256": None,
        "request_bytes": 0,
    }
    assert _safe_local_http_exchange(record) == {
        "contract_version": "local-http-exchange.v1",
        "state": "REQUEST_SERIALIZED",
        "delivery_observation": "UNKNOWN",
        "request_serialized": True,
        "request_attempted": False,
        "request_sha256": _HEX_A,
        "request_bytes": 0,
    }


@pytest.mark.parametrize(
    "overrides",
    [
        {"state": "REQUEST_ATTEMPTED"},
        {"state": "TRANSPORT_FAILURE"},
        {"state": "UNKNOWN"},
        {"state": "HTTP_ERROR_RESPONSE", "http_status": 500},
        {"state": "HTTP_RESPONSE_RECEIVED", "elapsed_ms": 1.5},
        {"state": "HTTP_RESPONSE_RECEIVED", "provider_id": "p", "model_id": "m"},
    ],
)
def test_safe_local_http_exchange_valid_state_shapes(overrides):
    state = overrides["state"]
    record = _base_exchange(**overrides)
    if state in {"REQUEST_ATTEMPTED", "TRANSPORT_FAILURE", "UNKNOWN"}:
        for field in ("http_status", "response_sha256", "response_bytes", "response_complete"):
            record.pop(field, None)
    if state == "REQUEST_ATTEMPTED":
        record["request_attempted"] = True
    if state == "UNKNOWN":
        record["request_attempted"] = False
    if state == "HTTP_ERROR_RESPONSE":
        record["request_attempted"] = True
    safe = _safe_local_http_exchange(record)
    assert safe is not None
    assert safe["state"] == state
    assert safe["request_serialized"] is True
    assert "unapproved" not in safe


@pytest.mark.parametrize(
    "record",
    [
        None,
        [],
        {},
        {"contract_version": "local-http-exchange.v2"},
        {"contract_version": "local-http-exchange.v1"},
        _base_exchange(delivery_observation="SENT"),
        _base_exchange(request_serialized=False),
        _base_exchange(request_serialized=1),
        _base_exchange(request_attempted=1),
        _base_exchange(request_attempted=None),
        _base_exchange(request_sha256="a" * 63),
        _base_exchange(request_sha256="A" * 64),
        _base_exchange(request_sha256=None),
        _base_exchange(endpoint_sha256="g" * 64),
        _base_exchange(endpoint_sha256=None),
        _base_exchange(request_bytes=-1),
        _base_exchange(request_bytes=True),
        _base_exchange(request_bytes=1.0),
        _base_exchange(request_bytes=64 * 1024 * 1024 + 2),
        _base_exchange(state="REQUEST_SERIALIZED", request_attempted=True, endpoint_sha256=None),
        _base_exchange(state="REQUEST_SERIALIZED", request_attempted=False, endpoint_sha256=None, http_status=None),
        _base_exchange(state="REQUEST_ATTEMPTED", request_attempted=False),
        _base_exchange(state="TRANSPORT_FAILURE", request_attempted=False),
        _base_exchange(state="TRANSPORT_FAILURE", http_status=500),
        _base_exchange(state="REQUEST_ATTEMPTED", response_bytes=1),
        _base_exchange(state="UNKNOWN", request_attempted=False, response_complete=True),
        _base_exchange(state="HTTP_RESPONSE_RECEIVED", request_attempted=False),
        _base_exchange(state="HTTP_RESPONSE_RECEIVED", http_status=True),
        _base_exchange(state="HTTP_RESPONSE_RECEIVED", http_status=99),
        _base_exchange(state="HTTP_RESPONSE_RECEIVED", http_status=600),
        _base_exchange(state="HTTP_RESPONSE_RECEIVED", http_status=None),
        _base_exchange(state="HTTP_RESPONSE_RECEIVED", response_sha256=None),
        _base_exchange(state="HTTP_RESPONSE_RECEIVED", response_bytes=None),
        _base_exchange(state="HTTP_RESPONSE_RECEIVED", response_sha256=None, response_bytes=None),
        _base_exchange(response_sha256="not-a-hash"),
        _base_exchange(response_bytes=-1),
        _base_exchange(response_bytes=True),
        _base_exchange(response_complete="yes"),
        _base_exchange(response_complete=None),
        _base_exchange(state="HTTP_ERROR_RESPONSE", http_status=600),
    ],
)
def test_safe_local_http_exchange_rejects_invalid_shapes(record):
    assert _safe_local_http_exchange(record) is None


def test_safe_local_http_exchange_drops_invalid_optional_identifiers_and_elapsed():
    safe = _safe_local_http_exchange(
        _base_exchange(
            provider_id="",
            model_id="x" * 257,
            elapsed_ms=float("nan"),
            state="REQUEST_SERIALIZED",
            request_attempted=False,
            endpoint_sha256=None,
            http_status=None,
            response_sha256=None,
            response_bytes=None,
            response_complete=None,
        )
    )
    assert safe is not None
    assert "provider_id" not in safe
    assert "model_id" not in safe
    assert "elapsed_ms" not in safe


def test_safe_local_http_exchange_ignores_negative_and_oversized_elapsed():
    for elapsed in (-1, float("inf"), 24 * 60 * 60 * 1000 + 1, True, "12"):
        safe = _safe_local_http_exchange(
            _base_exchange(
                elapsed_ms=elapsed,
                state="REQUEST_SERIALIZED",
                request_attempted=False,
                endpoint_sha256=None,
                http_status=None,
                response_sha256=None,
                response_bytes=None,
                response_complete=None,
            )
        )
        assert safe is not None
        assert "elapsed_ms" not in safe


def _base_metadata():
    return {
        "request_id": "request-1",
        "elapsed_seconds": 1.5,
        "usage": {"prompt_tokens": 3},
        "actual_output_bytes": 11,
        "raw_payload": "never-copy",
        "configured_model_alias": "private-alias",
        "provenance": {
            "request_hash": _HEX_A,
            "response_hash": _HEX_B,
            "http_status": 201,
            "response_bytes": 7,
            "output_truncated": True,
            "elapsed_ms": 2.5,
            "provider_contract_version": SPECIALIST_V4,
            "provider_reported_model_id": "untrusted",
            "response_body": "private",
        },
    }


def test_safe_provider_metadata_flattens_only_allowlisted_fields():
    assert _safe_provider_metadata(_base_metadata(), 100) == {
        "request_id": "request-1",
        "elapsed_seconds": 1.5,
        "usage": {"prompt_tokens": 3},
        "actual_output_bytes": 11,
        "request_hash": _HEX_A,
        "response_hash": _HEX_B,
        "http_status": 201,
        "response_bytes": 7,
        "output_truncated": True,
        "elapsed_ms": 2.5,
        "provider_contract_version": SPECIALIST_V4,
    }


def test_safe_provider_metadata_includes_safe_local_exchange_from_either_source():
    exchange = _base_exchange()
    meta = {
        "local_http_exchange": exchange,
        "provenance": {"local_http_exchange": exchange, "request_hash": _HEX_A},
    }
    safe = _safe_provider_metadata(meta, 100)
    assert safe["local_http_exchange"]["state"] == "HTTP_RESPONSE_RECEIVED"
    assert safe["request_hash"] == _HEX_A


def test_safe_provider_metadata_keeps_only_first_valid_hash_and_later_valid_overwrites():
    meta = {
        "request_hash": "invalid",
        "response_hash": "invalid",
        "provenance": {"request_hash": _HEX_A, "response_hash": _HEX_C},
    }
    safe = _safe_provider_metadata(meta, 100)
    assert safe == {"request_hash": _HEX_A, "response_hash": _HEX_C}


def test_safe_provider_metadata_drops_unbounded_and_malformed_diagnostics():
    meta = {
        "request_id": "r",
        "actual_output_bytes": 64 * 1024 * 1024 + 2,
        "provenance": {
            "request_hash": "invalid",
            "response_hash": _HEX_A,
            "http_status": True,
            "response_bytes": 64 * 1024 * 1024 + 2,
            "output_truncated": "true",
            "elapsed_ms": float("inf"),
            "provider_contract_version": "unknown-contract",
            "local_http_exchange": {"contract_version": "local-http-exchange.v1"},
        },
    }
    assert _safe_provider_metadata(meta, 100) == {"request_id": "r", "response_hash": _HEX_A}


def test_safe_provider_metadata_accepts_bounded_int_elapsed_and_float_elapsed():
    int_safe = _safe_provider_metadata({"provenance": {"elapsed_ms": 12}}, 1)
    float_safe = _safe_provider_metadata({"provenance": {"elapsed_ms": 12.5}}, 1)
    assert int_safe["elapsed_ms"] == 12
    assert float_safe["elapsed_ms"] == 12.5


def test_safe_provider_metadata_drops_negative_and_bool_observations():
    safe = _safe_provider_metadata(
        {
            "actual_output_bytes": True,
            "provenance": {
                "http_status": 200,
                "response_bytes": -1,
                "output_truncated": 1,
                "elapsed_ms": -3,
            },
        },
        1,
    )
    assert safe == {"http_status": 200}


def test_canonical_and_digest_are_stable_utf8_json():
    assert _canonical({"b": 1, "a": ["é", 2]}) == '{"a":["é",2],"b":1}'.encode()
    assert _canonical([True, None, 1.5]) == b"[true,null,1.5]"
    assert _canonical({"z": "é"}) == '{"z":"é"}'.encode()
    assert _digest({"a": 1, "b": 2}) == hashlib.sha256(b'{"a":1,"b":2}').hexdigest()


@pytest.mark.parametrize(
    "usage,known,expected",
    [
        (None, None, "UNKNOWN"),
        ([], None, "UNKNOWN"),
        ({}, None, "UNKNOWN"),
        ({"prompt_tokens": 1}, None, "PARTIAL"),
        ({"total_tokens": 5}, None, "PARTIAL"),
        ({"prompt_tokens": 1, "completion_tokens": 2, "total_tokens": 3}, None, "PARTIAL"),
        ({"prompt_tokens": 1, "completion_tokens": 2, "total_tokens": 3}, True, "KNOWN"),
        ({"prompt_tokens": 1, "completion_tokens": 2, "total_tokens": 3}, False, "PARTIAL"),
        ({"prompt_tokens": 1, "completion_tokens": 2, "total_tokens": 3}, 1, "PARTIAL"),
        ({"prompt_tokens": True, "completion_tokens": 2, "total_tokens": 3}, True, "PARTIAL"),
        ({"prompt_tokens": -1, "completion_tokens": 2, "total_tokens": 3}, True, "PARTIAL"),
        ({"prompt_tokens": 1, "completion_tokens": 2, "total_tokens": 3, "input_tokens": -1}, True, "KNOWN"),
    ],
)
def test_usage_state_classification(usage, known, expected):
    assert _usage_state(usage, known) == expected


@pytest.mark.parametrize(
    "value,expected",
    [
        (0, 0.0),
        (1, 1.0),
        (1.239, 1.24),
        (1.0001, 1.0),
        (True, None),
        (None, None),
        ("1", None),
        (float("nan"), None),
        (float("inf"), None),
        (-0.5, None),
    ],
)
def test_safe_elapsed_normalizes_scalars(value, expected):
    assert _safe_elapsed(value) == expected


def test_safe_elapsed_handles_overflowing_integer():
    assert _safe_elapsed(10**400) is None


def test_safe_settlement_observation_keeps_only_bounded_scalars():
    assert _safe_settlement_observation(
        {
            "stage": "primary",
            "request_attempted": True,
            "http_status": 200,
            "call_elapsed_ms": 1.239,
            "http_elapsed_ms": float("nan"),
            "prompt_tokens": 3,
            "completion_tokens": -1,
            "input_tokens": 4,
            "output_tokens": "5",
            "total_tokens": 7,
            "usage_known": True,
            "raw_payload": {"secret": True},
        }
    ) == {
        "stage": "primary",
        "request_attempted": True,
        "http_status": 200,
        "call_elapsed_ms": 1.24,
        "http_elapsed_ms": None,
        "usage": {
            "prompt_tokens": 3,
            "completion_tokens": None,
            "input_tokens": 4,
            "output_tokens": None,
            "total_tokens": 7,
        },
        "usage_state": "PARTIAL",
    }


def test_safe_settlement_observation_defaults_and_sanitizes_fields():
    assert _safe_settlement_observation(None) is None
    assert _safe_settlement_observation([]) is None
    assert _safe_settlement_observation({"stage": "unrecognized", "request_attempted": "yes", "http_status": 99}) == {
        "stage": "other",
        "request_attempted": None,
        "http_status": None,
        "call_elapsed_ms": None,
        "http_elapsed_ms": None,
        "usage": {
            "prompt_tokens": None,
            "completion_tokens": None,
            "input_tokens": None,
            "output_tokens": None,
            "total_tokens": None,
        },
        "usage_state": "UNKNOWN",
    }


def test_safe_settlement_observation_marks_usage_known_only_with_full_counters():
    observation = _safe_settlement_observation(
        {
            "stage": "followup",
            "prompt_tokens": 1,
            "completion_tokens": 2,
            "total_tokens": 3,
            "usage_known": True,
        }
    )
    assert observation["usage_state"] == "KNOWN"
    assert observation["stage"] == "followup"


@pytest.mark.parametrize(
    "reservation,expected",
    [
        ({"kind": "context_retrieval", "key": "x"}, "context_retrieval"),
        ({"kind": "deterministic_check", "key": "x"}, "deterministic_check"),
        ({"kind": "provider", "key": "task:review:1"}, "primary"),
        ({"kind": "provider", "key": "task:review:1:followup:2"}, "followup"),
        ({"kind": "provider", "key": "run:adjudicate:1"}, "semantic_adjudication"),
        ({"kind": "provider", "key": "claim-assessment:run"}, "claim_assessment"),
        ({"kind": "provider", "key": "system-one:advisory:run"}, "advisory"),
        ({"kind": "provider", "key": "unrelated"}, "other"),
        ({"kind": "provider"}, "other"),
        ({"kind": "provider", "key": 7}, "other"),
    ],
)
def test_stage_for_reservation_mapping(reservation, expected):
    assert _stage_for_reservation(reservation) == expected


@pytest.mark.parametrize(
    "key,expected",
    [
        (7, "unknown"),
        (None, "unknown"),
        ("task:review:2", "task:review"),
        ("task:review:abc", "task:review:abc"),
        ("task:review", "task:review"),
        ("task:attempt:3", "task:attempt"),
        ("task:attempt:abc", "task:attempt:abc"),
        ("system-one:advisory:9", "system-one:advisory"),
        ("system-one:advisory:abc", "system-one:advisory:abc"),
        ("plain", "plain"),
        ("plain:2", "plain:2"),
    ],
)
def test_attempt_family_groups_numeric_attempts_only(key, expected):
    assert _attempt_family(key) == expected


@pytest.mark.parametrize("value", [True, 0, -1, 1.0, "1", None])
def test_positive_int_rejects_non_positive_and_non_integer(value):
    with pytest.raises(ValueError, match="invalid reservation"):
        _positive_int(value, "count")


@pytest.mark.parametrize("value", [1, 7])
def test_positive_int_accepts_positive_ints(value):
    assert _positive_int(value, "count") == value


@pytest.mark.parametrize("value", [True, -1, 1.0, "1", None])
def test_nonnegative_int_rejects_invalid_values(value):
    with pytest.raises(ValueError, match="invalid reservation"):
        _nonnegative_int(value, "count")


@pytest.mark.parametrize("value", [0, 1, 7])
def test_nonnegative_int_accepts_nonnegative_ints(value):
    assert _nonnegative_int(value, "count") == value


def test_isolated_call_error_keeps_remote_identity_and_meta():
    error = budget_module.IsolatedCallError("TimeoutError", "DEADLINE_EXCEEDED")
    assert error.remote_type == "TimeoutError"
    assert str(error) == "DEADLINE_EXCEEDED"
    assert error.meta == {}
    with_meta = budget_module.IsolatedCallError("TypeError", "bad", {"request_id": "r"})
    assert with_meta.meta == {"request_id": "r"}


def test_bounded_wait_timeout_normalizes_and_rejects_invalid_values():
    assert _bounded_wait_timeout(None) is None
    assert _bounded_wait_timeout(0) == 0.0
    assert _bounded_wait_timeout(1) == 1.0
    for invalid in (True, -1, float("nan"), float("inf"), "1", None if False else object()):
        with pytest.raises(ValueError, match="invalid readiness wait timeout"):
            _bounded_wait_timeout(invalid)


# ---------------------------------------------------------------------------
# BudgetLedger arithmetic, reservation, settlement, ceilings and replay.


def _ledger(*, limits=None, state=None, persist=None):
    ledger_state = {} if state is None else state
    budget = BudgetLedger(limits or dict(LIMITS), ledger_state, persist=persist, deadline_epoch=time.time() + 60)
    return budget, ledger_state


def _estimate(**overrides):
    estimate = {
        "provider_calls": 1,
        "input_bytes": 10,
        "max_output_bytes": 100,
        "max_cost_microunits": 1,
        "reservation_kind": "operator_bound",
    }
    estimate.update(overrides)
    return estimate


def test_ledger_init_seeds_sections_and_default_persist():
    state = {"reservations": {"existing": {"key": "existing"}}}
    budget = BudgetLedger(dict(LIMITS), state)
    assert state["reservations"] == {"existing": {"key": "existing"}}
    assert state["settlements"] == {}
    assert state["context_retrievals"] == 0
    assert state["followup_tasks"] == 0
    assert budget.deadline_epoch is None
    assert budget.remaining_seconds() == 0.0
    budget._persist()


def test_remaining_seconds_is_transient_and_clamped(monkeypatch):
    monkeypatch.setattr(budget_module.time, "monotonic", lambda: 100.0)
    monkeypatch.setattr(budget_module.time, "time", lambda: 90.0)
    budget = BudgetLedger(dict(LIMITS), {}, deadline_epoch=110.0)
    assert budget._deadline_monotonic == 120.0
    assert budget.remaining_seconds() == 20.0

    monkeypatch.setattr(budget_module.time, "monotonic", lambda: 125.0)
    assert budget.remaining_seconds() == 0.0


def test_reserve_applies_defaults_and_exact_record_shape():
    budget, state = _ledger(limits={**LIMITS, "max_cost_microunits": None})
    reservation = budget.reserve("task-1", {"deadline_seconds": 5})
    assert reservation == {
        "key": "task-1",
        "kind": "provider",
        "provider_calls": 1,
        "input_bytes": 0,
        "max_output_bytes": LIMITS["max_output_bytes_per_task"],
        "max_cost_microunits": None,
        "reservation_kind": "unknown",
        "deadline_seconds": 5.0,
        "estimate_hash": _digest({}),
        "status": "RESERVED",
    }
    assert state["reservations"]["task-1"] is reservation


def test_reserve_default_deadline_uses_remaining_seconds():
    budget, _ = _ledger(limits={**LIMITS, "max_cost_microunits": None})
    reservation = budget.reserve("task-1", {})
    assert 0 < reservation["deadline_seconds"] <= 60


@pytest.mark.parametrize(
    "key,estimate",
    [
        ("", {}),
        (None, {}),
        (7, {}),
        ("key", None),
        ("key", []),
        ("key", "not-a-dict"),
    ],
)
def test_reserve_rejects_missing_key_or_estimate(key, estimate):
    budget, state = _ledger()
    with pytest.raises(ValueError, match="reservation key and estimate are required"):
        budget.reserve(key, estimate)
    assert state["reservations"] == {}


@pytest.mark.parametrize("floor", [True, -1, 1.0, "1", None])
def test_reserve_rejects_invalid_provider_call_floor(floor):
    budget, _ = _ledger()
    with pytest.raises(ValueError, match="provider_call_floor must be a nonnegative integer"):
        budget.reserve("key", {}, provider_call_floor=floor)


@pytest.mark.parametrize("floor", [True, -1, float("nan"), float("inf"), "1", None])
def test_reserve_rejects_invalid_deadline_floor(floor):
    budget, _ = _ledger()
    with pytest.raises(ValueError, match="deadline_floor_seconds must be a finite nonnegative number"):
        budget.reserve("key", {}, deadline_floor_seconds=floor)


@pytest.mark.parametrize(
    "estimate",
    [
        {"provider_calls": True},
        {"provider_calls": -1},
        {"provider_calls": 1.0},
        {"input_bytes": True},
        {"input_bytes": -1},
        {"max_output_bytes": -1},
        {"max_cost_microunits": True},
        {"max_cost_microunits": -1},
        {"deadline_seconds": 0},
        {"deadline_seconds": -1},
        {"deadline_seconds": float("nan")},
        {"deadline_seconds": float("inf")},
    ],
)
def test_reserve_rejects_invalid_estimates_without_mutating_state(estimate):
    budget, state = _ledger(limits={**LIMITS, "max_cost_microunits": None})
    with pytest.raises(ValueError):
        budget.reserve("key", estimate)
    assert state["reservations"] == {}
    assert state.get("budget_breaches") is None


def test_reserve_replay_is_idempotent_even_when_deadline_moves():
    persisted = []
    budget, state = _ledger(limits={**LIMITS, "max_cost_microunits": None}, persist=lambda: persisted.append(1))
    estimate = {"provider_calls": 1, "input_bytes": 10, "max_output_bytes": 100, "deadline_seconds": 9}
    first = budget.reserve("key", estimate)
    snapshot = copy.deepcopy(state)
    replay = budget.reserve("key", {**estimate, "deadline_seconds": 2})
    assert replay == first
    assert state == snapshot
    assert persisted == [1]


def test_reserve_key_reuse_with_changed_estimate_is_rejected():
    budget, state = _ledger()
    budget.reserve("key", _estimate(input_bytes=10))
    with pytest.raises(ValueError, match="reservation key reused with different estimate"):
        budget.reserve("key", _estimate(input_bytes=11))
    assert len(state["reservations"]) == 1


def test_reserve_deadline_exhaustion_is_explicit():
    budget, state = _ledger()
    budget.remaining_seconds = lambda: 0.0
    with pytest.raises(BudgetExhausted, match="DEADLINE_EXHAUSTED"):
        budget.reserve("key", _estimate(deadline_seconds=5))
    assert state["reservations"] == {}


def test_reserve_deadline_floor_reserves_required_claim_time():
    budget, _ = _ledger(limits={**LIMITS, "max_cost_microunits": None})
    budget.remaining_seconds = lambda: 10.0
    with pytest.raises(BudgetExhausted, match="REQUIRED_CLAIM_ASSESSMENT_DEADLINE_RESERVED"):
        budget.reserve("exact", {"deadline_seconds": 9}, deadline_floor_seconds=10)
    with pytest.raises(BudgetExhausted, match="REQUIRED_CLAIM_ASSESSMENT_DEADLINE_RESERVED"):
        budget.reserve("above", {"deadline_seconds": 9}, deadline_floor_seconds=10.01)

    clamped = budget.reserve("clamped", {"deadline_seconds": 9}, deadline_floor_seconds=4)
    assert clamped["deadline_seconds"] == 6.0
    short = budget.reserve("short", {"deadline_seconds": 2}, deadline_floor_seconds=4)
    assert short["deadline_seconds"] == 2.0


def test_reserve_provider_call_ceiling_is_inclusive_at_the_limit():
    budget, state = _ledger(limits={**LIMITS, "max_provider_calls": 2, "max_cost_microunits": None})
    budget.reserve("a", _estimate(provider_calls=1))
    budget.reserve("b", _estimate(provider_calls=1))
    with pytest.raises(BudgetExhausted, match="PROVIDER_CALL_BUDGET_EXHAUSTED"):
        budget.reserve("c", _estimate(provider_calls=1))
    assert set(state["reservations"]) == {"a", "b"}


def test_reserve_provider_call_floor_protects_required_claim_capacity():
    budget, _ = _ledger(limits={**LIMITS, "max_provider_calls": 3, "max_cost_microunits": None})
    budget.reserve("primary", _estimate(provider_calls=1))
    budget.reserve("adjudication", _estimate(provider_calls=1), provider_call_floor=1)
    with pytest.raises(BudgetExhausted, match="REQUIRED_CLAIM_ASSESSMENT_CAP_RESERVED"):
        budget.reserve("blocked", _estimate(provider_calls=1), provider_call_floor=2)


def test_reserve_context_byte_ceiling_counts_all_reservations():
    budget, _ = _ledger(
        limits={**LIMITS, "max_context_bytes": 100, "max_input_bytes_per_task": 100, "max_cost_microunits": None}
    )
    budget.reserve("a", _estimate(input_bytes=60, max_output_bytes=0))
    with pytest.raises(BudgetExhausted, match="CONTEXT_BYTE_BUDGET_EXHAUSTED"):
        budget.reserve("b", _estimate(input_bytes=41, max_output_bytes=0))
    assert budget.reserve("b", _estimate(input_bytes=40, max_output_bytes=0))["input_bytes"] == 40


def test_reserve_per_task_input_ceiling_is_independent_of_run_ceiling():
    budget, _ = _ledger(
        limits={
            **LIMITS,
            "max_context_bytes": 10_000,
            "max_input_bytes_per_task": 50,
            "max_cost_microunits": None,
        }
    )
    with pytest.raises(BudgetExhausted, match="INPUT_BYTE_LIMIT_EXCEEDED"):
        budget.reserve("a", _estimate(input_bytes=51))
    assert budget.reserve("a", _estimate(input_bytes=50))["input_bytes"] == 50


def test_reserve_per_task_output_ceiling_is_enforced():
    budget, _ = _ledger(
        limits={
            **LIMITS,
            "max_output_bytes_per_task": 50,
            "max_output_bytes": 10_000,
            "max_cost_microunits": None,
        }
    )
    with pytest.raises(BudgetExhausted, match="OUTPUT_BYTE_LIMIT_EXCEEDED"):
        budget.reserve("a", _estimate(max_output_bytes=51))
    assert budget.reserve("a", _estimate(max_output_bytes=50))["max_output_bytes"] == 50


def test_reserve_run_output_ceiling_counts_all_reservations():
    budget, _ = _ledger(
        limits={
            **LIMITS,
            "max_output_bytes_per_task": 100,
            "max_output_bytes": 100,
            "max_cost_microunits": None,
        }
    )
    budget.reserve("a", _estimate(max_output_bytes=60))
    with pytest.raises(BudgetExhausted, match="OUTPUT_BYTE_BUDGET_EXHAUSTED"):
        budget.reserve("b", _estimate(max_output_bytes=41))
    assert budget.reserve("b", _estimate(max_output_bytes=40))["max_output_bytes"] == 40


def test_reserve_monetary_ceiling_requires_an_authoritative_bound():
    budget, _ = _ledger(limits={**LIMITS, "max_cost_microunits": 10})
    with pytest.raises(BudgetExhausted, match="MONETARY_BOUND_UNAVAILABLE"):
        budget.reserve("missing", _estimate(max_cost_microunits=None))
    with pytest.raises(BudgetExhausted, match="MONETARY_BOUND_UNAVAILABLE"):
        budget.reserve("estimate", _estimate(reservation_kind="price_estimate"))
    assert budget.reserve("operator", _estimate(reservation_kind="operator_bound"))["max_cost_microunits"] == 1
    assert budget.reserve("table", _estimate(reservation_kind="price_table_bound"))["max_cost_microunits"] == 1


def test_reserve_monetary_ceiling_is_inclusive_at_the_limit():
    budget, state = _ledger(limits={**LIMITS, "max_cost_microunits": 10})
    budget.reserve("a", _estimate(max_cost_microunits=10))
    with pytest.raises(BudgetExhausted, match="MONETARY_BUDGET_EXHAUSTED"):
        budget.reserve("b", _estimate(max_cost_microunits=1))
    assert set(state["reservations"]) == {"a"}


def test_reserve_without_monetary_cap_allows_unknown_and_zero_cost():
    budget, _ = _ledger(limits={**LIMITS, "max_cost_microunits": None})
    assert budget.reserve("unknown", _estimate(max_cost_microunits=None))["max_cost_microunits"] is None
    assert budget.reserve("zero", _estimate(max_cost_microunits=0))["max_cost_microunits"] == 0


def test_reserve_persists_only_successful_new_reservations():
    persisted = []
    budget, _ = _ledger(persist=lambda: persisted.append(1))
    budget.reserve("a", _estimate())
    budget.reserve("a", _estimate())
    with pytest.raises(BudgetExhausted):
        budget.reserve("b", _estimate(provider_calls=3))
    assert persisted == [1]


def test_reserve_retrieval_reserves_bytes_and_counts_once():
    persisted = []
    budget, state = _ledger(limits={**LIMITS, "max_context_retrievals": 1}, persist=lambda: persisted.append(1))
    first = budget.reserve_retrieval("gap-1", 400)
    assert first["kind"] == "context_retrieval"
    assert first["provider_calls"] == 0
    assert first["input_bytes"] == 400
    assert first["max_output_bytes"] == 0
    assert first["max_cost_microunits"] == 0
    assert first["reservation_kind"] == "operator_bound"
    assert first["retrieval_counted"] is True
    assert state["context_retrievals"] == 1
    persisted_after_first = list(persisted)

    assert budget.reserve_retrieval("gap-1", 400) == first
    assert state["context_retrievals"] == 1
    assert persisted == persisted_after_first
    with pytest.raises(ValueError, match="retrieval reservation key reused with different estimate"):
        budget.reserve_retrieval("gap-1", 401)
    with pytest.raises(BudgetExhausted, match="CONTEXT_RETRIEVAL_BUDGET_EXHAUSTED"):
        budget.reserve_retrieval("gap-2", 100)


def test_reserve_retrieval_rejects_a_provider_reservation_with_the_same_key():
    budget, _ = _ledger()
    budget.reserve("gap", _estimate())
    with pytest.raises(ValueError, match="retrieval reservation key reused with different estimate"):
        budget.reserve_retrieval("gap", 10)


def test_reserve_retrieval_replay_after_settlement_does_not_double_count():
    budget, state = _ledger(limits={**LIMITS, "max_context_retrievals": 1})
    record = budget.reserve_retrieval("gap", 100)
    budget.settle("gap", output_bytes=10, usage={}, status="SUCCEEDED")
    assert budget.reserve_retrieval("gap", 100) == record
    assert state["context_retrievals"] == 1


def test_reserve_followup_is_sorted_idempotent_and_bounded():
    persisted = []
    budget, state = _ledger(limits={**LIMITS, "max_followup_tasks": 2}, persist=lambda: persisted.append(1))
    budget.reserve_followup("b")
    budget.reserve_followup("a")
    budget.reserve_followup("a")
    assert state["followup_task_keys"] == ["a", "b"]
    assert state["followup_tasks"] == 2
    assert persisted == [1, 1]
    with pytest.raises(BudgetExhausted, match="FOLLOWUP_TASK_BUDGET_EXHAUSTED"):
        budget.reserve_followup("c")
    assert state["followup_task_keys"] == ["a", "b"]


def test_settle_requires_a_reservation():
    budget, state = _ledger()
    with pytest.raises(ValueError, match="settlement without reservation"):
        budget.settle("missing", output_bytes=1, usage={}, status="SUCCEEDED")
    assert state["settlements"] == {}


def test_settle_records_actuals_and_marks_reservation_settled():
    persisted = []
    budget, state = _ledger(limits={**LIMITS, "max_cost_microunits": None}, persist=lambda: persisted.append(1))
    budget.reserve("call", _estimate())
    budget.settle(
        "call",
        output_bytes=12,
        usage={"billed_cost_microunits": 5, "estimated_cost_microunits": 6, "prompt_tokens": 2},
        status="SUCCEEDED",
    )
    settlement = state["settlements"]["call"]
    assert settlement["status"] == "SUCCEEDED"
    assert settlement["actual_output_bytes"] == 12
    assert settlement["usage"] == {
        "billed_cost_microunits": 5,
        "estimated_cost_microunits": 6,
        "prompt_tokens": 2,
    }
    assert settlement["billed_cost_microunits"] == 5
    assert settlement["estimated_cost_microunits"] == 6
    assert isinstance(settlement["settled_at_epoch"], float)
    assert "observation" not in settlement
    assert state["reservations"]["call"]["status"] == "SETTLED"
    assert persisted == [1, 1]


def test_settle_normalizes_missing_usage_and_output():
    budget, state = _ledger(limits={**LIMITS, "max_cost_microunits": None})
    budget.reserve("call", _estimate())
    budget.settle("call", output_bytes=None, usage=None, status="FAILED")
    settlement = state["settlements"]["call"]
    assert settlement["usage"] == {}
    assert settlement["billed_cost_microunits"] is None
    assert settlement["estimated_cost_microunits"] is None
    assert settlement["actual_output_bytes"] is None
    assert state.get("budget_breaches") is None


def test_settle_replay_is_idempotent_and_conflicts_fail_closed():
    budget, state = _ledger(limits={**LIMITS, "max_cost_microunits": None})
    budget.reserve("call", _estimate())
    budget.settle("call", output_bytes=12, usage={"billed_cost_microunits": 5}, status="SUCCEEDED")
    snapshot = copy.deepcopy(state)
    budget.settle("call", output_bytes=12, usage={"billed_cost_microunits": 5}, status="SUCCEEDED")
    assert state == snapshot

    for changed in (
        {"output_bytes": 13, "usage": {"billed_cost_microunits": 5}, "status": "SUCCEEDED"},
        {"output_bytes": 12, "usage": {"billed_cost_microunits": 6}, "status": "SUCCEEDED"},
        {"output_bytes": 12, "usage": {"billed_cost_microunits": 5}, "status": "FAILED"},
    ):
        with pytest.raises(ValueError, match="conflicting settlement replay"):
            budget.settle("call", **changed)
    assert state == snapshot


def test_settle_accepts_observation_on_legacy_checkpoint_but_does_not_rewrite_it():
    budget, state = _ledger(limits={**LIMITS, "max_cost_microunits": None})
    budget.reserve("call", _estimate())
    legacy = {
        "status": "SUCCEEDED",
        "actual_output_bytes": 12,
        "usage": {"billed_cost_microunits": 5},
        "billed_cost_microunits": 5,
        "estimated_cost_microunits": None,
        "settled_at_epoch": 1.0,
    }
    state["settlements"]["call"] = dict(legacy)
    budget.settle(
        "call",
        output_bytes=12,
        usage={"billed_cost_microunits": 5},
        status="SUCCEEDED",
        observation={"stage": "primary"},
    )
    assert state["settlements"]["call"] == legacy


def test_settle_observation_replay_allows_omission_after_a_recorded_observation():
    budget, state = _ledger(limits={**LIMITS, "max_cost_microunits": None})
    budget.reserve("call", _estimate())
    budget.settle(
        "call",
        output_bytes=12,
        usage={"billed_cost_microunits": 5},
        status="SUCCEEDED",
        observation={"stage": "primary"},
    )
    snapshot = copy.deepcopy(state)
    budget.settle("call", output_bytes=12, usage={"billed_cost_microunits": 5}, status="SUCCEEDED")
    assert state == snapshot
    with pytest.raises(ValueError, match="conflicting settlement replay"):
        budget.settle(
            "call",
            output_bytes=12,
            usage={"billed_cost_microunits": 5},
            status="SUCCEEDED",
            observation={"stage": "followup"},
        )


def test_settle_retrieval_overrun_is_recorded_only_above_the_input_cap():
    budget, state = _ledger(limits={**LIMITS, "max_context_retrievals": 3})
    budget.reserve_retrieval("equal", 100)
    budget.settle("equal", output_bytes=100, usage={}, status="SUCCEEDED")
    assert state.get("budget_breaches") is None

    budget.reserve_retrieval("over", 100)
    budget.settle("over", output_bytes=101, usage={}, status="SUCCEEDED")
    breaches = state["budget_breaches"]
    assert breaches == [
        {"key": "over", "reason": "CONTEXT_RETRIEVAL_RESERVATION_OVERRUN", "actual": 101, "reserved": 100}
    ]


def test_settle_provider_output_overrun_is_recorded_only_above_the_reservation():
    budget, state = _ledger(limits={**LIMITS, "max_cost_microunits": None})
    budget.reserve("equal", _estimate(max_output_bytes=100))
    budget.settle("equal", output_bytes=100, usage={}, status="SUCCEEDED")
    assert state.get("budget_breaches") is None

    budget.reserve("over", _estimate(max_output_bytes=100))
    budget.settle("over", output_bytes=101, usage={}, status="SUCCEEDED")
    assert state["budget_breaches"] == [
        {"key": "over", "reason": "OUTPUT_RESERVATION_OVERRUN", "actual": 101, "reserved": 100}
    ]


def test_settle_monetary_overrun_requires_a_strictly_greater_non_bool_integer():
    budget, state = _ledger(limits={**LIMITS, "max_cost_microunits": 100})
    budget.reserve("equal", _estimate(max_cost_microunits=20))
    budget.settle("equal", output_bytes=1, usage={"billed_cost_microunits": 20}, status="SUCCEEDED")
    assert state.get("budget_breaches") is None

    budget.reserve("over", _estimate(max_cost_microunits=20))
    budget.settle("over", output_bytes=1, usage={"billed_cost_microunits": 21}, status="SUCCEEDED")
    assert state["budget_breaches"] == [
        {"key": "over", "reason": "MONETARY_RESERVATION_OVERRUN", "actual": 21, "reserved": 20}
    ]

    budget.reserve("bool", _estimate(max_cost_microunits=20))
    budget.settle("bool", output_bytes=1, usage={"billed_cost_microunits": True}, status="SUCCEEDED")
    assert len(state["budget_breaches"]) == 1


def test_settle_run_budget_overrun_counts_only_known_nonnegative_billing():
    budget, state = _ledger(limits={**LIMITS, "max_cost_microunits": 10})
    budget.reserve("a", _estimate(max_cost_microunits=5))
    budget.reserve("b", _estimate(max_cost_microunits=5))
    budget.settle("a", output_bytes=1, usage={"billed_cost_microunits": 6}, status="SUCCEEDED")
    budget.settle("b", output_bytes=1, usage={"billed_cost_microunits": 5}, status="SUCCEEDED")
    assert state["budget_breaches"] == [
        {"key": "a", "reason": "MONETARY_RESERVATION_OVERRUN", "actual": 6, "reserved": 5},
        {"key": "b", "reason": "MONETARY_RUN_BUDGET_OVERRUN", "actual": 5, "limit": 10},
    ]


def test_settle_run_budget_overrun_ignores_bool_and_negative_prior_values():
    budget, state = _ledger(limits={**LIMITS, "max_cost_microunits": 10})
    # A negative prior settlement is not a known nonnegative cost. If it were
    # counted, 11 - 100 would hide the overrun below.
    state["settlements"]["negative"] = {"billed_cost_microunits": -100}
    state["reservations"]["call"] = {
        "key": "call",
        "kind": "provider",
        "provider_calls": 1,
        "input_bytes": 0,
        "max_output_bytes": 100,
        "max_cost_microunits": 20,
        "reservation_kind": "operator_bound",
        "status": "RESERVED",
    }
    budget.settle("call", output_bytes=1, usage={"billed_cost_microunits": 11}, status="SUCCEEDED")
    assert state["budget_breaches"] == [
        {"key": "call", "reason": "MONETARY_RUN_BUDGET_OVERRUN", "actual": 11, "limit": 10}
    ]

    budget, state = _ledger(limits={**LIMITS, "max_cost_microunits": 10})
    # A boolean prior is likewise not a known cost; counting it as 1 would
    # turn this exactly-at-limit settlement into a false overrun.
    state["settlements"]["boolean"] = {"billed_cost_microunits": True}
    state["reservations"]["call"] = {
        "key": "call",
        "kind": "provider",
        "provider_calls": 1,
        "input_bytes": 0,
        "max_output_bytes": 100,
        "max_cost_microunits": 10,
        "reservation_kind": "operator_bound",
        "status": "RESERVED",
    }
    budget.settle("call", output_bytes=1, usage={"billed_cost_microunits": 10}, status="SUCCEEDED")
    assert state.get("budget_breaches") is None


def test_settlement_replay_does_not_duplicate_breaches():
    budget, state = _ledger(limits={**LIMITS, "max_cost_microunits": None})
    budget.reserve("over", _estimate(max_output_bytes=100))
    budget.settle("over", output_bytes=500, usage={}, status="SUCCEEDED")
    snapshot = copy.deepcopy(state)
    budget.settle("over", output_bytes=500, usage={}, status="SUCCEEDED")
    assert state == snapshot
    assert len(state["budget_breaches"]) == 1


def test_summary_empty_ledger_is_exact():
    budget, _ = _ledger()
    assert budget.summary() == {
        "provider_calls_reserved": 0,
        "provider_calls_limit": 3,
        "local_check_reservations": 0,
        "local_check_input_bytes_reserved": 0,
        "local_check_output_bytes_reserved": 0,
        "context_bytes_reserved": 0,
        "context_bytes_limit": 10_000,
        "output_bytes_reserved": 0,
        "output_bytes_limit": 2_000,
        "context_retrievals_reserved": 0,
        "context_retrievals_limit": 1,
        "followup_tasks_reserved": 0,
        "followup_tasks_limit": 1,
        "cost_reserved_microunits": 0,
        "cost_limit_microunits": 20,
        "cost_billed_microunits": 0,
        "cost_billing_known": False,
        "cost_estimated_microunits": 0,
        "cost_estimate_known": False,
        "cost": "UNKNOWN",
        "provider_observability": {
            "provider_calls_reserved": 0,
            "tool_calls_reserved": 0,
            "retry_calls": 0,
            "stages": {},
        },
        "budget_breaches": [],
    }


def test_summary_tracks_local_checks_and_context_retrievals():
    budget, state = _ledger(limits={**LIMITS, "max_context_retrievals": 3, "max_cost_microunits": None})
    budget.reserve(
        "check",
        {"provider_calls": 0, "input_bytes": 7, "max_output_bytes": 0},
        kind="deterministic_check",
    )
    budget.reserve_retrieval("gap", 400)
    budget.reserve_followup("follow")
    summary = budget.summary()
    assert summary["local_check_reservations"] == 1
    assert summary["local_check_input_bytes_reserved"] == 7
    assert summary["local_check_output_bytes_reserved"] == 0
    assert summary["context_bytes_reserved"] == 407
    assert summary["output_bytes_reserved"] == 0
    assert summary["context_retrievals_reserved"] == 1
    assert summary["followup_tasks_reserved"] == 1


def test_summary_cost_known_flags_require_every_provider_settlement():
    budget, state = _ledger(limits={**LIMITS, "max_cost_microunits": 20})
    budget.reserve("a", _estimate(max_cost_microunits=10))
    budget.reserve("b", _estimate(max_cost_microunits=10))
    budget.settle("a", output_bytes=1, usage={"billed_cost_microunits": 4, "estimated_cost_microunits": 5}, status="OK")
    summary = budget.summary()
    assert summary["cost_reserved_microunits"] == 20
    assert summary["cost_billed_microunits"] == 4
    assert summary["cost_billing_known"] is False
    assert summary["cost_estimated_microunits"] == 5
    assert summary["cost_estimate_known"] is False
    assert summary["cost"] == "UNKNOWN"

    budget.settle("b", output_bytes=1, usage={"billed_cost_microunits": 6, "estimated_cost_microunits": 7}, status="OK")
    summary = budget.summary()
    assert summary["cost_billed_microunits"] == 10
    assert summary["cost_billing_known"] is True
    assert summary["cost_estimated_microunits"] == 12
    assert summary["cost_estimate_known"] is True
    assert summary["cost"] == 10


def test_summary_rejects_bool_and_negative_billing_from_known_totals():
    budget, _ = _ledger(limits={**LIMITS, "max_cost_microunits": 20})
    budget.reserve("a", _estimate(max_cost_microunits=10))
    budget.settle(
        "a",
        output_bytes=1,
        usage={"billed_cost_microunits": True, "estimated_cost_microunits": -1},
        status="OK",
    )
    summary = budget.summary()
    assert summary["cost_billed_microunits"] == 0
    assert summary["cost_billing_known"] is False
    assert summary["cost_estimated_microunits"] == 0
    assert summary["cost_estimate_known"] is False
    assert summary["cost"] == "UNKNOWN"


def test_summary_returns_a_copy_of_breaches():
    budget, state = _ledger()
    state["budget_breaches"] = [{"reason": "X"}]
    summary = budget.summary()
    summary["budget_breaches"].append({"reason": "Y"})
    assert state["budget_breaches"] == [{"reason": "X"}]


# ---------------------------------------------------------------------------
# Provider observability reduction: stages, attempt families, usage, elapsed.


def _observation_row(**overrides):
    row = {
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
        "usage_fields": {
            field: {"reported_count": 0, "reported_sum": 0}
            for field in ("prompt_tokens", "completion_tokens", "input_tokens", "output_tokens", "total_tokens")
        },
    }
    row.update(overrides)
    return row


def _usage_fields(**counts):
    fields = {
        field: {"reported_count": 0, "reported_sum": 0}
        for field in ("prompt_tokens", "completion_tokens", "input_tokens", "output_tokens", "total_tokens")
    }
    for field, (count, total) in counts.items():
        fields[field] = {"reported_count": count, "reported_sum": total}
    return fields


def _reservation(key, calls=1, kind="provider"):
    return {
        "key": key,
        "kind": kind,
        "provider_calls": calls,
        "input_bytes": 0,
        "max_output_bytes": 0,
        "max_cost_microunits": 0,
        "reservation_kind": "operator_bound",
        "status": "RESERVED",
    }


def test_provider_observability_reduces_stages_families_usage_and_costs():
    reservations = [
        _reservation("task:review:1"),
        _reservation("task:review:2"),
        _reservation("gap", calls=0, kind="context_retrieval"),
        _reservation("check", calls=0, kind="deterministic_check"),
        _reservation("claim-assessment:1"),
        _reservation(123),
        "not-a-reservation",
    ]
    settlements = {
        "task:review:1": {
            "observation": {
                "stage": "primary",
                "request_attempted": True,
                "call_elapsed_ms": 1.236,
                "http_elapsed_ms": 2.5,
                "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
                "usage_state": "KNOWN",
            },
            "usage": {},
            "billed_cost_microunits": 4,
            "estimated_cost_microunits": 5,
        },
        "task:review:2": {
            "observation": {
                "stage": "primary",
                "request_attempted": False,
                "usage": {},
                "usage_state": "UNKNOWN",
            },
            "usage": {},
        },
        "claim-assessment:1": {
            "usage": {"prompt_tokens": 10, "completion_tokens": 2, "total_tokens": 12, "known": True},
            "billed_cost_microunits": 3,
            "estimated_cost_microunits": 40,
        },
    }
    result = _provider_observability(reservations, settlements)
    assert result == {
        "provider_calls_reserved": 4,
        "tool_calls_reserved": 2,
        "retry_calls": 1,
        "stages": {
            "primary": _observation_row(
                provider_calls_reserved=2,
                retry_calls=1,
                settled_calls=2,
                settled_reservations=2,
                request_attempted=1,
                request_not_attempted=1,
                call_elapsed_ms_sum=1.24,
                call_elapsed_known=1,
                http_elapsed_ms_sum=2.5,
                http_elapsed_known=1,
                usage_known=1,
                usage_unknown=1,
                billed_cost_known=1,
                billed_cost_microunits=4,
                estimated_cost_known=1,
                estimated_cost_microunits=5,
                usage_fields=_usage_fields(prompt_tokens=(1, 10), completion_tokens=(1, 5), total_tokens=(1, 15)),
            ),
            "context_retrieval": _observation_row(tool_calls_reserved=1),
            "deterministic_check": _observation_row(tool_calls_reserved=1),
            "claim_assessment": _observation_row(
                provider_calls_reserved=1,
                retry_calls=0,
                settled_calls=1,
                settled_reservations=1,
                request_attempt_unknown=1,
                usage_known=1,
                billed_cost_known=1,
                billed_cost_microunits=3,
                estimated_cost_known=1,
                estimated_cost_microunits=40,
                usage_fields=_usage_fields(prompt_tokens=(1, 10), completion_tokens=(1, 2), total_tokens=(1, 12)),
            ),
            "other": _observation_row(
                provider_calls_reserved=1,
                request_attempt_unknown=1,
                usage_unknown=1,
            ),
        },
    }


def test_provider_observability_observation_stage_overrides_and_invalid_falls_back():
    reservations = [
        _reservation("task:review:1"),
        _reservation("task:review:2"),
        _reservation("task:review:3"),
        _reservation("task:review:4"),
    ]
    settlements = {
        "task:review:1": {
            "observation": {"stage": "followup", "usage": {"prompt_tokens": 5}, "usage_state": "PARTIAL"},
            "usage": {},
        },
        "task:review:2": {
            "observation": {"stage": "bogus", "usage": {"prompt_tokens": 7, "known": True}},
            "usage": {},
        },
        "task:review:3": {"observation": "not-a-dict", "usage": {"prompt_tokens": 9}},
        "task:review:4": {
            "observation": {"usage_state": "BOGUS", "usage": {}},
            "usage": {},
        },
    }
    result = _provider_observability(reservations, settlements)
    followup = result["stages"]["followup"]
    assert followup["provider_calls_reserved"] == 1
    assert followup["settled_calls"] == 1
    assert followup["settled_reservations"] == 1
    assert followup["usage_partial"] == 1
    assert followup["usage_fields"]["prompt_tokens"] == {"reported_count": 1, "reported_sum": 5}

    primary = result["stages"]["primary"]
    assert primary["provider_calls_reserved"] == 3
    assert primary["settled_calls"] == 3
    assert primary["settled_reservations"] == 3
    assert primary["usage_partial"] == 1
    assert primary["usage_unknown"] == 2
    assert primary["usage_fields"]["prompt_tokens"] == {"reported_count": 1, "reported_sum": 9}
    assert primary["retry_calls"] == 2
    assert result["retry_calls"] == 2


def test_provider_observability_rounds_elapsed_sums_and_ignores_invalid_values():
    reservations = [_reservation("task:review:1"), _reservation("task:review:2")]
    settlements = {
        "task:review:1": {
            "observation": {
                "stage": "primary",
                "call_elapsed_ms": 1.234,
                "http_elapsed_ms": 0.005,
                "request_attempted": True,
                "usage_state": "UNKNOWN",
                "usage": {},
            }
        },
        "task:review:2": {
            "observation": {
                "stage": "primary",
                "call_elapsed_ms": 2.345,
                "http_elapsed_ms": "invalid",
                "usage_state": "UNKNOWN",
                "usage": {},
            }
        },
    }
    primary = _provider_observability(reservations, settlements)["stages"]["primary"]
    assert primary["call_elapsed_ms_sum"] == 3.58
    assert primary["call_elapsed_known"] == 2
    assert primary["http_elapsed_ms_sum"] == 0.01
    assert primary["http_elapsed_known"] == 1


@pytest.mark.parametrize("invalid_calls", [True, -1, 1.5, "2", None])
def test_provider_observability_ignores_invalid_provider_call_counts(invalid_calls):
    reservation = _reservation("task:review:1")
    reservation["provider_calls"] = invalid_calls
    result = _provider_observability([reservation], {})
    assert result == {
        "provider_calls_reserved": 0,
        "tool_calls_reserved": 0,
        "retry_calls": 0,
        "stages": {
            "primary": _observation_row(),
        },
    }


def test_provider_observability_counts_zero_call_settled_tools():
    reservations = [_reservation("check", calls=0, kind="deterministic_check")]
    settlements = {"check": {"usage": {}, "observation": {"stage": "deterministic_check"}}}
    result = _provider_observability(reservations, settlements)
    assert result["stages"]["deterministic_check"] == _observation_row(
        tool_calls_reserved=1,
        settled_reservations=1,
        request_attempt_unknown=0,
    )
    assert result["tool_calls_reserved"] == 1


def test_provider_observability_uses_settlement_usage_when_observation_has_no_usage_state():
    reservation = _reservation("task:review:1")
    settlements = {
        "task:review:1": {
            "observation": {"stage": "primary", "request_attempted": True},
            "usage": {
                "prompt_tokens": 4,
                "completion_tokens": 1,
                "total_tokens": 5,
                "known": True,
            },
            "billed_cost_microunits": 2,
            "estimated_cost_microunits": 3,
        }
    }
    row = _provider_observability([reservation], settlements)["stages"]["primary"]
    assert row["usage_known"] == 1
    assert row["usage_fields"]["prompt_tokens"] == {"reported_count": 1, "reported_sum": 4}
    assert row["billed_cost_known"] == 1
    assert row["billed_cost_microunits"] == 2
    assert row["estimated_cost_known"] == 1
    assert row["estimated_cost_microunits"] == 3
