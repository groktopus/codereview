import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

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


def test_budget_summary_aggregates_observed_usage_without_inferencing_dispatch_or_billing():
    limits = {**LIMITS, "max_provider_calls": 3, "max_cost_microunits": None}
    state = {}
    budget = BudgetLedger(limits, state, deadline_epoch=time.time() + 10)
    reservation = {
        "provider_calls": 1,
        "input_bytes": 100,
        "max_output_bytes": 500,
        "reservation_kind": "price_estimate",
        "estimated_cost_microunits": 10,
    }
    for key in ("observed", "pretransport", "unknown"):
        budget.reserve(key, reservation if key != "unknown" else {**reservation, "estimated_cost_microunits": None})
    base_exchange = {
        "contract_version": "local-http-exchange.v1",
        "delivery_observation": "UNKNOWN",
        "request_serialized": True,
        "request_sha256": "a" * 64,
        "endpoint_sha256": "b" * 64,
        "request_bytes": 1,
    }
    budget.settle(
        "observed",
        output_bytes=12,
        usage={"prompt_tokens": 10, "completion_tokens": 4, "total_tokens": 14},
        status="SUCCEEDED",
        provenance={
            "elapsed_ms": 12.5,
            "estimated_cost_usd": 0.0003,
            "billed_cost_usd": None,
            "billed_cost_known": False,
            "local_http_exchange": {
                **base_exchange,
                "state": "HTTP_RESPONSE_RECEIVED",
                "request_attempted": True,
                "http_status": 200,
                "response_sha256": "c" * 64,
                "response_bytes": 1,
                "response_complete": True,
            },
            "prompt": "must not be retained",
        },
    )
    budget.settle(
        "pretransport",
        output_bytes=None,
        usage={},
        status="FAILED",
        provenance={
            "local_http_exchange": {
                **base_exchange,
                "state": "REQUEST_SERIALIZED",
                "request_attempted": False,
            }
        },
    )
    budget.settle("unknown", output_bytes=None, usage={"input_tokens": 9}, status="INTERRUPTED_UNKNOWN")

    summary = budget.summary()
    observed = summary["provider_observability"]
    assert observed["provider_calls_reserved"] == 3
    assert observed["http_attempts_observed"] == 1
    assert observed["http_attempts_not_observed"] == 1
    assert observed["dispatch_state_unknown"] == 1
    assert observed["input_tokens_observed"] == 19
    assert observed["output_tokens_observed"] == 4
    assert observed["input_token_calls_known"] == 2
    assert observed["output_token_calls_known"] == 1
    assert observed["token_usage_calls_known"] == 1
    assert observed["token_usage_calls_unknown"] == 2
    assert observed["token_usage_complete"] is False
    assert observed["request_latency_observations"] == 1
    assert observed["request_latency_ms_total"] == 12.5
    assert observed["estimated_cost_usd_observed"] == 0.0003
    assert observed["estimated_cost_complete"] is False
    assert observed["billed_cost_usd"] == "UNKNOWN"
    assert observed["billed_cost_complete"] is False
    assert summary["cost_price_estimate_microunits_reserved"] == 20
    assert summary["cost_price_estimate_calls_known"] == 2
    assert summary["cost_price_estimate_complete"] is False
    assert "prompt" not in state["settlements"]["observed"]["observation"]


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
