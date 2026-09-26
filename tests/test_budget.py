import subprocess
import sys
import time
from pathlib import Path

import pytest

from pr_review_harness.budget import BudgetExhausted, BudgetLedger, IsolatedCallError, IsolatedInvocation
from pr_review_harness.contracts import ADJUDICATION_V3, SPECIALIST_V4


class SpawnsDescendant:
    def __init__(self, pid_file: str, marker_file: str, ready_file: str, heartbeat_file: str):
        self.pid_file = pid_file
        self.marker_file = marker_file
        self.ready_file = ready_file
        self.heartbeat_file = heartbeat_file

    def __call__(self):
        script = (
            "import pathlib,signal,time; "
            f"signal.signal(signal.SIGTERM,lambda *_:pathlib.Path({self.marker_file!r}).write_text('terminated')); "
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
    marker_file = tmp_path / "child.terminated"
    ready_file = tmp_path / "child.ready"
    heartbeat_file = tmp_path / "child.heartbeat"
    invocation = IsolatedInvocation(
        SpawnsDescendant(str(pid_file), str(marker_file), str(ready_file), str(heartbeat_file)),
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
    assert marker_file.exists(), "descendant process did not receive group cancellation"
    before = heartbeat_file.read_text()
    time.sleep(0.08)
    assert heartbeat_file.read_text() == before, "descendant continued running after cancellation"
