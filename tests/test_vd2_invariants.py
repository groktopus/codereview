"""Deterministically generated invariant and provider-fault tests for VD-2.

The fixed seeds make every generated case reproducible without adding a runtime
or development dependency.  Each property below explores a bounded family of
budgets, keys, outcomes, or reducer states; it is not a statistical claim.
"""

from __future__ import annotations

import copy
import random
import time

import pytest

from pr_review_harness.budget import BudgetExhausted, BudgetLedger
from pr_review_harness.engine import _reduce
from pr_review_harness.reconcile import consolidate_findings

# Keep these constants visible in pytest output and the test report.
PROPERTY_SEEDS = {
    "dispatch_reservation": 25201,
    "settlement_attempt": 25202,
    "budget_ceiling": 25203,
    "ledger_replay": 25204,
    "blocker_reducer": 25205,
}


def _limits(*, calls=100, context=100_000, output=100_000, cost=100_000):
    return {
        "deadline_seconds": 60,
        "max_provider_calls": calls,
        "max_context_bytes": context,
        "max_input_bytes_per_task": context,
        "max_output_bytes_per_task": output,
        "max_output_bytes": output,
        "max_context_retrievals": 100,
        "max_followup_tasks": 100,
        "max_cost_microunits": cost,
    }


def _estimate(rng: random.Random, limits: dict) -> dict:
    return {
        "provider_calls": rng.randint(1, 3),
        "input_bytes": rng.randint(0, limits["max_input_bytes_per_task"]),
        "max_output_bytes": rng.randint(1, limits["max_output_bytes_per_task"]),
        "max_cost_microunits": rng.randint(0, limits["max_cost_microunits"]),
        "reservation_kind": "operator_bound",
    }


def test_generated_dispatch_is_not_prepared_when_reservation_is_unavailable(tmp_path, monkeypatch):
    """Exhausted provider-call budgets cannot yield an invocation to dispatch."""
    from test_review_stages import advance_to_dispatch, make_state

    from pr_review_harness import engine as engine_module
    from pr_review_harness.review_stages import start_attempt_stage

    rng = random.Random(PROPERTY_SEEDS["dispatch_reservation"])
    generated_cases = 0
    for index in range(24):
        state = make_state(tmp_path / str(index))
        advance_to_dispatch(state)
        task = state.tasks[0]
        # Fill the call cap; vary other reservation dimensions reproducibly.
        # The next attempt is denied solely on provider call count.
        state.limits["max_provider_calls"] = 1
        state.budget.limits["max_provider_calls"] = 1
        state.budget.reserve(
            f"occupied-{index}",
            {
                "provider_calls": 1,
                "input_bytes": rng.randint(0, 100),
                "max_output_bytes": rng.randint(1, 1_000),
                "max_cost_microunits": rng.randint(0, 20),
                "reservation_kind": "operator_bound",
            },
        )
        made_invocations = []

        def invocation_factory(*args, **kwargs):
            # A constructor call proves the workflow crossed its admission gate.
            made_invocations.append(True)
            raise AssertionError("budget-exhausted task must not construct an invocation")

        monkeypatch.setattr(engine_module, "IsolatedInvocation", invocation_factory)
        result = start_attempt_stage(state, task, 0)
        assert result["status"] == "SKIPPED"
        assert result["error_code"] == "PROVIDER_CALL_BUDGET_EXHAUSTED"
        assert made_invocations == []
        assert state.budget.state["settlements"] == {}
        generated_cases += 1
    assert generated_cases == 24


def test_generated_settlement_without_a_reserved_attempt_is_rejected():
    rng = random.Random(PROPERTY_SEEDS["settlement_attempt"])
    generated_cases = 0
    for index in range(100):
        state = {"reservations": {}, "settlements": {}}
        budget = BudgetLedger(_limits(), state, deadline_epoch=time.time() + 60)
        key = f"missing-attempt-{index}-{rng.getrandbits(32):08x}"
        with pytest.raises(ValueError, match="settlement without reservation"):
            budget.settle(
                key,
                output_bytes=rng.randint(0, 100_000),
                usage={"billed_cost_microunits": rng.randint(0, 1_000)},
                status="SUCCEEDED",
            )
        assert state["settlements"] == {}
        generated_cases += 1
    assert generated_cases == 100


def test_generated_successful_reservations_never_cross_any_budget_ceiling():
    rng = random.Random(PROPERTY_SEEDS["budget_ceiling"])
    generated_cases = 0
    for run in range(20):
        limits = _limits(
            calls=rng.randint(3, 20),
            context=rng.randint(100, 5_000),
            output=rng.randint(100, 5_000),
            cost=rng.randint(100, 5_000),
        )
        state = {}
        budget = BudgetLedger(limits, state, deadline_epoch=time.time() + 60)
        for index in range(40):
            estimate = _estimate(rng, limits)
            try:
                budget.reserve(f"run-{run}-call-{index}", estimate)
            except BudgetExhausted:
                pass
            reservations = list(state["reservations"].values())
            assert sum(row["provider_calls"] for row in reservations) <= limits["max_provider_calls"]
            assert sum(row["input_bytes"] for row in reservations) <= limits["max_context_bytes"]
            assert sum(row["max_output_bytes"] for row in reservations) <= limits["max_output_bytes"]
            assert sum(row["max_cost_microunits"] or 0 for row in reservations) <= limits["max_cost_microunits"]
            generated_cases += 1
    assert generated_cases == 800


def test_generated_reservation_and_settlement_ledger_replay_is_idempotent():
    rng = random.Random(PROPERTY_SEEDS["ledger_replay"])
    generated_cases = 0
    for index in range(80):
        state = {}
        budget = BudgetLedger(_limits(), state, deadline_epoch=time.time() + 60)
        key = f"replay-{index}"
        estimate = {
            "provider_calls": 1,
            "input_bytes": rng.randint(0, 10_000),
            "max_output_bytes": 10_000,
            "max_cost_microunits": 100,
            "reservation_kind": "operator_bound",
        }
        original_reservation = budget.reserve(key, estimate)
        reservation_state = copy.deepcopy(state)
        assert budget.reserve(key, estimate) == original_reservation
        assert state == reservation_state
        output_bytes = rng.randint(0, 10_000)
        usage = {"billed_cost_microunits": rng.randint(0, 100), "input_tokens": rng.randint(0, 500)}
        budget.settle(key, output_bytes=output_bytes, usage=usage, status="SUCCEEDED")
        after_first_settlement = copy.deepcopy(state)
        budget.settle(key, output_bytes=output_bytes, usage=usage, status="SUCCEEDED")
        assert state == after_first_settlement
        assert state["settlements"][key]["actual_output_bytes"] == output_bytes
        generated_cases += 1
    assert generated_cases == 80


def test_generated_reducer_never_clears_an_accepted_blocker():
    rng = random.Random(PROPERTY_SEEDS["blocker_reducer"])
    blocker = {"finding_id": "known-blocker", "status": "ACCEPTED", "blocking_class": "BLOCKING"}
    generated_cases = 0
    for _ in range(100):
        result = {
            "findings": [blocker],
            "coverage_state": rng.choice(["COMPLETE", "PARTIAL", "NOT_STARTED", "UNKNOWN"]),
            "freshness": rng.choice(["CURRENT", "STALE", "UNKNOWN"]),
            "budget": {"budget_breaches": rng.choice([[], [{"reason": "synthetic"}]])},
        }
        assert _reduce(result, allow_empty_approve=rng.choice([True, False]), policy_valid=rng.choice([True, False])) == "REQUEST_CHANGES"
        consolidated = consolidate_findings([dict(blocker, finding_id=f"blocker-{generated_cases}")])
        assert len(consolidated) == 1
        assert consolidated[0]["status"] == "ACCEPTED"
        assert consolidated[0]["blocking_class"] == "BLOCKING"
        generated_cases += 1
    assert generated_cases == 100


@pytest.mark.parametrize("freshness", ["CURRENT", "STALE", "UNKNOWN", None, "FUTURE_STATE"], ids=["current", "stale", "unknown", "missing", "unrecognized"])
@pytest.mark.parametrize("coverage", ["COMPLETE", "PARTIAL", "UNKNOWN", "FUTURE_STATE"], ids=["complete", "partial", "unknown", "unrecognized"])
def test_stale_or_unknown_evidence_never_reduces_to_approval(freshness, coverage):
    result = {"findings": [], "freshness": freshness, "coverage_state": coverage, "budget": {}}
    # The sole approving pair is explicitly current + complete. Every stale,
    # unknown, absent, or unrecognized input must fail closed.
    if freshness == "CURRENT" and coverage == "COMPLETE":
        assert _reduce(result, allow_empty_approve=True, policy_valid=True) == "APPROVE"
    else:
        assert _reduce(result, allow_empty_approve=True, policy_valid=True) != "APPROVE"
