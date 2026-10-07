import json
import os
import time
from pathlib import Path

import pytest
from test_engine import LIMITS, EmptyProvider, make_snapshot, profile

from pr_review_harness import engine as engine_module
from pr_review_harness.budget import BudgetLedger
from pr_review_harness.engine import run_review
from pr_review_harness.planner import plan_review


def _limits():
    return {**LIMITS, "max_provider_calls": 4}


def test_budget_summary_reports_stage_denominators_and_legacy_settlement_replay():
    reservations = {
        "unit:review:0": {"key": "unit:review:0", "kind": "provider", "provider_calls": 1},
        "unit:review:1": {"key": "unit:review:1", "kind": "provider", "provider_calls": 1},
        "system-one:advisory:0": {"key": "system-one:advisory:0", "kind": "provider", "provider_calls": 1},
        "retrieval:test": {"key": "retrieval:test", "kind": "context_retrieval", "provider_calls": 0},
    }
    old_settlement = {
        "status": "SUCCEEDED",
        "actual_output_bytes": 20,
        "usage": {"input_tokens": 10, "estimated_cost_microunits": 5},
        "billed_cost_microunits": None,
        "estimated_cost_microunits": 5,
    }
    state = {
        "reservations": reservations,
        "settlements": {"unit:review:0": old_settlement},
        "context_retrievals": 1,
        "followup_tasks": 0,
    }
    budget = BudgetLedger(_limits(), state)

    # A new caller can replay a legacy settlement with the optional field;
    # the old checkpoint remains unchanged and its missing receipt is unknown.
    budget.settle(
        "unit:review:0",
        output_bytes=20,
        usage={"input_tokens": 10, "estimated_cost_microunits": 5},
        status="SUCCEEDED",
        observation={"stage": "primary", "request_attempted": True},
    )
    budget.settle(
        "unit:review:1",
        output_bytes=30,
        usage={
            "known": True,
            "prompt_tokens": 9,
            "completion_tokens": 4,
            "total_tokens": 13,
            "estimated_cost_microunits": 11,
        },
        status="SUCCEEDED",
        observation={
            "stage": "primary",
            "request_attempted": True,
            "http_status": 200,
            "call_elapsed_ms": 10.5,
            "http_elapsed_ms": 8.0,
            "usage_known": True,
            "prompt_tokens": 9,
            "completion_tokens": 4,
            "total_tokens": 13,
            "estimated_cost_microunits": 11,
            "raw_response": "must not persist",
        },
    )
    budget.settle(
        "system-one:advisory:0",
        output_bytes=30,
        usage={"known": False},
        status="SUCCEEDED",
        observation={"stage": "advisory", "call_elapsed_ms": 4.0},
    )

    summary = budget.summary()
    obs = summary["provider_observability"]
    assert obs["provider_calls_reserved"] == 3
    assert obs["retry_calls"] == 1
    assert obs["tool_calls_reserved"] == 1
    primary = obs["stages"]["primary"]
    assert primary["request_attempted"] == 1
    assert primary["request_attempt_unknown"] == 1
    assert primary["usage_known"] == 1
    assert primary["usage_partial"] == 1
    assert primary["usage_fields"]["prompt_tokens"] == {"reported_count": 1, "reported_sum": 9}
    assert primary["estimated_cost_microunits"] == 16
    assert primary["estimated_cost_known"] == 2
    assert primary["billed_cost_known"] == 0
    assert obs["stages"]["advisory"]["request_attempt_unknown"] == 1
    assert obs["stages"]["advisory"]["usage_unknown"] == 1
    assert "raw_response" not in state["settlements"]["unit:review:1"]["observation"]
    assert "estimated_cost_microunits" not in state["settlements"]["unit:review:1"]["observation"]
    assert summary["cost"] == "UNKNOWN"
    assert summary["cost_estimate_known"] is False


def test_conflicting_observation_replay_is_rejected():
    state = {
        "reservations": {"system-one:advisory:0": {"key": "system-one:advisory:0", "provider_calls": 1}},
        "settlements": {},
    }
    budget = BudgetLedger(_limits(), state)
    budget.settle(
        "system-one:advisory:0",
        output_bytes=5,
        usage={},
        status="SUCCEEDED",
        observation={"stage": "advisory", "request_attempted": True},
    )
    with pytest.raises(ValueError, match="conflicting settlement replay"):
        budget.settle(
            "system-one:advisory:0",
            output_bytes=5,
            usage={},
            status="SUCCEEDED",
            observation={"stage": "advisory", "request_attempted": False},
        )


def test_primary_and_followup_have_separate_retry_denominators():
    reservations = {
        "parent:review:0": {"key": "parent:review:0", "kind": "provider", "provider_calls": 1},
        "parent:followup:0:review:0": {
            "key": "parent:followup:0:review:0",
            "kind": "provider",
            "provider_calls": 1,
        },
        "parent:followup:0:review:1": {
            "key": "parent:followup:0:review:1",
            "kind": "provider",
            "provider_calls": 1,
        },
    }
    state = {
        "reservations": reservations,
        "settlements": {
            key: {
                "status": "SUCCEEDED",
                "usage": {
                    "known": True,
                    "prompt_tokens": 2,
                    "completion_tokens": 1,
                    "total_tokens": 3,
                },
                "observation": {
                    "stage": "followup" if ":followup:" in key else "primary",
                    "usage": {
                        "prompt_tokens": 2,
                        "completion_tokens": 1,
                        "total_tokens": 3,
                    },
                    "usage_state": "KNOWN",
                },
            }
            for key in reservations
        },
    }
    summary = BudgetLedger(_limits(), state).summary()["provider_observability"]
    assert summary["stages"]["primary"]["provider_calls_reserved"] == 1
    assert summary["stages"]["primary"]["retry_calls"] == 0
    assert summary["stages"]["followup"]["provider_calls_reserved"] == 2
    assert summary["stages"]["followup"]["retry_calls"] == 1
    assert summary["retry_calls"] == 1


def test_usage_known_requires_valid_provider_token_tuple_and_elapsed_is_sanitized():
    reservations = {
        key: {"key": key, "kind": "provider", "provider_calls": 1}
        for key in ("known-empty:review:0", "known-malformed:review:0", "partial:review:0")
    }
    settlements = {
        "known-empty:review:0": {
            "usage": {"known": True},
            "observation": {
                "stage": "primary",
                "usage_state": "KNOWN",
                "usage": {},
                "call_elapsed_ms": float("inf"),
                "http_elapsed_ms": 10**1000,
            },
        },
        "known-malformed:review:0": {
            "usage": {"known": True, "prompt_tokens": True, "completion_tokens": -1, "total_tokens": True},
        },
        "partial:review:0": {"usage": {"prompt_tokens": 3}},
    }
    summary = BudgetLedger(_limits(), {"reservations": reservations, "settlements": settlements}).summary()
    row = summary["provider_observability"]["stages"]["primary"]
    assert row["usage_known"] == 0
    assert row["usage_partial"] == 1
    assert row["usage_unknown"] == 2
    assert row["call_elapsed_known"] == 0


class _ObservedProvider(EmptyProvider):
    identity = {"kind": "observability-fixture", "model": "fixed"}

    def __init__(self, receipt):
        super().__init__()
        self.receipt = receipt

    def review(self, task, evidence, limits):
        self.calls += 1
        _record_fake_call("specialist")
        refs = list(task["evidence_ids"])
        provenance = {"provider": "local-deterministic-fixture"}
        if self.receipt:
            provenance["local_http_exchange"] = {
                "request_attempted": True,
                "http_status": 200,
                "elapsed_ms": 2.0,
            }
        return {
            "payload": {
                "finding_candidates": [],
                "context_gap_proposals": [],
                "coverage_notes": [
                    {
                        "unit_id": unit_id,
                        "state": "COVERED",
                        "reason_code": "REVIEWED",
                        "evidence_refs": refs,
                        "coverage_basis": "STATIC_REVIEW",
                    }
                    for unit_id in task["unit_ids"]
                ],
                "specific_strengths": [],
                "future_guidance": [],
            },
            "usage": {"known": True, "input_tokens": 12, "output_tokens": 3},
            "provenance": provenance,
        }


class _ObservedDecisionProvider:
    identity = {"kind": "native-fixture", "model": "fixed-choice"}

    def __init__(self, receipt, delay_seconds=0):
        self.receipt = receipt
        self.delay_seconds = delay_seconds

    def assess(self, question, text, limits):
        if self.delay_seconds:
            time.sleep(self.delay_seconds)
        _record_fake_call("advisory")
        provenance = {"provider": "native-fixture"}
        if self.receipt:
            provenance["local_http_exchange"] = {"request_attempted": True, "http_status": 200, "elapsed_ms": 1.0}
        return {"payload": {"recommendation": "UNRESOLVED"}, "usage": {"known": False}, "provenance": provenance}


def _record_fake_call(stage):
    marker = os.environ.get("OBSERVABILITY_TEST_MARKER")
    if isinstance(marker, str):
        with Path(marker).open("a", encoding="utf-8") as stream:
            stream.write(stage + "\n")


def _run_observed(tmp_path, receipt):
    snapshot = make_snapshot()
    project_profile = profile()
    plan = plan_review(snapshot, project_profile, "AUTO")
    return run_review(
        snapshot,
        plan,
        project_profile,
        _ObservedProvider(receipt),
        _ObservedDecisionProvider(receipt),
        _limits(),
        str(tmp_path),
        "same-request-identity",
    )


def test_engine_observations_do_not_change_request_identity_or_reducer(tmp_path, monkeypatch):
    monkeypatch.setenv("OBSERVABILITY_TEST_MARKER", str(tmp_path / "calls.log"))
    with_receipts = _run_observed(tmp_path / "with", True)
    without_receipts = _run_observed(tmp_path / "without", False)

    assert with_receipts["request_hash"] == without_receipts["request_hash"]
    assert with_receipts["disposition"] == without_receipts["disposition"]
    assert with_receipts["coverage_state"] == without_receipts["coverage_state"]
    assert with_receipts["budget"]["provider_observability"]["stages"]["primary"]["request_attempted"] == 1
    assert without_receipts["budget"]["provider_observability"]["stages"]["primary"]["request_attempt_unknown"] == 1
    assert with_receipts["budget"]["provider_observability"]["stages"]["advisory"]["request_attempted"] == 1
    assert without_receipts["budget"]["provider_observability"]["stages"]["advisory"]["request_attempt_unknown"] == 1
    assert isinstance(with_receipts["run_elapsed_ms"], float)
    assert without_receipts["run_elapsed_ms"] >= 0
    report = engine_module.render_report(without_receipts)
    assert "dispatch attempted/not attempted/unknown 0/0/1" in report
    assert "usage_unknown" not in report


def test_run_elapsed_includes_final_advisory_stage(tmp_path, monkeypatch):
    monkeypatch.setenv("OBSERVABILITY_TEST_MARKER", str(tmp_path / "delayed-calls.log"))
    snapshot = make_snapshot()
    project_profile = profile()
    plan = plan_review(snapshot, project_profile, "AUTO")
    started = time.monotonic()
    result = run_review(
        snapshot,
        plan,
        project_profile,
        _ObservedProvider(receipt=False),
        _ObservedDecisionProvider(receipt=False, delay_seconds=0.15),
        _limits(),
        str(tmp_path / "delayed"),
        "delayed-advisory",
    )
    wall_elapsed_ms = (time.monotonic() - started) * 1000
    assert result["run_elapsed_ms"] >= wall_elapsed_ms - 25
    assert "run elapsed" in engine_module.render_report(result)


def test_legacy_completed_checkpoint_without_observations_resumes_without_dispatch(tmp_path, monkeypatch):
    marker = tmp_path / "calls.log"
    monkeypatch.setenv("OBSERVABILITY_TEST_MARKER", str(marker))
    provider = _ObservedProvider(receipt=True)
    decision = _ObservedDecisionProvider(receipt=True)
    snapshot = make_snapshot()
    project_profile = profile()
    plan = plan_review(snapshot, project_profile, "AUTO")
    output = tmp_path / "runs"
    original = run_review(snapshot, plan, project_profile, provider, decision, _limits(), str(output), "legacy")
    calls_before_resume = marker.read_text(encoding="utf-8").splitlines()
    assert calls_before_resume.count("specialist") == 1
    assert calls_before_resume.count("advisory") == 1

    saved_path = output / "legacy.json"
    saved = json.loads(saved_path.read_text(encoding="utf-8"))
    saved.pop("run_elapsed_ms", None)
    saved["ledger"].pop("run_started_at_epoch", None)
    for settlement in saved["ledger"]["budget"]["settlements"].values():
        settlement.pop("observation", None)
    saved["result_hash"] = engine_module._hash({key: value for key, value in saved.items() if key != "result_hash"})
    saved_path.write_text(json.dumps(saved, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")

    resumed = run_review(
        snapshot, plan, project_profile, provider, decision, _limits(), str(output), "legacy", resume=True
    )
    assert marker.read_text(encoding="utf-8").splitlines() == calls_before_resume
    assert resumed["request_hash"] == original["request_hash"]
    assert resumed["disposition"] == original["disposition"]
    assert "run_elapsed_ms" not in resumed
