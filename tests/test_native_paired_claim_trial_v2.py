from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from prepare_selected_pair_clean_control_trial import prepare_trial  # noqa: E402

from pr_review_harness.selected_model_trial import (  # noqa: E402
    MAX_CLAIM_ASSESSMENTS_PER_RUN,
    MAX_PROVIDER_CALLS_PER_RUN,
    NATIVE_PAIR_MAX_CLAIM_ASSESSMENTS_PER_RUN,
    NATIVE_PAIR_MAX_PROVIDER_CALLS_PER_RUN,
    PREPARED_CASE_IDS,
    PREPARED_PLAN_SCHEMA,
    _prepared_plan,
    trial_contract,
)


def test_v2_prepare_reserves_one_native_claim_call_and_never_dispatches(tmp_path):
    receipt = prepare_trial(tmp_path / "v2", version="v2")
    plan_path = Path(receipt["plan_path"])
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    inputs = plan["frozen_inputs"]
    profile = json.loads((plan_path.parent / inputs["profile_path"]).read_text(encoding="utf-8"))
    limits = json.loads((plan_path.parent / inputs["limits_path"]).read_text(encoding="utf-8"))

    assert plan["schema"] == "selected-pair-clean-control-trial.v2"
    assert profile["claim_reconciliation"] == {
        "version": "claim-reconciliation.v1",
        "enabled": True,
        "required": True,
        "max_assessments": 1,
    }
    assert limits["max_provider_calls"] == 5
    assert limits["max_retries_per_task"] == 0
    assert plan["bounds"]["primary_calls_per_review_max"] == 4
    assert plan["bounds"]["claim_jev_calls_per_review_max"] == 1
    assert plan["bounds"]["total_external_calls_max_if_classifier_enabled"] == 15
    assert plan["bounds"]["injection_classifier_calls_max"] == 0
    assert tuple(row["case_id"] for row in plan["cases"]) == PREPARED_CASE_IDS
    assert all(0 < row["primary_request_count"] <= 4 for row in plan["cases"])
    assert sum(row["primary_request_count"] for row in plan["cases"]) <= 12
    assert all(row["provider_calls"] == 0 for row in plan["cases"])
    assert plan["execution"]["provider_calls"] == 0
    assert plan["execution"]["target_code_execution"] == "NOT_RUN"
    assert plan["execution"]["publication"] == "NOT_PERFORMED"
    assert receipt["provider_calls"] == 0
    validated, _profile_path, _limits_path, _frozen = _prepared_plan(
        plan_path, ROOT, version="v2"
    )
    assert validated["schema"] == plan["schema"]


def test_v1_constants_and_contract_remain_unchanged():
    v1 = trial_contract("v1")
    v2 = trial_contract("v2")

    assert (v1.plan_schema, v1.max_provider_calls, v1.max_claim_assessments) == (
        PREPARED_PLAN_SCHEMA,
        MAX_PROVIDER_CALLS_PER_RUN,
        MAX_CLAIM_ASSESSMENTS_PER_RUN,
    )
    assert (v1.plan_schema, v1.max_provider_calls, v1.max_claim_assessments) == (
        "selected-pair-clean-control-trial.v1", 9, 4
    )
    assert (v2.plan_schema, v2.max_provider_calls, v2.max_claim_assessments) == (
        "selected-pair-clean-control-trial.v2",
        NATIVE_PAIR_MAX_PROVIDER_CALLS_PER_RUN,
        NATIVE_PAIR_MAX_CLAIM_ASSESSMENTS_PER_RUN,
    )
    assert (v2.max_provider_calls, v2.max_primary_requests, v2.max_claim_assessments) == (5, 4, 1)


def test_current_trial_workflow_keeps_v1_default_and_live_dispatch_disabled():
    workflow = (ROOT / ".github/workflows/selected-current-source-paired-trial.yml").read_text()

    assert "default: false" in workflow
    assert "trial_version:" in workflow
    assert "default: v1" in workflow
    assert "- v1\n          - v2" in workflow
    assert workflow.count('--trial-version "$TRIAL_VERSION"') == 2
    assert "if: inputs.run_live_trial == true" in workflow
