from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from prepare_selected_pair_clean_control_trial import prepare_trial  # noqa: E402

from pr_review_harness import selected_model_trial as trial  # noqa: E402
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
from pr_review_harness.snapshot import collect_snapshot  # noqa: E402


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
    validated, _profile_path, _limits_path, _frozen = _prepared_plan(plan_path, ROOT, version="v2")
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
        "selected-pair-clean-control-trial.v1",
        9,
        4,
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
    upload = workflow[workflow.index("- name: Upload only versioned sanitized trial receipts") :]
    assert '--failure-receipt "$FAILURE_RECEIPT"' in workflow
    assert "selected-current-source-failure-${{ github.run_id }}.json" in upload


def test_v2_prepared_runner_reconstructs_profile_and_reaches_all_fake_case_invocations(tmp_path, monkeypatch):
    prepared = prepare_trial(tmp_path / "prepared", root=ROOT, version="v2")
    plan_path = Path(prepared["plan_path"])
    plan = json.loads(plan_path.read_bytes())
    frozen = plan["frozen_inputs"]
    profile_path = plan_path.parent / frozen["profile_path"]
    limits_path = plan_path.parent / frozen["limits_path"]
    provider_path = plan_path.parent / frozen["provider_config_path"]
    decision_path = plan_path.parent / frozen["decision_config_path"]
    cli = tmp_path / "unused-installed-cli"
    cli.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    cli.chmod(0o700)
    source_fingerprint = {"file_hashes": {"src/pr_review_harness/selected_model_trial.py": "a" * 64}}

    class Matrix:
        def source_fingerprint(self):
            return source_fingerprint

    monkeypatch.setattr(trial, "_load_matrix_tools", lambda _root: Matrix())
    monkeypatch.setattr(
        trial,
        "_runtime_provenance",
        lambda _cli, _root: {
            "cli_path": str(cli),
            "source_fingerprint": source_fingerprint,
            "runtime_tree_sha256": "b" * 64,
        },
    )
    environ = {
        "PATH": "/usr/bin:/bin",
        "LLM_BASE_URL": trial.PRIMARY_IDENTITY["base_url"],
        "LLM_MODEL": trial.PRIMARY_IDENTITY["model"],
        "LLM_API_KEY": "local-test-primary-token",
        "JEV_BASE_URL": "https://api.typesafe.ai/v1",
        "JEV_MODEL": trial.DECISION_IDENTITY["model"],
        "JEV_API_KEY": "local-test-decision-token",
    }
    invocations = []
    rows = {row["case_id"]: row for row in plan["cases"]}

    def fake_invoke(command, *, cwd, env, timeout_seconds):
        run_id = command[command.index("--run-id") + 1]
        invocations.append((run_id, "prepare" if "--prepare-only" in command else "review"))
        if "--prepare-only" in command:
            case = rows[run_id]
            repo = Path(command[command.index("--repo") + 1])
            base = command[command.index("--base") + 1]
            head = command[command.index("--head") + 1]
            profile = json.loads(Path(command[command.index("--profile") + 1]).read_bytes())
            limits = json.loads(Path(command[command.index("--limits") + 1]).read_bytes())
            snapshot = collect_snapshot(str(repo), base, head, profile, limits)
            return {
                "run_status": "CLI_COMPLETED",
                "exit_code": 0,
                "cli_result": {
                    "status": "PREPARED_ONLY",
                    "no_provider_calls": True,
                    "no_target_code_execution": True,
                    "snapshot": {
                        "snapshot_id": snapshot["snapshot_id"],
                        "snapshot_hash": snapshot["snapshot_hash"],
                        "base_sha": base,
                        "head_sha": head,
                        "profile_file_sha256": hashlib.sha256(profile_path.read_bytes()).hexdigest(),
                        "limits_sha256": hashlib.sha256(limits_path.read_bytes()).hexdigest(),
                    },
                    "primary_requests": case["primary_requests"],
                },
                "stdout_bytes": 0,
                "stderr_bytes": 0,
            }
        assert command[command.index("--max-claim-assessments") + 1] == "1"
        assert (
            json.loads(Path(command[command.index("--profile") + 1]).read_bytes())["claim_reconciliation"]["required"]
            is True
        )
        assert json.loads(Path(command[command.index("--limits") + 1]).read_bytes())["max_provider_calls"] == 5
        return {
            "run_status": "CLI_FAILED",
            "exit_code": 1,
            "stdout_bytes": 0,
            "stderr_bytes": 0,
            "stdout_sha256": "0" * 64,
            "stderr_sha256": "0" * 64,
        }

    result = trial.run_provider_trial(
        output=tmp_path / "live-fake",
        cli_executable=cli,
        provider_config=provider_path,
        decision_config=decision_path,
        repo_support_root=ROOT,
        environ=environ,
        invoke=fake_invoke,
        prepared_plan=plan_path,
        version="v2",
    )

    assert result["status"] == "INCOMPLETE"
    assert [kind for _case_id, kind in invocations].count("prepare") == 3
    assert [kind for _case_id, kind in invocations].count("review") == 3


def test_current_trial_runner_persists_only_a_sanitized_failure_code(tmp_path):
    failure = tmp_path / "failure.json"
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/run_current_selected_model_trial.py"),
            "--run-provider-trial",
            "--trial-version",
            "v2",
            "--expected-source-revision",
            "a" * 40,
            "--preparation-dir",
            str(tmp_path / "missing-preparation"),
            "--output",
            str(tmp_path / "result"),
            "--cli-executable",
            str(tmp_path / "not-called-cli"),
            "--provider-config",
            str(tmp_path / "provider.json"),
            "--decision-config",
            str(tmp_path / "decision.json"),
            "--observe-effects",
            "--failure-receipt",
            str(failure),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 2
    assert json.loads(result.stdout) == {"error": "current_preparation_receipt_unavailable", "status": "FAILED"}
    receipt = json.loads(failure.read_bytes())
    assert receipt == {
        "error": "current_preparation_receipt_unavailable",
        "schema": "selected-current-source-failure.v1",
        "status": "FAILED",
        "trial_version": "v2",
    }
    assert failure.stat().st_mode & 0o777 == 0o600
    assert str(tmp_path) not in failure.read_text(encoding="utf-8")
