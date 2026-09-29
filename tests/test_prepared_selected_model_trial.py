from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))

import test_selected_model_trial as selected_trial_tests  # noqa: E402
from prepare_selected_pair_clean_control_trial import CASE_IDS, prepare_trial  # noqa: E402

from pr_review_harness import selected_model_trial as trial  # noqa: E402
from pr_review_harness.snapshot import collect_snapshot  # noqa: E402


@pytest.fixture
def prepared_inputs(tmp_path):
    prepared = prepare_trial(tmp_path / "prepared", root=ROOT)
    plan_path = Path(prepared["plan_path"])
    plan = json.loads(plan_path.read_bytes())
    frozen = plan["frozen_inputs"]
    primary = plan_path.parent / frozen["provider_config_path"]
    decision = plan_path.parent / frozen["decision_config_path"]
    profile = json.loads((plan_path.parent / frozen["profile_path"]).read_bytes())
    limits = json.loads((plan_path.parent / frozen["limits_path"]).read_bytes())
    snapshots = {}
    for case_id in CASE_IDS:
        case = frozen["cases"][case_id]
        repo = plan_path.parent / case["repository_path"]
        snapshots[case_id] = collect_snapshot(
            str(repo), case["base_sha"], case["head_sha"], profile, limits
        )
    cli = tmp_path / "installed-pr-review"
    cli.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    cli.chmod(0o755)
    env = {
        "PATH": "/usr/bin:/bin",
        "LLM_BASE_URL": trial.PRIMARY_IDENTITY["base_url"],
        "LLM_MODEL": trial.PRIMARY_IDENTITY["model"],
        "LLM_API_KEY": "offline-test-primary-key",
        "JEV_BASE_URL": "https://api.typesafe.ai/v1",
        "JEV_MODEL": trial.DECISION_IDENTITY["model"],
        "JEV_API_KEY": "offline-test-decision-key",
    }
    return {
        "prepared": prepared,
        "plan_path": plan_path,
        "plan": plan,
        "profile": profile,
        "snapshots": snapshots,
        "primary": primary,
        "decision": decision,
        "cli": cli,
        "env": env,
        "tmp_path": tmp_path,
    }


def _runtime(monkeypatch, cli: Path):
    source_fingerprint = {
        "file_hashes": {"src/pr_review_harness/selected_model_trial.py": "a" * 64}
    }

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


def _fake_invoker(
    plan, calls, *, snapshots=None, wrong_prepare_case: str | None = None,
    clean_result_factory=None,
):
    cases = {row["case_id"]: row for row in plan["cases"]}

    def invoke(command, *, cwd, env, timeout_seconds):
        row = {"command": command, "cwd": str(cwd), "timeout_seconds": timeout_seconds}
        run_id = command[command.index("--run-id") + 1]
        if "--prepare-only" in command:
            row["kind"] = "prepare"
            case = cases[run_id]
            snapshot_source = snapshots[run_id] if snapshots is not None else None
            snapshot = {
                "snapshot_id": snapshot_source["snapshot_id"] if snapshot_source else f"fresh-{run_id}",
                "snapshot_hash": snapshot_source["snapshot_hash"] if snapshot_source else "f" * 64,
                "base_sha": case["base_sha"],
                "head_sha": case["head_sha"],
                "profile_file_sha256": case["profile_sha256"],
                "limits_sha256": case["limits_sha256"],
                "inventory": snapshot_source["inventory"] if snapshot_source else [],
            }
            requests = case["primary_requests"]
            if run_id == wrong_prepare_case and requests:
                requests = [{**requests[0], "input_sha256": "0" * 64}, *requests[1:]]
            row["env_has_credentials"] = any(key.endswith("API_KEY") for key in env)
            calls.append(row)
            return {
                "run_status": "CLI_COMPLETED",
                "exit_code": 0,
                "cli_result": {
                    "status": "PREPARED_ONLY",
                    "no_provider_calls": True,
                    "no_target_code_execution": True,
                    "snapshot": snapshot,
                    "primary_requests": requests,
                },
                "stdout_bytes": 0,
                "stderr_bytes": 0,
            }
        row["kind"] = "review"
        row["env_has_credentials"] = all(key in env for key in ("LLM_API_KEY", "JEV_API_KEY"))
        calls.append(row)
        if run_id == CASE_IDS[2] and clean_result_factory is not None:
            output_path = Path(command[command.index("--output") + 1])
            output_path.mkdir(parents=True, exist_ok=True)
            result = clean_result_factory()
            result_path = output_path / "result.json"
            report_path = output_path / "report.json"
            result_path.write_bytes(trial.canonical_json(result))
            report_path.write_text("{}", encoding="utf-8")
            return {
                "run_status": "CLI_COMPLETED",
                "exit_code": 0,
                "stdout_bytes": 0,
                "stderr_bytes": 0,
                "stdout_sha256": "0" * 64,
                "stderr_sha256": "0" * 64,
                "cli_result": {
                    "artifact_path": str(result_path),
                    "report_path": str(report_path),
                    "snapshot_id": result["snapshot_id"],
                },
            }
        return {
            "run_status": "CLI_FAILED",
            "exit_code": 1,
            "stdout_bytes": 0,
            "stderr_bytes": 0,
            "stdout_sha256": "0" * 64,
            "stderr_sha256": "0" * 64,
        }

    return invoke


def _run(
    prepared_inputs, monkeypatch, invoke, *, env=None, output_name="trial-output", plan_path=None
):
    _runtime(monkeypatch, prepared_inputs["cli"])
    monkeypatch.setattr(trial, "MATRIX_TIMEOUT_SECONDS", 940)
    return trial.run_provider_trial(
        output=prepared_inputs["tmp_path"] / output_name,
        cli_executable=prepared_inputs["cli"],
        provider_config=prepared_inputs["primary"],
        decision_config=prepared_inputs["decision"],
        repo_support_root=ROOT,
        environ=prepared_inputs["env"] if env is None else env,
        invoke=invoke,
        prepared_plan=prepared_inputs["plan_path"] if plan_path is None else plan_path,
    )


def _clean_claim_result(prepared_inputs):
    case_id = CASE_IDS[2]
    snapshot = prepared_inputs["snapshots"][case_id]
    unit = snapshot["inventory"][0]
    evidence_id = unit["evidence_ids"][0]
    line = unit["changed_lines"][0][0]
    case = prepared_inputs["plan"]["frozen_inputs"]["cases"][case_id]
    profile_id = prepared_inputs["profile"]["version"]
    profile_hash = hashlib.sha256(trial.canonical_json(prepared_inputs["profile"])).hexdigest()
    candidate_id = "clean-candidate-1"
    candidate = {
        "candidate_id": candidate_id,
        "unit_id": unit["unit_id"],
        "location": {"kind": "line", "path": unit["path"], "side": "HEAD", "line": line},
        "evidence_refs": [evidence_id],
        "title": "Changed caller remains tenant scoped",
        "observation": "The behavior-preserving edit retains the owner equality predicate.",
        "consequence": "Cross-owner reads remain rejected by the caller identity check.",
        "rule_or_contract": "A caller may read only documents owned by that caller.",
    }
    claim = selected_trial_tests._assessment_row(candidate_id)
    claim["evidence_refs"] = [evidence_id]
    claim.update(
        snapshot_id=snapshot["snapshot_id"], snapshot_hash=snapshot["snapshot_hash"],
        profile_hash=profile_hash, base_sha=case["base_sha"], head_sha=case["head_sha"],
    )
    claim["provenance"].update(
        snapshot_id=snapshot["snapshot_id"], snapshot_hash=snapshot["snapshot_hash"],
        profile_id=profile_id, profile_hash=profile_hash,
        base_sha=case["base_sha"], head_sha=case["head_sha"],
    )
    for assessment in claim["assessments"].values():
        assessment["evidence_refs"] = [evidence_id]
    request_hash = "8" * 64
    result = {
        "snapshot_id": snapshot["snapshot_id"],
        "base_sha": case["base_sha"],
        "head_sha": case["head_sha"],
        "project_profile_version": profile_id,
        "disposition": "INCOMPLETE",
        "coverage_state": "COMPLETE",
        "request_hash": request_hash,
        "ledger": {
            "request_hash": request_hash,
            "identity": {"snapshot_id": snapshot["snapshot_id"], "profile_version": profile_id},
            "candidate_records": [{
                "candidate_id": candidate_id,
                "finding_id": "clean-finding-1",
                "snapshot_id": snapshot["snapshot_id"],
                "validation_state": "VALID",
                "raw": candidate,
            }],
        },
        "findings": [{
            "candidate_id": candidate_id,
            "status": "NEEDS_EVIDENCE",
            "blocking_class": "UNRESOLVED",
            "observation": candidate["observation"],
            "consequence": candidate["consequence"],
            "rule_or_contract": candidate["rule_or_contract"],
            "evidence_refs": [evidence_id],
        }],
        "claim_assessments": [claim],
        "evidence_index": {evidence_id: {"path": unit["path"]}},
    }
    result["result_hash"] = trial._safe_hash(result)
    return result


def test_prepared_plan_rechecks_all_case_descriptors_before_any_review(prepared_inputs, monkeypatch):
    assert [row["case_id"] for row in prepared_inputs["plan"]["cases"]] == list(CASE_IDS)
    assert [row["role"] for row in prepared_inputs["plan"]["cases"]] == [
        "defect_positive_prompt_attack",
        "defect_positive_benign_lookalike",
        "code_clean_negative_control",
    ]
    calls = []
    result = _run(
        prepared_inputs,
        monkeypatch,
        _fake_invoker(prepared_inputs["plan"], calls, snapshots=prepared_inputs["snapshots"]),
    )

    prepare_indices = [index for index, row in enumerate(calls) if row["kind"] == "prepare"]
    review_indices = [index for index, row in enumerate(calls) if row["kind"] == "review"]
    assert len(prepare_indices) == len(CASE_IDS) == 3
    assert len(review_indices) == len(CASE_IDS) == 3
    assert max(prepare_indices) < min(review_indices)
    assert [calls[index]["command"][calls[index]["command"].index("--run-id") + 1] for index in prepare_indices] == list(CASE_IDS)
    assert all(not calls[index]["env_has_credentials"] for index in prepare_indices)
    assert all(calls[index]["env_has_credentials"] for index in review_indices)
    profile_paths = {
        calls[index]["command"][calls[index]["command"].index("--profile") + 1]
        for index in prepare_indices + review_indices
    }
    limits_paths = {
        calls[index]["command"][calls[index]["command"].index("--limits") + 1]
        for index in prepare_indices + review_indices
    }
    assert len(profile_paths) == len(limits_paths) == 1
    assert result["status"] == "INCOMPLETE"
    manifest = json.loads((prepared_inputs["tmp_path"] / "trial-output" / "manifest.json").read_bytes())
    assert [row["snapshot_id"] for row in manifest["cases"]] == [
        prepared_inputs["snapshots"][case_id]["snapshot_id"] for case_id in CASE_IDS
    ]
    assert manifest["maximum_provider_calls_total"] == 27
    assert manifest["claim_assessments_cap_per_run"] == 4
    assert manifest["maximum_claim_assessments_total"] == 12
    assert manifest["maximum_external_calls_total"] == 39
    assert manifest["injection_classifier"] == "NOT_RUN_CONTRACT_COMPATIBILITY_UNRESOLVED"
    summary = json.loads((prepared_inputs["tmp_path"] / "trial-output" / "summary.json").read_bytes())
    assert summary["cases"][0]["run_status"] == "CLI_FAILED"


def test_clean_control_claim_binds_to_its_real_changed_unit_and_snapshot(prepared_inputs, monkeypatch):
    calls = []
    invoke = _fake_invoker(
        prepared_inputs["plan"], calls, snapshots=prepared_inputs["snapshots"],
        clean_result_factory=lambda: _clean_claim_result(prepared_inputs),
    )
    result = _run(prepared_inputs, monkeypatch, invoke, output_name="clean-claim-binding")

    assert result["status"] == "INCOMPLETE"  # Attack-pair fake calls deliberately return CLI_FAILED.
    clean_summary = next(row for row in result["cases"] if row["case_id"] == CASE_IDS[2])
    assert clean_summary["run_status"] == "CLI_COMPLETED"
    assert clean_summary["result_identity_match"] is True
    assert clean_summary["claim_projection_valid"] is True
    claim = clean_summary["claim_assessments"][0]
    assert claim["candidate_binding"] == "MATCH"
    assert claim["candidate_unit_id"] == prepared_inputs["snapshots"][CASE_IDS[2]]["inventory"][0]["unit_id"]
    assert claim["candidate_location"]["path"] == prepared_inputs["snapshots"][CASE_IDS[2]]["inventory"][0]["path"]
    assert claim["evidence_binding"] == "MATCH_RESULT_EVIDENCE_INDEX"
    assert claim["identity_binding"] == "MATCH_CONFIGURED_ALIAS_AND_ENDPOINT_PROVENANCE"


def test_second_prepared_descriptor_mismatch_stops_before_any_review(prepared_inputs, monkeypatch):
    calls = []
    invoke = _fake_invoker(
        prepared_inputs["plan"], calls, snapshots=prepared_inputs["snapshots"],
        wrong_prepare_case=CASE_IDS[1],
    )

    with pytest.raises(trial.SelectedTrialError):
        _run(prepared_inputs, monkeypatch, invoke, output_name="descriptor-mismatch")

    assert [row["kind"] for row in calls] == ["prepare", "prepare"]


def test_tampered_frozen_inputs_fail_before_any_installed_cli_invocation(prepared_inputs, monkeypatch):
    frozen = prepared_inputs["plan"]["frozen_inputs"]
    profile_path = prepared_inputs["plan_path"].parent / frozen["profile_path"]
    profile_path.write_bytes(profile_path.read_bytes() + b" ")
    calls = []

    with pytest.raises(trial.SelectedTrialError):
        _run(prepared_inputs, monkeypatch, _fake_invoker(prepared_inputs["plan"], calls, snapshots=prepared_inputs["snapshots"]), output_name="tampered-plan")

    assert calls == []


def test_operator_environment_config_mismatch_stops_before_preflight_or_review(prepared_inputs, monkeypatch):
    env = {**prepared_inputs["env"], "LLM_MODEL": "operator-selected-different-model"}
    calls = []

    with pytest.raises(trial.SelectedTrialError):
        _run(prepared_inputs, monkeypatch, _fake_invoker(prepared_inputs["plan"], calls, snapshots=prepared_inputs["snapshots"]), env=env,
             output_name="operator-config-mismatch")

    assert calls == []


@pytest.mark.parametrize(
    "mutation",
    ["source_inventory", "frozen_config_bytes", "repo_head", "repo_dirty", "construction_oracle", "fixture_hash"],
)
def test_tampered_prepared_provenance_fails_before_any_invocation(
    prepared_inputs, monkeypatch, mutation
):
    plan = json.loads(prepared_inputs["plan_path"].read_bytes())
    plan_path = prepared_inputs["plan_path"].with_name(f"tampered-{mutation}.json")
    if mutation == "source_inventory":
        plan["implementation_identity"]["file_hashes"].pop(
            "src/pr_review_harness/providers.py"
        )
    elif mutation == "frozen_config_bytes":
        config_path = prepared_inputs["primary"]
        config_path.write_bytes(config_path.read_bytes() + b" ")
    elif mutation == "repo_head":
        plan["frozen_inputs"]["cases"][CASE_IDS[0]]["head_sha"] = "f" * 40
    elif mutation == "repo_dirty":
        repo = (
            prepared_inputs["plan_path"].parent
            / plan["frozen_inputs"]["cases"][CASE_IDS[0]]["repository_path"]
        )
        (repo / "untracked-provenance-tamper.txt").write_text("tampered", encoding="utf-8")
    elif mutation == "construction_oracle":
        plan["construction_oracle"]["clean_control"]["expected_material_candidate"] = True
    elif mutation == "fixture_hash":
        plan["fixture_sources"]["clean_manifest_sha256"] = "0" * 64
    plan_path.write_text(json.dumps(plan, sort_keys=True, separators=(",", ":")), encoding="utf-8")
    calls = []

    with pytest.raises(trial.SelectedTrialError):
        _run(
            prepared_inputs,
            monkeypatch,
            _fake_invoker(prepared_inputs["plan"], calls, snapshots=prepared_inputs["snapshots"]),
            output_name=f"tampered-{mutation}-output",
            plan_path=plan_path,
        )

    assert calls == []


def test_exhausted_global_deadline_never_starts_a_review(prepared_inputs, monkeypatch):
    calls = []
    _runtime(monkeypatch, prepared_inputs["cli"])
    monkeypatch.setattr(trial, "PREPARED_GLOBAL_DEADLINE_SECONDS", 0)
    with pytest.raises(trial.SelectedTrialError, match="prepared_global_deadline_exhausted"):
        trial.run_provider_trial(
            output=prepared_inputs["tmp_path"] / "deadline-exhausted",
            cli_executable=prepared_inputs["cli"],
            provider_config=prepared_inputs["primary"],
            decision_config=prepared_inputs["decision"],
            repo_support_root=ROOT,
            environ=prepared_inputs["env"],
            invoke=_fake_invoker(prepared_inputs["plan"], calls, snapshots=prepared_inputs["snapshots"]),
            prepared_plan=prepared_inputs["plan_path"],
        )

    assert calls == []
