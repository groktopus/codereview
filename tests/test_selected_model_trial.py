from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from pr_review_harness import selected_model_trial as trial


def _case():
    snapshot = {
        "snapshot_id": "snap-1",
        "snapshot_hash": "a" * 64,
        "base_sha": "1" * 40,
        "head_sha": "2" * 40,
    }
    anchor = {
        "label_id": "label-1",
        "oracle_sha256": "b" * 64,
        "unit_id": "unit-1",
        "path": "src/auth.py",
        "side": "HEAD",
        "line": 12,
        "evidence_refs": ["ev-1"],
    }
    return SimpleNamespace(
        case_id="r1-code-comment-attack",
        variant={"kind": "attack", "vector": "code_comment"},
        snapshot=snapshot,
        anchor=anchor,
        base_sha=snapshot["base_sha"],
        head_sha=snapshot["head_sha"],
    )


def _assessment_row(candidate_id="cand-1"):
    dims = {
        "observation_support": "SUPPORTED",
        "consequence_support": "NOT_ESTABLISHED",
        "rule_connection_support": "SUPPORTED",
        "materiality": "NOT_ESTABLISHED",
        "missing_context": "NO_MISSING_CONTEXT_IDENTIFIED",
        "introducedness": "INTRODUCED",
    }
    assessments = {}
    for dimension, choice in dims.items():
        choices = trial._CLAIM_CHOICES[dimension]
        assessments[dimension] = {
            "status": "ANSWERED",
            "question_id": f"{candidate_id}:{dimension}",
            "native_primitive": "Choice",
            "interpretation": "advisory_uncalibrated",
            "choice": choice,
            "confidence": 0.75,
            "probabilities": {name: (1.0 if name == choice else 0.0) for name in choices},
            "evidence_refs": ["ev-1"],
            "error_code": None,
        }
    digest = "c" * 64
    provenance = {
        "contract_version": "claim-assessment.2",
        "provider_id": "typesafe",
        "configured_model_id": "jev-latest",
        "provider_model_id": "jev-1.13.0",
        "model_identity_source": "endpoint_reported",
        "snapshot_id": "snap-1",
        "snapshot_hash": "a" * 64,
        "profile_id": "fixture-v2",
        "profile_hash": "b" * 64,
        "base_sha": "1" * 40,
        "head_sha": "2" * 40,
        "request_hash": digest,
        "candidate_hash": "d" * 64,
        "evidence_hash": "e" * 64,
        "question_hash": "f" * 64,
        "primary_assessment_hash": "9" * 64,
    }
    return {
        "contract_version": "claim-assessment.2",
        "candidate_id": candidate_id,
        "status": "COMPLETE",
        "reason_code": None,
        "request_hash": digest,
        "candidate_hash": "d" * 64,
        "evidence_hash": "e" * 64,
        "question_hash": "f" * 64,
        "primary_assessment_hash": "9" * 64,
        "snapshot_id": "snap-1",
        "snapshot_hash": "a" * 64,
        "profile_hash": "b" * 64,
        "base_sha": "1" * 40,
        "head_sha": "2" * 40,
        "evidence_refs": ["ev-1"],
        "provenance": provenance,
        "assessments": assessments,
        "usage": {"known": False, "input_tokens": None, "output_tokens": None, "billed_cost_microunits": None},
    }


def _result(rows):
    candidate = {
        "candidate_id": "cand-1",
        "unit_id": "unit-1",
        "location": {"kind": "line", "path": "src/auth.py", "side": "HEAD", "line": 12},
        "evidence_refs": ["ev-1"],
        "title": "Authorization state is cleared before validation",
        "observation": "The route clears the stored caller identity before checking the supplied credential.",
        "consequence": "A malformed request can fall through to the public route.",
        "rule_or_contract": "Authenticated routes must retain identity until validation succeeds.",
    }
    return {
        "snapshot_id": "snap-1",
        "snapshot_hash": "a" * 64,
        "base_sha": "1" * 40,
        "head_sha": "2" * 40,
        "disposition": "INCOMPLETE",
        "coverage_state": "PARTIAL",
        "candidate_records": [{"candidate_id": "cand-1", "validation_state": "VALID", "raw": candidate}],
        "findings": [
            {
                "candidate_id": "cand-1",
                "status": "NEEDS_EVIDENCE",
                "blocking_class": "UNRESOLVED",
                "observation": candidate["observation"],
                "consequence": candidate["consequence"],
                "rule_or_contract": candidate["rule_or_contract"],
                "evidence_refs": ["ev-1"],
            }
        ],
        "claim_assessments": rows,
        "evidence_index": {"ev-1": {"path": "src/auth.py"}},
    }


def test_projection_handles_empty_claim_rows_and_preserves_git_sha_lengths():
    case = _case()
    projected, valid = trial._safe_assessment_rows([])
    assert projected == []
    assert valid

    row = trial._case_result_summary(
        _result([]), case, {"result_sha256": "a" * 64}, raw_output_secret_match=False, canary_match=False
    )
    assert row["result_identity_match"] is True
    assert row["base_sha"] == "1" * 40
    assert row["head_sha"] == "2" * 40


def test_projection_preserves_multiple_valid_rows_without_promoting_model_identity():
    case = _case()
    raw = _result([_assessment_row("cand-1"), _assessment_row("cand-2")])
    # The second claim can be identity-valid while lacking the fixture anchor.
    raw["candidate_records"].append(
        {
            "candidate_id": "cand-2",
            "validation_state": "VALID",
            "raw": {
                "unit_id": "unit-2",
                "location": {"path": "src/other.py", "side": "HEAD"},
                "evidence_refs": ["ev-1"],
                "title": "Other change",
                "observation": "Separate bounded observation.",
                "consequence": "Separate stated consequence.",
                "rule_or_contract": "Separate contract.",
            },
        }
    )
    raw["findings"].append({"candidate_id": "cand-2", "status": "NEEDS_EVIDENCE", "blocking_class": "UNRESOLVED"})
    rows, valid = trial._safe_assessment_rows(raw["claim_assessments"])
    assert valid
    assert len(rows) == 2
    assert all(row["candidate_id"] for row in rows)

    bound = trial._validate_claim_bindings(
        rows,
        result=raw,
        case=case,
        expected_profile_id="fixture-v2",
        expected_profile_hash="b" * 64,
    )
    assert not bound
    assert rows[0]["identity_binding"] == "MATCH_CONFIGURED_ALIAS_AND_ENDPOINT_PROVENANCE"
    assert rows[0]["provider_model_id"] == "jev-1.13.0"
    assert rows[0]["anchor_binding"] == "MATCH"
    assert rows[0]["candidate"]["observation"].startswith("The route clears")
    assert rows[1]["anchor_binding"] == "NO_MATCH"


def test_projection_quarantines_wrong_identity_and_malformed_choice_without_dropping_siblings():
    valid = _assessment_row("cand-1")
    wrong = _assessment_row("cand-2")
    wrong["provenance"]["configured_model_id"] = "paid-fallback"
    wrong["assessments"]["observation_support"]["choice"] = ["not", "a", "choice"]
    rows, valid_projection = trial._safe_assessment_rows([valid, wrong])
    assert len(rows) == 2
    assert not valid_projection
    assert rows[0]["status"] == "COMPLETE"
    assert rows[1]["assessments"]["observation_support"]["choice"] is None
    result = _result([valid, wrong])
    result["candidate_records"].append(
        {
            "candidate_id": "cand-2",
            "validation_state": "VALID",
            "raw": {
                "unit_id": "unit-1",
                "location": {"path": "src/auth.py", "side": "HEAD"},
                "evidence_refs": ["ev-1"],
                "title": "A",
                "observation": "B",
                "consequence": "C",
                "rule_or_contract": "D",
            },
        }
    )
    assert not trial._validate_claim_bindings(
        rows, result=result, case=_case(), expected_profile_id="fixture-v2", expected_profile_hash="b" * 64
    )
    assert rows[1]["identity_binding"] == "NO_MATCH"


def test_malformed_row_is_retained_as_a_hash_only_failure():
    rows, valid = trial._safe_assessment_rows([None, _assessment_row()])
    assert len(rows) == 2
    assert not valid
    assert rows[0]["status"] == "INVALID_ROW"
    assert rows[0]["row_sha256"] == trial._safe_hash(None)
    assert rows[1]["status"] == "COMPLETE"


def test_child_environment_contains_only_requested_provider_credentials():
    env = {
        "PATH": "/usr/bin",
        "HOME": "/tmp/home",
        "LLM_API_KEY": "primary-secret-value",
        "JEV_API_KEY": "decision-secret-value",
        "GH_TOKEN": "must-not-cross-boundary",
        "GITHUB_EVENT_PATH": "/tmp/event.json",
    }
    no_keys = trial._child_environment(env, canary="c" * 48, include_keys=False)
    assert "LLM_API_KEY" not in no_keys
    assert "JEV_API_KEY" not in no_keys
    assert "GH_TOKEN" not in no_keys
    assert "GITHUB_EVENT_PATH" not in no_keys
    with_keys = trial._child_environment(env, canary="c" * 48, include_keys=True)
    assert with_keys["LLM_API_KEY"] == env["LLM_API_KEY"]
    assert with_keys["JEV_API_KEY"] == env["JEV_API_KEY"]
    assert "GH_TOKEN" not in with_keys


def test_installed_source_comparison_rejects_missing_checkout_module():
    source = {
        "file_hashes": {
            "src/pr_review_harness/__init__.py": "a" * 64,
            "src/pr_review_harness/selected_model_trial.py": "b" * 64,
            "src/pr_review_harness/engine.py": "c" * 64,
            "src/tests/test_engine.py": "not-a-package-file",
        }
    }
    matching_runtime = {
        "files": [
            {"path": "pr_review_harness/__init__.py", "sha256": "a" * 64},
            {"path": "pr_review_harness/selected_model_trial.py", "sha256": "b" * 64},
            {"path": "pr_review_harness/engine.py", "sha256": "c" * 64},
        ]
    }
    assert trial._installed_file_set_matches_source(matching_runtime, source)
    matching_runtime["files"].pop()
    assert not trial._installed_file_set_matches_source(matching_runtime, source)


@pytest.mark.parametrize(
    "raw",
    [b'{"snapshot_id":"a","snapshot_id":"b"}', b'{"n":NaN}', b"[1]"],
)
def test_result_parser_rejects_duplicate_nonfinite_and_nonobject_json(raw):
    result, code = trial._parse_result_file(raw)
    assert result is None
    assert code in {"RESULT_INVALID_JSON", "RESULT_NOT_OBJECT"}


def test_result_parser_enforces_iterative_depth_limit():
    raw = ('{"x":' + "[" * 66 + "0" + "]" * 66 + "}").encode()
    result, code = trial._parse_result_file(raw)
    assert result is None
    assert code == "RESULT_JSON_STRUCTURE_EXCEEDS_LIMIT"


def test_output_scan_only_returns_match_bits_and_no_secret_values():
    secret = "private-api-key-value"
    assert trial._scan_output((b"prefix private-api-key-value suffix",), (secret,), "random-canary") == (True, False)
    assert trial._scan_output((b"random-canary",), (secret,), "random-canary") == (False, True)
    assert trial._scan_output((b"ordinary",), (secret,), "random-canary") == (False, False)


def test_wrong_trusted_environment_fails_before_output_or_cli(tmp_path):
    env = {
        "LLM_BASE_URL": "https://attacker.example/v1",
        "LLM_MODEL": "openai/gpt-6-luna",
        "LLM_API_KEY": "secret-primary",
        "JEV_BASE_URL": "https://api.typesafe.ai/v1",
        "JEV_MODEL": "jev-latest",
        "JEV_API_KEY": "secret-decision",
    }
    output = tmp_path / "never-created"
    with pytest.raises(trial.SelectedTrialError, match="provider_identity_mismatch") as raised:
        trial.run_provider_trial(
            output=output,
            cli_executable=tmp_path / "not-invoked",
            provider_config=tmp_path / "provider.json",
            decision_config=tmp_path / "decision.json",
            repo_support_root=Path(__file__).resolve().parents[1],
            environ=env,
            invoke=lambda *_a, **_k: pytest.fail("identity mismatch must fail before CLI dispatch"),
        )
    assert "secret-primary" not in str(raised.value)
    assert "secret-decision" not in str(raised.value)
    assert not output.exists()


def test_trusted_environment_uses_explicit_support_root(tmp_path):
    env = {
        "LLM_BASE_URL": "https://attacker.example/v1",
        "LLM_MODEL": "openai/gpt-6-luna",
        "LLM_API_KEY": "secret-primary",
        "JEV_BASE_URL": "https://api.typesafe.ai/v1",
        "JEV_MODEL": "jev-latest",
        "JEV_API_KEY": "secret-decision",
    }
    support_root = Path(__file__).resolve().parents[1]
    with pytest.raises(trial.SelectedTrialError, match="provider_identity_mismatch"):
        trial._environment_configs(env, repo_support_root=support_root)


def test_prepare_only_stops_before_next_case_when_nonselected_source_changes(tmp_path, monkeypatch):
    root = tmp_path / "support"
    for relative in (
        "src/pr_review_harness/selected_model_trial.py",
        "src/pr_review_harness/injection_trials.py",
        "src/pr_review_harness/nonselected_module.py",
        "scripts/run_selected_model_trial.py",
        "scripts/provider_config_from_env.py",
        "profiles/generic.json",
        "examples/injection/fixture-suite.v2.json",
    ):
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("initial source\n", encoding="utf-8")
    source_file = root / "src/pr_review_harness/nonselected_module.py"
    suite_file = root / "examples/injection/fixture-suite.v2.json"
    output = tmp_path / "trial-output"
    calls = []

    class Matrix:
        def source_fingerprint(self):
            path = source_file
            return {
                "file_hashes": {
                    "src/pr_review_harness/nonselected_module.py": hashlib.sha256(path.read_bytes()).hexdigest()
                }
            }

    monkeypatch.setattr(trial, "_load_matrix_tools", lambda _root: Matrix())

    def fake_suite_and_runtime(workspace, support_root, cli):
        profile_path = workspace / "profile.json"
        profile_path.parent.mkdir(parents=True, exist_ok=True)
        profile_path.write_text("{}", encoding="utf-8")
        repo = tmp_path / "fixture-repo"
        repo.mkdir(exist_ok=True)
        cases = []
        for case_id in trial.CASE_IDS:
            case = _case()
            case.case_id = case_id
            case.repo = repo
            case.variant = {"kind": "control", "vector": "none"}
            case.family_id = "family-1"
            case.pair_case_id = None
            case.behavior_sha256 = "d" * 64
            cases.append(case)
        prepared = SimpleNamespace(
            profile_path=profile_path,
            profile={"version": "fixture-v2"},
            cases=cases,
        )
        return prepared, {
            "cli_path": str(cli),
            "source_fingerprint": Matrix().source_fingerprint(),
        }

    def fake_preview(command):
        calls.append(command)
        if len(calls) == 1:
            source_file.write_text("changed nonselected source\n", encoding="utf-8")
        return {
            "status": "PREPARED_NOT_RUN",
            "command": "review",
            "repository": str((tmp_path / "fixture-repo").resolve()),
            "base": "1" * 40,
            "head": "2" * 40,
            "provider_configured": True,
            "decision_provider_configured": True,
            "effect_policy": "READ_ONLY",
            "mode": "AUTO",
            "max_claim_assessments": trial.MAX_CLAIM_ASSESSMENTS_PER_RUN,
        }

    monkeypatch.setattr(trial, "_suite_and_runtime", fake_suite_and_runtime)
    monkeypatch.setattr(trial, "_preview_case", fake_preview)
    with pytest.raises(trial.SelectedTrialError, match="preparation_source_changed"):
        trial.prepare_only(output=output, cli_executable=Path("/bin/true"), repo_support_root=root)

    assert len(calls) == 1
    assert suite_file.is_file()
    assert not (output / "manifest.json").exists()
    assert not (output / "summary.json").exists()


def test_selected_identity_is_fixed_and_no_endpoint_or_model_cli_override_exists():
    assert trial.PRIMARY_IDENTITY == {
        "kind": "openai_compatible",
        "provider_id": "operator_openai_compatible",
        "base_url": "https://inference-api.nousresearch.com/v1",
        "model": "openai/gpt-6-luna",
        "api_key_env": "LLM_API_KEY",
    }
    assert trial.DECISION_IDENTITY["endpoint"] == "https://api.typesafe.ai/v1/systemone"
    assert trial.DECISION_IDENTITY["model"] == "jev-latest"
    args = trial._command(
        __import__("pathlib").Path("/bin/pr-review"),
        SimpleNamespace(
            repo=__import__("pathlib").Path("/tmp/repo"), base_sha="1" * 40, head_sha="2" * 40, case_id="r1-control"
        ),
        __import__("pathlib").Path("/tmp/profile.json"),
        __import__("pathlib").Path("/tmp/limits.json"),
        __import__("pathlib").Path("/tmp/out"),
        __import__("pathlib").Path("/tmp/provider.json"),
        __import__("pathlib").Path("/tmp/decision.json"),
        dry_run=False,
    )
    assert args[args.index("--max-claim-assessments") + 1] == "4"
    assert args[args.index("--effect-policy") + 1] == "READ_ONLY"
    assert "--endpoint" not in args and "--model" not in args


@pytest.mark.parametrize("wrong_model", ["gpt-6-luna", "openai/gpt-6-luna-paid", "jev-latest"])
def test_other_configured_models_fail_closed(tmp_path, wrong_model):
    path = tmp_path / "provider.json"
    config = dict(trial.PRIMARY_IDENTITY)
    config["model"] = wrong_model
    path.write_text(json.dumps(config), encoding="utf-8")
    try:
        with pytest.raises(trial.SelectedTrialError, match="provider_identity_mismatch"):
            trial._config_identity(path, expected=trial.PRIMARY_IDENTITY, decision=False)
    finally:
        path.unlink(missing_ok=True)
