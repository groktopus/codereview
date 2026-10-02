"""Offline contract tests for the fixed historical PR466 wrapper."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/run_historical_functional_review.py"
SPEC = importlib.util.spec_from_file_location("historical_functional_review", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
review = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(review)


@pytest.fixture(autouse=True)
def isolate_github_actions_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep local test outcomes independent of the runner's event context."""
    for name in (
        "GITHUB_ACTIONS",
        "GITHUB_EVENT_NAME",
        "GITHUB_REF",
        "GITHUB_SHA",
        "GITHUB_WORKFLOW_REF",
    ):
        monkeypatch.delenv(name, raising=False)


def _bare_repo(path: Path) -> tuple[str, str]:
    path.mkdir()
    subprocess.run(["git", "init", "--bare", str(path)], check=True, capture_output=True)
    seed = path.parent / "seed"
    seed.mkdir()
    subprocess.run(["git", "init", str(seed)], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(seed), "config", "user.name", "Test"], check=True)
    subprocess.run(["git", "-C", str(seed), "config", "user.email", "test@example.invalid"], check=True)
    (seed / "case.txt").write_text("base\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(seed), "add", "case.txt"], check=True)
    subprocess.run(["git", "-C", str(seed), "commit", "-m", "base"], check=True, capture_output=True)
    base = subprocess.run(
        ["git", "-C", str(seed), "rev-parse", "HEAD"], check=True, capture_output=True, text=True
    ).stdout.strip()
    (seed / "case.txt").write_text("head\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(seed), "commit", "-am", "head"], check=True, capture_output=True)
    head = subprocess.run(
        ["git", "-C", str(seed), "rev-parse", "HEAD"], check=True, capture_output=True, text=True
    ).stdout.strip()
    subprocess.run(["git", "-C", str(seed), "push", str(path), "HEAD"], check=True, capture_output=True)
    return base, head


def test_target_preflight_requires_bare_repo_and_both_exact_objects(tmp_path: Path, monkeypatch) -> None:
    bare = tmp_path / "target.git"
    base, head = _bare_repo(bare)
    monkeypatch.setattr(review, "BASE", base)
    monkeypatch.setattr(review, "HEAD", head)

    review._validate_target(bare)
    with pytest.raises(review.SafeFailure, match="target_bare_repository_unavailable"):
        review._validate_target(tmp_path / "missing.git")
    with pytest.raises(review.SafeFailure, match="target_bare_repository_unavailable"):
        review._validate_target(bare / "not-a-repository")


@pytest.mark.parametrize("case_id", review.CASE_CHOICES)
def test_actual_prepare_main_uses_only_prepare_boundary_and_no_live_config(
    tmp_path: Path, monkeypatch, capsys, case_id: str
) -> None:
    bare = tmp_path / "target.git"
    base, head = _bare_repo(bare)
    monkeypatch.setattr(review, "BASE", base)
    monkeypatch.setattr(review, "HEAD", head)
    if case_id == "pr466-v6":
        monkeypatch.setattr(review, "V6_PREPARE_OBSERVATION", None)
    monkeypatch.setattr(review, "_validate_source_and_inputs", lambda _case_id, **_kwargs: {})
    monkeypatch.setattr(review, "_limits_valid", lambda _case_id: None)

    config_calls: list[bool] = []

    def configs(directory: Path, *, live: bool, case_id: str) -> tuple[Path, Path, str]:
        config_calls.append(live)
        assert live is False
        return directory / "provider.json", directory / "decision.json", "a" * 64

    cli_calls: list[dict] = []

    def cli(target: Path, output: Path, provider: Path, decision: Path, *, prepare: bool, case_id: str) -> dict:
        cli_calls.append({"target": target, "prepare": prepare, "case_id": case_id})
        assert prepare is True
        if case_id in ("pr466-v2", "pr466-v3", "pr466-v4", "pr466-v5"):
            prepare_observation = review._case_spec(case_id)["prepare_observation"]
            requests = prepare_observation["primary_requests"]
            if case_id in ("pr466-v4", "pr466-v5"):
                projection = review.V4_PROJECTION if case_id == "pr466-v4" else review.V5_PROJECTION
                requests = [
                    {
                        **row,
                        "admitted": True,
                        "context_omissions": [],
                        "evidence_bindings": (
                            [
                                {
                                    key: value
                                    for key, value in projection.items()
                                    if key != "included_primary_task_ids"
                                }
                            ]
                            if row["task_id"] in projection["included_primary_task_ids"]
                            else []
                        ),
                    }
                    for row in requests
                ]
            return {
                "no_provider_calls": True,
                "no_target_code_execution": True,
                "scope": {"primary_scope_admission_complete": True, "required_context_gaps": []},
                "capacity": {
                    "exact_primary_call_demand": prepare_observation["primary_request_count"],
                    "exact_primary_serialized_input_bytes": prepare_observation["total_primary_serialized_input_bytes"],
                },
                "primary_requests": requests,
            }
        if case_id == "pr466-v6":
            scope, _row, result = _v6_prepare_fixture()
            result["scope"] = scope
            result["capacity"] = {
                "exact_primary_call_demand": len(result["primary_requests"]),
                "exact_primary_serialized_input_bytes": sum(
                    row["input_bytes"] for row in result["primary_requests"]
                ),
            }
            return result
        return {
            "no_provider_calls": True,
            "no_target_code_execution": True,
            "scope": {"primary_scope_admission_complete": True},
            "capacity": {"exact_primary_call_demand": 7, "exact_primary_serialized_input_bytes": 353_963},
            "primary_requests": [
                {"input_bytes": value} for value in (49_595, 50_084, 49_564, 55_674, 56_175, 36_640, 56_231)
            ],
        }

    monkeypatch.setattr(review, "_configs", configs)
    monkeypatch.setattr(review, "_cli", cli)
    out = tmp_path / "result"
    monkeypatch.setattr(
        sys,
        "argv",
        [str(SCRIPT), "prepare", "--case", case_id, "--target-bare", str(bare), "--output-dir", str(out)],
    )
    for name in ("LLM_BASE_URL", "LLM_MODEL", "LLM_API_KEY", "JEV_BASE_URL", "JEV_MODEL", "JEV_API_KEY"):
        monkeypatch.setenv(name, "sentinel-must-not-be-used")

    assert review.main() == 0
    assert config_calls == [False]
    assert len(cli_calls) == 1 and cli_calls[0]["prepare"] is True and cli_calls[0]["case_id"] == case_id
    assert cli_calls[0]["target"] == bare.resolve()
    emitted = json.loads(capsys.readouterr().out)
    assert emitted["status"] == "PREPARED_ONLY"
    observation = json.loads((out / "prepare-observation.json").read_text(encoding="utf-8"))
    assert observation["provider_calls"] == 0
    assert observation["target_code_executed"] is False
    assert observation["case_id"] == case_id
    assert observation["capacity"]["exact_primary_call_demand"] == (4 if case_id == "pr466-v6" else 7)
    assert observation["profile_sha256"] == review._case_spec(case_id)["profile_sha256"]


@pytest.mark.parametrize(
    "capacity,requests",
    [
        ({"exact_primary_call_demand": 11, "exact_primary_serialized_input_bytes": 1}, [{"input_bytes": 1}]),
        ({"exact_primary_call_demand": 1, "exact_primary_serialized_input_bytes": 600_001}, [{"input_bytes": 1}]),
        ({"exact_primary_call_demand": 1, "exact_primary_serialized_input_bytes": 1}, [{"input_bytes": 64_001}]),
        ({"exact_primary_call_demand": True, "exact_primary_serialized_input_bytes": 1}, [{"input_bytes": 1}]),
    ],
)
def test_prepare_rejects_out_of_contract_demand_before_review(capacity: dict, requests: list[dict]) -> None:
    with pytest.raises(review.SafeFailure):
        review._validate_prepare(
            {
                "no_provider_calls": True,
                "no_target_code_execution": True,
                "scope": {"primary_scope_admission_complete": True},
                "capacity": capacity,
                "primary_requests": requests,
            }
        )


@pytest.mark.parametrize("case_id", review.CASE_CHOICES)
def test_registered_case_manifest_and_limits_are_exact(case_id: str) -> None:
    manifest = review._validate_source_and_inputs(case_id, allow_unpinned_prepare=case_id == "pr466-v6")
    review._limits_valid(case_id)
    assert manifest["case"]["pull_request_number"] == 466
    assert manifest["historical_checks"]["freshness_basis"] == "HISTORICAL_SNAPSHOT"
    assert manifest["limits"]["sha256"] == review._case_spec(case_id)["limits_sha256"]
    if case_id == "pr466-v1":
        assert "retained_prepare_observation" in manifest
        assert "prepare_observation" not in manifest
    elif case_id != "pr466-v6":
        assert "prepare_observation" in manifest
        assert "retained_prepare_observation" not in manifest
        assert manifest["prepare_observation"] == review._case_spec(case_id)["prepare_observation"]
    else:
        assert manifest["prepare_observation"] == review._case_spec(case_id)["prepare_observation"]


@pytest.mark.parametrize(
    ("case_id", "input_bytes"),
    [
        ("pr466-v1", 64_001),
        ("pr466-v2", 80_001),
        ("pr466-v3", 80_001),
        ("pr466-v4", 80_001),
        ("pr466-v5", 80_001),
        ("pr466-v6", 80_001),
    ],
)
def test_case_specific_request_input_caps_remain_bounded(case_id: str, input_bytes: int) -> None:
    with pytest.raises(review.SafeFailure, match="primary_request_capacity_exceeded"):
        review._validate_prepare(
            {
                "no_provider_calls": True,
                "no_target_code_execution": True,
                "scope": {"primary_scope_admission_complete": True},
                "capacity": {
                    "exact_primary_call_demand": 1,
                    "exact_primary_serialized_input_bytes": input_bytes,
                },
                "primary_requests": [{"input_bytes": input_bytes}],
            },
            case_id,
        )


def test_v2_prepare_observation_descriptors_match_committed_packet() -> None:
    packet = json.loads(review.V2_MANIFEST.read_text(encoding="utf-8"))
    assert review.V2_PREPARE_OBSERVATION == packet["prepare_observation"]


def test_v3_prepare_observation_descriptors_match_committed_packet() -> None:
    packet = json.loads(review.V3_MANIFEST.read_text(encoding="utf-8"))
    assert review.V3_PREPARE_OBSERVATION == packet["prepare_observation"]


def test_v4_prepare_observation_descriptors_match_committed_packet() -> None:
    packet = json.loads(review.V4_MANIFEST.read_text(encoding="utf-8"))
    assert review.V4_PREPARE_OBSERVATION == packet["prepare_observation"]



def test_v5_prepare_observation_descriptors_match_committed_packet() -> None:
    packet = json.loads(review.V5_MANIFEST.read_text(encoding="utf-8"))
    assert review.V5_PREPARE_OBSERVATION == packet["prepare_observation"]


def test_v5_profile_hash_mismatch_fails_closed(monkeypatch) -> None:
    monkeypatch.setattr(review, "V5_PROFILE_SHA256", "0" * 64)
    with pytest.raises(review.SafeFailure, match="case_input_hash_mismatch"):
        review._validate_source_and_inputs("pr466-v5")


def test_v5_case_preserves_v4_checks_limits_and_default() -> None:
    assert review.V5_CHECKS.read_bytes() == review.V4_CHECKS.read_bytes()
    assert review.V5_LIMITS.read_bytes() == review.V4_LIMITS.read_bytes()
    assert review._case_spec("pr466-v5")["input_cap"] == review.V4_INPUT_CAP
    assert review.DEFAULT_CASE == "pr466-v1"


def test_v6_case_preserves_caps_and_binds_required_reconciliation_profile() -> None:
    manifest = json.loads(review.V6_MANIFEST.read_text(encoding="utf-8"))
    profile = json.loads(review.V6_PROFILE.read_text(encoding="utf-8"))
    assert review.V6_CHECKS.read_bytes() == review.V5_CHECKS.read_bytes()
    assert review.V6_LIMITS.read_bytes() == review.V5_LIMITS.read_bytes()
    assert review._case_spec("pr466-v6")["input_cap"] == review.V5_INPUT_CAP
    assert profile["claim_reconciliation"] == {
        "version": "claim-reconciliation.v1",
        "enabled": True,
        "required": True,
        "max_assessments": 1,
    }
    assert manifest["case"] == {
        "repository": review.REPOSITORY,
        "pull_request_number": 466,
        "base_sha": review.BASE,
        "head_sha": review.HEAD,
    }
    assert manifest["diagnostic_scope"]["effect_policy"] == "READ_ONLY"
    assert manifest["diagnostic_scope"]["target_code_execution"] is False
    assert review.DEFAULT_CASE == "pr466-v1"


def test_v6_live_run_rejects_unpinned_runner_descriptor_before_config(monkeypatch) -> None:
    monkeypatch.setattr(review, "V6_PREPARE_OBSERVATION", None)
    with pytest.raises(review.SafeFailure, match="case_prepare_observation_not_pinned_in_runner"):
        review._validate_source_and_inputs("pr466-v6")


def test_v6_provider_config_identity_ignores_key_values_but_pins_endpoint_model_and_options(tmp_path, monkeypatch):
    configured = {
        "LLM_BASE_URL": "https://inference-api.nousresearch.com/v1",
        "LLM_MODEL": "openai/gpt-6-luna",
        "LLM_API_KEY": "trusted-test-key-alpha",
        "JEV_BASE_URL": "https://api.typesafe.ai/v1",
        "JEV_MODEL": "jev-latest",
        "JEV_API_KEY": "trusted-test-key-alpha",
    }
    for name, value in configured.items():
        monkeypatch.setenv(name, value)
    paths = review._configs(tmp_path / "first", live=True, case_id="pr466-v6")
    first_identity = paths[2]

    monkeypatch.setenv("LLM_API_KEY", "trusted-test-key-beta")
    monkeypatch.setenv("JEV_API_KEY", "trusted-test-key-beta")
    paths = review._configs(tmp_path / "second", live=True, case_id="pr466-v6")
    assert paths[2] == first_identity

    monkeypatch.setenv("LLM_MODEL", "unapproved-model")
    with pytest.raises(review.SafeFailure, match="v6_provider_configuration_identity_mismatch"):
        review._configs(tmp_path / "rejected", live=True, case_id="pr466-v6")


def _v6_prepare_fixture():
    lenses = ("correctness", "tests", "maintainability", "security")
    planned_scopes = []
    scope = {
        "primary_scope_admission_complete": True,
        "required_context_gaps": [],
        "admitted_obligation_ids": [],
        "unadmitted_obligation_ids": [],
        "uncovered_or_unadmitted_units": [],
        "skipped_units": [],
        "planned_obligations": 15,
    }
    rows = []
    for index, lens in enumerate(lenses):
        evidence_id = f"evidence-{index}"
        task_id = f"task-example-{index}"
        unit_id = f"unit-example-{index}"
        obligation_id = f"unit:{unit_id}:lens:{lens}"
        scope["admitted_obligation_ids"].append(obligation_id)
        planned_scopes.append(
            {
                "task_id": task_id,
                "task_kind": "SPECIALIST_FINDINGS",
                "lens": lens,
                "unit_ids": [unit_id],
                "obligation_ids": [obligation_id],
                "required_context_ids": [evidence_id],
                "evidence_ids": [evidence_id],
            }
        )
        rows.append(
            {
                "task_id": f"{task_id}:chunk-1",
                "lens": lens,
                "input_bytes": 20,
                "input_sha256": f"{index + 1:x}" * 64,
                "admitted": True,
                "unit_ids": [unit_id],
                "obligation_ids": [obligation_id],
                "evidence_ids": [evidence_id],
                "evidence_bindings": [
                    {
                        "evidence_id": evidence_id,
                        "path": "src/example.py",
                        "source_revision": review.HEAD,
                        "content_hash": "d" * 64,
                        "source_kind": "profile_context",
                        "trust": "repository_evidence",
                        "content_bytes": 1,
                    }
                ],
                "required_context_omissions": [],
            }
        )
    scope["admitted_obligation_ids"].extend(f"check:fixture-{index}" for index in range(11))
    scope["coverage_obligations"] = [
        {"obligation_id": obligation_id}
        for obligation_id in scope["admitted_obligation_ids"]
    ]
    scope["planned_task_scopes"] = planned_scopes
    result = {
        "no_provider_calls": True,
        "no_target_code_execution": True,
        "scope": scope,
        "capacity": {"exact_primary_call_demand": len(rows), "exact_primary_serialized_input_bytes": 20 * len(rows)},
        "primary_requests": rows,
    }
    return scope, rows, result


def test_v6_first_prepare_rejects_required_context_gaps_before_observation(monkeypatch):
    scope, _rows, result = _v6_prepare_fixture()
    scope["required_context_gaps"] = [{"required": True, "reason": "missing"}]
    monkeypatch.setattr(review, "V6_PREPARE_OBSERVATION", None)
    with pytest.raises(review.SafeFailure, match="case_required_context_gaps_present"):
        review._validate_prepare(result, "pr466-v6", reference_observation=True)


@pytest.mark.parametrize("mutation", ["extra_lens", "unplanned_task", "missing_required_lens", "omitted_binding"])
def test_v6_first_prepare_binds_requests_to_trusted_planned_specialist_scopes(monkeypatch, mutation):
    scope, rows, result = _v6_prepare_fixture()
    monkeypatch.setattr(review, "V6_PREPARE_OBSERVATION", None)
    if mutation == "extra_lens":
        rows[3]["lens"] = "unplanned"
    elif mutation == "unplanned_task":
        rows[3]["task_id"] = "task-not-in-plan:chunk-1"
    elif mutation == "missing_required_lens":
        rows[0]["lens"] = "security"
    else:
        rows[0]["evidence_bindings"] = []
    with pytest.raises(review.SafeFailure, match="case_prepare_observation_mismatch"):
        review._validate_prepare(result, "pr466-v6", reference_observation=True)


@pytest.mark.parametrize("mutation", ["request_hash", "reported_scope"])
def test_v6_live_prepare_binds_exact_body_hash_and_complete_scope(monkeypatch, mutation):
    scope, rows, result = _v6_prepare_fixture()
    monkeypatch.setattr(
        review,
        "V6_PREPARE_OBSERVATION",
        {
            "primary_requests": [
                {key: row[key] for key in ("task_id", "lens", "input_bytes", "input_sha256")}
                for row in rows
            ],
            "scope": scope,
        },
    )
    if mutation == "request_hash":
        result["primary_requests"][0]["input_sha256"] = "b" * 64
    else:
        result["scope"] = {**scope, "admitted_obligations": 0}
    with pytest.raises(review.SafeFailure, match="case_prepare_observation_mismatch"):
        review._validate_prepare(result, "pr466-v6", reference_observation=False)

def test_prepare_rejects_missing_execution_invariants() -> None:
    with pytest.raises(review.SafeFailure, match="prepare_invariant_failed"):
        review._validate_prepare(
            {
                "no_provider_calls": False,
                "no_target_code_execution": True,
                "capacity": {"exact_primary_call_demand": 1, "exact_primary_serialized_input_bytes": 1},
                "primary_requests": [{"input_bytes": 1}],
            }
        )


@pytest.mark.parametrize("scope", [None, {}, {"primary_scope_admission_complete": False}])
def test_prepare_rejects_missing_primary_scope_admission(scope: dict | None) -> None:
    result = {
        "no_provider_calls": True,
        "no_target_code_execution": True,
        "capacity": {"exact_primary_call_demand": 1, "exact_primary_serialized_input_bytes": 1},
        "primary_requests": [{"input_bytes": 1}],
    }
    if scope is not None:
        result["scope"] = scope
    with pytest.raises(review.SafeFailure, match="primary_request_capacity_exceeded"):
        review._validate_prepare(result)


def test_bad_fixed_input_hash_fails_before_configuration_or_cli(tmp_path: Path, monkeypatch, capsys) -> None:
    bad_checks = tmp_path / "bad-checks.json"
    bad_checks.write_text("{}\n", encoding="utf-8")
    monkeypatch.setattr(review, "CHECKS", bad_checks)
    monkeypatch.setattr(review, "_configs", lambda *args, **kwargs: pytest.fail("config reached before input hash"))
    monkeypatch.setattr(review, "_cli", lambda *args, **kwargs: pytest.fail("CLI reached before input hash"))
    monkeypatch.setattr(
        sys,
        "argv",
        [str(SCRIPT), "prepare", "--target-bare", str(tmp_path), "--output-dir", str(tmp_path / "out")],
    )

    assert review.main() == 2
    assert "case_input_hash_mismatch" in capsys.readouterr().err
    assert not (tmp_path / "out").exists()


def test_v2_profile_hash_mismatch_fails_closed(monkeypatch) -> None:
    monkeypatch.setattr(review, "V2_PROFILE_SHA256", "0" * 64)
    with pytest.raises(review.SafeFailure, match="case_input_hash_mismatch"):
        review._validate_source_and_inputs("pr466-v2")


def test_v3_profile_hash_mismatch_fails_closed(monkeypatch) -> None:
    monkeypatch.setattr(review, "V3_PROFILE_SHA256", "0" * 64)
    with pytest.raises(review.SafeFailure, match="case_input_hash_mismatch"):
        review._validate_source_and_inputs("pr466-v3")


def test_v4_profile_hash_mismatch_fails_closed(monkeypatch) -> None:
    monkeypatch.setattr(review, "V4_PROFILE_SHA256", "0" * 64)
    with pytest.raises(review.SafeFailure, match="case_input_hash_mismatch"):
        review._validate_source_and_inputs("pr466-v4")


def test_v3_case_uses_v2_checks_and_limits_without_changing_caps() -> None:
    assert review.V3_CHECKS.read_bytes() == review.V2_CHECKS.read_bytes()
    assert review.V3_LIMITS.read_bytes() == review.V2_LIMITS.read_bytes()
    assert review._case_spec("pr466-v3")["input_cap"] == review.V2_INPUT_CAP
    assert review.DEFAULT_CASE == "pr466-v1"


def test_v4_case_preserves_v3_checks_limits_and_default() -> None:
    assert review.V4_CHECKS.read_bytes() == review.V3_CHECKS.read_bytes()
    assert review.V4_LIMITS.read_bytes() == review.V3_LIMITS.read_bytes()
    assert review._case_spec("pr466-v4")["input_cap"] == review.V3_INPUT_CAP
    assert review.DEFAULT_CASE == "pr466-v1"


def _valid_v4_prepare_result() -> dict:
    requests = []
    for row in review.V4_PREPARE_OBSERVATION["primary_requests"]:
        requests.append(
            {
                **row,
                "admitted": True,
                "context_omissions": [],
                "evidence_bindings": (
                    [{key: value for key, value in review.V4_PROJECTION.items() if key != "included_primary_task_ids"}]
                    if row["task_id"] in review.V4_PROJECTION["included_primary_task_ids"]
                    else []
                ),
            }
        )
    return {
        "no_provider_calls": True,
        "no_target_code_execution": True,
        "scope": {"primary_scope_admission_complete": True, "required_context_gaps": []},
        "capacity": {
            "exact_primary_call_demand": len(requests),
            "exact_primary_serialized_input_bytes": review.V4_PREPARE_OBSERVATION[
                "total_primary_serialized_input_bytes"
            ],
        },
        "primary_requests": requests,
    }


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("missing", "dependency_projection_required_context_invalid"),
        ("wrong_revision", "dependency_projection_required_context_invalid"),
        ("wrong_hash", "dependency_projection_required_context_invalid"),
        ("required_gap", "dependency_projection_required_context_invalid"),
    ],
)
def test_v4_requires_exact_head_dependency_projection(mutation: str, message: str) -> None:
    result = _valid_v4_prepare_result()
    if mutation == "missing":
        result["primary_requests"][0]["evidence_bindings"] = []
    elif mutation == "wrong_revision":
        result["primary_requests"][0]["evidence_bindings"][0]["source_revision"] = "0" * 40
    elif mutation == "wrong_hash":
        result["primary_requests"][0]["evidence_bindings"][0]["content_hash"] = "0" * 64
    else:
        result["scope"]["required_context_gaps"] = ["required-dependency-context-missing"]
    with pytest.raises(review.SafeFailure, match=message):
        review._validate_prepare(result, "pr466-v4")


def test_v4_live_prepare_allows_provider_specific_sizes_without_changing_scope() -> None:
    result = _valid_v4_prepare_result()
    for request in result["primary_requests"]:
        request["input_bytes"] += 1
        request["input_sha256"] = "a" * 64
    result["capacity"]["exact_primary_serialized_input_bytes"] += len(result["primary_requests"])
    with pytest.raises(review.SafeFailure, match="case_prepare_observation_mismatch"):
        review._validate_prepare(result, "pr466-v4")
    review._validate_prepare(result, "pr466-v4", reference_observation=False)



def _valid_v5_prepare_result() -> dict:
    requests = []
    for row in review.V5_PREPARE_OBSERVATION["primary_requests"]:
        requests.append(
            {
                **row,
                "admitted": True,
                "context_omissions": [],
                "evidence_bindings": (
                    [{key: value for key, value in review.V5_PROJECTION.items() if key != "included_primary_task_ids"}]
                    if row["task_id"] in review.V5_PROJECTION["included_primary_task_ids"]
                    else []
                ),
            }
        )
    return {
        "no_provider_calls": True,
        "no_target_code_execution": True,
        "scope": {"primary_scope_admission_complete": True, "required_context_gaps": []},
        "capacity": {
            "exact_primary_call_demand": len(requests),
            "exact_primary_serialized_input_bytes": review.V5_PREPARE_OBSERVATION[
                "total_primary_serialized_input_bytes"
            ],
        },
        "primary_requests": requests,
    }


@pytest.mark.parametrize(
    "mutation",
    ["missing", "wrong_revision", "wrong_hash", "required_gap"],
)
def test_v5_requires_exact_head_dependency_projection(mutation: str) -> None:
    result = _valid_v5_prepare_result()
    if mutation == "missing":
        result["primary_requests"][0]["evidence_bindings"] = []
    elif mutation == "wrong_revision":
        result["primary_requests"][0]["evidence_bindings"][0]["source_revision"] = "0" * 40
    elif mutation == "wrong_hash":
        result["primary_requests"][0]["evidence_bindings"][0]["content_hash"] = "0" * 64
    else:
        result["scope"]["required_context_gaps"] = ["required-dependency-context-missing"]
    with pytest.raises(review.SafeFailure, match="dependency_projection_required_context_invalid"):
        review._validate_prepare(result, "pr466-v5")


def test_v5_live_prepare_allows_provider_specific_sizes_without_changing_scope() -> None:
    result = _valid_v5_prepare_result()
    for request in result["primary_requests"]:
        request["input_bytes"] += 1
        request["input_sha256"] = "a" * 64
    result["capacity"]["exact_primary_serialized_input_bytes"] += len(result["primary_requests"])
    with pytest.raises(review.SafeFailure, match="case_prepare_observation_mismatch"):
        review._validate_prepare(result, "pr466-v5")
    review._validate_prepare(result, "pr466-v5", reference_observation=False)

def test_custom_manifest_directory_cannot_replace_registered_case(tmp_path: Path, monkeypatch, capsys) -> None:
    monkeypatch.setattr(review, "_configs", lambda *args, **kwargs: pytest.fail("config reached before case binding"))
    monkeypatch.setattr(
        sys,
        "argv",
        [
            str(SCRIPT),
            "prepare",
            "--case",
            "pr466-v2",
            "--manifest-dir",
            str(tmp_path),
            "--target-bare",
            str(tmp_path),
            "--output-dir",
            str(tmp_path / "out"),
        ],
    )
    assert review.main() == 2
    assert "manifest_directory_not_trusted" in capsys.readouterr().err


def test_source_context_guard_rejects_wrong_repository_and_workflow_before_inputs(monkeypatch) -> None:
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_REPOSITORY", "attacker/repo")
    monkeypatch.setenv("GITHUB_REF", "refs/heads/main")
    monkeypatch.setenv(
        "GITHUB_WORKFLOW_REF",
        "attacker/repo/.github/workflows/historical-functional-review.yml@refs/heads/main",
    )
    with pytest.raises(review.SafeFailure, match="untrusted_source_context"):
        review._validate_source_and_inputs("pr466-v2")


def test_source_context_guard_rejects_stale_dispatch_revision(monkeypatch) -> None:
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_REPOSITORY", "groktopus/codereview")
    monkeypatch.setenv("GITHUB_REF", "refs/heads/main")
    monkeypatch.setenv(
        "GITHUB_WORKFLOW_REF",
        "groktopus/codereview/.github/workflows/historical-functional-review.yml@refs/heads/main",
    )
    monkeypatch.setenv("GITHUB_SHA", "a" * 40)
    with pytest.raises(review.SafeFailure, match="untrusted_source_revision"):
        review._validate_source_and_inputs("pr466-v2")


def test_run_with_untrusted_dispatch_context_fails_before_configuration(tmp_path: Path, monkeypatch, capsys) -> None:
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_EVENT_NAME", "workflow_dispatch")
    monkeypatch.setenv("GITHUB_REF", "refs/heads/attacker-branch")
    monkeypatch.setattr(review, "_configs", lambda *args, **kwargs: pytest.fail("config reached before source gate"))
    monkeypatch.setattr(review, "_cli", lambda *args, **kwargs: pytest.fail("CLI reached before source gate"))
    monkeypatch.setattr(
        sys,
        "argv",
        [str(SCRIPT), "run", "--target-bare", str(tmp_path), "--output-dir", str(tmp_path / "out")],
    )

    assert review.main() == 2
    assert "live_mode_requires_trusted_workflow_dispatch" in capsys.readouterr().err
    assert not (tmp_path / "out").exists()


def test_non_object_manifest_fails_with_sanitized_reason(tmp_path: Path, monkeypatch) -> None:
    malformed = tmp_path / "manifest.json"
    malformed.write_text("[]\n", encoding="utf-8")
    monkeypatch.setattr(review, "MANIFEST", malformed)

    with pytest.raises(review.SafeFailure, match="case_manifest_invalid"):
        review._validate_source_and_inputs()


def test_cli_child_has_explicit_case_and_strips_ambient_event_and_auth(tmp_path: Path, monkeypatch) -> None:
    seen: dict = {}

    class Completed:
        returncode = 0
        stdout = '{"no_provider_calls":true,"no_target_code_execution":true}'

    def run(command: list[str], **kwargs) -> Completed:
        seen["command"] = command
        seen["env"] = kwargs["env"]
        seen["timeout"] = kwargs["timeout"]
        return Completed()

    monkeypatch.setattr(review.subprocess, "run", run)
    for name in (
        "GITHUB_EVENT_PATH",
        "GITHUB_TOKEN",
        "GH_TOKEN",
        "ACTIONS_RUNTIME_TOKEN",
        "ACTIONS_RUNTIME_URL",
        "ACTIONS_RESULTS_URL",
    ):
        monkeypatch.setenv(name, "ambient-sentinel")

    result = review._cli(
        tmp_path / "target.git", tmp_path / "out", tmp_path / "provider", tmp_path / "decision", prepare=True
    )
    assert result["no_provider_calls"] is True
    assert "--historical-checks-json" in seen["command"]
    assert "--prepare-only" in seen["command"]
    assert "--max-claim-assessments" in seen["command"]
    assert "--github-pr" not in seen["command"]
    assert seen["timeout"] == 630
    assert all(
        name not in seen["env"]
        for name in (
            "GITHUB_EVENT_PATH",
            "GITHUB_TOKEN",
            "GH_TOKEN",
            "ACTIONS_RUNTIME_TOKEN",
            "ACTIONS_RUNTIME_URL",
            "ACTIONS_RESULTS_URL",
        )
    )


def test_workflow_uses_trusted_checkout_and_exact_artifact_allowlists() -> None:
    workflow = yaml.load(
        (ROOT / ".github/workflows/historical-functional-review.yml").read_text(encoding="utf-8"),
        Loader=yaml.BaseLoader,
    )
    jobs = workflow["jobs"]
    choice = workflow["on"]["workflow_dispatch"]["inputs"]["case"]
    assert choice["type"] == "choice"
    assert choice["default"] == review.DEFAULT_CASE
    assert choice["options"] == list(review.CASE_CHOICES)
    prepare = jobs["prepare"]
    live = jobs["live-diagnostic"]

    for job in (prepare, live):
        checkout = next(step for step in job["steps"] if step.get("uses", "").startswith("actions/checkout@"))
        assert checkout["with"]["ref"] == "${{ github.sha }}"
        assert checkout["with"]["persist-credentials"] == "false"

    prepare_upload = next(
        step for step in prepare["steps"] if step.get("uses", "").startswith("actions/upload-artifact@")
    )
    live_upload = next(step for step in live["steps"] if step.get("uses", "").startswith("actions/upload-artifact@"))
    assert prepare_upload["with"]["path"] == "${{ runner.temp }}/pr466-prepare/prepare-observation.json"
    assert live_upload["with"]["path"].splitlines() == [
        "${{ runner.temp }}/pr466-review/review-result.json",
        "${{ runner.temp }}/pr466-review/review-report.md",
    ]
    assert live["if"].startswith("inputs.execute_live == true")
    for job in (prepare, live):
        invocation = next(
            step["run"] for step in job["steps"] if "run_historical_functional_review.py" in step.get("run", "")
        )
        assert '--case "$CASE_ID"' in invocation
