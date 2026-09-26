from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from scripts import run_test_matrix as matrix


def _catalog(path: Path, *, retrieved_at: datetime | None = None, prompt: str = "0") -> Path:
    retrieved_at = retrieved_at or datetime.now(timezone.utc)
    content = {
        "retrieved_at": retrieved_at.isoformat(),
        "source": matrix.FREE_ENDPOINT + "/models",
        "catalog": {
            "data": [
                {"id": model["model_id"], "pricing": {"prompt": prompt, "completion": "0"}}
                for model in matrix.MODEL_ALLOWLIST.values()
            ]
        },
    }
    path.write_text(json.dumps(content), encoding="utf-8")
    return path


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True).stdout.strip()


def _repo_with_pair(path: Path) -> tuple[str, str]:
    subprocess.run(["git", "init", str(path)], check=True, capture_output=True)
    _git(path, "config", "user.email", "runner-test@example.invalid")
    _git(path, "config", "user.name", "Runner Test")
    (path / "reviewed.txt").write_text("before\n", encoding="utf-8")
    _git(path, "add", "reviewed.txt")
    _git(path, "commit", "-m", "base")
    base = _git(path, "rev-parse", "HEAD")
    (path / "reviewed.txt").write_text("after\n", encoding="utf-8")
    _git(path, "commit", "-am", "head")
    return base, _git(path, "rev-parse", "HEAD")


def test_resolve_pairs_preserves_six_pilot_and_explicit_pair_distinction(tmp_path):
    repo = tmp_path / "history"
    base, head = _repo_with_pair(repo)
    source_kind, explicit = matrix.resolve_pairs(repo, sample=None, explicit_pairs=[f"{base}..{head}"])
    assert source_kind == "EXPLICIT_REVISION_PAIRS"
    assert explicit[0]["sample_id"] == "operator-supplied"
    assert explicit[0]["base_sha"] == base and explicit[0]["head_sha"] == head
    assert len(matrix.HISTORICAL_PAIRS) == 6
    assert len(set(matrix.HISTORICAL_PAIRS)) == 6
    with pytest.raises(matrix.MatrixError, match="select_one_sample_or_explicit_pairs"):
        matrix.resolve_pairs(repo, sample="historical-pilot-v1", explicit_pairs=[f"{base}..{head}"])


def test_catalog_requires_fresh_exact_zero_price_model_ids(tmp_path):
    path = _catalog(tmp_path / "models.json")
    evidence = matrix.verify_model_catalog(path, ["solar", "stepfun"])
    assert evidence["selected_models"]["solar"]["model_id"] == "upstage/solar-pro4:free"
    assert evidence["selected_models"]["stepfun"]["catalog_prompt_price"] == "0"
    assert evidence["sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
    assert evidence["age_seconds_at_preflight"] < 5


def test_catalog_fails_closed_when_stale_or_not_free(tmp_path):
    stale = _catalog(tmp_path / "stale.json", retrieved_at=datetime.now(timezone.utc) - timedelta(hours=1))
    with pytest.raises(matrix.MatrixError, match="model_catalog_stale"):
        matrix.verify_model_catalog(stale, ["solar"], max_age_seconds=60)
    paid = _catalog(tmp_path / "paid.json", prompt="0.0001")
    with pytest.raises(matrix.MatrixError, match="allowlisted_model_not_free_in_catalog"):
        matrix.verify_model_catalog(paid, ["solar"])


def test_safe_summary_preserves_model_metering_and_unknown_billing_without_raw_findings():
    result = {
        "disposition": "REVIEW_REQUIRED",
        "coverage_state": "PARTIAL",
        "snapshot_id": "snap-1",
        "findings": [{"observation": "private source detail"}],
        "task_results": {
            "task-1": {
                "status": "INVALID",
                "error_code": "INVALID_PROVIDER_RESULT",
                "quarantined_items": [
                    {
                        "kind": "context_gap_proposals",
                        "index": 0,
                        "reason_code": "invalid_context_gap_target",
                        "item_hash": "c" * 64,
                    }
                ],
                "provider_error_meta": {
                    "usage": {"prompt_tokens": 41, "completion_tokens": 7, "total_tokens": 48},
                    "provenance": {
                        "provider_reported_model_id": "solar-revision-4",
                        "estimated_cost_usd": 0,
                        "billed_cost_usd": None,
                        "billed_cost_known": False,
                    },
                },
            }
        },
    }
    summary = matrix.safe_result_summary(result, {"model": "upstage/solar-pro4:free"})
    assert summary["provider_reported_model_ids"] == ["solar-revision-4"]
    assert summary["usage"] == {"prompt_tokens": 41, "completion_tokens": 7, "total_tokens": 48, "known": True}
    assert summary["provider_estimated_cost_usd"] == "0"
    assert summary["provider_billed_cost_usd"] is None
    assert summary["provider_billed_cost_known"] is False
    assert summary["provider_error_codes"] == {"INVALID_PROVIDER_RESULT": 1}
    assert summary["quarantined_items_by_kind"] == {"context_gap_proposals": 1}
    assert summary["quarantine_reason_codes"] == {"invalid_context_gap_target": 1}
    assert "private source detail" not in repr(summary)


def test_invoke_cli_keeps_failure_output_hash_only_and_enforces_absolute_deadline():
    failure = matrix.invoke_cli(
        [sys.executable, "-c", "print('sensitive provider echo'); raise SystemExit(9)"],
        env=dict(os.environ),
        cwd=Path.cwd(),
        timeout_seconds=3,
    )
    assert failure["run_status"] == "CLI_FAILED"
    assert failure["stdout_bytes"] > 0
    assert len(failure["stdout_sha256"]) == 64
    assert failure.get("cli_result") is None
    assert "sensitive provider echo" not in repr(failure)

    started = time.monotonic()
    timeout = matrix.invoke_cli(
        [sys.executable, "-c", "import time; time.sleep(3)"],
        env=dict(os.environ),
        cwd=Path.cwd(),
        timeout_seconds=0.1,
    )
    assert timeout["run_status"] == "RUN_TIMEOUT"
    assert time.monotonic() - started < 2


def test_minimal_child_environment_passes_only_named_transport_credential(tmp_path):
    env = matrix.minimal_child_env(
        {
            "PATH": "/bin",
            "NOUS_API_KEY": "transport-secret",
            "OTHER_TOKEN": "must-not-pass",
            "HOME": "/untrusted/home",
        },
        secret_name="NOUS_API_KEY",
        home=tmp_path / "isolated",
        module_mode=True,
    )
    assert env == {
        "PATH": "/bin",
        "HOME": str(tmp_path / "isolated"),
        "PYTHONPATH": str(matrix.ROOT / "src"),
        "NOUS_API_KEY": "transport-secret",
    }


def test_matrix_rotates_models_records_hashes_and_never_invents_cost_cap(tmp_path):
    repo = tmp_path / "source"
    base, head = _repo_with_pair(repo)
    profile = tmp_path / "profile.json"
    profile.write_text('{"version":"p1","required_lenses":["correctness"]}', encoding="utf-8")
    output = tmp_path / "results"
    catalog = _catalog(tmp_path / "catalog.json")
    calls = []

    def invoke(command, *, env, cwd, timeout_seconds):
        config_path = Path(command[command.index("--provider-config") + 1])
        limits_path = Path(command[command.index("--limits") + 1])
        config = json.loads(config_path.read_text(encoding="utf-8"))
        limits = json.loads(limits_path.read_text(encoding="utf-8"))
        assert "max_cost_microunits_per_call" not in config
        assert "max_cost_microunits" not in limits
        assert env[config["api_key_env"]] == "transport-secret"
        assert "OTHER_TOKEN" not in env
        calls.append(config["model"])
        return {
            "run_status": "CLI_COMPLETED",
            "exit_code": 0,
            "elapsed_ms": 25.0,
            "stdout_bytes": 80,
            "stderr_bytes": 0,
            "stdout_sha256": "a" * 64,
            "stderr_sha256": "b" * 64,
            "cli_result": {"disposition": "REVIEW_REQUIRED", "task_results": {}, "findings": []},
        }

    first_pair = {"pair_id": "pair-01", "base_sha": base, "head_sha": head}
    second_pair = {"pair_id": "pair-02", "base_sha": base, "head_sha": head}
    manifest = matrix.run_matrix(
        repo=repo,
        profile_path=profile,
        output=output,
        pairs=[first_pair, second_pair],
        sample_kind="EXPLICIT_REVISION_PAIRS",
        model_keys=["solar", "stepfun"],
        per_run_timeout=10,
        matrix_timeout=60,
        model_catalog_path=catalog,
        invoke=invoke,
        environment={"PATH": "/bin", "NOUS_API_KEY": "transport-secret", "OTHER_TOKEN": "must-not-pass"},
        matrix_id="test-rotation",
        source_probe=lambda: {"tree_hash": "fixed-source", "git_revision": "fixed-revision"},
    )
    assert calls == [
        "upstage/solar-pro4:free",
        "stepfun/step-3.7-flash:free",
        "stepfun/step-3.7-flash:free",
        "upstage/solar-pro4:free",
    ]
    assert manifest["status"] == "COMPLETE"
    assert manifest["sample_kind"] == "EXPLICIT_REVISION_PAIRS"
    assert manifest["model_catalog"]["sha256"] == hashlib.sha256(catalog.read_bytes()).hexdigest()
    assert manifest["runtime"]["actual_runtime_source"] == "workspace_source_tree"
    assert manifest["summary"]["completed_runs"] == 4
    assert all(row["provider_config_sha256"] and row["limits_sha256"] for row in manifest["runs"])
    assert "cost_limit_microunits" not in manifest["limits"]
    serialized = json.dumps(manifest)
    assert "transport-secret" not in serialized


def test_matrix_stops_and_marks_run_when_runtime_source_changes(tmp_path):
    repo = tmp_path / "source"
    base, head = _repo_with_pair(repo)
    profile = tmp_path / "profile.json"
    profile.write_text('{"version":"p1"}', encoding="utf-8")
    calls = []
    probes = iter(
        [
            {"tree_hash": "initial"},
            {"tree_hash": "initial"},
            {"tree_hash": "changed"},
        ]
    )

    def source_probe():
        return next(probes)

    def invoke(*_args, **_kwargs):
        calls.append(True)
        return {"run_status": "CLI_COMPLETED", "exit_code": 0, "elapsed_ms": 1, "cli_result": {}}

    manifest = matrix.run_matrix(
        repo=repo,
        profile_path=profile,
        output=tmp_path / "results",
        pairs=[{"pair_id": "pair-01", "base_sha": base, "head_sha": head}],
        sample_kind="EXPLICIT_REVISION_PAIRS",
        model_keys=["solar", "stepfun"],
        per_run_timeout=10,
        matrix_timeout=60,
        model_catalog_path=_catalog(tmp_path / "catalog.json"),
        invoke=invoke,
        environment={"NOUS_API_KEY": "transport-secret"},
        matrix_id="mutating-source",
        source_probe=source_probe,
    )
    assert calls == [True]
    assert manifest["source_integrity"] == "MUTATED"
    assert manifest["runs"][0]["run_status"] == "SOURCE_OR_CONFIGURATION_MUTATED_DURING_RUN"
    assert manifest["summary"]["run_status_counts"]["SKIPPED_SOURCE_MUTATION"] == 1


def _check_document(repository: str, pull_request_number: int, base_sha: str, head_sha: str) -> dict:
    return {
        "schema_version": "1.0",
        "repository": repository,
        "pull_request_number": pull_request_number,
        "base_sha": base_sha,
        "head_sha": head_sha,
        "captured_at": "2026-09-26T12:00:00Z",
        "complete": True,
        "runs": [],
    }


def test_checks_evidence_preflight_binds_profile_repository_and_pair_head(tmp_path):
    repo = tmp_path / "history"
    base, head = _repo_with_pair(repo)
    pair = {"pair_id": "pair-01", "base_sha": base, "head_sha": head}
    profile = {"repository": "owner/project"}
    checks = tmp_path / "checks.json"
    checks.write_text(json.dumps(_check_document("owner/project", 7, base, head)), encoding="utf-8")

    loaded = matrix.load_check_evidence_by_pair({"pair-01": checks}, [pair], profile)

    assert loaded["pair-01"]["repository"] == "owner/project"
    assert loaded["pair-01"]["pull_request_number"] == 7
    assert loaded["pair-01"]["base_sha"] == base
    assert loaded["pair-01"]["head_sha"] == head
    assert loaded["pair-01"]["sha256"] == hashlib.sha256(checks.read_bytes()).hexdigest()


@pytest.mark.parametrize(
    ("mutation", "error_code"),
    [
        ("repository", "check_evidence_repository_or_head_mismatch"),
        ("head", "check_evidence_repository_or_head_mismatch"),
        ("base", "check_evidence_base_mismatch"),
        ("boolean_pr", "check_evidence_pull_request_invalid"),
        ("unknown_pair", "check_evidence_pair_id_unknown"),
        ("profile_repository_missing", "check_evidence_requires_trusted_profile_repository"),
        ("duplicate_key", "check_evidence_json_duplicate_key"),
        ("nonfinite", "check_evidence_json_invalid"),
        ("overflow_float", "check_evidence_json_invalid"),
        ("deep_json", "check_evidence_json_invalid"),
        ("oversize", "check_evidence_size_limit_exceeded"),
    ],
)
def test_checks_evidence_preflight_rejects_identity_mismatches(tmp_path, mutation, error_code):
    repo = tmp_path / "history"
    base, head = _repo_with_pair(repo)
    pair = {"pair_id": "pair-01", "base_sha": base, "head_sha": head}
    profile = {"repository": "owner/project"}
    document = _check_document("owner/project", 7, base, head)
    if mutation == "repository":
        document["repository"] = "owner/other"
    elif mutation == "head":
        document["head_sha"] = "d" * 40
    elif mutation == "base":
        document["base_sha"] = "e" * 40
    elif mutation == "boolean_pr":
        document["pull_request_number"] = True
    checks = tmp_path / "checks.json"
    if mutation == "duplicate_key":
        checks.write_text('{"schema_version":"1.0","schema_version":"1.0"}', encoding="utf-8")
    elif mutation == "nonfinite":
        checks.write_text('{"value":NaN}', encoding="utf-8")
    elif mutation == "overflow_float":
        checks.write_text('{"value":1e9999}', encoding="utf-8")
    elif mutation == "deep_json":
        checks.write_text("[" * 2_000 + "0" + "]" * 2_000, encoding="utf-8")
    elif mutation == "oversize":
        checks.write_text(" " * (matrix.MAX_CHECK_EVIDENCE_BYTES + 1), encoding="utf-8")
    else:
        checks.write_text(json.dumps(document), encoding="utf-8")
    pair_id = "pair-other" if mutation == "unknown_pair" else "pair-01"
    if mutation == "profile_repository_missing":
        profile = {}

    with pytest.raises(matrix.MatrixError, match=error_code):
        matrix.load_check_evidence_by_pair({pair_id: checks}, [pair], profile)


def test_matrix_stages_checks_for_only_explicit_pair_and_hashes_input_identity(tmp_path):
    repo = tmp_path / "history"
    base, head = _repo_with_pair(repo)
    profile = tmp_path / "profile.json"
    profile.write_text(json.dumps({"version": "p1", "repository": "owner/project"}), encoding="utf-8")
    checks = tmp_path / "checks.json"
    document = _check_document("owner/project", 7, base, head)
    document.pop("base_sha")
    checks.write_text(json.dumps(document), encoding="utf-8")
    output = tmp_path / "results"
    catalog = _catalog(tmp_path / "catalog.json")
    observed = []

    def invoke(command, *, env, cwd, timeout_seconds):
        assert "--event-file" not in command
        assert "--github-pr" not in command
        if "--historical-checks-json" in command:
            checks_path = Path(command[command.index("--historical-checks-json") + 1])
            document = json.loads(checks_path.read_text(encoding="utf-8"))
            assert document["repository"] == "owner/project"
            assert document["head_sha"] == head
            observed.append({"checks": True, "bytes_sha256": hashlib.sha256(checks_path.read_bytes()).hexdigest()})
        else:
            observed.append({"checks": False})
        return {
            "run_status": "CLI_COMPLETED",
            "exit_code": 0,
            "elapsed_ms": 10,
            "stdout_bytes": 40,
            "stderr_bytes": 0,
            "stdout_sha256": "a" * 64,
            "stderr_sha256": "b" * 64,
            "cli_result": {
                "disposition": "INCOMPLETE",
                "coverage_state": "PARTIAL",
                "task_results": {},
                "findings": [],
                "coverage_ledger": [
                    {
                        "obligation_kind": "PROJECT_CHECK",
                        "obligation_id": "check:tests",
                        "check_binding_id": "external:tests",
                        "state": "COMPLETE" if observed[-1]["checks"] else "PARTIAL",
                        "reason_code": "VALID_RESULT" if observed[-1]["checks"] else "MISSING_RESULT",
                        "evidence_refs": ["check-evidence"] if observed[-1]["checks"] else [],
                    }
                ],
            },
        }

    pairs = [
        {"pair_id": "pair-01", "base_sha": base, "head_sha": head},
        {"pair_id": "pair-02", "base_sha": base, "head_sha": head},
    ]
    manifest = matrix.run_matrix(
        repo=repo,
        profile_path=profile,
        output=output,
        pairs=pairs,
        sample_kind="EXPLICIT_REVISION_PAIRS",
        model_keys=["solar"],
        per_run_timeout=10,
        matrix_timeout=60,
        model_catalog_path=catalog,
        invoke=invoke,
        environment={"PATH": "/bin", "NOUS_API_KEY": "transport-secret"},
        matrix_id="check-evidence-matrix",
        source_probe=lambda: {"tree_hash": "fixed-source", "git_revision": "fixed-revision"},
        checks_json_by_pair={"pair-01": checks},
    )

    assert [row["checks"] for row in observed] == [True, False]
    assert observed[0]["bytes_sha256"] == hashlib.sha256(checks.read_bytes()).hexdigest()
    assert manifest["checks_json_by_pair"]["pair-01"]["head_sha"] == head
    assert "pair-02" not in manifest["checks_json_by_pair"]
    assert len(manifest["input_identity_sha256"]) == 64
    assert all(row["input_identity_sha256"] == manifest["input_identity_sha256"] for row in manifest["runs"])
    assert manifest["runs"][0]["check_evidence"]["sha256"] == hashlib.sha256(checks.read_bytes()).hexdigest()
    assert manifest["runs"][1]["check_evidence"] is None
    assert manifest["runs"][0]["result"]["project_check_coverage"][0]["state"] == "COMPLETE"
    assert manifest["runs"][1]["result"]["project_check_coverage"][0]["state"] == "PARTIAL"


def test_matrix_marks_check_evidence_mutation_during_run_incomplete(tmp_path):
    repo = tmp_path / "history"
    base, head = _repo_with_pair(repo)
    profile = tmp_path / "profile.json"
    profile.write_text(json.dumps({"version": "p1", "repository": "owner/project"}), encoding="utf-8")
    checks = tmp_path / "checks.json"
    checks.write_text(json.dumps(_check_document("owner/project", 7, base, head)), encoding="utf-8")
    catalog = _catalog(tmp_path / "catalog.json")

    def invoke(*_args, **_kwargs):
        document = json.loads(checks.read_text(encoding="utf-8"))
        document["pull_request_number"] = 8
        checks.write_text(json.dumps(document), encoding="utf-8")
        return {
            "run_status": "CLI_COMPLETED",
            "exit_code": 0,
            "elapsed_ms": 1,
            "stdout_bytes": 1,
            "stderr_bytes": 0,
            "stdout_sha256": "a" * 64,
            "stderr_sha256": "b" * 64,
            "cli_result": {"disposition": "INCOMPLETE", "task_results": {}, "findings": []},
        }

    manifest = matrix.run_matrix(
        repo=repo,
        profile_path=profile,
        output=tmp_path / "results",
        pairs=[{"pair_id": "pair-01", "base_sha": base, "head_sha": head}],
        sample_kind="EXPLICIT_REVISION_PAIRS",
        model_keys=["solar"],
        per_run_timeout=10,
        matrix_timeout=60,
        model_catalog_path=catalog,
        invoke=invoke,
        environment={"PATH": "/bin", "NOUS_API_KEY": "transport-secret"},
        matrix_id="mutated-check-evidence",
        source_probe=lambda: {"tree_hash": "fixed-source", "git_revision": "fixed-revision"},
        checks_json_by_pair={"pair-01": checks},
    )

    assert manifest["source_integrity"] == "MUTATED"
    assert manifest["runs"][0]["run_status"] == "SOURCE_OR_CONFIGURATION_MUTATED_DURING_RUN"
    assert manifest["summary"]["run_status_counts"]["SOURCE_OR_CONFIGURATION_MUTATED_DURING_RUN"] == 1
