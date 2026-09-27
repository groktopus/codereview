from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path

from pr_review_harness import cli
from pr_review_harness.providers import OpenAIProvider


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args], check=True, text=True, stdout=subprocess.PIPE
    ).stdout.strip()


def _repo(tmp_path: Path) -> tuple[Path, str, str]:
    repo = tmp_path / "repo"
    subprocess.run(["git", "init", str(repo)], check=True, stdout=subprocess.DEVNULL)
    _git(repo, "config", "user.email", "prepare@example.invalid")
    _git(repo, "config", "user.name", "Prepare Test")
    (repo / "src").mkdir()
    (repo / "src" / "auth.py").write_text("def allowed(user):\n    return user.active\n")
    _git(repo, "add", "src/auth.py")
    _git(repo, "-c", "core.hooksPath=/dev/null", "commit", "-m", "base")
    base = _git(repo, "rev-parse", "HEAD")
    (repo / "src" / "auth.py").write_text("def allowed(user):\n    return user.active and user.tenant_id == owner.id\n")
    _git(repo, "add", "src/auth.py")
    _git(repo, "-c", "core.hooksPath=/dev/null", "commit", "-m", "head")
    head = _git(repo, "rev-parse", "HEAD")
    return repo, base, head


class _Response:
    status = 200

    def __init__(self, body: bytes):
        self.body = body
        self.offset = 0

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def read1(self, size: int) -> bytes:
        chunk = self.body[self.offset : self.offset + size]
        self.offset += len(chunk)
        return chunk


def test_prepared_request_bytes_equal_actual_review_transport_body(monkeypatch):
    provider = OpenAIProvider(
        {
            "kind": "openai_compatible",
            "base_url": "https://provider.example.invalid/v1",
            "model": "prepare-test-model",
            "api_key_env": "PREPARE_TEST_KEY",
        }
    )
    task = {"task_id": "t1", "task_kind": "SPECIALIST_FINDINGS", "unit_ids": ["u1"], "lens": "correctness"}
    evidence = [{"evidence_id": "ev1", "snapshot_id": "snap1", "path": "src/auth.py", "content": "return user.active"}]
    limits = {
        "max_input_bytes_per_task": 64_000,
        "max_output_bytes_per_task": 16_000,
        "max_output_tokens": 1_800,
        "deadline_seconds": 3,
    }
    prepared = provider.serialize_review_request(task, evidence, limits)
    report_payload = {
        "contract_version": "specialist-findings.v4",
        "finding_candidates": [],
        "context_gap_proposals": [],
        "coverage_notes": [
            {
                "unit_id": "u1",
                "state": "COVERED",
                "reason_code": "STATIC_REVIEW_EVIDENCE_BOUND",
                "evidence_refs": ["ev1"],
                "coverage_basis": "STATIC_REVIEW",
            }
        ],
        "specific_strengths": [],
        "future_guidance": [],
    }
    response_body = json.dumps(
        {"choices": [{"finish_reason": "stop", "message": {"content": json.dumps(report_payload)}}]}
    ).encode()
    captured = {}

    class _Opener:
        def open(self, request, timeout):
            captured["body"] = request.data
            captured["timeout"] = timeout
            return _Response(response_body)

    monkeypatch.setattr("pr_review_harness.providers._HTTP_OPENER", _Opener())
    monkeypatch.setenv("PREPARE_TEST_KEY", "synthetic-test-only")
    provider.review(task, evidence, limits)
    assert captured["body"] == prepared
    assert hashlib.sha256(captured["body"]).hexdigest() == hashlib.sha256(prepared).hexdigest()


def test_prepare_only_cli_returns_scope_and_exact_sizes_without_key_or_artifact(tmp_path, monkeypatch, capsys):
    repo, base, head = _repo(tmp_path)
    profile = tmp_path / "profile.json"
    profile.write_text(json.dumps({"version": "prepare-test-v1", "required_lenses": ["correctness"]}))
    provider_config = tmp_path / "provider.json"
    provider_config.write_text(
        json.dumps(
            {
                "kind": "openai_compatible",
                "base_url": "https://provider.example.invalid/v1",
                "model": "prepare-test-model",
                "api_key_env": "PREPARE_ONLY_ABSENT_KEY",
            }
        )
    )
    monkeypatch.delenv("PREPARE_ONLY_ABSENT_KEY", raising=False)
    monkeypatch.delenv("GITHUB_EVENT_PATH", raising=False)
    decision_config = tmp_path / "decision.json"
    decision_config.write_text(json.dumps({
        "kind": "typesafe", "endpoint": "https://api.typesafe.ai/v1/systemone",
        "model": "jev-latest", "api_key_env": "JEV_API_KEY",
    }))
    output_dir = tmp_path / "out"

    class GuardedEnv(dict):
        def get(self, key, default=None):
            if key in {"PREPARE_ONLY_ABSENT_KEY", "JEV_API_KEY"}:
                raise AssertionError("prepare-only read a provider credential value")
            return super().get(key, default)

    monkeypatch.setenv("PREPARE_ONLY_ABSENT_KEY", "synthetic-primary-secret")
    monkeypatch.setenv("JEV_API_KEY", "synthetic-jev-secret")
    monkeypatch.setattr(os, "environ", GuardedEnv(os.environ))

    class NoTransport:
        def open(self, *_args, **_kwargs):
            raise AssertionError("prepare-only opened provider transport")

    monkeypatch.setattr("pr_review_harness.providers._HTTP_OPENER", NoTransport())
    monkeypatch.setattr("pr_review_harness.claim_transport._HTTP_OPENER", NoTransport())
    code = cli.main(
        [
            "review", "--repo", str(repo), "--base", base, "--head", head,
            "--profile", str(profile), "--provider-config", str(provider_config),
            "--decision-config", str(decision_config), "--max-claim-assessments", "4",
            "--output", str(output_dir), "--prepare-only", "--json",
        ]
    )
    assert code == 0
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "PREPARED_ONLY"
    assert result["disposition"] is None
    assert result["no_provider_calls"] is True
    assert result["no_target_code_execution"] is True
    assert result["primary_requests"]
    assert all(request["admitted"] for request in result["primary_requests"])
    assert all(request["input_bytes"] > 0 and len(request["input_sha256"]) == 64 for request in result["primary_requests"])
    capacity = result["capacity"]
    assert capacity["semantic_adjudication_supported_by_primary_provider"] is True
    assert capacity["candidate_count_for_semantic_adjudication"] == "UNKNOWN_UNTIL_PRIMARY_RESULTS"
    assert capacity["candidate_adjudication_candidate_upper_bound_before_call_cap"] >= capacity["exact_primary_call_demand"]
    assert capacity["remaining_global_call_slots_after_primary"] == max(
        0, capacity["configured_max_provider_calls"] - capacity["exact_primary_call_demand"]
    )
    assert capacity["max_semantic_adjudication_calls_if_no_other_stage_uses_remaining_slots"] <= capacity["remaining_global_call_slots_after_primary"]
    assert capacity["runtime_call_demand"] == "UNKNOWN_UNTIL_PRIMARY_RESULTS_AND_OPTIONAL_STAGE_ADMISSION"
    assert capacity["fits_call_cap"] is None
    assert not output_dir.exists()


def test_prepare_only_preserves_unadmitted_obligations(tmp_path, monkeypatch, capsys):
    repo, base, head = _repo(tmp_path)
    profile = tmp_path / "profile.json"
    profile.write_text(json.dumps({"version": "prepare-cap-v1", "required_lenses": ["correctness", "tests"]}))
    provider_config = tmp_path / "provider.json"
    provider_config.write_text(json.dumps({
        "kind": "openai_compatible", "base_url": "https://provider.example.invalid/v1",
        "model": "prepare-test-model", "api_key_env": "UNREAD_TEST_KEY",
    }))
    limits = tmp_path / "limits.json"
    limits.write_text(json.dumps({"max_provider_calls": 12, "max_input_bytes_per_task": 1}))
    monkeypatch.delenv("GITHUB_EVENT_PATH", raising=False)
    monkeypatch.delenv("UNREAD_TEST_KEY", raising=False)
    code = cli.main([
        "review", "--repo", str(repo), "--base", base, "--head", head,
        "--profile", str(profile), "--provider-config", str(provider_config),
        "--limits", str(limits), "--prepare-only", "--json",
    ])
    assert code == 0
    report = json.loads(capsys.readouterr().out)
    assert report["primary_requests"] == []
    assert report["scope"]["unadmitted_obligation_ids"]
    assert report["scope"]["skipped_units"]
    assert report["capacity"]["fits_call_cap"] is None


def test_prepare_only_uses_lower_adapter_cap_and_never_admits_rejected_request(
    tmp_path, monkeypatch, capsys
):
    repo, base, head = _repo(tmp_path)
    profile = tmp_path / "profile.json"
    profile.write_text(json.dumps({"version": "adapter-cap-v1", "required_lenses": ["correctness"]}))
    provider_config = tmp_path / "provider.json"
    provider_config.write_text(json.dumps({
        "kind": "openai_compatible", "base_url": "https://provider.example.invalid/v1",
        "model": "prepare-test-model", "api_key_env": "ADAPTER_CAP_ABSENT_KEY",
        "max_request_bytes": 1,
    }))
    monkeypatch.delenv("GITHUB_EVENT_PATH", raising=False)
    monkeypatch.setenv("ADAPTER_CAP_ABSENT_KEY", "synthetic-secret-must-not-be-read")
    monkeypatch.setenv("JEV_API_KEY", "synthetic-jev-secret-must-not-be-read")

    class GuardedEnv(dict):
        def get(self, key, default=None):
            if key in {"ADAPTER_CAP_ABSENT_KEY", "JEV_API_KEY"}:
                raise AssertionError("prepare-only read a provider credential value")
            return super().get(key, default)

        def __getitem__(self, key):
            if key in {"ADAPTER_CAP_ABSENT_KEY", "JEV_API_KEY"}:
                raise AssertionError("prepare-only read a provider credential value")
            return super().__getitem__(key)

    monkeypatch.setattr(os, "environ", GuardedEnv(os.environ))

    class NoTransport:
        def open(self, *_args, **_kwargs):
            raise AssertionError("prepare-only opened provider transport")

    monkeypatch.setattr("pr_review_harness.providers._HTTP_OPENER", NoTransport())
    monkeypatch.setattr("pr_review_harness.claim_transport._HTTP_OPENER", NoTransport())
    limits = tmp_path / "limits.json"
    limits.write_text(json.dumps({"max_input_bytes_per_task": 64_000}))
    output_dir = tmp_path / "out"

    code = cli.main([
        "review", "--repo", str(repo), "--base", base, "--head", head,
        "--profile", str(profile), "--provider-config", str(provider_config),
        "--limits", str(limits), "--prepare-only", "--json",
        "--output", str(output_dir),
    ])
    assert code == 0
    report = json.loads(capsys.readouterr().out)
    assert report["primary_requests"] == []
    assert report["scope"]["required_unadmitted_obligation_ids"]
    assert report["scope"]["skipped_units"]
    assert report["capacity"]["configured_max_input_bytes_per_task"] == 64_000
    assert report["capacity"]["effective_max_input_bytes_per_task"] == 1
    assert report["capacity"]["overall_capacity"] == "PRIMARY_SCOPE_NOT_ADMITTED"
    assert report["no_provider_calls"] is True
    assert not output_dir.exists()


def test_separate_snapshot_cap_preserves_exact_requests_and_inference_headroom(tmp_path, monkeypatch, capsys):
    repo, base, head = _repo(tmp_path)
    profile = tmp_path / "profile.json"
    profile.write_text(json.dumps({"version": "split-budget-v1", "required_lenses": ["correctness"]}))
    provider_config = tmp_path / "provider.json"
    provider_config.write_text(json.dumps({
        "kind": "openai_compatible", "base_url": "https://provider.example.invalid/v1",
        "model": "prepare-test-model", "api_key_env": "SPLIT_BUDGET_ABSENT_KEY",
    }))
    monkeypatch.delenv("GITHUB_EVENT_PATH", raising=False)
    monkeypatch.delenv("SPLIT_BUDGET_ABSENT_KEY", raising=False)
    reports = []
    for inference_budget in (8_000_000, 10_000_000):
        limits = tmp_path / f"limits-{inference_budget}.json"
        limits.write_text(json.dumps({
            "max_context_bytes": inference_budget,
            "max_snapshot_context_bytes": 100_000,
        }))
        code = cli.main([
            "review", "--repo", str(repo), "--base", base, "--head", head,
            "--profile", str(profile), "--provider-config", str(provider_config),
            "--limits", str(limits), "--prepare-only", "--json",
        ])
        assert code == 0
        reports.append(json.loads(capsys.readouterr().out))

    first, second = reports
    assert first["snapshot"]["snapshot_hash"] == second["snapshot"]["snapshot_hash"]
    assert [row["input_sha256"] for row in first["primary_requests"]] == [
        row["input_sha256"] for row in second["primary_requests"]
    ]
    for report in reports:
        assert report["capacity"]["effective_snapshot_context_bytes"] == 100_000
        assert report["capacity"]["configured_max_context_bytes"] >= 8_000_000
        assert report["capacity"]["primary_serialized_input_bytes_fit_context_cap"] is True
        assert report["scope"]["primary_scope_admission_complete"] is True


def test_prepare_only_marks_known_primary_call_cap_excess(tmp_path, monkeypatch, capsys):
    repo, base, head = _repo(tmp_path)
    profile = tmp_path / "profile.json"
    profile.write_text(json.dumps({"version": "prepare-cap-v1", "required_lenses": ["correctness", "tests"]}))
    provider_config = tmp_path / "provider.json"
    provider_config.write_text(json.dumps({
        "kind": "openai_compatible", "base_url": "https://provider.example.invalid/v1",
        "model": "prepare-test-model", "api_key_env": "UNREAD_TEST_KEY",
    }))
    limits = tmp_path / "limits.json"
    limits.write_text(json.dumps({"max_provider_calls": 1}))
    monkeypatch.delenv("GITHUB_EVENT_PATH", raising=False)
    code = cli.main([
        "review", "--repo", str(repo), "--base", base, "--head", head,
        "--profile", str(profile), "--provider-config", str(provider_config),
        "--limits", str(limits), "--prepare-only", "--json",
    ])
    assert code == 0
    report = json.loads(capsys.readouterr().out)
    assert report["capacity"]["exact_primary_call_demand"] > report["capacity"]["configured_max_provider_calls"]
    assert report["capacity"]["overall_capacity"] == "PRIMARY_CALL_DEMAND_EXCEEDS_CAP"
    assert report["scope"]["unadmitted_obligation_ids"] == []


def test_prepare_only_rejects_event_and_dry_run_combinations(tmp_path, monkeypatch, capsys):
    repo, base, head = _repo(tmp_path)
    profile = tmp_path / "profile.json"
    profile.write_text(json.dumps({"version": "prepare-reject-v1"}))
    provider_config = tmp_path / "provider.json"
    provider_config.write_text(json.dumps({
        "kind": "openai_compatible", "base_url": "https://provider.example.invalid/v1",
        "model": "prepare-test-model", "api_key_env": "UNREAD_TEST_KEY",
    }))
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(tmp_path / "event.json"))
    common = [
        "review", "--repo", str(repo), "--base", base, "--head", head,
        "--profile", str(profile), "--provider-config", str(provider_config),
        "--prepare-only", "--json",
    ]
    assert cli.main(common) == 2
    assert json.loads(capsys.readouterr().out)["error"] == "preflight_rejected"
    monkeypatch.delenv("GITHUB_EVENT_PATH")
    assert cli.main(common + ["--dry-run"]) == 2
    assert json.loads(capsys.readouterr().out)["error"] == "preflight_rejected"


def test_prepare_wrapper_normalizes_only_pinned_check_names_and_preserves_cancellation(tmp_path):
    import importlib.util

    script = Path(__file__).resolve().parents[1] / "scripts" / "prepare_real_case_batch.py"
    spec = importlib.util.spec_from_file_location("prepare_real_case_batch", script)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    source = {
        "repository": "magnus919/SlopSearX",
        "pull_request_number": 457,
        "base_sha": "a" * 40,
        "head_sha": "b" * 40,
        "selected_runs": [
            {"id": 1, "name": name, "app_id": 15368, "status": "completed", "conclusion": "cancelled",
             "head_sha": "b" * 40, "completed_at": "2026-09-21T20:53:05Z", "url": "https://example.invalid/job"}
            for name in ("portal-contract", "portal-browser")
        ],
    }
    destination = tmp_path / "checks.json"
    module.normalize_checks(source, "magnus919/SlopSearX", 457, "a" * 40, "b" * 40, destination)
    normalized = json.loads(destination.read_text())
    assert normalized["schema_version"] == "1.0"
    assert {run["name"] for run in normalized["runs"]} == {"portal-contract", "portal-browser"}
    assert all(run["conclusion"] == "cancelled" for run in normalized["runs"])
    source["selected_runs"].append({"id": 2, "name": "unrelated", "app_id": 15368})
    import pytest
    with pytest.raises(ValueError, match="required_check_capture_names_mismatch"):
        module.normalize_checks(source, "magnus919/SlopSearX", 457, "a" * 40, "b" * 40, destination)


def test_prepare_wrapper_subprocess_output_and_deadline_are_bounded():
    import importlib.util
    import sys

    import pytest

    script = Path(__file__).resolve().parents[1] / "scripts" / "prepare_real_case_batch.py"
    spec = importlib.util.spec_from_file_location("prepare_real_case_batch_bounds", script)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    with pytest.raises(RuntimeError, match="subprocess_output_limit_exceeded"):
        module._bounded_run(
            [sys.executable, "-c", "print('x' * 10000)"], env={"PATH": os.environ.get("PATH", "")},
            timeout=5, stdout_cap=100, stderr_cap=100,
        )
    with pytest.raises(RuntimeError, match="subprocess_deadline_exceeded"):
        module._bounded_run(
            [sys.executable, "-c", "import time; time.sleep(2)"], env={"PATH": os.environ.get("PATH", "")},
            timeout=0.05, stdout_cap=100, stderr_cap=100,
        )
