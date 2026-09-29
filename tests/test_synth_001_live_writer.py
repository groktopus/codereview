from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import run_synth_001_live_writer as runner  # noqa: E402
from frozen_runtime import build_frozen_runtime_root  # noqa: E402

RunnerError = runner.RunnerError
run_preflight = runner.run_preflight
validate_receipt_bundle = runner.validate_receipt_bundle


def _receipt_paths(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    frozen_runtime = build_frozen_runtime_root(tmp_path)
    # Exercise the historical CLI source as well as the historical verifier.
    # The fixed fixture/profile/config paths are module constants and remain
    # rooted in the checkout; _prepare uses ROOT only for CLI import and cwd.
    monkeypatch.setattr(runner, "ROOT", frozen_runtime)
    original_verify = runner.verify

    def verify_with_frozen_runtime(*args, **kwargs):
        updated = list(args)
        updated[7] = frozen_runtime
        # Keep the verifier's fixed production pin intact while making tests
        # portable across the repository's supported CI Python matrix.
        kwargs["expected_python_identity"] = {
            "implementation": sys.implementation.name,
            "version": sys.version.split()[0],
        }
        return original_verify(*updated, **kwargs)

    monkeypatch.setattr(runner, "verify", verify_with_frozen_runtime)
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    result = run_preflight()
    work = Path(result["artifact_directory"])
    repo = work / "repo"
    return result, work, repo


def test_prepare_subprocess_ignores_ambient_github_event_path(monkeypatch, tmp_path):
    event = tmp_path / "workflow-event.json"
    event.write_text("{}", encoding="utf-8")
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(event))
    result, _work, _repo = _receipt_paths(monkeypatch, tmp_path)
    assert result["status"] == "MATCHED_PROVIDER_FREE_PREPARE"


def test_same_run_provider_free_preflight_emits_exact_bounded_bundle(monkeypatch, tmp_path):
    result, work, repo = _receipt_paths(monkeypatch, tmp_path)
    assert result["status"] == "MATCHED_PROVIDER_FREE_PREPARE"
    assert result["provider_calls_before_live_stage"] == 0
    assert result["publication_enabled"] is False
    bundle = validate_receipt_bundle(
        work / "live-preflight-bundle.json", work / "materialization.json",
        work / "prepared.json", work / "verification.json", repo,
    )
    assert bundle["max_provider_calls"] == bundle["planned_provider_calls"] == 1
    assert bundle["dispatched_provider_calls"] == 0
    assert bundle["retries"] == bundle["context_retrievals"] == bundle["followups"] == 0
    assert bundle["request_sha256"] == "a290fdffa94352ecc45d0f1b231883fbb4f73178a0a71599185811ed3ea98e1d"
    assert bundle["request_bytes"] == 11_687
    assert bundle["output_bytes_cap"] == 16_000
    assert bundle["output_tokens_cap"] == 1_200
    assert bundle["target_code_execution"] is False


def test_missing_bundle_is_rejected(tmp_path):
    with pytest.raises(RunnerError, match="preflight_bundle_missing_or_invalid"):
        validate_receipt_bundle(
            tmp_path / "missing.json", tmp_path / "materialization.json",
            tmp_path / "prepared.json", tmp_path / "verification.json", tmp_path,
        )


def test_tampered_prepared_receipt_is_rejected_before_consumption(monkeypatch, tmp_path):
    _result, work, repo = _receipt_paths(monkeypatch, tmp_path)
    prepared = work / "prepared.json"
    prepared.write_bytes(prepared.read_bytes() + b" ")
    with pytest.raises(RunnerError, match="preflight_receipt_tampered"):
        validate_receipt_bundle(
            work / "live-preflight-bundle.json", work / "materialization.json",
            prepared, work / "verification.json", repo,
        )


def test_bundle_bound_to_another_repository_path_is_rejected(monkeypatch, tmp_path):
    _result, work, repo = _receipt_paths(monkeypatch, tmp_path)
    bundle_path = work / "live-preflight-bundle.json"
    bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    bundle["repository_path_sha256"] = "0" * 64
    bundle_path.write_text(json.dumps(bundle, sort_keys=True, separators=(",", ":")), encoding="utf-8")
    with pytest.raises(RunnerError, match="repository_path_mismatch"):
        validate_receipt_bundle(
            bundle_path, work / "materialization.json", work / "prepared.json",
            work / "verification.json", repo,
        )
