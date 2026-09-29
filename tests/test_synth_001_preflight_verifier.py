from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "src"))

from frozen_runtime import build_frozen_runtime_root  # noqa: E402
from materialize_seeded_writer_synth_001 import materialize  # noqa: E402
from verify_synth_001_preflight import PYTHON_IDENTITY, SOURCE_REVISION, VerifyError, verify  # noqa: E402

from pr_review_harness.cli import _read_limits  # noqa: E402
from pr_review_harness.snapshot import collect_snapshot  # noqa: E402

FIXTURE = ROOT / "examples/evaluation/seeded-writer-synth-001"
PREPARED = ROOT / "tests/fixtures/synth-001-prepared-v1.json"
PROFILE = ROOT / "experiments/synth-001-writer-profile-v1.json"
LIMITS = ROOT / "experiments/synth-001-writer-limits-v1.json"
PROVIDER = ROOT / "experiments/synth-001-writer-provider-v1.json"
CURRENT_PYTHON_IDENTITY = {
    "implementation": sys.implementation.name,
    "version": sys.version.split()[0],
}
def _setup(tmp_path: Path) -> tuple[Path, Path]:
    repo = tmp_path / "repo"
    receipt = materialize(FIXTURE, repo)
    receipt_path = tmp_path / "materialization.json"
    receipt_path.write_text(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    return repo, receipt_path


def _verify(
    repo: Path,
    receipt: Path,
    prepared: Path = PREPARED,
    profile: Path = PROFILE,
    *,
    source_root: Path | None = None,
) -> dict:
    document = json.loads(prepared.read_text())
    snapshot = collect_snapshot(
        str(repo), "93f602c9ee0fff5f9ef11e0d476a2b40e6b005e1",
        "810a92b13f7bd83f6e9c3fc55a71caea2bab86a0", json.loads(profile.read_text()),
        _read_limits(SimpleNamespace(limits=str(LIMITS))),
    )
    document["snapshot"]["snapshot_hash"] = snapshot["snapshot_hash"]
    adjusted = receipt.parent / "prepared-at-current-path.json"
    adjusted.write_text(json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n")
    return verify(
        receipt, adjusted, repo, FIXTURE, profile, LIMITS, PROVIDER,
        # `source_root` is the historical implementation pin under test. The
        # verifier still checks its fixed CPython 3.14.7 runtime identity.
        build_frozen_runtime_root(receipt.parent) if source_root is None else source_root,
        expected_python_identity=CURRENT_PYTHON_IDENTITY,
    )


def test_live_verifier_default_remains_pinned_to_cpython_3147():
    assert PYTHON_IDENTITY == {"implementation": "cpython", "version": "3.14.7"}


def test_exact_provider_free_plan_verifies_and_emits_bounded_hash_receipt(tmp_path: Path):
    repo, receipt = _setup(tmp_path)
    result = _verify(repo, receipt)
    assert result["result"] == "MATCHED_PROVIDER_FREE_PREPARE"
    assert result["fixture_id"] == "SYNTH-001"
    assert result["source_revision"] == SOURCE_REVISION
    assert result["request_bytes"] == 11_687
    assert result["lens"] == "correctness"
    assert result["output_bytes_cap"] == 16_000
    assert result["output_tokens_cap"] == 1_200
    assert len(json.dumps(result)) < 2_000
    assert "return True" not in json.dumps(result)


@pytest.mark.parametrize("mutation", ["missing", "extra", "changed"])
def test_verifier_rejects_missing_extra_or_changed_writer_request(tmp_path: Path, mutation: str):
    repo, receipt = _setup(tmp_path)
    prepared = json.loads(PREPARED.read_text())
    if mutation == "missing":
        prepared["primary_requests"] = []
    elif mutation == "extra":
        prepared["primary_requests"].append(dict(prepared["primary_requests"][0]))
    else:
        prepared["primary_requests"][0]["input_bytes"] += 1
    altered = tmp_path / f"{mutation}.json"
    altered.write_text(json.dumps(prepared))
    with pytest.raises(VerifyError):
        _verify(repo, receipt, altered)


def test_verifier_rejects_tampered_receipt_and_config(tmp_path: Path):
    repo, receipt = _setup(tmp_path)
    altered_receipt = json.loads(receipt.read_text())
    altered_receipt["head_sha"] = "0" * 40
    receipt.write_text(json.dumps(altered_receipt))
    with pytest.raises(VerifyError, match="materialization_receipt_mismatch"):
        _verify(repo, receipt)

    _, receipt = _setup(tmp_path / "second")
    changed_profile = tmp_path / "profile.json"
    changed_profile.write_bytes(PROFILE.read_bytes() + b"\n")
    with pytest.raises(VerifyError, match="config_hash_mismatch"):
        _verify(repo, receipt, profile=changed_profile)


def test_verifier_rejects_dirty_materialized_repository(tmp_path: Path):
    repo, receipt = _setup(tmp_path)
    (repo / "extra.py").write_text("# unexpected\n")
    with pytest.raises(VerifyError, match="repository_worktree_not_clean"):
        _verify(repo, receipt)


def test_current_cli_output_matches_historical_prepare_request_pin(tmp_path: Path):
    """Compatibility check only; historical CLI execution is covered separately."""
    verified = []
    historical_runtime = build_frozen_runtime_root(tmp_path)
    for label in ("first", "second"):
        repo, receipt = _setup(tmp_path / f"{label}-distinct-temp-location")
        materialization = json.loads(receipt.read_text())
        prepared_path = tmp_path / f"captured-cli-output-{label}.json"
        env = os.environ.copy()
        env["PYTHONPATH"] = str(ROOT / "src")
        # CI sets GITHUB_EVENT_PATH for its pull_request event. This test uses
        # explicit historical SHAs, and prepare-only intentionally rejects any
        # GitHub event input, so remove it from the isolated local CLI process.
        for name in (
            "LLM_API_KEY", "OPENAI_API_KEY", "GITHUB_TOKEN", "GH_TOKEN", "GITHUB_EVENT_PATH",
        ):
            env.pop(name, None)
        completed = subprocess.run(
            [
                sys.executable, "-m", "pr_review_harness", "review",
                "--repo", str(repo), "--base", materialization["base_sha"],
                "--head", materialization["head_sha"], "--profile", str(PROFILE),
                "--provider-config", str(PROVIDER), "--limits", str(LIMITS),
                "--prepare-only", "--json",
            ],
            cwd=ROOT, env=env, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False,
        )
        assert completed.returncode == 0, completed.stderr.decode("utf-8", errors="replace")[:500]
        assert len(completed.stdout) <= 32_000
        prepared_path.write_bytes(completed.stdout)
        output = json.loads(completed.stdout)
        assert output["no_provider_calls"] is True
        assert output["no_target_code_execution"] is True
        assert len(output["primary_requests"]) == 1
        result = verify(
            receipt, prepared_path, repo, FIXTURE, PROFILE, LIMITS, PROVIDER,
            historical_runtime, expected_python_identity=CURRENT_PYTHON_IDENTITY,
        )
        assert result["result"] == "MATCHED_PROVIDER_FREE_PREPARE"
        assert result["request_sha256"] == "a290fdffa94352ecc45d0f1b231883fbb4f73178a0a71599185811ed3ea98e1d"
        assert result["snapshot_hash"] == output["snapshot"]["snapshot_hash"]
        assert result["repository_path_sha256"] == hashlib.sha256(
            os.fsencode(str(repo.resolve()))
        ).hexdigest()
        verified.append((output, result))
    assert verified[0][0]["snapshot"]["snapshot_hash"] != verified[1][0]["snapshot"]["snapshot_hash"]
    first = json.loads(json.dumps(verified[0][0]))
    second = json.loads(json.dumps(verified[1][0]))
    first["snapshot"]["snapshot_hash"] = second["snapshot"]["snapshot_hash"] = "<path-bound>"
    assert first == second


def test_verifier_rejects_current_checkout_against_historical_runtime_pin(tmp_path: Path):
    repo, receipt = _setup(tmp_path)
    with pytest.raises(VerifyError, match="runtime_tree_mismatch"):
        _verify(repo, receipt, source_root=ROOT)


def test_verifier_rejects_forged_path_bound_snapshot_hash(tmp_path: Path):
    repo, receipt = _setup(tmp_path)
    prepared = json.loads(PREPARED.read_text())
    prepared["snapshot"]["snapshot_hash"] = "0" * 64
    forged = tmp_path / "forged-snapshot-hash.json"
    forged.write_text(json.dumps(prepared, sort_keys=True, separators=(",", ":")) + "\n")
    with pytest.raises(VerifyError, match="snapshot_identity_mismatch"):
        verify(
            receipt, forged, repo, FIXTURE, PROFILE, LIMITS, PROVIDER,
            build_frozen_runtime_root(tmp_path), expected_python_identity=CURRENT_PYTHON_IDENTITY,
        )
