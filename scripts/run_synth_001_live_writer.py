#!/usr/bin/env python3
"""Create and verify a same-run, provider-free SYNTH-001 writer preflight bundle.

This command deliberately stops before provider construction or dispatch. A live
writer call requires separate workflow authorization and wiring.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "src"))

from materialize_seeded_writer_synth_001 import materialize  # noqa: E402
from verify_synth_001_preflight import verify  # noqa: E402

FIXTURE = ROOT / "examples/evaluation/seeded-writer-synth-001"
PROFILE_PATH = ROOT / "experiments/synth-001-writer-profile-v1.json"
LIMITS_PATH = ROOT / "experiments/synth-001-writer-limits-v1.json"
PROVIDER_PATH = ROOT / "experiments/synth-001-writer-provider-v1.json"
REQUEST_SHA256 = "a290fdffa94352ecc45d0f1b231883fbb4f73178a0a71599185811ed3ea98e1d"
REQUEST_BYTES = 11_687
OUTPUT_BYTES_CAP = 16_000
OUTPUT_TOKENS_CAP = 1_200


class RunnerError(ValueError):
    """A closed preflight failure."""


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _runner_temp() -> Path:
    raw = os.environ.get("RUNNER_TEMP")
    if not raw:
        raise RunnerError("runner_temp_unavailable")
    path = Path(raw)
    if not path.is_absolute() or path.is_symlink() or not path.is_dir():
        raise RunnerError("runner_temp_unavailable")
    return path.resolve(strict=True)


def _prepare(work: Path, repo: Path, materialization: dict[str, str]) -> tuple[Path, Path]:
    materialization_path = work / "materialization.json"
    materialization_path.write_bytes(_canonical(materialization) + b"\n")
    prepared_path = work / "prepared.json"
    env = os.environ.copy()
    # The prepare step is provider-free even when invoked on a credentialed runner.
    for key in ("LLM_API_KEY", "OPENAI_API_KEY", "GITHUB_TOKEN", "GH_TOKEN"):
        env.pop(key, None)
    env["PYTHONPATH"] = str(ROOT / "src")
    command = [
        sys.executable, "-m", "pr_review_harness", "review", "--repo", str(repo),
        "--base", materialization["base_sha"], "--head", materialization["head_sha"],
        "--profile", str(PROFILE_PATH), "--provider-config", str(PROVIDER_PATH),
        "--limits", str(LIMITS_PATH), "--prepare-only", "--json",
    ]
    try:
        completed = subprocess.run(
            command, cwd=ROOT, env=env, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=45, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        raise RunnerError("prepare_failed") from None
    if completed.returncode != 0 or len(completed.stdout) > 32_000:
        raise RunnerError("prepare_failed")
    prepared_path.write_bytes(completed.stdout)
    return materialization_path, prepared_path


def validate_receipt_bundle(bundle_path: Path, materialization_path: Path, prepared_path: Path,
                            verification_path: Path, repo: Path) -> dict[str, Any]:
    """Verify artifact hashes and the canonical repository path before any consumer uses them."""
    try:
        bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        raise RunnerError("preflight_bundle_missing_or_invalid") from None
    if not isinstance(bundle, dict) or bundle.get("schema") != "synth-001-live-preflight-bundle.v1":
        raise RunnerError("preflight_bundle_invalid")
    expected_repo_hash = hashlib.sha256(os.fsencode(str(repo.resolve(strict=True)))).hexdigest()
    expected = {
        "repository_path_sha256": expected_repo_hash,
        "materialization_sha256": _sha_file(materialization_path),
        "prepared_sha256": _sha_file(prepared_path),
        "verification_sha256": _sha_file(verification_path),
        "request_sha256": REQUEST_SHA256,
        "request_bytes": REQUEST_BYTES,
        "lens": "correctness",
        "output_bytes_cap": OUTPUT_BYTES_CAP,
        "output_tokens_cap": OUTPUT_TOKENS_CAP,
        "max_provider_calls": 1,
        "planned_provider_calls": 1,
        "dispatched_provider_calls": 0,
        "retries": 0,
        "context_retrievals": 0,
        "followups": 0,
        "decision_provider": None,
        "claim_assessments": 0,
        "publication_enabled": False,
        "target_code_execution": False,
    }
    if bundle.get("repository_path_sha256") != expected_repo_hash:
        raise RunnerError("repository_path_mismatch")
    if any(bundle.get(key) != value for key, value in expected.items()):
        raise RunnerError("preflight_receipt_tampered")
    return bundle


def run_preflight() -> dict[str, Any]:
    runner_temp = _runner_temp()
    nonce = secrets.token_hex(12)
    work = runner_temp / f"synth-001-preflight-{nonce}"
    work.mkdir(mode=0o700)
    os.chmod(work, 0o700)
    repo = work / "repo"
    materialization = materialize(FIXTURE, repo)
    materialization_path, prepared_path = _prepare(work, repo, materialization)
    verification = verify(
        materialization_path, prepared_path, repo, FIXTURE,
        PROFILE_PATH, LIMITS_PATH, PROVIDER_PATH, ROOT,
    )
    repo_hash = hashlib.sha256(os.fsencode(str(repo.resolve(strict=True)))).hexdigest()
    if verification.get("repository_path_sha256") != repo_hash:
        raise RunnerError("repository_path_mismatch")
    verification_path = work / "verification.json"
    verification_path.write_bytes(_canonical(verification) + b"\n")
    prepared = json.loads(prepared_path.read_text(encoding="utf-8"))
    if (prepared.get("status") != "PREPARED_ONLY" or prepared.get("no_provider_calls") is not True
            or prepared.get("no_target_code_execution") is not True):
        raise RunnerError("prepared_receipt_mismatch")
    requests = prepared.get("primary_requests")
    if not isinstance(requests, list) or len(requests) != 1:
        raise RunnerError("prepared_request_cardinality_mismatch")
    request = requests[0]
    if (request.get("input_sha256") != REQUEST_SHA256 or request.get("input_bytes") != REQUEST_BYTES
            or request.get("lens") != "correctness"
            or request.get("output_bytes_cap") != OUTPUT_BYTES_CAP
            or request.get("output_tokens_cap") != OUTPUT_TOKENS_CAP):
        raise RunnerError("prepared_request_mismatch")
    bundle = {
        "schema": "synth-001-live-preflight-bundle.v1",
        "job_nonce": nonce,
        "workflow_run_id": os.environ.get("GITHUB_RUN_ID", "local"),
        "workflow_run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT", "local"),
        "repository_path_sha256": repo_hash,
        "materialization_sha256": _sha_file(materialization_path),
        "prepared_sha256": _sha_file(prepared_path),
        "verification_sha256": _sha_file(verification_path),
        "request_sha256": REQUEST_SHA256,
        "request_bytes": REQUEST_BYTES,
        "lens": "correctness",
        "output_bytes_cap": OUTPUT_BYTES_CAP,
        "output_tokens_cap": OUTPUT_TOKENS_CAP,
        "max_provider_calls": 1,
        "planned_provider_calls": 1,
        "dispatched_provider_calls": 0,
        "retries": 0,
        "context_retrievals": 0,
        "followups": 0,
        "decision_provider": None,
        "claim_assessments": 0,
        "publication_enabled": False,
        "target_code_execution": False,
    }
    bundle_path = work / "live-preflight-bundle.json"
    bundle_path.write_bytes(_canonical(bundle) + b"\n")
    validated = validate_receipt_bundle(bundle_path, materialization_path, prepared_path, verification_path, repo)
    if verify(materialization_path, prepared_path, repo, FIXTURE,
               PROFILE_PATH, LIMITS_PATH, PROVIDER_PATH, ROOT) != verification:
        raise RunnerError("verification_receipt_mismatch")
    return {
        "schema": "synth-001-live-writer-preflight.v1",
        "status": "MATCHED_PROVIDER_FREE_PREPARE",
        "fixture_id": "SYNTH-001",
        "job_nonce": validated["job_nonce"],
        "request_sha256": REQUEST_SHA256,
        "request_bytes": REQUEST_BYTES,
        "provider_calls_before_live_stage": 0,
        "provider_calls_cap_for_future_live_stage": 1,
        "dispatched_provider_calls": 0,
        "publication_enabled": False,
        "target_code_execution": False,
        "artifact_directory": str(work),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prepare-only", action="store_true", required=True)
    parser.parse_args(argv)
    try:
        result = run_preflight()
    except Exception as exc:
        code = str(exc) if isinstance(exc, RunnerError) else "preflight_failed"
        print(json.dumps({"schema": "synth-001-live-writer-preflight.v1", "status": "REJECTED", "error": code},
                         sort_keys=True, separators=(",", ":")), file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
