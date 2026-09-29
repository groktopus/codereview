from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "src"))

import sanitize_model_only_shadow_writer_receipt as sanitizer  # noqa: E402
import select_frozen_pr464_no_candidate_packet as selector  # noqa: E402
import verify_model_only_shadow_live_preflight as preflight  # noqa: E402
from sealed_source_record_integration import SealedSourceIntegrationError, _validate_frozen_pr464  # noqa: E402

from pr_review_harness import cli  # noqa: E402
from pr_review_harness.providers import OpenAIProvider  # noqa: E402


class DeterministicNoFindingProvider(OpenAIProvider):
    """Keep real serialization/capture while replacing the HTTP response locally."""

    def _call(
        self,
        *,
        system,
        user,
        schema,
        limits,
        contract_version,
        capture_exchange=False,
        expected_request_sha256=None,
        serialized_request_bytes=None,
    ):
        assert capture_exchange is True
        assert serialized_request_bytes is not None
        assert hashlib.sha256(serialized_request_bytes).hexdigest() == expected_request_sha256
        counter_path = Path(self.fake_call_counter_path)
        descriptor = os.open(counter_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            os.write(descriptor, b"x")
        finally:
            os.close(descriptor)
        payload = {
            "contract_version": "specialist-findings.v4",
            "finding_candidates": [],
            "context_gap_proposals": [],
            "coverage_notes": [],
            "specific_strengths": [],
            "future_guidance": [],
        }
        content = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        envelope = json.dumps({"deterministic": "provider-free-fixture"}).encode("utf-8")
        return payload, {
            "usage": {},
            "provenance": {"provider": "deterministic-provider-free-fixture"},
            "_audit_exchange": {"structured_response_bytes": content, "response_bytes": envelope},
        }


def _source_repo() -> Path:
    value = os.environ.get("PR464_SOURCE_REPO")
    if not value:
        pytest.skip("set PR464_SOURCE_REPO to a read-only SlopSearX checkout containing both pinned PR464 commits")
    repo = Path(value).resolve()
    for revision in (
        "20a743f0434a1843aa00068483f608f1e213b2af",
        "bffc26f9e4bf95aca0c252e88a2396d03ece854c",
    ):
        subprocess.run(
            ["git", "-C", str(repo), "cat-file", "-e", f"{revision}^{{commit}}"],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
    return repo


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _prepare_frozen_pr464(source_repo, tmp_path, monkeypatch, capsys):
    plan_path = ROOT / "experiments/model-only-shadow-live-pr464-plan-v2.json"
    plan_raw = plan_path.read_bytes()
    plan = json.loads(plan_raw)
    profile_path = ROOT / "docs/real-case-trial-v1/profiles/PR-464.json"
    profile = json.loads(profile_path.read_text())
    limits = json.loads((ROOT / "experiments/model-only-shadow-live-writer-limits-v1.json").read_text())
    provider_config = json.loads((ROOT / "experiments/model-only-shadow-live-writer-provider-v1.json").read_text())
    provider = DeterministicNoFindingProvider(provider_config)
    fake_call_counter = tmp_path / "fake-call-counter.bin"
    provider.fake_call_counter_path = str(fake_call_counter)
    monkeypatch.setattr(cli, "_configs", lambda _args: (profile, limits, provider, None, None))
    monkeypatch.delenv("LLM_API_KEY", raising=False)
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    prepare_args = [
        "review",
        "--repo",
        str(source_repo),
        "--base",
        plan["case"]["base_sha"],
        "--head",
        plan["case"]["head_sha"],
        "--profile",
        str(profile_path),
        "--provider-config",
        str(ROOT / "experiments/model-only-shadow-live-writer-provider-v1.json"),
        "--limits",
        str(ROOT / "experiments/model-only-shadow-live-writer-limits-v1.json"),
        "--historical-checks-json",
        str(ROOT / "docs/real-case-trial-v1/checks/PR-464.json"),
        "--output",
        str(tmp_path / "prepare-output"),
        "--run-id",
        "pr464-provider-free-prepare",
        "--prepare-only",
        "--private-shadow-preflight-case-id",
        "PR-464",
        "--json",
    ]
    assert cli.main(prepare_args) == 0
    prepared = json.loads(capsys.readouterr().out)
    receipt = preflight.verify(plan, prepared, plan_bytes=plan_raw)
    return plan, plan_raw, profile, prepared, receipt, fake_call_counter


def test_frozen_pr464_prepare_only_matches_all_pinned_requests(tmp_path, monkeypatch, capsys):
    """Match all ten frozen request descriptors without invoking the provider."""
    source_repo = _source_repo()
    plan, _plan_raw, _profile, prepared, receipt, fake_call_counter = _prepare_frozen_pr464(
        source_repo, tmp_path, monkeypatch, capsys
    )
    assert receipt["status"] == "PLAN_MATCHED_PROVIDER_FREE"
    assert receipt["writer_calls_planned"] == 10
    assert receipt["writer_request_bytes_total"] == 893359
    assert receipt["writer_request_bytes_max"] == 96462
    expected = {row["task_id"]: (row["input_sha256"], row["input_bytes"]) for row in plan["writer_requests"]}
    observed = {row["task_id"]: (row["input_sha256"], row["input_bytes"]) for row in prepared["primary_requests"]}
    assert observed == expected
    assert receipt["provider_calls"] == 0
    assert not fake_call_counter.exists()


@pytest.mark.skipif(
    os.environ.get("GITHUB_ACTIONS", "").lower() == "true" or os.environ.get("PR464_RUN_FULL_CAPTURE") != "1",
    reason="full private capture is an explicit local-only integration",
)
def test_frozen_pr464_capture_roundtrips_real_plan_and_identity(tmp_path, monkeypatch, capsys):
    """Roundtrip the frozen requests through private capture without provider access.

    The frozen plan stores request hashes rather than prompt blobs, so this
    integration needs the original source revisions in a local, read-only
    checkout and explicit `PR464_RUN_FULL_CAPTURE=1` opt-in.
    It executes no reviewed-repository code.
    The fake `_call` bypasses production worker transport and isolation, so this
    verifies request serialization, capture artifacts, and downstream identity
    gates rather than provider transport behavior.
    """
    source_repo = _source_repo()
    plan_path = ROOT / "experiments/model-only-shadow-live-pr464-plan-v2.json"
    profile_path = ROOT / "docs/real-case-trial-v1/profiles/PR-464.json"
    profile_raw = profile_path.read_bytes()
    plan, plan_raw, profile, _prepared, receipt, fake_call_counter = _prepare_frozen_pr464(
        source_repo, tmp_path, monkeypatch, capsys
    )
    preflight_path = tmp_path / "preflight.json"
    preflight_path.write_text(json.dumps(receipt))

    capture_root = tmp_path / "private-capture"
    capture_args = [
        "review",
        "--repo",
        str(source_repo),
        "--base",
        plan["case"]["base_sha"],
        "--head",
        plan["case"]["head_sha"],
        "--profile",
        str(profile_path),
        "--provider-config",
        str(ROOT / "experiments/model-only-shadow-live-writer-provider-v1.json"),
        "--limits",
        str(ROOT / "experiments/model-only-shadow-live-writer-limits-v1.json"),
        "--historical-checks-json",
        str(ROOT / "docs/real-case-trial-v1/checks/PR-464.json"),
        "--output",
        str(tmp_path / "capture-output"),
        "--run-id",
        "writer-live-integration-1",
        "--json",
        "--private-shadow-capture",
        str(capture_root),
        "--private-shadow-case-id",
        "PR-464",
        "--private-shadow-plan",
        str(plan_path),
        "--private-shadow-preflight-receipt",
        str(preflight_path),
    ]
    assert cli.main(capture_args) == 0
    capsys.readouterr()

    sanitized_dir = tmp_path / "sanitized"
    writer = sanitizer.sanitize(capture_root, plan_path, preflight_path, sanitized_dir)
    result = selector.select(
        capture_root,
        plan_path,
        preflight_path,
        sanitized_dir / "writer-receipt.json",
        sanitized_dir / "writer-outcomes.json",
    )
    assert writer["writer_call_count"] == 10
    assert len(fake_call_counter.read_bytes()) == 10

    packet = json.loads((capture_root / result["packet_path"]).read_text())
    identity = json.loads((ROOT / "examples/evaluation/model-only-shadow-pr464-v2/corpus.json").read_text())["cases"][
        0
    ]["identity"]
    canonical_profile_hash = _sha(
        json.dumps(profile, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    )
    assert packet["profile_id"] == "slopsearx" == identity["profile"]["profile_id"]
    assert packet["snapshot"]["profile_hash"] == canonical_profile_hash
    assert packet["snapshot"]["profile_hash"] != _sha(profile_raw)
    assert _validate_frozen_pr464(packet) == _sha(plan_raw)

    wrong_alias = json.loads(json.dumps(packet))
    wrong_alias["profile_id"] = "slopsearx-v2"
    with pytest.raises(SealedSourceIntegrationError, match="frozen_pr464_identity_invalid"):
        _validate_frozen_pr464(wrong_alias)

    raw_hash_packet = json.loads(json.dumps(packet))
    raw_hash_packet["snapshot"]["profile_hash"] = _sha(profile_raw)
    with pytest.raises(SealedSourceIntegrationError, match="frozen_pr464_identity_invalid"):
        _validate_frozen_pr464(raw_hash_packet)
