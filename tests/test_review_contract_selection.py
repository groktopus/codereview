from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from scripts.resolve_review_contract import CONTRACTS, ProfileBindingError, resolve_review_contract

TARGET = "magnus919/SlopSearX"
V14_PROFILE = "profiles/slopsearx-v14-jev-reconciliation-candidate.json"
V14_LIMITS = "profiles/ordinary-review-limits-v2.json"
V16_PROFILE = "profiles/slopsearx-v16-bounded-production-candidate.json"
V16_LIMITS = "profiles/ordinary-review-limits-v3.json"


def _root(tmp_path: Path) -> Path:
    root = tmp_path / "harness"
    (root / "profiles").mkdir(parents=True)
    (root / "profiles/targets.json").write_text(
        json.dumps({"contract_version": "target-profile-bindings.v1", "targets": {}}), encoding="utf-8"
    )
    return root


def _profile(version: int) -> dict:
    legacy = version == 14
    return {
        "repository": TARGET,
        "version": f"slopsearx-production-v{version}-jev-reconciliation-candidate"
        if legacy
        else "slopsearx-production-v16-bounded-production-candidate",
        "profile_status": "context_selection_candidate_not_quality_validated"
        if legacy
        else "bounded_production_capacity_candidate_not_quality_validated",
        "context_selection": {
            "version": "context-selection.v2" if legacy else "context-selection.v3",
            "max_total_context_bytes": 120_000 if legacy else 128_000,
        },
        "retrieval_revisions": {"implementation": "base", "test": "base"}
        if legacy
        else {"implementation": "head", "test": "head"},
        "claim_reconciliation": {
            "enabled": True,
            "required": True,
            "max_assessments": 1 if legacy else 4,
            "version": "claim-reconciliation.v1",
        },
        "risk_rules": [
            {
                "lenses": ["security", "correctness", "tests"],
                "min_mode": "FOCUSED",
                "patterns": ["engines/*.py"],
                "reason": "Network-client adapters cross credential, upstream-input, and remote-service trust boundaries and need explicit security, correctness, and test review.",
            }
        ],
    }


def _write_contract(root: Path, version: int, *, limits_override: dict | None = None) -> None:
    profile_path = root / (V14_PROFILE if version == 14 else V16_PROFILE)
    limits_path = root / (V14_LIMITS if version == 14 else V16_LIMITS)
    profile_path.write_text(json.dumps(_profile(version)), encoding="utf-8")
    limits = (
        {"schema_version": "1.0", "max_context_bytes": 600_000, "max_input_bytes_per_task": 96_000}
        if version == 14
        else {
            "schema_version": "1.0",
            "deadline_seconds": 300,
            "max_concurrent_scopes": 3,
            "max_provider_calls": 32,
            "max_retries_per_task": 0,
            "max_context_bytes": 2_500_000,
            "max_input_bytes_per_task": 96_000,
            "max_output_bytes_per_task": 16_000,
            "max_output_bytes": 512_000,
            "max_output_tokens": 1800,
            "max_context_retrievals": 8,
            "max_followup_tasks": 8,
            "max_snapshot_context_bytes": 600_000,
        }
    )
    if limits_override:
        limits.update(limits_override)
    limits_path.write_text(json.dumps(limits), encoding="utf-8")
    if version == 14:
        profile_raw = profile_path.read_bytes()
        targets = {
            "contract_version": "target-profile-bindings.v1",
            "targets": {
                TARGET: {
                    "profile_path": V14_PROFILE,
                    "profile_sha256": hashlib.sha256(profile_raw).hexdigest(),
                    "profile_version": "slopsearx-production-v14-jev-reconciliation-candidate",
                }
            },
        }
        (root / "profiles/targets.json").write_text(json.dumps(targets), encoding="utf-8")


@pytest.mark.parametrize(
    ("contract", "version", "profile_path", "limits_path", "claim_cap"),
    [
        ("legacy-v14", 14, V14_PROFILE, V14_LIMITS, "1"),
        ("bounded-production-v16", 16, V16_PROFILE, V16_LIMITS, "4"),
    ],
)
def test_closed_contracts_resolve_only_their_fixed_hash_bound_inputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    contract: str,
    version: int,
    profile_path: str,
    limits_path: str,
    claim_cap: str,
):
    root = _root(tmp_path)
    _write_contract(root, version)
    monkeypatch.setitem(
        CONTRACTS,
        contract,
        {
            **CONTRACTS[contract],
            "profile_sha256": hashlib.sha256((root / profile_path).read_bytes()).hexdigest(),
            "limits_sha256": hashlib.sha256((root / limits_path).read_bytes()).hexdigest(),
        },
    )

    binding = resolve_review_contract(TARGET, contract, root=root)

    assert binding["review_contract"] == contract
    assert binding["profile_path"] == profile_path
    assert binding["limits_path"] == limits_path
    assert binding["profile_sha256"] == hashlib.sha256((root / profile_path).read_bytes()).hexdigest()
    assert binding["limits_sha256"] == hashlib.sha256((root / limits_path).read_bytes()).hexdigest()
    assert binding["max_claim_assessments"] == claim_cap


def test_unknown_contract_rejects_before_reading_profiles_or_limits(tmp_path: Path):
    root = tmp_path / "does-not-exist"
    with pytest.raises(ProfileBindingError, match="review_contract_unsupported"):
        resolve_review_contract(TARGET, "../../attacker/path", root=root)
    assert not root.exists()


def test_v16_contract_rejects_changed_native_output_cap(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    root = _root(tmp_path)
    _write_contract(root, 16, limits_override={"max_output_bytes_per_task": 16_001})
    monkeypatch.setitem(
        CONTRACTS,
        "bounded-production-v16",
        {
            **CONTRACTS["bounded-production-v16"],
            "profile_sha256": hashlib.sha256((root / V16_PROFILE).read_bytes()).hexdigest(),
            "limits_sha256": hashlib.sha256((root / V16_LIMITS).read_bytes()).hexdigest(),
        },
    )

    with pytest.raises(ProfileBindingError, match="review_contract_v16_contract_mismatch"):
        resolve_review_contract(TARGET, "bounded-production-v16", root=root)


def test_v16_contract_rejects_untrusted_target_repository_before_file_reads(tmp_path: Path):
    root = tmp_path / "does-not-exist"
    with pytest.raises(ProfileBindingError, match="target_repository_unsupported"):
        resolve_review_contract("attacker/repository", "bounded-production-v16", root=root)
    assert not root.exists()


def test_workflow_treats_contract_as_an_environment_value_and_binds_resolved_limits():
    workflow = (Path(__file__).parents[1] / ".github/workflows/pr-analysis.yml").read_text(encoding="utf-8")
    resolver_step = workflow.split("- name: Resolve the exact trusted profile for this target repository", 1)[1].split(
        "- name: Materialize private provider configuration", 1
    )[0]
    review_step = workflow.split("- name: Produce a bounded read-only report", 1)[1].split("- name:", 1)[0]

    assert "default: legacy-v14" in workflow
    assert "REVIEW_CONTRACT: ${{ inputs.review_contract }}" in resolver_step
    assert "python scripts/resolve_review_contract.py" in resolver_step
    assert '"$LIMITS"' in review_step
    assert '"$MAX_CLAIM_ASSESSMENTS"' in review_step
    assert '"$EXPECTED_LIMITS_SHA256"' in review_step
    assert "${{ inputs.review_contract }}" not in resolver_step.split("run: |", 1)[1]
