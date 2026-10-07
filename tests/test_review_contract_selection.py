from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from scripts.resolve_review_contract import (
    ALL_CONTRACTS,
    CODE_REVIEW_CONTRACTS,
    CONTRACTS,
    TARGET_CONTRACTS,
    ProfileBindingError,
    resolve_review_contract,
)

TARGET = "magnus919/SlopSearX"
CODEREVIEW_TARGET = "groktopus/codereview"
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


def test_codereview_contract_resolves_its_exact_profile_and_shared_finite_limits():
    binding = resolve_review_contract(CODEREVIEW_TARGET, "codereview-native-v1")
    profile = json.loads((Path(__file__).parents[1] / binding["profile_path"]).read_text(encoding="utf-8"))

    assert binding["target_repository"] == CODEREVIEW_TARGET
    assert binding["review_contract"] == "codereview-native-v1"
    assert binding["profile_path"] == "profiles/codereview-native-v1-candidate.json"
    assert binding["profile_version"] == "codereview-native-v1-candidate"
    assert binding["profile_sha256"] == CODE_REVIEW_CONTRACTS["codereview-native-v1"]["profile_sha256"]
    assert binding["limits_path"] == V16_LIMITS
    assert binding["limits_sha256"] == CODE_REVIEW_CONTRACTS["codereview-native-v1"]["limits_sha256"]
    assert binding["max_claim_assessments"] == "4"
    assert profile["profile_status"] == "candidate_not_quality_validated"
    assert profile["claim_reconciliation"] == {
        "enabled": True,
        "max_assessments": 4,
        "required": True,
        "version": "claim-reconciliation.v1",
    }
    assert profile["trusted_policy_paths"] == ["AGENTS.md"]
    assert profile["required_lenses"] == ["correctness", "tests", "maintainability"]
    assert len(profile["required_checks"]) == 7
    assert {item["github_app_id"] for item in profile["required_checks"]} == {15368}
    assert {item["github_check_name"] for item in profile["required_checks"]} == {
        "Tests and lint (Python 3.11)",
        "Tests and lint (Python 3.14)",
        "Build wheel and source distribution",
        "Installed wheel smoke (Python 3.11)",
        "Installed wheel smoke (Python 3.14)",
        "Linux external observer contract",
        "Installed loopback emitter and strict receipt validator",
    }
    assert profile["review_criteria"]["project_specific"].startswith("Use AGENTS.md from the base revision")


def test_target_contract_allowlist_keeps_slop_contracts_closed():
    assert TARGET_CONTRACTS[TARGET] == frozenset({"legacy-v14", "bounded-production-v16"})
    assert TARGET_CONTRACTS[CODEREVIEW_TARGET] == frozenset({"codereview-native-v1"})
    assert set(CONTRACTS) == {"legacy-v14", "bounded-production-v16"}
    assert set(ALL_CONTRACTS) == {"legacy-v14", "bounded-production-v16", "codereview-native-v1"}
    assert CONTRACTS == {
        "legacy-v14": {
            "profile_path": V14_PROFILE,
            "limits_path": V14_LIMITS,
            "profile_version": "slopsearx-production-v14-jev-reconciliation-candidate",
            "profile_sha256": "5e83bc43c615f717df0d3d29722de08dd5990c84c8e69d1705c94f3918d49692",
            "limits_sha256": "39abcf19666c9f322364961577f08f8cff8a3c539e68d894693b6cb0fb5a75e9",
            "max_claim_assessments": 1,
        },
        "bounded-production-v16": {
            "profile_path": V16_PROFILE,
            "limits_path": V16_LIMITS,
            "profile_version": "slopsearx-production-v16-bounded-production-candidate",
            "profile_sha256": "699f93fd7bc78d310de2455cad7402a1c3c8cf5ad61c3d4cbb77bb38da1189ed",
            "limits_sha256": "ec191dcde1672b4f86aac24ee6412752cd9a08871d1aba1b332d11341b6fd2a6",
            "max_claim_assessments": 4,
        },
    }


@pytest.mark.parametrize("contract", ["legacy-v14", "bounded-production-v16"])
def test_codereview_rejects_slop_contract_before_reading_files(tmp_path: Path, contract: str):
    root = tmp_path / "does-not-exist"
    with pytest.raises(ProfileBindingError, match="review_contract_target_mismatch"):
        resolve_review_contract(CODEREVIEW_TARGET, contract, root=root)
    assert not root.exists()


def test_codereview_rejects_profile_hash_tampering(tmp_path: Path):
    root = tmp_path / "harness"
    (root / "profiles").mkdir(parents=True)
    profile_source = Path(__file__).parents[1] / CODE_REVIEW_CONTRACTS["codereview-native-v1"]["profile_path"]
    profile_raw = profile_source.read_bytes()
    changed = profile_raw.replace(b"candidate_not_quality_validated", b"candidate_quality_validated")
    (root / CODE_REVIEW_CONTRACTS["codereview-native-v1"]["profile_path"]).parent.mkdir(parents=True, exist_ok=True)
    (root / CODE_REVIEW_CONTRACTS["codereview-native-v1"]["profile_path"]).write_bytes(changed)
    limits_source = Path(__file__).parents[1] / CODE_REVIEW_CONTRACTS["codereview-native-v1"]["limits_path"]
    (root / CODE_REVIEW_CONTRACTS["codereview-native-v1"]["limits_path"]).write_bytes(limits_source.read_bytes())
    target_map = {
        "contract_version": "target-profile-bindings.v1",
        "targets": {
            CODEREVIEW_TARGET: {
                "profile_path": CODE_REVIEW_CONTRACTS["codereview-native-v1"]["profile_path"],
                "profile_sha256": hashlib.sha256(changed).hexdigest(),
                "profile_version": CODE_REVIEW_CONTRACTS["codereview-native-v1"]["profile_version"],
            }
        },
    }
    (root / "profiles/targets.json").write_text(json.dumps(target_map), encoding="utf-8")

    with pytest.raises(ProfileBindingError, match="review_contract_digest_mismatch"):
        resolve_review_contract(CODEREVIEW_TARGET, "codereview-native-v1", root=root)


def test_codereview_rejects_selector_tampering_even_if_profile_hash_is_rebound(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    root = tmp_path / "harness"
    profiles = root / "profiles"
    profiles.mkdir(parents=True)
    profile_source = Path(__file__).parents[1] / CODE_REVIEW_CONTRACTS["codereview-native-v1"]["profile_path"]
    profile = json.loads(profile_source.read_text(encoding="utf-8"))
    profile["context_selection"]["max_total_context_bytes"] = 1_000_000
    profile_path = profiles / "codereview-native-v1-candidate.json"
    profile_path.write_text(json.dumps(profile), encoding="utf-8")
    limits_source = Path(__file__).parents[1] / CODE_REVIEW_CONTRACTS["codereview-native-v1"]["limits_path"]
    (profiles / "ordinary-review-limits-v3.json").write_bytes(limits_source.read_bytes())
    monkeypatch.setitem(
        CODE_REVIEW_CONTRACTS,
        "codereview-native-v1",
        {
            **CODE_REVIEW_CONTRACTS["codereview-native-v1"],
            "profile_sha256": hashlib.sha256(profile_path.read_bytes()).hexdigest(),
        },
    )
    (profiles / "targets.json").write_text(
        json.dumps({
            "contract_version": "target-profile-bindings.v1",
            "targets": {
                CODEREVIEW_TARGET: {
                    "profile_path": "profiles/codereview-native-v1-candidate.json",
                    "profile_sha256": hashlib.sha256(profile_path.read_bytes()).hexdigest(),
                    "profile_version": "codereview-native-v1-candidate",
                }
            },
        }),
        encoding="utf-8",
    )

    with pytest.raises(ProfileBindingError, match="review_contract_codereview_contract_mismatch"):
        resolve_review_contract(CODEREVIEW_TARGET, "codereview-native-v1", root=root)


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
