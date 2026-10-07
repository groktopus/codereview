from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from pr_review_harness.claim_reconciliation import validate_claim_reconciliation_policy
from scripts.resolve_target_profile import ProfileBindingError, main, resolve_target_profile

ROOT = Path(__file__).parents[1]
TARGET = "magnus919/SlopSearX"
CODEREVIEW_TARGET = "groktopus/codereview"


def _write_map(root: Path, *, profile_path: str, profile_raw: bytes, version: str) -> None:
    (root / "profiles").mkdir(parents=True, exist_ok=True)
    mapping = {
        "contract_version": "target-profile-bindings.v1",
        "targets": {
            TARGET: {
                "profile_path": profile_path,
                "profile_sha256": hashlib.sha256(profile_raw).hexdigest(),
                "profile_version": version,
            }
        },
    }
    (root / "profiles" / "targets.json").write_text(json.dumps(mapping), encoding="utf-8")


def _temporary_root(tmp_path: Path, *, repository: str = TARGET, version: str = "profile-v1") -> Path:
    root = tmp_path / "harness"
    profile_path = root / "profiles" / "slopsearx.json"
    profile_path.parent.mkdir(parents=True)
    profile_raw = json.dumps({"repository": repository, "version": version}).encode("utf-8")
    profile_path.write_bytes(profile_raw)
    _write_map(root, profile_path="profiles/slopsearx.json", profile_raw=profile_raw, version=version)
    return root


def _temporary_binding_root(tmp_path: Path) -> tuple[Path, dict[str, bytes]]:
    root = tmp_path / "trusted-harness"
    profiles = root / "profiles"
    profiles.mkdir(parents=True)
    bindings = {
        "fixture-alpha/alpha": ("profiles/alpha.json", "alpha-profile-v1"),
        "fixture-beta/beta": ("profiles/beta.json", "beta-profile-v1"),
    }
    profile_bytes: dict[str, bytes] = {}
    targets = {}
    for repository, (relative_path, version) in bindings.items():
        profile_raw = json.dumps({"repository": repository, "version": version}).encode("utf-8")
        (root / relative_path).write_bytes(profile_raw)
        profile_bytes[repository] = profile_raw
        targets[repository] = {
            "profile_path": relative_path,
            "profile_sha256": hashlib.sha256(profile_raw).hexdigest(),
            "profile_version": version,
        }
    (profiles / "targets.json").write_text(
        json.dumps({"contract_version": "target-profile-bindings.v1", "targets": targets}),
        encoding="utf-8",
    )
    return root, profile_bytes


def test_trusted_binding_resolves_exact_repository_profile_and_digest():
    binding = resolve_target_profile(TARGET)

    assert binding == {
        "target_repository": TARGET,
        "profile_path": "profiles/slopsearx-v14-jev-reconciliation-candidate.json",
        "profile_version": "slopsearx-production-v14-jev-reconciliation-candidate",
        "profile_sha256": "5e83bc43c615f717df0d3d29722de08dd5990c84c8e69d1705c94f3918d49692",
        "profile_map_sha256": hashlib.sha256((ROOT / "profiles/targets.json").read_bytes()).hexdigest(),
    }


def test_resolved_slopsearx_profile_enforces_bounded_required_claim_policy():
    binding = resolve_target_profile(TARGET)
    profile = json.loads((ROOT / binding["profile_path"]).read_text(encoding="utf-8"))

    policy = validate_claim_reconciliation_policy(profile)
    assert policy == {
        "version": "claim-reconciliation.v1",
        "enabled": True,
        "required": True,
        "max_assessments": 1,
    }
    assert profile["profile_status"] == "context_selection_candidate_not_quality_validated"

    workflow = (ROOT / ".github/workflows/pr-analysis.yml").read_text(encoding="utf-8")
    assert 'MAX_CLAIM_ASSESSMENTS: ${{ steps.resolve-profile.outputs.max_claim_assessments }}' in workflow
    assert "default: legacy-v14" in workflow
    assert "PROFILE: ${{ steps.resolve-profile.outputs.profile_path }}" in workflow
    assert "EXPECTED_PROFILE_SHA256: ${{ steps.resolve-profile.outputs.profile_sha256 }}" in workflow


def test_codereview_target_is_bound_to_its_fixed_candidate_profile():
    binding = resolve_target_profile(CODEREVIEW_TARGET)

    assert binding == {
        "target_repository": CODEREVIEW_TARGET,
        "profile_path": "profiles/codereview-native-v1-candidate.json",
        "profile_version": "codereview-native-v1-candidate",
        "profile_sha256": "32d4b63ac84c51eb5919d5f467060d80036f2fa535a3dde354963ecaaaa0c712",
        "profile_map_sha256": hashlib.sha256((ROOT / "profiles/targets.json").read_bytes()).hexdigest(),
    }


def test_unknown_repository_fails_closed_without_generic_fallback():
    with pytest.raises(ProfileBindingError, match="target_repository_unsupported"):
        resolve_target_profile("another-owner/another-project")


def test_distinct_temporary_repository_bindings_resolve_without_cross_project_fallback(tmp_path: Path):
    root, profile_bytes = _temporary_binding_root(tmp_path)

    alpha = resolve_target_profile("fixture-alpha/alpha", root=root)
    beta = resolve_target_profile("fixture-beta/beta", root=root)

    assert alpha["target_repository"] == "fixture-alpha/alpha"
    assert alpha["profile_path"] == "profiles/alpha.json"
    assert alpha["profile_version"] == "alpha-profile-v1"
    assert alpha["profile_sha256"] == hashlib.sha256(profile_bytes["fixture-alpha/alpha"]).hexdigest()
    assert beta["target_repository"] == "fixture-beta/beta"
    assert beta["profile_path"] == "profiles/beta.json"
    assert beta["profile_version"] == "beta-profile-v1"
    assert beta["profile_sha256"] == hashlib.sha256(profile_bytes["fixture-beta/beta"]).hexdigest()
    assert alpha["profile_path"] != beta["profile_path"]
    assert alpha["profile_sha256"] != beta["profile_sha256"]
    assert alpha["profile_map_sha256"] == beta["profile_map_sha256"]
    with pytest.raises(ProfileBindingError, match="target_repository_unsupported"):
        resolve_target_profile("fixture-gamma/unknown", root=root)


def test_temporary_trusted_digest_does_not_allow_cross_repository_profile_reuse(tmp_path: Path):
    root, _profile_bytes = _temporary_binding_root(tmp_path)
    profile_path = root / "profiles/beta.json"
    mismatched_raw = json.dumps(
        {"repository": "fixture-alpha/alpha", "version": "beta-profile-v1"}
    ).encode("utf-8")
    profile_path.write_bytes(mismatched_raw)
    map_path = root / "profiles/targets.json"
    mapping = json.loads(map_path.read_text(encoding="utf-8"))
    mapping["targets"]["fixture-beta/beta"]["profile_sha256"] = hashlib.sha256(mismatched_raw).hexdigest()
    map_path.write_text(json.dumps(mapping), encoding="utf-8")

    with pytest.raises(ProfileBindingError, match="profile_repository_mismatch"):
        resolve_target_profile("fixture-beta/beta", root=root)


@pytest.mark.parametrize(
    "repository",
    [
        "../SlopSearX",
        "owner/repo/extra",
        "owner/repo\nprofiles/generic.json",
        "owner\\repo",
        "",
    ],
)
def test_malicious_or_malformed_caller_repository_is_rejected(repository: str):
    with pytest.raises(ProfileBindingError, match="target_repository_invalid"):
        resolve_target_profile(repository)


def test_profile_digest_mismatch_is_rejected(tmp_path: Path):
    root = _temporary_root(tmp_path)
    profile_path = root / "profiles/slopsearx.json"
    profile_path.write_text('{"repository":"magnus919/SlopSearX","version":"profile-v1","extra":true}')

    with pytest.raises(ProfileBindingError, match="profile_digest_mismatch"):
        resolve_target_profile(TARGET, root=root)


def test_profile_repository_mismatch_is_rejected_even_when_trusted_digest_matches(tmp_path: Path):
    root = _temporary_root(tmp_path, repository="different-owner/different-repo")
    profile_raw = (root / "profiles/slopsearx.json").read_bytes()
    _write_map(root, profile_path="profiles/slopsearx.json", profile_raw=profile_raw, version="profile-v1")

    with pytest.raises(ProfileBindingError, match="profile_repository_mismatch"):
        resolve_target_profile(TARGET, root=root)


def test_profile_version_mismatch_is_rejected_even_when_trusted_digest_matches(tmp_path: Path):
    root = _temporary_root(tmp_path, version="other-version")
    profile_raw = (root / "profiles/slopsearx.json").read_bytes()
    _write_map(root, profile_path="profiles/slopsearx.json", profile_raw=profile_raw, version="profile-v1")

    with pytest.raises(ProfileBindingError, match="profile_version_mismatch"):
        resolve_target_profile(TARGET, root=root)


def test_trusted_mapping_cannot_escape_profiles_directory(tmp_path: Path):
    root = _temporary_root(tmp_path)
    map_path = root / "profiles/targets.json"
    mapping = json.loads(map_path.read_text())
    mapping["targets"][TARGET]["profile_path"] = "profiles/../../untrusted.json"
    map_path.write_text(json.dumps(mapping), encoding="utf-8")

    with pytest.raises(ProfileBindingError, match="profile_binding_invalid"):
        resolve_target_profile(TARGET, root=root)


def test_duplicate_mapping_keys_are_rejected(tmp_path: Path):
    root = _temporary_root(tmp_path)
    target_row = json.dumps({
        "profile_path": "profiles/slopsearx.json",
        "profile_sha256": "a" * 64,
        "profile_version": "profile-v1",
    })
    (root / "profiles/targets.json").write_text(
        '{"contract_version":"target-profile-bindings.v1","targets":{"'
        + TARGET
        + '":'
        + target_row
        + ',"'
        + TARGET
        + '":'
        + target_row
        + "}}",
        encoding="utf-8",
    )

    with pytest.raises(ProfileBindingError, match="profile_map_invalid"):
        resolve_target_profile(TARGET, root=root)


def test_resolver_cli_emits_hash_bound_profile_outputs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    github_output = tmp_path / "github-output"
    binding_artifact = tmp_path / "artifacts/profile-binding.json"
    github_output.write_text("", encoding="utf-8")
    monkeypatch.setenv("TARGET_REPOSITORY", TARGET)

    assert main(["--github-output", str(github_output), "--binding-artifact", str(binding_artifact)]) == 0

    binding = json.loads(binding_artifact.read_text(encoding="utf-8"))
    outputs = github_output.read_text(encoding="utf-8").splitlines()
    assert binding["target_repository"] == TARGET
    assert binding["profile_path"] == "profiles/slopsearx-v14-jev-reconciliation-candidate.json"
    assert binding["profile_sha256"] == hashlib.sha256((ROOT / binding["profile_path"]).read_bytes()).hexdigest()
    assert f"profile_path={binding['profile_path']}" in outputs
    assert f"profile_sha256={binding['profile_sha256']}" in outputs


def test_reusable_workflow_uses_only_resolved_profile_before_provider_configuration():
    workflow = (ROOT / ".github/workflows/pr-analysis.yml").read_text(encoding="utf-8")
    resolver = workflow.index("Resolve the exact trusted profile for this target repository")
    provider_config = workflow.index("Materialize private provider configuration from trusted secrets")
    review = workflow[workflow.index("Produce a bounded read-only report from the bare target object store") :]

    assert resolver < provider_config
    assert "--binding-artifact artifacts/profile-binding.json" in workflow[resolver:provider_config]
    assert "PROFILE: ${{ steps.resolve-profile.outputs.profile_path }}" in review
    assert "EXPECTED_PROFILE_SHA256: ${{ steps.resolve-profile.outputs.profile_sha256 }}" in review
    assert 'test "$(sha256sum "$PROFILE" | cut -d\' \' -f1)" = "$EXPECTED_PROFILE_SHA256"' in review
    assert "|| 'profiles/generic.json'" not in workflow
    assert "profile_path:" not in workflow.split("workflow_call:", 1)[1].split("secrets:", 1)[0]
