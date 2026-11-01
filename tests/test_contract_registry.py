"""CA-3: registry schema, single supported combination, preflight, artifacts, provenance."""

from __future__ import annotations

import copy
import hashlib
import json
import subprocess
from pathlib import Path

import jsonschema
import pytest
from test_engine import EmptyProvider, make_snapshot
from test_engine import run as run_engine
from test_review_stages import make_profile, make_state

import pr_review_harness.review_stages as stages
from pr_review_harness.contract_registry import (
    ContractRegistryError,
    default_contract_for_target,
    effective_contract_set,
    load_registry,
    receipt_contract_set,
    registry_digest,
    supported_combination,
    validate_registry,
)
from pr_review_harness.engine import EnginePreflightError
from pr_review_harness.planner import plan_review
from scripts.resolve_review_contract import (
    CONTRACT_STATUS,
    SUPPORTED_CONTRACT,
    TARGET_CONTRACTS,
    ProfileBindingError,
    resolve_review_contract,
)

ROOT = Path(__file__).resolve().parents[1]
REGISTRY_PATH = ROOT / "src/pr_review_harness/contract_registry.json"
SCHEMA_PATH = ROOT / "schemas/contract-registry.v1.schema.json"
SLOP = "magnus919/SlopSearX"
CODEREVIEW = "groktopus/codereview"
V3_LIMITS = {
    key: value
    for key, value in json.loads((ROOT / "profiles/ordinary-review-limits-v3.json").read_text()).items()
    if key != "schema_version"
}
CODEREVIEW_PROFILE = json.loads((ROOT / "profiles/codereview-native-v1-candidate.json").read_text())
V14_PROFILE = json.loads((ROOT / "profiles/slopsearx-v14-jev-reconciliation-candidate.json").read_text())
V14_LIMITS = json.loads((ROOT / "profiles/ordinary-review-limits-v2.json").read_text())


def _registered_profile() -> dict:
    """A synthetic plan-safe profile carrying the supported registry identity."""
    profile = make_profile()
    profile["repository"] = CODEREVIEW
    profile["version"] = "codereview-native-v1-candidate"
    return profile


def _entries(registry: dict) -> list[dict]:
    return registry["contracts"]


def _archived_tokens(registry: dict) -> set[str]:
    tokens: set[str] = set()
    for entry in _entries(registry):
        if entry["status"] != "archived":
            continue
        tokens.update({entry["name"], entry["version"]})
        if entry.get("source_path"):
            tokens.add(entry["source_path"])
    return {token for token in tokens if token}


# ---------------------------------------------------------------------------
# Schema and registry consistency


def test_registry_matches_its_published_schema():
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    registry = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(schema)
    validator = jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker())
    assert list(validator.iter_errors(registry)) == []


def test_registry_loader_validates_statuses_references_and_pinned_digests():
    registry = load_registry(REGISTRY_PATH)
    validate_registry(registry, root=ROOT)

    entries = _entries(registry)
    identities = [(entry["kind"], entry["name"]) for entry in entries]
    assert len(identities) == len(set(identities))
    for entry in entries:
        assert entry["status"] in {"supported", "deprecated", "archived"}
        assert entry["owner"]
        if entry["status"] == "deprecated":
            assert entry["deprecation"]["replacement_path"]
            assert entry["deprecation"]["compatibility_window"]["starts"] <= entry["deprecation"]["compatibility_window"]["ends"]
        if entry["status"] == "archived":
            assert entry["archived"]["archival_note"]
            assert entry["archived"]["evidence_paths"]


def test_every_profile_and_limits_file_is_registered_and_labeled():
    registry = load_registry(REGISTRY_PATH)
    registered = {
        entry["source_path"]
        for entry in _entries(registry)
        if entry["kind"] in {"review-profile", "review-profile-template", "review-limits"}
    }
    files = {
        path.relative_to(ROOT).as_posix()
        for path in (ROOT / "profiles").glob("*.json")
        if path.name != "targets.json"
    }
    assert files <= registered, f"unlabeled profile/limits files: {sorted(files - registered)}"


def test_registry_rejects_malformed_manipulation():
    registry = load_registry(REGISTRY_PATH)

    duplicated = copy.deepcopy(registry)
    duplicated["contracts"].append(copy.deepcopy(duplicated["contracts"][0]))
    with pytest.raises(ContractRegistryError, match="registry_duplicate_entry"):
        validate_registry(duplicated)

    second_supported = copy.deepcopy(registry)
    for entry in second_supported["contracts"]:
        if entry["kind"] == "review-limits" and entry["status"] == "deprecated":
            entry["status"] = "supported"
            entry["replaced_by"] = None
            entry["deprecation"] = None
            break
    with pytest.raises(ContractRegistryError, match="registry_supported_matrix"):
        validate_registry(second_supported)

    bad_reference = copy.deepcopy(registry)
    for entry in bad_reference["contracts"]:
        if entry["kind"] == "review-contract" and entry["status"] == "deprecated":
            entry["replaced_by"] = "does-not-exist"
            break
    with pytest.raises(ContractRegistryError, match="registry_unknown_reference"):
        validate_registry(bad_reference)

    missing_evidence = copy.deepcopy(registry)
    for entry in missing_evidence["contracts"]:
        if entry["status"] == "archived":
            entry["archived"]["evidence_paths"] = []
            break
    with pytest.raises(ContractRegistryError, match="registry_invalid"):
        validate_registry(missing_evidence)

    dangling_deprecation = copy.deepcopy(registry)
    for entry in dangling_deprecation["contracts"]:
        if entry["status"] == "deprecated" and entry["replaced_by"]:
            entry["replaced_by"] = None
            break
    with pytest.raises(ContractRegistryError, match="registry_invalid"):
        validate_registry(dangling_deprecation)


def test_registry_source_digest_mismatch_is_rejected(tmp_path: Path):
    registry = load_registry(REGISTRY_PATH)
    (tmp_path / "profiles").mkdir()
    profile = next(entry for entry in registry["contracts"] if entry["kind"] == "review-profile" and entry["status"] == "supported")
    (tmp_path / profile["source_path"]).write_text("{}", encoding="utf-8")
    limits = next(entry for entry in registry["contracts"] if entry["kind"] == "review-limits" and entry["status"] == "supported")
    (tmp_path / limits["source_path"]).write_bytes((ROOT / limits["source_path"]).read_bytes())
    with pytest.raises(ContractRegistryError, match="registry_source_mismatch"):
        validate_registry(registry, root=tmp_path)


# ---------------------------------------------------------------------------
# Single supported combination and selection defaults


def test_exactly_one_review_contract_profile_and_limits_set_is_supported():
    registry = load_registry(REGISTRY_PATH)
    supported = {
        kind: [entry["name"] for entry in _entries(registry) if entry["kind"] == kind and entry["status"] == "supported"]
        for kind in ("review-contract", "review-profile", "review-limits")
    }
    assert supported == {
        "review-contract": ["codereview-native-v1"],
        "review-profile": ["codereview-native-v1-candidate"],
        "review-limits": ["ordinary-review-limits-v3"],
    }
    combination = supported_combination(registry)
    assert combination == {
        "review_contract": "codereview-native-v1",
        "profile": "codereview-native-v1-candidate",
        "limits": "ordinary-review-limits-v3",
        "target_repository": CODEREVIEW,
    }
    assert default_contract_for_target(registry, CODEREVIEW) == SUPPORTED_CONTRACT
    assert TARGET_CONTRACTS[CODEREVIEW] == frozenset({SUPPORTED_CONTRACT})


def test_selection_defaults_to_the_supported_combination_and_rejects_archived_status(monkeypatch: pytest.MonkeyPatch):
    binding = resolve_review_contract(CODEREVIEW, "")
    assert binding["review_contract"] == SUPPORTED_CONTRACT
    assert binding["contract_status"] == "supported"
    assert resolve_review_contract(CODEREVIEW, "supported")["review_contract"] == SUPPORTED_CONTRACT

    slop_default = resolve_review_contract(SLOP, "")
    assert slop_default["review_contract"] == "legacy-v14"
    assert slop_default["contract_status"] == "deprecated"
    assert slop_default["contract_replaced_by"] == "bounded-production-v16"

    with pytest.raises(ProfileBindingError, match="review_contract_target_mismatch"):
        resolve_review_contract(SLOP, "supported")
    with pytest.raises(ProfileBindingError, match="review_contract_unsupported"):
        resolve_review_contract(CODEREVIEW, "not-a-contract")

    monkeypatch.setitem(CONTRACT_STATUS, "legacy-v14", "archived")
    with pytest.raises(ProfileBindingError, match="review_contract_archived"):
        resolve_review_contract(SLOP, "legacy-v14")


# ---------------------------------------------------------------------------
# Effective contract set and preflight validation


def test_effective_contract_set_for_the_supported_combination_is_fully_registered():
    registry = load_registry(REGISTRY_PATH)
    contracts = effective_contract_set(
        registry, CODEREVIEW_PROFILE, V3_LIMITS, claim_assessment_version="claim-assessment.2"
    )
    assert contracts["registration"] == "registered"
    assert contracts["review_contract"]["name"] == "codereview-native-v1"
    assert contracts["review_contract"]["status"] == "supported"
    assert contracts["profile"]["source_sha256"] == "32d4b63ac84c51eb5919d5f467060d80036f2fa535a3dde354963ecaaaa0c712"
    assert contracts["limits"]["source_sha256"] == "ec191dcde1672b4f86aac24ee6412752cd9a08871d1aba1b332d11341b6fd2a6"
    assert contracts["claim_assessment"]["name"] == "claim-assessment.2"
    assert contracts["specialist_findings"]["name"] == "specialist-findings.v4"
    assert contracts["adjudication"]["name"] == "semantic-adjudication.v3"
    assert contracts["registry"]["sha256"] == registry_digest(registry)


def test_deprecated_combination_is_recorded_and_can_be_rejected_strictly():
    registry = load_registry(REGISTRY_PATH)
    contracts = effective_contract_set(registry, V14_PROFILE, V14_LIMITS)
    assert contracts["review_contract"]["name"] == "legacy-v14"
    assert contracts["review_contract"]["status"] == "deprecated"
    assert contracts["review_contract"]["deprecation"]["compatibility_window"]["ends"] == "2027-02-01"
    with pytest.raises(ContractRegistryError, match="contract_deprecated"):
        effective_contract_set(registry, V14_PROFILE, V14_LIMITS, allow_deprecated=False)


def test_preflight_accepts_the_supported_combination_and_records_it(tmp_path: Path):
    profile = _registered_profile()
    snapshot = make_snapshot()
    state = make_state(
        tmp_path,
        snapshot=snapshot,
        profile=profile,
        plan=plan_review(snapshot, profile),
        limits=dict(V3_LIMITS),
    )
    stages.preflight_review(state)
    assert state.contracts["registration"] == "registered"
    assert state.contracts["review_contract"]["name"] == SUPPORTED_CONTRACT
    assert state.contracts["limits"]["name"] == "ordinary-review-limits-v3"


def test_preflight_rejects_limits_that_do_not_match_the_registered_combination(tmp_path: Path,):
    profile = _registered_profile()
    snapshot = make_snapshot()
    bad_limits = {**V3_LIMITS, "max_provider_calls": 999}
    state = make_state(tmp_path, snapshot=snapshot, profile=profile, limits=bad_limits)
    with pytest.raises(EnginePreflightError, match="contract limits do not match the registered combination"):
        stages.preflight_review(state)


def test_preflight_rejects_an_archived_combination_fail_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    registry = copy.deepcopy(load_registry(REGISTRY_PATH))
    for entry in registry["contracts"]:
        if entry["kind"] == "review-contract" and entry["name"] == SUPPORTED_CONTRACT:
            entry["status"] = "archived"
            entry["deprecation"] = None
            entry["archived"] = {
                "archived_on": "2026-11-01",
                "archival_note": "test-only archive state",
                "evidence_paths": ["tests/test_contract_registry.py"],
            }
            break
    monkeypatch.setattr(stages, "load_registry", lambda *args, **kwargs: registry)
    profile = _registered_profile()
    state = make_state(tmp_path, snapshot=make_snapshot(), profile=profile, limits=dict(V3_LIMITS))
    with pytest.raises(EnginePreflightError, match="archived contract combination rejected"):
        stages.preflight_review(state)


def test_preflight_rejects_an_unregistered_contract_version(tmp_path: Path):
    profile = _registered_profile()
    profile["context_selection"] = {"version": "context-selection.v99"}
    state = make_state(
        tmp_path,
        snapshot=make_snapshot(),
        profile=profile,
        plan={"tasks": [], "coverage_obligations": []},
        limits=dict(V3_LIMITS),
    )
    with pytest.raises(EnginePreflightError, match="contract version is not registered"):
        stages.preflight_review(state)


def test_preflight_rejects_an_unknown_version_of_a_real_profile_identity(tmp_path: Path):
    profile = _registered_profile()
    profile["profile_status"] = "candidate_not_quality_validated"
    profile["version"] = "codereview-native-v99-tampered"
    state = make_state(
        tmp_path,
        snapshot=make_snapshot(),
        profile=profile,
        plan={"tasks": [], "coverage_obligations": []},
        limits=dict(V3_LIMITS),
    )
    with pytest.raises(EnginePreflightError, match="profile is not registered for a review contract"):
        stages.preflight_review(state)


def test_unregistered_synthetic_profile_is_recorded_not_silently_promoted():
    registry = load_registry(REGISTRY_PATH)
    contracts = effective_contract_set(registry, make_profile(), {"deadline_seconds": 5})
    assert contracts["registration"] == "unregistered"
    assert contracts["review_contract"]["status"] == "unregistered"
    assert contracts["limits"]["status"] == "unregistered"


# ---------------------------------------------------------------------------
# Run artifact identity


def test_run_artifact_records_the_effective_contract_set(tmp_path: Path):
    profile = _registered_profile()
    result = run_engine(
        tmp_path,
        snap=make_snapshot(),
        prof=profile,
        provider=EmptyProvider(),
        limits=dict(V3_LIMITS),
        run_id="ca-3-artifact",
    )
    contracts = result["effective_contracts"]
    assert contracts["registration"] == "registered"
    assert contracts["review_contract"]["name"] == SUPPORTED_CONTRACT
    assert contracts["profile"]["name"] == "codereview-native-v1-candidate"
    assert contracts["limits"]["name"] == "ordinary-review-limits-v3"
    assert result["ledger"]["identity"]["effective_contracts"] == contracts
    assert contracts["registry"]["version"] == "contract-registry.v1"


def test_canary_receipt_registry_identity_is_exposed_without_publication_runtime_changes():
    registry = load_registry(REGISTRY_PATH)
    current = receipt_contract_set(registry, "actions-receipt-v2")
    assert current["canary_receipt"]["status"] == "supported"
    legacy = receipt_contract_set(registry, "actions-receipt-v1")
    assert legacy["canary_receipt"]["status"] == "deprecated"
    with pytest.raises(ContractRegistryError, match="registry_unknown_reference"):
        receipt_contract_set(registry, "actions-receipt-v99")


# ---------------------------------------------------------------------------
# Archived provenance and production-reference exclusion


def test_archived_files_are_byte_identical_to_the_committed_generation():
    registry = load_registry(REGISTRY_PATH)
    archived = [entry for entry in _entries(registry) if entry["status"] == "archived" and entry["source_path"]]
    assert archived
    for entry in archived:
        committed = subprocess.run(
            ["git", "-C", str(ROOT), "show", f"HEAD:{entry['source_path']}"],
            check=True,
            capture_output=True,
        ).stdout
        assert hashlib.sha256(committed).hexdigest() == entry["source_sha256"]
        assert hashlib.sha256((ROOT / entry["source_path"]).read_bytes()).hexdigest() == entry["source_sha256"]
        for evidence_path in entry["archived"]["evidence_paths"]:
            assert (ROOT / evidence_path).exists()


def test_archived_versions_are_not_referenced_by_production_surfaces():
    registry = load_registry(REGISTRY_PATH)
    forbidden = _archived_tokens(registry)
    production_paths = [
        *sorted((ROOT / "src/pr_review_harness").glob("*.py")),
        *sorted((ROOT / ".github/workflows").glob("*.yml")),
        ROOT / "scripts/resolve_review_contract.py",
        ROOT / "scripts/resolve_target_profile.py",
        ROOT / "scripts/central_pilot_admission.py",
        ROOT / "profiles/targets.json",
    ]
    for path in production_paths:
        text = path.read_text(encoding="utf-8")
        for token in forbidden:
            assert token not in text, f"archived contract token {token!r} referenced by {path}"
