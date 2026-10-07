from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import jsonschema
import pytest

import pr_review_harness.engine as engine_module
from pr_review_harness.context_targets import (
    build_context_target_manifest,
    validate_context_target_choice,
    validate_context_target_manifest,
    validate_context_target_manifest_profile,
)
from pr_review_harness.providers import OpenAIProvider


def _profile():
    return {
        "version": "fixture-v17",
        "retrieval_context_patterns": ["engines/*.py", "tests/*.py"],
        "trusted_policy_paths": ["AGENTS.md", "CONTRIBUTING.md"],
        "retrieval_revisions": {"implementation": "head", "test": "head"},
        "context_target_manifest": {
            "version": "context-target-manifest.v1",
            "max_entries": 16,
            "max_bytes": 16_384,
        },
    }


def _snapshot():
    base = "a" * 40
    head = "b" * 40
    evidence = {}
    for index, (path, revision, object_id) in enumerate(
        (
            ("engines/exa.py", head, "c" * 40),
            ("tests/test_exa.py", head, "d" * 40),
            ("AGENTS.md", base, "e" * 40),
            ("README.md", head, "f" * 40),
        )
    ):
        evidence[f"ev-{index}"] = {
            "source_kind": "head_file",
            "path": path,
            "source_revision": revision,
            "source_object_id": object_id,
            "source_object_format": "sha1",
            "trust": "untrusted_pr_content",
        }
    return {
        "snapshot_id": "snapshot-abc",
        "base_sha": base,
        "head_sha": head,
        "inventory": [
            {"unit_id": "unit-engine", "path": "engines/exa.py"},
            {"unit_id": "unit-test", "path": "tests/test_exa.py"},
            {"unit_id": "unit-policy", "path": "AGENTS.md"},
            {"unit_id": "unit-readme", "path": "README.md"},
        ],
        "evidence": evidence,
    }


def test_manifest_is_finite_and_uses_only_allowlisted_captured_paths():
    profile = _profile()
    task = {"task_id": "task-1", "task_kind": "SPECIALIST_FINDINGS", "unit_ids": ["unit-test"]}
    manifest = build_context_target_manifest(task, _snapshot(), profile)
    choices = validate_context_target_manifest(manifest)
    assert {(choice["kind"], choice["value"]) for choice in choices} == {
        ("path", "engines/exa.py"),
        ("path", "tests/test_exa.py"),
        ("unit", "unit-test"),
    }
    assert all("symbol" not in choice["kind"] for choice in choices)
    assert all("AGENTS.md" not in choice["value"] for choice in choices)
    assert all(choice["sources"].keys() == {"b" * 40} for choice in choices)
    proposal = {
        "evidence_kind": "implementation",
        "target": {"kind": "path", "value": "engines/exa.py"},
    }
    bound = validate_context_target_choice(manifest, proposal)
    assert bound["source_sha"] == "b" * 40
    assert bound["source_object_id"] == "c" * 40
    assert validate_context_target_choice(manifest, {**proposal, "evidence_kind": "configuration"}) is None
    assert validate_context_target_choice(
        manifest, {**proposal, "target": {"kind": "unit", "value": "engines/exa.py"}}
    ) is None


def test_manifest_hash_rejects_any_choice_or_revision_tampering():
    manifest = build_context_target_manifest(
        {"task_id": "task-1"}, _snapshot(), _profile()
    )
    tampered = copy.deepcopy(manifest)
    tampered["choices"][0]["value"] = "engines/other.py"
    with pytest.raises(ValueError, match="manifest_hash"):
        validate_context_target_manifest(tampered)


def test_engine_recomputes_manifest_from_trusted_snapshot_profile_and_task():
    snapshot, profile = _snapshot(), _profile()
    task = {"task_id": "task-1", "unit_ids": ["unit-test"], "evidence_ids": []}
    bound = engine_module._bind_specialist_input(task, snapshot, profile, [])
    engine_module._validate_bound_specialist_input(bound, snapshot, profile, [])
    tampered = copy.deepcopy(bound)
    tampered["context_target_manifest"]["choices"][0]["value"] = "invented.py"
    with pytest.raises(ValueError, match="invalid_context_target_manifest_binding"):
        engine_module._validate_bound_specialist_input(tampered, snapshot, profile, [])


def test_profile_manifest_limits_are_closed_and_bounded():
    profile = _profile()
    assert validate_context_target_manifest_profile(profile) == profile["context_target_manifest"]
    profile["context_target_manifest"]["max_bytes"] = 16_385
    with pytest.raises(ValueError, match="max_bytes"):
        validate_context_target_manifest_profile(profile)


def test_v17_profile_only_adds_the_opt_in_manifest_identity():
    root = Path(__file__).resolve().parents[1]
    v16 = json.loads((root / "profiles/slopsearx-v16-bounded-production-candidate.json").read_text())
    v17 = json.loads((root / "profiles/slopsearx-v17-context-target-manifest-candidate.json").read_text())
    expected = copy.deepcopy(v16)
    expected["version"] = v17["version"]
    expected["profile_status"] = v17["profile_status"]
    expected["context_target_manifest"] = {
        "version": "context-target-manifest.v1",
        "max_entries": 256,
        "max_bytes": 16_384,
    }
    assert v17 == expected


def test_provider_v4_schema_enumerates_opt_in_targets_but_default_stays_legacy():
    provider = OpenAIProvider(
        {
            "kind": "openai_compatible",
            "base_url": "https://provider.invalid/v1",
            "model": "fixture-model",
            "api_key_env": "UNUSED_TEST_CREDENTIAL_REFERENCE",
            "max_request_bytes": 100_000,
        }
    )
    task = {
        "task_id": "task-1",
        "unit_ids": ["unit-test"],
        "evidence_ids": ["ev-1"],
        "request_input_contract": "specialist-input.v2",
        "unit_evidence_bindings": [
            {"unit_id": "unit-test", "binding_status": "VERIFIED", "evidence_ids": ["ev-1"]}
        ],
        "context_target_manifest": build_context_target_manifest(
            {"task_id": "task-1", "unit_ids": ["unit-test"]}, _snapshot(), _profile()
        ),
    }
    evidence = [{"evidence_id": "ev-1"}]
    system, user, schema = provider._review_parts(task, evidence)
    target = schema["schema"]["properties"]["context_gap_proposals"]["items"]["properties"]["target"]
    jsonschema.Draft202012Validator.check_schema(schema["schema"])
    validator = jsonschema.Draft202012Validator(target)
    assert validator.is_valid({"kind": "path", "value": "engines/exa.py"})
    assert validator.is_valid({"kind": "path", "value": "tests/test_exa.py"})
    assert validator.is_valid({"kind": "unit", "value": "unit-test"})
    assert not validator.is_valid({"kind": "unit", "value": "engines/exa.py"})
    assert not validator.is_valid({"kind": "path", "value": "unit-test"})
    assert "choose only one exact {kind,value} pair" in system
    assert user["task"]["context_target_manifest"] == task["context_target_manifest"]

    default_task = {key: value for key, value in task.items() if key != "context_target_manifest"}
    legacy_system, legacy_user, legacy_schema = provider._review_parts(default_task, evidence)
    legacy_target = legacy_schema["schema"]["properties"]["context_gap_proposals"]["items"]["properties"]["target"]
    assert "enum" not in legacy_target
    assert legacy_target["properties"]["kind"]["enum"] == ["unit", "path", "symbol"]
    assert "context_target_manifest" not in legacy_user["task"]
    assert "choose only one exact {kind,value} pair" not in legacy_system
    limits = {
        "max_input_bytes_per_task": 100_000,
        "max_output_bytes_per_task": 16_000,
        "max_output_tokens": 1_800,
        "deadline_seconds": 5,
    }
    assert provider.review_input_bytes(task, evidence, limits) == len(
        provider.serialize_review_request(task, evidence, limits)
    )
    assert provider.review_input_bytes(task, evidence, limits) > provider.review_input_bytes(
        default_task, evidence, limits
    )
    legacy_body = provider.serialize_review_request(default_task, evidence, limits)
    assert len(legacy_body) == 8050
    assert hashlib.sha256(legacy_body).hexdigest() == "f443fa38c082303824cec8b393e842c70739a00b4e4100283daa66b64775b9a0"


def test_empty_target_manifest_uses_valid_uninhabitable_gap_schema():
    provider = OpenAIProvider(
        {
            "kind": "openai_compatible",
            "base_url": "https://provider.invalid/v1",
            "model": "fixture-model",
            "api_key_env": "UNUSED_TEST_CREDENTIAL_REFERENCE",
            "max_request_bytes": 100_000,
        }
    )
    snapshot = _snapshot()
    snapshot["inventory"] = []
    snapshot["evidence"] = {}
    task = {
        "task_id": "task-empty",
        "unit_ids": ["unit-test"],
        "evidence_ids": ["ev-1"],
        "request_input_contract": "specialist-input.v2",
        "unit_evidence_bindings": [
            {"unit_id": "unit-test", "binding_status": "VERIFIED", "evidence_ids": ["ev-1"]}
        ],
        "context_target_manifest": build_context_target_manifest(
            {"task_id": "task-empty", "unit_ids": ["unit-test"]}, snapshot, _profile()
        ),
    }
    assert task["context_target_manifest"]["choices"] == []
    system, _, schema = provider._review_parts(task, [{"evidence_id": "ev-1"}])
    proposal_schema = schema["schema"]["properties"]["context_gap_proposals"]
    assert proposal_schema["maxItems"] == 0
    jsonschema.Draft202012Validator.check_schema(schema["schema"])
    assert jsonschema.Draft202012Validator(proposal_schema).is_valid([])
    assert not jsonschema.Draft202012Validator(proposal_schema).is_valid([{}])
    assert "no available context-gap targets" in system
