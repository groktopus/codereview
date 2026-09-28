from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import pr_analysis_artifact_manifest as manifest

ROOT = Path(__file__).resolve().parents[1]


def _fixture(tmp_path: Path):
    root = tmp_path / "artifacts"
    review = root / "review"
    review.mkdir(parents=True)
    profile = tmp_path / "profile.json"
    profile_bytes = b'{"version":"profile-v1"}\n'
    profile.write_bytes(profile_bytes)
    provider = tmp_path / "provider.json"
    provider_bytes = b'{"api_key_env":"LLM_API_KEY","base_url":"https://example.invalid/v1","kind":"openai_compatible","model":"model-a","provider_id":"operator_openai_compatible"}\n'
    provider.write_bytes(provider_bytes)
    decision = tmp_path / "decision.json"
    decision_bytes = b'{"api_key_env":"JEV_API_KEY","endpoint":"https://example.invalid/v1/systemone","kind":"typesafe","model":"jev-latest"}\n'
    decision.write_bytes(decision_bytes)
    identity = {
        "workflow_repository": "owner/caller",
        "workflow_run_id": "42",
        "target_repository": "owner/project",
        "pull_request_number": 7,
        "base_sha": "a" * 40,
        "head_sha": "b" * 40,
        "harness_repository": "owner/harness",
        "harness_sha": "c" * 40,
        "profile_version": "profile-v1",
        "profile_sha256": hashlib.sha256(profile_bytes).hexdigest(),
        "provider_config_sha256": hashlib.sha256(provider_bytes).hexdigest(),
        "decision_config_sha256": hashlib.sha256(decision_bytes).hexdigest(),
        "run_id": "pr-7-42",
        "snapshot_id": "snapshot-42",
        "request_hash": "d" * 64,
    }
    checkpoint = {
        "run_id": "pr-7-42",
        "base_sha": "a" * 40,
        "head_sha": "b" * 40,
        "snapshot_id": "snapshot-42",
        "request_hash": "d" * 64,
        "project_profile_version": "profile-v1",
        "ledger": {"identity": {"snapshot_id": "snapshot-42", "profile_version": "profile-v1"}},
    }
    checkpoint_path = review / "pr-7-42.json"
    checkpoint_path.write_text(json.dumps(checkpoint, sort_keys=True) + "\n", encoding="utf-8")
    (root / "review-result.json").write_text('{"status":"INCOMPLETE"}\n', encoding="utf-8")
    return root, identity, checkpoint_path, profile, provider, decision


def test_manifest_binds_normal_pr_checkpoint_without_persisting_configs(tmp_path):
    root, identity, checkpoint, profile, provider, decision = _fixture(tmp_path)
    result = manifest.create_manifest(
        root, identity, checkpoint=checkpoint, profile=profile, provider_config=provider, decision_config=decision
    )
    checked = manifest.verify_manifest(root, identity)
    assert checked == result
    assert result["checkpoint_path"] == "review/pr-7-42.json"
    assert set(result["files"]) == {"review/pr-7-42.json", "review-result.json"}
    artifact_bytes = b"".join(path.read_bytes() for path in root.rglob("*") if path.is_file())
    assert b"https://example.invalid" not in artifact_bytes
    assert b"LLM_API_KEY" not in artifact_bytes
    assert b"JEV_API_KEY" not in artifact_bytes


@pytest.mark.parametrize(
    ("field", "value", "error"),
    [
        ("head_sha", "e" * 40, "recovery_identity_mismatch"),
        ("workflow_run_id", "43", "recovery_run_binding_mismatch"),
        ("profile_sha256", "f" * 64, "recovery_identity_mismatch"),
    ],
)
def test_manifest_rejects_changed_expected_identity(tmp_path, field, value, error):
    root, identity, checkpoint, profile, provider, decision = _fixture(tmp_path)
    manifest.create_manifest(
        root, identity, checkpoint=checkpoint, profile=profile, provider_config=provider, decision_config=decision
    )
    wrong = {**identity, field: value}
    with pytest.raises(manifest.ManifestError, match=error):
        manifest.verify_manifest(root, wrong)


def test_manifest_rejects_checkpoint_drift_before_emission(tmp_path):
    root, identity, checkpoint, profile, provider, decision = _fixture(tmp_path)
    row = json.loads(checkpoint.read_text(encoding="utf-8"))
    row["request_hash"] = "e" * 64
    checkpoint.write_text(json.dumps(row), encoding="utf-8")
    with pytest.raises(manifest.ManifestError, match="recovery_checkpoint_binding_mismatch"):
        manifest.create_manifest(
            root, identity, checkpoint=checkpoint, profile=profile, provider_config=provider, decision_config=decision
        )


def test_manifest_verifier_rejects_modified_output_and_symlink(tmp_path):
    root, identity, checkpoint, profile, provider, decision = _fixture(tmp_path)
    manifest.create_manifest(
        root, identity, checkpoint=checkpoint, profile=profile, provider_config=provider, decision_config=decision
    )
    (root / "review-result.json").write_text('{"status":"changed"}\n', encoding="utf-8")
    with pytest.raises(manifest.ManifestError, match="recovery_artifact_inventory_mismatch"):
        manifest.verify_manifest(root, identity)
    (root / "review-result.json").unlink()
    outside = tmp_path / "outside"
    outside.write_text("outside", encoding="utf-8")
    (root / "unexpected-link").symlink_to(outside)
    with pytest.raises(manifest.ManifestError, match="artifact_symlink_rejected"):
        manifest.verify_manifest(root, identity)


def test_manifest_refuses_unallowlisted_standard_artifact_path(tmp_path):
    root, identity, checkpoint, profile, provider, decision = _fixture(tmp_path)
    (root / "target-source.zip").write_bytes(b"must not be uploaded")
    with pytest.raises(manifest.ManifestError, match="recovery_artifact_path_allowlist_invalid"):
        manifest.create_manifest(
            root, identity, checkpoint=checkpoint, profile=profile, provider_config=provider, decision_config=decision
        )


def test_manifest_bounds_tree_walk_and_rejects_oversized_or_special_config(tmp_path, monkeypatch):
    root, identity, checkpoint, profile, provider, decision = _fixture(tmp_path)
    (root / "one").write_bytes(b"1")
    (root / "two").write_bytes(b"2")
    monkeypatch.setattr(manifest, "MAX_TREE_ENTRIES", 2)
    with pytest.raises(manifest.ManifestError, match="artifact_tree_entry_cap_exceeded"):
        manifest.create_manifest(
            root, identity, checkpoint=checkpoint, profile=profile, provider_config=provider, decision_config=decision
        )
    monkeypatch.setattr(manifest, "MAX_TREE_ENTRIES", 2048)
    provider.write_bytes(b" " * (manifest.MAX_FILE_BYTES + 1))
    with pytest.raises(manifest.ManifestError, match="artifact_file_invalid"):
        manifest.identity_from_inputs(
            artifact_root=root,
            workflow_repository=identity["workflow_repository"],
            workflow_run_id=identity["workflow_run_id"],
            target_repository=identity["target_repository"],
            pull_request_number=identity["pull_request_number"],
            base_sha=identity["base_sha"],
            head_sha=identity["head_sha"],
            harness_repository=identity["harness_repository"],
            harness_sha=identity["harness_sha"],
            profile=profile,
            expected_profile_sha256=identity["profile_sha256"],
            provider_config=provider,
            decision_config=decision,
        )
    provider.unlink()
    import os

    os.mkfifo(provider)
    with pytest.raises(manifest.ManifestError, match="artifact_file_invalid"):
        manifest.identity_from_inputs(
            artifact_root=root,
            workflow_repository=identity["workflow_repository"],
            workflow_run_id=identity["workflow_run_id"],
            target_repository=identity["target_repository"],
            pull_request_number=identity["pull_request_number"],
            base_sha=identity["base_sha"],
            head_sha=identity["head_sha"],
            harness_repository=identity["harness_repository"],
            harness_sha=identity["harness_sha"],
            profile=profile,
            expected_profile_sha256=identity["profile_sha256"],
            provider_config=provider,
            decision_config=decision,
        )


def test_materialized_provider_configs_match_the_exact_environment_generator_shape():
    sys.path.insert(0, str(ROOT / "scripts"))
    sys.path.insert(0, str(ROOT / "src"))
    from provider_config_from_env import configurations_from_environment

    provider, decision = configurations_from_environment(
        {
            "LLM_BASE_URL": "https://llm.example.invalid/v1",
            "LLM_MODEL": "model-a",
            "LLM_API_KEY": "test-only-credential",
            "JEV_BASE_URL": "https://jev.example.invalid/v1",
            "JEV_MODEL": "jev-latest",
            "JEV_API_KEY": "test-only-credential",
        }
    )
    provider_raw = manifest.canonical(provider)
    decision_raw = manifest.canonical(decision)
    assert set(provider) == {"kind", "provider_id", "base_url", "model", "api_key_env"}
    assert set(decision) == {"kind", "endpoint", "model", "api_key_env"}
    assert b"test-only-credential" not in provider_raw + decision_raw
    manifest._validate_config(
        provider_raw,
        expected_key_env="LLM_API_KEY",
        expected_kind="openai_compatible",
        required={"kind", "provider_id", "base_url", "model", "api_key_env"},
    )
    manifest._validate_config(
        decision_raw,
        expected_key_env="JEV_API_KEY",
        expected_kind="typesafe",
        required={"kind", "endpoint", "model", "api_key_env"},
    )


def test_manifest_requires_credential_reference_not_value(tmp_path):
    root, identity, checkpoint, profile, provider, decision = _fixture(tmp_path)
    provider.write_text('{"api_key":"fake-secret-value"}\n', encoding="utf-8")
    identity["provider_config_sha256"] = hashlib.sha256(provider.read_bytes()).hexdigest()
    with pytest.raises(manifest.ManifestError, match="provider_config_credential_field_rejected"):
        manifest.create_manifest(
            root, identity, checkpoint=checkpoint, profile=profile, provider_config=provider, decision_config=decision
        )


def test_manifest_rejects_duplicate_config_json_keys(tmp_path):
    root, identity, checkpoint, profile, provider, decision = _fixture(tmp_path)
    provider.write_text(
        '{"kind":"openai_compatible","kind":"other","provider_id":"operator_openai_compatible",'
        '"base_url":"https://example.invalid/v1","model":"model-a","api_key_env":"LLM_API_KEY"}\n',
        encoding="utf-8",
    )
    identity["provider_config_sha256"] = hashlib.sha256(provider.read_bytes()).hexdigest()
    with pytest.raises(manifest.ManifestError, match="provider_config_invalid"):
        manifest.create_manifest(
            root, identity, checkpoint=checkpoint, profile=profile, provider_config=provider, decision_config=decision
        )


def test_reusable_workflow_emits_hash_only_manifest_before_standard_artifact_upload():
    workflow = (ROOT / ".github/workflows/pr-analysis.yml").read_text(encoding="utf-8")
    start = workflow.index("      - name: Record recovery identity and artifact digests\n")
    end = workflow.index("      - uses: actions/upload-artifact@", start)
    step = workflow[start:end]
    assert "id: recovery-manifest" in step
    assert "if: always()" in step
    assert "scripts/pr_analysis_artifact_manifest.py" in step
    assert '--provider-config "$PROVIDER_CONFIG"' in step
    assert '--decision-config "$DECISION_CONFIG"' in step
    assert "${{ runner.temp }}/pr-review-provider-config/provider.json" in step
    assert "python - <<'PY'" not in step
    assert "recovery-inputs" not in step
    assert "artifacts/provider" not in step and "artifacts/decision" not in step
    assert "LLM_API_KEY" not in step and "JEV_API_KEY" not in step
    upload = workflow[end:]
    assert "if: always() && steps.recovery-manifest.outcome == 'success'" in upload
    assert "name: pr-review-${{ inputs.pull_request_number }}-${{ github.run_id }}" in upload
    assert "path: artifacts/" in upload
