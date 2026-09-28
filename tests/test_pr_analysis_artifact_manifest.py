from __future__ import annotations

import hashlib
import io
import json
import sys
import threading
import zipfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import fetch_pr_analysis_artifact as fetch
import intake_pr_analysis_artifact as intake
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
        "workflow_run_attempt": "2",
        "workflow_run_head_sha": "e" * 40,
        "run_workflow_ref": "owner/caller/.github/workflows/pr-review.yml@refs/heads/main",
        "called_workflow_ref": "owner/harness/.github/workflows/pr-analysis.yml@refs/heads/main",
        "called_workflow_sha": "c" * 40,
        "called_workflow_repository": "owner/harness",
        "called_workflow_file_path": ".github/workflows/pr-analysis.yml",
        "target_repository": "owner/caller",
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
            workflow_run_attempt=identity["workflow_run_attempt"],
            workflow_run_head_sha=identity["workflow_run_head_sha"],
            run_workflow_ref=identity["run_workflow_ref"],
            called_workflow_ref=identity["called_workflow_ref"],
            called_workflow_sha=identity["called_workflow_sha"],
            called_workflow_repository=identity["called_workflow_repository"],
            called_workflow_file_path=identity["called_workflow_file_path"],
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
            workflow_run_attempt=identity["workflow_run_attempt"],
            workflow_run_head_sha=identity["workflow_run_head_sha"],
            run_workflow_ref=identity["run_workflow_ref"],
            called_workflow_ref=identity["called_workflow_ref"],
            called_workflow_sha=identity["called_workflow_sha"],
            called_workflow_repository=identity["called_workflow_repository"],
            called_workflow_file_path=identity["called_workflow_file_path"],
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
    assert "WORKFLOW_RUN_ATTEMPT: ${{ github.run_attempt }}" in step
    assert "WORKFLOW_RUN_HEAD_SHA: ${{ github.sha }}" in step
    assert "RUN_WORKFLOW_REF: ${{ github.workflow_ref }}" in step
    assert "CALLED_WORKFLOW_REF: ${{ job.workflow_ref }}" in step
    assert "CALLED_WORKFLOW_SHA: ${{ job.workflow_sha }}" in step
    assert "CALLED_WORKFLOW_REPOSITORY: ${{ job.workflow_repository }}" in step
    assert "CALLED_WORKFLOW_FILE_PATH: ${{ job.workflow_file_path }}" in step
    upload = workflow[end:]
    assert "if: always() && steps.recovery-manifest.outcome == 'success'" in upload
    assert "name: pr-review-${{ inputs.pull_request_number }}-${{ github.run_id }}-${{ github.run_attempt }}" in upload
    assert "path: artifacts/" in upload


def _intake_fixture(tmp_path: Path):
    root, identity, checkpoint, profile, provider, decision = _fixture(tmp_path)
    manifest.create_manifest(
        root,
        identity,
        checkpoint=checkpoint,
        profile=profile,
        provider_config=provider,
        decision_config=decision,
    )
    archive_buffer = io.BytesIO()
    with zipfile.ZipFile(archive_buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(root.rglob("*")):
            if path.is_file():
                archive.write(path, path.relative_to(root).as_posix())
    archive_bytes = archive_buffer.getvalue()
    run = {
        "id": 42,
        "run_attempt": 2,
        "workflow_id": 77,
        "status": "completed",
        "conclusion": "cancelled",
        "path": ".github/workflows/pr-review.yml@main",
        "head_sha": "e" * 40,
        "repository": {"id": 99, "full_name": "owner/caller"},
        "pull_requests": [
            {
                "number": 7,
                "base": {"sha": "a" * 40},
                "head": {"sha": "b" * 40},
            }
        ],
        "referenced_workflows": [
            {
                "path": "owner/harness/.github/workflows/pr-analysis.yml@main",
                "sha": "c" * 40,
                "ref": "refs/heads/main",
            }
        ],
    }
    listing = {
        "total_count": 1,
        "artifacts": [
            {
                "id": 501,
                "name": "pr-review-7-42-2",
                "size_in_bytes": len(archive_bytes),
                "expired": False,
                "digest": "sha256:" + hashlib.sha256(archive_bytes).hexdigest(),
                "workflow_run": {"id": 42, "repository_id": 99, "head_sha": "e" * 40},
            }
        ],
    }
    return identity, json.dumps(run).encode(), json.dumps(listing).encode(), archive_bytes


def test_read_only_intake_binds_run_attempt_pr_artifact_and_manifest(tmp_path):
    identity, run, listing, archive = _intake_fixture(tmp_path)
    output = tmp_path / "recovered"
    result = intake.intake_pr_analysis_artifact(
        run_response=run,
        artifacts_response=listing,
        archive_bytes=archive,
        expected_identity=identity,
        output_dir=output,
    )
    assert result["status"] == "CONSISTENCY_VALIDATED"
    assert result["authenticated_fetch_performed"] is False
    assert result["expected_identity_independently_trusted"] is False
    assert result["resume_authorized"] is False
    assert result["artifact_id"] == 501
    assert result["files"] == 2
    recovered = output / "artifact"
    assert manifest.verify_manifest(recovered, identity)["identity"] == identity
    assert (recovered / "review" / "pr-7-42.json").is_file()


@pytest.mark.parametrize(
    ("change_run", "change_listing", "error"),
    [
        ({"run_attempt": 1}, None, "recovery_run_binding_mismatch"),
        ({"conclusion": "success"}, None, "recovery_run_binding_mismatch"),
        ({"status": "in_progress"}, None, "recovery_run_binding_mismatch"),
        ({"pull_requests": []}, None, "recovery_run_binding_mismatch"),
        (
            {
                "referenced_workflows": [
                    {
                        "path": "owner/harness/.github/workflows/pr-analysis.yml@main",
                        "sha": "f" * 40,
                        "ref": "refs/heads/main",
                    }
                ]
            },
            None,
            "recovery_run_binding_mismatch",
        ),
        (
            {"pull_requests": [{"number": 7, "base": {"sha": "f" * 40}, "head": {"sha": "b" * 40}}]},
            None,
            "recovery_run_pr_binding_mismatch",
        ),
        (None, {"duplicate": True}, "recovery_artifact_not_unique"),
    ],
)
def test_intake_rejects_wrong_run_pr_or_ambiguous_artifact(tmp_path, change_run, change_listing, error):
    identity, run_raw, listing_raw, archive = _intake_fixture(tmp_path)
    run = json.loads(run_raw)
    listing = json.loads(listing_raw)
    if change_run:
        run.update(change_run)
    if change_listing:
        listing["artifacts"].append(dict(listing["artifacts"][0]))
        listing["total_count"] = 2
    with pytest.raises(manifest.ManifestError, match=error):
        intake.intake_pr_analysis_artifact(
            run_response=json.dumps(run).encode(),
            artifacts_response=json.dumps(listing).encode(),
            archive_bytes=archive,
            expected_identity=identity,
            output_dir=tmp_path / "recovered",
        )


def test_intake_rejects_zip_traversal_and_oversized_api_bytes(tmp_path):
    identity, run_raw, listing_raw, archive = _intake_fixture(tmp_path)
    malicious_buffer = io.BytesIO()
    with zipfile.ZipFile(malicious_buffer, "w", compression=zipfile.ZIP_STORED) as malicious:
        malicious.writestr("../escape", b"x")
    malicious_archive = malicious_buffer.getvalue()
    listing = json.loads(listing_raw)
    listing["artifacts"][0]["size_in_bytes"] = len(malicious_archive)
    listing["artifacts"][0]["digest"] = "sha256:" + hashlib.sha256(malicious_archive).hexdigest()
    with pytest.raises(manifest.ManifestError, match="recovery_archive_path_invalid"):
        intake.intake_pr_analysis_artifact(
            run_response=run_raw,
            artifacts_response=json.dumps(listing).encode(),
            archive_bytes=malicious_archive,
            expected_identity=identity,
            output_dir=tmp_path / "recovered",
        )
    with pytest.raises(manifest.ManifestError, match="recovery_api_response_too_large"):
        intake.intake_pr_analysis_artifact(
            run_response=b" " * (intake.MAX_API_BYTES + 1),
            artifacts_response=listing_raw,
            archive_bytes=archive,
            expected_identity=identity,
            output_dir=tmp_path / "recovered-too-large",
        )


def test_intake_refuses_existing_empty_destination(tmp_path):
    identity, run, listing, archive = _intake_fixture(tmp_path)
    output = tmp_path / "reserved"
    output.mkdir()
    with pytest.raises(manifest.ManifestError, match="recovery_output_must_be_new"):
        intake.intake_pr_analysis_artifact(
            run_response=run,
            artifacts_response=listing,
            archive_bytes=archive,
            expected_identity=identity,
            output_dir=output,
        )


def test_intake_atomically_reserves_destination_for_competing_calls(tmp_path, monkeypatch):
    identity, run, listing, archive = _intake_fixture(tmp_path)
    output = tmp_path / "racing"
    both_staged = threading.Barrier(2)
    reserve = intake._reserve_output_directory

    def synchronized_reserve(path):
        both_staged.wait(timeout=5)
        reserve(path)

    monkeypatch.setattr(intake, "_reserve_output_directory", synchronized_reserve)
    successes = []
    failures = []

    def attempt():
        try:
            successes.append(
                intake.intake_pr_analysis_artifact(
                    run_response=run,
                    artifacts_response=listing,
                    archive_bytes=archive,
                    expected_identity=identity,
                    output_dir=output,
                )
            )
        except manifest.ManifestError as exc:
            failures.append(str(exc))

    threads = [threading.Thread(target=attempt) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)
    assert all(not thread.is_alive() for thread in threads)
    assert len(successes) == 1
    assert failures == ["recovery_output_must_be_new"]
    assert manifest.verify_manifest(output / "artifact", identity)


def _fetch_fixture(tmp_path: Path, *, empty_run_prs=False):
    identity, _, listing_raw, archive = _intake_fixture(tmp_path)
    run = {
        "id": 42,
        "run_attempt": 2,
        "workflow_id": 77,
        "status": "completed",
        "conclusion": "cancelled",
        "path": ".github/workflows/pr-review.yml@main",
        "head_sha": "e" * 40,
        "repository": {"id": 99, "full_name": "owner/caller"},
        "pull_requests": [] if empty_run_prs else [{"number": 7, "base": {"sha": "a" * 40}, "head": {"sha": "b" * 40}}],
        "referenced_workflows": [
            {
                "path": "owner/harness/.github/workflows/pr-analysis.yml@main",
                "sha": "c" * 40,
                "ref": "refs/heads/main",
            }
        ],
    }
    pull = {
        "number": 7,
        "state": "open",
        "base": {"sha": "a" * 40, "repo": {"full_name": "owner/caller"}},
        "head": {"sha": "b" * 40, "repo": {"full_name": "contributor/project"}},
    }
    trusted = {
        "schema_version": fetch.SCHEMA,
        "workflow_repository": "owner/caller",
        "workflow_run_id": "42",
        "workflow_run_attempt": "2",
        "run_workflow_ref": "owner/caller/.github/workflows/pr-review.yml@refs/heads/main",
        "target_repository": "owner/caller",
        "pull_request_number": 7,
        "harness_repository": "owner/harness",
        "harness_sha": "c" * 40,
        "called_workflow_ref": "owner/harness/.github/workflows/pr-analysis.yml@refs/heads/main",
        "called_workflow_sha": "c" * 40,
        "called_workflow_repository": "owner/harness",
        "called_workflow_file_path": ".github/workflows/pr-analysis.yml",
    }
    storage_url = "https://productionresultssa12.blob.core.windows.net/actions-results/signed?sig=test"
    api = "https://api.github.com"
    owner, repo = "owner", "caller"
    routes = {
        f"{api}/repos/{owner}/{repo}/actions/runs/42/attempts/2": fetch.HttpResponse(200, {}, json.dumps(run).encode()),
        f"{api}/repos/{owner}/{repo}/pulls/7": fetch.HttpResponse(200, {}, json.dumps(pull).encode()),
        f"{api}/repos/{owner}/{repo}/actions/runs/42/artifacts?per_page=100": fetch.HttpResponse(200, {}, listing_raw),
        f"{api}/repos/{owner}/{repo}/actions/artifacts/501/zip": fetch.HttpResponse(
            302, {"Location": storage_url}, b""
        ),
        storage_url: fetch.HttpResponse(200, {}, archive),
    }
    return trusted, routes, archive, api, storage_url


class _FakeHttpTransport:
    def __init__(self, routes):
        self.routes = routes
        self.calls = []

    def get(self, url, *, headers, limit):
        self.calls.append((url, dict(headers), limit))
        return self.routes[url]


def test_authenticated_fetch_uses_exact_api_bindings_and_strips_redirect_auth(tmp_path):
    trusted, routes, archive, api, storage_url = _fetch_fixture(tmp_path, empty_run_prs=True)
    transport = _FakeHttpTransport(routes)
    result = fetch.fetch_and_intake(
        request_value=trusted,
        token="read-only-actions-token",
        output_dir=tmp_path / "fetched",
        transport=transport,
        api_base=api,
    )
    assert result["status"] == "FETCHED_CONSISTENCY_VALIDATED"
    assert result["authenticated_fetch_performed"] is True
    assert result["current_pr_binding"] == "verified_by_authenticated_lookup"
    assert result["resume_authorized"] is False
    assert result["files"] == 2
    assert result["artifact_path"] == str(tmp_path / "fetched" / "artifact")
    assert transport.calls[0][0].endswith("/actions/runs/42/attempts/2")
    assert len(archive) == routes[storage_url].body.__len__()
    assert [call[0] for call in transport.calls] == list(routes)
    assert all(call[1].get("Authorization") == "Bearer read-only-actions-token" for call in transport.calls[:-1])
    assert "Authorization" not in transport.calls[-1][1]
    assert manifest.verify_manifest(
        tmp_path / "fetched" / "artifact",
        {
            **manifest._identity(intake._unpack_archive(archive)[1]["identity"]),
            "base_sha": "a" * 40,
            "head_sha": "b" * 40,
        },
    )


def test_fetch_rejects_malformed_called_workflow_identity_before_network(tmp_path):
    trusted, routes, _archive, api, _storage = _fetch_fixture(tmp_path)
    trusted["called_workflow_sha"] = "not-a-commit"
    transport = _FakeHttpTransport(routes)
    with pytest.raises(fetch.FetchError, match="trusted_request_identity_invalid"):
        fetch.fetch_and_intake(
            request_value=trusted,
            token="read-only-actions-token",
            output_dir=tmp_path / "invalid-request",
            transport=transport,
            api_base=api,
        )
    assert transport.calls == []


def test_authenticated_fetch_rejects_untrusted_redirect_before_second_request(tmp_path):
    trusted, routes, _archive, api, _storage = _fetch_fixture(tmp_path)
    download_url = f"{api}/repos/owner/caller/actions/artifacts/501/zip"
    routes[download_url] = fetch.HttpResponse(302, {"Location": "https://attacker.invalid/steal?token=redirect"}, b"")
    transport = _FakeHttpTransport(routes)
    with pytest.raises(fetch.FetchError, match="artifact_redirect_invalid"):
        fetch.fetch_and_intake(
            request_value=trusted,
            token="read-only-actions-token",
            output_dir=tmp_path / "blocked",
            transport=transport,
            api_base=api,
        )
    assert all("attacker.invalid" not in call[0] for call in transport.calls)


def test_authenticated_fetch_rejects_current_pr_drift_before_artifact_download(tmp_path):
    trusted, routes, _archive, api, _storage = _fetch_fixture(tmp_path)
    pull_url = f"{api}/repos/owner/caller/pulls/7"
    pull = json.loads(routes[pull_url].body)
    pull["head"]["sha"] = "f" * 40
    routes[pull_url] = fetch.HttpResponse(200, {}, json.dumps(pull).encode())
    transport = _FakeHttpTransport(routes)
    with pytest.raises(fetch.FetchError, match="recovery_run_pr_binding_mismatch"):
        fetch.fetch_and_intake(
            request_value=trusted,
            token="read-only-actions-token",
            output_dir=tmp_path / "stale",
            transport=transport,
            api_base=api,
        )
    assert not any("/actions/artifacts/501/zip" in call[0] for call in transport.calls)


def test_fetch_rejects_non_github_api_base_and_oversized_api_body(tmp_path):
    trusted, routes, _archive, _api, _storage = _fetch_fixture(tmp_path)
    with pytest.raises(fetch.FetchError, match="api_base_invalid"):
        fetch.fetch_and_intake(
            request_value=trusted,
            token="read-only-actions-token",
            output_dir=tmp_path / "wrong-api",
            transport=_FakeHttpTransport(routes),
            api_base="https://attacker.invalid",
        )
    transport = _FakeHttpTransport(routes)
    first_url = next(iter(routes))
    transport.routes[first_url] = fetch.HttpResponse(200, {}, b"x" * (fetch.API_LIMIT + 1))
    with pytest.raises(fetch.FetchError, match="recovery_response_too_large"):
        fetch.fetch_and_intake(
            request_value=trusted,
            token="read-only-actions-token",
            output_dir=tmp_path / "large-api",
            transport=transport,
        )


def test_fetch_cli_reads_named_token_without_printing_it(tmp_path, monkeypatch, capsys):
    trusted, _routes, _archive, _api, _storage = _fetch_fixture(tmp_path)
    request_path = tmp_path / "trusted-request.json"
    request_path.write_text(json.dumps(trusted), encoding="utf-8")
    token = "cli-secret-that-must-not-be-printed"
    monkeypatch.setenv("TEST_ACTIONS_READ_TOKEN", token)
    monkeypatch.setattr(
        fetch,
        "fetch_and_intake",
        lambda **kwargs: {
            "status": "FETCHED_CONSISTENCY_VALIDATED",
            "authenticated_fetch_performed": True,
            "resume_authorized": False,
        },
    )
    assert (
        fetch.main(
            [
                "--trusted-request",
                str(request_path),
                "--output-dir",
                str(tmp_path / "cli-output"),
                "--token-env",
                "TEST_ACTIONS_READ_TOKEN",
            ]
        )
        == 0
    )
    captured = capsys.readouterr()
    assert token not in captured.out + captured.err
    assert json.loads(captured.out)["resume_authorized"] is False
