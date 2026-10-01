import hashlib
import io
import json
import zipfile
from pathlib import Path

import pytest

from pr_review_harness.actions_publication import HTTPResponse
from pr_review_harness.artifact_intake import (
    MANIFEST_FILENAME,
    RESULT_FILENAME,
    ArtifactIntakeError,
    ArtifactTransportDigest,
    AttestationIdentity,
    AttestationState,
    intake_artifact_bundle,
)
from pr_review_harness.engine import _provider_identity
from pr_review_harness.providers import make_decision_provider, make_provider
from scripts.pr_analysis_publication_bundle import BundleError, _canonical_hash, create_publication_directory, main

REPO = "owner/repo"
BASE = "b" * 40
HEAD = "a" * 40
CALLER_SHA = "c" * 40
EVENT_SHA = HEAD
HARNESS_SHA = "d" * 40
PROFILE_SHA = "e" * 64
RUN_ID = 731245
ATTEMPT = 2
WORKFLOW_ID = 563
REPOSITORY_ID = 8123
PROVIDER_CONFIG = {
    "kind": "openai_compatible",
    "provider_id": "primary",
    "base_url": "https://llm.example/v1",
    "model": "model-a",
    "api_key_env": "LLM_API_KEY",
}
DECISION_CONFIG = {
    "kind": "typesafe",
    "endpoint": "https://jev.example/systemone",
    "model": "model-b",
    "api_key_env": "JEV_API_KEY",
}
PROVIDER_IDENTITY = _provider_identity(make_provider(PROVIDER_CONFIG), make_decision_provider(DECISION_CONFIG))


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sealed_result(**overrides):
    result = {
        "contract_version": "0.1",
        "run_id": f"pr-44-{RUN_ID}",
        "repository": REPO,
        "pull_request_number": 44,
        "base_sha": BASE,
        "head_sha": HEAD,
        "project_profile_version": "profile-v1",
        "provider_identity": PROVIDER_IDENTITY,
        "request_hash": "7" * 64,
        "disposition": "COMMENT",
    }
    result.update(overrides)
    result["result_hash"] = _canonical_hash({key: value for key, value in result.items() if key != "result_hash"})
    return result


class FakeTransport:
    def __init__(self, document, *, pull_request=None, branch_response=None):
        self.document = document
        self.pull_request = pull_request
        self.branch_response = branch_response or {"name": "main", "commit": {"sha": CALLER_SHA}}
        self.calls = 0

    def request(self, method, url, **kwargs):
        self.calls += 1
        assert method == "GET"
        assert kwargs["timeout_seconds"] == 10
        assert kwargs["max_response_bytes"] <= 512_000
        if url == f"https://api.github.com/repos/{REPO}/branches/main":
            document = self.branch_response
        elif url == f"https://api.github.com/repos/{REPO}/actions/runs/{RUN_ID}/attempts/{ATTEMPT}":
            document = self.document
        elif url == f"https://api.github.com/repos/{REPO}/pulls/44":
            document = self.pull_request or {
                "number": 44,
                "state": "open",
                "draft": False,
                "base": {
                    "ref": "main",
                    "sha": BASE,
                    "repo": {"id": REPOSITORY_ID, "full_name": REPO, "default_branch": "main"},
                },
                "head": {"ref": "feature/update-dependency", "sha": HEAD},
            }
        else:
            raise AssertionError(f"unexpected URL: {url}")
        return HTTPResponse(200, {"content-type": "application/json"}, canonical(document))


def run_api(**changes):
    run = {
        "id": RUN_ID,
        "run_attempt": ATTEMPT,
        "workflow_id": WORKFLOW_ID,
        "path": ".github/workflows/pr-review.yml",
        "head_sha": EVENT_SHA,
        "head_branch": "feature/update-dependency",
        "repository": {"id": REPOSITORY_ID, "full_name": REPO},
        "pull_requests": [
            {
                "number": 44,
                "base": {"sha": BASE, "repo": {"id": REPOSITORY_ID}},
                "head": {"sha": HEAD},
            }
        ],
    }
    run.update(changes)
    return run


def make_inputs(tmp_path: Path, *, result=None):
    result_path = tmp_path / "sealed.json"
    result_path.write_bytes(canonical(result or sealed_result()) + b"\n")
    profile_path = tmp_path / "profile.json"
    profile_path.write_bytes(canonical({"repository": REPO, "version": "profile-v1"}))
    profile_hash = hashlib.sha256(profile_path.read_bytes()).hexdigest()
    provider_path = tmp_path / "provider.json"
    provider_path.write_bytes(canonical(PROVIDER_CONFIG) + b"\n")
    decision_path = tmp_path / "decision.json"
    decision_path.write_bytes(canonical(DECISION_CONFIG) + b"\n")
    env = {
        "GITHUB_REPOSITORY": REPO,
        "TARGET_REPOSITORY": REPO,
        "GITHUB_RUN_ID": str(RUN_ID),
        "GITHUB_RUN_ATTEMPT": str(ATTEMPT),
        "GITHUB_SHA": CALLER_SHA,
        "GITHUB_WORKFLOW_SHA": CALLER_SHA,
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_WORKFLOW_REF": f"{REPO}/.github/workflows/pr-review.yml@refs/heads/main",
        "GITHUB_EVENT_NAME": "pull_request_target",
        "GITHUB_DEFAULT_BRANCH": "main",
        "PR_NUMBER": "44",
        "BASE_SHA": BASE,
        "HEAD_SHA": HEAD,
        "HARNESS_REPOSITORY": "harness/repo",
        "HARNESS_SHA": HARNESS_SHA,
        "CALLED_WORKFLOW_REPOSITORY": "harness/repo",
        "CALLED_WORKFLOW_FILE_PATH": ".github/workflows/pr-analysis.yml",
        "CALLED_WORKFLOW_SHA": HARNESS_SHA,
        "CALLED_WORKFLOW_REF": f"harness/repo/.github/workflows/pr-analysis.yml@{HARNESS_SHA}",
        "PROFILE_VERSION": "profile-v1",
        "PROFILE_SHA256": profile_hash,
        "PROVIDER_CONFIG": str(provider_path),
        "DECISION_CONFIG": str(decision_path),
        "GH_TOKEN": "fixture-gh-token",
        "LLM_API_KEY": "sentinel-primary-key-value",
        "JEV_API_KEY": "sentinel-decision-key-value",
    }
    return result_path, profile_path, env


def make_intake_zip(directory, *, extra=(), duplicate=False):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.write(directory / RESULT_FILENAME, RESULT_FILENAME)
        archive.write(directory / MANIFEST_FILENAME, MANIFEST_FILENAME)
        if duplicate:
            archive.writestr(RESULT_FILENAME, (directory / RESULT_FILENAME).read_bytes())
        for name, raw in extra:
            archive.writestr(name, raw)
    raw = stream.getvalue()
    return raw, ArtifactTransportDigest(
        source="test_fixture",
        subject="downloaded_zip_bytes",
        algorithm="sha256",
        hex_digest=hashlib.sha256(raw).hexdigest(),
    )


def test_emitted_directory_round_trips_through_existing_intake(tmp_path):
    result_path, profile_path, env = make_inputs(tmp_path)
    output = tmp_path / "publication"
    create_publication_directory(
        result_path=result_path,
        profile_path=profile_path,
        output_dir=output,
        env=env,
        transport=FakeTransport(run_api()),
    )
    assert sorted(path.name for path in output.iterdir()) == [MANIFEST_FILENAME, RESULT_FILENAME]
    raw, digest = make_intake_zip(output)
    manifest = json.loads((output / MANIFEST_FILENAME).read_text())
    attestation = AttestationIdentity(
        issuer="https://token.actions.githubusercontent.com",
        repository_id=manifest["repository_id"],
        repository=manifest["repository"],
        workflow_id=manifest["caller_workflow_id"],
        workflow_path=manifest["caller_workflow_path"],
        workflow_ref=manifest["caller_workflow_ref"],
        workflow_sha=manifest["caller_workflow_sha"],
        run_id=manifest["upstream_run_id"],
        run_attempt=manifest["upstream_run_attempt"],
        called_harness_repository=manifest["called_harness_repository"],
        called_harness_path=manifest["called_harness_path"],
        called_harness_sha=manifest["called_harness_sha"],
    )
    receipt = intake_artifact_bundle(
        io.BytesIO(raw),
        _identity_from_manifest(manifest),
        digest,
        trusted_attestation_identity=attestation,
    )
    assert receipt.attestation_state is AttestationState.UNAVAILABLE
    assert receipt.result_hash == manifest["result_hash"]
    assert manifest["provider_configuration_identity"] == "provider-identity-sha256:" + _canonical_hash(
        PROVIDER_IDENTITY
    )
    assert manifest["base_sha"] == BASE
    assert manifest["caller_workflow_sha"] == CALLER_SHA
    assert manifest["caller_workflow_sha"] != manifest["base_sha"]
    assert manifest["contract_versions"] == {"artifact_manifest": "1.0", "review_result": "0.1"}


def test_workflow_shaped_environment_and_cli_need_no_injected_provider_hash(tmp_path, capsys):
    result_path, profile_path, env = make_inputs(tmp_path)
    output = tmp_path / "publication"
    assert "PROVIDER_IDENTITY_SHA256" not in env
    assert {"PROVIDER_CONFIG", "DECISION_CONFIG"} <= env.keys()
    status = main(
        ["--result", str(result_path), "--profile", str(profile_path), "--output-dir", str(output)],
        environ=env,
        transport=FakeTransport(run_api()),
    )
    assert status == 0
    assert '"status":"BUNDLE_READY"' in capsys.readouterr().out
    assert sorted(path.name for path in output.iterdir()) == [MANIFEST_FILENAME, RESULT_FILENAME]


def _identity_from_manifest(manifest):
    from pr_review_harness.artifact_intake import ArtifactIdentity

    return ArtifactIdentity(
        repository_id=manifest["repository_id"],
        repository=manifest["repository"],
        pull_request_number=manifest["pull_request_number"],
        base_sha=manifest["base_sha"],
        head_sha=manifest["head_sha"],
        upstream_run_id=manifest["upstream_run_id"],
        upstream_run_attempt=manifest["upstream_run_attempt"],
        caller_workflow_id=manifest["caller_workflow_id"],
        caller_workflow_path=manifest["caller_workflow_path"],
        caller_workflow_ref=manifest["caller_workflow_ref"],
        caller_workflow_sha=manifest["caller_workflow_sha"],
        called_harness_repository=manifest["called_harness_repository"],
        called_harness_path=manifest["called_harness_path"],
        called_harness_sha=manifest["called_harness_sha"],
        profile_version=manifest["profile_version"],
        profile_sha256=manifest["profile_sha256"],
        provider_configuration_identity=manifest["provider_configuration_identity"],
        contract_versions=tuple(sorted(manifest["contract_versions"].items())),
    )


def test_wrong_api_head_fails_before_creating_publication_directory(tmp_path):
    result_path, profile_path, env = make_inputs(tmp_path)
    output = tmp_path / "publication"
    with pytest.raises(BundleError, match="github_run_head_pr_binding_mismatch"):
        create_publication_directory(
            result_path=result_path,
            profile_path=profile_path,
            output_dir=output,
            env=env,
            transport=FakeTransport(run_api(head_sha="9" * 40)),
        )
    assert not output.exists()


@pytest.mark.parametrize(
    "branch_response",
    [
        {"name": "release", "commit": {"sha": CALLER_SHA}},
        {"name": "main", "commit": {"sha": "9" * 40}},
        {"name": "main", "commit": {}},
    ],
)
def test_default_branch_tip_mismatch_rejects_bundle(tmp_path, branch_response):
    result_path, profile_path, env = make_inputs(tmp_path)
    output = tmp_path / "publication"
    transport = FakeTransport(run_api(), branch_response=branch_response)
    with pytest.raises(BundleError, match="github_default_branch_identity_mismatch"):
        create_publication_directory(
            result_path=result_path,
            profile_path=profile_path,
            output_dir=output,
            env=env,
            transport=transport,
        )
    assert transport.calls == 1
    assert not output.exists()


def test_target_run_with_empty_associations_uses_current_pr_api_binding(tmp_path):
    result_path, profile_path, env = make_inputs(tmp_path)
    output = tmp_path / "publication"
    create_publication_directory(
        result_path=result_path,
        profile_path=profile_path,
        output_dir=output,
        env=env,
        transport=FakeTransport(run_api(pull_requests=[])),
    )
    assert sorted(path.name for path in output.iterdir()) == ["provenance.json", "review-result.json"]


def test_target_run_with_omitted_associations_uses_current_pr_api_binding(tmp_path):
    result_path, profile_path, env = make_inputs(tmp_path)
    run = run_api()
    del run["pull_requests"]
    output = tmp_path / "publication"
    create_publication_directory(
        result_path=result_path,
        profile_path=profile_path,
        output_dir=output,
        env=env,
        transport=FakeTransport(run),
    )
    assert sorted(path.name for path in output.iterdir()) == ["provenance.json", "review-result.json"]


@pytest.mark.parametrize(
    ("associations", "reason"),
    [
        ([{"number": 45, "base": {"sha": BASE}, "head": {"sha": HEAD}}], "github_run_pull_request_revision_mismatch"),
        (
            [{"number": 44, "base": {"sha": "9" * 40}, "head": {"sha": HEAD}}],
            "github_run_pull_request_revision_mismatch",
        ),
        ([{"number": 44, "base": {"sha": BASE}, "head": {"sha": HEAD}}] * 2, "github_run_pull_requests_invalid"),
        (None, "github_run_pull_requests_invalid"),
    ],
)
def test_target_run_rejects_mismatching_or_ambiguous_present_associations(tmp_path, associations, reason):
    result_path, profile_path, env = make_inputs(tmp_path)
    with pytest.raises(BundleError, match=reason):
        create_publication_directory(
            result_path=result_path,
            profile_path=profile_path,
            output_dir=tmp_path / "publication",
            env=env,
            transport=FakeTransport(run_api(pull_requests=associations)),
        )


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        (
            {
                "base": {
                    "ref": "release",
                    "sha": BASE,
                    "repo": {"id": REPOSITORY_ID, "full_name": REPO, "default_branch": "main"},
                }
            },
            "github_pull_request_default_base_mismatch",
        ),
        (
            {
                "base": {
                    "ref": "main",
                    "sha": "9" * 40,
                    "repo": {"id": REPOSITORY_ID, "full_name": REPO, "default_branch": "main"},
                }
            },
            "caller_workflow_sha_invalid",
        ),
    ],
)
def test_moved_or_wrong_base_ref_fails_closed(tmp_path, change, reason):
    result_path, profile_path, env = make_inputs(tmp_path)
    pull = {
        "number": 44,
        "state": "open",
        "draft": False,
        "base": {
            "ref": "main",
            "sha": BASE,
            "repo": {"id": REPOSITORY_ID, "full_name": REPO, "default_branch": "main"},
        },
        "head": {"ref": "feature/update-dependency", "sha": HEAD},
    }
    pull.update(change)
    with pytest.raises(BundleError, match=reason):
        create_publication_directory(
            result_path=result_path,
            profile_path=profile_path,
            output_dir=tmp_path / "publication",
            env=env,
            transport=FakeTransport(run_api(), pull_request=pull),
        )


@pytest.mark.parametrize("event", ["pull_request", "workflow_dispatch", ""])
def test_non_target_source_event_cannot_emit_publication_bundle(tmp_path, event):
    result_path, profile_path, env = make_inputs(tmp_path)
    env["GITHUB_EVENT_NAME"] = event
    transport = FakeTransport(run_api())
    with pytest.raises(BundleError, match="publication_source_event_invalid"):
        create_publication_directory(
            result_path=result_path,
            profile_path=profile_path,
            output_dir=tmp_path / "publication",
            env=env,
            transport=transport,
        )
    assert transport.calls == 0


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    [
        ("GITHUB_REF", "refs/heads/feature", "github_workflow_ref_mismatch"),
        (
            "GITHUB_WORKFLOW_REF",
            f"{REPO}/.github/workflows/pr-review.yml@refs/heads/feature",
            "github_workflow_ref_mismatch",
        ),
        ("GITHUB_WORKFLOW_SHA", "9" * 40, "caller_workflow_sha_invalid"),
        ("GITHUB_SHA", "9" * 40, "caller_workflow_sha_invalid"),
    ],
)
def test_untrusted_or_moved_source_context_fails_before_api_reads(tmp_path, field, value, reason):
    result_path, profile_path, env = make_inputs(tmp_path)
    env[field] = value
    transport = FakeTransport(run_api())
    with pytest.raises(BundleError, match=reason):
        create_publication_directory(
            result_path=result_path,
            profile_path=profile_path,
            output_dir=tmp_path / "publication",
            env=env,
            transport=transport,
        )
    assert transport.calls == 0


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    [
        ("id", RUN_ID * 1.0, "github_run_id_invalid"),
        ("run_attempt", float(ATTEMPT), "github_run_attempt_invalid"),
    ],
)
def test_api_run_identifiers_must_be_positive_json_integers(tmp_path, field, value, reason):
    result_path, profile_path, env = make_inputs(tmp_path)
    with pytest.raises(BundleError, match=reason):
        create_publication_directory(
            result_path=result_path,
            profile_path=profile_path,
            output_dir=tmp_path / "publication",
            env=env,
            transport=FakeTransport(run_api(**{field: value})),
        )
    assert not (tmp_path / "publication").exists()


def test_profile_binding_mismatch_fails_before_github_read(tmp_path):
    result_path, profile_path, env = make_inputs(tmp_path)
    env["PROFILE_VERSION"] = "wrong-profile"
    transport = FakeTransport(run_api())
    with pytest.raises(BundleError, match="profile_binding_mismatch"):
        create_publication_directory(
            result_path=result_path,
            profile_path=profile_path,
            output_dir=tmp_path / "publication",
            env=env,
            transport=transport,
        )
    assert transport.calls == 0


def test_cross_repository_opt_in_fails_before_github_read(tmp_path):
    result_path, profile_path, env = make_inputs(tmp_path)
    env["TARGET_REPOSITORY"] = "other/repo"
    transport = FakeTransport(run_api())
    with pytest.raises(BundleError, match="publication_target_must_be_local"):
        create_publication_directory(
            result_path=result_path,
            profile_path=profile_path,
            output_dir=tmp_path / "publication",
            env=env,
            transport=transport,
        )
    assert transport.calls == 0


def test_workflow_publication_opt_in_is_disabled_by_default_and_read_only():
    root = Path(__file__).resolve().parents[1]
    workflow = (root / ".github/workflows/pr-analysis.yml").read_text()
    producer_step = workflow.split("Build the opt-in publication intake bundle from the sealed checkpoint", 1)[1]
    docs = (root / "docs/pr-analysis-publication-bundle.md").read_text()
    assert "emit_publication_bundle:" in workflow
    assert "default: false" in workflow
    assert "actions: read" in workflow
    assert "github.repository == inputs.target_repository" in workflow
    assert "PROVIDER_CONFIG:" in producer_step
    assert "DECISION_CONFIG:" in producer_step
    assert "github.event_name == 'pull_request_target'" in producer_step
    assert "github.ref == format('refs/heads/{0}', github.event.repository.default_branch)" in producer_step
    assert (chr(92) + "$" + "{{") not in workflow
    assert "actions: read" in docs
    assert "not a GitHub server attestation" in docs


def test_mutated_request_body_with_stale_result_hash_is_rejected(tmp_path):
    result_path, profile_path, env = make_inputs(tmp_path, result=sealed_result(request_hash="8" * 64))
    result = json.loads(result_path.read_text())
    result["request_hash"] = "9" * 64
    result_path.write_bytes(canonical(result) + b"\n")
    with pytest.raises(BundleError, match="sealed_result_intake_validation_failed"):
        create_publication_directory(
            result_path=result_path,
            profile_path=profile_path,
            output_dir=tmp_path / "publication",
            env=env,
            transport=FakeTransport(run_api()),
        )


def test_stale_result_hash_is_rejected_even_when_identity_matches(tmp_path):
    result = sealed_result()
    result["result_hash"] = "0" * 64
    result_path, profile_path, env = make_inputs(tmp_path, result=result)
    with pytest.raises(BundleError, match="sealed_result_intake_validation_failed"):
        create_publication_directory(
            result_path=result_path,
            profile_path=profile_path,
            output_dir=tmp_path / "publication",
            env=env,
            transport=FakeTransport(run_api()),
        )


def test_provider_identity_must_match_operator_configs_before_github_read(tmp_path):
    result_path, profile_path, env = make_inputs(tmp_path)
    changed_config = dict(PROVIDER_CONFIG, model="different-model")
    Path(env["PROVIDER_CONFIG"]).write_bytes(canonical(changed_config) + b"\n")
    transport = FakeTransport(run_api())
    with pytest.raises(BundleError, match="provider_identity_mismatch"):
        create_publication_directory(
            result_path=result_path,
            profile_path=profile_path,
            output_dir=tmp_path / "publication",
            env=env,
            transport=transport,
        )
    assert transport.calls == 0


def test_declared_result_contract_version_mismatch_is_rejected(tmp_path):
    result_path, profile_path, env = make_inputs(tmp_path, result=sealed_result(contract_version="1.0"))
    with pytest.raises(BundleError, match="result_contract_version_mismatch"):
        create_publication_directory(
            result_path=result_path,
            profile_path=profile_path,
            output_dir=tmp_path / "publication",
            env=env,
            transport=FakeTransport(run_api()),
        )


def test_provider_credential_value_in_sealed_result_is_rejected(tmp_path):
    secret = "credential-leak-sentinel-never-print"
    result_path, profile_path, env = make_inputs(tmp_path, result=sealed_result(debug_field=secret))
    env["LLM_API_KEY"] = secret
    with pytest.raises(BundleError, match="credential_leak_detected"):
        create_publication_directory(
            result_path=result_path,
            profile_path=profile_path,
            output_dir=tmp_path / "publication",
            env=env,
            transport=FakeTransport(run_api()),
        )


@pytest.mark.parametrize(
    ("duplicate", "extra", "expected"),
    [
        (True, (), "archive_file_count_invalid"),
        (False, (("unexpected.json", b"{}"),), "archive_file_count_invalid"),
    ],
)
def test_intake_rejects_duplicate_or_extra_members(tmp_path, duplicate, extra, expected):
    result_path, profile_path, env = make_inputs(tmp_path)
    output = tmp_path / "publication"
    create_publication_directory(
        result_path=result_path,
        profile_path=profile_path,
        output_dir=output,
        env=env,
        transport=FakeTransport(run_api()),
    )
    raw, digest = make_intake_zip(output, duplicate=duplicate, extra=extra)
    manifest = json.loads((output / MANIFEST_FILENAME).read_text())
    with pytest.raises(ArtifactIntakeError, match=expected):
        intake_artifact_bundle(
            io.BytesIO(raw),
            _identity_from_manifest(manifest),
            digest,
            trusted_attestation_identity=AttestationIdentity(
                issuer="https://token.actions.githubusercontent.com",
                repository_id=manifest["repository_id"],
                repository=manifest["repository"],
                workflow_id=manifest["caller_workflow_id"],
                workflow_path=manifest["caller_workflow_path"],
                workflow_ref=manifest["caller_workflow_ref"],
                workflow_sha=manifest["caller_workflow_sha"],
                run_id=manifest["upstream_run_id"],
                run_attempt=manifest["upstream_run_attempt"],
                called_harness_repository=manifest["called_harness_repository"],
                called_harness_path=manifest["called_harness_path"],
                called_harness_sha=manifest["called_harness_sha"],
            ),
        )
