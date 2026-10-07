import hashlib
import io
import json
import subprocess
import zipfile
from datetime import datetime, timedelta, timezone
from urllib.parse import unquote, urlsplit

import pytest
import test_pr_analysis_publication_bundle as producer_fixture
from test_actions_publication import BASE, HEAD, WRITER, bundle_for, make_policy, make_valid_result, response
from test_github_app_canary import private_key_pem

import pr_review_harness.protected_publication_runtime as runtime
from pr_review_harness.actions_publication import (
    ArtifactUploadResult,
    HTTPResponse,
)
from pr_review_harness.publication_receipts import EffectSlot
from pr_review_harness.report import render_report

CALLED_SHA = "e" * 40
DEFAULT_BRANCH_TIP = "f" * 40


def policy_document(*, enabled=True, dispositions=None):
    policy = make_policy()
    return {
        "schema": "pr-review-protected-publication-policy.v1",
        "enabled": enabled,
        "repository": {"name": policy.repository, "id": policy.repository_id},
        "default_branch": "main",
        "publisher_workflow": {
            "id": policy.publisher_workflow_id,
            "path": policy.publisher_workflow_path,
            "ref": f"{policy.repository}/{policy.publisher_workflow_path}@refs/heads/main",
        },
        "source_workflow": {
            "id": policy.caller_workflow_id,
            "path": policy.caller_workflow_path,
            "ref": f"{policy.repository}/{policy.caller_workflow_path}@refs/heads/main",
        },
        "called_harness": {
            "repository": policy.called_harness_repository,
            "path": policy.called_harness_path,
            "sha": CALLED_SHA,
        },
        "app": {"id": 333, "installation_id": 444, "slug": "review-agent", "actor_login": WRITER},
        "profile": {
            "version": policy.profile_version,
            "sha256": policy.profile_sha256,
            "provider_configuration_identity": policy.provider_configuration_identity,
        },
        "publication": {
            "allowed_dispositions": dispositions or ["COMMENT"],
            "max_review_body_bytes": 60_000,
            "effect_policy": "PUBLISH_REVIEW",
        },
        "limits": {"max_runs": 20, "max_pages": 2, "max_reviews": 100, "deadline_seconds": 25},
        "artifact_trust_mode": "API_BOUND_SHA256",
        "artifact_redirect_hosts": ["downloads.example.test"],
    }


def actions_token_policy_document(*, enabled=False):
    value = policy_document(enabled=enabled)
    value.pop("app")
    value["schema"] = "pr-review-protected-publication-policy.v2"
    value["authorization_mode"] = "STANDING_BOUNDED"
    value["credential"] = {"kind": "ACTIONS_TOKEN", "actor_login": "github-actions[bot]"}
    value["publisher_workflow"]["sha256"] = hashlib.sha256(
        b"name: protected publisher\n"
    ).hexdigest()
    return value


def protected_checkout(tmp_path, *, enabled=True, policy_value=None):
    workspace = tmp_path / "protected"
    (workspace / ".github/workflows").mkdir(parents=True)
    (workspace / ".github/pr-review-publisher-policy.json").write_text(
        json.dumps(policy_value or policy_document(enabled=enabled), sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    (workspace / ".github/workflows/pr-publish.yml").write_text("name: protected publisher\n", encoding="utf-8")
    (workspace / ".github/workflows/pr-analysis.yml").write_text("name: analysis source\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(workspace)], check=True)
    subprocess.run(["git", "-C", str(workspace), "add", "."], check=True)
    subprocess.run(
        ["git", "-C", str(workspace), "-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "trusted fixture"],
        check=True,
    )
    revision = subprocess.check_output(["git", "-C", str(workspace), "rev-parse", "HEAD"], text=True).strip()
    event_path = tmp_path / "event.json"
    event_path.write_text(json.dumps({}), encoding="utf-8")
    return workspace, revision, event_path


def event_payload(*, include_pr=True):
    policy = make_policy()
    return {
        "repository": {"id": policy.repository_id, "full_name": policy.repository, "default_branch": "main"},
        "workflow_run": {
            "id": policy.upstream_run_id,
            "run_attempt": policy.upstream_run_attempt,
            "workflow_id": policy.caller_workflow_id,
            "path": policy.caller_workflow_path,
            "head_branch": "feature/review-target",
            "head_sha": HEAD,
            "event": "pull_request_target",
            "pull_requests": [
                {"number": policy.pull_request_number, "base": {"sha": BASE}, "head": {"sha": HEAD}}
            ] if include_pr else [],
        },
    }


def rebind_manifest_target(bundle, *, base_sha=None, head_sha=None, caller_workflow_sha=None):
    source = io.BytesIO(bundle)
    entries = {}
    with zipfile.ZipFile(source) as archive:
        for info in archive.infolist():
            entries[info.filename] = archive.read(info.filename)
    manifest = json.loads(entries["provenance.json"])
    if base_sha is not None:
        manifest["base_sha"] = base_sha
    if head_sha is not None:
        manifest["head_sha"] = head_sha
    if caller_workflow_sha is not None:
        manifest["caller_workflow_sha"] = caller_workflow_sha
    entries["provenance.json"] = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in entries.items():
            archive.writestr(name, content)
    return output.getvalue()


def rebind_manifest_provider_identity(bundle, provider_identity):
    source = io.BytesIO(bundle)
    entries = {}
    with zipfile.ZipFile(source) as archive:
        for info in archive.infolist():
            entries[info.filename] = archive.read(info.filename)
    manifest = json.loads(entries["provenance.json"])
    manifest["provider_configuration_identity"] = provider_identity
    entries["provenance.json"] = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in entries.items():
            archive.writestr(name, content)
    return output.getvalue()


def actions_environment(workspace, revision, event_path):
    policy = make_policy()
    return {
        "GITHUB_WORKSPACE": str(workspace),
        "GITHUB_SHA": revision,
        "GITHUB_REPOSITORY": policy.repository,
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_WORKFLOW_REF": f"{policy.repository}/{policy.publisher_workflow_path}@refs/heads/main",
        "GITHUB_RUN_ID": str(policy.publisher_run_id),
        "GITHUB_RUN_ATTEMPT": "1",
        "GITHUB_EVENT_PATH": str(event_path),
        "GITHUB_TOKEN": "test-actions-read-token",
        "PR_REVIEW_GITHUB_APP_PRIVATE_KEY": "test-private-key-sentinel",
        "ACTIONS_RUNTIME_TOKEN": "test-artifact-runtime-token",
        "ACTIONS_RESULTS_URL": "https://actions.githubusercontent.com/results/",
        "PATH": "/usr/bin:/bin",
    }


class ReceiptUploader:
    def __init__(self, receipt_archives):
        self.receipt_archives = receipt_archives
        self.calls = []

    def upload(self, *, run_id, artifact_name, filename, content, timeout_seconds):
        self.calls.append((run_id, artifact_name, filename, content, timeout_seconds))
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr(filename, content)
        self.receipt_archives[run_id] = stream.getvalue()
        return ArtifactUploadResult("UPLOADED", artifact_id=991)


class E2ETransport:
    def __init__(self, responder, result_bundle, receipt_archives, events):
        self.responder = responder
        self.result_bundle = result_bundle
        self.receipt_archives = receipt_archives
        self.events = events
        self.calls = []
        self.download_calls = []

    def request(self, method, url, *, token, json_body, timeout_seconds, max_response_bytes):
        self.calls.append((method, url, token, json_body, timeout_seconds, max_response_bytes))
        if method == "POST" and urlsplit(url).path.endswith("/pulls/44/reviews"):
            self.events.append("review_post")
        return self.responder(method, url, json_body)

    def download(self, url, *, timeout_seconds, max_response_bytes):
        self.download_calls.append((url, timeout_seconds, max_response_bytes))
        self.events.append("source_artifact_download" if "result?" in url else "receipt_artifact_download")
        payload = self.result_bundle if "result?" in url else self.receipt_archives[900001]
        return HTTPResponse(200, {}, payload)


def test_disabled_policy_returns_before_private_key_event_or_github_access(tmp_path):
    workspace, revision, event_path = protected_checkout(tmp_path, enabled=False)
    env = actions_environment(workspace, revision, event_path)
    key_calls = []

    class NoGitHub:
        def request(self, *_args, **_kwargs):
            pytest.fail("disabled runtime must not call GitHub")

    result = runtime.run_protected_publication(env, transport=NoGitHub(), key_supplier=lambda: key_calls.append(True))

    assert result == {
        "schema": "pr-review-protected-publication.v1",
        "status": "DISABLED",
        "reason": "publication_disabled",
    }
    assert key_calls == []


def test_disabled_actions_token_policy_returns_before_any_credential_or_api_access(tmp_path):
    workspace, revision, event_path = protected_checkout(tmp_path, enabled=False)
    policy_path = workspace / ".github/pr-review-publisher-policy.json"
    policy_path.write_text(
        json.dumps(actions_token_policy_document(), sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    subprocess.run(["git", "-C", str(workspace), "add", "."], check=True)
    subprocess.run(
        ["git", "-C", str(workspace), "-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "disabled actions policy"],
        check=True,
    )
    revision = subprocess.check_output(["git", "-C", str(workspace), "rev-parse", "HEAD"], text=True).strip()
    env = actions_environment(workspace, revision, event_path)
    touched = []

    class TrackingEnvironment(dict):
        def get(self, key, default=None):
            if key in {"GITHUB_TOKEN", "PR_REVIEW_GITHUB_APP_PRIVATE_KEY"}:
                touched.append(key)
            return super().get(key, default)

    class NoGitHub:
        def request(self, *_args, **_kwargs):
            pytest.fail("disabled policy must not call GitHub")

    class NoUpload:
        def upload(self, *_args, **_kwargs):
            pytest.fail("disabled policy must not upload a receipt")

    result = runtime.run_protected_publication(TrackingEnvironment(env), transport=NoGitHub(), artifact_uploader=NoUpload())

    assert result["status"] == "DISABLED"
    assert result["reason"] == "publication_disabled"
    assert touched == []


def test_actions_token_v2_policy_is_strict_and_keeps_standing_authorization_explicit():
    parsed = runtime.ProtectedPublicationPolicy.parse(actions_token_policy_document())
    assert parsed.credential_kind.value == "ACTIONS_TOKEN"
    assert parsed.actor_login == "github-actions[bot]"
    assert parsed.actions_token_policy().permissions == (("actions", "read"), ("pull_requests", "write"))
    assert parsed.publication_config()["allowed_actors"] == ["github-actions[bot]"]

    malformed = actions_token_policy_document()
    malformed["credential"]["app"] = {"id": 1}
    with pytest.raises(runtime.ProtectedRuntimeError, match="protected_policy_credential_invalid"):
        runtime.ProtectedPublicationPolicy.parse(malformed)

    for provider_identity in (
        "provider-config-sha256:" + "c" * 64,
        "provider-identity-sha256:" + "g" * 64,
        "provider-identity-sha256:" + "c" * 63,
    ):
        malformed_identity = actions_token_policy_document()
        malformed_identity["profile"]["provider_configuration_identity"] = provider_identity
        with pytest.raises(runtime.ProtectedRuntimeError, match="protected_policy_profile_invalid"):
            runtime.ProtectedPublicationPolicy.parse(malformed_identity)

    missing_workflow_hash = actions_token_policy_document()
    missing_workflow_hash["publisher_workflow"].pop("sha256")
    with pytest.raises(runtime.ProtectedRuntimeError, match="protected_policy_workflow_invalid"):
        runtime.ProtectedPublicationPolicy.parse(missing_workflow_hash)

    unspecified = actions_token_policy_document()
    unspecified["authorization_mode"] = "PER_RESULT"
    with pytest.raises(runtime.ProtectedRuntimeError, match="protected_policy_schema_invalid"):
        runtime.ProtectedPublicationPolicy.parse(unspecified)


@pytest.mark.parametrize("schema", ["v1", "v2"])
@pytest.mark.parametrize("app_value", [None, "missing"])
def test_app_routes_require_a_real_app_policy_object(schema, app_value):
    value = policy_document()
    if schema == "v2":
        value = actions_token_policy_document()
        value["credential"] = {"kind": "APP_INSTALLATION", "app": {}}
    if app_value == "missing":
        if schema == "v1":
            value.pop("app")
        else:
            value["credential"].pop("app")
    elif schema == "v1":
        value["app"] = None
    else:
        value["credential"]["app"] = None
    with pytest.raises(runtime.ProtectedRuntimeError):
        runtime.ProtectedPublicationPolicy.parse(value)


def test_actions_workflow_digest_mismatch_fails_before_token_transport_or_upload(tmp_path):
    policy_value = actions_token_policy_document(enabled=True)
    policy_value["publisher_workflow"]["sha256"] = "0" * 64
    workspace, revision, event_path = protected_checkout(tmp_path, policy_value=policy_value)
    touched = []

    class NoGitHub:
        def request(self, *_args, **_kwargs):
            touched.append("http")
            pytest.fail("workflow mismatch must be rejected before API access")

    class NoUpload:
        def upload(self, *_args, **_kwargs):
            touched.append("upload")
            pytest.fail("workflow mismatch must be rejected before upload")

    class TrackingEnvironment(dict):
        def get(self, key, default=None):
            if key == "GITHUB_TOKEN":
                touched.append("token")
            return super().get(key, default)

    result = runtime.run_protected_publication(
        TrackingEnvironment(actions_environment(workspace, revision, event_path)),
        transport=NoGitHub(),
        artifact_uploader=NoUpload(),
    )
    assert result["status"] == "UNKNOWN"
    assert result["reason"] == "protected_publisher_workflow_mismatch"
    assert touched == []


def test_protected_policy_drift_is_rejected_before_key_supplier(tmp_path):
    workspace, revision, event_path = protected_checkout(tmp_path)
    policy_path = workspace / ".github/pr-review-publisher-policy.json"
    policy_path.write_text(policy_path.read_text(encoding="utf-8").replace('"enabled":true', '"enabled":false'), encoding="utf-8")
    key_calls = []

    result = runtime.run_protected_publication(
        actions_environment(workspace, revision, event_path),
        key_supplier=lambda: key_calls.append("secret"),
    )

    assert result["status"] == "UNKNOWN"
    assert result["reason"] == "protected_source_revision_mismatch"
    assert key_calls == []


@pytest.mark.parametrize("source_event", ["pull_request", "workflow_dispatch"])
def test_runtime_rejects_unprotected_source_event_before_app_key_or_api(tmp_path, source_event):
    workspace, revision, event_path = protected_checkout(tmp_path)
    event = event_payload()
    event["workflow_run"]["event"] = source_event
    event_path.write_text(json.dumps(event), encoding="utf-8")
    key_calls = []

    class NoGitHub:
        def request(self, *_args, **_kwargs):
            pytest.fail("unprotected source event must be rejected before GitHub access")

    result = runtime.run_protected_publication(
        actions_environment(workspace, revision, event_path),
        transport=NoGitHub(),
        key_supplier=lambda: key_calls.append("read"),
    )

    assert result["status"] == "UNKNOWN"
    assert result["reason"] == "workflow_event_identity_invalid"
    assert key_calls == []


@pytest.mark.parametrize(
    ("failure_mode", "source_association", "credential_route"),
    [
        (mode, association, "APP")
        for mode in (
            "success",
            "duplicate_source_artifact",
            "stale_base",
            "stale_head",
            "caller_workflow_sha_mismatch",
            "stale_default_tip_before_ack",
            "stale_default_tip_after_ack",
            "deadline",
            "receipt_ack_missing",
            "write_token_denied",
        )
        for association in ("empty", "omitted", "row-with-older-pr-base")
    ]
    + [("success", association, "ACTIONS_TOKEN") for association in ("empty", "omitted", "row-with-older-pr-base")]
    + [("post_forbidden", "empty", "ACTIONS_TOKEN")],
)
def test_runtime_composes_api_bound_intake_receipt_ack_fresh_head_and_single_post(
    tmp_path, monkeypatch, failure_mode, source_association, credential_route
):
    policy_value = (
        actions_token_policy_document(enabled=True)
        if credential_route == "ACTIONS_TOKEN"
        else policy_document(enabled=True)
    )
    workspace, revision, event_path = protected_checkout(tmp_path, policy_value=policy_value)
    event_path.write_text(json.dumps(event_payload(include_pr=False)), encoding="utf-8")
    policy = make_policy(publisher_workflow_sha=revision, caller_workflow_sha=DEFAULT_BRANCH_TIP)
    result = make_valid_result()
    bundle = bundle_for(policy, result)
    if failure_mode == "stale_base":
        bundle = rebind_manifest_target(bundle, base_sha="c" * 40)
    elif failure_mode == "stale_head":
        bundle = rebind_manifest_target(bundle, head_sha="c" * 40)
    elif failure_mode == "caller_workflow_sha_mismatch":
        bundle = rebind_manifest_target(bundle, caller_workflow_sha="d" * 40)
    elif failure_mode == "provider_identity_mismatch":
        bundle = rebind_manifest_provider_identity(bundle, "provider-identity-sha256:" + "0" * 64)
    receipt_archives = {}
    events = []
    stored_reviews = []
    post_bodies = []
    pull_reads = 0
    default_branch_reads = 0
    publisher_run = {
        "id": policy.publisher_run_id,
        "run_attempt": policy.publisher_run_attempt,
        "workflow_id": policy.publisher_workflow_id,
        "head_sha": revision,
        "head_branch": "main",
        "status": "in_progress",
        "conclusion": None,
        "repository": {"id": policy.repository_id, "full_name": policy.repository},
        "actor": {"login": WRITER},
        "pull_requests": [{"number": policy.pull_request_number, "base": {"sha": BASE}, "head": {"sha": HEAD}}],
        "path": policy.publisher_workflow_path,
        "event": "workflow_run",
    }
    publisher_detail = dict(publisher_run)
    upstream_detail = {
        "id": policy.upstream_run_id,
        "run_attempt": policy.upstream_run_attempt,
        "workflow_id": policy.caller_workflow_id,
        "repository": {"id": policy.repository_id, "full_name": policy.repository},
        "actor": {"login": WRITER},
        "head_branch": "feature/review-target",
        "path": policy.caller_workflow_path,
        "head_sha": HEAD,
        "event": "pull_request_target",
        "status": "completed",
        "conclusion": "success",
        "pull_requests": (
            []
            if source_association == "empty"
            else [
                {
                    "number": policy.pull_request_number,
                    "base": {"sha": BASE},
                    "head": {"sha": HEAD},
                }
            ]
            if source_association == "row-with-older-pr-base"
            else None
        ),
        "referenced_workflows": [
            {"path": policy.called_harness_repository + "/" + policy.called_harness_path + "@refs/heads/main", "sha": CALLED_SHA}
        ],
    }
    if source_association == "omitted":
        upstream_detail.pop("pull_requests")
    result_artifact = {
        "id": 123,
        "name": policy.result_artifact_name,
        "size_in_bytes": len(bundle),
        "digest": "sha256:" + hashlib.sha256(bundle).hexdigest(),
        "expired": False,
        "workflow_run": {"id": policy.upstream_run_id, "repository_id": policy.repository_id, "head_sha": HEAD},
    }

    def api_response(method, url, body):
        nonlocal pull_reads, default_branch_reads
        path = urlsplit(url).path
        query = urlsplit(url).query
        if path.endswith("/branches/main"):
            default_branch_reads += 1
            changed_at = 3 if failure_mode == "stale_default_tip_before_ack" else 4
            tip = "c" * 40 if failure_mode.startswith("stale_default_tip_") and default_branch_reads >= changed_at else DEFAULT_BRANCH_TIP
            return response({"name": "main", "commit": {"sha": tip}})
        if path == "/app":
            return response({"id": 333, "slug": "review-agent"})
        if path == "/app/installations/444" or path.endswith("/repos/owner/repo/installation"):
            return response({
                "id": 444,
                "app_id": 333,
                "account": {"login": "owner", "id": 77},
                "suspended_at": None,
            })
        if path == "/app/installations/444/access_tokens" and method == "POST":
            permissions = dict(body["permissions"])
            if permissions["pull_requests"] == "write":
                events.append("write_token_mint")
                if failure_mode == "write_token_denied":
                    return response({"message": "denied"}, status=403)
            return response({
                "token": "app-installation-" + permissions["pull_requests"],
                "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=55)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "permissions": {**permissions, "metadata": "read"},
            }, status=201)
        if path == "/installation/repositories":
            return response({"total_count": 1, "repositories": [{"id": policy.repository_id, "full_name": policy.repository}]})
        if path == "/users/review-agent[bot]" or unquote(path) == "/users/review-agent[bot]":
            return response({"id": 88, "login": WRITER, "type": "Bot"})
        if path.endswith("/pulls/44"):
            pull_reads += 1
            return response({"number": 44, "state": "open", "draft": False, "base": {"sha": BASE, "ref": "main", "repo": {"id": policy.repository_id}}, "head": {"sha": HEAD, "ref": "feature/review-target"}})
        if path.endswith(f"/actions/runs/{policy.upstream_run_id}/attempts/1"):
            return response(upstream_detail)
        if path.endswith(f"/actions/runs/{policy.upstream_run_id}"):
            return response(upstream_detail)
        if path.endswith(f"/actions/runs/{policy.publisher_run_id}/attempts/1"):
            return response(publisher_detail)
        if path.endswith(f"/actions/runs/{policy.publisher_run_id}"):
            return response(publisher_detail)
        if path.endswith(f"/actions/runs/{policy.upstream_run_id}/artifacts"):
            assert "name=" + policy.result_artifact_name in query
            if failure_mode == "duplicate_source_artifact":
                duplicate = dict(result_artifact)
                duplicate["id"] += 1
                return response({"total_count": 2, "artifacts": [result_artifact, duplicate]})
            return response({"total_count": 1, "artifacts": [result_artifact]})
        if path.endswith(f"/actions/runs/{policy.publisher_run_id}/artifacts"):
            if not receipt_archives or failure_mode == "receipt_ack_missing":
                return response({"total_count": 0, "artifacts": []})
            receipt_name = policy.receipt_artifact_name(EffectSlot(policy.repository_id, policy.repository, 44, HEAD))
            archived = receipt_archives[policy.publisher_run_id]
            return response({"total_count": 1, "artifacts": [{
                "id": 991, "name": receipt_name, "size_in_bytes": len(archived),
                "digest": "sha256:" + hashlib.sha256(archived).hexdigest(), "expired": False,
                "expires_at": "2999-01-01T00:00:00Z",
                "workflow_run": {"id": policy.publisher_run_id, "repository_id": policy.repository_id, "run_attempt": 1},
            }]})
        if path.endswith(f"/actions/workflows/{policy.publisher_workflow_id}/runs"):
            return response({"total_count": 0, "workflow_runs": []})
        if path.endswith("/pulls/44/reviews") and method == "GET":
            return response(stored_reviews)
        if path.endswith("/actions/artifacts/123/zip"):
            return HTTPResponse(302, {"location": "https://downloads.example.test/result?signature=one-use"}, b"")
        if path.endswith("/actions/artifacts/991/zip"):
            return HTTPResponse(302, {"location": "https://downloads.example.test/receipt?signature=one-use"}, b"")
        if path.endswith("/pulls/44/reviews") and method == "POST":
            post_bodies.append(body)
            if failure_mode == "post_forbidden":
                return response({"message": "permission denied"}, status=403)
            post_actor = "github-actions[bot]" if credential_route == "ACTIONS_TOKEN" else WRITER
            return response({"id": 777, "commit_id": HEAD, "state": "COMMENTED", "body": body["body"], "user": {"login": post_actor}})
        raise AssertionError(f"unexpected fake API request: {method} {url}")

    class TestClock:
        now = 0.0

        def __call__(self):
            return self.now

    clock = TestClock()

    class DeadlineTransport(E2ETransport):
        def request(self, method, url, *, token, json_body, timeout_seconds, max_response_bytes):
            result_value = super().request(
                method,
                url,
                token=token,
                json_body=json_body,
                timeout_seconds=timeout_seconds,
                max_response_bytes=max_response_bytes,
            )
            if failure_mode == "deadline" and url.endswith(f"/actions/runs/{policy.upstream_run_id}"):
                clock.now = 26.0
            return result_value

    transport = DeadlineTransport(api_response, bundle, receipt_archives, events)
    actual_key = private_key_pem()
    uploader = ReceiptUploader(receipt_archives)
    original_upload = uploader.upload

    def record_upload(**kwargs):
        events.append("receipt_upload")
        return original_upload(**kwargs)

    uploader.upload = record_upload
    key_calls = []
    admitted = []
    real_adapter = runtime.GitHubActionsPublicationAdapter

    class CapturingAdapter(real_adapter):
        def admit(self, result, config, limits):
            admission = super().admit(result, config, limits)
            admitted.append(admission)
            return admission

    monkeypatch.setattr(runtime, "GitHubActionsPublicationAdapter", CapturingAdapter)
    outcome = runtime.run_protected_publication(
        actions_environment(workspace, revision, event_path),
        transport=transport,
        artifact_uploader=uploader,
        key_supplier=lambda: (key_calls.append(True) or actual_key),
        clock=clock,
    )

    if failure_mode == "success":
        assert outcome["schema"] == "pr-review-protected-publication.v1"
        assert outcome["status"] == "CONFIRMED", (outcome, events, admitted)
        assert outcome["reason"] is None
        if credential_route == "ACTIONS_TOKEN":
            assert outcome["effect_observation"] == {
                "actor_login": "github-actions[bot]",
                "review_state": "COMMENTED",
                "review_id": 777,
                "write_capability": "OBSERVED_SUCCESS",
            }
            receipt_bytes = zipfile.ZipFile(io.BytesIO(receipt_archives[policy.publisher_run_id])).read(
                "attempt-receipt.json"
            )
            receipt_value = json.loads(receipt_bytes)
            assert receipt_value["protocol_version"] == "actions-receipt-v2"
            assert receipt_value["credential_provenance"]["write_capability"] == "NOT_TESTED"
            assert receipt_value["credential_provenance"]["permission_basis"] == "WORKFLOW_DECLARATION"
            assert receipt_value["credential_provenance"]["declared_job_permissions"] == {
                "actions": "read",
                "contents": "read",
                "pull-requests": "write",
            }
            assert receipt_value["credential_provenance"]["publisher_workflow_sha256"] == hashlib.sha256(
                b"name: protected publisher\n"
            ).hexdigest()
        else:
            assert outcome == {"schema": "pr-review-protected-publication.v1", "status": "CONFIRMED", "reason": None}
        assert len(admitted) == 1
        assert admitted[0].concurrency_scope == "repository"
        assert admitted[0].concurrency_group == f"pr-review-publish-{policy.repository_id}"
    else:
        assert outcome["status"] == "UNKNOWN"
        if failure_mode == "post_forbidden":
            assert outcome["reason"] == "submit_response_ambiguous"
        expected_reason = {
            "caller_workflow_sha_mismatch": "source_artifact_manifest_policy_mismatch",
            "provider_identity_mismatch": "source_artifact_manifest_policy_mismatch",
            "stale_default_tip_before_ack": "pre_receipt_head_unavailable",
            "stale_default_tip_after_ack": "post_receipt_head_unavailable",
        }.get(failure_mode)
        if expected_reason is not None:
            assert outcome["reason"] == expected_reason
    assert len(uploader.calls) == (
        0
        if failure_mode
        in {
            "duplicate_source_artifact",
            "stale_base",
            "stale_head",
            "caller_workflow_sha_mismatch",
            "provider_identity_mismatch",
            "stale_default_tip_before_ack",
            "deadline",
        }
        else 1
    ), (failure_mode, outcome, events)
    if failure_mode == "success":
        assert len(post_bodies) == 1
        assert events.count("source_artifact_download") == 3
        assert events.count("write_token_mint") == (1 if credential_route == "APP" else 0)
        assert events.count("receipt_upload") == 1
        assert events.count("receipt_artifact_download") == 1
        assert events.count("review_post") == 1
        assert max(i for i, item in enumerate(events) if item == "source_artifact_download") < events.index("receipt_upload")
        assert events.index("receipt_upload") < events.index("receipt_artifact_download")
        if credential_route == "APP":
            assert events.index("receipt_artifact_download") < events.index("write_token_mint") < events.index("review_post")
        assert post_bodies[0]["commit_id"] == HEAD
        assert post_bodies[0]["event"] == "COMMENT"
        assert post_bodies[0]["body"].endswith(" -->")
        assert any("/actions/artifacts/123/zip" in call[1] for call in transport.calls)
        assert any("/actions/artifacts/991/zip" in call[1] for call in transport.calls)
        assert pull_reads >= 3
        assert all(actual_key not in repr(call) for call in transport.calls)
        if credential_route == "ACTIONS_TOKEN":
            assert all(call[2] == "test-actions-read-token" for call in transport.calls)
            assert all("/app" not in call[1] for call in transport.calls)
    else:
        if failure_mode == "post_forbidden":
            assert len(post_bodies) == 1
            assert events.count("review_post") == 1
        else:
            assert post_bodies == []
            assert events.count("review_post") == 0
        assert len(key_calls) == (0 if credential_route == "ACTIONS_TOKEN" else (
            0
            if failure_mode in {"caller_workflow_sha_mismatch", "provider_identity_mismatch", "duplicate_source_artifact", "stale_base", "stale_head", "deadline"}
            else 1
        ))
        assert events.count("write_token_mint") == (1 if failure_mode == "write_token_denied" else 0)
        if failure_mode in {
            "duplicate_source_artifact",
            "stale_base",
            "stale_head",
            "caller_workflow_sha_mismatch",
            "provider_identity_mismatch",
            "stale_default_tip_before_ack",
            "deadline",
        }:
            assert events.count("receipt_upload") == 0
        if failure_mode == "receipt_ack_missing":
            assert events.count("receipt_upload") == 1
    if credential_route == "ACTIONS_TOKEN":
        assert key_calls == []
        assert events.count("write_token_mint") == 0
        assert all(call[2] == "test-actions-read-token" for call in transport.calls)
        assert all("/app" not in call[1] for call in transport.calls)


def test_real_bundle_producer_integrates_with_protected_consumer(tmp_path):
    provider_identity = producer_fixture.PROVIDER_IDENTITY
    provider_hash = producer_fixture._canonical_hash(provider_identity)
    profile_value = {"repository": "owner/repo", "version": "profile-v3"}
    profile_raw = producer_fixture.canonical(profile_value)
    profile_hash = hashlib.sha256(profile_raw).hexdigest()
    original_make_policy = make_policy
    counter = 0

    def integrated_policy(**kwargs):
        kwargs.setdefault("provider_configuration_identity", f"provider-identity-sha256:{provider_hash}")
        kwargs.setdefault("profile_sha256", profile_hash)
        kwargs.setdefault("called_harness_path", ".github/workflows/pr-analysis.yml")
        return original_make_policy(**kwargs)

    def real_producer_bundle(policy, result):
        nonlocal counter
        case_dir = tmp_path / f"producer-{counter}"
        counter += 1
        case_dir.mkdir()
        result_value = dict(result)
        result_value["run_id"] = f"pr-{policy.pull_request_number}-{policy.upstream_run_id}"
        result_value["project_profile_version"] = policy.profile_version
        result_value["provider_identity"] = provider_identity
        result_value["rendered_review"] = render_report(result_value)
        result_value["result_hash"] = producer_fixture._canonical_hash(
            {key: value for key, value in result_value.items() if key != "result_hash"}
        )
        result_path = case_dir / "sealed-result.json"
        result_path.write_bytes(producer_fixture.canonical(result_value) + b"\n")
        profile_path = case_dir / "profile.json"
        profile_path.write_bytes(profile_raw)
        provider_path = case_dir / "provider.json"
        provider_path.write_bytes(producer_fixture.canonical(producer_fixture.PROVIDER_CONFIG) + b"\n")
        decision_path = case_dir / "decision.json"
        decision_path.write_bytes(producer_fixture.canonical(producer_fixture.DECISION_CONFIG) + b"\n")
        env = {
            "GITHUB_REPOSITORY": policy.repository,
            "TARGET_REPOSITORY": policy.repository,
            "GITHUB_RUN_ID": str(policy.upstream_run_id),
            "GITHUB_RUN_ATTEMPT": str(policy.upstream_run_attempt),
            "GITHUB_SHA": DEFAULT_BRANCH_TIP,
            "GITHUB_WORKFLOW_SHA": DEFAULT_BRANCH_TIP,
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_WORKFLOW_REF": f"{policy.repository}/{policy.caller_workflow_path}@refs/heads/main",
            "GITHUB_EVENT_NAME": "pull_request_target",
            "GITHUB_DEFAULT_BRANCH": "main",
            "PR_NUMBER": str(policy.pull_request_number),
            "BASE_SHA": BASE,
            "HEAD_SHA": HEAD,
            "HARNESS_REPOSITORY": policy.called_harness_repository,
            "HARNESS_SHA": policy.called_harness_sha,
            "CALLED_WORKFLOW_REPOSITORY": policy.called_harness_repository,
            "CALLED_WORKFLOW_FILE_PATH": policy.called_harness_path,
            "CALLED_WORKFLOW_SHA": policy.called_harness_sha,
            "CALLED_WORKFLOW_REF": f"{policy.called_harness_repository}/{policy.called_harness_path}@{policy.called_harness_sha}",
            "PROFILE_VERSION": policy.profile_version,
            "PROFILE_SHA256": profile_hash,
            "PROVIDER_CONFIG": str(provider_path),
            "DECISION_CONFIG": str(decision_path),
            "GH_TOKEN": "fixture-read-token",
            "LLM_API_KEY": "fixture-primary-key",
            "JEV_API_KEY": "fixture-decision-key",
        }
        output = case_dir / "publication"
        run_document = producer_fixture.run_api(
            id=policy.upstream_run_id,
            run_attempt=policy.upstream_run_attempt,
            workflow_id=policy.caller_workflow_id,
            path=policy.caller_workflow_path,
            head_sha=HEAD,
            repository={"id": policy.repository_id, "full_name": policy.repository},
        )
        pull_document = {
            "number": policy.pull_request_number,
            "state": "open",
            "draft": False,
            "base": {
                "ref": "main",
                "sha": BASE,
                "repo": {"id": policy.repository_id, "full_name": policy.repository, "default_branch": "main"},
            },
            "head": {"ref": "feature/update-dependency", "sha": HEAD},
        }

        class ProducerAPI:
            def request(self, method, url, **kwargs):
                assert method == "GET"
                assert kwargs["timeout_seconds"] == 10
                if url.endswith("/branches/main"):
                    document = {"name": "main", "commit": {"sha": DEFAULT_BRANCH_TIP}}
                elif url.endswith(f"/actions/runs/{policy.upstream_run_id}/attempts/{policy.upstream_run_attempt}"):
                    document = run_document
                elif url.endswith(f"/pulls/{policy.pull_request_number}"):
                    document = pull_document
                else:
                    raise AssertionError(f"unexpected producer API URL: {url}")
                return producer_fixture.HTTPResponse(200, {"content-type": "application/json"}, producer_fixture.canonical(document))

        producer_fixture.create_publication_directory(
            result_path=result_path,
            profile_path=profile_path,
            output_dir=output,
            env=env,
            transport=ProducerAPI(),
            provider_config_path=provider_path,
            decision_config_path=decision_path,
        )
        bundle, _digest = producer_fixture.make_intake_zip(output)
        return bundle

    test_cases = (
        ("success", "Canonical producer identity is accepted and publishes once."),
        ("provider_identity_mismatch", "A different identity is rejected before fake POST."),
        ("duplicate_source_artifact", "Duplicate source artifacts produce no fake POST."),
    )
    import sys

    module = sys.modules[__name__]
    for index, (failure_mode, _description) in enumerate(test_cases):
        case_path = tmp_path / f"consumer-{index}"
        case_path.mkdir()
        with pytest.MonkeyPatch.context() as patcher:
            patcher.setattr(module, "make_policy", integrated_policy)
            patcher.setattr(module, "bundle_for", real_producer_bundle)
            test_runtime_composes_api_bound_intake_receipt_ack_fresh_head_and_single_post(
                case_path,
                patcher,
                failure_mode,
                "empty",
                "ACTIONS_TOKEN",
            )
