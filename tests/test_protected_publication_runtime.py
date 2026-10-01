import hashlib
import io
import json
import subprocess
import zipfile
from datetime import datetime, timedelta, timezone
from urllib.parse import unquote, urlsplit

import pytest
from test_actions_publication import BASE, HEAD, WRITER, bundle_for, make_policy, make_valid_result, response
from test_github_app_canary import private_key_pem

import pr_review_harness.protected_publication_runtime as runtime
from pr_review_harness.actions_publication import (
    ArtifactUploadResult,
    HTTPResponse,
)
from pr_review_harness.publication_receipts import EffectSlot

CALLED_SHA = "e" * 40


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


def protected_checkout(tmp_path, *, enabled=True):
    workspace = tmp_path / "protected"
    (workspace / ".github/workflows").mkdir(parents=True)
    (workspace / ".github/pr-review-publisher-policy.json").write_text(
        json.dumps(policy_document(enabled=enabled), sort_keys=True, separators=(",", ":")) + "\n",
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


def rebind_manifest_target(bundle, *, base_sha=None, head_sha=None):
    source = io.BytesIO(bundle)
    entries = {}
    with zipfile.ZipFile(source) as archive:
        for info in archive.infolist():
            entries[info.filename] = archive.read(info.filename)
    manifest = json.loads(entries["provenance.json"])
    if base_sha is not None:
        manifest["base_sha"] = base_sha
        manifest["caller_workflow_sha"] = base_sha
    if head_sha is not None:
        manifest["head_sha"] = head_sha
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
    "failure_mode",
    ["success", "duplicate_source_artifact", "stale_base", "stale_head", "deadline", "receipt_ack_missing", "write_token_denied"],
)
@pytest.mark.parametrize("source_association", [[], None], ids=["empty-associations", "omitted-associations"])
def test_runtime_composes_api_bound_intake_receipt_ack_fresh_head_and_single_post(
    tmp_path, failure_mode, source_association
):
    workspace, revision, event_path = protected_checkout(tmp_path)
    event_path.write_text(json.dumps(event_payload(include_pr=False)), encoding="utf-8")
    policy = make_policy(publisher_workflow_sha=revision, caller_workflow_sha=BASE)
    result = make_valid_result()
    bundle = bundle_for(policy, result)
    if failure_mode == "stale_base":
        bundle = rebind_manifest_target(bundle, base_sha="c" * 40)
    elif failure_mode == "stale_head":
        bundle = rebind_manifest_target(bundle, head_sha="c" * 40)
    receipt_archives = {}
    events = []
    stored_reviews = []
    post_bodies = []
    pull_reads = 0
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
        "pull_requests": source_association,
        "referenced_workflows": [
            {"path": policy.called_harness_repository + "/" + policy.called_harness_path + "@refs/heads/main", "sha": CALLED_SHA}
        ],
    }
    if source_association is None:
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
        nonlocal pull_reads
        path = urlsplit(url).path
        query = urlsplit(url).query
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
            return response({"id": 777, "commit_id": HEAD, "state": "COMMENTED", "body": body["body"], "user": {"login": WRITER}})
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
    outcome = runtime.run_protected_publication(
        actions_environment(workspace, revision, event_path),
        transport=transport,
        artifact_uploader=uploader,
        key_supplier=lambda: (key_calls.append(True) or actual_key),
        clock=clock,
    )

    if failure_mode == "success":
        assert outcome == {"schema": "pr-review-protected-publication.v1", "status": "CONFIRMED", "reason": None}
    else:
        assert outcome["status"] == "UNKNOWN"
    assert len(uploader.calls) == (
        0 if failure_mode in {"duplicate_source_artifact", "stale_base", "stale_head", "deadline"} else 1
    ), (failure_mode, outcome, events)
    if failure_mode == "success":
        assert len(post_bodies) == 1
        assert events.count("source_artifact_download") == 3
        assert events.count("write_token_mint") == 1
        assert events.count("receipt_upload") == 1
        assert events.count("receipt_artifact_download") == 1
        assert events.count("review_post") == 1
        assert max(i for i, item in enumerate(events) if item == "source_artifact_download") < events.index("receipt_upload")
        assert events.index("receipt_upload") < events.index("receipt_artifact_download")
        assert events.index("receipt_artifact_download") < events.index("write_token_mint") < events.index("review_post")
        assert post_bodies[0]["commit_id"] == HEAD
        assert post_bodies[0]["event"] == "COMMENT"
        assert post_bodies[0]["body"].endswith(" -->")
        assert any("/actions/artifacts/123/zip" in call[1] for call in transport.calls)
        assert any("/actions/artifacts/991/zip" in call[1] for call in transport.calls)
        assert pull_reads >= 3
        assert all(actual_key not in repr(call) for call in transport.calls)
    else:
        assert post_bodies == []
        assert events.count("review_post") == 0
        assert len(key_calls) == (0 if failure_mode in {"duplicate_source_artifact", "stale_base", "stale_head", "deadline"} else 1)
        assert events.count("write_token_mint") == (1 if failure_mode == "write_token_denied" else 0)
        if failure_mode in {"duplicate_source_artifact", "stale_base", "stale_head", "deadline"}:
            assert events.count("receipt_upload") == 0
        if failure_mode == "receipt_ack_missing":
            assert events.count("receipt_upload") == 1
