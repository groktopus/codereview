import hashlib
import io
import json
import zipfile
from urllib.parse import urlsplit

import pytest

from pr_review_harness.actions_publication import (
    ArtifactTrustMode,
    ArtifactUploadResult,
    CredentialKind,
    GitHubActionsPublicationAdapter,
    GitHubPublicationError,
    GitHubPublicationPolicy,
    HTTPResponse,
    IdentityState,
    PublisherCredential,
    VerifiedPublisherIdentity,
)
from pr_review_harness.artifact_intake import MANIFEST_FILENAME, RESULT_FILENAME
from pr_review_harness.publication_receipts import EffectSlot, HistoryStatus, ScanLimits
from pr_review_harness.publisher import _canonical_hash, publish_review_stateless
from pr_review_harness.report import render_report

HEAD = "a" * 40
BASE = "b" * 40
WRITER = "review-agent[bot]"
EFFECT = "effect-" + "c" * 64


def make_policy(**overrides):
    values = {
        "repository_id": 8123,
        "repository": "owner/repo",
        "pull_request_number": 44,
        "upstream_run_id": 731245,
        "upstream_run_attempt": 1,
        "publisher_run_id": 900001,
        "publisher_run_attempt": 1,
        "caller_workflow_id": 563,
        "caller_workflow_path": ".github/workflows/pr-analysis.yml",
        "caller_workflow_ref": "refs/heads/main",
        "caller_workflow_sha": "d" * 40,
        "called_harness_repository": "harness/repo",
        "called_harness_path": ".github/workflows/review.yml",
        "called_harness_sha": "e" * 40,
        "publisher_workflow_id": 904,
        "publisher_workflow_path": ".github/workflows/pr-publish.yml",
        "publisher_workflow_ref": "refs/heads/main",
        "publisher_workflow_sha": "f" * 40,
        "profile_version": "profile-v3",
        "profile_sha256": "1" * 64,
        "provider_configuration_identity": "provider-config-sha256:" + "2" * 64,
        "allowed_actor_login": WRITER,
        "artifact_trust_mode": ArtifactTrustMode.API_BOUND_SHA256,
        "artifact_redirect_hosts": ("downloads.example.test",),
    }
    values.update(overrides)
    return GitHubPublicationPolicy(**values)


def test_run_identity_accepts_bare_github_workflow_path_but_keeps_policy_identity():
    policy = make_policy()
    adapter = GitHubActionsPublicationAdapter(policy, Provider(), transport=FakeTransport(lambda *_: None))

    identity = adapter._run_identity(
        {
            "id": policy.publisher_run_id,
            "run_attempt": policy.publisher_run_attempt,
            "workflow_id": policy.publisher_workflow_id,
            "path": policy.publisher_workflow_path,
            "head_sha": policy.publisher_workflow_sha,
        },
        publisher=True,
    )

    assert identity.workflow_path == policy.publisher_workflow_path
    assert identity.workflow_ref == policy.publisher_workflow_ref
    assert identity.workflow_sha == policy.publisher_workflow_sha


@pytest.mark.parametrize("suffix", ["@", "@refs/heads/other"])
def test_run_identity_rejects_empty_or_untrusted_workflow_ref_suffix(suffix):
    policy = make_policy()
    adapter = GitHubActionsPublicationAdapter(policy, Provider(), transport=FakeTransport(lambda *_: None))

    with pytest.raises(GitHubPublicationError, match="workflow_path_or_ref_mismatch"):
        adapter._run_identity(
            {
                "id": policy.publisher_run_id,
                "run_attempt": policy.publisher_run_attempt,
                "workflow_id": policy.publisher_workflow_id,
                "path": policy.publisher_workflow_path + suffix,
                "head_sha": policy.publisher_workflow_sha,
            },
            publisher=True,
        )


class Provider:
    def __init__(self, *, state=IdentityState.VERIFIED, actor=WRITER, permissions=None):
        self.calls = []
        self.credential = PublisherCredential(
            token="test-secret-token",
            identity=VerifiedPublisherIdentity(
                state=state,
                actor_login=actor,
                credential_kind=CredentialKind.ACTIONS_TOKEN,
                evidence_id="3" * 64,
            ),
            repository_id=8123,
            permissions=permissions or (("actions", "read"), ("pull_requests", "write")),
            expires_at="2999-01-01T00:00:00Z",
        )

    def credential_for(self, repository_id, required_permissions, timeout_seconds):
        self.calls.append((repository_id, dict(required_permissions), timeout_seconds))
        return self.credential


class FakeTransport:
    def __init__(self, responder):
        self.responder = responder
        self.calls = []
        self.download_calls = []

    def request(self, method, url, *, token, json_body, timeout_seconds, max_response_bytes):
        self.calls.append((method, url, token, json_body, timeout_seconds, max_response_bytes))
        return self.responder(method, url, json_body)

    def download(self, url, *, timeout_seconds, max_response_bytes):
        self.download_calls.append((url, timeout_seconds, max_response_bytes))
        return HTTPResponse(200, {}, b"archive bytes")


def response(value, status=200, headers=None):
    return HTTPResponse(status, headers or {}, json.dumps(value).encode())


def run_record(run_id, *, status="completed", pull_number=44):
    return {
        "id": run_id,
        "run_attempt": 1,
        "workflow_id": 904,
        "event": "workflow_run",
        # workflow_run jobs execute against the publisher workflow's default
        # branch commit, which differs from the reviewed PR head.
        "head_sha": "f" * 40,
        "status": status,
        "conclusion": "success" if status == "completed" else None,
        "repository": {"id": 8123},
        "pull_requests": [{"number": pull_number, "base": {"sha": BASE}, "head": {"sha": HEAD}}],
        "path": ".github/workflows/pr-publish.yml@refs/heads/main",
    }


def adapter(responder, *, provider=None, policy=None):
    return GitHubActionsPublicationAdapter(
        policy or make_policy(),
        provider if provider is not None else Provider(),
        transport=FakeTransport(responder),
    )


def test_scan_reconciles_publisher_run_before_artifact_and_missing_receipt_is_unknown():
    previous = run_record(800)

    def responder(method, url, body):
        path = urlsplit(url).path
        if path.endswith("/pulls/44/reviews"):
            return response([])
        if "/actions/workflows/904/runs" in url:
            return response({"total_count": 1, "workflow_runs": [previous]})
        if path.endswith("/actions/runs/800/attempts/1"):
            return response(previous)
        if path.endswith("/actions/runs/800/artifacts"):
            return response({"total_count": 0, "artifacts": []})
        raise AssertionError(f"unexpected GitHub request: {method} {url}")

    client = adapter(responder)
    result = client.scan(
        EffectSlot(8123, "owner/repo", 44, HEAD),
        ScanLimits(max_runs=10, max_pages=2, max_reviews=100, deadline_seconds=4),
    )
    assert result.status is HistoryStatus.INCOMPLETE
    assert result.reason_code == "receipt_history_incomplete"
    paths = [urlsplit(call[1]).path for call in client.transport.calls]
    assert any("/actions/workflows/904/runs" in call[1] for call in client.transport.calls)
    assert "/repos/owner/repo/actions/runs/800/artifacts" in paths
    assert not any(path == "/repos/owner/repo/actions/artifacts" for path in paths)
    run_query = next(call[1] for call in client.transport.calls if "/actions/workflows/904/runs" in call[1])
    assert "head_sha=" not in run_query


def test_scan_defers_while_another_same_head_publisher_run_is_active():
    active = run_record(800, status="in_progress")

    def responder(method, url, body):
        path = urlsplit(url).path
        if path.endswith("/pulls/44/reviews"):
            return response([])
        if "/actions/workflows/904/runs" in url:
            return response({"total_count": 1, "workflow_runs": [active]})
        raise AssertionError(f"active run must defer before detail/artifact reads: {url}")

    result = adapter(responder).scan(
        EffectSlot(8123, "owner/repo", 44, HEAD),
        ScanLimits(max_runs=10, max_pages=2, max_reviews=100, deadline_seconds=4),
    )
    assert result.status is HistoryStatus.INCOMPLETE
    assert result.reason_code == "receipt_history_incomplete"


def test_scan_skips_only_the_exact_current_run_and_reports_visible_empty_history():
    def responder(method, url, body):
        path = urlsplit(url).path
        if path.endswith("/pulls/44/reviews"):
            return response([])
        if "/actions/workflows/904/runs" in url:
            return response({"total_count": 0, "workflow_runs": []})
        raise AssertionError(f"unexpected GitHub request: {url}")

    result = adapter(responder).scan(
        EffectSlot(8123, "owner/repo", 44, HEAD),
        ScanLimits(max_runs=10, max_pages=2, max_reviews=100, deadline_seconds=4),
    )
    assert result.status is HistoryStatus.COMPLETE


def test_submit_review_makes_one_authenticated_post_and_checks_writer_identity():
    calls = []
    body = "A concise review.\n\n<!-- pr-review-harness:" + EFFECT + " -->"
    responder_response = {
        "id": 1234,
        "commit_id": HEAD,
        "state": "COMMENTED",
        "body": body,
        "user": {"login": WRITER},
    }

    def responder(method, url, payload):
        calls.append((method, url, payload))
        return response(responder_response)

    client = adapter(responder)
    observation = client.submit_review({"commit_id": HEAD, "event": "COMMENT", "body": body}, EFFECT, 4.0)
    assert observation.actor_login == WRITER
    assert len(calls) == 1
    method, url, payload = calls[0]
    assert method == "POST"
    assert url.endswith("/pulls/44/reviews")
    assert payload == {"commit_id": HEAD, "event": "COMMENT", "body": body}
    assert all("/user" not in call[1] for call in client.transport.calls)
    assert client.transport.calls[0][2] == "test-secret-token"


def test_post_response_actor_mismatch_is_rejected_after_one_post_without_retry():
    def responder(method, url, body):
        return response(
            {
                "id": 1234,
                "commit_id": HEAD,
                "state": "COMMENTED",
                "body": body["body"],
                "user": {"login": "someone-else"},
            }
        )

    client = adapter(responder)
    body = "Review.\n\n<!-- pr-review-harness:" + EFFECT + " -->"
    with pytest.raises(Exception, match="review_post_response_identity_mismatch"):
        client.submit_review({"commit_id": HEAD, "event": "COMMENT", "body": body}, EFFECT, 4.0)
    assert len(client.transport.calls) == 1


def test_unverified_credentials_fail_closed_without_http_calls():
    client = adapter(lambda *_: pytest.fail("must not issue HTTP request"), provider=None)
    client.credential_provider = None
    result = client.scan(
        EffectSlot(8123, "owner/repo", 44, HEAD),
        ScanLimits(max_runs=10, max_pages=2, max_reviews=100, deadline_seconds=4),
    )
    assert result.status is HistoryStatus.UNAVAILABLE
    assert result.reason_code == "github_history_unavailable"
    assert client.transport.calls == []


def test_malformed_limits_are_refused_before_network_io():
    client = adapter(lambda *_: pytest.fail("must not issue HTTP request"))
    result = client.scan(EffectSlot(8123, "owner/repo", 44, HEAD), object())
    assert result.status is HistoryStatus.UNAVAILABLE
    assert result.reason_code == "history_limits_invalid"
    assert client.transport.calls == []


def test_artifact_redirect_uses_https_allowlist_and_download_never_receives_api_token():
    archive = b"archive bytes that pass minimum"

    def responder(method, url, body):
        return (
            HTTPResponse(
                302,
                {},
                b"",
            )
            if method == "GET"
            else response({})
        )

    transport = FakeTransport(responder)
    transport.download = lambda url, *, timeout_seconds, max_response_bytes: HTTPResponse(200, {}, archive)
    client = GitHubActionsPublicationAdapter(make_policy(), Provider(), transport=transport)
    artifact = {
        "id": 456,
        "name": "review-bundle",
        "size_in_bytes": len(archive),
        "digest": "sha256:" + hashlib.sha256(archive).hexdigest(),
        "expired": False,
    }
    with pytest.raises(Exception, match="artifact_download_location_untrusted"):
        client._download_artifact(artifact, 4, 1024)

    transport.responder = lambda method, url, body: HTTPResponse(
        302,
        {"location": "https://downloads.example.test/artifact?signature=opaque"},
        b"",
    )
    downloaded = client._download_artifact(artifact, 4, 1024)
    assert downloaded.archive == archive
    assert all(call[2] != "test-secret-token" for call in transport.download_calls)


def make_valid_result():
    value = {
        "run_id": "review-run-2026-09-26",
        "snapshot_id": "snapshot-1",
        "repository": "owner/repo",
        "pull_request_number": 44,
        "base_sha": BASE,
        "head_sha": HEAD,
        "freshness": "CURRENT",
        "contract_version": "0.1",
        "disposition": "COMMENT",
        "merge_eligibility": "NOT_EVALUATED",
        "project_profile_version": "profile-v3",
        "coverage_state": "COMPLETE",
        "coverage_ledger": [{"obligation_id": "obligation-1", "required": True, "state": "COMPLETE"}],
        "policy_valid": True,
        "allow_empty_approve": False,
        "task_results": {},
        "ledger": {"candidate_records": []},
        "evidence_index": {},
        "budget": {},
        "findings": [],
        "report_sections": {
            "blockers": [],
            "suggested_improvements": [],
            "specific_strengths": [],
            "future_guidance": [],
        },
    }
    value["rendered_review"] = render_report(value)
    value["result_hash"] = _canonical_hash(value)
    return value


def bundle_for(policy, result):
    result_raw = json.dumps(result, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    manifest = {
        "schema_version": "1.0",
        "repository_id": policy.repository_id,
        "repository": policy.repository,
        "pull_request_number": policy.pull_request_number,
        "base_sha": BASE,
        "head_sha": HEAD,
        "upstream_run_id": policy.upstream_run_id,
        "upstream_run_attempt": policy.upstream_run_attempt,
        "caller_workflow_id": policy.caller_workflow_id,
        "caller_workflow_path": policy.caller_workflow_path,
        "caller_workflow_ref": policy.caller_workflow_ref,
        "caller_workflow_sha": policy.caller_workflow_sha,
        "called_harness_repository": policy.called_harness_repository,
        "called_harness_path": policy.called_harness_path,
        "called_harness_sha": policy.called_harness_sha,
        "profile_version": policy.profile_version,
        "profile_sha256": policy.profile_sha256,
        "provider_configuration_identity": policy.provider_configuration_identity,
        "review_run_id": result["run_id"],
        "result_file_sha256": hashlib.sha256(result_raw).hexdigest(),
        "result_hash": result["result_hash"],
        "created_at": "2026-09-26T17:00:00Z",
        "contract_versions": dict(policy.contract_versions),
    }
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(RESULT_FILENAME, result_raw)
        archive.writestr(
            MANIFEST_FILENAME,
            json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode(),
        )
    return stream.getvalue()


class Uploader:
    def __init__(self, status="UPLOADED"):
        self.calls = []
        self.status = status

    def upload(self, *, run_id, artifact_name, filename, content, timeout_seconds):
        self.calls.append((run_id, artifact_name, filename, content, timeout_seconds))
        artifact_id = 991 if self.status == "UPLOADED" else None
        return ArtifactUploadResult(self.status, artifact_id=artifact_id)


@pytest.mark.parametrize(
    ("failure", "expected_status"),
    [
        (None, "CONFIRMED"),
        ("artifact_digest", "UNKNOWN"),
        ("upstream_binding", "UNKNOWN"),
        ("publisher_sha", "UNKNOWN"),
        ("receipt_upload", "REJECTED"),
        ("history_cap", "UNKNOWN"),
        ("post_state", "UNKNOWN"),
        ("receipt_missing", "UNKNOWN"),
        ("stale_after_receipt", "STALE"),
        ("lost_post_response", "CONFIRMED"),
        ("lost_post_history_unknown", "UNKNOWN"),
        ("admission_only", "CANDIDATE"),
        ("admission_only_repository", "CANDIDATE"),
    ],
)
def test_stateless_publication_end_to_end_admits_bundle_persists_receipt_then_posts_once(failure, expected_status):
    repository_scope = failure == "admission_only_repository"
    policy = make_policy(concurrency_scope="repository" if repository_scope else "pull_request")
    result = make_valid_result()
    bundle = bundle_for(policy, result)
    receipt_archives = {}
    post_bodies = []
    stored_reviews = []
    pull_reads = 0
    publisher_run = run_record(policy.publisher_run_id, status="in_progress")
    publisher_run["head_sha"] = policy.publisher_workflow_sha
    publisher_detail = {
        **publisher_run,
        "path": policy.publisher_workflow_path + "@" + policy.publisher_workflow_ref,
    }
    if failure == "publisher_sha":
        publisher_detail["head_sha"] = policy.caller_workflow_sha
    upstream_detail = {
        "id": policy.upstream_run_id,
        "run_attempt": policy.upstream_run_attempt,
        "workflow_id": policy.caller_workflow_id,
        "repository": {"id": policy.repository_id},
        "path": policy.caller_workflow_path + "@" + policy.caller_workflow_ref,
        "head_sha": HEAD,
        "event": "pull_request",
        "status": "completed",
        "conclusion": "success",
        "pull_requests": [{"number": 44, "base": {"sha": BASE}, "head": {"sha": HEAD}}],
        "referenced_workflows": [
            {
                "path": policy.called_harness_repository + "/" + policy.called_harness_path + "@refs/heads/main",
                "sha": policy.called_harness_sha,
            }
        ],
    }
    result_artifact = {
        "id": 123,
        "name": policy.result_artifact_name,
        "size_in_bytes": len(bundle),
        "digest": "sha256:" + hashlib.sha256(bundle).hexdigest(),
        "expired": False,
        "workflow_run": {
            "id": policy.upstream_run_id,
            "repository_id": policy.repository_id,
            "head_sha": HEAD,
        },
    }
    if failure == "artifact_digest":
        result_artifact["digest"] = "sha256:" + "0" * 64
    if failure == "upstream_binding":
        upstream_detail["pull_requests"][0]["head"]["sha"] = BASE
    publisher_runs = [publisher_run]
    if failure == "history_cap":
        publisher_runs.append(run_record(900002, status="completed"))

    def api_response(method, url, body):
        nonlocal pull_reads
        path = urlsplit(url).path
        query = urlsplit(url).query
        if path.endswith("/pulls/44"):
            pull_reads += 1
            return response(
                {
                    "number": 44,
                    "state": "open",
                    "base": {"sha": BASE, "repo": {"id": policy.repository_id}},
                    "head": {"sha": "c" * 40 if failure == "stale_after_receipt" and pull_reads == 3 else HEAD},
                }
            )
        if path.endswith(f"/actions/runs/{policy.upstream_run_id}/attempts/1"):
            return response(upstream_detail)
        if path.endswith(f"/actions/runs/{policy.publisher_run_id}/attempts/1"):
            return response(publisher_detail)
        if path.endswith(f"/actions/runs/{policy.upstream_run_id}/artifacts"):
            assert "name=" + policy.result_artifact_name in query
            return response({"total_count": 1, "artifacts": [result_artifact]})
        if path.endswith(f"/actions/runs/{policy.publisher_run_id}/artifacts"):
            name = policy.receipt_artifact_name(EffectSlot(policy.repository_id, policy.repository, 44, HEAD))
            artifact_bytes = receipt_archives.get(policy.publisher_run_id)
            if artifact_bytes is None:
                return response({"total_count": 0, "artifacts": []})
            return response(
                {
                    "total_count": 1,
                    "artifacts": [
                        {
                            "id": 991,
                            "name": name,
                            "size_in_bytes": len(artifact_bytes),
                            "digest": "sha256:" + hashlib.sha256(artifact_bytes).hexdigest(),
                            "expired": False,
                            "expires_at": "2999-01-01T00:00:00Z",
                            "workflow_run": {
                                "id": policy.publisher_run_id,
                                "repository_id": policy.repository_id,
                                "run_attempt": 1,
                            },
                        }
                    ],
                }
            )
        if path.endswith(f"/actions/workflows/{policy.publisher_workflow_id}/runs"):
            return response({"total_count": len(publisher_runs), "workflow_runs": publisher_runs})
        if path.endswith("/pulls/44/reviews") and method == "GET":
            if failure == "lost_post_history_unknown" and post_bodies:
                return response({"message": "history temporarily unavailable"}, status=503)
            return response(stored_reviews)
        if path.endswith("/actions/artifacts/123/zip"):
            return HTTPResponse(
                302,
                {"location": "https://downloads.example.test/result?signature=one-use"},
                b"",
            )
        if path.endswith("/actions/artifacts/991/zip"):
            return HTTPResponse(
                302,
                {"location": "https://downloads.example.test/receipt?signature=one-use"},
                b"",
            )
        if path.endswith("/pulls/44/reviews") and method == "POST":
            post_bodies.append(body)
            if failure in {"lost_post_response", "lost_post_history_unknown"}:
                if failure == "lost_post_response":
                    stored_reviews.append(
                        {
                            "id": 777,
                            "commit_id": HEAD,
                            "state": "COMMENTED",
                            "body": body["body"],
                            "user": {"login": WRITER},
                        }
                    )
                raise TimeoutError("response lost after simulated acceptance")
            state = "CHANGES_REQUESTED" if failure == "post_state" else "COMMENTED"
            return response(
                {
                    "id": 777,
                    "commit_id": HEAD,
                    "state": state,
                    "body": body["body"],
                    "user": {"login": WRITER},
                }
            )
        raise AssertionError(f"unexpected GitHub request: {method} {url}")

    class EndToEndTransport(FakeTransport):
        def download(self, url, *, timeout_seconds, max_response_bytes):
            self.download_calls.append((url, timeout_seconds, max_response_bytes))
            content = bundle if "result?" in url else receipt_archives[policy.publisher_run_id]
            return HTTPResponse(200, {}, content)

    transport = EndToEndTransport(api_response)
    uploader = Uploader("FAILED" if failure == "receipt_upload" else "UPLOADED")
    provider = Provider(
        permissions=(("actions", "read"), ("pull_requests", "read"))
        if failure in {"admission_only", "admission_only_repository"}
        else None
    )
    client = GitHubActionsPublicationAdapter(policy, provider, transport=transport, artifact_uploader=uploader)
    config = {
        "schema_version": "1.0",
        "enabled": True,
        "allowed_repositories": [policy.repository],
        "allowed_dispositions": ["COMMENT"],
        "allowed_profile_versions": [policy.profile_version],
        "allowed_actors": [WRITER],
        "max_review_body_bytes": 60_000,
    }
    if failure in {"admission_only", "admission_only_repository"}:
        admission = client.admit(
            result,
            config,
            ScanLimits(max_runs=20, max_pages=2, max_reviews=100, deadline_seconds=20),
        )
        assert admission.slot.pull_request_number == policy.pull_request_number
        assert admission.slot.head_sha == HEAD
        assert admission.base_sha == BASE
        assert admission.source_artifact_sha256 == hashlib.sha256(bundle).hexdigest()
        assert admission.upstream_run.run_id == policy.upstream_run_id
        assert admission.upstream_run.run_attempt == policy.upstream_run_attempt
        assert admission.publisher_run.run_id == policy.publisher_run_id
        assert admission.publisher_run.run_attempt == policy.publisher_run_attempt
        assert admission.actor_login == WRITER
        expected_group = "pr-review-publish-8123" if repository_scope else "pr-review-publish-8123-44"
        assert admission.concurrency_scope == policy.concurrency_scope
        assert admission.concurrency_group == expected_group
        assert admission.concurrency_contract_hash == _canonical_hash(
            {"scope": policy.concurrency_scope, "group": expected_group, "cancel": False}
        )
        with zipfile.ZipFile(io.BytesIO(bundle)) as archive:
            result_sha256 = hashlib.sha256(archive.read(RESULT_FILENAME)).hexdigest()
        assert admission.admission_evidence_hash == _canonical_hash(
            {
                "pr": {
                    "repository_id": policy.repository_id,
                    "repository": policy.repository,
                    "pull_request_number": policy.pull_request_number,
                    "base_sha": BASE,
                    "head_sha": HEAD,
                    "state": "open",
                },
                "upstream_run": admission.upstream_run.to_dict(),
                "publisher_run": admission.publisher_run.to_dict(),
                "artifact_id": 123,
                "artifact_archive_sha256": hashlib.sha256(bundle).hexdigest(),
                "artifact_result_sha256": result_sha256,
                "concurrency_scope": policy.concurrency_scope,
                "concurrency_group": expected_group,
            }
        )
        assert all(method == "GET" for method, *_ in transport.calls)
        assert all(required == {"actions": "read", "pull_requests": "read"} for _, required, _ in provider.calls)
        assert uploader.calls == []
        assert post_bodies == []
        return
    # The workflow artifact writer is the official Actions upload boundary;
    # this deterministic test double emits a receipt archive observable by the
    # API verifier, and no GitHub write is performed by the test.
    original_upload = uploader.upload

    def upload_and_record(**kwargs):
        outcome = original_upload(**kwargs)
        if failure == "receipt_missing":
            return outcome
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr(kwargs["filename"], kwargs["content"])
        receipt_archives[kwargs["run_id"]] = stream.getvalue()
        return outcome

    uploader.upload = upload_and_record
    outcome = publish_review_stateless(
        result,
        config,
        "PUBLISH_REVIEW",
        admission_provider=client,
        history_reader=client,
        receipt_writer=client,
        fresh_head=client.fresh_head,
        submit_review=client.submit_review,
        limits=ScanLimits(
            max_runs=1 if failure == "history_cap" else 20,
            max_pages=2,
            max_reviews=100,
            deadline_seconds=20,
        ),
    )
    assert outcome["status"] == expected_status
    if failure in {None, "post_state", "lost_post_response", "lost_post_history_unknown"}:
        assert len(uploader.calls) == 1
        assert len(post_bodies) == 1
        assert post_bodies[0]["commit_id"] == HEAD
        assert post_bodies[0]["event"] == "COMMENT"
        assert post_bodies[0]["body"].endswith(" -->")
        assert "<!-- pr-review-harness:effect-" in post_bodies[0]["body"]
        if failure == "post_state":
            assert outcome["reason"] == "submit_response_ambiguous"
        if failure == "lost_post_response":
            assert outcome["reason"] == "confirmed_after_ambiguous_response"
            assert len(stored_reviews) == 1
        if failure == "lost_post_history_unknown":
            assert outcome["reason"] == "submit_response_ambiguous"
            assert stored_reviews == []
    elif failure == "stale_after_receipt":
        assert len(uploader.calls) == 1
        assert post_bodies == []
        assert outcome["reason"] == "head_sha_changed_after_receipt"
    elif failure == "receipt_missing":
        assert len(uploader.calls) == 1
        assert post_bodies == []
        assert outcome["reason"] == "artifact_api_ack_missing"
    elif failure == "receipt_upload":
        assert len(uploader.calls) == 1
        assert outcome["reason"] == "artifact_upload_unconfirmed"
        assert post_bodies == []
    else:
        assert uploader.calls == []
        assert post_bodies == []
    assert all("/user" not in call[1] for call in transport.calls)


def test_publication_policy_rejects_unbounded_concurrency_scope():
    with pytest.raises(GitHubPublicationError, match="concurrency_scope"):
        make_policy(concurrency_scope="organization")


def test_publisher_deduplicates_exact_marker_from_real_adapter_history():
    from pr_review_harness.publication_receipts import PublicationAdmission, RunIdentity
    from pr_review_harness.publisher import _stateless_effect_key, preview_publication

    result = make_valid_result()
    policy = {
        "schema_version": "1.0",
        "enabled": True,
        "allowed_repositories": ["owner/repo"],
        "allowed_dispositions": ["COMMENT"],
        "allowed_profile_versions": ["profile-v3"],
        "allowed_actors": [WRITER],
        "max_review_body_bytes": 60_000,
    }
    request = preview_publication(result, policy)
    slot = EffectSlot(8123, "owner/repo", 44, HEAD)
    effect_key = _stateless_effect_key(
        slot, request["result_hash"], request["review_body_hash"], request["disposition"]
    )
    marked_body = f'{result["rendered_review"]}\n\n<!-- pr-review-harness:{effect_key} -->'
    current_policy = make_policy(publisher_run_id=900002)
    current_run = RunIdentity(
        repository_id=8123,
        workflow_id=current_policy.publisher_workflow_id,
        workflow_path=current_policy.publisher_workflow_path,
        workflow_ref=current_policy.publisher_workflow_ref,
        workflow_sha=current_policy.publisher_workflow_sha,
        run_id=current_policy.publisher_run_id,
        run_attempt=current_policy.publisher_run_attempt,
    )
    upstream_run = RunIdentity(
        repository_id=8123,
        workflow_id=current_policy.caller_workflow_id,
        workflow_path=current_policy.caller_workflow_path,
        workflow_ref=current_policy.caller_workflow_ref,
        workflow_sha=current_policy.caller_workflow_sha,
        run_id=current_policy.upstream_run_id,
        run_attempt=current_policy.upstream_run_attempt,
    )
    admission = PublicationAdmission(
        slot=slot,
        base_sha=BASE,
        effect_key=effect_key,
        result_hash=request["result_hash"],
        review_body_hash=request["review_body_hash"],
        disposition="COMMENT",
        review_event="COMMENT",
        actor_login=WRITER,
        profile_hash=current_policy.profile_sha256,
        policy_hash=_canonical_hash(policy),
        source_artifact_sha256="2" * 64,
        admission_evidence_hash="3" * 64,
        upstream_run=upstream_run,
        publisher_run=current_run,
        concurrency_group="pr-review-publish-8123-44",
        concurrency_contract_hash="4" * 64,
    )

    # This isolates the stateless controller's reconciliation against the real
    # GitHub history adapter; admission is a typed test capability, not a
    # second end-to-end run through artifact intake.
    class Admission:
        def admit(self, *_args):
            return admission

    class Writer:
        calls = 0

        def persist(self, *_args):
            self.calls += 1
            pytest.fail("confirmed review history must stop before receipt persistence")

    review = {
        "id": 707,
        "commit_id": HEAD,
        "state": "COMMENTED",
        "body": marked_body,
        "user": {"login": WRITER},
    }

    def api_response(method, url, _body):
        path = urlsplit(url).path
        if method == "GET" and path.endswith("/pulls/44/reviews"):
            return response([review])
        if method == "GET" and path.endswith("/actions/workflows/904/runs"):
            return response({"total_count": 0, "workflow_runs": []})
        raise AssertionError(f"unexpected simulated GitHub request: {method} {url}")

    client = GitHubActionsPublicationAdapter(current_policy, Provider(), transport=FakeTransport(api_response))
    writer = Writer()
    posted = []
    heads = []
    outcome = publish_review_stateless(
        result,
        policy,
        "PUBLISH_REVIEW",
        admission_provider=Admission(),
        history_reader=client,
        receipt_writer=writer,
        fresh_head=lambda *_args: heads.append(True),
        submit_review=lambda *args: posted.append(args),
        limits=ScanLimits(max_runs=10, max_pages=2, max_reviews=100, deadline_seconds=10),
    )

    assert outcome["status"] == "CONFIRMED"
    assert outcome["reason"] is None
    assert posted == []
    assert heads == []
    assert writer.calls == 0
    assert any(urlsplit(call[1]).path.endswith("/pulls/44/reviews") for call in client.transport.calls)


@pytest.mark.parametrize(
    "raw",
    [
        b'{"ok":1,"ok":2}',
        b'{"value":' + b"[" * 65 + b"0" + b"]" * 65 + b"}",
        b'{"id":123456789012345678901}',
        b'{"value":NaN}',
    ],
)
def test_api_json_parser_rejects_ambiguous_or_unbounded_json(raw):
    from pr_review_harness.actions_publication import _parse_api_json

    with pytest.raises(ValueError):
        _parse_api_json(raw)
