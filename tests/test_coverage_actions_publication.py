"""Coverage-focused refusal tests for ``actions_publication``.

Every refusal probe asserts the typed ``GitHubPublicationError`` code (or the
typed ``HistoryScan`` / ``ReceiptPersistence`` reason code) and the absence of
the forbidden effect: no POST, no artifact upload, no effect claim. All GitHub
I/O is a recording fake transport; nothing touches the network.
"""

import base64
import hashlib
import io
import json
import re
import urllib.error
import zipfile
from dataclasses import replace
from urllib.parse import parse_qs, urlsplit

import pytest
from test_actions_publication import (
    ACTION_CREDENTIAL_PROVENANCE,
    BASE,
    EFFECT,
    HEAD,
    WRITER,
    FakeTransport,
    Provider,
    bundle_for,
    make_policy,
    make_valid_result,
    response,
)
from test_publication_history_v4 import _blob_sha, _history, _run_identity

import pr_review_harness.actions_publication as ap
from pr_review_harness.actions_publication import (
    ArtifactDownloadMode,
    ArtifactTrustMode,
    ArtifactUploadResult,
    CredentialKind,
    GitHubActionsPublicationAdapter,
    GitHubPublicationError,
    HTTPResponse,
    IdentityState,
    PermissionBasis,
    PublisherCredential,
    UrllibGitHubTransport,
    VerifiedPublisherIdentity,
    _parse_api_json,
    _parse_utc,
    _read_receipt_archive,
    _utc_future,
    validate_api_issued_artifact_location,
)
from pr_review_harness.publication_receipts import (
    AttemptReceipt,
    EffectSlot,
    HistoryStatus,
    NoEffectReceipt,
    ReceiptPersistenceStatus,
    RunIdentity,
    ScanLimits,
)
from pr_review_harness.publisher import PublicationAdmissionUnavailable

LIMITS = ScanLimits(max_runs=20, max_pages=2, max_reviews=100, deadline_seconds=10)
SLOT = EffectSlot(8123, "owner/repo", 44, HEAD)


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


class StaticProvider:
    def __init__(self, credential):
        self.credential = credential
        self.calls = []

    def credential_for(self, repository_id, required_permissions, timeout_seconds):
        self.calls.append((repository_id, dict(required_permissions), timeout_seconds))
        return self.credential


class DownloadTransport(FakeTransport):
    """FakeTransport with an explicit, tokenless download body."""

    def __init__(self, responder, download_body=b"", download_factory=None):
        super().__init__(responder)
        self.download_body = download_body
        self.download_factory = download_factory

    def download(self, url, *, timeout_seconds, max_response_bytes):
        self.download_calls.append((url, timeout_seconds, max_response_bytes))
        if self.download_factory is not None:
            return self.download_factory(url)
        return HTTPResponse(200, {}, self.download_body)


def app_identity(**overrides):
    values = {
        "state": IdentityState.VERIFIED,
        "actor_login": WRITER,
        "credential_kind": CredentialKind.APP_INSTALLATION,
        "evidence_id": "3" * 64,
        "app_id": 333,
        "installation_id": 444,
    }
    values.update(overrides)
    return VerifiedPublisherIdentity(**values)


def actions_identity(**overrides):
    values = {
        "state": IdentityState.PLATFORM_BOUND,
        "actor_login": WRITER,
        "credential_kind": CredentialKind.ACTIONS_TOKEN,
        "evidence_id": "4" * 64,
    }
    values.update(overrides)
    return VerifiedPublisherIdentity(**values)


def credential(identity=None, **overrides):
    values = {
        "token": "test-secret-token",
        "identity": identity or app_identity(),
        "repository_id": 8123,
        "permissions": (("actions", "read"), ("pull_requests", "write")),
        "expires_at": "2999-01-01T00:00:00Z",
    }
    values.update(overrides)
    return PublisherCredential(**values)


def client(policy=None, provider=None, transport=None, **kwargs):
    return GitHubActionsPublicationAdapter(
        policy or make_policy(),
        provider if provider is not None else Provider(),
        transport=transport or FakeTransport(lambda *_: pytest.fail("unexpected GitHub request")),
        **kwargs,
    )


def pull_record(policy, head=HEAD):
    return {
        "number": policy.pull_request_number,
        "state": "open",
        "base": {"sha": BASE, "repo": {"id": policy.repository_id}},
        "head": {"sha": head},
    }


def upstream_record(policy, **overrides):
    value = {
        "id": policy.upstream_run_id,
        "run_attempt": policy.upstream_run_attempt,
        "workflow_id": policy.caller_workflow_id,
        "repository": {"id": policy.repository_id},
        "path": policy.caller_workflow_path + "@" + policy.caller_workflow_ref,
        "head_sha": HEAD,
        "event": "pull_request",
        "status": "completed",
        "conclusion": "success",
        "pull_requests": [{"number": policy.pull_request_number, "base": {"sha": BASE}, "head": {"sha": HEAD}}],
        "referenced_workflows": [
            {
                "path": policy.called_harness_repository + "/" + policy.called_harness_path + "@refs/heads/main",
                "sha": policy.called_harness_sha,
            }
        ],
    }
    value.update(overrides)
    return value


def publisher_record(policy, *, run_id=None, attempt=None, head_sha=None, event="workflow_run", status="in_progress"):
    return {
        "id": run_id or policy.publisher_run_id,
        "run_attempt": attempt or policy.publisher_run_attempt,
        "workflow_id": policy.publisher_workflow_id,
        "path": policy.publisher_workflow_path + "@" + policy.publisher_workflow_ref,
        "head_sha": head_sha or policy.publisher_workflow_sha,
        "event": event,
        "status": status,
        "repository": {"id": policy.repository_id},
    }


def attempt_receipt(policy=None, **overrides):
    policy = policy or make_policy()
    values = {
        "slot": EffectSlot(policy.repository_id, policy.repository, 44, HEAD),
        "effect_key": EFFECT,
        "result_hash": "1" * 64,
        "review_body_hash": "2" * 64,
        "disposition": "COMMENT",
        "review_event": "COMMENT",
        "actor_login": WRITER,
        "profile_hash": policy.profile_sha256,
        "upstream_run": RunIdentity(
            repository_id=policy.repository_id,
            workflow_id=policy.caller_workflow_id,
            workflow_path=policy.caller_workflow_path,
            workflow_ref=policy.caller_workflow_ref,
            workflow_sha=policy.caller_workflow_sha,
            run_id=policy.upstream_run_id,
            run_attempt=policy.upstream_run_attempt,
        ),
        "publisher_run": _run_identity(),
    }
    values.update(overrides)
    return AttemptReceipt(**values)


def no_effect_receipt(policy=None, **overrides):
    values = {"publisher_run": _run_identity(), "policy_hash": "a" * 64}
    values.update(overrides)
    return NoEffectReceipt(**values)


def zip_bytes(filename, content):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(filename, content)
    return stream.getvalue()


def artifact_record(
    name,
    content=b"artifact archive bytes that pass the minimum size",
    *,
    artifact_id=991,
    workflow_run=None,
    expires_at="2999-01-01T00:00:00Z",
    size=None,
    digest=None,
):
    return {
        "id": artifact_id,
        "name": name,
        "size_in_bytes": size if size is not None else max(22, len(content)),
        "digest": digest or "sha256:" + hashlib.sha256(content).hexdigest(),
        "expired": False,
        "expires_at": expires_at,
        "workflow_run": {"id": 900001, "repository_id": 8123} if workflow_run is None else workflow_run,
    }


# ---------------------------------------------------------------------------
# Artifact location validator and typed identity/credential validation
# ---------------------------------------------------------------------------


def test_api_location_validator_rejects_unparseable_authority():
    assert validate_api_issued_artifact_location("https://storage.example.test:notaport/file?sig=x") is False


@pytest.mark.parametrize(
    "location",
    [
        "",
        None,
        "http://storage.example.test/file?sig=x",
        "https://user:pass@storage.example.test/file?sig=x",
        "https://storage.example.test/file",
        "https://storage.example.test/file?sig=x#fragment",
        "https://storage.example.test:444/file?sig=x",
        "https://localhost/file?sig=x",
        "https://private.internal/file?sig=x",
        "https://127.1/file?sig=x",
    ],
)
def test_api_location_validator_rejects_unsafe_locations(location):
    assert validate_api_issued_artifact_location(location) is False


def test_api_location_validator_accepts_global_ip_literal():
    assert validate_api_issued_artifact_location("https://8.8.8.8/file?sig=x") is True


def test_api_location_validator_accepts_public_signed_locations():
    assert (
        validate_api_issued_artifact_location(
            "https://productionresultssa99.blob.core.windows.net/container/file?sig=opaque"
        )
        is True
    )
    assert validate_api_issued_artifact_location("https://storage.example.test/file?sig=x") is True


@pytest.mark.parametrize(
    ("overrides", "code"),
    [
        ({"state": "VERIFIED"}, "publisher_identity_state_invalid"),
        ({"actor_login": "not a login"}, "publisher_actor_invalid"),
        ({"credential_kind": "APP_INSTALLATION"}, "credential_kind_invalid"),
        ({"evidence_id": "not-a-hash"}, "publisher_identity_evidence_invalid"),
        ({"state": IdentityState.PLATFORM_BOUND}, "app_identity_state_invalid"),
        ({"app_id": None}, "app_identity_invalid"),
        ({"installation_id": 0}, "app_identity_invalid"),
    ],
)
def test_verified_publisher_identity_refuses_invalid_typed_claims(overrides, code):
    with pytest.raises(GitHubPublicationError, match=code):
        app_identity(**overrides)


def test_actions_token_identity_refuses_unexpected_verified_state():
    with pytest.raises(GitHubPublicationError, match="actions_identity_state_invalid"):
        actions_identity(state=IdentityState.VERIFIED)


def test_actions_token_identity_refuses_unexpected_app_binding():
    with pytest.raises(GitHubPublicationError, match="unexpected_app_identity"):
        actions_identity(app_id=333, installation_id=444)


@pytest.mark.parametrize(
    ("overrides", "code"),
    [
        ({"token": ""}, "publisher_credential_invalid"),
        ({"token": 5}, "publisher_credential_invalid"),
        ({"token": "has whitespace"}, "publisher_credential_invalid"),
        ({"identity": object()}, "publisher_identity_invalid"),
        (
            {"identity": app_identity(state=IdentityState.UNAVAILABLE)},
            "publisher_identity_unverified",
        ),
        ({"repository_id": 0}, "credential_repository_invalid"),
        ({"permissions": (("actions", "execute"),)}, "credential_permissions_invalid"),
        ({"permissions": (("actions", "read"), ("actions", "read"))}, "credential_permissions_invalid"),
        (
            {"permission_basis": PermissionBasis.WORKFLOW_DECLARATION},
            "credential_permission_basis_invalid",
        ),
        ({"write_capability": "TESTED"}, "credential_write_capability_invalid"),
    ],
)
def test_publisher_credential_refuses_invalid_runtime_bindings(overrides, code):
    with pytest.raises(GitHubPublicationError, match=code):
        credential(**overrides)


# ---------------------------------------------------------------------------
# Stdlib transport: request construction and bounded-read refusals
# ---------------------------------------------------------------------------


class FakeRawResponse:
    def __init__(self, chunks=None, *, status=200, headers=None, error=None):
        self._chunks = list(chunks) if chunks is not None else [b""]
        self.status = status
        self.headers = headers or {}
        self.error = error
        self.closed = False

    def read1(self, _size):
        if self.error is not None:
            raise self.error
        return self._chunks.pop(0) if self._chunks else b""

    def read(self, _size=-1):
        return self.read1(_size)

    def close(self):
        self.closed = True


class FakeOpener:
    def __init__(self, outcome):
        self.outcome = outcome

    def open(self, _request, timeout=None):
        if isinstance(self.outcome, Exception):
            raise self.outcome
        return self.outcome


def test_urllib_transport_request_sets_bearer_and_json_contract(monkeypatch):
    transport = UrllibGitHubTransport()
    captured = {}

    def fake_open(request, timeout_seconds, max_response_bytes):
        captured["request"] = request
        captured["timeout"] = timeout_seconds
        captured["cap"] = max_response_bytes
        return HTTPResponse(200, {}, b"{}")

    monkeypatch.setattr(transport, "_open", fake_open)
    page = urllib_transport_response = transport.request(
        "POST",
        "https://api.github.com/repos/owner/repo/pulls/44/reviews",
        token="opaque-token",
        json_body={"event": "COMMENT", "body": "text"},
        timeout_seconds=4,
        max_response_bytes=1024,
    )

    request = captured["request"]
    headers = {key.lower(): value for key, value in request.header_items()}
    assert page is urllib_transport_response
    assert request.get_method() == "POST"
    assert headers["authorization"] == "Bearer opaque-token"
    assert headers["content-type"] == "application/json"
    assert headers["x-github-api-version"] == "2026-03-10"
    assert captured["timeout"] == 4 and captured["cap"] == 1024
    assert json.loads(request.data) == {"body": "text", "event": "COMMENT"}

    # A tokenless GET carries neither authorization nor a JSON content type.
    transport.request(
        "GET",
        "https://api.github.com/repos/owner/repo",
        token=None,
        json_body=None,
        timeout_seconds=4,
        max_response_bytes=1024,
    )
    headers = {key.lower(): value for key, value in captured["request"].header_items()}
    assert "authorization" not in headers
    assert "content-type" not in headers
    assert captured["request"].data is None


def test_urllib_transport_download_is_tokenless_get(monkeypatch):
    transport = UrllibGitHubTransport()
    captured = {}

    def fake_open(request, timeout_seconds, max_response_bytes):
        captured["request"] = request
        return HTTPResponse(200, {}, b"archive")

    monkeypatch.setattr(transport, "_open", fake_open)
    result = transport.download("https://downloads.example.test/a?sig=1", timeout_seconds=3, max_response_bytes=1024)
    assert result.body == b"archive"
    assert captured["request"].get_method() == "GET"
    assert "authorization" not in {key.lower() for key, _ in captured["request"].header_items()}


def test_urllib_transport_refuses_nonpositive_or_nonfinite_deadline():
    transport = UrllibGitHubTransport()
    for timeout in (0, -1, float("nan"), float("inf")):
        with pytest.raises(GitHubPublicationError, match="deadline_exhausted"):
            transport._open(FakeRawResponse(), timeout, 1024)


def test_urllib_transport_refuses_url_error_without_leaking_cause(monkeypatch):
    transport = UrllibGitHubTransport()
    monkeypatch.setattr(transport, "_opener", FakeOpener(urllib.error.URLError("dns")))
    with pytest.raises(GitHubPublicationError) as excinfo:
        transport._open(FakeRawResponse(), 4, 1024)
    assert excinfo.value.code == "github_transport_failed"
    assert excinfo.value.__cause__ is None


def test_urllib_transport_refuses_read_error_after_absolute_deadline(monkeypatch):
    transport = UrllibGitHubTransport()
    response = FakeRawResponse(error=OSError("slow drip"))
    monkeypatch.setattr(transport, "_opener", FakeOpener(response))
    ticks = iter([10.0, 10.5, 20.0])
    monkeypatch.setattr(ap.time, "monotonic", lambda: next(ticks))
    with pytest.raises(GitHubPublicationError, match="github_transport_deadline_exhausted"):
        transport._open(response, 1.0, 1024)
    assert response.closed is True


def test_urllib_transport_reads_bounded_chunks_and_lowercases_headers(monkeypatch):
    transport = UrllibGitHubTransport()
    response = FakeRawResponse([b"ab", b"cd"], headers={"X-Test": "yes"})
    monkeypatch.setattr(transport, "_opener", FakeOpener(response))
    result = transport._open(response, 4, 1024)
    assert result.status == 200 and result.body == b"abcd"
    assert result.headers == {"x-test": "yes"}
    assert response.closed is True


def test_urllib_transport_reads_http_error_body_as_response(monkeypatch):
    transport = UrllibGitHubTransport()

    class FakeHTTPError(urllib.error.HTTPError):
        def __init__(self):
            super().__init__("https://api.github.com/x", 404, "not found", {"X-Test": "error"}, None)
            self._sent = False

        def read1(self, _size):
            if self._sent:
                return b""
            self._sent = True
            return b"{}"

        def read(self, _size=-1):
            return self.read1(_size)

        def close(self):
            self.closed = True

    error = FakeHTTPError()
    monkeypatch.setattr(transport, "_opener", FakeOpener(error))
    result = transport._open(error, 4, 1024)
    assert result.status == 404 and result.body == b"{}"


def test_urllib_transport_refuses_deadline_between_chunks(monkeypatch):
    transport = UrllibGitHubTransport()
    response = FakeRawResponse([b"a", b"b"])
    monkeypatch.setattr(transport, "_opener", FakeOpener(response))
    ticks = iter([10.0, 10.5, 20.0])
    monkeypatch.setattr(ap.time, "monotonic", lambda: next(ticks))
    with pytest.raises(GitHubPublicationError, match="github_transport_deadline_exhausted"):
        transport._open(response, 1.0, 1024)


def test_urllib_transport_refuses_read_error_before_deadline(monkeypatch):
    transport = UrllibGitHubTransport()
    response = FakeRawResponse(error=OSError("reset"))
    monkeypatch.setattr(transport, "_opener", FakeOpener(response))
    ticks = iter([10.0, 10.5, 10.6])
    monkeypatch.setattr(ap.time, "monotonic", lambda: next(ticks))
    with pytest.raises(GitHubPublicationError, match="github_transport_failed"):
        transport._open(response, 4, 1024)


def test_urllib_transport_refuses_chunk_over_cap(monkeypatch):
    transport = UrllibGitHubTransport()
    response = FakeRawResponse([b"abcdef"])
    monkeypatch.setattr(transport, "_opener", FakeOpener(response))
    with pytest.raises(GitHubPublicationError, match="github_response_too_large"):
        transport._open(response, 4, 2)


def test_urllib_transport_refuses_joined_body_over_cap(monkeypatch):
    transport = UrllibGitHubTransport()
    response = FakeRawResponse([b""])
    monkeypatch.setattr(transport, "_opener", FakeOpener(response))
    with pytest.raises(GitHubPublicationError, match="github_response_too_large"):
        transport._open(response, 4, -1)


# ---------------------------------------------------------------------------
# Policy and upload-result validation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("overrides", "code"),
    [
        ({"publication_mode": "OTHER"}, "publication_policy_mode_invalid"),
        ({"publication_mode": "NON_BINDING_COMMENT"}, "publication_policy_mode_invalid"),
        ({"repository_id": 0}, "publication_policy_integer_invalid"),
        ({"repository": "owner"}, "publication_policy_repository_invalid"),
        ({"caller_workflow_sha": "z" * 40}, "publication_policy_digest_invalid"),
        ({"profile_sha256": "z" * 64}, "publication_policy_digest_invalid"),
        ({"profile_version": ""}, "publication_policy_text_invalid"),
        ({"allowed_actor_login": "bad login"}, "publication_actor_policy_invalid"),
        ({"artifact_trust_mode": "API_BOUND_SHA256"}, "artifact_trust_mode_invalid"),
        ({"artifact_download_mode": "STATIC_HOST_ALLOWLIST"}, "artifact_download_mode_invalid"),
        ({"credential_provenance": {"schema": "x"}}, "publication_credential_provenance_invalid"),
        ({"api_base_url": "http://api.github.com"}, "github_api_base_invalid"),
        ({"max_bundle_bytes": 9 * 1024 * 1024}, "publication_policy_bytes_exceeded"),
        ({"max_api_response_bytes": 3 * 1024 * 1024}, "publication_policy_bytes_exceeded"),
        ({"artifact_redirect_hosts": ("bad host",)}, "artifact_redirect_host_invalid"),
        (
            {
                "artifact_download_mode": ArtifactDownloadMode.AUTHENTICATED_API_LOCATION_NO_AUTH,
                "api_base_url": "https://github.enterprise/api/v3",
                "artifact_redirect_hosts": (),
            },
            "artifact_download_mode_invalid",
        ),
        (
            {
                "no_effect_only": True,
                "history_reconciliation": _history(),
                "no_effect_policy_hash": "a" * 64,
                "pull_request_number": 44,
            },
            "publication_policy_context_invalid",
        ),
        ({"concurrency_scope": "organization"}, "publication_concurrency_scope_invalid"),
    ],
)
def test_publication_policy_refuses_invalid_trusted_configuration(overrides, code):
    with pytest.raises(GitHubPublicationError, match=code):
        make_policy(**overrides)


@pytest.mark.parametrize(
    ("overrides", "code"),
    [
        (
            {
                "history_reconciliation": {
                    "schema": "publisher-history-reconciliation.v1",
                    "max_historical_exceptions": 4,
                }
            },
            "publication_history_policy_invalid",
        ),
        (
            {"history_reconciliation": _history(), "no_effect_policy_hash": "not-a-hash"},
            "publication_history_policy_hash_invalid",
        ),
        (
            {
                "history_reconciliation": {
                    "schema": "publisher-history-reconciliation.v2",
                    "max_historical_exceptions": 4,
                    "historical_exceptions": [],
                },
                "no_effect_policy_hash": "b" * 64,
            },
            "publication_history_policy_invalid",
        ),
    ],
)
def test_publication_policy_refuses_invalid_history_reconciliation(overrides, code):
    overrides = dict(overrides)
    overrides.setdefault("no_effect_policy_hash", "b" * 64)
    with pytest.raises(GitHubPublicationError, match=code):
        make_policy(**overrides)


@pytest.mark.parametrize(
    ("kwargs", "code"),
    [
        ({"status": "POSTED"}, "artifact_upload_result_invalid"),
        ({"status": "UPLOADED"}, "artifact_upload_id_invalid"),
        ({"status": "UPLOADED", "artifact_id": 1, "reason_code": "Bad Reason"}, "artifact_upload_reason_invalid"),
    ],
)
def test_artifact_upload_result_refuses_invalid_uploader_claims(kwargs, code):
    with pytest.raises(GitHubPublicationError, match=code):
        ArtifactUploadResult(**kwargs)


# ---------------------------------------------------------------------------
# Adapter deadline, credential, endpoint, request and JSON refusals
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("timeout", [0, -1, float("nan"), float("inf"), True, "4", None])
def test_adapter_deadline_and_start_refuse_unbounded_budget(timeout):
    adapter = client()
    with pytest.raises(GitHubPublicationError, match="deadline_exhausted"):
        adapter._deadline(timeout)
    with pytest.raises(GitHubPublicationError, match="deadline_exhausted"):
        adapter._start_deadline(timeout)


def test_credential_refuses_exhausted_remaining_budget():
    adapter = client()
    adapter._deadline_at = 10.0
    adapter._clock = lambda: 100.0
    with pytest.raises(GitHubPublicationError, match="deadline_exhausted"):
        adapter._credential(20, {"actions": "read", "pull_requests": "read"})


def test_credential_refuses_missing_or_failing_provider():
    policy = make_policy()
    adapter = GitHubActionsPublicationAdapter(policy, None, transport=FakeTransport(lambda *_: pytest.fail("no IO")))
    with pytest.raises(GitHubPublicationError, match="publisher_identity_unavailable"):
        adapter._credential(10, {"actions": "read", "pull_requests": "read"})

    class Boom:
        def credential_for(self, *_args):
            raise RuntimeError("provider secret text")

    adapter = client(provider=Boom())
    with pytest.raises(GitHubPublicationError) as excinfo:
        adapter._credential(10, {"actions": "read", "pull_requests": "read"})
    assert excinfo.value.code == "publisher_identity_unavailable"
    assert excinfo.value.__cause__ is None
    assert adapter.transport.calls == []


def test_credential_refuses_non_typed_provider_result():
    adapter = client(provider=StaticProvider(object()))
    with pytest.raises(GitHubPublicationError, match="publisher_credential_unavailable"):
        adapter._credential(10, {"actions": "read", "pull_requests": "read"})


def test_credential_refuses_actor_not_in_trusted_policy():
    adapter = client(provider=StaticProvider(credential(identity=app_identity(actor_login="other-writer"))))
    with pytest.raises(GitHubPublicationError, match="publisher_actor_policy_mismatch"):
        adapter._credential(10, {"actions": "read", "pull_requests": "read"})


def test_actions_token_credential_requires_policy_provenance():
    actions_credential = credential(
        identity=actions_identity(),
        permission_basis=PermissionBasis.WORKFLOW_DECLARATION,
    )
    adapter = client(provider=StaticProvider(actions_credential))
    with pytest.raises(GitHubPublicationError, match="publisher_credential_provenance_missing"):
        adapter._credential(10, {"actions": "read", "pull_requests": "read"})


def test_app_credential_rejects_unexpected_policy_provenance():
    policy = make_policy(credential_provenance=ACTION_CREDENTIAL_PROVENANCE)
    adapter = client(policy=policy, provider=StaticProvider(credential()))
    with pytest.raises(GitHubPublicationError, match="publisher_credential_provenance_unexpected"):
        adapter._credential(10, {"actions": "read", "pull_requests": "read"})


def test_credential_refuses_identity_change_between_requests():
    provider = Provider()
    adapter = client(provider=provider)
    adapter._credential(10, {"actions": "read", "pull_requests": "read"})
    provider.credential = credential(identity=app_identity(evidence_id="4" * 64))
    with pytest.raises(GitHubPublicationError, match="publisher_identity_changed"):
        adapter._credential(10, {"actions": "read", "pull_requests": "read"})
    assert adapter.transport.calls == []


@pytest.mark.parametrize(
    ("path_query", "code"),
    [
        ("repos/owner/repo", "github_endpoint_invalid"),
        ("//evil.example.test/path", "github_endpoint_invalid"),
        ("/repos/owner/../repo", "github_endpoint_invalid"),
        ("https://evil.example.test/path", "github_endpoint_invalid"),
    ],
)
def test_endpoint_refuses_untrusted_relative_paths(path_query, code):
    with pytest.raises(GitHubPublicationError, match=code):
        client()._url(path_query)


def test_no_effect_adapter_refuses_post_before_network():
    policy = make_policy(
        no_effect_only=True,
        pull_request_number=None,
        upstream_run_id=None,
        upstream_run_attempt=None,
        history_reconciliation=_history(),
        no_effect_policy_hash="a" * 64,
    )
    adapter = client(policy=policy)
    with pytest.raises(GitHubPublicationError, match="no_effect_adapter_read_only"):
        adapter._request("POST", "/repos/owner/repo/x", 10, payload={})
    assert adapter.transport.calls == []


def test_request_refuses_expired_deadline_before_credential():
    adapter = client()
    adapter._deadline_at = 10.0
    adapter._clock = lambda: 100.0
    with pytest.raises(GitHubPublicationError, match="deadline_exhausted"):
        adapter._request("GET", "/repos/owner/repo", 20)
    assert adapter.transport.calls == []


def test_request_refuses_deadline_consumed_by_credential_provider():
    now = {"value": 0.0}

    class SlowProvider(Provider):
        def credential_for(self, *args, **kwargs):
            now["value"] = 100.0
            return super().credential_for(*args, **kwargs)

    adapter = client(provider=SlowProvider(), clock=lambda: now["value"])
    adapter._start_deadline(50)
    with pytest.raises(GitHubPublicationError, match="deadline_exhausted"):
        adapter._request("GET", "/repos/owner/repo", 20)
    assert adapter.transport.calls == []


def test_request_refuses_non_success_status():
    adapter = client(transport=FakeTransport(lambda *_: HTTPResponse(500, {}, b"{}")))
    with pytest.raises(GitHubPublicationError, match="github_api_request_failed"):
        adapter._request("GET", "/repos/owner/repo", 10)


def test_pull_includes_created_at_for_history_reconciliation():
    policy = make_policy(history_reconciliation=_history(), no_effect_policy_hash="a" * 64)
    pull = pull_record(policy)
    pull["created_at"] = "2026-10-01T00:00:00Z"
    adapter = client(policy=policy, transport=FakeTransport(lambda *_: response(pull)))
    assert adapter._pull(10)["created_at"] == "2026-10-01T00:00:00Z"


def test_request_refuses_non_http_transport_value():
    adapter = client(transport=FakeTransport(lambda *_: object()))
    with pytest.raises(GitHubPublicationError, match="github_response_invalid"):
        adapter._request("GET", "/repos/owner/repo", 10)


@pytest.mark.parametrize(
    ("raw", "code"),
    [(b"{not-json", "github_json_invalid"), (b"\xff", "github_json_invalid"), (b"[]", "github_json_object_required")],
)
def test_json_object_refuses_invalid_or_non_object_bodies(raw, code):
    adapter = client(transport=FakeTransport(lambda *_: HTTPResponse(200, {}, raw)))
    with pytest.raises(GitHubPublicationError, match=code):
        adapter._json("GET", "/repos/owner/repo", 10)


@pytest.mark.parametrize(
    ("raw", "code"),
    [(b"{not-json", "github_json_invalid"), (b"{}", "github_json_array_required")],
)
def test_json_array_refuses_invalid_or_non_array_bodies(raw, code):
    adapter = client(transport=FakeTransport(lambda *_: HTTPResponse(200, {}, raw)))
    with pytest.raises(GitHubPublicationError, match=code):
        adapter._array("/repos/owner/repo/reviews", 10)


# ---------------------------------------------------------------------------
# Run, upstream and artifact identity verification refusals
# ---------------------------------------------------------------------------


def test_pull_refuses_mismatched_api_identity():
    adapter = client(transport=FakeTransport(lambda *_: response({"number": 45, "state": "open"})))
    with pytest.raises(GitHubPublicationError, match="pull_request_identity_invalid"):
        adapter._pull(10)


@pytest.mark.parametrize(("run_id", "attempt"), [(0, 1), (900001, 0)])
def test_run_refuses_nonpositive_identity_arguments(run_id, attempt):
    adapter = client()
    with pytest.raises(GitHubPublicationError, match="workflow_run_identity_invalid"):
        adapter._run(run_id, attempt, 10)
    assert adapter.transport.calls == []


def test_run_refuses_mismatched_api_record():
    policy = make_policy()
    detail = publisher_record(policy, run_id=900009)
    adapter = client(policy=policy, transport=FakeTransport(lambda *_: response(detail)))
    with pytest.raises(GitHubPublicationError, match="workflow_run_identity_mismatch"):
        adapter._run(policy.publisher_run_id, 1, 10)


def test_latest_run_attempt_refuses_foreign_run_record():
    policy = make_policy()
    adapter = client(
        policy=policy,
        transport=FakeTransport(lambda *_: response({"id": 900009, "workflow_id": 904, "repository": {"id": 8123}})),
    )
    assert adapter._latest_run_attempt(policy.publisher_run_id, 10) is None


def test_run_identity_refuses_wrong_workflow_id():
    adapter = client()
    run = {"workflow_id": 904, "path": ".github/workflows/pr-analysis.yml", "id": 1, "run_attempt": 1}
    with pytest.raises(GitHubPublicationError, match="workflow_id_mismatch"):
        adapter._run_identity(run, publisher=False)


def test_run_identity_refuses_unbounded_publisher_sha():
    policy = make_policy()
    adapter = client(policy=policy)
    run = {
        "workflow_id": policy.publisher_workflow_id,
        "path": policy.publisher_workflow_path,
        "head_sha": "not-a-sha",
        "id": policy.publisher_run_id,
        "run_attempt": 1,
    }
    with pytest.raises(GitHubPublicationError, match="workflow_sha_policy_invalid"):
        adapter._run_identity(run, publisher=True)


def test_harness_reference_refuses_missing_and_foreign_provenance():
    adapter = client()
    with pytest.raises(GitHubPublicationError, match="called_workflow_provenance_missing"):
        adapter._verify_harness_reference({"referenced_workflows": None})
    with pytest.raises(GitHubPublicationError, match="called_workflow_provenance_mismatch"):
        adapter._verify_harness_reference(
            {
                "referenced_workflows": [
                    None,
                    "not-a-record",
                    {"path": 1, "sha": 2},
                    {"path": "other/repo/.github/workflows/review.yml@x", "sha": "e" * 40},
                ]
            }
        )


def test_upstream_run_refuses_missing_pull_request_binding():
    policy = make_policy()
    detail = upstream_record(policy, pull_requests=None)
    adapter = client(policy=policy, transport=FakeTransport(lambda *_: response(detail)))
    with pytest.raises(GitHubPublicationError, match="workflow_run_pr_binding_missing"):
        adapter._validate_upstream_run({"base_sha": BASE, "head_sha": HEAD}, 10)


def test_upstream_run_refuses_nonmatching_pull_request_rows():
    policy = make_policy()
    detail = upstream_record(policy, pull_requests=[None, {"number": 99}])
    adapter = client(policy=policy, transport=FakeTransport(lambda *_: response(detail)))
    with pytest.raises(GitHubPublicationError, match="workflow_run_not_successfully_bound"):
        adapter._validate_upstream_run({"base_sha": BASE, "head_sha": HEAD}, 10)


def _receipt_upstream_adapter(policy, upstream):
    return client(policy=policy, transport=FakeTransport(lambda *_: response(upstream)))


def test_receipt_upstream_refuses_workflow_identity_mismatch():
    policy = make_policy()
    receipt = attempt_receipt(policy, upstream_run=replace(attempt_receipt(policy).upstream_run, workflow_sha="a" * 40))
    upstream = upstream_record(policy)
    adapter = _receipt_upstream_adapter(policy, upstream)
    with pytest.raises(GitHubPublicationError, match="receipt_upstream_workflow_mismatch"):
        adapter._verify_receipt_upstream(receipt, 10)


def test_receipt_upstream_refuses_foreign_pull_request_binding():
    policy = make_policy()
    receipt = attempt_receipt(policy, slot=EffectSlot(8123, "owner/repo", 44, "c" * 40))
    upstream = upstream_record(policy)
    adapter = _receipt_upstream_adapter(policy, upstream)
    with pytest.raises(GitHubPublicationError, match="receipt_upstream_pr_mismatch"):
        adapter._verify_receipt_upstream(receipt, 10)


def test_receipt_upstream_refuses_unsuccessful_run():
    policy = make_policy()
    receipt = attempt_receipt(policy)
    upstream = upstream_record(policy, conclusion="failure")
    adapter = _receipt_upstream_adapter(policy, upstream)
    with pytest.raises(GitHubPublicationError, match="receipt_upstream_run_unsuccessful"):
        adapter._verify_receipt_upstream(receipt, 10)


@pytest.mark.parametrize(
    "artifact",
    [
        {"id": 0, "name": "x", "size_in_bytes": 30, "digest": "sha256:" + "a" * 64, "expired": False},
        {"id": 1, "name": "wrong", "size_in_bytes": 30, "digest": "sha256:" + "a" * 64, "expired": False},
        {"id": 1, "name": "x", "size_in_bytes": 10, "digest": "sha256:" + "a" * 64, "expired": False},
        {"id": 1, "name": "x", "size_in_bytes": 30, "digest": "md5:00", "expired": False},
        {"id": 1, "name": "x", "size_in_bytes": 30, "digest": "sha256:" + "a" * 64, "expired": True},
        {
            "id": 1,
            "name": "x",
            "size_in_bytes": 30,
            "digest": "sha256:" + "a" * 64,
            "expired": False,
            "workflow_run": {"id": 999, "repository_id": 8123},
        },
    ],
)
def test_artifact_metadata_refuses_invalid_or_foreign_metadata(artifact):
    adapter = client()
    code = "artifact_run_binding_invalid" if artifact.get("workflow_run") else "artifact_metadata_invalid_or_expired"
    with pytest.raises(GitHubPublicationError, match=code):
        adapter._artifact_metadata(artifact, expected_name="x", run_id=900001)


def test_download_returns_digest_bound_archive():
    archive = b"archive bytes that pass minimum"
    adapter = client(
        transport=DownloadTransport(
            lambda *_: HTTPResponse(302, {"location": "https://downloads.example.test/f?sig=1"}, b""),
            archive,
        )
    )
    downloaded = adapter._download_artifact(artifact_record("x", archive), 10, 4096)
    assert downloaded.archive == archive
    assert downloaded.archive_sha256 == hashlib.sha256(archive).hexdigest()


@pytest.mark.parametrize(
    ("redirect", "download", "code"),
    [
        (
            "https://untrusted.example.test/f?sig=1",
            b"archive bytes that pass minimum",
            "artifact_download_location_untrusted",
        ),
        (
            "https://downloads.example.test/f?sig=1",
            None,
            "artifact_download_failed",
        ),
        (
            "https://downloads.example.test/f?sig=1",
            b"other archive bytes that pass minimum",
            "artifact_transport_digest_mismatch",
        ),
    ],
)
def test_download_refuses_untrusted_redirect_failed_transport_or_digest(redirect, download, code):
    archive = b"archive bytes that pass minimum"
    factory = (lambda _url: HTTPResponse(500, {}, b"")) if download is None else None
    transport = DownloadTransport(
        lambda *_: HTTPResponse(302, {"location": redirect}, b""),
        archive if download is None else download,
        download_factory=factory,
    )
    adapter = client(transport=transport)
    with pytest.raises(GitHubPublicationError, match=code):
        adapter._download_artifact(artifact_record("x", archive), 10, 4096)


def test_download_refuses_artifact_over_bundle_cap():
    adapter = client()
    artifact = artifact_record("x", size=5000)
    with pytest.raises(GitHubPublicationError, match="artifact_size_limit_exceeded"):
        adapter._download_artifact(artifact, 10, 1024)
    assert adapter.transport.calls == []


def test_download_refuses_missing_redirect():
    adapter = client(transport=FakeTransport(lambda *_: response({"ok": 1})))
    with pytest.raises(GitHubPublicationError, match="artifact_download_redirect_missing"):
        adapter._download_artifact(artifact_record("x"), 10, 1024)


def test_download_refuses_deadline_consumed_after_redirect():
    now = {"value": 0.0}

    def responder(*_):
        now["value"] = 100.0
        return HTTPResponse(302, {"location": "https://downloads.example.test/f?sig=1"}, b"")

    adapter = client(transport=DownloadTransport(responder, b"archive"), clock=lambda: now["value"])
    adapter._start_deadline(50)
    with pytest.raises(GitHubPublicationError, match="deadline_exhausted"):
        adapter._download_artifact(artifact_record("x"), 50, 4096)
    assert adapter.transport.download_calls == []


# ---------------------------------------------------------------------------
# Paginated artifact and publisher-run listing
# ---------------------------------------------------------------------------


def _artifact_pages(pages):
    def responder(_method, url, _body):
        page = int(parse_qs(urlsplit(url).query)["page"][0])
        return response(pages[page - 1])

    return responder


def test_list_named_artifacts_bounds_items_and_reports_completeness():
    adapter = client(
        transport=FakeTransport(_artifact_pages([{"total_count": 3, "artifacts": [{"id": 1}, {"id": 2}, {"id": 3}]}]))
    )
    items, complete = adapter._list_named_artifacts(
        "x", ScanLimits(max_runs=20, max_pages=2, max_reviews=100, deadline_seconds=10), 2
    )
    assert items == [{"id": 1}, {"id": 2}] and complete is False

    adapter = client(
        transport=FakeTransport(_artifact_pages([{"total_count": 2, "artifacts": [{"id": 1}, {"id": 2}]}]))
    )
    items, complete = adapter._list_named_artifacts("x", LIMITS, 100)
    assert items == [{"id": 1}, {"id": 2}] and complete is True

    adapter = client(
        transport=FakeTransport(_artifact_pages([{"total_count": 5, "artifacts": [{"id": 1}, {"id": 2}]}]))
    )
    items, complete = adapter._list_named_artifacts("x", LIMITS, 100)
    assert items == [{"id": 1}, {"id": 2}] and complete is False


def test_list_named_artifacts_reaches_final_page_bound():
    adapter = client(
        transport=FakeTransport(
            _artifact_pages([{"total_count": 200, "artifacts": [{"id": index} for index in range(100)]}])
        )
    )
    items, complete = adapter._list_named_artifacts(
        "x", ScanLimits(max_runs=20, max_pages=1, max_reviews=100, deadline_seconds=10), 200
    )
    assert len(items) == 100 and complete is False


def test_list_named_artifacts_refuses_inconsistent_or_oversized_pages():
    adapter = client(transport=FakeTransport(_artifact_pages([{"total_count": 2, "artifacts": None}])))
    with pytest.raises(GitHubPublicationError, match="artifact_listing_invalid"):
        adapter._list_named_artifacts("x", LIMITS, 100)

    adapter = client(
        transport=FakeTransport(
            _artifact_pages(
                [
                    {"total_count": 200, "artifacts": [{"id": index} for index in range(100)]},
                    {"total_count": 201, "artifacts": [{"id": 100}]},
                ]
            )
        )
    )
    with pytest.raises(GitHubPublicationError, match="artifact_listing_invalid"):
        adapter._list_named_artifacts("x", LIMITS, 200)

    adapter = client(
        transport=FakeTransport(
            _artifact_pages([{"total_count": 101, "artifacts": [{"id": index} for index in range(101)]}])
        )
    )
    with pytest.raises(GitHubPublicationError, match="artifact_page_limit_exceeded"):
        adapter._list_named_artifacts("x", LIMITS, 200)


def test_list_run_artifacts_refuses_count_mismatch():
    adapter = client(transport=FakeTransport(lambda *_: response({"total_count": 2, "artifacts": [{"id": 1}]})))
    with pytest.raises(GitHubPublicationError, match="artifact_listing_invalid"):
        adapter._list_run_artifacts(900001, None, 10)


def _publisher_runs_adapter(policy, pages):
    def responder(_method, url, _body):
        page = int(parse_qs(urlsplit(url).query).get("page", ["1"])[0])
        return response(pages[page - 1])

    return client(policy=policy, transport=FakeTransport(responder))


def _publisher_run_row(policy, run_id):
    return {
        "id": run_id,
        "run_attempt": 1,
        "workflow_id": policy.publisher_workflow_id,
        "head_sha": policy.publisher_workflow_sha,
        "event": "workflow_run",
        "repository": {"id": policy.repository_id},
    }


def test_publisher_runs_refuses_invalid_listing_envelope():
    policy = make_policy()
    adapter = _publisher_runs_adapter(policy, [{"total_count": 1, "workflow_runs": None}])
    with pytest.raises(GitHubPublicationError, match="publisher_run_listing_invalid"):
        adapter._publisher_runs(SLOT, LIMITS)


def test_publisher_runs_refuses_non_record_row():
    policy = make_policy()
    adapter = _publisher_runs_adapter(policy, [{"total_count": 1, "workflow_runs": [None]}])
    with pytest.raises(GitHubPublicationError, match="publisher_run_record_invalid"):
        adapter._publisher_runs(SLOT, LIMITS)


def test_publisher_runs_refuses_foreign_workflow_identity():
    policy = make_policy()
    row = _publisher_run_row(policy, 900001)
    row["workflow_id"] = 999
    adapter = _publisher_runs_adapter(policy, [{"total_count": 1, "workflow_runs": [row]}])
    with pytest.raises(GitHubPublicationError, match="publisher_run_identity_mismatch"):
        adapter._publisher_runs(SLOT, LIMITS)


def test_publisher_runs_refuses_foreign_repository():
    policy = make_policy()
    row = _publisher_run_row(policy, 900001)
    row["repository"] = {"id": 999}
    adapter = _publisher_runs_adapter(policy, [{"total_count": 1, "workflow_runs": [row]}])
    with pytest.raises(GitHubPublicationError, match="publisher_run_repository_mismatch"):
        adapter._publisher_runs(SLOT, LIMITS)


def test_publisher_runs_marks_short_page_with_stale_total_incomplete():
    policy = make_policy()
    row = _publisher_run_row(policy, 900001)
    adapter = _publisher_runs_adapter(policy, [{"total_count": 200, "workflow_runs": [row]}])
    runs, count, complete = adapter._publisher_runs(SLOT, LIMITS)
    assert runs == [row] and count == 1 and complete is False


def test_publisher_runs_reaches_page_bound_with_large_total():
    policy = make_policy()
    rows = [_publisher_run_row(policy, index + 1) for index in range(100)]
    adapter = _publisher_runs_adapter(policy, [{"total_count": 200, "workflow_runs": rows}])
    limits = ScanLimits(max_runs=100, max_pages=1, max_reviews=100, deadline_seconds=10)
    runs, count, complete = adapter._publisher_runs(SLOT, limits)
    assert len(runs) == 100 and count == 100 and complete is False


# ---------------------------------------------------------------------------
# Per-run receipt binding refusals
# ---------------------------------------------------------------------------


def _receipt_adapter(policy, *, detail, artifacts, latest=1, archive=None, archive_name="attempt-receipt.json"):
    state = {"latest_calls": 0}

    def responder(_method, url, _body):
        path = urlsplit(url).path
        if path.endswith(f"/actions/runs/{detail['id']}/attempts/{detail['run_attempt']}"):
            return response(detail)
        if path.endswith(f"/actions/runs/{detail['id']}"):
            state["latest_calls"] += 1
            value = latest(state["latest_calls"]) if callable(latest) else latest
            return response(
                {
                    "id": detail["id"],
                    "run_attempt": value,
                    "workflow_id": detail["workflow_id"],
                    "repository": {"id": detail["repository"]["id"]},
                }
            )
        if path.endswith(f"/actions/runs/{detail['id']}/artifacts"):
            return response({"total_count": len(artifacts), "artifacts": artifacts})
        match = re.search(r"/actions/artifacts/([0-9]+)/zip$", path)
        if match:
            return HTTPResponse(302, {"location": "https://downloads.example.test/receipt?sig=1"}, b"")
        raise AssertionError((_method, path))

    transport = DownloadTransport(responder, archive)
    return GitHubActionsPublicationAdapter(policy, Provider(), transport=transport), transport


def test_receipt_for_run_refuses_rerun_attempt_history():
    policy = make_policy()
    adapter = client(policy=policy)
    run = {"id": 900001, "run_attempt": 2, "status": "completed", "conclusion": "success"}
    with pytest.raises(GitHubPublicationError, match="publisher_rerun_history_unavailable"):
        adapter._receipt_for_publisher_run(SLOT, run, 10)
    assert adapter.transport.calls == []


def test_receipt_for_run_refuses_other_in_progress_publisher_run():
    policy = make_policy()
    adapter = client(policy=policy)
    run = {"id": 900002, "run_attempt": 1, "status": "in_progress"}
    with pytest.raises(GitHubPublicationError, match="publisher_run_still_in_progress"):
        adapter._receipt_for_publisher_run(SLOT, run, 10)
    assert adapter.transport.calls == []


def test_receipt_for_run_refuses_unknown_conclusion():
    policy = make_policy()
    adapter = client(policy=policy)
    run = {"id": 900001, "run_attempt": 1, "status": "completed", "conclusion": "mystery"}
    with pytest.raises(GitHubPublicationError, match="publisher_run_conclusion_unknown"):
        adapter._receipt_for_publisher_run(SLOT, run, 10)
    assert adapter.transport.calls == []


def test_receipt_for_run_refuses_attempt_or_event_mismatch():
    policy = make_policy()
    detail = publisher_record(policy, event="pull_request", status="completed")
    run = {
        "id": 900001,
        "run_attempt": 1,
        "status": "completed",
        "conclusion": "success",
        "head_sha": policy.publisher_workflow_sha,
    }
    adapter, _transport = _receipt_adapter(policy, detail=detail, artifacts=[])
    with pytest.raises(GitHubPublicationError, match="publisher_run_attempt_mismatch"):
        adapter._receipt_for_publisher_run(SLOT, run, 10)


def test_receipt_for_run_refuses_current_workflow_sha_change():
    policy = make_policy()
    detail = publisher_record(policy, head_sha="9" * 40, status="completed")
    run = {
        "id": 900001,
        "run_attempt": 1,
        "status": "completed",
        "conclusion": "success",
        "head_sha": "9" * 40,
    }
    adapter, _transport = _receipt_adapter(policy, detail=detail, artifacts=[])
    with pytest.raises(GitHubPublicationError, match="current_publisher_workflow_sha_mismatch"):
        adapter._receipt_for_publisher_run(SLOT, run, 10)


def test_receipt_for_current_run_returns_none_without_candidates():
    policy = make_policy()
    detail = publisher_record(policy)
    adapter, _transport = _receipt_adapter(policy, detail=detail, artifacts=[])
    assert adapter._receipt_for_publisher_run(SLOT, detail, 10) is None


def test_receipt_for_run_refuses_ambiguous_candidates():
    policy = make_policy()
    detail = publisher_record(policy)
    name = policy.receipt_artifact_name(SLOT)
    first = artifact_record(name, artifact_id=1, workflow_run={"id": 900001, "repository_id": 8123})
    second = artifact_record(name, artifact_id=2, workflow_run={"id": 900001, "repository_id": 8123})
    adapter, _transport = _receipt_adapter(policy, detail=detail, artifacts=[first, second])
    with pytest.raises(GitHubPublicationError, match="publisher_receipt_missing_or_ambiguous"):
        adapter._receipt_for_publisher_run(SLOT, detail, 10)


def test_no_effect_receipt_refuses_attempt_binding_mismatch():
    policy = make_policy(history_reconciliation=_history(), no_effect_policy_hash="a" * 64)
    detail = publisher_record(policy)
    name = policy.no_effect_artifact_name(900001, 1)
    artifact = artifact_record(name, workflow_run={"id": 900001, "repository_id": 8123, "run_attempt": 2})
    adapter, _transport = _receipt_adapter(policy, detail=detail, artifacts=[artifact], latest=1)
    with pytest.raises(GitHubPublicationError, match="publisher_no_effect_attempt_mismatch"):
        adapter._receipt_for_publisher_run(SLOT, detail, 10)


def test_no_effect_receipt_refuses_unproven_attempt():
    policy = make_policy(history_reconciliation=_history(), no_effect_policy_hash="a" * 64)
    detail = publisher_record(policy)
    name = policy.no_effect_artifact_name(900001, 1)
    artifact = artifact_record(name, workflow_run={"id": 900001, "repository_id": 8123})
    adapter, _transport = _receipt_adapter(policy, detail=detail, artifacts=[artifact], latest=2)
    with pytest.raises(GitHubPublicationError, match="publisher_no_effect_attempt_unproven"):
        adapter._receipt_for_publisher_run(SLOT, detail, 10)


def test_attempt_receipt_refuses_attempt_metadata_mismatch():
    policy = make_policy()
    detail = publisher_record(policy)
    name = policy.receipt_artifact_name(SLOT)
    artifact = artifact_record(name, workflow_run={"id": 900001, "repository_id": 8123, "run_attempt": 2})
    adapter, _transport = _receipt_adapter(policy, detail=detail, artifacts=[artifact], latest=1)
    with pytest.raises(GitHubPublicationError, match="publisher_receipt_attempt_mismatch"):
        adapter._receipt_for_publisher_run(SLOT, detail, 10)


def test_attempt_receipt_refuses_expired_receipt_archive():
    policy = make_policy()
    detail = publisher_record(policy)
    name = policy.receipt_artifact_name(SLOT)
    artifact = artifact_record(name, expires_at="2000-01-01T00:00:00Z")
    adapter, _transport = _receipt_adapter(policy, detail=detail, artifacts=[artifact], latest=1)
    with pytest.raises(GitHubPublicationError, match="publisher_receipt_expired"):
        adapter._receipt_for_publisher_run(SLOT, detail, 10)


def test_attempt_receipt_refuses_oversized_archive_metadata():
    policy = make_policy()
    detail = publisher_record(policy)
    name = policy.receipt_artifact_name(SLOT)
    artifact = artifact_record(name, size=policy.max_receipt_archive_bytes + 1)
    adapter, _transport = _receipt_adapter(policy, detail=detail, artifacts=[artifact], latest=1)
    with pytest.raises(GitHubPublicationError, match="publisher_receipt_too_large"):
        adapter._receipt_for_publisher_run(SLOT, detail, 10)


def test_no_effect_receipt_refuses_attempt_changed_after_download(monkeypatch):
    policy = make_policy(history_reconciliation=_history(), no_effect_policy_hash="a" * 64)
    detail = publisher_record(policy)
    identity = _run_identity()
    receipt = no_effect_receipt(publisher_run=identity)
    archive = zip_bytes("no-effect-receipt.json", receipt.to_bytes())
    name = policy.no_effect_artifact_name(900001, 1)
    artifact = artifact_record(name, archive, workflow_run={"id": 900001, "repository_id": 8123})
    adapter, _transport = _receipt_adapter(
        policy, detail=detail, artifacts=[artifact], latest=lambda call: 1 if call == 1 else 2, archive=archive
    )
    monkeypatch.setattr(adapter, "_historical_policy_hash", lambda *_args: receipt.policy_hash)
    with pytest.raises(GitHubPublicationError, match="publisher_no_effect_attempt_changed"):
        adapter._receipt_for_publisher_run(SLOT, detail, 10)


def test_attempt_receipt_refuses_foreign_publisher_run():
    policy = make_policy()
    detail = publisher_record(policy)
    receipt = attempt_receipt(policy, publisher_run=_run_identity(run_id=900002))
    archive = zip_bytes("attempt-receipt.json", receipt.to_bytes())
    name = policy.receipt_artifact_name(SLOT)
    artifact = artifact_record(name, archive, workflow_run={"id": 900001, "repository_id": 8123, "run_attempt": 1})
    adapter, _transport = _receipt_adapter(policy, detail=detail, artifacts=[artifact], archive=archive)
    with pytest.raises(GitHubPublicationError, match="publisher_receipt_binding_mismatch"):
        adapter._receipt_for_publisher_run(SLOT, detail, 10)


def test_attempt_receipt_refuses_name_slot_mismatch():
    policy = make_policy()
    detail = publisher_record(policy)
    receipt = attempt_receipt(policy, slot=EffectSlot(8123, "owner/repo", 45, HEAD))
    archive = zip_bytes("attempt-receipt.json", receipt.to_bytes())
    name = policy.receipt_artifact_name(SLOT)
    artifact = artifact_record(name, archive, workflow_run={"id": 900001, "repository_id": 8123, "run_attempt": 1})
    adapter, _transport = _receipt_adapter(policy, detail=detail, artifacts=[artifact], archive=archive)
    with pytest.raises(GitHubPublicationError, match="publisher_receipt_name_or_slot_mismatch"):
        adapter._receipt_for_publisher_run(SLOT, detail, 10)


# ---------------------------------------------------------------------------
# Historical no-effect and historical policy verification
# ---------------------------------------------------------------------------


PUBLISHER_WORKFLOW = b"name: publisher\n"
ANALYSIS_WORKFLOW = b"name: analysis\n"


def _historical_exception(**overrides):
    record = {
        "run_id": 900001,
        "attempt": 1,
        "publisher_workflow_id": 904,
        "publisher_run_head_sha": "f" * 40,
        "runtime_pin": "e" * 40,
        "publisher_workflow_blob_sha": _blob_sha(PUBLISHER_WORKFLOW),
        "analysis_workflow_blob_sha": _blob_sha(ANALYSIS_WORKFLOW),
        "publisher_job_id": 222,
        "publisher_job_name": "publisher",
        "runtime_step": 8,
        "log_sha256": "c" * 64,
        "log_bytes": 123,
        "outcome": "UNKNOWN",
        "reason_code": "source_artifact_redirect_untrusted",
        "proof_kind": "TRUSTED_PRE_POST_RECONCILIATION",
    }
    record.update(overrides)
    return record


def _content_response(content):
    return response(
        {
            "sha": _blob_sha(content),
            "encoding": "base64",
            "content": base64.encodebytes(content).decode("ascii"),
        }
    )


def test_historical_no_effect_returns_false_without_exception_match():
    assert client()._verify_historical_no_effect({"id": 900001}, 10) is False

    policy = make_policy(history_reconciliation=_history(), no_effect_policy_hash="a" * 64)
    adapter = client(policy=policy)
    assert adapter._verify_historical_no_effect({"id": 900001}, 10) is False


def test_historical_no_effect_refuses_unbound_run_record():
    policy = make_policy(
        history_reconciliation={**_history(), "historical_exceptions": [_historical_exception()]},
        no_effect_policy_hash="a" * 64,
    )
    adapter = client(policy=policy)
    with pytest.raises(GitHubPublicationError, match="historical_no_effect_run_mismatch"):
        adapter._verify_historical_no_effect({"id": 900001, "run_attempt": 2, "workflow_id": 904}, 10)
    assert adapter.transport.calls == []


def test_historical_no_effect_refuses_unparseable_historic_policy():
    policy = make_policy(
        history_reconciliation={**_history(), "historical_exceptions": [_historical_exception()]},
        no_effect_policy_hash="a" * 64,
    )
    publisher = PUBLISHER_WORKFLOW
    analysis = ANALYSIS_WORKFLOW

    def responder(_method, url, _body):
        path = urlsplit(url).path
        if path.endswith("/contents/.github/workflows/pr-publish.yml"):
            return _content_response(publisher)
        if path.endswith("/contents/.github/workflows/pr-analysis.yml"):
            return _content_response(analysis)
        if path.endswith("/contents/.github/pr-review-publisher-policy.json"):
            return _content_response(b"not-json")
        raise AssertionError(path)

    adapter = client(policy=policy, transport=FakeTransport(responder))
    run = {
        "id": 900001,
        "run_attempt": 1,
        "workflow_id": 904,
        "head_sha": "f" * 40,
        "event": "workflow_run",
        "status": "completed",
        "conclusion": "success",
    }
    with pytest.raises(GitHubPublicationError, match="historical_policy_unavailable"):
        adapter._verify_historical_no_effect(run, 10)


def test_historical_no_effect_refuses_runtime_pin_and_job_binding():
    policy = make_policy(
        history_reconciliation={**_history(), "historical_exceptions": [_historical_exception()]},
        no_effect_policy_hash="a" * 64,
    )
    publisher = PUBLISHER_WORKFLOW
    analysis = ANALYSIS_WORKFLOW
    policy_doc = api_policy_document()
    policy_doc["called_harness"]["sha"] = "d" * 40  # not the runtime pin
    policy_bytes = json.dumps(policy_doc, sort_keys=True, separators=(",", ":")).encode()
    run = {
        "id": 900001,
        "run_attempt": 1,
        "workflow_id": 904,
        "head_sha": "f" * 40,
        "event": "workflow_run",
        "status": "completed",
        "conclusion": "success",
    }

    def responder(_method, url, _body):
        path = urlsplit(url).path
        if path.endswith("/contents/.github/workflows/pr-publish.yml"):
            return _content_response(publisher)
        if path.endswith("/contents/.github/workflows/pr-analysis.yml"):
            return _content_response(analysis)
        if path.endswith("/contents/.github/pr-review-publisher-policy.json"):
            return _content_response(policy_bytes)
        if path.endswith("/actions/runs/900001/jobs"):
            return response({"total_count": 1, "jobs": [{}]})
        raise AssertionError(path)

    adapter = client(policy=policy, transport=FakeTransport(responder))
    with pytest.raises(GitHubPublicationError, match="historical_runtime_pin_mismatch"):
        adapter._verify_historical_no_effect(run, 10)

    policy_doc["called_harness"]["sha"] = "e" * 40
    policy_bytes = json.dumps(policy_doc, sort_keys=True, separators=(",", ":")).encode()
    adapter = client(policy=policy, transport=FakeTransport(responder))
    with pytest.raises(GitHubPublicationError, match="historical_no_effect_job_binding_invalid"):
        adapter._verify_historical_no_effect(run, 10)


def test_historical_no_effect_refuses_foreign_job_binding():
    policy = make_policy(
        history_reconciliation={**_history(), "historical_exceptions": [_historical_exception()]},
        no_effect_policy_hash="a" * 64,
    )
    publisher = PUBLISHER_WORKFLOW
    analysis = ANALYSIS_WORKFLOW
    policy_bytes = json.dumps(api_policy_document(), sort_keys=True, separators=(",", ":")).encode()
    job = {
        "id": 222,
        "name": "other-job",
        "run_id": 900001,
        "run_attempt": 1,
        "status": "completed",
        "conclusion": "success",
        "steps": [{"number": index, "conclusion": "success"} for index in range(1, 9)],
    }

    def responder(_method, url, _body):
        path = urlsplit(url).path
        if path.endswith("/contents/.github/workflows/pr-publish.yml"):
            return _content_response(publisher)
        if path.endswith("/contents/.github/workflows/pr-analysis.yml"):
            return _content_response(analysis)
        if path.endswith("/contents/.github/pr-review-publisher-policy.json"):
            return _content_response(policy_bytes)
        if path.endswith("/actions/runs/900001/jobs"):
            return response({"total_count": 1, "jobs": [job]})
        raise AssertionError(path)

    adapter = client(policy=policy, transport=FakeTransport(responder))
    run = {
        "id": 900001,
        "run_attempt": 1,
        "workflow_id": 904,
        "head_sha": "f" * 40,
        "event": "workflow_run",
        "status": "completed",
        "conclusion": "success",
    }
    with pytest.raises(GitHubPublicationError, match="historical_no_effect_job_binding_invalid"):
        adapter._verify_historical_no_effect(run, 10)


def test_historical_content_blob_refuses_missing_or_invalid_base64():
    def adapter_for(value):
        return client(transport=FakeTransport(lambda *_: response(value)))

    valid = {"sha": "a" * 40, "encoding": "base64", "content": None}
    with pytest.raises(GitHubPublicationError, match="historical_content_blob_invalid"):
        adapter_for(valid)._historical_content_blob("path", "f" * 40, 10, 1024)

    invalid = {"sha": "a" * 40, "encoding": "base64", "content": "!!!"}
    with pytest.raises(GitHubPublicationError, match="historical_content_blob_invalid"):
        adapter_for(invalid)._historical_content_blob("path", "f" * 40, 10, 1024)
    assert adapter_for(invalid).transport.calls == []


def api_policy_document(*, enabled=True):
    from test_protected_publication_runtime import api_location_policy_document

    value = api_location_policy_document(enabled=enabled)
    value["schema"] = "pr-review-protected-publication-policy.v4"
    value["history_reconciliation"] = _history()
    return value


def _historical_policy_adapter(
    policy_bytes, *, workflow=b"name: protected publisher\n", extra=None, policy_override=None, workflow_override=None
):
    def responder(_method, url, _body):
        path = urlsplit(url).path
        if path.endswith("/contents/.github/pr-review-publisher-policy.json"):
            if policy_override is not None:
                return policy_override
            return _content_response(policy_bytes)
        if path.endswith("/contents/.github/workflows/pr-publish.yml"):
            if workflow_override is not None:
                return workflow_override
            return _content_response(workflow)
        if extra is not None:
            return extra(_method, url, _body)
        raise AssertionError(path)

    return client(transport=FakeTransport(responder))


def test_historical_policy_hash_refuses_non_object_policy_root():
    adapter = _historical_policy_adapter(b"[]")
    with pytest.raises(GitHubPublicationError, match="historical_policy_invalid"):
        adapter._historical_policy_hash(_run_identity(), 10)


def test_historical_policy_hash_refuses_non_history_schema():
    value = api_policy_document()
    value["schema"] = "pr-review-protected-publication-policy.v3"
    value.pop("history_reconciliation")
    adapter = _historical_policy_adapter(json.dumps(value).encode())
    with pytest.raises(GitHubPublicationError, match="historical_policy_invalid"):
        adapter._historical_policy_hash(_run_identity(), 10)


def test_historical_policy_hash_refuses_foreign_publisher_identity():
    value = api_policy_document()
    value["repository"] = {"name": "other/repo", "id": 999}
    adapter = _historical_policy_adapter(json.dumps(value).encode())
    with pytest.raises(GitHubPublicationError, match="historical_policy_invalid"):
        adapter._historical_policy_hash(_run_identity(), 10)


def test_historical_policy_hash_refuses_workflow_digest_mismatch():
    adapter = _historical_policy_adapter(json.dumps(api_policy_document()).encode(), workflow=b"tampered workflow\n")
    with pytest.raises(GitHubPublicationError, match="historical_policy_invalid"):
        adapter._historical_policy_hash(_run_identity(), 10)


def test_historical_policy_hash_propagates_typed_blob_errors():
    value = api_policy_document()
    adapter = _historical_policy_adapter(
        json.dumps(value).encode(),
        policy_override=response({"sha": "z" * 40, "encoding": "base64", "content": "eA=="}),
    )
    with pytest.raises(GitHubPublicationError, match="historical_content_blob_invalid"):
        adapter._historical_policy_hash(_run_identity(), 10)


def test_historical_policy_hash_reraises_typed_workflow_blob_error():
    value = api_policy_document()
    adapter = _historical_policy_adapter(
        json.dumps(value).encode(),
        workflow_override=response({"sha": "z" * 40, "encoding": "base64", "content": "eA=="}),
    )
    with pytest.raises(GitHubPublicationError, match="historical_content_blob_invalid"):
        adapter._historical_policy_hash(_run_identity(), 10)


def test_historical_policy_hash_returns_canonical_hash_for_bound_policy():
    value = api_policy_document()
    adapter = _historical_policy_adapter(json.dumps(value, sort_keys=True).encode())
    from pr_review_harness.publisher import _canonical_hash

    assert adapter._historical_policy_hash(_run_identity(), 10) == _canonical_hash(value)


def test_skipped_publisher_run_returns_false_for_completed_run():
    assert client()._verify_skipped_publisher_run({"id": 900001, "conclusion": "success"}, 10) is False


@pytest.mark.parametrize(
    "payload",
    [
        {"total_count": True, "jobs": [{"run_id": 900001, "run_attempt": 1}]},
        {
            "total_count": 1,
            "jobs": [
                {
                    "id": 222,
                    "name": "publisher",
                    "run_id": 900001,
                    "run_attempt": 1,
                    "status": "completed",
                    "conclusion": "skipped",
                    "steps": [{}],
                }
            ],
        },
    ],
)
def test_skipped_publisher_run_refuses_unproven_job_shape(payload):
    policy = make_policy(history_reconciliation=_history(), no_effect_policy_hash="a" * 64)
    adapter = client(policy=policy, transport=FakeTransport(lambda *_: response(payload)))
    with pytest.raises(GitHubPublicationError):
        adapter._verify_skipped_publisher_run({"id": 900001, "run_attempt": 1, "conclusion": "skipped"}, 10)


def test_skipped_publisher_run_accepts_proven_zero_step_job():
    policy = make_policy(history_reconciliation=_history(), no_effect_policy_hash="a" * 64)
    job = {
        "id": 222,
        "name": "publisher-disabled",
        "run_id": 900001,
        "run_attempt": 1,
        "status": "completed",
        "conclusion": "skipped",
        "steps": [],
    }
    adapter = client(
        policy=policy,
        transport=FakeTransport(lambda *_: response({"total_count": 1, "jobs": [job]})),
    )
    assert adapter._verify_skipped_publisher_run({"id": 900001, "run_attempt": 1, "conclusion": "skipped"}, 10) is True


# ---------------------------------------------------------------------------
# Admission refusals
# ---------------------------------------------------------------------------


def _admit_setup(
    policy,
    *,
    bundle,
    result,
    artifacts,
    pull=None,
    upstream=None,
    publisher=None,
    config=None,
    download=None,
):
    upstream = upstream if upstream is not None else upstream_record(policy)
    publisher = publisher if publisher is not None else publisher_record(policy, status="in_progress")
    pull = pull if pull is not None else pull_record(policy)
    body = bundle if download is None else download

    def responder(method, url, _body):
        path = urlsplit(url).path
        if path.endswith(f"/pulls/{policy.pull_request_number}"):
            return response(pull)
        if path.endswith(f"/actions/runs/{policy.upstream_run_id}/attempts/{policy.upstream_run_attempt}"):
            return response(upstream)
        if path.endswith(f"/actions/runs/{policy.publisher_run_id}/attempts/{policy.publisher_run_attempt}"):
            return response(publisher)
        if path.endswith(f"/actions/runs/{policy.upstream_run_id}/artifacts"):
            return response({"total_count": len(artifacts), "artifacts": artifacts})
        if re.search(r"/actions/artifacts/[0-9]+/zip$", path):
            return HTTPResponse(302, {"location": "https://downloads.example.test/bundle?sig=1"}, b"")
        raise AssertionError((method, path))

    transport = DownloadTransport(responder, body)
    adapter = GitHubActionsPublicationAdapter(policy, Provider(), transport=transport)
    settings = {
        "schema_version": "1.0",
        "enabled": True,
        "allowed_repositories": [policy.repository],
        "allowed_dispositions": ["COMMENT"],
        "allowed_profile_versions": [policy.profile_version],
        "allowed_actors": [WRITER],
        "max_review_body_bytes": 60_000,
    }
    settings.update(config or {})
    return adapter, transport, settings


def _default_admit_artifact(policy, bundle, **overrides):
    value = {
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
    value.update(overrides)
    return value


def test_admit_refuses_no_effect_adapter():
    policy = make_policy(
        no_effect_only=True,
        pull_request_number=None,
        upstream_run_id=None,
        upstream_run_attempt=None,
        history_reconciliation=_history(),
        no_effect_policy_hash="a" * 64,
    )
    adapter = client(policy=policy)
    with pytest.raises(PublicationAdmissionUnavailable) as excinfo:
        adapter.admit({}, {}, LIMITS)
    assert excinfo.value.reason_code == "publication_admission_unavailable"
    assert adapter.transport.calls == []


def test_admit_refuses_invalid_limits_and_result_before_network():
    result = make_valid_result()
    policy = make_policy()
    bundle = bundle_for(policy, result)
    adapter, transport, settings = _admit_setup(
        policy, bundle=bundle, result=result, artifacts=[_default_admit_artifact(policy, bundle)]
    )
    with pytest.raises(PublicationAdmissionUnavailable, match="publication_limits_invalid"):
        adapter.admit(result, settings, object())
    assert transport.calls == []

    adapter, transport, settings = _admit_setup(
        policy, bundle=bundle, result=result, artifacts=[_default_admit_artifact(policy, bundle)]
    )
    with pytest.raises(PublicationAdmissionUnavailable, match="review_result_invalid"):
        adapter.admit(object(), settings, LIMITS)
    assert transport.calls == []


def test_admit_refuses_stale_result_and_missing_artifact():
    result = make_valid_result()
    policy = make_policy()
    bundle = bundle_for(policy, result)
    stale = dict(result, head_sha="c" * 40)
    adapter, transport, settings = _admit_setup(
        policy, bundle=bundle, result=stale, artifacts=[_default_admit_artifact(policy, bundle)]
    )
    with pytest.raises(PublicationAdmissionUnavailable, match="review_result_target_stale_or_mismatched"):
        adapter.admit(stale, settings, LIMITS)

    adapter, transport, settings = _admit_setup(policy, bundle=bundle, result=result, artifacts=[])
    with pytest.raises(PublicationAdmissionUnavailable, match="result_artifact_missing_or_ambiguous"):
        adapter.admit(result, settings, LIMITS)
    assert all(call[0] == "GET" for call in transport.calls)


def test_admit_refuses_publisher_run_state_invalid():
    result = make_valid_result()
    policy = make_policy()
    bundle = bundle_for(policy, result)
    adapter, _transport, settings = _admit_setup(
        policy,
        bundle=bundle,
        result=result,
        artifacts=[_default_admit_artifact(policy, bundle)],
        publisher=publisher_record(policy, status="queued"),
    )
    with pytest.raises(PublicationAdmissionUnavailable, match="publisher_run_state_invalid"):
        adapter.admit(result, settings, LIMITS)


def test_admit_refuses_canonical_review_mismatch():
    from pr_review_harness.publisher import _canonical_hash

    result = make_valid_result()
    policy = make_policy()
    tampered = dict(result)
    tampered["rendered_review"] = "different review body"
    tampered["result_hash"] = _canonical_hash({key: value for key, value in tampered.items() if key != "result_hash"})
    bundle = bundle_for(policy, tampered)
    adapter, _transport, settings = _admit_setup(
        policy, bundle=bundle, result=tampered, artifacts=[_default_admit_artifact(policy, bundle)]
    )
    with pytest.raises(PublicationAdmissionUnavailable, match="canonical_review_mismatch"):
        adapter.admit(tampered, settings, LIMITS)


def test_admit_refuses_oversized_and_foreign_bound_result_artifacts():
    result = make_valid_result()
    policy = make_policy()
    bundle = bundle_for(policy, result)
    adapter, _transport, settings = _admit_setup(
        policy,
        bundle=bundle,
        result=result,
        artifacts=[_default_admit_artifact(policy, bundle, size_in_bytes=policy.max_bundle_bytes + 1)],
    )
    with pytest.raises(PublicationAdmissionUnavailable, match="result_artifact_too_large"):
        adapter.admit(result, settings, LIMITS)

    adapter, _transport, settings = _admit_setup(
        policy,
        bundle=bundle,
        result=result,
        artifacts=[
            _default_admit_artifact(
                policy,
                bundle,
                workflow_run={
                    "id": policy.upstream_run_id,
                    "repository_id": policy.repository_id,
                    "head_sha": "c" * 40,
                },
            )
        ],
    )
    with pytest.raises(PublicationAdmissionUnavailable, match="result_artifact_head_binding_invalid"):
        adapter.admit(result, settings, LIMITS)


def test_admit_refuses_result_content_binding_mismatch():
    result = make_valid_result()
    policy = make_policy()
    bundle = bundle_for(policy, result)
    tampered = dict(result, admitted_note="extra")
    adapter, _transport, settings = _admit_setup(
        policy,
        bundle=bundle,
        result=result,
        artifacts=[_default_admit_artifact(policy, bundle)],
    )
    with pytest.raises(PublicationAdmissionUnavailable, match="result_artifact_content_mismatch"):
        adapter.admit(tampered, settings, LIMITS)


def test_admit_maps_corrupt_bundle_to_generic_unavailability():
    policy = make_policy()
    corrupt = b"x" * 64
    artifact = _default_admit_artifact(policy, corrupt)
    adapter, transport, settings = _admit_setup(
        policy, bundle=corrupt, result=make_valid_result(), artifacts=[artifact]
    )
    with pytest.raises(PublicationAdmissionUnavailable) as excinfo:
        adapter.admit(make_valid_result(), settings, LIMITS)
    assert excinfo.value.reason_code == "publication_admission_unavailable"
    assert all(call[0] == "GET" for call in transport.calls)


def test_admit_refuses_unavailable_signed_attestation():
    result = make_valid_result()
    policy = make_policy(artifact_trust_mode=ArtifactTrustMode.SIGNED_ATTESTATION)
    bundle = bundle_for(policy, result)
    adapter, _transport, settings = _admit_setup(
        policy, bundle=bundle, result=result, artifacts=[_default_admit_artifact(policy, bundle)]
    )
    with pytest.raises(PublicationAdmissionUnavailable, match="result_artifact_attestation_unavailable"):
        adapter.admit(result, settings, LIMITS)


def test_admit_returns_bound_capability_for_matching_bundle():
    result = make_valid_result()
    policy = make_policy()
    bundle = bundle_for(policy, result)
    adapter, transport, settings = _admit_setup(
        policy, bundle=bundle, result=result, artifacts=[_default_admit_artifact(policy, bundle)]
    )
    admission = adapter.admit(result, settings, LIMITS)
    assert admission.slot == EffectSlot(policy.repository_id, policy.repository, 44, HEAD)
    assert admission.base_sha == BASE
    assert admission.actor_login == WRITER
    assert admission.review_event == "COMMENT"
    assert admission.disposition == "COMMENT"
    assert admission.publisher_run.run_id == policy.publisher_run_id
    assert admission.upstream_run.run_id == policy.upstream_run_id
    assert admission.source_artifact_sha256 == hashlib.sha256(bundle).hexdigest()
    assert admission.concurrency_group == "pr-review-publish-8123-44"
    assert admission.publication_mode == "DISPOSITION"
    assert all(call[0] == "GET" for call in transport.calls)


def test_admit_refuses_publication_mode_mismatch():
    result = make_valid_result()
    policy = make_policy()
    bundle = bundle_for(policy, result)
    adapter, _transport, settings = _admit_setup(
        policy,
        bundle=bundle,
        result=result,
        artifacts=[_default_admit_artifact(policy, bundle)],
        config={"publication_mode": "NON_BINDING_COMMENT"},
    )
    with pytest.raises(PublicationAdmissionUnavailable) as excinfo:
        adapter.admit(result, settings, LIMITS)
    assert excinfo.value.reason_code == "publication_admission_unavailable"


# ---------------------------------------------------------------------------
# Review page scanning refusals
# ---------------------------------------------------------------------------


def _review_adapter(reviews):
    return client(transport=FakeTransport(lambda *_: response(reviews)))


def test_review_pages_refuse_oversized_page_and_review_bound():
    adapter = _review_adapter([{"body": "unmarked"} for _ in range(101)])
    with pytest.raises(GitHubPublicationError, match="review_page_limit_exceeded"):
        adapter._review_pages(SLOT, LIMITS)

    adapter = _review_adapter([{"body": "unmarked"}, {"body": "unmarked"}])
    limits = ScanLimits(max_runs=20, max_pages=2, max_reviews=1, deadline_seconds=10)
    observations, scanned, pages, complete = adapter._review_pages(SLOT, limits)
    assert observations == [] and scanned == 2 and pages == 1 and complete is False


@pytest.mark.parametrize(
    ("review", "code"),
    [
        (None, "review_record_invalid"),
        ({"body": 5}, "review_body_invalid"),
        (
            {
                "body": f"a <!-- pr-review-harness:{EFFECT} -->\n\n<!-- pr-review-harness:{EFFECT} -->",
                "commit_id": HEAD,
                "state": "COMMENTED",
                "user": {"login": WRITER},
            },
            "review_marker_ambiguous",
        ),
        (
            {
                "body": f"Review.\n\n<!-- pr-review-harness:{EFFECT} -->",
                "commit_id": "not-a-sha",
                "state": "COMMENTED",
                "user": {"login": WRITER},
            },
            "review_commit_invalid",
        ),
        (
            {
                "body": f"Review.\n\n<!-- pr-review-harness:{EFFECT} -->",
                "commit_id": HEAD,
                "state": "DISMISSED",
                "user": {"login": WRITER},
            },
            "review_identity_invalid",
        ),
    ],
)
def test_review_pages_refuse_invalid_review_records(review, code):
    adapter = _review_adapter([review])
    with pytest.raises(GitHubPublicationError, match=code):
        adapter._review_pages(SLOT, LIMITS)


def test_review_pages_binds_marked_review_and_skips_foreign_head():
    marked = {
        "id": 1234,
        "commit_id": HEAD,
        "state": "COMMENTED",
        "body": f"Review body.\n\n<!-- pr-review-harness:{EFFECT} -->",
        "user": {"login": WRITER},
    }
    foreign = dict(marked, id=1235, commit_id="c" * 40)
    adapter = _review_adapter([marked, foreign])
    observations, scanned, pages, complete = adapter._review_pages(SLOT, LIMITS)
    assert len(observations) == 1 and observations[0].review_id == 1234
    assert observations[0].actor_login == WRITER
    assert scanned == 2 and pages == 1 and complete is True


def test_review_pages_marks_page_bound_without_terminal_page_incomplete():
    adapter = _review_adapter([{"body": "ordinary unmarked review"} for _ in range(100)])
    limits = ScanLimits(max_runs=20, max_pages=1, max_reviews=100, deadline_seconds=10)
    observations, scanned, pages, complete = adapter._review_pages(SLOT, limits)
    assert observations == [] and scanned == 100 and pages == 1 and complete is False


def test_review_pages_treats_null_body_as_unmarked():
    adapter = _review_adapter([{"body": None}])
    observations, scanned, _pages, complete = adapter._review_pages(SLOT, LIMITS)
    assert observations == [] and scanned == 1 and complete is True


# ---------------------------------------------------------------------------
# Scan control-flow refusals
# ---------------------------------------------------------------------------


def test_scan_refuses_no_effect_adapter_and_foreign_slot():
    policy = make_policy(
        no_effect_only=True,
        pull_request_number=None,
        upstream_run_id=None,
        upstream_run_attempt=None,
        history_reconciliation=_history(),
        no_effect_policy_hash="a" * 64,
    )
    adapter = client(policy=policy)
    result = adapter.scan(SLOT, LIMITS)
    assert result.status is HistoryStatus.UNAVAILABLE
    assert result.reason_code == "no_effect_adapter_read_only"
    assert adapter.transport.calls == []

    adapter = client()
    result = adapter.scan(EffectSlot(999, "owner/repo", 44, HEAD), LIMITS)
    assert result.status is HistoryStatus.UNAVAILABLE
    assert result.reason_code == "history_target_mismatch"
    assert adapter.transport.calls == []


def test_scan_refuses_deadline_consumed_by_receipt_history(monkeypatch):
    now = {"value": 0.0}
    adapter = client(
        transport=FakeTransport(lambda *_: response([])),
        clock=lambda: now["value"],
    )
    adapter._start_deadline = lambda timeout: adapter.__dict__.__setitem__("_deadline_at", now["value"] + timeout)

    def receipt_history(*_args):
        now["value"] = 100.0
        return [], [], 0, True

    monkeypatch.setattr(adapter, "_receipt_history", receipt_history)
    result = adapter.scan(SLOT, LIMITS)
    assert result.status is HistoryStatus.UNAVAILABLE
    assert result.reason_code == "history_deadline_exhausted"


def test_scan_refuses_adapter_limit_caps():
    adapter = client()
    limits = ScanLimits(max_runs=101, max_pages=2, max_reviews=100, deadline_seconds=10)
    result = adapter.scan(SLOT, limits)
    assert result.status is HistoryStatus.UNAVAILABLE
    assert result.reason_code == "history_limits_invalid"
    assert adapter.transport.calls == []


def test_scan_refuses_deadline_consumed_by_review_pages():
    now = {"value": 0.0}

    def responder(*_args):
        now["value"] = 100.0
        return response([])

    adapter = client(transport=FakeTransport(responder), clock=lambda: now["value"])
    result = adapter.scan(SLOT, LIMITS)
    assert result.status is HistoryStatus.UNAVAILABLE
    assert result.reason_code == "history_deadline_exhausted"
    assert len(adapter.transport.calls) == 1


def test_scan_maps_typed_publication_error_to_unavailable(monkeypatch):
    adapter = client()
    monkeypatch.setattr(adapter, "_review_pages", lambda *_: (_ for _ in ()).throw(GitHubPublicationError("x")))
    result = adapter.scan(SLOT, LIMITS)
    assert result.status is HistoryStatus.UNAVAILABLE
    assert result.reason_code == "github_history_unavailable"


def test_scan_refuses_unexpected_internal_failure(monkeypatch):
    adapter = client()
    monkeypatch.setattr(adapter, "_review_pages", lambda *_: (_ for _ in ()).throw(RuntimeError("boom")))
    result = adapter.scan(SLOT, LIMITS)
    assert result.status is HistoryStatus.UNAVAILABLE
    assert result.reason_code == "github_history_invalid"
    assert adapter.transport.calls == []


def _history_adapter(policy, monkeypatch, *, runs, receipt, historical=False, skipped=False):
    adapter = client(policy=policy, transport=FakeTransport(lambda *_: response([])))
    monkeypatch.setattr(adapter, "_publisher_runs", lambda *_args: (runs, len(runs), True))
    monkeypatch.setattr(adapter, "_receipt_for_publisher_run", lambda *_args: receipt)
    monkeypatch.setattr(adapter, "_verify_historical_no_effect", lambda *_args: historical)
    monkeypatch.setattr(adapter, "_verify_skipped_publisher_run", lambda *_args: skipped)
    return adapter


def test_receipt_history_returns_incomplete_when_publisher_listing_is_partial(monkeypatch):
    adapter = client(transport=FakeTransport(lambda *_: response([])))
    monkeypatch.setattr(adapter, "_publisher_runs", lambda *_args: ([], 0, False))
    result = adapter.scan(SLOT, LIMITS)
    assert result.status is HistoryStatus.INCOMPLETE
    assert result.reason_code == "receipt_history_incomplete"


def test_receipt_history_records_matching_attempt_receipts(monkeypatch):
    policy = make_policy()
    receipt = attempt_receipt(policy)
    adapter = _history_adapter(policy, monkeypatch, runs=[{"id": 900001}], receipt=receipt)
    result = adapter.scan(SLOT, LIMITS)
    assert result.status is HistoryStatus.COMPLETE
    assert result.receipts == (receipt,)


def test_receipt_history_records_no_effect_receipts(monkeypatch):
    policy = make_policy(history_reconciliation=_history(), no_effect_policy_hash="a" * 64)
    receipt = no_effect_receipt()
    adapter = _history_adapter(policy, monkeypatch, runs=[{"id": 900001}], receipt=receipt)
    result = adapter.scan(SLOT, LIMITS)
    assert result.status is HistoryStatus.COMPLETE
    assert result.no_effects == (receipt,)


def test_receipt_history_legacy_none_receipt_is_tolerated(monkeypatch):
    policy = make_policy()
    adapter = _history_adapter(policy, monkeypatch, runs=[{"id": 900001}], receipt=None)
    result = adapter.scan(SLOT, LIMITS)
    assert result.status is HistoryStatus.COMPLETE
    assert result.receipts == ()


def test_receipt_history_accepts_current_and_proven_historical_runs(monkeypatch):
    policy = make_policy(history_reconciliation=_history(), no_effect_policy_hash="a" * 64)
    adapter = _history_adapter(policy, monkeypatch, runs=[{"id": 900001}], receipt=None, historical=True)
    result = adapter.scan(SLOT, LIMITS)
    assert result.status is HistoryStatus.COMPLETE

    adapter = _history_adapter(policy, monkeypatch, runs=[{"id": 900002}], receipt=None, skipped=True)
    result = adapter.scan(SLOT, LIMITS)
    assert result.status is HistoryStatus.COMPLETE


def test_receipt_history_accepts_current_run_without_receipt(monkeypatch):
    policy = make_policy(history_reconciliation=_history(), no_effect_policy_hash="a" * 64)
    adapter = _history_adapter(policy, monkeypatch, runs=[{"id": 900001}], receipt=None)
    result = adapter.scan(SLOT, LIMITS)
    assert result.status is HistoryStatus.COMPLETE


def test_receipt_history_marks_unproven_missing_receipt_incomplete(monkeypatch):
    policy = make_policy(history_reconciliation=_history(), no_effect_policy_hash="a" * 64)
    adapter = _history_adapter(policy, monkeypatch, runs=[{"id": 900002}], receipt=None)
    result = adapter.scan(SLOT, LIMITS)
    assert result.status is HistoryStatus.INCOMPLETE
    assert result.reason_code == "receipt_history_incomplete"
    assert result.receipts == ()


# ---------------------------------------------------------------------------
# Receipt persistence refusals (attempt receipts)
# ---------------------------------------------------------------------------


class RecordingUploader:
    def __init__(self, status="UPLOADED", artifact_id=55, reason_code=None):
        self.status = status
        self.artifact_id = artifact_id
        self.reason_code = reason_code
        self.calls = []

    def upload(self, **kwargs):
        self.calls.append(kwargs)
        return ArtifactUploadResult(self.status, artifact_id=self.artifact_id, reason_code=self.reason_code)


def test_persist_refuses_no_effect_adapter_and_invalid_limits():
    policy = make_policy(
        no_effect_only=True,
        pull_request_number=None,
        upstream_run_id=None,
        upstream_run_attempt=None,
        history_reconciliation=_history(),
        no_effect_policy_hash="a" * 64,
    )
    adapter = client(policy=policy, artifact_uploader=RecordingUploader())
    result = adapter.persist(attempt_receipt(), LIMITS)
    assert result.status is ReceiptPersistenceStatus.REJECTED
    assert result.reason_code == "no_effect_adapter_read_only"

    adapter = client(artifact_uploader=RecordingUploader())
    result = adapter.persist(attempt_receipt(), object())
    assert result.status is ReceiptPersistenceStatus.UNKNOWN
    assert result.reason_code == "receipt_limits_invalid"
    assert adapter.transport.calls == []


def test_persist_refuses_invalid_deadline_and_missing_uploader():
    limits = object.__new__(ScanLimits)
    for name, value in (("max_runs", 20), ("max_pages", 2), ("max_reviews", 100), ("deadline_seconds", 0)):
        object.__setattr__(limits, name, value)
    adapter = client(artifact_uploader=RecordingUploader())
    result = adapter.persist(attempt_receipt(), limits)
    assert result.reason_code == "receipt_deadline_invalid"

    adapter = client()
    result = adapter.persist(attempt_receipt(), LIMITS)
    assert result.reason_code == "artifact_uploader_unavailable"
    assert adapter.transport.calls == []


def test_persist_refuses_foreign_receipt_run_identity():
    uploader = RecordingUploader()
    adapter = client(artifact_uploader=uploader)
    result = adapter.persist(attempt_receipt(publisher_run=_run_identity(run_id=900002)), LIMITS)
    assert result.status is ReceiptPersistenceStatus.REJECTED
    assert result.reason_code == "publisher_run_mismatch"
    assert uploader.calls == []

    adapter = client(artifact_uploader=uploader)
    result = adapter.persist(attempt_receipt(publisher_run=_run_identity(sha="a" * 40)), LIMITS)
    assert result.status is ReceiptPersistenceStatus.REJECTED
    assert result.reason_code == "publisher_identity_mismatch"
    assert uploader.calls == []


def test_persist_refuses_completed_publisher_run_before_upload():
    policy = make_policy()
    detail = publisher_record(policy, status="completed")
    uploader = RecordingUploader()
    adapter = client(
        policy=policy, transport=DownloadTransport(lambda *_: response(detail)), artifact_uploader=uploader
    )
    result = adapter.persist(attempt_receipt(policy), LIMITS)
    assert result.status is ReceiptPersistenceStatus.REJECTED
    assert result.reason_code == "publisher_identity_mismatch"
    assert uploader.calls == []


def _persist_ack_setup(policy, receipt, *, expires_at="2999-01-01T00:00:00Z", post_sha=None, archive=None):
    archive = archive if archive is not None else zip_bytes("attempt-receipt.json", receipt.to_bytes())
    uploader = RecordingUploader()
    state = {"archive_calls": 0}

    def responder(_method, url, _body):
        path = urlsplit(url).path
        if path.endswith(f"/actions/runs/{policy.publisher_run_id}/attempts/{policy.publisher_run_attempt}"):
            state["archive_calls"] += 1
            sha = policy.publisher_workflow_sha if post_sha is None or state["archive_calls"] == 1 else post_sha
            return response(publisher_record(policy, head_sha=sha))
        if path.endswith(f"/actions/runs/{policy.publisher_run_id}/artifacts"):
            name = policy.receipt_artifact_name(receipt.slot)
            metadata = {
                "id": 55,
                "name": name,
                "size_in_bytes": len(archive),
                "digest": "sha256:" + hashlib.sha256(archive).hexdigest(),
                "expired": False,
                "expires_at": expires_at,
                "workflow_run": {"id": policy.publisher_run_id, "repository_id": policy.repository_id},
            }
            return response({"total_count": 1, "artifacts": [metadata]})
        match = re.search(r"/actions/artifacts/55/zip$", path)
        if match:
            return HTTPResponse(302, {"location": "https://downloads.example.test/receipt?sig=1"}, b"")
        raise AssertionError(path)

    adapter = client(
        policy=policy,
        transport=DownloadTransport(responder, archive),
        artifact_uploader=uploader,
    )
    return adapter, uploader


def test_persist_refuses_unverified_artifact_content():
    policy = make_policy()
    receipt = attempt_receipt(policy)
    foreign = attempt_receipt(policy, result_hash="9" * 64)
    archive = zip_bytes("attempt-receipt.json", foreign.to_bytes())
    adapter, _uploader = _persist_ack_setup(policy, receipt, expires_at=None, archive=archive)
    result = adapter.persist(receipt, LIMITS)
    assert result.status is ReceiptPersistenceStatus.UNKNOWN
    assert result.reason_code == "artifact_content_mismatch"


def test_persist_refuses_identity_change_after_upload():
    policy = make_policy()
    receipt = attempt_receipt(policy)
    adapter, _uploader = _persist_ack_setup(policy, receipt, post_sha="9" * 40)
    result = adapter.persist(receipt, LIMITS)
    assert result.status is ReceiptPersistenceStatus.UNKNOWN
    assert result.reason_code == "publisher_identity_changed"


def test_persist_maps_unexpected_transport_failure_to_unknown():
    uploader = RecordingUploader()
    adapter = client(
        transport=FakeTransport(lambda *_: (_ for _ in ()).throw(RuntimeError("boom"))),
        artifact_uploader=uploader,
    )
    result = adapter.persist(attempt_receipt(), LIMITS)
    assert result.status is ReceiptPersistenceStatus.UNKNOWN
    assert result.reason_code == "artifact_persistence_unknown"


def test_persist_maps_unconfirmed_upload_to_unknown_without_ack():
    policy = make_policy()
    uploader = RecordingUploader(status="UNAVAILABLE", artifact_id=None)
    adapter = client(
        policy=policy,
        transport=FakeTransport(lambda *_: response(publisher_record(policy))),
        artifact_uploader=uploader,
    )
    result = adapter.persist(attempt_receipt(policy), LIMITS)
    assert result.status is ReceiptPersistenceStatus.UNKNOWN
    assert result.reason_code == "artifact_upload_unconfirmed"
    assert len(uploader.calls) == 1


# ---------------------------------------------------------------------------
# No-effect receipt persistence refusals
# ---------------------------------------------------------------------------


def _no_effect_policy(**overrides):
    values = {"history_reconciliation": _history(), "no_effect_policy_hash": "a" * 64}
    values.update(overrides)
    return make_policy(**values)


class NoEffectUploader(RecordingUploader):
    def __init__(self, archive_holder=None):
        super().__init__()
        self.archive_holder = archive_holder

    def upload(self, **kwargs):
        self.calls.append(kwargs)
        if self.archive_holder is not None:
            stream = io.BytesIO()
            with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                archive.writestr(kwargs["filename"], kwargs["content"])
            self.archive_holder["archive"] = stream.getvalue()
        return ArtifactUploadResult("UPLOADED", artifact_id=55)


def _no_effect_setup(
    policy,
    receipt,
    *,
    artifacts=None,
    latest=1,
    archive_holder=None,
    upload=None,
    run_status="in_progress",
    post_sha=None,
):
    uploader = upload if upload is not None else NoEffectUploader(archive_holder)
    state = {"run_calls": 0, "artifacts_calls": 0, "latest_calls": 0}

    def responder(_method, url, _body):
        path = urlsplit(url).path
        if path.endswith(f"/actions/runs/{policy.publisher_run_id}/attempts/{policy.publisher_run_attempt}"):
            state["run_calls"] += 1
            sha = policy.publisher_workflow_sha
            if post_sha is not None and state["run_calls"] > 1:
                sha = post_sha
            return response(publisher_record(policy, head_sha=sha, status=run_status))
        if path.endswith(f"/actions/runs/{policy.publisher_run_id}"):
            state["latest_calls"] += 1
            value = latest(state["latest_calls"]) if callable(latest) else latest
            return response(
                {
                    "id": policy.publisher_run_id,
                    "run_attempt": value,
                    "workflow_id": policy.publisher_workflow_id,
                    "repository": {"id": policy.repository_id},
                }
            )
        if path.endswith(f"/actions/runs/{policy.publisher_run_id}/artifacts"):
            state["artifacts_calls"] += 1
            listing = artifacts(state["artifacts_calls"]) if callable(artifacts) else (artifacts or [])
            return response({"total_count": len(listing), "artifacts": listing})
        match = re.search(r"/actions/artifacts/([0-9]+)/zip$", path)
        if match:
            return HTTPResponse(302, {"location": "https://downloads.example.test/receipt?sig=1"}, b"")
        raise AssertionError(path)

    body = archive_holder.get("archive") if archive_holder else b""
    adapter = client(
        policy=policy,
        transport=DownloadTransport(
            responder,
            body or b"",
            download_factory=lambda _url: HTTPResponse(200, {}, (archive_holder or {}).get("archive", b"")),
        ),
        artifact_uploader=uploader,
    )
    return adapter, uploader


def test_persist_no_effect_refuses_unavailable_policy_and_uploader():
    policy = make_policy()
    adapter = client(policy=policy, artifact_uploader=NoEffectUploader())
    result = adapter.persist_no_effect(no_effect_receipt(), LIMITS)
    assert result.status is ReceiptPersistenceStatus.REJECTED
    assert result.reason_code == "no_effect_policy_unavailable"

    adapter = client(policy=_no_effect_policy())
    result = adapter.persist_no_effect(no_effect_receipt(), LIMITS)
    assert result.status is ReceiptPersistenceStatus.UNKNOWN
    assert result.reason_code == "artifact_uploader_unavailable"
    assert adapter.transport.calls == []


def test_persist_no_effect_refuses_foreign_receipt_run():
    policy = _no_effect_policy()
    uploader = NoEffectUploader()
    adapter, _uploader = _no_effect_setup(policy, no_effect_receipt(), upload=uploader)
    result = adapter.persist_no_effect(no_effect_receipt(publisher_run=_run_identity(run_id=900002)), LIMITS)
    assert result.status is ReceiptPersistenceStatus.REJECTED
    assert result.reason_code == "publisher_run_mismatch"
    assert uploader.calls == []


def test_persist_no_effect_refuses_completed_run_or_policy_hash_change():
    policy = _no_effect_policy()
    adapter, uploader = _no_effect_setup(policy, no_effect_receipt(), run_status="completed")
    result = adapter.persist_no_effect(no_effect_receipt(), LIMITS)
    assert result.status is ReceiptPersistenceStatus.REJECTED
    assert result.reason_code == "publisher_identity_mismatch"
    assert uploader.calls == []

    adapter, uploader = _no_effect_setup(policy, no_effect_receipt(policy_hash="b" * 64))
    result = adapter.persist_no_effect(no_effect_receipt(policy_hash="b" * 64), LIMITS)
    assert result.reason_code == "publisher_identity_mismatch"
    assert uploader.calls == []


def test_persist_no_effect_refuses_existing_no_effect_artifact():
    policy = _no_effect_policy()
    name = policy.no_effect_artifact_name(900001, 1)
    adapter, uploader = _no_effect_setup(policy, no_effect_receipt(), artifacts=[{"name": name}])
    result = adapter.persist_no_effect(no_effect_receipt(), LIMITS)
    assert result.status is ReceiptPersistenceStatus.UNKNOWN
    assert result.reason_code == "no_effect_artifact_already_exists"
    assert uploader.calls == []


def test_persist_no_effect_refuses_ambiguous_or_foreign_prior_receipt():
    policy = _no_effect_policy()
    receipt = no_effect_receipt(pull_request_number=44, base_sha=BASE, head_sha=HEAD)
    slot = EffectSlot(8123, "owner/repo", 44, HEAD)
    name = policy.receipt_artifact_name(slot)

    # Two same-named prior attempt receipts are ambiguous.
    adapter, uploader = _no_effect_setup(policy, receipt, artifacts=[{"name": name}, {"name": name}])
    result = adapter.persist_no_effect(receipt, LIMITS)
    assert result.reason_code == "attempt_receipt_ambiguous"
    assert uploader.calls == []

    # A single prior receipt that binds a different slot is not adopted.
    foreign = attempt_receipt(policy, slot=EffectSlot(8123, "owner/repo", 45, HEAD))
    archive = zip_bytes("attempt-receipt.json", foreign.to_bytes())
    prior = artifact_record(
        name, archive, workflow_run={"id": policy.publisher_run_id, "repository_id": policy.repository_id}
    )
    adapter, uploader = _no_effect_setup(policy, receipt, artifacts=[prior])
    adapter.transport.download_factory = lambda _url: HTTPResponse(200, {}, archive)
    result = adapter.persist_no_effect(receipt, LIMITS)
    assert result.reason_code == "attempt_receipt_binding_mismatch"
    assert uploader.calls == []


def test_persist_no_effect_refuses_ack_and_attempt_metadata():
    policy = _no_effect_policy()
    receipt = no_effect_receipt()
    holder = {}
    adapter, uploader = _no_effect_setup(policy, receipt, artifacts=[], archive_holder=holder)
    result = adapter.persist_no_effect(receipt, LIMITS)
    assert result.reason_code == "no_effect_artifact_ack_missing"
    assert len(uploader.calls) == 1

    name = policy.no_effect_artifact_name(900001, 1)

    def artifacts_with_attempt(call):
        if call == 1:
            return []
        return [
            artifact_record(
                name,
                holder["archive"],
                artifact_id=55,
                workflow_run={"id": 900001, "repository_id": 8123, "run_attempt": 2},
            )
        ]

    adapter, uploader = _no_effect_setup(policy, receipt, artifacts=artifacts_with_attempt, archive_holder=holder)
    result = adapter.persist_no_effect(receipt, LIMITS)
    assert result.reason_code == "no_effect_attempt_binding_mismatch"
    assert len(uploader.calls) == 1


def test_persist_no_effect_refuses_unproven_attempt_for_rerun_policy():
    policy = _no_effect_policy(publisher_run_attempt=2)
    receipt = no_effect_receipt(publisher_run=_run_identity(attempt=2))
    holder = {}
    name = policy.no_effect_artifact_name(900001, 2)

    def artifacts_with_binding(call):
        if call == 1:
            return []
        return [
            artifact_record(name, holder["archive"], artifact_id=55, workflow_run={"id": 900001, "repository_id": 8123})
        ]

    adapter, uploader = _no_effect_setup(
        policy, receipt, artifacts=artifacts_with_binding, archive_holder=holder, latest=2
    )
    result = adapter.persist_no_effect(receipt, LIMITS)
    assert result.reason_code == "no_effect_attempt_not_proven"
    assert len(uploader.calls) == 1


def test_persist_no_effect_refuses_latest_attempt_change_after_metadata():
    policy = _no_effect_policy()
    receipt = no_effect_receipt()
    holder = {}
    name = policy.no_effect_artifact_name(900001, 1)

    def artifacts_with_binding(call):
        if call == 1:
            return []
        return [
            artifact_record(name, holder["archive"], artifact_id=55, workflow_run={"id": 900001, "repository_id": 8123})
        ]

    adapter, uploader = _no_effect_setup(
        policy,
        receipt,
        artifacts=artifacts_with_binding,
        archive_holder=holder,
        latest=lambda _call: 2,
    )
    result = adapter.persist_no_effect(receipt, LIMITS)
    assert result.reason_code == "no_effect_attempt_not_proven"

    adapter, uploader = _no_effect_setup(
        policy,
        receipt,
        artifacts=artifacts_with_binding,
        archive_holder=holder,
        latest=lambda call: 1 if call == 1 else 2,
    )
    result = adapter.persist_no_effect(receipt, LIMITS)
    assert result.reason_code == "no_effect_attempt_not_proven"
    assert len(uploader.calls) == 1


def test_persist_no_effect_refuses_unverified_content_and_identity_change():
    policy = _no_effect_policy()
    receipt = no_effect_receipt()
    holder = {}
    name = policy.no_effect_artifact_name(900001, 1)

    def artifacts_without_expiry(call):
        if call == 1:
            return []
        return [
            artifact_record(
                name,
                holder["archive"],
                artifact_id=55,
                expires_at=None,
                workflow_run={"id": 900001, "repository_id": 8123},
            )
        ]

    # The readback bytes match, but the API cannot prove the archive is unexpired.
    adapter, _uploader = _no_effect_setup(
        policy,
        receipt,
        artifacts=artifacts_without_expiry,
        archive_holder=holder,
        latest=1,
    )
    result = adapter.persist_no_effect(receipt, LIMITS)
    assert result.reason_code == "no_effect_artifact_content_mismatch"

    def artifacts_with_binding(call):
        if call == 1:
            return []
        return [
            artifact_record(
                name,
                holder["archive"],
                artifact_id=55,
                workflow_run={"id": 900001, "repository_id": 8123},
            )
        ]

    adapter, _uploader = _no_effect_setup(
        policy,
        receipt,
        artifacts=artifacts_with_binding,
        archive_holder=holder,
        latest=1,
        post_sha="9" * 40,
    )
    result = adapter.persist_no_effect(receipt, LIMITS)
    assert result.reason_code == "publisher_identity_changed"


def test_persist_no_effect_maps_unexpected_failure_to_unknown():
    policy = _no_effect_policy()
    adapter = client(
        policy=policy,
        transport=FakeTransport(lambda *_: (_ for _ in ()).throw(RuntimeError("boom"))),
        artifact_uploader=NoEffectUploader(),
    )
    result = adapter.persist_no_effect(no_effect_receipt(), LIMITS)
    assert result.status is ReceiptPersistenceStatus.UNKNOWN
    assert result.reason_code == "no_effect_persistence_unknown"


# ---------------------------------------------------------------------------
# Submit review, fresh head, live identity
# ---------------------------------------------------------------------------


def test_fresh_head_refuses_no_effect_adapter():
    policy = make_policy(
        no_effect_only=True,
        pull_request_number=None,
        upstream_run_id=None,
        upstream_run_attempt=None,
        history_reconciliation=_history(),
        no_effect_policy_hash="a" * 64,
    )
    adapter = client(policy=policy)
    with pytest.raises(GitHubPublicationError, match="no_effect_adapter_read_only"):
        adapter.fresh_head(10)
    assert adapter.transport.calls == []


@pytest.mark.parametrize(
    ("payload", "code"),
    [
        ({"event": "MERGE"}, "review_payload_invalid"),
        ("not-a-dict", "review_payload_invalid"),
        ({"event": "COMMENT", "commit_id": HEAD, "body": "x"}, "review_slot_invalid"),
        (
            {"event": "COMMENT", "commit_id": HEAD, "body": "missing marker"},
            "review_marker_invalid",
        ),
        (
            {
                "event": "COMMENT",
                "commit_id": HEAD,
                "body": "x" * 60_000 + "\n\n<!-- pr-review-harness:" + EFFECT + " -->",
            },
            "review_body_limit_exceeded",
        ),
    ],
)
def test_submit_review_refuses_invalid_payload_without_post(payload, code):
    policy = make_policy(receipt_artifact_prefix="pr-review-attempt!") if code == "review_slot_invalid" else None
    adapter = client(policy=policy)
    with pytest.raises(GitHubPublicationError, match=code):
        adapter.submit_review(payload, EFFECT, 10)
    assert adapter.transport.calls == []


def test_submit_review_refuses_no_effect_adapter():
    policy = make_policy(
        no_effect_only=True,
        pull_request_number=None,
        upstream_run_id=None,
        upstream_run_attempt=None,
        history_reconciliation=_history(),
        no_effect_policy_hash="a" * 64,
    )
    adapter = client(policy=policy)
    with pytest.raises(GitHubPublicationError, match="no_effect_adapter_read_only"):
        adapter.submit_review({"event": "COMMENT"}, EFFECT, 10)
    assert adapter.transport.calls == []


def test_submit_review_posts_once_and_returns_bound_observation():
    body = "A concise review.\n\n<!-- pr-review-harness:" + EFFECT + " -->"
    calls = []

    def responder(method, url, payload):
        calls.append((method, url, payload))
        return response(
            {
                "id": 1234,
                "commit_id": HEAD,
                "state": "COMMENTED",
                "body": body,
                "user": {"login": WRITER},
            }
        )

    adapter = client(transport=FakeTransport(responder))
    observed = adapter.submit_review({"commit_id": HEAD, "event": "COMMENT", "body": body}, EFFECT, 10)
    assert observed.actor_login == WRITER
    assert observed.review_id == 1234
    assert observed.slot == EffectSlot(8123, "owner/repo", 44, HEAD)
    assert len(calls) == 1 and calls[0][0] == "POST"
    assert calls[0][2] == {"commit_id": HEAD, "event": "COMMENT", "body": body}


def test_submit_review_refuses_foreign_post_response_identity():
    body = "Review.\n\n<!-- pr-review-harness:" + EFFECT + " -->"

    def responder(_method, _url, _payload):
        return response(
            {"id": 1234, "commit_id": HEAD, "state": "COMMENTED", "body": body, "user": {"login": "someone-else"}}
        )

    adapter = client(transport=FakeTransport(responder))
    with pytest.raises(GitHubPublicationError, match="review_post_response_identity_mismatch"):
        adapter.submit_review({"commit_id": HEAD, "event": "COMMENT", "body": body}, EFFECT, 10)
    assert len(adapter.transport.calls) == 1


def test_submit_review_refuses_foreign_post_response_content():
    body = "Review.\n\n<!-- pr-review-harness:" + EFFECT + " -->"

    def responder(_method, _url, _payload):
        return response({"id": 1234, "commit_id": HEAD, "state": "APPROVED", "body": body, "user": {"login": WRITER}})

    adapter = client(transport=FakeTransport(responder))
    with pytest.raises(GitHubPublicationError, match="review_post_response_content_mismatch"):
        adapter.submit_review({"commit_id": HEAD, "event": "COMMENT", "body": body}, EFFECT, 10)
    assert len(adapter.transport.calls) == 1


def test_fresh_head_returns_current_pull_head():
    policy = make_policy()
    adapter = client(policy=policy, transport=FakeTransport(lambda *_: response(pull_record(policy))))
    assert adapter.fresh_head(10) == HEAD


def test_read_live_identity_requires_read_scopes_and_returns_verified_identity():
    provider = Provider()
    adapter = client(provider=provider)
    identity = adapter.read_live_identity(10)
    assert identity == provider.credential.identity
    assert provider.calls[0][1] == {"actions": "read", "pull_requests": "read"}
    assert adapter.transport.calls == []


# ---------------------------------------------------------------------------
# Receipt archive parsing
# ---------------------------------------------------------------------------


def test_read_receipt_archive_refuses_unsupported_member_contract():
    with pytest.raises(GitHubPublicationError, match="receipt_archive_member_invalid"):
        _read_receipt_archive(b"x" * 32, expected_filename="other.json")

    for value in (b"short", None, "text"):
        with pytest.raises(GitHubPublicationError, match="receipt_archive_invalid"):
            _read_receipt_archive(value)

    with pytest.raises(GitHubPublicationError, match="receipt_archive_invalid"):
        _read_receipt_archive(b"x" * 64)


def test_read_receipt_archive_refuses_wrong_member_filename():
    with pytest.raises(GitHubPublicationError, match="receipt_archive_member_invalid"):
        _read_receipt_archive(zip_bytes("wrong-receipt.json", b"{}"))


def test_read_receipt_archive_refuses_multiple_members():
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr("attempt-receipt.json", b"{}")
        archive.writestr("extra.json", b"{}")
    with pytest.raises(GitHubPublicationError, match="receipt_archive_members_invalid"):
        _read_receipt_archive(stream.getvalue())


def test_read_receipt_archive_refuses_member_read_failure(monkeypatch):
    class Member:
        filename = "attempt-receipt.json"
        file_size = 10
        compress_size = 2
        external_attr = 0o100644 << 16

        def is_dir(self):
            return False

    class Archive:
        def __init__(self, content):
            self.content = content

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def infolist(self):
            return [Member()]

        def read(self, _member):
            if self.content is None:
                raise OSError("unreadable member")
            return self.content

    monkeypatch.setattr(ap.zipfile, "ZipFile", lambda *_args, **_kwargs: Archive(None))
    with pytest.raises(GitHubPublicationError, match="receipt_archive_read_failed"):
        _read_receipt_archive(b"x" * 64)

    monkeypatch.setattr(ap.zipfile, "ZipFile", lambda *_args, **_kwargs: Archive(b"short"))
    with pytest.raises(GitHubPublicationError, match="receipt_archive_length_invalid"):
        _read_receipt_archive(b"x" * 64)


# ---------------------------------------------------------------------------
# Time and JSON parsing refusals
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("value", ["2026-01-01", None, 5, "2026-13-01T00:00:00Z"])
def test_parse_utc_refuses_invalid_or_impossible_timestamps(value):
    with pytest.raises(GitHubPublicationError, match="credential_expiry"):
        _parse_utc(value, "credential_expiry")


def test_utc_future_refuses_invalid_timestamp_as_not_future():
    assert _utc_future(None) is False
    assert _utc_future("not-a-time") is False
    assert _utc_future("2999-01-01T00:00:00Z") is True


@pytest.mark.parametrize("raw", ["text", None, 5])
def test_api_json_parser_refuses_non_bytes_input(raw):
    with pytest.raises(ValueError):
        _parse_api_json(raw)


def test_api_json_parser_accepts_bounded_documents():
    assert _parse_api_json(b'{"a":1,"b":[true,null],"c":1.5}') == {
        "a": 1,
        "b": [True, None],
        "c": 1.5,
    }


@pytest.mark.parametrize(
    "raw",
    [
        b"x" * (2 * 1024 * 1024 + 1),
        b'{"id":123456789012345678901}',
        b"]",
        b"[" + b"," * 200_001 + b"]",
        b'"unterminated',
        b'{"value":1e400}',
        b'{"value":NaN}',
        b'{"a":1,"a":2}',
        b"[" * 65 + b"0" + b"]" * 65,
        b"\xff\xfe",
        b"{",
    ],
)
def test_api_json_parser_refuses_unbounded_or_ambiguous_json(raw):
    with pytest.raises(ValueError):
        _parse_api_json(raw)
