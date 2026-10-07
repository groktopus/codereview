import json
from datetime import datetime, timedelta, timezone

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from pr_review_harness.actions_publication import (
    ArtifactTrustMode,
    CredentialKind,
    GitHubActionsPublicationAdapter,
    GitHubPublicationError,
    GitHubPublicationPolicy,
    HTTPResponse,
    IdentityState,
    VerifiedPublisherIdentity,
)
from pr_review_harness.github_app_credentials import (
    GitHubAppCredentialPolicy,
    GitHubAppPublisherCredentialProvider,
)

REPOSITORY = "owner/repo"
REPO_ID = 8123
APP_ID = 333
INSTALLATION_ID = 444
APP_SLUG = "review-agent"
BOT_LOGIN = f"{APP_SLUG}[bot]"
INSTALLATION_TOKEN = "ghs-mock-installation-token"
NOW = datetime.now(timezone.utc).replace(microsecond=0)


def utc_string(value):
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def private_key_pem():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")


def make_policy(**overrides):
    values = {
        "app_id": APP_ID,
        "installation_id": INSTALLATION_ID,
        "repository_id": REPO_ID,
        "repository": REPOSITORY,
        "app_slug": APP_SLUG,
        "actor_login": BOT_LOGIN,
    }
    values.update(overrides)
    return GitHubAppCredentialPolicy(**values)


def canary_identity(**overrides):
    values = {
        "state": IdentityState.VERIFIED,
        "actor_login": BOT_LOGIN,
        "credential_kind": CredentialKind.APP_INSTALLATION,
        "evidence_id": "5" * 64,
        "app_id": APP_ID,
        "installation_id": INSTALLATION_ID,
    }
    values.update(overrides)
    return VerifiedPublisherIdentity(**values)


class FakeTransport:
    def __init__(self, *, mutate=None, fail_at=None):
        self.calls = []
        self.mutate = mutate
        self.fail_at = fail_at

    def request(self, method, url, *, token, json_body, timeout_seconds, max_response_bytes):
        self.calls.append((method, url, token, json_body, timeout_seconds, max_response_bytes))
        index = len(self.calls)
        if index == self.fail_at:
            raise RuntimeError("private transport credential-canary")
        payload = self.payload_for(method, url, json_body)
        status = 201 if method == "POST" else 200
        if method == "GET" and url.endswith("/pulls/44") and getattr(self, "reject_adapter_get", False):
            return HTTPResponse(401, {}, b'{"message":"revoked-secret-token"}')
        if self.mutate is not None:
            status, payload = self.mutate(index, method, url, status, payload)
        body = payload if isinstance(payload, bytes) else json.dumps(payload).encode("utf-8")
        return HTTPResponse(status, {}, body)

    def payload_for(self, method, url, json_body):
        if url.endswith("/app"):
            return {"id": APP_ID, "slug": APP_SLUG}
        if url.endswith(f"/app/installations/{INSTALLATION_ID}") or url.endswith("/installation"):
            return {
                "id": INSTALLATION_ID,
                "app_id": APP_ID,
                "account": {"login": "owner", "id": 22},
                "suspended_at": None,
            }
        if url.endswith("/access_tokens"):
            assert method == "POST"
            permissions = json_body["permissions"]
            # The test transport reflects the requested phase permissions.
            return {
                "token": f"{INSTALLATION_TOKEN}-{len(self.calls)}",
                "expires_at": utc_string(NOW + timedelta(minutes=55)),
                "permissions": {**permissions, "metadata": "read"},
            }
        if url.endswith("/installation/repositories?per_page=2"):
            return {"total_count": 1, "repositories": [{"id": REPO_ID, "full_name": REPOSITORY}]}
        if url.endswith("/users/review-agent%5Bbot%5D"):
            return {"id": 55, "login": BOT_LOGIN, "type": "Bot"}
        if url.endswith("/pulls/44"):
            return {
                "number": 44,
                "state": "open",
                "base": {"sha": "b" * 40, "repo": {"id": REPO_ID}},
                "head": {"sha": "a" * 40},
            }
        if url.endswith("/pulls/44/reviews"):
            return {
                "id": 991,
                "commit_id": "a" * 40,
                "state": "COMMENTED",
                "body": json_body["body"],
                "user": {"login": BOT_LOGIN},
            }
        raise AssertionError(f"unexpected request route {method} {url}")


def provider(transport=None, **kwargs):
    kwargs.setdefault("canary_identity", canary_identity())
    return GitHubAppPublisherCredentialProvider(
        make_policy(),
        private_key_pem(),
        transport=transport or FakeTransport(),
        utcnow=lambda: NOW,
        **kwargs,
    )


@pytest.mark.parametrize("level", ["read", "write"])
def test_provider_mints_exact_one_repo_token_and_verifies_server_identity_and_scope(level):
    transport = FakeTransport()
    credential_provider = provider(transport)
    required = {"actions": "read", "pull_requests": level}

    credential = credential_provider.credential_for(REPO_ID, required, 30)

    assert credential.repository_id == REPO_ID
    assert credential.identity.actor_login == BOT_LOGIN
    assert credential.identity.app_id == APP_ID
    assert credential.identity.installation_id == INSTALLATION_ID
    assert credential.identity.evidence_id
    assert dict(credential.permissions) == required
    assert credential.token.startswith(INSTALLATION_TOKEN + "-")
    assert credential.valid_for(REPO_ID, required, now=NOW)
    assert len(transport.calls) == 6
    assert [call[0] for call in transport.calls] == ["GET", "GET", "GET", "POST", "GET", "GET"]
    assert transport.calls[0][1] == "https://api.github.com/app"
    assert transport.calls[1][1].endswith(f"/app/installations/{INSTALLATION_ID}")
    assert transport.calls[2][1].endswith(f"/repos/{REPOSITORY}/installation")
    assert transport.calls[3][1].endswith(f"/app/installations/{INSTALLATION_ID}/access_tokens")
    assert transport.calls[3][3] == {
        "repository_ids": [REPO_ID],
        "permissions": required,
    }
    assert transport.calls[4][1].endswith("/installation/repositories?per_page=2")
    assert transport.calls[4][2] == credential.token
    assert transport.calls[5][1].endswith("/users/review-agent%5Bbot%5D")
    assert transport.calls[5][2] == credential.token
    assert all(call[5] == 256 * 1024 for call in transport.calls)
    assert INSTALLATION_TOKEN not in repr(credential)


def test_app_jwt_is_rs256_with_bounded_claims_and_provider_repr_redacts_key():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")
    transport = FakeTransport()
    credential_provider = GitHubAppPublisherCredentialProvider(
        make_policy(), key, canary_identity=canary_identity(), transport=transport, utcnow=lambda: NOW
    )

    credential_provider.credential_for(REPO_ID, {"actions": "read", "pull_requests": "read"}, 30)

    app_jwt = transport.calls[0][2]
    claims = jwt.decode(app_jwt, private_key.public_key(), algorithms=["RS256"], options={"verify_exp": False})
    assert jwt.get_unverified_header(app_jwt)["alg"] == "RS256"
    assert claims == {"iat": int(NOW.timestamp()) - 60, "exp": int(NOW.timestamp()) + 540, "iss": str(APP_ID)}
    assert key not in repr(credential_provider)
    assert INSTALLATION_TOKEN not in repr(credential_provider)


def test_missing_private_key_is_unavailable_before_any_api_or_token_request():
    transport = FakeTransport()
    credential_provider = GitHubAppPublisherCredentialProvider(
        make_policy(), None, canary_identity=canary_identity(), transport=transport
    )

    with pytest.raises(GitHubPublicationError, match="publisher_identity_unavailable"):
        credential_provider.credential_for(REPO_ID, {"actions": "read", "pull_requests": "read"}, 30)

    assert transport.calls == []


def test_missing_policy_is_unavailable_before_any_api_or_token_request():
    transport = FakeTransport()
    credential_provider = GitHubAppPublisherCredentialProvider(
        None, private_key_pem(), canary_identity=canary_identity(), transport=transport
    )

    with pytest.raises(GitHubPublicationError, match="publisher_identity_unavailable"):
        credential_provider.credential_for(REPO_ID, {"actions": "read", "pull_requests": "read"}, 30)

    assert transport.calls == []


def test_missing_canary_identity_is_unavailable_before_any_api_or_token_request():
    transport = FakeTransport()
    credential_provider = GitHubAppPublisherCredentialProvider(
        make_policy(), private_key_pem(), transport=transport
    )

    with pytest.raises(GitHubPublicationError, match="publisher_identity_unavailable"):
        credential_provider.credential_for(REPO_ID, {"actions": "read", "pull_requests": "read"}, 30)

    assert transport.calls == []


@pytest.mark.parametrize("mismatch", ["state", "actor", "app", "installation", "kind"])
def test_canary_identity_mismatch_fails_before_api_or_token_request(mismatch):
    identity = {
        "state": canary_identity().state,
        "actor_login": BOT_LOGIN,
        "credential_kind": CredentialKind.APP_INSTALLATION,
        "evidence_id": "5" * 64,
        "app_id": APP_ID,
        "installation_id": INSTALLATION_ID,
    }
    expected_error = "github_app_canary_identity_mismatch"
    if mismatch == "state":
        identity["state"] = IdentityState.UNAVAILABLE
    elif mismatch == "actor":
        identity["actor_login"] = "other-bot[bot]"
    elif mismatch == "app":
        identity["app_id"] = APP_ID + 1
    elif mismatch == "installation":
        identity["installation_id"] = INSTALLATION_ID + 1
    else:
        identity["credential_kind"] = CredentialKind.ACTIONS_TOKEN
        identity["app_id"] = None
        identity["installation_id"] = None
        with pytest.raises(GitHubPublicationError, match="actions_identity_state_invalid"):
            canary_identity(**identity)
        return
    transport = FakeTransport()
    credential_provider = GitHubAppPublisherCredentialProvider(
        make_policy(), private_key_pem(), canary_identity=canary_identity(**identity), transport=transport
    )

    with pytest.raises(GitHubPublicationError, match=expected_error):
        credential_provider.credential_for(REPO_ID, {"actions": "read", "pull_requests": "write"}, 30)

    assert transport.calls == []


def test_oversized_private_key_is_rejected_before_signing_or_api_calls():
    transport = FakeTransport()
    credential_provider = GitHubAppPublisherCredentialProvider(
        make_policy(), "x" * (16 * 1024 + 1), canary_identity=canary_identity(), transport=transport
    )

    with pytest.raises(GitHubPublicationError, match="publisher_identity_unavailable"):
        credential_provider.credential_for(REPO_ID, {"actions": "read", "pull_requests": "read"}, 30)

    assert transport.calls == []


def test_expired_deadline_fails_before_any_http_request():
    ticks = iter([10.0, 40.0])
    transport = FakeTransport()
    credential_provider = GitHubAppPublisherCredentialProvider(
        make_policy(), private_key_pem(), canary_identity=canary_identity(), transport=transport,
        clock=lambda: next(ticks), utcnow=lambda: NOW
    )

    with pytest.raises(GitHubPublicationError, match="github_app_deadline_exhausted"):
        credential_provider.credential_for(REPO_ID, {"actions": "read", "pull_requests": "read"}, 30)

    assert transport.calls == []


@pytest.mark.parametrize(
    ("repository_id", "permissions"),
    [
        (REPO_ID + 1, {"actions": "read", "pull_requests": "read"}),
        (float(REPO_ID), {"actions": "read", "pull_requests": "read"}),
        (str(REPO_ID), {"actions": "read", "pull_requests": "read"}),
        (True, {"actions": "read", "pull_requests": "read"}),
        (REPO_ID, {"actions": "write", "pull_requests": "read"}),
        (REPO_ID, {"actions": "read", "pull_requests": "admin"}),
        (REPO_ID, {"actions": "read", "pull_requests": "read", "contents": "read"}),
    ],
)
def test_wrong_target_or_permission_request_fails_before_api_calls(repository_id, permissions):
    transport = FakeTransport()

    with pytest.raises(GitHubPublicationError):
        provider(transport).credential_for(repository_id, permissions, 30)

    assert transport.calls == []


def test_invalid_policy_object_is_unavailable_without_attribute_error_or_http_calls():
    transport = FakeTransport()
    credential_provider = GitHubAppPublisherCredentialProvider(
        {"app_id": APP_ID}, private_key_pem(), transport=transport  # type: ignore[arg-type]
    )

    with pytest.raises(GitHubPublicationError, match="publisher_identity_unavailable"):
        credential_provider.credential_for(REPO_ID, {"actions": "read", "pull_requests": "read"}, 30)

    assert transport.calls == []


@pytest.mark.parametrize(
    ("mutate", "expected_error"),
    [
        (
            lambda i, method, url, status, body: (status, {**body, "id": APP_ID + 1}) if i == 1 else (status, body),
            "github_app_identity_mismatch",
        ),
        (
            lambda i, method, url, status, body: (status, {**body, "suspended_at": NOW.isoformat()})
            if i == 2
            else (status, body),
            "github_app_installation_identity_mismatch",
        ),
        (
            lambda i, method, url, status, body: (status, {**body, "id": INSTALLATION_ID + 1})
            if i == 3
            else (status, body),
            "github_app_installation_identity_mismatch",
        ),
        (
            lambda i, method, url, status, body: (status, {**body, "permissions": {**body["permissions"], "contents": "read"}})
            if i == 4
            else (status, body),
            "github_app_token_scope_mismatch",
        ),
        (
            lambda i, method, url, status, body: (
                status,
                {**body, "total_count": 2, "repositories": [*body["repositories"], {"id": 9000, "full_name": "owner/other"}]},
            )
            if i == 5
            else (status, body),
            "github_app_token_scope_mismatch",
        ),
        (
            lambda i, method, url, status, body: (status, {**body, "login": "someone-else[bot]"})
            if i == 6
            else (status, body),
            "github_app_bot_identity_mismatch",
        ),
    ],
)
def test_api_identity_and_scope_mismatches_fail_closed_without_secret_echo(mutate, expected_error):
    transport = FakeTransport(mutate=mutate)

    with pytest.raises(GitHubPublicationError, match=expected_error) as caught:
        provider(transport).credential_for(REPO_ID, {"actions": "read", "pull_requests": "read"}, 30)

    assert INSTALLATION_TOKEN not in str(caught.value)
    assert len(transport.calls) <= 6


def test_token_response_expiry_must_be_future_and_within_one_hour_plus_skew():
    def expired(_i, _method, url, status, body):
        if url.endswith("/access_tokens"):
            return status, {**body, "expires_at": utc_string(NOW - timedelta(seconds=1))}
        return status, body

    transport = FakeTransport(mutate=expired)
    with pytest.raises(GitHubPublicationError, match="github_app_token_expired"):
        provider(transport).credential_for(REPO_ID, {"actions": "read", "pull_requests": "read"}, 30)
    assert len(transport.calls) == 4

    def too_long(_i, _method, url, status, body):
        if url.endswith("/access_tokens"):
            return status, {**body, "expires_at": utc_string(NOW + timedelta(hours=1, minutes=3))}
        return status, body

    transport = FakeTransport(mutate=too_long)
    with pytest.raises(GitHubPublicationError, match="github_app_token_expiry_invalid"):
        provider(transport).credential_for(REPO_ID, {"actions": "read", "pull_requests": "read"}, 30)
    assert len(transport.calls) == 4


def test_redirect_invalid_json_and_transport_exception_are_generic_and_single_attempt():
    for status, body, fail_at, expected in (
        (302, {"location": "https://attacker.invalid"}, None, "github_app_response_unavailable"),
        (200, b'{"id":333,"id":999}', None, "github_app_response_invalid"),
        (200, {}, 1, "github_app_transport_unavailable"),
    ):
        def mutate(index, _method, _url, default_status, default_body):
            return (status, body) if index == 1 else (default_status, default_body)

        transport = FakeTransport(mutate=mutate if fail_at is None else None, fail_at=fail_at)
        with pytest.raises(GitHubPublicationError, match=expected) as caught:
            provider(transport).credential_for(REPO_ID, {"actions": "read", "pull_requests": "read"}, 30)
        assert "private transport credential-canary" not in str(caught.value)
        assert len(transport.calls) == 1


def test_token_mint_transport_failure_is_not_retried():
    transport = FakeTransport(fail_at=4)

    with pytest.raises(GitHubPublicationError, match="github_app_transport_unavailable") as caught:
        provider(transport).credential_for(REPO_ID, {"actions": "read", "pull_requests": "read"}, 30)

    assert "private transport credential-canary" not in str(caught.value)
    assert len(transport.calls) == 4
    assert sum(call[0] == "POST" for call in transport.calls) == 1


def make_adapter_policy():
    return GitHubPublicationPolicy(
        repository_id=REPO_ID,
        repository=REPOSITORY,
        pull_request_number=44,
        upstream_run_id=731245,
        upstream_run_attempt=1,
        publisher_run_id=900001,
        publisher_run_attempt=1,
        caller_workflow_id=563,
        caller_workflow_path=".github/workflows/pr-analysis.yml",
        caller_workflow_ref="refs/heads/main",
        caller_workflow_sha="d" * 40,
        called_harness_repository="harness/repo",
        called_harness_path=".github/workflows/review.yml",
        called_harness_sha="e" * 40,
        publisher_workflow_id=904,
        publisher_workflow_path=".github/workflows/pr-publish.yml",
        publisher_workflow_ref="refs/heads/main",
        publisher_workflow_sha="f" * 40,
        profile_version="profile-v3",
        profile_sha256="1" * 64,
        provider_configuration_identity="provider-identity-sha256:" + "2" * 64,
        allowed_actor_login=BOT_LOGIN,
        artifact_trust_mode=ArtifactTrustMode.API_BOUND_SHA256,
    )


def test_real_adapter_read_then_write_uses_stable_identity_and_two_exact_scope_tokens():
    transport = FakeTransport()
    credential_provider = GitHubAppPublisherCredentialProvider(
        make_policy(), private_key_pem(), canary_identity=canary_identity(), transport=transport, utcnow=lambda: NOW
    )
    client = GitHubActionsPublicationAdapter(make_adapter_policy(), credential_provider, transport=transport)

    assert client.fresh_head(30) == "a" * 40
    body = "Ordinary review comment.\n\n<!-- pr-review-harness:effect-" + "c" * 64 + " -->"
    result = client.submit_review(
        {"commit_id": "a" * 40, "event": "COMMENT", "body": body}, "effect-" + "c" * 64, 30
    )

    assert result.actor_login == BOT_LOGIN
    assert [call[3] for call in transport.calls if call[0] == "POST" and call[1].endswith("/access_tokens")] == [
        {"repository_ids": [REPO_ID], "permissions": {"actions": "read", "pull_requests": "read"}},
        {"repository_ids": [REPO_ID], "permissions": {"actions": "read", "pull_requests": "write"}},
    ]
    assert sum(call[0] == "POST" and call[1].endswith("/access_tokens") for call in transport.calls) == 2
    pull_get = next(call for call in transport.calls if call[0] == "GET" and call[1].endswith("/pulls/44"))
    review_post = next(call for call in transport.calls if call[0] == "POST" and call[1].endswith("/pulls/44/reviews"))
    assert pull_get[2].endswith("-4")
    assert review_post[2].endswith("-11")
    read_credential = credential_provider.credential_for(
        REPO_ID, {"actions": "read", "pull_requests": "read"}, 30
    )
    write_credential = credential_provider.credential_for(
        REPO_ID, {"actions": "read", "pull_requests": "write"}, 30
    )
    assert read_credential.identity == write_credential.identity == client._identity
    assert dict(read_credential.permissions) == {"actions": "read", "pull_requests": "read"}
    assert dict(write_credential.permissions) == {"actions": "read", "pull_requests": "write"}
    before_cache_hits = len(transport.calls)
    assert credential_provider.credential_for(
        REPO_ID, {"actions": "read", "pull_requests": "read"}, 30
    ) is read_credential
    assert len(transport.calls) == before_cache_hits


def test_verified_identity_evidence_binds_protected_canary_and_server_bot_user():
    first_transport = FakeTransport()
    first = provider(first_transport).credential_for(REPO_ID, {"actions": "read", "pull_requests": "read"}, 30)

    second_transport = FakeTransport()
    second = provider(
        second_transport, canary_identity=canary_identity(evidence_id="6" * 64)
    ).credential_for(REPO_ID, {"actions": "read", "pull_requests": "read"}, 30)

    changed_bot_transport = FakeTransport(
        mutate=lambda index, method, url, status, body: (status, {**body, "id": 56})
        if url.endswith("/users/review-agent%5Bbot%5D")
        else (status, body)
    )
    changed_bot = provider(changed_bot_transport).credential_for(
        REPO_ID, {"actions": "read", "pull_requests": "read"}, 30
    )

    assert first.identity.evidence_id != second.identity.evidence_id
    assert first.identity.evidence_id != changed_bot.identity.evidence_id


def test_writer_cache_entry_is_never_reused_for_read_scope():
    transport = FakeTransport()
    credential_provider = provider(transport)

    writer = credential_provider.credential_for(
        REPO_ID, {"actions": "read", "pull_requests": "write"}, 30
    )
    reader = credential_provider.credential_for(
        REPO_ID, {"actions": "read", "pull_requests": "read"}, 30
    )

    assert dict(writer.permissions) == {"actions": "read", "pull_requests": "write"}
    assert dict(reader.permissions) == {"actions": "read", "pull_requests": "read"}
    assert writer.token != reader.token
    assert writer.identity == reader.identity
    assert sum(call[0] == "POST" and call[1].endswith("/access_tokens") for call in transport.calls) == 2


def test_cache_never_returns_credential_expiring_inside_requested_deadline():
    now = [NOW]

    def make_expiry_later(index, method, url, status, body):
        if method == "POST" and url.endswith("/access_tokens") and index == 10:
            return status, {**body, "expires_at": utc_string(now[0] + timedelta(minutes=59))}
        return status, body

    transport = FakeTransport(mutate=make_expiry_later)
    credential_provider = GitHubAppPublisherCredentialProvider(
        make_policy(), private_key_pem(), canary_identity=canary_identity(), transport=transport, utcnow=lambda: now[0]
    )
    first = credential_provider.credential_for(REPO_ID, {"actions": "read", "pull_requests": "read"}, 30)
    now[0] = NOW + timedelta(minutes=54, seconds=45)
    refreshed = credential_provider.credential_for(REPO_ID, {"actions": "read", "pull_requests": "read"}, 30)

    assert refreshed is not first
    assert refreshed.token != first.token
    assert sum(call[0] == "POST" and call[1].endswith("/access_tokens") for call in transport.calls) == 2


def test_adapter_does_not_retry_or_remint_after_cached_token_is_revoked():
    transport = FakeTransport()
    credential_provider = GitHubAppPublisherCredentialProvider(
        make_policy(), private_key_pem(), canary_identity=canary_identity(), transport=transport, utcnow=lambda: NOW
    )
    client = GitHubActionsPublicationAdapter(make_adapter_policy(), credential_provider, transport=transport)
    cached = credential_provider.credential_for(REPO_ID, {"actions": "read", "pull_requests": "read"}, 30)
    transport.reject_adapter_get = True

    with pytest.raises(GitHubPublicationError, match="github_api_request_failed"):
        client.fresh_head(30)

    assert len(transport.calls) == 7
    assert transport.calls[-1][2] == cached.token
    assert sum(call[0] == "POST" and call[1].endswith("/access_tokens") for call in transport.calls) == 1
    assert not any(call[0] == "POST" and call[1].endswith("/pulls/44/reviews") for call in transport.calls)
