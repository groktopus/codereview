import json
from datetime import datetime, timedelta, timezone

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from pr_review_harness.actions_publication import (
    CredentialKind,
    GitHubPublicationError,
    HTTPResponse,
    IdentityState,
)
from pr_review_harness.github_app_canary import (
    CanaryLimits,
    ProtectedCanaryRun,
    verify_github_app_identity_canary,
)
from pr_review_harness.github_app_credentials import GitHubAppCredentialPolicy

OWNER_REPO = "owner/repo"
REPO_ID = 8123
APP_ID = 333
INSTALLATION_ID = 444
APP_SLUG = "review-agent"
BOT_LOGIN = f"{APP_SLUG}[bot]"
GITHUB_ACTIONS_TOKEN = "ghs-actions-read-token"
INSTALLATION_TOKEN = "ghs-installation-read-token"
NOW = datetime(2026, 9, 30, 12, 0, tzinfo=timezone.utc)


def utc_string(value):
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def private_key_pem():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")


def make_policy():
    return GitHubAppCredentialPolicy(
        app_id=APP_ID,
        installation_id=INSTALLATION_ID,
        repository_id=REPO_ID,
        repository=OWNER_REPO,
        app_slug=APP_SLUG,
        actor_login=BOT_LOGIN,
    )


def make_platform(**overrides):
    values = {
        "repository_id": REPO_ID,
        "repository": OWNER_REPO,
        "default_branch": "main",
        "publisher_run_id": 701,
        "publisher_run_attempt": 2,
        "publisher_workflow_id": 801,
        "publisher_workflow_path": ".github/workflows/pr-publish.yml",
        "publisher_workflow_ref": "owner/repo/.github/workflows/pr-publish.yml@refs/heads/main",
        "publisher_workflow_sha": "c" * 40,
        "source_head_branch": "feature/update-dependency",
        "source_run_id": 601,
        "source_run_attempt": 1,
        "source_workflow_id": 802,
        "source_workflow_path": ".github/workflows/review.yml",
        "source_workflow_ref": "owner/repo/.github/workflows/review.yml@refs/heads/main",
        "source_event": "pull_request_target",
        "source_workflow_sha": "b" * 40,
        "source_run_head_sha": "f" * 40,
        "pull_request_head_sha": "a" * 40,
        "pull_request_number": 44,
        "base_sha": "b" * 40,
    }
    values.update(overrides)
    return ProtectedCanaryRun(**values)


class FakeTransport:
    def __init__(self, *, mutate=None, fail_at=None):
        self.calls = []
        self.mutate = mutate
        self.fail_at = fail_at

    def request(self, method, url, *, token, json_body, timeout_seconds, max_response_bytes):
        self.calls.append((method, url, token, json_body, timeout_seconds, max_response_bytes))
        index = len(self.calls)
        if index == self.fail_at:
            raise RuntimeError("transport rejected private-token-redaction-probe")
        payload, status = self.payload(method, url, json_body)
        if self.mutate is not None:
            status, payload = self.mutate(index, method, url, status, payload)
        body = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        return HTTPResponse(status, {}, body)

    def payload(self, method, url, body):
        platform = make_platform()
        if url.endswith(f"/actions/runs/{platform.publisher_run_id}"):
            return {
                "id": platform.publisher_run_id,
                "run_attempt": platform.publisher_run_attempt,
                "workflow_id": platform.publisher_workflow_id,
                "path": platform.publisher_workflow_path,
                "head_branch": "main",
                "head_sha": platform.publisher_workflow_sha,
                "status": "in_progress",
                "conclusion": None,
                "event": "workflow_run",
                "repository": {"id": REPO_ID, "full_name": OWNER_REPO},
                "actor": {"login": "release-operator"},
            }, 200
        if url.endswith(f"/actions/runs/{platform.source_run_id}"):
            source_record = {
                "id": platform.source_run_id,
                "run_attempt": platform.source_run_attempt,
                "workflow_id": platform.source_workflow_id,
                "path": platform.source_workflow_path,
                "head_branch": platform.source_head_branch,
                "head_sha": platform.source_run_head_sha,
                "status": "completed",
                "conclusion": "success",
                "event": platform.source_event,
                "repository": {"id": REPO_ID, "full_name": OWNER_REPO},
                "actor": {"login": "review-caller"},
            }
            if getattr(self, "include_source_pr", False):
                source_record["pull_requests"] = [
                    {
                        "number": 44,
                        "base": {"sha": "b" * 40},
                        "head": {"sha": "a" * 40},
                    }
                ]
            return source_record, 200
        if url.endswith("/pulls/44"):
            return {
                "number": 44,
                "state": "open",
                "base": {"sha": "b" * 40, "ref": "main", "repo": {"id": REPO_ID}},
                "head": {"sha": "a" * 40, "ref": "feature/update-dependency"},
            }, 200
        if url.endswith("/app"):
            return {"id": APP_ID, "slug": APP_SLUG}, 200
        if url.endswith(f"/app/installations/{INSTALLATION_ID}") or url.endswith("/installation"):
            return {
                "id": INSTALLATION_ID,
                "app_id": APP_ID,
                "account": {"login": "owner", "id": 22},
                "suspended_at": None,
            }, 200
        if url.endswith("/access_tokens"):
            assert method == "POST"
            assert body == {
                "repository_ids": [REPO_ID],
                "permissions": {"actions": "read", "pull_requests": "read"},
            }
            return {
                "token": INSTALLATION_TOKEN,
                "expires_at": utc_string(NOW + timedelta(minutes=50)),
                "permissions": {"actions": "read", "pull_requests": "read", "metadata": "read"},
            }, 201
        if url.endswith("/installation/repositories?per_page=2"):
            return {"total_count": 1, "repositories": [{"id": REPO_ID, "full_name": OWNER_REPO}]}, 200
        if url.endswith("/users/review-agent%5Bbot%5D"):
            return {"id": 55, "login": BOT_LOGIN, "type": "Bot"}, 200
        raise AssertionError(f"unexpected route: {method} {url}")


def invoke(*, transport=None, key_supplier=None, platform=None, limits=None, clock=None):
    return verify_github_app_identity_canary(
        enabled=True,
        platform=platform or make_platform(),
        policy=make_policy(),
        actions_token=GITHUB_ACTIONS_TOKEN,
        app_private_key_supplier=key_supplier or private_key_pem,
        transport=transport or FakeTransport(),
        limits=limits,
        clock=clock or (lambda: 100.0),
        utcnow=lambda: NOW,
    )


def test_canary_verifies_platform_then_mints_read_only_single_repo_token_and_receipt():
    transport = FakeTransport()
    identity, receipt = invoke(transport=transport)

    assert identity.state is IdentityState.VERIFIED
    assert identity.credential_kind is CredentialKind.APP_INSTALLATION
    assert identity.actor_login == BOT_LOGIN
    assert identity.app_id == APP_ID
    assert identity.installation_id == INSTALLATION_ID
    assert receipt.evidence_id == identity.evidence_id
    assert len(receipt.nonce) == 32
    assert dict(receipt.read_permissions) == {"actions": "read", "pull_requests": "read"}
    assert len(transport.calls) == 9
    assert [call[0] for call in transport.calls] == ["GET", "GET", "GET", "GET", "GET", "GET", "POST", "GET", "GET"]
    assert [call[1].rsplit("/", 1)[-1] for call in transport.calls[:3]] == ["701", "601", "44"]
    assert all(call[2] == GITHUB_ACTIONS_TOKEN for call in transport.calls[:3])
    assert transport.calls[6][1].endswith(f"/app/installations/{INSTALLATION_ID}/access_tokens")
    assert transport.calls[6][3] == {
        "repository_ids": [REPO_ID],
        "permissions": {"actions": "read", "pull_requests": "read"},
    }
    assert all("/pulls/44/reviews" not in call[1] for call in transport.calls)
    serialized = json.dumps(receipt.to_dict())
    assert GITHUB_ACTIONS_TOKEN not in serialized
    assert INSTALLATION_TOKEN not in serialized
    assert "token" not in receipt.to_dict()
    assert all(call[5] == 256 * 1024 for call in transport.calls)


def test_canary_signs_real_rs256_app_jwt_only_after_platform_validation():
    key = private_key_pem()
    private_key = serialization.load_pem_private_key(key.encode(), password=None)
    transport = FakeTransport()
    invoke(transport=transport, key_supplier=lambda: key)
    app_jwt = transport.calls[3][2]
    claims = jwt.decode(app_jwt, private_key.public_key(), algorithms=["RS256"], options={"verify_exp": False})
    assert jwt.get_unverified_header(app_jwt)["alg"] == "RS256"
    assert claims["iss"] == str(APP_ID)
    assert claims["exp"] - claims["iat"] == 600


def test_target_source_run_without_optional_pr_association_keeps_source_sha_distinct():
    identity, receipt = invoke()

    assert identity.state is IdentityState.VERIFIED
    assert receipt.source_workflow_sha == "b" * 40
    assert receipt.source_run_head_sha == "f" * 40
    assert receipt.pull_request_head_sha == "a" * 40
    assert receipt.source_workflow_sha != receipt.pull_request_head_sha
    assert receipt.source_run_head_sha != receipt.source_workflow_sha


def test_target_source_run_accepts_exact_optional_pr_association():
    transport = FakeTransport()
    transport.include_source_pr = True
    identity, _receipt = invoke(transport=transport)
    assert identity.state is IdentityState.VERIFIED


def test_target_source_run_accepts_empty_optional_pr_association():
    def mutate(index, method, url, status, payload):
        if index == 2:
            payload = {**payload, "pull_requests": []}
        return status, payload

    identity, _receipt = invoke(transport=FakeTransport(mutate=mutate))
    assert identity.state is IdentityState.VERIFIED


@pytest.mark.parametrize(
    "associations",
    [
        [{"number": 45, "base": {"sha": "b" * 40}, "head": {"sha": "a" * 40}}],
        [{"number": 44, "base": {"sha": "b" * 40}, "head": {"sha": "f" * 40}}],
        [
            {"number": 44, "base": {"sha": "b" * 40}, "head": {"sha": "a" * 40}},
            {"number": 44, "base": {"sha": "b" * 40}, "head": {"sha": "a" * 40}},
        ],
    ],
)
def test_target_source_run_rejects_present_nonexact_pr_association(associations):
    def mutate(index, method, url, status, payload):
        if index == 2:
            payload = {**payload, "pull_requests": associations}
        return status, payload

    with pytest.raises(GitHubPublicationError, match="github_app_canary_source_pr_mismatch"):
        invoke(transport=FakeTransport(mutate=mutate))


def test_non_target_source_event_rejects_before_network_or_key_access():
    calls = []
    with pytest.raises(GitHubPublicationError, match="github_app_canary_expectation_mismatch"):
        invoke(
            platform=make_platform(source_event="workflow_dispatch"),
            transport=FakeTransport(),
            key_supplier=lambda: calls.append("key") or private_key_pem(),
        )
    assert calls == []


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("publisher_run_attempt", 3),
        ("publisher_workflow_sha", "d" * 40),
        ("source_run_attempt", 2),
        ("source_workflow_sha", "e" * 40),
        ("source_run_head_sha", "e" * 40),
        ("pull_request_head_sha", "e" * 40),
        ("source_workflow_path", ".github/workflows/untrusted.yml"),
    ],
)
def test_invalid_local_expectations_reject_before_key_or_transport(field, value):
    calls = []

    def supplier():
        calls.append("read")
        return private_key_pem()

    with pytest.raises(GitHubPublicationError):
        invoke(platform=make_platform(**{field: value}), key_supplier=supplier, transport=FakeTransport())
    assert calls == []


@pytest.mark.parametrize("field", ["id", "run_attempt", "workflow_id", "path", "head_sha", "repository"])
def test_invalid_current_actions_run_rejects_before_key_supplier(field):
    key_calls = []

    def mutate(index, method, url, status, payload):
        if index == 1:
            changed = dict(payload)
            changed[field] = {"id": 999, "full_name": "wrong/repo"} if field == "repository" else "wrong"
            return status, changed
        return status, payload

    with pytest.raises(GitHubPublicationError, match="github_app_canary_actions_run_mismatch"):
        invoke(
            transport=FakeTransport(mutate=mutate),
            key_supplier=lambda: key_calls.append("read") or private_key_pem(),
        )
    assert key_calls == []


def test_wrong_pr_head_rejects_before_app_key_access():
    key_calls = []

    def mutate(index, method, url, status, payload):
        if index == 3:
            payload = {**payload, "head": {"sha": "f" * 40}}
        return status, payload

    with pytest.raises(GitHubPublicationError, match="github_app_canary_pull_request_mismatch"):
        invoke(
            transport=FakeTransport(mutate=mutate),
            key_supplier=lambda: key_calls.append("read") or private_key_pem(),
        )
    assert key_calls == []


@pytest.mark.parametrize(
    ("base_field", "value"),
    [("ref", "other"), ("sha", "9" * 40)],
)
def test_wrong_default_base_pr_identity_rejects_before_app_key_access(base_field, value):
    key_calls = []

    def mutate(index, method, url, status, payload):
        if index == 3:
            base = dict(payload["base"])
            base[base_field] = value
            payload = {**payload, "base": base}
        return status, payload

    with pytest.raises(GitHubPublicationError, match="github_app_canary_pull_request_mismatch"):
        invoke(
            transport=FakeTransport(mutate=mutate),
            key_supplier=lambda: key_calls.append("read") or private_key_pem(),
        )
    assert key_calls == []


def test_source_run_with_incomplete_pr_binding_rejects_before_app_key_access():
    key_calls = []

    def mutate(index, method, url, status, payload):
        if index == 2:
            payload = {**payload, "pull_requests": [{"number": 44}]}
        return status, payload

    with pytest.raises(GitHubPublicationError, match="github_app_canary_source_pr_mismatch"):
        invoke(
            transport=FakeTransport(mutate=mutate),
            key_supplier=lambda: key_calls.append("read") or private_key_pem(),
        )
    assert key_calls == []


def test_app_identity_mismatch_and_bot_mismatch_fail_closed_without_review_post():
    def mutate_app(index, method, url, status, payload):
        if url.endswith("/app"):
            payload = {**payload, "id": APP_ID + 1}
        return status, payload

    with pytest.raises(GitHubPublicationError, match="github_app_identity_mismatch"):
        invoke(transport=FakeTransport(mutate=mutate_app))

    def mutate_bot(index, method, url, status, payload):
        if url.endswith("/users/review-agent%5Bbot%5D"):
            payload = {**payload, "type": "User"}
        return status, payload

    transport = FakeTransport(mutate=mutate_bot)
    with pytest.raises(GitHubPublicationError, match="github_app_bot_identity_mismatch"):
        invoke(transport=transport)
    assert all("/pulls/44/reviews" not in call[1] for call in transport.calls)


def test_canary_limits_cannot_expand_call_deadline_or_response_caps():
    for kwargs in (
        {"max_calls": 10},
        {"deadline_seconds": 31},
        {"max_response_bytes": 256 * 1024 + 1},
    ):
        with pytest.raises(GitHubPublicationError, match="github_app_canary_limits_invalid"):
            CanaryLimits(**kwargs)


def test_api_failure_redacts_secret_and_stops_without_retry():
    transport = FakeTransport(fail_at=5)
    with pytest.raises(GitHubPublicationError) as exc:
        invoke(transport=transport)
    assert str(exc.value) == "github_app_canary_transport_unavailable"
    assert "private-token-redaction-probe" not in str(exc.value)
    assert len(transport.calls) == 5


def test_oversized_app_key_is_rejected_before_app_api_or_jwt_signing():
    transport = FakeTransport()
    key_calls = []

    def oversized_key():
        key_calls.append("read")
        return "x" * (16 * 1024 + 1)

    with pytest.raises(GitHubPublicationError, match="publisher_identity_unavailable"):
        invoke(transport=transport, key_supplier=oversized_key)
    assert key_calls == ["read"]
    assert len(transport.calls) == 3
    assert all(call[0] == "GET" for call in transport.calls)


def test_late_final_api_response_cannot_issue_verified_identity():
    now = [100.0]

    class LateTransport(FakeTransport):
        def request(self, *args, **kwargs):
            response = super().request(*args, **kwargs)
            if len(self.calls) == 9:
                now[0] = 131.0
            return response

    with pytest.raises(GitHubPublicationError, match="github_app_canary_deadline_exhausted"):
        invoke(transport=LateTransport(), clock=lambda: now[0])


def test_disabled_canary_does_not_read_key_or_make_any_api_call():
    key_calls = []
    transport = FakeTransport()
    with pytest.raises(GitHubPublicationError, match="github_app_canary_disabled"):
        verify_github_app_identity_canary(
            platform=make_platform(),
            policy=make_policy(),
            actions_token=GITHUB_ACTIONS_TOKEN,
            app_private_key_supplier=lambda: key_calls.append("read") or private_key_pem(),
            transport=transport,
        )
    assert key_calls == []
    assert transport.calls == []
