from datetime import datetime, timezone

import pytest

from pr_review_harness.actions_publication import (
    CredentialKind,
    GitHubPublicationError,
    IdentityState,
    PermissionBasis,
    VerifiedPublisherIdentity,
    WriteCapability,
)
from pr_review_harness.github_actions_credentials import (
    GitHubActionsTokenCredentialProvider,
    GitHubActionsTokenPolicy,
)

NOW = datetime(2026, 10, 2, 12, 0, tzinfo=timezone.utc)
REPO_ID = 8123
ACTOR = "github-actions[bot]"
PERMISSIONS = (("actions", "read"), ("pull_requests", "write"))


def make_policy(**overrides):
    values = {
        "repository_id": REPO_ID,
        "repository": "owner/repo",
        "actor_login": ACTOR,
        "permissions": PERMISSIONS,
    }
    values.update(overrides)
    return GitHubActionsTokenPolicy(**values)


def make_identity(**overrides):
    values = {
        "state": IdentityState.PLATFORM_BOUND,
        "actor_login": ACTOR,
        "credential_kind": CredentialKind.ACTIONS_TOKEN,
        "evidence_id": "a" * 64,
    }
    values.update(overrides)
    return VerifiedPublisherIdentity(**values)


def make_provider(**overrides):
    values = {
        "policy": make_policy(),
        "token": "test-actions-token-sentinel",
        "identity": make_identity(),
        "utcnow": lambda: NOW,
    }
    values.update(overrides)
    return GitHubActionsTokenCredentialProvider(**values)


def test_actions_token_credential_is_repo_bound_and_permissions_are_only_declared():
    provider = make_provider()

    credential = provider.credential_for(
        REPO_ID,
        {"actions": "read", "pull_requests": "write"},
        25,
    )

    assert credential.identity.state is IdentityState.PLATFORM_BOUND
    assert credential.identity.credential_kind is CredentialKind.ACTIONS_TOKEN
    assert credential.repository_id == REPO_ID
    assert dict(credential.permissions) == dict(PERMISSIONS)
    assert credential.permission_basis is PermissionBasis.WORKFLOW_DECLARATION
    assert credential.write_capability is WriteCapability.NOT_TESTED
    assert credential.expires_at == "2026-10-02T12:00:25Z"
    assert "test-actions-token-sentinel" not in repr(provider)
    assert "test-actions-token-sentinel" not in repr(credential)


@pytest.mark.parametrize(
    ("repository_id", "permissions", "timeout"),
    [
        (REPO_ID + 1, {"actions": "read", "pull_requests": "write"}, 25),
        (REPO_ID, {"actions": "write", "pull_requests": "write"}, 25),
        (REPO_ID, {"actions": "read", "pull_requests": "admin"}, 25),
        (REPO_ID, {"actions": "read", "pull_requests": "write", "contents": "read"}, 25),
        (REPO_ID, {"actions": "read", "pull_requests": "write"}, 0),
        (REPO_ID, {"actions": "read", "pull_requests": "write"}, 301),
        (REPO_ID, {"actions": "read", "pull_requests": "write"}, True),
    ],
)
def test_actions_token_rejects_wrong_scope_or_request(repository_id, permissions, timeout):
    provider = make_provider()
    with pytest.raises(GitHubPublicationError):
        provider.credential_for(repository_id, permissions, timeout)


def test_actions_token_requires_platform_bound_identity_and_target_actor():
    with pytest.raises(GitHubPublicationError, match="actions_identity_state_invalid"):
        make_identity(state=IdentityState.VERIFIED)
    with pytest.raises(GitHubPublicationError, match="actions_token_identity_unavailable"):
        make_provider(identity=make_identity(actor_login="untrusted[bot]"))


@pytest.mark.parametrize("token", ["", "x" * 16_385, "contains whitespace"])
def test_invalid_token_is_rejected_without_rendering_secret(token):
    with pytest.raises(GitHubPublicationError, match="actions_token_unavailable"):
        make_provider(token=token)


def test_actions_policy_cannot_grant_permissions_beyond_review_publication():
    with pytest.raises(GitHubPublicationError, match="actions_token_policy_invalid"):
        make_policy(permissions=(("actions", "read"), ("contents", "write")))

