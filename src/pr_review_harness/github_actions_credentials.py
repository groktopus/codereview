"""Use only the trusted current Actions job's repository-scoped token.

This provider does not mint a token or independently query its effective
permissions. Its identity is platform-bound to validated protected workflow
and GitHub API run facts. Workflow-declared permission scope remains distinct
from observed write capability; only exact effect reconciliation observes a
successful write.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable, Mapping

from .actions_publication import (
    CredentialKind,
    GitHubPublicationError,
    IdentityState,
    PermissionBasis,
    PublisherCredential,
    VerifiedPublisherIdentity,
    WriteCapability,
    _positive_int,
)

_REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
_LOGIN = re.compile(r"[A-Za-z0-9-]{1,39}(?:\[bot\])?\Z")
_MAX_TOKEN_BYTES = 16_384
_MAX_LIFETIME_SECONDS = 300.0


@dataclass(frozen=True)
class GitHubActionsTokenPolicy:
    """Protected target identity and adapter operation requirements."""

    repository_id: int
    repository: str
    actor_login: str
    permissions: tuple[tuple[str, str], ...]

    def __post_init__(self) -> None:
        if (
            not _positive_int(self.repository_id)
            or not isinstance(self.repository, str)
            or not _REPOSITORY.fullmatch(self.repository)
            or self.actor_login != "github-actions[bot]"
            or not isinstance(self.permissions, tuple)
            or dict(self.permissions) != {"actions": "read", "pull_requests": "write"}
            or len(self.permissions) != 2
        ):
            raise GitHubPublicationError("actions_token_policy_invalid")


class GitHubActionsTokenCredentialProvider:
    """Expose a fixed Actions token as a bounded, target-scoped credential.

    ``token`` must be supplied by the protected runtime from the fixed
    ``${{ github.token }}`` binding. The provider never reads ambient env,
    performs no HTTP request, and stores no token in repr or evidence.
    ``identity`` is PLATFORM_BOUND, not an independently authenticated actor
    claim. The expected actor is checked against the actual review response and
    later history reconciliation.
    """

    def __init__(
        self,
        policy: GitHubActionsTokenPolicy,
        token: str,
        *,
        identity: VerifiedPublisherIdentity,
        utcnow: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ) -> None:
        if not isinstance(policy, GitHubActionsTokenPolicy):
            raise GitHubPublicationError("actions_token_policy_invalid")
        if (
            not isinstance(identity, VerifiedPublisherIdentity)
            or identity.state is not IdentityState.PLATFORM_BOUND
            or identity.credential_kind is not CredentialKind.ACTIONS_TOKEN
            or identity.actor_login != policy.actor_login
        ):
            raise GitHubPublicationError("actions_token_identity_unavailable")
        if not isinstance(token, str) or not token:
            raise GitHubPublicationError("actions_token_unavailable")
        try:
            token_size = len(token.encode("utf-8"))
        except UnicodeEncodeError:
            raise GitHubPublicationError("actions_token_unavailable") from None
        if token_size > _MAX_TOKEN_BYTES or any(character.isspace() for character in token):
            raise GitHubPublicationError("actions_token_unavailable")
        self.policy = policy
        self.identity = identity
        self._token = token
        self._utcnow = utcnow

    def __repr__(self) -> str:
        return "GitHubActionsTokenCredentialProvider(policy=<protected>, token=<redacted>)"

    def credential_for(
        self,
        repository_id: int,
        required_permissions: Mapping[str, str],
        timeout_seconds: float,
    ) -> PublisherCredential:
        if not _positive_int(repository_id) or repository_id != self.policy.repository_id:
            raise GitHubPublicationError("actions_token_repository_mismatch")
        if (
            not isinstance(required_permissions, Mapping)
            or set(required_permissions) != {"actions", "pull_requests"}
            or required_permissions.get("actions") != "read"
            or required_permissions.get("pull_requests") not in {"read", "write"}
        ):
            raise GitHubPublicationError("actions_token_permission_request_invalid")
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not math.isfinite(timeout_seconds)
            or timeout_seconds <= 0
            or timeout_seconds > _MAX_LIFETIME_SECONDS
        ):
            raise GitHubPublicationError("actions_token_deadline_invalid")
        now = self._utcnow()
        if now.tzinfo is None or now.utcoffset() is None:
            raise GitHubPublicationError("actions_token_deadline_invalid")
        # This is a conservative local use-by bound, not a claim about the
        # token's server-side expiration time.
        use_by = now.astimezone(timezone.utc) + timedelta(seconds=timeout_seconds)
        return PublisherCredential(
            token=self._token,
            identity=self.identity,
            repository_id=self.policy.repository_id,
            permissions=self.policy.permissions,
            expires_at=use_by.isoformat().replace("+00:00", "Z"),
            permission_basis=PermissionBasis.WORKFLOW_DECLARATION,
            write_capability=WriteCapability.NOT_TESTED,
        )
