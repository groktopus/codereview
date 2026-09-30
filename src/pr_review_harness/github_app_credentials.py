"""Least-privilege GitHub App installation credentials for publication.

This provider verifies protected identity expectations against GitHub's App,
installation, and target-repository APIs before it mints a one-repository
installation token. It does not authorize publication; the caller must still
pass the separate publication-admission and owner-authorization gates.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable, Mapping
from urllib.parse import quote

from .actions_publication import (
    CredentialKind,
    GitHubHTTPTransport,
    GitHubPublicationError,
    IdentityState,
    PublisherCredential,
    VerifiedPublisherIdentity,
    _parse_utc,
    _positive_int,
)

_API_ROOT = "https://api.github.com"
_MAX_RESPONSE_BYTES = 256 * 1024
_MAX_TOKEN_BYTES = 16_384
_MAX_PRIVATE_KEY_BYTES = 16 * 1024
_REPO = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
_SLUG = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,98}[a-z0-9])?\Z")
_LOGIN = re.compile(r"[A-Za-z0-9-]{1,39}(?:\[bot\])?\Z")
_ALLOWED_PERMISSION_NAMES = frozenset({"actions", "pull_requests"})


def _safe_error(code: str) -> GitHubPublicationError:
    return GitHubPublicationError(code)


def _id_matches(value: object, expected: int) -> bool:
    return _positive_int(value) and value == expected


def _parse_json(response: object, *, expected_status: int) -> dict[str, object]:
    if (
        not isinstance(getattr(response, "status", None), int)
        or isinstance(response.status, bool)
        or response.status != expected_status
        or not isinstance(getattr(response, "body", None), bytes)
        or len(response.body) > _MAX_RESPONSE_BYTES
    ):
        raise _safe_error("github_app_response_unavailable")

    def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate_key")
            result[key] = value
        return result

    try:
        value = json.loads(
            response.body,
            object_pairs_hook=unique_object,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("invalid_number")),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError):
        raise _safe_error("github_app_response_invalid") from None
    if not isinstance(value, dict):
        raise _safe_error("github_app_response_invalid")
    return value


@dataclass(frozen=True)
class GitHubAppCredentialPolicy:
    """Protected expectations for one App installation and one repository."""

    app_id: int
    installation_id: int
    repository_id: int
    repository: str
    app_slug: str
    actor_login: str

    def __post_init__(self) -> None:
        if (
            not _positive_int(self.app_id)
            or not _positive_int(self.installation_id)
            or not _positive_int(self.repository_id)
            or not isinstance(self.repository, str)
            or not _REPO.fullmatch(self.repository)
            or not isinstance(self.app_slug, str)
            or not _SLUG.fullmatch(self.app_slug)
            or not isinstance(self.actor_login, str)
            or not _LOGIN.fullmatch(self.actor_login)
            or self.actor_login != f"{self.app_slug}[bot]"
        ):
            raise _safe_error("github_app_policy_invalid")


class GitHubAppPublisherCredentialProvider:
    """Mint exact-permission, single-repository App installation tokens.

    ``private_key_pem`` is held only in memory and excluded from repr. The
    optional PyJWT dependency performs RS256 signing; errors are always
    projected to fixed codes so neither API bodies nor credential material are
    included in exceptions.
    """

    def __init__(
        self,
        policy: GitHubAppCredentialPolicy | None,
        private_key_pem: str | None,
        *,
        canary_identity: VerifiedPublisherIdentity | None = None,
        transport: GitHubHTTPTransport | None = None,
        clock: Callable[[], float] = time.monotonic,
        utcnow: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ) -> None:
        self.policy = policy
        self._private_key_pem = private_key_pem
        self._canary_identity = canary_identity
        self.transport = transport
        self._clock = clock
        self._utcnow = utcnow
        self._cache: dict[tuple[int, tuple[tuple[str, str], ...]], PublisherCredential] = {}

    def __repr__(self) -> str:
        return "GitHubAppPublisherCredentialProvider(policy=<protected>, private_key_pem=<redacted>)"

    @staticmethod
    def _requested_permissions(required: Mapping[str, str]) -> dict[str, str]:
        try:
            values = dict(required)
        except Exception:
            raise _safe_error("github_app_permission_request_invalid") from None
        if (
            set(values) != _ALLOWED_PERMISSION_NAMES
            or not isinstance(values.get("actions"), str)
            or values.get("actions") != "read"
            or not isinstance(values.get("pull_requests"), str)
            or values.get("pull_requests") not in {"read", "write"}
        ):
            raise _safe_error("github_app_permission_request_invalid")
        return {"actions": "read", "pull_requests": values["pull_requests"]}

    def _app_jwt(self, now: datetime) -> str:
        if self.policy is None or not isinstance(self._private_key_pem, str) or not self._private_key_pem:
            raise _safe_error("publisher_identity_unavailable")
        if now.tzinfo is None or now.utcoffset() is None:
            raise _safe_error("github_app_signer_unavailable")
        try:
            import jwt

            issued_at = int(now.timestamp())
            encoded = jwt.encode(
                {"iat": issued_at - 60, "exp": issued_at + 540, "iss": str(self.policy.app_id)},
                self._private_key_pem,
                algorithm="RS256",
            )
        except Exception:
            raise _safe_error("github_app_signer_unavailable") from None
        if isinstance(encoded, bytes):
            try:
                encoded = encoded.decode("ascii")
            except UnicodeDecodeError:
                raise _safe_error("github_app_signer_unavailable") from None
        if not isinstance(encoded, str) or not encoded or len(encoded) > _MAX_TOKEN_BYTES or any(c.isspace() for c in encoded):
            raise _safe_error("github_app_signer_unavailable")
        return encoded

    def credential_for(
        self,
        repository_id: int,
        required_permissions: Mapping[str, str],
        timeout_seconds: float,
    ) -> PublisherCredential:
        policy = self.policy
        if (
            not isinstance(policy, GitHubAppCredentialPolicy)
            or not isinstance(self._private_key_pem, str)
            or not self._private_key_pem
        ):
            raise _safe_error("publisher_identity_unavailable")
        canary_identity = self._canary_identity
        if canary_identity is None:
            raise _safe_error("publisher_identity_unavailable")
        if (
            not isinstance(canary_identity, VerifiedPublisherIdentity)
            or canary_identity.state is not IdentityState.VERIFIED
            or canary_identity.credential_kind is not CredentialKind.APP_INSTALLATION
            or canary_identity.actor_login != policy.actor_login
            or canary_identity.app_id != policy.app_id
            or canary_identity.installation_id != policy.installation_id
        ):
            raise _safe_error("github_app_canary_identity_mismatch")
        if not _positive_int(repository_id) or repository_id != policy.repository_id:
            raise _safe_error("github_app_repository_policy_mismatch")
        permissions = self._requested_permissions(required_permissions)
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not math.isfinite(timeout_seconds)
            or timeout_seconds <= 0
            or timeout_seconds > 300
        ):
            raise _safe_error("github_app_deadline_invalid")

        if len(self._private_key_pem) > _MAX_PRIVATE_KEY_BYTES:
            raise _safe_error("publisher_identity_unavailable")
        try:
            key_size = len(self._private_key_pem.encode("utf-8"))
        except UnicodeEncodeError:
            raise _safe_error("publisher_identity_unavailable") from None
        if key_size > _MAX_PRIVATE_KEY_BYTES:
            raise _safe_error("publisher_identity_unavailable")

        now = self._utcnow()
        if now.tzinfo is None or now.utcoffset() is None:
            raise _safe_error("github_app_signer_unavailable")
        cache_key = (repository_id, tuple(sorted(permissions.items())))
        cached = self._cache.get(cache_key)
        if cached is not None:
            try:
                cached_expiry = _parse_utc(cached.expires_at, "github_app_token_expiry_invalid")
            except GitHubPublicationError:
                cached_expiry = now
            if (
                dict(cached.permissions) == permissions
                and cached.valid_for(repository_id, permissions, now=now)
                and cached_expiry > now.astimezone(timezone.utc) + timedelta(seconds=float(timeout_seconds))
            ):
                return cached
            self._cache.pop(cache_key, None)

        deadline = self._clock() + float(timeout_seconds)
        app_jwt = self._app_jwt(now)
        transport = self.transport
        if transport is None:
            from .actions_publication import UrllibGitHubTransport

            transport = UrllibGitHubTransport()

        def request(
            method: str,
            path: str,
            *,
            body: Mapping[str, object] | None,
            status: int,
            auth_token: str | None = None,
        ) -> dict[str, object]:
            remaining = deadline - self._clock()
            if remaining <= 0:
                raise _safe_error("github_app_deadline_exhausted")
            try:
                response = transport.request(
                    method,
                    _API_ROOT + path,
                    token=app_jwt if auth_token is None else auth_token,
                    json_body=body,
                    timeout_seconds=remaining,
                    max_response_bytes=_MAX_RESPONSE_BYTES,
                )
            except Exception:
                raise _safe_error("github_app_transport_unavailable") from None
            return _parse_json(response, expected_status=status)

        repo_path = "/repos/" + quote(policy.repository, safe="/")
        app_data = request("GET", "/app", body=None, status=200)
        if not _id_matches(app_data.get("id"), policy.app_id) or app_data.get("slug") != policy.app_slug:
            raise _safe_error("github_app_identity_mismatch")

        installation_path = f"/app/installations/{policy.installation_id}"
        installation = request("GET", installation_path, body=None, status=200)
        self._validate_installation(installation, policy)

        repo_installation = request("GET", repo_path + "/installation", body=None, status=200)
        self._validate_installation(repo_installation, policy)
        if repo_installation.get("id") != installation.get("id"):
            raise _safe_error("github_app_installation_mismatch")

        mint_started = self._utcnow().astimezone(timezone.utc)
        token_response = request(
            "POST",
            installation_path + "/access_tokens",
            body={"repository_ids": [policy.repository_id], "permissions": permissions},
            status=201,
        )
        token = token_response.get("token")
        expires_at = token_response.get("expires_at")
        if (
            not isinstance(token, str)
            or not token
            or len(token) > _MAX_TOKEN_BYTES
            or any(char.isspace() for char in token)
        ):
            raise _safe_error("github_app_token_response_invalid")
        try:
            expiry = _parse_utc(expires_at, "github_app_token_expiry_invalid")
            current = self._utcnow().astimezone(timezone.utc)
        except Exception:
            raise _safe_error("github_app_token_expiry_invalid") from None
        if expiry <= current:
            raise _safe_error("github_app_token_expired")
        if expiry <= current + timedelta(seconds=float(timeout_seconds)) or expiry > mint_started + timedelta(
            hours=1, minutes=2
        ):
            raise _safe_error("github_app_token_expiry_invalid")
        self._validate_token_scope(token_response, policy, permissions)

        installation_repositories = request(
            "GET",
            "/installation/repositories?per_page=2",
            body=None,
            status=200,
            auth_token=token,
        )
        scoped_repositories = installation_repositories.get("repositories")
        if (
            isinstance(installation_repositories.get("total_count"), bool)
            or not isinstance(installation_repositories.get("total_count"), int)
            or installation_repositories.get("total_count") != 1
            or not isinstance(scoped_repositories, list)
            or len(scoped_repositories) != 1
            or not isinstance(scoped_repositories[0], dict)
            or not _id_matches(scoped_repositories[0].get("id"), policy.repository_id)
            or scoped_repositories[0].get("full_name") != policy.repository
        ):
            raise _safe_error("github_app_token_scope_mismatch")

        bot = request(
            "GET",
            "/users/" + quote(policy.actor_login, safe=""),
            body=None,
            status=200,
            auth_token=token,
        )
        if (
            bot.get("login") != policy.actor_login
            or bot.get("login") != canary_identity.actor_login
            or bot.get("type") != "Bot"
            or not _positive_int(bot.get("id"))
        ):
            raise _safe_error("github_app_bot_identity_mismatch")

        facts = {
            "schema": "github-app-publisher-identity.v1",
            "app_id": policy.app_id,
            "app_slug": policy.app_slug,
            "installation_id": policy.installation_id,
            "repository_id": policy.repository_id,
            "repository": policy.repository,
            "actor_login": policy.actor_login,
            "canary_identity_evidence_id": canary_identity.evidence_id,
            "api_facts": {
                "app_id": app_data["id"],
                "app_slug": app_data["slug"],
                "installation_id": installation["id"],
                "installation_app_id": installation["app_id"],
                "installation_account": (installation.get("account") or {}).get("login"),
                "repository_installation_id": repo_installation["id"],
                "token_repository_count": installation_repositories["total_count"],
                "token_repository_id": scoped_repositories[0]["id"],
                "bot_user_id": bot["id"],
            },
        }
        evidence_id = hashlib.sha256(
            json.dumps(facts, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        identity = VerifiedPublisherIdentity(
            state=IdentityState.VERIFIED,
            actor_login=policy.actor_login,
            credential_kind=CredentialKind.APP_INSTALLATION,
            evidence_id=evidence_id,
            app_id=policy.app_id,
            installation_id=policy.installation_id,
        )
        exact_permissions = tuple(sorted(permissions.items()))
        credential = PublisherCredential(
            token=token,
            identity=identity,
            repository_id=policy.repository_id,
            permissions=exact_permissions,
            expires_at=expires_at,
        )
        self._cache[cache_key] = credential
        return credential

    @staticmethod
    def _validate_installation(data: Mapping[str, object], policy: GitHubAppCredentialPolicy) -> None:
        account = data.get("account")
        if not isinstance(account, dict):
            raise _safe_error("github_app_installation_identity_mismatch")
        expected_owner = policy.repository.split("/", 1)[0]
        if (
            not _id_matches(data.get("id"), policy.installation_id)
            or not _id_matches(data.get("app_id"), policy.app_id)
            or account.get("login") != expected_owner
            or not _positive_int(account.get("id"))
            or "suspended_at" not in data
            or data.get("suspended_at") is not None
        ):
            raise _safe_error("github_app_installation_identity_mismatch")

    @staticmethod
    def _validate_token_scope(
        response: Mapping[str, object], policy: GitHubAppCredentialPolicy, permissions: Mapping[str, str]
    ) -> None:
        returned_permissions = response.get("permissions")
        expected_permissions = {**permissions, "metadata": "read"}
        if (
            not isinstance(returned_permissions, dict)
            or returned_permissions != expected_permissions
        ):
            raise _safe_error("github_app_token_scope_mismatch")
