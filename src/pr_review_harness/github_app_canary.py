"""Protected, read-only GitHub App identity canary for publication runtimes.

The canary verifies the current protected Actions run and its exact source run
through GitHub's API, then verifies App, installation, repository, read-token
scope, and bot identity. It returns an in-memory identity capability and a
sanitized receipt; the receipt is diagnostic evidence and is never accepted as
an identity input.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import secrets
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable
from urllib.parse import quote

from .actions_publication import (
    CredentialKind,
    GitHubHTTPTransport,
    GitHubPublicationError,
    IdentityState,
    VerifiedPublisherIdentity,
)
from .github_app_credentials import (
    _MAX_RESPONSE_BYTES,
    _MAX_TOKEN_BYTES,
    GitHubAppCredentialPolicy,
    GitHubAppPublisherCredentialProvider,
    _id_matches,
    _parse_json,
    _parse_utc,
)

_API_ROOT = "https://api.github.com"
_SHA = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_WORKFLOW_PATH = re.compile(r"\.github/workflows/[A-Za-z0-9_.-]{1,128}\.ya?ml\Z")
_MAX_RUN_ID = 2**63 - 1
_CANARY_CALL_CAP = 9  # 3 Actions/PR reads + 6 App/install/token identity calls.
_MAX_PRIVATE_KEY_BYTES = 16 * 1024


def _reject(code: str) -> GitHubPublicationError:
    return GitHubPublicationError(code)


@dataclass(frozen=True)
class ProtectedCanaryRun:
    """Expected identities copied from trusted GitHub Actions runtime context.

    A production entrypoint must construct this from platform-provided event
    and run context, never from PR files, CLI arguments, or a receipt artifact.
    The API reads below verify these expectations independently.
    """

    repository_id: int
    repository: str
    default_branch: str
    publisher_run_id: int
    publisher_run_attempt: int
    publisher_workflow_id: int
    publisher_workflow_path: str
    publisher_workflow_ref: str
    publisher_workflow_sha: str
    source_head_branch: str
    source_run_id: int
    source_run_attempt: int
    source_workflow_id: int
    source_workflow_path: str
    source_workflow_ref: str
    source_event: str
    source_workflow_sha: str
    source_run_head_sha: str
    pull_request_head_sha: str
    pull_request_number: int
    base_sha: str

    def validate(self, policy: GitHubAppCredentialPolicy) -> None:
        if not isinstance(policy, GitHubAppCredentialPolicy):
            raise _reject("github_app_canary_policy_invalid")
        positive = (
            self.repository_id,
            self.publisher_run_id,
            self.publisher_run_attempt,
            self.publisher_workflow_id,
            self.source_run_id,
            self.source_run_attempt,
            self.source_workflow_id,
            self.pull_request_number,
        )
        if any(
            isinstance(value, bool) or not isinstance(value, int) or value <= 0 or value > _MAX_RUN_ID
            for value in positive
        ):
            raise _reject("github_app_canary_run_identity_invalid")
        if (
            self.repository_id != policy.repository_id
            or self.repository != policy.repository
            or not isinstance(self.default_branch, str)
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,127}", self.default_branch)
            or ".." in self.default_branch.split("/")
            or "//" in self.default_branch
            or self.publisher_workflow_path != ".github/workflows/pr-publish.yml"
            or not isinstance(self.source_workflow_path, str)
            or not _WORKFLOW_PATH.fullmatch(self.source_workflow_path)
            or self.publisher_workflow_ref
            != f"{self.repository}/{self.publisher_workflow_path}@refs/heads/{self.default_branch}"
            or self.source_workflow_ref
            != f"{self.repository}/{self.source_workflow_path}@refs/heads/{self.default_branch}"
            or self.source_event != "pull_request_target"
            or not isinstance(self.source_head_branch, str)
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,127}", self.source_head_branch)
            or ".." in self.source_head_branch.split("/")
            or "//" in self.source_head_branch
            or not isinstance(self.publisher_workflow_sha, str)
            or not _SHA.fullmatch(self.publisher_workflow_sha)
            or not isinstance(self.source_workflow_sha, str)
            or not _SHA.fullmatch(self.source_workflow_sha)
            or self.source_workflow_sha != self.base_sha
            or not isinstance(self.source_run_head_sha, str)
            or not _SHA.fullmatch(self.source_run_head_sha)
            or not isinstance(self.pull_request_head_sha, str)
            or not _SHA.fullmatch(self.pull_request_head_sha)
            or not isinstance(self.base_sha, str)
            or not _SHA.fullmatch(self.base_sha)
        ):
            raise _reject("github_app_canary_expectation_mismatch")


@dataclass(frozen=True)
class CanaryLimits:
    """Hard upper bounds for one identity canary invocation."""

    deadline_seconds: float = 30.0
    max_calls: int = _CANARY_CALL_CAP
    max_response_bytes: int = _MAX_RESPONSE_BYTES

    def __post_init__(self) -> None:
        if (
            isinstance(self.deadline_seconds, bool)
            or not isinstance(self.deadline_seconds, (int, float))
            or not math.isfinite(self.deadline_seconds)
            or not 0 < self.deadline_seconds <= 30
            or isinstance(self.max_calls, bool)
            or not isinstance(self.max_calls, int)
            or not 1 <= self.max_calls <= _CANARY_CALL_CAP
            or isinstance(self.max_response_bytes, bool)
            or not isinstance(self.max_response_bytes, int)
            or not 1 <= self.max_response_bytes <= _MAX_RESPONSE_BYTES
        ):
            raise _reject("github_app_canary_limits_invalid")


@dataclass(frozen=True)
class CanaryReceipt:
    """Sanitized, hash-bound diagnostic facts. Contains no tokens or API bodies."""

    schema: str
    nonce: str
    evidence_id: str
    repository_id: int
    repository: str
    publisher_run_id: int
    publisher_run_attempt: int
    publisher_workflow_id: int
    publisher_workflow_path: str
    publisher_workflow_ref: str
    publisher_workflow_sha: str
    source_run_id: int
    source_run_attempt: int
    source_workflow_id: int
    source_workflow_path: str
    source_workflow_ref: str
    source_event: str
    source_workflow_sha: str
    source_run_head_sha: str
    source_head_branch: str
    pull_request_head_sha: str
    pull_request_number: int
    base_sha: str
    app_id: int
    installation_id: int
    actor_login: str
    bot_user_id: int
    read_permissions: tuple[tuple[str, str], ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "nonce": self.nonce,
            "evidence_id": self.evidence_id,
            "repository_id": self.repository_id,
            "repository": self.repository,
            "publisher_run_id": self.publisher_run_id,
            "publisher_run_attempt": self.publisher_run_attempt,
            "publisher_workflow_id": self.publisher_workflow_id,
            "publisher_workflow_path": self.publisher_workflow_path,
            "publisher_workflow_ref": self.publisher_workflow_ref,
            "publisher_workflow_sha": self.publisher_workflow_sha,
            "source_run_id": self.source_run_id,
            "source_run_attempt": self.source_run_attempt,
            "source_workflow_id": self.source_workflow_id,
            "source_workflow_path": self.source_workflow_path,
            "source_workflow_ref": self.source_workflow_ref,
            "source_event": self.source_event,
            "source_workflow_sha": self.source_workflow_sha,
            "source_run_head_sha": self.source_run_head_sha,
            "source_head_branch": self.source_head_branch,
            "pull_request_head_sha": self.pull_request_head_sha,
            "pull_request_number": self.pull_request_number,
            "base_sha": self.base_sha,
            "app_id": self.app_id,
            "installation_id": self.installation_id,
            "actor_login": self.actor_login,
            "bot_user_id": self.bot_user_id,
            "read_permissions": {name: level for name, level in self.read_permissions},
        }


def _validate_run(record: dict[str, object], expected: ProtectedCanaryRun, *, source: bool) -> str:
    run_id = expected.source_run_id if source else expected.publisher_run_id
    attempt = expected.source_run_attempt if source else expected.publisher_run_attempt
    workflow_id = expected.source_workflow_id if source else expected.publisher_workflow_id
    workflow_path = expected.source_workflow_path if source else expected.publisher_workflow_path
    workflow_sha = expected.source_run_head_sha if source else expected.publisher_workflow_sha
    raw_path = record.get("path")
    if not isinstance(raw_path, str):
        raise _reject("github_app_canary_actions_run_mismatch")
    repository = record.get("repository")
    actor = record.get("actor")
    if (
        not _id_matches(record.get("id"), run_id)
        or not _id_matches(record.get("run_attempt"), attempt)
        or not _id_matches(record.get("workflow_id"), workflow_id)
        or raw_path != workflow_path
        or record.get("head_branch") != (expected.source_head_branch if source else expected.default_branch)
        or record.get("head_sha") != workflow_sha
        or (record.get("status") != "completed" if source else record.get("status") != "in_progress")
        or (record.get("conclusion") != "success" if source else record.get("conclusion") is not None)
        or record.get("event") != (expected.source_event if source else "workflow_run")
        or not isinstance(repository, dict)
        or not _id_matches(repository.get("id"), expected.repository_id)
        or repository.get("full_name") != expected.repository
        or not isinstance(actor, dict)
        or not isinstance(actor.get("login"), str)
    ):
        raise _reject("github_app_canary_actions_run_mismatch")
    return actor["login"]


def verify_github_app_identity_canary(
    *,
    enabled: bool = False,
    platform: ProtectedCanaryRun,
    policy: GitHubAppCredentialPolicy,
    actions_token: str,
    app_private_key_supplier: Callable[[], str],
    transport: GitHubHTTPTransport,
    limits: CanaryLimits | None = None,
    clock: Callable[[], float] = time.monotonic,
    utcnow: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> tuple[VerifiedPublisherIdentity, CanaryReceipt]:
    """Verify platform and App identity, returning a runtime-only capability.

    `actions_token` is explicitly for read-only current-run/source-run/PR GETs.
    The canary itself is disabled unless the protected caller sets `enabled`
    to the literal boolean `True`.
    The supplied App key is not requested until local expectations and those
    platform reads pass. The only App-token POST is issuance of a one-repo
    token restricted to `actions:read` and `pull_requests:read`; this function
    contains no review/comment write path.
    """
    if not isinstance(enabled, bool):
        raise _reject("github_app_canary_enablement_invalid")
    if not enabled:
        raise _reject("github_app_canary_disabled")
    if not isinstance(platform, ProtectedCanaryRun):
        raise _reject("github_app_canary_platform_identity_invalid")
    platform.validate(policy)
    if not isinstance(actions_token, str) or not actions_token or len(actions_token) > _MAX_TOKEN_BYTES:
        raise _reject("github_app_canary_actions_token_unavailable")
    if not callable(app_private_key_supplier) or not callable(getattr(transport, "request", None)):
        raise _reject("github_app_canary_capability_unavailable")
    bounds = limits if limits is not None else CanaryLimits()
    if not isinstance(bounds, CanaryLimits):
        raise _reject("github_app_canary_limits_invalid")

    deadline = clock() + float(bounds.deadline_seconds)
    calls = 0
    nonce = secrets.token_hex(16)

    def request(method: str, path: str, token: str, body: dict[str, object] | None = None, status: int = 200):
        nonlocal calls
        calls += 1
        remaining = deadline - clock()
        if calls > bounds.max_calls or remaining <= 0:
            raise _reject("github_app_canary_budget_exhausted")
        try:
            response = transport.request(
                method,
                _API_ROOT + path,
                token=token,
                json_body=body,
                timeout_seconds=remaining,
                max_response_bytes=bounds.max_response_bytes,
            )
        except GitHubPublicationError:
            raise
        except Exception:
            raise _reject("github_app_canary_transport_unavailable") from None
        if clock() >= deadline:
            raise _reject("github_app_canary_deadline_exhausted")
        if len(response.body) > bounds.max_response_bytes:
            raise _reject("github_app_canary_response_too_large")
        return _parse_json(response, expected_status=status)

    repo_path = "/repos/" + quote(policy.repository, safe="/")
    publisher_run = request("GET", f"{repo_path}/actions/runs/{platform.publisher_run_id}", actions_token)
    publisher_actor = _validate_run(publisher_run, platform, source=False)
    source_run = request("GET", f"{repo_path}/actions/runs/{platform.source_run_id}", actions_token)
    source_actor = _validate_run(source_run, platform, source=True)
    # GitHub may omit pull_requests for pull_request_target workflow runs.
    # If it reports associations, require a single exact PR/base/head tuple.
    source_prs = source_run.get("pull_requests")
    if source_prs not in (None, []):
        if not isinstance(source_prs, list) or len(source_prs) != 1:
            raise _reject("github_app_canary_source_pr_mismatch")
        item = source_prs[0]
        source_base = item.get("base") if isinstance(item, dict) and isinstance(item.get("base"), dict) else {}
        source_head = item.get("head") if isinstance(item, dict) and isinstance(item.get("head"), dict) else {}
        if (
            not isinstance(item, dict)
            or item.get("number") != platform.pull_request_number
            or source_base.get("sha") != platform.base_sha
            or source_head.get("sha") != platform.pull_request_head_sha
        ):
            raise _reject("github_app_canary_source_pr_mismatch")
    pr = request("GET", f"{repo_path}/pulls/{platform.pull_request_number}", actions_token)
    base = pr.get("base")
    head = pr.get("head")
    pr_repo = base.get("repo") if isinstance(base, dict) else None
    if (
        not _id_matches(pr.get("number"), platform.pull_request_number)
        or pr.get("state") != "open"
        or not isinstance(base, dict)
        or base.get("sha") != platform.base_sha
        or base.get("ref") != platform.default_branch
        or not isinstance(pr_repo, dict)
        or not _id_matches(pr_repo.get("id"), platform.repository_id)
        or not isinstance(head, dict)
        or head.get("sha") != platform.pull_request_head_sha
        or head.get("ref") != platform.source_head_branch
    ):
        raise _reject("github_app_canary_pull_request_mismatch")

    try:
        private_key_pem = app_private_key_supplier()
    except Exception:
        raise _reject("publisher_identity_unavailable") from None
    if not isinstance(private_key_pem, str) or not private_key_pem:
        raise _reject("publisher_identity_unavailable")
    try:
        private_key_size = len(private_key_pem.encode("utf-8"))
    except UnicodeEncodeError:
        raise _reject("publisher_identity_unavailable") from None
    if private_key_size > _MAX_PRIVATE_KEY_BYTES:
        raise _reject("publisher_identity_unavailable")
    signer = GitHubAppPublisherCredentialProvider(
        policy,
        private_key_pem,
        canary_identity=None,
        transport=transport,
        clock=clock,
        utcnow=utcnow,
    )
    now = utcnow()
    if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
        raise _reject("github_app_signer_unavailable")
    app_jwt = signer._app_jwt(now)
    app_data = request("GET", "/app", app_jwt)
    if not _id_matches(app_data.get("id"), policy.app_id) or app_data.get("slug") != policy.app_slug:
        raise _reject("github_app_identity_mismatch")
    installation_path = f"/app/installations/{policy.installation_id}"
    installation = request("GET", installation_path, app_jwt)
    GitHubAppPublisherCredentialProvider._validate_installation(installation, policy)
    repo_installation = request("GET", repo_path + "/installation", app_jwt)
    GitHubAppPublisherCredentialProvider._validate_installation(repo_installation, policy)
    if repo_installation.get("id") != installation.get("id"):
        raise _reject("github_app_installation_mismatch")

    read_permissions = {"actions": "read", "pull_requests": "read"}
    minted_at = utcnow().astimezone(timezone.utc)
    token_response = request(
        "POST",
        installation_path + "/access_tokens",
        app_jwt,
        {"repository_ids": [policy.repository_id], "permissions": read_permissions},
        status=201,
    )
    token = token_response.get("token")
    if (
        not isinstance(token, str)
        or not token
        or len(token) > _MAX_TOKEN_BYTES
        or any(char.isspace() for char in token)
    ):
        raise _reject("github_app_token_response_invalid")
    expiry = _parse_utc(token_response.get("expires_at"), "github_app_token_expiry_invalid")
    current = utcnow().astimezone(timezone.utc)
    if expiry <= current or expiry > minted_at + timedelta(hours=1, minutes=2):
        raise _reject("github_app_token_expiry_invalid")
    GitHubAppPublisherCredentialProvider._validate_token_scope(token_response, policy, read_permissions)
    repositories = request("GET", "/installation/repositories?per_page=2", token)
    listed = repositories.get("repositories")
    if (
        isinstance(repositories.get("total_count"), bool)
        or repositories.get("total_count") != 1
        or not isinstance(listed, list)
        or len(listed) != 1
        or not isinstance(listed[0], dict)
        or not _id_matches(listed[0].get("id"), policy.repository_id)
        or listed[0].get("full_name") != policy.repository
    ):
        raise _reject("github_app_token_scope_mismatch")
    bot = request("GET", "/users/" + quote(policy.actor_login, safe=""), token)
    if (
        bot.get("login") != policy.actor_login
        or bot.get("type") != "Bot"
        or not isinstance(bot.get("id"), int)
        or isinstance(bot.get("id"), bool)
        or bot["id"] <= 0
    ):
        raise _reject("github_app_bot_identity_mismatch")

    facts = {
        "schema": "github-app-identity-canary.v1",
        "nonce": nonce,
        "repository_id": platform.repository_id,
        "repository": platform.repository,
        "publisher_run_id": platform.publisher_run_id,
        "publisher_run_attempt": platform.publisher_run_attempt,
        "publisher_workflow_id": platform.publisher_workflow_id,
        "publisher_workflow_path": platform.publisher_workflow_path,
        "publisher_workflow_ref": platform.publisher_workflow_ref,
        "publisher_workflow_sha": platform.publisher_workflow_sha,
        "source_run_id": platform.source_run_id,
        "source_run_attempt": platform.source_run_attempt,
        "source_event": platform.source_event,
        "source_workflow_id": platform.source_workflow_id,
        "source_workflow_path": platform.source_workflow_path,
        "source_workflow_ref": platform.source_workflow_ref,
        "source_workflow_sha": platform.source_workflow_sha,
        "source_run_head_sha": platform.source_run_head_sha,
        "source_head_branch": platform.source_head_branch,
        "pull_request_head_sha": platform.pull_request_head_sha,
        "pull_request_number": platform.pull_request_number,
        "base_sha": platform.base_sha,
        "app_id": policy.app_id,
        "installation_id": policy.installation_id,
        "actor_login": policy.actor_login,
        "bot_user_id": bot["id"],
        "read_permissions": read_permissions,
        "observed": {
            "publisher_actor": publisher_actor,
            "source_actor": source_actor,
            "app_id": app_data["id"],
            "app_slug": app_data["slug"],
            "installation_id": installation["id"],
            "installation_app_id": installation["app_id"],
            "repository_installation_id": repo_installation["id"],
            "token_repository_count": repositories["total_count"],
            "token_repository_id": listed[0]["id"],
            "bot_user_id": bot["id"],
        },
    }
    evidence_id = hashlib.sha256(json.dumps(facts, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    identity = VerifiedPublisherIdentity(
        state=IdentityState.VERIFIED,
        actor_login=policy.actor_login,
        credential_kind=CredentialKind.APP_INSTALLATION,
        evidence_id=evidence_id,
        app_id=policy.app_id,
        installation_id=policy.installation_id,
    )
    receipt = CanaryReceipt(
        schema="github-app-identity-canary.v1",
        nonce=nonce,
        evidence_id=evidence_id,
        repository_id=platform.repository_id,
        repository=platform.repository,
        publisher_run_id=platform.publisher_run_id,
        publisher_run_attempt=platform.publisher_run_attempt,
        publisher_workflow_id=platform.publisher_workflow_id,
        publisher_workflow_path=platform.publisher_workflow_path,
        publisher_workflow_ref=platform.publisher_workflow_ref,
        publisher_workflow_sha=platform.publisher_workflow_sha,
        source_run_id=platform.source_run_id,
        source_run_attempt=platform.source_run_attempt,
        source_workflow_id=platform.source_workflow_id,
        source_workflow_path=platform.source_workflow_path,
        source_workflow_ref=platform.source_workflow_ref,
        source_event=platform.source_event,
        source_workflow_sha=platform.source_workflow_sha,
        source_run_head_sha=platform.source_run_head_sha,
        source_head_branch=platform.source_head_branch,
        pull_request_head_sha=platform.pull_request_head_sha,
        pull_request_number=platform.pull_request_number,
        base_sha=platform.base_sha,
        app_id=policy.app_id,
        installation_id=policy.installation_id,
        actor_login=policy.actor_login,
        bot_user_id=bot["id"],
        read_permissions=tuple(sorted(read_permissions.items())),
    )
    return identity, receipt
