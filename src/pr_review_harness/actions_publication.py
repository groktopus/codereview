"""Fail-closed GitHub Actions capabilities for stateless PR-review publishing.

The module uses only an injected credential provider and an injected artifact
uploader. It never reads ``gh auth``, ``/user``, or environment booleans. A
credential provider must return the typed identity bound by the protected
workflow and its separately completed identity canary. Without that verified
capability, all publication paths are unavailable.

Receipt artifact upload is deliberately an interface for the official
``@actions/artifact`` workflow boundary. This module does not invent a REST
upload endpoint. It verifies uploaded artifacts and history using GitHub's
documented Actions artifact REST API.
"""

from __future__ import annotations

import hashlib
import io
import json
import math
import re
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Mapping, Protocol

from .artifact_intake import (
    ArtifactIdentity,
    ArtifactTransportDigest,
    AttestationIdentity,
    IntakeLimits,
    TrustedAttestationVerifier,
    intake_artifact_bundle,
)
from .publication_receipts import (
    AttemptReceipt,
    EffectSlot,
    HistoryScan,
    HistoryStatus,
    PublicationAdmission,
    ReceiptAcknowledgement,
    ReceiptPersistence,
    ReceiptPersistenceStatus,
    ReviewObservation,
    ReviewState,
    RunIdentity,
    ScanLimits,
    validate_credential_provenance,
)
from .publisher import _canonical_hash, _stateless_effect_key

_REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
_SHA = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_LOGIN = re.compile(r"[A-Za-z0-9-]{1,39}(?:\[bot\])?\Z")
_MARKER = re.compile(r"<!-- pr-review-harness:(effect-[0-9a-f]{64}) -->\Z")
_EFFECT_ARTIFACT = re.compile(r"pr-review-attempt-([1-9][0-9]*)-([0-9a-f]{40}|[0-9a-f]{64})\Z")
_MAX_API_BYTES = 2 * 1024 * 1024
_MAX_ARCHIVE_BYTES = 8 * 1024 * 1024
_MAX_RECEIPT_ARCHIVE_BYTES = 128 * 1024
_MAX_RECEIPT_BYTES = 16 * 1024
_API_VERSION = "2026-03-10"
_API_JSON_MAX_DEPTH = 64
_API_JSON_MAX_TOKENS = 200_000
_MAX_RUN_HISTORY = 100
_MAX_HISTORY_PAGES = 10
_MAX_REVIEW_HISTORY = 1000


class GitHubPublicationError(ValueError):
    """A safe error code for a bounded GitHub publication operation."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


class CredentialKind(StrEnum):
    ACTIONS_TOKEN = "ACTIONS_TOKEN"
    APP_INSTALLATION = "APP_INSTALLATION"


class IdentityState(StrEnum):
    VERIFIED = "VERIFIED"
    PLATFORM_BOUND = "PLATFORM_BOUND"
    UNAVAILABLE = "UNAVAILABLE"


class PermissionBasis(StrEnum):
    API_VERIFIED = "API_VERIFIED"
    WORKFLOW_DECLARATION = "WORKFLOW_DECLARATION"


class WriteCapability(StrEnum):
    NOT_TESTED = "NOT_TESTED"


class ArtifactTrustMode(StrEnum):
    API_BOUND_SHA256 = "API_BOUND_SHA256"
    SIGNED_ATTESTATION = "SIGNED_ATTESTATION"


@dataclass(frozen=True)
class VerifiedPublisherIdentity:
    """Writer identity bound by the trusted runtime adapter/canary."""

    state: IdentityState
    actor_login: str
    credential_kind: CredentialKind
    evidence_id: str
    app_id: int | None = None
    installation_id: int | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.state, IdentityState):
            raise GitHubPublicationError("publisher_identity_state_invalid")
        if not isinstance(self.actor_login, str) or not _LOGIN.fullmatch(self.actor_login):
            raise GitHubPublicationError("publisher_actor_invalid")
        if not isinstance(self.credential_kind, CredentialKind):
            raise GitHubPublicationError("credential_kind_invalid")
        if not _HASH.fullmatch(self.evidence_id):
            raise GitHubPublicationError("publisher_identity_evidence_invalid")
        if self.credential_kind is CredentialKind.APP_INSTALLATION:
            if self.state not in {IdentityState.VERIFIED, IdentityState.UNAVAILABLE}:
                raise GitHubPublicationError("app_identity_state_invalid")
            if not _positive_int(self.app_id) or not _positive_int(self.installation_id):
                raise GitHubPublicationError("app_identity_invalid")
        else:
            if self.state not in {IdentityState.PLATFORM_BOUND, IdentityState.UNAVAILABLE}:
                raise GitHubPublicationError("actions_identity_state_invalid")
            if self.app_id is not None or self.installation_id is not None:
                raise GitHubPublicationError("unexpected_app_identity")


@dataclass(frozen=True)
class PublisherCredential:
    """Short-lived token from a trusted runtime provider.

    ``permissions`` records only operations required by this adapter; it is not
    a complete or independently observed token permission map. Actions-token
    workflow declaration provenance is carried separately by protected policy.
    """

    token: str = field(repr=False)
    identity: VerifiedPublisherIdentity
    repository_id: int
    permissions: tuple[tuple[str, str], ...]
    expires_at: str
    permission_basis: PermissionBasis = PermissionBasis.API_VERIFIED
    write_capability: WriteCapability = WriteCapability.NOT_TESTED

    def __post_init__(self) -> None:
        if (
            not isinstance(self.token, str)
            or not self.token
            or len(self.token) > 16_384
            or any(character.isspace() for character in self.token)
        ):
            raise GitHubPublicationError("publisher_credential_invalid")
        if not isinstance(self.identity, VerifiedPublisherIdentity):
            raise GitHubPublicationError("publisher_identity_invalid")
        expected_state = (
            IdentityState.VERIFIED
            if self.identity.credential_kind is CredentialKind.APP_INSTALLATION
            else IdentityState.PLATFORM_BOUND
        )
        if self.identity.state is not expected_state:
            raise GitHubPublicationError("publisher_identity_unverified")
        if not _positive_int(self.repository_id):
            raise GitHubPublicationError("credential_repository_invalid")
        if (
            not isinstance(self.permissions, tuple)
            or len(set(self.permissions)) != len(self.permissions)
            or any(
                not isinstance(item, tuple)
                or len(item) != 2
                or item[0] not in {"actions", "pull_requests"}
                or item[1] not in {"read", "write"}
                for item in self.permissions
            )
        ):
            raise GitHubPublicationError("credential_permissions_invalid")
        expected_basis = (
            PermissionBasis.API_VERIFIED
            if self.identity.credential_kind is CredentialKind.APP_INSTALLATION
            else PermissionBasis.WORKFLOW_DECLARATION
        )
        if self.permission_basis is not expected_basis:
            raise GitHubPublicationError("credential_permission_basis_invalid")
        if self.write_capability is not WriteCapability.NOT_TESTED:
            raise GitHubPublicationError("credential_write_capability_invalid")
        _parse_utc(self.expires_at, "credential_expiry")

    def valid_for(self, repository_id: int, required: Mapping[str, str], now: datetime | None = None) -> bool:
        current = now or datetime.now(timezone.utc)
        permissions = dict(self.permissions)
        return (
            self.identity.state
            is (
                IdentityState.VERIFIED
                if self.identity.credential_kind is CredentialKind.APP_INSTALLATION
                else IdentityState.PLATFORM_BOUND
            )
            and self.repository_id == repository_id
            and all(
                permissions.get(name) == "write" or permissions.get(name) == level for name, level in required.items()
            )
            and _parse_utc(self.expires_at, "credential_expiry") > current.astimezone(timezone.utc)
        )


class PublisherCredentialProvider(Protocol):
    """Trusted, canary-backed source for least-privilege runtime credentials."""

    def credential_for(
        self,
        repository_id: int,
        required_permissions: Mapping[str, str],
        timeout_seconds: float,
    ) -> PublisherCredential: ...


@dataclass(frozen=True)
class HTTPResponse:
    status: int
    headers: Mapping[str, str]
    body: bytes


class GitHubHTTPTransport(Protocol):
    """Transport boundary used by the production urllib client and tests."""

    def request(
        self,
        method: str,
        url: str,
        *,
        token: str | None,
        json_body: Mapping[str, object] | None,
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> HTTPResponse: ...

    def download(
        self,
        url: str,
        *,
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> HTTPResponse: ...


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


class UrllibGitHubTransport:
    """Small stdlib transport with bounded bodies and no implicit redirects."""

    def __init__(self):
        self._opener = urllib.request.build_opener(_NoRedirect())

    def request(
        self,
        method: str,
        url: str,
        *,
        token: str | None,
        json_body: Mapping[str, object] | None,
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> HTTPResponse:
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": _API_VERSION,
            "User-Agent": "pr-review-harness/1",
        }
        if token is not None:
            headers["Authorization"] = f"Bearer {token}"
        body = None
        if json_body is not None:
            body = json.dumps(json_body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(url, data=body, headers=headers, method=method)
        return self._open(request, timeout_seconds, max_response_bytes)

    def download(self, url: str, *, timeout_seconds: float, max_response_bytes: int) -> HTTPResponse:
        request = urllib.request.Request(url, headers={"User-Agent": "pr-review-harness/1"}, method="GET")
        return self._open(request, timeout_seconds, max_response_bytes)

    def _open(self, request, timeout_seconds: float, max_response_bytes: int) -> HTTPResponse:
        if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
            raise GitHubPublicationError("deadline_exhausted")
        deadline = time.monotonic() + timeout_seconds
        try:
            response = self._opener.open(request, timeout=timeout_seconds)
        except urllib.error.HTTPError as exc:
            response = exc
        except (urllib.error.URLError, TimeoutError, OSError):
            raise GitHubPublicationError("github_transport_failed") from None
        try:
            chunks = []
            size = 0
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise GitHubPublicationError("github_transport_deadline_exhausted")
                # urllib's socket timeout is an idle timeout. Tighten it on
                # every bounded read and check the absolute deadline between
                # reads so a slow-drip response cannot renew the whole budget.
                try:
                    response.fp.raw._sock.settimeout(remaining)
                except AttributeError:
                    pass
                reader = getattr(response, "read1", response.read)
                try:
                    chunk = reader(min(64 * 1024, max_response_bytes + 1 - size))
                except (TimeoutError, OSError, urllib.error.URLError):
                    if time.monotonic() >= deadline:
                        raise GitHubPublicationError("github_transport_deadline_exhausted") from None
                    raise GitHubPublicationError("github_transport_failed") from None
                if not chunk:
                    break
                size += len(chunk)
                if size > max_response_bytes:
                    raise GitHubPublicationError("github_response_too_large")
                chunks.append(chunk)
            raw = b"".join(chunks)
            if len(raw) > max_response_bytes:
                raise GitHubPublicationError("github_response_too_large")
            headers = {key.lower(): value for key, value in response.headers.items()}
            return HTTPResponse(response.status, headers, raw)
        finally:
            response.close()


@dataclass(frozen=True)
class GitHubPublicationPolicy:
    """Trusted expected identities and finite limits for one protected run."""

    repository_id: int
    repository: str
    pull_request_number: int
    upstream_run_id: int
    upstream_run_attempt: int
    publisher_run_id: int
    publisher_run_attempt: int
    caller_workflow_id: int
    caller_workflow_path: str
    caller_workflow_ref: str
    caller_workflow_sha: str
    called_harness_repository: str
    called_harness_path: str
    called_harness_sha: str
    publisher_workflow_id: int
    publisher_workflow_path: str
    publisher_workflow_ref: str
    publisher_workflow_sha: str
    profile_version: str
    profile_sha256: str
    provider_configuration_identity: str
    allowed_actor_login: str
    artifact_trust_mode: ArtifactTrustMode
    result_artifact_name: str = "pr-review-result"
    receipt_artifact_prefix: str = "pr-review-attempt"
    api_base_url: str = "https://api.github.com"
    artifact_redirect_hosts: tuple[str, ...] = ()
    contract_versions: tuple[tuple[str, str], ...] = (
        ("artifact_manifest", "1.0"),
        ("review_result", "0.1"),
    )
    max_api_response_bytes: int = _MAX_API_BYTES
    max_bundle_bytes: int = _MAX_ARCHIVE_BYTES
    max_receipt_archive_bytes: int = _MAX_RECEIPT_ARCHIVE_BYTES
    concurrency_scope: str = "pull_request"
    credential_provenance: dict | None = None

    def __post_init__(self) -> None:
        integer_fields = (
            "repository_id",
            "pull_request_number",
            "upstream_run_id",
            "upstream_run_attempt",
            "publisher_run_id",
            "publisher_run_attempt",
            "caller_workflow_id",
            "publisher_workflow_id",
            "max_api_response_bytes",
            "max_bundle_bytes",
            "max_receipt_archive_bytes",
        )
        if any(not _positive_int(getattr(self, key)) for key in integer_fields):
            raise GitHubPublicationError("publication_policy_integer_invalid")
        if not _REPOSITORY.fullmatch(self.repository) or not _REPOSITORY.fullmatch(self.called_harness_repository):
            raise GitHubPublicationError("publication_policy_repository_invalid")
        for key in (
            "caller_workflow_sha",
            "called_harness_sha",
            "publisher_workflow_sha",
            "profile_sha256",
        ):
            value = getattr(self, key)
            if not isinstance(value, str) or not (
                _SHA.fullmatch(value) if key != "profile_sha256" else _HASH.fullmatch(value)
            ):
                raise GitHubPublicationError("publication_policy_digest_invalid")
        for key in (
            "caller_workflow_path",
            "caller_workflow_ref",
            "called_harness_path",
            "publisher_workflow_path",
            "publisher_workflow_ref",
            "profile_version",
            "provider_configuration_identity",
            "result_artifact_name",
        ):
            if not isinstance(getattr(self, key), str) or not getattr(self, key) or len(getattr(self, key)) > 512:
                raise GitHubPublicationError("publication_policy_text_invalid")
        if not _LOGIN.fullmatch(self.allowed_actor_login):
            raise GitHubPublicationError("publication_actor_policy_invalid")
        if not isinstance(self.artifact_trust_mode, ArtifactTrustMode):
            raise GitHubPublicationError("artifact_trust_mode_invalid")
        if not isinstance(self.concurrency_scope, str) or self.concurrency_scope not in {"pull_request", "repository"}:
            raise GitHubPublicationError("publication_concurrency_scope_invalid")
        if self.credential_provenance is not None:
            try:
                validate_credential_provenance(self.credential_provenance)
            except Exception:
                raise GitHubPublicationError("publication_credential_provenance_invalid") from None
        parsed = urllib.parse.urlsplit(self.api_base_url)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/api/v3"}
        ):
            raise GitHubPublicationError("github_api_base_invalid")
        if self.max_bundle_bytes > _MAX_ARCHIVE_BYTES or self.max_receipt_archive_bytes > _MAX_RECEIPT_ARCHIVE_BYTES:
            raise GitHubPublicationError("publication_policy_bytes_exceeded")
        if self.max_api_response_bytes > _MAX_API_BYTES:
            raise GitHubPublicationError("publication_policy_bytes_exceeded")
        if any(
            not isinstance(host, str) or not re.fullmatch(r"[A-Za-z0-9.-]+", host)
            for host in self.artifact_redirect_hosts
        ):
            raise GitHubPublicationError("artifact_redirect_host_invalid")

    def receipt_artifact_name(self, slot: EffectSlot) -> str:
        return f"{self.receipt_artifact_prefix}-{slot.pull_request_number}-{slot.head_sha}"


@dataclass(frozen=True)
class ArtifactUploadResult:
    """Result returned by a trusted official @actions/artifact uploader."""

    status: str
    artifact_id: int | None = None
    reason_code: str | None = None

    def __post_init__(self) -> None:
        if self.status not in {"UPLOADED", "UNAVAILABLE", "FAILED"}:
            raise GitHubPublicationError("artifact_upload_result_invalid")
        if self.status == "UPLOADED" and not _positive_int(self.artifact_id):
            raise GitHubPublicationError("artifact_upload_id_invalid")
        if self.reason_code is not None and not re.fullmatch(r"[a-z0-9_]{1,64}", self.reason_code):
            raise GitHubPublicationError("artifact_upload_reason_invalid")


class ActionsArtifactUploader(Protocol):
    """Workflow adapter implemented with the official ``@actions/artifact``."""

    def upload(
        self,
        *,
        run_id: int,
        artifact_name: str,
        filename: str,
        content: bytes,
        timeout_seconds: float,
    ) -> ArtifactUploadResult: ...


@dataclass(frozen=True)
class DownloadedArtifact:
    metadata: dict
    archive: bytes
    archive_sha256: str


class GitHubActionsPublicationAdapter:
    """Bounded run/artifact/review adapter for ``publish_review_stateless``.

    The required credential provider must return a `PublisherCredential` whose
    identity state is VERIFIED from a trusted runtime canary. This module does
    not manufacture that assertion, infer it from ``github.actor``, or fall
    back to ambient credentials. A missing identity or artifact uploader
    yields UNKNOWN before a GitHub write. A COMPLETE history scan means all
    API-visible runs returned inside the configured bounds were reconciled; it
    cannot prove that a privileged administrator never deleted a workflow run.
    Protect run/artifact retention for the reconciliation horizon. No GitHub
    API idempotency contract is claimed for the one-shot review POST.
    """

    def __init__(
        self,
        policy: GitHubPublicationPolicy,
        credential_provider: PublisherCredentialProvider | None,
        *,
        transport: GitHubHTTPTransport | None = None,
        artifact_uploader: ActionsArtifactUploader | None = None,
        attestation_verifier: TrustedAttestationVerifier | None = None,
        attestation_identity: AttestationIdentity | None = None,
        clock=None,
    ):
        self.policy = policy
        self.credential_provider = credential_provider
        self.transport = transport or UrllibGitHubTransport()
        self.artifact_uploader = artifact_uploader
        self.attestation_verifier = attestation_verifier
        self.attestation_identity = attestation_identity
        self._clock = clock or time.monotonic
        self._deadline_at: float | None = None
        self._identity: VerifiedPublisherIdentity | None = None

    def _deadline(self, timeout: float) -> float:
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout)
            or timeout <= 0
        ):
            raise GitHubPublicationError("deadline_exhausted")
        return min(float(timeout), max(0.0, self._deadline_at - self._clock())) if self._deadline_at else float(timeout)

    def _start_deadline(self, timeout: float) -> None:
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout)
            or timeout <= 0
        ):
            raise GitHubPublicationError("deadline_exhausted")
        self._deadline_at = self._clock() + float(timeout)

    @staticmethod
    def _limits_within_adapter_caps(limits: ScanLimits) -> bool:
        return (
            isinstance(limits, ScanLimits)
            and limits.max_runs <= _MAX_RUN_HISTORY
            and limits.max_pages <= _MAX_HISTORY_PAGES
            and limits.max_reviews <= _MAX_REVIEW_HISTORY
        )

    def _credential(self, timeout_seconds: float, required: Mapping[str, str]) -> PublisherCredential:
        remaining = self._deadline(timeout_seconds)
        if remaining <= 0:
            raise GitHubPublicationError("deadline_exhausted")
        if self.credential_provider is None:
            raise GitHubPublicationError("publisher_identity_unavailable")
        try:
            credential = self.credential_provider.credential_for(self.policy.repository_id, required, remaining)
        except Exception:
            raise GitHubPublicationError("publisher_identity_unavailable") from None
        if not isinstance(credential, PublisherCredential) or not credential.valid_for(
            self.policy.repository_id, required
        ):
            raise GitHubPublicationError("publisher_credential_unavailable")
        if credential.identity.actor_login != self.policy.allowed_actor_login:
            raise GitHubPublicationError("publisher_actor_policy_mismatch")
        if credential.identity.credential_kind is CredentialKind.ACTIONS_TOKEN and self.policy.credential_provenance is None:
            raise GitHubPublicationError("publisher_credential_provenance_missing")
        if credential.identity.credential_kind is CredentialKind.APP_INSTALLATION and self.policy.credential_provenance is not None:
            raise GitHubPublicationError("publisher_credential_provenance_unexpected")
        if self._identity is not None and credential.identity != self._identity:
            raise GitHubPublicationError("publisher_identity_changed")
        self._identity = credential.identity
        return credential

    def _url(self, path_query: str) -> str:
        if not isinstance(path_query, str) or not path_query.startswith("/") or path_query.startswith("//"):
            raise GitHubPublicationError("github_endpoint_invalid")
        parsed = urllib.parse.urlsplit(path_query)
        if parsed.scheme or parsed.netloc or ".." in parsed.path.split("/"):
            raise GitHubPublicationError("github_endpoint_invalid")
        return self.policy.api_base_url.rstrip("/") + path_query

    def _request(
        self,
        method: str,
        path_query: str,
        timeout_seconds: float,
        *,
        payload: Mapping[str, object] | None = None,
        allow_redirect: bool = False,
    ) -> HTTPResponse:
        remaining = self._deadline(timeout_seconds)
        if remaining <= 0:
            raise GitHubPublicationError("deadline_exhausted")
        required = {"actions": "read", "pull_requests": "write" if method == "POST" else "read"}
        credential = self._credential(remaining, required)
        remaining = self._deadline(timeout_seconds)
        if remaining <= 0:
            raise GitHubPublicationError("deadline_exhausted")
        response = self.transport.request(
            method,
            self._url(path_query),
            token=credential.token,
            json_body=payload,
            timeout_seconds=remaining,
            max_response_bytes=self.policy.max_api_response_bytes,
        )
        if not isinstance(response, HTTPResponse) or not isinstance(response.status, int):
            raise GitHubPublicationError("github_response_invalid")
        if response.status == 302 and allow_redirect:
            return response
        if not 200 <= response.status < 300:
            raise GitHubPublicationError("github_api_request_failed")
        return response

    def _json(self, method: str, path_query: str, timeout_seconds: float, payload=None) -> dict:
        response = self._request(method, path_query, timeout_seconds, payload=payload)
        try:
            value = _parse_api_json(response.body)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
            raise GitHubPublicationError("github_json_invalid") from None
        if not isinstance(value, dict):
            raise GitHubPublicationError("github_json_object_required")
        return value

    def _array(self, path_query: str, timeout_seconds: float) -> list:
        response = self._request("GET", path_query, timeout_seconds)
        try:
            value = _parse_api_json(response.body)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
            raise GitHubPublicationError("github_json_invalid") from None
        if not isinstance(value, list):
            raise GitHubPublicationError("github_json_array_required")
        return value

    def _repo_path(self, suffix: str) -> str:
        return f"/repos/{urllib.parse.quote(self.policy.repository, safe='/')}{suffix}"

    def _pull(self, timeout_seconds: float) -> dict:
        value = self._json("GET", self._repo_path(f"/pulls/{self.policy.pull_request_number}"), timeout_seconds)
        base = value.get("base") if isinstance(value.get("base"), dict) else {}
        head = value.get("head") if isinstance(value.get("head"), dict) else {}
        base_repo = base.get("repo") if isinstance(base.get("repo"), dict) else {}
        if (
            not _positive_int(value.get("number"))
            or value.get("number") != self.policy.pull_request_number
            or not isinstance(base_repo.get("id"), int)
            or isinstance(base_repo.get("id"), bool)
            or base_repo.get("id") != self.policy.repository_id
            or not isinstance(base.get("sha"), str)
            or not _SHA.fullmatch(base["sha"])
            or not isinstance(head.get("sha"), str)
            or not _SHA.fullmatch(head["sha"])
            or value.get("state") != "open"
        ):
            raise GitHubPublicationError("pull_request_identity_invalid")
        return {
            "repository_id": self.policy.repository_id,
            "repository": self.policy.repository,
            "pull_request_number": self.policy.pull_request_number,
            "base_sha": base["sha"],
            "head_sha": head["sha"],
            "state": value["state"],
        }

    def _run(self, run_id: int, attempt: int, timeout_seconds: float) -> dict:
        if not _positive_int(run_id) or not _positive_int(attempt):
            raise GitHubPublicationError("workflow_run_identity_invalid")
        value = self._json(
            "GET",
            self._repo_path(f"/actions/runs/{run_id}/attempts/{attempt}"),
            timeout_seconds,
        )
        repository = value.get("repository") if isinstance(value.get("repository"), dict) else {}
        if (
            not _positive_int(value.get("id"))
            or value.get("id") != run_id
            or not _positive_int(value.get("run_attempt"))
            or value.get("run_attempt") != attempt
            or not _positive_int(value.get("workflow_id"))
            or value.get("workflow_id") not in {self.policy.caller_workflow_id, self.policy.publisher_workflow_id}
            or not _positive_int(repository.get("id"))
            or repository.get("id") != self.policy.repository_id
            or not isinstance(value.get("path"), str)
            or not isinstance(value.get("head_sha"), str)
            or not _SHA.fullmatch(value["head_sha"])
        ):
            raise GitHubPublicationError("workflow_run_identity_mismatch")
        return value

    def _run_identity(self, run: dict, *, publisher: bool) -> RunIdentity:
        expected_id = self.policy.publisher_workflow_id if publisher else self.policy.caller_workflow_id
        expected_path = self.policy.publisher_workflow_path if publisher else self.policy.caller_workflow_path
        expected_ref = self.policy.publisher_workflow_ref if publisher else self.policy.caller_workflow_ref
        expected_sha = self.policy.publisher_workflow_sha if publisher else self.policy.caller_workflow_sha
        if not _positive_int(run.get("workflow_id")) or run.get("workflow_id") != expected_id:
            raise GitHubPublicationError("workflow_id_mismatch")
        raw_path = run.get("path", "")
        actual_path = raw_path.split("@", 1)[0]
        has_ref = "@" in raw_path
        actual_ref = raw_path.split("@", 1)[1] if has_ref else ""
        # GitHub's workflow-run API commonly returns only the bare workflow
        # path.  The ref remains the trusted policy value in RunIdentity; when
        # the API includes a suffix, still require it to agree exactly.
        if actual_path != expected_path or (
            has_ref and actual_ref not in {expected_ref, expected_ref.removeprefix("refs/heads/")}
        ):
            raise GitHubPublicationError("workflow_path_or_ref_mismatch")
        api_sha = run.get("head_sha") if publisher else expected_sha
        if not isinstance(api_sha, str) or not _SHA.fullmatch(api_sha):
            raise GitHubPublicationError("workflow_sha_policy_invalid")
        return RunIdentity(
            repository_id=self.policy.repository_id,
            workflow_id=expected_id,
            workflow_path=expected_path,
            workflow_ref=expected_ref,
            workflow_sha=api_sha,
            run_id=run["id"],
            run_attempt=run["run_attempt"],
        )

    def _verify_harness_reference(self, run: dict) -> None:
        references = run.get("referenced_workflows")
        if not isinstance(references, list):
            raise GitHubPublicationError("called_workflow_provenance_missing")
        for item in references:
            if not isinstance(item, dict):
                continue
            raw_path = item.get("path")
            raw_sha = item.get("sha")
            if not isinstance(raw_path, str) or not isinstance(raw_sha, str):
                continue
            parts = raw_path.split("/", 2)
            if len(parts) != 3 or f"{parts[0]}/{parts[1]}" != self.policy.called_harness_repository:
                continue
            if (
                parts[2].split("@", 1)[0] == self.policy.called_harness_path
                and raw_sha == self.policy.called_harness_sha
            ):
                return
        raise GitHubPublicationError("called_workflow_provenance_mismatch")

    def _validate_upstream_run(self, pr: dict, timeout_seconds: float) -> tuple[dict, RunIdentity]:
        run = self._run(self.policy.upstream_run_id, self.policy.upstream_run_attempt, timeout_seconds)
        identity = self._run_identity(run, publisher=False)
        pull_requests = run.get("pull_requests")
        target_event_without_rows = run.get("event") == "pull_request_target" and pull_requests in (None, [])
        if (not isinstance(pull_requests, list) and not target_event_without_rows) or (
            isinstance(pull_requests, list) and not pull_requests and not target_event_without_rows
        ):
            raise GitHubPublicationError("workflow_run_pr_binding_missing")
        matches = []
        for item in pull_requests if isinstance(pull_requests, list) else []:
            if not isinstance(item, dict) or item.get("number") != self.policy.pull_request_number:
                continue
            base = item.get("base") if isinstance(item.get("base"), dict) else {}
            head = item.get("head") if isinstance(item.get("head"), dict) else {}
            if base.get("sha") == pr["base_sha"] and head.get("sha") == pr["head_sha"]:
                matches.append(item)
        if (
            (len(matches) != 1 and not target_event_without_rows)
            or run.get("event") not in {"pull_request", "pull_request_target"}
            or run.get("status") != "completed"
            or run.get("conclusion") != "success"
        ):
            raise GitHubPublicationError("workflow_run_not_successfully_bound")
        self._verify_harness_reference(run)
        return run, identity

    def _verify_receipt_upstream(self, receipt: AttemptReceipt, timeout_seconds: float) -> None:
        upstream = self._run(
            receipt.upstream_run.run_id,
            receipt.upstream_run.run_attempt,
            self._deadline(timeout_seconds),
        )
        identity = self._run_identity(upstream, publisher=False)
        if identity != receipt.upstream_run:
            raise GitHubPublicationError("receipt_upstream_workflow_mismatch")
        pull_requests = upstream.get("pull_requests")
        target_event_without_rows = upstream.get("event") == "pull_request_target" and pull_requests in (None, [])
        pull_rows = pull_requests if isinstance(pull_requests, list) else []
        receipt_matches = [
            item
            for item in pull_rows
            if isinstance(item, dict)
            and item.get("number") == receipt.slot.pull_request_number
            and isinstance(item.get("base"), dict)
            and isinstance(item.get("head"), dict)
            and item["head"].get("sha") == receipt.slot.head_sha
        ] if isinstance(pull_requests, list) else []
        if (not isinstance(pull_requests, list) and not target_event_without_rows) or (
            not target_event_without_rows and len(receipt_matches) != 1
        ):
            raise GitHubPublicationError("receipt_upstream_pr_mismatch")
        if (
            upstream.get("event") not in {"pull_request", "pull_request_target"}
            or upstream.get("status") != "completed"
            or upstream.get("conclusion") != "success"
        ):
            raise GitHubPublicationError("receipt_upstream_run_unsuccessful")

    def _artifact_metadata(self, artifact: dict, *, expected_name: str, run_id: int | None = None) -> dict:
        if (
            not _positive_int(artifact.get("id"))
            or artifact.get("name") != expected_name
            or isinstance(artifact.get("size_in_bytes"), bool)
            or not isinstance(artifact.get("size_in_bytes"), int)
            or artifact["size_in_bytes"] < 22
            or not isinstance(artifact.get("digest"), str)
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", artifact["digest"])
            or artifact.get("expired") is not False
        ):
            raise GitHubPublicationError("artifact_metadata_invalid_or_expired")
        if run_id is not None:
            workflow_run = artifact.get("workflow_run") if isinstance(artifact.get("workflow_run"), dict) else {}
            if workflow_run.get("id") != run_id or workflow_run.get("repository_id") != self.policy.repository_id:
                raise GitHubPublicationError("artifact_run_binding_invalid")
        return artifact

    def _download_artifact(self, artifact: dict, timeout_seconds: float, cap: int) -> DownloadedArtifact:
        artifact = self._artifact_metadata(artifact, expected_name=artifact.get("name", ""))
        if artifact["size_in_bytes"] > cap:
            raise GitHubPublicationError("artifact_size_limit_exceeded")
        artifact_id = artifact["id"]
        response = self._request(
            "GET",
            self._repo_path(f"/actions/artifacts/{artifact_id}/zip"),
            timeout_seconds,
            allow_redirect=True,
        )
        if response.status != 302:
            raise GitHubPublicationError("artifact_download_redirect_missing")
        redirect = response.headers.get("location")
        parsed = urllib.parse.urlsplit(redirect or "")
        allowed = {host.lower() for host in self.policy.artifact_redirect_hosts}
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.hostname.lower() not in allowed
            or parsed.username
            or parsed.password
            or not parsed.query
            or parsed.fragment
        ):
            raise GitHubPublicationError("artifact_download_location_untrusted")
        remaining = self._deadline(timeout_seconds)
        if remaining <= 0:
            raise GitHubPublicationError("deadline_exhausted")
        downloaded = self.transport.download(redirect, timeout_seconds=remaining, max_response_bytes=cap)
        if downloaded.status != 200 or len(downloaded.body) > cap:
            raise GitHubPublicationError("artifact_download_failed")
        digest = hashlib.sha256(downloaded.body).hexdigest()
        if artifact["digest"] != f"sha256:{digest}":
            raise GitHubPublicationError("artifact_transport_digest_mismatch")
        return DownloadedArtifact(artifact, downloaded.body, digest)

    def _list_named_artifacts(self, name: str, limits: ScanLimits, max_items: int) -> tuple[list[dict], bool]:
        items = []
        total_count = None
        for page in range(1, limits.max_pages + 1):
            query = urllib.parse.urlencode({"name": name, "per_page": 100, "page": page})
            value = self._json("GET", self._repo_path(f"/actions/artifacts?{query}"), limits.deadline_seconds)
            artifacts = value.get("artifacts")
            count = value.get("total_count")
            if (
                not isinstance(artifacts, list)
                or isinstance(count, bool)
                or not isinstance(count, int)
                or count < 0
                or (total_count is not None and count != total_count)
            ):
                raise GitHubPublicationError("artifact_listing_invalid")
            total_count = count
            if len(artifacts) > 100:
                raise GitHubPublicationError("artifact_page_limit_exceeded")
            items.extend(artifacts)
            if len(items) > max_items:
                return items[:max_items], False
            if len(items) >= total_count:
                return items, True
            if len(artifacts) < 100:
                return items, False
        return items, total_count == len(items)

    def _list_run_artifacts(self, run_id: int, artifact_name: str | None, timeout_seconds: float) -> list[dict]:
        params = {"per_page": 100, "page": 1}
        if artifact_name is not None:
            params["name"] = artifact_name
        query = urllib.parse.urlencode(params)
        value = self._json("GET", self._repo_path(f"/actions/runs/{run_id}/artifacts?{query}"), timeout_seconds)
        artifacts = value.get("artifacts")
        count = value.get("total_count")
        if (
            not isinstance(artifacts, list)
            or isinstance(count, bool)
            or not isinstance(count, int)
            or count != len(artifacts)
        ):
            raise GitHubPublicationError("artifact_listing_invalid")
        return artifacts

    def _publisher_runs(self, slot: EffectSlot, limits: ScanLimits) -> tuple[list[dict], int, bool]:
        """Enumerate publisher runs, then bind each one through receipt history.

        An artifact listing cannot establish that a receipt was never created:
        artifacts may expire or be deleted. Every run returned by this trusted
        workflow/event query (not filtered by the reviewed PR head) therefore
        has to resolve to an attempt receipt. `workflow_run` executes against
        the publisher workflow's default-branch SHA. A run-history total beyond
        the supplied cap is incomplete, never an apparently empty history.
        """
        runs: list[dict] = []
        total_count: int | None = None
        query_base = {"event": "workflow_run", "per_page": 100}
        for page in range(1, limits.max_pages + 1):
            query = urllib.parse.urlencode({**query_base, "page": page})
            value = self._json(
                "GET",
                self._repo_path(f"/actions/workflows/{self.policy.publisher_workflow_id}/runs?{query}"),
                limits.deadline_seconds,
            )
            batch = value.get("workflow_runs")
            count = value.get("total_count")
            if (
                not isinstance(batch, list)
                or isinstance(count, bool)
                or not isinstance(count, int)
                or count < 0
                or (total_count is not None and count != total_count)
                or len(batch) > 100
            ):
                raise GitHubPublicationError("publisher_run_listing_invalid")
            total_count = count
            for item in batch:
                if not isinstance(item, dict):
                    raise GitHubPublicationError("publisher_run_record_invalid")
                # A workflow_run event executes on the publisher workflow's
                # default-branch SHA, not the reviewed PR head. Enumerate the
                # workflow's runs without a PR-head filter, then bind each run
                # through its immutable pre-POST receipt and upstream run.
                if (
                    not _positive_int(item.get("id"))
                    or not _positive_int(item.get("run_attempt"))
                    or not _positive_int(item.get("workflow_id"))
                    or item.get("workflow_id") != self.policy.publisher_workflow_id
                    or not isinstance(item.get("head_sha"), str)
                    or not _SHA.fullmatch(item.get("head_sha", ""))
                    or item.get("event") != "workflow_run"
                ):
                    raise GitHubPublicationError("publisher_run_identity_mismatch")
                repository = item.get("repository")
                if (
                    not isinstance(repository, dict)
                    or not _positive_int(repository.get("id"))
                    or repository.get("id") != slot.repository_id
                ):
                    raise GitHubPublicationError("publisher_run_repository_mismatch")
                runs.append(item)
                if len(runs) > limits.max_runs:
                    return runs[: limits.max_runs], len(runs), False
            if total_count is not None and page * 100 >= total_count:
                return runs, len(runs), True
            if len(batch) < 100:
                return runs, len(runs), total_count == (page - 1) * 100 + len(batch)
        return runs, len(runs), total_count is not None and limits.max_pages * 100 >= total_count

    def _receipt_for_publisher_run(
        self,
        slot: EffectSlot,
        run_record: dict,
        timeout_seconds: float,
    ) -> AttemptReceipt | None:
        run_id = run_record["id"]
        attempt = run_record["run_attempt"]
        is_current = run_id == self.policy.publisher_run_id and attempt == self.policy.publisher_run_attempt
        if attempt != 1:
            # GitHub's run-artifacts endpoint does not expose a documented
            # per-attempt history contract. Refuse to infer that overwritten
            # artifacts from earlier rerun attempts were absent.
            raise GitHubPublicationError("publisher_rerun_history_unavailable")
        status = run_record.get("status")
        if not is_current and status != "completed":
            raise GitHubPublicationError("publisher_run_still_in_progress")
        if status == "completed" and run_record.get("conclusion") not in {
            "success",
            "failure",
            "cancelled",
            "timed_out",
            "action_required",
            "stale",
            "startup_failure",
            "neutral",
            "skipped",
        }:
            raise GitHubPublicationError("publisher_run_conclusion_unknown")
        full_run = self._run(run_id, attempt, self._deadline(timeout_seconds))
        identity = self._run_identity(full_run, publisher=True)
        if (
            identity.run_id != run_id
            or identity.run_attempt != attempt
            or full_run.get("event") != "workflow_run"
            or full_run.get("head_sha") != run_record.get("head_sha")
        ):
            raise GitHubPublicationError("publisher_run_attempt_mismatch")
        if is_current and identity.workflow_sha != self.policy.publisher_workflow_sha:
            raise GitHubPublicationError("current_publisher_workflow_sha_mismatch")
        artifacts = self._list_run_artifacts(run_id, None, self._deadline(timeout_seconds))
        prefix = re.escape(self.policy.receipt_artifact_prefix)
        receipt_name = re.compile(rf"{prefix}-([1-9][0-9]*)-([0-9a-f]{{40}}|[0-9a-f]{{64}})\Z")
        candidates = [
            item for item in artifacts if isinstance(item, dict) and receipt_name.fullmatch(item.get("name", ""))
        ]
        if is_current and not candidates:
            return None
        if len(candidates) != 1:
            raise GitHubPublicationError("publisher_receipt_missing_or_ambiguous")
        artifact_name = candidates[0].get("name")
        artifacts = candidates
        metadata = self._artifact_metadata(artifacts[0], expected_name=artifact_name, run_id=run_id)
        workflow_run = metadata.get("workflow_run")
        if not isinstance(workflow_run, dict) or workflow_run.get("run_attempt", 1) != attempt:
            raise GitHubPublicationError("publisher_receipt_attempt_mismatch")
        if not _utc_future(metadata.get("expires_at")):
            raise GitHubPublicationError("publisher_receipt_expired")
        if metadata["size_in_bytes"] > self.policy.max_receipt_archive_bytes:
            raise GitHubPublicationError("publisher_receipt_too_large")
        downloaded = self._download_artifact(
            metadata, self._deadline(timeout_seconds), self.policy.max_receipt_archive_bytes
        )
        receipt = AttemptReceipt.from_bytes(_read_receipt_archive(downloaded.archive))
        if receipt.publisher_run != identity:
            raise GitHubPublicationError("publisher_receipt_binding_mismatch")
        expected_name = self.policy.receipt_artifact_name(receipt.slot)
        if artifact_name != expected_name or (is_current and receipt.slot != slot):
            raise GitHubPublicationError("publisher_receipt_name_or_slot_mismatch")
        self._verify_receipt_upstream(receipt, self._deadline(timeout_seconds))
        return receipt

    def admit(self, result: dict, config: dict, limits: ScanLimits) -> PublicationAdmission:
        """Build a publication capability from current PR, protected runs and exact artifact bytes."""
        try:
            if not self._limits_within_adapter_caps(limits):
                raise GitHubPublicationError("publication_limits_invalid")
            self._start_deadline(limits.deadline_seconds)
            if not isinstance(result, dict):
                raise GitHubPublicationError("review_result_invalid")
            pr = self._pull(limits.deadline_seconds)
            if (
                result.get("repository") != pr["repository"]
                or result.get("pull_request_number") != pr["pull_request_number"]
                or result.get("base_sha") != pr["base_sha"]
                or result.get("head_sha") != pr["head_sha"]
            ):
                raise GitHubPublicationError("review_result_target_stale_or_mismatched")
            upstream, upstream_identity = self._validate_upstream_run(pr, self._deadline(limits.deadline_seconds))
            current_run = self._run(
                self.policy.publisher_run_id,
                self.policy.publisher_run_attempt,
                self._deadline(limits.deadline_seconds),
            )
            publisher_identity = self._run_identity(current_run, publisher=True)
            if (
                publisher_identity.workflow_sha != self.policy.publisher_workflow_sha
                or current_run.get("event") != "workflow_run"
                or current_run.get("status") not in {"in_progress", "completed"}
            ):
                raise GitHubPublicationError("publisher_run_state_invalid")
            artifact_name = self.policy.result_artifact_name
            candidates = self._list_run_artifacts(
                self.policy.upstream_run_id,
                artifact_name,
                self._deadline(limits.deadline_seconds),
            )
            if len(candidates) != 1:
                raise GitHubPublicationError("result_artifact_missing_or_ambiguous")
            artifact = self._artifact_metadata(
                candidates[0], expected_name=artifact_name, run_id=self.policy.upstream_run_id
            )
            if artifact["size_in_bytes"] > self.policy.max_bundle_bytes:
                raise GitHubPublicationError("result_artifact_too_large")
            artifact_run = artifact.get("workflow_run", {})
            if artifact_run.get("head_sha") != upstream.get("head_sha"):
                raise GitHubPublicationError("result_artifact_head_binding_invalid")
            downloaded = self._download_artifact(
                artifact,
                self._deadline(limits.deadline_seconds),
                self.policy.max_bundle_bytes,
            )
            expected = ArtifactIdentity(
                repository_id=self.policy.repository_id,
                repository=self.policy.repository,
                pull_request_number=self.policy.pull_request_number,
                base_sha=pr["base_sha"],
                head_sha=pr["head_sha"],
                upstream_run_id=self.policy.upstream_run_id,
                upstream_run_attempt=self.policy.upstream_run_attempt,
                caller_workflow_id=self.policy.caller_workflow_id,
                caller_workflow_path=self.policy.caller_workflow_path,
                caller_workflow_ref=self.policy.caller_workflow_ref,
                caller_workflow_sha=self.policy.caller_workflow_sha,
                called_harness_repository=self.policy.called_harness_repository,
                called_harness_path=self.policy.called_harness_path,
                called_harness_sha=self.policy.called_harness_sha,
                profile_version=self.policy.profile_version,
                profile_sha256=self.policy.profile_sha256,
                provider_configuration_identity=self.policy.provider_configuration_identity,
                contract_versions=self.policy.contract_versions,
            )
            trusted_attestation = self.attestation_identity or AttestationIdentity(
                issuer="github-actions-api-bound",
                repository_id=self.policy.repository_id,
                repository=self.policy.repository,
                workflow_id=self.policy.caller_workflow_id,
                workflow_path=self.policy.caller_workflow_path,
                workflow_ref=self.policy.caller_workflow_ref,
                workflow_sha=self.policy.caller_workflow_sha,
                run_id=self.policy.upstream_run_id,
                run_attempt=self.policy.upstream_run_attempt,
                called_harness_repository=self.policy.called_harness_repository,
                called_harness_path=self.policy.called_harness_path,
                called_harness_sha=self.policy.called_harness_sha,
            )
            receipt = intake_artifact_bundle(
                io.BytesIO(downloaded.archive),
                expected,
                ArtifactTransportDigest(
                    source="github_artifact_api",
                    subject="downloaded_zip_bytes",
                    algorithm="sha256",
                    hex_digest=downloaded.archive_sha256,
                ),
                trusted_attestation_identity=trusted_attestation,
                attestation_verifier=self.attestation_verifier,
                limits=IntakeLimits(max_archive_bytes=self.policy.max_bundle_bytes),
            )
            if receipt.manifest.get("review_run_id") != result.get("run_id"):
                raise GitHubPublicationError("result_artifact_run_binding_invalid")
            if _canonical_hash(receipt.result) != _canonical_hash(result):
                raise GitHubPublicationError("result_artifact_content_mismatch")
            if (
                self.policy.artifact_trust_mode is ArtifactTrustMode.SIGNED_ATTESTATION
                and receipt.attestation_state.value != "VERIFIED"
            ):
                raise GitHubPublicationError("result_artifact_attestation_unavailable")
            identity = self._identity
            if identity is None or identity.actor_login != self.policy.allowed_actor_login:
                raise GitHubPublicationError("publisher_identity_unavailable")
            body = result.get("rendered_review")
            if not isinstance(body, str):
                raise GitHubPublicationError("canonical_review_missing")
            body_hash = hashlib.sha256(body.encode("utf-8")).hexdigest()
            slot = EffectSlot(
                self.policy.repository_id,
                self.policy.repository,
                self.policy.pull_request_number,
                pr["head_sha"],
            )
            disposition = result.get("disposition")
            effect_key = _stateless_effect_key(slot, result["result_hash"], body_hash, disposition)
            concurrency_group = (
                f"pr-review-publish-{self.policy.repository_id}-{self.policy.pull_request_number}"
                if self.policy.concurrency_scope == "pull_request"
                else f"pr-review-publish-{self.policy.repository_id}"
            )
            return PublicationAdmission(
                slot=slot,
                base_sha=pr["base_sha"],
                effect_key=effect_key,
                result_hash=result["result_hash"],
                review_body_hash=body_hash,
                disposition=disposition,
                review_event="COMMENT" if disposition == "INCOMPLETE" else disposition,
                actor_login=identity.actor_login,
                profile_hash=self.policy.profile_sha256,
                policy_hash=_canonical_hash(config),
                source_artifact_sha256=receipt.archive_sha256,
                admission_evidence_hash=_canonical_hash(
                    {
                        "pr": pr,
                        "upstream_run": upstream_identity.to_dict(),
                        "publisher_run": publisher_identity.to_dict(),
                        "artifact_id": artifact["id"],
                        "artifact_archive_sha256": receipt.archive_sha256,
                        "artifact_result_sha256": receipt.result_sha256,
                        "concurrency_scope": self.policy.concurrency_scope,
                        "concurrency_group": concurrency_group,
                        **(
                            {"credential_provenance": self.policy.credential_provenance}
                            if self.policy.credential_provenance is not None
                            else {}
                        ),
                    }
                ),
                upstream_run=upstream_identity,
                publisher_run=publisher_identity,
                concurrency_group=concurrency_group,
                concurrency_contract_hash=_canonical_hash(
                    {"scope": self.policy.concurrency_scope, "group": concurrency_group, "cancel": False}
                ),
                concurrency_scope=self.policy.concurrency_scope,
                credential_provenance=self.policy.credential_provenance,
            )
        except GitHubPublicationError as exc:
            raise RuntimeError(exc.code) from None
        except Exception as exc:
            # No third-party response or raw artifact text is exposed.
            code = getattr(exc, "code", None)
            raise RuntimeError(code if isinstance(code, str) else "publication_admission_unavailable") from None

    def _review_pages(self, slot: EffectSlot, limits: ScanLimits) -> tuple[list[ReviewObservation], int, bool]:
        observations = []
        scanned = 0
        for page in range(1, limits.max_pages + 1):
            query = urllib.parse.urlencode({"per_page": 100, "page": page})
            reviews = self._array(
                self._repo_path(f"/pulls/{slot.pull_request_number}/reviews?{query}"),
                limits.deadline_seconds,
            )
            if len(reviews) > 100:
                raise GitHubPublicationError("review_page_limit_exceeded")
            scanned += len(reviews)
            if scanned > limits.max_reviews:
                return observations, scanned, False
            for value in reviews:
                if not isinstance(value, dict):
                    raise GitHubPublicationError("review_record_invalid")
                body = value.get("body")
                if body is None:
                    body = ""
                if not isinstance(body, str):
                    raise GitHubPublicationError("review_body_invalid")
                marker_line = body.rsplit("\n\n", 1)[-1] if "\n\n" in body else ""
                marker = _MARKER.fullmatch(marker_line)
                if not marker:
                    continue
                if body.count("<!-- pr-review-harness:") != 1:
                    raise GitHubPublicationError("review_marker_ambiguous")
                user = value.get("user") if isinstance(value.get("user"), dict) else {}
                commit_id = value.get("commit_id")
                if not isinstance(commit_id, str) or not _SHA.fullmatch(commit_id):
                    raise GitHubPublicationError("review_commit_invalid")
                if commit_id != slot.head_sha:
                    continue
                state = value.get("state")
                review_state = {
                    "APPROVED": ReviewState.APPROVED,
                    "CHANGES_REQUESTED": ReviewState.CHANGES_REQUESTED,
                    "COMMENTED": ReviewState.COMMENTED,
                }.get(state)
                login = user.get("login")
                review_id = value.get("id")
                if review_state is None or not isinstance(login, str) or not _LOGIN.fullmatch(login):
                    raise GitHubPublicationError("review_identity_invalid")
                canonical_body = body[: -(len(marker_line) + 2)]
                observations.append(
                    ReviewObservation(
                        slot=slot,
                        effect_key=marker.group(1),
                        review_body_hash=hashlib.sha256(canonical_body.encode("utf-8")).hexdigest(),
                        actor_login=login,
                        state=review_state,
                        review_id=review_id,
                    )
                )
            if len(reviews) < 100:
                return observations, scanned, True
        return observations, scanned, False

    def _receipt_history(self, slot: EffectSlot, limits: ScanLimits) -> tuple[list[AttemptReceipt], int, bool]:
        runs, scanned, complete = self._publisher_runs(slot, limits)
        if not complete:
            return [], scanned, False
        receipts = []
        for run in runs:
            try:
                receipt = self._receipt_for_publisher_run(slot, run, limits.deadline_seconds)
                if receipt is not None and receipt.slot == slot:
                    receipts.append(receipt)
            except Exception:
                # Missing/expired/deleted artifact evidence and incomplete
                # attempt history are unknown; they never prove no prior POST.
                return receipts, scanned, False
        return receipts, scanned, True

    def scan(self, slot: EffectSlot, limits: ScanLimits) -> HistoryScan:
        try:
            if not self._limits_within_adapter_caps(limits):
                return HistoryScan(HistoryStatus.UNAVAILABLE, reason_code="history_limits_invalid")
            self._start_deadline(limits.deadline_seconds)
            if slot.repository_id != self.policy.repository_id or slot.repository != self.policy.repository:
                return HistoryScan(HistoryStatus.UNAVAILABLE, reason_code="history_target_mismatch")
            reviews, review_count, reviews_complete = self._review_pages(slot, limits)
            receipts, artifact_count, receipts_complete = self._receipt_history(slot, limits)
            if self._clock() >= self._deadline_at:
                return HistoryScan(HistoryStatus.UNAVAILABLE, reason_code="history_deadline_exhausted")
            if not reviews_complete:
                return HistoryScan(
                    HistoryStatus.INCOMPLETE,
                    tuple(receipts),
                    tuple(reviews),
                    "review_history_limit",
                    scanned_pages=min(limits.max_pages, math.ceil(review_count / 100)),
                )
            if not receipts_complete:
                return HistoryScan(
                    HistoryStatus.INCOMPLETE,
                    tuple(receipts),
                    tuple(reviews),
                    "receipt_history_incomplete",
                    scanned_runs=artifact_count,
                )
            return HistoryScan(
                HistoryStatus.COMPLETE,
                tuple(receipts),
                tuple(reviews),
                scanned_runs=artifact_count,
                scanned_pages=min(limits.max_pages, math.ceil(review_count / 100)),
            )
        except GitHubPublicationError:
            return HistoryScan(HistoryStatus.UNAVAILABLE, reason_code="github_history_unavailable")
        except Exception:
            return HistoryScan(HistoryStatus.UNAVAILABLE, reason_code="github_history_invalid")

    def persist(self, receipt: AttemptReceipt, limits: ScanLimits) -> ReceiptPersistence:
        if not self._limits_within_adapter_caps(limits):
            return ReceiptPersistence(ReceiptPersistenceStatus.UNKNOWN, reason_code="receipt_limits_invalid")
        try:
            self._start_deadline(limits.deadline_seconds)
        except GitHubPublicationError:
            return ReceiptPersistence(ReceiptPersistenceStatus.UNKNOWN, reason_code="receipt_deadline_invalid")
        if self.artifact_uploader is None:
            return ReceiptPersistence(ReceiptPersistenceStatus.UNKNOWN, reason_code="artifact_uploader_unavailable")
        try:
            self._credential(limits.deadline_seconds, {"actions": "read", "pull_requests": "read"})
            if (
                receipt.publisher_run.run_id != self.policy.publisher_run_id
                or receipt.publisher_run.run_attempt != self.policy.publisher_run_attempt
            ):
                return ReceiptPersistence(ReceiptPersistenceStatus.REJECTED, reason_code="publisher_run_mismatch")
            if (
                receipt.publisher_run.repository_id != self.policy.repository_id
                or receipt.publisher_run.workflow_id != self.policy.publisher_workflow_id
                or receipt.publisher_run.workflow_path != self.policy.publisher_workflow_path
                or receipt.publisher_run.workflow_ref != self.policy.publisher_workflow_ref
                or receipt.publisher_run.workflow_sha != self.policy.publisher_workflow_sha
            ):
                return ReceiptPersistence(ReceiptPersistenceStatus.REJECTED, reason_code="publisher_identity_mismatch")
            pre_upload_run = self._run(
                self.policy.publisher_run_id,
                self.policy.publisher_run_attempt,
                self._deadline(limits.deadline_seconds),
            )
            pre_upload_identity = self._run_identity(pre_upload_run, publisher=True)
            if (
                pre_upload_identity != receipt.publisher_run
                or pre_upload_run.get("event") != "workflow_run"
                or pre_upload_run.get("status") != "in_progress"
            ):
                return ReceiptPersistence(ReceiptPersistenceStatus.REJECTED, reason_code="publisher_identity_mismatch")
            upload = self.artifact_uploader.upload(
                run_id=self.policy.publisher_run_id,
                artifact_name=self.policy.receipt_artifact_name(receipt.slot),
                filename="attempt-receipt.json",
                content=receipt.to_bytes(),
                timeout_seconds=self._deadline(limits.deadline_seconds),
            )
            if not isinstance(upload, ArtifactUploadResult) or upload.status != "UPLOADED":
                status = (
                    ReceiptPersistenceStatus.REJECTED
                    if isinstance(upload, ArtifactUploadResult) and upload.status == "FAILED"
                    else ReceiptPersistenceStatus.UNKNOWN
                )
                return ReceiptPersistence(status, reason_code="artifact_upload_unconfirmed")
            artifacts = self._list_run_artifacts(
                self.policy.publisher_run_id,
                self.policy.receipt_artifact_name(receipt.slot),
                self._deadline(limits.deadline_seconds),
            )
            matches = [item for item in artifacts if item.get("id") == upload.artifact_id]
            if len(matches) != 1:
                return ReceiptPersistence(ReceiptPersistenceStatus.UNKNOWN, reason_code="artifact_api_ack_missing")
            metadata = self._artifact_metadata(
                matches[0],
                expected_name=self.policy.receipt_artifact_name(receipt.slot),
                run_id=self.policy.publisher_run_id,
            )
            downloaded = self._download_artifact(
                metadata, self._deadline(limits.deadline_seconds), self.policy.max_receipt_archive_bytes
            )
            verified_content = _read_receipt_archive(downloaded.archive)
            if verified_content != receipt.to_bytes() or not _utc_future(metadata.get("expires_at")):
                return ReceiptPersistence(ReceiptPersistenceStatus.UNKNOWN, reason_code="artifact_content_mismatch")
            run = self._run(self.policy.publisher_run_id, self.policy.publisher_run_attempt, limits.deadline_seconds)
            publisher_run = self._run_identity(run, publisher=True)
            if publisher_run != receipt.publisher_run:
                return ReceiptPersistence(ReceiptPersistenceStatus.UNKNOWN, reason_code="publisher_identity_changed")
            acknowledgement = ReceiptAcknowledgement(
                artifact_id=metadata["id"],
                publisher_run=publisher_run,
                archive_sha256=downloaded.archive_sha256,
                receipt_sha256=hashlib.sha256(verified_content).hexdigest(),
                expires_at=metadata["expires_at"],
            )
            return ReceiptPersistence(ReceiptPersistenceStatus.ACKNOWLEDGED, acknowledgement=acknowledgement)
        except Exception:
            return ReceiptPersistence(ReceiptPersistenceStatus.UNKNOWN, reason_code="artifact_persistence_unknown")

    def fresh_head(self, timeout_seconds: float) -> str:
        self._start_deadline(timeout_seconds)
        return self._pull(timeout_seconds)["head_sha"]

    def submit_review(self, payload: dict, effect_key: str, timeout_seconds: float) -> ReviewObservation:
        self._start_deadline(timeout_seconds)
        if not isinstance(payload, dict) or payload.get("event") not in {"APPROVE", "REQUEST_CHANGES", "COMMENT"}:
            raise GitHubPublicationError("review_payload_invalid")
        slot = EffectSlot(
            self.policy.repository_id,
            self.policy.repository,
            self.policy.pull_request_number,
            payload.get("commit_id"),
        )
        if not _EFFECT_ARTIFACT.fullmatch(self.policy.receipt_artifact_name(slot)):
            raise GitHubPublicationError("review_slot_invalid")
        marker = f"<!-- pr-review-harness:{effect_key} -->"
        body = payload.get("body")
        if not isinstance(body, str) or not body.endswith(marker) or body.count("<!-- pr-review-harness:") != 1:
            raise GitHubPublicationError("review_marker_invalid")
        if len(body.encode("utf-8")) > 60_000:
            raise GitHubPublicationError("review_body_limit_exceeded")
        response = self._json(
            "POST",
            self._repo_path(f"/pulls/{self.policy.pull_request_number}/reviews"),
            timeout_seconds,
            {"commit_id": payload["commit_id"], "event": payload["event"], "body": body},
        )
        user = response.get("user") if isinstance(response.get("user"), dict) else {}
        if (
            response.get("commit_id") != payload["commit_id"]
            or user.get("login") != self.policy.allowed_actor_login
            or not _positive_int(response.get("id"))
        ):
            raise GitHubPublicationError("review_post_response_identity_mismatch")
        expected_state = {
            "APPROVE": ReviewState.APPROVED,
            "REQUEST_CHANGES": ReviewState.CHANGES_REQUESTED,
            "COMMENT": ReviewState.COMMENTED,
        }[payload["event"]]
        review_state = {
            "APPROVED": ReviewState.APPROVED,
            "CHANGES_REQUESTED": ReviewState.CHANGES_REQUESTED,
            "COMMENTED": ReviewState.COMMENTED,
        }.get(response.get("state"))
        if review_state is not expected_state or response.get("body") != body:
            raise GitHubPublicationError("review_post_response_content_mismatch")
        response_body = response["body"]
        if not isinstance(response_body, str) or response_body.count("<!-- pr-review-harness:") != 1:
            raise GitHubPublicationError("review_post_response_marker_mismatch")
        response_marker = response_body.rsplit("\n\n", 1)[-1]
        if _MARKER.fullmatch(response_marker) is None or response_marker != marker:
            raise GitHubPublicationError("review_post_response_marker_mismatch")
        canonical_body = response_body[: -(len(marker) + 2)]
        return ReviewObservation(
            slot=slot,
            effect_key=effect_key,
            review_body_hash=hashlib.sha256(canonical_body.encode("utf-8")).hexdigest(),
            actor_login=user["login"],
            state=review_state,
            review_id=response["id"],
        )

    def read_live_identity(self, timeout_seconds: float) -> VerifiedPublisherIdentity:
        """Expose typed identity only after the injected provider has verified it."""
        credential = self._credential(timeout_seconds, {"actions": "read", "pull_requests": "read"})
        return credential.identity


def _read_receipt_archive(archive_bytes: bytes) -> bytes:
    if not isinstance(archive_bytes, bytes) or not 22 <= len(archive_bytes) <= _MAX_RECEIPT_ARCHIVE_BYTES:
        raise GitHubPublicationError("receipt_archive_invalid")
    try:
        archive = zipfile.ZipFile(io.BytesIO(archive_bytes), "r")
    except (zipfile.BadZipFile, OSError, ValueError):
        raise GitHubPublicationError("receipt_archive_invalid") from None
    with archive:
        members = archive.infolist()
        if len(members) != 1:
            raise GitHubPublicationError("receipt_archive_members_invalid")
        member = members[0]
        mode = (member.external_attr >> 16) & 0xFFFF
        if (
            member.filename != "attempt-receipt.json"
            or member.is_dir()
            or member.file_size < 1
            or member.file_size > _MAX_RECEIPT_BYTES
            or member.compress_size < 1
            or member.file_size / member.compress_size > 100
            or (mode & 0o170000) == 0o120000
        ):
            raise GitHubPublicationError("receipt_archive_member_invalid")
        try:
            content = archive.read(member)
        except (OSError, RuntimeError, zipfile.BadZipFile):
            raise GitHubPublicationError("receipt_archive_read_failed") from None
        if len(content) != member.file_size:
            raise GitHubPublicationError("receipt_archive_length_invalid")
        AttemptReceipt.from_bytes(content)
        return content


def _parse_utc(value: object, code: str) -> datetime:
    if not isinstance(value, str) or not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)", value
    ):
        raise GitHubPublicationError(code)
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
    except ValueError:
        raise GitHubPublicationError(code) from None
    if parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise GitHubPublicationError(code)
    return parsed.astimezone(timezone.utc)


def _utc_future(value: object) -> bool:
    try:
        return _parse_utc(value, "artifact_expiry_invalid") > datetime.now(timezone.utc)
    except GitHubPublicationError:
        return False


def _positive_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _unique_pairs(pairs: list[tuple[str, object]]) -> dict:
    value = {}
    for key, child in pairs:
        if key in value:
            raise ValueError("duplicate key")
        value[key] = child
    return value


def _parse_api_json(raw: bytes) -> object:
    if not isinstance(raw, bytes) or len(raw) > _MAX_API_BYTES:
        raise ValueError("API JSON exceeds byte bound")
    depth = 0
    tokens = 0
    in_string = False
    escaped = False
    for byte in raw:
        if in_string:
            if escaped:
                escaped = False
            elif byte == 0x5C:
                escaped = True
            elif byte == 0x22:
                in_string = False
            continue
        if byte == 0x22:
            in_string = True
            tokens += 1
        elif byte in (0x7B, 0x5B):
            depth += 1
            tokens += 1
            if depth > _API_JSON_MAX_DEPTH:
                raise ValueError("API JSON nesting exceeds bound")
        elif byte in (0x7D, 0x5D):
            depth -= 1
            tokens += 1
            if depth < 0:
                raise ValueError("API JSON structure invalid")
        elif byte in (0x2C, 0x3A):
            tokens += 1
        if tokens > _API_JSON_MAX_TOKENS:
            raise ValueError("API JSON structure exceeds bound")
    if in_string or depth != 0:
        raise ValueError("API JSON structure invalid")

    def parse_int(text: str) -> int:
        if len(text.lstrip("-")) > 20:
            raise ValueError("API integer exceeds bound")
        return int(text)

    def parse_float(text: str) -> float:
        value = float(text)
        if not math.isfinite(value):
            raise ValueError("API nonfinite number")
        return value

    try:
        return json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_unique_pairs,
            parse_constant=_reject_constant,
            parse_int=parse_int,
            parse_float=parse_float,
        )
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ValueError("API JSON invalid") from None


def _reject_constant(_value: str):
    raise ValueError("nonfinite JSON value")
