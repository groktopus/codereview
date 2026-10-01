"""Compose the protected, disabled-by-default GitHub review writer runtime.

This entrypoint accepts only a bounded policy file checked out with the
protected publisher workflow. Pull-request artifacts supply the review result,
never policy, identity, or an enablement decision.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import stat
import subprocess
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping
from urllib.parse import quote, urlsplit

from .actions_publication import (
    ArtifactTrustMode,
    GitHubActionsPublicationAdapter,
    GitHubHTTPTransport,
    GitHubPublicationError,
    GitHubPublicationPolicy,
    UrllibGitHubTransport,
)
from .actions_runtime import OfficialActionsArtifactUploader
from .artifact_intake import (
    MANIFEST_FILENAME,
    ArtifactIdentity,
    ArtifactTransportDigest,
    AttestationIdentity,
    IntakeLimits,
    intake_artifact_bundle,
)
from .github_app_canary import (
    CanaryLimits,
    ProtectedCanaryRun,
    verify_github_app_identity_canary,
)
from .github_app_credentials import GitHubAppCredentialPolicy, GitHubAppPublisherCredentialProvider
from .publication_receipts import ScanLimits
from .publisher import publish_review_stateless

_POLICY_PATH = Path(".github/pr-review-publisher-policy.json")
_POLICY_MAX_BYTES = 64 * 1024
_EVENT_MAX_BYTES = 256 * 1024
_SHA = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
_WORKFLOW_PATH = re.compile(r"\.github/workflows/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*\.ya?ml\Z")
_PROFILE_HASH = re.compile(r"[0-9a-f]{64}\Z")
_PROVIDER_IDENTITY = re.compile(r"provider-config-sha256:[0-9a-f]{64}\Z")
_CONFIG_KEYS = {
    "schema",
    "enabled",
    "repository",
    "default_branch",
    "publisher_workflow",
    "source_workflow",
    "called_harness",
    "app",
    "profile",
    "publication",
    "limits",
    "artifact_trust_mode",
    "artifact_redirect_hosts",
}


class ProtectedRuntimeError(ValueError):
    """Sanitized fail-closed runtime error."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _reject_constant(_value):
    raise ValueError("nonstandard JSON number")


def _json_object(raw: bytes, *, limit: int, code: str) -> dict[str, object]:
    if not isinstance(raw, bytes) or len(raw) > limit:
        raise ProtectedRuntimeError(code)
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object, parse_constant=_reject_constant)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError):
        raise ProtectedRuntimeError(code) from None
    if not isinstance(value, dict):
        raise ProtectedRuntimeError(code)
    return value


def _read_regular(path: Path, limit: int, code: str) -> bytes:
    try:
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > limit:
            raise ProtectedRuntimeError(code)
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
        with os.fdopen(descriptor, "rb") as source:
            opened = os.fstat(source.fileno())
            if not stat.S_ISREG(opened.st_mode) or opened.st_size > limit:
                raise ProtectedRuntimeError(code)
            raw = source.read(limit + 1)
    except ProtectedRuntimeError:
        raise
    except OSError:
        raise ProtectedRuntimeError(code) from None
    if len(raw) > limit:
        raise ProtectedRuntimeError(code)
    return raw


def _positive_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


@dataclass(frozen=True)
class ProtectedPublicationPolicy:
    """Validated, trusted policy from the protected publisher revision."""

    raw: dict[str, object]

    @classmethod
    def parse(cls, value: dict[str, object]) -> "ProtectedPublicationPolicy":
        if set(value) != _CONFIG_KEYS or value.get("schema") != "pr-review-protected-publication-policy.v1":
            raise ProtectedRuntimeError("protected_policy_schema_invalid")
        if not isinstance(value.get("enabled"), bool):
            raise ProtectedRuntimeError("protected_policy_enablement_invalid")
        repository = value.get("repository")
        if not isinstance(repository, dict) or set(repository) != {"name", "id"}:
            raise ProtectedRuntimeError("protected_policy_repository_invalid")
        if not isinstance(repository.get("name"), str) or not _REPOSITORY.fullmatch(repository["name"]):
            raise ProtectedRuntimeError("protected_policy_repository_invalid")
        if not _positive_int(repository.get("id")):
            raise ProtectedRuntimeError("protected_policy_repository_invalid")
        branch = value.get("default_branch")
        if not isinstance(branch, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", branch):
            raise ProtectedRuntimeError("protected_policy_branch_invalid")
        for key in ("publisher_workflow", "source_workflow"):
            workflow = value.get(key)
            expected_path = ".github/workflows/pr-publish.yml" if key == "publisher_workflow" else None
            if not isinstance(workflow, dict) or set(workflow) != {"id", "path", "ref"}:
                raise ProtectedRuntimeError("protected_policy_workflow_invalid")
            if (
                not _positive_int(workflow.get("id"))
                or not isinstance(workflow.get("path"), str)
                or not _WORKFLOW_PATH.fullmatch(workflow["path"])
                or (expected_path is not None and workflow.get("path") != expected_path)
                or workflow.get("ref") != f"{repository['name']}/{workflow['path']}@refs/heads/{branch}"
            ):
                raise ProtectedRuntimeError("protected_policy_workflow_invalid")
        harness = value.get("called_harness")
        if (
            not isinstance(harness, dict)
            or set(harness) != {"repository", "path", "sha"}
            or not isinstance(harness.get("repository"), str)
            or not _REPOSITORY.fullmatch(harness["repository"])
            or not isinstance(harness.get("path"), str)
            or not _WORKFLOW_PATH.fullmatch(harness["path"])
            or not isinstance(harness.get("sha"), str)
            or not _SHA.fullmatch(harness["sha"])
        ):
            raise ProtectedRuntimeError("protected_policy_harness_invalid")
        app = value.get("app")
        if (
            not isinstance(app, dict)
            or set(app) != {"id", "installation_id", "slug", "actor_login"}
            or not _positive_int(app.get("id"))
            or not _positive_int(app.get("installation_id"))
            or not isinstance(app.get("slug"), str)
            or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,98}[a-z0-9])?", app["slug"])
            or app.get("actor_login") != f"{app['slug']}[bot]"
        ):
            raise ProtectedRuntimeError("protected_policy_app_invalid")
        profile = value.get("profile")
        if (
            not isinstance(profile, dict)
            or set(profile) != {"version", "sha256", "provider_configuration_identity"}
            or not isinstance(profile.get("version"), str)
            or not profile["version"]
            or len(profile["version"]) > 128
            or not isinstance(profile.get("sha256"), str)
            or not _PROFILE_HASH.fullmatch(profile["sha256"])
            or not isinstance(profile.get("provider_configuration_identity"), str)
            or not _PROVIDER_IDENTITY.fullmatch(profile["provider_configuration_identity"])
        ):
            raise ProtectedRuntimeError("protected_policy_profile_invalid")
        publication = value.get("publication")
        if (
            not isinstance(publication, dict)
            or set(publication)
            != {"allowed_dispositions", "max_review_body_bytes", "effect_policy"}
            or publication.get("effect_policy") != "PUBLISH_REVIEW"
            or not isinstance(publication.get("allowed_dispositions"), list)
            or not publication["allowed_dispositions"]
            or any(not isinstance(item, str) for item in publication["allowed_dispositions"])
            or len(set(publication["allowed_dispositions"])) != len(publication["allowed_dispositions"])
            or any(item not in {"COMMENT", "APPROVE", "REQUEST_CHANGES"} for item in publication["allowed_dispositions"])
            or not isinstance(publication.get("max_review_body_bytes"), int)
            or isinstance(publication.get("max_review_body_bytes"), bool)
            or not 1 <= publication["max_review_body_bytes"] <= 60_000
        ):
            raise ProtectedRuntimeError("protected_policy_publication_invalid")
        limits = value.get("limits")
        if (
            not isinstance(limits, dict)
            or set(limits) != {"max_runs", "max_pages", "max_reviews", "deadline_seconds"}
            or any(not _positive_int(limits.get(key)) for key in ("max_runs", "max_pages", "max_reviews"))
            or limits["max_runs"] > 100
            or limits["max_pages"] > 10
            or limits["max_reviews"] > 1000
            or not isinstance(limits.get("deadline_seconds"), (int, float))
            or isinstance(limits.get("deadline_seconds"), bool)
            or not 0 < limits["deadline_seconds"] <= 300
        ):
            raise ProtectedRuntimeError("protected_policy_limits_invalid")
        if value.get("artifact_trust_mode") != "API_BOUND_SHA256":
            raise ProtectedRuntimeError("protected_policy_artifact_trust_invalid")
        hosts = value.get("artifact_redirect_hosts")
        if (
            not isinstance(hosts, list)
            or not hosts
            or len(hosts) > 10
            or any(not isinstance(host, str) or not re.fullmatch(r"[A-Za-z0-9.-]{1,253}", host) for host in hosts)
            or len(set(hosts)) != len(hosts)
        ):
            raise ProtectedRuntimeError("protected_policy_artifact_hosts_invalid")
        return cls(raw=value)

    @property
    def enabled(self) -> bool:
        return self.raw["enabled"] is True

    def app_policy(self) -> GitHubAppCredentialPolicy:
        app = self.raw["app"]
        repo = self.raw["repository"]
        return GitHubAppCredentialPolicy(
            app_id=app["id"],
            installation_id=app["installation_id"],
            repository_id=repo["id"],
            repository=repo["name"],
            app_slug=app["slug"],
            actor_login=app["actor_login"],
        )

    def publication_config(self) -> dict[str, object]:
        return {
            "schema_version": "1.0",
            "enabled": self.enabled,
            "allowed_repositories": [self.raw["repository"]["name"]],
            "allowed_dispositions": list(self.raw["publication"]["allowed_dispositions"]),
            "allowed_profile_versions": [self.raw["profile"]["version"]],
            "allowed_actors": [self.raw["app"]["actor_login"]],
            "max_review_body_bytes": self.raw["publication"]["max_review_body_bytes"],
        }


def _policy_from_workspace(environ: Mapping[str, str]) -> ProtectedPublicationPolicy:
    workspace = environ.get("GITHUB_WORKSPACE")
    if not isinstance(workspace, str) or not workspace or not Path(workspace).is_absolute():
        raise ProtectedRuntimeError("protected_workspace_unavailable")
    root = Path(workspace).resolve(strict=True)
    expected_sha = environ.get("GITHUB_SHA", "")
    if not _SHA.fullmatch(expected_sha):
        raise ProtectedRuntimeError("protected_source_revision_invalid")
    _verify_protected_checkout(root, expected_sha)
    path = root / _POLICY_PATH
    try:
        resolved_path = path.resolve(strict=True)
        resolved_path.relative_to(root)
    except (OSError, ValueError):
        raise ProtectedRuntimeError("protected_policy_path_untrusted") from None
    relative = resolved_path.relative_to(root).as_posix()
    if relative != _POLICY_PATH.as_posix():
        raise ProtectedRuntimeError("protected_policy_path_untrusted")
    raw = _read_regular(path, _POLICY_MAX_BYTES, "protected_policy_unavailable")
    committed = _git_read(root, "show", f"{expected_sha}:{relative}", limit=_POLICY_MAX_BYTES)
    if raw != committed:
        raise ProtectedRuntimeError("protected_policy_source_mismatch")
    return ProtectedPublicationPolicy.parse(
        _json_object(raw, limit=_POLICY_MAX_BYTES, code="protected_policy_invalid")
    )


def _git_read(root: Path, *args: str, limit: int = 4096) -> bytes:
    try:
        completed = subprocess.run(
            ["git", "--no-optional-locks", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", "-C", str(root), *args],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=5,
            check=False,
            env={"PATH": os.defpath, "HOME": str(root), "GIT_CONFIG_NOSYSTEM": "1", "GIT_TERMINAL_PROMPT": "0"},
        )
    except (OSError, subprocess.TimeoutExpired):
        raise ProtectedRuntimeError("protected_source_verification_unavailable") from None
    if completed.returncode != 0 or len(completed.stdout) > limit:
        raise ProtectedRuntimeError("protected_source_verification_unavailable")
    return completed.stdout


def _verify_protected_checkout(root: Path, expected_sha: str) -> None:
    top = _git_read(root, "rev-parse", "--show-toplevel", limit=4096).decode("utf-8", errors="strict").strip()
    head = _git_read(root, "rev-parse", "HEAD", limit=4096).decode("ascii", errors="strict").strip()
    status = _git_read(root, "status", "--porcelain=v1", "--untracked-files=all", limit=64 * 1024)
    if Path(top).resolve(strict=True) != root or head != expected_sha or status:
        raise ProtectedRuntimeError("protected_source_revision_mismatch")


def _workflow_event_parts(
    environ: Mapping[str, str], event_raw: bytes, policy: ProtectedPublicationPolicy
) -> tuple[dict[str, object], tuple[int, str, str] | None]:
    event = _json_object(event_raw, limit=_EVENT_MAX_BYTES, code="workflow_event_invalid")
    repository = event.get("repository")
    upstream = event.get("workflow_run")
    if not isinstance(repository, dict) or not isinstance(upstream, dict):
        raise ProtectedRuntimeError("workflow_event_identity_invalid")
    repo = policy.raw["repository"]
    publisher = policy.raw["publisher_workflow"]
    source = policy.raw["source_workflow"]
    if (
        repository.get("full_name") != repo["name"]
        or repository.get("id") != repo["id"]
        or repository.get("default_branch") != policy.raw["default_branch"]
        or environ.get("GITHUB_REPOSITORY") != repo["name"]
        or environ.get("GITHUB_REF") != f"refs/heads/{policy.raw['default_branch']}"
        or environ.get("GITHUB_WORKFLOW_REF")
        != publisher["ref"]
    ):
        raise ProtectedRuntimeError("protected_workflow_source_mismatch")
    pr_rows = upstream.get("pull_requests")
    claim = None
    if not isinstance(pr_rows, list):
        raise ProtectedRuntimeError("workflow_event_pr_binding_invalid")
    if pr_rows:
        if len(pr_rows) != 1 or not isinstance(pr_rows[0], dict):
            raise ProtectedRuntimeError("workflow_event_pr_binding_missing_or_ambiguous")
        pull = pr_rows[0]
        base = pull.get("base")
        head = pull.get("head")
        if (
            not _positive_int(pull.get("number"))
            or not isinstance(base, dict)
            or not isinstance(head, dict)
            or not isinstance(base.get("sha"), str)
            or not _SHA.fullmatch(base["sha"])
            or not isinstance(head.get("sha"), str)
            or not _SHA.fullmatch(head["sha"])
        ):
            raise ProtectedRuntimeError("workflow_event_pr_binding_invalid")
        claim = (pull["number"], base["sha"], head["sha"])
    source_path = upstream.get("path")
    if isinstance(source_path, str) and "@" in source_path:
        source_path = source_path.split("@", 1)[0]
    if (
        upstream.get("workflow_id") != source["id"]
        or source_path != source["path"]
        or not _positive_int(upstream.get("id"))
        or not _positive_int(upstream.get("run_attempt"))
        or not isinstance(upstream.get("head_sha"), str)
        or not _SHA.fullmatch(upstream["head_sha"])
        or not isinstance(upstream.get("head_branch"), str)
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,127}", upstream["head_branch"])
        or ".." in upstream["head_branch"].split("/")
        or "//" in upstream["head_branch"]
        or upstream.get("event") != "pull_request_target"
        or not isinstance(environ.get("GITHUB_SHA"), str)
        or not _SHA.fullmatch(environ["GITHUB_SHA"])
    ):
        raise ProtectedRuntimeError("workflow_event_identity_invalid")
    current_run_id = environ.get("GITHUB_RUN_ID", "")
    current_attempt = environ.get("GITHUB_RUN_ATTEMPT", "")
    if not re.fullmatch(r"[1-9][0-9]{0,17}", current_run_id) or not re.fullmatch(r"[1-9][0-9]{0,8}", current_attempt):
        raise ProtectedRuntimeError("publisher_run_identity_invalid")
    return upstream, claim


def _platform_context(
    environ: Mapping[str, str],
    event_raw: bytes,
    policy: ProtectedPublicationPolicy,
    target_claim: tuple[int, str, str],
    source_workflow_sha: str,
) -> ProtectedCanaryRun:
    upstream, event_claim = _workflow_event_parts(environ, event_raw, policy)
    if event_claim is not None and event_claim != target_claim:
        raise ProtectedRuntimeError("workflow_event_pr_binding_mismatch")
    pr_number, base_sha, head_sha = target_claim
    repo = policy.raw["repository"]
    publisher = policy.raw["publisher_workflow"]
    source = policy.raw["source_workflow"]
    current_run_id = environ["GITHUB_RUN_ID"]
    current_attempt = environ["GITHUB_RUN_ATTEMPT"]
    return ProtectedCanaryRun(
        repository_id=repo["id"],
        repository=repo["name"],
        default_branch=policy.raw["default_branch"],
        publisher_run_id=int(current_run_id),
        publisher_run_attempt=int(current_attempt),
        publisher_workflow_id=publisher["id"],
        publisher_workflow_path=publisher["path"],
        publisher_workflow_ref=publisher["ref"],
        publisher_workflow_sha=environ["GITHUB_SHA"],
        source_head_branch=upstream["head_branch"],
        source_run_id=upstream["id"],
        source_run_attempt=upstream["run_attempt"],
        source_workflow_id=source["id"],
        source_workflow_path=source["path"],
        source_workflow_ref=source["ref"],
        source_event=upstream["event"],
        source_workflow_sha=source_workflow_sha,
        source_run_head_sha=upstream["head_sha"],
        pull_request_head_sha=head_sha,
        pull_request_number=pr_number,
        base_sha=base_sha,
    )


def _publication_policy(
    protected: ProtectedPublicationPolicy,
    platform: ProtectedCanaryRun,
) -> GitHubPublicationPolicy:
    caller = protected.raw["source_workflow"]
    publisher = protected.raw["publisher_workflow"]
    harness = protected.raw["called_harness"]
    profile = protected.raw["profile"]
    app = protected.raw["app"]
    repo = protected.raw["repository"]
    return GitHubPublicationPolicy(
        repository_id=repo["id"],
        repository=repo["name"],
        pull_request_number=platform.pull_request_number,
        upstream_run_id=platform.source_run_id,
        upstream_run_attempt=platform.source_run_attempt,
        publisher_run_id=platform.publisher_run_id,
        publisher_run_attempt=platform.publisher_run_attempt,
        caller_workflow_id=caller["id"],
        caller_workflow_path=caller["path"],
        caller_workflow_ref=f"refs/heads/{protected.raw['default_branch']}",
        caller_workflow_sha=platform.source_workflow_sha,
        called_harness_repository=harness["repository"],
        called_harness_path=harness["path"],
        called_harness_sha=harness["sha"],
        publisher_workflow_id=publisher["id"],
        publisher_workflow_path=publisher["path"],
        publisher_workflow_ref=f"refs/heads/{protected.raw['default_branch']}",
        publisher_workflow_sha=platform.publisher_workflow_sha,
        profile_version=profile["version"],
        profile_sha256=profile["sha256"],
        provider_configuration_identity=profile["provider_configuration_identity"],
        allowed_actor_login=app["actor_login"],
        concurrency_scope="repository",
        artifact_trust_mode=ArtifactTrustMode.API_BOUND_SHA256,
        artifact_redirect_hosts=tuple(protected.raw["artifact_redirect_hosts"]),
    )


def _artifact_environment(environ: Mapping[str, str]) -> dict[str, str]:
    names = (
        "PATH",
        "HOME",
        "TMPDIR",
        "GITHUB_RUN_ID",
        "GITHUB_RUN_ATTEMPT",
        "ACTIONS_RUNTIME_TOKEN",
        "ACTIONS_RESULTS_URL",
        "ACTIONS_RUNTIME_URL",
    )
    return {name: value for name in names if isinstance((value := environ.get(name)), str)}


def _bootstrap_target_claim(
    environ: Mapping[str, str],
    event_raw: bytes,
    protected: ProtectedPublicationPolicy,
    transport: GitHubHTTPTransport,
    deadline: float,
    clock: Callable[[], float],
) -> tuple[tuple[int, str, str], str]:
    """Extract only the PR identity from a bounded API-bound source manifest.

    All other manifest fields are compared with protected policy here and the
    complete archive is independently admitted again by the publication
    adapter before any write-scoped credential is requested.
    """
    upstream, event_claim = _workflow_event_parts(environ, event_raw, protected)
    read_token = environ.get("GITHUB_TOKEN", "")
    if not isinstance(read_token, str) or not read_token or len(read_token) > 16_384:
        raise ProtectedRuntimeError("actions_read_token_unavailable")
    repository = protected.raw["repository"]["name"]
    repository_id = protected.raw["repository"]["id"]
    run_id = upstream["id"]
    root = "https://api.github.com/repos/" + quote(repository, safe="/")

    def request(method: str, url: str, *, expected_status: int = 200, body=None):
        remaining = deadline - clock()
        if remaining <= 0:
            raise ProtectedRuntimeError("protected_publication_deadline_exhausted")
        try:
            response = transport.request(
                method,
                url,
                token=read_token,
                json_body=body,
                timeout_seconds=min(remaining, 10.0),
                max_response_bytes=256 * 1024,
            )
        except Exception:
            raise ProtectedRuntimeError("source_artifact_api_unavailable") from None
        if clock() >= deadline:
            raise ProtectedRuntimeError("protected_publication_deadline_exhausted")
        if (
            getattr(response, "status", None) != expected_status
            or not isinstance(getattr(response, "body", None), bytes)
            or len(response.body) > 256 * 1024
        ):
            raise ProtectedRuntimeError("source_artifact_api_unavailable")
        return response

    default_branch = protected.raw["default_branch"]
    branch_value = _json_object(
        request("GET", f"{root}/branches/{quote(default_branch, safe='')}").body,
        limit=256 * 1024,
        code="default_branch_api_invalid",
    )
    branch_commit = branch_value.get("commit") if isinstance(branch_value.get("commit"), dict) else {}
    source_workflow_sha = branch_commit.get("sha")
    if (
        branch_value.get("name") != default_branch
        or not isinstance(source_workflow_sha, str)
        or not _SHA.fullmatch(source_workflow_sha)
    ):
        raise ProtectedRuntimeError("default_branch_tip_invalid")

    source_run = _json_object(
        request("GET", f"{root}/actions/runs/{run_id}").body,
        limit=256 * 1024,
        code="source_run_api_invalid",
    )
    source_path = source_run.get("path")
    if (
        not _positive_int(source_run.get("id"))
        or source_run.get("id") != run_id
        or not _positive_int(source_run.get("run_attempt"))
        or source_run.get("run_attempt") != upstream["run_attempt"]
        or not _positive_int(source_run.get("workflow_id"))
        or source_run.get("workflow_id") != protected.raw["source_workflow"]["id"]
        or not isinstance(source_path, str)
        or source_path.split("@", 1)[0] != protected.raw["source_workflow"]["path"]
        or source_run.get("event") != "pull_request_target"
        or source_run.get("status") != "completed"
        or source_run.get("conclusion") != "success"
        or source_run.get("head_sha") != upstream["head_sha"]
        or source_run.get("head_branch") != upstream["head_branch"]
        or not isinstance(source_run.get("repository"), dict)
        or source_run["repository"].get("id") != repository_id
        or source_run["repository"].get("full_name") != repository
    ):
        raise ProtectedRuntimeError("source_run_api_binding_invalid")

    artifact_list = _json_object(
        request(
            "GET",
            f"{root}/actions/runs/{run_id}/artifacts?name=pr-review-result&per_page=2&page=1",
        ).body,
        limit=256 * 1024,
        code="source_artifact_metadata_invalid",
    )
    artifacts = artifact_list.get("artifacts")
    if (
        not isinstance(artifact_list.get("total_count"), int)
        or isinstance(artifact_list.get("total_count"), bool)
        or artifact_list.get("total_count") != 1
        or not isinstance(artifacts, list)
        or len(artifacts) != 1
        or not isinstance(artifacts[0], dict)
    ):
        raise ProtectedRuntimeError("source_artifact_missing_or_ambiguous")
    artifact = artifacts[0]
    workflow_run = artifact.get("workflow_run") if isinstance(artifact.get("workflow_run"), dict) else {}
    if (
        not _positive_int(artifact.get("id"))
        or artifact.get("name") != "pr-review-result"
        or artifact.get("expired") is not False
        or not isinstance(artifact.get("size_in_bytes"), int)
        or isinstance(artifact.get("size_in_bytes"), bool)
        or not 22 <= artifact["size_in_bytes"] <= 8 * 1024 * 1024
        or not isinstance(artifact.get("digest"), str)
        or not re.fullmatch(r"sha256:[0-9a-f]{64}", artifact["digest"])
        or workflow_run.get("id") != run_id
        or workflow_run.get("repository_id") != repository_id
        or workflow_run.get("head_sha") != source_run.get("head_sha")
    ):
        raise ProtectedRuntimeError("source_artifact_metadata_invalid")
    redirect = request("GET", f"{root}/actions/artifacts/{artifact['id']}/zip", expected_status=302)
    location = redirect.headers.get("location") if isinstance(redirect.headers, dict) else None
    parsed = urlsplit(location) if isinstance(location, str) else None
    if (
        parsed is None
        or parsed.scheme != "https"
        or not parsed.hostname
        or parsed.hostname not in protected.raw["artifact_redirect_hosts"]
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise ProtectedRuntimeError("source_artifact_redirect_untrusted")
    remaining = deadline - clock()
    if remaining <= 0:
        raise ProtectedRuntimeError("protected_publication_deadline_exhausted")
    try:
        downloaded = transport.download(
            location,
            timeout_seconds=min(remaining, 10.0),
            max_response_bytes=8 * 1024 * 1024,
        )
    except Exception:
        raise ProtectedRuntimeError("source_artifact_download_unavailable") from None
    if (
        clock() >= deadline
        or getattr(downloaded, "status", None) != 200
        or not isinstance(getattr(downloaded, "body", None), bytes)
        or len(downloaded.body) > 8 * 1024 * 1024
        or "sha256:" + hashlib.sha256(downloaded.body).hexdigest() != artifact["digest"]
    ):
        raise ProtectedRuntimeError("source_artifact_digest_mismatch")
    try:
        with zipfile.ZipFile(io.BytesIO(downloaded.body)) as archive:
            infos = archive.infolist()
            by_name = {item.filename: item for item in infos}
            if (
                len(infos) != 2
                or len(by_name) != 2
                or set(by_name) != {MANIFEST_FILENAME, "review-result.json"}
                or any(item.is_dir() or item.flag_bits & 0x1 for item in infos)
                or any(stat.S_ISLNK(item.external_attr >> 16) for item in infos)
                or sum(item.file_size for item in infos) > 16 * 1024 * 1024
                or any(item.file_size > 15 * 1024 * 1024 for item in infos)
                or any(item.compress_size == 0 and item.file_size for item in infos)
                or any(item.compress_size and item.file_size / item.compress_size > 1000 for item in infos)
            ):
                raise ProtectedRuntimeError("source_artifact_archive_invalid")
            manifest_info = by_name[MANIFEST_FILENAME]
            if manifest_info.file_size > 64 * 1024:
                raise ProtectedRuntimeError("source_artifact_manifest_too_large")
            with archive.open(manifest_info) as manifest_stream:
                manifest_raw = manifest_stream.read(64 * 1024 + 1)
    except ProtectedRuntimeError:
        raise
    except (OSError, ValueError, zipfile.BadZipFile, RuntimeError, EOFError):
        raise ProtectedRuntimeError("source_artifact_archive_invalid") from None
    manifest = _json_object(manifest_raw, limit=64 * 1024, code="source_artifact_manifest_invalid")
    source = protected.raw["source_workflow"]
    harness = protected.raw["called_harness"]
    profile = protected.raw["profile"]
    if (
        manifest.get("repository_id") != repository_id
        or manifest.get("repository") != repository
        or manifest.get("upstream_run_id") != run_id
        or manifest.get("upstream_run_attempt") != upstream["run_attempt"]
        or manifest.get("caller_workflow_id") != source["id"]
        or manifest.get("caller_workflow_path") != source["path"]
        or manifest.get("caller_workflow_ref") != source["ref"].split("@", 1)[1]
        or manifest.get("called_harness_repository") != harness["repository"]
        or manifest.get("called_harness_path") != harness["path"]
        or manifest.get("called_harness_sha") != harness["sha"]
        or manifest.get("profile_version") != profile["version"]
        or manifest.get("profile_sha256") != profile["sha256"]
        or manifest.get("provider_configuration_identity") != profile["provider_configuration_identity"]
        or manifest.get("caller_workflow_sha") != source_workflow_sha
        or manifest.get("head_sha") != source_run.get("head_sha")
    ):
        raise ProtectedRuntimeError("source_artifact_manifest_policy_mismatch")
    pr_number = manifest.get("pull_request_number")
    base_sha = manifest.get("base_sha")
    head_sha = manifest.get("head_sha")
    if not _positive_int(pr_number) or not isinstance(base_sha, str) or not _SHA.fullmatch(base_sha) or not isinstance(head_sha, str) or not _SHA.fullmatch(head_sha):
        raise ProtectedRuntimeError("source_artifact_manifest_target_invalid")
    claim = (pr_number, base_sha, head_sha)
    if event_claim is not None and event_claim != claim:
        raise ProtectedRuntimeError("workflow_event_pr_binding_mismatch")
    return claim, source_workflow_sha


def _load_review_result(adapter: GitHubActionsPublicationAdapter, limits: ScanLimits) -> dict[str, object]:
    """Read the exact API-bound source artifact before any write-scoped token."""
    adapter._start_deadline(limits.deadline_seconds)
    policy = adapter.policy
    pr = adapter._pull(adapter._deadline(limits.deadline_seconds))
    upstream, _upstream_identity = adapter._validate_upstream_run(pr, adapter._deadline(limits.deadline_seconds))
    current = adapter._run(policy.publisher_run_id, policy.publisher_run_attempt, adapter._deadline(limits.deadline_seconds))
    current_identity = adapter._run_identity(current, publisher=True)
    if (
        current_identity.workflow_sha != policy.publisher_workflow_sha
        or current.get("event") != "workflow_run"
        or current.get("status") != "in_progress"
    ):
        raise ProtectedRuntimeError("publisher_run_binding_invalid")
    candidates = adapter._list_run_artifacts(
        policy.upstream_run_id,
        policy.result_artifact_name,
        adapter._deadline(limits.deadline_seconds),
    )
    if len(candidates) != 1:
        raise ProtectedRuntimeError("result_artifact_missing_or_ambiguous")
    artifact = adapter._artifact_metadata(
        candidates[0], expected_name=policy.result_artifact_name, run_id=policy.upstream_run_id
    )
    if artifact["size_in_bytes"] > policy.max_bundle_bytes:
        raise ProtectedRuntimeError("result_artifact_too_large")
    artifact_run = artifact.get("workflow_run", {})
    if artifact_run.get("head_sha") != upstream.get("head_sha"):
        raise ProtectedRuntimeError("result_artifact_head_binding_invalid")
    downloaded = adapter._download_artifact(
        artifact,
        adapter._deadline(limits.deadline_seconds),
        policy.max_bundle_bytes,
    )
    expected = ArtifactIdentity(
        repository_id=policy.repository_id,
        repository=policy.repository,
        pull_request_number=policy.pull_request_number,
        base_sha=pr["base_sha"],
        head_sha=pr["head_sha"],
        upstream_run_id=policy.upstream_run_id,
        upstream_run_attempt=policy.upstream_run_attempt,
        caller_workflow_id=policy.caller_workflow_id,
        caller_workflow_path=policy.caller_workflow_path,
        caller_workflow_ref=policy.caller_workflow_ref,
        caller_workflow_sha=policy.caller_workflow_sha,
        called_harness_repository=policy.called_harness_repository,
        called_harness_path=policy.called_harness_path,
        called_harness_sha=policy.called_harness_sha,
        profile_version=policy.profile_version,
        profile_sha256=policy.profile_sha256,
        provider_configuration_identity=policy.provider_configuration_identity,
        contract_versions=policy.contract_versions,
    )
    trusted_attestation = AttestationIdentity(
        issuer="github-actions-api-bound",
        repository_id=policy.repository_id,
        repository=policy.repository,
        workflow_id=policy.caller_workflow_id,
        workflow_path=policy.caller_workflow_path,
        workflow_ref=policy.caller_workflow_ref,
        workflow_sha=policy.caller_workflow_sha,
        run_id=policy.upstream_run_id,
        run_attempt=policy.upstream_run_attempt,
        called_harness_repository=policy.called_harness_repository,
        called_harness_path=policy.called_harness_path,
        called_harness_sha=policy.called_harness_sha,
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
        limits=IntakeLimits(
            max_archive_bytes=policy.max_bundle_bytes,
            max_read_seconds=limits.deadline_seconds,
        ),
    )
    result = receipt.result
    if receipt.manifest.get("review_run_id") != result.get("run_id"):
        raise ProtectedRuntimeError("result_artifact_run_binding_invalid")
    return result


def _safe_outcome(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        return {"schema": "pr-review-protected-publication.v1", "status": "UNKNOWN", "reason": "publisher_result_invalid"}
    status = value.get("status")
    reason = value.get("reason")
    if status not in {"CONFIRMED", "REJECTED", "UNKNOWN", "DEFERRED", "STALE", "CONFLICT", "CANDIDATE"}:
        status = "UNKNOWN"
    if not isinstance(reason, str) or not re.fullmatch(r"[a-z0-9_]{1,64}", reason):
        reason = None
    return {"schema": "pr-review-protected-publication.v1", "status": status, "reason": reason}


def run_protected_publication(
    environ: Mapping[str, str] | None = None,
    *,
    transport: GitHubHTTPTransport | None = None,
    artifact_uploader=None,
    key_supplier: Callable[[], str] | None = None,
    clock: Callable[[], float] = time.monotonic,
) -> dict[str, object]:
    """Run protected composition, refusing missing or untrusted inputs.

    Test seams inject fake transports, uploaders and a lazy key supplier. The
    production path reads only a fixed protected policy file and fixed Actions
    environment names; no CLI argument or artifact field controls policy.
    """
    env = os.environ if environ is None else environ
    deadline: float | None = None
    try:
        protected = _policy_from_workspace(env)
        if not protected.enabled:
            return {"schema": "pr-review-protected-publication.v1", "status": "DISABLED", "reason": "publication_disabled"}
        publication_limits = ScanLimits(**protected.raw["limits"])
        deadline = clock() + float(publication_limits.deadline_seconds)
        event_path = env.get("GITHUB_EVENT_PATH")
        if not isinstance(event_path, str) or not Path(event_path).is_absolute():
            raise ProtectedRuntimeError("workflow_event_unavailable")
        event_raw = _read_regular(Path(event_path), _EVENT_MAX_BYTES, "workflow_event_unavailable")
        client = transport or UrllibGitHubTransport()
        target_claim, source_workflow_sha = _bootstrap_target_claim(env, event_raw, protected, client, deadline, clock)
        platform = _platform_context(env, event_raw, protected, target_claim, source_workflow_sha)
        app_policy = protected.app_policy()
        github_policy = _publication_policy(protected, platform)
        key_cache: list[str] = []
        source_key_supplier = key_supplier or (lambda: env.get("PR_REVIEW_GITHUB_APP_PRIVATE_KEY", ""))

        def actual_key_supplier() -> str:
            if not key_cache:
                key_cache.append(source_key_supplier())
            return key_cache[0]
        identity, _canary_receipt = verify_github_app_identity_canary(
            enabled=True,
            platform=platform,
            policy=app_policy,
            actions_token=env.get("GITHUB_TOKEN", ""),
            app_private_key_supplier=actual_key_supplier,
            transport=client,
            limits=CanaryLimits(deadline_seconds=min(30.0, _remaining(deadline, clock))),
            clock=clock,
        )
        remaining = _remaining(deadline, clock)
        provider = GitHubAppPublisherCredentialProvider(
            app_policy,
            actual_key_supplier(),
            canary_identity=identity,
            transport=client,
            clock=clock,
        )
        uploader = artifact_uploader or OfficialActionsArtifactUploader(environ=_artifact_environment(env))
        adapter = GitHubActionsPublicationAdapter(
            github_policy,
            provider,
            transport=client,
            artifact_uploader=uploader,
            clock=clock,
        )
        publication_config = protected.publication_config()
        result = _load_review_result(adapter, _with_deadline(publication_limits, remaining))
        if not isinstance(result, dict):
            raise ProtectedRuntimeError("result_artifact_intake_unavailable")

        def fresh_head(timeout_seconds: float) -> str:
            remaining_seconds = min(timeout_seconds, _remaining(deadline, clock))
            default_branch = protected.raw["default_branch"]
            branch_response = client.request(
                "GET",
                "https://api.github.com/repos/"
                + quote(protected.raw["repository"]["name"], safe="/")
                + "/branches/"
                + quote(default_branch, safe=""),
                token=env.get("GITHUB_TOKEN", ""),
                json_body=None,
                timeout_seconds=remaining_seconds,
                max_response_bytes=256 * 1024,
            )
            if clock() >= deadline:
                raise ProtectedRuntimeError("protected_publication_deadline_exhausted")
            if (
                getattr(branch_response, "status", None) != 200
                or not isinstance(getattr(branch_response, "body", None), bytes)
                or len(branch_response.body) > 256 * 1024
            ):
                raise ProtectedRuntimeError("default_branch_tip_unavailable")
            branch_value = _json_object(
                branch_response.body, limit=256 * 1024, code="default_branch_api_invalid"
            )
            branch_commit = branch_value.get("commit") if isinstance(branch_value.get("commit"), dict) else {}
            if branch_value.get("name") != default_branch or branch_commit.get("sha") != source_workflow_sha:
                raise ProtectedRuntimeError("default_branch_tip_changed")
            pr = adapter._pull(remaining_seconds)
            if clock() >= deadline:
                raise ProtectedRuntimeError("protected_publication_deadline_exhausted")
            if pr["base_sha"] != target_claim[1] or pr["head_sha"] != target_claim[2]:
                raise ProtectedRuntimeError("pull_request_target_changed")
            return pr["head_sha"]

        remaining = _remaining(deadline, clock)
        outcome = publish_review_stateless(
            result,
            publication_config,
            "PUBLISH_REVIEW",
            admission_provider=adapter,
            history_reader=adapter,
            receipt_writer=adapter,
            fresh_head=fresh_head,
            submit_review=adapter.submit_review,
            limits=_with_deadline(publication_limits, remaining),
        )
        return _safe_outcome(outcome)
    except ProtectedRuntimeError as exc:
        return {"schema": "pr-review-protected-publication.v1", "status": "UNKNOWN", "reason": exc.code}
    except GitHubPublicationError as exc:
        return {"schema": "pr-review-protected-publication.v1", "status": "UNKNOWN", "reason": exc.code}
    except (OSError, ValueError, TypeError, KeyError):
        return {"schema": "pr-review-protected-publication.v1", "status": "UNKNOWN", "reason": "protected_publication_input_invalid"}
    except Exception:
        return {"schema": "pr-review-protected-publication.v1", "status": "UNKNOWN", "reason": "protected_publication_unavailable"}


def _remaining(deadline: float, clock: Callable[[], float]) -> float:
    remaining = deadline - clock()
    if not isinstance(remaining, (int, float)) or remaining <= 0:
        raise ProtectedRuntimeError("protected_publication_deadline_exhausted")
    return remaining


def _with_deadline(limits: ScanLimits, seconds: float) -> ScanLimits:
    return ScanLimits(
        max_runs=limits.max_runs,
        max_pages=limits.max_pages,
        max_reviews=limits.max_reviews,
        deadline_seconds=min(float(limits.deadline_seconds), seconds),
    )


def main() -> int:
    print(json.dumps(run_protected_publication(), sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
