"""Read-only GitHub Actions identity canary (archived experiment harness).

The canary verifies only facts returned by GitHub's read API. It never infers
writer identity from workflow context and never proves write permission. It is
not installed with ``pr-review-harness``; the artifact upload bridge it uses is
the production ``pr_review_harness.actions_runtime`` module.
"""

import hashlib
import json
import math
import os
import re
import stat
import subprocess
import sys
import time
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Callable, Mapping, Protocol
from urllib.parse import quote

from pr_review_harness.actions_publication import (
    ArtifactUploadResult,
    HTTPResponse,
    UrllibGitHubTransport,
)
from pr_review_harness.actions_runtime import (
    OfficialActionsArtifactUploader,
    _reject_json_constant,
    _strict_object,
)

_REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
_SHA = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_LOGIN = re.compile(r"[A-Za-z0-9-]{1,39}(?:\[bot\])?\Z")
_ARTIFACT_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_WORKFLOW_PATH = re.compile(r"\.github/workflows/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*\.ya?ml\Z")
_BRANCH_REF = re.compile(r"refs/heads/[A-Za-z0-9._/-]{1,240}\Z")
_MAX_RESPONSE_BYTES = 256 * 1024
_MAX_RESPONSE_NODES = 40_000
_MAX_RESPONSE_DEPTH = 48
_MAX_UPLOAD_BYTES = 128 * 1024
_MAX_UPLOAD_SECONDS = 300.0
_MAX_BRIDGE_OUTPUT_BYTES = 4096
_API_ROOT = "https://api.github.com"
_MAX_RUNTIME_MODULES = 256
_MAX_RUNTIME_SOURCE_BYTES = 4 * 1024 * 1024


class ActionsRuntimeError(ValueError):
    """Safe error code from the isolated Actions canary or artifact bridge."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


class ReadOnlyTransport(Protocol):
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


@dataclass(frozen=True)
class CanaryLimits:
    deadline_seconds: float = 30.0
    max_api_calls: int = 5
    max_response_bytes: int = _MAX_RESPONSE_BYTES

    def __post_init__(self) -> None:
        if (
            isinstance(self.deadline_seconds, bool)
            or not isinstance(self.deadline_seconds, (int, float))
            or not math.isfinite(self.deadline_seconds)
            or not 0 < self.deadline_seconds <= 120
            or isinstance(self.max_api_calls, bool)
            or not isinstance(self.max_api_calls, int)
            or not 1 <= self.max_api_calls <= 5
            or isinstance(self.max_response_bytes, bool)
            or not isinstance(self.max_response_bytes, int)
            or not 1024 <= self.max_response_bytes <= _MAX_RESPONSE_BYTES
        ):
            raise ActionsRuntimeError("canary_limits_invalid")


@dataclass(frozen=True)
class CanaryExpectation:
    repository: str
    repository_id: int
    publisher_run_id: int
    publisher_run_attempt: int
    publisher_workflow_id: int
    publisher_workflow_path: str
    publisher_workflow_ref: str
    publisher_workflow_sha: str
    upstream_run_id: int
    upstream_run_attempt: int
    caller_workflow_id: int
    caller_workflow_path: str
    caller_workflow_ref: str
    pull_request_number: int
    base_sha: str
    head_sha: str
    expected_actor_login: str | None = None

    def __post_init__(self) -> None:
        positive_ints = (
            self.repository_id,
            self.publisher_run_id,
            self.publisher_run_attempt,
            self.publisher_workflow_id,
            self.upstream_run_id,
            self.upstream_run_attempt,
            self.caller_workflow_id,
            self.pull_request_number,
        )
        if (
            not isinstance(self.repository, str)
            or not _REPOSITORY.fullmatch(self.repository)
            or any(isinstance(value, bool) or not isinstance(value, int) or value < 1 for value in positive_ints)
            or not isinstance(self.publisher_workflow_path, str)
            or not _WORKFLOW_PATH.fullmatch(self.publisher_workflow_path)
            or ".." in self.publisher_workflow_path.split("/")
            or not isinstance(self.caller_workflow_path, str)
            or not _WORKFLOW_PATH.fullmatch(self.caller_workflow_path)
            or ".." in self.caller_workflow_path.split("/")
            or not isinstance(self.publisher_workflow_ref, str)
            or not _BRANCH_REF.fullmatch(self.publisher_workflow_ref)
            or ".." in self.publisher_workflow_ref.split("/")
            or not isinstance(self.caller_workflow_ref, str)
            or not _BRANCH_REF.fullmatch(self.caller_workflow_ref)
            or ".." in self.caller_workflow_ref.split("/")
            or not isinstance(self.publisher_workflow_sha, str)
            or not _SHA.fullmatch(self.publisher_workflow_sha)
            or not isinstance(self.base_sha, str)
            or not _SHA.fullmatch(self.base_sha)
            or not isinstance(self.head_sha, str)
            or not _SHA.fullmatch(self.head_sha)
            or (
                self.expected_actor_login is not None
                and (not isinstance(self.expected_actor_login, str) or not _LOGIN.fullmatch(self.expected_actor_login))
            )
        ):
            raise ActionsRuntimeError("canary_expectation_invalid")


@dataclass(frozen=True)
class RuntimeCanaryResult:
    state: str
    reason: str
    repository_id: int | None
    api_actor_login: str | None
    actor_binding: str
    verified_reads: tuple[str, ...]
    response_hashes: tuple[tuple[str, str], ...]
    publication_capability: str = "UNAVAILABLE"
    write_permission: str = "NOT_TESTED"
    runtime_identity: Mapping[str, object] | None = None

    def as_dict(self) -> dict[str, object]:
        return {
            "schema": "pr-review-actions-canary.v2",
            "state": self.state,
            "reason": self.reason,
            "repository_id": self.repository_id,
            "api_actor_login": self.api_actor_login,
            "actor_binding": self.actor_binding,
            "verified_reads": list(self.verified_reads),
            "response_hashes": [{"endpoint": endpoint, "sha256": digest} for endpoint, digest in self.response_hashes],
            "publication_capability": self.publication_capability,
            "write_permission": self.write_permission,
            "runtime_identity": dict(self.runtime_identity or {
                "state": "UNAVAILABLE",
                "reason_code": "runtime_identity_not_checked",
                "source_revision": None,
                "module_count": 0,
                "module_tree_sha256": None,
            }),
            "safe_to_publish": False,
        }


def _runtime_source_identity(
    environ: Mapping[str, str], *, module_file: Path | None = None
) -> dict[str, object]:
    """Bind the loaded canary module and package sources to the runner checkout SHA.

    This is local source-integrity evidence only. It does not prove credential
    permissions or create a publisher capability.
    """

    def unavailable(reason: str) -> dict[str, object]:
        return {
            "state": "UNAVAILABLE",
            "reason_code": reason,
            "source_revision": None,
            "module_count": 0,
            "module_tree_sha256": None,
        }

    workspace_value = environ.get("GITHUB_WORKSPACE")
    expected_revision = environ.get("GITHUB_SHA")
    if (
        not isinstance(workspace_value, str)
        or not workspace_value
        or not isinstance(expected_revision, str)
        or not _SHA.fullmatch(expected_revision)
    ):
        return unavailable("runtime_identity_inputs_invalid")

    try:
        workspace = Path(workspace_value).resolve(strict=True)
        package_root = workspace / "src" / "pr_review_harness"
        if (workspace / "src").is_symlink() or package_root.is_symlink():
            return unavailable("runtime_source_tree_mismatch")
        loaded_module = (module_file or Path(__file__)).resolve(strict=True)
        expected_module = (workspace / "experiments" / "harness" / "actions_canary.py").resolve(strict=True)
        if loaded_module != expected_module or not package_root.is_dir():
            return unavailable("runtime_module_origin_mismatch")
        package_root_resolved = package_root.resolve(strict=True)
        if module_file is None:
            for name, loaded in tuple(sys.modules.items()):
                if name == "pr_review_harness" or name.startswith("pr_review_harness."):
                    loaded_path = getattr(loaded, "__file__", None)
                    if not isinstance(loaded_path, str):
                        return unavailable("runtime_module_origin_mismatch")
                    resolved_path = Path(loaded_path).resolve(strict=True)
                    try:
                        resolved_path.relative_to(package_root_resolved)
                    except ValueError:
                        return unavailable("runtime_module_origin_mismatch")

        # Ambient git routing/config variables could redirect these checks to a
        # different repository, so run git with a minimal explicit environment.
        git_environment = {
            "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
            "LC_ALL": "C",
        }

        def git(*args: str) -> subprocess.CompletedProcess[bytes]:
            return subprocess.run(
                ["git", "-C", str(workspace), *args],
                env=git_environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=5,
                check=False,
            )

        head = git("rev-parse", "--verify", "HEAD^{commit}")
        if head.returncode != 0:
            return unavailable("runtime_source_revision_unavailable")
        actual_revision = head.stdout.decode("ascii", errors="strict").strip()
        if actual_revision != expected_revision:
            return unavailable("runtime_source_revision_mismatch")

        clean = git("diff", "--quiet", "--exit-code", actual_revision, "--", "src/pr_review_harness")
        if clean.returncode == 1:
            return unavailable("runtime_source_tree_dirty")
        if clean.returncode != 0:
            return unavailable("runtime_source_tree_unavailable")

        tracked = git("ls-tree", "-r", "-z", "--name-only", actual_revision, "--", "src/pr_review_harness")
        if tracked.returncode != 0:
            return unavailable("runtime_source_tree_unavailable")
        tracked_modules = {
            item.decode("utf-8", errors="strict")
            for item in tracked.stdout.split(b"\0")
            if item.endswith(b".py")
        }

        source_files: dict[str, Path] = {}
        for directory, directory_names, filenames in os.walk(package_root, followlinks=False):
            current = Path(directory)
            if any((current / name).is_symlink() for name in directory_names):
                return unavailable("runtime_source_tree_mismatch")
            for filename in filenames:
                path = current / filename
                if filename.endswith(".py"):
                    if path.is_symlink() or not path.is_file():
                        return unavailable("runtime_source_tree_mismatch")
                    source_files[path.relative_to(workspace).as_posix()] = path
        if set(source_files) != tracked_modules:
            return unavailable("runtime_source_tree_mismatch")
        if not source_files or len(source_files) > _MAX_RUNTIME_MODULES:
            return unavailable("runtime_source_tree_size_invalid")

        entries = []
        total_bytes = 0
        for relative, path in sorted(source_files.items()):
            source_size = path.stat().st_size
            if source_size < 0 or source_size > _MAX_RUNTIME_SOURCE_BYTES - total_bytes:
                return unavailable("runtime_source_tree_size_invalid")
            raw = path.read_bytes()
            total_bytes += len(raw)
            if len(raw) != source_size or total_bytes > _MAX_RUNTIME_SOURCE_BYTES:
                return unavailable("runtime_source_tree_size_invalid")
            entries.append({"path": relative, "sha256": hashlib.sha256(raw).hexdigest()})
        tree_digest = hashlib.sha256(
            json.dumps(entries, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        ).hexdigest()
    except (OSError, UnicodeError, subprocess.SubprocessError, ValueError):
        return unavailable("runtime_source_identity_unavailable")

    return {
        "state": "VERIFIED",
        "reason_code": None,
        "source_revision": actual_revision,
        "module_count": len(entries),
        "module_tree_sha256": tree_digest,
    }


def _validate_json_tree(value: object, *, max_depth: int = _MAX_RESPONSE_DEPTH) -> None:
    stack = [(value, 0)]
    count = 0
    while stack:
        item, depth = stack.pop()
        count += 1
        if count > _MAX_RESPONSE_NODES or depth > max_depth:
            raise ActionsRuntimeError("github_response_complexity_exceeded")
        if isinstance(item, dict):
            stack.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            stack.extend((child, depth + 1) for child in item)


def _decode_response(response: HTTPResponse, max_bytes: int) -> tuple[dict[str, object], str]:
    if not isinstance(response, HTTPResponse) or not isinstance(response.body, bytes) or len(response.body) > max_bytes:
        raise ActionsRuntimeError("github_response_invalid_or_oversized")
    digest = hashlib.sha256(response.body).hexdigest()
    if response.status != 200:
        raise ActionsRuntimeError("github_read_unavailable")

    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate_json_key")
            result[key] = value
        return result

    def reject_constant(_value):
        raise ValueError("nonfinite_json_number")

    try:
        value = json.loads(response.body, object_pairs_hook=unique_object, parse_constant=reject_constant)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError):
        raise ActionsRuntimeError("github_response_invalid_json") from None
    _validate_json_tree(value)
    if not isinstance(value, dict):
        raise ActionsRuntimeError("github_response_invalid_record")
    return value, digest


def _api_path(repository: str, suffix: str) -> str:
    return f"{_API_ROOT}/repos/{quote(repository, safe='/')}{suffix}"


def _workflow_ref(path: object) -> tuple[str, str] | None:
    if not isinstance(path, str) or "@" not in path:
        return None
    workflow_path, ref = path.rsplit("@", 1)
    return workflow_path, ref


def _workflow_reference_matches(path: object, expected_path: str, expected_ref: str) -> bool:
    actual = _workflow_ref(path)
    if actual is None or actual[0] != expected_path:
        return False
    if expected_ref.startswith("refs/heads/"):
        branch = expected_ref.removeprefix("refs/heads/")
        # The documented workflow-run `path` example uses `@main`; accept the
        # fully-qualified spelling only when it names that same configured ref.
        return actual[1] in {branch, expected_ref}
    return actual[1] == expected_ref


def _api_id_matches(actual: object, expected: int) -> bool:
    return isinstance(actual, int) and not isinstance(actual, bool) and actual == expected


def verify_read_only_actions_context(
    expectation: CanaryExpectation,
    token: str,
    *,
    transport: ReadOnlyTransport | None = None,
    limits: CanaryLimits | None = None,
    clock: Callable[[], float] = time.monotonic,
) -> RuntimeCanaryResult:
    """Check server-returned run, PR and optional actor facts; never authorize a write."""
    if not isinstance(expectation, CanaryExpectation):
        return RuntimeCanaryResult("UNKNOWN", "canary_expectation_invalid", None, None, "UNAVAILABLE", (), ())
    try:
        limits = limits or CanaryLimits()
    except ActionsRuntimeError:
        return RuntimeCanaryResult("UNKNOWN", "canary_limits_invalid", None, None, "UNAVAILABLE", (), ())
    if not isinstance(token, str) or not token or len(token) > 16_384 or any(char.isspace() for char in token):
        return RuntimeCanaryResult("UNKNOWN", "github_token_unavailable", None, None, "UNAVAILABLE", (), ())

    client = transport or UrllibGitHubTransport()
    deadline = clock() + float(limits.deadline_seconds)
    hashes: list[tuple[str, str]] = []
    verified_reads: list[str] = []
    calls = 0

    def get(endpoint: str, api_path: str) -> dict[str, object]:
        nonlocal calls
        if calls >= limits.max_api_calls:
            raise ActionsRuntimeError("canary_api_call_budget_exhausted")
        calls += 1
        remaining = deadline - clock()
        if remaining <= 0:
            raise ActionsRuntimeError("canary_deadline_exhausted")
        response = client.request(
            "GET",
            api_path,
            token=token,
            json_body=None,
            timeout_seconds=remaining,
            max_response_bytes=limits.max_response_bytes,
        )
        value, digest = _decode_response(response, limits.max_response_bytes)
        hashes.append((endpoint, digest))
        verified_reads.append(endpoint)
        return value

    actor: str | None = None
    actor_binding = "UNAVAILABLE"
    try:
        try:
            actor_data = get("authenticated_actor", f"{_API_ROOT}/user")
            raw_actor = actor_data.get("login")
            if isinstance(raw_actor, str) and _LOGIN.fullmatch(raw_actor):
                actor = raw_actor
                if expectation.expected_actor_login is None:
                    actor_binding = "UNCONFIGURED"
                elif actor == expectation.expected_actor_login:
                    actor_binding = "MATCHED_TRUSTED_POLICY"
                else:
                    actor_binding = "MISMATCHED_TRUSTED_POLICY"
            else:
                actor_binding = "INVALID_API_IDENTITY"
        except ActionsRuntimeError as exc:
            # GITHUB_TOKEN is an installation token on current Actions; GET /user
            # is not guaranteed to identify it. Other authoritative reads continue.
            if exc.code != "github_read_unavailable":
                raise
            actor_binding = "UNAVAILABLE"

        repository = get("repository", _api_path(expectation.repository, ""))
        if (
            not _api_id_matches(repository.get("id"), expectation.repository_id)
            or not isinstance(repository.get("full_name"), str)
            or repository["full_name"].casefold() != expectation.repository.casefold()
        ):
            raise ActionsRuntimeError("repository_identity_mismatch")

        publisher = get(
            "publisher_run",
            _api_path(
                expectation.repository,
                f"/actions/runs/{expectation.publisher_run_id}/attempts/{expectation.publisher_run_attempt}",
            ),
        )
        publisher_repo = publisher.get("repository") if isinstance(publisher.get("repository"), dict) else {}
        if (
            not _api_id_matches(publisher.get("id"), expectation.publisher_run_id)
            or not _api_id_matches(publisher.get("run_attempt"), expectation.publisher_run_attempt)
            or not _api_id_matches(publisher.get("workflow_id"), expectation.publisher_workflow_id)
            or not _api_id_matches(publisher_repo.get("id"), expectation.repository_id)
            or publisher.get("head_sha") != expectation.publisher_workflow_sha
            or not _workflow_reference_matches(
                publisher.get("path"),
                expectation.publisher_workflow_path,
                expectation.publisher_workflow_ref,
            )
        ):
            raise ActionsRuntimeError("publisher_run_identity_mismatch")

        upstream = get(
            "upstream_run",
            _api_path(
                expectation.repository,
                f"/actions/runs/{expectation.upstream_run_id}/attempts/{expectation.upstream_run_attempt}",
            ),
        )
        upstream_repo = upstream.get("repository") if isinstance(upstream.get("repository"), dict) else {}
        upstream_matches = []
        pull_requests = upstream.get("pull_requests")
        if isinstance(pull_requests, list):
            for item in pull_requests:
                if not isinstance(item, dict) or not _api_id_matches(
                    item.get("number"), expectation.pull_request_number
                ):
                    continue
                base = item.get("base") if isinstance(item.get("base"), dict) else {}
                head = item.get("head") if isinstance(item.get("head"), dict) else {}
                if base.get("sha") == expectation.base_sha and head.get("sha") == expectation.head_sha:
                    upstream_matches.append(item)
        if (
            not _api_id_matches(upstream.get("id"), expectation.upstream_run_id)
            or not _api_id_matches(upstream.get("run_attempt"), expectation.upstream_run_attempt)
            or not _api_id_matches(upstream.get("workflow_id"), expectation.caller_workflow_id)
            or not _api_id_matches(upstream_repo.get("id"), expectation.repository_id)
            # For pull_request runs, the workflow-run head SHA is a run commit
            # and may be a synthetic merge ref. Bind the source head/base using
            # the API's pull_requests entries and the fresh PR endpoint below.
            or not _workflow_reference_matches(
                upstream.get("path"),
                expectation.caller_workflow_path,
                expectation.caller_workflow_ref,
            )
            or upstream.get("event") != "pull_request"
            or upstream.get("status") != "completed"
            or upstream.get("conclusion") != "success"
            or len(upstream_matches) != 1
        ):
            raise ActionsRuntimeError("upstream_run_identity_mismatch")

        pull = get(
            "pull_request",
            _api_path(expectation.repository, f"/pulls/{expectation.pull_request_number}"),
        )
        base = pull.get("base") if isinstance(pull.get("base"), dict) else {}
        head = pull.get("head") if isinstance(pull.get("head"), dict) else {}
        base_repo = base.get("repo") if isinstance(base.get("repo"), dict) else {}
        if (
            not _api_id_matches(pull.get("number"), expectation.pull_request_number)
            or pull.get("state") != "open"
            or not _api_id_matches(base_repo.get("id"), expectation.repository_id)
            or base.get("sha") != expectation.base_sha
            or head.get("sha") != expectation.head_sha
        ):
            raise ActionsRuntimeError("pull_request_identity_mismatch")

        return RuntimeCanaryResult(
            "READ_ONLY_CONTEXT_VERIFIED",
            "publisher_write_capability_not_verified",
            expectation.repository_id,
            actor,
            actor_binding,
            tuple(verified_reads),
            tuple(hashes),
        )
    except ActionsRuntimeError as exc:
        return RuntimeCanaryResult(
            "UNKNOWN",
            exc.code,
            expectation.repository_id if "repository" in verified_reads else None,
            actor,
            actor_binding,
            tuple(verified_reads),
            tuple(hashes),
        )
    except Exception:
        # Transport exceptions may contain URLs, headers or credential details.
        return RuntimeCanaryResult(
            "UNKNOWN",
            "github_read_unavailable",
            expectation.repository_id if "repository" in verified_reads else None,
            actor,
            actor_binding,
            tuple(verified_reads),
            tuple(hashes),
        )


def _positive_platform_int(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int) and 0 < value <= 2**53 - 1:
        return value
    if isinstance(value, str) and re.fullmatch(r"[1-9][0-9]{0,15}", value):
        parsed = int(value)
        return parsed if parsed <= 2**53 - 1 else None
    return None


def canary_expectation_from_environment(environ: Mapping[str, str], event_bytes: bytes) -> CanaryExpectation:
    """Build the trusted-boundary expectation from runner context and repo policy vars."""
    if not isinstance(event_bytes, bytes) or len(event_bytes) > 256 * 1024:
        raise ActionsRuntimeError("workflow_event_invalid_or_oversized")
    try:
        event = json.loads(event_bytes, object_pairs_hook=_strict_object, parse_constant=_reject_json_constant)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError):
        raise ActionsRuntimeError("workflow_event_invalid_json") from None
    if not isinstance(event, dict):
        raise ActionsRuntimeError("workflow_event_invalid")
    upstream = event.get("workflow_run") if isinstance(event.get("workflow_run"), dict) else {}
    repository = event.get("repository") if isinstance(event.get("repository"), dict) else {}
    pull_requests = upstream.get("pull_requests")
    if not isinstance(pull_requests, list) or len(pull_requests) != 1 or not isinstance(pull_requests[0], dict):
        raise ActionsRuntimeError("workflow_event_pr_binding_missing_or_ambiguous")
    pull = pull_requests[0]
    expected_workflow_name = environ.get("PR_REVIEW_ANALYSIS_WORKFLOW_NAME")
    if (
        not isinstance(expected_workflow_name, str)
        or not expected_workflow_name
        or len(expected_workflow_name) > 128
        or upstream.get("name") != expected_workflow_name
    ):
        raise ActionsRuntimeError("workflow_event_name_mismatch")
    base = pull.get("base") if isinstance(pull.get("base"), dict) else {}
    head = pull.get("head") if isinstance(pull.get("head"), dict) else {}
    values = {
        "repository": environ.get("GITHUB_REPOSITORY"),
        "repository_id": _positive_platform_int(repository.get("id")),
        "publisher_run_id": _positive_platform_int(environ.get("GITHUB_RUN_ID")),
        "publisher_run_attempt": _positive_platform_int(environ.get("GITHUB_RUN_ATTEMPT")),
        "publisher_workflow_id": _positive_platform_int(environ.get("PR_REVIEW_PUBLISHER_WORKFLOW_ID")),
        "publisher_workflow_path": environ.get("PR_REVIEW_PUBLISHER_WORKFLOW_PATH", ".github/workflows/pr-publish.yml"),
        "publisher_workflow_ref": environ.get("GITHUB_REF"),
        "publisher_workflow_sha": environ.get("GITHUB_SHA"),
        "upstream_run_id": _positive_platform_int(upstream.get("id")),
        "upstream_run_attempt": _positive_platform_int(upstream.get("run_attempt")),
        "caller_workflow_id": _positive_platform_int(environ.get("PR_REVIEW_ANALYSIS_WORKFLOW_ID")),
        "caller_workflow_path": environ.get("PR_REVIEW_ANALYSIS_WORKFLOW_PATH"),
        "caller_workflow_ref": environ.get("PR_REVIEW_ANALYSIS_WORKFLOW_REF"),
        "pull_request_number": _positive_platform_int(pull.get("number")),
        "base_sha": base.get("sha"),
        "head_sha": head.get("sha"),
        "expected_actor_login": environ.get("PR_REVIEW_PUBLISHER_ACTOR") or None,
    }
    try:
        return CanaryExpectation(**values)
    except (TypeError, ActionsRuntimeError):
        raise ActionsRuntimeError("trusted_canary_policy_unavailable_or_invalid") from None


def run_actions_canary(
    environ: Mapping[str, str] | None = None,
    *,
    transport: ReadOnlyTransport | None = None,
    uploader: "OfficialActionsArtifactUploader | None" = None,
) -> dict[str, object]:
    """Verify local runtime provenance and read-only API bindings, then upload a receipt."""
    environ = os.environ if environ is None else environ
    runtime_identity = _runtime_source_identity(environ)
    if runtime_identity["state"] != "VERIFIED":
        result = RuntimeCanaryResult(
            "UNKNOWN",
            str(runtime_identity["reason_code"]),
            None,
            None,
            "UNAVAILABLE",
            (),
            (),
            runtime_identity=runtime_identity,
        )
    else:
        try:
            event_path = environ.get("GITHUB_EVENT_PATH")
            if not isinstance(event_path, str) or not event_path:
                raise ActionsRuntimeError("workflow_event_unavailable")
            event_file = Path(event_path)
            file_stat = event_file.lstat()
            if not stat.S_ISREG(file_stat.st_mode) or file_stat.st_size > 256 * 1024:
                raise ActionsRuntimeError("workflow_event_invalid_or_oversized")
            with event_file.open("rb") as source:
                event_bytes = source.read(256 * 1024 + 1)
            expectation = canary_expectation_from_environment(environ, event_bytes)
            result = verify_read_only_actions_context(
                expectation, environ.get("GITHUB_TOKEN", ""), transport=transport
            )
        except ActionsRuntimeError as exc:
            result = RuntimeCanaryResult("UNKNOWN", exc.code, None, None, "UNAVAILABLE", (), ())
        except OSError:
            result = RuntimeCanaryResult("UNKNOWN", "workflow_event_unavailable", None, None, "UNAVAILABLE", (), ())
        result = replace(result, runtime_identity=runtime_identity)
    document = result.as_dict()
    payload = (json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")
    try:
        upload_result = (uploader or OfficialActionsArtifactUploader(environ=environ)).upload(
            run_id=_positive_platform_int(environ.get("GITHUB_RUN_ID")) or 0,
            artifact_name="pr-review-actions-canary-"
            + str(_positive_platform_int(environ.get("GITHUB_RUN_ID")) or "unbound"),
            filename="canary.json",
            content=payload,
            timeout_seconds=30.0,
        )
    except Exception:
        upload_result = ArtifactUploadResult("UNAVAILABLE", reason_code="artifact_upload_failed")
    document["artifact_upload_state"] = upload_result.status
    document["artifact_id"] = upload_result.artifact_id
    document["artifact_upload_reason"] = upload_result.reason_code
    return document


if __name__ == "__main__":
    print(json.dumps(run_actions_canary(), sort_keys=True, separators=(",", ":")))
