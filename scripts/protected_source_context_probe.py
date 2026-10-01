#!/usr/bin/env python3
"""Emit bounded, sanitized observations of a protected PR-target run context.

This is a qualification probe, not an identity verifier. Its output records
what the runner environment and read-only GitHub REST API returned; callers
must not use the report as authorization or as a publication receipt.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Callable, Mapping
from urllib.parse import quote

from pr_review_harness.actions_publication import GitHubHTTPTransport, UrllibGitHubTransport

_API_ROOT = "https://api.github.com"
_EVENT_LIMIT = 256 * 1024
_BODY_LIMIT = 128 * 1024
_TOKEN_LIMIT = 16 * 1024
_TIME_LIMIT = 20.0
_CALL_LIMIT = 3
_SHA = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_REPO = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
_REF = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,127}\Z")
_SAFE_REF_PATH = re.compile(r"refs/heads/[A-Za-z0-9][A-Za-z0-9._/-]{0,127}\Z")


class ProbeError(ValueError):
    """Safe, stable failure code for a probe that could not observe context."""

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
    raise ValueError("invalid JSON constant")


def _json_object(raw: bytes, *, limit: int, code: str) -> dict[str, object]:
    if not isinstance(raw, bytes) or len(raw) > limit:
        raise ProbeError(code)
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError):
        raise ProbeError(code) from None
    if not isinstance(value, dict):
        raise ProbeError(code)
    return value


def _positive_integer(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _sha(value: object) -> bool:
    return isinstance(value, str) and _SHA.fullmatch(value) is not None


def _safe_ref(value: object) -> str | None:
    if (
        not isinstance(value, str)
        or not _REF.fullmatch(value)
        or ".." in value.split("/")
        or "//" in value
        or "@{" in value
    ):
        return None
    return value


def _sha256_text(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def _safe_workflow_ref(value: object) -> str | None:
    if not isinstance(value, str) or len(value) > 512 or any(ord(ch) < 0x20 for ch in value):
        return None
    if "@" not in value:
        return None
    repo_path, ref = value.rsplit("@", 1)
    parts = repo_path.split("/")
    if (
        len(parts) < 4
        or not _REPO.fullmatch(parts[0] + "/" + parts[1])
        or not re.fullmatch(r"\.github/workflows/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*\.ya?ml", "/".join(parts[2:]))
    ):
        return None
    if not _SAFE_REF_PATH.fullmatch(ref) or ".." in ref.split("/") or "//" in ref:
        return None
    return value


def _safe_api_workflow_path(value: object) -> str | None:
    if not isinstance(value, str) or len(value) > 256:
        return None
    path = value.split("@", 1)[0]
    if not re.fullmatch(r"\.github/workflows/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*\.ya?ml", path):
        return None
    return path


def _api_get(
    transport: GitHubHTTPTransport,
    token: str,
    url: str,
    *,
    deadline: float,
    clock: Callable[[], float],
) -> dict[str, object]:
    remaining = deadline - clock()
    if remaining <= 0:
        raise ProbeError("probe_deadline_exhausted")
    try:
        response = transport.request(
            "GET",
            url,
            token=token,
            json_body=None,
            timeout_seconds=min(5.0, remaining),
            max_response_bytes=_BODY_LIMIT,
        )
    except Exception:
        raise ProbeError("github_read_unavailable") from None
    if clock() >= deadline:
        raise ProbeError("probe_deadline_exhausted")
    if (
        getattr(response, "status", None) != 200
        or not isinstance(getattr(response, "body", None), bytes)
        or len(response.body) > _BODY_LIMIT
    ):
        raise ProbeError("github_read_unavailable")
    return _json_object(response.body, limit=_BODY_LIMIT, code="github_response_invalid")


def run_probe(
    environ: Mapping[str, str] | None = None,
    *,
    transport: GitHubHTTPTransport | None = None,
    clock: Callable[[], float] = time.monotonic,
) -> dict[str, object]:
    """Collect three bounded read-only observations without asserting trust."""
    env = os.environ if environ is None else environ
    token = env.get("GITHUB_TOKEN", "")
    repository = env.get("GITHUB_REPOSITORY", "")
    run_id = env.get("GITHUB_RUN_ID", "")
    attempt = env.get("GITHUB_RUN_ATTEMPT", "")
    pr_number = env.get("PR_NUMBER", "")
    if (
        not isinstance(token, str)
        or not token
        or len(token) > _TOKEN_LIMIT
        or any(char.isspace() for char in token)
        or not isinstance(repository, str)
        or not _REPO.fullmatch(repository)
        or not re.fullmatch(r"[1-9][0-9]{0,17}", run_id)
        or not re.fullmatch(r"[1-9][0-9]{0,8}", attempt)
        or not re.fullmatch(r"[1-9][0-9]{0,9}", pr_number)
    ):
        raise ProbeError("probe_environment_invalid")
    context_sha = env.get("GITHUB_SHA", "")
    workflow_sha = env.get("GITHUB_WORKFLOW_SHA", "")
    event_name = env.get("GITHUB_EVENT_NAME", "")
    raw_context_ref = env.get("GITHUB_REF", "")
    context_ref = _safe_ref(raw_context_ref.removeprefix("refs/heads/")) if isinstance(raw_context_ref, str) and raw_context_ref.startswith("refs/heads/") else None
    workflow_ref = _safe_workflow_ref(env.get("GITHUB_WORKFLOW_REF", ""))
    if not _sha(context_sha) or not _sha(workflow_sha) or event_name != "pull_request_target":
        raise ProbeError("probe_context_invalid")
    event_path = env.get("GITHUB_EVENT_PATH", "")
    if not isinstance(event_path, str) or not Path(event_path).is_absolute():
        raise ProbeError("probe_event_unavailable")
    try:
        event_stat = Path(event_path).stat()
        if not Path(event_path).is_file() or event_stat.st_size > _EVENT_LIMIT:
            raise ProbeError("probe_event_unavailable")
        with Path(event_path).open("rb") as source:
            event_raw = source.read(_EVENT_LIMIT + 1)
    except OSError:
        raise ProbeError("probe_event_unavailable") from None
    event = _json_object(event_raw, limit=_EVENT_LIMIT, code="probe_event_invalid")
    event_repo = event.get("repository")
    event_pr = event.get("pull_request")
    event_base = event_pr.get("base") if isinstance(event_pr, dict) and isinstance(event_pr.get("base"), dict) else {}
    event_head = event_pr.get("head") if isinstance(event_pr, dict) and isinstance(event_pr.get("head"), dict) else {}
    if (
        not isinstance(event_repo, dict)
        or event_repo.get("full_name") != repository
        or not _positive_integer(event_repo.get("id"))
        or not isinstance(event_pr, dict)
        or not _positive_integer(event_pr.get("number"))
        or event_pr.get("number") != int(pr_number)
    ):
        raise ProbeError("probe_event_binding_invalid")

    api = transport or UrllibGitHubTransport()
    deadline = clock() + _TIME_LIMIT
    repo_path = "/repos/" + quote(repository, safe="/")
    repo = _api_get(api, token, _API_ROOT + repo_path, deadline=deadline, clock=clock)
    run = _api_get(
        api,
        token,
        _API_ROOT + repo_path + f"/actions/runs/{run_id}/attempts/{attempt}",
        deadline=deadline,
        clock=clock,
    )
    pr = _api_get(api, token, _API_ROOT + repo_path + f"/pulls/{pr_number}", deadline=deadline, clock=clock)

    base = pr.get("base") if isinstance(pr.get("base"), dict) else {}
    head = pr.get("head") if isinstance(pr.get("head"), dict) else {}
    base_repo = base.get("repo") if isinstance(base.get("repo"), dict) else {}
    run_repository = run.get("repository") if isinstance(run.get("repository"), dict) else {}
    if (
        repo.get("full_name") != repository
        or not _positive_integer(repo.get("id"))
        or not _positive_integer(run.get("id"))
        or run.get("id") != int(run_id)
        or not _positive_integer(run.get("run_attempt"))
        or run.get("run_attempt") != int(attempt)
        or run.get("event") != "pull_request_target"
        or run_repository.get("id") != repo.get("id")
        or not _positive_integer(pr.get("number"))
        or pr.get("number") != int(pr_number)
        or not _positive_integer(base_repo.get("id"))
        or not _sha(base.get("sha"))
        or not _sha(head.get("sha"))
        or not isinstance(repo.get("default_branch"), str)
        or not _safe_ref(repo["default_branch"])
        or not isinstance(base.get("ref"), str)
        or not _safe_ref(base["ref"])
        or not isinstance(head.get("ref"), str)
        or not _safe_ref(head["ref"])
    ):
        raise ProbeError("github_observation_invalid")

    default_branch = repo["default_branch"]
    base_ref = base["ref"]
    base_sha = base["sha"]
    head_sha = head["sha"]
    api_head_sha = run.get("head_sha") if _sha(run.get("head_sha")) else None
    api_head_branch = _safe_ref(run.get("head_branch"))
    return {
        "schema": "protected-source-context-observation.v1",
        "status": "OBSERVED",
        "evidence_class": "runner_context_and_read_only_api_observations",
        "authorization": "NONE",
        "repository": {
            "full_name": repository,
            "id": repo["id"],
            "default_branch": default_branch,
            "event_payload_id": event_repo["id"],
        },
        "context": {
            "event_name": event_name,
            "ref": "refs/heads/" + context_ref if context_ref is not None else None,
            "sha": context_sha,
            "workflow_ref": workflow_ref,
            "workflow_ref_sha256": _sha256_text(env.get("GITHUB_WORKFLOW_REF")),
            "workflow_sha": workflow_sha,
        },
        "workflow_run_api": {
            "id": int(run_id),
            "attempt": int(attempt),
            "event": run["event"],
            "workflow_id": run.get("workflow_id") if _positive_integer(run.get("workflow_id")) else None,
            "path": _safe_api_workflow_path(run.get("path")),
            "head_branch": api_head_branch,
            "head_branch_sha256": _sha256_text(run.get("head_branch")),
            "head_sha": api_head_sha,
        },
        "pull_request_api": {
            "number": int(pr_number),
            "state": pr.get("state") if pr.get("state") in {"open", "closed"} else "unknown",
            "base_ref": base_ref,
            "base_sha": base_sha,
            "base_repository_id": base_repo["id"],
            "head_ref": _safe_ref(head["ref"]),
            "head_ref_sha256": _sha256_text(head.get("ref")),
            "head_sha": head_sha,
        },
        "pull_request_event": {
            "number": int(pr_number),
            "base_ref": _safe_ref(event_base.get("ref")),
            "base_ref_sha256": _sha256_text(event_base.get("ref")),
            "base_sha": event_base.get("sha") if _sha(event_base.get("sha")) else None,
            "head_ref": _safe_ref(event_head.get("ref")),
            "head_ref_sha256": _sha256_text(event_head.get("ref")),
            "head_sha": event_head.get("sha") if _sha(event_head.get("sha")) else None,
        },
        "comparisons": {
            "event_repository_id_equals_api_repository_id": event_repo["id"] == repo["id"],
            "context_ref_is_default_branch": context_ref == default_branch,
            "pr_base_ref_is_default_branch": base_ref == default_branch,
            "context_sha_equals_workflow_sha": context_sha == workflow_sha,
            "context_sha_equals_current_pr_base_sha": context_sha == base_sha,
            "workflow_sha_equals_current_pr_base_sha": workflow_sha == base_sha,
            "api_run_head_sha_equals_current_pr_head_sha": api_head_sha == head_sha,
            "api_run_head_branch_equals_current_pr_head_ref": api_head_branch == head["ref"],
            "event_base_sha_equals_current_pr_base_sha": event_base.get("sha") == base_sha,
            "event_head_sha_equals_current_pr_head_sha": event_head.get("sha") == head_sha,
        },
        "interpretation": "observations_only; equality values are not identity proof or publication authorization",
    }


def main() -> int:
    try:
        result = run_probe()
    except ProbeError as exc:
        result = {
            "schema": "protected-source-context-observation.v1",
            "status": "INCOMPLETE",
            "authorization": "NONE",
            "reason": exc.code,
        }
    except Exception:
        result = {
            "schema": "protected-source-context-observation.v1",
            "status": "INCOMPLETE",
            "authorization": "NONE",
            "reason": "probe_unavailable",
        }
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result.get("status") == "OBSERVED" else 1


if __name__ == "__main__":
    sys.exit(main())
