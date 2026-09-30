#!/usr/bin/env python3
"""Emit the existing two-file publication artifact from a sealed review result.

The manifest records producer claims. The publication receiver must derive and
check every identity field independently from GitHub's API and operator policy.
This command only performs a bounded read of the current Actions run attempt.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pr_review_harness.actions_publication import HTTPResponse, UrllibGitHubTransport
from pr_review_harness.artifact_intake import ArtifactIdentity, _manifest_for_identity, _validate_manifest
from pr_review_harness.engine import _provider_identity
from pr_review_harness.providers import make_decision_provider, make_provider

_REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
_GIT_SHA = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_SHA40 = re.compile(r"[0-9a-f]{40}\Z")
_SHA64 = re.compile(r"[0-9a-f]{64}\Z")
_MAX_RESULT = 15 * 1024 * 1024
_MAX_PROFILE = 256_000
_MAX_API = 512_000
_API_BASE = "https://api.github.com"
_ENGINE_RESULT_CONTRACT_VERSION = "0.1"


class BundleError(ValueError):
    """Safe stable error code; messages never include input or credential data."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate_json_key")
        value[key] = item
    return value


def _parse_object(raw: bytes, code: str) -> dict[str, Any]:
    try:
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicates,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("nonstandard_json_number")),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError):
        raise BundleError(code) from None
    if not isinstance(value, dict):
        raise BundleError(code)
    return value


def _read_regular(path: Path, limit: int, code: str) -> bytes:
    try:
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > limit:
            raise BundleError(code)
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
        with os.fdopen(descriptor, "rb") as stream:
            opened = os.fstat(stream.fileno())
            if not stat.S_ISREG(opened.st_mode) or opened.st_size > limit:
                raise BundleError(code)
            raw = stream.read(limit + 1)
    except BundleError:
        raise
    except OSError:
        raise BundleError(code) from None
    if len(raw) > limit:
        raise BundleError(code)
    return raw


def _positive_int(env: dict[str, str], name: str) -> int:
    raw = env.get(name, "")
    if not re.fullmatch(r"[1-9][0-9]{0,17}", raw):
        raise BundleError("workflow_integer_invalid")
    return int(raw)


def _api_positive_int(value: Any, code: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise BundleError(code)
    return value


def _github_run(
    *,
    repository: str,
    run_id: int,
    attempt: int,
    token: str,
    transport: Any,
) -> dict[str, Any]:
    if not _REPOSITORY.fullmatch(repository) or not token:
        raise BundleError("github_run_request_invalid")
    try:
        response: HTTPResponse = transport.request(
            "GET",
            f"{_API_BASE}/repos/{repository}/actions/runs/{run_id}/attempts/{attempt}",
            token=token,
            json_body=None,
            timeout_seconds=10,
            max_response_bytes=_MAX_API,
        )
    except Exception:
        raise BundleError("github_run_read_failed") from None
    if response.status != 200 or len(response.body) > _MAX_API:
        raise BundleError("github_run_read_failed")
    return _parse_object(response.body, "github_run_response_invalid")


def _identity_from_run(
    env: dict[str, str],
    run: dict[str, Any],
    provider_identity_hash: str,
) -> ArtifactIdentity:
    repository = env.get("GITHUB_REPOSITORY", "")
    target = env.get("TARGET_REPOSITORY", "")
    if not _REPOSITORY.fullmatch(repository) or repository != target:
        raise BundleError("publication_target_must_be_local")
    repo_obj = run.get("repository")
    if not isinstance(repo_obj, dict):
        raise BundleError("github_run_repository_invalid")
    if repo_obj.get("full_name") != repository:
        raise BundleError("github_run_repository_mismatch")
    repository_id = repo_obj.get("id")
    if isinstance(repository_id, bool) or not isinstance(repository_id, int) or repository_id <= 0:
        raise BundleError("github_run_repository_id_invalid")

    run_id = _positive_int(env, "GITHUB_RUN_ID")
    attempt = _positive_int(env, "GITHUB_RUN_ATTEMPT")
    if _api_positive_int(run.get("id"), "github_run_id_invalid") != run_id:
        raise BundleError("github_run_id_mismatch")
    if _api_positive_int(run.get("run_attempt"), "github_run_attempt_invalid") != attempt:
        raise BundleError("github_run_attempt_mismatch")

    workflow_id = run.get("workflow_id")
    if isinstance(workflow_id, bool) or not isinstance(workflow_id, int) or workflow_id <= 0:
        raise BundleError("github_workflow_id_invalid")
    workflow_path = run.get("path")
    full_workflow_ref = env.get("GITHUB_WORKFLOW_REF", "")
    ref_prefix = f"{repository}/"
    if not full_workflow_ref.startswith(ref_prefix) or "@" not in full_workflow_ref:
        raise BundleError("github_workflow_ref_invalid")
    expected_path, separator, caller_ref = full_workflow_ref[len(ref_prefix):].rpartition("@")
    if not separator or not caller_ref.startswith("refs/"):
        raise BundleError("github_workflow_ref_invalid")
    if not isinstance(workflow_path, str) or workflow_path != expected_path or not workflow_path.startswith(".github/workflows/"):
        raise BundleError("github_workflow_path_mismatch")
    workflow_sha = run.get("head_sha")
    if not isinstance(workflow_sha, str) or not _GIT_SHA.fullmatch(workflow_sha):
        raise BundleError("github_run_head_sha_invalid")
    if workflow_sha != env.get("GITHUB_SHA"):
        raise BundleError("github_run_head_sha_mismatch")
    caller_workflow_sha = env.get("GITHUB_WORKFLOW_SHA", "")
    if not _GIT_SHA.fullmatch(caller_workflow_sha):
        raise BundleError("caller_workflow_sha_invalid")
    branch = run.get("head_branch")
    if not isinstance(branch, str) or not branch or any(c in branch for c in "\r\n\x00"):
        raise BundleError("github_run_branch_invalid")
    pr_number = _positive_int(env, "PR_NUMBER")
    if caller_ref not in {
        f"refs/heads/{branch}",
        f"refs/tags/{branch}",
        f"refs/pull/{pr_number}/merge",
    }:
        raise BundleError("github_workflow_ref_mismatch")

    base_sha = env.get("BASE_SHA", "")
    head_sha = env.get("HEAD_SHA", "")
    if not _GIT_SHA.fullmatch(base_sha) or not _GIT_SHA.fullmatch(head_sha):
        raise BundleError("target_revision_invalid")
    prs = run.get("pull_requests")
    if not isinstance(prs, list):
        raise BundleError("github_run_pull_requests_invalid")
    matching = [
        item
        for item in prs
        if isinstance(item, dict)
        and isinstance(item.get("number"), int)
        and not isinstance(item.get("number"), bool)
        and item.get("number") == pr_number
    ]
    if len(matching) != 1:
        raise BundleError("github_run_pull_request_binding_missing")
    pr = matching[0]
    base = pr.get("base")
    head = pr.get("head")
    if not isinstance(base, dict) or not isinstance(head, dict):
        raise BundleError("github_run_pull_request_binding_invalid")
    if base.get("sha") != base_sha or head.get("sha") != head_sha:
        raise BundleError("github_run_pull_request_revision_mismatch")
    base_repo = base.get("repo")
    if isinstance(base_repo, dict) and base_repo.get("id") != repository_id:
        raise BundleError("github_run_pull_request_repository_mismatch")

    harness_repository = env.get("HARNESS_REPOSITORY", "")
    harness_sha = env.get("HARNESS_SHA", "")
    called_path = env.get("CALLED_WORKFLOW_FILE_PATH", "")
    called_sha = env.get("CALLED_WORKFLOW_SHA", "")
    called_repo = env.get("CALLED_WORKFLOW_REPOSITORY", "")
    called_ref = env.get("CALLED_WORKFLOW_REF", "")
    expected_called_ref = f"{called_repo}/{called_path}@{harness_sha}"
    if (
        not _REPOSITORY.fullmatch(harness_repository)
        or not _GIT_SHA.fullmatch(harness_sha)
        or harness_repository != called_repo
        or harness_sha != called_sha
        or called_ref != expected_called_ref
        or called_path != ".github/workflows/pr-analysis.yml"
    ):
        raise BundleError("called_harness_identity_mismatch")

    profile_version = env.get("PROFILE_VERSION", "")
    profile_sha = env.get("PROFILE_SHA256", "")
    if not profile_version or len(profile_version) > 128 or not _SHA64.fullmatch(profile_sha):
        raise BundleError("profile_binding_invalid")
    if not _SHA64.fullmatch(provider_identity_hash):
        raise BundleError("provider_identity_invalid")
    return ArtifactIdentity(
        repository_id=repository_id,
        repository=repository,
        pull_request_number=pr_number,
        base_sha=base_sha,
        head_sha=head_sha,
        upstream_run_id=run_id,
        upstream_run_attempt=attempt,
        caller_workflow_id=workflow_id,
        caller_workflow_path=workflow_path,
        caller_workflow_ref=caller_ref,
        caller_workflow_sha=caller_workflow_sha,
        called_harness_repository=harness_repository,
        called_harness_path=called_path,
        called_harness_sha=harness_sha,
        profile_version=profile_version,
        profile_sha256=profile_sha,
        provider_configuration_identity=f"provider-identity-sha256:{provider_identity_hash}",
        contract_versions=(("artifact_manifest", "1.0"), ("review_result", _ENGINE_RESULT_CONTRACT_VERSION)),
    )


def _canonical_hash(value: Any) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _effective_provider_identity(provider_path: Path, decision_path: Path) -> dict[str, Any]:
    provider_raw = _read_regular(provider_path, 128_000, "provider_config_unavailable")
    decision_raw = _read_regular(decision_path, 128_000, "decision_config_unavailable")
    provider_config = _parse_object(provider_raw, "provider_config_invalid")
    decision_config = _parse_object(decision_raw, "decision_config_invalid")
    try:
        provider = make_provider(provider_config)
        decision_provider = make_decision_provider(decision_config)
        identity = _provider_identity(provider, decision_provider)
    except Exception:
        raise BundleError("provider_config_invalid") from None
    if not isinstance(identity, dict):
        raise BundleError("provider_identity_invalid")
    return identity


def create_publication_directory(
    *,
    result_path: Path,
    profile_path: Path,
    output_dir: Path,
    env: dict[str, str],
    transport: Any | None = None,
    provider_config_path: Path | None = None,
    decision_config_path: Path | None = None,
) -> ArtifactIdentity:
    """Create exactly review-result.json and provenance.json in a new directory."""
    repository = env.get("GITHUB_REPOSITORY", "")
    if repository != env.get("TARGET_REPOSITORY") or not _REPOSITORY.fullmatch(repository):
        raise BundleError("publication_target_must_be_local")
    result_raw = _read_regular(result_path, _MAX_RESULT, "sealed_result_unavailable")
    profile_raw = _read_regular(profile_path, _MAX_PROFILE, "profile_unavailable")
    result = _parse_object(result_raw, "sealed_result_invalid")
    profile = _parse_object(profile_raw, "profile_invalid")
    profile_sha = hashlib.sha256(profile_raw).hexdigest()
    if profile_sha != env.get("PROFILE_SHA256") or profile.get("repository") != repository:
        raise BundleError("profile_binding_mismatch")
    if profile.get("version") != env.get("PROFILE_VERSION"):
        raise BundleError("profile_binding_mismatch")
    if provider_config_path is None or decision_config_path is None:
        provider_config_path = Path(env.get("PROVIDER_CONFIG", ""))
        decision_config_path = Path(env.get("DECISION_CONFIG", ""))
    expected_provider_identity = _effective_provider_identity(provider_config_path, decision_config_path)
    provider_identity = result.get("provider_identity")
    if not isinstance(provider_identity, dict) or provider_identity != expected_provider_identity:
        raise BundleError("provider_identity_mismatch")
    provider_sha = _canonical_hash(expected_provider_identity)
    if result.get("contract_version") != _ENGINE_RESULT_CONTRACT_VERSION:
        raise BundleError("result_contract_version_mismatch")

    token = env.get("GH_TOKEN", "")
    run_id = _positive_int(env, "GITHUB_RUN_ID")
    attempt = _positive_int(env, "GITHUB_RUN_ATTEMPT")
    api_run = _github_run(
        repository=repository,
        run_id=run_id,
        attempt=attempt,
        token=token,
        transport=transport or UrllibGitHubTransport(),
    )
    identity = _identity_from_run(env, api_run, provider_sha)
    expected_result_id = f"pr-{identity.pull_request_number}-{identity.upstream_run_id}"
    if (
        result.get("repository") != identity.repository
        or result.get("pull_request_number") != identity.pull_request_number
        or result.get("base_sha") != identity.base_sha
        or result.get("head_sha") != identity.head_sha
        or result.get("project_profile_version") != identity.profile_version
        or result.get("run_id") != expected_result_id
        or not isinstance(result.get("result_hash"), str)
    ):
        raise BundleError("sealed_result_identity_mismatch")

    manifest = _manifest_for_identity(identity)
    manifest.update(
        {
            "review_run_id": result["run_id"],
            "result_file_sha256": hashlib.sha256(result_raw).hexdigest(),
            "result_hash": result["result_hash"],
            "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        }
    )
    try:
        _validate_manifest(manifest, identity, result_raw, result)
    except Exception:
        raise BundleError("sealed_result_intake_validation_failed") from None
    manifest_raw = (json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()
    secret_values = [env.get("LLM_API_KEY", ""), env.get("JEV_API_KEY", ""), token]
    if any(secret and (secret.encode("utf-8") in result_raw or secret.encode("utf-8") in manifest_raw) for secret in secret_values):
        raise BundleError("credential_leak_detected")

    try:
        output_dir.mkdir(mode=0o700, parents=False, exist_ok=False)
        for name, raw in (("review-result.json", result_raw), ("provenance.json", manifest_raw)):
            descriptor = os.open(
                output_dir / name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
                0o600,
            )
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
    except OSError:
        raise BundleError("publication_bundle_write_failed") from None
    return identity


def main(
    argv: list[str] | None = None,
    *,
    environ: dict[str, str] | None = None,
    transport: Any | None = None,
) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--result", type=Path, required=True)
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        create_publication_directory(
            result_path=args.result,
            profile_path=args.profile,
            output_dir=args.output_dir,
            env=dict(os.environ) if environ is None else environ,
            transport=transport,
        )
    except BundleError as exc:
        print(json.dumps({"status": "REJECTED", "error": exc.code}, sort_keys=True, separators=(",", ":")), file=sys.stderr)
        return 2
    print('{"status":"BUNDLE_READY","identity_source":"bounded_github_run_attempt_api_plus_local_inputs"}')
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
