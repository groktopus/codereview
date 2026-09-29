#!/usr/bin/env python3
"""Authenticated, read-only fetch for one selected PR-analysis workflow artifact.

The operator must supply a trusted request file and a read-only Actions token via
an environment variable. Responses and archive bytes are bounded. This fetcher
does not publish, dispatch, call providers, execute target code, or authorize resume.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Protocol

import intake_pr_analysis_artifact as intake
from pr_analysis_artifact_manifest import (
    ManifestError,
    _identity,
    _parse_json,
    _workflow_target_binding_valid,
    canonical,
)

SCHEMA = "pr-analysis-recovery-request.v1"
TRUSTED_KEYS = {
    "schema_version",
    "workflow_repository",
    "workflow_run_id",
    "workflow_run_attempt",
    "run_workflow_ref",
    "target_repository",
    "pull_request_number",
    "harness_repository",
    "harness_sha",
    "called_workflow_ref",
    "called_workflow_sha",
    "called_workflow_repository",
    "called_workflow_file_path",
}
API_VERSION = "2026-03-10"
API_LIMIT = intake.MAX_API_BYTES
TOKEN_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
REPO = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
SHA1 = re.compile(r"^[0-9a-f]{40}$")
RUN_ID = re.compile(r"^[1-9][0-9]{0,19}$")
RUN_ATTEMPT = re.compile(r"^[1-9][0-9]{0,5}$")
# Observed GitHub.com Actions artifact redirect host pattern. The REST contract
# promises a Location redirect but does not standardize this storage hostname;
# unsupported hosts fail closed until confirmed against a live GitHub.com run.
ARTIFACT_HOST = re.compile(r"^productionresultssa[0-9]+\.blob\.core\.windows\.net$")


class FetchError(ValueError):
    pass


@dataclass(frozen=True)
class HttpResponse:
    status: int
    headers: Mapping[str, str]
    body: bytes


class HttpTransport(Protocol):
    def get(self, url: str, *, headers: Mapping[str, str], limit: int) -> HttpResponse: ...


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


class UrllibTransport:
    """No-follow HTTPS transport. Redirect policy is enforced by the caller."""

    def __init__(self, timeout: float = 20.0) -> None:
        self.timeout = timeout
        self.opener = urllib.request.build_opener(_NoRedirect())

    def get(self, url: str, *, headers: Mapping[str, str], limit: int) -> HttpResponse:
        request = urllib.request.Request(url, headers=dict(headers), method="GET")
        try:
            response = self.opener.open(request, timeout=self.timeout)
        except urllib.error.HTTPError as error:
            response = error
        except (urllib.error.URLError, TimeoutError, OSError):
            raise FetchError("recovery_fetch_failed") from None
        with response:
            data = response.read(limit + 1)
            if len(data) > limit:
                raise FetchError("recovery_response_too_large")
            return HttpResponse(int(response.status), dict(response.headers.items()), data)


def _validate_request(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != TRUSTED_KEYS or value.get("schema_version") != SCHEMA:
        raise FetchError("trusted_request_shape_invalid")
    if (
        not isinstance(value.get("workflow_repository"), str)
        or not REPO.fullmatch(value["workflow_repository"])
        or not isinstance(value.get("target_repository"), str)
        or not REPO.fullmatch(value["target_repository"])
        or not _workflow_target_binding_valid(
            value["workflow_repository"],
            value["target_repository"],
            value.get("run_workflow_ref"),
            harness_repository=value.get("harness_repository"),
            called_workflow_repository=value.get("called_workflow_repository"),
            harness_sha=value.get("harness_sha"),
            called_workflow_sha=value.get("called_workflow_sha"),
        )
        or not isinstance(value.get("workflow_run_id"), str)
        or not RUN_ID.fullmatch(value["workflow_run_id"])
        or not isinstance(value.get("workflow_run_attempt"), str)
        or not RUN_ATTEMPT.fullmatch(value["workflow_run_attempt"])
        or isinstance(value.get("pull_request_number"), bool)
        or not isinstance(value.get("pull_request_number"), int)
        or value["pull_request_number"] < 1
        or not isinstance(value.get("harness_repository"), str)
        or not REPO.fullmatch(value["harness_repository"])
        or not isinstance(value.get("harness_sha"), str)
        or not SHA1.fullmatch(value["harness_sha"])
        or not isinstance(value.get("called_workflow_sha"), str)
        or not SHA1.fullmatch(value["called_workflow_sha"])
        or value.get("called_workflow_repository") != value.get("harness_repository")
        or value.get("called_workflow_file_path") != ".github/workflows/pr-analysis.yml"
    ):
        raise FetchError("trusted_request_identity_invalid")
    for field, repo_field, path_field in (
        ("run_workflow_ref", "workflow_repository", None),
        ("called_workflow_ref", "called_workflow_repository", "called_workflow_file_path"),
    ):
        reference = value.get(field)
        prefix = f"{value[repo_field]}/"
        ref_path = reference.rsplit("@", 1)[0] if isinstance(reference, str) and "@" in reference else ""
        workflow_path = ref_path[len(prefix) :] if ref_path.startswith(prefix) else ""
        if (
            not isinstance(reference, str)
            or len(reference) > 1024
            or reference.count("@") != 1
            or not ref_path.startswith(prefix)
            or not re.fullmatch(r"\.github/workflows/[A-Za-z0-9._/-]+\.ya?ml", workflow_path)
            or (path_field and workflow_path != value[path_field])
            or not re.fullmatch(r"[A-Za-z0-9._/-]{1,256}", reference.rsplit("@", 1)[1])
        ):
            raise FetchError("trusted_request_workflow_invalid")
    run_ref_path = value["run_workflow_ref"].split("@", 1)[0]
    if run_ref_path.count("/") < 3:
        raise FetchError("trusted_request_workflow_invalid")
    return dict(value)


def _api_base(value: str) -> str:
    parsed = urllib.parse.urlsplit(value)
    try:
        port = parsed.port
    except ValueError:
        raise FetchError("api_base_invalid") from None
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.hostname.lower() != "api.github.com"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or port not in {None, 443}
    ):
        raise FetchError("api_base_invalid")
    return value.rstrip("/")


def _repo_path(repository: str) -> str:
    owner, name = repository.split("/", 1)
    return f"repos/{urllib.parse.quote(owner, safe='')}/{urllib.parse.quote(name, safe='')}"


def _request(
    transport: HttpTransport,
    url: str,
    *,
    token: str,
    limit: int,
    accept: str = "application/vnd.github+json",
) -> bytes:
    response = transport.get(
        url,
        headers={
            "Accept": accept,
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": API_VERSION,
        },
        limit=limit,
    )
    if len(response.body) > limit:
        raise FetchError("recovery_response_too_large")
    if response.status != 200:
        raise FetchError("recovery_api_status_invalid")
    return response.body


def _validate_redirect(location: str) -> str:
    if not isinstance(location, str) or len(location) > 16_384:
        raise FetchError("artifact_redirect_invalid")
    parsed = urllib.parse.urlsplit(location)
    try:
        port = parsed.port
    except ValueError:
        raise FetchError("artifact_redirect_invalid") from None
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or port not in {None, 443}
        or parsed.fragment
        or not ARTIFACT_HOST.fullmatch(parsed.hostname.lower())
    ):
        raise FetchError("artifact_redirect_invalid")
    return location


def _download_archive(transport: HttpTransport, url: str, *, token: str, limit: int) -> bytes:
    response = transport.get(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": API_VERSION,
        },
        limit=16 * 1024,
    )
    if response.status != 302:
        raise FetchError("artifact_download_redirect_required")
    location = next((value for key, value in response.headers.items() if key.lower() == "location"), None)
    location = _validate_redirect(location)
    # Do not send the API bearer token to the signed storage URL.
    archive = transport.get(location, headers={"Accept": "application/zip"}, limit=limit)
    if archive.status != 200 or len(archive.body) > limit:
        raise FetchError("artifact_download_failed")
    return archive.body


def _validate_pull_response(raw: bytes, request: dict[str, Any]) -> dict[str, Any]:
    pull = _parse_json(raw, "recovery_pull_request_invalid")
    base = pull.get("base")
    head = pull.get("head")
    base_repo = base.get("repo") if isinstance(base, dict) else None
    if (
        isinstance(pull.get("number"), bool)
        or pull.get("number") != request["pull_request_number"]
        or pull.get("state") != "open"
        or not isinstance(base, dict)
        or not isinstance(head, dict)
        or not SHA1.fullmatch(base.get("sha", ""))
        or not SHA1.fullmatch(head.get("sha", ""))
        or not isinstance(base_repo, dict)
        or not isinstance(base_repo.get("full_name"), str)
        or base_repo["full_name"].casefold() != request["target_repository"].casefold()
    ):
        raise FetchError("recovery_pull_request_binding_mismatch")
    return {"number": pull["number"], "base_sha": base["sha"], "head_sha": head["sha"]}


def _normalize_run_prs(run_raw: bytes, pr: dict[str, Any]) -> bytes:
    run = _parse_json(run_raw, "recovery_run_metadata_invalid")
    rows = run.get("pull_requests")
    expected = {
        "number": pr["number"],
        "base": {"sha": pr["base_sha"]},
        "head": {"sha": pr["head_sha"]},
    }
    if rows == []:
        run["pull_requests"] = [expected]
    elif not isinstance(rows, list) or len(rows) != 1:
        raise FetchError("recovery_run_pr_binding_mismatch")
    else:
        row = rows[0]
        if (
            not isinstance(row, dict)
            or isinstance(row.get("number"), bool)
            or row.get("number") != expected["number"]
            or not isinstance(row.get("base"), dict)
            or not isinstance(row.get("head"), dict)
            or row["base"].get("sha") != pr["base_sha"]
            or row["head"].get("sha") != pr["head_sha"]
        ):
            raise FetchError("recovery_run_pr_binding_mismatch")
    return canonical(run)


def _trusted_expected_identity(
    request: dict[str, Any], run_raw: bytes, pr: dict[str, Any], archive: bytes
) -> dict[str, Any]:
    _files, archive_manifest = intake._unpack_archive(archive)
    identity = archive_manifest.get("identity")
    if not isinstance(identity, dict):
        raise FetchError("recovery_manifest_invalid")
    identity = _identity(identity)
    run = _parse_json(run_raw, "recovery_run_metadata_invalid")
    trusted = {
        "workflow_repository": request["workflow_repository"],
        "workflow_run_id": request["workflow_run_id"],
        "workflow_run_attempt": request["workflow_run_attempt"],
        "workflow_run_head_sha": run.get("head_sha"),
        "run_workflow_ref": request["run_workflow_ref"],
        "target_repository": request["target_repository"],
        "pull_request_number": request["pull_request_number"],
        "base_sha": pr["base_sha"],
        "head_sha": pr["head_sha"],
        "harness_repository": request["harness_repository"],
        "harness_sha": request["harness_sha"],
        "called_workflow_ref": request["called_workflow_ref"],
        "called_workflow_sha": request["called_workflow_sha"],
        "called_workflow_repository": request["called_workflow_repository"],
        "called_workflow_file_path": request["called_workflow_file_path"],
    }
    if any(identity.get(key) != value for key, value in trusted.items()):
        raise FetchError("recovery_trusted_identity_mismatch")
    return identity


def fetch_and_intake(
    *,
    request_value: Any,
    token: str,
    output_dir: Path,
    transport: HttpTransport | None = None,
    api_base: str = "https://api.github.com",
) -> dict[str, Any]:
    request = _validate_request(request_value)
    if not isinstance(token, str) or not token or len(token) > 8192 or "\n" in token or "\r" in token:
        raise FetchError("actions_read_token_required")
    base = _api_base(api_base)
    transport = transport or UrllibTransport()
    run_url = (
        f"{base}/{_repo_path(request['workflow_repository'])}/actions/runs/"
        f"{request['workflow_run_id']}/attempts/{request['workflow_run_attempt']}"
    )
    pr_url = f"{base}/{_repo_path(request['target_repository'])}/pulls/{request['pull_request_number']}"
    artifacts_url = f"{base}/{_repo_path(request['workflow_repository'])}/actions/runs/{request['workflow_run_id']}/artifacts?per_page=100"
    run_raw = _request(transport, run_url, token=token, limit=API_LIMIT)
    pr_raw = _request(transport, pr_url, token=token, limit=API_LIMIT)
    pr = _validate_pull_response(pr_raw, request)
    artifacts_raw = _request(transport, artifacts_url, token=token, limit=API_LIMIT)
    run_obj = _parse_json(run_raw, "recovery_run_metadata_invalid")
    if not isinstance(run_obj.get("head_sha"), str) or not SHA1.fullmatch(run_obj["head_sha"]):
        raise FetchError("recovery_run_metadata_invalid")
    normalized_run = _normalize_run_prs(run_raw, pr)
    expected_seed = {
        "workflow_repository": request["workflow_repository"],
        "workflow_run_id": request["workflow_run_id"],
        "workflow_run_attempt": request["workflow_run_attempt"],
        "workflow_run_head_sha": run_obj["head_sha"],
        "run_workflow_ref": request["run_workflow_ref"],
        "called_workflow_ref": request["called_workflow_ref"],
        "called_workflow_sha": request["called_workflow_sha"],
        "called_workflow_repository": request["called_workflow_repository"],
        "called_workflow_file_path": request["called_workflow_file_path"],
        "target_repository": request["target_repository"],
        "pull_request_number": request["pull_request_number"],
        "base_sha": pr["base_sha"],
        "head_sha": pr["head_sha"],
        "harness_repository": request["harness_repository"],
        "harness_sha": request["harness_sha"],
        "profile_version": "pending",
        "profile_sha256": "0" * 64,
        "provider_config_sha256": "0" * 64,
        "decision_config_sha256": "0" * 64,
        "run_id": f"pr-{request['pull_request_number']}-{request['workflow_run_id']}",
        "snapshot_id": "pending",
        "request_hash": "0" * 64,
    }
    # Validate the complete listing and identify the only expected attempt-named artifact.
    selected = intake._select_artifact(artifacts_raw, _identity(expected_seed), run_obj)
    archive_url = f"{base}/{_repo_path(request['workflow_repository'])}/actions/artifacts/{selected['id']}/zip"
    archive = _download_archive(transport, archive_url, token=token, limit=intake.MAX_ARCHIVE_BYTES)
    if len(archive) != selected["size_in_bytes"] or hashlib.sha256(archive).hexdigest() != selected["sha256"]:
        raise FetchError("recovery_artifact_digest_mismatch")
    expected_identity = _trusted_expected_identity(request, run_raw, pr, archive)
    result = intake.intake_pr_analysis_artifact(
        run_response=normalized_run,
        artifacts_response=artifacts_raw,
        archive_bytes=archive,
        expected_identity=expected_identity,
        output_dir=output_dir,
    )
    return {
        **result,
        "status": "FETCHED_CONSISTENCY_VALIDATED",
        "authenticated_fetch_performed": True,
        "trusted_request_matched": True,
        "current_pr_binding": "verified_by_authenticated_lookup",
        "resume_authorized": False,
        "artifact_path": str(output_dir.absolute() / "artifact"),
        "run_id": request["workflow_run_id"],
        "run_attempt": request["workflow_run_attempt"],
        "pull_request_number": request["pull_request_number"],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trusted-request", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--token-env", default="GITHUB_TOKEN")
    parser.add_argument("--api-base-url", default="https://api.github.com")
    args = parser.parse_args(argv)
    if not TOKEN_NAME.fullmatch(args.token_env):
        print('{"error":"token_environment_name_invalid"}', file=sys.stderr)
        return 2
    token = os.environ.get(args.token_env)
    try:
        request = _parse_json(
            intake._read_input(args.trusted_request, 64 * 1024, "trusted_request_invalid"), "trusted_request_invalid"
        )
        result = fetch_and_intake(
            request_value=request,
            token=token or "",
            output_dir=args.output_dir,
            api_base=args.api_base_url,
        )
    except (FetchError, ManifestError, OSError, TypeError, KeyError, AttributeError) as error:
        code = str(error) if isinstance(error, (FetchError, ManifestError)) else "recovery_fetch_failed"
        print(json.dumps({"error": code}, separators=(",", ":")), file=sys.stderr)
        return 2
    print(json.dumps(result, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
