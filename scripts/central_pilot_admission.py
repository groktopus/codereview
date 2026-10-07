#!/usr/bin/env python3
"""Read-only admission check for a retained central SlopSearX pilot artifact.

This module emits only a hash-based candidate receipt. It performs bounded GETs
through an injected transport, never calls a model/provider, never executes
target code, and never writes to GitHub. A receipt is local consistency evidence,
not publication authority or proof of a hosted workflow's permissions.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any

import fetch_pr_analysis_artifact as fetch
import intake_pr_analysis_artifact as intake
import pr_analysis_artifact_manifest as manifests
import resolve_review_contract as review_contracts

# This operator entry point is run directly from a source checkout by Actions.
# Make the package used by the recovery-manifest verifier available even when
# the checkout has not been installed and PYTHONPATH is unset.
_SOURCE_PACKAGE = Path(__file__).resolve().parents[1] / "src"
if _SOURCE_PACKAGE.is_dir() and str(_SOURCE_PACKAGE) not in sys.path:
    sys.path.insert(0, str(_SOURCE_PACKAGE))

CALLER = "groktopus/codereview"
CALLER_PATH = ".github/workflows/slopsearx-pilot.yml"
CALLER_REF = "refs/heads/main"
TARGET = "magnus919/SlopSearX"
BASE_REF = "main"
REUSABLE_PATH = ".github/workflows/pr-analysis.yml"
REUSABLE_SHA = "dd01a24976631c957a34f3ecc80dcb097948e450"
MAX_EVENT_BYTES = 64 * 1024
SHA1 = re.compile(r"^[0-9a-f]{40}$")
RUN_ID = re.compile(r"^[1-9][0-9]{0,19}$")
RUN_ATTEMPT = re.compile(r"^[1-9][0-9]{0,5}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")


class AdmissionError(ValueError):
    pass


def _object(raw: bytes, code: str) -> dict[str, Any]:
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError):
        raise AdmissionError(code) from None
    if not isinstance(value, dict):
        raise AdmissionError(code)
    return value


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise ValueError("duplicate_json_key")
        out[key] = value
    return out


def _event_binding(raw: bytes, pr_number: int) -> tuple[str, str, str, int, int]:
    if len(raw) > MAX_EVENT_BYTES or isinstance(pr_number, bool) or not isinstance(pr_number, int) or pr_number < 1:
        raise AdmissionError("event_shape_invalid")
    event = _object(raw, "event_json_invalid")
    repository = event.get("repository")
    run = event.get("workflow_run")
    if (not isinstance(repository, dict) or not isinstance(repository.get("full_name"), str)
            or repository["full_name"].casefold() != CALLER.casefold()):
        raise AdmissionError("dispatch_repository_mismatch")
    if not isinstance(run, dict) or run.get("event") != "workflow_dispatch":
        raise AdmissionError("dispatch_origin_invalid")
    run_id = run.get("id")
    attempt = run.get("run_attempt")
    workflow_id = run.get("workflow_id")
    repository_id = repository.get("id") if isinstance(repository, dict) else None
    if (isinstance(run_id, bool) or not isinstance(run_id, int) or run_id < 1
            or isinstance(attempt, bool) or not isinstance(attempt, int) or attempt < 1
            or isinstance(workflow_id, bool) or not isinstance(workflow_id, int) or workflow_id < 1
            or isinstance(repository_id, bool) or not isinstance(repository_id, int) or repository_id < 1):
        raise AdmissionError("dispatch_run_identity_invalid")
    # Actions' workflow-run API omits the ref suffix from `path`; `head_branch`
    # supplies the branch binding. This exact bare path is verified against the
    # hosted central run shape and cannot select another workflow file.
    if run.get("path") != CALLER_PATH or run.get("head_branch") != "main":
        raise AdmissionError("dispatch_workflow_identity_mismatch")
    if not isinstance(run.get("head_sha"), str) or not SHA1.fullmatch(run["head_sha"]):
        raise AdmissionError("dispatch_sha_invalid")
    # The event has no trusted PR-number input field in workflow_run payloads.
    # The operator-supplied number is subsequently bound to the retained artifact
    # and independently re-read target PR.
    return str(run_id), str(attempt), run["head_sha"], workflow_id, repository_id


def _api_json(transport: Any, url: str, token: str) -> tuple[bytes, fetch.HttpResponse]:
    response = transport.get(url, headers={
        "Accept": "application/vnd.github+json", "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": fetch.API_VERSION,
    }, limit=intake.MAX_API_BYTES)
    if len(response.body) > intake.MAX_API_BYTES or response.status != 200:
        raise AdmissionError("read_only_api_response_invalid")
    return response.body, response


def _validate_token(token: Any) -> str:
    if not isinstance(token, str) or not token or len(token) > 8192 or any(char.isspace() for char in token):
        raise AdmissionError("read_only_token_required")
    return token


def discover_pr_number(*, event_bytes: bytes, token: str, transport: Any,
                       api_base: str = "https://api.github.com") -> int:
    """Derive the PR only from one exact run/attempt artifact name.

    This is a selector only. ``verify_candidate`` re-fetches the run and
    artifact list, then verifies artifact metadata, digest and manifest.
    """
    token = _validate_token(token)
    run_id, attempt, _caller_sha, _workflow_id, _repository_id = _event_binding(event_bytes, 1)
    base = fetch._api_base(api_base)
    url = f"{base}/{fetch._repo_path(CALLER)}/actions/runs/{run_id}/artifacts?per_page=100"
    raw, _ = _api_json(transport, url, token)
    listing = intake._parse_json(raw, "recovery_artifact_listing_invalid")
    rows = listing.get("artifacts")
    if not isinstance(rows, list) or listing.get("total_count") != len(rows) or len(rows) > 100:
        raise AdmissionError("recovery_artifact_listing_incomplete")
    pattern = re.compile(rf"^pr-review-([1-9][0-9]{{0,8}})-{run_id}-{attempt}$")
    numbers = [int(match.group(1)) for row in rows if isinstance(row, dict)
               and isinstance(row.get("name"), str)
               if (match := pattern.fullmatch(row["name"])) is not None]
    if len(numbers) != 1:
        raise AdmissionError("recovery_artifact_not_unique")
    return numbers[0]


def manual_event_for_existing_run(*, run_id: str, attempt: str, token: str,
                                  transport: Any, api_base: str = "https://api.github.com") -> bytes:
    """Construct a manual-rehearsal input from a read-only source attempt lookup."""
    token = _validate_token(token)
    if not isinstance(run_id, str) or not RUN_ID.fullmatch(run_id):
        raise AdmissionError("dispatch_run_identity_invalid")
    if not isinstance(attempt, str) or not RUN_ATTEMPT.fullmatch(attempt):
        raise AdmissionError("dispatch_run_identity_invalid")
    base = fetch._api_base(api_base)
    url = f"{base}/{fetch._repo_path(CALLER)}/actions/runs/{run_id}/attempts/{attempt}"
    raw, _ = _api_json(transport, url, token)
    run = intake._parse_json(raw, "source_run_invalid")
    repo = run.get("repository")
    if (isinstance(run.get("id"), bool) or not isinstance(run.get("id"), int)
            or str(run["id"]) != run_id or isinstance(run.get("run_attempt"), bool)
            or run.get("run_attempt") != int(attempt) or not isinstance(repo, dict)
            or not isinstance(repo.get("id"), int) or isinstance(repo.get("id"), bool)
            or not isinstance(repo.get("full_name"), str) or repo["full_name"].casefold() != CALLER.casefold()
            or not isinstance(run.get("workflow_id"), int) or isinstance(run.get("workflow_id"), bool)):
        raise AdmissionError("manual_source_run_binding_mismatch")
    event = {"repository": {"id": repo["id"], "full_name": repo["full_name"]}, "workflow_run": {
        key: run[key] for key in ("id", "run_attempt", "workflow_id", "event", "path", "head_branch", "head_sha")
        if key in run
    }}
    return (json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _validate_source_run(raw: bytes, *, run_id: str, attempt: str, caller_sha: str,
                         workflow_id: int, repository_id: int) -> dict[str, Any]:
    run = intake._parse_json(raw, "source_run_invalid")
    repo = run.get("repository")
    if (isinstance(run.get("id"), bool) or not isinstance(run.get("id"), int) or run.get("id", 0) < 1
            or str(run["id"]) != run_id or isinstance(run.get("run_attempt"), bool)
            or run.get("run_attempt") != int(attempt)
            or isinstance(run.get("workflow_id"), bool) or not isinstance(run.get("workflow_id"), int)
            or isinstance(run.get("workflow_id"), int) and run["workflow_id"] < 1
            or isinstance(repo, dict) and (isinstance(repo.get("id"), bool)
                                           or not isinstance(repo.get("id"), int)
                                           or repo.get("id", 0) < 1)
            or run.get("event") != "workflow_dispatch" or run.get("path") != CALLER_PATH
            or run.get("head_branch") != "main" or run.get("head_sha") != caller_sha
            or not isinstance(repo, dict) or not isinstance(repo.get("full_name"), str)
            or repo["full_name"].casefold() != CALLER.casefold() or repo.get("id") != repository_id
            or run.get("workflow_id") != workflow_id
            or run.get("status") != "completed" or run.get("conclusion") != "success"):
        raise AdmissionError("source_run_binding_mismatch")
    refs = run.get("referenced_workflows")
    expected_called_ref = f"{CALLER}/{REUSABLE_PATH}@{REUSABLE_SHA}"
    matches = [item for item in refs if isinstance(item, dict)
               and item.get("path") == expected_called_ref and item.get("sha") == REUSABLE_SHA
               and item.get("ref") in {None, REUSABLE_SHA}] if isinstance(refs, list) else []
    if len(matches) != 1:
        raise AdmissionError("reusable_workflow_binding_mismatch")
    return run


def _validate_current_pr(raw: bytes, number: int) -> dict[str, Any]:
    pr = intake._parse_json(raw, "target_pr_invalid")
    base = pr.get("base")
    head = pr.get("head")
    base_repo = base.get("repo") if isinstance(base, dict) else None
    if (isinstance(pr.get("number"), bool) or not isinstance(pr.get("number"), int)
            or pr.get("number") != number or pr.get("state") != "open" or pr.get("draft") is not False
            or not isinstance(base, dict) or base.get("ref") != BASE_REF
            or not isinstance(base_repo, dict) or not isinstance(base_repo.get("full_name"), str)
            or base_repo["full_name"].casefold() != TARGET.casefold()
            or not isinstance(head, dict) or not isinstance(base.get("sha"), str)
            or not SHA1.fullmatch(base["sha"]) or not isinstance(head.get("sha"), str)
            or not SHA1.fullmatch(head["sha"])):
        raise AdmissionError("target_pr_not_current_open_candidate")
    return {"number": number, "base_sha": base["sha"], "head_sha": head["sha"]}


def _validate_review_contract_binding(raw: bytes, identity: dict[str, Any]) -> dict[str, Any]:
    """Bind artifact profile metadata to one fixed caller-selected contract."""
    binding = _object(raw, "review_contract_binding_invalid")
    required_fields = {
        "target_repository",
        "profile_path",
        "profile_version",
        "profile_sha256",
        "profile_map_sha256",
        "review_contract",
        "limits_path",
        "limits_sha256",
        "max_claim_assessments",
    }
    if set(binding) != required_fields or binding.get("target_repository") != TARGET:
        raise AdmissionError("review_contract_binding_invalid")
    if not isinstance(binding.get("profile_map_sha256"), str) or not SHA256.fullmatch(binding["profile_map_sha256"]):
        raise AdmissionError("review_contract_binding_invalid")
    contract_name = binding.get("review_contract")
    contract = review_contracts.CONTRACTS.get(contract_name) if isinstance(contract_name, str) else None
    if contract is None:
        raise AdmissionError("review_contract_unsupported")
    expected = {
        "profile_path": contract["profile_path"],
        "profile_version": contract["profile_version"],
        "profile_sha256": contract["profile_sha256"],
        "limits_path": contract["limits_path"],
        "limits_sha256": contract["limits_sha256"],
        "max_claim_assessments": str(contract["max_claim_assessments"]),
    }
    if any(binding.get(key) != value for key, value in expected.items()):
        raise AdmissionError("review_contract_binding_mismatch")
    if (
        identity.get("profile_sha256") != binding["profile_sha256"]
        or identity.get("profile_version") != binding["profile_version"]
    ):
        raise AdmissionError("review_contract_identity_mismatch")
    return {
        "review_contract": contract_name,
        **expected,
        "max_claim_assessments": contract["max_claim_assessments"],
    }


def verify_candidate(*, event_bytes: bytes, pull_request_number: int, token: str,
                     transport: Any, api_base: str = "https://api.github.com") -> dict[str, Any]:
    """Verify one dispatch run, its retained artifact and current target PR.

    ``transport`` must implement GET only. No default network client is provided,
    making accidental live calls impossible in local validation and tests.
    """
    token = _validate_token(token)
    base = fetch._api_base(api_base)
    run_id, attempt, caller_sha, workflow_id, repository_id = _event_binding(event_bytes, pull_request_number)
    repo_path = fetch._repo_path(CALLER)
    run_url = f"{base}/{repo_path}/actions/runs/{run_id}/attempts/{attempt}"
    target_url = f"{base}/{fetch._repo_path(TARGET)}/pulls/{pull_request_number}"
    artifacts_url = f"{base}/{repo_path}/actions/runs/{run_id}/artifacts?per_page=100"
    run_raw, _ = _api_json(transport, run_url, token)
    run = _validate_source_run(run_raw, run_id=run_id, attempt=attempt, caller_sha=caller_sha,
                               workflow_id=workflow_id, repository_id=repository_id)
    pr_raw, _ = _api_json(transport, target_url, token)
    pr = _validate_current_pr(pr_raw, pull_request_number)
    artifacts_raw, _ = _api_json(transport, artifacts_url, token)

    identity_hint = {"pull_request_number": pull_request_number, "workflow_run_id": run_id,
                     "workflow_run_attempt": attempt}
    try:
        artifact = intake._select_artifact(artifacts_raw, identity_hint, run)
    except manifests.ManifestError as error:
        raise AdmissionError(str(error)) from None
    artifact_url = f"{base}/{repo_path}/actions/artifacts/{artifact['id']}/zip"
    archive = fetch._download_archive(transport, artifact_url, token=token, limit=intake.MAX_ARCHIVE_BYTES)
    if len(archive) != artifact["size_in_bytes"] or hashlib.sha256(archive).hexdigest() != artifact["sha256"]:
        raise AdmissionError("artifact_digest_mismatch")
    try:
        files, manifest_doc = intake._unpack_archive(archive)
    except manifests.ManifestError as error:
        raise AdmissionError(str(error)) from None
    identity = manifest_doc.get("identity") if isinstance(manifest_doc, dict) else None
    if not isinstance(identity, dict):
        raise AdmissionError("recovery_manifest_invalid")
    try:
        identity = manifests._identity(identity)
    except manifests.ManifestError as error:
        raise AdmissionError(str(error)) from None
    expected = {
        "workflow_repository": CALLER, "workflow_run_id": run_id, "workflow_run_attempt": attempt,
        "workflow_run_head_sha": caller_sha, "run_workflow_ref": manifests.CENTRAL_PILOT_CALLER_REF,
        "called_workflow_ref": f"{CALLER}/{REUSABLE_PATH}@{REUSABLE_SHA}",
        "called_workflow_sha": REUSABLE_SHA, "called_workflow_repository": CALLER,
        "called_workflow_file_path": REUSABLE_PATH, "target_repository": TARGET,
        "pull_request_number": pull_request_number, "base_sha": pr["base_sha"], "head_sha": pr["head_sha"],
        "harness_repository": CALLER, "harness_sha": REUSABLE_SHA,
    }
    if any(identity.get(key) != value for key, value in expected.items()):
        raise AdmissionError("recovery_trusted_identity_mismatch")
    contract_binding = _validate_review_contract_binding(files.get("profile-binding.json", b""), identity)
    # Verify complete archive inventory and the strict recovery-inputs packet.
    with tempfile.TemporaryDirectory(prefix="central-pilot-admission-") as temp:
        root = Path(temp)
        for name, content in files.items():
            if name == manifests.MANIFEST_NAME:
                continue
            path = root.joinpath(*PurePosixPath(name).parts)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
        (root / manifests.MANIFEST_NAME).write_bytes(
            next(data for name, data in files.items() if name == manifests.MANIFEST_NAME)
        )
        try:
            manifests.verify_manifest(root, identity)
        except manifests.ManifestError as error:
            raise AdmissionError(str(error)) from None
    receipt = {
        "schema_version": "central-pilot-candidate-receipt.v1", "status": "CONSISTENCY_VALIDATED",
        "source_run_id": run_id, "source_run_attempt": attempt,
        "caller_repository": CALLER, "caller_workflow_sha256": hashlib.sha256(caller_sha.encode()).hexdigest(),
        "reusable_workflow_sha256": hashlib.sha256(REUSABLE_SHA.encode()).hexdigest(),
        "target_repository": TARGET, "pull_request_number": pull_request_number,
        "base_sha256": hashlib.sha256(pr["base_sha"].encode()).hexdigest(),
        "head_sha256": hashlib.sha256(pr["head_sha"].encode()).hexdigest(),
        "artifact_id": artifact["id"], "artifact_sha256": hashlib.sha256(archive).hexdigest(),
        "manifest_sha256": hashlib.sha256(files[manifests.MANIFEST_NAME]).hexdigest(),
        "recovery_inputs_sha256": manifest_doc["recovery_inputs"]["packet_sha256"],
        **contract_binding,
        "publication_authorized": False,
    }
    return receipt


def run_canary(*, event_name: str, event_bytes: bytes | None, run_id: str | None,
               attempt: str | None, token: str, transport: Any, receipt_path: Path,
               api_base: str = "https://api.github.com") -> dict[str, Any]:
    """Run a hosted trigger or a separately labeled manual rehearsal."""
    if event_name == "workflow_run":
        if event_bytes is None or run_id is not None or attempt is not None:
            raise AdmissionError("workflow_run_inputs_invalid")
        event = event_bytes
        trigger_mode = "workflow_run"
        trigger_evidence = "OBSERVED_EVENT_PAYLOAD"
    elif event_name == "workflow_dispatch":
        if event_bytes is not None or run_id is None or attempt is None:
            raise AdmissionError("manual_rehearsal_inputs_invalid")
        event = manual_event_for_existing_run(
            run_id=run_id, attempt=attempt, token=token, transport=transport, api_base=api_base,
        )
        trigger_mode = "manual_rehearsal"
        trigger_evidence = "NOT_ESTABLISHED_BY_MANUAL_REHEARSAL"
    else:
        raise AdmissionError("trigger_mode_invalid")
    pr_number = discover_pr_number(event_bytes=event, token=token, transport=transport, api_base=api_base)
    receipt = verify_candidate(
        event_bytes=event, pull_request_number=pr_number, token=token,
        transport=transport, api_base=api_base,
    )
    receipt.update({"trigger_mode": trigger_mode, "workflow_run_trigger_evidence": trigger_evidence})
    raw = (json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n").encode()
    if len(raw) > 4096 or receipt_path.exists() or receipt_path.is_symlink():
        raise AdmissionError("receipt_output_invalid")
    receipt_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        descriptor = os.open(receipt_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    except OSError:
        raise AdmissionError("receipt_output_invalid") from None
    return receipt


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--event-name", required=True, choices=("workflow_run", "workflow_dispatch"))
    parser.add_argument("--event-path", type=Path)
    parser.add_argument("--run-id")
    parser.add_argument("--attempt")
    parser.add_argument("--receipt-output", type=Path, required=True)
    parser.add_argument("--token-env", default="GITHUB_TOKEN")
    args = parser.parse_args(argv)
    token = os.environ.get(args.token_env, "")
    try:
        if args.event_name == "workflow_run":
            if args.event_path is None:
                raise AdmissionError("event_path_required")
            event_bytes = intake._read_input(args.event_path, MAX_EVENT_BYTES, "event_json_invalid")
        else:
            if args.event_path is not None:
                raise AdmissionError("manual_rehearsal_inputs_invalid")
            event_bytes = None
        receipt = run_canary(
            event_name=args.event_name, event_bytes=event_bytes, run_id=args.run_id,
            attempt=args.attempt, token=token, transport=fetch.UrllibTransport(),
            receipt_path=args.receipt_output,
        )
    except (AdmissionError, fetch.FetchError, intake.ManifestError, OSError, TypeError, KeyError) as error:
        code = str(error) if isinstance(error, (AdmissionError, fetch.FetchError, intake.ManifestError)) else "admission_failed"
        print(json.dumps({"error": code}, separators=(",", ":")), file=sys.stderr)
        return 2
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
