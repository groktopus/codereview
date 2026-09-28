#!/usr/bin/env python3
"""Consistency-check one supplied normal PR-analysis artifact for recovery.

The caller supplies bounded REST response bodies and ZIP bytes. This module does
not authenticate their provenance, read credentials, make HTTP requests, call
providers, or execute target code. Before any resume, the caller must obtain the
responses and archive through an authenticated fetch and provide an independently
trusted expected identity. This intake result alone never authorizes a resume.
It currently requires exactly one PR entry with base/head SHAs in the workflow-run
response; runs without that shape, including manual or non-PR callers, are rejected.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import stat
import sys
import tempfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

from pr_analysis_artifact_manifest import (
    MANIFEST_NAME,
    MAX_FILE_BYTES,
    MAX_TOTAL_BYTES,
    ManifestError,
    _identity,
    _parse_json,
    canonical,
    verify_manifest,
)

MAX_API_BYTES = 1024 * 1024
MAX_ARCHIVE_BYTES = MAX_TOTAL_BYTES
MAX_ARCHIVE_ENTRIES = 520
SHA256 = re.compile(r"^sha256:([0-9a-f]{64})$")


def _read_input(path: Path, limit: int, code: str) -> bytes:
    try:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise ManifestError(code)
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
        with os.fdopen(descriptor, "rb") as stream:
            opened = os.fstat(stream.fileno())
            if not stat.S_ISREG(opened.st_mode) or opened.st_size > limit:
                raise ManifestError(code)
            data = stream.read(limit + 1)
    except ManifestError:
        raise
    except OSError:
        raise ManifestError(code) from None
    if len(data) > limit:
        raise ManifestError(code)
    return data


def _positive_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _reserve_output_directory(path: Path) -> None:
    """Atomically claim the destination; mkdir fails if any entry already exists."""
    path.mkdir(mode=0o700)


def _run_path_matches(api_path: Any, workflow_ref: str) -> bool:
    if not isinstance(api_path, str) or api_path.count("@") != 1:
        return False
    expected_source, expected_ref = workflow_ref.split("@", 1)
    source_parts = expected_source.split("/", 2)
    if len(source_parts) != 3:
        return False
    expected_file = source_parts[2]
    actual_file, actual_ref = api_path.split("@", 1)
    ref_aliases = {expected_ref}
    for prefix in ("refs/heads/", "refs/tags/"):
        if expected_ref.startswith(prefix):
            ref_aliases.add(expected_ref[len(prefix) :])
    return actual_file == expected_file and actual_ref in ref_aliases


def _called_workflow_matches(run: dict[str, Any], expected: dict[str, Any]) -> bool:
    referenced = run.get("referenced_workflows")
    if not isinstance(referenced, list) or len(referenced) > 100:
        return False
    expected_path, expected_ref = expected["called_workflow_ref"].split("@", 1)
    candidates = []
    for row in referenced:
        if not isinstance(row, dict) or not isinstance(row.get("path"), str):
            continue
        path = row["path"]
        if path.count("@") != 1:
            continue
        path_prefix, path_ref = path.split("@", 1)
        aliases = {expected_ref}
        for prefix in ("refs/heads/", "refs/tags/"):
            if expected_ref.startswith(prefix):
                aliases.add(expected_ref[len(prefix) :])
        ref_matches = row.get("ref") in {None, expected_ref, path_ref}
        if (
            path_prefix == expected_path
            and path_ref in aliases
            and row.get("sha") == expected["called_workflow_sha"]
            and ref_matches
        ):
            # A missing ref is documented for commit-SHA-pinned workflows only.
            if row.get("ref") is not None or expected_ref == expected["called_workflow_sha"]:
                candidates.append(row)
    return len(candidates) == 1


def _validate_run(raw: bytes, expected: dict[str, Any]) -> dict[str, Any]:
    run = _parse_json(raw, "recovery_run_metadata_invalid")
    repository = run.get("repository")
    if not isinstance(repository, dict):
        raise ManifestError("recovery_run_binding_mismatch")
    pull_requests = run.get("pull_requests")
    if (
        str(run.get("id")) != expected["workflow_run_id"]
        or run.get("run_attempt") != int(expected["workflow_run_attempt"])
        or run.get("status") != "completed"
        or run.get("conclusion") not in {"cancelled", "failure", "timed_out"}
        or repository.get("full_name", "").casefold() != expected["workflow_repository"].casefold()
        or not _positive_int(repository.get("id"))
        or not _positive_int(run.get("workflow_id"))
        or run.get("head_sha") != expected["workflow_run_head_sha"]
        or not _run_path_matches(run.get("path"), expected["run_workflow_ref"])
        or not _called_workflow_matches(run, expected)
        or not isinstance(pull_requests, list)
        or len(pull_requests) != 1
    ):
        raise ManifestError("recovery_run_binding_mismatch")
    pull = pull_requests[0]
    if (
        not isinstance(pull, dict)
        or pull.get("number") != expected["pull_request_number"]
        or not isinstance(pull.get("base"), dict)
        or not isinstance(pull.get("head"), dict)
        or pull["base"].get("sha") != expected["base_sha"]
        or pull["head"].get("sha") != expected["head_sha"]
    ):
        raise ManifestError("recovery_run_pr_binding_mismatch")
    return run


def _select_artifact(raw: bytes, expected: dict[str, Any], run: dict[str, Any]) -> dict[str, Any]:
    listing = _parse_json(raw, "recovery_artifact_listing_invalid")
    rows = listing.get("artifacts")
    expected_name = (
        f"pr-review-{expected['pull_request_number']}-{expected['workflow_run_id']}-{expected['workflow_run_attempt']}"
    )
    if not isinstance(rows, list) or listing.get("total_count") != len(rows) or len(rows) > 100:
        raise ManifestError("recovery_artifact_listing_incomplete")
    matches = [row for row in rows if isinstance(row, dict) and row.get("name") == expected_name]
    if len(matches) != 1:
        raise ManifestError("recovery_artifact_not_unique")
    row = matches[0]
    run_meta = row.get("workflow_run")
    digest = row.get("digest")
    digest_match = SHA256.fullmatch(digest) if isinstance(digest, str) else None
    if (
        not _positive_int(row.get("id"))
        or row.get("expired") is not False
        or not _positive_int(row.get("size_in_bytes"))
        or row["size_in_bytes"] > MAX_ARCHIVE_BYTES
        or not isinstance(run_meta, dict)
        or run_meta.get("id") != run.get("id")
        or run_meta.get("repository_id") != run["repository"]["id"]
        or run_meta.get("head_sha") != run.get("head_sha")
        or digest_match is None
    ):
        raise ManifestError("recovery_artifact_binding_mismatch")
    return {
        "id": row["id"],
        "name": expected_name,
        "size_in_bytes": row["size_in_bytes"],
        "sha256": digest_match.group(1),
    }


def _unpack_archive(raw: bytes) -> tuple[dict[str, bytes], dict[str, Any]]:
    if not raw or len(raw) > MAX_ARCHIVE_BYTES:
        raise ManifestError("recovery_archive_size_invalid")
    try:
        archive = zipfile.ZipFile(io.BytesIO(raw))
    except (OSError, zipfile.BadZipFile, ValueError):
        raise ManifestError("recovery_archive_invalid") from None
    files: dict[str, bytes] = {}
    total = 0
    try:
        infos = archive.infolist()
        if not infos or len(infos) > MAX_ARCHIVE_ENTRIES:
            raise ManifestError("recovery_archive_entry_limit")
        seen: set[str] = set()
        for info in infos:
            name = info.filename
            if (
                not isinstance(name, str)
                or not name
                or "\\" in name
                or name.startswith("/")
                or "\x00" in name
                or any(part in {"", ".", ".."} for part in PurePosixPath(name.rstrip("/")).parts)
                or name in seen
                or info.flag_bits & 0x1
            ):
                raise ManifestError("recovery_archive_path_invalid")
            seen.add(name)
            mode = info.external_attr >> 16
            kind = stat.S_IFMT(mode)
            if info.is_dir():
                if name != "review/" or (kind not in {0, stat.S_IFDIR}) or info.file_size != 0:
                    raise ManifestError("recovery_archive_path_invalid")
                continue
            if kind not in {0, stat.S_IFREG} or info.file_size > MAX_FILE_BYTES:
                raise ManifestError("recovery_archive_member_invalid")
            if info.compress_size > MAX_ARCHIVE_BYTES:
                raise ManifestError("recovery_archive_member_invalid")
            total += info.file_size
            if total > MAX_TOTAL_BYTES:
                raise ManifestError("recovery_archive_size_invalid")
            with archive.open(info, "r") as stream:
                data = stream.read(info.file_size + 1)
            if len(data) != info.file_size:
                raise ManifestError("recovery_archive_member_invalid")
            files[name] = data
    except ManifestError:
        raise
    except (OSError, RuntimeError, zipfile.BadZipFile, EOFError):
        raise ManifestError("recovery_archive_invalid") from None
    finally:
        archive.close()
    manifest_raw = files.get(MANIFEST_NAME)
    if manifest_raw is None or len(manifest_raw) > 256 * 1024:
        raise ManifestError("recovery_manifest_invalid")
    manifest = _parse_json(manifest_raw, "recovery_manifest_invalid")
    return files, manifest


def intake_pr_analysis_artifact(
    *,
    run_response: bytes,
    artifacts_response: bytes,
    archive_bytes: bytes,
    expected_identity: dict[str, Any],
    output_dir: Path,
) -> dict[str, Any]:
    """Consistency-check supplied metadata and ZIP bytes, then stage validated files.

    API authentication and independent trust in ``expected_identity`` remain the
    caller's responsibility; a validated result does not prove either one.
    """
    if len(run_response) > MAX_API_BYTES or len(artifacts_response) > MAX_API_BYTES:
        raise ManifestError("recovery_api_response_too_large")
    if not isinstance(expected_identity, dict):
        raise ManifestError("trusted_identity_invalid")
    expected = _identity(expected_identity)
    run = _validate_run(run_response, expected)
    artifact = _select_artifact(artifacts_response, expected, run)
    if len(archive_bytes) != artifact["size_in_bytes"]:
        raise ManifestError("recovery_artifact_size_mismatch")
    if hashlib.sha256(archive_bytes).hexdigest() != artifact["sha256"]:
        raise ManifestError("recovery_artifact_digest_mismatch")
    files, archive_manifest = _unpack_archive(archive_bytes)
    if set(archive_manifest) != {"schema_version", "identity", "checkpoint_path", "files"}:
        raise ManifestError("recovery_manifest_invalid")
    if archive_manifest.get("schema_version") != "pr-analysis-recovery-artifact.v2":
        raise ManifestError("recovery_manifest_invalid")
    if _identity(archive_manifest.get("identity", {})) != expected:
        raise ManifestError("recovery_identity_mismatch")
    listed_files = archive_manifest.get("files")
    if not isinstance(listed_files, dict) or set(files) != set(listed_files) | {MANIFEST_NAME}:
        raise ManifestError("recovery_artifact_inventory_mismatch")
    for name, data in files.items():
        if name == MANIFEST_NAME:
            continue
        if not isinstance(listed_files.get(name), dict) or listed_files[name] != {
            "sha256": hashlib.sha256(data).hexdigest(),
            "bytes": len(data),
        }:
            raise ManifestError("recovery_artifact_inventory_mismatch")
    output_dir = output_dir.absolute()
    payload_dir = output_dir / "artifact"
    try:
        output_dir.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="pr-analysis-intake-", dir=output_dir.parent) as temporary:
            stage = Path(temporary) / "payload"
            stage.mkdir(mode=0o700)
            for name, data in files.items():
                path = stage.joinpath(*PurePosixPath(name).parts)
                path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
                with os.fdopen(descriptor, "wb") as stream:
                    stream.write(data)
                    stream.flush()
                    os.fsync(stream.fileno())
            verify_manifest(stage, expected)
            try:
                _reserve_output_directory(output_dir)
            except FileExistsError:
                raise ManifestError("recovery_output_must_be_new") from None
            try:
                os.rename(stage, payload_dir)
            except OSError:
                try:
                    output_dir.rmdir()
                except OSError:
                    pass
                raise
    except ManifestError:
        raise
    except OSError:
        raise ManifestError("recovery_output_write_failed") from None
    return {
        "status": "CONSISTENCY_VALIDATED",
        "authenticated_fetch_performed": False,
        "expected_identity_independently_trusted": False,
        "resume_authorized": False,
        "artifact_id": artifact["id"],
        "artifact_path": str(payload_dir),
        "files": len(listed_files),
        "manifest_sha256": hashlib.sha256(canonical(archive_manifest)).hexdigest(),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        epilog=(
            "This command only checks consistency. Authenticate the REST and artifact fetches, "
            "supply an independently trusted expected identity, and perform freshness checks "
            "before wiring any resume. Exactly one pull request with base/head SHAs must be "
            "present in the run response; no secondary PR lookup is performed."
        ),
    )
    parser.add_argument("--run-response", type=Path, required=True)
    parser.add_argument("--artifacts-response", type=Path, required=True)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--expected-identity", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = intake_pr_analysis_artifact(
            run_response=_read_input(args.run_response, MAX_API_BYTES, "recovery_run_metadata_invalid"),
            artifacts_response=_read_input(args.artifacts_response, MAX_API_BYTES, "recovery_artifact_listing_invalid"),
            archive_bytes=_read_input(args.archive, MAX_ARCHIVE_BYTES, "recovery_archive_size_invalid"),
            expected_identity=_parse_json(
                _read_input(args.expected_identity, 64 * 1024, "trusted_identity_invalid"), "trusted_identity_invalid"
            ),
            output_dir=args.output_dir,
        )
    except (ManifestError, OSError, TypeError, KeyError, AttributeError) as exc:
        code = str(exc) if isinstance(exc, ManifestError) else "recovery_intake_failed"
        print(json.dumps({"error": code}, separators=(",", ":")), file=sys.stderr)
        return 2
    print(json.dumps(result, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
