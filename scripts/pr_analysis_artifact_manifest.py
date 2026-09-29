#!/usr/bin/env python3
"""Create and verify bounded identity manifests for reusable PR analysis artifacts.

This records the exact normal ``pr-analysis.yml`` run inputs and checkpoint so a
separately authorized recovery workflow can validate an artifact before resume.
It performs no downloads, provider calls, or target effects.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlsplit

MAX_FILES = 512
MAX_TREE_ENTRIES = 2048
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024
MANIFEST_NAME = "recovery-manifest.json"
SCHEMA = "pr-analysis-recovery-artifact.v3"
IDENTITY_KEYS = (
    "workflow_repository",
    "workflow_run_id",
    "workflow_run_attempt",
    "workflow_run_head_sha",
    "run_workflow_ref",
    "called_workflow_ref",
    "called_workflow_sha",
    "called_workflow_repository",
    "called_workflow_file_path",
    "target_repository",
    "pull_request_number",
    "base_sha",
    "head_sha",
    "harness_repository",
    "harness_sha",
    "profile_version",
    "profile_sha256",
    "provider_config_sha256",
    "decision_config_sha256",
    "run_id",
    "snapshot_id",
    "request_hash",
)
SHA256 = re.compile(r"^[0-9a-f]{64}$")
SHA1 = re.compile(r"^[0-9a-f]{40}$")
REPO = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


class ManifestError(ValueError):
    pass


def canonical(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode()


def _read_regular(path: Path, limit: int) -> bytes:
    try:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise ManifestError("artifact_file_invalid")
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
        with os.fdopen(descriptor, "rb") as stream:
            opened = os.fstat(stream.fileno())
            if not stat.S_ISREG(opened.st_mode) or opened.st_size > limit:
                raise ManifestError("artifact_file_invalid")
            data = stream.read(limit + 1)
    except ManifestError:
        raise
    except OSError:
        raise ManifestError("artifact_file_unavailable") from None
    if len(data) > limit:
        raise ManifestError("artifact_file_too_large")
    return data


def _inventory(root: Path) -> dict[str, dict[str, Any]]:
    if root.is_symlink() or not root.is_dir():
        raise ManifestError("artifact_root_invalid")
    rows: dict[str, dict[str, Any]] = {}
    total = 0
    stack = [root]
    visited = 0
    while stack:
        directory = stack.pop()
        try:
            scanner = os.scandir(directory)
        except OSError:
            raise ManifestError("artifact_directory_unavailable") from None
        with scanner:
            for entry in scanner:
                visited += 1
                if visited > MAX_TREE_ENTRIES:
                    raise ManifestError("artifact_tree_entry_cap_exceeded")
                path = Path(entry.path)
                relative = path.relative_to(root).as_posix()
                pure = PurePosixPath(relative)
                if pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
                    raise ManifestError("artifact_path_invalid")
                if entry.is_symlink():
                    raise ManifestError("artifact_symlink_rejected")
                if entry.is_dir(follow_symlinks=False):
                    stack.append(path)
                    continue
                if relative == MANIFEST_NAME:
                    continue
                if len(rows) >= MAX_FILES:
                    raise ManifestError("artifact_file_count_exceeded")
                data = _read_regular(path, MAX_FILE_BYTES)
                total += len(data)
                if total > MAX_TOTAL_BYTES:
                    raise ManifestError("artifact_total_size_exceeded")
                rows[relative] = {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}
    return rows


def _validate_artifact_paths(files: dict[str, Any], run_id: str) -> None:
    checkpoint = f"review/{run_id}.json"
    allowed = {checkpoint, f"review/{run_id}.md", "review-result.json", "profile-binding.json", "recovery-inputs.json"}
    if checkpoint not in files or set(files) - allowed:
        raise ManifestError("recovery_artifact_path_allowlist_invalid")
    if "recovery-inputs.json" not in files:
        raise ManifestError("recovery_inputs_missing")


def _recovery_input_record(root: Path, identity: dict[str, Any]) -> dict[str, str]:
    try:
        from pr_review_harness.recovery_inputs import (
            RecoveryInputError,
            read_packet,
            sha256,
        )
        from pr_review_harness.recovery_inputs import (
            canonical as recovery_canonical,
        )
    except ImportError:
        raise ManifestError("recovery_inputs_invalid") from None
    try:
        packet, raw = read_packet(
            root / "recovery-inputs.json",
            repository=identity["target_repository"],
            run_id=identity["run_id"],
            base_sha=identity["base_sha"],
            head_sha=identity["head_sha"],
        )
    except (OSError, RecoveryInputError):
        raise ManifestError("recovery_inputs_invalid") from None
    if raw != recovery_canonical(packet) or packet["source_event_id"] != identity["workflow_run_id"]:
        raise ManifestError("recovery_inputs_binding_mismatch")
    return {
        "source_event_id": packet["source_event_id"],
        "packet_sha256": sha256(raw),
        "checks_document_sha256": sha256(recovery_canonical(packet["checks_document"])),
    }


def _parse_json(raw: bytes, error_code: str) -> dict[str, Any]:
    def reject_duplicates(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate_json_key")
            result[key] = value
        return result

    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=reject_duplicates,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("invalid_constant")),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError):
        raise ManifestError(error_code) from None
    if not isinstance(value, dict):
        raise ManifestError(error_code)
    return value


def _identity(value: dict[str, Any]) -> dict[str, Any]:
    if set(value) != set(IDENTITY_KEYS):
        raise ManifestError("recovery_identity_shape_invalid")
    if not REPO.fullmatch(value["workflow_repository"]) or not REPO.fullmatch(value["target_repository"]):
        raise ManifestError("recovery_repository_invalid")
    if not REPO.fullmatch(value["harness_repository"]):
        raise ManifestError("recovery_repository_invalid")
    if not isinstance(value["workflow_run_id"], str) or not re.fullmatch(r"[1-9][0-9]{0,19}", value["workflow_run_id"]):
        raise ManifestError("recovery_run_id_invalid")
    if not isinstance(value["workflow_run_attempt"], str) or not re.fullmatch(
        r"[1-9][0-9]{0,5}", value["workflow_run_attempt"]
    ):
        raise ManifestError("recovery_run_attempt_invalid")
    if not REPO.fullmatch(value["called_workflow_repository"]):
        raise ManifestError("recovery_workflow_repository_invalid")
    if not SHA1.fullmatch(value["called_workflow_sha"]):
        raise ManifestError("recovery_workflow_revision_invalid")
    if not SHA1.fullmatch(value["workflow_run_head_sha"]):
        raise ManifestError("recovery_run_revision_invalid")
    workflow_ref = value["called_workflow_ref"]
    workflow_path = value["called_workflow_file_path"]
    run_workflow_ref = value["run_workflow_ref"]
    if value["workflow_repository"].casefold() != value["target_repository"].casefold():
        raise ManifestError("recovery_workflow_target_mismatch")
    if value["called_workflow_repository"] != value["harness_repository"]:
        raise ManifestError("recovery_workflow_repository_mismatch")
    if (
        not isinstance(workflow_ref, str)
        or len(workflow_ref) > 1024
        or workflow_ref.count("@") != 1
        or workflow_ref.split("@", 1)[0] != f"{value['called_workflow_repository']}/{workflow_path}"
        or not re.fullmatch(r"[A-Za-z0-9._/-]{1,256}", workflow_ref.split("@", 1)[1])
        or workflow_path != ".github/workflows/pr-analysis.yml"
        or not isinstance(run_workflow_ref, str)
        or len(run_workflow_ref) > 1024
        or run_workflow_ref.count("@") != 1
        or run_workflow_ref.split("@", 1)[0].count("/") < 3
        or not re.fullmatch(r"[A-Za-z0-9._/-]{1,256}", run_workflow_ref.split("@", 1)[1])
        or not run_workflow_ref.startswith(f"{value['workflow_repository']}/")
    ):
        raise ManifestError("recovery_workflow_identity_invalid")
    if (
        isinstance(value["pull_request_number"], bool)
        or not isinstance(value["pull_request_number"], int)
        or value["pull_request_number"] < 1
    ):
        raise ManifestError("recovery_pr_number_invalid")
    if (
        not SHA1.fullmatch(value["base_sha"])
        or not SHA1.fullmatch(value["head_sha"])
        or not SHA1.fullmatch(value["harness_sha"])
    ):
        raise ManifestError("recovery_revision_invalid")
    for key in ("profile_sha256", "provider_config_sha256", "decision_config_sha256", "request_hash"):
        if not isinstance(value[key], str) or not SHA256.fullmatch(value[key]):
            raise ManifestError("recovery_digest_invalid")
    for key in ("profile_version", "run_id", "snapshot_id"):
        if not isinstance(value[key], str) or not value[key] or len(value[key]) > 256:
            raise ManifestError("recovery_identity_field_invalid")
    if value["run_id"] != f"pr-{value['pull_request_number']}-{value['workflow_run_id']}":
        raise ManifestError("recovery_run_binding_mismatch")
    return {key: value[key] for key in IDENTITY_KEYS}


def _validate_config(raw: bytes, *, expected_key_env: str, expected_kind: str, required: set[str]) -> dict[str, Any]:
    value = _parse_json(raw, "provider_config_invalid")
    if (
        set(value) != required
        or value.get("api_key_env") != expected_key_env
        or value.get("kind") != expected_kind
        or any(
            not isinstance(item, str) or not item or len(item.encode("utf-8")) > 2048
            for key, item in value.items()
            if key in {"kind", "provider_id", "base_url", "endpoint", "model", "api_key_env"}
        )
        or ("provider_id" in value and value["provider_id"] != "operator_openai_compatible")
    ):
        raise ManifestError("provider_config_credential_field_rejected")
    endpoint = value.get("base_url", value.get("endpoint"))
    try:
        parsed = urlsplit(endpoint)
        host = parsed.hostname
        _ = parsed.port
    except ValueError:
        raise ManifestError("provider_config_credential_field_rejected") from None
    if (
        parsed.scheme not in {"https", "http"}
        or not host
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or (parsed.scheme == "http" and host not in {"localhost", "127.0.0.1", "::1"})
    ):
        raise ManifestError("provider_config_credential_field_rejected")
    return value


def identity_from_inputs(
    *,
    artifact_root: Path,
    workflow_repository: str,
    workflow_run_id: str,
    workflow_run_attempt: str,
    workflow_run_head_sha: str,
    run_workflow_ref: str,
    called_workflow_ref: str,
    called_workflow_sha: str,
    called_workflow_repository: str,
    called_workflow_file_path: str,
    target_repository: str,
    pull_request_number: int,
    base_sha: str,
    head_sha: str,
    harness_repository: str,
    harness_sha: str,
    profile: Path,
    expected_profile_sha256: str,
    provider_config: Path,
    decision_config: Path,
) -> dict[str, Any]:
    """Build identity from bounded local inputs; persist only their hashes."""
    profile_raw = _read_regular(profile, MAX_FILE_BYTES)
    provider_raw = _read_regular(provider_config, MAX_FILE_BYTES)
    decision_raw = _read_regular(decision_config, MAX_FILE_BYTES)
    if hashlib.sha256(profile_raw).hexdigest() != expected_profile_sha256:
        raise ManifestError("recovery_profile_binding_mismatch")
    profile_doc = _parse_json(profile_raw, "profile_invalid")
    _validate_config(
        provider_raw,
        expected_key_env="LLM_API_KEY",
        expected_kind="openai_compatible",
        required={"kind", "provider_id", "base_url", "model", "api_key_env"},
    )
    _validate_config(
        decision_raw,
        expected_key_env="JEV_API_KEY",
        expected_kind="typesafe",
        required={"kind", "endpoint", "model", "api_key_env"},
    )
    run_id = f"pr-{pull_request_number}-{workflow_run_id}"
    checkpoint = artifact_root / "review" / f"{run_id}.json"
    result = _parse_json(_read_regular(checkpoint, MAX_FILE_BYTES), "checkpoint_or_profile_invalid")
    identity = {
        "workflow_repository": workflow_repository,
        "workflow_run_id": workflow_run_id,
        "workflow_run_attempt": workflow_run_attempt,
        "workflow_run_head_sha": workflow_run_head_sha,
        "run_workflow_ref": run_workflow_ref,
        "called_workflow_ref": called_workflow_ref,
        "called_workflow_sha": called_workflow_sha,
        "called_workflow_repository": called_workflow_repository,
        "called_workflow_file_path": called_workflow_file_path,
        "target_repository": target_repository,
        "pull_request_number": pull_request_number,
        "base_sha": base_sha,
        "head_sha": head_sha,
        "harness_repository": harness_repository,
        "harness_sha": harness_sha,
        "profile_version": profile_doc.get("version", profile_doc.get("profile_version")),
        "profile_sha256": hashlib.sha256(profile_raw).hexdigest(),
        "provider_config_sha256": hashlib.sha256(provider_raw).hexdigest(),
        "decision_config_sha256": hashlib.sha256(decision_raw).hexdigest(),
        "run_id": run_id,
        "snapshot_id": result.get("snapshot_id"),
        "request_hash": result.get("request_hash"),
    }
    return _identity(identity)


def create_manifest(
    root: Path,
    identity: dict[str, Any],
    *,
    checkpoint: Path,
    profile: Path,
    provider_config: Path,
    decision_config: Path,
) -> dict[str, Any]:
    identity = _identity(identity)
    try:
        relative_checkpoint = checkpoint.resolve(strict=True).relative_to(root.resolve(strict=True)).as_posix()
        profile_bytes = _read_regular(profile, MAX_FILE_BYTES)
        provider_bytes = _read_regular(provider_config, MAX_FILE_BYTES)
        decision_bytes = _read_regular(decision_config, MAX_FILE_BYTES)
    except (OSError, ValueError):
        raise ManifestError("recovery_input_unavailable") from None
    try:
        result = _parse_json(_read_regular(checkpoint, MAX_FILE_BYTES), "checkpoint_or_profile_invalid")
        profile_doc = _parse_json(profile_bytes, "checkpoint_or_profile_invalid")
    except OSError:
        raise ManifestError("checkpoint_or_profile_invalid") from None
    ledger = result.get("ledger") if isinstance(result, dict) else None
    ledger_identity = ledger.get("identity") if isinstance(ledger, dict) else None
    _validate_config(
        provider_bytes,
        expected_key_env="LLM_API_KEY",
        expected_kind="openai_compatible",
        required={"kind", "provider_id", "base_url", "model", "api_key_env"},
    )
    _validate_config(
        decision_bytes,
        expected_key_env="JEV_API_KEY",
        expected_kind="typesafe",
        required={"kind", "endpoint", "model", "api_key_env"},
    )
    if (
        relative_checkpoint != f"review/{identity['run_id']}.json"
        or result.get("run_id") != identity["run_id"]
        or result.get("base_sha") != identity["base_sha"]
        or result.get("head_sha") != identity["head_sha"]
        or result.get("snapshot_id") != identity["snapshot_id"]
        or result.get("request_hash") != identity["request_hash"]
        or result.get("project_profile_version") != identity["profile_version"]
        or not isinstance(ledger_identity, dict)
        or ledger_identity.get("snapshot_id") != identity["snapshot_id"]
        or ledger_identity.get("profile_version") != identity["profile_version"]
        or profile_doc.get("version", profile_doc.get("profile_version")) != identity["profile_version"]
        or hashlib.sha256(profile_bytes).hexdigest() != identity["profile_sha256"]
        or hashlib.sha256(provider_bytes).hexdigest() != identity["provider_config_sha256"]
        or hashlib.sha256(decision_bytes).hexdigest() != identity["decision_config_sha256"]
    ):
        raise ManifestError("recovery_checkpoint_binding_mismatch")
    files = _inventory(root)
    _validate_artifact_paths(files, identity["run_id"])
    recovery_inputs = _recovery_input_record(root, identity)
    manifest = {
        "schema_version": SCHEMA,
        "identity": identity,
        "checkpoint_path": relative_checkpoint,
        "recovery_inputs": recovery_inputs,
        "files": files,
    }
    manifest_path = root / MANIFEST_NAME
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(manifest_path, flags, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(canonical(manifest))
            stream.flush()
            os.fsync(stream.fileno())
    except OSError:
        raise ManifestError("recovery_manifest_write_failed") from None
    return manifest


def verify_manifest(root: Path, expected_identity: dict[str, Any]) -> dict[str, Any]:
    try:
        manifest = _parse_json(_read_regular(root / MANIFEST_NAME, 256 * 1024), "recovery_manifest_invalid")
    except OSError:
        raise ManifestError("recovery_manifest_invalid") from None
    if set(manifest) != {"schema_version", "identity", "checkpoint_path", "recovery_inputs", "files"}:
        raise ManifestError("recovery_manifest_invalid")
    if manifest["schema_version"] != SCHEMA or _identity(manifest["identity"]) != _identity(expected_identity):
        raise ManifestError("recovery_identity_mismatch")
    observed = _inventory(root)
    _validate_artifact_paths(observed, manifest["identity"]["run_id"])
    if manifest["files"] != observed:
        raise ManifestError("recovery_artifact_inventory_mismatch")
    if manifest["recovery_inputs"] != _recovery_input_record(root, manifest["identity"]):
        raise ManifestError("recovery_inputs_digest_mismatch")
    checkpoint = manifest["checkpoint_path"]
    if checkpoint != f"review/{manifest['identity']['run_id']}.json" or checkpoint not in observed:
        raise ManifestError("recovery_checkpoint_path_invalid")
    return manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--artifact-root", type=Path, required=True)
    parser.add_argument("--identity-json", type=Path, help="trusted identity JSON produced by the workflow controller")
    parser.add_argument("--workflow-repository")
    parser.add_argument("--workflow-run-id")
    parser.add_argument("--workflow-run-attempt")
    parser.add_argument("--workflow-run-head-sha")
    parser.add_argument("--run-workflow-ref")
    parser.add_argument("--called-workflow-ref")
    parser.add_argument("--called-workflow-sha")
    parser.add_argument("--called-workflow-repository")
    parser.add_argument("--called-workflow-file-path")
    parser.add_argument("--target-repository")
    parser.add_argument("--pull-request-number", type=int)
    parser.add_argument("--base-sha")
    parser.add_argument("--head-sha")
    parser.add_argument("--harness-repository")
    parser.add_argument("--harness-sha")
    parser.add_argument("--expected-profile-sha256")
    parser.add_argument("--profile", type=Path)
    parser.add_argument("--provider-config", type=Path)
    parser.add_argument("--decision-config", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.verify:
            if args.identity_json is None:
                raise ManifestError("trusted_identity_required")
            identity = _parse_json(_read_regular(args.identity_json, 64 * 1024), "recovery_manifest_invalid")
            result = verify_manifest(args.artifact_root, identity)
        else:
            if not all((args.profile, args.provider_config, args.decision_config)):
                raise ManifestError("recovery_inputs_required")
            if not all(
                (
                    args.workflow_repository,
                    args.workflow_run_id,
                    args.workflow_run_attempt,
                    args.workflow_run_head_sha,
                    args.run_workflow_ref,
                    args.called_workflow_ref,
                    args.called_workflow_sha,
                    args.called_workflow_repository,
                    args.called_workflow_file_path,
                    args.target_repository,
                    args.pull_request_number,
                    args.base_sha,
                    args.head_sha,
                    args.harness_repository,
                    args.harness_sha,
                    args.expected_profile_sha256,
                )
            ):
                raise ManifestError("recovery_identity_inputs_required")
            identity = identity_from_inputs(
                artifact_root=args.artifact_root,
                workflow_repository=args.workflow_repository,
                workflow_run_id=args.workflow_run_id,
                workflow_run_attempt=args.workflow_run_attempt,
                workflow_run_head_sha=args.workflow_run_head_sha,
                run_workflow_ref=args.run_workflow_ref,
                called_workflow_ref=args.called_workflow_ref,
                called_workflow_sha=args.called_workflow_sha,
                called_workflow_repository=args.called_workflow_repository,
                called_workflow_file_path=args.called_workflow_file_path,
                target_repository=args.target_repository,
                pull_request_number=args.pull_request_number,
                base_sha=args.base_sha,
                head_sha=args.head_sha,
                harness_repository=args.harness_repository,
                harness_sha=args.harness_sha,
                profile=args.profile,
                expected_profile_sha256=args.expected_profile_sha256,
                provider_config=args.provider_config,
                decision_config=args.decision_config,
            )
            checkpoint = args.artifact_root / "review" / f"{identity['run_id']}.json"
            result = create_manifest(
                args.artifact_root,
                identity,
                checkpoint=checkpoint,
                profile=args.profile,
                provider_config=args.provider_config,
                decision_config=args.decision_config,
            )
    except (ManifestError, OSError, TypeError, KeyError, AttributeError) as exc:
        code = str(exc) if isinstance(exc, ManifestError) else "recovery_manifest_failed"
        print(json.dumps({"error": code}, separators=(",", ":")), file=sys.stderr)
        return 2
    print(
        json.dumps(
            {
                "status": "verified",
                "manifest_sha256": hashlib.sha256(canonical(result)).hexdigest(),
                "file_count": len(result["files"]),
                "checkpoint_path": result["checkpoint_path"],
            },
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
