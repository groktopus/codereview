#!/usr/bin/env python3
"""Verify the fixed, provider-free SYNTH-001 prepare-only plan."""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from materialize_seeded_writer_synth_001 import MaterializeError, _validated_fixture  # noqa: E402

FIXTURE_ID = "SYNTH-001"
FIXTURE_PAYLOAD_SHA256 = "7aeae889a915e54aab796c84542529607e0cdd0f8035e3cb2cf5fde43eacb97f"
BASE_SHA = "93f602c9ee0fff5f9ef11e0d476a2b40e6b005e1"
HEAD_SHA = "810a92b13f7bd83f6e9c3fc55a71caea2bab86a0"
CONFIG_HASHES = {
    "profile": "d62a83f4ecbf0b807770c318bd3222c49c72311455eef19f15d6e3d2c7e1ad58",
    "limits": "1b3cf01229d00bd63e9dcf4140504108b1b697e886baf155a46d95e29536b432",
    "provider": "8f160c593f4d04d41dcfbc247eb5814c13ded5e88dd5bfdf95d3d78264634d5f",
}
SNAPSHOT_ID = "snap-a6c6ac33adda6c436e2cf3cf"
EVIDENCE_INDEX_SHA256 = "034fdbb66f32a5fdbedfacdce793d66c636ce93a961530ecb7827f967fc43bd5"
PROVIDER_IDENTITY_SHA256 = "767c2615b9e01ccff12c78a93d0c0f914d53ba2fbf4509567c7f9859a7d615a0"
REQUEST_SHA256 = "a290fdffa94352ecc45d0f1b231883fbb4f73178a0a71599185811ed3ea98e1d"
REQUEST_DESCRIPTOR_SHA256 = "7c444c1d74564cfa2962ffec76141932101be55861c434b59c8f38181df8d10a"
NORMALIZED_PREPARED_SHA256 = "4f3679ee5c4bdc5772f6b52a98759ddddc917ef9513993864bfa197b4aa0f63b"
EVIDENCE_INDEX_CANONICAL_SHA256 = "b52998a8d258e72f5b45f19a48825697330e3bcc629eab8a750e3784c9b86c82"
REQUEST_BYTES = 11_687
OUTPUT_BYTES_CAP = 16_000
OUTPUT_TOKENS_CAP = 1_200
MODULE_COUNT = 35
# Interim provider-free preparation pin at PR #157 head. The v3 finalizer
# rewrites these values from the exact immutable runtime revision selected for
# the combined stack; until then, package identity v3 remains pending.
MODULE_TREE_SHA256 = "838fb5619048fb1bb4bcf84ad8721bb6d7cba37ce9464a3b5089ee9d3080b6c5"
SOURCE_REVISION = "cd6ceaa0b9120b328a5e75d86f2a0729ce6052fd"
PYTHON_IDENTITY = {"implementation": "cpython", "version": "3.14.7"}
SHA256 = re.compile(r"^[0-9a-f]{64}$")
SHA1 = re.compile(r"^[0-9a-f]{40}$")
MAX_INPUT_BYTES = 256_000


class VerifyError(ValueError):
    """A materialization or prepare receipt does not match the pinned plan."""


def _read(path: Path, limit: int = MAX_INPUT_BYTES) -> bytes:
    try:
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
            raise VerifyError("input_invalid")
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        try:
            opened = os.fstat(fd)
            if (not stat.S_ISREG(opened.st_mode) or opened.st_dev != before.st_dev
                    or opened.st_ino != before.st_ino or opened.st_size > limit):
                raise VerifyError("input_invalid")
            data = bytearray()
            while len(data) <= limit:
                chunk = os.read(fd, min(16_384, limit + 1 - len(data)))
                if not chunk:
                    break
                data.extend(chunk)
            if len(data) > limit:
                raise VerifyError("input_too_large")
            return bytes(data)
        finally:
            os.close(fd)
    except OSError:
        raise VerifyError("input_invalid") from None


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise VerifyError("input_invalid_json")
        result[key] = value
    return result


def _document(path: Path) -> tuple[dict[str, Any], bytes]:
    raw = _read(path)
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        raise VerifyError("input_invalid_json") from None
    if not isinstance(value, dict):
        raise VerifyError("input_invalid_shape")
    return value, raw


def _git(repo: Path, *args: str) -> str:
    env = {
        "PATH": os.defpath,
        "LANG": "C",
        "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
    }
    try:
        result = subprocess.run(
            ["git", "-C", str(repo), *args], check=True, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env, timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        raise VerifyError("repository_identity_mismatch") from None
    return result.stdout.strip()


def _config_hash(path: Path, label: str) -> None:
    if hashlib.sha256(_read(path, 32_000)).hexdigest() != CONFIG_HASHES[label]:
        raise VerifyError("config_hash_mismatch")


def _module_tree(root: Path) -> tuple[int, str]:
    module_dir = root / "src" / "pr_review_harness"
    try:
        if module_dir.is_symlink() or not module_dir.is_dir():
            raise VerifyError("runtime_tree_mismatch")
        files = sorted(module_dir.glob("*.py"), key=lambda item: item.name)
        digest = hashlib.sha256()
        for path in files:
            if path.is_symlink() or not path.is_file():
                raise VerifyError("runtime_tree_mismatch")
            content_hash = hashlib.sha256(_read(path, 2_000_000)).hexdigest()
            digest.update(path.name.encode("utf-8") + b"\0" + content_hash.encode("ascii") + b"\n")
    except OSError:
        raise VerifyError("runtime_tree_mismatch") from None
    return len(files), digest.hexdigest()


def _verify_repo(repo: Path, receipt: dict[str, Any]) -> None:
    if repo.is_symlink() or not repo.is_dir():
        raise VerifyError("repository_identity_mismatch")
    if receipt.get("base_sha") != BASE_SHA or receipt.get("head_sha") != HEAD_SHA:
        raise VerifyError("materialization_receipt_mismatch")
    if _git(repo, "rev-parse", "HEAD") != HEAD_SHA:
        raise VerifyError("repository_identity_mismatch")
    if _git(repo, "rev-parse", HEAD_SHA + "^") != BASE_SHA:
        raise VerifyError("repository_identity_mismatch")
    if _git(repo, "diff", "--name-only", BASE_SHA, HEAD_SHA).splitlines() != ["auth.py"]:
        raise VerifyError("repository_changed_paths_mismatch")
    if _git(repo, "ls-tree", "-r", "--name-only", HEAD_SHA).splitlines() != ["auth.py", "caller.py", "contract.md"]:
        raise VerifyError("repository_tree_mismatch")
    if _git(repo, "status", "--porcelain", "--untracked-files=all"):
        raise VerifyError("repository_worktree_not_clean")


def verify(
    materialization_path: Path,
    prepared_path: Path,
    repo: Path,
    fixture_dir: Path,
    profile_path: Path,
    limits_path: Path,
    provider_path: Path,
    source_root: Path,
    expected_python_identity: dict[str, str] = PYTHON_IDENTITY,
) -> dict[str, Any]:
    materialization, _ = _document(materialization_path)
    expected_materialization = {
        "schema": "seeded-writer-materialization.v1",
        "fixture_id": FIXTURE_ID,
        "seed": "457001",
        "payload_sha256": FIXTURE_PAYLOAD_SHA256,
        "base_sha": BASE_SHA,
        "head_sha": HEAD_SHA,
        "changed_path": "auth.py",
    }
    if materialization != expected_materialization:
        raise VerifyError("materialization_receipt_mismatch")
    try:
        _, payload_sha = _validated_fixture(fixture_dir.resolve(strict=True))
    except (MaterializeError, OSError, RuntimeError):
        raise VerifyError("fixture_identity_mismatch") from None
    if payload_sha != FIXTURE_PAYLOAD_SHA256:
        raise VerifyError("fixture_identity_mismatch")
    _config_hash(profile_path, "profile")
    _config_hash(limits_path, "limits")
    _config_hash(provider_path, "provider")
    _verify_repo(repo.resolve(strict=True), materialization)

    prepared, _prepared_raw = _document(prepared_path)
    required_top = {
        "capacity", "checks", "command", "disposition", "no_provider_calls",
        "no_target_code_execution", "primary_requests", "scope", "snapshot", "status",
    }
    if set(prepared) != required_top:
        raise VerifyError("prepared_shape_mismatch")
    if (prepared["command"] != "review" or prepared["status"] != "PREPARED_ONLY"
            or prepared["disposition"] is not None or prepared["no_provider_calls"] is not True
            or prepared["no_target_code_execution"] is not True):
        raise VerifyError("prepared_status_mismatch")
    if prepared["checks"] != {"check_evidence_hash": None, "check_results": [], "historical_check_identity": None}:
        raise VerifyError("prepared_checks_mismatch")
    capacity = prepared["capacity"]
    if (not isinstance(capacity, dict) or capacity.get("configured_max_provider_calls") != 1
            or capacity.get("exact_primary_call_demand") != 1
            or capacity.get("exact_primary_serialized_input_bytes") != REQUEST_BYTES
            or capacity.get("configured_max_context_retrievals") not in (None, 0)
            or capacity.get("configured_max_followup_tasks") not in (None, 0)
            or capacity.get("configured_claim_assessment_call_slots") != 0
            or capacity.get("configured_followup_task_slots") != 0
            or capacity.get("configured_summary_advisory_call_slots") != 0
            or capacity.get("remaining_global_call_slots_after_primary") != 0):
        raise VerifyError("prepared_capacity_mismatch")
    if prepared["primary_requests"].__class__ is not list or len(prepared["primary_requests"]) != 1:
        raise VerifyError("primary_request_cardinality_mismatch")
    request = prepared["primary_requests"][0]
    request_descriptor_hash = hashlib.sha256(
        json.dumps(request, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    if request_descriptor_hash != REQUEST_DESCRIPTOR_SHA256:
        raise VerifyError("primary_request_descriptor_mismatch")
    if (request.get("admitted") is not True or request.get("input_sha256") != REQUEST_SHA256
            or request.get("input_bytes") != REQUEST_BYTES or request.get("lens") != "correctness"
            or request.get("output_bytes_cap") != OUTPUT_BYTES_CAP
            or request.get("output_tokens_cap") != OUTPUT_TOKENS_CAP):
        raise VerifyError("primary_request_mismatch")

    snapshot = prepared["snapshot"]
    if not isinstance(snapshot, dict) or not isinstance(snapshot.get("snapshot_hash"), str):
        raise VerifyError("snapshot_identity_mismatch")
    normalized_prepared = json.loads(json.dumps(prepared))
    normalized_prepared["snapshot"]["snapshot_hash"] = "<path-bound>"
    normalized_prepared_bytes = (
        json.dumps(normalized_prepared, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
    )
    if hashlib.sha256(normalized_prepared_bytes).hexdigest() != NORMALIZED_PREPARED_SHA256:
        raise VerifyError("prepared_artifact_mismatch")
    source_root = source_root.resolve(strict=True)
    if str(source_root / "src") not in sys.path:
        sys.path.insert(0, str(source_root / "src"))
    importlib.invalidate_caches()
    try:
        from pr_review_harness.cli import _read_limits
        from pr_review_harness.snapshot import collect_snapshot

        profile_document, _ = _document(profile_path)
        limits = _read_limits(SimpleNamespace(limits=str(limits_path)))
        expected_snapshot = collect_snapshot(
            str(repo.resolve(strict=True)), BASE_SHA, HEAD_SHA, profile_document, limits
        )
    except Exception:
        raise VerifyError("snapshot_recomputation_failed") from None
    if (not isinstance(snapshot, dict) or snapshot.get("base_sha") != BASE_SHA
            or snapshot.get("head_sha") != HEAD_SHA or snapshot.get("snapshot_id") != SNAPSHOT_ID
            or snapshot.get("snapshot_hash") != expected_snapshot.get("snapshot_hash")
            or snapshot.get("evidence_index_sha256") != EVIDENCE_INDEX_SHA256
            or hashlib.sha256(json.dumps(snapshot.get("evidence_index"), sort_keys=True,
                                         separators=(",", ":")).encode("utf-8")).hexdigest()
            != EVIDENCE_INDEX_CANONICAL_SHA256
            or snapshot.get("profile_file_sha256") != CONFIG_HASHES["profile"]
            or snapshot.get("limits_sha256") != CONFIG_HASHES["limits"]
            or snapshot.get("provider_identity_sha256") != PROVIDER_IDENTITY_SHA256):
        raise VerifyError("snapshot_identity_mismatch")
    count, tree_sha = _module_tree(source_root.resolve(strict=True))
    if count != MODULE_COUNT or tree_sha != MODULE_TREE_SHA256:
        raise VerifyError("runtime_tree_mismatch")
    runtime = {"implementation": sys.implementation.name, "version": sys.version.split()[0]}
    if runtime != expected_python_identity:
        raise VerifyError("runtime_identity_mismatch")
    return {
        "schema": "synth-001-preflight-verification.v1",
        "result": "MATCHED_PROVIDER_FREE_PREPARE",
        "fixture_id": FIXTURE_ID,
        "payload_sha256": FIXTURE_PAYLOAD_SHA256,
        "base_sha": BASE_SHA,
        "head_sha": HEAD_SHA,
        "changed_path": "auth.py",
        "snapshot_id": SNAPSHOT_ID,
        "snapshot_hash": snapshot["snapshot_hash"],
        "repository_path_sha256": hashlib.sha256(os.fsencode(str(repo.resolve(strict=True)))).hexdigest(),
        "request_sha256": REQUEST_SHA256,
        "request_bytes": REQUEST_BYTES,
        "lens": "correctness",
        "output_bytes_cap": OUTPUT_BYTES_CAP,
        "output_tokens_cap": OUTPUT_TOKENS_CAP,
        "module_count": count,
        "module_tree_sha256": tree_sha,
        "source_revision": SOURCE_REVISION,
        "runtime": runtime,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--materialization", type=Path, required=True)
    parser.add_argument("--prepared", type=Path, required=True)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--fixture-dir", type=Path, required=True)
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--limits", type=Path, required=True)
    parser.add_argument("--provider-config", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args(argv)
    try:
        result = verify(args.materialization, args.prepared, args.repo, args.fixture_dir,
                        args.profile, args.limits, args.provider_config, args.source_root)
    except (VerifyError, OSError) as exc:
        code = str(exc) if isinstance(exc, VerifyError) else "verification_failed"
        print(json.dumps({"schema": "synth-001-preflight-verification.v1", "result": "REJECTED", "error": code},
                         sort_keys=True, separators=(",", ":")), file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
