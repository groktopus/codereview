#!/usr/bin/env python3
"""Freeze SYNTH-001 v3 runtime pins from one immutable runtime revision.

Run after the combined runtime source is final and committed. The selected
revision must contain the same ``src/pr_review_harness/*.py`` tree as the
working checkout. This updates only the v3 identity, its verifier constants,
and the package route digest; v1/v2 artifacts are untouched.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
IDENTITY_PATH = ROOT / "experiments/synth-001-package-identity-v3.json"
VERIFIER_PATH = ROOT / "scripts/verify_synth_001_preflight.py"
PACKAGE_PATH = ROOT / "scripts/package_synth_001_cross_model.py"
MODULE_RELATIVE = "src/pr_review_harness"
SHA1 = re.compile(r"[0-9a-f]{40}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")


class FinalizeError(ValueError):
    """The requested immutable runtime cannot be safely bound."""


def _git(root: Path, *args: str) -> bytes:
    try:
        result = subprocess.run(
            ["git", "-C", str(root), *args], check=False, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=15,
        )
    except (OSError, subprocess.SubprocessError):
        raise FinalizeError("runtime_revision_unavailable") from None
    if result.returncode:
        raise FinalizeError("runtime_revision_unavailable")
    return result.stdout


def _module_tree_from_files(files: dict[str, bytes]) -> tuple[int, str]:
    digest = hashlib.sha256()
    for name, content in sorted(files.items()):
        digest.update(name.encode("utf-8") + b"\0")
        digest.update(hashlib.sha256(content).hexdigest().encode("ascii") + b"\n")
    return len(files), digest.hexdigest()


def _module_tree_worktree(root: Path) -> tuple[int, str]:
    module_dir = root / MODULE_RELATIVE
    if module_dir.is_symlink() or not module_dir.is_dir():
        raise FinalizeError("runtime_tree_invalid")
    files: dict[str, bytes] = {}
    for path in module_dir.glob("*.py"):
        try:
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or path.is_symlink():
                raise FinalizeError("runtime_tree_invalid")
            files[path.name] = path.read_bytes()
        except OSError:
            raise FinalizeError("runtime_tree_invalid") from None
    if not files:
        raise FinalizeError("runtime_tree_invalid")
    return _module_tree_from_files(files)


def _module_tree_revision(root: Path, revision: str) -> tuple[int, str]:
    names = _git(root, "ls-tree", "-r", "--name-only", revision, "--", MODULE_RELATIVE).decode("utf-8").splitlines()
    prefix = MODULE_RELATIVE + "/"
    direct = sorted(
        name[len(prefix):] for name in names
        if name.startswith(prefix) and "/" not in name[len(prefix):] and name.endswith(".py")
    )
    files = {name: _git(root, "show", f"{revision}:{MODULE_RELATIVE}/{name}") for name in direct}
    if not files:
        raise FinalizeError("runtime_tree_invalid")
    return _module_tree_from_files(files)


def _replace_once(raw: bytes, pattern: bytes, replacement: bytes, error: str) -> bytes:
    updated, count = re.subn(pattern, replacement, raw, count=1, flags=re.MULTILINE)
    if count != 1:
        raise FinalizeError(error)
    return updated


def _atomic_write(path: Path, raw: bytes) -> None:
    mode = stat.S_IMODE(path.stat().st_mode)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temp_path = Path(temporary)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_path, path)
    except OSError:
        try:
            temp_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise FinalizeError("finalization_write_failed") from None


def finalize(root: Path, revision: str) -> dict[str, Any]:
    if not SHA1.fullmatch(revision):
        raise FinalizeError("runtime_revision_invalid")
    canonical_revision = _git(root, "rev-parse", "--verify", f"{revision}^{{commit}}").decode().strip()
    if canonical_revision != revision:
        raise FinalizeError("runtime_revision_invalid")
    count, tree_sha = _module_tree_revision(root, revision)
    if _module_tree_worktree(root) != (count, tree_sha):
        raise FinalizeError("runtime_worktree_revision_mismatch")

    identity_raw = IDENTITY_PATH.read_bytes()
    try:
        identity = json.loads(identity_raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise FinalizeError("identity_invalid") from None
    if not isinstance(identity, dict):
        raise FinalizeError("identity_invalid")
    configuration = identity.get("configuration") if isinstance(identity, dict) else None
    if (identity.get("schema") != "synth-001-cross-model-package-identity.v2"
            or not isinstance(configuration, dict)
            or configuration.get("runtime_pin_status") != "REQUIRES_FINAL_STACKED_RUNTIME"
            or configuration.get("module_count") is not None
            or configuration.get("module_tree_sha256") is not None
            or configuration.get("source_revision") is not None):
        raise FinalizeError("identity_not_pending")

    verifier_raw = VERIFIER_PATH.read_bytes()
    package_raw = PACKAGE_PATH.read_bytes()
    identity_sha = hashlib.sha256(identity_raw).hexdigest()
    digest_match = re.findall(rb'^IDENTITY_SHA256 = "([0-9a-f]{64})"$', package_raw, flags=re.MULTILINE)
    if len(digest_match) != 1 or digest_match[0].decode("ascii") != identity_sha:
        raise FinalizeError("package_identity_route_mismatch")
    finalized_identity = json.loads(json.dumps(identity))
    finalized_configuration = finalized_identity["configuration"]
    finalized_configuration.update({
        "module_count": count,
        "module_tree_sha256": tree_sha,
        "source_revision": revision,
        "runtime_pin_status": "FROZEN",
    })
    finalized_identity_raw = (json.dumps(finalized_identity, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    updated_verifier = _replace_once(
        verifier_raw, rb"^MODULE_COUNT = [0-9]+$", f"MODULE_COUNT = {count}".encode(),
        "verifier_module_count_route_invalid",
    )
    updated_verifier = _replace_once(
        updated_verifier, rb'^MODULE_TREE_SHA256 = "[0-9a-f]{64}"$',
        f'MODULE_TREE_SHA256 = "{tree_sha}"'.encode(), "verifier_module_tree_route_invalid",
    )
    updated_verifier = _replace_once(
        updated_verifier, rb'^SOURCE_REVISION = "[0-9a-f]{40}"$',
        f'SOURCE_REVISION = "{revision}"'.encode(), "verifier_revision_route_invalid",
    )
    identity_sha = hashlib.sha256(finalized_identity_raw).hexdigest()
    updated_package = _replace_once(
        package_raw, rb'^IDENTITY_SHA256 = "[0-9a-f]{64}"$',
        f'IDENTITY_SHA256 = "{identity_sha}"'.encode(), "package_digest_route_invalid",
    )

    # All contracts and bytes are computed before the first replacement.
    _atomic_write(IDENTITY_PATH, finalized_identity_raw)
    _atomic_write(VERIFIER_PATH, updated_verifier)
    _atomic_write(PACKAGE_PATH, updated_package)
    return {
        "schema": "synth-001-identity-v3-finalization.v1",
        "status": "FROZEN",
        "source_revision": revision,
        "module_count": count,
        "module_tree_sha256": tree_sha,
        "identity_sha256": identity_sha,
        "provider_calls": 0,
        "target_code_execution": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-revision", required=True, help="immutable commit containing the final runtime module tree")
    args = parser.parse_args(argv)
    try:
        result = finalize(ROOT, args.source_revision)
    except Exception as exc:
        error = str(exc) if isinstance(exc, FinalizeError) else "finalization_failed"
        print(json.dumps({"schema": "synth-001-identity-v3-finalization.v1", "status": "REJECTED", "error": error},
                         sort_keys=True, separators=(",", ":")), file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
