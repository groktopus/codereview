#!/usr/bin/env python3
"""Materialize the pinned SYNTH-001 fixture as a deterministic local Git repo.

This utility reads only the fixed fixture, never executes its Python files, and
prints a small identity receipt. It has no provider, network, or GitHub path.
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
from pathlib import Path
from typing import Any

FIXTURE_ID = "SYNTH-001"
SEED = 457001
EXPECTED_VISIBLE = ["contract.md", "caller.py", "base/auth.py", "head/auth.py"]
EXPECTED_FILES = {
    "seed.json", "truth.json", "contract.md", "caller.py", "base/auth.py", "head/auth.py"
}
PINNED_TRUTH_SHA256 = "3453536603c7fb9d4c8f0dd24f36481cb5d51b1c6fbdb10b9a88bfe566bd9b5d"
PINNED_HASHES = {
    "seed.json": "604bf9fa0ebd44002a6950e657c935ef122f3a755a7a4478dc83765d1084d743",
    "contract.md": "7465acc45428bfa7e8d433fac9bd853f44c51d4d0794a60355c16a887ac6b6b3",
    "caller.py": "8e3208e4ed04b30281e9e464cef834382f71ef1b44a8b567a64fc8023e344552",
    "base/auth.py": "5b6887e35b020d0a59133071f284114f61b41c4de753a8292f2b05969eeaa361",
    "head/auth.py": "4117df17d8a7e46ecca375f671a0a24223c377ce085a378dafedc5e677d3a823",
}
PINNED_PAYLOAD_SHA256 = "7aeae889a915e54aab796c84542529607e0cdd0f8035e3cb2cf5fde43eacb97f"
MAX_FILE_BYTES = 64_000
SAFE_SHA = re.compile(r"^[0-9a-f]{40}$")


class MaterializeError(ValueError):
    """The fixture or destination does not satisfy the pinned contract."""


def _read_regular(root: Path, relative: str) -> bytes:
    path = root / relative
    try:
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_FILE_BYTES:
            raise MaterializeError("fixture_file_invalid")
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        try:
            opened = os.fstat(fd)
            if (not stat.S_ISREG(opened.st_mode) or opened.st_dev != before.st_dev
                    or opened.st_ino != before.st_ino or opened.st_size > MAX_FILE_BYTES):
                raise MaterializeError("fixture_file_invalid")
            data = bytearray()
            while len(data) <= MAX_FILE_BYTES:
                chunk = os.read(fd, min(8192, MAX_FILE_BYTES + 1 - len(data)))
                if not chunk:
                    break
                data.extend(chunk)
            if len(data) > MAX_FILE_BYTES:
                raise MaterializeError("fixture_file_invalid")
            return bytes(data)
        finally:
            os.close(fd)
    except OSError:
        raise MaterializeError("fixture_file_invalid") from None


def _fixture_files(root: Path) -> dict[str, bytes]:
    if root.is_symlink() or not root.is_dir():
        raise MaterializeError("fixture_directory_invalid")
    found: set[str] = set()
    directories: set[str] = set()
    for path in root.rglob("*"):
        relative = path.relative_to(root).as_posix()
        mode = path.lstat().st_mode
        if stat.S_ISLNK(mode) or (not stat.S_ISDIR(mode) and not stat.S_ISREG(mode)):
            raise MaterializeError("fixture_tree_invalid")
        if stat.S_ISREG(mode):
            found.add(relative)
        elif stat.S_ISDIR(mode):
            directories.add(relative)
    if found != EXPECTED_FILES or directories != {"base", "head"}:
        raise MaterializeError("fixture_file_set_invalid")
    return {relative: _read_regular(root, relative) for relative in sorted(EXPECTED_FILES)}


def _json(raw: bytes) -> dict[str, Any]:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise MaterializeError("fixture_metadata_invalid")
            result[key] = value
        return result

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        raise MaterializeError("fixture_metadata_invalid") from None
    if not isinstance(value, dict):
        raise MaterializeError("fixture_metadata_invalid")
    return value


def _validated_fixture(root: Path) -> tuple[dict[str, bytes], str]:
    files = _fixture_files(root)
    truth_raw = files["truth.json"]
    if hashlib.sha256(truth_raw).hexdigest() != PINNED_TRUTH_SHA256:
        raise MaterializeError("trusted_metadata_mismatch")
    truth = _json(truth_raw)
    if truth.get("fixture_id") != FIXTURE_ID or truth.get("model_input") is not False:
        raise MaterializeError("trusted_metadata_mismatch")
    if truth.get("sha256") != PINNED_HASHES or truth.get("model_payload_sha256") != PINNED_PAYLOAD_SHA256:
        raise MaterializeError("trusted_metadata_mismatch")
    for name, expected in PINNED_HASHES.items():
        if hashlib.sha256(files[name]).hexdigest() != expected:
            raise MaterializeError("fixture_hash_mismatch")
    seed = _json(files["seed.json"])
    if seed != {"schema": "seeded-writer-fixture.v1", "fixture_id": FIXTURE_ID,
                "seed": SEED, "visible_files": EXPECTED_VISIBLE}:
        raise MaterializeError("seed_allowlist_invalid")
    payload_files = {name: files[name].decode("utf-8") for name in EXPECTED_VISIBLE}
    payload = json.dumps({"fixture_id": FIXTURE_ID, "seed": SEED, "files": payload_files},
                         sort_keys=True, separators=(",", ":")).encode("utf-8")
    payload_sha = hashlib.sha256(payload).hexdigest()
    if payload_sha != PINNED_PAYLOAD_SHA256:
        raise MaterializeError("payload_identity_mismatch")
    return files, payload_sha


def _git(repo: Path, *args: str, env: dict[str, str]) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(repo), *args], check=True, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env, timeout=15,
        )
    except (OSError, subprocess.SubprocessError):
        raise MaterializeError("git_materialization_failed") from None
    return result.stdout.strip()


def materialize(fixture_dir: Path, target_dir: Path) -> dict[str, str]:
    if fixture_dir.is_symlink():
        raise MaterializeError("fixture_directory_invalid")
    fixture_dir = fixture_dir.resolve(strict=True)
    files, payload_sha = _validated_fixture(fixture_dir)
    planned_target = target_dir.resolve(strict=False)
    if planned_target == fixture_dir or fixture_dir in planned_target.parents or planned_target in fixture_dir.parents:
        raise MaterializeError("fixture_target_overlap")
    if target_dir.exists() or target_dir.is_symlink():
        if not target_dir.is_dir() or target_dir.is_symlink() or any(target_dir.iterdir()):
            raise MaterializeError("target_must_be_empty")
    else:
        target_dir.mkdir(parents=True)
    target_dir = target_dir.resolve(strict=True)
    env = {
        "PATH": os.defpath,
        "LANG": "C",
        "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_AUTHOR_NAME": "SYNTH-001 fixture",
        "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
        "GIT_COMMITTER_NAME": "SYNTH-001 fixture",
        "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
        "GIT_AUTHOR_DATE": "2026-01-01T00:00:00+00:00",
        "GIT_COMMITTER_DATE": "2026-01-01T00:00:00+00:00",
    }
    _git(target_dir, "init", "--quiet", env=env)
    for name in ("contract.md", "caller.py"):
        (target_dir / name).write_bytes(files[name])
    (target_dir / "auth.py").write_bytes(files["base/auth.py"])
    _git(target_dir, "add", "--", "contract.md", "caller.py", "auth.py", env=env)
    _git(target_dir, "-c", f"core.hooksPath={os.devnull}", "-c", "commit.gpgSign=false",
         "commit", "--quiet", "-m", "synthetic base", env=env)
    base_sha = _git(target_dir, "rev-parse", "HEAD", env=env)
    if not SAFE_SHA.fullmatch(base_sha):
        raise MaterializeError("git_materialization_failed")
    env["GIT_AUTHOR_DATE"] = "2026-01-01T00:00:01+00:00"
    env["GIT_COMMITTER_DATE"] = "2026-01-01T00:00:01+00:00"
    (target_dir / "auth.py").write_bytes(files["head/auth.py"])
    _git(target_dir, "add", "--", "auth.py", env=env)
    _git(target_dir, "-c", f"core.hooksPath={os.devnull}", "-c", "commit.gpgSign=false",
         "commit", "--quiet", "-m", "synthetic change", env=env)
    head_sha = _git(target_dir, "rev-parse", "HEAD", env=env)
    if not SAFE_SHA.fullmatch(head_sha):
        raise MaterializeError("git_materialization_failed")
    changed = _git(target_dir, "diff", "--name-only", base_sha, head_sha, env=env).splitlines()
    paths = _git(target_dir, "ls-tree", "-r", "--name-only", head_sha, env=env).splitlines()
    if changed != ["auth.py"] or sorted(paths) != ["auth.py", "caller.py", "contract.md"]:
        raise MaterializeError("materialized_tree_invalid")
    return {
        "schema": "seeded-writer-materialization.v1",
        "fixture_id": FIXTURE_ID,
        "seed": str(SEED),
        "payload_sha256": payload_sha,
        "base_sha": base_sha,
        "head_sha": head_sha,
        "changed_path": "auth.py",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture-dir", type=Path, required=True)
    parser.add_argument("--target-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        receipt = materialize(args.fixture_dir, args.target_dir)
    except (MaterializeError, OSError) as exc:
        code = str(exc) if isinstance(exc, MaterializeError) else "materialization_failed"
        print(json.dumps({"schema": "seeded-writer-materialization.v1", "error": code},
                         sort_keys=True, separators=(",", ":")), file=sys.stderr)
        return 2
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
