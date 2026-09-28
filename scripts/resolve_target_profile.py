#!/usr/bin/env python3
"""Resolve a target repository to its trusted, digest-pinned review profile."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
MAP_PATH = ROOT / "profiles" / "targets.json"
MAX_MAP_BYTES = 64_000
MAX_PROFILE_BYTES = 256_000
_REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_PROFILE_PATH = re.compile(r"^profiles/[a-z0-9][a-z0-9-]{0,99}\.json$")
_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class ProfileBindingError(ValueError):
    """A safe, stable profile-binding failure code."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _read_regular_file(path: Path, limit: int, code: str) -> bytes:
    try:
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > limit:
            raise ProfileBindingError(code)
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
        with os.fdopen(descriptor, "rb") as stream:
            raw = stream.read(limit + 1)
    except ProfileBindingError:
        raise
    except OSError:
        raise ProfileBindingError(code) from None
    if len(raw) > limit:
        raise ProfileBindingError(code)
    return raw


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_json_key")
        result[key] = value
    return result


def _parse_json(raw: bytes, code: str) -> dict[str, Any]:
    try:
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicates,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("invalid_constant")),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError):
        raise ProfileBindingError(code) from None
    if not isinstance(value, dict):
        raise ProfileBindingError(code)
    return value


def _valid_repository(value: object) -> bool:
    if not isinstance(value, str) or not _REPOSITORY.fullmatch(value):
        return False
    owner, repository = value.split("/", 1)
    return owner not in {".", ".."} and repository not in {".", ".."}


def resolve_target_profile(target_repository: str, *, root: Path = ROOT) -> dict[str, str]:
    """Resolve only entries in the trusted checkout's fixed target map."""
    if not _valid_repository(target_repository):
        raise ProfileBindingError("target_repository_invalid")

    map_raw = _read_regular_file(root / "profiles" / "targets.json", MAX_MAP_BYTES, "profile_map_unavailable")
    profile_map = _parse_json(map_raw, "profile_map_invalid")
    if set(profile_map) != {"contract_version", "targets"} or profile_map.get("contract_version") != "target-profile-bindings.v1":
        raise ProfileBindingError("profile_map_invalid")
    targets = profile_map.get("targets")
    if not isinstance(targets, dict):
        raise ProfileBindingError("profile_map_invalid")

    binding = targets.get(target_repository)
    if binding is None:
        raise ProfileBindingError("target_repository_unsupported")
    if not isinstance(binding, dict) or set(binding) != {"profile_path", "profile_sha256", "profile_version"}:
        raise ProfileBindingError("profile_binding_invalid")
    relative_path = binding.get("profile_path")
    expected_hash = binding.get("profile_sha256")
    expected_version = binding.get("profile_version")
    if (
        not isinstance(relative_path, str)
        or not _PROFILE_PATH.fullmatch(relative_path)
        or not isinstance(expected_hash, str)
        or not _SHA256.fullmatch(expected_hash)
        or not isinstance(expected_version, str)
        or not _VERSION.fullmatch(expected_version)
    ):
        raise ProfileBindingError("profile_binding_invalid")

    profile_raw = _read_regular_file(root / relative_path, MAX_PROFILE_BYTES, "profile_unavailable")
    observed_hash = hashlib.sha256(profile_raw).hexdigest()
    if observed_hash != expected_hash:
        raise ProfileBindingError("profile_digest_mismatch")
    profile = _parse_json(profile_raw, "profile_invalid")
    if profile.get("repository") != target_repository:
        raise ProfileBindingError("profile_repository_mismatch")
    if profile.get("version") != expected_version:
        raise ProfileBindingError("profile_version_mismatch")

    return {
        "target_repository": target_repository,
        "profile_path": relative_path,
        "profile_version": expected_version,
        "profile_sha256": observed_hash,
        "profile_map_sha256": hashlib.sha256(map_raw).hexdigest(),
    }


def _write_binding_artifact(path: Path, binding: dict[str, str]) -> None:
    data = (json.dumps(binding, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0), 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except OSError:
        raise ProfileBindingError("profile_binding_artifact_write_failed") from None


def _write_github_outputs(path: Path, binding: dict[str, str]) -> None:
    try:
        with path.open("a", encoding="utf-8") as stream:
            for key in ("profile_path", "profile_version", "profile_sha256", "profile_map_sha256"):
                stream.write(f"{key}={binding[key]}\n")
    except OSError:
        raise ProfileBindingError("github_output_unavailable") from None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--github-output", type=Path, required=True)
    parser.add_argument("--binding-artifact", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        binding = resolve_target_profile(os.environ.get("TARGET_REPOSITORY", ""))
        _write_binding_artifact(args.binding_artifact, binding)
        _write_github_outputs(args.github_output, binding)
    except ProfileBindingError as exc:
        print(json.dumps({"status": "REJECTED", "error": exc.code}, sort_keys=True, separators=(",", ":")), file=sys.stderr)
        return 2
    print(json.dumps({"status": "RESOLVED", **binding}, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
