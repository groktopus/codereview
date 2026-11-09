#!/usr/bin/env python3
"""Inventory hash-shaped literals without deciding whether they are pins.

Read-only VD-3 diagnostic. It scans explicitly enumerated text roots and emits
bounded occurrence metadata. The supplied source revision is caller-declared and
is not verified against the filesystem. Hash classes are candidates, not pins.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

ROOT = Path(os.path.abspath(__file__)).parent.parent
TOKEN = re.compile(r"(?<![0-9a-fA-F])(?:[0-9a-fA-F]{40}|[0-9a-f]{64})(?![0-9a-fA-F])")
REVISION = re.compile(r"[0-9a-f]{40}")
TEXT_SUFFIXES = {".py", ".md", ".json", ".yml", ".yaml", ".toml", ".ini", ".cfg"}
EXCLUDED_PARTS = {".git", ".venv", "venv", "__pycache__", ".mypy_cache", ".pytest_cache"}
SELF_AUDIT_PATHS = (
    "scripts/audit_compatibility_pin_literals.py",
    "tests/test_compatibility_pin_inventory.py",
)
GENERATED_CENSUS_PATH = "docs/evidence/vd3-pin-census-*.json"
GENERATED_CENSUS_RE = re.compile(r"docs/evidence/vd3-pin-census-[^/]+\.json\Z")
ROOTS = ("src", "scripts", "tests", "experiments", "docs", "examples", ".github")
MAX_SCAN_FILES = 10_000
MAX_SCAN_DEPTH = 64
MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_TOTAL_BYTES = 128 * 1024 * 1024
MAX_OCCURRENCES = 250_000
MAX_DIRECTORY_ENTRIES = 10_000
DIR_FLAGS = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
FILE_FLAGS = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)
CREATE_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
SECURE_DIRFD_SUPPORTED = (
    os.open in os.supports_dir_fd
    and os.stat in os.supports_dir_fd
    and os.stat in os.supports_follow_symlinks
    and os.scandir in os.supports_fd
    and bool(getattr(os, "O_NOFOLLOW", 0))
    and bool(getattr(os, "O_DIRECTORY", 0))
)
SECURE_ATOMIC_OUTPUT_SUPPORTED = (
    SECURE_DIRFD_SUPPORTED
    and os.link in os.supports_dir_fd
    and os.link in os.supports_follow_symlinks
    and hasattr(os, "O_TMPFILE")
    and os.name == "posix"
    and os.path.exists("/proc/self/fd")
    and hasattr(os, "fsync")
)


class ScanRootError(ValueError):
    """Selected scan root is invalid or contains a symlink component."""


class PublishedButDurabilityUnconfirmed(OSError):
    """Canonical report link was created, but directory fsync failed."""


def _open_dir(parent_fd: int, name: str) -> int:
    return os.open(name, DIR_FLAGS, dir_fd=parent_fd)


def _bounded_names(parent_fd: int, budget: dict[str, int]) -> list[str]:
    """Read directory names incrementally, aborting before unbounded allocation."""
    names: list[str] = []
    with os.scandir(parent_fd) as entries:
        for entry in entries:
            names.append(entry.name)
            budget["directory_entries"] += 1
            if len(names) > MAX_DIRECTORY_ENTRIES or budget["directory_entries"] > MAX_SCAN_FILES * 4:
                raise OSError("inventory exceeds directory-entry limit")
    names.sort()
    return names


def _open_root(root: Path) -> int:
    """Open absolute root component-by-component with no-follow directory opens."""
    if not root.is_absolute():
        raise ScanRootError("scan root must be absolute")
    if not SECURE_DIRFD_SUPPORTED:
        raise ScanRootError("platform lacks dirfd, no-follow, or directory-open support for safe inventory")
    try:
        fd = os.open(root.anchor, DIR_FLAGS)
    except OSError as exc:
        raise ScanRootError("cannot open scan root") from exc
    try:
        for part in root.parts[1:]:
            try:
                child = _open_dir(fd, part)
            except OSError as exc:
                raise ScanRootError("scan root path contains a symlink or non-directory component") from exc
            os.close(fd)
            fd = child
        _bounded_names(fd, {"directory_entries": 0})
        metadata = os.stat("pyproject.toml", dir_fd=fd, follow_symlinks=False)
        if not stat.S_ISREG(metadata.st_mode):
            raise ScanRootError("pyproject.toml must be a regular file")
        for name in ROOTS:
            try:
                child = _open_dir(fd, name)
            except FileNotFoundError as exc:
                raise ScanRootError(f"declared scan root is missing: {name}") from exc
            except OSError as exc:
                raise ScanRootError(f"declared scan root is a symlink or not a directory: {name}") from exc
            os.close(child)
        return fd
    except BaseException:
        os.close(fd)
        raise


def _classify(path: str, line: str, token: str) -> tuple[str, str]:
    """Classify conservative candidates only; ambiguous values remain unknown."""
    lowered = line.lower()
    if path.startswith(".github/") and re.search(r"uses\s*:\s*[^\s@]+@" + re.escape(token), line):
        return "action_commit_pin", "GitHub workflow action reference uses @<revision> syntax."
    if len(token) == 40 and re.search(r"(?:historical|source)_revision|\b(?:base|head)_sha\b|commit(?:_sha)?", lowered):
        return "git_revision_candidate", "40-hex value occurs in a source or revision identity field."
    if len(token) == 64 and re.search(r"(?:sha256|digest|content_hash|artifact_hash|fixture_hash)", lowered):
        return "content_digest_candidate", "64-hex value occurs in a digest or hash field."
    if len(token) == 64 and re.search(r"(?:pinned|historical|compatibility|value_pin)", lowered):
        return "compatibility_pin_candidate", "64-hex value is named as a pin or historical compatibility value."
    return "unknown", "Hash-shaped token has no sufficiently strong local structural signal."


def _read_file_at(parent_fd: int, name: str, relative: str, budget: dict[str, int]) -> bytes:
    """Read one regular file via held parent; cap bytes despite concurrent growth."""
    try:
        fd = os.open(name, FILE_FLAGS, dir_fd=parent_fd)
    except OSError as exc:
        raise OSError(f"unable to open inventory file without following links: {relative}") from exc
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode):
            raise OSError(f"not a regular inventory file: {relative}")
        if metadata.st_size > MAX_FILE_BYTES:
            raise OSError(f"inventory file exceeds byte limit: {relative}")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(MAX_FILE_BYTES + 1)
        if len(raw) > MAX_FILE_BYTES:
            raise OSError(f"inventory file grew beyond byte limit: {relative}")
        budget["total_bytes"] += len(raw)
        if budget["total_bytes"] > MAX_TOTAL_BYTES:
            raise OSError("inventory exceeds total byte limit")
        return raw
    finally:
        os.close(fd)


def _walk(
    parent_fd: int,
    prefix: str,
    skipped: list[str],
    budget: dict[str, int],
    excluded_paths: set[str],
) -> Iterator[tuple[str, bytes]]:
    """Iteratively walk held descriptors with entry, depth, and resource caps."""
    root_fd = os.dup(parent_fd)
    stack: list[tuple[int, str, int, list[str], int]] = [(root_fd, prefix, 0, [], 0)]
    try:
        root_names = _bounded_names(root_fd, budget)
        stack[0] = (root_fd, prefix, 0, root_names, 0)
        while stack:
            directory_fd, directory_path, depth, names, index = stack[-1]
            if index >= len(names):
                os.close(directory_fd)
                stack.pop()
                continue
            name = names[index]
            stack[-1] = (directory_fd, directory_path, depth, names, index + 1)
            relative = f"{directory_path}/{name}" if directory_path else name
            metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if stat.S_ISLNK(metadata.st_mode):
                skipped.append(relative)
            elif stat.S_ISDIR(metadata.st_mode):
                if name in EXCLUDED_PARTS:
                    continue
                if depth >= MAX_SCAN_DEPTH:
                    raise OSError("inventory exceeds maximum directory depth")
                child = _open_dir(directory_fd, name)
                try:
                    child_names = _bounded_names(child, budget)
                except BaseException:
                    os.close(child)
                    raise
                stack.append((child, relative, depth + 1, child_names, 0))
            elif stat.S_ISREG(metadata.st_mode) and Path(name).suffix.lower() in TEXT_SUFFIXES:
                if relative in excluded_paths or GENERATED_CENSUS_RE.fullmatch(relative):
                    continue
                if metadata.st_size > MAX_FILE_BYTES:
                    raise OSError(f"inventory file exceeds byte limit: {relative}")
                budget["file_count"] += 1
                if budget["file_count"] > MAX_SCAN_FILES:
                    raise OSError("inventory exceeds maximum file count")
                if budget["total_bytes"] + metadata.st_size > MAX_TOTAL_BYTES:
                    raise OSError("inventory exceeds total byte limit")
                yield relative, _read_file_at(directory_fd, name, relative, budget)
    finally:
        for directory_fd, _path, _depth, _names, _index in stack:
            os.close(directory_fd)


def _inventory_fd(root_fd: int, source_revision: str | None, excluded_paths: set[str]) -> dict[str, Any]:
    excluded_paths = set(excluded_paths)
    excluded_paths.add(GENERATED_CENSUS_PATH)
    occurrences: list[dict[str, Any]] = []
    skipped_symlinks: list[str] = []
    scanned_files = 0
    budget = {"file_count": 0, "total_bytes": 0, "directory_entries": 0}
    for root_name in ROOTS:
        try:
            metadata = os.stat(root_name, dir_fd=root_fd, follow_symlinks=False)
        except FileNotFoundError as exc:
            raise ScanRootError(f"declared scan root is missing: {root_name}") from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise ScanRootError(f"declared scan root is a symlink: {root_name}")
        if not stat.S_ISDIR(metadata.st_mode):
            raise ScanRootError(f"declared scan root is not a directory: {root_name}")
        child = _open_dir(root_fd, root_name)
        try:
            for relative_path, raw in _walk(child, root_name, skipped_symlinks, budget, excluded_paths):
                try:
                    text = raw.decode("utf-8")
                except UnicodeError as exc:
                    raise OSError(f"inventory file is not UTF-8 text: {relative_path}") from exc
                scanned_files += 1
                for line_number, line in enumerate(text.splitlines(), start=1):
                    for match in TOKEN.finditer(line):
                        token = match.group(0)
                        category, rationale = _classify(relative_path, line, token)
                        context_hash = hashlib.sha256(line.strip()[:240].encode("utf-8")).hexdigest()
                        occurrences.append(
                            {
                                "path": relative_path,
                                "line": line_number,
                                "token": token,
                                "width": len(token),
                                "category": category,
                                "rationale": rationale,
                                "context_sha256": context_hash,
                            }
                        )
                        if len(occurrences) > MAX_OCCURRENCES:
                            raise OSError("inventory exceeds maximum occurrence count")
        finally:
            os.close(child)
    occurrences.sort(key=lambda item: (item["path"], item["line"], item["token"]))
    category_counts: dict[str, int] = {}
    for occurrence in occurrences:
        category_counts[occurrence["category"]] = category_counts.get(occurrence["category"], 0) + 1
    return {
        "schema": "vd3-compatibility-pin-census.v1",
        "source_revision": source_revision,
        "source_revision_verification": "caller-declared only; not checked against scan root content",
        "scope_roots": list(ROOTS),
        "excluded_paths": sorted(excluded_paths),
        "scanned_file_count": scanned_files,
        "skipped_symlink_paths": sorted(set(skipped_symlinks)),
        "occurrence_count": len(occurrences),
        "category_counts": dict(sorted(category_counts.items())),
        "classification_note": "Candidate inventory only; hash shape and heuristic category do not prove a compatibility pin. Unknowns require review; no migration or enforcement is implied.",
        "occurrences": occurrences,
    }


def audit(
    root: Path,
    *,
    source_revision: str | None = None,
    output_relative_path: str | None = None,
) -> dict[str, Any]:
    """Inventory an explicit tree; source revision remains caller-declared."""
    if source_revision is not None and not REVISION.fullmatch(source_revision):
        raise ValueError("source_revision must be a full lowercase 40-character Git revision")
    if not root.is_absolute():
        raise ValueError("scan root must be absolute")
    if output_relative_path is not None:
        raise ValueError("output_relative_path is obsolete; use the CLI --output option")
    root_fd = _open_root(root)
    try:
        return _inventory_fd(root_fd, source_revision, set(SELF_AUDIT_PATHS))
    finally:
        os.close(root_fd)


def _write_output_at(root_fd: int, source_revision: str, rendered: str) -> None:
    """Publish the held temporary inode without following mutable path entries."""
    docs_fd = evidence_fd = temp_fd = None
    final_name = f"vd3-pin-census-main-{source_revision[:8]}.json"
    published = False
    try:
        docs_fd = _open_dir(root_fd, "docs")
        try:
            evidence_fd = _open_dir(docs_fd, "evidence")
        except BaseException:
            os.close(docs_fd)
            docs_fd = None
            raise
        if not SECURE_ATOMIC_OUTPUT_SUPPORTED:
            raise OSError("platform lacks O_TMPFILE and /proc/self/fd for safe atomic output")
        temp_fd = os.open(".", os.O_TMPFILE | os.O_RDWR | getattr(os, "O_CLOEXEC", 0), 0o600, dir_fd=evidence_fd)
        payload = rendered.encode("utf-8")
        offset = 0
        while offset < len(payload):
            written = os.write(temp_fd, payload[offset:])
            if written <= 0:
                raise OSError("short write while creating census report")
            offset += written
        os.fsync(temp_fd)
        # O_TMPFILE has no directory entry that a concurrent writer can replace.
        # Promotion therefore always links the inode held by temp_fd.
        os.link(
            f"/proc/self/fd/{temp_fd}",
            final_name,
            dst_dir_fd=evidence_fd,
            follow_symlinks=True,
        )
        published = True
        try:
            os.fsync(evidence_fd)
        except OSError as exc:
            raise PublishedButDurabilityUnconfirmed(
                f"report published at docs/evidence/{final_name}, but directory durability could not be confirmed"
            ) from exc
    except BaseException as exc:
        if published:
            raise PublishedButDurabilityUnconfirmed(
                f"report published at docs/evidence/{final_name}, but completion after publication failed"
            ) from exc
        raise
    finally:
        try:
            if temp_fd is not None:
                try:
                    os.close(temp_fd)
                except OSError as exc:
                    if published:
                        raise PublishedButDurabilityUnconfirmed(
                            f"report published at docs/evidence/{final_name}, but closing the report descriptor failed"
                        ) from exc
                    raise
        finally:
            evidence_close_error = None
            try:
                if evidence_fd is not None:
                    os.close(evidence_fd)
            except OSError as exc:
                evidence_close_error = exc
            finally:
                if docs_fd is not None:
                    try:
                        os.close(docs_fd)
                    except OSError as exc:
                        if evidence_close_error is None:
                            evidence_close_error = exc
            if evidence_close_error is not None:
                if published:
                    raise PublishedButDurabilityUnconfirmed(
                        f"report published at docs/evidence/{final_name}, but closing an evidence directory failed"
                    ) from evidence_close_error
                raise evidence_close_error


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT, help="absolute repository or git-archive tree")
    parser.add_argument(
        "--source-revision",
        help="caller-declared full Git revision; omitted stdout scans report an unknown source revision",
    )
    parser.add_argument("--output", action="store_true", help="write the canonical census under root/docs/evidence")
    args = parser.parse_args(argv)
    root_fd = None
    primary_error: BaseException | None = None
    try:
        if not args.root.is_absolute():
            raise ValueError("scan root must be absolute")
        root_fd = _open_root(args.root)
        source_revision = args.source_revision
        if source_revision is not None and not REVISION.fullmatch(source_revision):
            raise ValueError("--source-revision must be a full lowercase 40-character Git revision")
        if args.output and source_revision is None:
            raise ValueError("--output requires --source-revision")
        exclusions = set(SELF_AUDIT_PATHS)
        report = _inventory_fd(root_fd, source_revision, exclusions)
        rendered = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
        if args.output:
            _write_output_at(root_fd, source_revision, rendered)
            try:
                os.close(root_fd)
            except OSError as exc:
                root_fd = None
                print(
                    f"error: report may already be published, but closing the scan-root descriptor failed: {exc}",
                    file=sys.stderr,
                )
                return 3
            root_fd = None
        else:
            try:
                os.close(root_fd)
            except OSError as exc:
                root_fd = None
                parser.error(f"scan-root descriptor close failed before report output: {exc}")
            root_fd = None
            sys.stdout.write(rendered)
    except PublishedButDurabilityUnconfirmed as exc:
        primary_error = exc
        print(f"error: {exc}", file=sys.stderr)
        return 3
    except (OSError, ValueError) as exc:
        primary_error = exc
        parser.error(str(exc))
    finally:
        if root_fd is not None:
            try:
                os.close(root_fd)
            except OSError as exc:
                detail = f"scan-root descriptor cleanup failed: {exc}"
                if primary_error is not None:
                    print(f"error: {detail} (while handling an earlier failure)", file=sys.stderr)
                elif args.output:
                    print(f"error: report may already be published, but {detail}", file=sys.stderr)
                    raise SystemExit(3) from None
                else:
                    parser.error(f"{detail} before report output")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
