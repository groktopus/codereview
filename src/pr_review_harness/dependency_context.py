"""Small source-bound projections of Python dependency declarations.

These records describe repository manifests at a pinned Git revision. They do
not establish which packages are installed by a running service.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import re
import tomllib
from typing import Any

_ROOT_KEYS = {"version", "max_total_projection_bytes", "max_source_bytes", "bindings"}
_BINDING_KEYS = {"unit_patterns", "lenses", "sides", "manifest_path", "lock_path", "packages", "max_bytes"}
_LENSES = {"correctness", "tests", "design", "security", "performance", "maintainability", "project_specific"}
_PACKAGE_NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")
_SHA = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")


class DependencyContextError(ValueError):
    """A trusted dependency projection policy or source is invalid."""


def _safe_path(value: Any) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and not value.startswith("/")
        and "\\" not in value
        and ".." not in value.split("/")
        and not any(char in value for char in "*?[]")
    )


def validate_dependency_context(profile: dict[str, Any]) -> dict[str, Any] | None:
    """Validate an opt-in, finite Python project dependency projection policy."""
    config = profile.get("dependency_context")
    if config is None:
        return None
    if not isinstance(config, dict) or set(config) != _ROOT_KEYS or config.get("version") != "dependency-context.v1":
        raise DependencyContextError("dependency_context policy is invalid")

    def bounded(value: Any, low: int, high: int) -> bool:
        return isinstance(value, int) and not isinstance(value, bool) and low <= value <= high

    if not bounded(config.get("max_total_projection_bytes"), 1, 65_536):
        raise DependencyContextError("dependency_context projection limit is invalid")
    if not bounded(config.get("max_source_bytes"), 1, 262_144):
        raise DependencyContextError("dependency_context source limit is invalid")
    bindings = config.get("bindings")
    if not isinstance(bindings, list) or not bindings or len(bindings) > 16:
        raise DependencyContextError("dependency_context bindings are invalid")
    context_paths = profile.get("context_paths", [])
    if isinstance(context_paths, str):
        context_paths = [context_paths]
    retrieval = profile.get("retrieval_context_patterns", [])
    if isinstance(retrieval, str):
        retrieval = [retrieval]
    if not isinstance(context_paths, list) or not isinstance(retrieval, list):
        raise DependencyContextError("dependency_context allowlists are invalid")
    for binding in bindings:
        if not isinstance(binding, dict) or set(binding) != _BINDING_KEYS:
            raise DependencyContextError("dependency_context binding is invalid")
        patterns = binding.get("unit_patterns")
        lenses = binding.get("lenses")
        sides = binding.get("sides")
        packages = binding.get("packages")
        if (
            not isinstance(patterns, list)
            or not patterns
            or len(patterns) > 32
            or any(not isinstance(item, str) or not item or any(c in item for c in "\\\0") for item in patterns)
        ):
            raise DependencyContextError("dependency_context unit patterns are invalid")
        if not isinstance(lenses, list) or not lenses or any(
            not isinstance(item, str) or item not in _LENSES for item in lenses
        ):
            raise DependencyContextError("dependency_context lenses are invalid")
        if not isinstance(sides, list) or not sides or any(
            not isinstance(item, str) or item not in {"BASE", "HEAD"} for item in sides
        ):
            raise DependencyContextError("dependency_context sides are invalid")
        if len(set(sides)) != len(sides):
            raise DependencyContextError("dependency_context sides must be unique")
        if not isinstance(packages, list) or not packages or len(packages) > 32:
            raise DependencyContextError("dependency_context packages are invalid")
        if any(not isinstance(item, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", item) for item in packages):
            raise DependencyContextError("dependency_context package names are invalid")
        if len({item.casefold().replace("_", "-").replace(".", "-") for item in packages}) != len(packages):
            raise DependencyContextError("dependency_context package names must be unique")
        manifest = binding.get("manifest_path")
        lock = binding.get("lock_path")
        for path in (manifest, lock):
            if not _safe_path(path):
                raise DependencyContextError("dependency_context paths must be exact relative paths")
            if not any(
                isinstance(allowed, str)
                and (
                    allowed == path
                    or (any(char in allowed for char in "*?[") and fnmatch.fnmatchcase(path, allowed))
                )
                for allowed in [*context_paths, *retrieval]
            ):
                raise DependencyContextError("dependency_context path is outside profile allowlists")
        if not bounded(binding.get("max_bytes"), 1, config["max_total_projection_bytes"]):
            raise DependencyContextError("dependency_context binding limit is invalid")
    return config


def project_python_dependencies(
    *,
    binding: dict[str, Any],
    side: str,
    revision: str,
    manifest_oid: str,
    manifest_bytes: bytes,
    lock_oid: str | None,
    lock_bytes: bytes | None,
    max_bytes: int,
) -> dict[str, Any]:
    """Extract selected PEP 621 direct requirements and optional uv lock facts."""
    if side not in {"BASE", "HEAD"} or not _SHA.fullmatch(revision):
        raise DependencyContextError("dependency_context source identity is invalid")
    if not _SHA.fullmatch(manifest_oid) or len(manifest_oid) != len(revision):
        raise DependencyContextError("dependency_context manifest identity is invalid")
    if lock_bytes is not None and (
        not isinstance(lock_oid, str) or not _SHA.fullmatch(lock_oid) or len(lock_oid) != len(revision)
    ):
        raise DependencyContextError("dependency_context lock identity is invalid")
    if lock_bytes is None and lock_oid is not None:
        raise DependencyContextError("dependency_context lock identity is incomplete")
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes < 1:
        raise DependencyContextError("dependency_context output limit is invalid")
    try:
        project = tomllib.loads(manifest_bytes.decode("utf-8"))
    except (UnicodeError, tomllib.TOMLDecodeError):
        raise DependencyContextError("dependency_context manifest is invalid") from None
    project_table = project.get("project", {})
    if not isinstance(project_table, dict):
        raise DependencyContextError("dependency_context project table is invalid")
    rows = project_table.get("dependencies", [])
    if not isinstance(rows, list) or any(not isinstance(item, str) for item in rows):
        raise DependencyContextError("dependency_context direct declarations are invalid")
    declared: dict[str, set[str]] = {}
    for requirement in rows:
        match = _PACKAGE_NAME.match(requirement)
        if not match:
            raise DependencyContextError("dependency_context requirement syntax is unsupported")
        remainder = requirement[match.end() :].lstrip()
        if remainder and remainder[0] not in "[()<>=!~;@":
            raise DependencyContextError("dependency_context requirement syntax is unsupported")
        key = match.group(1).casefold().replace("_", "-").replace(".", "-")
        declared.setdefault(key, set()).add(requirement.strip())
    selected = [str(item) for item in binding["packages"]]
    lock_status = "LOCK_FILE_ABSENT"
    locked: dict[str, str] = {}
    if lock_bytes is not None:
        try:
            lock_data = tomllib.loads(lock_bytes.decode("utf-8"))
        except (UnicodeError, tomllib.TOMLDecodeError):
            raise DependencyContextError("dependency_context lock is invalid") from None
        packages = lock_data.get("package", [])
        if not isinstance(packages, list):
            raise DependencyContextError("dependency_context lock package table is invalid")
        for row in packages:
            if (
                not isinstance(row, dict)
                or not isinstance(row.get("name"), str)
                or not isinstance(row.get("version"), str)
            ):
                raise DependencyContextError("dependency_context lock package entry is invalid")
            key = row["name"].casefold().replace("_", "-").replace(".", "-")
            locked.setdefault(key, set()).add(row["version"])
        lock_status = "LOCK_FILE_PRESENT"
    projected = []
    for package in selected:
        key = package.casefold().replace("_", "-").replace(".", "-")
        requirements = sorted(declared.get(key, set()))
        if not requirements:
            projected.append({"package": package, "declaration_status": "NOT_DECLARED"})
        elif lock_bytes is None:
            projected.append(
                {"package": package, "declaration_status": "DECLARED", "requirements": requirements,
                 "lock_status": "LOCK_FILE_ABSENT"}
            )
        elif key in locked and len(locked[key]) == 1:
            projected.append(
                {"package": package, "declaration_status": "DECLARED", "requirements": requirements,
                 "lock_status": "LOCK_ENTRY_PRESENT", "locked_versions": sorted(locked[key])}
            )
        elif key in locked:
            projected.append(
                {"package": package, "declaration_status": "DECLARED", "requirements": requirements,
                 "lock_status": "LOCK_ENTRIES_MULTIPLE", "locked_versions": sorted(locked[key])}
            )
        else:
            projected.append(
                {"package": package, "declaration_status": "DECLARED", "requirements": requirements,
                 "lock_status": "PACKAGE_NOT_IN_LOCK"}
            )
    record = {
        "schema": "dependency-projection.v1",
        "statement": "Static declarations from repository manifests; this does not identify installed runtime packages.",
        "side": side,
        "source_revision": revision,
        "manifest_path": binding["manifest_path"],
        "manifest_object_id": manifest_oid,
        "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "lock_path": binding["lock_path"],
        "lock_status": lock_status,
        "lock_object_id": lock_oid,
        "lock_sha256": hashlib.sha256(lock_bytes).hexdigest() if lock_bytes is not None else None,
        "packages": projected,
    }
    content = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    if len(content.encode("utf-8")) > max_bytes:
        raise DependencyContextError("dependency_context projection exceeds its byte limit")
    return {**record, "content": content, "content_hash": hashlib.sha256(content.encode("utf-8")).hexdigest()}


def valid_projection_evidence(
    item: Any,
    *,
    evidence_id: str,
    snapshot_id: str,
    binding_id: str,
    path: str,
    side: str,
    revision: str,
    packages: list[str],
) -> bool:
    """Validate the projection's content and immutable source identity before routing."""
    if not isinstance(item, dict) or item.get("evidence_id") != evidence_id:
        return False
    content = item.get("content")
    if (
        item.get("snapshot_id") != snapshot_id
        or item.get("source_kind") != "dependency_projection"
        or item.get("trust") != "repository_evidence"
        or item.get("path") != path
        or item.get("source_side") != side
        or item.get("source_revision") != revision
        or item.get("dependency_binding_id") != binding_id
        or item.get("content_truncated") is not False
        or not isinstance(content, str)
        or not isinstance(item.get("content_hash"), str)
        or hashlib.sha256(content.encode("utf-8")).hexdigest() != item.get("content_hash")
    ):
        return False
    try:
        record = json.loads(content)
    except (json.JSONDecodeError, TypeError):
        return False
    manifest_oid = item.get("source_object_id")
    lock_oid = item.get("lock_object_id")
    return bool(
        isinstance(record, dict)
        and record.get("schema") == "dependency-projection.v1"
        and record.get("source_revision") == revision
        and record.get("side") == side
        and record.get("manifest_path") == path
        and record.get("statement")
        == "Static declarations from repository manifests; this does not identify installed runtime packages."
        and record.get("manifest_object_id") == manifest_oid
        and isinstance(manifest_oid, str)
        and _SHA.fullmatch(manifest_oid)
        and len(manifest_oid) == len(revision)
        and item.get("source_object_format") == ("sha256" if len(manifest_oid) == 64 else "sha1")
        and isinstance(item.get("source_object_size_bytes"), int)
        and not isinstance(item.get("source_object_size_bytes"), bool)
        and item.get("source_object_size_bytes") >= 0
        and item.get("manifest_sha256") == record.get("manifest_sha256")
        and isinstance(record.get("manifest_sha256"), str)
        and re.fullmatch(r"[0-9a-f]{64}", record["manifest_sha256"])
        and (
            lock_oid is None
            or (
                isinstance(lock_oid, str)
                and _SHA.fullmatch(lock_oid)
                and len(lock_oid) == len(revision)
                and isinstance(record.get("lock_sha256"), str)
                and re.fullmatch(r"[0-9a-f]{64}", record["lock_sha256"])
            )
        )
        and (lock_oid is not None or record.get("lock_sha256") is None)
        and record.get("lock_object_id") == lock_oid
        and record.get("lock_sha256") == item.get("lock_sha256")
        and record.get("lock_status") == ("LOCK_FILE_ABSENT" if lock_oid is None else "LOCK_FILE_PRESENT")
        and isinstance(record.get("packages"), list)
        and [row.get("package") for row in record["packages"] if isinstance(row, dict)] == packages
    )
