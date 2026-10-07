"""Finite, snapshot-bound context target manifests for opted-in profiles."""

from __future__ import annotations

import fnmatch
import hashlib
import json
import re
from typing import Any

_VERSION = "context-target-manifest.v1"
_GAP_KINDS = (
    "caller",
    "implementation",
    "test",
    "configuration",
    "contract",
    "trust_boundary",
    "provenance",
    "other",
)
_OBJECT_ID = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def validate_context_target_manifest_profile(profile: dict) -> dict | None:
    """Validate the deliberately small opt-in profile extension."""
    config = profile.get("context_target_manifest")
    if config is None:
        return None
    if not isinstance(config, dict) or set(config) != {"version", "max_entries", "max_bytes"}:
        raise ValueError("context_target_manifest must match a supported finite contract")
    if config.get("version") != _VERSION:
        raise ValueError("context_target_manifest version is unsupported")
    for name, low, high in (("max_entries", 1, 256), ("max_bytes", 512, 16_384)):
        value = config.get(name)
        if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
            raise ValueError(f"context_target_manifest {name} is outside finite bounds")
    return config


def build_context_target_manifest(task: dict, snapshot: dict, profile: dict) -> dict | None:
    """Bind finite path/unit targets to the exact captured Git objects.

    Choices are server-side IDs. The model receives the bounded typed target
    pairs in ``choices`` but cannot invent a path or select a source revision.
    """
    config = validate_context_target_manifest_profile(profile)
    if config is None or task.get("task_kind", "SPECIALIST_FINDINGS") != "SPECIALIST_FINDINGS":
        return None
    inventory = snapshot.get("inventory")
    evidence_map = snapshot.get("evidence")
    if not isinstance(inventory, list) or not isinstance(evidence_map, dict):
        raise ValueError("context target manifest requires a captured inventory")
    patterns = profile.get("retrieval_context_patterns", profile.get("context_paths", []))
    if isinstance(patterns, str):
        patterns = [patterns]
    trusted = profile.get("trusted_policy_paths", [])
    if isinstance(trusted, str):
        trusted = [trusted]
    if not isinstance(patterns, list) or not isinstance(trusted, list):
        raise ValueError("context target manifest requires trusted path rules")
    revision_rules = profile.get("retrieval_revisions", {})
    if not isinstance(revision_rules, dict):
        raise ValueError("context target manifest retrieval revisions are invalid")

    profile_hash = hashlib.sha256(_canonical(profile)).hexdigest()
    # A source tuple is available only when the immutable snapshot itself
    # records a matching path, revision, and Git blob identity.
    captured: dict[tuple[str, str], tuple[str, str]] = {}
    for item in evidence_map.values():
        if (
            not isinstance(item, dict)
            or item.get("source_kind") not in {"base_file", "head_file", "source_window"}
            or item.get("trust") not in {"untrusted_pr_content", "repository_evidence"}
        ):
            continue
        path, revision, object_id = item.get("path"), item.get("source_revision"), item.get("source_object_id")
        object_format = item.get("source_object_format")
        if (
            isinstance(path, str)
            and isinstance(revision, str)
            and isinstance(object_id, str)
            and _OBJECT_ID.fullmatch(object_id)
            and object_format in {"sha1", "sha256"}
            and ((object_format == "sha1" and len(object_id) == 40) or (object_format == "sha256" and len(object_id) == 64))
        ):
            prior = captured.get((path, revision))
            if prior is not None and prior != (object_id, object_format):
                raise ValueError("context target manifest source identity conflict")
            captured[(path, revision)] = (object_id, object_format)

    rows: list[dict[str, Any]] = []
    row_keys: set[tuple[str, str]] = set()
    revisions = {
        kind: snapshot.get("head_sha") if revision_rules.get(kind) == "head" else snapshot.get("base_sha")
        for kind in _GAP_KINDS
    }
    unit_rows = [row for row in inventory if isinstance(row, dict)]
    task_unit_ids = task.get("unit_ids", task.get("scope_unit_ids", []))
    if not isinstance(task_unit_ids, list) or any(not isinstance(unit_id, str) for unit_id in task_unit_ids):
        raise ValueError("context target manifest task scope is invalid")
    task_unit_set = set(task_unit_ids)
    for unit in unit_rows:
        path, unit_id = unit.get("path"), unit.get("unit_id")
        if not isinstance(path, str) or not isinstance(unit_id, str) or not unit_id:
            continue
        if path.startswith("/") or ".." in path.split("/"):
            continue
        if not any(isinstance(pattern, str) and fnmatch.fnmatchcase(path, pattern) for pattern in patterns):
            continue
        # Policy files stay governed by the existing BASE-only trusted-policy
        # path. They are not promoted into repository-context choices.
        if any(isinstance(pattern, str) and fnmatch.fnmatchcase(path, pattern) for pattern in trusted):
            continue
        sources = {
            revision: {"source_object_id": captured[(path, revision)][0], "source_object_format": captured[(path, revision)][1]}
            for revision in sorted(set(revisions.values()))
            if isinstance(revision, str) and (path, revision) in captured
        }
        available_kinds = [kind for kind in _GAP_KINDS if revisions[kind] in sources]
        if not available_kinds:
            continue
        target_values = [("path", path)]
        if unit_id in task_unit_set:
            target_values.append(("unit", unit_id))
        for target_kind, value in target_values:
            row_key = (target_kind, value)
            if row_key in row_keys:
                continue
            row_keys.add(row_key)
            choice_body = {
                "kind": target_kind,
                "value": value,
                "evidence_kinds": available_kinds,
                "sources": sources,
            }
            choice_id = hashlib.sha256(_canonical(choice_body)).hexdigest()[:24]
            rows.append({"choice_id": choice_id, **choice_body})

    rows.sort(key=lambda row: (row["kind"], row["value"]))
    if len(rows) > config["max_entries"]:
        raise ValueError("context target manifest exceeds max_entries")
    manifest = {
        "version": _VERSION,
        "snapshot_id": snapshot.get("snapshot_id"),
        "profile_sha256": profile_hash,
        "task_id": task.get("task_id"),
        "revision_by_evidence_kind": revisions,
        "choices": rows,
    }
    manifest["manifest_sha256"] = hashlib.sha256(_canonical(manifest)).hexdigest()
    if len(_canonical(manifest)) > config["max_bytes"]:
        raise ValueError("context target manifest exceeds max_bytes")
    validate_context_target_manifest(manifest)
    return manifest


def validate_context_target_choice(manifest: dict, proposal: dict) -> dict | None:
    """Return the opaque server-side choice only for an exact typed match."""
    target = proposal.get("target") if isinstance(proposal, dict) else None
    if not isinstance(target, dict):
        return None
    if set(target) == {"kind", "value"}:
        target_kind, target_value = target.get("kind"), target.get("value")
    elif set(target) == {"target_unit_id", "target_path", "target_symbol"}:
        selected = [(key, value) for key, value in target.items() if isinstance(value, str) and value]
        if len(selected) != 1:
            return None
        field, target_value = selected[0]
        target_kind = {"target_unit_id": "unit", "target_path": "path", "target_symbol": "symbol"}[field]
    else:
        return None
    kind = proposal.get("evidence_kind")
    for choice in manifest.get("choices", []):
        if (
            isinstance(choice, dict)
            and choice.get("kind") == target_kind
            and choice.get("value") == target_value
            and kind in choice.get("evidence_kinds", [])
        ):
            revision = choice_source_revision(manifest, kind)
            source = choice["sources"].get(revision)
            if not isinstance(source, dict):
                return None
            return {**choice, "source_sha": revision, **source}
    return None


def choice_source_revision(manifest: dict, evidence_kind: str) -> str:
    """Return source revision selected by the trusted profile-binding result."""
    # The source map contains only captured BASE/HEAD identities. The engine
    # validates that the returned choice revision agrees with profile policy.
    source = manifest.get("revision_by_evidence_kind", {})
    revision = source.get(evidence_kind) if isinstance(source, dict) else None
    if not isinstance(revision, str):
        raise ValueError("context target manifest revision binding missing")
    return revision


def validate_context_target_manifest(manifest: Any) -> list[dict[str, str]]:
    """Validate the hash and closed fields before provider schema creation."""
    required = {
        "version", "snapshot_id", "profile_sha256", "task_id", "revision_by_evidence_kind", "choices", "manifest_sha256"
    }
    if not isinstance(manifest, dict) or set(manifest) != required or manifest.get("version") != _VERSION:
        raise ValueError("invalid_context_target_manifest")
    if any(not isinstance(manifest.get(key), str) or not manifest[key] for key in ("snapshot_id", "task_id")):
        raise ValueError("invalid_context_target_manifest_identity")
    if not isinstance(manifest.get("profile_sha256"), str) or not re.fullmatch(r"[0-9a-f]{64}", manifest["profile_sha256"]):
        raise ValueError("invalid_context_target_manifest_profile_hash")
    choices = manifest.get("choices")
    if not isinstance(choices, list) or len(choices) > 256:
        raise ValueError("invalid_context_target_manifest_choices")
    revisions = manifest.get("revision_by_evidence_kind")
    if not isinstance(revisions, dict) or set(revisions) != set(_GAP_KINDS) or any(
        not isinstance(value, str) or not _OBJECT_ID.fullmatch(value) for value in revisions.values()
    ):
        raise ValueError("invalid_context_target_manifest_revisions")
    expected_hash = hashlib.sha256(_canonical({key: value for key, value in manifest.items() if key != "manifest_sha256"})).hexdigest()
    if manifest.get("manifest_sha256") != expected_hash:
        raise ValueError("invalid_context_target_manifest_hash")
    seen_ids: set[str] = set()
    seen_pairs: set[tuple[str, str]] = set()
    for choice in choices:
        if not isinstance(choice, dict) or set(choice) != {
            "choice_id", "kind", "value", "evidence_kinds", "sources"
        }:
            raise ValueError("invalid_context_target_manifest_choice")
        if (
            choice.get("kind") not in {"unit", "path"}
            or not isinstance(choice.get("value"), str)
            or not choice["value"]
            or not isinstance(choice.get("evidence_kinds"), list)
            or not choice["evidence_kinds"]
            or any(kind not in _GAP_KINDS for kind in choice["evidence_kinds"])
            or not isinstance(choice.get("sources"), dict)
            or any(
                not isinstance(revision, str)
                or not _OBJECT_ID.fullmatch(revision)
                or not isinstance(source, dict)
                or set(source) != {"source_object_id", "source_object_format"}
                or not isinstance(source.get("source_object_id"), str)
                or not _OBJECT_ID.fullmatch(source["source_object_id"])
                or source.get("source_object_format") not in {"sha1", "sha256"}
                for revision, source in choice["sources"].items()
            )
            or not isinstance(choice.get("choice_id"), str)
            or not re.fullmatch(r"[0-9a-f]{24}", choice["choice_id"])
        ):
            raise ValueError("invalid_context_target_manifest_choice")
        identity = (choice["kind"], choice["value"])
        if choice["choice_id"] in seen_ids or identity in seen_pairs:
            raise ValueError("duplicate_context_target_manifest_choice")
        expected_id = hashlib.sha256(
            _canonical({key: value for key, value in choice.items() if key != "choice_id"})
        ).hexdigest()[:24]
        if choice["choice_id"] != expected_id:
            raise ValueError("invalid_context_target_choice_id")
        expected_kinds = [kind for kind in _GAP_KINDS if revisions[kind] in choice["sources"]]
        if choice["evidence_kinds"] != expected_kinds:
            raise ValueError("invalid_context_target_manifest_kind_binding")
        seen_ids.add(choice["choice_id"])
        seen_pairs.add(identity)
    return choices
