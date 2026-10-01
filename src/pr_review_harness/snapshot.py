"""Read-only, content-addressed Git snapshot construction."""

from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import re
import select
import subprocess
import time
from typing import Any
from urllib.parse import quote, urlsplit, urlunsplit

from .dependency_context import DependencyContextError, project_python_dependencies, validate_dependency_context
from .planner import validate_context_selection


class SnapshotError(ValueError):
    """A requested Git snapshot could not be resolved safely."""


def _git(repo: str, *args: str, input: bytes | None = None) -> bytes:
    try:
        p = subprocess.run(
            ["git", "-C", os.fspath(repo), *args],
            input=input,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SnapshotError(f"git operation failed ({args[0]})") from exc
    if p.returncode:
        # Do not surface raw stderr: it can contain remote URLs or credentials.
        raise SnapshotError(f"git operation failed ({args[0]})")
    return p.stdout


def _git_limited(repo: str, args: list[str], limit: int, deadline: float | None = None) -> tuple[bytes, bool]:
    """Read at most limit bytes from a Git stream and stop oversized output."""
    argv = ["git", "-C", os.fspath(repo), *args]
    proc = None
    try:
        proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        assert proc.stdout is not None
        output = bytearray()
        truncated = False
        deadline = min(time.monotonic() + 30, deadline) if deadline is not None else time.monotonic() + 30
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([proc.stdout], [], [], max(0, remaining))[0]:
                raise subprocess.TimeoutExpired(argv, 30)
            chunk = os.read(proc.stdout.fileno(), min(65536, max(1, limit + 1 - len(output))))
            if not chunk:
                break
            output.extend(chunk)
            if len(output) > limit:
                truncated = True
                break
        if truncated:
            proc.terminate()
        proc.wait(timeout=1 if truncated else max(0.001, deadline - time.monotonic()))
    except (OSError, subprocess.TimeoutExpired) as exc:
        if proc is not None:
            proc.kill()
            proc.wait(timeout=1)
        raise SnapshotError("git content read failed") from exc
    if not truncated and proc.returncode:
        raise SnapshotError("git content read failed")
    return bytes(output[:limit]), truncated


def _sha(repo: str, revision: str) -> str:
    if not revision or revision.startswith("-"):
        raise SnapshotError("invalid revision")
    out = _git(repo, "rev-parse", "--verify", "--end-of-options", f"{revision}^{{commit}}")
    sha = out.decode("ascii", "strict").strip()
    if len(sha) != 40 or any(c not in "0123456789abcdef" for c in sha):
        raise SnapshotError("revision did not resolve to a full commit SHA")
    return sha


def _tree(repo: str, sha: str) -> dict[str, tuple[str, str]]:
    raw = _git(repo, "ls-tree", "-rz", "--full-tree", sha)
    result: dict[str, tuple[str, str]] = {}
    for entry in raw.split(b"\0"):
        if not entry:
            continue
        try:
            meta, path_b = entry.split(b"\t", 1)
            mode, _kind, oid = meta.decode("ascii").split(" ")
            path = path_b.decode("utf-8", "surrogateescape")
        except (ValueError, UnicodeDecodeError) as exc:
            raise SnapshotError("could not parse Git tree") from exc
        result[path] = (mode, oid)
    return result


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _context_head_relation(base_entry: tuple[str, str], head_entry: tuple[str, str] | None) -> tuple[str, str | None]:
    """Compare one exact configured context path by immutable Git blob identity."""
    base_mode, base_oid = base_entry
    if base_mode not in {"100644", "100755"} or not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", base_oid):
        return "UNKNOWN", None
    if head_entry is None:
        return "MISSING_HEAD", None
    head_mode, head_oid = head_entry
    if head_mode not in {"100644", "100755"} or not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", head_oid):
        return "UNKNOWN", None
    return ("UNCHANGED" if base_oid == head_oid else "CHANGED"), head_oid


def _json_hash(value: Any) -> str:
    return _digest(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode())


def _repository_url(profile: dict) -> str | None:
    candidate = profile.get("repository_url")
    if not candidate and isinstance(profile.get("repository"), str):
        name = profile["repository"].strip()
        if re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", name):
            candidate = "https://github.com/" + name
    if candidate is None:
        return None
    if not isinstance(candidate, str):
        raise SnapshotError("repository URL is invalid")
    try:
        parts = urlsplit(candidate)
        if (
            parts.scheme != "https"
            or not parts.hostname
            or parts.username
            or parts.password
            or parts.query
            or parts.fragment
            or not re.fullmatch(r"/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/?", parts.path)
        ):
            raise ValueError
        return urlunsplit(("https", parts.netloc.lower(), parts.path.rstrip("/"), "", ""))
    except ValueError as exc:
        raise SnapshotError("repository URL is invalid") from exc


def _source_url(repository_url: str | None, revision: str, path: str, start: int | None, end: int | None) -> str | None:
    if not repository_url:
        return None
    target = f"{repository_url}/blob/{revision}/{quote(path, safe='/')}"
    if start and start > 0:
        target += f"#L{start}"
        if end and end >= start:
            target += f"-L{end}"
    return target


def bind_repository_url(snapshot: dict, repository_url: str) -> dict:
    """Bind snapshot evidence URLs to one canonical repository identity."""
    canonical = _repository_url({"repository_url": repository_url})
    if not isinstance(snapshot, dict) or not canonical:
        raise SnapshotError("snapshot repository URL is invalid")
    snapshot["repository_url"] = canonical
    for item in snapshot.get("evidence", {}).values():
        if not isinstance(item, dict) or not isinstance(item.get("path"), str):
            continue
        revision = item.get("source_revision")
        if not isinstance(revision, str) or not re.fullmatch(r"[0-9a-f]{40,64}", revision):
            continue
        item["source_url"] = _source_url(
            canonical, revision, item["path"], item.get("line_start"), item.get("line_end")
        )
    return snapshot


def _kind(path: str, modes: tuple[str | None, str | None], profile: dict) -> str:
    classifications = profile.get("classifications", {})
    if isinstance(classifications, dict) and path in classifications:
        value = classifications[path]
        if value in {"human_code", "config", "test", "generated", "binary", "unknown", "documentation"}:
            return value
    generated = profile.get("generated_patterns", [])
    if isinstance(generated, list) and any(
        isinstance(pattern, str) and fnmatch.fnmatchcase(path, pattern) for pattern in generated
    ):
        return "generated"
    mode = next((m for m in modes if m), None)
    if mode == "160000":
        return "unknown"
    lower = path.lower()
    name = lower.rsplit("/", 1)[-1]
    if lower.endswith((".md", ".markdown", ".rst", ".txt", ".adoc")):
        return "documentation"
    if (
        "/test/" in f"/{lower}/"
        or "/tests/" in f"/{lower}/"
        or name.startswith(("test_", "tests_"))
        or name.endswith(("_test.py", ".test.js", ".spec.ts", ".spec.js"))
    ):
        return "test"
    if lower.endswith(
        (".yaml", ".yml", ".toml", ".ini", ".cfg", ".json", ".xml", ".env", ".properties", ".lock", ".tf")
    ) or name in {"dockerfile", "makefile"}:
        return "config"
    if lower.endswith(
        (
            ".py",
            ".pyi",
            ".js",
            ".jsx",
            ".ts",
            ".tsx",
            ".go",
            ".rs",
            ".java",
            ".kt",
            ".c",
            ".h",
            ".cpp",
            ".rb",
            ".php",
            ".sh",
            ".bash",
            ".sql",
        )
    ):
        return "human_code"
    return "unknown"


def _changed_line_ranges(diff: str) -> list[list[int]]:
    """Return compressed HEAD line ranges added or replaced by unified diff."""
    changed: set[int] = set()
    current_line: int | None = None
    for row in diff.splitlines():
        match = re.match(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@", row)
        if match:
            current_line = int(match.group(1))
            continue
        if current_line is None or row.startswith("\\"):
            continue
        if row.startswith("+"):
            changed.add(current_line)
            current_line += 1
        elif row.startswith(" "):
            current_line += 1
        # Removed lines exist only in BASE and do not advance HEAD positions.
    if not changed:
        # A deletion-only unit has no HEAD line that can be verified as changed.
        # This empty-range sentinel makes the current core's positive-line
        # validator reject fabricated locations until file-level deleted-line
        # locations are supported explicitly.
        return [[0, 0]] if any(row.startswith("-") and not row.startswith("---") for row in diff.splitlines()) else []
    ordered = sorted(changed)
    ranges: list[list[int]] = []
    start = end = ordered[0]
    for line in ordered[1:]:
        if line == end + 1:
            end = line
        else:
            ranges.append([start, end])
            start = end = line
    ranges.append([start, end])
    return ranges


def _deleted_line_ranges(diff: str) -> list[list[int]]:
    """Return compressed BASE line ranges removed or replaced by a diff."""
    deleted: set[int] = set()
    current_line: int | None = None
    for row in diff.splitlines():
        match = re.match(r"^@@ -(\d+)(?:,(\d+))? \+\d+(?:,\d+)? @@", row)
        if match:
            current_line = int(match.group(1))
            continue
        if current_line is None or row.startswith("\\"):
            continue
        if row.startswith("-") and not row.startswith("---"):
            deleted.add(current_line)
            current_line += 1
        elif row.startswith(" "):
            current_line += 1
        # Added lines do not consume positions in BASE.
    if not deleted:
        return []
    ordered = sorted(deleted)
    ranges: list[list[int]] = []
    start = end = ordered[0]
    for line in ordered[1:]:
        if line == end + 1:
            end = line
        else:
            ranges.append([start, end])
            start = end = line
    ranges.append([start, end])
    return ranges


def collect_snapshot(repo: str, base: str, head: str, profile: dict, limits: dict) -> dict:
    """Capture immutable diff and bounded file evidence from Git objects only.

    `max_snapshot_context_bytes` bounds source context payloads in aggregate
    when configured; otherwise the legacy `max_context_bytes` value is used.
    Omitted bytes are represented by explicit gap records. Profile context paths are
    read only from the base tree and require a fixed profile hash.
    """
    if not isinstance(profile, dict) or not isinstance(limits, dict):
        raise SnapshotError("profile and limits must be objects")
    context_revision_metadata = profile.get("context_revision_metadata", False)
    if not isinstance(context_revision_metadata, bool):
        raise SnapshotError("profile context_revision_metadata must be boolean")
    profile_version = profile.get("version") or profile.get("profile_version")
    if not isinstance(profile_version, str) or not profile_version.strip():
        raise SnapshotError("profile version is required")
    try:
        context_selection = validate_context_selection(profile)
    except ValueError as exc:
        raise SnapshotError(str(exc)) from exc
    try:
        dependency_context = validate_dependency_context(profile)
    except DependencyContextError as exc:
        raise SnapshotError(str(exc)) from exc
    base_sha, head_sha = _sha(repo, base), _sha(repo, head)
    base_tree, head_tree = _tree(repo, base_sha), _tree(repo, head_sha)
    # Git's NUL-delimited status output safely handles whitespace/newlines.
    status = _git(repo, "diff", "--name-status", "-z", "--find-renames", base_sha, head_sha).split(b"\0")
    changes: list[tuple[str, str | None, str]] = []
    i = 0
    while i < len(status) and status[i]:
        code = status[i].decode("ascii", "replace")
        i += 1
        if code.startswith("R") or code.startswith("C"):
            old = status[i].decode("utf-8", "surrogateescape")
            new = status[i + 1].decode("utf-8", "surrogateescape")
            i += 2
            changes.append((new, old, "renamed"))
        else:
            path = status[i].decode("utf-8", "surrogateescape")
            i += 1
            changes.append(
                (path, None, {"A": "added", "D": "deleted", "M": "modified", "T": "modified"}.get(code[:1], "modified"))
            )
    # A disabled opt-in is equivalent to the legacy absence of the field.
    # Preserve existing snapshot IDs and request hashes for unchanged profiles.
    profile_identity = profile
    if not context_revision_metadata and "context_revision_metadata" in profile:
        profile_identity = {key: value for key, value in profile.items() if key != "context_revision_metadata"}
    profile_hash = _json_hash(profile_identity)
    snapshot_id = "snap-" + _json_hash({"base": base_sha, "head": head_sha, "profile_hash": profile_hash})[:24]
    repo_id = os.path.realpath(repo)
    repository_url = _repository_url(profile)
    evidence: dict[str, dict] = {}
    inventory: list[dict] = []
    gaps: list[dict] = []
    max_context = limits.get("max_snapshot_context_bytes", limits.get("max_context_bytes", 120000))
    if isinstance(max_context, bool) or not isinstance(max_context, int) or max_context <= 0:
        raise SnapshotError("snapshot context byte limit must be a positive integer")
    remaining = max_context
    selection_bytes_remaining = context_selection["max_total_context_bytes"] if context_selection else 0

    def add_evidence(
        path: str,
        data: bytes,
        source_kind: str,
        trust: str,
        source_sha: str,
        source_revision: str,
        line_start: int = 1,
        required: bool = True,
        total_size: int | None = None,
        object_id: str | None = None,
        source_size_bytes: int | None = None,
    ) -> str | None:
        nonlocal remaining
        if b"\0" in data:
            gaps.append({"path": path, "source_kind": source_kind, "reason": "binary_content", "required": required})
            return None
        taken = min(len(data), remaining)
        chunk = data[:taken]
        remaining -= taken
        content = chunk.decode("utf-8", "replace")
        expected_size = len(data) if total_size is None else total_size
        eid = (
            "ev-"
            + _json_hash(
                {
                    "snapshot": snapshot_id,
                    "path": path,
                    "source": source_kind,
                    "sha": source_sha,
                    "hash": _digest(chunk),
                    "start": line_start,
                }
            )[:24]
        )
        evidence[eid] = {
            "evidence_id": eid,
            "path": path,
            "content": content,
            "line_start": line_start,
            "line_end": line_start + max(len(content.splitlines()) - 1, 0),
            "content_hash": _digest(chunk),
            "source_kind": source_kind,
            "trust": trust,
            "source_revision": source_revision,
            "source_object_id": object_id,
            "source_object_format": "sha256"
            if isinstance(object_id, str) and len(object_id) == 64
            else "sha1"
            if object_id
            else None,
            "source_object_size_bytes": source_size_bytes,
            "content_truncated": taken < expected_size,
            "snapshot_id": snapshot_id,
            "source_url": _source_url(
                repository_url,
                source_revision,
                path,
                line_start,
                line_start + max(len(content.splitlines()) - 1, 0),
            ),
        }
        if taken < expected_size:
            gaps.append(
                {
                    "path": path,
                    "source_kind": source_kind,
                    "reason": "context_truncated",
                    "required": required,
                    "omitted_bytes": expected_size - taken,
                    "captured_bytes": taken,
                }
            )
        return eid

    diff_quota = max(1, max_context // max(len(changes), 1))
    for path, old_path, change in changes:
        old_entry = base_tree.get(old_path or path)
        new_entry = head_tree.get(path)
        modes = (old_entry[0] if old_entry else None, new_entry[0] if new_entry else None)
        diff_bytes, diff_truncated = _git_limited(
            repo,
            [
                "--literal-pathspecs",
                "diff",
                "--no-ext-diff",
                "--no-textconv",
                "--no-color",
                "--find-renames",
                "--unified=3",
                base_sha,
                head_sha,
                "--",
                path,
            ],
            min(remaining, diff_quota),
        )
        diff = diff_bytes.decode("utf-8", "replace")
        kind = _kind(path, modes, profile)
        if b"Binary files " in diff_bytes:
            kind = "binary"
        entry = {
            "unit_id": "unit-" + _json_hash({"path": path, "old_path": old_path})[:20],
            "path": path,
            "old_path": old_path,
            "change": change,
            "change_type": {"added": "add", "deleted": "delete", "renamed": "rename", "modified": "modify"}.get(
                change, "modify"
            ),
            "kind": kind,
            "diff": diff,
            "evidence_ids": [],
            "review_context_evidence_ids": [],
            "changed_lines": _changed_line_ranges(diff),
            "old_line_ranges": _deleted_line_ranges(diff),
        }
        entry["diff_hash"] = _digest(diff_bytes)
        diff_eid = add_evidence(
            path, diff.encode("utf-8"), "diff", "untrusted_pr_content", entry["diff_hash"], head_sha, required=True
        )
        if diff_truncated:
            gaps.append(
                {
                    "path": path,
                    "source_kind": "diff",
                    "reason": "diff_truncated",
                    "required": True,
                    "captured_bytes": len(diff_bytes),
                    "omitted_bytes": "unknown",
                }
            )
        if diff_eid:
            entry["evidence_ids"].append(diff_eid)
            entry["review_context_evidence_ids"].append(diff_eid)
            entry["diff"] = evidence[diff_eid]["content"]
        else:
            entry["diff"] = ""
        inventory.append(entry)

    # Preserve the diff budget first, then capture changed full-file context.
    file_sources = []
    for entry, (_path, old_path, _change) in zip(inventory, changes):
        path = entry["path"]
        old_entry = base_tree.get(old_path or path)
        new_entry = head_tree.get(path)
        for source_path, tree_entry, source_kind in (
            (old_path or path, old_entry, "base_file"),
            (path, new_entry, "head_file"),
        ):
            if not tree_entry:
                continue
            mode, oid = tree_entry
            if mode in {"120000", "160000"}:
                gaps.append(
                    {
                        "path": source_path,
                        "source_kind": source_kind,
                        "reason": "symlink_not_followed" if mode == "120000" else "submodule_not_read",
                        "required": True,
                    }
                )
                continue
            file_sources.append((entry, source_path, mode, oid, source_kind))
    for index, (entry, source_path, mode, oid, source_kind) in enumerate(file_sources):
        size = int(_git(repo, "cat-file", "-s", oid).decode("ascii").strip())
        file_available = (
            max(0, remaining - min(selection_bytes_remaining, remaining)) if context_selection else remaining
        )
        fair_share = file_available // max(1, len(file_sources) - index)
        data, _truncated = _git_limited(repo, ["cat-file", "blob", oid], fair_share)
        source_rev = base_sha if source_kind == "base_file" else head_sha
        eid = add_evidence(
            source_path,
            data,
            source_kind,
            "untrusted_pr_content",
            oid,
            source_rev,
            required=context_selection is None,
            total_size=size,
            object_id=oid,
            source_size_bytes=size,
        )
        if eid:
            entry["evidence_ids"].append(eid)

    # Explicit file-level anchors are issued only when the matching file blob
    # was captured from the same immutable side and path. The evidence hash is
    # the anchor proof consumed by reconciliation; a diff alone does not grant
    # a whole-file location.
    for entry in inventory:
        change_type = entry["change_type"]
        if change_type == "delete":
            wanted_path, wanted_side, reason = entry["path"], "BASE", "deleted_file_base_blob"
        elif change_type == "rename" and not entry["changed_lines"] and not entry["old_line_ranges"]:
            wanted_path, wanted_side, reason = entry["old_path"], "BASE", "rename_only_base_blob"
        else:
            wanted_path, wanted_side, reason = entry["path"], "HEAD", "changed_file_head_blob"
        wanted_revision = base_sha if wanted_side == "BASE" else head_sha
        anchor_evidence = next(
            (
                evidence[eid]
                for eid in entry["evidence_ids"]
                if eid in evidence
                and evidence[eid].get("path") == wanted_path
                and evidence[eid].get("source_revision") == wanted_revision
                and evidence[eid].get("source_kind") in {"base_file", "head_file"}
                and evidence[eid].get("content_truncated") is False
            ),
            None,
        )
        if anchor_evidence is not None:
            entry["file_level_location"] = {
                "kind": "file",
                "path": wanted_path,
                "side": wanted_side,
                "reason": reason,
                "evidence_id": anchor_evidence["evidence_id"],
                "evidence_hash": anchor_evidence["content_hash"],
            }

    # Context paths are exact eager reads. Only explicit policy-path rules grant
    # policy authority; immutable base provenance alone remains repository evidence.
    context_paths = profile.get("context_paths", [])
    if not isinstance(context_paths, list) or any(not isinstance(p, str) for p in context_paths):
        raise SnapshotError("profile context_paths must be a list of paths")
    trusted_policy_paths = profile.get("trusted_policy_paths", [])
    if isinstance(trusted_policy_paths, str):
        trusted_policy_paths = [trusted_policy_paths]
    if not isinstance(trusted_policy_paths, list) or any(not isinstance(path, str) for path in trusted_policy_paths):
        raise SnapshotError("profile trusted_policy_paths must be a list of patterns")
    retrieval_patterns = profile.get("retrieval_context_patterns", [])
    if isinstance(retrieval_patterns, str):
        retrieval_patterns = [retrieval_patterns]
    if not isinstance(retrieval_patterns, list) or any(not isinstance(path, str) for path in retrieval_patterns):
        raise SnapshotError("profile retrieval_context_patterns must be a list of patterns")
    trusted_context_refs = []
    required_context = set(profile.get("required_context_paths", []))
    binding_units_by_path: dict[str, dict[str, set[str]]] = {}
    if context_selection:
        for binding in context_selection["bindings"]:
            matched_units = {
                entry["unit_id"]
                for entry in inventory
                if any(fnmatch.fnmatchcase(entry["path"], pattern) for pattern in binding["unit_patterns"])
            }
            for path in binding["context_paths"]:
                row = binding_units_by_path.setdefault(path, {"unit_ids": set(), "lenses": set()})
                row["unit_ids"].update(matched_units)
                row["lenses"].update(binding["lenses"])
        requested_paths = list(
            dict.fromkeys(
                context_selection["mandatory_policy_paths"]
                + [path for path in required_context if isinstance(path, str)]
                + sorted(path for path, match in binding_units_by_path.items() if match["unit_ids"])
            )
        )
    else:
        requested_paths = context_paths
    if context_selection:
        selected_set = set(requested_paths)
        for path in context_paths:
            if path not in selected_set and not any(char in path for char in "*?[]"):
                gaps.append(
                    {
                        "path": path,
                        "source_kind": "profile_context",
                        "reason": "not_bound_by_context_selection",
                        "required": False,
                        "retrievable": any(
                            isinstance(pattern, str) and fnmatch.fnmatchcase(path, pattern)
                            for pattern in retrieval_patterns
                        ),
                    }
                )
    for path in requested_paths:
        is_required = path in required_context
        selection_match = binding_units_by_path.get(path, {"unit_ids": set(), "lenses": set()})
        is_mandatory = bool(context_selection and path in context_selection["mandatory_policy_paths"])
        is_bound = bool(context_selection and selection_match["unit_ids"])
        selected_required = is_required or is_mandatory or is_bound
        item = base_tree.get(path)
        if not item:
            gaps.append(
                {
                    "path": path,
                    "source_kind": "profile_context",
                    "reason": "missing_from_base",
                    "required": selected_required,
                    "unit_ids": sorted(selection_match["unit_ids"]),
                    "lenses": sorted(selection_match["lenses"]),
                }
            )
            continue
        mode, oid = item
        if mode in {"120000", "160000"}:
            gaps.append(
                {
                    "path": path,
                    "source_kind": "profile_context",
                    "reason": "unsafe_file_type",
                    "required": selected_required,
                    "unit_ids": sorted(selection_match["unit_ids"]),
                    "lenses": sorted(selection_match["lenses"]),
                }
            )
            continue
        size = int(_git(repo, "cat-file", "-s", oid).decode("ascii").strip())
        context_limit = remaining
        if context_selection:
            context_limit = min(context_limit, selection_bytes_remaining)
            if selected_required and size > context_limit:
                gaps.append(
                    {
                        "path": path,
                        "source_kind": "profile_context",
                        "reason": "context_selection_budget_exhausted",
                        "required": True,
                        "unit_ids": sorted(selection_match["unit_ids"]),
                        "lenses": sorted(selection_match["lenses"]),
                        "omitted_bytes": size,
                    }
                )
                continue
        data, truncated = _git_limited(repo, ["cat-file", "blob", oid], min(context_limit, size))
        if context_selection and selected_required and truncated:
            gaps.append(
                {
                    "path": path,
                    "source_kind": "profile_context",
                    "reason": "context_selection_budget_exhausted",
                    "required": True,
                    "unit_ids": sorted(selection_match["unit_ids"]),
                    "lenses": sorted(selection_match["lenses"]),
                    "omitted_bytes": max(0, size - len(data)),
                }
            )
            continue
        eid = add_evidence(
            path,
            data,
            "profile_context",
            "trusted_policy"
            if any(fnmatch.fnmatchcase(path, pattern) for pattern in trusted_policy_paths)
            else "repository_evidence",
            oid,
            base_sha,
            required=is_required,
            total_size=size,
            object_id=oid,
            source_size_bytes=size,
        )
        if eid:
            if context_revision_metadata:
                relation, head_object_id = _context_head_relation(item, head_tree.get(path))
                evidence[eid]["head_relation"] = relation
                evidence[eid]["head_object_id"] = head_object_id
            trusted_context_refs.append(eid)
            if context_selection:
                selection_bytes_remaining -= len(data)

    if context_selection:
        selection_deadline = time.monotonic() + 30
        window_cfg = context_selection["window"]
        for entry, (_path, old_path, _change) in zip(inventory, changes):
            windows_used = 0
            source_sides = (
                (
                    "BASE",
                    old_path or entry["path"],
                    entry["old_line_ranges"],
                    base_tree.get(old_path or entry["path"]),
                    base_sha,
                ),
                ("HEAD", entry["path"], entry["changed_lines"], head_tree.get(entry["path"]), head_sha),
            )
            for side, source_path, changed_ranges, tree_entry, source_revision in source_sides:
                if not changed_ranges:
                    continue
                if tree_entry is None:
                    gaps.append(
                        {
                            "path": source_path,
                            "source_kind": "source_window",
                            "reason": "changed_source_unavailable",
                            "required": True,
                            "unit_ids": [entry["unit_id"]],
                            "side": side,
                            "line_ranges": changed_ranges,
                        }
                    )
                    continue
                mode, oid = tree_entry
                if mode in {"120000", "160000"}:
                    continue
                intervals = []
                for raw_range in changed_ranges:
                    if not isinstance(raw_range, (list, tuple)) or len(raw_range) != 2:
                        continue
                    start = max(1, int(raw_range[0]) - window_cfg["before_lines"])
                    end = int(raw_range[1]) + window_cfg["after_lines"]
                    intervals.append((start, end, int(raw_range[0]), int(raw_range[1])))
                merged = []
                for start, end, changed_start, changed_end in sorted(intervals):
                    if merged and start <= merged[-1][1] + 1:
                        merged[-1] = (
                            merged[-1][0],
                            max(merged[-1][1], end),
                            min(merged[-1][2], changed_start),
                            max(merged[-1][3], changed_end),
                        )
                    else:
                        merged.append((start, end, changed_start, changed_end))
                source_size = int(_git(repo, "cat-file", "-s", oid).decode("ascii").strip())
                scan_limit = min(window_cfg["max_scan_bytes"], source_size)
                try:
                    source_bytes, scan_truncated = _git_limited(
                        repo,
                        ["cat-file", "blob", oid],
                        scan_limit,
                        deadline=selection_deadline,
                    )
                except SnapshotError:
                    source_bytes, scan_truncated = b"", True
                lines = source_bytes.splitlines(keepends=True)
                for start, end, changed_start, changed_end in merged:
                    if windows_used >= window_cfg["max_windows_per_unit"]:
                        gaps.append(
                            {
                                "path": source_path,
                                "source_kind": "source_window",
                                "reason": "window_count_limit",
                                "required": True,
                                "unit_ids": [entry["unit_id"]],
                                "side": side,
                                "line_ranges": [[changed_start, changed_end]],
                            }
                        )
                        continue
                    effective_end = min(end, len(lines)) if not scan_truncated else end
                    if effective_end > len(lines):
                        gaps.append(
                            {
                                "path": source_path,
                                "source_kind": "source_window",
                                "reason": "window_scan_limit" if scan_truncated else "changed_line_unavailable",
                                "required": True,
                                "unit_ids": [entry["unit_id"]],
                                "side": side,
                                "line_ranges": [[changed_start, changed_end]],
                                "scan_limit_bytes": scan_limit,
                            }
                        )
                        continue
                    window_bytes = b"".join(lines[start - 1 : effective_end])
                    if len(window_bytes) > window_cfg["max_bytes"]:
                        gaps.append(
                            {
                                "path": source_path,
                                "source_kind": "source_window",
                                "reason": "changed_hunk_exceeds_window_limit",
                                "required": True,
                                "unit_ids": [entry["unit_id"]],
                                "side": side,
                                "line_ranges": [[changed_start, changed_end]],
                                "window_bytes": len(window_bytes),
                                "max_window_bytes": window_cfg["max_bytes"],
                            }
                        )
                        continue
                    if len(window_bytes) > selection_bytes_remaining or len(window_bytes) > remaining:
                        gaps.append(
                            {
                                "path": source_path,
                                "source_kind": "source_window",
                                "reason": "context_selection_budget_exhausted",
                                "required": True,
                                "unit_ids": [entry["unit_id"]],
                                "side": side,
                                "line_ranges": [[changed_start, changed_end]],
                            }
                        )
                        continue
                    window_lines = window_bytes.decode("utf-8", "replace").splitlines()
                    window_eid = add_evidence(
                        source_path,
                        window_bytes,
                        "source_window",
                        "untrusted_pr_content",
                        oid,
                        source_revision,
                        line_start=start,
                        required=True,
                        total_size=len(window_bytes),
                        object_id=oid,
                        source_size_bytes=source_size,
                    )
                    if window_eid:
                        record = evidence[window_eid]
                        record["source_side"] = side
                        record["changed_line_ranges"] = [[changed_start, changed_end]]
                        record["line_end"] = start + max(0, len(window_lines) - 1)
                        record["source_url"] = _source_url(
                            repository_url,
                            source_revision,
                            source_path,
                            start,
                            record["line_end"],
                        )
                        entry["evidence_ids"].append(window_eid)
                        entry["review_context_evidence_ids"].append(window_eid)
                        windows_used += 1
                        selection_bytes_remaining -= len(window_bytes)

    if dependency_context:
        projection_total = 0
        for binding_index, binding in enumerate(dependency_context["bindings"]):
            matching_units = [
                entry
                for entry in inventory
                if any(fnmatch.fnmatchcase(entry["path"], pattern) for pattern in binding["unit_patterns"])
            ]
            if not matching_units:
                continue
            binding_id = "dependency-binding-" + _json_hash({"index": binding_index, "binding": binding})[:16]
            for side in binding["sides"]:
                revision = base_sha if side == "BASE" else head_sha
                tree = base_tree if side == "BASE" else head_tree
                manifest_entry = tree.get(binding["manifest_path"])
                reason = None
                projection = None
                manifest_oid = None
                lock_oid = None
                lock_bytes = None
                if manifest_entry is None:
                    reason = "dependency_manifest_missing"
                elif manifest_entry[0] != "100644" and manifest_entry[0] != "100755":
                    reason = "dependency_manifest_unsafe_type"
                else:
                    manifest_oid = manifest_entry[1]
                    manifest_size = int(_git(repo, "cat-file", "-s", manifest_oid).decode("ascii").strip())
                    if manifest_size > dependency_context["max_source_bytes"]:
                        reason = "dependency_manifest_source_limit"
                    else:
                        manifest_bytes, truncated = _git_limited(
                            repo, ["cat-file", "blob", manifest_oid], manifest_size + 1
                        )
                        if truncated or len(manifest_bytes) != manifest_size:
                            reason = "dependency_manifest_source_unavailable"
                        else:
                            lock_entry = tree.get(binding["lock_path"])
                            if lock_entry is not None:
                                if lock_entry[0] not in {"100644", "100755"}:
                                    reason = "dependency_lock_unsafe_type"
                                else:
                                    lock_oid = lock_entry[1]
                                    lock_size = int(_git(repo, "cat-file", "-s", lock_oid).decode("ascii").strip())
                                    if lock_size > dependency_context["max_source_bytes"]:
                                        reason = "dependency_lock_source_limit"
                                    else:
                                        lock_bytes, truncated = _git_limited(
                                            repo, ["cat-file", "blob", lock_oid], lock_size + 1
                                        )
                                        if truncated or len(lock_bytes) != lock_size:
                                            reason = "dependency_lock_source_unavailable"
                            if reason is None:
                                try:
                                    projection = project_python_dependencies(
                                        binding=binding,
                                        side=side,
                                        revision=revision,
                                        manifest_oid=manifest_oid,
                                        manifest_bytes=manifest_bytes,
                                        lock_oid=lock_oid,
                                        lock_bytes=lock_bytes,
                                        max_bytes=binding["max_bytes"],
                                    )
                                except DependencyContextError as exc:
                                    reason = str(exc)
                selected_units = [entry["unit_id"] for entry in matching_units]
                if projection is None:
                    gaps.append(
                        {
                            "path": binding["manifest_path"],
                            "source_kind": "dependency_projection",
                            "reason": reason or "dependency_projection_unavailable",
                            "required": True,
                            "side": side,
                            "source_revision": revision,
                            "unit_ids": selected_units,
                        }
                    )
                    projection_key = _json_hash(
                        {"snapshot": snapshot_id, "binding": binding_id, "side": side, "revision": revision}
                    )[:24]
                    for entry in matching_units:
                        for lens in binding["lenses"]:
                            route = entry.setdefault("dependency_context_ids_by_lens", {}).setdefault(lens, [])
                            route.append(f"missing-dependency-context-{projection_key}")
                    continue
                content = projection["content"]
                content_bytes = len(content.encode("utf-8"))
                if (
                    content_bytes > binding["max_bytes"]
                    or content_bytes > dependency_context["max_total_projection_bytes"] - projection_total
                    or content_bytes > remaining
                    or (context_selection and content_bytes > selection_bytes_remaining)
                ):
                    gaps.append(
                        {
                            "path": binding["manifest_path"],
                            "source_kind": "dependency_projection",
                            "reason": "dependency_projection_budget_exhausted",
                            "required": True,
                            "side": side,
                            "source_revision": revision,
                            "unit_ids": selected_units,
                            "projection_bytes": content_bytes,
                        }
                    )
                    projection_key = _json_hash(
                        {"snapshot": snapshot_id, "binding": binding_id, "side": side, "revision": revision}
                    )[:24]
                    for entry in matching_units:
                        for lens in binding["lenses"]:
                            entry.setdefault("dependency_context_ids_by_lens", {}).setdefault(lens, []).append(
                                f"missing-dependency-context-{projection_key}"
                            )
                    continue
                evidence_id = "ev-dependency-" + _json_hash(
                    {
                        "snapshot": snapshot_id,
                        "binding": binding_id,
                        "side": side,
                        "revision": revision,
                        "manifest_oid": manifest_oid,
                        "lock_oid": lock_oid,
                        "content_hash": projection["content_hash"],
                    }
                )[:24]
                evidence[evidence_id] = {
                    "evidence_id": evidence_id,
                    "path": binding["manifest_path"],
                    "content": content,
                    "content_hash": projection["content_hash"],
                    "source_kind": "dependency_projection",
                    "trust": "repository_evidence",
                    "source_revision": revision,
                    "source_side": side,
                    "source_object_id": manifest_oid,
                    "source_object_format": "sha256" if len(manifest_oid) == 64 else "sha1",
                    "source_object_size_bytes": len(manifest_bytes),
                    "manifest_sha256": projection["manifest_sha256"],
                    "lock_object_id": lock_oid,
                    "lock_sha256": projection["lock_sha256"],
                    "snapshot_id": snapshot_id,
                    "content_truncated": False,
                    "dependency_binding_id": binding_id,
                    "dependency_lenses": list(binding["lenses"]),
                    "dependency_unit_ids": selected_units,
                }
                remaining -= content_bytes
                projection_total += content_bytes
                if context_selection:
                    selection_bytes_remaining -= content_bytes
                for entry in matching_units:
                    for lens in binding["lenses"]:
                        entry.setdefault("dependency_context_ids_by_lens", {}).setdefault(lens, []).append(evidence_id)

    payload = {
        "repository": repo_id,
        "repository_url": repository_url,
        "base_sha": base_sha,
        "head_sha": head_sha,
        "profile_version": profile_version,
        "profile_hash": profile_hash,
        "inventory": inventory,
        "evidence": evidence,
        "gaps": gaps,
        "trusted_context_refs": trusted_context_refs,
    }
    return {"snapshot_id": snapshot_id, **payload, "snapshot_hash": _json_hash(payload)}


def recent_commits(repo: str, count: int, head: str = "HEAD") -> list[dict]:
    """Return bounded first-parent commit pairs, newest first."""
    if not isinstance(count, int) or count < 1 or count > 100:
        raise SnapshotError("count must be between 1 and 100")
    head_sha = _sha(repo, head)
    raw = _git(repo, "rev-list", "--first-parent", "--parents", f"--max-count={count}", head_sha)
    commits = [row.decode("ascii", "strict").split() for row in raw.splitlines() if row]
    pairs = []
    for row in commits:
        sha = row[0]
        if len(sha) != 40 or any(c not in "0123456789abcdef" for c in sha):
            raise SnapshotError("git returned an invalid commit identity")
        if len(row) == 1:
            continue
        parent = row[1]
        subject = _git(repo, "show", "-s", "--format=%s", sha).decode("utf-8", "replace").strip()
        pairs.append({"base": parent, "head": sha, "subject": subject})
        if len(pairs) == count:
            break
    return pairs
