"""Deterministic, bounded context retrieval from immutable Git objects."""

from __future__ import annotations

import fnmatch
import hashlib
import math
import os
import re
import select
import subprocess
import time
from datetime import datetime, timezone
from urllib.parse import quote, urlsplit

from .budget import _canonical as _ipc_canonical


class EvidenceError(ValueError):
    """A context request is invalid or cannot be safely satisfied."""


class ContextRetriever:
    """Picklable CLI adapter binding retrieval to a local bare Git repository."""

    def __init__(self, repo: str | os.PathLike[str]):
        self._repo = os.fspath(repo)

    def __call__(self, snapshot: dict, profile: dict, proposal: dict, limits: dict) -> dict:
        return retrieve_context_gap(self._repo, snapshot, profile, proposal, limits)


_GAP_KINDS = {"caller", "implementation", "test", "configuration", "contract", "trust_boundary", "provenance", "other"}
_LENSES = {"correctness", "tests", "design", "security", "performance", "maintainability", "project_specific"}
_SHA_RE = re.compile(r"^[0-9a-f]{40,64}$")


def _fit_ipc_envelope(result: dict, max_result_bytes: int) -> dict:
    """Fit trusted retrieval content to the existing serialized IPC ceiling.

    Only evidence content is shortened. The complete envelope is measured with
    the same canonical serializer used by ``IsolatedInvocation``; all evidence
    bindings are then recomputed and truncation is made explicit.
    """
    if len(_ipc_canonical(result)) <= max_result_bytes:
        return result
    evidence = result.get("evidence")
    if not isinstance(evidence, dict) or not isinstance(evidence.get("content"), str):
        return {"status": "UNRESOLVED", "reason": "retrieval_metadata_exceeds_ipc_limit", "evidence": None}

    original_content = evidence["content"]
    original_bytes = original_content.encode("utf-8")
    if hashlib.sha256(original_bytes).hexdigest() != evidence.get("content_hash"):
        # The source was not representable as the UTF-8 text whose hash the
        # engine verifies. Do not manufacture a different evidence identity.
        return {"status": "UNRESOLVED", "reason": "retrieval_evidence_encoding_invalid", "evidence": None}

    low, high = 0, len(original_content)
    best = None
    while low <= high:
        middle = (low + high) // 2
        candidate_content = original_content[:middle]
        candidate_bytes = candidate_content.encode("utf-8")
        candidate_evidence = {
            **evidence,
            "content": candidate_content,
            "content_hash": hashlib.sha256(candidate_bytes).hexdigest(),
            "captured_bytes": len(candidate_bytes),
            "truncated": True,
        }
        candidate_evidence["evidence_id"] = (
            "ev-"
            + hashlib.sha256(
                _ipc_canonical(
                    {
                        "snapshot_id": candidate_evidence.get("snapshot_id"),
                        "revision": candidate_evidence.get("source_revision"),
                        "path": candidate_evidence.get("path"),
                        "hash": candidate_evidence["content_hash"],
                    }
                )
            ).hexdigest()[:24]
        )
        source_url = candidate_evidence.get("source_url")
        if isinstance(source_url, str) and "#L1-" in source_url:
            base_url = source_url.split("#L1-", 1)[0]
            line_count = max(len(candidate_content.splitlines()), 1)
            candidate_evidence["source_url"] = f"{base_url}#L1-L{line_count}"
        candidate_result = {
            **result,
            "status": "PARTIAL",
            "reason": "ipc_envelope_truncated",
            "evidence": candidate_evidence,
        }
        if len(_ipc_canonical(candidate_result)) <= max_result_bytes:
            best = candidate_result
            low = middle + 1
        else:
            high = middle - 1

    if best is None:
        return {"status": "UNRESOLVED", "reason": "retrieval_metadata_exceeds_ipc_limit", "evidence": None}
    return best


def _git(repo: str, *args: str, deadline: float | None = None) -> bytes:
    remaining = 15.0 if deadline is None else min(15.0, deadline - time.monotonic())
    if remaining <= 0:
        raise EvidenceError("immutable evidence deadline exhausted")
    try:
        result = subprocess.run(
            ["git", "-C", os.fspath(repo), *args],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=remaining,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise EvidenceError("immutable evidence read failed") from exc
    if result.returncode:
        raise EvidenceError("immutable evidence read failed")
    return result.stdout


def _git_blob_limited(repo: str, object_id: str, limit: int, deadline: float) -> tuple[bytes, bool]:
    argv = ["git", "-C", os.fspath(repo), "cat-file", "blob", object_id]
    process = None
    try:
        process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        assert process.stdout is not None
        chunks = bytearray()
        truncated = False
        while len(chunks) <= limit:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([process.stdout], [], [], remaining)[0]:
                raise subprocess.TimeoutExpired(argv, 15)
            block = os.read(process.stdout.fileno(), min(65536, limit + 1 - len(chunks)))
            if not block:
                break
            chunks.extend(block)
        if len(chunks) > limit:
            truncated = True
            process.terminate()
        remaining = deadline - time.monotonic()
        process.wait(timeout=max(0.01, min(1.0, remaining)))
    except subprocess.TimeoutExpired as exc:
        if process is not None:
            process.kill()
            process.wait()
        raise EvidenceError("immutable evidence deadline exhausted") from exc
    except OSError as exc:
        if process is not None:
            process.kill()
            process.wait()
        raise EvidenceError("immutable evidence read failed") from exc
    finally:
        if process is not None and process.stdout is not None:
            process.stdout.close()
    if not truncated and process.returncode:
        raise EvidenceError("immutable evidence read failed")
    return bytes(chunks[:limit]), truncated


def retrieve_context_gap(
    repo: str,
    snapshot: dict,
    profile: dict,
    proposal: dict,
    limits: dict,
) -> dict:
    """Resolve one typed proposal through trusted path rules and Git objects.

    The returned object contains either a content-addressed evidence item or a
    typed reason. Model-provided paths and symbols never become Git commands;
    only paths already named by the trusted profile can be read. Retrieval
    defaults to the immutable base revision and never checks out or executes
    repository content.
    """
    if not all(isinstance(item, dict) for item in (snapshot, profile, proposal, limits)):
        raise EvidenceError("snapshot, profile, proposal, and limits must be objects")
    base_sha = snapshot.get("base_sha")
    head_sha = snapshot.get("head_sha")
    snapshot_id = snapshot.get("snapshot_id")
    if not isinstance(base_sha, str) or not _SHA_RE.fullmatch(base_sha):
        raise EvidenceError("snapshot base identity is invalid")
    if not isinstance(head_sha, str) or not _SHA_RE.fullmatch(head_sha):
        raise EvidenceError("snapshot head identity is invalid")
    if not isinstance(snapshot_id, str) or not snapshot_id:
        raise EvidenceError("snapshot identity is missing")
    if proposal.get("evidence_kind") not in _GAP_KINDS or proposal.get("required_lens") not in _LENSES:
        raise EvidenceError("context proposal type is unsupported")
    target = proposal.get("target", proposal)
    if not isinstance(target, dict):
        raise EvidenceError("context proposal target is invalid")
    target_keys = [key for key in ("target_unit_id", "target_path", "target_symbol") if target.get(key)]
    if len(target_keys) != 1:
        raise EvidenceError("context proposal must have exactly one target")
    if not isinstance(proposal.get("rationale"), str) or not proposal["rationale"].strip():
        raise EvidenceError("context proposal rationale is required")
    if target_keys[0] == "target_symbol":
        return {"status": "UNRESOLVED", "reason": "symbol_lookup_not_in_allowlist_contract", "evidence": None}

    inventory = snapshot.get("inventory", [])
    if not isinstance(inventory, list):
        raise EvidenceError("snapshot inventory is invalid")
    unit = None
    requested_path = target.get("target_path")
    if target_keys[0] == "target_unit_id":
        unit = next(
            (u for u in inventory if isinstance(u, dict) and u.get("unit_id") == target["target_unit_id"]), None
        )
        if unit is None:
            return {"status": "UNRESOLVED", "reason": "target_unit_not_in_snapshot", "evidence": None}
        requested_path = unit.get("path")
    if (
        not isinstance(requested_path, str)
        or not requested_path
        or requested_path.startswith("/")
        or ".." in requested_path.split("/")
    ):
        return {"status": "UNRESOLVED", "reason": "target_path_invalid", "evidence": None}

    # A target must be explicitly allowlisted. A changed unit does not grant
    # arbitrary neighboring-file access.
    allowlist = profile.get("retrieval_context_patterns", profile.get("context_paths", []))
    if isinstance(allowlist, str):
        allowlist = [allowlist]
    if not isinstance(allowlist, list) or not any(
        isinstance(pattern, str) and fnmatch.fnmatchcase(requested_path, pattern) for pattern in allowlist
    ):
        return {"status": "UNRESOLVED", "reason": "target_path_not_allowlisted", "evidence": None}
    policy_paths = profile.get("trusted_policy_paths", [])
    if isinstance(policy_paths, str):
        policy_paths = [policy_paths]
    if not isinstance(policy_paths, list) or any(not isinstance(path, str) for path in policy_paths):
        raise EvidenceError("trusted policy path rules are invalid")

    kind = proposal["evidence_kind"]
    # Policy and contract context is sourced from base. Implementation/test
    # context may be from head only when a trusted profile explicitly permits
    # it via retrieval_revisions; the default remains base-only.
    revision = base_sha
    revision_policy = profile.get("retrieval_revisions", {})
    if isinstance(revision_policy, dict) and revision_policy.get(kind) == "head":
        revision = head_sha
    target_binding = proposal.get("_context_target_binding")
    if target_binding is not None:
        if (
            not isinstance(target_binding, dict)
            or target_binding.get("snapshot_id") != snapshot_id
            or target_binding.get("path") != requested_path
            or target_binding.get("evidence_kind") != kind
            or target_binding.get("source_sha") != revision
            or not isinstance(target_binding.get("choice_id"), str)
        ):
            raise EvidenceError("context target manifest binding mismatch")
    max_bytes = limits.get("max_bytes", limits.get("max_context_bytes"))
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes < 1:
        raise EvidenceError("context retrieval byte limit is invalid")
    remaining = limits.get("context_bytes_remaining", max_bytes)
    if isinstance(remaining, bool) or not isinstance(remaining, int) or remaining < 1:
        return {"status": "UNRESOLVED", "reason": "context_budget_exhausted", "evidence": None}
    retrieval_bytes = limits.get("max_retrieval_bytes", max_bytes)
    if isinstance(retrieval_bytes, bool) or not isinstance(retrieval_bytes, int) or retrieval_bytes < 1:
        raise EvidenceError("context retrieval byte limit is invalid")
    limit = min(max_bytes, remaining, retrieval_bytes)
    if limit < 1:
        return {"status": "UNRESOLVED", "reason": "context_budget_exhausted", "evidence": None}
    # Resolve the allowlisted path to an immutable blob ID, then stream at
    # most the budgeted amount from Git. No checkout or working-tree file read.
    deadline_seconds = limits.get("deadline_seconds", 15)
    if (
        isinstance(deadline_seconds, bool)
        or not isinstance(deadline_seconds, (int, float))
        or not math.isfinite(deadline_seconds)
        or deadline_seconds <= 0
    ):
        return {"status": "UNRESOLVED", "reason": "context_budget_exhausted", "evidence": None}
    deadline = time.monotonic() + min(float(deadline_seconds), 15.0)
    object_id = (
        _git(repo, "rev-parse", "--verify", "--end-of-options", f"{revision}:{requested_path}", deadline=deadline)
        .decode()
        .strip()
    )
    if not re.fullmatch(r"[0-9a-f]{40,64}", object_id):
        raise EvidenceError("immutable evidence object identity is invalid")
    if target_binding is not None and target_binding.get("source_object_id") != object_id:
        return {"status": "UNRESOLVED", "reason": "context_target_source_identity_mismatch", "evidence": None}
    raw, truncated = _git_blob_limited(repo, object_id, limit, deadline)
    if b"\0" in raw:
        return {"status": "UNRESOLVED", "reason": "binary_context_not_retrieved", "evidence": None}
    try:
        content = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        if truncated and exc.reason == "unexpected end of data" and exc.end == len(raw):
            # The captured prefix is valid UTF-8 except for an incomplete final
            # code point at the byte boundary; the uncaptured tail is unknown.
            raw = raw[: exc.start]
            content = raw.decode("utf-8")
        else:
            return {"status": "UNRESOLVED", "reason": "retrieval_evidence_encoding_invalid", "evidence": None}
    content_bytes = content.encode("utf-8")
    content_hash = hashlib.sha256(content_bytes).hexdigest()
    evidence_id = (
        "ev-"
        + hashlib.sha256(
            _ipc_canonical({"snapshot_id": snapshot_id, "revision": revision, "path": requested_path, "hash": content_hash})
        ).hexdigest()[:24]
    )
    evidence = {
        "evidence_id": evidence_id,
        "snapshot_id": snapshot_id,
        "path": requested_path,
        "content": content,
        "source_kind": "repository_file",
        "source_revision": revision,
        "source_object_id": object_id,
        "content_hash": content_hash,
        "captured_bytes": len(content_bytes),
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "trust": (
            "trusted_policy"
            if revision == base_sha
            and any(
                isinstance(pattern, str) and fnmatch.fnmatchcase(requested_path, pattern) for pattern in policy_paths
            )
            else "repository_evidence"
        ),
        "evidence_kind": kind,
        "required_lens": proposal["required_lens"],
        "proposal_id": proposal.get("_proposal_id"),
        "task_id": proposal.get("_task_id"),
        "truncated": truncated,
    }
    repository_url = snapshot.get("repository_url")
    if isinstance(repository_url, str):
        parsed = urlsplit(repository_url)
        if parsed.scheme == "https" and parsed.hostname and not parsed.username and not parsed.password:
            source_url = f"https://{parsed.netloc.lower()}{parsed.path.rstrip('/')}/blob/{revision}/{quote(requested_path, safe='/')}"
            line_count = max(len(evidence["content"].splitlines()), 1)
            evidence["source_url"] = f"{source_url}#L1-L{line_count}"
    result = {"status": "RESOLVED" if not evidence["truncated"] else "PARTIAL", "reason": None, "evidence": evidence}
    max_result_bytes = limits.get("max_result_bytes")
    if max_result_bytes is not None:
        if isinstance(max_result_bytes, bool) or not isinstance(max_result_bytes, int) or max_result_bytes < 1:
            raise EvidenceError("context retrieval result byte limit is invalid")
        result = _fit_ipc_envelope(result, max_result_bytes)
    return result
