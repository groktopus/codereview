"""Bounded, lossless extraction of immutable trusted policy context.

This module does not interpret policy. It partitions captured BASE policy bytes
into exact spans and emits a total clause-by-obligation trace. Applicability is
UNRESOLVED unless a matching, reviewed rule is explicitly bound in the trusted
profile.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import math
import re
from collections.abc import Mapping, Sequence
from typing import Any


class PolicyInventoryError(ValueError):
    """The frozen profile, snapshot, obligation, or finite limits are invalid."""


_EXTRACTOR_ID = "paragraph-boundary-v1"
_MAX_INPUT_BYTES = 2_000_000
_MAX_SOURCES = 128
_MAX_NODES = 100_000
_MAX_CLAUSES = 8_192
_MAX_TRACE_ROWS = 100_000
_MAX_TRACE_BYTES = 8_000_000
_OBJECT_ID = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_SOURCE_KINDS = {"profile_context", "repository_file", "base_file"}
_BLANK_LINE = re.compile(rb"(?:\r?\n[ \t]*){2,}")
_FENCED_BLOCK = re.compile(rb"(?m)^ {0,3}(?:`{3,}|~{3,})")


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _validate_bounded_json(value: Any, *, max_nodes: int, max_string_chars: int) -> None:
    """Reject cycles, exotic values, deep trees and large strings before hashing."""
    stack: list[tuple[Any, int, bool]] = [(value, 0, False)]
    active_containers: set[int] = set()
    nodes = 0
    chars = 0
    while stack:
        item, depth, exiting = stack.pop()
        if exiting:
            active_containers.remove(id(item))
            continue
        nodes += 1
        if nodes > max_nodes:
            raise PolicyInventoryError("input_node_limit_exceeded")
        if depth > 64:
            raise PolicyInventoryError("input_depth_limit_exceeded")
        if item is None or isinstance(item, (bool, int)):
            continue
        if isinstance(item, float):
            if not math.isfinite(item):
                raise PolicyInventoryError("input_number_invalid")
            continue
        if isinstance(item, str):
            chars += len(item)
            if chars > max_string_chars:
                raise PolicyInventoryError("input_string_limit_exceeded")
            continue
        if isinstance(item, list):
            marker = id(item)
            if marker in active_containers:
                raise PolicyInventoryError("cyclic_input")
            active_containers.add(marker)
            stack.append((item, depth, True))
            stack.extend((child, depth + 1, False) for child in item)
            continue
        if isinstance(item, dict):
            marker = id(item)
            if marker in active_containers:
                raise PolicyInventoryError("cyclic_input")
            active_containers.add(marker)
            stack.append((item, depth, True))
            for key, child in item.items():
                if not isinstance(key, str):
                    raise PolicyInventoryError("input_key_invalid")
                chars += len(key)
                if chars > max_string_chars:
                    raise PolicyInventoryError("input_string_limit_exceeded")
                stack.append((child, depth + 1, False))
            continue
        raise PolicyInventoryError("input_type_invalid")


def _sha256_json(value: Any) -> str:
    return _sha256(_canonical_bytes(value))


def _validate_identity(snapshot: Mapping[str, Any], profile: Mapping[str, Any], max_nodes: int) -> None:
    _validate_bounded_json(snapshot, max_nodes=max_nodes, max_string_chars=_MAX_INPUT_BYTES)
    _validate_bounded_json(profile, max_nodes=max_nodes, max_string_chars=_MAX_INPUT_BYTES)
    payload = {key: value for key, value in snapshot.items() if key not in {"snapshot_id", "snapshot_hash"}}
    profile_hash = _sha256_json(profile)
    if snapshot.get("profile_hash") != profile_hash:
        raise PolicyInventoryError("profile_hash_mismatch")
    if snapshot.get("snapshot_hash") != _sha256_json(payload):
        raise PolicyInventoryError("snapshot_hash_mismatch")
    base_sha = snapshot.get("base_sha")
    head_sha = snapshot.get("head_sha")
    if not isinstance(base_sha, str) or not _OBJECT_ID.fullmatch(base_sha):
        raise PolicyInventoryError("base_revision_invalid")
    if not isinstance(head_sha, str) or not _OBJECT_ID.fullmatch(head_sha):
        raise PolicyInventoryError("head_revision_invalid")
    expected_snapshot = "snap-" + _sha256_json({"base": base_sha, "head": head_sha, "profile_hash": profile_hash})[:24]
    if snapshot.get("snapshot_id") != expected_snapshot:
        raise PolicyInventoryError("snapshot_id_mismatch")
    version = profile.get("version") or profile.get("profile_version")
    if not isinstance(version, str) or snapshot.get("profile_version") != version:
        raise PolicyInventoryError("profile_version_mismatch")


def _limits(value: Mapping[str, Any]) -> dict[str, int]:
    names = {
        "max_input_bytes": _MAX_INPUT_BYTES,
        "max_sources": _MAX_SOURCES,
        "max_nodes": _MAX_NODES,
        "max_clauses": _MAX_CLAUSES,
        "max_trace_rows": _MAX_TRACE_ROWS,
        "max_trace_bytes": _MAX_TRACE_BYTES,
    }
    result: dict[str, int] = {}
    for name, hard_max in names.items():
        raw = value.get(name, hard_max)
        if isinstance(raw, bool) or not isinstance(raw, int) or not 1 <= raw <= hard_max:
            raise PolicyInventoryError(f"{name}_invalid")
        result[name] = raw
    return result


def _trusted_patterns(profile: Mapping[str, Any]) -> list[str]:
    raw = profile.get("trusted_policy_paths", [])
    if isinstance(raw, str):
        raw = [raw]
    if not isinstance(raw, list) or any(not isinstance(pattern, str) or not pattern for pattern in raw):
        raise PolicyInventoryError("trusted_policy_paths_invalid")
    return list(raw)


def _source_bytes(record: Mapping[str, Any], max_bytes: int) -> tuple[bytes | None, str | None]:
    content = record.get("content")
    if not isinstance(content, str):
        return None, "source_content_unavailable"
    # Character count is a safe early rejection: UTF-8 bytes cannot be smaller
    # than this. Encoding only occurs after the finite character bound.
    if len(content) > max_bytes:
        return None, "source_byte_limit_exceeded"
    try:
        raw = content.encode("utf-8", "strict")
    except UnicodeEncodeError:
        return None, "source_encoding_unsupported"
    if len(raw) > max_bytes:
        return None, "source_byte_limit_exceeded"
    if record.get("content_truncated") is not False and record.get("truncated") is not False:
        return None, "source_not_known_complete"
    expected_size = record.get("source_object_size_bytes", record.get("captured_bytes"))
    if isinstance(expected_size, bool) or not isinstance(expected_size, int) or expected_size != len(raw):
        return None, "source_size_mismatch"
    digest = record.get("content_hash")
    if not isinstance(digest, str) or digest != _sha256(raw):
        return None, "source_content_hash_mismatch"
    return raw, None


def _segments(raw: bytes, max_parts: int) -> list[tuple[int, int, str]]:
    """Partition Markdown-ish content at blank-line boundaries, preserving bytes."""
    if not raw or _FENCED_BLOCK.search(raw):
        return [(0, len(raw), "whole_blob")]
    matches = _BLANK_LINE.finditer(raw)
    spans: list[tuple[int, int, str]] = []
    start = 0
    for match in matches:
        end = match.end()
        if end > start:
            spans.append((start, end, "paragraph_boundary"))
            start = end
            if len(spans) >= max_parts:
                return [(0, len(raw), "whole_blob")]
    if not spans:
        return [(0, len(raw), "whole_blob")]
    if start < len(raw):
        spans.append((start, len(raw), "paragraph_boundary"))
    if not spans:
        return [(0, len(raw), "whole_blob")]
    if (
        spans[0][0] != 0
        or spans[-1][1] != len(raw)
        or any(left[1] != right[0] for left, right in zip(spans, spans[1:]))
    ):
        return [(0, len(raw), "whole_blob")]
    return spans


def _line_range(raw: bytes, start: int, end: int) -> tuple[int, int]:
    line_start = raw[:start].count(b"\n") + 1
    part = raw[start:end]
    newlines = part.count(b"\n")
    line_end = line_start + newlines - (1 if part.endswith(b"\n") else 0)
    return line_start, max(line_start, line_end)


def _normalize_obligations(obligations: Sequence[Mapping[str, Any]], max_nodes: int) -> list[dict[str, Any]]:
    if not isinstance(obligations, Sequence) or isinstance(obligations, (str, bytes)):
        raise PolicyInventoryError("obligations_invalid")
    if len(obligations) > max_nodes:
        raise PolicyInventoryError("obligation_node_limit_exceeded")
    normalized: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in obligations:
        if not isinstance(item, Mapping):
            raise PolicyInventoryError("obligation_invalid")
        oid = item.get("obligation_id")
        kind = item.get("obligation_kind")
        if not isinstance(oid, str) or not oid or oid in seen or not isinstance(kind, str) or not kind:
            raise PolicyInventoryError("obligation_identity_invalid")
        scope_unit_ids = item.get("scope_unit_ids", [])
        if not isinstance(scope_unit_ids, list) or any(not isinstance(value, str) for value in scope_unit_ids):
            raise PolicyInventoryError("obligation_scope_invalid")
        seen.add(oid)
        normalized.append(
            {
                "obligation_id": oid,
                "obligation_kind": kind,
                "required": item.get("required") is True,
                "scope_unit_ids": sorted(set(scope_unit_ids)),
                "lens": item.get("lens") if isinstance(item.get("lens"), str) else None,
                "check_binding_id": item.get("check_binding_id")
                if isinstance(item.get("check_binding_id"), str)
                else None,
            }
        )
    return normalized


def _git_blob_matches(raw: bytes, object_id: str, object_format: str) -> bool:
    if object_format not in {"sha1", "sha256"}:
        return False
    if len(object_id) != (40 if object_format == "sha1" else 64):
        return False
    digest = hashlib.new(object_format)
    digest.update(f"blob {len(raw)}\0".encode("ascii"))
    digest.update(raw)
    return digest.hexdigest() == object_id


def _rules(
    profile: Mapping[str, Any],
    evidence: Mapping[str, Any],
    obligations: Sequence[Mapping[str, Any]],
    snapshot_id: str,
    base_sha: str,
) -> list[dict[str, Any]]:
    rules = profile.get("policy_applicability_rules", [])
    if not isinstance(rules, list):
        raise PolicyInventoryError("policy_applicability_rules_invalid")
    known_obligations = {item["obligation_id"] for item in obligations}
    valid: list[dict[str, Any]] = []
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        if rule.get("reviewed") is not True:
            continue
        if not isinstance(rule.get("rule_id"), str) or not rule["rule_id"]:
            continue
        if not isinstance(rule.get("rule_version"), str) or not rule["rule_version"]:
            continue
        if rule.get("state") not in {"APPLICABLE", "NOT_APPLICABLE"}:
            continue
        if rule.get("obligation_id") not in known_obligations:
            continue
        if not isinstance(rule.get("source_path"), str) or not rule["source_path"]:
            continue
        source_oid = rule.get("source_git_object_id")
        if not isinstance(source_oid, str) or not _OBJECT_ID.fullmatch(source_oid):
            continue
        source_revision = rule.get("source_revision")
        if not isinstance(source_revision, str) or not _OBJECT_ID.fullmatch(source_revision):
            continue
        if not isinstance(rule.get("clause_bytes_sha256"), str):
            continue
        basis_oids = rule.get("basis_git_object_ids")
        if (
            not isinstance(basis_oids, list)
            or not basis_oids
            or any(not isinstance(oid, str) or not _OBJECT_ID.fullmatch(oid) for oid in basis_oids)
        ):
            continue
        basis_ids: list[str] = []
        for object_id in sorted(set(basis_oids)):
            candidates = sorted(
                key
                for key, item in evidence.items()
                if isinstance(key, str)
                and isinstance(item, Mapping)
                and item.get("evidence_id") == key
                and item.get("snapshot_id") == snapshot_id
                and item.get("source_revision") == base_sha
                and item.get("source_object_id") == object_id
            )
            if not candidates:
                break
            basis_ids.append(candidates[0])
        if len(basis_ids) != len(set(basis_oids)):
            continue
        valid.append({**rule, "_basis_evidence_ids": basis_ids})
    return valid


def build_policy_inventory(
    snapshot: Mapping[str, Any],
    profile: Mapping[str, Any],
    obligations: Sequence[Mapping[str, Any]],
    limits: Mapping[str, Any],
) -> dict[str, Any]:
    """Create a revision-bound, lossless policy inventory and total trace.

    The only source of policy authority is a content-addressed snapshot record
    whose path matches the snapshot-bound trusted profile's explicit allowlist.
    Repository evidence, regardless of its self-reported ``trust`` field, is
    never promoted to policy.
    """
    if not isinstance(snapshot, Mapping) or not isinstance(profile, Mapping) or not isinstance(limits, Mapping):
        raise PolicyInventoryError("input_mapping_invalid")
    bounded = _limits(limits)
    _validate_identity(snapshot, profile, bounded["max_nodes"])
    normalized_obligations = _normalize_obligations(obligations, bounded["max_nodes"])
    evidence = snapshot.get("evidence")
    refs = snapshot.get("trusted_context_refs")
    if not isinstance(evidence, Mapping) or not isinstance(refs, list):
        raise PolicyInventoryError("snapshot_evidence_invalid")
    trusted_patterns = _trusted_patterns(profile)
    candidates: list[dict[str, Any]] = []
    gaps: list[dict[str, Any]] = []
    for evidence_id in refs:
        item = evidence.get(evidence_id) if isinstance(evidence_id, str) else None
        if not isinstance(item, Mapping):
            gaps.append({"reason": "trusted_context_record_missing", "source_evidence_id": evidence_id})
            continue
        if item.get("evidence_id") != evidence_id:
            gaps.append({"reason": "evidence_map_key_mismatch", "source_evidence_id": evidence_id})
            continue
        path = item.get("path")
        # trusted_context_refs include ordinary repository evidence. The
        # profile's exact policy path binding is independently mandatory.
        if not isinstance(path, str) or not any(fnmatch.fnmatchcase(path, pattern) for pattern in trusted_patterns):
            continue
        candidates.append(dict(item))
    candidates.sort(key=lambda item: (str(item.get("path", "")), str(item.get("evidence_id", ""))))
    if len(candidates) > bounded["max_sources"]:
        gaps.append({"reason": "source_count_limit_exceeded", "expected_sources": len(candidates)})
        candidates = candidates[: bounded["max_sources"]]

    policy_sources: list[dict[str, Any]] = []
    clauses: list[dict[str, Any]] = []
    source_clause_pairs: list[tuple[dict[str, Any], dict[str, Any]]] = []
    input_bytes = 0
    for item in candidates:
        evidence_id = item.get("evidence_id")
        path = item.get("path")
        source_kind = item.get("source_kind")
        source_rev = item.get("source_revision")
        source_oid = item.get("source_object_id")
        object_format = item.get("source_object_format")
        source_size = item.get("source_object_size_bytes", item.get("captured_bytes"))
        if (
            not isinstance(evidence_id, str)
            or evidence_id not in refs
            or item.get("snapshot_id") != snapshot.get("snapshot_id")
            or not isinstance(source_kind, str)
            or source_kind not in _SOURCE_KINDS
            or item.get("trust") != "trusted_policy"
            or source_rev != snapshot.get("base_sha")
            or not isinstance(source_oid, str)
            or not _OBJECT_ID.fullmatch(source_oid)
            or not isinstance(object_format, str)
            or object_format not in {"sha1", "sha256"}
            or len(source_oid) != (40 if object_format == "sha1" else 64)
            or isinstance(source_size, bool)
            or not isinstance(source_size, int)
            or source_size < 0
        ):
            gaps.append({"reason": "source_provenance_invalid", "source_evidence_id": evidence_id, "path": path})
            continue
        remaining = bounded["max_input_bytes"] - input_bytes
        if remaining <= 0:
            gaps.append(
                {"reason": "aggregate_input_byte_limit_exceeded", "source_evidence_id": evidence_id, "path": path}
            )
            continue
        raw, source_gap = _source_bytes(item, remaining)
        if source_gap:
            gaps.append({"reason": source_gap, "source_evidence_id": evidence_id, "path": path})
            continue
        assert raw is not None
        input_bytes += len(raw)
        if source_size != len(raw):
            gaps.append({"reason": "source_size_mismatch", "source_evidence_id": evidence_id, "path": path})
            continue
        if not _git_blob_matches(raw, source_oid, object_format):
            gaps.append({"reason": "source_git_object_mismatch", "source_evidence_id": evidence_id, "path": path})
            continue
        try:
            raw.decode("utf-8", "strict")
        except UnicodeDecodeError:
            gaps.append({"reason": "source_encoding_unsupported", "source_evidence_id": evidence_id, "path": path})
            continue

        source = {
            "source_id": evidence_id,
            "evidence_id": evidence_id,
            "path": path,
            "source_kind": source_kind,
            "trust_class": "trusted_policy",
            "source_side": "BASE",
            "source_revision": source_rev,
            "git_object_format": object_format,
            "git_object_id": source_oid,
            "source_byte_length": len(raw),
            "full_source_sha256": _sha256(raw),
            "extractor_id": _EXTRACTOR_ID,
            "extractor_status": "COMPLETE",
        }
        if len(policy_sources) + len(clauses) + len(normalized_obligations) + 1 > bounded["max_nodes"]:
            gaps.append({"reason": "output_node_limit_exceeded", "source_evidence_id": evidence_id, "path": path})
            continue
        policy_sources.append(source)
        source_spans = _segments(raw, bounded["max_clauses"] - len(clauses))
        if len(clauses) + len(source_spans) > bounded["max_clauses"]:
            source_spans = [(0, len(raw), "whole_blob")]
        if len(clauses) + len(source_spans) > bounded["max_clauses"]:
            policy_sources.pop()
            gaps.append({"reason": "clause_count_limit_exceeded", "source_evidence_id": evidence_id, "path": path})
            continue
        for start, end, extract_kind in source_spans:
            clause_raw = raw[start:end]
            line_start, line_end = _line_range(raw, start, end)
            clause_hash = _sha256(clause_raw)
            clause_id = (
                "clause-"
                + _sha256(
                    _canonical_bytes(
                        {
                            "source_evidence_id": evidence_id,
                            "source_revision": source_rev,
                            "source_object_id": source_oid,
                            "start": start,
                            "end": end,
                            "sha256": clause_hash,
                        }
                    )
                )[:24]
            )
            clause = {
                "clause_id": clause_id,
                "source_id": evidence_id,
                "source_evidence_id": evidence_id,
                "path": path,
                "source_kind": source_kind,
                "source_revision": source_rev,
                "source_object_id": source_oid,
                "extract_kind": extract_kind,
                "byte_range": {"start_inclusive": start, "end_exclusive": end},
                "line_range": {"start_inclusive": line_start, "end_inclusive": line_end},
                "byte_length": len(clause_raw),
                "clause_bytes_sha256": clause_hash,
                "content": clause_raw.decode("utf-8", "strict"),
                "extraction_status": "EXTRACTED",
            }
            if len(policy_sources) + len(clauses) + len(normalized_obligations) + 1 > bounded["max_nodes"]:
                policy_sources.pop()
                clauses = [clause for clause in clauses if clause["source_id"] != evidence_id]
                source_clause_pairs = [pair for pair in source_clause_pairs if pair[0]["source_id"] != evidence_id]
                gaps.append({"reason": "output_node_limit_exceeded", "source_evidence_id": evidence_id, "path": path})
                break
            clauses.append(clause)
            source_clause_pairs.append((source, clause))

    # A missing source that the trusted profile explicitly names is a typed
    # gap, even if no snapshot evidence record exists to identify its object.
    captured_paths = {source["path"] for source in policy_sources}
    for pattern in trusted_patterns:
        if not any(char in pattern for char in "*?[") and pattern not in captured_paths:
            gaps.append({"reason": "trusted_policy_source_not_captured", "path": pattern})
        elif any(char in pattern for char in "*?["):
            gaps.append({"reason": "trusted_policy_pattern_source_coverage_unresolved", "pattern": pattern})
    for gap in snapshot.get("gaps", []) if isinstance(snapshot.get("gaps"), list) else []:
        if isinstance(gap, dict) and isinstance(gap.get("path"), str):
            path = gap["path"]
            if any(fnmatch.fnmatchcase(path, pattern) for pattern in trusted_patterns) and path not in captured_paths:
                gaps.append(
                    {
                        "reason": "trusted_policy_source_capture_gap",
                        "path": path,
                        "snapshot_gap_reason": gap.get("reason"),
                    }
                )

    rules = _rules(
        profile, evidence, normalized_obligations, str(snapshot.get("snapshot_id")), str(snapshot.get("base_sha"))
    )
    expected_rows = len(source_clause_pairs) * len(normalized_obligations)
    trace: list[dict[str, Any]] = []
    trace_bytes = 0
    trace_complete = True
    if expected_rows > bounded["max_trace_rows"]:
        trace_complete = False
        gaps.append({"reason": "trace_row_limit_exceeded", "expected_trace_rows": expected_rows})
    else:
        for source, clause in source_clause_pairs:
            for obligation in normalized_obligations:
                matches = [
                    rule
                    for rule in rules
                    if rule.get("source_path") == source["path"]
                    and rule.get("source_git_object_id") == source["git_object_id"]
                    and rule.get("source_revision") == source["source_revision"]
                    and rule.get("clause_bytes_sha256") == clause["clause_bytes_sha256"]
                    and rule.get("obligation_id") == obligation["obligation_id"]
                ]
                row = {
                    "obligation_id": obligation["obligation_id"],
                    "clause_id": clause["clause_id"],
                    "state": "UNRESOLVED",
                    "rule_id": None,
                    "rule_version": None,
                    "basis_evidence_ids": [],
                    "reason_code": "no_reviewed_deterministic_rule",
                }
                if len(matches) == 1:
                    rule = matches[0]
                    row.update(
                        {
                            "state": rule["state"],
                            "rule_id": rule["rule_id"],
                            "rule_version": rule["rule_version"],
                            "basis_evidence_ids": rule["_basis_evidence_ids"],
                            "reason_code": "reviewed_deterministic_rule",
                        }
                    )
                elif len(matches) > 1:
                    row["reason_code"] = "multiple_matching_rules"
                encoded_size = len(_canonical_bytes(row))
                total_nodes = len(policy_sources) + len(clauses) + len(normalized_obligations) + len(trace) + 1
                if total_nodes > bounded["max_nodes"] or trace_bytes + encoded_size > bounded["max_trace_bytes"]:
                    trace_complete = False
                    gaps.append({"reason": "trace_output_limit_exceeded", "expected_trace_rows": expected_rows})
                    break
                trace.append(row)
                trace_bytes += encoded_size
            if not trace_complete:
                break

    if gaps:
        trace_complete = False
    state_counts = {
        state: sum(row["state"] == state for row in trace) for state in ("APPLICABLE", "NOT_APPLICABLE", "UNRESOLVED")
    }
    applicability_complete = (
        trace_complete and not gaps and state_counts["UNRESOLVED"] == 0 and len(trace) == expected_rows
    )
    return {
        "schema_version": "context-policy-inventory.v1",
        "status": "COMPLETE" if trace_complete and not gaps else "GAP",
        "identity": {
            "repository": snapshot.get("repository"),
            "snapshot_id": snapshot.get("snapshot_id"),
            "snapshot_sha256": snapshot.get("snapshot_hash"),
            "profile_version": snapshot.get("profile_version"),
            "profile_sha256": snapshot.get("profile_hash"),
            "base_sha": snapshot.get("base_sha"),
            "head_sha": snapshot.get("head_sha"),
            "extractor_id": _EXTRACTOR_ID,
        },
        "obligations": normalized_obligations,
        "policy_sources": policy_sources,
        "clauses": clauses,
        "applicability_trace": trace,
        "trace_summary": {
            "expected_rows": expected_rows,
            "emitted_rows": len(trace),
            "complete": trace_complete and len(trace) == expected_rows and not gaps,
            "applicability_complete": applicability_complete,
            "state_counts": state_counts,
        },
        "limits": bounded,
        "gaps": gaps,
    }
