"""Resolve exact Markdown policy sections from validated immutable evidence.

This opt-in primitive selects bytes only. It does not decide applicability,
authorize omission, or change planner/engine behavior. Callers must retain the
full source whenever the result requests a full-source fallback.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from typing import Any

from .policy_inventory import PolicyInventoryError, build_policy_inventory


class ContextSelectionError(ValueError):
    """The source binding, selector, or finite limits are invalid."""


_SELECTOR_VERSION = "policy-section-selector.v1"
_PARSER_ID = "markdown-atx-fenced-v1"
_MAX_SECTION_BYTES = 2_000_000
_MAX_SOURCE_BYTES = 2_000_000
_MAX_HEADINGS = 20_000
_MAX_HEADING_PATH_DEPTH = 6
_MAX_HEADING_PATH_CHARS = 2_048
_MAX_HEADING_CHARS = 512
_MAX_OCCURRENCE = 1_000
_ATX = re.compile(rb"^( {0,3})(#{1,6})(?:[ \t]+|$)(.*?)[ \t]*\r?\n?$")
_FENCE = re.compile(rb"^ {0,3}(`{3,}|~{3,})(.*?)(?:\r?\n)?$")
_SETEXT = re.compile(rb"^ {0,3}(?:=+|-+)[ \t]*\r?\n?$")
_HTML_BLOCK = re.compile(
    rb"<(?:!--|/?(?:address|article|aside|base|blockquote|body|caption|center|col|dd|details|dialog|dir|div|dl|dt|fieldset|figcaption|figure|footer|form|frame|frameset|h[1-6]|head|header|hr|html|iframe|legend|li|link|main|menu|menuitem|nav|ol|optgroup|option|p|param|search|section|summary|table|tbody|td|tfoot|th|thead|title|tr|track|ul)\b)",
    re.IGNORECASE,
)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_hash(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    return _sha256(encoded)


def _selection_limits(limits: Mapping[str, Any]) -> dict[str, int]:
    defaults = {
        "max_source_bytes": _MAX_SOURCE_BYTES,
        "max_section_bytes": _MAX_SECTION_BYTES,
        "max_headings": _MAX_HEADINGS,
    }
    output: dict[str, int] = {}
    hard_caps = {
        "max_source_bytes": _MAX_SOURCE_BYTES,
        "max_section_bytes": _MAX_SECTION_BYTES,
        "max_headings": _MAX_HEADINGS,
    }
    for name, default in defaults.items():
        value = limits.get(name, default)
        if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= hard_caps[name]:
            raise ContextSelectionError(f"{name}_invalid")
        output[name] = value
    return output


def _parse_selector(selector: Mapping[str, Any]) -> tuple[tuple[str, ...], int, bool, str]:
    if selector.get("schema_version") != _SELECTOR_VERSION:
        raise ContextSelectionError("selector_version_unsupported")
    path = selector.get("heading_path")
    occurrence = selector.get("occurrence")
    include_subsections = selector.get("include_subsections", True)
    if (
        not isinstance(path, list)
        or not path
        or len(path) > _MAX_HEADING_PATH_DEPTH
        or any(not isinstance(part, str) or not part.strip() or "\n" in part or "\r" in part for part in path)
        or any(len(part) > _MAX_HEADING_CHARS for part in path if isinstance(part, str))
        or sum(len(part) for part in path if isinstance(part, str)) > _MAX_HEADING_PATH_CHARS
    ):
        raise ContextSelectionError("heading_path_invalid")
    if isinstance(occurrence, bool) or not isinstance(occurrence, int) or not 1 <= occurrence <= _MAX_OCCURRENCE:
        raise ContextSelectionError("occurrence_invalid")
    if not isinstance(include_subsections, bool):
        raise ContextSelectionError("include_subsections_invalid")
    normalized = {
        "schema_version": _SELECTOR_VERSION,
        "heading_path": path,
        "occurrence": occurrence,
        "include_subsections": include_subsections,
    }
    return tuple(path), occurrence, include_subsections, _canonical_hash(normalized)


def _markdown_heads(raw: bytes, max_headings: int) -> tuple[list[dict[str, Any]], str | None]:
    """Parse ATX headings only; uncertainty causes a full-source fallback."""
    try:
        raw.decode("utf-8", "strict")
    except UnicodeDecodeError:
        return [], "source_encoding_unsupported"

    lines: list[tuple[int, int, bytes]] = []
    offset = 0
    while offset < len(raw):
        newline = raw.find(b"\n", offset)
        if newline < 0:
            line = raw[offset:]
            end = len(raw)
        else:
            end = newline + 1
            line = raw[offset:end]
        terminator_bytes = 2 if line.endswith(b"\r\n") else 1 if line.endswith(b"\n") else 0
        if b"\r" in line[:-terminator_bytes] if terminator_bytes else b"\r" in line:
            return [], "unsupported_line_ending"
        lines.append((offset, end, line))
        offset = end
    if raw.endswith((b"\n", b"\r\n")):
        pass
    elif raw == b"":
        return [], "source_empty"
    elif b"\r" in raw:
        return [], "unsupported_line_ending"

    headings: list[dict[str, Any]] = []
    stack: list[tuple[int, str]] = []
    fence_char: int | None = None
    fence_length = 0
    for line_no, (line_start, line_end, line) in enumerate(lines, start=1):
        body = line.rstrip(b"\r\n")
        if fence_char is not None:
            close = re.match(rb"^ {0,3}([`~]+)[ \t]*$", body)
            if (
                close
                and len(set(close.group(1))) == 1
                and close.group(1)[0] == fence_char
                and len(close.group(1)) >= fence_length
            ):
                fence_char = None
                fence_length = 0
            continue
        fence = _FENCE.match(line)
        if fence:
            marker = fence.group(1)
            # CommonMark forbids backticks in info strings for backtick fences.
            if marker[0] == ord("`") and b"`" in fence.group(2):
                continue
            fence_char = marker[0]
            fence_length = len(marker)
            continue
        if _HTML_BLOCK.search(body):
            return [], "unsupported_html_block"
        match = _ATX.match(line)
        if not match:
            if _SETEXT.match(line):
                return [], "unsupported_setext_heading"
            continue
        level = len(match.group(2))
        text = match.group(3).decode("utf-8", "strict")
        text = re.sub(r"[ \t]+#+[ \t]*$", "", text).strip()
        if not text or len(text) > _MAX_HEADING_CHARS:
            return [], "empty_heading_unsupported"
        while stack and stack[-1][0] >= level:
            stack.pop()
        stack.append((level, text))
        if len(headings) >= max_headings:
            return [], "heading_count_limit_exceeded"
        headings.append(
            {
                "level": level,
                "text": text,
                "path": tuple(value for _, value in stack),
                "start": line_start,
                "line_end_offset": line_end,
                "line": line_no,
            }
        )
        if len(headings) > max_headings:
            return [], "heading_count_limit_exceeded"
    if fence_char is not None:
        return [], "unclosed_fence_unsupported"
    return headings, None


def _line_bounds(raw: bytes, start: int, end: int) -> tuple[int, int]:
    first = raw[:start].count(b"\n") + 1
    section = raw[start:end]
    newline_count = section.count(b"\n")
    last = first + newline_count - (1 if section.endswith(b"\n") else 0)
    return first, max(first, last)


def select_policy_section(
    snapshot: Mapping[str, Any],
    profile: Mapping[str, Any],
    evidence_id: str,
    selector: Mapping[str, Any],
    limits: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Select one exact BASE policy section, or require the complete source.

    Provenance validation is delegated to ``build_policy_inventory`` so the
    selector does not maintain a second snapshot/profile trust implementation.
    The selected evidence must be in the resulting policy-source inventory,
    which independently checks the explicit trusted path binding and Git blob.
    """
    if not isinstance(snapshot, Mapping) or not isinstance(profile, Mapping):
        raise ContextSelectionError("input_mapping_invalid")
    if not isinstance(evidence_id, str) or not evidence_id:
        raise ContextSelectionError("evidence_id_invalid")
    if not isinstance(selector, Mapping):
        raise ContextSelectionError("selector_invalid")
    if limits is None:
        limits = {}
    elif not isinstance(limits, Mapping):
        raise ContextSelectionError("limits_invalid")
    bounded = _selection_limits(limits)
    heading_path, occurrence, include_subsections, selector_hash = _parse_selector(selector)

    evidence_map = snapshot.get("evidence")
    requested_record = evidence_map.get(evidence_id) if isinstance(evidence_map, Mapping) else None
    requested_path = requested_record.get("path") if isinstance(requested_record, Mapping) else None
    trusted_paths = profile.get("trusted_policy_paths", [])
    if isinstance(trusted_paths, str):
        trusted_paths = [trusted_paths]
    if (
        not isinstance(trusted_paths, list)
        or not isinstance(requested_path, str)
        or requested_path not in trusted_paths
    ):
        return {
            "schema_version": "policy-section-selection.v1",
            "status": "FULL_SOURCE_REQUIRED",
            "reason": "source_not_bound_by_exact_trusted_policy_path",
            "evidence_id": evidence_id,
            "parser_id": _PARSER_ID,
            "selector_sha256": selector_hash,
        }

    try:
        inventory = build_policy_inventory(
            snapshot,
            profile,
            [],
            {
                "max_input_bytes": _MAX_SOURCE_BYTES,
                "max_sources": 128,
                "max_nodes": 100_000,
                "max_clauses": 8192,
                "max_trace_rows": 100_000,
                "max_trace_bytes": 8_000_000,
            },
        )
    except (PolicyInventoryError, TypeError, ValueError) as exc:
        raise ContextSelectionError(f"policy_provenance_invalid:{exc}") from exc

    source = next((item for item in inventory["policy_sources"] if item.get("evidence_id") == evidence_id), None)
    if source is None:
        return {
            "schema_version": "policy-section-selection.v1",
            "status": "FULL_SOURCE_REQUIRED",
            "reason": "evidence_not_validated_as_trusted_policy",
            "evidence_id": evidence_id,
            "parser_id": _PARSER_ID,
            "selector_sha256": selector_hash,
        }
    source_gaps = [gap for gap in inventory["gaps"] if gap.get("source_evidence_id") == evidence_id]
    if source_gaps:
        return {
            "schema_version": "policy-section-selection.v1",
            "status": "FULL_SOURCE_REQUIRED",
            "reason": "source_inventory_incomplete",
            "source_gaps": source_gaps,
            "evidence_id": evidence_id,
            "parser_id": _PARSER_ID,
            "selector_sha256": selector_hash,
        }

    record = evidence_map.get(evidence_id) if isinstance(evidence_map, Mapping) else None
    content = record.get("content") if isinstance(record, Mapping) else None
    if not isinstance(content, str):
        return {
            "schema_version": "policy-section-selection.v1",
            "status": "FULL_SOURCE_REQUIRED",
            "reason": "source_content_unavailable",
            "evidence_id": evidence_id,
            "parser_id": _PARSER_ID,
            "selector_sha256": selector_hash,
        }
    raw = content.encode("utf-8", "strict")
    if len(raw) > bounded["max_source_bytes"]:
        return {
            "schema_version": "policy-section-selection.v1",
            "status": "FULL_SOURCE_REQUIRED",
            "reason": "source_byte_limit_exceeded",
            "source_byte_length": len(raw),
            "evidence_id": evidence_id,
            "parser_id": _PARSER_ID,
            "selector_sha256": selector_hash,
        }
    source_hash = _sha256(raw)
    if source_hash != source["full_source_sha256"]:
        return {
            "schema_version": "policy-section-selection.v1",
            "status": "FULL_SOURCE_REQUIRED",
            "reason": "validated_source_changed",
            "evidence_id": evidence_id,
            "parser_id": _PARSER_ID,
            "selector_sha256": selector_hash,
        }

    headings, parse_gap = _markdown_heads(raw, bounded["max_headings"])
    provenance = {
        "snapshot_id": inventory["identity"]["snapshot_id"],
        "snapshot_sha256": inventory["identity"]["snapshot_sha256"],
        "profile_version": inventory["identity"]["profile_version"],
        "profile_sha256": inventory["identity"]["profile_sha256"],
        "source_evidence_id": source["evidence_id"],
        "path": source["path"],
        "source_kind": source["source_kind"],
        "trust_class": source["trust_class"],
        "source_side": source["source_side"],
        "source_revision": source["source_revision"],
        "git_object_format": source["git_object_format"],
        "git_object_id": source["git_object_id"],
        "full_source_sha256": source["full_source_sha256"],
    }
    base_result = {
        "schema_version": "policy-section-selection.v1",
        "parser_id": _PARSER_ID,
        "selector_sha256": selector_hash,
        "provenance": provenance,
    }
    if parse_gap:
        return {**base_result, "status": "FULL_SOURCE_REQUIRED", "reason": parse_gap}

    matches = [item for item in headings if item["path"] == heading_path]
    if occurrence > len(matches):
        return {
            **base_result,
            "status": "FULL_SOURCE_REQUIRED",
            "reason": "heading_occurrence_not_found",
            "matching_occurrences": len(matches),
        }
    chosen = matches[occurrence - 1]
    end = len(raw)
    for heading in headings:
        if heading["start"] <= chosen["start"]:
            continue
        if heading["level"] <= chosen["level"] or (not include_subsections and heading["level"] > chosen["level"]):
            end = heading["start"]
            break
    selected = raw[chosen["start"] : end]
    if len(selected) > bounded["max_section_bytes"]:
        return {
            **base_result,
            "status": "FULL_SOURCE_REQUIRED",
            "reason": "section_byte_limit_exceeded",
            "section_byte_length": len(selected),
        }
    line_start, line_end = _line_bounds(raw, chosen["start"], end)
    return {
        **base_result,
        "status": "SELECTED",
        "reason": None,
        "heading_path": list(heading_path),
        "occurrence": occurrence,
        "include_subsections": include_subsections,
        "byte_range": {"start_inclusive": chosen["start"], "end_exclusive": end},
        "line_range": {"start_inclusive": line_start, "end_inclusive": line_end},
        "byte_length": len(selected),
        "selected_bytes_sha256": _sha256(selected),
        "content": selected.decode("utf-8", "strict"),
    }
