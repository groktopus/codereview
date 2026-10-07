"""Deterministic risk routing and scope planning for PR review snapshots."""

from __future__ import annotations

import fnmatch
import hashlib
import json
import re
from typing import Any

from .claim_reconciliation import validate_claim_reconciliation_policy
from .dependency_context import DependencyContextError, valid_projection_evidence, validate_dependency_context

_MODE_ORDER = {"LIGHT": 0, "FOCUSED": 1, "DEEP": 2}
_ALL_LENSES = ("correctness", "tests", "design", "security", "performance", "maintainability", "project_specific")
_SECURITY_TERMS = (
    "auth",
    "permission",
    "trust",
    "secret",
    "input_validation",
    "policy",
    "credential",
    "access_control",
)
_LENS_LIST_FIELDS = (
    "required_lenses",
    "default_lenses",
    "docs_lenses",
    "documentation_lenses",
    "security_lenses",
)
_POSSIBLE_CODE_EXAMPLE = re.compile(
    r"(?im)^[ \t]{0,3}(?:`{3,}|~{3,})"
    r"|^ {4,}\S"
    r"|^[ \t]*\.\.[ \t]+(?:code(?:-block)?|sourcecode|literalinclude|parsed-literal)::"
    r"|^[ \t]*<(?:pre|code)\b"
    r"|^[ \t]*(?:>>>|\$[ \t]+|PS>[ \t]+)\S"
    r"|::[ \t]*(?:\n[ \t]*\n)[ \t]+\S"
)


def validate_profile_lenses(profile: dict) -> None:
    """Reject malformed or unsupported configured review lenses.

    These fields define required review scope. Silently skipping an unknown
    value can erase obligations and make an empty plan appear complete.
    Validate every configured alias, including fields not selected by a
    particular unit route, so dormant typos cannot become active later.
    """
    allowed = set(_ALL_LENSES)

    def validate_lens_list(value: Any, field: str) -> None:
        if not isinstance(value, list):
            raise ValueError(f"profile {field} must be a list of supported lenses")
        if any(not isinstance(lens, str) or lens not in allowed for lens in value):
            raise ValueError(f"profile {field} contains an unsupported lens")

    for field in _LENS_LIST_FIELDS:
        if field in profile:
            validate_lens_list(profile[field], field)

    rules = profile.get("risk_rules", [])
    if not isinstance(rules, list):
        raise ValueError("profile risk_rules must be a list")
    for index, rule in enumerate(rules):
        if not isinstance(rule, dict):
            raise ValueError(f"profile risk_rules[{index}] must be an object")
        if "lenses" in rule:
            validate_lens_list(rule["lenses"], f"risk_rules[{index}].lenses")

    criteria = profile.get("review_criteria", {})
    if not isinstance(criteria, dict):
        raise ValueError("profile review_criteria must be an object keyed by supported lenses")
    if any(not isinstance(lens, str) or lens not in allowed for lens in criteria):
        raise ValueError("profile review_criteria contains an unsupported lens")
    if any(not isinstance(value, str) for value in criteria.values()):
        raise ValueError("profile review_criteria values must be strings")


def allow_empty_approve(profile: dict) -> bool:
    """Return the explicitly configured empty-review approval authority.

    The historical profile key is retained as an alias, but ambiguous or
    non-boolean values are rejected instead of relying on Python truthiness.
    """
    values = [profile[key] for key in ("allow_empty_approve", "allow_empty_approval") if key in profile]
    if any(not isinstance(value, bool) for value in values):
        raise ValueError("allow_empty_approve profile setting must be a boolean")
    if len(values) == 2 and values[0] is not values[1]:
        raise ValueError("allow_empty_approve profile aliases disagree")
    return values[0] if values else False


_CONTEXT_SELECTION_KEYS = {"version", "mandatory_policy_paths", "max_total_context_bytes", "window", "bindings"}
_CONTEXT_SELECTION_BINDING_V1_KEYS = {"unit_patterns", "lenses", "context_paths", "max_context_bytes"}
_CONTEXT_SELECTION_BINDING_V2_KEYS = _CONTEXT_SELECTION_BINDING_V1_KEYS | {"head_context_paths"}


def validate_context_selection(profile: dict) -> dict | None:
    """Validate the opt-in, finite context-selection profile contract."""
    selection = profile.get("context_selection")
    if selection is None:
        return None
    if not isinstance(selection, dict) or set(selection) != _CONTEXT_SELECTION_KEYS:
        raise ValueError("context_selection must match a supported version contract")
    version = selection.get("version")
    if not isinstance(version, str) or version not in {
        "context-selection.v1",
        "context-selection.v2",
        "context-selection.v3",
    }:
        raise ValueError("context_selection version is unsupported")

    def bounded_int(value: Any, name: str, low: int, high: int) -> int:
        if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
            raise ValueError(f"context_selection {name} is outside its finite bounds")
        return value

    mandatory = selection.get("mandatory_policy_paths")
    if (
        not isinstance(mandatory, list)
        or len(mandatory) > 32
        or any(not _safe_profile_path(path) for path in mandatory)
    ):
        raise ValueError("context_selection mandatory_policy_paths must be relative paths")
    if len(set(mandatory)) != len(mandatory):
        raise ValueError("context_selection mandatory policy paths must be unique")
    bounded_int(selection.get("max_total_context_bytes"), "max_total_context_bytes", 1, 1_000_000)
    window = selection.get("window")
    if not isinstance(window, dict) or set(window) != {
        "before_lines",
        "after_lines",
        "max_bytes",
        "max_windows_per_unit",
        "max_scan_bytes",
    }:
        raise ValueError("context_selection window must match the v1 window contract")
    bounded_int(window.get("before_lines"), "window.before_lines", 0, 200)
    bounded_int(window.get("after_lines"), "window.after_lines", 0, 200)
    bounded_int(window.get("max_bytes"), "window.max_bytes", 1, 32_768)
    bounded_int(window.get("max_windows_per_unit"), "window.max_windows_per_unit", 1, 32)
    bounded_int(window.get("max_scan_bytes"), "window.max_scan_bytes", 1, 16_777_216)
    bindings = selection.get("bindings")
    if not isinstance(bindings, list) or len(bindings) > 64:
        raise ValueError("context_selection bindings must be an array")
    allowed_lenses = set(_ALL_LENSES)
    context_paths = profile.get("context_paths", [])
    if isinstance(context_paths, str):
        context_paths = [context_paths]
    retrieval_paths = profile.get("retrieval_context_patterns", [])
    if isinstance(retrieval_paths, str):
        retrieval_paths = [retrieval_paths]
    if not isinstance(context_paths, list) or not isinstance(retrieval_paths, list):
        raise ValueError("context_selection requires valid trusted context allowlists")
    trusted = profile.get("trusted_policy_paths", [])
    if isinstance(trusted, str):
        trusted = [trusted]
    if not isinstance(trusted, list):
        raise ValueError("trusted_policy_paths must be a list of patterns")
    for path in mandatory:
        if not any(isinstance(pattern, str) and _matches(pattern, path) for pattern in context_paths):
            raise ValueError("mandatory policy path is outside profile context_paths")
        if not isinstance(trusted, list) or not any(
            isinstance(pattern, str) and _matches(pattern, path) for pattern in trusted
        ):
            raise ValueError("mandatory policy path is not in trusted_policy_paths")
    selected_policy_paths = set(mandatory)
    for binding in bindings:
        if isinstance(binding, dict) and isinstance(binding.get("context_paths"), list):
            selected_policy_paths.update(binding["context_paths"])
    for path in context_paths:
        if (
            _safe_profile_path(path)
            and any(isinstance(pattern, str) and _matches(pattern, path) for pattern in trusted)
            and path not in selected_policy_paths
        ):
            raise ValueError("trusted policy context must be mandatory or explicitly bound")
    for binding in bindings:
        expected_binding_keys = (
            _CONTEXT_SELECTION_BINDING_V2_KEYS
            if version in {"context-selection.v2", "context-selection.v3"}
            else _CONTEXT_SELECTION_BINDING_V1_KEYS
        )
        if not isinstance(binding, dict) or set(binding) != expected_binding_keys:
            raise ValueError("context_selection binding is invalid")
        patterns = binding.get("unit_patterns")
        lenses = binding.get("lenses")
        paths = binding.get("context_paths")
        if (
            not isinstance(patterns, list)
            or not patterns
            or len(patterns) > 32
            or any(not isinstance(item, str) or not item for item in patterns)
        ):
            raise ValueError("context_selection unit_patterns must be nonempty strings")
        if not isinstance(lenses, list) or not lenses or any(item not in allowed_lenses for item in lenses):
            raise ValueError("context_selection lenses are invalid")
        if not isinstance(paths, list) or len(paths) > 32 or any(not _safe_profile_path(path) for path in paths):
            raise ValueError("context_selection binding paths must be exact relative paths")
        if len(set(paths)) != len(paths):
            raise ValueError("context_selection binding paths must be unique")
        for path in paths:
            allowed = any(isinstance(pattern, str) and _matches(pattern, path) for pattern in context_paths)
            allowed = allowed or any(
                isinstance(pattern, str) and fnmatch.fnmatchcase(path, pattern) for pattern in retrieval_paths
            )
            if not allowed:
                raise ValueError("context_selection binding path is outside profile allowlists")
        if version in {"context-selection.v2", "context-selection.v3"}:
            head_paths = binding.get("head_context_paths")
            if (
                not isinstance(head_paths, list)
                or len(head_paths) > 32
                or any(not _safe_profile_path(path) for path in head_paths)
                or len(set(head_paths)) != len(head_paths)
            ):
                raise ValueError("context_selection head_context_paths must be unique exact relative paths")
            for path in head_paths:
                allowed = any(isinstance(pattern, str) and _matches(pattern, path) for pattern in context_paths)
                allowed = allowed or any(
                    isinstance(pattern, str) and fnmatch.fnmatchcase(path, pattern) for pattern in retrieval_paths
                )
                if not allowed:
                    raise ValueError("context_selection head context path is outside profile allowlists")
        bounded_int(binding.get("max_context_bytes"), "binding.max_context_bytes", 1, 262_144)
    return selection


def _safe_profile_path(path: Any) -> bool:
    return (
        isinstance(path, str)
        and bool(path)
        and not path.startswith("/")
        and "\\" not in path
        and ".." not in path.split("/")
        and not any(ch in path for ch in "*?[]")
    )


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _matches(pattern: str, path: str) -> bool:
    if any(ch in pattern for ch in "*?["):
        return fnmatch.fnmatchcase(path, pattern)
    return re.search(pattern, path, re.IGNORECASE) is not None


def _id(prefix: str, value: Any) -> str:
    return f"{prefix}-{hashlib.sha256(_canonical(value).encode()).hexdigest()[:16]}"


def _unit_risk(unit: dict, profile: dict) -> set[str]:
    risks: set[str] = set()
    path = unit.get("path", "")
    for mapping_key in ("risk_by_path", "unit_risks"):
        mapping = profile.get(mapping_key, {})
        if isinstance(mapping, dict):
            for pattern, vals in mapping.items():
                if _matches(pattern, path):
                    risks.update(str(x).lower() for x in ([vals] if isinstance(vals, str) else vals or []))
    declared = unit.get("risk_signals", [])
    if isinstance(declared, str):
        declared = [declared]
    risks.update(str(x).lower() for x in declared or [])
    for rule in profile.get("risk_rules", []) or []:
        if not isinstance(rule, dict):
            continue
        patterns = rule.get("patterns", [])
        if isinstance(patterns, str):
            patterns = [patterns]
        if any(_matches(p, path) for p in patterns if isinstance(p, str)):
            risks.add(str(rule.get("reason", "profile_risk_rule")).lower())
    return risks


def _is_docs_only(unit: dict, profile: dict) -> bool:
    path = str(unit.get("path", ""))
    classifications = profile.get("classifications", {})
    if isinstance(classifications, dict) and path in classifications:
        return classifications[path] == "documentation"
    if unit.get("kind") in {"documentation", "docs", "prose"}:
        return True
    path = path.lower()
    patterns = profile.get("documentation_paths", [r"(^|/)(docs?/|.*\.md$|.*\.rst$|.*\.txt$)"])
    return any(_matches(p, path) for p in patterns if isinstance(p, str))


def _complete_evidence(snapshot: dict, unit: dict, source_kind: str, path: str, revision: str) -> dict | None:
    """Return one complete, identity-bound evidence item for a document side."""
    evidence = snapshot.get("evidence", {})
    if not isinstance(evidence, dict):
        return None
    matches = [
        evidence[eid]
        for eid in unit.get("evidence_ids", [])
        if isinstance(eid, str)
        and isinstance(evidence.get(eid), dict)
        and evidence[eid].get("source_kind") == source_kind
        and evidence[eid].get("path") == path
        and evidence[eid].get("source_revision") == revision
        and evidence[eid].get("snapshot_id") == snapshot.get("snapshot_id")
    ]
    if len(matches) != 1:
        return None
    item = matches[0]
    content = item.get("content")
    if (
        not isinstance(content, str)
        or item.get("content_truncated") is not False
        or not isinstance(item.get("content_hash"), str)
        or hashlib.sha256(content.encode("utf-8")).hexdigest() != item.get("content_hash")
    ):
        return None
    if source_kind in {"base_file", "head_file"}:
        size = item.get("source_object_size_bytes")
        if isinstance(size, bool) or not isinstance(size, int) or size != len(content.encode("utf-8")):
            return None
        if not isinstance(item.get("source_object_id"), str) or not item["source_object_id"]:
            return None
    return item


def _mandatory_policy_path(path: str, profile: dict) -> bool:
    selection = profile.get("context_selection")
    mandatory = selection.get("mandatory_policy_paths", []) if isinstance(selection, dict) else []
    return isinstance(mandatory, list) and any(
        isinstance(pattern, str) and _matches(pattern, path) for pattern in mandatory
    )


def _head_context_evidence(snapshot: dict, path: str) -> list[str]:
    """Return complete, exact-path HEAD diff/window evidence selected by v2 policy.

    This indexes only source already captured by the snapshot builder. It does
    not read Git, resolve symbols, or promote PR content to policy authority.
    An incomplete matching capture invalidates the whole exact-path selection.
    """
    head_sha = snapshot.get("head_sha")
    snapshot_id = snapshot.get("snapshot_id")
    evidence = snapshot.get("evidence")
    if (
        not isinstance(head_sha, str)
        or not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", head_sha)
        or not isinstance(snapshot_id, str)
        or not isinstance(evidence, dict)
    ):
        return []
    gaps = snapshot.get("gaps", [])
    if isinstance(gaps, list) and any(
        isinstance(gap, dict)
        and gap.get("path") == path
        and gap.get("required") is True
        and (
            (gap.get("source_kind") == "diff" and gap.get("reason") == "diff_truncated")
            or (gap.get("source_kind") == "source_window" and gap.get("side") == "HEAD")
        )
        for gap in gaps
    ):
        return []

    selected: list[str] = []
    has_diff = False
    has_head_window = False
    for evidence_id, item in evidence.items():
        if not isinstance(evidence_id, str) or not isinstance(item, dict):
            continue
        source_kind = item.get("source_kind")
        if source_kind not in {"diff", "source_window"}:
            continue
        if item.get("path") != path or item.get("source_revision") != head_sha:
            continue
        if (
            item.get("evidence_id") != evidence_id
            or item.get("snapshot_id") != snapshot_id
            or item.get("trust") != "untrusted_pr_content"
            or item.get("content_truncated") is not False
            or not isinstance(item.get("content"), str)
            or not isinstance(item.get("content_hash"), str)
            or hashlib.sha256(item["content"].encode("utf-8")).hexdigest() != item["content_hash"]
        ):
            return []
        if source_kind == "diff":
            has_diff = True
        elif item.get("source_side") != "HEAD":
            return []
        else:
            has_head_window = True
            object_id = item.get("source_object_id")
            object_format = item.get("source_object_format")
            if (
                not isinstance(object_id, str)
                or object_format not in {"sha1", "sha256"}
                or len(object_id) != (40 if object_format == "sha1" else 64)
                or re.fullmatch(r"[0-9a-f]+", object_id) is None
            ):
                return []
        selected.append(evidence_id)
    return selected if has_diff and has_head_window else []


def _verified_prose_document(snapshot: dict, unit: dict) -> bool:
    """Certify only complete documentation evidence without code-example blocks.

    The bounded snapshot already limits the total evidence bytes. This scan is
    linear in the captured diff and full file blobs; uncertain or incomplete
    snapshots simply cannot take the LIGHT route.
    """
    change_type = unit.get("change_type")
    if change_type not in {"add", "delete", "modify", "rename"}:
        change_type = {
            "added": "add",
            "deleted": "delete",
            "modified": "modify",
            "renamed": "rename",
        }.get(unit.get("change"))
    path = unit.get("path")
    old_path = unit.get("old_path") or path
    base_sha = snapshot.get("change_base_sha", snapshot.get("base_sha"))
    head_sha = snapshot.get("head_sha")
    snapshot_id = snapshot.get("snapshot_id")
    if not all(isinstance(value, str) and value for value in (path, base_sha, head_sha, snapshot_id)):
        return False
    diff = _complete_evidence(snapshot, unit, "diff", path, head_sha)
    if diff is None:
        return False
    source_sides = {
        "add": (("head_file", path, head_sha),),
        "delete": (("base_file", old_path, base_sha),),
        "modify": (("base_file", old_path, base_sha), ("head_file", path, head_sha)),
        "rename": (("base_file", old_path, base_sha), ("head_file", path, head_sha)),
    }.get(change_type)
    if source_sides is None:
        return False
    items = [diff]
    for source_kind, source_path, revision in source_sides:
        item = _complete_evidence(snapshot, unit, source_kind, source_path, revision)
        if item is None:
            return False
        items.append(item)
    contents = [item["content"] for item in items[1:]]
    diff_lines = []
    for line in diff["content"].splitlines():
        if line.startswith(("+++", "---")):
            continue
        if line.startswith(("+", "-", " ")):
            line = line[1:]
        diff_lines.append(line)
    contents.append("\n".join(diff_lines))
    return not any(_POSSIBLE_CODE_EXAMPLE.search(content) for content in contents)


def plan_review(snapshot: dict, profile: dict, mode: str = "AUTO") -> dict:
    """Freeze required unit/lens/check obligations before any provider work.

    The profile is trusted input. Unknown unit type/context raises the floor to
    FOCUSED and marks policy/context uncertainty instead of silently reducing it.
    """
    if not isinstance(snapshot, dict) or not isinstance(profile, dict):
        raise ValueError("snapshot and profile must be objects")
    allow_empty_approve(profile)
    validate_profile_lenses(profile)
    validate_claim_reconciliation_policy(profile)
    context_selection = validate_context_selection(profile)
    try:
        dependency_context = validate_dependency_context(profile)
    except DependencyContextError as exc:
        raise ValueError(str(exc)) from exc
    requested = str(mode).upper()
    if requested not in {*_MODE_ORDER, "AUTO"}:
        raise ValueError("mode must be AUTO, LIGHT, FOCUSED, or DEEP")
    inventory = snapshot.get("inventory")
    if not isinstance(inventory, list):
        raise ValueError("snapshot.inventory must be an array")

    profile_valid = bool(
        profile.get("version")
        or profile.get("profile_version")
        or snapshot.get("profile_version")
        or snapshot.get("project_profile_version")
    )
    reasons: list[str] = []
    floor = str(profile.get("minimum_mode", "LIGHT")).upper()
    if floor not in _MODE_ORDER:
        floor = "FOCUSED"
        reasons.append("unknown_profile_minimum_mode")
        profile_valid = False
    if any(isinstance(gap, dict) and gap.get("required") is True for gap in snapshot.get("gaps", [])):
        floor = max((floor, "DEEP"), key=lambda x: _MODE_ORDER[x])
        reasons.append("snapshot_context_gap_raises_depth_floor")
    scopes: list[dict] = []
    tasks: list[dict] = []
    not_applicable: list[dict] = []
    risk_by_unit: dict[str, set[str]] = {}
    allowed_context_paths = profile.get("context_paths", [])
    if isinstance(allowed_context_paths, str):
        allowed_context_paths = [allowed_context_paths]
    refs = snapshot.get("trusted_context_refs", []) or []
    trusted_context_ids = []
    matched_context_ids = []
    context_ids_by_path: dict[str, list[str]] = {}
    evidence_map = snapshot.get("evidence", {}) if isinstance(snapshot.get("evidence", {}), dict) else {}
    for ref in refs:
        eid = ref.get("evidence_id") if isinstance(ref, dict) else ref
        item = evidence_map.get(eid, {}) if isinstance(eid, str) else {}
        path = item.get("path", ref.get("path") if isinstance(ref, dict) else None)
        if eid and path and any(_matches(p, str(path)) for p in allowed_context_paths if isinstance(p, str)):
            context_ids_by_path.setdefault(str(path), []).append(eid)
            matched_context_ids.append(eid)
            if item.get("trust") == "trusted_policy":
                trusted_context_ids.append(eid)
    selection_mandatory_ids = [
        eid
        for path in (context_selection or {}).get("mandatory_policy_paths", [])
        for eid in context_ids_by_path.get(path, [])
        if evidence_map.get(eid, {}).get("trust") == "trusted_policy"
    ]
    for unit in inventory:
        if not isinstance(unit, dict) or not unit.get("unit_id"):
            raise ValueError("each inventory unit requires unit_id")
        uid = str(unit["unit_id"])
        is_generated = any(
            _matches(pattern, str(unit.get("path", "")))
            for pattern in profile.get("generated_patterns", [])
            if isinstance(pattern, str)
        )
        risks = _unit_risk(unit, profile)
        if is_generated:
            risks.add("trusted_generated_path_rule")
        risk_by_unit[uid] = risks
        unit_rules = [
            r
            for r in profile.get("risk_rules", []) or []
            if isinstance(r, dict) and r.get("reason", "profile_risk_rule").lower() in risks
        ]
        docs_only = _is_docs_only(unit, profile)
        prose_only = docs_only and _verified_prose_document(snapshot, unit)
        policy_path = _mandatory_policy_path(str(unit.get("path", "")), profile)
        if (
            prose_only
            and not risks
            and not is_generated
            and not policy_path
            and unit.get("kind") not in {"unknown", "binary", "generated"}
        ):
            unit_floor, lenses = (
                "LIGHT",
                list(
                    profile.get("docs_lenses", profile.get("documentation_lenses", ["correctness", "maintainability"]))
                ),
            )
            reasons.append(f"{uid}:trusted_docs_only_route")
        elif unit.get("kind") in {"unknown", "binary", "generated"} or is_generated:
            unit_floor, lenses = (
                "DEEP",
                list(
                    profile.get("security_lenses", profile.get("required_lenses", ["correctness", "security", "tests"]))
                ),
            )
            reasons.append(f"{uid}:unknown_or_generated_provenance_deep_floor")
        elif risks.intersection(_SECURITY_TERMS):
            unit_floor, lenses = (
                "FOCUSED",
                list(
                    profile.get("security_lenses", profile.get("required_lenses", ["correctness", "security", "tests"]))
                ),
            )
            reasons.append(f"{uid}:risk_or_unknown_context_floor")
        elif docs_only:
            unit_floor = "FOCUSED"
            lenses = list(
                profile.get(
                    "required_lenses",
                    profile.get("default_lenses", ["correctness", "tests", "design", "maintainability"]),
                )
            )
            reason = (
                "docs_prose_only_unverified_focused_floor"
                if not prose_only
                else "docs_mandatory_policy_path_focused_floor"
                if policy_path
                else "docs_profile_risk_focused_floor"
            )
            reasons.append(f"{uid}:{reason}")
        else:
            unit_floor = "FOCUSED" if unit.get("kind") in {"human_code", "config", "test"} else "FOCUSED"
            lenses = list(
                profile.get(
                    "required_lenses",
                    profile.get("default_lenses", ["correctness", "tests", "design", "maintainability"]),
                )
            )
        for rule in unit_rules:
            rule_floor = str(rule.get("min_mode", "FOCUSED")).upper()
            if rule_floor in _MODE_ORDER:
                unit_floor = max((unit_floor, rule_floor), key=lambda x: _MODE_ORDER[x])
            if rule.get("lenses"):
                lenses = list(dict.fromkeys(lenses + list(rule["lenses"])))
            reasons.append(f"{uid}:{rule.get('reason', 'profile_risk_rule')}")
        floor = max((floor, unit_floor), key=lambda x: _MODE_ORDER[x])
        selected = _ALL_LENSES if requested == "DEEP" or floor == "DEEP" else lenses
        for lens in dict.fromkeys(str(x) for x in selected):
            if lens not in _ALL_LENSES:
                continue
            oid = f"unit:{uid}:lens:{lens}"
            obligation = {
                "obligation_id": oid,
                "obligation_kind": "CHANGED_UNIT_LENS",
                "required": True,
                "scope_unit_ids": [uid],
                "lens": lens,
            }
            scopes.append(obligation)
            # Repository policy/context is sourced only from the BASE tree by
            # snapshot collection and follows changed-unit evidence. The core
            # input budget drops tail context before changed diff/file evidence.
            if context_selection is None:
                unit_review_ids = list(unit.get("evidence_ids", []))
                unit_context_ids = list(matched_context_ids)
            else:
                unit_review_ids = list(unit.get("review_context_evidence_ids", unit.get("evidence_ids", [])))
                unit_context_ids = list(selection_mandatory_ids)
                unit_path = str(unit.get("path", ""))
                for binding in context_selection["bindings"]:
                    if lens not in binding["lenses"] or not any(
                        fnmatch.fnmatchcase(unit_path, pattern) for pattern in binding["unit_patterns"]
                    ):
                        continue
                    selected_bytes = 0
                    for path in binding["context_paths"]:
                        for eid in context_ids_by_path.get(path, []):
                            size = len(str(evidence_map.get(eid, {}).get("content", "")).encode("utf-8"))
                            if selected_bytes + size > binding["max_context_bytes"]:
                                continue
                            selected_bytes += size
                            unit_context_ids.append(eid)
                    if context_selection.get("version") == "context-selection.v2":
                        head_paths = binding["head_context_paths"]
                        for path in head_paths:
                            # HEAD context is opt-in, exact-path, already-captured
                            # changed evidence. It never reads or trusts a new path.
                            changed_path = any(row.get("path") == path for row in inventory)
                            if not changed_path:
                                continue
                            head_items = _head_context_evidence(snapshot, path)
                            if not head_items:
                                missing_id = _id(
                                    "missing-head-context",
                                    {
                                        "snapshot": snapshot.get("snapshot_id"),
                                        "head": snapshot.get("head_sha"),
                                        "path": path,
                                    },
                                )
                                unit_context_ids.append(missing_id)
                                continue
                            item_bytes = sum(
                                len(str(evidence_map.get(item_id, {}).get("content", "")).encode("utf-8"))
                                for item_id in head_items
                            )
                            if selected_bytes + item_bytes > binding["max_context_bytes"]:
                                missing_id = _id(
                                    "missing-head-context",
                                    {
                                        "snapshot": snapshot.get("snapshot_id"),
                                        "head": snapshot.get("head_sha"),
                                        "path": path,
                                    },
                                )
                                unit_context_ids.append(missing_id)
                                continue
                            selected_bytes += item_bytes
                            unit_context_ids.extend(head_items)
            if dependency_context:
                unit_path = str(unit.get("path", ""))
                snapshot_id = snapshot.get("snapshot_id")
                evidence_map = snapshot.get("evidence", {})
                for binding_index, binding in enumerate(dependency_context["bindings"]):
                    if lens not in binding["lenses"] or not any(
                        fnmatch.fnmatchcase(unit_path, pattern) for pattern in binding["unit_patterns"]
                    ):
                        continue
                    binding_id = "dependency-binding-" + hashlib.sha256(
                        _canonical({"index": binding_index, "binding": binding}).encode("utf-8")
                    ).hexdigest()[:16]
                    for side in binding["sides"]:
                        revision = snapshot.get(
                            "change_base_sha" if side == "BASE" and snapshot.get("comparison_mode") == "PR_MERGE_BASE"
                            else "base_sha" if side == "BASE" else "head_sha"
                        )
                        candidates = [
                            (evidence_id, item)
                            for evidence_id, item in evidence_map.items()
                            if isinstance(item, dict)
                            and item.get("dependency_binding_id") == binding_id
                            and item.get("source_side") == side
                            and item.get("path") == binding["manifest_path"]
                        ] if isinstance(evidence_map, dict) else []
                        if (
                            isinstance(snapshot_id, str)
                            and len(candidates) == 1
                            and isinstance(revision, str)
                            and valid_projection_evidence(
                                candidates[0][1],
                                evidence_id=candidates[0][0],
                                snapshot_id=snapshot_id,
                                binding_id=binding_id,
                                path=binding["manifest_path"],
                                side=side,
                                revision=revision,
                                packages=binding["packages"],
                            )
                        ):
                            unit_context_ids.append(candidates[0][0])
                        else:
                            unit_context_ids.append(
                                _id(
                                    "missing-dependency-context",
                                    {
                                        "snapshot": snapshot_id,
                                        "binding": binding_id,
                                        "side": side,
                                        "revision": revision,
                                    },
                                )
                            )
            unit_context_ids = list(dict.fromkeys(unit_context_ids))
            evidence_ids = list(dict.fromkeys(unit_review_ids + unit_context_ids))
            context_grouping = context_selection is not None or dependency_context is not None
            task = next(
                (
                    t
                    for t in tasks
                    if t.get("task_kind") == "SPECIALIST_FINDINGS"
                    and t.get("lens") == lens
                    and t.get("_group") == tuple(sorted(selected))
                    and (not context_grouping or t.get("_context_group") == tuple(sorted(unit_context_ids)))
                ),
                None,
            )
            if task is None:
                task = {
                    "task_id": _id(
                        "task",
                        {
                            "snapshot": snapshot.get("snapshot_id"),
                            "lens": lens,
                            "group": sorted(selected),
                            "context_group": sorted(unit_context_ids) if context_grouping else None,
                        },
                    ),
                    "scope_id": _id(
                        "scope",
                        {
                            "snapshot": snapshot.get("snapshot_id"),
                            "lens": lens,
                            "group": sorted(selected),
                            "context_group": sorted(unit_context_ids) if context_grouping else None,
                        },
                    ),
                    "obligation_id": oid,
                    "obligation_ids": [oid],
                    "task_kind": "SPECIALIST_FINDINGS",
                    "lens": lens,
                    "unit_ids": [uid],
                    "scope_unit_ids": [uid],
                    "evidence_ids": evidence_ids,
                    "required": True,
                    "base_context_ids": unit_context_ids,
                    "required_context_ids": unit_context_ids if context_grouping else [],
                    "review_criteria": (profile.get("review_criteria", {}) or {}).get(lens, ""),
                    "project_rules": list(profile.get("rules", []) or []),
                    "question_version": str(profile.get("question_version", "0.1")),
                    "_group": tuple(sorted(selected)),
                    "_context_group": tuple(sorted(unit_context_ids)) if context_grouping else None,
                }
                tasks.append(task)
            else:
                task["unit_ids"].append(uid)
                task["scope_unit_ids"].append(uid)
                task["evidence_ids"] = list(dict.fromkeys(task["evidence_ids"] + evidence_ids))
                task["base_context_ids"] = list(dict.fromkeys(task.get("base_context_ids", []) + unit_context_ids))
                if context_grouping:
                    task["required_context_ids"] = list(
                        dict.fromkeys(task.get("required_context_ids", []) + unit_context_ids)
                    )
                task["obligation_ids"].append(oid)

    for check in profile.get("required_checks", []) or []:
        if not isinstance(check, dict) or not (check.get("id") or check.get("check_id")):
            reasons.append("invalid_required_check_binding")
            profile_valid = False
            continue
        check_id = check.get("id", check.get("check_id"))
        oid = f"check:{check_id}"
        units = list(check.get("unit_ids", []))
        if not units and check.get("patterns"):
            units = [
                u.get("unit_id")
                for u in inventory
                if any(_matches(p, str(u.get("path", ""))) for p in check["patterns"] if isinstance(p, str))
            ]
            if not units:
                not_applicable.append(
                    {
                        "obligation_id": f"check:{check_id}",
                        "obligation_kind": "PROJECT_CHECK",
                        "reason": "configured_path_patterns_did_not_match",
                        "profile_rationale": check.get("reason"),
                        "state": "NOT_APPLICABLE",
                    }
                )
                continue
        scopes.append(
            {
                "obligation_id": oid,
                "obligation_kind": "PROJECT_CHECK",
                "required": True,
                "scope_unit_ids": units,
                "check_binding_id": check.get("binding", check.get("binding_id", check_id)),
                "reason": check.get("reason"),
            }
        )
        tasks.append(
            {
                "task_id": _id("task", {"snapshot": snapshot.get("snapshot_id"), "obligation": oid}),
                "scope_id": _id("scope", {"obligation": oid}),
                "obligation_id": oid,
                "task_kind": "DETERMINISTIC_CHECK",
                "lens": "project_specific",
                "unit_ids": units,
                "scope_unit_ids": units,
                "evidence_ids": list(check.get("evidence_ids", [])),
                "required": True,
                "check_binding_id": check.get("binding", check.get("binding_id", check_id)),
                "check_id": check_id,
                "question_version": "1",
            }
        )

    for index, gap in enumerate(snapshot.get("gaps", []) or []):
        if isinstance(gap, dict) and gap.get("required") is True:
            oid = f"context:{gap.get('gap_id', index)}"
            scopes.append(
                {
                    "obligation_id": oid,
                    "obligation_kind": "REQUIRED_CONTEXT",
                    "required": True,
                    "scope_unit_ids": list(gap.get("unit_ids", [])),
                    "reason": gap.get("reason", "required_context_missing"),
                }
            )

    selected_mode = (
        "FOCUSED"
        if requested == "AUTO"
        and floor == "LIGHT"
        and any(u.get("kind") in {"human_code", "config", "test", "unknown", "binary", "generated"} for u in inventory)
        else (floor if requested == "AUTO" else requested)
    )
    if selected_mode in _MODE_ORDER and _MODE_ORDER[selected_mode] < _MODE_ORDER[floor]:
        reasons.append(f"requested_{selected_mode.lower()}_raised_to_{floor.lower()}")
        selected_mode = floor
    if not profile_valid:
        reasons.append("trusted_profile_version_missing_or_invalid")
    return {
        "plan_version": "0.1",
        "snapshot_id": snapshot.get("snapshot_id"),
        "profile_version": profile.get(
            "version",
            profile.get("profile_version", snapshot.get("profile_version", snapshot.get("project_profile_version"))),
        ),
        "requested_mode": requested,
        "mode": selected_mode,
        "risk_floor": floor,
        "routing_reasons": list(dict.fromkeys(reasons)),
        "policy_valid": profile_valid,
        "risk_by_unit": {k: sorted(v) for k, v in risk_by_unit.items()},
        "coverage_obligations": scopes,
        "not_applicable": not_applicable,
        "tasks": tasks,
    }
