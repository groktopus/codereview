"""Deterministic retrieval plans over already-captured snapshot evidence.

Plans never re-read Git, dispatch a provider, or promote HEAD content to
policy. They enumerate changed symbols, bounded definition windows, and
referenced test paths the immutable snapshot already proves, record typed gaps
for whatever it cannot prove, and hash only those anchor fields.
"""

from __future__ import annotations

import fnmatch
import hashlib
import re
from typing import Any

from .budget import _canonical
from .evidence import _symbol_window

SCHEMA = "retrieval-plan.v1"
_DEF = re.compile(r"^[ \t]*(?:async[ \t]+)?(?:def|class)[ \t]+([A-Za-z_]\w*)\b")
_DIFF = re.compile(r"^[+-][ \t]*(?:async[ \t]+)?(?:def|class)[ \t]+([A-Za-z_]\w*)\b")
_TEST = re.compile(r"(?:^|/)(?:tests?/|test_[^/]*\.py$|[^/]*_test\.py$)")
_SOURCE, _SHA = {"base_file", "head_file", "source_window"}, re.compile(r"^[0-9a-f]{40,64}$")


class RetrievalPlanError(ValueError):
    """A captured snapshot cannot produce a trustworthy retrieval plan."""


def _lines(content: str) -> list[str]:
    lines = content.split("\n")
    return lines[:-1] if lines and lines[-1] == "" else lines


def enclosing_definition(content: str, line: int) -> tuple[str, int] | None:
    """Return the nearest preceding def/class that lexically contains ``line``."""
    lines = _lines(content)
    if not 1 <= line <= len(lines):
        return None
    changed = lines[line - 1]
    indent = len(changed) - len(changed.lstrip(" \t"))
    for index in range(line, 0, -1):
        candidate, match = lines[index - 1], _DEF.match(lines[index - 1])
        if match and (index == line or len(candidate) - len(candidate.lstrip(" \t")) < indent):
            return match.group(1), index
    return None


def derive_changed_symbols(diff: str) -> list[dict[str, str]]:
    """Extract added/removed def and class names in deterministic first-seen order."""
    symbols: dict[tuple[str, str], None] = {}
    for line in diff.splitlines():
        if match := _DIFF.match(line):
            symbols.setdefault((match.group(1), "added" if line[0] == "+" else "removed"), None)
    return [{"symbol": symbol, "change": change} for symbol, change in symbols]


def _allowlisted(profile: dict, path: str, scope_paths: set[str]) -> bool:
    patterns = profile.get("retrieval_context_patterns", profile.get("context_paths", []))
    patterns = [patterns] if isinstance(patterns, str) else patterns
    return path in scope_paths or bool(
        isinstance(patterns, list)
        and any(isinstance(pattern, str) and fnmatch.fnmatchcase(path, pattern) for pattern in patterns)
    )


def _source_rows(snapshot: dict, unit: dict, path: str) -> list[dict]:
    evidence, rows = snapshot.get("evidence", {}), []
    for evidence_id in unit.get("evidence_ids", []):
        item = evidence.get(evidence_id) if isinstance(evidence, dict) else None
        if (
            isinstance(item, dict)
            and item.get("path") == path
            and item.get("source_kind") in _SOURCE
            and isinstance(item.get("content"), str)
            and item.get("content_truncated") is False
            and isinstance(item.get("source_revision"), str)
            and _SHA.fullmatch(item["source_revision"])
        ):
            rows.append(item)
    return sorted(rows, key=lambda item: (item["source_revision"], item.get("line_start", 1), item["evidence_id"]))


def _anchor(unit_id: str, item: dict, start: int, end: int, text: str, role: str, symbol: str) -> dict:
    return {
        "unit_id": unit_id,
        "evidence_id": item["evidence_id"],
        "path": item["path"],
        "source_revision": item["source_revision"],
        "source_object_id": item.get("source_object_id"),
        "line_start": start,
        "line_end": end,
        "content_hash": hashlib.sha256(text.encode("utf-8")).hexdigest(),
        "trust": "repository_evidence",
        "role": role,
        "symbol": symbol,
    }


def _windows(
    unit_id: str, rows: list[dict], symbols: list[dict], ranges: list, cfg: tuple[int, int, int]
) -> list[dict]:
    before, after, limit = cfg
    windows = []
    for item in rows:
        offset = int(item.get("line_start", 1)) - 1
        for symbol in symbols:
            located = _symbol_window(item["content"], symbol["symbol"], limit, before, after)
            if not isinstance(located, str):
                start, end, text = located
                windows.append(
                    _anchor(unit_id, item, start + offset, end + offset, text, "changed_definition", symbol["symbol"])
                )
        for raw in ranges if isinstance(ranges, list) else []:
            if not isinstance(raw, list) or len(raw) != 2:
                continue
            found = enclosing_definition(item["content"], int(raw[0]) - offset)
            located = _symbol_window(item["content"], found[0], limit, before, after) if found else None
            if located is not None and not isinstance(located, str):
                start, end, text = located
                windows.append(
                    _anchor(unit_id, item, start + offset, end + offset, text, "enclosing_definition", found[0])
                )
    return windows


def _referenced_tests(snapshot: dict, unit: dict, names: set[str]) -> list[dict]:
    inventory, evidence, found = snapshot.get("inventory", []), snapshot.get("evidence", {}), []
    for other in inventory if isinstance(inventory, list) else []:
        path = other.get("path") if isinstance(other, dict) else None
        if not isinstance(path, str) or path == unit.get("path") or not _TEST.search(path):
            continue
        for evidence_id in other.get("evidence_ids", []):
            item = evidence.get(evidence_id) if isinstance(evidence, dict) else None
            content = item.get("content") if isinstance(item, dict) else None
            if isinstance(content, str) and any(re.search(rf"\b{re.escape(name)}\b", content) for name in names):
                found.append({"path": path, "unit_id": other.get("unit_id"), "evidence_id": evidence_id})
                break
    return sorted(found, key=lambda row: (row["path"], str(row.get("evidence_id"))))


def plan_hash(plan: dict) -> str:
    """Hash anchor fields only; volatile and observational fields are excluded."""
    return hashlib.sha256(
        _canonical({k: v for k, v in plan.items() if k not in {"plan_hash", "sufficiency"}})
    ).hexdigest()


def assess_retrieval_sufficiency(plan: dict) -> dict:
    required = [gap for gap in plan.get("gaps", []) if gap.get("severity") == "REQUIRED"]
    return {"schema": SCHEMA, "sufficient": not required, "required_gap_count": len(required)}


def build_retrieval_plan(
    snapshot: dict, profile: dict, task: dict, limits: dict, obligations: dict | None = None
) -> dict:
    """Build one bounded plan for a task from captured inventory evidence."""
    if not isinstance(snapshot, dict) or not isinstance(profile, dict) or not isinstance(task, dict):
        raise RetrievalPlanError("retrieval plan inputs must be objects")
    snapshot_id, base_sha, head_sha = (snapshot.get(key) for key in ("snapshot_id", "base_sha", "head_sha"))
    if not isinstance(snapshot_id, str) or not snapshot_id:
        raise RetrievalPlanError("snapshot identity is missing")
    if not all(isinstance(sha, str) and _SHA.fullmatch(sha) for sha in (base_sha, head_sha)):
        raise RetrievalPlanError("snapshot revision identity is invalid")
    inventory, evidence = snapshot.get("inventory"), snapshot.get("evidence", {})
    if not isinstance(inventory, list) or not isinstance(evidence, dict):
        raise RetrievalPlanError("snapshot inventory or evidence is invalid")
    task_id, obligation_ids = task.get("task_id"), task.get("obligation_ids", [task.get("obligation_id")])
    unit_ids = task.get("unit_ids", task.get("scope_unit_ids", []))
    if (
        not isinstance(task_id, str)
        or not task_id
        or not isinstance(unit_ids, list)
        or not isinstance(obligation_ids, list)
    ):
        raise RetrievalPlanError("retrieval plan task binding is invalid")
    units = [row for row in inventory if isinstance(row, dict) and row.get("unit_id") in set(unit_ids)]
    scope_paths = {row.get("path") for row in units if isinstance(row.get("path"), str)}
    window = (profile.get("context_selection") or {}).get("window") or {}
    cfg = (
        min(max(int(window.get("before_lines", limits.get("window_before_lines", 20))), 0), 200),
        min(max(int(window.get("after_lines", limits.get("window_after_lines", 20))), 0), 200),
        max(1, min(int(window.get("max_bytes", limits.get("max_window_bytes", 12_000))), 1_048_576)),
    )
    max_windows = max(1, min(int(window.get("max_windows_per_unit", 4)), 32))
    gaps, planned = [], []
    for unit in units:
        unit_id, path = unit.get("unit_id"), unit.get("path")
        if not isinstance(unit_id, str) or not isinstance(path, str) or path.startswith("/") or ".." in path.split("/"):
            gaps.append({"code": "retrieval_target_invalid", "severity": "REQUIRED", "unit_id": unit_id})
            continue
        symbols = derive_changed_symbols(unit.get("diff", "") if isinstance(unit.get("diff"), str) else "")
        applicable = [
            oid
            for oid in obligation_ids
            if isinstance(obligations, dict)
            and isinstance(obligations.get(oid), dict)
            and (not obligations[oid].get("scope_unit_ids") or unit_id in obligations[oid].get("scope_unit_ids", []))
        ]
        referenced = _referenced_tests(snapshot, unit, {item["symbol"] for item in symbols})
        allowed = [row for row in referenced if _allowlisted(profile, row["path"], set())]
        if denied := [row["path"] for row in referenced if row not in allowed]:
            gaps.append(
                {
                    "code": "referenced_test_not_allowlisted",
                    "severity": "REQUIRED",
                    "unit_id": unit_id,
                    "path": path,
                    "paths": denied,
                }
            )
        row = {
            "unit_id": unit_id,
            "path": path,
            "changed_symbols": symbols,
            "obligation_ids": applicable or list(obligation_ids),
            "windows": [],
            "referenced_test_paths": allowed,
        }
        if not _allowlisted(profile, path, scope_paths):
            gaps.append(
                {"code": "target_path_not_allowlisted", "severity": "REQUIRED", "unit_id": unit_id, "path": path}
            )
            planned.append(row)
            continue
        ordered, seen = [], set()
        for anchor in sorted(
            _windows(unit_id, _source_rows(snapshot, unit, path), symbols, unit.get("changed_lines", []), cfg),
            key=lambda item: (
                item["path"],
                item["source_revision"],
                item["line_start"],
                item["line_end"],
                item["role"],
                item["symbol"],
            ),
        ):
            key = (
                anchor["path"],
                anchor["source_revision"],
                anchor["line_start"],
                anchor["line_end"],
                anchor["content_hash"],
                anchor["role"],
                anchor["symbol"],
            )
            if key not in seen:
                seen.add(key)
                ordered.append(anchor)
        row["windows"] = ordered[:max_windows]
        if len(ordered) > max_windows:
            gaps.append(
                {
                    "code": "window_count_limit",
                    "severity": "OPTIONAL",
                    "unit_id": unit_id,
                    "path": path,
                    "omitted_windows": len(ordered) - max_windows,
                }
            )
        if symbols and not row["windows"]:
            gaps.append(
                {
                    "code": "changed_symbol_window_unavailable",
                    "severity": "REQUIRED",
                    "unit_id": unit_id,
                    "path": path,
                    "symbols": [item["symbol"] for item in symbols],
                }
            )
        planned.append(row)
    plan = {
        "schema": SCHEMA,
        "task_id": task_id,
        "snapshot_id": snapshot_id,
        "base_sha": base_sha,
        "head_sha": head_sha,
        "obligation_ids": list(obligation_ids),
        "units": planned,
        "gaps": gaps,
    }
    plan["sufficiency"] = assess_retrieval_sufficiency(plan)
    plan["plan_hash"] = plan_hash(plan)
    return plan


def record_dispatch_retrieval_plans(state: Any) -> None:
    """Build and persist pre-dispatch plans and typed gaps on the run ledger."""
    snapshot = {**state.snapshot, "evidence": state.snapshot_captured_evidence}
    plans, gaps = [], []
    for task in state.primary_tasks:
        if task.get("task_kind", "SPECIALIST_FINDINGS") == "SPECIALIST_FINDINGS":
            plan = build_retrieval_plan(snapshot, state.profile, task, state.limits, state.obligation_by_id)
            plans.append(plan)
            gaps.extend({"task_id": task.get("task_id"), **gap} for gap in plan["gaps"])
    state.retrieval_plans, state.retrieval_plan_gaps = plans, gaps
    state.retrieval_sufficient = not any(gap.get("severity") == "REQUIRED" for gap in gaps)
    state.ledger["retrieval_plans"], state.ledger["retrieval_plan_gaps"] = plans, gaps
