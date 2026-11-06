"""Deterministic retrieval plans over already-captured snapshot evidence."""

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
_ROLE_PRIORITY = {"changed_definition": 0, "enclosing_definition": 1}
_ANCHOR_FIELDS = ("schema", "task_id", "snapshot_id", "base_sha", "head_sha", "obligation_ids", "units")


class RetrievalPlanError(ValueError):
    pass


def enclosing_definition(content: str, line: int) -> tuple[str, int] | None:
    lines = content.split("\n")
    lines = lines[:-1] if lines and lines[-1] == "" else lines
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
    symbols: dict[tuple[str, str], None] = {}
    for line in diff.splitlines():
        if match := _DIFF.match(line):
            symbols.setdefault((match.group(1), "added" if line[0] == "+" else "removed"), None)
    return [{"symbol": symbol, "change": change} for symbol, change in symbols]


def _gap(code: str, severity: str, **fields: Any) -> dict:
    return {"code": code, "severity": severity, **fields}


def _allowlisted(profile: dict, path: str, scope_paths: set[str]) -> bool:
    patterns = profile.get("retrieval_context_patterns", profile.get("context_paths", []))
    patterns = [patterns] if isinstance(patterns, str) else patterns
    return path in scope_paths or bool(
        isinstance(patterns, list)
        and any(isinstance(pattern, str) and fnmatch.fnmatchcase(path, pattern) for pattern in patterns)
    )


def _source_rows(snapshot: dict, unit: dict, path: str) -> list[tuple[dict, str]]:
    evidence, rows = snapshot.get("evidence", {}), []
    base_path = unit.get("old_path") or path
    for evidence_id in unit.get("evidence_ids", []):
        item = evidence.get(evidence_id) if isinstance(evidence, dict) else None
        if not isinstance(item, dict) or item.get("source_kind") not in _SOURCE:
            continue
        side = item.get("source_side")
        side = side if side in {"BASE", "HEAD"} else "BASE" if item.get("source_kind") == "base_file" else "HEAD"
        if item.get("path") != (base_path if side == "BASE" else path):
            continue
        if (
            not isinstance(item.get("content"), str)
            or item.get("content_truncated") is not False
            or not isinstance(item.get("source_revision"), str)
            or not _SHA.fullmatch(item["source_revision"])
        ):
            continue
        rows.append((item, side))
    return sorted(rows, key=lambda row: (row[0]["source_revision"], row[0].get("line_start", 1), row[0]["evidence_id"]))


def _anchor(item: dict, side: str, start: int, end: int, text: str, role: str, symbol: str) -> dict:
    return {
        "path": item["path"],
        "source_revision": item["source_revision"],
        "source_object_id": item.get("source_object_id"),
        "source_side": side,
        "line_start": start,
        "line_end": end,
        "content_hash": hashlib.sha256(text.encode("utf-8")).hexdigest(),
        "roles": [role],
        "symbols": [symbol],
    }


def _windows(
    rows: list[tuple[dict, str]], symbols: list[dict], changed: list, old: list, cfg: tuple[int, int, int]
) -> list[dict]:
    before, after, limit = cfg
    windows = []
    for item, side in rows:
        offset = int(item.get("line_start", 1)) - 1
        ranges = old if side == "BASE" else changed
        for symbol in symbols:
            if side != ("BASE" if symbol["change"] == "removed" else "HEAD"):
                continue
            located = _symbol_window(item["content"], symbol["symbol"], limit, before, after)
            if not isinstance(located, str):
                start, end, text = located
                windows.append(
                    _anchor(item, side, start + offset, end + offset, text, "changed_definition", symbol["symbol"])
                )
        for raw in ranges if isinstance(ranges, list) else []:
            if not isinstance(raw, list) or len(raw) != 2:
                continue
            found = enclosing_definition(item["content"], int(raw[0]) - offset)
            located = _symbol_window(item["content"], found[0], limit, before, after) if found else None
            if located is not None and not isinstance(located, str):
                start, end, text = located
                windows.append(
                    _anchor(item, side, start + offset, end + offset, text, "enclosing_definition", found[0])
                )
    return windows


def _anchor_key(anchor: dict) -> tuple:
    role = _ROLE_PRIORITY.get(anchor["roles"][0], len(_ROLE_PRIORITY))
    return (anchor["source_side"] != "HEAD", role) + tuple(
        anchor[key] for key in ("path", "source_revision", "line_start", "line_end", "content_hash")
    )


def _merged(windows: list[dict]) -> list[dict]:
    merged: dict[tuple, dict] = {}
    for anchor in sorted(windows, key=_anchor_key):
        key = (
            anchor["path"],
            anchor["source_revision"],
            anchor["line_start"],
            anchor["line_end"],
            anchor["content_hash"],
        )
        prior = merged.get(key)
        if prior is None:
            merged[key] = anchor
            continue
        prior["roles"] = list(dict.fromkeys(prior["roles"] + anchor["roles"]))
        prior["symbols"] = list(dict.fromkeys(prior["symbols"] + anchor["symbols"]))
    return sorted(merged.values(), key=_anchor_key)


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


def _snapshot_gaps(snapshot: dict, unit_ids: set[str], paths: set[str]) -> list[dict]:
    raw = snapshot.get("gaps")
    if not isinstance(raw, list):
        return []
    return [
        _gap("snapshot_gap_required", "REQUIRED", reason=gap.get("reason"), path=gap.get("path"))
        for gap in raw
        if isinstance(gap, dict)
        and gap.get("required") is True
        and ((set(gap["unit_ids"]) & unit_ids) if gap.get("unit_ids") else gap.get("path") in paths)
    ]


def plan_hash(plan: dict) -> str:
    return hashlib.sha256(_canonical({key: plan.get(key) for key in _ANCHOR_FIELDS})).hexdigest()


def assess_retrieval_sufficiency(plan: dict) -> dict:
    required = [gap for gap in plan.get("gaps", []) if gap.get("severity") == "REQUIRED"]
    return {"schema": SCHEMA, "sufficient": not required, "required_gap_count": len(required)}


def build_retrieval_plan(snapshot: dict, profile: dict, task: dict, limits: dict) -> dict:
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
    if not isinstance(task_id, str) or not task_id or not all(isinstance(x, list) for x in (unit_ids, obligation_ids)):
        raise RetrievalPlanError("retrieval plan task binding is invalid")
    units = [row for row in inventory if isinstance(row, dict) and row.get("unit_id") in set(unit_ids)]
    scope_paths = {row.get("path") for row in units if isinstance(row.get("path"), str)}
    scope_paths |= {row.get("old_path") for row in units if isinstance(row.get("old_path"), str)}
    gaps = _snapshot_gaps(snapshot, {row.get("unit_id") for row in units}, scope_paths)
    window = (profile.get("context_selection") or {}).get("window") or {}
    cfg = (
        min(max(int(window.get("before_lines", limits.get("window_before_lines", 20))), 0), 200),
        min(max(int(window.get("after_lines", limits.get("window_after_lines", 20))), 0), 200),
        max(1, min(int(window.get("max_bytes", limits.get("max_window_bytes", 12_000))), 1_048_576)),
    )
    max_windows = max(1, min(int(window.get("max_windows_per_unit", 4)), 32))
    planned = []
    for unit in units:
        uid, path = unit.get("unit_id"), unit.get("path")
        if not isinstance(uid, str) or not isinstance(path, str) or path.startswith("/") or ".." in path.split("/"):
            gaps.append(_gap("retrieval_target_invalid", "REQUIRED", unit_id=uid))
            continue
        diff = unit.get("diff") if isinstance(unit.get("diff"), str) else ""
        symbols = derive_changed_symbols(diff)
        tests = _referenced_tests(snapshot, unit, {item["symbol"] for item in symbols})
        allowed = [row for row in tests if _allowlisted(profile, row["path"], set())]
        if denied := [row["path"] for row in tests if row not in allowed]:
            gaps.append(_gap("referenced_test_not_allowlisted", "REQUIRED", unit_id=uid, path=path, paths=denied))
        row = dict(
            unit_id=uid,
            path=path,
            changed_symbols=symbols,
            obligation_ids=list(obligation_ids),
            windows=[],
            referenced_test_paths=allowed,
        )
        if not diff.strip():
            gaps.append(_gap("diff_unavailable", "REQUIRED", unit_id=uid, path=path))
        elif any(
            evidence.get(evidence_id, {}).get("content_truncated") is True
            for evidence_id in unit.get("evidence_ids", [])
            if isinstance(evidence.get(evidence_id), dict) and evidence[evidence_id].get("source_kind") == "diff"
        ):
            gaps.append(_gap("diff_truncated", "REQUIRED", unit_id=uid, path=path))
        if not _allowlisted(profile, path, scope_paths):
            gaps.append(_gap("target_path_not_allowlisted", "REQUIRED", unit_id=uid, path=path))
            planned.append(row)
            continue
        ordered = _merged(
            _windows(
                _source_rows(snapshot, unit, path),
                symbols,
                unit.get("changed_lines", []),
                unit.get("old_line_ranges", []),
                cfg,
            )
        )
        row["windows"] = ordered[:max_windows]
        dropped = ordered[max_windows:]
        if dropped:
            head = [anchor for anchor in dropped if anchor["source_side"] == "HEAD"]
            gaps.append(
                _gap(
                    "window_count_limit",
                    "REQUIRED" if head else "OPTIONAL",
                    unit_id=uid,
                    path=path,
                    dropped_windows=len(dropped),
                    dropped_head_windows=len(head),
                )
            )
        for sym in symbols:
            side = "BASE" if sym["change"] == "removed" else "HEAD"
            if not any(
                sym["symbol"] in anchor["symbols"]
                and "changed_definition" in anchor["roles"]
                and anchor["source_side"] == side
                for anchor in row["windows"]
            ):
                gaps.append(
                    _gap(
                        "changed_symbol_window_unavailable",
                        "REQUIRED",
                        unit_id=uid,
                        path=path,
                        symbol=sym["symbol"],
                        change=sym["change"],
                    )
                )
        change = unit.get("change", unit.get("change_type"))
        changed_lines = unit.get("changed_lines")
        has_positive_head_line = isinstance(changed_lines, list) and any(
            isinstance(item, list) and len(item) == 2 and item != [0, 0] for item in changed_lines
        )
        if (
            change not in {"delete", "deleted"}
            and has_positive_head_line
            and not any(anchor["source_side"] == "HEAD" for anchor in row["windows"])
        ):
            gaps.append(_gap("current_side_window_unavailable", "REQUIRED", unit_id=uid, path=path))
        planned.append(row)
    plan = {"schema": SCHEMA, "task_id": task_id, "snapshot_id": snapshot_id}
    plan.update(base_sha=base_sha, head_sha=head_sha, obligation_ids=list(obligation_ids), units=planned, gaps=gaps)
    plan["sufficiency"] = assess_retrieval_sufficiency(plan)
    plan["plan_hash"] = plan_hash(plan)
    return plan


def record_dispatch_retrieval_plans(state: Any) -> None:
    snapshot = {**state.snapshot, "evidence": state.snapshot_captured_evidence}
    plans = [
        build_retrieval_plan(snapshot, state.profile, task, state.limits)
        for task in state.primary_tasks
        if task.get("task_kind", "SPECIALIST_FINDINGS") == "SPECIALIST_FINDINGS"
    ]
    gaps = [{"task_id": plan["task_id"], **gap} for plan in plans for gap in plan["gaps"]]
    state.retrieval_plans, state.retrieval_plan_gaps = plans, gaps
    state.retrieval_sufficient = not any(gap.get("severity") == "REQUIRED" for gap in gaps)
    state.ledger["retrieval_plans"], state.ledger["retrieval_plan_gaps"] = plans, gaps
