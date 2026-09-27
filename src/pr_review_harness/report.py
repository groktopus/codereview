"""Concise, evidence-linked advisory report rendering."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import quote, urlparse


def render_report(result: dict) -> str:
    if not isinstance(result, dict):
        raise ValueError("result must be an object")

    def safe(value: Any) -> str:
        value = str(value if value is not None else "").replace("\r", " ").replace("\n", " ")
        for char in ("|", "<", ">", "`", "[", "]", "(", ")", "#", "*", "_", "!"):
            value = value.replace(char, "\\" + char)
        return value

    def source_link(path: str, side: str, line: int | None) -> str:
        repository = result.get("repository_url") or result.get("snapshot", {}).get("repository_url")
        revision = (
            side
            if isinstance(side, str) and len(side) == 40
            else result.get("base_sha")
            if side == "BASE"
            else result.get("head_sha")
        )
        escaped = quote(path, safe="/")
        parsed = urlparse(repository) if isinstance(repository, str) else None
        if (
            parsed
            and parsed.scheme == "https"
            and parsed.hostname == "github.com"
            and not parsed.username
            and not parsed.password
            and revision
        ):
            url = f"{repository.rstrip('/')}/blob/{revision}/{escaped}"
            if line:
                url += f"#L{line}"
        else:
            url = f"./{escaped}" + (f"#L{line}" if line else "")
        return url

    sections = result.get("report_sections", {})
    required = ("blockers", "suggested_improvements", "specific_strengths", "future_guidance")
    if (
        not isinstance(sections, dict)
        or set(sections) != set(required)
        or any(not isinstance(sections[k], list) for k in required)
    ):
        raise ValueError("report requires exactly four section arrays")
    expected_blockers = {
        f.get("finding_id")
        for f in result.get("findings", [])
        if isinstance(f, dict) and f.get("status") == "ACCEPTED" and f.get("blocking_class") == "BLOCKING"
    }
    rendered_blockers = {item.get("finding_id") for item in sections["blockers"] if isinstance(item, dict)}
    if not expected_blockers.issubset(rendered_blockers):
        raise ValueError("report omits an accepted blocker")

    lines = [
        f"PR review {safe(result.get('run_id', 'unknown'))}: {safe(result.get('disposition', 'INCOMPLETE'))}",
        f"Coverage: {result.get('coverage_state', 'NOT_STARTED')} | Freshness: {result.get('freshness', 'UNKNOWN')} | Merge eligibility: {result.get('merge_eligibility', 'NOT_EVALUATED')}",
        f"Reviewed: {safe(result.get('base_sha', 'unknown'))}..{safe(result.get('head_sha', 'unknown'))} | Profile: {safe(result.get('project_profile_version', 'unknown'))}",
        f"Budgets: {result.get('budget', {}).get('provider_calls_reserved', 0)}/{result.get('budget', {}).get('provider_calls_limit', 'unknown')} calls; input {result.get('budget', {}).get('context_bytes_reserved', 0)}/{result.get('budget', {}).get('context_bytes_limit', 'unknown')} bytes; output {result.get('budget', {}).get('output_bytes_reserved', 0)}/{result.get('budget', {}).get('output_bytes_limit', 'unknown')} bytes; cost {safe(result.get('budget', {}).get('cost', 'UNKNOWN'))}.",
    ]
    names = (
        ("Blockers", "blockers"),
        ("Suggested improvements", "suggested_improvements"),
        ("Specific strengths", "specific_strengths"),
        ("Future guidance", "future_guidance"),
    )
    evidence_index = result.get("evidence_index", {})
    for title, key in names:
        lines.extend(("", f"## {title}"))
        items = sections[key]
        if not items:
            lines.append("None recorded.")
            continue
        for item in items:
            if not isinstance(item, dict):
                continue
            location = item.get("location") if isinstance(item.get("location"), dict) else {}
            path = item.get("path") or location.get("path")
            side = location.get("side", "HEAD")
            line = location.get("line", item.get("line"))
            if path:
                line_suffix = f":{line}" if line else " (file-level)" if location.get("kind") == "file" else ""
                loc = f"[{safe(path + line_suffix)}]({source_link(path, side, line)})"
            else:
                loc = "evidence-backed scope"
            refs = []
            for evidence_id in item.get("evidence_refs", []):
                ev = evidence_index.get(evidence_id, {})
                evpath = ev.get("path")
                if evpath:
                    evside = ev.get("source_revision", side)
                    evline = ev.get("line_start")
                    anchor = f"[{safe(evidence_id)}]({source_link(evpath, evside, evline)})"
                else:
                    anchor = safe(evidence_id)
                refs.append(anchor)
            evidence = ", ".join(refs) or "no evidence references"
            note_type = (
                "why_it_matters" if key == "specific_strengths" else "guidance" if key == "future_guidance" else None
            )
            if note_type:
                lines.append(
                    f"- **{safe(item.get('finding_id', 'unidentified'))}** {safe(item.get('title', ''))}: {safe(item.get('observation', ''))} {safe(item.get(note_type, ''))} Evidence: {evidence}."
                )
            else:
                lines.append(
                    f"- **{safe(item.get('finding_id', 'unidentified'))}** {safe(item.get('title', ''))} at {loc}. {safe(item.get('observation', ''))} Consequence: {safe(item.get('consequence', ''))} Rule: {safe(item.get('rule_or_contract', ''))} Evidence: {evidence}."
                )

    coverage_rows = result.get("coverage_ledger", [])
    counts = {
        state: sum(row.get("state") == state for row in coverage_rows)
        for state in ("COMPLETE", "PARTIAL", "NOT_STARTED")
    }
    unresolved = [row for row in coverage_rows if row.get("required", True) and row.get("state") != "COMPLETE"]
    lines.extend(("", "Coverage"))
    lines.append(
        f"{counts['COMPLETE']} complete, {counts['PARTIAL']} partial, {counts['NOT_STARTED']} not started across {len(coverage_rows)} obligations."
    )
    if unresolved:
        for row in sorted(unresolved, key=lambda item: (item.get("state") != "PARTIAL", item.get("obligation_id", "")))[
            :8
        ]:
            lines.append(
                f"- {safe(row.get('obligation_id'))}: {safe(row.get('state'))} ({safe(row.get('reason_code'))})"
            )
            reasons = _specialist_partial_reasons(row, result.get("task_results", {}))
            if reasons:
                lines.append(
                    f"  Specialist reported partial coverage: {', '.join(safe(reason) for reason in reasons)}."
                )
        if len(unresolved) > 8:
            lines.append(f"- {len(unresolved) - 8} more unresolved obligations are retained in the durable result.")
    for entry in result.get("not_applicable", []):
        lines.append(f"- {safe(entry.get('obligation_id'))}: NOT_APPLICABLE ({safe(entry.get('reason'))})")
    for gap in result.get("context_gaps", []):
        proposal = gap.get("proposal", {})
        lines.append(
            f"- Context gap {safe(gap.get('proposal_id'))} ({safe(gap.get('status'))}): {safe(proposal.get('rationale'))}"
        )
    unresolved_findings = sum(f.get("blocking_class") == "UNRESOLVED" for f in result.get("findings", []))
    if unresolved_findings:
        lines.append(
            f"{unresolved_findings} unverified claims remain in the durable result and are not presented as recommendations."
        )
    return "\n".join(lines).rstrip() + "\n"


def _specialist_partial_reasons(row: dict, task_results: Any) -> list[str]:
    """Return a few bounded source reason codes as advisory report text only."""
    if (
        row.get("state") != "PARTIAL"
        or row.get("obligation_kind") != "CHANGED_UNIT_LENS"
        or row.get("reason_code") != "PARTIAL_REVIEW_COVERAGE"
        or not isinstance(task_results, dict)
    ):
        return []
    scope_units = row.get("scope_unit_ids")
    task_ids = row.get("task_ids")
    if (
        not isinstance(scope_units, list)
        or len(scope_units) > 64
        or any(not isinstance(unit, str) for unit in scope_units)
        or not isinstance(task_ids, list)
        or len(task_ids) > 64
        or any(not isinstance(task_id, str) for task_id in task_ids)
    ):
        return []
    reasons: set[str] = set()
    for task_id in task_ids:
        task = task_results.get(task_id)
        if not isinstance(task, dict) or task.get("status") != "SUCCEEDED":
            continue
        payload = task.get("payload")
        if not isinstance(payload, dict):
            continue
        notes = payload.get("coverage_notes")
        if not isinstance(notes, list):
            continue
        dispatched = task.get("input_evidence_ids")
        dispatched_ids = (
            set(dispatched) if isinstance(dispatched, list) and all(isinstance(x, str) for x in dispatched) else set()
        )
        for note in notes[:64]:
            if (
                not isinstance(note, dict)
                or note.get("unit_id") not in scope_units
                or note.get("state") not in {"PARTIAL", "NOT_COVERED"}
                or note.get("coverage_basis") != "STATIC_REVIEW"
            ):
                continue
            refs = note.get("evidence_refs")
            reason = note.get("reason_code")
            if (
                isinstance(refs, list)
                and refs
                and all(isinstance(ref, str) and ref in dispatched_ids for ref in refs)
                and isinstance(reason, str)
                and len(reason) <= 128
                and re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", reason)
            ):
                reasons.add(reason)
    return sorted(reasons)[:3]
