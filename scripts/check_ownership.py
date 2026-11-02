#!/usr/bin/env python3
"""Verify GA-3 ownership, CODEOWNERS coverage, and backlog triage consistency.

The check is deliberately structural. It verifies that:

* every production module in ``docs/public-surface.json`` has an effective,
  non-default CODEOWNERS rule whose group matches the module map in
  ``docs/OWNERSHIP.md``;
* the ownership document contains the required accountability, review,
  incident, credential, and unavailability sections;
* the backlog table lists exactly the checked open-issue snapshot, with one
  accountable owner, one valid state label, and a filed-issue ID for each row.

It does not prove that an owner is available, that a reviewer was independent,
that a credential is stored safely, or that a closure claim is true.
"""

from __future__ import annotations

import argparse
import datetime
import fnmatch
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path

SURFACE_SCHEMA = "pr-review-public-surface.v1"
SNAPSHOT_SCHEMA = "review-harness-backlog-snapshot.v1"
REQUIRED_OWNER = "@magnus919"
MODULE_GROUPS = ("core-review", "publication-effects", "security-credentials")
ALL_GROUPS = (*MODULE_GROUPS, "docs", "workflows", "release", "default")
STATE_LABELS = {
    "triage": "state:triage",
    "ready": "state:ready",
    "in-progress": "state:in-progress",
    "blocked": "state:blocked",
    "awaiting-evidence": "state:awaiting-evidence",
}
REQUIRED_OWNERSHIP_SECTIONS = (
    "Bus factor and authority",
    "Ownership map",
    "Module map",
    "Second-reviewer path",
    "Publication incident and rollback ownership",
    "Credential and access ownership",
    "If the maintainer is unavailable",
    "Backlog triage",
    "Verification",
)
GROUP_RE = re.compile(r"^#\s*group:\s*(?P<group>[a-z0-9-]+)\s*$")
BACKTICK_RE = re.compile(r"`([^`]+)`")
ISSUE_RE = re.compile(r"^#(?P<number>[0-9]+)$")
ISSUE_URL_RE = re.compile(r"issues/(?P<number>[0-9]+)\b")
TITLE_ID_RE = re.compile(r"^\[(?P<id>[A-Z]{2}-[0-9]+)\]")
SUMMARY_RE = re.compile(
    r"Summary:\s*\*\*(?P<ready>\d+)\s+`ready`,\s*"
    r"(?P<blocked>\d+)\s+`blocked`,\s*"
    r"(?P<awaiting>\d+)\s+`awaiting-evidence`,\s*"
    r"(?P<progress>\d+)\s+`in-progress`\*\*"
)


@dataclass(frozen=True)
class Rule:
    line: int
    pattern: str
    owners: tuple[str, ...]
    group: str


def _normalise(path: str) -> str:
    path = path.strip()
    while path.startswith("./"):
        path = path[2:]
    return path.lstrip("/")


def pattern_matches(pattern: str, path: str) -> bool:
    """Approximate GitHub CODEOWNERS matching for the patterns used here."""

    path = _normalise(path)
    pattern = _normalise(pattern)
    if pattern in {"", "*"}:
        return True
    if pattern.endswith("/"):
        prefix = pattern.rstrip("/")
        return path == prefix or path.startswith(f"{prefix}/")
    if any(char in pattern for char in "*?["):
        if "/" not in pattern:
            return fnmatch.fnmatchcase(path.rsplit("/", 1)[-1], pattern)
        return fnmatch.fnmatchcase(path, pattern)
    if "/" not in pattern:
        return path.rsplit("/", 1)[-1] == pattern
    return path == pattern


def parse_codeowners(root: Path) -> tuple[list[Rule], list[str]]:
    path = root / ".github" / "CODEOWNERS"
    errors: list[str] = []
    if not path.is_file():
        return [], [".github/CODEOWNERS: file is missing"]
    rules: list[Rule] = []
    group = "default"
    for number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("#"):
            match = GROUP_RE.match(line)
            if match:
                group = match.group("group")
                if group not in ALL_GROUPS:
                    errors.append(f".github/CODEOWNERS:{number}: unknown group {group!r}")
            continue
        parts = line.split()
        if len(parts) < 2:
            errors.append(f".github/CODEOWNERS:{number}: rule needs a pattern and at least one owner")
            continue
        pattern, owners = parts[0], tuple(parts[1:])
        rules.append(Rule(number, pattern, owners, group))
        for owner in owners:
            if not owner.startswith("@") or owner.lower() in {"@tbd", "@todo", "@unknown", "@none"}:
                errors.append(f".github/CODEOWNERS:{number}: invalid or placeholder owner {owner!r}")
    if not rules:
        errors.append(".github/CODEOWNERS: no ownership rules")
    if not any(rule.pattern == "*" for rule in rules):
        errors.append(".github/CODEOWNERS: missing the default `*` rule")
    return rules, errors


def effective_rule(rules: list[Rule], path: str) -> Rule | None:
    matched = [rule for rule in rules if pattern_matches(rule.pattern, path)]
    return matched[-1] if matched else None


def _load_json(path: Path, label: str, errors: list[str]) -> dict[str, object]:
    if not path.is_file():
        errors.append(f"{label}: file is missing")
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        errors.append(f"{label}: invalid JSON: {exc}")
        return {}
    if not isinstance(data, dict):
        errors.append(f"{label}: top-level JSON must be an object")
        return {}
    return data


def parse_ownership(path: Path, errors: list[str]) -> tuple[set[str], dict[str, str]]:
    """Return required-section names found and module -> group from the module table."""

    if not path.is_file():
        errors.append("docs/OWNERSHIP.md: file is missing")
        return set(), {}
    sections: set[str] = set()
    modules: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        if raw_line.startswith("## "):
            sections.add(raw_line[3:].strip().rstrip("#").strip())
        line = raw_line.strip()
        if not line.startswith("|"):
            continue
        cells = [cell.strip() for cell in line.strip("|").split("|")]
        if len(cells) != 3:
            continue
        group_match = BACKTICK_RE.fullmatch(cells[0])
        if not group_match or group_match.group(1) not in MODULE_GROUPS:
            continue
        group = group_match.group(1)
        if cells[2].strip("` ") != REQUIRED_OWNER:
            errors.append(f"docs/OWNERSHIP.md: module group {group} owner must be {REQUIRED_OWNER}")
        for token in BACKTICK_RE.findall(cells[1]):
            if not token.endswith(".py"):
                continue
            if token in modules:
                errors.append(f"docs/OWNERSHIP.md: module {token} appears in more than one group")
            modules[token] = group
    return sections, modules


def parse_filed_issues(path: Path, errors: list[str]) -> dict[int, str]:
    if not path.is_file():
        errors.append("docs/issues/FILED.md: file is missing")
        return {}
    filed: dict[int, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line.startswith("|"):
            continue
        cells = [cell.strip() for cell in line.strip("|").split("|")]
        if len(cells) < 2 or not re.fullmatch(r"[A-Z]{2}-[0-9]+", cells[0]):
            continue
        url = ISSUE_URL_RE.search(cells[1])
        if url:
            filed[int(url.group("number"))] = cells[0]
    return filed


def parse_backlog(path: Path, errors: list[str]) -> list[dict[str, str]]:
    if not path.is_file():
        errors.append("docs/BACKLOG.md: file is missing")
        return []
    text = path.read_text(encoding="utf-8")
    start = text.find("<!-- backlog-table:start -->")
    end = text.find("<!-- backlog-table:end -->")
    if start == -1 or end == -1 or end <= start:
        errors.append("docs/BACKLOG.md: missing backlog table markers")
        return []
    rows: list[dict[str, str]] = []
    for number, raw_line in enumerate(text[start:end].splitlines(), 1):
        line = raw_line.strip()
        if not line.startswith("|"):
            continue
        cells = [cell.strip() for cell in line.strip("|").split("|")]
        if len(cells) != 7 or cells[0] in {"Issue", "---"} or set(cells[0]) <= {"-", ":"}:
            continue
        issue = ISSUE_RE.fullmatch(cells[0])
        if not issue:
            errors.append(f"docs/BACKLOG.md: table row {number} has no issue number cell")
            continue
        rows.append(
            {
                "number": issue.group("number"),
                "id": cells[1],
                "title": cells[2],
                "owner": cells[3].strip("` "),
                "state": cells[4].strip("` "),
                "labels": cells[5],
                "next": cells[6],
            }
        )
    return rows


def check(root: Path) -> dict[str, object]:
    errors: list[str] = []
    rules, rule_errors = parse_codeowners(root)
    errors.extend(rule_errors)

    surface = _load_json(root / "docs" / "public-surface.json", "docs/public-surface.json", errors)
    if surface.get("schema") != SURFACE_SCHEMA:
        errors.append(f"docs/public-surface.json: schema must be {SURFACE_SCHEMA!r}")
    production = surface.get("production_modules")
    if not isinstance(production, list) or not all(isinstance(item, str) for item in production):
        errors.append("docs/public-surface.json: production_modules must be a list of strings")
        production = []
    modules = set(production)
    if len(modules) != len(production):
        errors.append("docs/public-surface.json: duplicate production module names")

    sections, module_groups = parse_ownership(root / "docs" / "OWNERSHIP.md", errors)
    for section in REQUIRED_OWNERSHIP_SECTIONS:
        if section not in sections:
            errors.append(f"docs/OWNERSHIP.md: missing required section: ## {section}")
    if set(module_groups) != modules:
        for module in sorted(modules - set(module_groups)):
            errors.append(f"docs/OWNERSHIP.md: production module is not in the module map: {module}")
        for module in sorted(set(module_groups) - modules):
            errors.append(f"docs/OWNERSHIP.md: module map names an unknown production module: {module}")

    for module in sorted(modules):
        path = f"src/pr_review_harness/{module}"
        rule = effective_rule(rules, path)
        if rule is None:
            errors.append(f".github/CODEOWNERS: no rule covers production module {path}")
            continue
        if rule.group == "default":
            errors.append(f".github/CODEOWNERS: production module {path} is covered only by the default rule")
        expected = module_groups.get(module)
        if expected and rule.group != expected:
            errors.append(
                f".github/CODEOWNERS: effective group for {path} is {rule.group!r}; "
                f"docs/OWNERSHIP.md says {expected!r}"
            )
        if rule.owners != (REQUIRED_OWNER,):
            errors.append(f".github/CODEOWNERS: effective owner for {path} must be {REQUIRED_OWNER}")

    for rule in rules:
        if rule.group not in ALL_GROUPS:
            continue
        pattern = _normalise(rule.pattern)
        if rule.pattern != "*" and not any(char in pattern for char in "*?["):
            target = root / pattern.rstrip("/")
            if not target.exists():
                errors.append(f".github/CODEOWNERS:{rule.line}: path does not exist: {rule.pattern}")

    snapshot = _load_json(root / "docs" / "backlog-open-issues.json", "docs/backlog-open-issues.json", errors)
    if snapshot.get("schema") != SNAPSHOT_SCHEMA:
        errors.append(f"docs/backlog-open-issues.json: schema must be {SNAPSHOT_SCHEMA!r}")
    if snapshot.get("repository") != "groktopus/codereview":
        errors.append("docs/backlog-open-issues.json: repository must be groktopus/codereview")
    captured = snapshot.get("captured_at")
    if not isinstance(captured, str):
        errors.append("docs/backlog-open-issues.json: captured_at must be an ISO timestamp")
    else:
        try:
            datetime.datetime.fromisoformat(captured.replace("Z", "+00:00"))
        except ValueError:
            errors.append("docs/backlog-open-issues.json: captured_at is not a valid ISO timestamp")
    open_numbers = snapshot.get("open_issue_numbers")
    if not isinstance(open_numbers, list) or not all(isinstance(item, int) for item in open_numbers):
        errors.append("docs/backlog-open-issues.json: open_issue_numbers must be a list of integers")
        open_numbers = []
    open_set = set(open_numbers)
    if len(open_set) != len(open_numbers):
        errors.append("docs/backlog-open-issues.json: open_issue_numbers contains duplicates")
    if snapshot.get("state") != "open":
        errors.append("docs/backlog-open-issues.json: state must be 'open'")

    filed = parse_filed_issues(root / "docs" / "issues" / "FILED.md", errors)
    if snapshot.get("total_filed") != len(filed):
        errors.append(
            f"docs/backlog-open-issues.json: total_filed is {snapshot.get('total_filed')!r}, "
            f"but FILED.md lists {len(filed)} issues"
        )
    for number in sorted(open_set - set(filed)):
        errors.append(f"docs/backlog-open-issues.json: open issue #{number} is not in FILED.md")

    rows = parse_backlog(root / "docs" / "BACKLOG.md", errors)
    row_numbers: list[int] = []
    for row in rows:
        number = int(row["number"])
        if number in row_numbers:
            errors.append(f"docs/BACKLOG.md: duplicate issue #{number}")
        row_numbers.append(number)
        if row["owner"] != REQUIRED_OWNER:
            errors.append(f"docs/BACKLOG.md: issue #{number} owner must be {REQUIRED_OWNER}")
        if row["state"] not in STATE_LABELS:
            errors.append(f"docs/BACKLOG.md: issue #{number} has invalid state {row['state']!r}")
        else:
            tokens = re.findall(r"`(state:[a-z-]+)`", row["labels"])
            if len(tokens) != 1:
                errors.append(f"docs/BACKLOG.md: issue #{number} must list exactly one state label")
            elif tokens[0] != STATE_LABELS[row["state"]]:
                errors.append(
                    f"docs/BACKLOG.md: issue #{number} state {row['state']!r} needs label "
                    f"{STATE_LABELS[row['state']]!r}"
                )
        if not row["title"]:
            errors.append(f"docs/BACKLOG.md: issue #{number} has no title")
        if not row["next"]:
            errors.append(f"docs/BACKLOG.md: issue #{number} has no next action or blocker")
        if number in filed:
            title_match = TITLE_ID_RE.match(row["title"])
            if not title_match:
                errors.append(f"docs/BACKLOG.md: issue #{number} title must start with [<ID>]")
            elif title_match.group("id") != filed[number]:
                errors.append(
                    f"docs/BACKLOG.md: issue #{number} ID {title_match.group('id')!r} "
                    f"does not match FILED.md ({filed[number]!r})"
                )
        if row["state"] in {"blocked", "awaiting-evidence"} and "#" not in row["next"] and "owner action" not in row["next"].lower():
            errors.append(
                f"docs/BACKLOG.md: issue #{number} is {row['state']!r} but names no blocker, "
                "issue number, or owner action"
            )

    if len(row_numbers) != len(set(row_numbers)):
        errors.append("docs/BACKLOG.md: backlog table has duplicate issue numbers")
    if set(row_numbers) != open_set:
        for number in sorted(open_set - set(row_numbers)):
            errors.append(f"docs/BACKLOG.md: open issue #{number} is missing from the table")
        for number in sorted(set(row_numbers) - open_set):
            errors.append(f"docs/BACKLOG.md: issue #{number} is in the table but not in the open snapshot")
    if row_numbers != sorted(row_numbers):
        errors.append("docs/BACKLOG.md: backlog table must be ordered by issue number")

    counts = {state: sum(1 for row in rows if row["state"] == state) for state in STATE_LABELS}
    backlog_path = root / "docs" / "BACKLOG.md"
    summary = SUMMARY_RE.search(backlog_path.read_text(encoding="utf-8")) if backlog_path.is_file() else None
    if not summary:
        errors.append("docs/BACKLOG.md: missing summary counts line")
    else:
        expected_counts = {
            "ready": int(summary.group("ready")),
            "blocked": int(summary.group("blocked")),
            "awaiting-evidence": int(summary.group("awaiting")),
            "in-progress": int(summary.group("progress")),
        }
        for state, expected in expected_counts.items():
            if counts[state] != expected:
                errors.append(
                    f"docs/BACKLOG.md: summary says {expected} {state} issues, table has {counts[state]}"
                )

    return {
        "errors": errors,
        "production_modules": len(modules),
        "modules_mapped": len(module_groups),
        "codeowners_rules": len(rules),
        "open_issues": len(row_numbers),
        "states": counts,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)

    result = check(args.root.resolve())
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    elif not args.quiet:
        print(
            "Ownership: "
            f"{result['modules_mapped']}/{result['production_modules']} modules mapped, "
            f"{result['codeowners_rules']} CODEOWNERS rules, "
            f"{result['open_issues']} open issues triaged"
        )
        for error in result.get("errors", []):
            print(f"  ERROR: {error}")
        if not result["errors"]:
            print("OK: ownership sections, module coverage, and backlog triage are consistent")
    return 1 if result["errors"] else 0


if __name__ == "__main__":
    sys.exit(main())
