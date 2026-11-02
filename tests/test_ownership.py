"""Tests for CODEOWNERS coverage, ownership sections, and backlog triage."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import check_ownership as ownership  # noqa: E402

MODULE = "core.py"
SURFACE = {
    "schema": ownership.SURFACE_SCHEMA,
    "production_modules": [MODULE],
}
OWNERSHIP_SECTIONS = "\n\n".join(f"## {section}\n\nText." for section in ownership.REQUIRED_OWNERSHIP_SECTIONS)
OWNERSHIP = f"""# Ownership

{OWNERSHIP_SECTIONS}

| Group | Modules | Accountable owner |
|---|---|---|
| `core-review` | `{MODULE}` | `@magnus919` |
"""
CODEOWNERS = """* @magnus919

# group: core-review
/src/pr_review_harness/core.py @magnus919
"""
BACKLOG = """# Backlog

<!-- backlog-table:start -->
| Issue | ID | Title | Owner | State | Labels to add | Next action / blocker |
|---|---|---|---|---|---|---|
| #239 | RC-1 | [RC-1] Test issue | `@magnus919` | `ready` | `state:ready` | Do the work. |
<!-- backlog-table:end -->

Summary: **1 `ready`, 0 `blocked`, 0 `awaiting-evidence`, 0 `in-progress`**
"""
SNAPSHOT = {
    "schema": ownership.SNAPSHOT_SCHEMA,
    "repository": "groktopus/codereview",
    "captured_at": "2026-11-02T07:20:00Z",
    "source": "test",
    "state": "open",
    "total_filed": 1,
    "open_issue_numbers": [239],
}
FILED = """# Filed issues

| ID | Title | Priority | Theme |
|---|---|---|---|
| RC-1 | [Test](https://github.com/groktopus/codereview/issues/239) | P0 | Test |
"""


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def make_repo(tmp_path: Path) -> Path:
    write(tmp_path / ".github" / "CODEOWNERS", CODEOWNERS)
    write(tmp_path / "src" / "pr_review_harness" / MODULE, "# module\n")
    write(tmp_path / "docs" / "public-surface.json", json.dumps(SURFACE))
    write(tmp_path / "docs" / "OWNERSHIP.md", OWNERSHIP)
    write(tmp_path / "docs" / "BACKLOG.md", BACKLOG)
    write(tmp_path / "docs" / "backlog-open-issues.json", json.dumps(SNAPSHOT))
    write(tmp_path / "docs" / "issues" / "FILED.md", FILED)
    return tmp_path


def test_repository_ownership_record_passes() -> None:
    result = ownership.check(ROOT)
    assert result["errors"] == []
    assert result["production_modules"] == 40
    assert result["modules_mapped"] == 40
    assert result["open_issues"] == 15


def test_production_module_covered_only_by_default_fails(tmp_path: Path) -> None:
    make_repo(tmp_path)
    write(tmp_path / ".github" / "CODEOWNERS", "* @magnus919\n")
    errors = ownership.check(tmp_path)["errors"]
    assert any("covered only by the default rule" in error for error in errors)


def test_effective_group_must_match_module_map(tmp_path: Path) -> None:
    make_repo(tmp_path)
    write(
        tmp_path / ".github" / "CODEOWNERS",
        "* @magnus919\n\n# group: security-credentials\n/src/pr_review_harness/core.py @magnus919\n",
    )
    errors = ownership.check(tmp_path)["errors"]
    assert any("docs/OWNERSHIP.md says 'core-review'" in error for error in errors)


def test_missing_ownership_section_fails(tmp_path: Path) -> None:
    make_repo(tmp_path)
    path = tmp_path / "docs" / "OWNERSHIP.md"
    path.write_text(path.read_text(encoding="utf-8").replace("## Credential and access ownership", "## Other"), encoding="utf-8")
    errors = ownership.check(tmp_path)["errors"]
    assert any("missing required section: ## Credential and access ownership" in error for error in errors)


def test_backlog_open_number_mismatch_fails(tmp_path: Path) -> None:
    make_repo(tmp_path)
    snapshot = dict(SNAPSHOT, open_issue_numbers=[239, 240])
    write(tmp_path / "docs" / "backlog-open-issues.json", json.dumps(snapshot))
    write(
        tmp_path / "docs" / "issues" / "FILED.md",
        FILED + "| RC-2 | [Other](https://github.com/groktopus/codereview/issues/240) | P1 | Test |\n",
    )
    snapshot["total_filed"] = 2
    write(tmp_path / "docs" / "backlog-open-issues.json", json.dumps(snapshot))
    errors = ownership.check(tmp_path)["errors"]
    assert any("open issue #240 is missing from the table" in error for error in errors)


def test_invalid_state_and_label_fail(tmp_path: Path) -> None:
    make_repo(tmp_path)
    write(tmp_path / "docs" / "BACKLOG.md", BACKLOG.replace("`ready`", "`shipping`"))
    errors = ownership.check(tmp_path)["errors"]
    assert any("invalid state 'shipping'" in error for error in errors)


def test_placeholder_owner_fails(tmp_path: Path) -> None:
    make_repo(tmp_path)
    write(tmp_path / "docs" / "BACKLOG.md", BACKLOG.replace("`@magnus919` | `ready`", "`@tbd` | `ready`"))
    errors = ownership.check(tmp_path)["errors"]
    assert any("owner must be @magnus919" in error for error in errors)


def test_duplicate_module_map_entry_fails(tmp_path: Path) -> None:
    make_repo(tmp_path)
    path = tmp_path / "docs" / "OWNERSHIP.md"
    path.write_text(
        path.read_text(encoding="utf-8")
        + "\n| `security-credentials` | `core.py` | `@magnus919` |\n",
        encoding="utf-8",
    )
    errors = ownership.check(tmp_path)["errors"]
    assert any("appears in more than one group" in error for error in errors)


def test_backlog_row_with_two_state_labels_fails(tmp_path: Path) -> None:
    root = make_repo(tmp_path)
    backlog = root / "docs" / "BACKLOG.md"
    text = backlog.read_text().replace("`state:ready`", "`state:ready` `state:blocked`", 1)
    backlog.write_text(text)
    assert any("exactly one state label" in error for error in ownership.check(root)["errors"])
