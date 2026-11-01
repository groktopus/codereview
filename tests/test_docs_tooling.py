"""Tests for the documentation index and relative-link checkers."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import check_docs_index as index_check  # noqa: E402
import check_relative_links as link_check  # noqa: E402


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def make_index(docs: list[str], current: list[str] | None = None) -> str:
    current = current if current is not None else docs[:1]
    reference = [doc for doc in docs if doc not in current]
    lines = ["# Index", "", "## Current", "", "| Document |", "|---|"]
    lines += [f"| [{doc}]({doc}) |" for doc in current]
    lines += ["", "## Reference contracts", "", "| Document |", "|---|"]
    lines += [f"| [{doc}]({doc}) |" for doc in reference]
    lines += ["", "## History and evidence", "", "None.", "", "## Archive", "", "None.", ""]
    return "\n".join(lines)


def test_repository_index_and_links_pass() -> None:
    result = index_check.check(ROOT, ROOT / "docs", ROOT / "docs/README.md")
    assert result["errors"] == []
    assert result["indexed"] == result["documents"]
    assert result["counts"]["current"] <= index_check.MAX_CURRENT

    _, broken = link_check.check_paths(ROOT, [ROOT / "README.md", ROOT / "docs"])
    assert broken == []


def test_unindexed_document_fails(tmp_path: Path) -> None:
    docs = tmp_path / "docs"
    write(docs / "a.md", "# A\n")
    write(docs / "b.md", "# B\n")
    write(docs / "README.md", make_index(["a.md"]))
    result = index_check.check(tmp_path, docs, docs / "README.md")
    assert any("unindexed document: docs/b.md" in error for error in result["errors"])


def test_duplicate_section_fails(tmp_path: Path) -> None:
    docs = tmp_path / "docs"
    write(docs / "a.md", "# A\n")
    index = make_index(["a.md"]) + "\n## Archive\n\n| [a](a.md) |\n"
    write(docs / "README.md", index)
    result = index_check.check(tmp_path, docs, docs / "README.md")
    assert any("multiple sections" in error for error in result["errors"])


def test_current_cap_fails(tmp_path: Path) -> None:
    docs = tmp_path / "docs"
    names = [f"doc-{number}.md" for number in range(11)]
    for name in names:
        write(docs / name, f"# {name}\n")
    write(docs / "README.md", make_index(names, current=names))
    result = index_check.check(tmp_path, docs, docs / "README.md")
    assert any("maximum is 10" in error for error in result["errors"])


def test_missing_index_target_fails(tmp_path: Path) -> None:
    docs = tmp_path / "docs"
    write(docs / "a.md", "# A\n")
    write(docs / "README.md", make_index(["a.md", "missing.md"]))
    result = index_check.check(tmp_path, docs, docs / "README.md")
    assert any("missing document" in error for error in result["errors"])


def test_relative_link_checker_reports_only_real_breaks(tmp_path: Path) -> None:
    write(tmp_path / "docs" / "target.md", "# Target\n")
    write(
        tmp_path / "docs" / "page.md",
        "# Page\n\n"
        "[ok](target.md)\n"
        "[fragment](target.md#section)\n"
        "[external](https://example.com/missing)\n"
        "[fragment-only](#local)\n"
        "[broken](missing.md)\n"
        "```markdown\n[example](not-a-real-link.md)\n```\n",
    )
    files, broken = link_check.check_paths(tmp_path, [tmp_path / "docs"])
    assert len(files) == 2
    assert [(item["line"], item["target"]) for item in broken] == [(7, "missing.md")]
