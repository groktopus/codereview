#!/usr/bin/env python3
"""Verify that docs/README.md indexes every Markdown document under docs/.

The index has four canonical sections: Current, Reference contracts,
History and evidence, and Archive. Every Markdown file under docs/ (except the
index itself) must be linked from exactly one section, and every documentation
link in the index must resolve. The Current section may contain at most ten
documents.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from check_relative_links import markdown_links  # noqa: E402

SECTION_NAMES = ("current", "reference contracts", "history and evidence", "archive")
MAX_CURRENT = 10


def headings_by_line(lines: list[str]) -> dict[int, str]:
    sections: dict[int, str] = {}
    for number, line in enumerate(lines, 1):
        if line.startswith("## "):
            name = line[3:].strip().rstrip("#").strip().lower()
            if name in SECTION_NAMES:
                sections[number] = name
    return sections


def section_for(line: int, headings: dict[int, str]) -> str | None:
    applicable = [number for number in headings if number <= line]
    if not applicable:
        return None
    return headings[max(applicable)]


def check(root: Path, docs_dir: Path, index_path: Path) -> dict[str, object]:
    errors: list[str] = []
    if not index_path.is_file():
        return {"errors": [f"index not found: {index_path}"], "documents": 0, "indexed": 0, "counts": {}, "unindexed": []}

    docs = sorted(
        path.relative_to(docs_dir).as_posix()
        for path in docs_dir.rglob("*.md")
        if path.resolve() != index_path.resolve()
    )
    known = set(docs)

    lines = index_path.read_text(encoding="utf-8").splitlines()
    headings = headings_by_line(lines)
    for name in SECTION_NAMES:
        if name not in headings.values():
            errors.append(f"missing canonical section: ## {name.title()}")

    memberships: dict[str, set[str]] = {}
    current_docs: set[str] = set()
    for line, target in markdown_links(index_path):
        if target.startswith(("http://", "https://", "mailto:", "#")) or target.startswith("/"):
            continue
        relative = target.split("#", 1)[0].split("?", 1)[0]
        if not relative.endswith(".md"):
            continue
        resolved = (index_path.parent / relative).resolve()
        try:
            doc = resolved.relative_to(docs_dir.resolve()).as_posix()
        except ValueError:
            continue
        section = section_for(line, headings)
        if section is None:
            errors.append(f"index link outside a canonical section: {target} (line {line})")
            continue
        if doc not in known:
            errors.append(f"index link points to a missing document: {target} (line {line})")
            continue
        memberships.setdefault(doc, set()).add(section)
        if section == "current":
            current_docs.add(doc)

    for doc in docs:
        sections = memberships.get(doc, set())
        if not sections:
            errors.append(f"unindexed document: docs/{doc}")
        elif len(sections) > 1:
            errors.append(f"document listed in multiple sections {sorted(sections)}: docs/{doc}")

    if len(current_docs) > MAX_CURRENT:
        errors.append(f"Current section lists {len(current_docs)} documents; maximum is {MAX_CURRENT}")

    counts = {
        section: sum(1 for sections in memberships.values() if section in sections)
        for section in SECTION_NAMES
    }
    return {
        "documents": len(docs),
        "indexed": len(memberships),
        "counts": counts,
        "unindexed": sorted(set(docs) - set(memberships)),
        "errors": errors,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--docs-dir", type=Path)
    parser.add_argument("--index", type=Path)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)

    root = args.root.resolve()
    docs_dir = (args.docs_dir or root / "docs").resolve()
    index_path = (args.index or docs_dir / "README.md").resolve()
    result = check(root, docs_dir, index_path)

    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    elif not args.quiet:
        print(
            "Docs index: "
            f"{result['indexed']}/{result['documents']} documents indexed "
            f"(current {result['counts'].get('current', 0)}, "
            f"reference {result['counts'].get('reference contracts', 0)}, "
            f"history {result['counts'].get('history and evidence', 0)}, "
            f"archive {result['counts'].get('archive', 0)})"
        )
        for error in result["errors"]:
            print(f"  ERROR: {error}")
        if not result["errors"]:
            print("OK: index covers every Markdown document under docs/")
    return 1 if result["errors"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
