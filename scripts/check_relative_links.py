#!/usr/bin/env python3
"""Check relative Markdown links in the root README and docs/.

External URLs, mail links, fragments, and absolute paths are ignored. Fenced
code blocks are skipped so documentation examples do not produce false
failures. A link is broken when its path does not exist relative to the file
that contains it.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from urllib.parse import unquote

LINK_RE = re.compile(r"!?\[[^\]]*\]\(\s*(<[^>]+>|[^)\s]+)(?:\s+[\"'][^\"']*[\"'])?\s*\)")
REFERENCE_RE = re.compile(r"^\s*\[[^\]]+\]:\s*(\S+)")
FENCE_RE = re.compile(r"^\s*(```+|~~~+)")
IGNORED_PREFIXES = ("http://", "https://", "mailto:", "tel:", "data:", "ftp://", "//")


def markdown_links(path: Path) -> list[tuple[int, str]]:
    """Return (line_number, target) for inline and reference-style links."""

    links: list[tuple[int, str]] = []
    in_fence = False
    fence_marker = ""
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        fence = FENCE_RE.match(line)
        if fence:
            marker = fence.group(1)
            if not in_fence:
                in_fence = True
                fence_marker = marker[0]
            elif marker[0] == fence_marker:
                in_fence = False
                fence_marker = ""
            continue
        if in_fence:
            continue
        for match in LINK_RE.finditer(line):
            target = match.group(1).strip()
            if target.startswith("<") and target.endswith(">"):
                target = target[1:-1].strip()
            links.append((number, target))
        reference = REFERENCE_RE.match(line)
        if reference:
            links.append((number, reference.group(1)))
    return links


def is_external(target: str) -> bool:
    return not target or target.startswith("#") or target.startswith(IGNORED_PREFIXES)


def split_target(target: str) -> str:
    path = target.split("#", 1)[0].split("?", 1)[0]
    return unquote(path)


def check_paths(root: Path, paths: list[Path]) -> tuple[list[Path], list[dict[str, object]]]:
    files: list[Path] = []
    for path in paths:
        if path.is_dir():
            files.extend(sorted(path.rglob("*.md")))
        elif path.is_file():
            files.append(path)
        else:
            raise FileNotFoundError(path)

    broken: list[dict[str, object]] = []
    for file_path in files:
        for line, target in markdown_links(file_path):
            if is_external(target):
                continue
            relative = split_target(target)
            if not relative or relative.startswith("/"):
                continue
            destination = (file_path.parent / relative).resolve()
            if not destination.exists():
                broken.append(
                    {
                        "file": str(file_path),
                        "line": line,
                        "target": target,
                        "resolved": str(destination),
                    }
                )
    return files, broken


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("paths", nargs="*", type=Path, help="Files or directories; defaults to README.md and docs/")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)

    root = args.root.resolve()
    paths = args.paths or [root / "README.md", root / "docs"]
    try:
        files, broken = check_paths(root, [p if p.is_absolute() else root / p for p in paths])
    except FileNotFoundError as error:
        print(f"ERROR: path not found: {error}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps({"files_checked": len(files), "broken": broken}, indent=2))
    elif not args.quiet:
        link_count = sum(len(markdown_links(path)) for path in files)
        print(f"Relative link check: {len(files)} Markdown files, {link_count} links, {len(broken)} broken")
        for item in broken:
            print(f"  {item['file']}:{item['line']}: {item['target']} -> missing {item['resolved']}")
        if not broken:
            print("OK: no broken relative links")
    return 1 if broken else 0


if __name__ == "__main__":
    raise SystemExit(main())
