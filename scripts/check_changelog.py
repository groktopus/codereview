#!/usr/bin/env python3
"""Check CHANGELOG.md structure and classify changes.

The changelog is a release input, not free prose: only the categories in
``Keep a Changelog`` are accepted, every released version needs a date, and
breaking changes must be explicit. ``classify`` provides the deterministic
mapping used to decide which section a merged change belongs in.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

SEMVER_RE = re.compile(
    r"^(?P<major>0|[1-9]\d*)\.(?P<minor>0|[1-9]\d*)\.(?P<patch>0|[1-9]\d*)"
    r"(?:-(?P<pre>[0-9A-Za-z.-]+))?(?:\+(?P<build>[0-9A-Za-z.-]+))?$"
)
RELEASE_RE = re.compile(r"^##\s+\[(?P<version>[^\]]+)\](?:\s+-\s+(?P<date>\d{4}-\d{2}-\d{2}))?\s*$")
CATEGORY_RE = re.compile(r"^###\s+(?P<category>[A-Za-z][A-Za-z -]*?)\s*$")
BULLET_RE = re.compile(r"^[-*]\s+(?P<text>\S.*)$")
HEADING_TWO_RE = re.compile(r"^##\s+")
CONVENTIONAL_RE = re.compile(r"^(?P<type>[A-Za-z]+)(?:\([^)]*\))?(?P<breaking>!)?:\s*(?P<subject>\S.*)$")
BREAKING_RE = re.compile(r"BREAKING(?: |-)CHANGE:")

CATEGORIES = ("Added", "Changed", "Deprecated", "Removed", "Fixed", "Security")
BREAKING_CATEGORIES = ("Breaking", "Breaking changes")
TYPE_CATEGORIES = {
    "feat": "Added",
    "fix": "Fixed",
    "perf": "Changed",
    "refactor": "Changed",
    "revert": "Changed",
    "build": "Changed",
    "ci": "Changed",
    "docs": "Changed",
    "style": "Changed",
    "test": "Changed",
    "chore": "Changed",
    "deprecate": "Deprecated",
    "remove": "Removed",
    "security": "Security",
}


@dataclass
class Release:
    """One ``## [version]`` section."""

    version: str
    date: str | None
    line: int
    categories: dict[str, list[tuple[int, str]]] = field(default_factory=dict)
    prose: list[tuple[int, str]] = field(default_factory=list)

    @property
    def entry_count(self) -> int:
        return sum(len(entries) for entries in self.categories.values())

    def body(self) -> str:
        """Return the section body without its release heading."""

        lines: list[str] = []
        for category, entries in self.categories.items():
            lines.append(f"### {category}")
            lines.extend(f"- {text}" for _, text in entries)
            lines.append("")
        return "\n".join(lines).strip() + "\n"


def version_key(version: str) -> tuple[int, int, int, int, tuple[tuple[int, int, str], ...]]:
    """Return a sortable SemVer key; numeric prerelease ids compare numerically."""

    match = SEMVER_RE.match(version)
    if not match:
        raise ValueError(f"not a semantic version: {version!r}")
    pre = match.group("pre")
    identifiers: tuple[tuple[int, int, str], ...] = ()
    if pre:
        identifiers = tuple((0, int(part), "") if part.isdigit() else (1, 0, part) for part in pre.split("."))
    return (
        int(match.group("major")),
        int(match.group("minor")),
        int(match.group("patch")),
        0 if pre else 1,
        identifiers,
    )


def classify_message(message: str) -> str | None:
    """Map a conventional-commit message to one changelog category.

    A ``!`` marker or a ``BREAKING CHANGE:`` footer always returns
    ``Breaking``. Unknown commit types return ``None`` instead of guessing.
    """

    text = message.strip()
    if not text:
        return None
    if BREAKING_RE.search(text):
        return "Breaking"
    first_line = text.splitlines()[0]
    match = CONVENTIONAL_RE.match(first_line)
    if not match:
        return None
    if match.group("breaking"):
        return "Breaking"
    return TYPE_CATEGORIES.get(match.group("type").lower())


def parse_changelog(path: Path) -> tuple[list[Release], list[str]]:
    """Parse a changelog into releases and structural problems."""

    findings: list[str] = []
    lines = path.read_text(encoding="utf-8").splitlines()
    releases: list[Release] = []
    current: Release | None = None
    category: str | None = None

    for number, raw_line in enumerate(lines, 1):
        if HEADING_TWO_RE.match(raw_line):
            match = RELEASE_RE.match(raw_line)
            if not match:
                findings.append(f"CHANGELOG.md:{number}: malformed release heading: {raw_line.strip()}")
                current = None
                category = None
                continue
            current = Release(version=match.group("version"), date=match.group("date"), line=number)
            releases.append(current)
            category = None
            continue
        if current is None:
            continue
        stripped = raw_line.strip()
        if not stripped:
            continue
        if stripped.startswith("### "):
            match = CATEGORY_RE.match(stripped)
            if not match:
                findings.append(f"CHANGELOG.md:{number}: malformed category heading: {stripped}")
                category = None
                continue
            category = match.group("category")
            if category not in CATEGORIES and category not in BREAKING_CATEGORIES:
                findings.append(f"CHANGELOG.md:{number}: unknown changelog category {category!r}")
            if category in current.categories:
                findings.append(f"CHANGELOG.md:{number}: duplicate changelog category {category!r}")
            current.categories.setdefault(category, [])
            continue
        bullet = BULLET_RE.match(stripped)
        if bullet:
            if category is None:
                findings.append(f"CHANGELOG.md:{number}: entry outside a changelog category")
                continue
            current.categories[category].append((number, bullet.group("text")))
            continue
        current.prose.append((number, stripped))

    versions: dict[str, int] = {}
    for release in releases:
        if release.version == "Unreleased":
            if release.line != releases[0].line:
                findings.append(f"CHANGELOG.md:{release.line}: Unreleased must be the first section")
            continue
        if not SEMVER_RE.match(release.version):
            findings.append(f"CHANGELOG.md:{release.line}: released version {release.version!r} is not semantic")
            continue
        if not release.date:
            findings.append(
                f"CHANGELOG.md:{release.line}: released version {release.version!r} needs a YYYY-MM-DD date"
            )
        if release.version in versions:
            findings.append(f"CHANGELOG.md:{release.line}: duplicate released version {release.version!r}")
        versions[release.version] = release.line
        if release.entry_count == 0:
            findings.append(
                f"CHANGELOG.md:{release.line}: released version {release.version!r} has no classified entries"
            )
        for version_category, entries in release.categories.items():
            if not entries:
                findings.append(f"CHANGELOG.md:{release.line}: category {version_category!r} has no entries")

    if not releases:
        findings.append("CHANGELOG.md: no release headings found")
    elif releases[0].version != "Unreleased":
        findings.append("CHANGELOG.md: an Unreleased section is required before released versions")

    ordered = [release for release in releases if release.version != "Unreleased" and SEMVER_RE.match(release.version)]
    for earlier, later in zip(ordered, ordered[1:]):
        if version_key(earlier.version) < version_key(later.version):
            findings.append(
                f"CHANGELOG.md:{later.line}: released versions must be newest first "
                f"({earlier.version} precedes {later.version})"
            )
    return releases, findings


def release_for(releases: list[Release], version: str) -> Release | None:
    return next((release for release in releases if release.version == version), None)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--changelog", type=Path, default=Path("CHANGELOG.md"))
    parser.add_argument("--classify", metavar="MESSAGE", help="classify one conventional-commit message and exit")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    if args.classify is not None:
        category = classify_message(args.classify)
        if args.json:
            print(json.dumps({"message": args.classify, "category": category}, sort_keys=True))
        elif category is None:
            print("unclassified")
        else:
            print(category)
        return 0 if category is not None else 1

    if not args.changelog.is_file():
        print(f"changelog not found: {args.changelog}", file=sys.stderr)
        return 1
    releases, findings = parse_changelog(args.changelog)
    if args.json:
        print(
            json.dumps(
                {"ok": not findings, "findings": findings, "releases": [release.version for release in releases]}
            )
        )
    elif findings:
        for finding in findings:
            print(finding)
    else:
        print(f"changelog ok: {len(releases)} section(s)")
    return 0 if not findings else 1


if __name__ == "__main__":
    raise SystemExit(main())
