"""RS-2: changelog structure and deterministic change classification."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from check_changelog import (  # noqa: E402
    classify_message,
    parse_changelog,
    release_for,
    version_key,
)


def _write(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    return path


@pytest.mark.parametrize(
    ("message", "category"),
    [
        ("feat(cli): add a JSON stats export", "Added"),
        ("fix: reject an empty base revision", "Fixed"),
        ("perf: avoid copying the source tree", "Changed"),
        ("refactor: split the reducer", "Changed"),
        ("docs: explain the release gate", "Changed"),
        ("deprecate: mark the legacy limits profile", "Deprecated"),
        ("remove: drop the old receipt", "Removed"),
        ("security: reject credential-bearing URLs", "Security"),
        ("feat!: drop the legacy review flag", "Breaking"),
        ("fix: handle a stale tag\n\nBREAKING CHANGE: tags are now immutable", "Breaking"),
    ],
)
def test_classification_maps_conventional_types(message: str, category: str) -> None:
    assert classify_message(message) == category


@pytest.mark.parametrize(
    "message",
    ["", "merge branch 'main'", "Update README", "feat add missing colon"],
)
def test_unknown_messages_are_not_guessed(message: str) -> None:
    assert classify_message(message) is None


def test_repository_changelog_is_structurally_valid() -> None:
    releases, findings = parse_changelog(ROOT / "CHANGELOG.md")
    assert findings == []
    assert releases[0].version == "Unreleased"
    assert release_for(releases, "0.1.0") is not None


def test_parser_rejects_missing_unreleased_and_unknown_categories(tmp_path: Path) -> None:
    path = _write(
        tmp_path / "CHANGELOG.md",
        "# Changelog\n\n## [0.1.0] - 2026-11-02\n### Misc\n- unclassified entry\n",
    )
    _, findings = parse_changelog(path)
    assert any("Unreleased" in finding for finding in findings)
    assert any("unknown changelog category" in finding for finding in findings)


def test_parser_rejects_entries_outside_a_category_and_empty_categories(tmp_path: Path) -> None:
    path = _write(
        tmp_path / "CHANGELOG.md",
        "# Changelog\n\n## [Unreleased]\n- loose entry\n\n## [0.1.0] - 2026-11-02\n### Added\n",
    )
    _, findings = parse_changelog(path)
    assert any("outside a changelog category" in finding for finding in findings)
    assert any("has no entries" in finding for finding in findings)


def test_parser_rejects_missing_dates_duplicates_and_ordering(tmp_path: Path) -> None:
    path = _write(
        tmp_path / "CHANGELOG.md",
        (
            "# Changelog\n\n## [Unreleased]\n\n"
            "## [0.1.0] - 2026-11-02\n### Added\n- older\n\n"
            "## [0.2.0]\n### Added\n- newer without a date\n\n"
            "## [0.1.0] - 2026-11-01\n### Fixed\n- duplicate\n"
        ),
    )
    _, findings = parse_changelog(path)
    assert any("needs a YYYY-MM-DD date" in finding for finding in findings)
    assert any("duplicate released version" in finding for finding in findings)
    assert any("newest first" in finding for finding in findings)


def test_release_body_contains_only_classified_entries(tmp_path: Path) -> None:
    path = _write(
        tmp_path / "CHANGELOG.md",
        "# Changelog\n\n## [Unreleased]\n\n## [0.1.0] - 2026-11-02\n### Added\n- one\n\n### Fixed\n- two\n",
    )
    releases, findings = parse_changelog(path)
    assert findings == []
    assert releases[1].body() == "### Added\n- one\n\n### Fixed\n- two\n"


def test_version_key_orders_final_release_after_prerelease() -> None:
    assert version_key("0.1.0") > version_key("0.1.0-rc1")
    assert version_key("0.2.0") > version_key("0.1.9")


def test_repository_changelog_makes_no_quality_or_replacement_claims() -> None:
    text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8").lower()
    for phrase in ("production-ready", "production ready", "replaces droid", "replacement for droid", "fully replaces"):
        assert phrase not in text


def test_cli_classify_is_scriptable_and_exits_nonzero_for_unknown_types() -> None:
    script = ROOT / "scripts/check_changelog.py"
    known = subprocess.run(
        [sys.executable, str(script), "--classify", "feat(cli): add output", "--json"],
        check=False,
        text=True,
        capture_output=True,
    )
    assert known.returncode == 0
    assert json.loads(known.stdout)["category"] == "Added"

    unknown = subprocess.run(
        [sys.executable, str(script), "--classify", "merge branch 'main'"],
        check=False,
        text=True,
        capture_output=True,
    )
    assert unknown.returncode == 1
    assert unknown.stdout.strip() == "unclassified"



def test_version_key_uses_semver_prerelease_rules() -> None:
    assert version_key("0.1.0-rc.10") > version_key("0.1.0-rc.9")
    assert version_key("0.1.0-1") < version_key("0.1.0-alpha")
    assert version_key("0.1.0-alpha") < version_key("0.1.0-alpha.1")
