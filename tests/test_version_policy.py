"""RS-2: package, changelog, tag, and contract-registry consistency."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from check_changelog import parse_changelog, release_for  # noqa: E402
from check_version_policy import check_repository  # noqa: E402

PACKAGE_NAME = "pr-review-harness"


def _changelog(version: str = "0.1.0") -> str:
    return (
        "# Changelog\n\n"
        "## [Unreleased]\n\n"
        "No unreleased changes.\n\n"
        f"## [{version}] - 2026-11-02\n\n"
        "### Added\n\n"
        "- Initial release fixture.\n"
    )


def _policy() -> dict:
    return json.loads((ROOT / "scripts/release-policy.v1.json").read_text(encoding="utf-8"))


def _make_root(
    tmp_path: Path,
    *,
    version: str = "0.1.0",
    changelog_version: str | None = None,
    policy: dict | None = None,
) -> Path:
    root = tmp_path
    (root / "src" / "pr_review_harness").mkdir(parents=True)
    shutil.copy2(ROOT / "src/pr_review_harness/contract_registry.json", root / "src/pr_review_harness")
    shutil.copytree(ROOT / "schemas", root / "schemas")
    (root / "scripts").mkdir()
    (root / "pyproject.toml").write_text(
        f'[project]\nname = "{PACKAGE_NAME}"\nversion = "{version}"\n',
        encoding="utf-8",
    )
    (root / "CHANGELOG.md").write_text(_changelog(changelog_version or version), encoding="utf-8")
    (root / "scripts/release-policy.v1.json").write_text(
        json.dumps(policy or _policy()),
        encoding="utf-8",
    )
    return root


def _git(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["git", *args], cwd=root, check=True, text=True, capture_output=True)


def _commit_fixture(root: Path) -> None:
    _git(root, "init", "-q")
    _git(root, "config", "user.email", "release-test@example.com")
    _git(root, "config", "user.name", "Release Test")
    _git(root, "add", ".")
    _git(root, "commit", "-qm", "fixture")


def test_repository_release_metadata_is_consistent() -> None:
    assert check_repository(ROOT) == []


def test_repository_version_has_attestation_notes() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    assert project["version"] == "0.1.2"

    releases, findings = parse_changelog(ROOT / "CHANGELOG.md")
    assert findings == []
    release = release_for(releases, "0.1.2")
    assert release is not None
    added = " ".join(text for _, text in release.categories.get("Added", []))
    assert "attest-build-provenance" in added
    assert "unsigned" in added.lower()

    notes_path = ROOT / "docs/releases/0.1.2.md"
    assert notes_path.is_file()
    notes = notes_path.read_text(encoding="utf-8")
    assert "gh attestation verify" in notes
    assert "--repo groktopus/codereview" in notes
    assert "v0.1.0" in notes and "remains unsigned" in notes.lower()
    index = (ROOT / "docs/README.md").read_text(encoding="utf-8")
    assert "(releases/0.1.2.md)" in index


def test_temporary_repository_passes_all_checks(tmp_path: Path) -> None:
    root = _make_root(tmp_path)
    assert check_repository(root) == []


def test_version_without_a_matching_changelog_section_is_rejected(tmp_path: Path) -> None:
    root = _make_root(tmp_path, version="0.2.0", changelog_version="0.1.0")
    findings = check_repository(root)
    assert any("has no release section" in finding for finding in findings)
    assert any("newest released version" in finding for finding in findings)


def test_tag_mode_requires_the_exact_existing_tag_and_writes_notes(tmp_path: Path) -> None:
    root = _make_root(tmp_path)
    _commit_fixture(root)

    findings = check_repository(root, tag="v0.1.0")
    assert any("does not exist" in finding for finding in findings)

    _git(root, "tag", "v0.1.0")
    notes = root / "notes.md"
    assert check_repository(root, tag="v0.1.0", notes_out=notes) == []
    assert notes.read_text(encoding="utf-8") == "### Added\n- Initial release fixture.\n"


def test_tag_that_does_not_match_the_package_version_is_rejected(tmp_path: Path) -> None:
    root = _make_root(tmp_path)
    _commit_fixture(root)
    _git(root, "tag", "v0.2.0")
    findings = check_repository(root, tag="v0.2.0")
    assert any("does not match the package version" in finding for finding in findings)
    assert any("newer than the package version" in finding for finding in findings)


def test_tag_without_a_changelog_entry_is_rejected(tmp_path: Path) -> None:
    root = _make_root(tmp_path)
    _commit_fixture(root)
    _git(root, "tag", "v0.0.9")
    findings = check_repository(root)
    assert any("has no CHANGELOG.md release entry" in finding for finding in findings)


def test_undeclared_artifact_schema_is_rejected(tmp_path: Path) -> None:
    root = _make_root(tmp_path)
    (root / "schemas/review-extra.v1.schema.json").write_text(
        json.dumps({"$id": "review-extra.v1.schema.json", "properties": {"schema": {"const": "review-extra.v1"}}}),
        encoding="utf-8",
    )
    findings = check_repository(root)
    assert any("is not declared in artifact_schemas" in finding for finding in findings)


def test_undeclared_artifact_contract_is_rejected(tmp_path: Path) -> None:
    policy = _policy()
    policy["contracts"]["artifact_contract_ids"].append("review-result.v9")
    root = _make_root(tmp_path, policy=policy)
    findings = check_repository(root)
    assert any("is not registered as kind 'artifact'" in finding for finding in findings)


def test_registry_version_must_match_its_schema(tmp_path: Path) -> None:
    root = _make_root(tmp_path)
    registry_path = root / "src/pr_review_harness/contract_registry.json"
    registry = json.loads(registry_path.read_text(encoding="utf-8"))
    registry["registry_version"] = "contract-registry.v2"
    registry_path.write_text(json.dumps(registry), encoding="utf-8")
    findings = check_repository(root)
    assert any("does not match registry_version" in finding for finding in findings)
    assert any("no registry entry names registry_version" in finding for finding in findings)
