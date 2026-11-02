#!/usr/bin/env python3
"""Enforce release metadata consistency.

Checks the package version, changelog, tag shape, and contract registry against
``scripts/release-policy.v1.json``. The release workflow invokes this with an
explicit ``--tag`` before it builds or publishes anything; the repository test
suite invokes it without a tag so version-only changes fail early.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from check_changelog import (  # noqa: E402
    BREAKING_CATEGORIES,
    CATEGORIES,
    SEMVER_RE,
    parse_changelog,
    release_for,
    version_key,
)

POLICY_SCHEMA = "release-policy.v1"
REGISTRY_VERSION_RE = re.compile(r"^[a-z0-9][a-z0-9.-]*\.v[0-9]+$")


def _read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _git(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["git", "-C", str(root), *args], check=False, text=True, capture_output=True)


def _git_tags(root: Path) -> list[str]:
    completed = _git(root, "tag", "--list", "v*")
    if completed.returncode != 0:
        return []
    return sorted(tag for tag in completed.stdout.splitlines() if tag)


def _tag_exists(root: Path, tag: str) -> bool:
    completed = _git(root, "rev-parse", "--verify", f"refs/tags/{tag}^{{commit}}")
    return completed.returncode == 0


def _check_policy(root: Path, policy: dict, findings: list[str]) -> None:
    if policy.get("schema") != POLICY_SCHEMA:
        findings.append(f"release policy: schema must be {POLICY_SCHEMA!r}")
    package = policy.get("package")
    if not isinstance(package, dict):
        findings.append("release policy: package must be an object")
        return
    for key in ("name", "version_source", "tag_prefix", "changelog"):
        if not isinstance(package.get(key), str) or not package[key]:
            findings.append(f"release policy: package.{key} must be a non-empty string")
    if package.get("tag_prefix") != "v":
        findings.append("release policy: only the 'v' tag prefix is supported by the release workflow")
    changelog_policy = policy.get("changelog")
    if not isinstance(changelog_policy, dict):
        findings.append("release policy: changelog must be an object")
    else:
        if sorted(changelog_policy.get("categories", [])) != sorted(CATEGORIES):
            findings.append("release policy: changelog.categories must match the checker's categories")
        if sorted(changelog_policy.get("breaking_categories", [])) != sorted(BREAKING_CATEGORIES):
            findings.append("release policy: changelog.breaking_categories must match the checker's categories")
    for relative in (package.get("version_source"), package.get("changelog")):
        if isinstance(relative, str) and not (root / relative).is_file():
            findings.append(f"release policy: referenced file is missing: {relative}")


def _check_registry(root: Path, policy: dict, findings: list[str]) -> None:
    contracts_policy = policy.get("contracts")
    if not isinstance(contracts_policy, dict):
        findings.append("release policy: contracts must be an object")
        return
    registry_path = root / str(contracts_policy.get("registry", ""))
    schema_path = root / str(contracts_policy.get("registry_schema", ""))
    for path, label in ((registry_path, "registry"), (schema_path, "registry schema")):
        if not path.is_file():
            findings.append(f"release policy: {label} file is missing: {path.relative_to(root)}")
            return

    try:
        registry = _read_json(registry_path)
        schema = _read_json(schema_path)
    except (OSError, json.JSONDecodeError) as error:
        findings.append(f"contract registry: cannot read registry or schema: {error}")
        return

    registry_version = registry.get("registry_version")
    if not isinstance(registry_version, str) or not REGISTRY_VERSION_RE.match(registry_version):
        findings.append("contract registry: registry_version must be a name with a .vN suffix")
        return
    if not schema_path.name.startswith(f"{registry_version}.schema.json"):
        findings.append(
            f"contract registry: schema file {schema_path.name} does not match registry_version {registry_version}"
        )
    const = schema.get("properties", {}).get("registry_version", {}).get("const")
    if const != registry_version:
        findings.append(
            f"contract registry: schema const {const!r} does not match registry_version {registry_version!r}"
        )

    entries = registry.get("contracts")
    if not isinstance(entries, list) or not entries:
        findings.append("contract registry: contracts must be a non-empty array")
        return
    identities: list[tuple[str, str]] = []
    kinds: set[str] = set()
    artifact_ids: set[str] = set()
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            findings.append(f"contract registry: contracts[{index}] must be an object")
            continue
        name, kind, version = entry.get("name"), entry.get("kind"), entry.get("version")
        if not all(isinstance(value, str) and value for value in (name, kind, version)):
            findings.append(f"contract registry: contracts[{index}] needs non-empty name, kind, and version")
            continue
        identities.append((kind, name))
        kinds.add(kind)
        if kind == "artifact":
            artifact_ids.add(version)
    if len(identities) != len(set(identities)):
        findings.append("contract registry: duplicate (kind, name) contract identities")

    for kind in contracts_policy.get("required_kinds", []):
        if kind not in kinds:
            findings.append(f"contract registry: required contract kind {kind!r} is absent")
    if ("registry", registry_version) not in identities:
        findings.append(f"contract registry: no registry entry names registry_version {registry_version!r}")

    declared_artifacts = set(contracts_policy.get("artifact_contract_ids", []))
    for contract_id in sorted(declared_artifacts - artifact_ids):
        findings.append(f"release policy: artifact contract {contract_id!r} is not registered as kind 'artifact'")
    for contract_id in sorted(artifact_ids - declared_artifacts):
        findings.append(f"release policy: registered artifact contract {contract_id!r} is not declared in policy")

    schema_glob = sorted(path.relative_to(root).as_posix() for path in (root / "schemas").glob("*.schema.json"))
    declared_schemas = set(contracts_policy.get("artifact_schemas", []))
    for relative in sorted(set(schema_glob) - declared_schemas):
        findings.append(f"release policy: schema {relative} is not declared in artifact_schemas")
    for relative in sorted(declared_schemas - set(schema_glob)):
        findings.append(f"release policy: declared schema {relative} does not exist under schemas/")
    for relative in sorted(set(schema_glob) & declared_schemas):
        try:
            artifact_schema = _read_json(root / relative)
        except (OSError, json.JSONDecodeError) as error:
            findings.append(f"schema {relative}: cannot read: {error}")
            continue
        schema_id = artifact_schema.get("$id")
        if not isinstance(schema_id, str) or not schema_id.endswith(Path(relative).name):
            findings.append(f"schema {relative}: $id must end with its filename")
        properties = artifact_schema.get("properties", {})
        for key in ("schema", "contract_version"):
            value = properties.get(key, {}).get("const") if isinstance(properties.get(key), dict) else None
            if isinstance(value, str) and not Path(relative).name.startswith(value):
                findings.append(f"schema {relative}: {key} const {value!r} does not match the filename")


def _check_tags(root: Path, package_version: str, tag: str | None, releases, findings: list[str]) -> None:
    versions = {release.version for release in releases}
    for candidate in _git_tags(root):
        tag_version = candidate[1:]
        if not SEMVER_RE.match(tag_version):
            findings.append(f"git tag {candidate!r} is not a semantic version tag")
            continue
        if tag_version not in versions:
            findings.append(f"git tag {candidate!r} has no CHANGELOG.md release entry")
        if version_key(tag_version) > version_key(package_version):
            findings.append(f"git tag {candidate!r} is newer than the package version {package_version}")
    if tag is None:
        return
    if not tag.startswith("v") or not SEMVER_RE.match(tag[1:]):
        findings.append(f"release tag {tag!r} must be 'v' followed by a semantic version")
        return
    tag_version = tag[1:]
    if tag_version != package_version:
        findings.append(f"release tag {tag!r} does not match the package version {package_version!r}")
    if tag_version not in versions:
        findings.append(f"release tag {tag!r} has no CHANGELOG.md release entry")
    if not _tag_exists(root, tag):
        findings.append(f"release tag {tag!r} does not exist; the release workflow never creates tags")


def check_repository(
    root: Path,
    *,
    policy_path: Path | None = None,
    tag: str | None = None,
    notes_out: Path | None = None,
) -> list[str]:
    """Return every release-metadata problem found under ``root``."""

    root = root.resolve()
    policy_path = policy_path or root / "scripts" / "release-policy.v1.json"
    findings: list[str] = []
    if not policy_path.is_file():
        return [f"release policy not found: {policy_path}"]
    try:
        policy = _read_json(policy_path)
    except (OSError, json.JSONDecodeError) as error:
        return [f"release policy cannot be read: {error}"]

    _check_policy(root, policy, findings)
    package = policy.get("package", {}) if isinstance(policy.get("package"), dict) else {}
    version_source = root / str(package.get("version_source", "pyproject.toml"))
    changelog_path = root / str(package.get("changelog", "CHANGELOG.md"))
    if not version_source.is_file():
        return findings + [f"package version source not found: {version_source.relative_to(root)}"]
    try:
        project = tomllib.loads(version_source.read_text(encoding="utf-8")).get("project", {})
    except (OSError, tomllib.TOMLDecodeError) as error:
        return findings + [f"pyproject.toml cannot be read: {error}"]

    version = project.get("version")
    if project.get("name") != package.get("name"):
        findings.append(f"pyproject.toml: project name {project.get('name')!r} does not match release policy")
    if not isinstance(version, str) or not SEMVER_RE.match(version):
        findings.append(f"pyproject.toml: version {version!r} is not a semantic version")
        return findings

    releases = []
    if not changelog_path.is_file():
        findings.append(f"changelog not found: {changelog_path.relative_to(root)}")
    else:
        releases, changelog_findings = parse_changelog(changelog_path)
        findings.extend(changelog_findings)
        if not release_for(releases, version):
            findings.append(f"CHANGELOG.md: package version {version!r} has no release section")
        released = [
            release for release in releases if release.version != "Unreleased" and SEMVER_RE.match(release.version)
        ]
        if released:
            newest = max(released, key=lambda release: version_key(release.version))
            if newest.version != version:
                findings.append(
                    f"CHANGELOG.md: newest released version {newest.version!r} does not match package version {version!r}"
                )

    _check_registry(root, policy, findings)
    _check_tags(root, version, tag, releases, findings)

    if notes_out is not None:
        release = release_for(releases, version)
        if release is None:
            findings.append(f"cannot write release notes: no CHANGELOG.md section for {version!r}")
        else:
            notes_out.parent.mkdir(parents=True, exist_ok=True)
            notes_out.write_text(release.body(), encoding="utf-8")
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--policy", type=Path)
    parser.add_argument("--tag", help="release tag that must exist and match the package version")
    parser.add_argument("--notes-out", type=Path, help="write the matching changelog section as release notes")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    findings = check_repository(
        args.root,
        policy_path=args.policy,
        tag=args.tag,
        notes_out=args.notes_out,
    )
    if args.json:
        print(json.dumps({"ok": not findings, "findings": findings, "tag": args.tag}, sort_keys=True))
    elif findings:
        for finding in findings:
            print(finding)
    else:
        print("release metadata ok")
    return 0 if not findings else 1


if __name__ == "__main__":
    raise SystemExit(main())
