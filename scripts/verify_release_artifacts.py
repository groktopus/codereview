#!/usr/bin/env python3
"""Verify release artifacts against their checksums, SBOM, and provenance.

This is the consumer-side check for a published release. It recomputes the
SHA-256 of every wheel and source distribution and compares it with
``SHA256SUMS``, the CycloneDX SBOM, and the provenance subjects. It also checks
the SBOM's package metadata (name, version, MIT license, zero runtime
dependencies, Python requirement) against the distribution metadata itself.

The provenance may be unsigned. This script reports ``signed: false`` and does
not cryptographically verify signatures. ``--require-signed`` therefore always
fails until signature verification is implemented; a claimed signed status is
reported as present-but-unverified, never as a passing signature check.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from generate_sbom import (  # noqa: E402
    REQUIRED_LICENSE,
    SupplyChainError,
    discover_artifacts,
    license_identifier,
    read_artifact_metadata,
    runtime_requirements,
    sha256_file,
)


class VerificationError(Exception):
    """The release evidence is incomplete or inconsistent."""


def parse_checksums(path: Path) -> dict[str, str]:
    if not path.is_file():
        raise VerificationError(f"checksum file not found: {path}")
    entries: dict[str, str] = {}
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        parts = line.split(maxsplit=1)
        if len(parts) != 2 or len(parts[0]) != 64:
            raise VerificationError(f"{path.name}:{number}: expected '<sha256>  <file>'")
        digest, name = parts[0].lower(), parts[1].strip()
        if name.startswith("*"):
            name = name[1:]
        if name.startswith("./"):
            name = name[2:]
        if name in entries:
            raise VerificationError(f"{path.name}:{number}: duplicate checksum entry for {name}")
        entries[name] = digest
    if not entries:
        raise VerificationError(f"{path.name}: no checksum entries")
    return entries


def _artifact_hashes(dist: Path) -> dict[str, str]:
    return {path.name: sha256_file(path) for path in discover_artifacts(dist)}


def _sbom_failures(sbom_path: Path, expected: dict[str, str], dist: Path) -> list[str]:
    failures: list[str] = []
    if not sbom_path.is_file():
        return [f"SBOM not found: {sbom_path}"]
    try:
        document = json.loads(sbom_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        return [f"SBOM cannot be read: {error}"]
    if document.get("bomFormat") != "CycloneDX" or document.get("specVersion") not in {"1.5", "1.6"}:
        failures.append("SBOM is not CycloneDX 1.5/1.6")
    component = document.get("metadata", {}).get("component", {})
    artifacts = discover_artifacts(dist)
    expected_name = expected_version = ""
    if artifacts:
        first = read_artifact_metadata(artifacts[0])
        expected_name, expected_version = str(first.get("Name")), str(first.get("Version"))
    if expected_name and component.get("name") != expected_name:
        failures.append(f"SBOM package name is {component.get('name')!r}, expected {expected_name!r}")
    if expected_version and component.get("version") != expected_version:
        failures.append(f"SBOM package version is {component.get('version')!r}, expected {expected_version!r}")
    licenses = [item.get("license", {}).get("id") for item in component.get("licenses", [])]
    if licenses != [REQUIRED_LICENSE]:
        failures.append(f"SBOM licenses are {licenses!r}, expected ['{REQUIRED_LICENSE}']")
    properties = {item.get("name"): item.get("value") for item in component.get("properties", [])}
    if properties.get("pr-review-harness:runtime-dependencies") != "0":
        failures.append("SBOM does not record zero runtime dependencies")
    if not properties.get("pr-review-harness:requires-python"):
        failures.append("SBOM does not record the Python requirement")

    sbom_hashes: dict[str, str] = {}
    for item in document.get("components", []):
        hashes = item.get("hashes") or []
        sha256 = [entry.get("content") for entry in hashes if entry.get("alg") == "SHA-256"]
        if len(sha256) != 1:
            failures.append(f"SBOM component {item.get('name')!r} does not have exactly one SHA-256")
            continue
        sbom_hashes[str(item.get("name"))] = str(sha256[0])
    if sbom_hashes != expected:
        failures.append(f"SBOM artifact hashes do not match the distributions: {sbom_hashes} != {expected}")

    for artifact in artifacts:
        message = read_artifact_metadata(artifact)
        if str(message.get("Name")) != component.get("name") or str(message.get("Version")) != component.get("version"):
            failures.append(f"{artifact.name}: distribution metadata disagrees with the SBOM package identity")
        if license_identifier(message) != REQUIRED_LICENSE:
            failures.append(f"{artifact.name}: distribution license is not {REQUIRED_LICENSE}")
        if runtime_requirements(message):
            failures.append(f"{artifact.name}: distribution declares runtime dependencies")
    return failures


def _provenance_result(
    provenance_path: Path, expected: dict[str, str], require_signed: bool
) -> tuple[list[str], bool, list[str]]:
    failures: list[str] = []
    notes: list[str] = []
    if not provenance_path.is_file():
        return [f"provenance not found: {provenance_path}"], False, notes
    try:
        document = json.loads(provenance_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        return [f"provenance cannot be read: {error}"], False, notes
    if document.get("_type") != "https://in-toto.io/Statement/v1":
        failures.append("provenance is not an in-toto Statement v1")
    if document.get("predicateType") != "https://slsa.dev/provenance/v1":
        failures.append("provenance does not carry an SLSA provenance v1 predicate type")
    subjects: dict[str, str] = {}
    for item in document.get("subject", []):
        digest = item.get("digest", {})
        if digest.get("sha256"):
            subjects[str(item.get("name"))] = str(digest["sha256"])
    if subjects != expected:
        failures.append(f"provenance subjects do not match the distributions: {subjects} != {expected}")
    signing = document.get("signing") or {}
    signed = signing.get("status") == "signed" and bool(signing.get("signature"))
    if signing.get("status") not in {"signed", "unsigned"}:
        failures.append(f"provenance signing status is {signing.get('status')!r}, expected 'signed' or 'unsigned'")
    if signing.get("status") == "signed" and not signing.get("signature"):
        failures.append("provenance claims a signed status but has no signature value")
    if require_signed:
        failures.append(
            "cryptographic signature verification is not implemented; refusing to accept a claimed signature"
        )
    if signed:
        notes.append("provenance declares a signature; this stdlib script does not cryptographically verify it")
    else:
        notes.append("provenance is unsigned: hashes are inspectable but origin is not authenticated")
    if not document.get("predicate"):
        failures.append("provenance has no predicate")
    return failures, signed, notes


def verify(
    dist: Path,
    *,
    sbom: Path,
    provenance: Path,
    checksums: Path | None = None,
    source_revision: str | None = None,
    workflow_ref: str | None = None,
    require_signed: bool = False,
) -> dict[str, object]:
    failures: list[str] = []
    notes: list[str] = []
    actual = _artifact_hashes(dist)
    if not actual:
        failures.append("no wheel or source distribution found")
    checks: list[dict[str, str]] = []

    if checksums is not None:
        checksum_failures: list[str] = []
        try:
            entries = parse_checksums(checksums)
        except VerificationError as error:
            checksum_failures.append(str(error))
            entries = {}
        for name, digest in entries.items():
            path = dist / name
            if not path.is_file():
                checksum_failures.append(f"checksum entry names a missing file: {name}")
                continue
            if sha256_file(path) != digest:
                checksum_failures.append(f"checksum mismatch for {name}")
        missing = sorted(set(actual) - set(entries))
        if missing:
            checksum_failures.append(f"checksum file does not cover distribution artifacts: {missing}")
        for label, path in (("SBOM", sbom), ("provenance", provenance)):
            if path.resolve().parent != dist.resolve():
                checksum_failures.append(f"{label} path is outside the checksummed dist directory")
            elif path.name not in entries:
                checksum_failures.append(f"checksum file does not cover the {label} asset")
        failures.extend(checksum_failures)
        checks.append({"check": "sha256sums", "status": "FAIL" if checksum_failures else "PASS"})

    sbom_failures = _sbom_failures(sbom, actual, dist)
    failures.extend(sbom_failures)
    checks.append({"check": "sbom", "status": "FAIL" if sbom_failures else "PASS"})

    provenance_failures, signed, provenance_notes = _provenance_result(provenance, actual, require_signed)
    failures.extend(provenance_failures)
    notes.extend(provenance_notes)
    checks.append({"check": "provenance", "status": "FAIL" if provenance_failures else "PASS"})

    if source_revision or workflow_ref:
        try:
            document = json.loads(provenance.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            document = {}
        external = document.get("predicate", {}).get("buildDefinition", {}).get("externalParameters", {})
        recorded_revision = external.get("source", {}).get("revision")
        recorded_workflow = external.get("workflow", {}).get("ref")
        identity_failures: list[str] = []
        if source_revision and recorded_revision != source_revision:
            identity_failures.append(
                f"provenance source revision {recorded_revision!r} != expected {source_revision!r}"
            )
        if workflow_ref and recorded_workflow != workflow_ref:
            identity_failures.append(f"provenance workflow ref {recorded_workflow!r} != expected {workflow_ref!r}")
        failures.extend(identity_failures)
        checks.append({"check": "provenance_identity", "status": "FAIL" if identity_failures else "PASS"})

    return {
        "status": "FAIL" if failures else "PASS",
        "signed": signed,
        "checks": checks,
        "failures": failures,
        "notes": notes,
        "artifacts": actual,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dist", type=Path, required=True, help="directory containing the released wheel and sdist")
    parser.add_argument("--sbom", type=Path, required=True, help="CycloneDX SBOM asset")
    parser.add_argument("--provenance", type=Path, required=True, help="provenance asset")
    parser.add_argument("--checksums", type=Path, help="SHA256SUMS asset")
    parser.add_argument("--source-revision", help="expected source commit recorded in provenance")
    parser.add_argument("--workflow-ref", help="expected workflow reference recorded in provenance")
    parser.add_argument(
        "--require-signed",
        action="store_true",
        help="always fail until cryptographic signature verification is implemented",
    )
    parser.add_argument("--json", action="store_true", help="print the full result as JSON")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)

    try:
        result = verify(
            args.dist,
            sbom=args.sbom,
            provenance=args.provenance,
            checksums=args.checksums,
            source_revision=args.source_revision,
            workflow_ref=args.workflow_ref,
            require_signed=args.require_signed,
        )
    except (SupplyChainError, OSError) as error:
        print(f"release verification failed: {error}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    elif not args.quiet:
        print(f"Release verification: {result['status']} (signed: {'yes' if result['signed'] else 'no'})")
        for check in result["checks"]:  # type: ignore[union-attr]
            print(f"  {check['check']}: {check['status']}")
        for failure in result["failures"]:  # type: ignore[union-attr]
            print(f"  FAIL: {failure}")
        for note in result["notes"]:  # type: ignore[union-attr]
            print(f"  note: {note}")
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
