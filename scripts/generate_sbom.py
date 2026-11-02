#!/usr/bin/env python3
"""Generate a deterministic CycloneDX 1.5 SBOM from built release artifacts.

The generator reads the actual wheel and source distribution, not
``pyproject.toml``. It takes the package name, version, license expression, and
``Requires-Python`` from the distribution metadata, requires that every
distribution declares no runtime dependency, and records each artifact with its
SHA-256. The output is byte-identical for the same artifacts and the same
``--created`` value (or the same ``SOURCE_DATE_EPOCH``).

This is a stdlib-only script; it adds no runtime dependency to the package.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tarfile
import uuid
import zipfile
from datetime import datetime, timezone
from email import message_from_string
from email.message import Message
from pathlib import Path

SCHEMA = "cyclonedx-1.5"
BOM_FORMAT = "CycloneDX"
SPEC_VERSION = "1.5"
GENERATOR_NAME = "pr-review-harness-sbom"
GENERATOR_VERSION = "1.0.0"
REQUIRED_LICENSE = "MIT"
SERIAL_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_URL, "https://github.com/grokopus/codereview/sbom")
WHEEL_SUFFIX = ".whl"
SDIST_SUFFIX = ".tar.gz"


class SupplyChainError(Exception):
    """A release artifact cannot be described truthfully."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def discover_artifacts(dist: Path) -> list[Path]:
    """Return the wheel and source distribution files, sorted by file name."""

    if not dist.is_dir():
        raise SupplyChainError(f"distribution directory not found: {dist}")
    artifacts = sorted(
        (path for path in dist.iterdir() if path.is_file() and path.name.endswith((WHEEL_SUFFIX, SDIST_SUFFIX))),
        key=lambda path: path.name,
    )
    if not artifacts:
        raise SupplyChainError(f"no wheel or source distribution found under {dist}")
    return artifacts


def _metadata_message(raw: str, artifact: Path) -> Message:
    message = message_from_string(raw)
    if message.get("Name") is None or message.get("Version") is None:
        raise SupplyChainError(f"{artifact.name}: distribution metadata has no Name/Version")
    return message


def read_wheel_metadata(path: Path) -> Message:
    try:
        with zipfile.ZipFile(path) as archive:
            names = sorted(name for name in archive.namelist() if name.endswith(".dist-info/METADATA"))
            if len(names) != 1:
                raise SupplyChainError(f"{path.name}: expected exactly one .dist-info/METADATA, found {len(names)}")
            return _metadata_message(archive.read(names[0]).decode("utf-8"), path)
    except (OSError, zipfile.BadZipFile, UnicodeDecodeError) as error:
        raise SupplyChainError(f"{path.name}: cannot read wheel metadata: {error}") from error


def read_sdist_metadata(path: Path) -> Message:
    try:
        with tarfile.open(path, "r:gz") as archive:
            names = sorted(
                member.name
                for member in archive.getmembers()
                if member.name.count("/") == 1 and member.name.endswith("/PKG-INFO")
            )
            if len(names) != 1:
                raise SupplyChainError(f"{path.name}: expected exactly one top-level PKG-INFO, found {len(names)}")
            extracted = archive.extractfile(names[0])
            if extracted is None:
                raise SupplyChainError(f"{path.name}: PKG-INFO is not a regular file")
            return _metadata_message(extracted.read().decode("utf-8"), path)
    except (OSError, tarfile.TarError, UnicodeDecodeError) as error:
        raise SupplyChainError(f"{path.name}: cannot read source distribution metadata: {error}") from error


def read_artifact_metadata(path: Path) -> Message:
    if path.name.endswith(WHEEL_SUFFIX):
        return read_wheel_metadata(path)
    if path.name.endswith(SDIST_SUFFIX):
        return read_sdist_metadata(path)
    raise SupplyChainError(f"{path.name}: unsupported distribution artifact")


def _marker(message: Message, name: str) -> str:
    return str(message.get(name) or "")


def runtime_requirements(message: Message) -> list[str]:
    """Return ``Requires-Dist`` entries that are not guarded by an extra."""

    runtime: list[str] = []
    for requirement in message.get_all("Requires-Dist") or []:
        text = str(requirement).strip()
        marker = text.split(";", 1)[1].strip().lower() if ";" in text else ""
        if "extra ==" in marker or "extra==" in marker:
            continue
        runtime.append(text)
    return runtime


def license_identifier(message: Message) -> str:
    expression = str(message.get("License-Expression") or "").strip()
    if expression:
        return expression
    declared = str(message.get("License") or "").strip()
    if declared:
        return declared
    for classifier in message.get_all("Classifier") or []:
        if str(classifier).strip().endswith("MIT License"):
            return REQUIRED_LICENSE
    return ""


def describe_artifact(path: Path) -> dict[str, object]:
    message = read_artifact_metadata(path)
    requires_python = _marker(message, "Requires-Python").strip()
    runtime = runtime_requirements(message)
    return {
        "name": str(message.get("Name")).strip(),
        "version": str(message.get("Version")).strip(),
        "license": license_identifier(message),
        "requires_python": requires_python,
        "runtime_requirements": runtime,
        "sha256": sha256_file(path),
        "size": path.stat().st_size,
        "kind": "wheel" if path.name.endswith(WHEEL_SUFFIX) else "sdist",
    }


def _validate_artifact_set(artifacts: list[Path]) -> tuple[str, str, str, str]:
    descriptions = [describe_artifact(path) for path in artifacts]
    names = {str(item["name"]) for item in descriptions}
    versions = {str(item["version"]) for item in descriptions}
    licenses = {str(item["license"]) for item in descriptions}
    requires_python = {str(item["requires_python"]) for item in descriptions}
    if len(names) != 1:
        raise SupplyChainError(f"distribution artifacts disagree on package name: {sorted(names)}")
    if len(versions) != 1:
        raise SupplyChainError(f"distribution artifacts disagree on package version: {sorted(versions)}")
    if len(requires_python) != 1 or not next(iter(requires_python)):
        raise SupplyChainError(f"distribution artifacts must declare one non-empty Requires-Python: {sorted(requires_python)}")
    if licenses != {REQUIRED_LICENSE}:
        raise SupplyChainError(f"expected license {REQUIRED_LICENSE!r} in every artifact, found {sorted(licenses)}")
    for path, description in zip(artifacts, descriptions, strict=True):
        if description["runtime_requirements"]:
            raise SupplyChainError(
                f"{path.name}: runtime dependency declared, but this package must have zero: "
                f"{description['runtime_requirements']}"
            )
    return next(iter(names)), next(iter(versions)), next(iter(licenses)), next(iter(requires_python))


def epoch_to_created(epoch: str | int | None) -> str | None:
    if epoch is None or str(epoch).strip() == "":
        return None
    try:
        value = int(str(epoch).strip())
    except ValueError as error:
        raise SupplyChainError(f"SOURCE_DATE_EPOCH must be an integer, got {epoch!r}") from error
    return datetime.fromtimestamp(value, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def resolved_created(created: str | None) -> str | None:
    """Resolve an explicit ISO timestamp, else SOURCE_DATE_EPOCH, else nothing."""

    value = (created or "").strip()
    if not value and os.environ.get("SOURCE_DATE_EPOCH"):
        value = epoch_to_created(os.environ["SOURCE_DATE_EPOCH"]) or ""
    if not value:
        return None
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as error:
        raise SupplyChainError(f"--created must be an ISO-8601 UTC timestamp such as 1970-01-01T00:00:00Z: {value!r}") from error
    return value


def build_document(dist: Path, created: str | None = None) -> dict[str, object]:
    artifacts = discover_artifacts(dist)
    name, version, license_id, requires_python = _validate_artifact_set(artifacts)
    components: list[dict[str, object]] = []
    for path in artifacts:
        description = describe_artifact(path)
        components.append(
            {
                "type": "file",
                "bom-ref": f"urn:sha256:{description['sha256']}",
                "name": path.name,
                "hashes": [{"alg": "SHA-256", "content": description["sha256"]}],
                "properties": [
                    {"name": "pr-review-harness:artifact-kind", "value": description["kind"]},
                    {"name": "pr-review-harness:size-bytes", "value": str(description["size"])},
                ],
            }
        )

    canonical = "\n".join(
        f"{name}@{version}:{component['name']}:{component['hashes'][0]['content']}" for component in components
    )
    document: dict[str, object] = {
        "bomFormat": BOM_FORMAT,
        "specVersion": SPEC_VERSION,
        "serialNumber": f"urn:uuid:{uuid.uuid5(SERIAL_NAMESPACE, canonical)}",
        "version": 1,
        "metadata": {
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": GENERATOR_NAME,
                        "version": GENERATOR_VERSION,
                    }
                ]
            },
            "component": {
                "type": "library",
                "bom-ref": f"pkg:pypi/{name}@{version}",
                "name": name,
                "version": version,
                "purl": f"pkg:pypi/{name}@{version}",
                "licenses": [{"license": {"id": license_id}}],
                "properties": [
                    {"name": "pr-review-harness:requires-python", "value": requires_python},
                    {"name": "pr-review-harness:runtime-dependencies", "value": "0"},
                    {"name": "pr-review-harness:distribution-artifacts", "value": str(len(artifacts))},
                ],
            },
        },
        "components": components,
        "dependencies": [
            {
                "ref": f"pkg:pypi/{name}@{version}",
                "dependsOn": [str(component["bom-ref"]) for component in components],
            }
        ],
    }
    if created is not None:
        document["metadata"]["timestamp"] = created  # type: ignore[index]
    return document


def write_document(document: dict[str, object], output: Path) -> None:
    text = json.dumps(document, indent=2, sort_keys=True) + "\n"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(text, encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dist", type=Path, required=True, help="directory containing the wheel and sdist")
    parser.add_argument("--output", type=Path, required=True, help="CycloneDX JSON output path")
    parser.add_argument(
        "--created",
        help="ISO-8601 UTC timestamp for metadata.timestamp; defaults to SOURCE_DATE_EPOCH, and is omitted when neither is set",
    )
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)

    try:
        created = resolved_created(args.created)
        document = build_document(args.dist, created=created)
        write_document(document, args.output)
    except SupplyChainError as error:
        print(f"SBOM generation failed: {error}", file=sys.stderr)
        return 1
    if not args.quiet:
        component = document["metadata"]["component"]  # type: ignore[index]
        print(
            f"CycloneDX SBOM: {args.output} "
            f"({component['name']} {component['version']}, {len(document['components'])} artifacts, "
            f"license {component['licenses'][0]['license']['id']}, zero runtime dependencies)"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
