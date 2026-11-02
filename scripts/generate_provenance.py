#!/usr/bin/env python3
"""Record inspectable, unsigned build provenance for release artifacts.

The output is an in-toto Statement shaped like SLSA provenance v1. It records
the source revision, workflow reference, builder identity, build command, and
the SHA-256 of every release artifact. It is deliberately unsigned: this script
has no signing key and does not call a Sigstore or GitHub attestation service,
so it marks ``signing.status`` as ``unsigned`` and states the limits in the
document. Do not present it as a verified attestation.

The output is byte-identical for the same arguments and the same ``--created``
value (or ``SOURCE_DATE_EPOCH``). This is a stdlib-only script.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from generate_sbom import (  # noqa: E402
    SupplyChainError,
    discover_artifacts,
    resolved_created,
    sha256_file,
)

SCHEMA = "pr-review-harness-provenance.v1"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://slsa.dev/provenance/v1"
DEFAULT_BUILD_COMMAND = "python -m build --wheel --sdist --outdir dist"
UNSIGNED_REASON = (
    "No signing credential, Sigstore bundle, or GitHub artifact attestation was produced by this build. "
    "This file is inspectable provenance, not a verified attestation."
)
LIMITATIONS = [
    "Unsigned: integrity and origin are not cryptographically authenticated by this file.",
    "The builder identity is self-asserted by the release script; it is not independently verified.",
    "Only the listed wheel and source-distribution bytes are covered. Development dependencies and the "
    "development environment are out of scope.",
    "Bit-for-bit reproducibility is not claimed; see the retained reproducibility report for the observed result.",
]


class ProvenanceError(SupplyChainError):
    """Provenance cannot be recorded truthfully from the supplied inputs."""


def _git_head(root: Path) -> str:
    completed = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"], check=False, text=True, capture_output=True
    )
    if completed.returncode != 0 or not completed.stdout.strip():
        return ""
    return completed.stdout.strip()


def _repository_url(repository: str) -> str:
    value = repository.strip()
    if value.startswith(("http://", "https://")):
        return value.rstrip("/")
    return f"https://github.com/{value}"


def _subjects(dist: Path) -> list[dict[str, object]]:
    artifacts = discover_artifacts(dist)
    return [
        {"name": path.name, "digest": {"sha256": sha256_file(path)}}
        for path in sorted(artifacts, key=lambda item: item.name)
    ]


def build_provenance(
    dist: Path,
    *,
    repository: str,
    source_revision: str,
    source_ref: str,
    workflow_ref: str,
    workflow_sha: str,
    builder_id: str,
    builder_image: str,
    invocation_id: str,
    python_version: str,
    build_command: str,
    created: str | None = None,
    source_date_epoch: int | None = None,
) -> dict[str, object]:
    if not repository.strip():
        raise ProvenanceError("--repository is required (or set GITHUB_REPOSITORY)")
    if not source_revision.strip():
        raise ProvenanceError("--source-revision is required when Git HEAD cannot be resolved")
    if not workflow_ref.strip():
        raise ProvenanceError("--workflow-ref is required")
    if not builder_id.strip():
        raise ProvenanceError("--builder-id is required")

    repository_url = _repository_url(repository)
    subjects = _subjects(dist)
    run_metadata: dict[str, object] = {"invocationId": invocation_id}
    if created is not None:
        run_metadata["startedOn"] = created
    predicate: dict[str, object] = {
        "buildDefinition": {
            "buildType": f"{repository_url}/release-build/v1",
            "externalParameters": {
                "source": {
                    "repository": repository_url,
                    "revision": source_revision,
                    "ref": source_ref,
                },
                "workflow": {"ref": workflow_ref, "sha": workflow_sha},
                "build": {"command": build_command},
            },
            "internalParameters": {
                "pythonVersion": python_version,
                "builderImage": builder_image,
            },
            "resolvedDependencies": [
                {
                    "uri": f"git+{repository_url}@{source_revision}",
                    "digest": {"gitCommit": source_revision},
                }
            ],
        },
        "runDetails": {
            "builder": {"id": builder_id},
            "metadata": run_metadata,
            "byproducts": [],
        },
    }
    if source_date_epoch is not None:
        predicate["buildDefinition"]["externalParameters"]["build"]["sourceDateEpoch"] = str(source_date_epoch)  # type: ignore[index]

    return {
        "schema": SCHEMA,
        "_type": STATEMENT_TYPE,
        "predicateType": PREDICATE_TYPE,
        "subject": subjects,
        "predicate": predicate,
        "signing": {
            "status": "unsigned",
            "signature": None,
            "certificate": None,
            "tool": None,
            "reason": UNSIGNED_REASON,
        },
        "limitations": list(LIMITATIONS),
    }


def write_document(document: dict[str, object], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _default(value: str | None, environment: str) -> str:
    return (value or os.environ.get(environment) or "").strip()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dist", type=Path, required=True, help="directory containing the wheel and sdist")
    parser.add_argument("--output", type=Path, required=True, help="provenance JSON output path")
    parser.add_argument("--repository", help="owner/repository or repository URL; defaults to GITHUB_REPOSITORY")
    parser.add_argument("--source-revision", help="source commit; defaults to GITHUB_SHA or Git HEAD")
    parser.add_argument("--source-ref", help="source ref; defaults to GITHUB_REF")
    parser.add_argument("--workflow-ref", help="workflow reference; defaults to GITHUB_WORKFLOW_REF")
    parser.add_argument("--workflow-sha", help="workflow commit; defaults to GITHUB_SHA or the source revision")
    parser.add_argument("--builder-id", help="builder identity URI; derived from the repository and workflow when omitted")
    parser.add_argument("--builder-image", help="builder image or runner label")
    parser.add_argument("--invocation-id", help="build invocation; defaults to GITHUB_RUN_ID")
    parser.add_argument("--python-version", help="Python version used for the build")
    parser.add_argument("--build-command", default=DEFAULT_BUILD_COMMAND, help="recorded build command")
    parser.add_argument(
        "--created",
        help="ISO-8601 UTC build start; defaults to SOURCE_DATE_EPOCH, and is omitted when neither is set",
    )
    parser.add_argument("--source-date-epoch", help="recorded SOURCE_DATE_EPOCH; defaults to the environment")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1], help="repository root")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)

    try:
        repository = _default(args.repository, "GITHUB_REPOSITORY")
        source_revision = _default(args.source_revision, "GITHUB_SHA") or _git_head(args.root)
        source_ref = _default(args.source_ref, "GITHUB_REF") or "local"
        workflow_ref = _default(args.workflow_ref, "GITHUB_WORKFLOW_REF") or (
            f"{repository}/.github/workflows/release.yml@{source_ref}"
        )
        workflow_sha = _default(args.workflow_sha, "GITHUB_SHA") or source_revision
        builder_image = args.builder_image or (
            "GitHub Actions ubuntu-latest" if os.environ.get("GITHUB_ACTIONS") == "true" else "local"
        )
        invocation_id = _default(args.invocation_id, "GITHUB_RUN_ID") or "local"
        workflow_identity = (
            workflow_ref if workflow_ref.startswith(("http://", "https://")) else f"https://github.com/{workflow_ref}"
        )
        builder_id = args.builder_id or workflow_identity
        creation = resolved_created(args.created)
        epoch_text = args.source_date_epoch if args.source_date_epoch is not None else os.environ.get("SOURCE_DATE_EPOCH")
        source_date_epoch = int(epoch_text) if epoch_text not in (None, "") else None
        document = build_provenance(
            args.dist,
            repository=repository,
            source_revision=source_revision,
            source_ref=source_ref,
            workflow_ref=workflow_ref,
            workflow_sha=workflow_sha,
            builder_id=builder_id,
            builder_image=builder_image,
            invocation_id=invocation_id,
            python_version=args.python_version or platform.python_version(),
            build_command=args.build_command,
            created=creation,
            source_date_epoch=source_date_epoch,
        )
        write_document(document, args.output)
    except (SupplyChainError, ValueError) as error:
        print(f"provenance generation failed: {error}", file=sys.stderr)
        return 1
    if not args.quiet:
        print(
            f"Provenance: {args.output} ({len(document['subject'])} subjects, unsigned, "
            f"source {source_revision[:12] or 'unknown'}, builder {builder_id})"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
