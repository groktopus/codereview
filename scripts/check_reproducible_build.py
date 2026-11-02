#!/usr/bin/env python3
"""Check whether two builds from the same source produce the same artifacts.

The default mode copies the source tree twice, builds a wheel and source
distribution in each copy with a fixed ``SOURCE_DATE_EPOCH``, and compares the
results. ``--compare`` mode skips building and compares two existing
distribution directories, which is useful when auditing a published release.

The report distinguishes three outcomes:

``REPRODUCIBLE``
    Every artifact is byte-for-byte identical.
``CONTENT_REPRODUCIBLE``
    Artifact bytes differ, but every archive member is identical. This is the
    observed source-distribution result: setuptools does not clamp the gzip
    header or directory-entry timestamps to ``SOURCE_DATE_EPOCH``.
``NOT_REPRODUCIBLE``
    Archive content differs, or the artifact sets differ.

The script records hashes and reasons instead of hiding the difference. It is
stdlib-only; building requires the ``build`` package, which is a development
dependency, not a runtime dependency.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

SDIST_SUFFIX = ".tar.gz"
WHEEL_SUFFIX = ".whl"
SCHEMA = "pr-review-harness-reproducibility.v1"


class ReproducibilityError(Exception):
    """The check could not run or its inputs are invalid."""


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def discover_artifacts(dist: Path) -> list[Path]:
    if not dist.is_dir():
        raise ReproducibilityError(f"distribution directory not found: {dist}")
    return sorted(
        (path for path in dist.iterdir() if path.is_file() and path.name.endswith((WHEEL_SUFFIX, SDIST_SUFFIX))),
        key=lambda path: path.name,
    )


def hash_distributions(dist: Path) -> dict[str, dict[str, object]]:
    return {
        path.name: {"sha256": sha256_file(path), "size": path.stat().st_size}
        for path in discover_artifacts(dist)
    }


def wheel_members(path: Path) -> dict[str, object]:
    members: dict[str, object] = {}
    with zipfile.ZipFile(path) as archive:
        for name in sorted(archive.namelist()):
            info = archive.getinfo(name)
            if info.is_dir():
                members[name] = {"type": "dir", "size": 0, "sha256": None}
                continue
            members[name] = {"type": "file", "size": info.file_size, "sha256": sha256_bytes(archive.read(name))}
    return members


def sdist_members(path: Path) -> dict[str, object]:
    import tarfile

    members: dict[str, object] = {}
    with tarfile.open(path, "r:gz") as archive:
        for member in sorted(archive.getmembers(), key=lambda item: item.name):
            if member.isdir():
                members[member.name] = {"type": "dir", "mode": member.mode, "size": 0, "sha256": None}
                continue
            extracted = archive.extractfile(member)
            content = extracted.read() if extracted is not None else b""
            members[member.name] = {
                "type": "file",
                "mode": member.mode,
                "size": member.size,
                "sha256": sha256_bytes(content),
            }
    return members


def content_members(path: Path) -> dict[str, object]:
    if path.name.endswith(WHEEL_SUFFIX):
        return wheel_members(path)
    if path.name.endswith(SDIST_SUFFIX):
        return sdist_members(path)
    raise ReproducibilityError(f"{path.name}: unsupported distribution artifact")


def content_digest(members: dict[str, object]) -> str:
    return sha256_bytes(json.dumps(members, sort_keys=True, separators=(",", ":")).encode("utf-8"))


def gzip_mtime(path: Path) -> int | None:
    try:
        header = path.read_bytes()[:8]
    except OSError:
        return None
    if len(header) < 8 or header[:2] != b"\x1f\x8b":
        return None
    return struct.unpack("<I", header[4:8])[0]


def sdist_timestamp_differences(first: Path, second: Path) -> list[str]:
    import tarfile

    differences: list[str] = []
    with tarfile.open(first, "r:gz") as left, tarfile.open(second, "r:gz") as right:
        left_members = {member.name: member for member in left.getmembers()}
        right_members = {member.name: member for member in right.getmembers()}
        for name in sorted(set(left_members) & set(right_members)):
            left_member, right_member = left_members[name], right_members[name]
            if left_member.mtime != right_member.mtime:
                differences.append(f"tar entry mtime differs: {name}")
    mtime_left, mtime_right = gzip_mtime(first), gzip_mtime(second)
    if mtime_left != mtime_right:
        differences.append(f"gzip header mtime differs: {mtime_left} != {mtime_right}")
    return differences


def compare_build_dirs(first: Path, second: Path) -> dict[str, object]:
    left = hash_distributions(first)
    right = hash_distributions(second)
    if set(left) != set(right):
        return {
            "artifacts": [],
            "status": "NOT_REPRODUCIBLE",
            "artifact_hashes_match": False,
            "content_matches": False,
            "non_determinism": [
                f"artifact set differs: only-first={sorted(set(left) - set(right))} "
                f"only-second={sorted(set(right) - set(left))}"
            ],
        }

    artifacts: list[dict[str, object]] = []
    non_determinism: list[str] = []
    for name in sorted(left):
        first_path, second_path = first / name, second / name
        hashes_match = left[name]["sha256"] == right[name]["sha256"]
        first_members = content_members(first_path)
        second_members = content_members(second_path)
        members_match = first_members == second_members
        artifacts.append(
            {
                "name": name,
                "sha256_first": left[name]["sha256"],
                "sha256_second": right[name]["sha256"],
                "artifact_match": hashes_match,
                "content_match": members_match,
                "content_digest_first": content_digest(first_members),
                "content_digest_second": content_digest(second_members),
            }
        )
        if hashes_match:
            continue
        if not members_match:
            non_determinism.append(f"{name}: archive member content differs")
            continue
        if name.endswith(SDIST_SUFFIX):
            details = sdist_timestamp_differences(first_path, second_path)
            gzip_details = [detail for detail in details if detail.startswith("gzip")]
            tar_details = [detail for detail in details if detail.startswith("tar")]
            summary = list(gzip_details)
            if tar_details:
                summary.append(f"{len(tar_details)} tar entry mtimes differ (for example {tar_details[0]})")
            detail = "; ".join(summary) if summary else "archive metadata differs"
            non_determinism.append(
                f"{name}: byte difference is limited to non-content tar/gzip metadata ({detail}); "
                "setuptools does not clamp these timestamps to SOURCE_DATE_EPOCH"
            )
        else:
            non_determinism.append(f"{name}: archive bytes differ although members are identical")

    if not artifacts:
        return {
            "artifacts": [],
            "status": "NOT_REPRODUCIBLE",
            "artifact_hashes_match": False,
            "content_matches": False,
            "non_determinism": ["no wheel or source distribution found in both directories"],
        }
    artifact_hashes_match = all(bool(item["artifact_match"]) for item in artifacts)
    content_matches = all(bool(item["content_match"]) for item in artifacts)
    if artifact_hashes_match:
        status = "REPRODUCIBLE"
    elif content_matches:
        status = "CONTENT_REPRODUCIBLE"
    else:
        status = "NOT_REPRODUCIBLE"
    return {
        "artifacts": artifacts,
        "status": status,
        "artifact_hashes_match": artifact_hashes_match,
        "content_matches": content_matches,
        "non_determinism": non_determinism,
    }


def _run(python: str, root: Path, outdir: Path, epoch: int) -> None:
    environment = os.environ.copy()
    environment.update(
        {
            "SOURCE_DATE_EPOCH": str(epoch),
            "PYTHONHASHSEED": "0",
            "TZ": "UTC",
            "LC_ALL": "C.UTF-8",
            "LANG": "C.UTF-8",
        }
    )
    completed = subprocess.run(
        [python, "-m", "build", "--wheel", "--sdist", "--outdir", str(outdir)],
        cwd=root,
        env=environment,
        check=False,
        text=True,
        capture_output=True,
    )
    if completed.returncode != 0:
        tail = "\n".join((completed.stdout + completed.stderr).splitlines()[-20:])
        raise ReproducibilityError(f"build failed in {root} (exit {completed.returncode}):\n{tail}")


def _copy_source(root: Path, destination: Path) -> None:
    ignore = shutil.ignore_patterns(
        ".git",
        "dist",
        "build",
        "*.egg-info",
        "__pycache__",
        ".pytest_cache",
        ".ruff_cache",
        "artifacts",
        ".venv",
    )
    shutil.copytree(root, destination, ignore=ignore, symlinks=True)


def _build_metadata(python: str) -> dict[str, str]:
    completed = subprocess.run(
        [
            python,
            "-c",
            "import build, importlib.metadata, sys; "
            "print(build.__version__); print(importlib.metadata.version('setuptools')); print(sys.version.split()[0])",
        ],
        check=False,
        text=True,
        capture_output=True,
    )
    if completed.returncode != 0:
        raise ReproducibilityError(
            "the build package is not importable by the selected Python; install the development dependencies "
            "(python -m pip install '.[dev]') or pass --python"
        )
    lines = completed.stdout.splitlines()
    if len(lines) < 3:
        raise ReproducibilityError("could not determine build frontend versions")
    return {"build": lines[0], "setuptools": lines[1], "python": lines[2]}


def run(
    root: Path,
    *,
    python: str,
    epoch: int,
    work_dir: Path | None = None,
    dist_out: Path | None = None,
    created: str | None = None,
    compare: tuple[Path, Path] | None = None,
) -> dict[str, object]:
    if compare is not None and dist_out is not None:
        raise ReproducibilityError("--dist-out cannot be combined with --compare")
    if work_dir is not None and work_dir.resolve().is_relative_to(root.resolve()):
        raise ReproducibilityError("--work-dir must be outside the source tree so the second copy is independent")
    temporary: Path | None = None
    try:
        if compare is not None:
            comparison = compare_build_dirs(compare[0], compare[1])
            metadata = {
                "build": "not used (compare mode)",
                "setuptools": "not used (compare mode)",
                "python": sys.version.split()[0],
            }
        else:
            metadata = _build_metadata(python)
            base = work_dir
            if base is None:
                temporary = Path(tempfile.mkdtemp(prefix="pr-review-reproducibility-"))
                base = temporary
            base.mkdir(parents=True, exist_ok=True)
            first_source, second_source = base / "source-a", base / "source-b"
            for path in (first_source, second_source):
                if path.exists():
                    shutil.rmtree(path)
            _copy_source(root, first_source)
            _copy_source(root, second_source)
            first_dist, second_dist = base / "dist-a", base / "dist-b"
            for path in (first_dist, second_dist):
                if path.exists():
                    shutil.rmtree(path)
            _run(python, first_source, first_dist, epoch)
            _run(python, second_source, second_dist, epoch)
            comparison = compare_build_dirs(first_dist, second_dist)
            if dist_out is not None:
                dist_out.mkdir(parents=True, exist_ok=True)
                for artifact in discover_artifacts(first_dist):
                    shutil.copy2(artifact, dist_out / artifact.name)

        report: dict[str, object] = {
            "schema": SCHEMA,
            "source_date_epoch": epoch,
            "python_version": metadata["python"],
            "build_frontend": metadata["build"],
            "setuptools_version": metadata["setuptools"],
            **comparison,
        }
        if created is not None:
            report["created"] = created
        return report
    finally:
        if temporary is not None:
            shutil.rmtree(temporary, ignore_errors=True)


def summary_markdown(report: dict[str, object]) -> str:
    status = str(report["status"])
    lines = [
        "# Reproducibility report",
        "",
        f"- Status: **{status}**",
        f"- SOURCE_DATE_EPOCH: `{report['source_date_epoch']}`",
        f"- Python: `{report['python_version']}`",
        f"- build: `{report['build_frontend']}`",
        f"- setuptools: `{report['setuptools_version']}`",
        "- Artifact hashes match: " + ("yes" if report["artifact_hashes_match"] else "no"),
        "- Archive content matches: " + ("yes" if report["content_matches"] else "no"),
        "",
        "| Artifact | SHA-256 (first) | SHA-256 (second) | Bytes match | Content match |",
        "|---|---|---|---|---|",
    ]
    for artifact in report["artifacts"]:  # type: ignore[union-attr]
        lines.append(
            f"| `{artifact['name']}` | `{artifact['sha256_first']}` | `{artifact['sha256_second']}` | "
            f"{'yes' if artifact['artifact_match'] else 'no'} | {'yes' if artifact['content_match'] else 'no'} |"
        )
    reasons = report.get("non_determinism") or []
    lines.extend(["", "## Recorded non-determinism", ""])
    if reasons:
        lines.extend(f"- {reason}" for reason in reasons)  # type: ignore[union-attr]
    else:
        lines.append("- None observed.")
    lines.extend(
        [
            "",
            "`CONTENT_REPRODUCIBLE` means the archive bytes differ while every archive member is identical. "
            "It is not a bit-for-bit reproducibility claim.",
            "",
        ]
    )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--python", default=sys.executable, help="Python interpreter that has the build package")
    parser.add_argument(
        "--source-date-epoch",
        type=int,
        help="fixed build timestamp; defaults to SOURCE_DATE_EPOCH or the current commit time",
    )
    parser.add_argument("--work-dir", type=Path, help="directory for the two source copies and build outputs")
    parser.add_argument("--dist-out", type=Path, help="copy the first build's wheel and sdist here")
    parser.add_argument("--json-out", type=Path, help="write the machine-readable report here")
    parser.add_argument("--summary", type=Path, help="write a Markdown summary here")
    parser.add_argument("--created", help="optional ISO-8601 UTC timestamp recorded in the report")
    parser.add_argument(
        "--compare",
        nargs=2,
        type=Path,
        metavar=("FIRST_DIST", "SECOND_DIST"),
        help="compare two existing distribution directories instead of building",
    )
    parser.add_argument(
        "--require-identical-artifacts",
        action="store_true",
        help="fail when archives differ in bytes even if their content is identical",
    )
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)

    try:
        epoch = args.source_date_epoch
        if epoch is None:
            environment_epoch = os.environ.get("SOURCE_DATE_EPOCH", "").strip()
            if environment_epoch:
                epoch = int(environment_epoch)
            else:
                completed = subprocess.run(
                    ["git", "-C", str(args.root), "log", "-1", "--format=%ct"],
                    check=False,
                    text=True,
                    capture_output=True,
                )
                if completed.returncode != 0 or not completed.stdout.strip():
                    raise ReproducibilityError(
                        "--source-date-epoch is required when SOURCE_DATE_EPOCH is unset and Git HEAD is unavailable"
                    )
                epoch = int(completed.stdout.strip())
        report = run(
            args.root,
            python=args.python,
            epoch=epoch,
            work_dir=args.work_dir,
            dist_out=args.dist_out,
            created=args.created,
            compare=(args.compare[0], args.compare[1]) if args.compare else None,
        )
    except (ReproducibilityError, OSError, ValueError) as error:
        print(f"reproducibility check failed: {error}", file=sys.stderr)
        return 2

    if args.json_out is not None:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.summary is not None:
        args.summary.parent.mkdir(parents=True, exist_ok=True)
        args.summary.write_text(summary_markdown(report), encoding="utf-8")
    if not args.quiet:
        print(
            f"Reproducibility: {report['status']} "
            f"(artifact hashes match: {'yes' if report['artifact_hashes_match'] else 'no'}, "
            f"content matches: {'yes' if report['content_matches'] else 'no'})"
        )
        for reason in report.get("non_determinism") or []:
            print(f"  - {reason}")

    if report["status"] == "NOT_REPRODUCIBLE":
        return 1
    if args.require_identical_artifacts and report["status"] != "REPRODUCIBLE":
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
