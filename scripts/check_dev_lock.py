#!/usr/bin/env python3
"""Verify the development/test dependency lock is fresh, pinned, and hash-verified.

The repository has no runtime dependencies. The development/test environment is
resolved once into ``uv.lock`` and exported to ``requirements-dev.lock`` by the
pinned ``uv`` release in the ``dev`` extra. This check proves, in order, that:

* ``uv lock --check`` reports ``uv.lock`` is current with ``pyproject.toml``;
* a fresh ``uv export --locked ... --extra dev`` is byte-identical to the
  checked-in ``requirements-dev.lock``;
* every exported requirement is exactly pinned (``name==version``), has at
  least one ``--hash=sha256:`` value, and never emits an editable, direct-URL,
  alternate-index, or local-path requirement;
* every direct ``dev`` requirement is present in the export.

Run it with the locked environment (``uv`` is installed from the same lock)::

    python -m pip install --require-hashes --no-deps -r requirements-dev.lock
    python scripts/check_dev_lock.py

The script prefers ``python -m uv`` from that interpreter, then ``.venv``, then
``uv`` on PATH. Pass ``--uv /path/to/uv`` to select an already-installed pinned
executable explicitly; a mismatched version fails with remediation instead of
rewriting the lock.

Exit status is 0 only when every check passes. ``--json`` prints the machine
readable result; ``--summary PATH`` appends a Markdown summary for CI.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib
from dataclasses import dataclass
from pathlib import Path

REQUIREMENTS = "requirements-dev.lock"
UV_LOCK = "uv.lock"
EXPORT_ARGS = (
    "export",
    "--locked",
    "--format",
    "requirements-txt",
    "--no-emit-project",
    "--extra",
    "dev",
    "--no-header",
)
NAME_RE = re.compile(r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)==(?P<version>[^\s;\\]+)")
HASH_RE = re.compile(r"--hash=sha256:(?P<digest>[0-9a-f]{64})")
FORBIDDEN_PREFIXES = (
    "-e ",
    "--editable",
    "-r ",
    "--requirement",
    "-c ",
    "--constraint",
    "--index-url",
    "--extra-index-url",
    "--find-links",
)
URL_RE = re.compile(r"\s@\s|://")
VERSION_RE = re.compile(r"uv (?P<version>[0-9][^\s]*)")


@dataclass(frozen=True)
class Requirement:
    name: str
    version: str
    hashes: tuple[str, ...]
    marker: str | None
    line: int


@dataclass(frozen=True)
class Check:
    name: str
    status: str
    detail: str

    def as_dict(self) -> dict[str, str]:
        return {"name": self.name, "status": self.status, "detail": self.detail}


class CheckFailure(Exception):
    """A single lock contract check failed."""


def normalise_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def parse_requirements(path: Path) -> list[Requirement]:
    """Parse a pip requirements file that was exported with hashes.

    Only the shapes emitted by ``uv export`` are accepted. Anything that could
    bypass the pinned, hashed set is rejected.
    """

    requirements: list[Requirement] = []
    lines = path.read_text(encoding="utf-8").splitlines()
    block: list[str] = []
    block_line = 0

    def flush() -> None:
        if not block:
            return
        for line in block:
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or stripped.startswith("--hash="):
                continue
            if stripped.startswith(FORBIDDEN_PREFIXES):
                raise CheckFailure(f"{path.name}:{block_line}: forbidden requirement directive {stripped!r}")
        match = NAME_RE.match(block[0])
        if match is None:
            raise CheckFailure(f"{path.name}:{block_line}: requirement is not exactly pinned: {block[0]!r}")
        if URL_RE.search(block[0].split(";", 1)[0]):
            raise CheckFailure(f"{path.name}:{block_line}: direct URL or local path requirement: {block[0]!r}")
        hashes = tuple(
            match_hash.group("digest") for line in block for match_hash in [HASH_RE.search(line)] if match_hash
        )
        if not hashes:
            raise CheckFailure(f"{path.name}:{block_line}: requirement has no sha256 hash: {block[0]!r}")
        if len(set(hashes)) != len(hashes):
            raise CheckFailure(f"{path.name}:{block_line}: duplicate sha256 hash: {block[0]!r}")
        marker = block[0].split(";", 1)[1].strip().rstrip("\\").strip() if ";" in block[0] else None
        requirements.append(Requirement(match.group("name"), match.group("version"), hashes, marker, block_line))

    for number, line in enumerate(lines, 1):
        if not line.strip() or line.startswith("#"):
            continue
        if line[0].isspace() or line.startswith("--hash="):
            if not block:
                raise CheckFailure(f"{path.name}:{number}: continuation line without a requirement")
            block.append(line)
            continue
        flush()
        block = [line]
        block_line = number
    flush()
    return requirements


def uv_command(root: Path, override: str | None = None) -> list[str]:
    """Prefer the pinned ``uv`` installed in this interpreter, then a local venv, then PATH."""

    if override:
        return [override]
    candidates: list[list[str]] = [[sys.executable, "-m", "uv"]]
    for venv_python in (root / ".venv" / "bin" / "python", root / ".venv" / "Scripts" / "python.exe"):
        if venv_python.is_file():
            candidates.append([str(venv_python), "-m", "uv"])
    for candidate in candidates:
        probe = subprocess.run(
            [*candidate, "--version"],
            text=True,
            capture_output=True,
            check=False,
        )
        if probe.returncode == 0:
            return candidate
    executable = shutil.which("uv")
    if executable:
        return [executable]
    raise CheckFailure(
        "uv is not available in this interpreter or PATH; install the locked dev set first: "
        "python -m pip install --require-hashes --no-deps -r requirements-dev.lock "
        "(or pass --uv /path/to/uv)"
    )


def run_uv(command: list[str], args: tuple[str, ...], root: Path) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        [*command, *args],
        cwd=root,
        text=True,
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip().splitlines()
        tail = " | ".join(detail[-3:]) if detail else "no output"
        raise CheckFailure(f"uv {' '.join(args)} exited {completed.returncode}: {tail}")
    return completed


def _direct_dev_requirements(pyproject: dict[str, object]) -> set[str]:
    project = pyproject.get("project")
    if not isinstance(project, dict):
        raise CheckFailure("pyproject.toml: missing [project] table")
    extras = project.get("optional-dependencies")
    if not isinstance(extras, dict) or "dev" not in extras:
        raise CheckFailure("pyproject.toml: missing [project.optional-dependencies].dev")
    names = set()
    for requirement in extras["dev"]:
        if not isinstance(requirement, str):
            raise CheckFailure(f"pyproject.toml: dev requirement is not a string: {requirement!r}")
        match = re.match(r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)", requirement)
        if match is None:
            raise CheckFailure(f"pyproject.toml: cannot parse dev requirement {requirement!r}")
        names.add(normalise_name(match.group("name")))
    return names


def check(root: Path, uv_bin: str | None = None) -> dict[str, object]:
    checks: list[Check] = []
    failures: list[str] = []

    def record(name: str, detail: str) -> None:
        checks.append(Check(name, "pass", detail))

    def fail(name: str, detail: str) -> None:
        checks.append(Check(name, "fail", detail))
        failures.append(f"{name}: {detail}")

    uv = uv_command(root, uv_bin)
    version_output = run_uv(uv, ("--version",), root).stdout.strip()
    version_match = VERSION_RE.search(version_output)
    if version_match is None:
        fail("uv-version", f"cannot parse uv version from {version_output!r}")
    else:
        record("uv-version", version_output)

    pyproject_path = root / "pyproject.toml"
    pyproject = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))
    project = pyproject.get("project", {})
    if not isinstance(project, dict):
        raise CheckFailure("pyproject.toml: [project] is not a table")
    runtime = project.get("dependencies")
    expected_runtime: list[object] = []
    if runtime != expected_runtime:
        fail("zero-runtime-dependencies", f"pyproject [project].dependencies must be [], found {runtime!r}")
    else:
        record("zero-runtime-dependencies", "pyproject [project].dependencies == []")
    required_version = pyproject.get("tool", {}).get("uv", {}).get("required-version")
    if version_match and required_version and required_version.startswith("=="):
        expected = required_version[2:]
        if version_match.group("version") != expected:
            fail(
                "uv-version-pin",
                f"uv {version_match.group('version')} does not match required-version {required_version}; "
                "run this check with the locked environment "
                "(python -m pip install --require-hashes --no-deps -r requirements-dev.lock) "
                f"or pass --uv /path/to/uv {expected}",
            )
            return _result(checks, failures, version_output, None, None)
        record("uv-version-pin", f"uv {expected} matches [tool.uv].required-version")

    direct = _direct_dev_requirements(pyproject)
    lock_path = root / REQUIREMENTS
    uv_lock_path = root / UV_LOCK
    for path in (lock_path, uv_lock_path):
        if not path.is_file():
            fail("lock-exists", f"missing {path.name}")
    if failures:
        return _result(checks, failures, version_output, None, None)

    run_uv(uv, ("lock", "--check"), root)
    record("uv-lock-check", "uv lock --check reports uv.lock is current")

    with tempfile.TemporaryDirectory() as directory:
        exported = Path(directory) / "requirements-dev.lock"
        run_uv(uv, (*EXPORT_ARGS, "--output-file", str(exported)), root)
        expected = exported.read_bytes()
    actual = lock_path.read_bytes()
    if actual != expected:
        fail(
            "export-freshness",
            f"{REQUIREMENTS} is not the byte-identical export; regenerate with: "
            f"uv {(' '.join(EXPORT_ARGS))} --output-file {REQUIREMENTS}",
        )
    else:
        record("export-freshness", f"{REQUIREMENTS} matches a fresh uv export byte for byte")

    try:
        requirements = parse_requirements(lock_path)
    except CheckFailure as error:
        fail("hash-pins", str(error))
        requirements = []

    if requirements:
        names = [normalise_name(requirement.name) for requirement in requirements]
        duplicates = sorted({name for name in names if names.count(name) > 1})
        if duplicates:
            fail("hash-pins", f"duplicate requirements: {duplicates}")
        else:
            hashes = sum(len(requirement.hashes) for requirement in requirements)
            record(
                "hash-pins",
                f"{len(requirements)} pinned requirements carry {hashes} sha256 hashes",
            )
        missing = sorted(direct - set(names))
        if missing:
            fail("direct-dev-requirements", f"dev requirements missing from {REQUIREMENTS}: {missing}")
        else:
            record("direct-dev-requirements", f"all {len(direct)} direct dev requirements are locked")
        if normalise_name(project.get("name", "")) in set(names):
            fail("no-project-install", f"{REQUIREMENTS} must not install the project itself")
        else:
            record("no-project-install", "the exported set does not include the project")
    else:
        hashes = 0

    lock_text = uv_lock_path.read_text(encoding="utf-8")
    if "name = " not in lock_text or "revision = " not in lock_text:
        fail("uv-lock-shape", "uv.lock is not a uv lockfile")
    else:
        record("uv-lock-shape", "uv.lock is a uv lockfile")

    return _result(
        checks,
        failures,
        version_output,
        {
            "sha256": digest(lock_path),
            "bytes": lock_path.stat().st_size,
            "packages": len(requirements) if requirements else 0,
            "hashes": hashes if requirements else 0,
        },
        {"sha256": digest(uv_lock_path), "bytes": uv_lock_path.stat().st_size},
    )


def _result(
    checks: list[Check],
    failures: list[str],
    uv_version: str,
    requirements_lock: dict[str, object] | None,
    uv_lock: dict[str, object] | None,
) -> dict[str, object]:
    return {
        "schema": "pr-review-dev-lock-check.v1",
        "status": "fail" if failures else "pass",
        "uv": uv_version,
        "requirements": requirements_lock,
        "uv_lock": uv_lock,
        "checks": [check.as_dict() for check in checks],
        "failures": failures,
    }


def _markdown(result: dict[str, object]) -> str:
    lines = [
        "### Development/test dependency lock",
        "",
        f"Status: **{str(result['status']).upper()}**",
        "",
        "| Check | Status | Detail |",
        "|---|---|---|",
    ]
    for item in result["checks"]:  # type: ignore[union-attr]
        lines.append(f"| `{item['name']}` | {item['status']} | {item['detail']} |")
    requirements = result.get("requirements")
    if isinstance(requirements, dict):
        lines.extend(
            [
                "",
                f"`requirements-dev.lock`: {requirements['packages']} packages, "
                f"{requirements['hashes']} sha256 hashes, sha256 `{requirements['sha256']}`.",
            ]
        )
    uv_lock = result.get("uv_lock")
    if isinstance(uv_lock, dict):
        lines.append(f"`uv.lock`: sha256 `{uv_lock['sha256']}`.")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--uv", dest="uv_bin", help="path to the pinned uv executable (default: python -m uv)")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--summary", type=Path)
    args = parser.parse_args(argv)

    try:
        result = check(args.root.resolve(), args.uv_bin)
    except CheckFailure as error:
        result = _result([], [str(error)], "", None, None)
    except (OSError, tomllib.TOMLDecodeError) as error:
        result = _result([], [f"unreadable lock metadata: {error}"], "", None, None)

    if args.summary:
        args.summary.write_text(_markdown(result), encoding="utf-8")
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(f"Development/test lock check: {str(result['status']).upper()}")
        for item in result["checks"]:  # type: ignore[union-attr]
            print(f"  [{item['status']}] {item['name']}: {item['detail']}")
        for failure in result["failures"]:  # type: ignore[union-attr]
            print(f"  FAILURE: {failure}")
    return 0 if result["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
