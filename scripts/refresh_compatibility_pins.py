#!/usr/bin/env python3
"""Refresh the reviewed compatibility pins.

Two manifests are supported:

* File-byte pins (default): ``tests/fixtures/frozen-runtime-7d550b6/pins.json``.
  The tool recomputes the SHA-256 digest of every file listed in ``pin_files``
  and reports the changes it would make.
* Named value pins (``--value-pins``): ``tests/compatibility-pins.v1.json``.
  Value pins are semantic identities (module-tree, snapshot, plan, contract
  digests) that cannot be recomputed from a single tracked file, so the
  reviewed replacement value is supplied explicitly with ``--set``.

Both modes are dry-run by default. ``--confirm`` atomically rewrites the
manifest after appending reviewed provenance to ``refresh_history``. A refresh
is refused without a reviewed reason and a 40-character source revision. The
tool never touches the network and never edits a fixture.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = Path("tests/fixtures/frozen-runtime-7d550b6/pins.json")
DEFAULT_VALUE_MANIFEST = Path("tests/compatibility-pins.v1.json")
SCHEMA = "pr-review-historical-pins.v1"
VALUE_SCHEMA = "pr-review-compatibility-value-pins.v1"
REVISION_RE = re.compile(r"[0-9a-fA-F]{40}")
SHA256_RE = re.compile(r"[0-9a-f]{64}")
PIN_NAME_RE = re.compile(r"[a-z0-9]+(?:[._][a-z0-9]+)*")
PROVENANCE_FIELDS = ("artifact", "source_revision", "recorded_at", "reason")
MIN_REASON = 10
MAX_REPORTED_TEXT = 240


class PinRefreshError(Exception):
    """A refusal with a sanitized, operator-facing message."""


@dataclass(frozen=True)
class PinChange:
    """One file pin whose computed digest differs from the manifest."""

    name: str
    old_sha256: str | None
    new_sha256: str


@dataclass(frozen=True)
class ValuePinChange:
    """One named value pin whose reviewed replacement differs from the manifest."""

    name: str
    old_sha256: str
    new_sha256: str
    artifact: str


def _sanitize(value: object, limit: int = MAX_REPORTED_TEXT) -> str:
    """Return printable single-line text, bounded for terminal output."""
    text = "".join(character if character.isprintable() else " " for character in str(value))
    text = " ".join(text.split())
    if len(text) > limit:
        text = text[: limit - 3] + "..."
    return text


def _load_manifest(path: Path) -> dict[str, object]:
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise PinRefreshError("manifest is unavailable or invalid") from None
    if not isinstance(manifest, dict):
        raise PinRefreshError("manifest root must be a JSON object")
    if manifest.get("schema") != SCHEMA:
        raise PinRefreshError("manifest schema is invalid")
    revision = manifest.get("historical_revision")
    if not isinstance(revision, str) or not REVISION_RE.fullmatch(revision):
        raise PinRefreshError("manifest historical revision is invalid")
    pin_files = manifest.get("pin_files")
    pins = manifest.get("pins")
    pin_revisions = manifest.get("pin_revisions")
    history = manifest.get("refresh_history")
    if not isinstance(pin_files, dict) or not pin_files:
        raise PinRefreshError("manifest pin_files are invalid")
    if not isinstance(pins, dict):
        raise PinRefreshError("manifest pins are invalid")
    if not isinstance(pin_revisions, dict):
        raise PinRefreshError("manifest pin_revisions are invalid")
    if not isinstance(history, list):
        raise PinRefreshError("manifest refresh_history is invalid")
    for name, relative in pin_files.items():
        if not isinstance(name, str) or not name or not name.isprintable():
            raise PinRefreshError("manifest pin name is invalid")
        if not isinstance(relative, str) or not relative:
            raise PinRefreshError("manifest pin path is invalid")
        path = PurePosixPath(relative)
        if path.is_absolute() or ".." in path.parts:
            raise PinRefreshError("manifest pin path escapes the repository")
        pinned = pins.get(name)
        if pinned is not None and (not isinstance(pinned, str) or not SHA256_RE.fullmatch(pinned)):
            raise PinRefreshError("manifest pin digest is invalid")
        pinned_revision = pin_revisions.get(name)
        if pinned_revision is not None and (
            not isinstance(pinned_revision, str) or not REVISION_RE.fullmatch(pinned_revision)
        ):
            raise PinRefreshError("manifest pin revision is invalid")
    return manifest


def _load_value_manifest(path: Path) -> dict[str, object]:
    """Read and validate the named value-pin manifest."""
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise PinRefreshError("value-pin manifest is unavailable or invalid") from None
    if not isinstance(manifest, dict):
        raise PinRefreshError("value-pin manifest root must be a JSON object")
    if manifest.get("schema") != VALUE_SCHEMA:
        raise PinRefreshError("value-pin manifest schema is invalid")
    pins = manifest.get("pins")
    if not isinstance(pins, dict) or not pins:
        raise PinRefreshError("value-pin manifest pins are invalid")
    history = manifest.get("refresh_history", [])
    if not isinstance(history, list):
        raise PinRefreshError("value-pin manifest refresh_history is invalid")
    for name, entry in pins.items():
        if not isinstance(name, str) or not PIN_NAME_RE.fullmatch(name):
            raise PinRefreshError("value-pin name is invalid")
        if not isinstance(entry, dict):
            raise PinRefreshError(f"value pin {name!r} must be an object")
        value = entry.get("value")
        if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
            raise PinRefreshError(f"value pin {name!r} digest is invalid")
        if not isinstance(entry.get("kind"), str) or not entry["kind"]:
            raise PinRefreshError(f"value pin {name!r} kind is missing")
        provenance = entry.get("provenance")
        if not isinstance(provenance, dict):
            raise PinRefreshError(f"value pin {name!r} provenance is missing")
        for field in PROVENANCE_FIELDS:
            field_value = provenance.get(field)
            if not isinstance(field_value, str) or not field_value.strip():
                raise PinRefreshError(f"value pin {name!r} provenance.{field} is missing")
        revision = provenance["source_revision"]
        if not isinstance(revision, str) or not REVISION_RE.fullmatch(revision):
            raise PinRefreshError(f"value pin {name!r} provenance.source_revision is invalid")
        reason = provenance["reason"]
        if not isinstance(reason, str) or len(reason.strip()) < MIN_REASON:
            raise PinRefreshError(f"value pin {name!r} provenance.reason is too short")
    return manifest


def _parse_value_assignments(raw_values: list[str]) -> dict[str, str]:
    """Parse repeated ``NAME=SHA256`` arguments, refusing ambiguity."""
    assignments: dict[str, str] = {}
    for raw in raw_values:
        name, separator, value = raw.partition("=")
        if not separator or not PIN_NAME_RE.fullmatch(name):
            raise PinRefreshError("invalid --set value; expected NAME=<sha256>")
        if not SHA256_RE.fullmatch(value):
            raise PinRefreshError(f"--set for {name!r} must be a lower-case 64-character SHA-256 digest")
        previous = assignments.get(name)
        if previous is not None and previous != value:
            raise PinRefreshError(f"conflicting --set values for {name!r}")
        assignments[name] = value
    if not assignments:
        raise PinRefreshError("at least one --set NAME=<sha256> is required with --value-pins")
    return assignments


def _plan_value_changes(manifest: dict[str, object], assignments: dict[str, str]) -> list[ValuePinChange]:
    pins = manifest["pins"]
    assert isinstance(pins, dict)
    unknown = sorted(set(assignments) - set(pins))
    if unknown:
        available = ", ".join(sorted(pins))
        raise PinRefreshError(f"unknown value pin(s) {', '.join(unknown)}; available names: {available}")
    changes: list[ValuePinChange] = []
    for name in sorted(assignments):
        entry = pins[name]
        assert isinstance(entry, dict)
        provenance = entry["provenance"]
        assert isinstance(provenance, dict)
        old_digest = entry["value"]
        new_digest = assignments[name]
        assert isinstance(old_digest, str) and isinstance(provenance.get("artifact"), str)
        if old_digest != new_digest:
            changes.append(
                ValuePinChange(
                    name=name,
                    old_sha256=old_digest,
                    new_sha256=new_digest,
                    artifact=provenance["artifact"],
                )
            )
    if not changes:
        raise PinRefreshError("no changed value pins; refusing to record an empty refresh")
    return changes


def _apply_value_changes(manifest: dict[str, object], changes: list[ValuePinChange], reason: str, revision: str) -> str:
    pins = manifest["pins"]
    assert isinstance(pins, dict)
    history = manifest.setdefault("refresh_history", [])
    assert isinstance(history, list)
    timestamp = _timestamp()
    for change in changes:
        entry = pins[change.name]
        assert isinstance(entry, dict)
        provenance = entry["provenance"]
        assert isinstance(provenance, dict)
        entry["value"] = change.new_sha256
        provenance["source_revision"] = revision
        provenance["recorded_at"] = timestamp
        provenance["reason"] = reason
        history.append(
            {
                "name": change.name,
                "old_sha256": change.old_sha256,
                "new_sha256": change.new_sha256,
                "timestamp": timestamp,
                "reason": reason,
                "source_revision": revision,
            }
        )
    return timestamp


def _report_value(changes: list[ValuePinChange], reason: str, revision: str, *, confirm: bool) -> None:
    mode = "confirmed" if confirm else "dry run"
    print(f"compatibility value-pin refresh ({mode}): {len(changes)} changed pin(s)")
    print(f"  reason: {_sanitize(reason)}")
    print(f"  source revision: {revision}")
    for change in changes:
        print(f"  {_sanitize(change.name)} ({_sanitize(change.artifact)}): {change.old_sha256} -> {change.new_sha256}")
    if not confirm:
        print("no files written; re-run with --confirm to update the manifest atomically")


def _pin_target(root: Path, relative: str) -> tuple[Path, bool]:
    """Resolve a pin path and report whether it is a safe regular file."""
    raw = root.joinpath(*PurePosixPath(relative).parts)
    try:
        resolved = raw.resolve()
    except OSError:
        return raw, False
    safe = resolved.is_relative_to(root) and not raw.is_symlink() and resolved.is_file()
    return resolved, safe


def _plan_changes(manifest: dict[str, object], root: Path) -> list[PinChange]:
    pin_files = manifest["pin_files"]
    pins = manifest["pins"]
    assert isinstance(pin_files, dict) and isinstance(pins, dict)
    changes: list[PinChange] = []
    missing: list[str] = []
    for name, relative in pin_files.items():
        assert isinstance(name, str) and isinstance(relative, str)
        target, safe = _pin_target(root, relative)
        if not safe:
            missing.append(name)
            continue
        try:
            digest = hashlib.sha256(target.read_bytes()).hexdigest()
        except OSError:
            missing.append(name)
            continue
        old_digest = pins.get(name)
        if old_digest != digest:
            changes.append(PinChange(name=name, old_sha256=old_digest, new_sha256=digest))
    if missing:
        raise PinRefreshError("pin files are missing or unsafe: " + ", ".join(sorted(missing)))
    if not changes:
        raise PinRefreshError("no changed pins; refusing to record an empty refresh")
    return changes


def _provenance(reason: str | None, source_revision: str | None) -> tuple[str, str]:
    cleaned_reason = (reason or "").strip()
    if len(cleaned_reason) < MIN_REASON:
        raise PinRefreshError(f"--reason must be at least {MIN_REASON} characters")
    if any(not character.isprintable() for character in cleaned_reason):
        raise PinRefreshError("--reason must be single-line printable text")
    revision = (source_revision or "").strip()
    if not REVISION_RE.fullmatch(revision):
        raise PinRefreshError("--source-revision must be a 40-character hexadecimal Git revision")
    return cleaned_reason, revision.lower()


def _timestamp() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _apply_changes(manifest: dict[str, object], changes: list[PinChange], reason: str, revision: str) -> str:
    pins = manifest["pins"]
    pin_revisions = manifest["pin_revisions"]
    history = manifest["refresh_history"]
    assert isinstance(pins, dict) and isinstance(pin_revisions, dict) and isinstance(history, list)
    timestamp = _timestamp()
    for change in changes:
        pins[change.name] = change.new_sha256
        pin_revisions[change.name] = revision
        history.append(
            {
                "name": change.name,
                "old_sha256": change.old_sha256,
                "new_sha256": change.new_sha256,
                "timestamp": timestamp,
                "reason": reason,
                "source_revision": revision,
            }
        )
    return timestamp


def _atomic_write(path: Path, text: str) -> None:
    try:
        mode = stat.S_IMODE(path.stat().st_mode)
        descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    except OSError:
        raise PinRefreshError("manifest could not be written atomically") from None
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except OSError:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        raise PinRefreshError("manifest could not be written atomically") from None


def _report(changes: list[PinChange], reason: str, revision: str, *, confirm: bool) -> None:
    mode = "confirmed" if confirm else "dry run"
    print(f"compatibility pin refresh ({mode}): {len(changes)} changed pin(s)")
    print(f"  reason: {_sanitize(reason)}")
    print(f"  source revision: {revision}")
    for change in sorted(changes, key=lambda item: item.name):
        print(f"  {_sanitize(change.name)}: {change.old_sha256} -> {change.new_sha256}")
    if not confirm:
        print("no files written; re-run with --confirm to update the manifest atomically")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--confirm", action="store_true", help="write the refreshed manifest atomically")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="report the planned refresh without writing (the default; cannot be combined with --confirm)",
    )
    parser.add_argument("--reason", help=f"reviewed provenance for the refresh (at least {MIN_REASON} characters)")
    parser.add_argument("--source-revision", help="40-hex Git revision the refreshed pins come from")
    parser.add_argument(
        "--manifest", type=Path, help=f"file-pin manifest path (default: {DEFAULT_MANIFEST.as_posix()})"
    )
    parser.add_argument(
        "--value-pins",
        action="store_true",
        help="refresh named value pins instead of frozen-runtime file pins",
    )
    parser.add_argument(
        "--value-manifest",
        type=Path,
        help=f"value-pin manifest path (default: {DEFAULT_VALUE_MANIFEST.as_posix()})",
    )
    parser.add_argument(
        "--set",
        dest="values",
        action="append",
        default=[],
        metavar="NAME=SHA256",
        help="reviewed replacement value for a named value pin (repeatable)",
    )
    parser.add_argument("--root", type=Path, default=ROOT, help="repository root used to resolve manifest paths")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.dry_run and args.confirm:
            raise PinRefreshError("--dry-run cannot be combined with --confirm")
        confirm = args.confirm and not args.dry_run
        reason, revision = _provenance(args.reason, args.source_revision)
        root = args.root.resolve()
        if args.value_pins:
            if args.manifest is not None:
                raise PinRefreshError("--manifest applies to file-byte pins; use --value-manifest with --value-pins")
            manifest_path = args.value_manifest or DEFAULT_VALUE_MANIFEST
            if not manifest_path.is_absolute():
                manifest_path = root / manifest_path
            manifest = _load_value_manifest(manifest_path)
            assignments = _parse_value_assignments(args.values)
            changes = _plan_value_changes(manifest, assignments)
            if not confirm:
                _report_value(changes, reason, revision, confirm=False)
                return 0
            _apply_value_changes(manifest, changes, reason, revision)
            payload = json.dumps(manifest, indent=2, ensure_ascii=False) + "\n"
            _atomic_write(manifest_path, payload)
            _report_value(changes, reason, revision, confirm=True)
            return 0
        if args.values:
            raise PinRefreshError("--set requires --value-pins")
        if args.value_manifest is not None:
            raise PinRefreshError("--value-manifest requires --value-pins")
        manifest_path = args.manifest or DEFAULT_MANIFEST
        if not manifest_path.is_absolute():
            manifest_path = root / manifest_path
        manifest = _load_manifest(manifest_path)
        changes = _plan_changes(manifest, root)
        if not confirm:
            _report(changes, reason, revision, confirm=False)
            return 0
        _apply_changes(manifest, changes, reason, revision)
        payload = json.dumps(manifest, indent=2, ensure_ascii=False) + "\n"
        _atomic_write(manifest_path, payload)
        _report(changes, reason, revision, confirm=True)
        return 0
    except PinRefreshError as error:
        print(f"error: {_sanitize(error)}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
