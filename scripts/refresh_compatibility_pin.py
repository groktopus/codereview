#!/usr/bin/env python3
"""Refresh a pin in the CA-2 frozen-runtime compatibility manifest.

Only tests/fixtures/frozen-runtime-7d550b6 blobs are managed here. Other historical
hashes have distinct evidence semantics and remain in their owning records.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "tests" / "fixtures" / "frozen-runtime-7d550b6" / "pins.json"
REVISION_RE = re.compile(r"[0-9a-f]{40,64}\Z")
HASH_RE = re.compile(r"[0-9a-f]{64}\Z")


class PinRefreshError(ValueError):
    """Invalid or incomplete historical-pin refresh request."""


def _source_revision(revision: str) -> str:
    if not REVISION_RE.fullmatch(revision):
        raise PinRefreshError("--source-revision must be a full lowercase Git commit ID")
    try:
        resolved = subprocess.run(
            ["git", "-C", str(ROOT), "rev-parse", "--verify", f"{revision}^{{commit}}"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
    except (subprocess.CalledProcessError, OSError):
        raise PinRefreshError(f"source revision is not an available Git commit: {revision}") from None
    if resolved != revision:
        raise PinRefreshError(f"source revision did not resolve exactly to supplied commit: {revision}")
    return resolved


def _verify_revision_blob(revision: str, relative_path: Path, expected_hash: str, *, repo_root: Path) -> None:
    """Require the supplied commit to contain the exact fixture blob being pinned."""
    git_path = relative_path.as_posix()
    try:
        blob = subprocess.run(
            ["git", "-C", str(repo_root), "show", f"{revision}:{git_path}"],
            check=True,
            capture_output=True,
        ).stdout
    except (subprocess.CalledProcessError, OSError):
        raise PinRefreshError(f"source revision does not contain the fixture blob: {git_path}") from None
    if hashlib.sha256(blob).hexdigest() != expected_hash:
        raise PinRefreshError(
            f"source revision fixture blob does not match current bytes for {git_path}: {revision}"
        )


def refresh_pin(
    *, module: str, reason: str | None, source_revision: str | None, dry_run: bool = False,
    manifest_path: Path = MANIFEST, timestamp: dt.datetime | None = None, allowed_root: Path = ROOT,
) -> dict[str, object]:
    """Preview or persist one explicit pin update, requiring complete provenance."""
    if not reason or not reason.strip():
        raise PinRefreshError("refusing pin refresh: --reason is required")
    if not source_revision:
        raise PinRefreshError("refusing pin refresh: --source-revision is required")
    if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]*", module) or ".." in module:
        raise PinRefreshError("--module must name a manifest pin key, for example context_selector.py")
    revision = _source_revision(source_revision)
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise PinRefreshError(f"pin manifest unavailable or invalid: {manifest_path}") from None
    pins = manifest.get("pins")
    pin_files = manifest.get("pin_files")
    if manifest.get("schema") != "pr-review-historical-pins.v1" or not isinstance(pins, dict):
        raise PinRefreshError("pin manifest schema is invalid")
    if module not in pins:
        raise PinRefreshError(f"module is not listed in frozen-runtime manifest: {module}")
    if not isinstance(pin_files, dict) or module not in pin_files:
        raise PinRefreshError(f"module has no fixture path in frozen-runtime manifest: {module}")
    configured_path = Path(pin_files[module])
    fixture_path = (configured_path if configured_path.is_absolute() else allowed_root / configured_path).resolve()
    try:
        fixture_path.relative_to(allowed_root.resolve())
    except ValueError:
        raise PinRefreshError("pin file path escapes repository root") from None
    try:
        new_hash = hashlib.sha256(fixture_path.read_bytes()).hexdigest()
    except OSError:
        raise PinRefreshError(f"fixture blob unavailable: {fixture_path}") from None
    old_hash = pins[module]
    if not isinstance(old_hash, str) or not HASH_RE.fullmatch(old_hash):
        raise PinRefreshError(f"existing pin is invalid for module: {module}")
    if old_hash == new_hash and not dry_run:
        raise PinRefreshError(f"refusing no-op pin refresh: fixture still matches recorded blob for {module}")
    try:
        relative_fixture = fixture_path.relative_to(allowed_root.resolve())
    except ValueError:
        raise PinRefreshError("pin file path escapes repository root") from None
    _verify_revision_blob(revision, relative_fixture, new_hash, repo_root=allowed_root)
    record = {
        "module": module,
        "old_blob_sha256": old_hash,
        "new_blob_sha256": new_hash,
        "reason": reason.strip(),
        "source_revision": revision,
        "historical_revision": manifest.get("historical_revision"),
        "timestamp": (timestamp or dt.datetime.now(dt.timezone.utc)).astimezone(dt.timezone.utc).isoformat(),
    }
    if dry_run:
        return {"dry_run": True, **record}
    history = manifest.setdefault("refresh_history", [])
    if not isinstance(history, list):
        raise PinRefreshError("pin manifest refresh_history must be a list")
    history.append(record)
    pins[module] = new_hash
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return {"dry_run": False, **record}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--module", required=True, help="manifest pin key (fixture basename or named tree pin)")
    parser.add_argument("--reason", help="why historical evidence must be updated")
    parser.add_argument("--source-revision", help="full Git commit supplying the revised blob")
    parser.add_argument("--dry-run", action="store_true", help="show the provenance record without writing")
    args = parser.parse_args(argv)
    try:
        result = refresh_pin(
            module=args.module,
            reason=args.reason,
            source_revision=args.source_revision,
            dry_run=args.dry_run,
        )
    except PinRefreshError as error:
        print(str(error), file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
