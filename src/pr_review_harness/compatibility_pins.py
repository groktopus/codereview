"""Load the canonical, provenance-carrying compatibility pin resource."""

from __future__ import annotations

import json
import re
from importlib.resources import files
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Final, cast

RESOURCE_NAME: Final = "compatibility-pins.v1.json"
SCHEMA: Final = "pr-review-compatibility-pins.v1"
HEX256: Final = re.compile(r"[0-9a-f]{64}\Z")
REVISION: Final = re.compile(r"[0-9a-f]{40}\Z")
PIN_NAME: Final = re.compile(r"[a-z0-9]+(?:[._][a-z0-9]+)*\Z")
PROVENANCE_FIELDS: Final = ("artifact", "source_revision", "recorded_at", "reason")


class CompatibilityPinError(ValueError):
    """A canonical pin resource or named-pin lookup failed closed."""


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _read(path: Path | None) -> tuple[dict[str, Any], str]:
    target = files(__package__).joinpath(RESOURCE_NAME) if path is None else Path(path)
    try:
        raw = target.read_text(encoding="utf-8")
        manifest = json.loads(raw, object_pairs_hook=_unique_object)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
        raise CompatibilityPinError(f"compatibility pin resource {RESOURCE_NAME} is unavailable or invalid") from None
    if not isinstance(manifest, dict) or manifest.get("schema") != SCHEMA:
        raise CompatibilityPinError(f"compatibility pin resource {RESOURCE_NAME} has an invalid schema")
    if not isinstance(manifest.get("fixture_set"), str) or not manifest["fixture_set"].strip():
        raise CompatibilityPinError("compatibility pin resource fixture set is invalid")
    if (
        not isinstance(manifest.get("value_manifest_description"), str)
        or not manifest["value_manifest_description"].strip()
    ):
        raise CompatibilityPinError("compatibility value-pin description is invalid")
    return manifest, RESOURCE_NAME


def load_manifest(path: Path | None = None) -> dict[str, Any]:
    """Read and validate both pin sections from the installed resource."""
    manifest, _ = _read(path)
    values = manifest.get("value_pins")
    files_section = manifest.get("file_pins")
    pin_files = manifest.get("pin_files")
    revisions = manifest.get("pin_revisions")
    if not isinstance(values, dict) or not values or not isinstance(files_section, dict) or not files_section:
        raise CompatibilityPinError("compatibility pin resource has missing or empty pin sections")
    if not isinstance(pin_files, dict) or not set(pin_files) <= set(files_section):
        raise CompatibilityPinError("compatibility pin resource file paths do not match file pins")
    if not isinstance(revisions, dict) or set(revisions) - set(files_section):
        raise CompatibilityPinError("compatibility pin resource file revisions are invalid")
    for name, entry in values.items():
        if not isinstance(name, str) or not PIN_NAME.fullmatch(name) or not isinstance(entry, dict):
            raise CompatibilityPinError("compatibility value pin name or entry is invalid")
        provenance = entry.get("provenance")
        if (
            not isinstance(entry.get("value"), str)
            or not HEX256.fullmatch(entry["value"])
            or not isinstance(entry.get("kind"), str)
            or not isinstance(provenance, dict)
        ):
            raise CompatibilityPinError(f"compatibility value pin {name!r} is invalid")
        if not isinstance(entry.get("kind"), str) or not entry["kind"].strip():
            raise CompatibilityPinError(f"compatibility value pin {name!r} kind is invalid")
        for field in PROVENANCE_FIELDS:
            if not isinstance(provenance.get(field), str) or not provenance[field].strip():
                raise CompatibilityPinError(f"compatibility value pin {name!r} provenance is invalid")
        if not REVISION.fullmatch(provenance["source_revision"]):
            raise CompatibilityPinError(f"compatibility value pin {name!r} revision is invalid")
        if len(provenance["reason"].strip()) < 10:
            raise CompatibilityPinError(f"compatibility value pin {name!r} reason is too short")
    historical_revision = manifest.get("historical_revision")
    if not isinstance(historical_revision, str) or not REVISION.fullmatch(historical_revision):
        raise CompatibilityPinError("compatibility historical revision is invalid")
    for name, digest in files_section.items():
        if not isinstance(name, str) or not name or not isinstance(digest, str) or not HEX256.fullmatch(digest):
            raise CompatibilityPinError("compatibility file pin is invalid")
        if name in pin_files:
            relative = pin_files[name]
            posix = PurePosixPath(relative) if isinstance(relative, str) else PurePosixPath("")
            windows = PureWindowsPath(relative) if isinstance(relative, str) else PureWindowsPath("")
            if (
                not isinstance(relative, str)
                or not relative
                or "\\" in relative
                or posix.is_absolute()
                or windows.is_absolute()
                or windows.drive
                or any(part in {"", ".", ".."} for part in relative.split("/"))
            ):
                raise CompatibilityPinError(f"compatibility file pin path for {name!r} is invalid")
        if name in revisions and (not isinstance(revisions[name], str) or not REVISION.fullmatch(revisions[name])):
            raise CompatibilityPinError(f"compatibility file pin revision for {name!r} is invalid")
    for history_name in ("value_refresh_history", "file_refresh_history"):
        history = manifest.get(history_name)
        if not isinstance(history, list):
            raise CompatibilityPinError("compatibility pin refresh history is invalid")
        for record in history:
            if (
                not isinstance(record, dict)
                or not isinstance(record.get("name"), str)
                or any(
                    not isinstance(record.get(field), str)
                    for field in ("old_sha256", "new_sha256", "timestamp", "reason", "source_revision")
                )
            ):
                raise CompatibilityPinError("compatibility pin refresh history record is invalid")
            if (
                not HEX256.fullmatch(record["old_sha256"])
                or not HEX256.fullmatch(record["new_sha256"])
                or not REVISION.fullmatch(record["source_revision"])
                or len(record["reason"].strip()) < 10
            ):
                raise CompatibilityPinError("compatibility pin refresh history provenance is invalid")
    return manifest


def pins(path: Path | None = None) -> dict[str, dict[str, Any]]:
    """Return named semantic pins keyed by name."""
    entries = load_manifest(path)["value_pins"]
    assert isinstance(entries, dict)
    return cast(dict[str, dict[str, Any]], entries)


def pin(name: str, path: Path | None = None) -> str:
    """Return one named value pin, failing closed with available names."""
    entries = pins(path)
    if name not in entries:
        raise CompatibilityPinError(
            f"unknown compatibility pin {name!r}; available names: {', '.join(sorted(entries))}"
        )
    return str(entries[name]["value"])


def pin_names(path: Path | None = None) -> tuple[str, ...]:
    return tuple(sorted(pins(path)))


def refresh_command(name: str, value: str) -> str:
    return (
        "python scripts/refresh_compatibility_pins.py --value-pins "
        f"--set {name}={value} --reason '<reviewed reason>' --source-revision <40-hex-commit> --confirm"
    )


def assert_pin_value(name: str, actual: object, *, module: str, path: Path | None = None) -> None:
    entry = pins(path).get(name)
    if entry is None:
        pin(name, path)
        raise AssertionError("unreachable")
    expected, observed = str(entry["value"]), str(actual)
    if observed == expected:
        return
    provenance = entry["provenance"]
    raise CompatibilityPinError(
        f"compatibility value-pin mismatch: pin {name!r} for module {module!r} "
        f"(artifact {provenance['artifact']!r}) at historical revision {provenance['source_revision']}; "
        f"expected {expected}, got {observed}. Preserve prior evidence and record a reviewed migration. "
        f"The exact refresh command is:\n  {refresh_command(name, observed)}"
    )
