"""Load named, provenance-carrying compatibility pins (VD-3).

Historical evidence and contract artifacts are pinned by SHA-256 digests.  Those
digests live in ``tests/compatibility-pins.v1.json`` rather than in individual
tests so a reviewed migration can update one named entry.  Synthetic fixture
digests are deliberately *not* recorded here; they are local test data and are
marked ``# vd3-non-pin:`` where they appear.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Final

MANIFEST_PATH: Final = Path(__file__).resolve().parent / "compatibility-pins.v1.json"
SCHEMA: Final = "pr-review-compatibility-value-pins.v1"
HEX256: Final = re.compile(r"[0-9a-f]{64}\Z")
REVISION: Final = re.compile(r"[0-9a-f]{40}\Z")
PIN_NAME: Final = re.compile(r"[a-z0-9]+(?:[._][a-z0-9]+)*\Z")
PROVENANCE_FIELDS: Final = ("artifact", "source_revision", "recorded_at", "reason")
NON_PIN_MARKER: Final = "vd3-non-pin"


class CompatibilityPinError(ValueError):
    """A manifest or named-pin lookup failed with an actionable message."""


def _invalid(detail: str) -> CompatibilityPinError:
    return CompatibilityPinError(
        f"invalid compatibility pin manifest {MANIFEST_PATH.name}: {detail}. "
        f"Named pins are reviewed evidence; update the manifest only through a reviewed migration."
    )


def _validate_entry(name: object, entry: object) -> None:
    if not isinstance(name, str) or not PIN_NAME.fullmatch(name):
        raise _invalid(f"pin name {name!r} is not a lower-case dotted identifier")
    if not isinstance(entry, dict):
        raise _invalid(f"pin {name!r} must be an object")
    value = entry.get("value")
    if not isinstance(value, str) or not HEX256.fullmatch(value):
        raise _invalid(f"pin {name!r} value must be a lower-case 64-character SHA-256 digest")
    kind = entry.get("kind")
    if not isinstance(kind, str) or not kind:
        raise _invalid(f"pin {name!r} kind is missing")
    provenance = entry.get("provenance")
    if not isinstance(provenance, dict):
        raise _invalid(f"pin {name!r} provenance is missing")
    for field in PROVENANCE_FIELDS:
        field_value = provenance.get(field)
        if not isinstance(field_value, str) or not field_value.strip():
            raise _invalid(f"pin {name!r} provenance.{field} is missing")
    revision = provenance["source_revision"]
    if not isinstance(revision, str) or not REVISION.fullmatch(revision):
        raise _invalid(f"pin {name!r} provenance.source_revision must be a 40-character Git revision")
    if len(provenance["reason"].strip()) < 10:
        raise _invalid(f"pin {name!r} provenance.reason must explain the pin in at least 10 characters")


def load_manifest(path: Path | None = None) -> dict[str, Any]:
    """Read and validate the compatibility manifest."""
    target = MANIFEST_PATH if path is None else Path(path)
    try:
        manifest = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise CompatibilityPinError(
            f"compatibility pin manifest {target.name} is unavailable or invalid JSON; "
            "restore the reviewed manifest rather than inlining digests in tests"
        ) from None
    if not isinstance(manifest, dict):
        raise _invalid("root must be a JSON object")
    if manifest.get("schema") != SCHEMA:
        raise _invalid(f"schema must be {SCHEMA!r}")
    entries = manifest.get("pins")
    if not isinstance(entries, dict) or not entries:
        raise _invalid("pins must be a non-empty object")
    for name, entry in entries.items():
        _validate_entry(name, entry)
    manifest["pins"] = entries
    return manifest


def pins(path: Path | None = None) -> dict[str, dict[str, Any]]:
    """Return the named pin entries keyed by name."""
    entries = load_manifest(path)["pins"]
    assert isinstance(entries, dict)
    return entries


def pin(name: str, path: Path | None = None) -> str:
    """Return one named pin value, failing closed with the available names."""
    entries = pins(path)
    entry = entries.get(name)
    if entry is None:
        available = ", ".join(sorted(entries))
        raise CompatibilityPinError(
            f"unknown compatibility pin {name!r}; named pins live in {MANIFEST_PATH.name} "
            f"and the available names are: {available}"
        )
    return str(entry["value"])


def pin_names(path: Path | None = None) -> tuple[str, ...]:
    """Return every named pin in the manifest."""
    return tuple(sorted(pins(path)))


def refresh_command(name: str, value: str) -> str:
    """Return the exact reviewed command that replaces one value pin."""
    return (
        "python scripts/refresh_compatibility_pins.py --value-pins "
        f"--set {name}={value} --reason '<reviewed reason>' "
        "--source-revision <40-hex-commit> --confirm"
    )


def assert_pin_value(name: str, actual: object, *, module: str, path: Path | None = None) -> None:
    """Fail with the module, historical revision, and exact refresh command.

    Tests that compare a recomputed historical identity to a named pin use this
    helper so a mismatch tells the operator what changed and how a reviewed
    migration is recorded, instead of raising a bare assertion.
    """
    entries = pins(path)
    entry = entries.get(name)
    if entry is None:
        pin(name, path)
        raise AssertionError("unreachable: pin() must raise for an unknown name")
    expected = str(entry["value"])
    observed = str(actual)
    if observed == expected:
        return
    provenance = entry["provenance"]
    assert isinstance(provenance, dict)
    revision = provenance["source_revision"]
    artifact = provenance["artifact"]
    raise CompatibilityPinError(
        f"compatibility value-pin mismatch: pin {name!r} for module {module!r} "
        f"(artifact {artifact!r}) at historical revision {revision}; "
        f"expected {expected}, got {observed}. Historical pins are immutable; preserve prior "
        "evidence and record a reviewed migration before refreshing. The exact refresh command is:\n  "
        + refresh_command(name, observed)
    )
