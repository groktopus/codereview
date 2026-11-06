"""VD-3 checks: compatibility pins live in one named, provenance-carrying manifest."""

from __future__ import annotations

import ast
import re
from pathlib import Path

import compatibility_pins
import pytest

TESTS = Path(__file__).resolve().parent
ROOT = TESTS.parent
SHA256_TEXT = re.compile(r"\b[0-9a-f]{64}\b")
NON_PIN_MARKER = re.compile(r"^\s*#\s*vd3-non-pin:\s*(\S.*)\Z")
MIN_EXCEPTION_REASON = 10


def _test_files() -> list[Path]:
    return sorted(path for path in TESTS.rglob("*.py") if "fixtures" not in path.relative_to(TESTS).parts)


def _marked(lines: list[str], lineno: int) -> bool:
    """Return whether the literal on ``lineno`` has an explicit exception marker."""
    if NON_PIN_MARKER.search(lines[lineno - 1]):
        return True
    return lineno >= 2 and bool(NON_PIN_MARKER.search(lines[lineno - 2]))


def _adhoc_sha256_literals() -> list[str]:
    violations: list[str] = []
    for path in _test_files():
        lines = path.read_text(encoding="utf-8").splitlines()
        for lineno, line in enumerate(lines, start=1):
            for match in SHA256_TEXT.finditer(line):
                if _marked(lines, lineno):
                    continue
                relative = path.relative_to(ROOT).as_posix()
                violations.append(f"{relative}:{lineno}: {match.group(0)}")
    return violations


def _exception_markers() -> list[tuple[str, int, str]]:
    markers: list[tuple[str, int, str]] = []
    for path in _test_files():
        lines = path.read_text(encoding="utf-8").splitlines()
        for lineno, line in enumerate(lines, start=1):
            match = NON_PIN_MARKER.search(line)
            if match:
                markers.append((path.relative_to(ROOT).as_posix(), lineno, match.group(1)))
    return markers


def _pins_called_by_tests() -> set[str]:
    called: set[str] = set()
    for path in _test_files():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not node.args:
                continue
            function = node.func
            name = function.id if isinstance(function, ast.Name) else getattr(function, "attr", None)
            argument = node.args[0]
            if name == "pin" and isinstance(argument, ast.Constant) and isinstance(argument.value, str):
                called.add(argument.value)
    return called


def test_manifest_loads_named_pins_with_provenance():
    manifest = compatibility_pins.load_manifest()
    entries = compatibility_pins.pins()

    assert manifest["schema"] == compatibility_pins.SCHEMA
    assert entries
    assert compatibility_pins.pin_names() == tuple(sorted(entries))
    assert len({entry["value"] for entry in entries.values()}) == len(entries)
    for name, entry in entries.items():
        assert entry["kind"], name
        assert entry["provenance"]["artifact"], name
        assert len(entry["provenance"]["reason"].strip()) >= MIN_EXCEPTION_REASON, name


def test_unknown_pin_fails_closed_with_the_available_names():
    with pytest.raises(compatibility_pins.CompatibilityPinError, match="unknown compatibility pin"):
        compatibility_pins.pin("compatibility.not_a_real_pin")


def test_every_manifest_pin_is_referenced_by_a_test():
    known = set(compatibility_pins.pin_names())
    assert _pins_called_by_tests() & known == known


def test_no_adhoc_sha256_literals_outside_the_manifest():
    violations = _adhoc_sha256_literals()

    assert not violations, (
        "ad-hoc 64-hex pin literals must not live in tests. Declare a named entry in "
        "tests/compatibility-pins.v1.json and load it with compatibility_pins.pin(<name>), or, "
        "when the digest is synthetic fixture data rather than a pin, put "
        "'# vd3-non-pin: <reason>' on the line directly above it.\n" + "\n".join(violations)
    )


def test_non_pin_exceptions_are_documented():
    markers = _exception_markers()

    assert markers, "expected at least one synthetic fixture hash marked '# vd3-non-pin:'"
    for path, lineno, reason in markers:
        assert len(reason.strip()) >= MIN_EXCEPTION_REASON, f"{path}:{lineno}: exception reason is too short"
