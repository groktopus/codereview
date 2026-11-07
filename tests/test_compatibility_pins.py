"""VD-3 checks: compatibility pins live in one named, provenance-carrying manifest."""

from __future__ import annotations

import ast
import json
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
            if name in {"pin", "assert_pin_value"} and isinstance(argument, ast.Constant):
                if isinstance(argument.value, str):
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


VALUE_PIN_PREFIXES = ("historical.", "runtime.", "fixture.", "contract.")


def _compatibility_decorated(node: ast.AST) -> bool:
    decorators = getattr(node, "decorator_list", ())
    return any("pytest.mark.compatibility" in ast.unparse(decorator) for decorator in decorators)


def _module_marks_compatibility(tree: ast.Module) -> bool:
    for node in tree.body:
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        names = [target.id for target in targets if isinstance(target, ast.Name)]
        if "pytestmark" in names and node.value is not None:
            if "pytest.mark.compatibility" in ast.unparse(node.value):
                return True
    return False


def _value_pin_names_called(node: ast.AST) -> list[str]:
    names: list[str] = []
    for child in ast.walk(node):
        if not isinstance(child, ast.Call) or not child.args:
            continue
        function = child.func
        function_name = function.id if isinstance(function, ast.Name) else getattr(function, "attr", None)
        argument = child.args[0]
        if function_name in {"pin", "assert_pin_value"} and isinstance(argument, ast.Constant):
            if isinstance(argument.value, str) and argument.value.startswith(VALUE_PIN_PREFIXES):
                names.append(argument.value)
    return names


def test_value_pin_bearing_tests_are_marked_compatibility():
    known = set(compatibility_pins.pin_names())
    missing: list[str] = []
    for path in _test_files():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        module_marked = _module_marks_compatibility(tree)
        for node in tree.body:
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if not node.name.startswith("test_") or module_marked or _compatibility_decorated(node):
                continue
            for name in _value_pin_names_called(node):
                if name in known:
                    missing.append(f"{path.relative_to(ROOT).as_posix()}::{node.name}: {name}")

    assert not missing, (
        "tests asserting historical value pins must carry '@pytest.mark.compatibility' "
        "so the ordinary suite does not depend on historical evidence and CI runs them "
        "in the separate compatibility job.\n" + "\n".join(missing)
    )


def test_compatibility_marker_is_registered_and_ci_runs_it_separately():
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    workflow = (ROOT / ".github" / "workflows" / "test.yml").read_text(encoding="utf-8")

    assert "compatibility: historical compatibility checks against preserved revision pins" in pyproject
    assert "python -m pytest -q -m compatibility" in workflow
    assert 'python -m pytest -q -m "not compatibility"' in workflow
    assert "Historical compatibility suite" in workflow


def test_value_pin_mismatch_names_module_revision_and_exact_refresh_command(tmp_path: Path):
    name = "runtime.example.module_tree_sha256"
    revision = "c" * 40
    expected = "a" * 64
    actual = "b" * 64
    manifest = tmp_path / "compatibility-pins.v1.json"
    manifest.write_text(
        json.dumps(
            {
                "schema": compatibility_pins.SCHEMA,
                "pins": {
                    name: {
                        "value": expected,
                        "kind": "historical-runtime",
                        "provenance": {
                            "artifact": "scripts/run_example.py",
                            "source_revision": revision,
                            "recorded_at": "2026-11-06",
                            "reason": "Reviewed historical runtime identity for the example fixture set.",
                        },
                    }
                },
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(compatibility_pins.CompatibilityPinError) as error:
        compatibility_pins.assert_pin_value(name, actual, module="scripts/run_example.py", path=manifest)

    message = str(error.value)
    assert "compatibility value-pin mismatch" in message
    assert "module 'scripts/run_example.py'" in message
    assert f"historical revision {revision}" in message
    assert expected in message
    assert actual in message
    assert compatibility_pins.refresh_command(name, actual) in message
    assert "--value-pins" in message and "--reason" in message and "--source-revision" in message

    compatibility_pins.assert_pin_value(name, expected, module="scripts/run_example.py", path=manifest)


def test_assert_pin_value_refuses_unknown_names(tmp_path: Path):
    manifest = tmp_path / "compatibility-pins.v1.json"
    manifest.write_text(
        json.dumps(
            {
                "schema": compatibility_pins.SCHEMA,
                "pins": {
                    "runtime.example.module_tree_sha256": {
                        "value": "a" * 64,
                        "kind": "historical-runtime",
                        "provenance": {
                            "artifact": "scripts/run_example.py",
                            "source_revision": "c" * 40,
                            "recorded_at": "2026-11-06",
                            "reason": "Reviewed historical runtime identity for the example fixture set.",
                        },
                    }
                },
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(compatibility_pins.CompatibilityPinError, match="unknown compatibility pin"):
        compatibility_pins.assert_pin_value("runtime.not_a_pin", "b" * 64, module="x.py", path=manifest)
