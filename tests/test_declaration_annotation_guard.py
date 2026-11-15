from __future__ import annotations

import json
import shutil
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Any

import pytest

from scripts import check_declaration_annotations as guard

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/check_declaration_annotations.py"


def declarations(source: str) -> list[guard.Declaration]:
    return guard.declarations_for_source("synthetic.py", source)


def test_all_parameter_kinds_and_return_are_checked() -> None:
    source = """\
def complete(posonly: int, /, ordinary: int, *args: int, keyword: int, **kwargs: int) -> int:
    return ordinary

def incomplete(posonly, /, ordinary, *args, keyword, **kwargs) -> int:
    return 1
"""
    found = declarations(source)
    assert len(found) == 1
    assert found[0].qualname == "incomplete"
    assert found[0].missing == (
        "positional_only:posonly",
        "positional_or_keyword:ordinary",
        "vararg:args",
        "keyword_only:keyword",
        "kwarg:kwargs",
    )


def test_async_and_missing_return_are_counted() -> None:
    found = declarations("async def fetch(value: int):\n    return value\n")
    assert len(found) == 1
    assert found[0].missing == ("return",)


def test_method_receiver_exemption_is_scope_based_not_name_based() -> None:
    source = """\
import builtins
from builtins import staticmethod as static

class C:
    def instance(self, value: int) -> None:
        pass

    @classmethod
    def classmethod(cls, value: int) -> None:
        pass

    @staticmethod
    def plain_static(value):
        pass

    @builtins.staticmethod
    def qualified_static(value):
        pass

    @static
    def aliased_static(value):
        pass

    def nested_owner(self) -> None:
        def nested(self):
            pass

def ordinary(self):
    pass
"""
    found = declarations(source)
    by_name = {record.qualname: record.missing for record in found}
    assert "C.instance" not in by_name
    assert "C.classmethod" not in by_name
    assert by_name["C.plain_static"] == ("positional_or_keyword:value", "return")
    assert by_name["C.qualified_static"] == ("positional_or_keyword:value", "return")
    assert by_name["C.aliased_static"] == ("positional_or_keyword:value", "return")
    assert by_name["C.nested_owner.nested"] == ("positional_or_keyword:self", "return")
    assert by_name["ordinary"] == ("positional_or_keyword:self", "return")


def test_shadowed_staticmethod_name_is_not_treated_as_builtin() -> None:
    source = """\
staticmethod = custom_decorator

class C:
    @staticmethod
    def decorated(self):
        pass
"""
    found = declarations(source)
    assert len(found) == 1
    assert found[0].missing == ("return",)


def test_comprehension_targets_do_not_shadow_builtin_staticmethod() -> None:
    source = """\
[staticmethod for staticmethod in decorators]

class C:
    @staticmethod
    def static(value):
        pass
"""
    found = declarations(source)
    assert len(found) == 1
    assert found[0].missing == ("positional_or_keyword:value", "return")


def test_walrus_binding_does_shadow_builtin_staticmethod() -> None:
    source = """\
if (staticmethod := custom_decorator):
    pass

class C:
    @staticmethod
    def decorated(self):
        pass
"""
    found = declarations(source)
    assert len(found) == 1
    assert found[0].missing == ("return",)


def test_init_infers_none_but_still_requires_other_parameters() -> None:
    source = """\
class C:
    def __init__(self, value: int):
        self.value = value

    def __init_subclass__(cls):
        pass
"""
    found = declarations(source)
    assert len(found) == 1
    assert found[0].qualname == "C.__init_subclass__"
    assert found[0].missing == ("return",)


def test_init_requires_return_until_any_parameter_is_annotated() -> None:
    source = """\
class NoAnnotations:
    def __init__(self):
        pass

class ReceiverAnnotation:
    def __init__(self: object):
        pass

class MissingOtherParameter:
    def __init__(self: object, value):
        pass

class StaticInitializer:
    @staticmethod
    def __init__(value: int):
        pass

class ClassmethodInitializer:
    @classmethod
    def __init__(cls: type):
        pass

class UnannotatedClassmethodInitializer:
    @classmethod
    def __init__(cls):
        pass
"""
    found = declarations(source)
    by_name = {record.qualname: record.missing for record in found}
    assert by_name["NoAnnotations.__init__"] == ("return",)
    assert "ReceiverAnnotation.__init__" not in by_name
    assert by_name["MissingOtherParameter.__init__"] == ("positional_or_keyword:value",)
    assert "StaticInitializer.__init__" not in by_name
    assert "ClassmethodInitializer.__init__" not in by_name
    assert by_name["UnannotatedClassmethodInitializer.__init__"] == ("return",)


@pytest.mark.parametrize("parameter", ["*, value: int", "*values: int", "**values: int"])
def test_init_keyword_and_variadic_annotations_allow_implicit_none(parameter: str) -> None:
    source = f"class C:\n    def __init__(self, {parameter}):\n        pass\n"
    assert declarations(source) == []


def test_any_and_well_formed_function_type_comments_are_declarations() -> None:
    source = """\
from typing import Any

def inline(value: Any) -> Any:
    return value

def commented(value, other):  # type: (Any, int) -> Any
    return value

class C:
    def method(self, value):  # type: (int) -> None
        pass
"""
    assert declarations(source) == []


def test_type_comment_may_include_method_receiver() -> None:
    source = """\
class C:
    def method(self, value):  # type: (Any, int) -> None
        pass
"""
    assert declarations(source) == []


def test_ellipsis_type_comment_does_not_hide_explicit_untyped_parameters() -> None:
    source = "def loose(value, other):  # type: (...) -> int\n    return 1\n"
    found = declarations(source)
    assert len(found) == 1
    assert found[0].missing == ("positional_or_keyword:value", "positional_or_keyword:other")


@pytest.mark.parametrize(
    "source",
    [
        "def malformed(value):  # type: any words\n    return value\n",
        "def wrong_arity(value, other):  # type: (int) -> int\n    return value\n",
        "def mixed_ellipsis(value, other):  # type: (..., int) -> int\n    return value\n",
        "def conflict(value: int):  # type: (int) -> int\n    return value\n",
    ],
)
def test_malformed_or_mismatched_function_type_comments_fail_closed(source: str) -> None:
    with pytest.raises(guard.DeclarationError):
        declarations(source)


def test_signature_identity_ignores_body_and_line_motion_but_tracks_declaration_edits() -> None:
    original = declarations("def item(value):\n    return value\n")[0]
    moved = declarations("# moved\n\ndef item(value):\n    return 1\n")[0]
    renamed = declarations("def renamed(value):\n    return value\n")[0]
    changed = declarations("def item(value, other):\n    return value\n")[0]
    assert original.key == moved.key
    assert original.key != renamed.key
    assert original.key != changed.key


def test_new_duplicate_and_removed_declaration_identities_fail_ratchet() -> None:
    old = declarations("def item(value):\n    return value\n")[0]
    new = declarations("def item(value, other):\n    return value\n")[0]
    current = Counter({new.key: 1})
    findings = guard.compare(current, Counter({old.key: 1}))
    assert {item["kind"] for item in findings} == {"NEW_UNANNOTATED_DECLARATION", "STALE_ALLOWANCE"}
    assert guard.compare(Counter({old.key: 2}), Counter({old.key: 1}))[0]["kind"] == "DEBT_GROWTH"


def _minimal_compatibility_manifest() -> dict[str, Any]:
    return {
        "schema": "pr-review-compatibility-pins.v1",
        "fixture_set": "synthetic-test-fixture-set",
        "value_manifest_description": "Synthetic compatibility resource for checker tests.",
        "historical_revision": "a" * 40,
        "value_pins": {
            "probe.value": {
                "value": "b" * 64,
                "kind": "test",
                "provenance": {
                    "artifact": "synthetic test input",
                    "source_revision": "a" * 40,
                    "recorded_at": "2026-11-15",
                    "reason": "synthetic loader bootstrap fixture",
                },
            }
        },
        "file_pins": {"probe.file": "c" * 64},
        "pin_files": {},
        "pin_revisions": {},
        "value_refresh_history": [],
        "file_refresh_history": [],
    }


def prepare_synthetic_root(root: Path) -> None:
    for directory in ("src/pr_review_harness", "scripts", "experiments", "tests"):
        (root / directory).mkdir(parents=True, exist_ok=True)
    shutil.copyfile(
        ROOT / "src/pr_review_harness/compatibility_pins.py", root / "src/pr_review_harness/compatibility_pins.py"
    )
    (root / "src/pr_review_harness/__init__.py").write_text("", encoding="utf-8")
    (root / "src/pr_review_harness/compatibility-pins.v1.json").write_text(
        json.dumps(_minimal_compatibility_manifest()), encoding="utf-8"
    )
    (root / "scripts/check_declaration_annotations.py").write_text("", encoding="utf-8")
    (root / "tests/test_declaration_annotation_guard.py").write_text("", encoding="utf-8")


def run_checker(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), "--root", str(root), "--baseline", "baseline.json", *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )


def accept_synthetic_baseline(root: Path) -> None:
    result = run_checker(
        root,
        "--write-candidate",
        "candidate.json",
        "--reason",
        "Synthetic empty declaration baseline for checker test",
    )
    assert result.returncode == 0, (result.stdout, result.stderr)
    (root / "candidate.json").replace(root / "baseline.json")


def test_cli_accepts_typed_new_file_and_rejects_untyped_new_files(tmp_path: Path) -> None:
    prepare_synthetic_root(tmp_path)
    accept_synthetic_baseline(tmp_path)
    (tmp_path / "scripts/typed_new.py").write_text(
        "def typed(value: int) -> int:\n    return value\n", encoding="utf-8"
    )
    typed = run_checker(tmp_path, "--json")
    assert typed.returncode == 0
    assert json.loads(typed.stdout)["status"] == "PASS"
    (tmp_path / "scripts/untyped_new.py").write_text("def untyped(value):\n    return value\n", encoding="utf-8")
    untyped = run_checker(tmp_path, "--json")
    assert untyped.returncode == 1
    report = json.loads(untyped.stdout)
    assert report["status"] == "FAIL"
    assert any(item["kind"] == "NEW_UNANNOTATED_DECLARATION" for item in report["findings"])


@pytest.mark.parametrize(
    "relative",
    [
        "scripts/new_script.py",
        "scripts/new_stub.pyi",
        "experiments/new_experiment.py",
        "tests/test_new_file.py",
    ],
)
def test_cli_catches_untyped_declarations_in_every_noncore_root(tmp_path: Path, relative: str) -> None:
    prepare_synthetic_root(tmp_path)
    accept_synthetic_baseline(tmp_path)
    destination = tmp_path / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text("def new_function(value):\n    return value\n", encoding="utf-8")
    result = run_checker(tmp_path, "--json")
    assert result.returncode == 1
    report = json.loads(result.stdout)
    assert any(
        item["kind"] == "NEW_UNANNOTATED_DECLARATION" and item["path"] == relative for item in report["findings"]
    )


def test_baseline_rejects_duplicate_keys_and_overwrite(tmp_path: Path) -> None:
    prepare_synthetic_root(tmp_path)
    result = run_checker(tmp_path, "--write-candidate", "candidate.json", "--reason", "Synthetic test baseline reason")
    assert result.returncode == 0
    overwrite = run_checker(
        tmp_path, "--write-candidate", "candidate.json", "--reason", "Synthetic test baseline reason"
    )
    assert overwrite.returncode == 2
    (tmp_path / "baseline.json").write_text('{"schema":"first","schema":"second"}', encoding="utf-8")
    invalid = run_checker(tmp_path, "--json")
    assert invalid.returncode == 2
    assert json.loads(invalid.stdout)["status"] == "ERROR"
