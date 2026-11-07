"""Real mypy 1.15 implementation probes; no runtime source execution."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from collections import Counter
from pathlib import Path
from unittest.mock import patch

import pytest

from scripts import check_typing as guard

pytestmark = pytest.mark.skipif(sys.version_info >= (3, 14), reason="mypy 1.15 supports host Python 3.11-3.13 only")

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/check_typing.py"
BAD = "def seeded(value):\n    return value\n"


def prepare(root: Path, source: str = "") -> Path:
    (root / "src").mkdir()
    (root / "scripts").mkdir()
    (root / "tests").mkdir()
    shutil.copyfile(ROOT / guard.CONFIG, root / guard.CONFIG)
    for name in guard.OWN_FILES:
        (root / name).write_text("", encoding="utf-8")
    path = root / "src/mod.py"
    path.write_text(source, encoding="utf-8")
    return path


def run(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), "--root", str(root), "--baseline", "baseline.json", *args],
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )


def accept(root: Path) -> None:
    result = run(root, "--write-candidate", "candidate.json", "--reason", "Reviewed synthetic historical debt")
    assert result.returncode == 0, (result.stdout, result.stderr)
    (root / "baseline.json").write_bytes((root / "candidate.json").read_bytes())


def report(root: Path, expected: int) -> dict[str, object]:
    result = run(root, "--json")
    assert result.returncode == expected, (result.stdout, result.stderr)
    data: dict[str, object] = json.loads(result.stdout)
    return data


def test_seeded_untyped_implementation_fails(tmp_path: Path) -> None:
    path = prepare(tmp_path)
    accept(tmp_path)
    path.write_text(BAD, encoding="utf-8")
    result = report(tmp_path, 1)
    assert result["status"] == "FAIL"
    assert "no-untyped-def" in json.dumps(result["findings"])
    assert "NEW_ERROR" in json.dumps(result["findings"])


def test_wrong_shape_real_implementation_fails(tmp_path: Path) -> None:
    path = prepare(tmp_path)
    accept(tmp_path)
    path.write_text(
        "from typing import TypedDict\nclass Record(TypedDict):\n    unit_ids: list[str]\n"
        "def seeded() -> Record:\n    return {'unit_ids': 'wrong'}\n",
        encoding="utf-8",
    )
    result = report(tmp_path, 1)
    assert "typeddict-item" in json.dumps(result["findings"])
    assert result["implementation_files"] == ["src/mod.py"]


def test_line_motion_stable_rename_and_cleanup_stale(tmp_path: Path) -> None:
    path = prepare(tmp_path, BAD)
    accept(tmp_path)
    path.write_text("# moved\n\n" + BAD, encoding="utf-8")
    assert report(tmp_path, 0)["remaining_debt"] == 1
    path.write_text(BAD.replace("seeded", "renamed"), encoding="utf-8")
    findings = json.dumps(report(tmp_path, 1)["findings"])
    assert "NEW_ERROR" in findings and "STALE_DEBT" in findings
    path.write_text("", encoding="utf-8")
    assert "STALE_DEBT" in json.dumps(report(tmp_path, 1)["findings"])


def test_unicode_byte_column_binds_the_actual_statement(tmp_path: Path) -> None:
    source = 'def f() -> None:\n    éééééééééééé: int = "a"; x: int = 1\n'
    path = prepare(tmp_path, source)
    accept(tmp_path)
    path.write_text(source.replace("x: int = 1", "x: int = 2"), encoding="utf-8")
    assert report(tmp_path, 0)["remaining_debt"] == 1
    path.write_text(source.replace('"a"', '"b"'), encoding="utf-8")
    assert "NEW_ERROR" in json.dumps(report(tmp_path, 1)["findings"])


def test_new_modules_are_automatically_checked(tmp_path: Path) -> None:
    prepare(tmp_path)
    accept(tmp_path)
    path = tmp_path / "src/new_module.py"
    path.write_text("def clean() -> int:\n    return 1\n", encoding="utf-8")
    result = report(tmp_path, 0)
    assert result["new_implementations"] == ["src/new_module.py"]
    files = result["implementation_files"]
    assert isinstance(files, list) and "src/new_module.py" in files
    path.write_text(BAD, encoding="utf-8")
    assert "src/new_module.py" in json.dumps(report(tmp_path, 1)["findings"])


def test_missing_module_and_shadow_stub_fail_closed(tmp_path: Path) -> None:
    path = prepare(tmp_path)
    accept(tmp_path)
    path.rename(tmp_path / "src/renamed.py")
    assert "MISSING_IMPLEMENTATION" in json.dumps(report(tmp_path, 1)["findings"])
    (tmp_path / "src/renamed.pyi").write_text("", encoding="utf-8")
    assert run(tmp_path).returncode == 2


def test_suppressions_are_explicit_debt_and_directives_rejected(tmp_path: Path) -> None:
    path = prepare(tmp_path)
    accept(tmp_path)
    path.write_text(BAD.replace(":\n", ":  # type: ignore[no-untyped-def]\n"), encoding="utf-8")
    assert "type-ignore" in json.dumps(report(tmp_path, 1)["findings"])
    path.write_text(BAD.replace(":\n", ":  # type:\tignore[no-untyped-def]\n"), encoding="utf-8")
    assert "type-ignore" in json.dumps(report(tmp_path, 1)["findings"])
    path.write_text("# mypy: ignore-errors\n" + BAD, encoding="utf-8")
    assert run(tmp_path).returncode == 2
    path.write_text("from typing import no_type_check as exempt\n@exempt\n" + BAD, encoding="utf-8")
    assert run(tmp_path).returncode == 2
    path.write_text("import typing as t\n@t.no_type_check\n" + BAD, encoding="utf-8")
    assert run(tmp_path).returncode == 2


def test_imports_config_versions_and_overwrite_fail_closed(tmp_path: Path) -> None:
    path = prepare(tmp_path)
    accept(tmp_path)
    (tmp_path / "mypy.py").write_text("raise RuntimeError('repository module must not execute')\n", encoding="utf-8")
    assert report(tmp_path, 0)["status"] == "PASS"
    path.write_text("import vd4_missing_dependency\n", encoding="utf-8")
    assert run(tmp_path).returncode == 2
    path.write_text("", encoding="utf-8")
    config = tmp_path / guard.CONFIG
    config.write_text(config.read_text(encoding="utf-8") + "\n# changed policy\n", encoding="utf-8")
    assert run(tmp_path).returncode == 2
    assert run(tmp_path, "--write-candidate", "baseline.json", "--reason", "Reviewed synthetic debt").returncode == 2
    with patch.dict(guard.VERSIONS, {"mypy": "not-installed"}):
        try:
            guard.environment()
        except ValueError as exc:
            assert "version mismatch" in str(exc)
        else:
            raise AssertionError("wrong mypy version accepted")


def test_identity_counts_cannot_spend_other_allowances() -> None:
    first: guard.Key = ("src/mod.py", "assignment", "seeded", "first")
    second: guard.Key = ("src/mod.py", "assignment", "other", "second")
    baseline = Counter({first: 1, second: 1})
    findings = guard.compare(Counter({first: 2}), baseline)
    assert {item["kind"] for item in findings} == {"DEBT_GROWTH", "STALE_DEBT"}


def test_actual_repository_all_runtime_modules_are_in_scope() -> None:
    files = guard.implementation_files(ROOT)
    assert len(files) >= 42
    for module in ("engine", "cli", "providers", "actions_publication", "contracts", "github_app_credentials"):
        assert f"src/pr_review_harness/{module}.py" in files
    assert not any(path.endswith(".pyi") for path in files)
