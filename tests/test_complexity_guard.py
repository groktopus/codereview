"""Tests for the function-length complexity guard (VD-4)."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import check_complexity  # noqa: E402


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def write_baseline(path: Path, entries: list[dict[str, object]] | None = None, threshold: int = 10) -> None:
    write(
        path,
        json.dumps(
            {
                "schema": check_complexity.BASELINE_SCHEMA,
                "threshold": threshold,
                "entries": entries or [],
            }
        ),
    )


def function_source(name: str = "big", body_lines: int = 12) -> str:
    lines = [f"def {name}() -> int:"]
    lines.extend(f"    value_{index} = {index}" for index in range(body_lines))
    lines.append("    return value_0")
    return "\n".join(lines) + "\n"


def test_new_function_over_threshold_fails(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    write(tmp_path / "pkg/mod.py", function_source(body_lines=12))
    write_baseline(tmp_path / "baseline.json")

    exit_code = check_complexity.main(
        [
            "--root",
            str(tmp_path),
            "--baseline",
            str(tmp_path / "baseline.json"),
            "--paths",
            "pkg",
            "--threshold",
            "10",
            "--json",
        ]
    )
    report = json.loads(capsys.readouterr().out)
    assert exit_code == 1
    assert report["status"] == "FAIL"
    assert report["mode"] == "manifest"
    assert [finding["code"] for finding in report["findings"]] == ["NEW_OVER_THRESHOLD"]
    assert report["findings"][0]["qualname"] == "big"
    assert report["findings"][0]["lines"] == 14


def test_baselined_function_passes_until_it_grows(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    module = tmp_path / "pkg/mod.py"
    write(module, function_source(body_lines=12))
    baseline = tmp_path / "baseline.json"
    write_baseline(baseline, [{"path": "pkg/mod.py", "qualname": "big", "lines": 14}])

    args = ["--root", str(tmp_path), "--baseline", str(baseline), "--paths", "pkg", "--threshold", "10", "--json"]
    assert check_complexity.main(args) == 0
    assert json.loads(capsys.readouterr().out)["findings"] == []

    write(module, function_source(body_lines=13))
    assert check_complexity.main(args) == 1
    report = json.loads(capsys.readouterr().out)
    assert [finding["code"] for finding in report["findings"]] == ["BASELINE_GROWTH"]
    assert "grew from 14 to 15 lines" in report["findings"][0]["message"]


def test_stale_baseline_entry_fails(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    write(tmp_path / "pkg/mod.py", function_source(body_lines=2))
    baseline = tmp_path / "baseline.json"
    write_baseline(baseline, [{"path": "pkg/mod.py", "qualname": "removed_function", "lines": 20}])

    exit_code = check_complexity.main(
        ["--root", str(tmp_path), "--baseline", str(baseline), "--paths", "pkg", "--threshold", "10", "--json"]
    )
    report = json.loads(capsys.readouterr().out)
    assert exit_code == 1
    assert [finding["code"] for finding in report["findings"]] == ["BASELINE_STALE"]


def test_invalid_baseline_is_a_usage_error(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    write(tmp_path / "pkg/mod.py", function_source(body_lines=2))
    write(tmp_path / "baseline.json", json.dumps({"schema": "wrong", "entries": []}))

    exit_code = check_complexity.main(
        [
            "--root",
            str(tmp_path),
            "--baseline",
            str(tmp_path / "baseline.json"),
            "--paths",
            "pkg",
            "--threshold",
            "10",
        ]
    )
    assert exit_code == 2
    assert "baseline schema" in capsys.readouterr().err


def test_update_baseline_makes_the_checked_manifest_pass(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    write(tmp_path / "pkg/mod.py", function_source(body_lines=12))
    baseline = tmp_path / "baseline.json"
    common = ["--root", str(tmp_path), "--baseline", str(baseline), "--paths", "pkg", "--threshold", "10"]

    assert check_complexity.main([*common, "--update-baseline"]) == 0
    capsys.readouterr()
    payload = json.loads(baseline.read_text(encoding="utf-8"))
    assert payload["schema"] == check_complexity.BASELINE_SCHEMA
    assert payload["entries"] == [{"path": "pkg/mod.py", "qualname": "big", "lines": 14}]

    assert check_complexity.main([*common, "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "PASS"


def test_nested_functions_use_qualified_names() -> None:
    source = "class Outer:\n    def method(self):\n        def inner():\n            return 1\n        return inner()\n"
    records = check_complexity.functions_in_source("pkg/mod.py", source)
    assert [record.qualname for record in records] == ["Outer.method", "Outer.method.inner"]


def _git(root: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-C", str(root), "-c", "commit.gpgsign=false", *args],
        check=True,
        capture_output=True,
        text=True,
    )


def test_diff_mode_checks_only_functions_with_changed_lines(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    _git(tmp_path, "init")
    _git(tmp_path, "config", "user.email", "guard@example.invalid")
    _git(tmp_path, "config", "user.name", "Complexity Guard Test")
    module = tmp_path / "pkg/mod.py"
    write(module, function_source("existing", body_lines=12))
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-m", "initial")

    # The existing offender is not baselined, but it is untouched; only the new
    # function is in the diff and should be reported.
    write(module, function_source("existing", body_lines=12) + "\n" + function_source("added", body_lines=12))
    write_baseline(tmp_path / "baseline.json")

    exit_code = check_complexity.main(
        [
            "--root",
            str(tmp_path),
            "--baseline",
            str(tmp_path / "baseline.json"),
            "--paths",
            "pkg",
            "--threshold",
            "10",
            "--diff-base",
            "HEAD",
            "--json",
        ]
    )
    report = json.loads(capsys.readouterr().out)
    assert exit_code == 1
    assert report["mode"] == "diff"
    assert [finding["qualname"] for finding in report["findings"]] == ["added"]


def test_diff_mode_growth_check_applies_to_touched_baselined_function(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _git(tmp_path, "init")
    _git(tmp_path, "config", "user.email", "guard@example.invalid")
    _git(tmp_path, "config", "user.name", "Complexity Guard Test")
    module = tmp_path / "pkg/mod.py"
    write(module, function_source("big", body_lines=12))
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-m", "initial")
    baseline = tmp_path / "baseline.json"
    write_baseline(baseline, [{"path": "pkg/mod.py", "qualname": "big", "lines": 14}])

    write(module, function_source("big", body_lines=13))
    exit_code = check_complexity.main(
        [
            "--root",
            str(tmp_path),
            "--baseline",
            str(baseline),
            "--paths",
            "pkg",
            "--threshold",
            "10",
            "--diff-base",
            "HEAD",
            "--json",
        ]
    )
    report = json.loads(capsys.readouterr().out)
    assert exit_code == 1
    assert [finding["code"] for finding in report["findings"]] == ["BASELINE_GROWTH"]


def test_partial_scan_does_not_report_out_of_scope_baseline_entries_as_stale(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    write(tmp_path / "pkg/mod.py", function_source(body_lines=2))
    write(tmp_path / "other/mod.py", function_source(body_lines=12))
    baseline = tmp_path / "baseline.json"
    write_baseline(baseline, [{"path": "other/mod.py", "qualname": "big", "lines": 14}])

    exit_code = check_complexity.main(
        ["--root", str(tmp_path), "--baseline", str(baseline), "--paths", "pkg", "--threshold", "10", "--json"]
    )
    assert exit_code == 0
    assert json.loads(capsys.readouterr().out)["findings"] == []


def test_repository_baseline_is_current() -> None:
    records, scanned = check_complexity.scan(ROOT, check_complexity.DEFAULT_PATHS)
    baseline = check_complexity.load_baseline(ROOT / check_complexity.DEFAULT_BASELINE)
    assert scanned
    assert check_complexity.evaluate(records, baseline, check_complexity.DEFAULT_THRESHOLD) == []
    scanned_paths = {record.path for record in records}
    assert "tests/fixtures/frozen-runtime-7d550b6/cross_model.py" not in scanned_paths
    assert "tests/fixtures/engine-pr170-base.py" not in scanned_paths
