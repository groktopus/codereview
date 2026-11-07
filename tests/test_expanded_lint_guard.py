"""Actual pinned-Ruff CLI probes for the expanded lint debt ratchet."""

from __future__ import annotations

import ast
import hashlib
import importlib.util
import json
import subprocess
import sys
from collections import Counter
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/check_expanded_lint.py"
SPEC = importlib.util.spec_from_file_location("check_expanded_lint", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
GUARD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GUARD)
BAD = "def seeded(items=[]):\n    return items\n"


def prepare(root: Path) -> Path:
    for name in GUARD.ROOTS:
        (root / name).mkdir()
    manifest = root / GUARD.PIN_MANIFEST
    manifest.parent.mkdir(parents=True)
    manifest.write_text('{"pins": {}, "pin_files": {}}', encoding="utf-8")
    path = root / "src/mod.py"
    path.write_text(BAD, encoding="utf-8")
    return path


def run(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), "--root", str(root), "--baseline", "baseline.json", *args],
        capture_output=True,
        text=True,
        check=False,
    )


def accept(root: Path) -> None:
    result = run(root, "--write-candidate", "candidate.json", "--reason", "Reviewed synthetic test debt")
    assert result.returncode == 0, result.stderr
    (root / "baseline.json").write_bytes((root / "candidate.json").read_bytes())


def report(result: subprocess.CompletedProcess[str], expected: int) -> dict:
    assert result.returncode == expected, (result.stdout, result.stderr)
    return json.loads(result.stdout)


def test_seeded_new_violation_fails_cli(tmp_path: Path) -> None:
    path = prepare(tmp_path)
    path.write_text("", encoding="utf-8")
    accept(tmp_path)
    path.write_text(BAD, encoding="utf-8")
    result = report(run(tmp_path, "--json"), 1)
    assert result["status"] == "FAIL"
    assert [(item["kind"], item["code"], item["scope"]) for item in result["findings"]] == [
        ("NEW_FINDING", "B006", "seeded")
    ]


def test_line_motion_is_stable_but_growth_and_cleanup_fail(tmp_path: Path) -> None:
    path = prepare(tmp_path)
    accept(tmp_path)
    path.write_text("# inserted lines\n\n" + BAD, encoding="utf-8")
    assert report(run(tmp_path, "--json"), 0)["remaining_debt"] == 1
    path.write_text(BAD + "\n" + BAD, encoding="utf-8")
    assert {item["kind"] for item in report(run(tmp_path, "--json"), 1)["findings"]} == {"BASELINE_GROWTH"}
    path.write_text("", encoding="utf-8")
    assert {item["kind"] for item in report(run(tmp_path, "--json"), 1)["findings"]} == {"BASELINE_STALE"}


@pytest.mark.parametrize("change", ["rename", "move", "replace", "noqa", "ignore", "syntax"])
def test_identity_changes_and_suppression_cannot_hide_debt(tmp_path: Path, change: str) -> None:
    path = prepare(tmp_path)
    accept(tmp_path)
    if change == "rename":
        path.write_text(BAD.replace("seeded", "renamed"), encoding="utf-8")
    elif change == "move":
        (tmp_path / "tests/moved.py").write_text(path.read_text(encoding="utf-8"), encoding="utf-8")
        path.write_text("", encoding="utf-8")
    elif change == "replace":
        path.write_text(BAD.replace("items", "other"), encoding="utf-8")
    elif change == "noqa":
        path.write_text(BAD.replace("):", "):  # noqa: B006"), encoding="utf-8")
    elif change == "ignore":
        (tmp_path / "ruff.toml").write_text('exclude = ["src/**"]\n[lint]\nignore = ["B006"]\n', encoding="utf-8")
        (tmp_path / ".gitignore").write_text("src/\n", encoding="utf-8")
    else:
        path.write_text("def invalid(\n", encoding="utf-8")
    if change in {"noqa", "ignore"}:
        assert report(run(tmp_path, "--json"), 0)["remaining_debt"] == 1
    elif change == "syntax":
        assert run(tmp_path).returncode == 2
    else:
        findings = report(run(tmp_path, "--json"), 1)["findings"]
        assert {item["kind"] for item in findings} == {"NEW_FINDING", "BASELINE_STALE"}


def test_only_explicit_immutable_files_excluded(tmp_path: Path) -> None:
    prepare(tmp_path)
    frozen = tmp_path / "tests/fixtures/frozen-runtime-7d550b6/nested/mod.py"
    frozen.parent.mkdir(parents=True)
    frozen.write_text("def intentionally_invalid(\n", encoding="utf-8")
    base = tmp_path / "tests/fixtures/historical-base.py"
    base.write_text(BAD, encoding="utf-8")
    maintained = tmp_path / "tests/fixtures/maintained.py"
    maintained.write_text(BAD, encoding="utf-8")
    manifest = {
        "pin_files": {str(index): path.relative_to(tmp_path).as_posix() for index, path in enumerate((frozen, base))},
        "pins": {
            str(index): hashlib.sha256(path.read_bytes()).hexdigest() for index, path in enumerate((frozen, base))
        },
    }
    (tmp_path / GUARD.PIN_MANIFEST).write_text(json.dumps(manifest), encoding="utf-8")
    files = {path.relative_to(tmp_path).as_posix() for path in GUARD.maintained_files(tmp_path)}
    assert files == {"src/mod.py", "tests/fixtures/maintained.py"}
    base.write_text("changed", encoding="utf-8")
    with pytest.raises(ValueError, match="pin mismatch"):
        GUARD.maintained_files(tmp_path)
    base.write_text(BAD, encoding="utf-8")
    (tmp_path / "tests/fixtures/new-base.py").write_text(BAD, encoding="utf-8")
    with pytest.raises(ValueError, match="unregistered immutable"):
        GUARD.maintained_files(tmp_path)


def test_tool_mismatch_and_candidate_overwrite_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    prepare(tmp_path)
    monkeypatch.setattr(GUARD, "RUFF_VERSION", "not-installed")
    with pytest.raises(ValueError, match="requires ruff"):
        GUARD.collect(tmp_path)
    assert run(tmp_path, "--write-candidate", "baseline.json", "--reason", "Reviewed synthetic debt").returncode == 2
    accept(tmp_path)
    assert run(tmp_path, "--write-candidate", "candidate.json", "--reason", "Reviewed synthetic debt").returncode == 2


def test_malformed_baseline_rejected(tmp_path: Path) -> None:
    prepare(tmp_path)
    accept(tmp_path)
    path = tmp_path / "baseline.json"
    original = json.loads(path.read_text(encoding="utf-8"))
    for mutation in ("version", "count", "duplicate", "path", "fingerprint"):
        data = json.loads(json.dumps(original))
        if mutation == "version":
            data["policy"]["ruff_version"] = "0.15.20"
        elif mutation == "count":
            data["entries"][0]["count"] = True
        elif mutation == "duplicate":
            data["entries"].append(data["entries"][0])
        elif mutation == "path":
            data["entries"][0]["path"] = "../outside.py"
        else:
            data["entries"][0]["fingerprint"] = "bad"
        path.write_text(json.dumps(data), encoding="utf-8")
        with pytest.raises(ValueError):
            GUARD.load_baseline(path)


def test_comment_replacement_is_new_debt(tmp_path: Path) -> None:
    path = prepare(tmp_path)
    # Construct untrusted ambiguous character data without putting it in authored comments.
    ambiguous = chr(0x0410)
    path.write_text(f"# old ambiguous {ambiguous}\nx = 1\n", encoding="utf-8")
    accept(tmp_path)
    path.write_text(f"x = 1\n# newly introduced ambiguous {ambiguous} elsewhere\n", encoding="utf-8")
    findings = report(run(tmp_path, "--json"), 1)["findings"]
    assert {item["kind"] for item in findings} == {"NEW_FINDING", "BASELINE_STALE"}


def test_ast_fingerprint_ignores_optional_empty_fields() -> None:
    tree = ast.parse("def f(items=[]):\n    return items\n")
    original = GUARD.canonical_ast(tree)
    tree.body[0].type_params = []
    assert GUARD.canonical_ast(tree) == original
    assert '"kwonlyargs"' not in json.dumps(original)


def test_counter_no_cross_scope_or_code_budget_transfer() -> None:
    key = ("src/mod.py", "B006", "first", "fingerprint")
    baseline = Counter({key: 2})
    other = ("src/mod.py", "B006", "second", "fingerprint")
    findings = GUARD.compare(Counter({key: 1, other: 1}), baseline)
    assert {item["kind"] for item in findings} == {"BASELINE_STALE", "NEW_FINDING"}
