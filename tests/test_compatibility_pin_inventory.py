from __future__ import annotations

import json
import sys
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

import audit_compatibility_pin_literals as pin_inventory  # noqa: E402

audit = pin_inventory.audit


def _make_root(tmp_path: Path) -> Path:
    for name in ("src", "scripts", "tests", "experiments", "docs", "examples", ".github"):
        (tmp_path / name).mkdir()
    return tmp_path


def test_inventory_classifies_obvious_shapes_but_preserves_unknowns(tmp_path: Path):
    root = _make_root(tmp_path)
    revision = "0123456789abcdef" * 2 + "01234567"
    (root / "src" / "runtime.py").write_text(
        f'SOURCE_REVISION = "{revision}"\nresponse_sha256 = "' + "a" * 64 + '"\nopaque = "' + "b" * 64 + '"\n',
        encoding="utf-8",
    )
    (root / ".github" / "action.yml").write_text(
        f"steps:\n  - uses: owner/action@{revision}\n",
        encoding="utf-8",
    )

    result = audit(root)
    categories = [item["category"] for item in result["occurrences"]]

    assert categories.count("git_revision_candidate") == 1
    assert categories.count("content_digest_candidate") == 1
    assert categories.count("unknown") == 1
    assert categories.count("action_commit_pin") == 1
    assert result["occurrence_count"] == 4
    assert all(len(item["context_sha256"]) == 64 for item in result["occurrences"])
    assert "do not prove a compatibility pin" in result["classification_note"]


def test_inventory_is_deterministic_and_does_not_scan_hidden_worktrees(tmp_path: Path):
    root = _make_root(tmp_path)
    (root / "tests" / "sample.py").write_text('value = "' + "c" * 64 + '"\n', encoding="utf-8")
    (root / "tests" / ".git").mkdir()
    (root / "tests" / ".git" / "ignored.py").write_text('value = "' + "d" * 64 + '"\n', encoding="utf-8")
    (root / "docs" / "evidence").mkdir()
    (root / "docs" / "evidence" / "vd3-pin-census-main.json").write_text(
        'value = "' + "e" * 64 + '"\n', encoding="utf-8"
    )

    first = audit(root, source_revision="a" * 40)
    second = audit(root, source_revision="a" * 40)

    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)
    assert first["source_revision"] == "a" * 40
    assert first["occurrence_count"] == 1
    paths = [item["path"] for item in first["occurrences"]]
    assert "docs/evidence/vd3-pin-census-main.json" not in paths


def test_cli_refuses_evidence_output_without_explicit_opt_in(tmp_path: Path, monkeypatch):
    root = _make_root(tmp_path)
    destination = root / "docs" / "evidence" / "census.json"
    destination.parent.mkdir(parents=True)
    monkeypatch.setattr(pin_inventory, "ROOT", root)

    try:
        pin_inventory.main(["--root", str(root), "--source-revision", "c" * 40, "--output", str(destination)])
    except SystemExit as exc:
        assert exc.code == 2
    else:
        raise AssertionError("docs/evidence output must be explicit")
    assert not destination.exists()

    assert (
        pin_inventory.main(
            [
                "--root",
                str(root),
                "--source-revision",
                "c" * 40,
                "--output",
                str(destination),
                "--evidence-output",
            ]
        )
        == 0
    )
    assert json.loads(destination.read_text(encoding="utf-8"))["source_revision"] == "c" * 40
