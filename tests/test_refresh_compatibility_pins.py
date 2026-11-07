"""Tests for the VD-3 historical compatibility pin refresh tool."""

from __future__ import annotations

import hashlib
import json
import sys
from datetime import datetime
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import refresh_compatibility_pins  # noqa: E402

REASON = "Reviewed historical fixture migration"
REVISION = "a" * 40
OLD_REVISION = "b" * 40
OLD_SHA = "0" * 64
HISTORICAL_REVISION = "7d550b61825defec8a8a0625511c914ba8efd5cb"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def build_manifest(
    tmp_path: Path,
    files: dict[str, bytes],
    pins: dict[str, str],
    revisions: dict[str, str] | None = None,
    *,
    tree_pins: dict[str, str] | None = None,
    history: list[dict[str, object]] | None = None,
) -> Path:
    """Write fixture files plus a manifest rooted at ``tmp_path``."""
    for name, data in files.items():
        target = tmp_path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    pin_files = {name: name for name in files}
    all_pins = dict(pins)
    all_pins.update(tree_pins or {})
    manifest = {
        "fixture_set": "frozen-runtime-test",
        "historical_revision": HISTORICAL_REVISION,
        "pin_files": pin_files,
        "pin_revisions": revisions or {name: OLD_REVISION for name in files},
        "pins": all_pins,
        "refresh_history": history or [],
        "schema": refresh_compatibility_pins.SCHEMA,
    }
    path = tmp_path / "pins.json"
    path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return path


def invoke(
    tmp_path: Path,
    manifest: Path,
    *,
    confirm: bool = False,
    reason: str | None = REASON,
    revision: str | None = REVISION,
) -> int:
    arguments = ["--root", str(tmp_path), "--manifest", str(manifest)]
    if confirm:
        arguments.append("--confirm")
    if reason is not None:
        arguments.extend(["--reason", reason])
    if revision is not None:
        arguments.extend(["--source-revision", revision])
    return refresh_compatibility_pins.main(arguments)


def test_dry_run_reports_changes_without_writing(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    manifest = build_manifest(tmp_path, {"a.py": b"current bytes"}, {"a.py": OLD_SHA})
    before = manifest.read_bytes()

    assert invoke(tmp_path, manifest) == 0

    captured = capsys.readouterr()
    assert manifest.read_bytes() == before
    assert "dry run" in captured.out
    assert "a.py" in captured.out
    assert OLD_SHA in captured.out
    assert sha256(b"current bytes") in captured.out
    assert str(tmp_path) not in captured.out + captured.err


@pytest.mark.parametrize(
    ("reason", "revision", "expected"),
    [
        (None, REVISION, "--reason"),
        ("too short", REVISION, "at least 10"),
        ("line\nbreak in reason", REVISION, "single-line"),
        (REASON, None, "--source-revision"),
        (REASON, "abc123", "40-character"),
    ],
)
def test_missing_provenance_is_refused(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    reason: str | None,
    revision: str | None,
    expected: str,
) -> None:
    manifest = build_manifest(tmp_path, {"a.py": b"current bytes"}, {"a.py": OLD_SHA})
    before = manifest.read_bytes()

    assert invoke(tmp_path, manifest, confirm=True, reason=reason, revision=revision) == 1

    assert expected in capsys.readouterr().err
    assert manifest.read_bytes() == before


def test_unchanged_pins_are_refused(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    manifest = build_manifest(tmp_path, {"a.py": b"stable bytes"}, {"a.py": sha256(b"stable bytes")})
    before = manifest.read_bytes()

    assert invoke(tmp_path, manifest, confirm=True) == 1

    assert "no changed pins" in capsys.readouterr().err
    assert manifest.read_bytes() == before


def test_changed_pin_is_rewritten_with_new_revision(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    tree_pin = "1" * 64
    manifest = build_manifest(
        tmp_path,
        {"a.py": b"new bytes", "b.py": b"unchanged bytes"},
        {"a.py": OLD_SHA, "b.py": sha256(b"unchanged bytes")},
        {"a.py": OLD_REVISION, "b.py": OLD_REVISION},
        tree_pins={"pr170-tree-model": tree_pin},
    )

    assert invoke(tmp_path, manifest, confirm=True) == 0

    captured = capsys.readouterr()
    assert "confirmed" in captured.out
    updated = json.loads(manifest.read_text(encoding="utf-8"))
    assert updated["schema"] == refresh_compatibility_pins.SCHEMA
    assert updated["historical_revision"] == HISTORICAL_REVISION
    assert updated["pins"]["a.py"] == sha256(b"new bytes")
    assert updated["pins"]["b.py"] == sha256(b"unchanged bytes")
    assert updated["pins"]["pr170-tree-model"] == tree_pin
    assert updated["pin_revisions"]["a.py"] == REVISION
    assert updated["pin_revisions"]["b.py"] == OLD_REVISION
    assert len(updated["refresh_history"]) == 1
    assert list(tmp_path.glob("*.tmp")) == []


def test_history_records_reviewed_provenance(tmp_path: Path) -> None:
    manifest = build_manifest(
        tmp_path,
        {"a.py": b"alpha", "b.py": b"beta"},
        {"a.py": OLD_SHA, "b.py": OLD_SHA},
    )

    assert invoke(tmp_path, manifest, confirm=True) == 0

    updated = json.loads(manifest.read_text(encoding="utf-8"))
    history = updated["refresh_history"]
    assert [entry["name"] for entry in history] == ["a.py", "b.py"]
    for entry in history:
        assert set(entry) == {
            "name",
            "old_sha256",
            "new_sha256",
            "timestamp",
            "reason",
            "source_revision",
        }
        assert entry["old_sha256"] == OLD_SHA
        assert entry["reason"] == REASON
        assert entry["source_revision"] == REVISION
        assert entry["new_sha256"] == updated["pins"][entry["name"]]
        assert entry["timestamp"].endswith("Z")
        datetime.fromisoformat(entry["timestamp"].replace("Z", "+00:00"))


def test_missing_pin_file_is_refused(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    manifest = build_manifest(tmp_path, {"a.py": b"new bytes"}, {"a.py": OLD_SHA})
    value = json.loads(manifest.read_text(encoding="utf-8"))
    value["pin_files"]["missing.py"] = "tests/fixtures/missing.py"
    value["pins"]["missing.py"] = OLD_SHA
    value["pin_revisions"]["missing.py"] = OLD_REVISION
    manifest.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    before = manifest.read_bytes()

    assert invoke(tmp_path, manifest, confirm=True) == 1

    captured = capsys.readouterr()
    assert "missing or unsafe" in captured.err
    assert "missing.py" in captured.err
    assert manifest.read_bytes() == before


@pytest.mark.parametrize(
    "raw",
    [
        "{not json",
        json.dumps({"schema": "wrong", "historical_revision": HISTORICAL_REVISION}),
        json.dumps(
            {
                "schema": refresh_compatibility_pins.SCHEMA,
                "historical_revision": "too-short",
                "pin_files": {"a.py": "a.py"},
                "pins": {},
                "pin_revisions": {},
                "refresh_history": [],
            }
        ),
        json.dumps(
            {
                "schema": refresh_compatibility_pins.SCHEMA,
                "historical_revision": HISTORICAL_REVISION,
                "pin_files": [],
                "pins": {},
                "pin_revisions": {},
                "refresh_history": [],
            }
        ),
        json.dumps(
            {
                "schema": refresh_compatibility_pins.SCHEMA,
                "historical_revision": HISTORICAL_REVISION,
                "pin_files": {"a.py": "a.py"},
                "pins": {},
                "pin_revisions": {},
                "refresh_history": {},
            }
        ),
    ],
)
def test_invalid_manifest_is_refused(tmp_path: Path, capsys: pytest.CaptureFixture[str], raw: str) -> None:
    manifest = tmp_path / "pins.json"
    manifest.write_text(raw, encoding="utf-8")
    before = manifest.read_bytes()

    assert invoke(tmp_path, manifest, confirm=True) == 1

    assert "invalid" in capsys.readouterr().err
    assert manifest.read_bytes() == before


VALUE_OLD = "1" * 64
VALUE_NEW = "2" * 64
VALUE_OTHER = "3" * 64
VALUE_PIN = "runtime.example.module_tree_sha256"


def value_entry(
    value: str = VALUE_OLD,
    *,
    revision: str = OLD_REVISION,
    artifact: str = "scripts/run_example.py",
) -> dict[str, object]:
    return {
        "value": value,
        "kind": "historical-runtime",
        "provenance": {
            "artifact": artifact,
            "source_revision": revision,
            "recorded_at": "2026-11-06",
            "reason": "Reviewed historical runtime identity for the example fixture set.",
        },
    }


def build_value_manifest(
    tmp_path: Path,
    pins: dict[str, dict[str, object]] | None = None,
    *,
    history: list[dict[str, object]] | None = None,
) -> Path:
    manifest = {
        "schema": refresh_compatibility_pins.VALUE_SCHEMA,
        "description": "test value-pin manifest",
        "pins": pins or {VALUE_PIN: value_entry()},
        "refresh_history": history or [],
    }
    path = tmp_path / "compatibility-pins.v1.json"
    path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return path


def invoke_value(
    tmp_path: Path,
    manifest: Path,
    *,
    confirm: bool = False,
    reason: str | None = REASON,
    revision: str | None = REVISION,
    values: tuple[str, ...] = (f"{VALUE_PIN}={VALUE_NEW}",),
) -> int:
    arguments = [
        "--root",
        str(tmp_path),
        "--value-pins",
        "--value-manifest",
        str(manifest),
    ]
    if confirm:
        arguments.append("--confirm")
    if reason is not None:
        arguments.extend(["--reason", reason])
    if revision is not None:
        arguments.extend(["--source-revision", revision])
    for value in values:
        arguments.extend(["--set", value])
    return refresh_compatibility_pins.main(arguments)


def test_value_dry_run_reports_changes_without_writing(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    manifest = build_value_manifest(tmp_path)
    before = manifest.read_bytes()

    assert invoke_value(tmp_path, manifest) == 0

    captured = capsys.readouterr()
    assert manifest.read_bytes() == before
    assert "value-pin refresh (dry run)" in captured.out
    assert VALUE_PIN in captured.out
    assert "scripts/run_example.py" in captured.out
    assert VALUE_OLD in captured.out
    assert VALUE_NEW in captured.out
    assert "no files written" in captured.out
    assert str(tmp_path) not in captured.out + captured.err


@pytest.mark.parametrize(
    ("reason", "revision", "expected"),
    [
        (None, REVISION, "--reason"),
        ("too short", REVISION, "at least 10"),
        ("line\nbreak in reason", REVISION, "single-line"),
        (REASON, None, "--source-revision"),
        (REASON, "abc123", "40-character"),
    ],
)
def test_value_refresh_without_provenance_is_refused(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    reason: str | None,
    revision: str | None,
    expected: str,
) -> None:
    manifest = build_value_manifest(tmp_path)
    before = manifest.read_bytes()

    assert invoke_value(tmp_path, manifest, confirm=True, reason=reason, revision=revision) == 1

    assert expected in capsys.readouterr().err
    assert manifest.read_bytes() == before


def test_value_refresh_requires_an_explicit_replacement(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    manifest = build_value_manifest(tmp_path)
    before = manifest.read_bytes()

    assert invoke_value(tmp_path, manifest, confirm=True, values=()) == 1

    assert "at least one --set" in capsys.readouterr().err
    assert manifest.read_bytes() == before


def test_value_refresh_refuses_unknown_pins(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    manifest = build_value_manifest(tmp_path)
    before = manifest.read_bytes()

    assert invoke_value(tmp_path, manifest, confirm=True, values=("runtime.not_a_pin=" + VALUE_NEW,)) == 1

    captured = capsys.readouterr()
    assert "unknown value pin" in captured.err
    assert "runtime.example.module_tree_sha256" in captured.err
    assert manifest.read_bytes() == before


@pytest.mark.parametrize("value", ["ABCDEF", "f" * 63, "F" * 64])
def test_value_refresh_refuses_invalid_digests(tmp_path: Path, capsys: pytest.CaptureFixture[str], value: str) -> None:
    manifest = build_value_manifest(tmp_path)
    before = manifest.read_bytes()

    assert invoke_value(tmp_path, manifest, confirm=True, values=(f"{VALUE_PIN}={value}",)) == 1

    assert "64-character SHA-256" in capsys.readouterr().err
    assert manifest.read_bytes() == before


def test_value_refresh_refuses_conflicting_duplicate_assignments(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    manifest = build_value_manifest(tmp_path)
    before = manifest.read_bytes()

    assert (
        invoke_value(
            tmp_path,
            manifest,
            confirm=True,
            values=(f"{VALUE_PIN}={VALUE_NEW}", f"{VALUE_PIN}={VALUE_OTHER}"),
        )
        == 1
    )

    assert "conflicting --set" in capsys.readouterr().err
    assert manifest.read_bytes() == before


def test_value_refresh_refuses_an_unchanged_pin_set(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    manifest = build_value_manifest(tmp_path)
    before = manifest.read_bytes()

    assert invoke_value(tmp_path, manifest, confirm=True, values=(f"{VALUE_PIN}={VALUE_OLD}",)) == 1

    assert "no changed value pins" in capsys.readouterr().err
    assert manifest.read_bytes() == before


def test_value_refresh_requires_provenance_on_the_pin_entry(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    entry = value_entry()
    del entry["provenance"]
    manifest = build_value_manifest(tmp_path, {VALUE_PIN: entry})
    before = manifest.read_bytes()

    assert invoke_value(tmp_path, manifest, confirm=True) == 1

    assert "provenance is missing" in capsys.readouterr().err
    assert manifest.read_bytes() == before


def test_value_refresh_updates_value_provenance_and_history(tmp_path: Path) -> None:
    other_pin = "historical.example.baseline_plan_sha256"
    manifest = build_value_manifest(
        tmp_path,
        {VALUE_PIN: value_entry(), other_pin: value_entry(VALUE_OTHER)},
    )

    assert invoke_value(tmp_path, manifest, confirm=True) == 0

    updated = json.loads(manifest.read_text(encoding="utf-8"))
    assert updated["schema"] == refresh_compatibility_pins.VALUE_SCHEMA
    assert updated["pins"][VALUE_PIN]["value"] == VALUE_NEW
    assert updated["pins"][VALUE_PIN]["provenance"]["source_revision"] == REVISION
    assert updated["pins"][VALUE_PIN]["provenance"]["reason"] == REASON
    assert updated["pins"][VALUE_PIN]["provenance"]["recorded_at"].endswith("Z")
    assert updated["pins"][other_pin]["value"] == VALUE_OTHER
    assert updated["pins"][other_pin]["provenance"]["source_revision"] == OLD_REVISION
    history = updated["refresh_history"]
    assert len(history) == 1
    entry = history[0]
    assert set(entry) == {
        "name",
        "old_sha256",
        "new_sha256",
        "timestamp",
        "reason",
        "source_revision",
    }
    assert entry["name"] == VALUE_PIN
    assert entry["old_sha256"] == VALUE_OLD
    assert entry["new_sha256"] == VALUE_NEW
    assert entry["reason"] == REASON
    assert entry["source_revision"] == REVISION
    assert entry["timestamp"] == updated["pins"][VALUE_PIN]["provenance"]["recorded_at"]
    datetime.fromisoformat(entry["timestamp"].replace("Z", "+00:00"))
    assert list(tmp_path.glob("*.tmp")) == []


def test_value_refresh_keeps_existing_history(tmp_path: Path) -> None:
    prior = {
        "name": VALUE_PIN,
        "old_sha256": "4" * 64,
        "new_sha256": VALUE_OLD,
        "timestamp": "2026-11-01T00:00:00Z",
        "reason": "Prior reviewed migration of the example runtime identity.",
        "source_revision": OLD_REVISION,
    }
    manifest = build_value_manifest(tmp_path, history=[prior])

    assert invoke_value(tmp_path, manifest, confirm=True) == 0

    history = json.loads(manifest.read_text(encoding="utf-8"))["refresh_history"]
    assert history[0] == prior
    assert len(history) == 2
    assert history[1]["new_sha256"] == VALUE_NEW


def test_set_without_value_pin_mode_is_refused(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    manifest = build_value_manifest(tmp_path)
    before = manifest.read_bytes()

    assert (
        refresh_compatibility_pins.main(
            [
                "--root",
                str(tmp_path),
                "--value-manifest",
                str(manifest),
                "--reason",
                REASON,
                "--source-revision",
                REVISION,
                "--set",
                f"{VALUE_PIN}={VALUE_NEW}",
            ]
        )
        == 1
    )

    assert "--set requires --value-pins" in capsys.readouterr().err
    assert manifest.read_bytes() == before


@pytest.mark.parametrize(
    "raw",
    [
        "{not json",
        json.dumps({"schema": "wrong", "pins": {VALUE_PIN: value_entry()}}),
        json.dumps({"schema": refresh_compatibility_pins.VALUE_SCHEMA, "pins": []}),
        json.dumps(
            {
                "schema": refresh_compatibility_pins.VALUE_SCHEMA,
                "pins": {VALUE_PIN: value_entry()},
                "refresh_history": {},
            }
        ),
    ],
)
def test_invalid_value_manifest_is_refused(tmp_path: Path, capsys: pytest.CaptureFixture[str], raw: str) -> None:
    manifest = tmp_path / "compatibility-pins.v1.json"
    manifest.write_text(raw, encoding="utf-8")
    before = manifest.read_bytes()

    assert invoke_value(tmp_path, manifest, confirm=True) == 1

    assert "value-pin manifest" in capsys.readouterr().err
    assert manifest.read_bytes() == before


def test_explicit_dry_run_flag_never_writes(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    manifest = build_value_manifest(tmp_path)
    before = manifest.read_bytes()

    assert (
        refresh_compatibility_pins.main(
            [
                "--root",
                str(tmp_path),
                "--value-pins",
                "--value-manifest",
                str(manifest),
                "--dry-run",
                "--reason",
                REASON,
                "--source-revision",
                REVISION,
                "--set",
                f"{VALUE_PIN}={VALUE_NEW}",
            ]
        )
        == 0
    )

    assert "dry run" in capsys.readouterr().out
    assert manifest.read_bytes() == before


def test_dry_run_and_confirm_together_are_refused(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    manifest = build_value_manifest(tmp_path)
    before = manifest.read_bytes()

    assert (
        refresh_compatibility_pins.main(
            [
                "--root",
                str(tmp_path),
                "--value-pins",
                "--value-manifest",
                str(manifest),
                "--dry-run",
                "--confirm",
                "--reason",
                REASON,
                "--source-revision",
                REVISION,
                "--set",
                f"{VALUE_PIN}={VALUE_NEW}",
            ]
        )
        == 1
    )

    assert "--dry-run cannot be combined with --confirm" in capsys.readouterr().err
    assert manifest.read_bytes() == before
