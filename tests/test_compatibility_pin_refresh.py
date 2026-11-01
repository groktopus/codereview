from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

pytestmark = pytest.mark.compatibility

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "refresh_compatibility_pin.py"
MODULE_SPEC = importlib.util.spec_from_file_location("refresh_compatibility_pin", SCRIPT)
assert MODULE_SPEC and MODULE_SPEC.loader
refresh = importlib.util.module_from_spec(MODULE_SPEC)
MODULE_SPEC.loader.exec_module(refresh)


def _manifest(tmp_path: Path) -> tuple[Path, Path, str]:
    fixture_dir = tmp_path / "tests" / "fixtures" / "frozen-runtime-7d550b6"
    fixture_dir.mkdir(parents=True)
    blob = fixture_dir / "context_selector.py"
    blob.write_bytes(b"new fixture bytes\n")
    manifest = fixture_dir / "pins.json"
    manifest.write_text(
        json.dumps(
            {
                "schema": "pr-review-historical-pins.v1",
                "historical_revision": "7d550b61825defec8a8a0625511c914ba8efd5cb",
                "fixture_set": "frozen-runtime-7d550b6",
                "pin_files": {"context_selector.py": str(blob.resolve())},
                "pins": {"context_selector.py": "a" * 64},
                "refresh_history": [],
            }
        ),
        encoding="utf-8",
    )
    return manifest, blob, "tests/fixtures/frozen-runtime-7d550b6/context_selector.py"


def test_refresh_tool_requires_provenance_even_for_dry_run():
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--module", "context_selector.py", "--dry-run"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 2
    assert "refusing pin refresh" in result.stderr
    assert "--reason is required" in result.stderr


def test_refresh_tool_refuses_missing_reason():
    result = subprocess.run(
        [
            sys.executable, str(SCRIPT), "--module", "context_selector.py",
            "--source-revision", "6e18f8103daedd042027be9b27921e0416cbd05b", "--dry-run",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 2
    assert "--reason is required" in result.stderr


def test_refresh_dry_run_records_provenance_without_writing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    manifest, _, relative = _manifest(tmp_path)
    before = manifest.read_bytes()
    monkeypatch.setattr(refresh, "ROOT", tmp_path)
    monkeypatch.setattr(refresh, "_source_revision", lambda revision: revision)
    monkeypatch.setattr(refresh, "_verify_revision_blob", lambda *args, **kwargs: None)
    payload = json.loads(before)
    payload["pin_files"]["context_selector.py"] = relative
    manifest.write_text(json.dumps(payload), encoding="utf-8")
    before = manifest.read_bytes()
    stamp = datetime(2026, 11, 1, 12, 0, tzinfo=timezone.utc)
    record = refresh.refresh_pin(
        module="context_selector.py",
        reason="Retain corrected historical bytes from reviewed source.",
        source_revision="6e18f8103daedd042027be9b27921e0416cbd05b",
        dry_run=True,
        manifest_path=manifest,
        timestamp=stamp,
        allowed_root=tmp_path,
    )
    assert record["old_blob_sha256"] == "a" * 64
    assert record["new_blob_sha256"]
    assert record["source_revision"] == "6e18f8103daedd042027be9b27921e0416cbd05b"
    assert record["timestamp"] == stamp.isoformat()
    assert manifest.read_bytes() == before


def test_explicit_refresh_appends_old_and_new_hashes_with_reason_revision_and_timestamp(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    manifest, _, relative = _manifest(tmp_path)
    monkeypatch.setattr(refresh, "ROOT", tmp_path)
    monkeypatch.setattr(refresh, "_source_revision", lambda revision: revision)
    monkeypatch.setattr(refresh, "_verify_revision_blob", lambda *args, **kwargs: None)
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    payload["pin_files"]["context_selector.py"] = relative
    manifest.write_text(json.dumps(payload), encoding="utf-8")
    stamp = datetime(2026, 11, 1, 12, 0, tzinfo=timezone.utc)
    result = refresh.refresh_pin(
        module="context_selector.py",
        reason="Restore preserved source bytes after reviewed fixture repair.",
        source_revision="6e18f8103daedd042027be9b27921e0416cbd05b",
        dry_run=False,
        manifest_path=manifest,
        timestamp=stamp,
        allowed_root=tmp_path,
    )
    updated = json.loads(manifest.read_text(encoding="utf-8"))
    assert updated["pins"]["context_selector.py"] == result["new_blob_sha256"]
    assert updated["refresh_history"] == [
        {
            "module": "context_selector.py",
            "old_blob_sha256": "a" * 64,
            "new_blob_sha256": result["new_blob_sha256"],
            "reason": "Restore preserved source bytes after reviewed fixture repair.",
            "source_revision": "6e18f8103daedd042027be9b27921e0416cbd05b",
            "historical_revision": "7d550b61825defec8a8a0625511c914ba8efd5cb",
            "timestamp": stamp.isoformat(),
        }
    ]


def test_refresh_refuses_non_manifest_module(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    manifest, _, relative = _manifest(tmp_path)
    monkeypatch.setattr(refresh, "ROOT", tmp_path)
    monkeypatch.setattr(refresh, "_source_revision", lambda revision: revision)
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    payload["pin_files"]["context_selector.py"] = relative
    manifest.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(refresh.PinRefreshError, match="not listed"):
        refresh.refresh_pin(
            module="not-pinned.py",
            reason="Test refusal",
            source_revision="6e18f8103daedd042027be9b27921e0416cbd05b",
            manifest_path=manifest,
        )


def test_refresh_refuses_path_escape(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    manifest, _, _ = _manifest(tmp_path)
    monkeypatch.setattr(refresh, "ROOT", tmp_path)
    monkeypatch.setattr(refresh, "_source_revision", lambda revision: revision)
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    payload["pin_files"]["context_selector.py"] = "../outside.py"
    manifest.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(refresh.PinRefreshError, match="escapes repository root"):
        refresh.refresh_pin(
            module="context_selector.py", reason="escape test",
            source_revision="6e18f8103daedd042027be9b27921e0416cbd05b",
            manifest_path=manifest, allowed_root=tmp_path,
        )


def test_refresh_refuses_noop_even_in_dry_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    manifest, blob, relative = _manifest(tmp_path)
    monkeypatch.setattr(refresh, "ROOT", tmp_path)
    monkeypatch.setattr(refresh, "_source_revision", lambda revision: revision)
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    payload["pin_files"]["context_selector.py"] = relative
    payload["pins"]["context_selector.py"] = __import__("hashlib").sha256(blob.read_bytes()).hexdigest()
    manifest.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(refresh.PinRefreshError, match="no-op"):
        refresh.refresh_pin(
            module="context_selector.py", reason="no-op test",
            source_revision="6e18f8103daedd042027be9b27921e0416cbd05b",
            dry_run=True, manifest_path=manifest, allowed_root=tmp_path,
        )


def test_tree_refresh_synchronizes_legacy_verifier_literals(tmp_path: Path):
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    (scripts / "verify_model_only_shadow_live_preflight.py").write_text(
        'EXPECTED_MODULE_TREE_SHA256 = "' + "a" * 64 + '"\n', encoding="utf-8"
    )
    (scripts / "verify_synth_001_preflight.py").write_text(
        'MODULE_TREE_SHA256 = "' + "b" * 64 + '"\n', encoding="utf-8"
    )
    refresh._update_verifier_tree_literals(tmp_path, "c" * 64, "d" * 64)
    assert "c" * 64 in (scripts / "verify_model_only_shadow_live_preflight.py").read_text()
    assert "d" * 64 in (scripts / "verify_synth_001_preflight.py").read_text()


def test_tree_refresh_updates_manifest_and_verifier_literals(tmp_path: Path, monkeypatch):
    fixture_dir = tmp_path / "tests" / "fixtures" / "frozen-runtime-7d550b6"
    fixture_dir.mkdir(parents=True)
    manifest = fixture_dir / "pins.json"
    manifest.write_text(json.dumps({
        "schema": "pr-review-historical-pins.v1",
        "historical_revision": "7d550b61825defec8a8a0625511c914ba8efd5cb",
        "pins": {"pr170-tree-model": "a" * 64, "pr170-tree-synthesis": "b" * 64},
        "pin_revisions": {},
        "refresh_history": [],
    }), encoding="utf-8")
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    (scripts / "verify_model_only_shadow_live_preflight.py").write_text(
        'EXPECTED_MODULE_TREE_SHA256 = "' + "a" * 64 + '"\n', encoding="utf-8")
    (scripts / "verify_synth_001_preflight.py").write_text(
        'MODULE_TREE_SHA256 = "' + "b" * 64 + '"\n', encoding="utf-8")
    monkeypatch.setitem(sys.modules, "frozen_runtime", SimpleNamespace(
        frozen_tree_hashes=lambda _root: {"model": "c" * 64, "synthesis": "d" * 64}))
    monkeypatch.setattr(refresh, "_source_revision", lambda revision: revision)
    monkeypatch.setattr(refresh.subprocess, "run", lambda *args, **kwargs: SimpleNamespace(returncode=0))
    record = refresh.refresh_tree_pins(
        reason="tree refresh test", source_revision="e" * 40,
        manifest_path=manifest, allowed_root=tmp_path,
    )
    updated = json.loads(manifest.read_text(encoding="utf-8"))
    assert updated["pins"]["pr170-tree-model"] == "c" * 64
    assert updated["pins"]["pr170-tree-synthesis"] == "d" * 64
    assert updated["refresh_history"][0]["kind"] == "tree"
    assert record["new"]["pr170-tree-model"] == "c" * 64
    assert "c" * 64 in (scripts / "verify_model_only_shadow_live_preflight.py").read_text()
    assert "d" * 64 in (scripts / "verify_synth_001_preflight.py").read_text()
