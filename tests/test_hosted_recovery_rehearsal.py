from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import stat
import sys
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import hosted_recovery_rehearsal as rehearsal


def _stage(tmp_path: Path) -> Path:
    stage = tmp_path / "stage"
    stage.mkdir()
    files = {
        "checkpoint.json": b"checkpoint",
        "fixture.bundle": b"fixture",
        "provider-ledger.json": b"ledger",
        "readiness.json": b"ready",
        rehearsal.WHEEL_NAME: b"wheel",
    }
    for name, payload in files.items():
        (stage / name).write_bytes(payload)
    manifest = {
        "schema_version": "hosted-recovery.v1",
        "files": {name: hashlib.sha256(payload).hexdigest() for name, payload in files.items()},
    }
    (stage / "manifest.json").write_bytes(rehearsal.canonical(manifest))
    return stage


def test_stage_accepts_only_hashed_regular_allowlisted_files(tmp_path):
    stage = _stage(tmp_path)
    result = rehearsal.validate_stage(stage)
    assert result["manifest"]["schema_version"] == "hosted-recovery.v1"
    assert result["total_bytes"] < rehearsal.MAX_BYTES


def test_stage_rejects_digest_mismatch_and_unknown_file(tmp_path):
    stage = _stage(tmp_path)
    (stage / "checkpoint.json").write_text("changed")
    with pytest.raises(rehearsal.DrillError, match="artifact_digest_mismatch"):
        rehearsal.validate_stage(stage)
    (stage / "checkpoint.json").write_text("checkpoint")
    (stage / "unexpected.txt").write_text("no")
    with pytest.raises(rehearsal.DrillError, match="artifact_allowlist_invalid"):
        rehearsal.validate_stage(stage)


def test_stage_rejects_symlink_and_total_size_over_cap(tmp_path):
    stage = _stage(tmp_path)
    victim = tmp_path / "outside"
    victim.write_text("outside")
    (stage / "checkpoint.json").unlink()
    (stage / "checkpoint.json").symlink_to(victim)
    with pytest.raises(rehearsal.DrillError, match="artifact_file_type_or_size_invalid"):
        rehearsal.validate_stage(stage)

    (stage / "checkpoint.json").unlink()
    (stage / "checkpoint.json").write_bytes(b"x" * rehearsal.MAX_FILE_BYTES)
    (stage / "fixture.bundle").write_bytes(b"y" * 2_000_000)
    (stage / "manifest.json").write_bytes(rehearsal.canonical({
        "schema_version": "hosted-recovery.v1",
        "files": {name: rehearsal.digest(stage / name) for name in (
            "checkpoint.json", "fixture.bundle", "provider-ledger.json", "readiness.json", rehearsal.WHEEL_NAME
        )},
    }))
    with pytest.raises(rehearsal.DrillError, match="artifact_total_size_exceeded"):
        rehearsal.validate_stage(stage)


def test_manifest_inventory_must_bind_every_transfer_file(tmp_path):
    stage = _stage(tmp_path)
    manifest = json.loads((stage / "manifest.json").read_text())
    manifest["files"].pop("provider-ledger.json")
    (stage / "manifest.json").write_bytes(rehearsal.canonical(manifest))
    with pytest.raises(rehearsal.DrillError, match="artifact_file_inventory_mismatch"):
        rehearsal.validate_stage(stage)


def test_resume_source_run_id_is_numeric_before_any_artifact_access(tmp_path):
    with pytest.raises(rehearsal.DrillError, match="source_run_id_invalid"):
        rehearsal.run_b(
            root=tmp_path / "root",
            stage=tmp_path / "nonexistent",
            expected_run_id="../unexpected",
            expected_sha="a" * 40,
            repository="groktopus/codereview",
            source_root=Path(__file__).resolve().parents[1],
            output=tmp_path / "output",
        )


def test_synthetic_cli_environment_excludes_enclosing_workflow_event():
    env = rehearsal._synthetic_cli_environment("/isolated/venv/bin:/usr/bin", "/isolated/home",
                                               api_key=rehearsal.API_KEY)
    assert env == {
        "PATH": "/isolated/venv/bin:/usr/bin", "HOME": "/isolated/home",
        "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "PYTHONNOUSERSITE": "1",
        "HOSTED_RECOVERY_FAKE_KEY": rehearsal.API_KEY,
    }
    assert "GITHUB_EVENT_PATH" not in env


@pytest.mark.parametrize("api_path", [
    rehearsal.WORKFLOW_PATH,
    rehearsal.WORKFLOW_PATH + "@main",
    rehearsal.WORKFLOW_PATH + "@refs/heads/main",
])
def test_run_b_archive_download_checks_canceled_main_identity_and_extracts_bounded_files(tmp_path, monkeypatch, api_path):
    files = {
        "checkpoint.json": b"checkpoint",
        "fixture.bundle": b"fixture",
        "provider-ledger.json": b"ledger",
        "readiness.json": b"ready",
        rehearsal.WHEEL_NAME: b"wheel",
    }
    manifest = {"schema_version": "hosted-recovery.v1", "files": {
        name: hashlib.sha256(content).hexdigest() for name, content in files.items()
    }}
    files["manifest.json"] = rehearsal.canonical(manifest)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED) as archive:
        for name, content in files.items():
            archive.writestr(name, content)
    archive_bytes = buffer.getvalue()
    ready_buffer = io.BytesIO()
    with zipfile.ZipFile(ready_buffer, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("readiness.json", b"ready")
    ready_archive_bytes = ready_buffer.getvalue()
    run_doc = {
        "id": 42, "repository": {"full_name": rehearsal.CANONICAL_REPOSITORY},
        "event": "workflow_dispatch", "status": "completed", "conclusion": "cancelled",
        "head_branch": "main", "head_sha": "a" * 40,
        "path": api_path, "workflow_id": 9,
    }
    workflow_doc = {"path": rehearsal.WORKFLOW_PATH}
    artifact_doc = {"artifacts": [{
        "id": 51, "name": "hosted-recovery-42", "expired": False,
        "size_in_bytes": len(archive_bytes), "workflow_run": {"id": 42},
    }, {
        "id": 52, "name": "hosted-recovery-ready-42", "expired": False,
        "size_in_bytes": len(ready_archive_bytes), "workflow_run": {"id": 42},
    }]}
    encoded_archive = base64.b64encode(archive_bytes).decode("ascii")
    encoded_ready_archive = base64.b64encode(ready_archive_bytes).decode("ascii")
    fake_gh = tmp_path / "gh"
    fake_gh.write_text(
        "#!/usr/bin/env python3\n"
        "import base64,json,sys\n"
        "endpoint=sys.argv[2]\n"
        f"if endpoint.endswith('/actions/runs/42'): print(json.dumps({run_doc!r}))\n"
        f"elif endpoint.endswith('/actions/workflows/9'): print(json.dumps({workflow_doc!r}))\n"
        f"elif '/artifacts?per_page=100' in endpoint: print(json.dumps({artifact_doc!r}))\n"
        f"elif endpoint.endswith('/actions/artifacts/52/zip'): sys.stdout.buffer.write(base64.b64decode({encoded_ready_archive!r}))\n"
        f"elif endpoint.endswith('/actions/artifacts/51/zip'): sys.stdout.buffer.write(base64.b64decode({encoded_archive!r}))\n"
        "else: raise SystemExit(2)\n",
        encoding="utf-8",
    )
    fake_gh.chmod(0o700)
    monkeypatch.setenv("PATH", f"{tmp_path}:{os.environ.get('PATH', '')}")
    destination = tmp_path / "download"
    result = rehearsal._download_canceled_run_artifact(
        "42", "a" * 40, destination, repository=rehearsal.CANONICAL_REPOSITORY, token="test-token"
    )
    assert result["artifact_id"] == 51
    assert result["readiness_artifact_id"] == 52
    assert result["readiness_receipt_sha256"] == hashlib.sha256(b"ready").hexdigest()
    assert result["readiness_receipt_bytes"] == 5
    assert rehearsal.digest(destination / "checkpoint.json") == hashlib.sha256(b"checkpoint").hexdigest()
    assert not (destination.parent / ".hosted-recovery-42.zip").exists()


@pytest.mark.parametrize(("field", "value"), [
    ("path", "other.yml"),
    ("head_branch", "feature"),
    ("head_sha", "b" * 40),
    ("event", "push"),
    ("conclusion", "success"),
    ("repository", {"full_name": "attacker/fork"}),
])
def test_run_b_rejects_source_run_identity_before_artifact_lookup(tmp_path, monkeypatch, field, value):
    run_doc = {
        "id": 42, "repository": {"full_name": rehearsal.CANONICAL_REPOSITORY},
        "event": "workflow_dispatch", "status": "completed", "conclusion": "cancelled",
        "head_branch": "main", "head_sha": "a" * 40,
        "path": rehearsal.WORKFLOW_PATH, "workflow_id": 9,
    }
    run_doc[field] = value
    calls = tmp_path / "gh-calls.txt"
    fake_gh = tmp_path / "gh"
    fake_gh.write_text(
        "#!/usr/bin/env python3\nimport json,os,sys\n"
        f"open({str(calls)!r},'a',encoding='utf-8').write(sys.argv[2]+'\\n')\n"
        f"print(json.dumps({run_doc!r}))\n", encoding="utf-8"
    )
    fake_gh.chmod(0o700)
    monkeypatch.setenv("PATH", f"{tmp_path}:{os.environ.get('PATH', '')}")
    with pytest.raises(rehearsal.DrillError, match="source_run_not_expected_canceled_main_workflow"):
        rehearsal._download_canceled_run_artifact(
            "42", "a" * 40, tmp_path / "download", repository=rehearsal.CANONICAL_REPOSITORY, token="test-token"
        )
    assert calls.read_text(encoding="utf-8").splitlines() == ["repos/groktopus/codereview/actions/runs/42"]


def test_run_b_rejects_non_canceled_run_before_artifact_listing(tmp_path, monkeypatch):
    run_doc = {
        "id": 42, "repository": {"full_name": rehearsal.CANONICAL_REPOSITORY},
        "event": "workflow_dispatch", "status": "completed", "conclusion": "success",
        "head_branch": "main", "head_sha": "a" * 40,
        "path": rehearsal.WORKFLOW_PATH + "@refs/heads/main", "workflow_id": 9,
    }
    fake_gh = tmp_path / "gh"
    fake_gh.write_text(
        "#!/usr/bin/env python3\nimport json,sys\n"
        f"print(json.dumps({run_doc!r}))\n", encoding="utf-8"
    )
    fake_gh.chmod(0o700)
    monkeypatch.setenv("PATH", f"{tmp_path}:{os.environ.get('PATH', '')}")
    with pytest.raises(rehearsal.DrillError, match="source_run_not_expected_canceled_main_workflow"):
        rehearsal._download_canceled_run_artifact(
            "42", "a" * 40, tmp_path / "download", repository=rehearsal.CANONICAL_REPOSITORY, token="test-token"
        )


def test_bounded_subprocess_stops_at_output_limit(tmp_path):
    noisy = tmp_path / "noisy"
    noisy.write_text("#!/usr/bin/env python3\nprint('x' * 10000)\n", encoding="utf-8")
    noisy.chmod(0o700)
    with pytest.raises(rehearsal.DrillError, match="command_output_limit_exceeded"):
        rehearsal._run([str(noisy)], cwd=tmp_path, env={"PATH": os.environ.get("PATH", "")},
                       timeout=5, output_limit=100)


def _fake_readiness_receipt():
    return {
        "schema_version": "hosted-recovery-readiness.v1", "run_id": 42, "run_attempt": 1,
        "repository": rehearsal.CANONICAL_REPOSITORY, "workflow_path": rehearsal.WORKFLOW_PATH,
        "workflow_ref": "refs/heads/main", "harness_sha": "a" * 40,
        "source_modules_sha256": "c" * 64, "state": "READY_TO_CANCEL",
        "provider_ordinal": 2, "provider_in_flight": True,
        "completed_reservations": 1, "uncertain_reservations": 1,
        "historical_provider_requests": 2, "new_resume_requests_expected": 0,
        "checkpoint_sha256": "b" * 64, "checkpoint_bytes": 123,
        "snapshot_id": "snapshot-1", "request_hash": "d" * 64,
        "held_deadline_unix": 1_800_000_000,
    }


def test_readiness_upload_uses_safe_bounded_receipt_and_returns_identity(tmp_path, monkeypatch):
    monkeypatch.setenv("GITHUB_RUN_ID", "42")
    monkeypatch.setenv("ACTIONS_RUNTIME_TOKEN", "synthetic-runtime-secret")
    monkeypatch.setenv("HOSTED_RECOVERY_FAKE_KEY", "synthetic-provider-secret")
    monkeypatch.setattr(rehearsal, "_PHASE_DEADLINE", __import__("time").monotonic() + 20)
    receipt = _fake_readiness_receipt()
    content = rehearsal.canonical(receipt)

    class FakeUploader:
        request = None

        def upload(self, **kwargs):
            self.request = kwargs
            return SimpleNamespace(status="UPLOADED", artifact_id=9001, reason_code=None)

    uploader = FakeUploader()
    result = rehearsal._upload_readiness_receipt(
        source_root=tmp_path, receipt=receipt, content=content, uploader=uploader,
    )
    assert result == {
        "artifact_id": 9001,
        "artifact_name": "hosted-recovery-ready-42",
        "receipt_sha256": hashlib.sha256(content).hexdigest(),
        "receipt_bytes": len(content),
    }
    assert uploader.request["timeout_seconds"] <= rehearsal.READINESS_UPLOAD_SECONDS
    assert uploader.request["content"] == content
    assert len(content) <= 2048
    assert b"synthetic-runtime-secret" not in content
    assert b"synthetic-provider-secret" not in content


def test_readiness_upload_failure_stops_before_ready_state(tmp_path, monkeypatch):
    monkeypatch.setenv("GITHUB_RUN_ID", "42")

    class FakeUploader:
        def upload(self, **_kwargs):
            return SimpleNamespace(status="UNAVAILABLE", artifact_id=None, reason_code="artifact_upload_failed")

    with pytest.raises(rehearsal.DrillError, match="readiness_artifact_upload_failed"):
        rehearsal._upload_readiness_receipt(
            source_root=tmp_path, receipt=_fake_readiness_receipt(),
            content=rehearsal.canonical(_fake_readiness_receipt()), uploader=FakeUploader(),
        )


def test_readiness_upload_respects_shared_deadline_and_fails_closed(tmp_path, monkeypatch):
    monkeypatch.setenv("GITHUB_RUN_ID", "42")

    class FakeUploader:
        timeout = None

        def upload(self, **kwargs):
            self.timeout = kwargs["timeout_seconds"]
            return SimpleNamespace(status="UNAVAILABLE", artifact_id=None,
                                   reason_code="artifact_upload_deadline_exhausted")

    import time
    uploader = FakeUploader()
    monkeypatch.setattr(rehearsal, "_PHASE_DEADLINE", time.monotonic() + 0.05)
    with pytest.raises(rehearsal.DrillError, match="readiness_artifact_upload_deadline_exhausted"):
        rehearsal._upload_readiness_receipt(
            source_root=tmp_path, receipt=_fake_readiness_receipt(),
            content=rehearsal.canonical(_fake_readiness_receipt()), uploader=uploader,
        )
    assert 0 < uploader.timeout <= 0.05

    monkeypatch.setattr(rehearsal, "_PHASE_DEADLINE", time.monotonic() - 1)
    uploader.timeout = None
    with pytest.raises(rehearsal.DrillError, match="readiness_artifact_upload_deadline_exhausted"):
        rehearsal._upload_readiness_receipt(
            source_root=tmp_path, receipt=_fake_readiness_receipt(),
            content=rehearsal.canonical(_fake_readiness_receipt()), uploader=uploader,
        )
    assert uploader.timeout is None


def test_run_b_readiness_validation_rejects_missing_receipt(tmp_path):
    stage = _stage(tmp_path)
    manifest = json.loads((stage / "manifest.json").read_text(encoding="utf-8"))
    manifest.update({"run_id": "42", "run_attempt": 1, "harness_sha": "a" * 40,
                    "snapshot_id": "snapshot-1", "request_hash": "d" * 64,
                    "source_modules": {"module.py": "e" * 64},
                    "readiness_publication": {"artifact_id": 52, "artifact_name": "hosted-recovery-ready-42",
                                               "receipt_sha256": "f" * 64, "receipt_bytes": 1}})
    (stage / "readiness.json").unlink()
    with pytest.raises(rehearsal.DrillError, match="readiness_receipt_missing_or_invalid"):
        rehearsal._validate_readiness_receipt(
            stage, manifest, expected_run_id="42", expected_sha="a" * 40, readiness_artifact_id=52,
        )


def test_readiness_validation_matches_separately_retrieved_receipt_bytes(tmp_path):
    stage = _stage(tmp_path)
    source_modules = {"module.py": "e" * 64}
    receipt = _fake_readiness_receipt()
    receipt.update({
        "source_modules_sha256": rehearsal.source_inventory_digest(source_modules),
        "checkpoint_sha256": rehearsal.digest(stage / "checkpoint.json"),
        "checkpoint_bytes": (stage / "checkpoint.json").stat().st_size,
    })
    receipt_bytes = rehearsal.canonical(receipt)
    (stage / "readiness.json").write_bytes(receipt_bytes)
    manifest = json.loads((stage / "manifest.json").read_text(encoding="utf-8"))
    manifest.update({
        "run_id": "42", "run_attempt": 1, "harness_sha": "a" * 40,
        "snapshot_id": "snapshot-1", "request_hash": "d" * 64,
        "source_modules": source_modules,
        "files": {name: rehearsal.digest(stage / name) for name in (
            "checkpoint.json", "fixture.bundle", "provider-ledger.json", "readiness.json", rehearsal.WHEEL_NAME
        )},
        "readiness_publication": {
            "artifact_id": 52, "artifact_name": "hosted-recovery-ready-42",
            "receipt_sha256": hashlib.sha256(receipt_bytes).hexdigest(),
            "receipt_bytes": len(receipt_bytes),
        },
    })
    rehearsal._validate_readiness_receipt(
        stage, manifest, expected_run_id="42", expected_sha="a" * 40,
        readiness_artifact_id=52,
        retrieved_receipt_sha256=hashlib.sha256(receipt_bytes).hexdigest(),
        retrieved_receipt_bytes=len(receipt_bytes),
    )
    with pytest.raises(rehearsal.DrillError, match="readiness_artifact_content_mismatch"):
        rehearsal._validate_readiness_receipt(
            stage, manifest, expected_run_id="42", expected_sha="a" * 40,
            readiness_artifact_id=52, retrieved_receipt_sha256="0" * 64,
            retrieved_receipt_bytes=len(receipt_bytes),
        )


def test_readiness_archive_rejects_special_zip_modes_but_accepts_permission_only(tmp_path):
    permission_only = tmp_path / "permissions-only.zip"
    with zipfile.ZipFile(permission_only, "w") as archive:
        info = zipfile.ZipInfo("readiness.json")
        info.external_attr = 0o600 << 16
        archive.writestr(info, b"receipt")
    content, sha256 = rehearsal._read_readiness_receipt_archive(permission_only)
    assert content == b"receipt"
    assert sha256 == hashlib.sha256(content).hexdigest()

    special = tmp_path / "fifo.zip"
    with zipfile.ZipFile(special, "w") as archive:
        info = zipfile.ZipInfo("readiness.json")
        info.external_attr = (stat.S_IFIFO | 0o600) << 16
        archive.writestr(info, b"receipt")
    with pytest.raises(rehearsal.DrillError, match="source_readiness_artifact_file_invalid"):
        rehearsal._read_readiness_receipt_archive(special)
