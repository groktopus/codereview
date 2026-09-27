from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import sys
import zipfile
from pathlib import Path

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
    }]}
    encoded_archive = base64.b64encode(archive_bytes).decode("ascii")
    fake_gh = tmp_path / "gh"
    fake_gh.write_text(
        "#!/usr/bin/env python3\n"
        "import base64,json,sys\n"
        "endpoint=sys.argv[2]\n"
        f"if endpoint.endswith('/actions/runs/42'): print(json.dumps({run_doc!r}))\n"
        f"elif endpoint.endswith('/actions/workflows/9'): print(json.dumps({workflow_doc!r}))\n"
        f"elif '/artifacts?per_page=100' in endpoint: print(json.dumps({artifact_doc!r}))\n"
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
