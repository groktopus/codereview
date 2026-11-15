from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
FIXTURE = ROOT / "examples/evaluation/seeded-writer-synth-001"
SCRIPT = ROOT / "scripts/materialize_seeded_writer_synth_001.py"


def _run(fixture: Path, target: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), "--fixture-dir", str(fixture), "--target-dir", str(target)],
        cwd=target.parent,
        text=True,
        capture_output=True,
        check=False,
    )


def test_pin_consumers_import_without_reading_resource(tmp_path: Path):
    verifier = ROOT / "scripts/verify_synth_001_preflight.py"
    code = (
        "import importlib.resources, runpy, unittest.mock\n"
        "with unittest.mock.patch('importlib.resources.files', side_effect=AssertionError('resource read')):\n"
        f"    runpy.run_path({str(SCRIPT)!r}, run_name='materializer_import_probe')\n"
        f"    runpy.run_path({str(verifier)!r}, run_name='verifier_import_probe')\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=tmp_path,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr


def test_cli_entrypoints_fail_closed_when_pin_resource_is_unavailable(tmp_path: Path):
    site_dir = tmp_path / "site"
    site_dir.mkdir()
    (site_dir / "sitecustomize.py").write_text(
        "import importlib.resources\n"
        "class UnavailableResource:\n"
        "    def joinpath(self, _name): return self\n"
        "    def read_text(self, **_kwargs): raise OSError('opaque resource sentinel')\n"
        "importlib.resources.files = lambda _package: UnavailableResource()\n",
        encoding="utf-8",
    )
    environment = os.environ.copy()
    environment["PYTHONPATH"] = os.pathsep.join((str(site_dir), str(ROOT / "src")))

    target = tmp_path / "materialized-target"
    materializer = subprocess.run(
        [sys.executable, str(SCRIPT), "--fixture-dir", str(FIXTURE), "--target-dir", str(target)],
        cwd=tmp_path,
        env=environment,
        text=True,
        capture_output=True,
        check=False,
    )
    assert materializer.returncode == 2
    assert json.loads(materializer.stderr) == {
        "schema": "seeded-writer-materialization.v1",
        "error": "fixture_pin_resource_unavailable",
    }
    assert not target.exists()
    assert "opaque resource sentinel" not in materializer.stderr

    verifier = ROOT / "scripts/verify_synth_001_preflight.py"
    verification = subprocess.run(
        [
            sys.executable,
            str(verifier),
            "--materialization",
            str(tmp_path / "materialization.json"),
            "--prepared",
            str(tmp_path / "prepared.json"),
            "--repo",
            str(tmp_path / "repo"),
            "--fixture-dir",
            str(FIXTURE),
            "--profile",
            str(tmp_path / "profile.json"),
            "--limits",
            str(tmp_path / "limits.json"),
            "--provider-config",
            str(tmp_path / "provider.json"),
        ],
        cwd=tmp_path,
        env=environment,
        text=True,
        capture_output=True,
        check=False,
    )
    assert verification.returncode == 2
    assert json.loads(verification.stderr) == {
        "schema": "synth-001-preflight-verification.v1",
        "result": "REJECTED",
        "error": "fixture_pin_resource_unavailable",
    }
    assert "opaque resource sentinel" not in verification.stderr


@pytest.mark.compatibility
def test_synth_fixture_pins_match_immutable_artifact_bytes():
    from pr_review_harness.compatibility_pins import pin, pins

    artifact_paths = {
        "fixture.seeded_writer_synth_001.truth_sha256": (
            "truth.json",
            pin("fixture.seeded_writer_synth_001.truth_sha256"),
        ),
        "fixture.seeded_writer_synth_001.seed_sha256": (
            "seed.json",
            pin("fixture.seeded_writer_synth_001.seed_sha256"),
        ),
        "fixture.seeded_writer_synth_001.contract_sha256": (
            "contract.md",
            pin("fixture.seeded_writer_synth_001.contract_sha256"),
        ),
        "fixture.seeded_writer_synth_001.caller_sha256": (
            "caller.py",
            pin("fixture.seeded_writer_synth_001.caller_sha256"),
        ),
        "fixture.seeded_writer_synth_001.base_auth_sha256": (
            "base/auth.py",
            pin("fixture.seeded_writer_synth_001.base_auth_sha256"),
        ),
        "fixture.seeded_writer_synth_001.head_auth_sha256": (
            "head/auth.py",
            pin("fixture.seeded_writer_synth_001.head_auth_sha256"),
        ),
    }
    records = pins()
    for name, (relative, recorded_hash) in artifact_paths.items():
        artifact = FIXTURE / relative
        assert recorded_hash == hashlib.sha256(artifact.read_bytes()).hexdigest()
        provenance = records[name]["provenance"]
        assert records[name]["kind"] == "evaluation-fixture"
        assert provenance["artifact"] == f"examples/evaluation/seeded-writer-synth-001/{relative}"
        assert provenance["source_revision"] == "43ba7b9050c8c74f81eae9bcc714c967de8fa4b3"
        assert provenance["recorded_at"] == "2026-09-28"

    visible_files = {
        relative: (FIXTURE / relative).read_text(encoding="utf-8")
        for relative in ("contract.md", "caller.py", "base/auth.py", "head/auth.py")
    }
    payload = json.dumps(
        {"fixture_id": "SYNTH-001", "seed": 457001, "files": visible_files},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    payload_key = "fixture.seeded_writer_synth_001.payload_sha256"
    assert pin(payload_key) == hashlib.sha256(payload).hexdigest()
    payload_provenance = records[payload_key]["provenance"]
    assert records[payload_key]["kind"] == "evaluation-fixture"
    assert payload_provenance["artifact"] == "examples/evaluation/seeded-writer-synth-001/truth.json"
    assert payload_provenance["source_revision"] == "43ba7b9050c8c74f81eae9bcc714c967de8fa4b3"
    assert payload_provenance["recorded_at"] == "2026-09-28"


@pytest.mark.compatibility
def test_materialization_is_deterministic_and_contains_only_review_inputs(tmp_path: Path):
    first = _run(FIXTURE, tmp_path / "first")
    second = _run(FIXTURE, tmp_path / "second")
    assert first.returncode == second.returncode == 0, first.stderr + second.stderr
    one = json.loads(first.stdout)
    two = json.loads(second.stdout)
    assert one == two
    assert one["fixture_id"] == "SYNTH-001"
    from pr_review_harness.compatibility_pins import pin

    assert one["payload_sha256"] == pin("fixture.seeded_writer_synth_001.payload_sha256")
    assert one["changed_path"] == "auth.py"
    assert one["base_sha"] != one["head_sha"]
    assert (
        hashlib.sha256((tmp_path / "first" / "auth.py").read_bytes()).hexdigest()
        == hashlib.sha256((FIXTURE / "head/auth.py").read_bytes()).hexdigest()
    )
    tracked = subprocess.run(
        ["git", "-C", str(tmp_path / "first"), "ls-tree", "-r", "--name-only", one["head_sha"]],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    ).stdout.splitlines()
    assert tracked == ["auth.py", "caller.py", "contract.md"]
    assert "truth" not in first.stdout.lower()
    assert (tmp_path / "first" / "truth.json").exists() is False
    assert (tmp_path / "first" / "base").exists() is False
    assert (tmp_path / "first" / "head").exists() is False


def test_materializer_rejects_tampering_and_extra_files(tmp_path: Path):
    changed = tmp_path / "changed"
    changed.mkdir()
    for path in FIXTURE.iterdir():
        if path.is_file():
            (changed / path.name).write_bytes(path.read_bytes())
        elif path.is_dir():
            import shutil

            shutil.copytree(path, changed / path.name)
    (changed / "caller.py").write_bytes((changed / "caller.py").read_bytes() + b"# changed\n")
    result = _run(changed, tmp_path / "tampered-target")
    assert result.returncode != 0
    assert json.loads(result.stderr)["error"] == "fixture_hash_mismatch"

    (changed / "caller.py").write_bytes((FIXTURE / "caller.py").read_bytes())
    (changed / "extra.txt").write_text("extra")
    result = _run(changed, tmp_path / "extra-target")
    assert result.returncode != 0
    assert json.loads(result.stderr)["error"] == "fixture_file_set_invalid"


def test_materializer_rejects_symlinks_and_nonempty_target(tmp_path: Path):
    fixture_link = tmp_path / "fixture-link"
    fixture_link.symlink_to(FIXTURE, target_is_directory=True)
    result = _run(fixture_link, tmp_path / "root-symlink-target")
    assert result.returncode != 0
    assert json.loads(result.stderr)["error"] == "fixture_directory_invalid"

    linked = tmp_path / "linked"
    linked.mkdir()
    for path in FIXTURE.iterdir():
        if path.is_file():
            (linked / path.name).write_bytes(path.read_bytes())
        elif path.is_dir():
            import shutil

            shutil.copytree(path, linked / path.name)
    (linked / "caller.py").unlink()
    (linked / "caller.py").symlink_to(FIXTURE / "caller.py")
    result = _run(linked, tmp_path / "symlink-target")
    assert result.returncode != 0
    assert json.loads(result.stderr)["error"] == "fixture_tree_invalid"

    target = tmp_path / "occupied"
    target.mkdir()
    (target / "keep").write_text("keep")
    result = _run(FIXTURE, target)
    assert result.returncode != 0
    assert json.loads(result.stderr)["error"] == "target_must_be_empty"
