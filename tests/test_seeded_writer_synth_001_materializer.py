from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
FIXTURE = ROOT / "examples/evaluation/seeded-writer-synth-001"
SCRIPT = ROOT / "scripts/materialize_seeded_writer_synth_001.py"


def _run(fixture: Path, target: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), "--fixture-dir", str(fixture), "--target-dir", str(target)],
        text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )


def test_materialization_is_deterministic_and_contains_only_review_inputs(tmp_path: Path):
    first = _run(FIXTURE, tmp_path / "first")
    second = _run(FIXTURE, tmp_path / "second")
    assert first.returncode == second.returncode == 0, first.stderr + second.stderr
    one = json.loads(first.stdout)
    two = json.loads(second.stdout)
    assert one == two
    assert one["fixture_id"] == "SYNTH-001"
    assert one["payload_sha256"] == "7aeae889a915e54aab796c84542529607e0cdd0f8035e3cb2cf5fde43eacb97f"
    assert one["changed_path"] == "auth.py"
    assert one["base_sha"] != one["head_sha"]
    assert hashlib.sha256((tmp_path / "first" / "auth.py").read_bytes()).hexdigest() == hashlib.sha256(
        (FIXTURE / "head/auth.py").read_bytes()
    ).hexdigest()
    tracked = subprocess.run(
        ["git", "-C", str(tmp_path / "first"), "ls-tree", "-r", "--name-only", one["head_sha"]],
        check=True, text=True, stdout=subprocess.PIPE,
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
