from __future__ import annotations

import hashlib
import json
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))

import frozen_runtime  # noqa: E402


def _inventory_hashes(source_root: Path) -> tuple[int, str, str]:
    files = sorted((source_root / "src/pr_review_harness").glob("*.py"), key=lambda path: path.name)
    model_hashes = {
        f"pr_review_harness/{path.name}": hashlib.sha256(path.read_bytes()).hexdigest()
        for path in files
    }
    model_tree = hashlib.sha256(
        json.dumps(model_hashes, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()
    synth_digest = hashlib.sha256()
    for path in files:
        content_hash = model_hashes[f"pr_review_harness/{path.name}"]
        synth_digest.update(path.name.encode("utf-8") + b"\0" + content_hash.encode("ascii") + b"\n")
    return len(files), model_tree, synth_digest.hexdigest()


def test_contract_overlay_is_exact_a0988f2_base_blob():
    assert hashlib.sha256(frozen_runtime.FROZEN_CONTRACTS.read_bytes()).hexdigest() == (
        "5b23d6dc84bb7d4b684bb94326acf586796a4068426890f74f111690785201a3"
    )


def test_frozen_runtime_reconstructs_both_historical_inventories(tmp_path: Path):
    assert hashlib.sha256(frozen_runtime.FROZEN_ENGINE.read_bytes()).hexdigest() == (
        "da5923ea3b1cf8902612e0c6d97ba4aef64cbe5af80da014a3615d6488656977"
    )
    assert hashlib.sha256(frozen_runtime.FROZEN_BUDGET.read_bytes()).hexdigest() == (
        "d061b7e6e81ec75b52fb11ae8e74accdcab3a2308bdeeaeb3a46290d6669ff41"
    )
    assert hashlib.sha256(frozen_runtime.FROZEN_PLANNER.read_bytes()).hexdigest() == (
        "82bc1851dc593ad5d17abf4f4ff2bb1185c33916051f1388813437db58a052ff"
    )
    assert hashlib.sha256(frozen_runtime.FROZEN_PUBLICATION_RECEIPTS.read_bytes()).hexdigest() == (
        "c31cf6bddbd10e3ad5b663b79d0ead51046f6d8279561b7d6c0d84f831f3ab41"
    )
    assert hashlib.sha256(frozen_runtime.FROZEN_SNAPSHOT.read_bytes()).hexdigest() == (
        "68c621245d28af38f6cf5d9bf1d621d962ebe544174da50add6dda75570d3b5f"
    )
    assert hashlib.sha256(frozen_runtime.FROZEN_MODULE.read_bytes()).hexdigest() == (
        "a2efc2c78368c7d18c6f678bd889a62c0425652529316bb0c9b8d8bf699d7664"
    )
    runtime_root = frozen_runtime.build_frozen_runtime_root(tmp_path)
    assert _inventory_hashes(runtime_root) == (
        35,
        frozen_runtime.EXPECTED_MODEL_TREE_SHA256,
        frozen_runtime.EXPECTED_SYNTH_TREE_SHA256,
    )


def test_modified_archived_module_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    tampered = tmp_path / "tampered-selected-model-trial.py"
    tampered.write_bytes(frozen_runtime.FROZEN_MODULE.read_bytes() + b"\n")
    monkeypatch.setattr(frozen_runtime, "FROZEN_MODULE", tampered)
    with pytest.raises(AssertionError, match="historical inventory"):
        frozen_runtime.build_frozen_runtime_root(tmp_path)


def test_unlisted_new_module_is_excluded_from_historical_runtime(tmp_path: Path):
    new_module = ROOT / "src/pr_review_harness/github_app_credentials.py"
    assert new_module.is_file()
    runtime_root = frozen_runtime.build_frozen_runtime_root(tmp_path)
    assert not (runtime_root / "src/pr_review_harness/github_app_credentials.py").exists()
    assert _inventory_hashes(runtime_root)[0] == frozen_runtime.EXPECTED_MODULE_COUNT


@pytest.mark.parametrize(
    "inventory",
    [
        [],
        ["__init__.py"] * frozen_runtime.EXPECTED_MODULE_COUNT,
        ["../outside.py"] + ["placeholder.py"] * (frozen_runtime.EXPECTED_MODULE_COUNT - 1),
    ],
)
def test_invalid_frozen_module_inventory_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, inventory):
    inventory_path = tmp_path / "inventory.json"
    inventory_path.write_text(json.dumps(inventory), encoding="utf-8")
    monkeypatch.setattr(frozen_runtime, "MODULE_INVENTORY", inventory_path)
    with pytest.raises(AssertionError, match="historical module inventory"):
        frozen_runtime.build_frozen_runtime_root(tmp_path)


def test_missing_historical_source_module_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    source_root = tmp_path / "source"
    source_dir = source_root / "src/pr_review_harness"
    shutil.copytree(ROOT / "src/pr_review_harness", source_dir)
    (source_dir / "engine.py").unlink()
    monkeypatch.setattr(frozen_runtime, "ROOT", source_root)
    with pytest.raises(AssertionError, match="source is missing"):
        frozen_runtime.build_frozen_runtime_root(tmp_path)


def test_modified_historical_module_bytes_are_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    source_root = tmp_path / "source"
    source_dir = source_root / "src/pr_review_harness"
    shutil.copytree(ROOT / "src/pr_review_harness", source_dir)
    with (source_dir / "checks.py").open("ab") as source:
        source.write(b"\n# changed historical module\n")
    monkeypatch.setattr(frozen_runtime, "ROOT", source_root)
    with pytest.raises(AssertionError, match="historical inventory"):
        frozen_runtime.build_frozen_runtime_root(tmp_path)
