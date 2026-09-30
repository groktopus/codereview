from __future__ import annotations

import hashlib
import json
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


def test_frozen_runtime_reconstructs_both_historical_inventories(tmp_path: Path):
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
