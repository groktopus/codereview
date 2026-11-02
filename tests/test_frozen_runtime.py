from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))

import frozen_runtime  # noqa: E402

pytestmark = pytest.mark.compatibility


def _inventory_hashes(source_root: Path) -> tuple[int, str, str]:
    files = sorted((source_root / "src/pr_review_harness").glob("*.py"), key=lambda path: path.name)
    model_hashes = {f"pr_review_harness/{path.name}": hashlib.sha256(path.read_bytes()).hexdigest() for path in files}
    model_tree = hashlib.sha256(
        json.dumps(model_hashes, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()
    synth_digest = hashlib.sha256()
    for path in files:
        content_hash = model_hashes[f"pr_review_harness/{path.name}"]
        synth_digest.update(path.name.encode("utf-8") + b"\0" + content_hash.encode("ascii") + b"\n")
    return len(files), model_tree, synth_digest.hexdigest()


def test_contract_overlay_is_exact_a0988f2_base_blob():
    frozen_runtime.assert_frozen_runtime_pin("contracts-a0988f2-base.py", frozen_runtime.FROZEN_CONTRACTS)


def test_publisher_overlay_is_exact_publication_branch_base_blob():
    frozen_runtime.assert_frozen_runtime_pin("publisher-pr-actions-token-base.py", frozen_runtime.FROZEN_PUBLISHER)


def test_frozen_runtime_reconstructs_both_historical_inventories(tmp_path: Path):
    for fixture in (
        frozen_runtime.FROZEN_CLI,
        frozen_runtime.FROZEN_ENGINE,
        frozen_runtime.FROZEN_BUDGET,
        frozen_runtime.FROZEN_PLANNER,
        frozen_runtime.FROZEN_PUBLICATION_RECEIPTS,
        frozen_runtime.FROZEN_SNAPSHOT,
        frozen_runtime.FROZEN_MODULE,
        frozen_runtime.FROZEN_EVIDENCE,
        frozen_runtime.FROZEN_ACTIONS_RUNTIME,
        frozen_runtime.FROZEN_OBSERVER,
        frozen_runtime.FROZEN_REPORT,
        frozen_runtime.FROZEN_ARTIFACT_INTAKE,
        frozen_runtime.FROZEN_ACTIONS_PUBLICATION,
        frozen_runtime.FROZEN_PROVIDERS,
        frozen_runtime.FROZEN_CLAIM_ASSESSMENT,
        frozen_runtime.FROZEN_CLAIM_TRANSPORT,
        frozen_runtime.FROZEN_GITHUB,
        frozen_runtime.FROZEN_POLICY_INVENTORY,
        frozen_runtime.FROZEN_SHADOW_AUDIT,
    ):
        name = fixture.name
        frozen_runtime.assert_frozen_runtime_pin(name, fixture)
    runtime_root = frozen_runtime.build_frozen_runtime_root(tmp_path)
    pins = frozen_runtime._load_pins()
    assert _inventory_hashes(runtime_root) == (35, pins["pr170-tree-model"], pins["pr170-tree-synthesis"])


def test_modified_archived_module_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    tampered = tmp_path / "tampered-selected-model-trial.py"
    tampered.write_bytes(frozen_runtime.FROZEN_MODULE.read_bytes() + b"\n")
    monkeypatch.setattr(frozen_runtime, "FROZEN_MODULE", tampered)
    with pytest.raises(AssertionError, match="historical compatibility mismatch"):
        frozen_runtime.assert_frozen_runtime_pin("selected_model_trial-pr170-base.py", tampered)


def test_historical_pin_failure_names_module_revision_and_migration(tmp_path: Path):
    changed = tmp_path / "modified.py"
    changed.write_bytes(b"not the historical blob")
    with pytest.raises(AssertionError) as error:
        frozen_runtime.assert_frozen_runtime_pin("selected_model_trial-pr170-base.py", changed)
    message = str(error.value)
    assert "modified.py" in message
    assert frozen_runtime.HISTORICAL_REVISION in message
    assert "reviewed migration" in message


def test_unlisted_new_module_is_excluded_from_historical_runtime(tmp_path: Path):
    new_module = ROOT / "src/pr_review_harness/github_app_credentials.py"
    assert new_module.is_file()
    context_targets = ROOT / "src/pr_review_harness/context_targets.py"
    assert context_targets.is_file()
    runtime_root = frozen_runtime.build_frozen_runtime_root(tmp_path)
    assert not (runtime_root / "src/pr_review_harness/github_app_credentials.py").exists()
    assert not (runtime_root / "src/pr_review_harness/context_targets.py").exists()
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


def test_modified_historical_module_bytes_are_rejected(tmp_path: Path):
    tampered = tmp_path / "checks.py"
    tampered.write_bytes((frozen_runtime.PINNED_RELOCATED / "checks.py").read_bytes() + b"\n# changed\n")
    with pytest.raises(AssertionError, match="historical compatibility mismatch"):
        frozen_runtime.assert_frozen_runtime_pin("checks.py", tampered)


def test_manifest_pins_match_revision_source_bytes():
    manifest = json.loads(frozen_runtime.PIN_MANIFEST.read_text(encoding="utf-8"))
    pins = manifest["pins"]
    files = manifest["pin_files"]
    revisions = manifest["pin_revisions"]
    for name, digest in pins.items():
        if name in {"pr170-tree-model", "pr170-tree-synthesis"}:
            continue
        source = files[name]
        blob = subprocess.run(
            ["git", "-C", str(ROOT), "show", f"{revisions[name]}:{source}"],
            check=True,
            capture_output=True,
        ).stdout
        assert hashlib.sha256(blob).hexdigest() == digest, name
