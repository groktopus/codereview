from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "src"))

import finalize_synth_001_identity_v3 as finalizer  # noqa: E402
import package_synth_001_cross_model as package  # noqa: E402


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def test_v3_package_route_is_versioned_and_frozen_runtime_matches() -> None:
    identity = package._identity()
    assert identity["schema"] == "synth-001-cross-model-package-identity.v2"
    configuration = identity["configuration"]
    assert configuration["runtime_pin_status"] == "FROZEN"
    assert configuration["module_count"] > 0
    assert re.fullmatch(r"[0-9a-f]{64}", configuration["module_tree_sha256"])
    assert re.fullmatch(r"[0-9a-f]{40}", configuration["source_revision"])
    verification = {
        key: configuration[key]
        for key in (
            "runtime",
            "module_count",
            "module_tree_sha256",
            "source_revision",
        )
    }
    assert package._check_configuration(identity, verification)

    pending = json.loads(json.dumps(identity))
    pending["configuration"].update(
        {
            "runtime_pin_status": "REQUIRES_FINAL_STACKED_RUNTIME",
            "module_count": None,
            "module_tree_sha256": None,
            "source_revision": None,
        }
    )
    with pytest.raises(package.PackageError, match="package_runtime_pin_pending"):
        package._check_configuration(pending, {})

    historical = json.loads((ROOT / "experiments/synth-001-package-identity-v2.json").read_text())
    assert historical["schema"] == "synth-001-cross-model-package-identity.v1"
    assert historical["configuration"]["source_revision"] == "42e5d5bad7cc4f22f3be6fdd6ce99560edd275ea"


def test_finalizer_requires_prevalidated_pins_and_preserves_frozen_idempotence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "repo"
    (repo / "src/pr_review_harness").mkdir(parents=True)
    source = ROOT / "src/pr_review_harness"
    for path in source.glob("*.py"):
        shutil.copyfile(path, repo / "src/pr_review_harness" / path.name)

    subprocess.run(["git", "-C", str(repo), "init", "-q"], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.name", "test"], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.email", "test@example.invalid"], check=True)
    subprocess.run(["git", "-C", str(repo), "add", "src/pr_review_harness"], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-qm", "runtime fixture"], check=True)
    revision = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()

    experiments = repo / "experiments"
    scripts = repo / "scripts"
    experiments.mkdir()
    scripts.mkdir()
    identity_path = experiments / "synth-001-package-identity-v3.json"
    identity_path.write_bytes((ROOT / "experiments/synth-001-package-identity-v3.json").read_bytes())
    verifier_path = scripts / "verify_synth_001_preflight.py"
    verifier_path.write_bytes((ROOT / "scripts/verify_synth_001_preflight.py").read_bytes())
    package_path = scripts / "package_synth_001_cross_model.py"
    package_raw = (ROOT / "scripts/package_synth_001_cross_model.py").read_bytes()
    identity = json.loads(identity_path.read_text())
    identity["configuration"].update(
        {
            "runtime_pin_status": "REQUIRES_FINAL_STACKED_RUNTIME",
            "module_count": None,
            "module_tree_sha256": None,
            "source_revision": None,
        }
    )
    identity_raw = (json.dumps(identity, indent=2, ensure_ascii=False) + "\n").encode()
    identity_path.write_bytes(identity_raw)
    package_path.write_bytes(package_raw)
    pins_path = tmp_path / "pins.json"
    manifest = json.loads((ROOT / "src/pr_review_harness/compatibility-pins.v1.json").read_text())
    tree_count, tree_sha = finalizer._module_tree_revision(repo, revision)
    finalized = json.loads(json.dumps(identity))
    finalized["configuration"].update(
        {
            "module_count": tree_count,
            "module_tree_sha256": tree_sha,
            "source_revision": revision,
            "runtime_pin_status": "FROZEN",
        }
    )
    finalized_raw = (json.dumps(finalized, indent=2, ensure_ascii=False) + "\n").encode()
    manifest["file_pins"]["pr170-tree-synthesis"] = tree_sha
    manifest["file_pins"]["synth-001-package-identity-v3"] = _sha(finalized_raw)
    pins_path.write_text(json.dumps(manifest), encoding="utf-8")
    monkeypatch.setattr(finalizer, "IDENTITY_PATH", identity_path)
    monkeypatch.setattr(finalizer, "VERIFIER_PATH", verifier_path)
    monkeypatch.setattr(finalizer, "PACKAGE_PATH", package_path)
    monkeypatch.setattr(finalizer, "PINS_PATH", pins_path)

    result = finalizer.finalize(repo, revision)
    identity_raw = identity_path.read_bytes()
    identity = json.loads(identity_raw)
    config = identity["configuration"]
    assert result["status"] == "FROZEN"
    assert config["runtime_pin_status"] == "FROZEN"
    assert config["source_revision"] == revision
    assert config["module_count"] == result["module_count"]
    assert config["module_tree_sha256"] == result["module_tree_sha256"]
    assert result["identity_sha256"] == _sha(identity_raw)
    assert f"MODULE_COUNT = {config['module_count']}".encode() in verifier_path.read_bytes()
    assert f'SOURCE_REVISION = "{revision}"'.encode() in verifier_path.read_bytes()
    assert package_path.read_bytes() == package_raw
    assert pins_path.read_text(encoding="utf-8") == json.dumps(manifest)
    frozen_bytes = (identity_path.read_bytes(), verifier_path.read_bytes(), package_path.read_bytes())
    repeated = finalizer.finalize(repo, revision)
    assert repeated == result
    assert frozen_bytes == (identity_path.read_bytes(), verifier_path.read_bytes(), package_path.read_bytes())


def test_finalizer_refuses_unpinned_candidate_before_writes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = tmp_path / "repo"
    module_dir = repo / "src/pr_review_harness"
    module_dir.mkdir(parents=True)
    (module_dir / "a.py").write_text("VALUE = 1\n")
    subprocess.run(["git", "-C", str(repo), "init", "-q"], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.name", "test"], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.email", "test@example.invalid"], check=True)
    subprocess.run(["git", "-C", str(repo), "add", "src/pr_review_harness"], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-qm", "runtime fixture"], check=True)
    revision = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    (module_dir / "a.py").write_text("VALUE = 2\n")

    experiments = repo / "experiments"
    scripts = repo / "scripts"
    experiments.mkdir()
    scripts.mkdir()
    identity_path = experiments / "synth-001-package-identity-v3.json"
    identity_path.write_bytes((ROOT / "experiments/synth-001-package-identity-v3.json").read_bytes())
    verifier_path = scripts / "verify_synth_001_preflight.py"
    verifier_path.write_bytes((ROOT / "scripts/verify_synth_001_preflight.py").read_bytes())
    package_path = scripts / "package_synth_001_cross_model.py"
    package_path.write_bytes((ROOT / "scripts/package_synth_001_cross_model.py").read_bytes())
    monkeypatch.setattr(finalizer, "IDENTITY_PATH", identity_path)
    monkeypatch.setattr(finalizer, "VERIFIER_PATH", verifier_path)
    monkeypatch.setattr(finalizer, "PACKAGE_PATH", package_path)
    with pytest.raises(finalizer.FinalizeError, match="runtime_worktree_revision_mismatch"):
        finalizer.finalize(repo, revision)


@pytest.mark.parametrize("pin_mismatch", ["tree", "identity"])
def test_finalizer_refuses_unprevalidated_pin_without_writes(
    pin_mismatch: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "repo"
    module_dir = repo / "src/pr_review_harness"
    module_dir.mkdir(parents=True)
    (module_dir / "a.py").write_text("VALUE = 1\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "init", "-q"], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.name", "test"], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.email", "test@example.invalid"], check=True)
    subprocess.run(["git", "-C", str(repo), "add", "src/pr_review_harness"], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-qm", "runtime fixture"], check=True)
    revision = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"], check=True, capture_output=True, text=True
    ).stdout.strip()

    identity_path = tmp_path / "identity.json"
    identity = json.loads((ROOT / "experiments/synth-001-package-identity-v3.json").read_text())
    identity["configuration"].update(
        {
            "runtime_pin_status": "REQUIRES_FINAL_STACKED_RUNTIME",
            "module_count": None,
            "module_tree_sha256": None,
            "source_revision": None,
        }
    )
    identity_path.write_text(json.dumps(identity, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    verifier_path = tmp_path / "verifier.py"
    verifier_path.write_bytes((ROOT / "scripts/verify_synth_001_preflight.py").read_bytes())
    package_path = tmp_path / "package.py"
    package_path.write_bytes((ROOT / "scripts/package_synth_001_cross_model.py").read_bytes())
    pins_path = tmp_path / "pins.json"
    manifest = json.loads((ROOT / "src/pr_review_harness/compatibility-pins.v1.json").read_text())
    if pin_mismatch == "identity":
        _count, candidate_tree = finalizer._module_tree_revision(repo, revision)
        manifest["file_pins"][finalizer.TREE_PIN_NAME] = candidate_tree
    pins_path.write_text(json.dumps(manifest), encoding="utf-8")
    monkeypatch.setattr(finalizer, "IDENTITY_PATH", identity_path)
    monkeypatch.setattr(finalizer, "VERIFIER_PATH", verifier_path)
    monkeypatch.setattr(finalizer, "PACKAGE_PATH", package_path)
    monkeypatch.setattr(finalizer, "PINS_PATH", pins_path)
    originals = (identity_path.read_bytes(), verifier_path.read_bytes(), package_path.read_bytes())
    expected_error = (
        "runtime_tree_pin_not_prevalidated" if pin_mismatch == "tree" else "finalized_identity_pin_not_prevalidated"
    )
    with pytest.raises(finalizer.FinalizeError, match=expected_error):
        finalizer.finalize(repo, revision)
    assert originals == (identity_path.read_bytes(), verifier_path.read_bytes(), package_path.read_bytes())
