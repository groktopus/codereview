"""Build the exact source inventory pinned by historical prepare plans."""

from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FROZEN_MODULE = Path(__file__).resolve().parent / "fixtures" / "selected_model_trial-pr170-base.py"
FROZEN_OBSERVER = Path(__file__).resolve().parent / "fixtures" / "external_effect_observer-pr170-base.py"
FROZEN_REPORT = Path(__file__).resolve().parent / "fixtures" / "report-pr170-base.py"
FROZEN_SNAPSHOT = Path(__file__).resolve().parent / "fixtures" / "snapshot-pr170-base.py"
EXPECTED_MODULE_COUNT = 35
EXPECTED_MODEL_TREE_SHA256 = "400e26f99f054a960d2622241462af02a4d67d1fa4dbbc467c4858b32b9f9ea3"
EXPECTED_SYNTH_TREE_SHA256 = "75b3ead743048b4f1296bb132f4e135837224a1886e23693031d15c8e67e5991"


def build_frozen_runtime_root(tmp_path: Path) -> Path:
    """Return a temp source root matching the original PR-170 plan inventory.

    Current source is copied as regular files, then the selected-trial module,
    observer, and report changed since the historical runtime pins are restored from their
    exact main-base blobs. Both verifier hash encodings are recomputed so unrelated
    source drift invalidates the fixture.
    """
    runtime_root = tmp_path / "frozen-runtime"
    module_dir = runtime_root / "src" / "pr_review_harness"
    module_dir.parent.mkdir(parents=True)
    shutil.copytree(ROOT / "src" / "pr_review_harness", module_dir)
    (module_dir / "selected_model_trial.py").write_bytes(FROZEN_MODULE.read_bytes())
    (module_dir / "external_effect_observer.py").write_bytes(FROZEN_OBSERVER.read_bytes())
    (module_dir / "report.py").write_bytes(FROZEN_REPORT.read_bytes())
    (module_dir / "snapshot.py").write_bytes(FROZEN_SNAPSHOT.read_bytes())

    files = sorted(module_dir.glob("*.py"), key=lambda path: path.name)
    module_hashes = {
        f"pr_review_harness/{path.name}": hashlib.sha256(path.read_bytes()).hexdigest()
        for path in files
    }
    model_tree = hashlib.sha256(
        json.dumps(
            module_hashes, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
    ).hexdigest()
    synth_digest = hashlib.sha256()
    for path in files:
        content_hash = module_hashes[f"pr_review_harness/{path.name}"]
        synth_digest.update(path.name.encode("utf-8") + b"\0" + content_hash.encode("ascii") + b"\n")
    if (len(files) != EXPECTED_MODULE_COUNT or model_tree != EXPECTED_MODEL_TREE_SHA256
            or synth_digest.hexdigest() != EXPECTED_SYNTH_TREE_SHA256):
        raise AssertionError("frozen runtime fixture no longer matches historical inventory")
    return runtime_root
