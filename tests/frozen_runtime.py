"""Build the exact source inventory pinned by historical prepare plans."""

from __future__ import annotations

import hashlib
import json
import re
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FROZEN_MODULE = Path(__file__).resolve().parent / "fixtures" / "selected_model_trial-pr170-base.py"
FROZEN_OBSERVER = Path(__file__).resolve().parent / "fixtures" / "external_effect_observer-pr170-base.py"
FROZEN_REPORT = Path(__file__).resolve().parent / "fixtures" / "report-pr170-base.py"
FROZEN_ARTIFACT_INTAKE = Path(__file__).resolve().parent / "fixtures" / "artifact_intake-pr170-base.py"
FROZEN_ACTIONS_PUBLICATION = Path(__file__).resolve().parent / "fixtures" / "actions_publication-pr170-base.py"
MODULE_INVENTORY = Path(__file__).resolve().parent / "fixtures" / "pr170-module-inventory.json"
EXPECTED_MODULE_COUNT = 35
EXPECTED_MODEL_TREE_SHA256 = "400e26f99f054a960d2622241462af02a4d67d1fa4dbbc467c4858b32b9f9ea3"
EXPECTED_SYNTH_TREE_SHA256 = "75b3ead743048b4f1296bb132f4e135837224a1886e23693031d15c8e67e5991"
_MODULE_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\.py\Z")


def _load_module_inventory() -> tuple[str, ...]:
    try:
        names = json.loads(MODULE_INVENTORY.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise AssertionError("historical module inventory is unavailable or invalid") from None
    if (
        not isinstance(names, list)
        or len(names) != EXPECTED_MODULE_COUNT
        or any(not isinstance(name, str) or not _MODULE_NAME.fullmatch(name) for name in names)
        or len(set(names)) != len(names)
    ):
        raise AssertionError("historical module inventory is unavailable or invalid")
    return tuple(names)


def build_frozen_runtime_root(tmp_path: Path) -> Path:
    """Return a temp source root matching the original PR-170 plan inventory.

    Only the pinned original modules are copied, then modules changed after the
    historical runtime pins are restored from exact main-base blobs. Both
    verifier hash encodings are recomputed so unrelated source drift invalidates
    the fixture.
    """
    runtime_root = tmp_path / "frozen-runtime"
    module_dir = runtime_root / "src" / "pr_review_harness"
    module_dir.parent.mkdir(parents=True)
    module_dir.mkdir()
    source_dir = ROOT / "src" / "pr_review_harness"
    module_names = _load_module_inventory()
    for name in module_names:
        source = source_dir / name
        if not source.is_file() or source.is_symlink():
            raise AssertionError("historical module inventory source is missing or unsafe")
        shutil.copyfile(source, module_dir / name)
    for name, fixture in (
        ("selected_model_trial.py", FROZEN_MODULE),
        ("external_effect_observer.py", FROZEN_OBSERVER),
        ("report.py", FROZEN_REPORT),
        ("artifact_intake.py", FROZEN_ARTIFACT_INTAKE),
        ("actions_publication.py", FROZEN_ACTIONS_PUBLICATION),
    ):
        (module_dir / name).write_bytes(fixture.read_bytes())

    files = sorted(module_dir.glob("*.py"), key=lambda path: path.name)
    if tuple(path.name for path in files) != tuple(sorted(module_names)):
        raise AssertionError("frozen runtime source inventory changed")
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
    if (
        len(files) != EXPECTED_MODULE_COUNT
        or model_tree != EXPECTED_MODEL_TREE_SHA256
        or synth_digest.hexdigest() != EXPECTED_SYNTH_TREE_SHA256
    ):
        raise AssertionError("frozen runtime fixture no longer matches historical inventory")
    return runtime_root
