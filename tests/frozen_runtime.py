"""Build the exact source inventory pinned by historical prepare plans."""

from __future__ import annotations

import hashlib
import json
import re
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FROZEN_MODULE = Path(__file__).resolve().parent / "fixtures" / "selected_model_trial-pr170-base.py"
FROZEN_ENGINE = Path(__file__).resolve().parent / "fixtures" / "engine-pr170-base.py"
FROZEN_BUDGET = Path(__file__).resolve().parent / "fixtures" / "budget-pr170-base.py"
FROZEN_PLANNER = Path(__file__).resolve().parent / "fixtures" / "planner-pr170-base.py"
FROZEN_OBSERVER = Path(__file__).resolve().parent / "fixtures" / "external_effect_observer-pr170-base.py"
FROZEN_REPORT = Path(__file__).resolve().parent / "fixtures" / "report-pr170-base.py"
FROZEN_ARTIFACT_INTAKE = Path(__file__).resolve().parent / "fixtures" / "artifact_intake-pr170-base.py"
FROZEN_ACTIONS_PUBLICATION = Path(__file__).resolve().parent / "fixtures" / "actions_publication-pr170-base.py"
FROZEN_ACTIONS_RUNTIME = Path(__file__).resolve().parent / "fixtures" / "actions_runtime-pr170-base.py"
FROZEN_PROVIDERS = Path(__file__).resolve().parent / "fixtures" / "providers-pr170-base.py"
FROZEN_CONTRACTS = Path(__file__).resolve().parent / "fixtures" / "contracts-a0988f2-base.py"
FROZEN_PUBLICATION_RECEIPTS = Path(__file__).resolve().parent / "fixtures" / "publication_receipts-pr170-base.py"
FROZEN_PUBLISHER = Path(__file__).resolve().parent / "fixtures" / "publisher-pr-actions-token-base.py"
MODULE_INVENTORY = Path(__file__).resolve().parent / "fixtures" / "pr170-module-inventory.json"
# Exact source bytes for inventory modules that the consolidation moved out of
# ``src`` into ``experiments/harness``.  The historical runtime is reconstructed
# from these pinned bytes, so relocating or later editing an experiment module
# cannot drift the archived evidence tree.
PINNED_RELOCATED = Path(__file__).resolve().parent / "fixtures" / "frozen-runtime-7d550b6"
# Relocated inventory modules that already have a dedicated historical overlay
# fixture. Their pre-consolidation bytes are already pinned by that overlay, so
# the copy step can use it instead of keeping a second identical copy.
RELOCATED_WITH_OVERLAY = frozenset(
    {"selected_model_trial.py", "actions_runtime.py", "policy_inventory.py", "shadow_audit.py"}
)
FROZEN_SNAPSHOT = Path(__file__).resolve().parent / "fixtures" / "snapshot-pr170-base.py"
FROZEN_SHADOW_AUDIT = Path(__file__).resolve().parent / "fixtures" / "shadow_audit-pr201-base.py"
FROZEN_CLI = Path(__file__).resolve().parent / "fixtures" / "cli-pr170-base.py"
FROZEN_CLAIM_ASSESSMENT = Path(__file__).resolve().parent / "fixtures" / "claim_assessment-pr214-base.py"
FROZEN_CLAIM_TRANSPORT = Path(__file__).resolve().parent / "fixtures" / "claim_transport-pr214-base.py"
FROZEN_GITHUB = Path(__file__).resolve().parent / "fixtures" / "github-pr214-base.py"
FROZEN_POLICY_INVENTORY = Path(__file__).resolve().parent / "fixtures" / "policy_inventory-pr214-base.py"
FROZEN_EVIDENCE = Path(__file__).resolve().parent / "fixtures" / "evidence-pr223-base.py"
EXPECTED_MODULE_COUNT = 35
PIN_MANIFEST = PINNED_RELOCATED / "pins.json"
HISTORICAL_REVISION = "7d550b61825defec8a8a0625511c914ba8efd5cb"
FILE_PIN_REFRESH_COMMAND = (
    "python scripts/refresh_compatibility_pins.py --reason '<reviewed reason>' "
    "--source-revision <40-hex-commit> --confirm"
)


def _load_pins() -> dict[str, str]:
    try:
        manifest = json.loads(PIN_MANIFEST.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise AssertionError("historical compatibility pin manifest is unavailable or invalid") from None
    if (
        manifest.get("schema") != "pr-review-historical-pins.v1"
        or manifest.get("historical_revision") != HISTORICAL_REVISION
    ):
        raise AssertionError("historical compatibility pin manifest schema or revision is invalid")
    pins = manifest.get("pins")
    if not isinstance(pins, dict):
        raise AssertionError("historical compatibility pin manifest pins are invalid")
    return pins


def assert_frozen_runtime_pin(name: str, path: Path) -> None:
    """Check a CA-2 archived blob with a named, revision-bound remedy."""
    expected = _load_pins().get(name)
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if expected != actual:
        raise AssertionError(
            f"historical compatibility mismatch: module {path.name!r} at revision {HISTORICAL_REVISION}; "
            f"expected {expected!r}, got {actual}. Historical pins are immutable; preserve prior evidence and "
            "use a reviewed migration rather than editing a fixture. The exact refresh command is:\n  "
            f"{FILE_PIN_REFRESH_COMMAND}"
        )


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


def _frozen_runtime_root_and_hashes(tmp_path: Path, *, verify: bool = True) -> tuple[Path, dict[str, str]]:
    """Assemble the historical tree and return its model/synthesis digests.

    Only the pinned original modules are copied, then modules changed after the
    historical runtime pins are restored from exact main-base blobs. Modules the
    CA-2 consolidation relocated outside ``src`` are read from their pinned
    historical bytes instead. Both verifier hash encodings are recomputed so
    unrelated source drift invalidates the fixture.
    """
    overlays = (
        ("engine.py", FROZEN_ENGINE, "engine-pr170-base.py"),
        ("budget.py", FROZEN_BUDGET, "budget-pr170-base.py"),
        ("planner.py", FROZEN_PLANNER, "planner-pr170-base.py"),
        ("selected_model_trial.py", FROZEN_MODULE, "selected_model_trial-pr170-base.py"),
        ("external_effect_observer.py", FROZEN_OBSERVER, "external_effect_observer-pr170-base.py"),
        ("report.py", FROZEN_REPORT, "report-pr170-base.py"),
        ("artifact_intake.py", FROZEN_ARTIFACT_INTAKE, "artifact_intake-pr170-base.py"),
        ("actions_publication.py", FROZEN_ACTIONS_PUBLICATION, "actions_publication-pr170-base.py"),
        ("actions_runtime.py", FROZEN_ACTIONS_RUNTIME, "actions_runtime-pr170-base.py"),
        ("providers.py", FROZEN_PROVIDERS, "providers-pr170-base.py"),
        ("contracts.py", FROZEN_CONTRACTS, "contracts-a0988f2-base.py"),
        ("publication_receipts.py", FROZEN_PUBLICATION_RECEIPTS, "publication_receipts-pr170-base.py"),
        ("publisher.py", FROZEN_PUBLISHER, "publisher-pr-actions-token-base.py"),
        ("snapshot.py", FROZEN_SNAPSHOT, "snapshot-pr170-base.py"),
        ("cli.py", FROZEN_CLI, "cli-pr170-base.py"),
        ("claim_assessment.py", FROZEN_CLAIM_ASSESSMENT, "claim_assessment-pr214-base.py"),
        ("claim_transport.py", FROZEN_CLAIM_TRANSPORT, "claim_transport-pr214-base.py"),
        ("github.py", FROZEN_GITHUB, "github-pr214-base.py"),
        ("policy_inventory.py", FROZEN_POLICY_INVENTORY, "policy_inventory-pr214-base.py"),
        ("shadow_audit.py", FROZEN_SHADOW_AUDIT, "shadow_audit-pr201-base.py"),
        ("evidence.py", FROZEN_EVIDENCE, "evidence-pr223-base.py"),
    )
    runtime_root = tmp_path / "frozen-runtime"
    module_dir = runtime_root / "src" / "pr_review_harness"
    module_dir.parent.mkdir(parents=True)
    module_dir.mkdir()
    source_dir = ROOT / "src" / "pr_review_harness"
    module_names = _load_module_inventory()
    overlay_sources = {name: path for name, path, _pin in overlays}
    manifest = json.loads(PIN_MANIFEST.read_text(encoding="utf-8"))
    for name in module_names:
        source = PINNED_RELOCATED / name
        if source.is_file():
            assert_frozen_runtime_pin(name, source)
            expected_path = manifest["pin_files"].get(name)
            fixture_root = Path(__file__).resolve().parent.parent
            if expected_path != str(source.relative_to(fixture_root)):
                raise AssertionError(
                    f"historical compatibility manifest path mismatch: module {name!r} at revision "
                    f"{HISTORICAL_REVISION}; expected fixture {expected_path!r}, got {source}. "
                    "Historical pins are immutable; preserve prior evidence and use a reviewed migration. "
                    f"The exact refresh command is:\n  {FILE_PIN_REFRESH_COMMAND}"
                )
    for name in module_names:
        pinned = PINNED_RELOCATED / name
        if pinned.is_file():
            source = pinned
        elif (source_dir / name).is_file():
            source = source_dir / name
        elif name in RELOCATED_WITH_OVERLAY and name in overlay_sources:
            # The overlay below writes this module's pinned historical bytes;
            # this copy only satisfies the inventory completeness check.
            source = overlay_sources[name]
        else:
            source = source_dir / name
        if not source.is_file() or source.is_symlink():
            raise AssertionError("historical module inventory source is missing or unsafe")
        shutil.copyfile(source, module_dir / name)
    manifest = json.loads(PIN_MANIFEST.read_text(encoding="utf-8"))
    for name, fixture, pin_name in overlays:
        assert_frozen_runtime_pin(pin_name, fixture)
        expected_path = manifest["pin_files"].get(pin_name)
        if expected_path != str(fixture.relative_to(Path(__file__).resolve().parent.parent)):
            raise AssertionError(
                f"historical compatibility manifest path mismatch: module {fixture.name!r} at revision "
                f"{HISTORICAL_REVISION}; expected fixture {expected_path!r}, got {fixture}. "
                "Historical pins are immutable; preserve prior evidence and use a reviewed migration. "
                f"The exact refresh command is:\n  {FILE_PIN_REFRESH_COMMAND}"
            )
        (module_dir / name).write_bytes(fixture.read_bytes())

    files = sorted(module_dir.glob("*.py"), key=lambda path: path.name)
    if tuple(path.name for path in files) != tuple(sorted(module_names)):
        raise AssertionError("frozen runtime source inventory changed")
    module_hashes = {f"pr_review_harness/{path.name}": hashlib.sha256(path.read_bytes()).hexdigest() for path in files}
    model_tree = hashlib.sha256(
        json.dumps(module_hashes, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()
    synth_digest = hashlib.sha256()
    for path in files:
        content_hash = module_hashes[f"pr_review_harness/{path.name}"]
        synth_digest.update(path.name.encode("utf-8") + b"\0" + content_hash.encode("ascii") + b"\n")
    if verify:
        pins = _load_pins()
        if (
            len(files) != EXPECTED_MODULE_COUNT
            or model_tree != pins.get("pr170-tree-model")
            or synth_digest.hexdigest() != pins.get("pr170-tree-synthesis")
        ):
            raise AssertionError(
                f"historical compatibility mismatch: module inventory at revision {HISTORICAL_REVISION}; "
                f"expected model tree {pins.get('pr170-tree-model')!r}, got {model_tree}; "
                f"expected synthesis tree {pins.get('pr170-tree-synthesis')!r}, got {synth_digest.hexdigest()}. "
                "Historical pins are immutable; preserve prior evidence and use a reviewed migration. "
                f"The exact refresh command is:\n  {FILE_PIN_REFRESH_COMMAND}"
            )
    return runtime_root, {"model": model_tree, "synthesis": synth_digest.hexdigest()}


def build_frozen_runtime_root(tmp_path: Path) -> Path:
    """Return a temp source root matching the original PR-170 plan inventory."""
    return _frozen_runtime_root_and_hashes(tmp_path)[0]


def frozen_tree_hashes(tmp_path: Path) -> dict[str, str]:
    """Return recomputed model/synthesis tree digests without pin comparison."""
    return _frozen_runtime_root_and_hashes(tmp_path, verify=False)[1]
