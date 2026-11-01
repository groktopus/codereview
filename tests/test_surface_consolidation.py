"""CA-2 consolidation gates: one orchestrator, no experiment modules in the wheel.

These tests are executable statements of the consolidation contract documented in
``docs/ARCHITECTURE.md`` and ``docs/public-surface.json``. They do not exercise
provider or network paths.
"""

from __future__ import annotations

import ast
import importlib.util
import json
import subprocess
import sys
import tomllib
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "pr_review_harness"
MANIFEST_PATH = ROOT / "docs" / "public-surface.json"
FROZEN_INVENTORY = ROOT / "tests" / "fixtures" / "pr170-module-inventory.json"
PINNED_RELOCATED = ROOT / "tests" / "fixtures" / "frozen-runtime-7d550b6"


def _manifest() -> dict:
    return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))


def _src_line_count() -> int:
    return sum(len(path.read_text(encoding="utf-8").splitlines()) for path in SRC.glob("*.py"))


def _top_level_run_definitions() -> dict[str, list[str]]:
    found: dict[str, list[str]] = {}
    for path in sorted(SRC.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        names = [
            node.name
            for node in tree.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("run_")
        ]
        if names:
            found[path.name] = names
    return found


def test_documented_public_surface_matches_the_installed_package():
    manifest = _manifest()
    assert manifest["schema"] == "pr-review-public-surface.v1"
    documented = set(manifest["production_modules"])
    assert documented == {path.name for path in SRC.glob("*.py")}
    assert len(documented) == len(manifest["production_modules"]), "duplicate production module entry"


def test_src_reduction_meets_the_documented_floor():
    manifest = _manifest()["consolidation"]
    current = _src_line_count()
    assert current <= manifest["base_src_lines"]
    reduction = (manifest["base_src_lines"] - current) / manifest["base_src_lines"]
    assert reduction >= manifest["required_reduction"], (
        f"src reduction {reduction:.4f} is below the required {manifest['required_reduction']}"
    )
    assert manifest["measured_reduction"] >= manifest["required_reduction"]


def test_src_has_exactly_one_review_orchestrator_and_documented_helpers():
    found = _top_level_run_definitions()
    assert found == {
        "engine.py": ["run_review"],
        "protected_publication_runtime.py": ["run_protected_publication"],
        "review_stages.py": ["run_followup_stage", "run_followups"],
    }, found
    manifest = _manifest()
    assert manifest["review_orchestrator"] == {
        "module": "pr_review_harness.engine",
        "function": "run_review",
    }
    documented = {
        f"{manifest['review_orchestrator']['module']}:{manifest['review_orchestrator']['function']}",
        *manifest["internal_stage_functions"],
        *(
            f"{entry['module']}:{entry['function']}"
            for entry in manifest["guarded_effect_entrypoints"]
        ),
    }
    found_pairs = {
        f"pr_review_harness.{module.removesuffix('.py')}:{name}"
        for module, names in found.items()
        for name in names
    }
    assert found_pairs == documented
    assert "pr_review_harness.protected_publication_runtime:run_protected_publication" in found_pairs


def test_documented_review_orchestrator_is_importable():
    from pr_review_harness.engine import run_review

    assert callable(run_review)
    spec = importlib.util.find_spec("pr_review_harness.engine")
    assert spec is not None


@pytest.mark.parametrize("module", [row["module"] for row in _manifest()["relocated_experiment_modules"]])
def test_experiment_modules_are_archived_outside_the_installed_package(module: str):
    assert importlib.util.find_spec(f"experiments.harness.{module}") is not None
    assert importlib.util.find_spec(f"experiments.harness.{module}").origin is not None
    assert importlib.util.find_spec(f"pr_review_harness.{module}") is None
    assert not (SRC / f"{module}.py").exists()


def test_relocated_modules_keep_their_pinned_historical_bytes():
    inventory = set(json.loads(FROZEN_INVENTORY.read_text(encoding="utf-8")))
    relocated = {row["module"] for row in _manifest()["relocated_experiment_modules"]}
    expected = sorted(relocated & inventory)
    fixtures = ROOT / "tests" / "fixtures"
    unpinned = []
    for name in expected:
        if (PINNED_RELOCATED / f"{name}.py").is_file():
            continue
        if list(fixtures.glob(f"{name}-*.py")):
            # Covered by a dedicated historical overlay fixture instead of a
            # second identical pinned copy.
            continue
        unpinned.append(name)
    assert not unpinned, unpinned
    assert list(fixtures.glob("actions_runtime-*.py"))
    assert not (SRC / "source_audit.py").is_symlink()


def test_no_experiment_module_defines_or_forks_budget_and_settlement():
    assert (SRC / "budget.py").is_file()
    for path in sorted((ROOT / "experiments" / "harness").glob("*.py")):
        text = path.read_text(encoding="utf-8")
        assert "class BudgetLedger" not in text, path
        assert "def reserve(" not in text, path
        assert "def settle(" not in text, path
    budget_source = (SRC / "budget.py").read_text(encoding="utf-8")
    assert "class BudgetLedger" in budget_source
    assert "def reserve(" in budget_source and "def settle(" in budget_source


def test_production_imports_do_not_load_experiment_modules():
    probe = (
        "import sys\n"
        "import pr_review_harness.cli\n"
        "import pr_review_harness.engine\n"
        "loaded = sorted(name for name in sys.modules if name == 'experiments' or name.startswith('experiments.'))\n"
        "raise SystemExit(0 if not loaded else 1)\n"
    )
    completed = subprocess.run(
        [sys.executable, "-c", probe],
        cwd=ROOT,
        env={
            "PATH": "/usr/bin:/bin",
            "PYTHONPATH": f"{ROOT / 'src'}:{ROOT}",
            "PYTHONDONTWRITEBYTECODE": "1",
        },
        text=True,
        capture_output=True,
        check=False,
        timeout=120,
    )
    assert completed.returncode == 0, completed.stderr[-2000:]


def test_wheel_package_discovery_is_limited_to_src_and_excludes_experiments():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    find = project["tool"]["setuptools"]["packages"]["find"]
    assert find["where"] == ["src"]
    manifest = (ROOT / "MANIFEST.in").read_text(encoding="utf-8")
    assert "recursive-include experiments *.py *.md" in manifest
    assert not (ROOT / "src" / "experiments").exists()
    assert not (SRC / "__pycache__" / "selected_model_trial.py").exists()


def _load_pinned_shadow_audit(monkeypatch: pytest.MonkeyPatch):
    """Import the pinned pre-consolidation shadow_audit with production deps."""
    import pr_review_harness.claim_assessment as claim_assessment
    import pr_review_harness.providers as providers
    from experiments.harness import shadow_preflight

    package_name = "pinned_historical_shadow"
    package = types.ModuleType(package_name)
    package.__path__ = [str(PINNED_RELOCATED)]
    monkeypatch.setitem(sys.modules, package_name, package)
    monkeypatch.setitem(sys.modules, f"{package_name}.claim_assessment", claim_assessment)
    monkeypatch.setitem(sys.modules, f"{package_name}.providers", providers)
    monkeypatch.setitem(sys.modules, f"{package_name}.shadow_preflight", shadow_preflight)
    spec = importlib.util.spec_from_file_location(
        f"{package_name}.shadow_audit", PINNED_RELOCATED / "shadow_audit.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, spec.name, module)
    spec.loader.exec_module(module)
    return module


def test_extracted_source_audit_serializer_matches_the_archived_implementation(monkeypatch: pytest.MonkeyPatch):
    from pr_review_harness import source_audit

    archived = _load_pinned_shadow_audit(monkeypatch)

    class _StubProvider:
        def _serialize_request_body(self, system, user, schema, limits):
            return json.dumps(
                {"system": system, "user": user, "schema": schema, "limits": limits}, sort_keys=True
            ).encode("utf-8")

    provider = _StubProvider()
    arguments = {
        "case_id": "PR-0",
        "snapshot": {
            "snapshot_id": "snapshot",
            "snapshot_hash": "a" * 64,
            "base_sha": "b" * 40,
            "head_sha": "c" * 40,
            "profile_hash": "d" * 64,
        },
        "profile_id": "profile",
        "task": {"task_id": "task-1", "task_kind": "SPECIALIST_FINDINGS", "question": "q"},
        "evidence": [{"evidence_id": "e1", "excerpt": "source text"}],
        "limits": {"max_input_bytes_per_task": 4096, "max_output_bytes_per_task": 4096},
    }
    assert archived.serialize_source_audit_request(provider, **arguments) == (
        source_audit.serialize_source_audit_request(provider, **arguments)
    )
    assert archived.serialize_canonical_source_audit_request(provider, **arguments) == (
        source_audit.serialize_canonical_source_audit_request(provider, **arguments)
    )
    assert archived.SOURCE_AUDIT_SERIALIZER_CANONICAL == source_audit.SOURCE_AUDIT_SERIALIZER_CANONICAL
    assert archived.SOURCE_AUDIT_SERIALIZER_LEGACY == source_audit.SOURCE_AUDIT_SERIALIZER_LEGACY
