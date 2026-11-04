"""Import-surface and internal-module policy checks for RS-4.

The machine-readable manifest (``docs/public-surface.json``) is the source of
truth for which installed modules exist and which names are documented.
``docs/PUBLIC-API.md`` is the human contract. These tests keep both honest and
prove that importing the documented surface performs no work and pulls in no
experiment packages.
"""

from __future__ import annotations

import importlib
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "pr_review_harness"
MANIFEST = ROOT / "docs" / "public-surface.json"
PUBLIC_API = ROOT / "docs" / "PUBLIC-API.md"
SUPPORT_MATRIX = ROOT / "docs" / "SUPPORT-MATRIX.md"


def _manifest() -> dict[str, object]:
    return json.loads(MANIFEST.read_text(encoding="utf-8"))


def _module_name(entry: str) -> str:
    return entry.split(":", 1)[0]


def _function_name(entry: str) -> str:
    return entry.split(":", 1)[1]


def test_all_production_modules_are_documented_and_importable():
    manifest = _manifest()
    modules = manifest["production_modules"]
    assert isinstance(modules, list)
    assert len(modules) == len(set(modules)), "duplicate production module entry"
    assert set(modules) == {path.name for path in SRC.glob("*.py")}
    for name in modules:
        if name == "__main__.py":
            # Importing __main__ executes the CLI by design; the subprocess test
            # below covers that entry point instead.
            continue
        module = importlib.import_module(f"pr_review_harness.{name.removesuffix('.py')}")
        assert module.__name__.endswith(name.removesuffix(".py"))


def test_documented_stable_names_are_importable_and_described():
    manifest = _manifest()
    documented = {
        f"{manifest['review_orchestrator']['module']}:{manifest['review_orchestrator']['function']}",
        *manifest["internal_stage_functions"],
        *(f"{entry['module']}:{entry['function']}" for entry in manifest["guarded_effect_entrypoints"]),
    }
    text = PUBLIC_API.read_text(encoding="utf-8")
    for entry in sorted(documented):
        module_name, function_name = _module_name(entry), _function_name(entry)
        module = importlib.import_module(module_name)
        assert callable(getattr(module, function_name)), entry
        assert function_name in text, f"docs/PUBLIC-API.md does not document {function_name}"
        assert module_name in text, f"docs/PUBLIC-API.md does not document {module_name}"
    assert "not part of the installed package" in text


def test_public_api_documents_the_internal_module_policy_and_zero_dependencies():
    text = PUBLIC_API.read_text(encoding="utf-8")
    assert "internal" in text.lower()
    assert "may be renamed, split, merged, or removed" in text
    assert "No runtime dependencies are declared" in text
    assert "SUPPORT-MATRIX.md" in text
    assert "tests/test_public_surface.py" in text


def test_no_documented_module_is_private_by_name():
    manifest = _manifest()
    for name in manifest["production_modules"]:
        if name in {"__init__.py", "__main__.py"}:
            continue
        assert not name.startswith("_"), "private modules belong outside the documented production surface"


def test_support_matrix_and_public_api_are_indexed_and_linked():
    index = (ROOT / "docs" / "README.md").read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    for document in ("PUBLIC-API.md", "SUPPORT-MATRIX.md"):
        assert f"[{document.removesuffix('.md')}" in index or document in index
        assert document in readme or f"docs/{document}" in readme
    matrix = SUPPORT_MATRIX.read_text(encoding="utf-8")
    assert "PUBLIC-API.md" in matrix
    assert "3.11" in matrix and "3.14" in matrix
    assert "requirements-dev.lock" in matrix
    assert "DEPENDENCY_GRAPH_ENABLED" in matrix


def test_documented_surface_imports_without_loading_experiments(tmp_path: Path):
    manifest = _manifest()
    probes = [
        "import pr_review_harness"
        if module == "__init__.py"
        else f"import pr_review_harness.{module.removesuffix('.py')}"
        for module in manifest["production_modules"]
        if module != "__main__.py"
    ]
    probe = (
        "import pr_review_harness\n"
        "assert pr_review_harness.__version__\n"
        "public = [name for name in dir(pr_review_harness) if not name.startswith('_')]\n"
        "assert public == [], public\n" + "\n".join(probes) + "\nimport sys\n"
        "loaded = sorted(name for name in sys.modules if name == 'experiments' or name.startswith('experiments.'))\n"
        "assert not loaded, loaded\n"
        "print('OK')\n"
    )
    env = {
        "PATH": os.defpath,
        "PYTHONPATH": f"{ROOT / 'src'}:{ROOT}",
        "PYTHONDONTWRITEBYTECODE": "1",
        "HOME": str(tmp_path),
    }
    completed = subprocess.run(
        [sys.executable, "-c", probe],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
        timeout=180,
    )
    assert completed.returncode == 0, completed.stderr[-4000:]
    assert completed.stdout.strip() == "OK"


def test_module_entry_point_help_runs_without_repository_configuration(tmp_path: Path):
    env = {
        "PATH": os.defpath,
        "PYTHONPATH": str(ROOT / "src"),
        "PYTHONDONTWRITEBYTECODE": "1",
        "HOME": str(tmp_path),
    }
    completed = subprocess.run(
        [sys.executable, "-m", "pr_review_harness", "--help"],
        cwd=tmp_path,
        env=env,
        text=True,
        capture_output=True,
        check=False,
        timeout=120,
    )
    assert completed.returncode == 0, completed.stderr[-4000:]
    assert "usage:" in completed.stdout.lower()
