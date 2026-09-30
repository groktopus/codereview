"""Load the archived PR-170 provider prompt for historical fake-provider tests."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pr_review_harness.providers as providers

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "providers-pr170-base.py"
MODULE_NAME = "pr_review_harness._historical_pr170_providers"


def install_historical_review_parts(monkeypatch) -> ModuleType:
    """Restore only the old prompt builder for this test's fake provider.

    The engine, schemas, serializer, and all other runtime modules remain the
    current checkout; this does not recreate or prove historical model behavior.
    """
    spec = importlib.util.spec_from_file_location(MODULE_NAME, FIXTURE)
    if spec is None or spec.loader is None:
        raise AssertionError("historical provider fixture cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, MODULE_NAME, module)
    spec.loader.exec_module(module)
    monkeypatch.setattr(providers.OpenAIProvider, "_review_parts", module.OpenAIProvider._review_parts)
    return module
