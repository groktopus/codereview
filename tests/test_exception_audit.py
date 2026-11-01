"""SE-3 regression tests: no pickle proxy, canonical binding, typed defects."""

from __future__ import annotations

import inspect

import pytest

import pr_review_harness.engine as engine_module
import pr_review_harness.github as github_module
from pr_review_harness.budget import BudgetExhausted, IsolatedCallError
from pr_review_harness.errors import (
    BoundaryRuntimeError,
    BoundaryValueError,
    classify_exception,
    defect_name,
    is_defect,
)
from pr_review_harness.providers import ProviderError


class _ConfiguredAssessor:
    identity = {"contract_version": "claim-assessment.2", "provider": "offline-fake"}
    configuration = {"threshold": 0.5, "dimensions": ["observation_support"], "nested": {"enabled": True}}

    def prepare(self, *args, **kwargs):
        return None

    def estimate_prepared(self, prepared, limits):
        return {}

    def assess_prepared(self, prepared, limits):
        return {}


class _OversizedConfigurationAssessor(_ConfiguredAssessor):
    configuration = {"padding": "x" * 70_000}


class _NonCanonicalConfigurationAssessor(_ConfiguredAssessor):
    configuration = {"bad": object()}


def test_engine_source_contains_no_pickle():
    source = inspect.getsource(engine_module).lower()
    assert "pickle" not in source


def test_assessor_binding_is_deterministic_and_uses_declared_configuration():
    first = engine_module._claim_assessor_binding(_ConfiguredAssessor(), "claim-assessment.2")
    second = engine_module._claim_assessor_binding(_ConfiguredAssessor(), "claim-assessment.2")

    assert first == second
    assert first[0] == engine_module._hash(_ConfiguredAssessor.identity)
    assert first[1] == "claim-assessment.2"
    assert len(first[2]) == 64


def test_assessor_binding_keeps_legacy_non_serializable_message():
    with pytest.raises(ValueError, match="claim assessor identity or adapter is not serializable"):
        engine_module._claim_assessor_binding(_NonCanonicalConfigurationAssessor(), "claim-assessment.2")


def test_assessor_binding_bounds_declared_configuration():
    with pytest.raises(ValueError, match="claim assessor configuration exceeds its finite preflight bound"):
        engine_module._claim_assessor_binding(_OversizedConfigurationAssessor(), "claim-assessment.2")


def test_taxonomy_distinguishes_expected_boundaries_from_defects():
    assert classify_exception(BoundaryValueError("invalid")) == "boundary"
    assert classify_exception(BoundaryRuntimeError("unavailable")) == "boundary"
    assert classify_exception(ProviderError("transport_failed")) == "boundary"
    assert classify_exception(BudgetExhausted("DEADLINE_EXHAUSTED")) == "boundary"
    assert classify_exception(TypeError("bug")) == "defect"
    assert classify_exception(RuntimeError("unclassified")) == "unexpected"
    assert is_defect(TypeError("bug")) is True
    assert is_defect(IsolatedCallError("TypeError", "WRAPPER")) is True
    assert is_defect(IsolatedCallError("ProviderError", "transport_failed")) is False
    assert defect_name(IsolatedCallError("AttributeError", "WRAPPER")) == "AttributeError"
    assert defect_name(ProviderError("transport_failed")) is None


def test_github_freshness_propagates_a_harness_defect(monkeypatch):
    class DefectiveAdapter:
        def __init__(self, *args, **kwargs):
            pass

        def pull_request(self, repository, number):
            raise TypeError("freshness adapter defect")

    monkeypatch.setattr(github_module, "GitHubPRAdapter", DefectiveAdapter)
    check = github_module.GitHubFreshnessCheck("owner/repo", 7, "b" * 40)
    with pytest.raises(TypeError, match="freshness adapter defect"):
        check()
