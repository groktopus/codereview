"""Picklable offline providers for waiver tests.

Multiprocessing spawn re-imports this module in the child. Keep the imports
limited to test support that does not import ``test_waiver`` or any test-only
aggregate module.
"""

from __future__ import annotations

from test_engine import EmptyProvider, FindingProvider


class PartialProvider(EmptyProvider):
    def review(self, task, evidence, limits):
        result = super().review(task, evidence, limits)
        for note in result["payload"]["coverage_notes"]:
            note["state"] = "PARTIAL"
            note["reason_code"] = "STATIC_TEST_CONTEXT_INSUFFICIENT"
        return result


class PartialFindingProvider(FindingProvider):
    def review(self, task, evidence, limits):
        result = super().review(task, evidence, limits)
        result["coverage_notes"][0]["state"] = "PARTIAL"
        result["coverage_notes"][0]["reason_code"] = "STATIC_TEST_CONTEXT_INSUFFICIENT"
        return result


class QuarantinedCoverageProvider(EmptyProvider):
    """Produce a required-output execution failure without a provider call failure."""

    def review(self, task, evidence, limits):
        result = super().review(task, evidence, limits)
        result["payload"]["coverage_notes"] = []
        result["payload"]["quarantined_items"] = [
            {
                "kind": "coverage_notes",
                "index": 0,
                "reason_code": "invalid_coverage_note_state",
                "item_hash": "a" * 64,
            }
        ]
        return result
