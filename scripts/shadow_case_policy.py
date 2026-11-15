"""Closed case policy for the private shadow writer and audit lane."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import TypedDict

from pr_review_harness import compatibility_pins


class CasePolicy(TypedDict):
    plan_relative_path: str
    plan_sha256: str
    plan_schema: str
    audit_input_limit: int
    writer_calls: int
    snapshot_id: str
    snapshot_sha256: str
    profile_path: str
    profile_sha256: str
    evidence_index_sha256: str
    historical_checks_sha256: str
    check_evidence_sha256: str


CASE_PLAN_PATHS = {
    "PR-457": "experiments/model-only-shadow-live-pr457-plan-v3.json",
    "PR-464": "experiments/model-only-shadow-live-pr464-plan-v3.json",
}


def case_policies() -> dict[str, CasePolicy]:
    """Build fresh case mappings from the canonical pin resource on demand."""
    try:
        manifest = compatibility_pins.load_manifest()
        values = manifest["value_pins"]
        return {
            "PR-457": {
                "plan_relative_path": CASE_PLAN_PATHS["PR-457"],
                "plan_sha256": values["runtime.model_only_shadow_live_pr457.plan_sha256"]["value"],
                "plan_schema": "model-only-shadow-live-writer-plan.v2",
                "audit_input_limit": 120_000,
                "writer_calls": 6,
                "snapshot_id": "snap-24293f430e4f8006a52bac18",
                "snapshot_sha256": values["runtime.current_source_pr457.snapshot_sha256"]["value"],
                "profile_path": "docs/real-case-trial-v1/profiles/PR-457.json",
                "profile_sha256": values["runtime.current_source_pr457.profile_file_sha256"]["value"],
                "evidence_index_sha256": values["runtime.current_source_pr457.evidence_index_sha256"]["value"],
                "historical_checks_sha256": values["runtime.current_source_pr457.historical_checks_sha256"]["value"],
                "check_evidence_sha256": values["runtime.current_source_pr457.check_evidence_sha256"]["value"],
            },
            "PR-464": {
                "plan_relative_path": CASE_PLAN_PATHS["PR-464"],
                "plan_sha256": values["runtime.model_only_shadow_live_pr464.plan_sha256"]["value"],
                "plan_schema": "model-only-shadow-live-writer-plan.v2",
                "audit_input_limit": 96_000,
                "writer_calls": 10,
                "snapshot_id": "snap-e20deb18f2ac6cb39c6ebafd",
                "snapshot_sha256": values["historical.pr464.capture_snapshot_sha256"]["value"],
                "profile_path": "docs/real-case-trial-v1/profiles/PR-464.json",
                "profile_sha256": values["runtime.model_only_shadow_live_pr464.profile_file_sha256"]["value"],
                "evidence_index_sha256": values["runtime.model_only_shadow_live_pr464.evidence_index_sha256"]["value"],
                "historical_checks_sha256": values["runtime.model_only_shadow_live_pr464.historical_checks_sha256"][
                    "value"
                ],
                "check_evidence_sha256": values["runtime.model_only_shadow_live_pr464.check_evidence_sha256"]["value"],
            },
        }
    except (compatibility_pins.CompatibilityPinError, KeyError, TypeError):
        raise ValueError("shadow_policy_unavailable") from None


def historical_model_tree_sha256() -> str:
    """Return the existing immutable PR-170 model-tree identity."""
    try:
        file_pins = compatibility_pins.load_manifest()["file_pins"]
        digest = file_pins["pr170-tree-model"]
        if not isinstance(digest, str):
            raise TypeError
        return digest
    except (compatibility_pins.CompatibilityPinError, KeyError, TypeError):
        raise ValueError("shadow_policy_unavailable") from None


def policy_for_case(case_id: str) -> CasePolicy:
    try:
        return case_policies()[case_id]
    except (KeyError, TypeError):
        raise ValueError("shadow_case_invalid") from None


def case_for_plan_path(path: Path, root: Path) -> tuple[str, CasePolicy]:
    absolute = path.absolute()
    for case_id, policy in case_policies().items():
        if absolute == (root / policy["plan_relative_path"]).absolute():
            return case_id, policy
    raise ValueError("shadow_plan_path_invalid")


def known_case_for_plan_path(path: Path, root: Path) -> str:
    """Identify a fixed plan path without loading canonical pin data."""
    absolute = path.absolute()
    for case_id, relative_path in CASE_PLAN_PATHS.items():
        if absolute == (root / relative_path).absolute():
            return case_id
    raise ValueError("shadow_plan_path_invalid")


def validate_plan_binding(plan: dict[str, object], plan_bytes: bytes) -> tuple[str, CasePolicy]:
    case = plan.get("case") if isinstance(plan, dict) else None
    case_id = case.get("case_id") if isinstance(case, dict) else None
    policy = policy_for_case(case_id)
    budget = plan.get("budget")
    requests = plan.get("writer_requests")
    if (
        hashlib.sha256(plan_bytes).hexdigest() != policy["plan_sha256"]
        or plan.get("schema") != policy["plan_schema"]
        or case.get("snapshot_id") != policy["snapshot_id"]
        or case.get("snapshot_sha256") != policy["snapshot_sha256"]
        or case.get("profile_file_sha256") != policy["profile_sha256"]
        or not isinstance(budget, dict)
        or budget.get("writer_exact_call_count") != policy["writer_calls"]
        or budget.get("writer_max_provider_calls") != 10
        or budget.get("audit_max_input_bytes_per_call") != policy["audit_input_limit"]
        or not isinstance(requests, list)
        or len(requests) != policy["writer_calls"]
    ):
        raise ValueError("shadow_plan_binding_invalid")
    return case_id, policy
