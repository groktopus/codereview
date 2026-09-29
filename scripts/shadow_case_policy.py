"""Closed case policy for the private shadow writer and audit lane."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

CASE_POLICY: dict[str, dict[str, Any]] = {
    "PR-457": {
        "plan_relative_path": "experiments/model-only-shadow-live-pr457-plan-v2.json",
        "plan_sha256": "3207c554d4271a746d248778a65e663bf84e0728fb21e2e30834c27818e1dd84",
        "writer_calls": 6,
        "snapshot_id": "snap-24293f430e4f8006a52bac18",
        "snapshot_sha256": "14bd673c2c77ffc59875c957c095b32e262d534fb581f3ec38aaf94898a19fea",
        "profile_path": "docs/real-case-trial-v1/profiles/PR-457.json",
        "profile_sha256": "c3b5f82b0d2d38e3173f836a06af1b39afd8b47b81609caab5bae0e842435918",
    },
    "PR-464": {
        "plan_relative_path": "experiments/model-only-shadow-live-pr464-plan-v2.json",
        "plan_sha256": "250a6df08587685b5c93d5216d5cf385bf5664a46db9b0ba650a203e4e23300e",
        "writer_calls": 10,
        "snapshot_id": "snap-e20deb18f2ac6cb39c6ebafd",
        "snapshot_sha256": "e45e9327fcb1ad37d6c37155fb40499f3179fc8dfd73d16a8d261f3a18691868",
        "profile_path": "docs/real-case-trial-v1/profiles/PR-464.json",
        "profile_sha256": "66e65ad3eec3e9311ff9df820ec4eba85baea236a1d56256781475455c6e0ea8",
    },
}


def policy_for_case(case_id: str) -> dict[str, Any]:
    try:
        return CASE_POLICY[case_id]
    except (KeyError, TypeError):
        raise ValueError("shadow_case_invalid") from None


def case_for_plan_path(path: Path, root: Path) -> tuple[str, dict[str, Any]]:
    absolute = path.absolute()
    for case_id, policy in CASE_POLICY.items():
        if absolute == (root / policy["plan_relative_path"]).absolute():
            return case_id, policy
    raise ValueError("shadow_plan_path_invalid")


def validate_plan_binding(plan: dict[str, Any], plan_bytes: bytes) -> tuple[str, dict[str, Any]]:
    case = plan.get("case") if isinstance(plan, dict) else None
    case_id = case.get("case_id") if isinstance(case, dict) else None
    policy = policy_for_case(case_id)
    budget = plan.get("budget")
    requests = plan.get("writer_requests")
    if (
        hashlib.sha256(plan_bytes).hexdigest() != policy["plan_sha256"]
        or plan.get("schema") != "model-only-shadow-live-writer-plan.v1"
        or case.get("snapshot_id") != policy["snapshot_id"]
        or case.get("snapshot_sha256") != policy["snapshot_sha256"]
        or case.get("profile_file_sha256") != policy["profile_sha256"]
        or not isinstance(budget, dict)
        or budget.get("writer_exact_call_count") != policy["writer_calls"]
        or budget.get("writer_max_provider_calls") != 10
        or not isinstance(requests, list)
        or len(requests) != policy["writer_calls"]
    ):
        raise ValueError("shadow_plan_binding_invalid")
    return case_id, policy
