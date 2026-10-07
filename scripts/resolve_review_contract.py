#!/usr/bin/env python3
"""Resolve one closed, caller-selected hosted review contract."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any

try:
    from .resolve_target_profile import ProfileBindingError, _parse_json, _read_regular_file, resolve_target_profile
except ImportError:  # Direct script execution places scripts/, not the repository root, on sys.path.
    from resolve_target_profile import ProfileBindingError, _parse_json, _read_regular_file, resolve_target_profile

ROOT = Path(__file__).resolve().parents[1]
TARGET = "magnus919/SlopSearX"
MAX_JSON_BYTES = 256_000
CONTRACTS = {
    "legacy-v14": {
        "profile_path": "profiles/slopsearx-v14-jev-reconciliation-candidate.json",
        "limits_path": "profiles/ordinary-review-limits-v2.json",
        "profile_version": "slopsearx-production-v14-jev-reconciliation-candidate",
        "profile_sha256": "5e83bc43c615f717df0d3d29722de08dd5990c84c8e69d1705c94f3918d49692",
        "limits_sha256": "39abcf19666c9f322364961577f08f8cff8a3c539e68d894693b6cb0fb5a75e9",
        "max_claim_assessments": 1,
    },
    "bounded-production-v16": {
        "profile_path": "profiles/slopsearx-v16-bounded-production-candidate.json",
        "limits_path": "profiles/ordinary-review-limits-v3.json",
        "profile_version": "slopsearx-production-v16-bounded-production-candidate",
        "profile_sha256": "699f93fd7bc78d310de2455cad7402a1c3c8cf5ad61c3d4cbb77bb38da1189ed",
        "limits_sha256": "ec191dcde1672b4f86aac24ee6412752cd9a08871d1aba1b332d11341b6fd2a6",
        "max_claim_assessments": 4,
    },
}
V16_RISK_RULE = {
    "lenses": ["security", "correctness", "tests"],
    "min_mode": "FOCUSED",
    "patterns": ["engines/*.py"],
    "reason": "Network-client adapters cross credential, upstream-input, and remote-service trust boundaries and need explicit security, correctness, and test review.",
}
V16_LIMITS = {
    "schema_version": "1.0",
    "deadline_seconds": 300,
    "max_concurrent_scopes": 3,
    "max_provider_calls": 32,
    "max_retries_per_task": 0,
    "max_context_bytes": 2_500_000,
    "max_input_bytes_per_task": 96_000,
    "max_output_bytes_per_task": 16_000,
    "max_output_bytes": 512_000,
    "max_output_tokens": 1800,
    "max_context_retrievals": 8,
    "max_followup_tasks": 8,
    "max_snapshot_context_bytes": 600_000,
}


def _document(path: Path, code: str) -> tuple[bytes, dict[str, Any]]:
    raw = _read_regular_file(path, MAX_JSON_BYTES, code)
    return raw, _parse_json(raw, code)


def _write_binding(path: Path, binding: dict[str, Any]) -> None:
    data = (json.dumps(binding, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0), 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except OSError:
        raise ProfileBindingError("review_contract_binding_write_failed") from None


def resolve_review_contract(
    target_repository: str,
    review_contract: str,
    *,
    root: Path = ROOT,
) -> dict[str, Any]:
    """Resolve only the two repository-owned profile and limit pairs."""
    selected = CONTRACTS.get(review_contract)
    if selected is None:
        raise ProfileBindingError("review_contract_unsupported")
    if target_repository != TARGET:
        raise ProfileBindingError("target_repository_unsupported")

    # Preserve the existing target-map digest gate for the legacy contract.
    if review_contract == "legacy-v14":
        profile_binding = resolve_target_profile(target_repository, root=root)
        if profile_binding["profile_path"] != selected["profile_path"]:
            raise ProfileBindingError("review_contract_profile_mismatch")
    else:
        map_raw = _read_regular_file(root / "profiles/targets.json", 64_000, "profile_map_unavailable")
        profile_binding = {
            "target_repository": target_repository,
            "profile_map_sha256": hashlib.sha256(map_raw).hexdigest(),
        }

    profile_raw, profile = _document(root / selected["profile_path"], "profile_invalid")
    limits_raw, limits = _document(root / selected["limits_path"], "limits_invalid")
    if profile.get("repository") != target_repository or profile.get("version") != selected["profile_version"]:
        raise ProfileBindingError("review_contract_profile_mismatch")
    profile_digest = hashlib.sha256(profile_raw).hexdigest()
    limits_digest = hashlib.sha256(limits_raw).hexdigest()
    if profile_digest != selected["profile_sha256"] or limits_digest != selected["limits_sha256"]:
        raise ProfileBindingError("review_contract_digest_mismatch")
    claim_policy = profile.get("claim_reconciliation")
    expected_claim_policy = {
        "enabled": True,
        "required": True,
        "max_assessments": selected["max_claim_assessments"],
        "version": "claim-reconciliation.v1",
    }
    if claim_policy != expected_claim_policy:
        raise ProfileBindingError("review_contract_claim_policy_mismatch")

    if review_contract == "legacy-v14":
        if limits != {
            "schema_version": "1.0",
            "max_context_bytes": 600_000,
            "max_input_bytes_per_task": 96_000,
        }:
            raise ProfileBindingError("review_contract_limits_mismatch")
    else:
        selector = profile.get("context_selection")
        retrieval = profile.get("retrieval_revisions")
        if (
            profile.get("profile_status") != "bounded_production_capacity_candidate_not_quality_validated"
            or not isinstance(selector, dict)
            or selector.get("version") != "context-selection.v3"
            or selector.get("max_total_context_bytes") != 128_000
            or retrieval != {"implementation": "head", "test": "head"}
            or V16_RISK_RULE not in profile.get("risk_rules", [])
            or limits != V16_LIMITS
        ):
            raise ProfileBindingError("review_contract_v16_contract_mismatch")

    binding: dict[str, Any] = {
        **profile_binding,
        "review_contract": review_contract,
        "profile_path": selected["profile_path"],
        "profile_version": selected["profile_version"],
        "profile_sha256": profile_digest,
        "limits_path": selected["limits_path"],
        "limits_sha256": limits_digest,
        "max_claim_assessments": str(selected["max_claim_assessments"]),
    }
    return binding


def _write_outputs(path: Path, binding: dict[str, Any]) -> None:
    try:
        with path.open("a", encoding="utf-8") as stream:
            for key in (
                "review_contract",
                "profile_path",
                "profile_version",
                "profile_sha256",
                "profile_map_sha256",
                "limits_path",
                "limits_sha256",
                "max_claim_assessments",
            ):
                stream.write(f"{key}={binding.get(key, '')}\n")
    except OSError:
        raise ProfileBindingError("github_output_unavailable") from None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--github-output", type=Path, required=True)
    parser.add_argument("--binding-artifact", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        binding = resolve_review_contract(
            os.environ.get("TARGET_REPOSITORY", ""),
            os.environ.get("REVIEW_CONTRACT", ""),
        )
        _write_binding(args.binding_artifact, binding)
        _write_outputs(args.github_output, binding)
    except ProfileBindingError as exc:
        print(json.dumps({"status": "REJECTED", "error": exc.code}, sort_keys=True, separators=(",", ":")), file=sys.stderr)
        return 2
    print(json.dumps({"status": "RESOLVED", **binding}, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
