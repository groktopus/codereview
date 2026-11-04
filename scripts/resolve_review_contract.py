#!/usr/bin/env python3
"""Resolve one closed, caller-selected hosted review contract.

The authoritative contract/profile/limits matrix comes from the packaged
machine-readable registry (``contract_registry.json``).  This module only turns
one registry entry into a digest-pinned binding; it never relaxes the registry.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
_SOURCE_PACKAGE = ROOT / "src"
if _SOURCE_PACKAGE.is_dir() and str(_SOURCE_PACKAGE) not in sys.path:
    sys.path.insert(0, str(_SOURCE_PACKAGE))

try:
    from .resolve_target_profile import ProfileBindingError, _parse_json, _read_regular_file, resolve_target_profile
except ImportError:  # Direct script execution places scripts/, not the repository root, on sys.path.
    from resolve_target_profile import ProfileBindingError, _parse_json, _read_regular_file, resolve_target_profile

from pr_review_harness.contract_registry import (  # noqa: E402
    ContractRegistryError,
    default_contract_for_target,
    load_registry,
    supported_combination,
    validate_contract_checks,
)

TARGET = "magnus919/SlopSearX"
CODE_REVIEW_TARGET = "groktopus/codereview"
MAX_JSON_BYTES = 256_000
_REGISTRY = load_registry(ROOT / "src/pr_review_harness/contract_registry.json")
SUPPORTED_CONTRACT = supported_combination(_REGISTRY)["review_contract"]
SUPPORTED_TARGET = supported_combination(_REGISTRY)["target_repository"]
_ENTRIES: dict[str, dict[str, dict[str, Any]]] = {}
for _entry in _REGISTRY["contracts"]:
    _ENTRIES.setdefault(_entry["kind"], {})[_entry["name"]] = _entry


def _selected(entry: dict[str, Any]) -> dict[str, Any]:
    combination = entry["combination"]
    profile = _ENTRIES["review-profile"][combination["profile"]]
    limits = _ENTRIES["review-limits"][combination["limits"]]
    return {
        "profile_path": profile["source_path"],
        "limits_path": limits["source_path"],
        "profile_version": profile["version"],
        "profile_sha256": profile["source_sha256"],
        "limits_sha256": limits["source_sha256"],
        "max_claim_assessments": combination["max_claim_assessments"],
    }


_REGISTRY_ENTRIES = _ENTRIES["review-contract"]
CONTRACTS = {
    name: _selected(entry)
    for name, entry in _REGISTRY_ENTRIES.items()
    if entry["combination"]["target_repository"] == TARGET
}
# Keep this Slop-only mapping stable for the separate central pilot admission
# consumer. New target contracts are resolved through the target-scoped map.
CODE_REVIEW_CONTRACTS = {
    name: _selected(entry)
    for name, entry in _REGISTRY_ENTRIES.items()
    if entry["combination"]["target_repository"] == CODE_REVIEW_TARGET
}
ALL_CONTRACTS = {**CONTRACTS, **CODE_REVIEW_CONTRACTS}
TARGET_CONTRACTS = {
    repository: frozenset(target["review_contracts"]) for repository, target in _REGISTRY["targets"].items()
}
CONTRACT_STATUS = {name: entry["status"] for name, entry in _REGISTRY_ENTRIES.items()}
CONTRACT_REPLACED_BY = {name: entry["replaced_by"] for name, entry in _REGISTRY_ENTRIES.items()}
CONTRACT_DEPRECATION = {
    name: entry["deprecation"] for name, entry in _REGISTRY_ENTRIES.items() if entry["status"] == "deprecated"
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


def _select_contract(target_repository: str, review_contract: str) -> str:
    if review_contract == "supported":
        if target_repository != SUPPORTED_TARGET:
            raise ProfileBindingError("review_contract_target_mismatch")
        return SUPPORTED_CONTRACT
    if review_contract in {"", "default"}:
        default = default_contract_for_target(_REGISTRY, target_repository)
        if default is None:
            raise ProfileBindingError("target_repository_unsupported")
        return default
    return review_contract


def resolve_review_contract(
    target_repository: str,
    review_contract: str,
    *,
    root: Path = ROOT,
) -> dict[str, Any]:
    """Resolve only a fixed profile/limit pair allowed for this target."""
    review_contract = _select_contract(target_repository, review_contract)
    if review_contract not in ALL_CONTRACTS:
        raise ProfileBindingError("review_contract_unsupported")
    if target_repository not in TARGET_CONTRACTS:
        raise ProfileBindingError("target_repository_unsupported")
    if review_contract not in TARGET_CONTRACTS[target_repository]:
        raise ProfileBindingError("review_contract_target_mismatch")
    status = CONTRACT_STATUS[review_contract]
    if status == "archived":
        raise ProfileBindingError("review_contract_archived")
    registry = CONTRACTS if target_repository == TARGET else CODE_REVIEW_CONTRACTS
    selected = registry[review_contract]
    entry = _REGISTRY_ENTRIES[review_contract]

    # Both repository v1 mappings are verified by the target-profile resolver.
    # Slop v16/v17 remain pinned by their fixed registry entries and record the
    # map digest without changing the historical binding behavior.
    if (target_repository == TARGET and review_contract == "legacy-v14") or target_repository == CODE_REVIEW_TARGET:
        profile_binding = resolve_target_profile(target_repository, root=root)
        if (
            profile_binding["profile_path"] != selected["profile_path"]
            or profile_binding["profile_version"] != selected["profile_version"]
        ):
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

    try:
        validate_contract_checks(profile, limits, entry)
    except ContractRegistryError:
        raise ProfileBindingError(entry["mismatch_error"]) from None

    binding: dict[str, Any] = {
        **profile_binding,
        "review_contract": review_contract,
        "contract_status": status,
        "contract_replaced_by": CONTRACT_REPLACED_BY.get(review_contract),
        "profile_path": selected["profile_path"],
        "profile_version": selected["profile_version"],
        "profile_sha256": profile_digest,
        "limits_path": selected["limits_path"],
        "limits_sha256": limits_digest,
        "max_claim_assessments": str(selected["max_claim_assessments"]),
    }
    if review_contract in CONTRACT_DEPRECATION:
        binding["contract_deprecation"] = CONTRACT_DEPRECATION[review_contract]
    return binding


def _write_outputs(path: Path, binding: dict[str, Any]) -> None:
    try:
        with path.open("a", encoding="utf-8") as stream:
            for key in (
                "review_contract",
                "contract_status",
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
        print(
            json.dumps({"status": "REJECTED", "error": exc.code}, sort_keys=True, separators=(",", ":")),
            file=sys.stderr,
        )
        return 2
    print(json.dumps({"status": "RESOLVED", **binding}, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
