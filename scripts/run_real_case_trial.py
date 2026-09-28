#!/usr/bin/env python3
"""Run only the fixed, read-only historical SlopSearX provider trial."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import shutil
import stat
import subprocess
import time
from pathlib import Path
from typing import Any

try:
    from prepare_real_case_batch import _bounded_run, _clean_git_env, git_command
    from provider_config_from_env import ConfigError, configurations_from_environment
except ModuleNotFoundError:
    from scripts.prepare_real_case_batch import _bounded_run, _clean_git_env, git_command
    from scripts.provider_config_from_env import ConfigError, configurations_from_environment

ROOT = Path(__file__).resolve().parents[1]
INPUT_ROOT = ROOT / "docs" / "real-case-trial-v1"
CASES_SHA256 = "702a83e0c1456a8881416b5767eeda1aa9aac711ff51a68aecd0b609593f594b"
RUNTIME_SHA = "ed7aa8b82f8d0c8deee03b6f99d8f4f599529301"
RUNTIME_MODULE_TREE_SHA256 = "e21b1686bc3ccb485e389d6fc04f5aea0b0d4d6425e2809de570945b841258b3"
V2_RUNTIME_SHA = "5873c3f1b297a96c49b78cbcb7be674ab70b3cea"
V2_RUNTIME_MODULE_TREE_SHA256 = "d8bdb53517abb7d85fff59805224f457f296832e7e0074b1485c50691dae1ad4"
V2_WHEEL_SHA256 = "4e3dff00930ed5a430a622eb840151f583710d4a29d200f6bb13765106a94be3"
V2_PREPARATION_MANIFEST_SHA256 = "c83715789fbb1892c6fddcd380d0506bec73f2b75304b1f80e8c310f7c297270"
V2_PREPARATION_VERIFICATION_SHA256 = "86594df8c3dd0a5b2c1c12b1c87fa2b667307065e87bc77a7d0c8c67cedbce82"
V2_PLAN_PATH = ROOT / "docs" / "real-case-trial-v2" / "manifest.json"
V2_PLAN_SHA256 = "b8958c589fc49d7beeb4e3b5530c0c99d385bd40cee8b124cdf395090a0c3322"
CONTEXT_FOLLOWUP_RUNTIME_SHA = "37d9896b229d08a925ddd726eb1bd7e6b5b489a3"
CONTEXT_FOLLOWUP_MODULE_TREE_SHA256 = "eaacdfce96354925414ca8c547c4fd87f0bf5b4b7862bbdfb910870db45afdf1"
CONTEXT_FOLLOWUP_PLAN_PATH = ROOT / "docs" / "real-case-trial-context-followup-v1" / "manifest.json"
CONTEXT_FOLLOWUP_PLAN_SHA256 = "9daf5f1688d21f7a89287d8c813fafb1f9ade67b8776ce31ed6dcbae212427f0"
CONTEXT_FOLLOWUP_SELECTOR = "specialist-input-v2-context-followup-v1"
CONTEXT_FOLLOWUP_TREE_PROOF_SHA256 = "cff87be824d59a8673e9c8b672c0704e1c1da27e441929a48f9e7ba4e6192018"
CONTEXT_FOLLOWUP_PRIMARY_PROOF_SHA256 = "1505b8ac9f8511b1b6f9da4482e771fb1ec4c4b5229ea1c0515f5a23b60d54d1"
CONTEXT_FOLLOWUP_V2_RUNTIME_SHA = "7c89ad17327b8f0ed4fc381bf5c93255fd4e548e"
CONTEXT_FOLLOWUP_V2_MODULE_TREE_SHA256 = "c5b7c4e43aeddfad55bbcfdcb9e07c4a89fd0b6a3a263a31f046c8852dd8838a"
CONTEXT_FOLLOWUP_V2_PLAN_PATH = ROOT / "docs" / "real-case-trial-context-followup-v2" / "manifest.json"
CONTEXT_FOLLOWUP_V2_PLAN_SHA256 = "65faf40b36fd065a6e7b943d8150ac64c9b707c3bf8ba106aca445d385ff40fb"
CONTEXT_FOLLOWUP_V2_SELECTOR = "specialist-input-v2-context-followup-v2"
CONTEXT_FOLLOWUP_V2_MODULE_PROOF_SHA256 = "d8de5be2c34519a9a0661710c5f20d20e8b8825cb5036a555c0b22ee49d1f900"
CONTEXT_FOLLOWUP_V2_PRIMARY_PROOF_SHA256 = "8d4a2c9e3f46a23d2f823c8b0134dabddf57527355a676e93dcd9f5ac0fc7615"
CONTEXT_FOLLOWUP_V2_PREPARE_PROOF_SHA256 = "0ce2b0ffcc1da8135b196598d6eeb4c5c855b2d60917a081a2cf972d556419ed"
CONTEXT_FOLLOWUP_V2_LOCAL_WHEEL_SHA256 = "5f14d8d4ac8e700f9c5cdc6fe8abd37a45e548e8b76d65a400dab8f8b8eba313"
CONTEXT_FOLLOWUP_V2_LOCAL_PREPARE_PROOF_SHA256 = "040e263ca9e761326a11ce3af183aa2cdd510a3ce28f1b99350bd8844c3d8cdc"
CONTEXT_FOLLOWUP_V3_PLAN_PATH = ROOT / "docs" / "real-case-trial-context-followup-v3" / "manifest.json"
CONTEXT_FOLLOWUP_V3_PLAN_SHA256 = "fccc745fade50066d12a2173af987b13d548ac214861f8e99b3a8d3078694857"
CONTEXT_FOLLOWUP_V3_SELECTOR = "specialist-input-v2-context-followup-v3"
INPUT_CONTRACTS = (
    "specialist-input-v1", "specialist-input-v2", CONTEXT_FOLLOWUP_SELECTOR,
    CONTEXT_FOLLOWUP_V2_SELECTOR, CONTEXT_FOLLOWUP_V3_SELECTOR,
)
RUNTIME_MODULE_INVENTORY = (
    "__init__.py",
    "__main__.py",
    "actions_publication.py",
    "actions_runtime.py",
    "artifact_intake.py",
    "budget.py",
    "checks.py",
    "claim_assessment.py",
    "claim_transport.py",
    "claim_triage.py",
    "cli.py",
    "context_selector.py",
    "contracts.py",
    "engine.py",
    "evaluation.py",
    "evidence.py",
    "external_effect_observer.py",
    "github.py",
    "injection_trials.py",
    "planner.py",
    "policy_inventory.py",
    "providers.py",
    "publication_receipts.py",
    "publisher.py",
    "reconcile.py",
    "report.py",
    "selected_model_trial.py",
    "snapshot.py",
)
FROZEN_PLAN_MANIFEST_SHA256 = "820a98512df38a257531b92e5cdc02f314e9f87c6230435ada0fd5d357a41dab"
REPOSITORY_URL = "https://github.com/magnus919/SlopSearX.git"
EXPECTED_LLM_ENDPOINT = "https://inference-api.nousresearch.com/v1"
EXPECTED_LLM_MODEL = "openai/gpt-6-luna"
EXPECTED_JEV_BASE_URL = "https://api.typesafe.ai/v1"
EXPECTED_JEV_ENDPOINT = "https://api.typesafe.ai/v1/systemone"
EXPECTED_JEV_ALIAS = "jev-latest"
SECRET_NAMES = ("LLM_API_KEY", "JEV_API_KEY")
IDENTITY_ENV_NAMES = ("LLM_BASE_URL", "LLM_MODEL", "JEV_BASE_URL", "JEV_MODEL")
TRIAL_ENV_NAMES = IDENTITY_ENV_NAMES + SECRET_NAMES
OUTPUT_CAP = 1_000_000
STDERR_CAP = 128_000
V2_ARTIFACT_SUMMARY_CAP = 128_000
V2_ARTIFACT_MANIFEST_CAP = 4_000_000
CASE_SECONDS = 660
MATRIX_SECONDS = 1980
CASE_CLEANUP_RESERVE_SECONDS = 15
MATRIX_CLEANUP_RESERVE_SECONDS = 30
MAX_OBJECT_COUNT = 200_000
MAX_PACK_KIB = 300_000
PYTHON_XFUNCNAME = r"^[[:space:]]*((async[[:space:]]+)?def[[:space:]].*|class[[:space:]].*)"


class TrialError(ValueError):
    """Stable fail-closed trial error."""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise TrialError("pinned_input_unreadable") from None
    if not isinstance(value, dict):
        raise TrialError("pinned_input_invalid")
    return value


def read_v2_plan() -> dict[str, Any]:
    """Read the compact v2 plan with a strict duplicate-key and size bound."""
    try:
        if V2_PLAN_PATH.is_symlink() or not V2_PLAN_PATH.is_file() or V2_PLAN_PATH.stat().st_size > 128_000:
            raise TrialError("v2_plan_manifest_limit_exceeded")
        raw = V2_PLAN_PATH.read_bytes()

        def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("duplicate_json_key")
                result[key] = value
            return result

        value = json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=unique_object)
    except TrialError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
        raise TrialError("v2_plan_manifest_invalid") from None
    if not isinstance(value, dict):
        raise TrialError("v2_plan_manifest_invalid")
    return value


def read_context_followup_plan() -> dict[str, Any]:
    """Read the separately frozen dynamic-contract experiment plan."""
    try:
        if (
            CONTEXT_FOLLOWUP_PLAN_PATH.is_symlink()
            or not CONTEXT_FOLLOWUP_PLAN_PATH.is_file()
            or CONTEXT_FOLLOWUP_PLAN_PATH.stat().st_size > 128_000
        ):
            raise TrialError("context_followup_plan_manifest_limit_exceeded")
        raw = CONTEXT_FOLLOWUP_PLAN_PATH.read_bytes()
        if sha256(raw) != CONTEXT_FOLLOWUP_PLAN_SHA256:
            raise TrialError("context_followup_plan_manifest_hash_mismatch")

        def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("duplicate_json_key")
                result[key] = value
            return result

        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=unique_object,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("non_finite_json_number")),
        )
    except TrialError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
        raise TrialError("context_followup_plan_manifest_invalid") from None
    if not isinstance(value, dict):
        raise TrialError("context_followup_plan_manifest_invalid")
    return value


def read_context_followup_v2_plan() -> dict[str, Any]:
    """Read the fixed context-followup-v2 plan without permissive JSON parsing."""
    try:
        if (
            CONTEXT_FOLLOWUP_V2_PLAN_PATH.is_symlink()
            or not CONTEXT_FOLLOWUP_V2_PLAN_PATH.is_file()
            or CONTEXT_FOLLOWUP_V2_PLAN_PATH.stat().st_size > 128_000
        ):
            raise TrialError("context_followup_v2_plan_manifest_limit_exceeded")
        raw = CONTEXT_FOLLOWUP_V2_PLAN_PATH.read_bytes()
        if sha256(raw) != CONTEXT_FOLLOWUP_V2_PLAN_SHA256:
            raise TrialError("context_followup_v2_plan_manifest_hash_mismatch")

        def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("duplicate_json_key")
                result[key] = value
            return result

        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=unique_object,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("non_finite_json_number")),
        )
    except TrialError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
        raise TrialError("context_followup_v2_plan_manifest_invalid") from None
    if not isinstance(value, dict):
        raise TrialError("context_followup_v2_plan_manifest_invalid")
    return value


def read_context_followup_v3_plan() -> dict[str, Any]:
    """Read the v3 selector plan with a fixed digest and strict bounded JSON."""
    try:
        if (
            CONTEXT_FOLLOWUP_V3_PLAN_PATH.is_symlink()
            or not CONTEXT_FOLLOWUP_V3_PLAN_PATH.is_file()
            or CONTEXT_FOLLOWUP_V3_PLAN_PATH.stat().st_size > 128_000
        ):
            raise TrialError("context_followup_v3_plan_manifest_limit_exceeded")
        raw = CONTEXT_FOLLOWUP_V3_PLAN_PATH.read_bytes()
        if sha256(raw) != CONTEXT_FOLLOWUP_V3_PLAN_SHA256:
            raise TrialError("context_followup_v3_plan_manifest_hash_mismatch")

        def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("duplicate_json_key")
                result[key] = value
            return result

        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=unique_object,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("non_finite_json_number")),
        )
    except TrialError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
        raise TrialError("context_followup_v3_plan_manifest_invalid") from None
    if not isinstance(value, dict):
        raise TrialError("context_followup_v3_plan_manifest_invalid")
    return value


def read_result(path: Path) -> dict[str, Any]:
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 8_000_000:
            raise TrialError("durable_result_invalid")
        return read_json(path)
    except OSError:
        raise TrialError("durable_result_unavailable") from None


def _safe_relative(value: str) -> bool:
    path = Path(value)
    return bool(value) and not path.is_absolute() and ".." not in path.parts and "\\" not in value


def _load_locked_cases_v1() -> tuple[dict[str, Any], list[dict[str, Any]]]:
    cases_path = INPUT_ROOT / "cases.json"
    raw = cases_path.read_bytes()
    if sha256(raw) != CASES_SHA256:
        raise TrialError("fixed_case_manifest_hash_mismatch")
    document = read_json(cases_path)
    cases = document.get("cases")
    if not isinstance(cases, list) or [case.get("case_id") for case in cases] != ["PR-457", "PR-463", "PR-464"]:
        raise TrialError("fixed_case_set_mismatch")
    for case in cases:
        if not isinstance(case, dict):
            raise TrialError("fixed_case_record_invalid")
        for key, path_key, hash_key in (
            ("profile", "profile_path", "profile_sha256"),
            ("checks", "checks_path", "checks_sha256"),
        ):
            relative = case.get(path_key)
            if not isinstance(relative, str) or not _safe_relative(relative):
                raise TrialError("fixed_case_path_invalid")
            target = INPUT_ROOT / relative
            if target.is_symlink() or not target.is_file() or sha256(target.read_bytes()) != case.get(hash_key):
                raise TrialError(f"fixed_{key}_hash_mismatch")
        if case.get("repository") != "magnus919/SlopSearX":
            raise TrialError("fixed_repository_mismatch")
        if not re.fullmatch(r"[0-9a-f]{40}", str(case.get("base_sha", ""))) or not re.fullmatch(
            r"[0-9a-f]{40}", str(case.get("head_sha", ""))
        ):
            raise TrialError("fixed_revision_invalid")
    return document, cases


def load_locked_cases(input_contract: str = "specialist-input-v1") -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Load one immutable input-contract plan; v1 remains the default."""
    if input_contract == "specialist-input-v1":
        return _load_locked_cases_v1()
    if input_contract == CONTEXT_FOLLOWUP_V3_SELECTOR:
        parent_document, parent_cases = load_locked_cases(CONTEXT_FOLLOWUP_V2_SELECTOR)
        parent_plan = read_context_followup_v2_plan()
        plan = read_context_followup_v3_plan()
        fields = {
            "schema", "status", "experiment_id", "input_contract", "dynamic_followup_contract",
            "dynamic_followup_projection", "response_contract", "runtime_revision", "runtime_module_tree_sha256",
            "runtime_module_file_count", "primary_parent_plan_sha256", "primary_input_parent_plan_sha256",
            "primary_requests_total", "primary_serialized_input_bytes_total", "required_obligations_total",
            "max_claim_assessments_per_case", "max_retries_per_task", "limits", "selectors", "cases",
            "interpretation", "projection_limitations",
        }
        if set(plan) != fields:
            raise TrialError("context_followup_v3_plan_manifest_shape_invalid")
        if (
            plan.get("schema") != "historical-real-case-context-followup-input-plan.v3"
            or plan.get("status") != "FROZEN_CANDIDATE_PRIMARY_IDENTITY_PROVIDER_FREE"
            or plan.get("experiment_id") != "historical-context-followup-v3"
            or plan.get("input_contract") != "specialist-input.v2"
            or plan.get("dynamic_followup_contract") != "context-followup.v1"
            or plan.get("dynamic_followup_projection") != "context-followup-observation.v3"
            or plan.get("response_contract") != "specialist-findings.v4"
            or plan.get("runtime_revision") != CONTEXT_FOLLOWUP_V2_RUNTIME_SHA
            or plan.get("runtime_module_tree_sha256") != CONTEXT_FOLLOWUP_V2_MODULE_TREE_SHA256
            or plan.get("runtime_module_file_count") != len(RUNTIME_MODULE_INVENTORY)
            or plan.get("primary_parent_plan_sha256") != CONTEXT_FOLLOWUP_V2_PLAN_SHA256
            or plan.get("primary_input_parent_plan_sha256") != V2_PLAN_SHA256
            or plan.get("primary_requests_total") != 47
            or plan.get("primary_serialized_input_bytes_total") != 4_002_927
            or plan.get("required_obligations_total") != 124
            or plan.get("max_claim_assessments_per_case") != 4
            or plan.get("max_retries_per_task") != 0
            or plan.get("limits") != parent_plan.get("limits")
            or plan.get("selectors") != ["staged-pr464", "full-three-case"]
            or plan.get("cases") != parent_plan.get("cases")
            or plan.get("interpretation") != (
                "The exact primary descriptors, scope, byte counts, obligations, and limits are inherited from the "
                "frozen context-followup-v2 plan. This selector adds only the direct-Python "
                "context-followup-observation.v3 projection. The provider-free prepare workflow and synthetic "
                "projection check do not establish provider delivery, live context handoff, review quality, semantic "
                "accuracy, cost, adoption, or production readiness."
            )
            or plan.get("projection_limitations") != [
                "The candidate preparation preserves only exact primary request hashes, identities, and binding metadata; "
                "it does not retain serialized request bodies or raw source.",
                "The v3 projection can report persisted handoff bindings; it does not prove provider delivery, model "
                "consumption, or semantic use.",
                "Actual provider calls and cost remain UNKNOWN after any provider dispatch unless separate evidence "
                "establishes them.",
            ]
        ):
            raise TrialError("context_followup_v3_plan_manifest_identity_mismatch")
        document = dict(parent_document)
        document.update({
            "experiment_selector": CONTEXT_FOLLOWUP_V3_SELECTOR,
            "context_followup_plan_sha256": CONTEXT_FOLLOWUP_V3_PLAN_SHA256,
            "context_followup_runtime_revision": CONTEXT_FOLLOWUP_V2_RUNTIME_SHA,
            "context_followup_module_tree_sha256": CONTEXT_FOLLOWUP_V2_MODULE_TREE_SHA256,
            "dynamic_followup_contract": "context-followup.v1",
            "dynamic_followup_projection": "context-followup-observation.v3",
        })
        return document, parent_cases
    if input_contract == CONTEXT_FOLLOWUP_V2_SELECTOR:
        v2_document, v2_cases = load_locked_cases("specialist-input-v2")
        plan = read_context_followup_v2_plan()
        fields = {
            "schema", "status", "experiment_id", "input_contract", "dynamic_followup_contract",
            "dynamic_followup_projection", "response_contract", "runtime_revision", "runtime_module_tree_sha256",
            "runtime_module_file_count", "primary_parent_plan_sha256", "runtime_module_map_proof_sha256",
            "primary_receipt_comparison_proof_sha256", "primary_prepare_proof_sha256",
            "local_prepare_input_proof_sha256", "local_preparation_wheel_sha256", "cases",
            "primary_requests_total", "primary_serialized_input_bytes_total", "required_obligations_total",
            "max_claim_assessments_per_case", "max_retries_per_task", "limits", "selectors",
            "interpretation", "projection_limitations",
        }
        if set(plan) != fields:
            raise TrialError("context_followup_v2_plan_manifest_shape_invalid")
        if (
            plan.get("schema") != "historical-real-case-context-followup-input-plan.v2"
            or plan.get("status") != "FROZEN_CANDIDATE_PRIMARY_IDENTITY_PROVIDER_FREE"
            or plan.get("experiment_id") != "historical-context-followup-v2"
            or plan.get("input_contract") != "specialist-input.v2"
            or plan.get("dynamic_followup_contract") != "context-followup.v1"
            or plan.get("dynamic_followup_projection") != "context-followup-observation.v2"
            or plan.get("response_contract") != "specialist-findings.v4"
            or plan.get("runtime_revision") != CONTEXT_FOLLOWUP_V2_RUNTIME_SHA
            or plan.get("runtime_module_tree_sha256") != CONTEXT_FOLLOWUP_V2_MODULE_TREE_SHA256
            or plan.get("runtime_module_file_count") != len(RUNTIME_MODULE_INVENTORY)
            or plan.get("primary_parent_plan_sha256") != V2_PLAN_SHA256
            or plan.get("runtime_module_map_proof_sha256") != CONTEXT_FOLLOWUP_V2_MODULE_PROOF_SHA256
            or plan.get("primary_receipt_comparison_proof_sha256") != CONTEXT_FOLLOWUP_V2_PRIMARY_PROOF_SHA256
            or plan.get("primary_prepare_proof_sha256") != CONTEXT_FOLLOWUP_V2_PREPARE_PROOF_SHA256
            or plan.get("local_preparation_wheel_sha256") != CONTEXT_FOLLOWUP_V2_LOCAL_WHEEL_SHA256
            or plan.get("local_prepare_input_proof_sha256") != CONTEXT_FOLLOWUP_V2_LOCAL_PREPARE_PROOF_SHA256
            or plan.get("primary_requests_total") != 47
            or plan.get("primary_serialized_input_bytes_total") != 4_002_927
            or plan.get("required_obligations_total") != 124
            or plan.get("max_claim_assessments_per_case") != 4
            or plan.get("max_retries_per_task") != 0
            or plan.get("limits") != limits_for(64)
            or plan.get("selectors") != ["staged-pr464", "full-three-case"]
            or plan.get("interpretation") != (
                "This is a new context-followup-v2 selector with a new runtime and bounded closure-diagnostic projection. "
                "Its primary specialist-input.v2 descriptors, scope, and limits are inherited exactly from the frozen v2 "
                "parent plan. The local proof is provider-free preparation only; it does not establish provider behavior, "
                "review quality, semantic accuracy, cost, adoption, or production readiness."
            )
        ):
            raise TrialError("context_followup_v2_plan_manifest_identity_mismatch")
        proof_files = {
            "proofs/runtime-module-map.json": CONTEXT_FOLLOWUP_V2_MODULE_PROOF_SHA256,
            "proofs/primary-receipt-comparison.json": CONTEXT_FOLLOWUP_V2_PRIMARY_PROOF_SHA256,
            "proofs/candidate-primary-prepare.json": CONTEXT_FOLLOWUP_V2_PREPARE_PROOF_SHA256,
        }
        for relative, expected_hash in proof_files.items():
            proof_path = CONTEXT_FOLLOWUP_V2_PLAN_PATH.parent / relative
            try:
                if proof_path.is_symlink() or not proof_path.is_file() or proof_path.stat().st_size > 128_000:
                    raise TrialError("context_followup_v2_plan_proof_invalid")
                if sha256(proof_path.read_bytes()) != expected_hash:
                    raise TrialError("context_followup_v2_plan_proof_hash_mismatch")
            except OSError:
                raise TrialError("context_followup_v2_plan_proof_unavailable") from None
        expected_plan_cases = [
            {
                "case_id": case["case_id"],
                "base_sha": case["base_sha"],
                "head_sha": case["head_sha"],
                "mode": case["mode"],
                "profile_sha256": case["profile_sha256"],
                "checks_sha256": case["checks_sha256"],
                "snapshot_hash": case["snapshot_hash"],
                "evidence_index_sha256": case["evidence_index_sha256"],
                "scope_count": case["expected_scope_count"],
                "scope_sha256": case["expected_scope_sha256"],
                "primary_request_count": case["expected_primary_count"],
                "primary_serialized_input_bytes": case["expected_primary_serialized_input_bytes"],
                "primary_descriptor_sha256": case["expected_primary_descriptor_sha256"],
            }
            for case in v2_cases
        ]
        if plan.get("cases") != expected_plan_cases:
            raise TrialError("context_followup_v2_plan_primary_binding_mismatch")
        document = dict(v2_document)
        document.update(
            {
                "experiment_selector": CONTEXT_FOLLOWUP_V2_SELECTOR,
                "context_followup_plan_sha256": CONTEXT_FOLLOWUP_V2_PLAN_SHA256,
                "context_followup_runtime_revision": CONTEXT_FOLLOWUP_V2_RUNTIME_SHA,
                "context_followup_module_tree_sha256": CONTEXT_FOLLOWUP_V2_MODULE_TREE_SHA256,
                "dynamic_followup_contract": "context-followup.v1",
                "dynamic_followup_projection": "context-followup-observation.v2",
            }
        )
        return document, v2_cases
    if input_contract == CONTEXT_FOLLOWUP_SELECTOR:
        v2_document, v2_cases = load_locked_cases("specialist-input-v2")
        plan = read_context_followup_plan()
        fields = {
            "schema", "status", "experiment_id", "input_contract", "dynamic_followup_contract",
            "response_contract", "runtime_revision", "runtime_module_tree_sha256", "runtime_module_file_count",
            "primary_parent_plan_sha256", "prior_provider_free_primary_identity_proof_sha256",
            "prior_installed_module_proof_sha256", "cases", "primary_requests_total",
            "primary_serialized_input_bytes_total", "required_obligations_total",
            "max_claim_assessments_per_case", "max_retries_per_task", "limits", "selectors",
            "interpretation", "projection_limitations",
        }
        if set(plan) != fields:
            raise TrialError("context_followup_plan_manifest_shape_invalid")
        if (
            plan.get("schema") != "historical-real-case-context-followup-input-plan.v1"
            or plan.get("status") != "FROZEN_PRIMARY_IDENTITY_BASIS_PROVIDER_FREE"
            or plan.get("experiment_id") != "historical-context-followup-v1"
            or plan.get("input_contract") != "specialist-input.v2"
            or plan.get("dynamic_followup_contract") != "context-followup.v1"
            or plan.get("response_contract") != "specialist-findings.v4"
            or plan.get("runtime_revision") != CONTEXT_FOLLOWUP_RUNTIME_SHA
            or plan.get("runtime_module_tree_sha256") != CONTEXT_FOLLOWUP_MODULE_TREE_SHA256
            or plan.get("runtime_module_file_count") != len(RUNTIME_MODULE_INVENTORY)
            or plan.get("primary_parent_plan_sha256") != V2_PLAN_SHA256
            or plan.get("prior_provider_free_primary_identity_proof_sha256") != CONTEXT_FOLLOWUP_PRIMARY_PROOF_SHA256
            or plan.get("prior_installed_module_proof_sha256") != CONTEXT_FOLLOWUP_TREE_PROOF_SHA256
            or plan.get("primary_requests_total") != 47
            or plan.get("primary_serialized_input_bytes_total") != 4_002_927
            or plan.get("required_obligations_total") != 124
            or plan.get("max_claim_assessments_per_case") != 4
            or plan.get("max_retries_per_task") != 0
            or plan.get("limits") != limits_for(64)
            or plan.get("selectors") != ["staged-pr464", "full-three-case"]
            or plan.get("interpretation") != (
                "Fixed primary input identity is inherited from and must match the frozen specialist-input.v2 plan exactly. "
                "The runtime source and dynamic follow-up contract are new. This plan is not hosted prepare evidence and "
                "makes no provider, coverage, quality, accuracy, adoption, or production-readiness claim."
            )
        ):
            raise TrialError("context_followup_plan_manifest_identity_mismatch")
        expected_plan_cases = [
            {
                "case_id": case["case_id"],
                "base_sha": case["base_sha"],
                "head_sha": case["head_sha"],
                "mode": case["mode"],
                "profile_sha256": case["profile_sha256"],
                "checks_sha256": case["checks_sha256"],
                "snapshot_hash": case["snapshot_hash"],
                "evidence_index_sha256": case["evidence_index_sha256"],
                "scope_count": case["expected_scope_count"],
                "scope_sha256": case["expected_scope_sha256"],
                "primary_request_count": case["expected_primary_count"],
                "primary_serialized_input_bytes": case["expected_primary_serialized_input_bytes"],
                "primary_descriptor_sha256": case["expected_primary_descriptor_sha256"],
            }
            for case in v2_cases
        ]
        if plan.get("cases") != expected_plan_cases:
            raise TrialError("context_followup_plan_primary_binding_mismatch")
        document = dict(v2_document)
        document.update(
            {
                "experiment_selector": CONTEXT_FOLLOWUP_SELECTOR,
                "context_followup_plan_sha256": CONTEXT_FOLLOWUP_PLAN_SHA256,
                "context_followup_runtime_revision": CONTEXT_FOLLOWUP_RUNTIME_SHA,
                "context_followup_module_tree_sha256": CONTEXT_FOLLOWUP_MODULE_TREE_SHA256,
                "dynamic_followup_contract": "context-followup.v1",
            }
        )
        return document, v2_cases
    if input_contract != "specialist-input-v2":
        raise TrialError("input_contract_invalid")

    v1_document, v1_cases = _load_locked_cases_v1()
    raw = V2_PLAN_PATH.read_bytes()
    if sha256(raw) != V2_PLAN_SHA256:
        raise TrialError("v2_plan_manifest_hash_mismatch")
    plan = read_v2_plan()
    plan_fields = {
        "schema", "input_contract", "response_contract", "status", "runtime_revision",
        "runtime_module_tree_sha256", "runtime_module_file_count", "local_preparation_wheel_sha256",
        "preparation_manifest_sha256", "independent_preparation_verification_sha256",
        "case_input_manifest_v1_sha256", "limits", "max_claim_assessments_per_case",
        "max_retries_per_task", "selectors", "cases", "required_obligations_total",
        "primary_requests_total", "primary_serialized_input_bytes_total", "interpretation",
        "projection_limitations",
    }
    if set(plan) != plan_fields:
        raise TrialError("v2_plan_manifest_shape_invalid")
    if (
        plan.get("schema") != "historical-real-case-input-plan.v2"
        or plan.get("input_contract") != "specialist-input.v2"
        or plan.get("response_contract") != "specialist-findings.v4"
        or plan.get("runtime_revision") != V2_RUNTIME_SHA
        or plan.get("runtime_module_tree_sha256") != V2_RUNTIME_MODULE_TREE_SHA256
        or plan.get("runtime_module_file_count") != len(RUNTIME_MODULE_INVENTORY)
        or plan.get("local_preparation_wheel_sha256") != V2_WHEEL_SHA256
        or plan.get("preparation_manifest_sha256") != V2_PREPARATION_MANIFEST_SHA256
        or plan.get("independent_preparation_verification_sha256") != V2_PREPARATION_VERIFICATION_SHA256
        or plan.get("status") != "FROZEN_PROVIDER_FREE_PREPARATION"
        or plan.get("case_input_manifest_v1_sha256") != CASES_SHA256
        or plan.get("max_claim_assessments_per_case") != 4
        or plan.get("max_retries_per_task") != 0
        or plan.get("selectors") != ["staged-pr464", "full-three-case"]
        or plan.get("primary_requests_total") != 47
        or plan.get("required_obligations_total") != 124
        or plan.get("primary_serialized_input_bytes_total") != 4_002_927
        or plan.get("limits") != limits_for(64)
    ):
        raise TrialError("v2_plan_manifest_identity_mismatch")
    v2_cases = plan.get("cases")
    if not isinstance(v2_cases, list) or [row.get("case_id") for row in v2_cases if isinstance(row, dict)] != [
        case["case_id"] for case in v1_cases
    ]:
        raise TrialError("v2_case_set_mismatch")

    merged: list[dict[str, Any]] = []
    for v1_case, v2_case in zip(v1_cases, v2_cases, strict=True):
        case_fields = {
            "case_id", "base_sha", "head_sha", "mode", "profile_sha256", "checks_sha256",
            "snapshot_hash", "evidence_index_sha256", "scope_count", "scope_sha256",
            "v1_primary_requests", "v1_primary_bytes", "primary_request_count",
            "primary_serialized_input_bytes", "primary_descriptor_sha256", "evidence_index",
            "primary_requests",
        }
        if not isinstance(v2_case, dict) or set(v2_case) != case_fields:
            raise TrialError("v2_case_shape_invalid")
        if (
            v2_case.get("base_sha") != v1_case.get("base_sha")
            or v2_case.get("head_sha") != v1_case.get("head_sha")
            or v2_case.get("mode") != v1_case.get("mode")
            or v2_case.get("profile_sha256") != v1_case.get("profile_sha256")
            or v2_case.get("checks_sha256") != v1_case.get("checks_sha256")
            or v2_case.get("scope_count") != v1_case.get("expected_scope_count")
            or v2_case.get("scope_sha256") != v1_case.get("expected_scope_sha256")
            or v2_case.get("v1_primary_requests") != v1_case.get("expected_primary_count")
            or v2_case.get("v1_primary_bytes") != v1_case.get("expected_primary_serialized_input_bytes")
        ):
            raise TrialError("v2_case_identity_mismatch")
        evidence_index = v2_case.get("evidence_index")
        descriptors = v2_case.get("primary_requests")
        if not isinstance(evidence_index, dict) or not isinstance(descriptors, list):
            raise TrialError("v2_request_plan_invalid")
        evidence_fields = {
            "evidence_id", "path", "source_revision", "content_hash", "source_kind", "trust", "content_bytes"
        }
        for evidence_id, evidence in evidence_index.items():
            if (
                not isinstance(evidence_id, str)
                or not isinstance(evidence, dict)
                or set(evidence) != evidence_fields
                or evidence.get("evidence_id") != evidence_id
                or not isinstance(evidence.get("content_bytes"), int)
                or isinstance(evidence.get("content_bytes"), bool)
                or evidence["content_bytes"] < 0
            ):
                raise TrialError("v2_evidence_index_shape_invalid")
        full_descriptors: list[dict[str, Any]] = []
        request_fields = {
            "task_id", "lens", "unit_ids", "obligation_ids", "evidence_ids", "required_context_ids",
            "context_omissions", "required_context_omissions", "input_bytes", "input_sha256", "admitted",
            "output_bytes_cap", "output_tokens_cap", "request_input_contract", "unit_evidence_bindings",
        }
        for descriptor in descriptors:
            if not isinstance(descriptor, dict) or set(descriptor) != request_fields:
                raise TrialError("v2_request_plan_invalid")
            evidence_ids = descriptor.get("evidence_ids")
            if (
                not isinstance(evidence_ids, list)
                or any(not isinstance(evidence_id, str) or evidence_id not in evidence_index for evidence_id in evidence_ids)
                or len(evidence_ids) != len(set(evidence_ids))
            ):
                raise TrialError("v2_request_evidence_index_invalid")
            binding_rows = descriptor.get("unit_evidence_bindings")
            unit_ids = descriptor.get("unit_ids")
            if not isinstance(binding_rows, list) or not isinstance(unit_ids, list):
                raise TrialError("v2_request_binding_shape_invalid")
            if [row.get("unit_id") for row in binding_rows if isinstance(row, dict)] != unit_ids:
                raise TrialError("v2_request_binding_shape_invalid")
            for binding in binding_rows:
                if (
                    not isinstance(binding, dict)
                    or set(binding) != {"unit_id", "binding_status", "evidence_ids"}
                    or binding.get("binding_status") not in {"VERIFIED", "UNKNOWN"}
                    or not isinstance(binding.get("evidence_ids"), list)
                    or any(not isinstance(evidence_id, str) for evidence_id in binding["evidence_ids"])
                    or not set(binding["evidence_ids"]).issubset(evidence_ids)
                    or (binding["binding_status"] == "UNKNOWN" and binding["evidence_ids"])
                ):
                    raise TrialError("v2_request_binding_shape_invalid")
            request = dict(descriptor)
            request["evidence_bindings"] = [evidence_index[evidence_id] for evidence_id in evidence_ids]
            full_descriptors.append(request)
        if (
            len(full_descriptors) != v2_case.get("primary_request_count")
            or v2_case.get("primary_request_count") != v1_case.get("expected_primary_count")
            or sum(row.get("input_bytes", 0) for row in full_descriptors)
            != v2_case.get("primary_serialized_input_bytes")
            or v2_case.get("primary_serialized_input_bytes") > 8_000_000
            or sha256(canonical(full_descriptors)) != v2_case.get("primary_descriptor_sha256")
        ):
            raise TrialError("v2_request_plan_digest_mismatch")
        case = dict(v1_case)
        case.update(
            {
                "expected_primary_count": v2_case["primary_request_count"],
                "expected_primary_serialized_input_bytes": v2_case["primary_serialized_input_bytes"],
                "expected_primary_descriptor_sha256": v2_case["primary_descriptor_sha256"],
                "expected_primary_request_descriptors": full_descriptors,
                "expected_evidence_index": evidence_index,
                "input_contract": "specialist-input.v2",
            }
        )
        merged.append(case)
    if (
        sum(case["expected_primary_count"] for case in merged) != 47
        or sum(case["expected_primary_serialized_input_bytes"] for case in merged) != 4_002_927
        or sum(case["expected_scope_count"] for case in merged) != 124
    ):
        raise TrialError("v2_plan_totals_mismatch")
    document = dict(v1_document)
    document.update(
        {
            "input_contract": "specialist-input.v2",
            "baseline_plan_sha256": V2_PLAN_SHA256,
            "runtime_revision": V2_RUNTIME_SHA,
            "runtime_module_tree_sha256": V2_RUNTIME_MODULE_TREE_SHA256,
            "preparation_manifest_sha256": plan["preparation_manifest_sha256"],
        }
    )
    return document, merged


def selected_cases(mode: str, cases: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if mode == "staged-pr464":
        return [case for case in cases if case["case_id"] == "PR-464"]
    if mode == "full-three-case":
        return cases
    raise TrialError("trial_mode_invalid")


def build_configs(directory: Path) -> tuple[Path, Path, list[str]]:
    environment = {name: os.environ.get(name, "") for name in TRIAL_ENV_NAMES}
    secrets = []
    for name in SECRET_NAMES:
        value = environment[name]
        if not value or len(value) > 4096 or any(ch in value for ch in "\r\n\x00"):
            raise TrialError("provider_credential_unavailable")
        secrets.append(value)

    # Use the same API-root contract and validation as the normal production
    # environment translator, then pin the resulting endpoint/model identities.
    try:
        llm, jev = configurations_from_environment(environment)
    except ConfigError:
        raise TrialError("provider_identity_configuration_mismatch") from None
    if (
        llm.get("base_url") != EXPECTED_LLM_ENDPOINT
        or llm.get("model") != EXPECTED_LLM_MODEL
        or jev.get("endpoint") != EXPECTED_JEV_ENDPOINT
        or jev.get("model") != EXPECTED_JEV_ALIAS
    ):
        raise TrialError("provider_identity_configuration_mismatch")
    secrets.extend(environment[name] for name in IDENTITY_ENV_NAMES)
    secrets.extend(
        (
            EXPECTED_LLM_ENDPOINT,
            EXPECTED_LLM_MODEL,
            EXPECTED_JEV_BASE_URL,
            EXPECTED_JEV_ENDPOINT,
            EXPECTED_JEV_ALIAS,
        )
    )

    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    os.chmod(directory, 0o700)
    llm.update(
        {
            "timeout_seconds": 75,
            "max_request_bytes": 128000,
            "max_response_bytes": 16000,
            "max_output_tokens": 1800,
            "max_output_items": 100,
            "semantic_adjudication": True,
        }
    )
    llm_path = directory / "provider.json"
    jev_path = directory / "decision.json"
    for path, value in ((llm_path, llm), (jev_path, jev)):
        path.write_bytes(canonical(value))
        os.chmod(path, 0o600)
    return llm_path, jev_path, secrets


def build_prepare_configs(directory: Path) -> tuple[Path, Path]:
    provider_path = directory / "provider.json"
    decision_path = directory / "decision.json"
    write_json(
        provider_path,
        {
            "kind": "openai_compatible",
            "provider_id": "operator_openai_compatible",
            "base_url": EXPECTED_LLM_ENDPOINT,
            "model": EXPECTED_LLM_MODEL,
            "api_key_env": "LLM_API_KEY",
            "max_request_bytes": 128000,
            "max_response_bytes": 16000,
            "max_output_tokens": 1800,
            "max_output_items": 100,
        },
    )
    # ClaimTransport.from_decision_config requires this exact four-key contract.
    write_json(
        decision_path,
        {
            "kind": "typesafe",
            "endpoint": EXPECTED_JEV_ENDPOINT,
            "model": EXPECTED_JEV_ALIAS,
            "api_key_env": "JEV_API_KEY",
        },
    )
    return provider_path, decision_path


def limits_for(calls: int) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "deadline_seconds": 600,
        "max_concurrent_scopes": 4,
        "max_provider_calls": calls,
        "max_retries_per_task": 0,
        "max_context_bytes": 8_000_000,
        "max_snapshot_context_bytes": 300_000,
        "max_input_bytes_per_task": 128_000,
        "max_output_bytes_per_task": 32_768,
        "max_output_bytes": 2_097_152,
        "max_output_tokens": 1800,
        "max_context_retrievals": 8,
        "max_followup_tasks": 8,
    }


def runtime_identity(input_contract: str = "specialist-input-v1") -> tuple[str, str]:
    if input_contract == "specialist-input-v1":
        return RUNTIME_SHA, RUNTIME_MODULE_TREE_SHA256
    if input_contract == "specialist-input-v2":
        return V2_RUNTIME_SHA, V2_RUNTIME_MODULE_TREE_SHA256
    if input_contract == CONTEXT_FOLLOWUP_SELECTOR:
        return CONTEXT_FOLLOWUP_RUNTIME_SHA, CONTEXT_FOLLOWUP_MODULE_TREE_SHA256
    if input_contract == CONTEXT_FOLLOWUP_V2_SELECTOR:
        return CONTEXT_FOLLOWUP_V2_RUNTIME_SHA, CONTEXT_FOLLOWUP_V2_MODULE_TREE_SHA256
    if input_contract == CONTEXT_FOLLOWUP_V3_SELECTOR:
        return CONTEXT_FOLLOWUP_V2_RUNTIME_SHA, CONTEXT_FOLLOWUP_V2_MODULE_TREE_SHA256
    raise TrialError("input_contract_invalid")


def _uses_v2_primary(input_contract: str) -> bool:
    return input_contract in {
        "specialist-input-v2", CONTEXT_FOLLOWUP_SELECTOR, CONTEXT_FOLLOWUP_V2_SELECTOR, CONTEXT_FOLLOWUP_V3_SELECTOR,
    }


def _primary_input_contract(input_contract: str) -> str:
    return "specialist-input-v2" if _uses_v2_primary(input_contract) else "specialist-input-v1"


def _is_context_followup_experiment(input_contract: str) -> bool:
    return input_contract in {CONTEXT_FOLLOWUP_SELECTOR, CONTEXT_FOLLOWUP_V2_SELECTOR, CONTEXT_FOLLOWUP_V3_SELECTOR}


def _is_context_followup_v2(input_contract: str) -> bool:
    return input_contract == CONTEXT_FOLLOWUP_V2_SELECTOR


def _is_context_followup_v3(input_contract: str) -> bool:
    return input_contract == CONTEXT_FOLLOWUP_V3_SELECTOR


def _runtime_provenance_version(input_contract: str) -> str:
    if _is_context_followup_v3(input_contract):
        return "historical-real-case-runtime.context-followup.v3"
    if _is_context_followup_v2(input_contract):
        return "historical-real-case-runtime.context-followup.v2"
    if _is_context_followup_experiment(input_contract):
        return "historical-real-case-runtime.context-followup.v1"
    return "historical-real-case-runtime.v2"


def _manifest_schema(input_contract: str) -> str:
    if _is_context_followup_v3(input_contract):
        return "historical-real-case-trial-manifest.context-followup.v3"
    if _is_context_followup_v2(input_contract):
        return "historical-real-case-trial-manifest.context-followup.v2"
    if _is_context_followup_experiment(input_contract):
        return "historical-real-case-trial-manifest.context-followup.v1"
    return "historical-real-case-trial-manifest.v2" if _uses_v2_primary(input_contract) else "historical-real-case-trial-manifest.v1"


def _plan_identity(input_contract: str) -> str:
    if _is_context_followup_v3(input_contract):
        return CONTEXT_FOLLOWUP_V3_PLAN_SHA256
    if _is_context_followup_v2(input_contract):
        return CONTEXT_FOLLOWUP_V2_PLAN_SHA256
    if _is_context_followup_experiment(input_contract):
        return CONTEXT_FOLLOWUP_PLAN_SHA256
    return V2_PLAN_SHA256 if input_contract == "specialist-input-v2" else FROZEN_PLAN_MANIFEST_SHA256


def _experiment_identity_fields(input_contract: str) -> dict[str, Any]:
    if _is_context_followup_v3(input_contract):
        return {
            "experiment_selector": CONTEXT_FOLLOWUP_V3_SELECTOR,
            "input_contract": "specialist-input.v2",
            "dynamic_followup_contract": "context-followup.v1",
            "context_followup_plan_sha256": CONTEXT_FOLLOWUP_V3_PLAN_SHA256,
            "primary_parent_plan_sha256": CONTEXT_FOLLOWUP_V2_PLAN_SHA256,
            "primary_input_identity": "FROZEN_V2_DESCRIPTOR_PLAN_SELECTED",
            "dynamic_followup_projection": "context-followup-observation.v3",
        }
    if _is_context_followup_v2(input_contract):
        return {
            "experiment_selector": CONTEXT_FOLLOWUP_V2_SELECTOR,
            "input_contract": "specialist-input.v2",
            "dynamic_followup_contract": "context-followup.v1",
            "context_followup_plan_sha256": CONTEXT_FOLLOWUP_V2_PLAN_SHA256,
            "primary_parent_plan_sha256": V2_PLAN_SHA256,
            "primary_input_identity": "FROZEN_V2_DESCRIPTOR_PLAN_SELECTED",
            "dynamic_followup_projection": "context-followup-observation.v2",
        }
    if _is_context_followup_experiment(input_contract):
        return {
            "experiment_selector": CONTEXT_FOLLOWUP_SELECTOR,
            "input_contract": "specialist-input.v2",
            "dynamic_followup_contract": "context-followup.v1",
            "context_followup_plan_sha256": CONTEXT_FOLLOWUP_PLAN_SHA256,
            "primary_parent_plan_sha256": V2_PLAN_SHA256,
            "primary_input_identity": "FROZEN_V2_DESCRIPTOR_PLAN_SELECTED",
            "dynamic_followup_projection": "context-followup-observation.v1",
        }
    return {"input_contract": "specialist-input-v2"} if input_contract == "specialist-input-v2" else {}


def verify_runtime(
    cli: Path, runtime_source: Path, input_contract: str = "specialist-input-v1"
) -> dict[str, Any]:
    expected_revision, expected_tree = runtime_identity(input_contract)
    if not runtime_source.is_dir() or not re.fullmatch(r"[0-9a-f]{40}", expected_revision):
        raise TrialError("trusted_runtime_source_unavailable")
    try:
        from prepare_real_case_batch import installed_module_proof
    except ModuleNotFoundError:
        from scripts.prepare_real_case_batch import installed_module_proof

    if git_command(["--no-lazy-fetch", "-C", str(runtime_source), "rev-parse", "HEAD"], timeout=10) != expected_revision:
        raise TrialError("trusted_runtime_revision_mismatch")
    proof = installed_module_proof(cli, runtime_source)
    if proof.get("module_file_count") != 28 or proof.get("module_tree_sha256") != expected_tree:
        raise TrialError("installed_runtime_identity_mismatch")
    module_root = runtime_source / "src" / "pr_review_harness"
    inventory = sorted(path.relative_to(module_root).as_posix() for path in module_root.rglob("*.py") if path.is_file())
    if inventory != list(RUNTIME_MODULE_INVENTORY):
        raise TrialError("installed_runtime_inventory_mismatch")
    proof["module_inventory"] = inventory
    proof["runtime_revision"] = expected_revision
    proof["input_contract"] = input_contract
    return proof


def verify_dispatch_context(runner_root: Path) -> str:
    revision = os.environ.get("GITHUB_SHA", "")
    if (
        os.environ.get("GITHUB_REPOSITORY") != "groktopus/codereview"
        or os.environ.get("GITHUB_REF") != "refs/heads/main"
        or os.environ.get("GITHUB_EVENT_NAME") != "workflow_dispatch"
        or not re.fullmatch(r"[0-9a-f]{40}", revision)
    ):
        raise TrialError("provider_trial_dispatch_context_invalid")
    if git_command(["--no-lazy-fetch", "-C", str(runner_root), "rev-parse", "HEAD"], timeout=10) != revision:
        raise TrialError("runner_revision_mismatch")
    return revision


def _remaining(case_deadline: float, matrix_deadline: float) -> float:
    remaining = min(
        case_deadline - time.monotonic() - CASE_CLEANUP_RESERVE_SECONDS,
        matrix_deadline - time.monotonic() - MATRIX_CLEANUP_RESERVE_SECONDS,
    )
    if remaining <= 0:
        raise TrialError("case_deadline_exceeded")
    return remaining


def _parse_object_store_counts(report: str) -> tuple[int, int, int]:
    matches = [re.search(rf"^{name}: (\d+)$", report, re.MULTILINE) for name in ("count", "in-pack", "size-pack")]
    if any(match is None for match in matches):
        raise TrialError("target_object_store_report_invalid")
    loose_count, in_pack_count, pack_kib = (int(match.group(1)) for match in matches if match)
    return loose_count, in_pack_count, pack_kib


def _python_diff_command(git_dir: Path, attributes_file: Path, base_sha: str, head_sha: str) -> list[str]:
    return [
        "git",
        "-c",
        f"core.attributesFile={attributes_file}",
        "-c",
        f"diff.codereview-python.xfuncname={PYTHON_XFUNCNAME}",
        "--no-lazy-fetch",
        "--git-dir",
        str(git_dir),
        "diff",
        "--no-ext-diff",
        "--no-textconv",
        "--no-color",
        "--find-renames",
        "--unified=3",
        base_sha,
        head_sha,
    ]


def _write_python_attributes(path: Path) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(b"*.py diff=codereview-python\n")
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        try:
            os.close(descriptor)
        except OSError:
            pass
        try:
            path.unlink()
        except OSError:
            pass
        raise


def _matrix_deadline(provider_run: bool) -> float:
    monotonic_now = time.monotonic()
    raw = os.environ.get("TRIAL_STARTED_EPOCH", "")
    if not raw and not provider_run:
        return monotonic_now + MATRIX_SECONDS
    if not re.fullmatch(r"[0-9]{10,12}", raw):
        raise TrialError("trial_start_time_missing")
    remaining = float(raw) + MATRIX_SECONDS - time.time()
    if remaining <= MATRIX_CLEANUP_RESERVE_SECONDS:
        raise TrialError("matrix_deadline_exceeded")
    return monotonic_now + remaining


def acquire_bare_case(
    case: dict[str, Any],
    path: Path,
    case_deadline: float,
    matrix_deadline: float,
    source_bare: Path | None = None,
    auxiliary_dir: Path | None = None,
) -> dict[str, Any]:
    git_env = _clean_git_env()
    if source_bare is None:
        _bounded_run(
            ["git", "--no-lazy-fetch", "init", "--bare", str(path)],
            env=git_env,
            timeout=min(30, _remaining(case_deadline, matrix_deadline)),
            stdout_cap=32_000,
            stderr_cap=STDERR_CAP,
        )
        _bounded_run(
            [
                "git",
                "--no-lazy-fetch",
                "--git-dir",
                str(path),
                "fetch",
                "--depth=1",
                "--no-tags",
                "--no-write-fetch-head",
                REPOSITORY_URL,
                case["base_sha"],
                case["head_sha"],
            ],
            env=git_env,
            timeout=min(120, _remaining(case_deadline, matrix_deadline)),
            stdout_cap=32_000,
            stderr_cap=STDERR_CAP,
        )
    else:
        info = source_bare.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise TrialError("target_bare_source_invalid")
        bare_check = git_command(
            ["--no-lazy-fetch", "--git-dir", str(source_bare), "rev-parse", "--is-bare-repository"], timeout=10
        )
        if bare_check != "true":
            raise TrialError("target_bare_source_invalid")
        path = source_bare
    for revision in (case["base_sha"], case["head_sha"]):
        got = git_command(
            ["--no-lazy-fetch", "--git-dir", str(path), "rev-parse", f"{revision}^{{commit}}"],
            timeout=min(30, _remaining(case_deadline, matrix_deadline)),
        )
        if got != revision:
            raise TrialError("target_git_identity_mismatch")
    object_report = git_command(
        ["--no-lazy-fetch", "--git-dir", str(path), "count-objects", "-v"],
        timeout=min(30, _remaining(case_deadline, matrix_deadline)),
    )
    loose_count, in_pack_count, pack_kib = _parse_object_store_counts(object_report)
    object_count = loose_count + in_pack_count
    if object_count > MAX_OBJECT_COUNT or pack_kib > MAX_PACK_KIB:
        raise TrialError("target_object_store_acceptance_cap_exceeded")
    attributes_file = (auxiliary_dir or path.parent) / "python-diff.attributes"
    _write_python_attributes(attributes_file)
    try:
        patch, _ = _bounded_run(
            _python_diff_command(path, attributes_file, case["base_sha"], case["head_sha"]),
            env=git_env,
            timeout=min(60, _remaining(case_deadline, matrix_deadline)),
            stdout_cap=4_000_000,
            stderr_cap=STDERR_CAP,
        )
    finally:
        attributes_file.unlink(missing_ok=True)
    if sha256(patch) != case["patch_sha256"]:
        raise TrialError("immutable_patch_hash_mismatch")
    return {
        "base_sha": case["base_sha"],
        "head_sha": case["head_sha"],
        "patch_sha256": sha256(patch),
        "isolated_object_count": object_count,
        "isolated_loose_object_count": loose_count,
        "isolated_in_pack_object_count": in_pack_count,
        "isolated_pack_kib": pack_kib,
        "bare_object_store": str(path),
    }


def write_json(path: Path, value: Any) -> None:
    data = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        try:
            os.close(descriptor)
        except OSError:
            pass
        try:
            path.unlink()
        except OSError:
            pass
        raise


def run_cli(
    cli: Path,
    case: dict[str, Any],
    bare: Path,
    profile_path: Path,
    checks_path: Path,
    provider_path: Path,
    decision_path: Path,
    limits_path: Path,
    output: Path,
    prepare: bool,
    env: dict[str, str],
    timeout: float,
) -> dict[str, Any]:
    if timeout <= 0:
        raise TrialError("case_deadline_exceeded")
    run_id = f"trial-{case['case_id'].lower()}-{'prepare' if prepare else 'review'}"
    command = [
        str(cli),
        "review",
        "--repo",
        str(bare),
        "--base",
        case["base_sha"],
        "--head",
        case["head_sha"],
        "--profile",
        str(profile_path),
        "--historical-checks-json",
        str(checks_path),
        "--limits",
        str(limits_path),
        "--mode",
        case["mode"],
        "--effect-policy",
        "READ_ONLY",
        "--run-id",
        run_id,
        "--output",
        str(output),
        "--provider-config",
        str(provider_path),
        "--decision-config",
        str(decision_path),
        "--max-claim-assessments",
        "4",
        "--json",
    ]
    if prepare:
        command.append("--prepare-only")
    started = time.monotonic()
    stdout, _ = _bounded_run(command, env=env, timeout=timeout, stdout_cap=OUTPUT_CAP, stderr_cap=STDERR_CAP)
    elapsed = round(time.monotonic() - started, 3)
    try:
        value = json.loads(stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise TrialError("cli_result_invalid") from None
    if (
        not isinstance(value, dict)
        or (prepare and value.get("command") != "review")
        or (not prepare and not isinstance(value.get("artifact_path"), str))
    ):
        raise TrialError("cli_result_invalid")
    return {"value": value, "elapsed_seconds": elapsed, "run_id": run_id}


def validate_prepare(case: dict[str, Any], prepared: dict[str, Any], overall_max_bytes: int) -> None:
    value = prepared["value"]
    primary = value.get("primary_requests")
    scope = value.get("scope", {})
    snapshot = value.get("snapshot", {})
    evidence_index = snapshot.get("evidence_index")
    if isinstance(evidence_index, list):
        projected_evidence = [
            {key: row[key] for key in ("evidence_id", "content_hash", "path", "source_revision") if key in row}
            for row in evidence_index
            if isinstance(row, dict)
        ]
        projected_evidence.sort(key=lambda row: str(row.get("evidence_id", "")))
    else:
        projected_evidence = None
    obligations = scope.get("coverage_obligations")
    projected_obligations = (
        sorted(
            (
                {
                    **{key: row.get(key) for key in ("obligation_id", "obligation_kind", "lens", "check_binding_id")},
                    "scope_unit_ids": sorted(row.get("scope_unit_ids", []))
                    if isinstance(row.get("scope_unit_ids"), list)
                    else row.get("scope_unit_ids"),
                }
                for row in obligations
                if isinstance(row, dict) and isinstance(row.get("obligation_id"), str)
            ),
            key=lambda row: row["obligation_id"],
        )
        if isinstance(obligations, list)
        else None
    )
    if (
        value.get("status") != "PREPARED_ONLY"
        or value.get("disposition") is not None
        or snapshot.get("base_sha") != case["base_sha"]
        or snapshot.get("head_sha") != case["head_sha"]
        or snapshot.get("snapshot_hash") != case["snapshot_hash"]
        or snapshot.get("evidence_index_sha256") != case["evidence_index_sha256"]
        or snapshot.get("profile_file_sha256") != case["profile_sha256"]
        or snapshot.get("provider_identity_sha256") != case["primary_provider_identity_sha256"]
        or snapshot.get("profile_version") != case["profile_version"]
        or projected_evidence is None
        or sha256(canonical(projected_evidence)) != case["evidence_index_sha256"]
    ):
        raise TrialError("prepared_snapshot_identity_mismatch")
    if (
        scope.get("primary_scope_admission_complete") is not True
        or scope.get("required_unadmitted_obligation_ids") != []
        or scope.get("planned_obligations") != case["expected_scope_count"]
        or projected_obligations is None
        or len(projected_obligations) != case["expected_scope_count"]
        or sha256(canonical(projected_obligations)) != case["expected_scope_sha256"]
        or not isinstance(primary, list)
        or len(primary) != case["expected_primary_count"]
    ):
        raise TrialError("prepared_scope_mismatch")
    if sum(request.get("input_bytes", 0) for request in primary) != case["expected_primary_serialized_input_bytes"]:
        raise TrialError("prepared_primary_size_mismatch")
    if (
        any(
            isinstance(request.get("input_bytes"), bool)
            or not isinstance(request.get("input_bytes"), int)
            or request["input_bytes"] > 128_000
            for request in primary
        )
        or len(primary) > 64
        or sum(request["input_bytes"] for request in primary) > 8_000_000
    ):
        raise TrialError("prepared_primary_exceeds_case_caps")
    if len(canonical(primary)) > overall_max_bytes:
        raise TrialError("prepared_primary_ledger_over_limit")
    projection = []
    for request in primary:
        projection.append(
            {
                key: request.get(key)
                for key in (
                    "task_id",
                    "lens",
                    "unit_ids",
                    "obligation_ids",
                    "evidence_ids",
                    "input_bytes",
                    "input_sha256",
                )
            }
        )
    if sha256(canonical(projection)) != case["expected_primary_descriptor_sha256"]:
        raise TrialError("prepared_primary_descriptor_mismatch")


def validate_prepare_v2(
    case: dict[str, Any], prepared: dict[str, Any], overall_max_bytes: int, call_cap: int
) -> None:
    """Require the exact frozen specialist-input.v2 descriptors before inference."""
    value = prepared.get("value")
    if not isinstance(value, dict):
        raise TrialError("prepared_result_invalid")
    snapshot = value.get("snapshot")
    scope = value.get("scope")
    primary = value.get("primary_requests")
    if not isinstance(snapshot, dict) or not isinstance(scope, dict) or not isinstance(primary, list):
        raise TrialError("prepared_result_invalid")
    projected_evidence = snapshot.get("evidence_index")
    if isinstance(projected_evidence, list):
        projected_evidence = [
            {key: row[key] for key in ("evidence_id", "content_hash", "path", "source_revision") if key in row}
            for row in projected_evidence
            if isinstance(row, dict)
        ]
        projected_evidence.sort(key=lambda row: str(row.get("evidence_id", "")))
    else:
        raise TrialError("prepared_evidence_index_missing")
    obligations = scope.get("coverage_obligations")
    projected_obligations = (
        sorted(
            (
                {
                    **{key: row.get(key) for key in ("obligation_id", "obligation_kind", "lens", "check_binding_id")},
                    "scope_unit_ids": sorted(row.get("scope_unit_ids", []))
                    if isinstance(row.get("scope_unit_ids"), list)
                    else row.get("scope_unit_ids"),
                }
                for row in obligations
                if isinstance(row, dict) and isinstance(row.get("obligation_id"), str)
            ),
            key=lambda row: row["obligation_id"],
        )
        if isinstance(obligations, list)
        else None
    )
    if (
        value.get("status") != "PREPARED_ONLY"
        or value.get("disposition") is not None
        or value.get("no_provider_calls") is not True
        or value.get("no_target_code_execution") is not True
        or snapshot.get("base_sha") != case["base_sha"]
        or snapshot.get("head_sha") != case["head_sha"]
        or snapshot.get("snapshot_hash") != case["snapshot_hash"]
        or snapshot.get("evidence_index_sha256") != case["evidence_index_sha256"]
        or snapshot.get("profile_file_sha256") != case["profile_sha256"]
        or snapshot.get("provider_identity_sha256") != case["primary_provider_identity_sha256"]
        or snapshot.get("profile_version") != case["profile_version"]
        or sha256(canonical(projected_evidence)) != case["evidence_index_sha256"]
    ):
        raise TrialError("prepared_snapshot_identity_mismatch")
    if (
        scope.get("primary_scope_admission_complete") is not True
        or scope.get("required_unadmitted_obligation_ids") != []
        or scope.get("planned_obligations") != case["expected_scope_count"]
        or projected_obligations is None
        or len(projected_obligations) != case["expected_scope_count"]
        or sha256(canonical(projected_obligations)) != case["expected_scope_sha256"]
    ):
        raise TrialError("prepared_scope_mismatch")
    if (
        len(primary) != case["expected_primary_count"]
        or len(primary) > call_cap
        or any(
            isinstance(row, dict)
            and (isinstance(row.get("input_bytes"), bool) or not isinstance(row.get("input_bytes"), int))
            for row in primary
        )
        or any(not isinstance(row, dict) for row in primary)
        or sum(row["input_bytes"] for row in primary) != case["expected_primary_serialized_input_bytes"]
        or any(row["input_bytes"] > 128_000 or row.get("admitted") is not True for row in primary)
        or sum(row["input_bytes"] for row in primary) > 8_000_000
        or len(canonical(primary)) > overall_max_bytes
    ):
        raise TrialError("prepared_primary_caps_or_count_mismatch")
    expected = case.get("expected_primary_request_descriptors")
    if not isinstance(expected, list) or primary != expected:
        raise TrialError("prepared_primary_descriptor_mismatch")
    if sha256(canonical(primary)) != case["expected_primary_descriptor_sha256"]:
        raise TrialError("prepared_primary_descriptor_mismatch")
    for row in primary:
        if row.get("request_input_contract") != "specialist-input.v2":
            raise TrialError("prepared_input_contract_mismatch")
        bindings = row.get("unit_evidence_bindings")
        unit_ids = row.get("unit_ids")
        delivered = row.get("evidence_ids")
        if (
            not isinstance(unit_ids, list)
            or not isinstance(delivered, list)
            or not isinstance(bindings, list)
            or [binding.get("unit_id") for binding in bindings if isinstance(binding, dict)] != unit_ids
        ):
            raise TrialError("prepared_unit_evidence_binding_invalid")
        for binding in bindings:
            ids = binding.get("evidence_ids")
            status = binding.get("binding_status")
            if (
                not isinstance(ids, list)
                or status not in {"VERIFIED", "UNKNOWN"}
                or any(not isinstance(evidence_id, str) for evidence_id in ids)
                or not set(ids).issubset(delivered)
                or (status == "UNKNOWN" and ids)
            ):
                raise TrialError("prepared_unit_evidence_binding_invalid")


_FOLLOWUP_TASK_STATUSES = frozenset({"SUCCEEDED", "FAILED", "TIMED_OUT", "SKIPPED", "INTERRUPTED_UNKNOWN", "INVALID"})
_FOLLOWUP_COVERAGE_STATES = frozenset({"COMPLETE", "PARTIAL", "NOT_STARTED"})
_FOLLOWUP_SETTLEMENT_STATUSES = frozenset({"SUCCEEDED", "FAILED", "TIMED_OUT", "INVALID", "INTERRUPTED_UNKNOWN", "NOT_RUN"})
_FOLLOWUP_LENSES = frozenset({"correctness", "tests", "design", "security", "performance", "maintainability", "project_specific"})
_FOLLOWUP_TARGET_KINDS = frozenset({"unit", "path", "symbol"})
_FOLLOWUP_LINK_STATES = frozenset({"PERSISTED_RECORDS_MATCH", "PERSISTED_RECORDS_MISMATCH", "UNKNOWN"})
_FOLLOWUP_HANDOFF_STATES = frozenset({"VERIFIED", "MISMATCH", "UNKNOWN"})
_FOLLOWUP_PROJECTION_MAX_IDS = 500
_REQUIRED_CONTEXT_DIAGNOSTIC_MAX_ROWS = 200
_REQUIRED_CONTEXT_FOLLOWUP_SOURCE_MAX_ROWS = 8
_REQUIRED_CONTEXT_COVERAGE_REASONS = frozenset({
    "CONTEXT_GAP_UNRESOLVED",
    "VALID_RESULT",
    "CHECK_RESULT_EVIDENCE_INVALID",
    "REQUIRED_OUTPUT_QUARANTINED",
    "REQUIRED_CONTEXT_NOT_COVERED",
    "CHECK_RESULT_UNAVAILABLE",
    "COVERAGE_NOTE_EVIDENCE_INVALID",
    "PARTIAL_REVIEW_COVERAGE",
    "COVERAGE_NOTE_MISSING",
    "MISSING_RESULT",
})
_CLOSURE_NOTE_CODES = frozenset({
    "NOTE_NOT_OBJECT", "STATE_NOT_COVERED", "BASIS_NOT_STATIC_REVIEW", "UNIT_OUT_OF_SCOPE",
    "NO_RETRIEVED_EVIDENCE_REFERENCE", "REFERENCE_NOT_IN_TASK_INPUT", "MATCH", "NO_COVERAGE_NOTES", "UNKNOWN",
})
_CLOSURE_QUARANTINE_KINDS = frozenset({
    "finding_candidates", "context_gap_proposals", "coverage_notes", "other_required_kind",
})


def _bounded_object_hash(value: Any, max_bytes: int = 64_000) -> str | None:
    try:
        raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()
    except (TypeError, ValueError, RecursionError):
        return None
    return sha256(raw) if len(raw) <= max_bytes else None


def _safe_followup_id(value: Any) -> str:
    return value if isinstance(value, str) and _CLAIM_DIMENSION_ID.fullmatch(value) else "UNKNOWN"


def _safe_followup_enum(value: Any, allowed: frozenset[str]) -> str:
    return value if isinstance(value, str) and value in allowed else "UNKNOWN"


def _followup_metadata_contract_state(value: Any) -> str:
    """Observe the pinned runtime's canonical v1 shape validator, without retaining its errors."""
    if not isinstance(value, dict):
        return "UNKNOWN"
    try:
        from pr_review_harness.contracts import ContractIssue, validate_context_followup_metadata
    except ImportError:
        return "UNKNOWN"
    try:
        validate_context_followup_metadata(value)
    except ContractIssue:
        return "INVALID"
    except Exception:
        return "UNKNOWN"
    return "VALID"


def _bounded_followup_evidence_ids(value: Any) -> bool:
    if not isinstance(value, list) or len(value) > _FOLLOWUP_PROJECTION_MAX_IDS:
        return False
    return all(_safe_followup_id(item) != "UNKNOWN" for item in value) and len(value) == len(set(value))


def _project_required_context_closure_diagnostics(value: Any) -> dict[str, Any]:
    """Allowlist the engine's typed closure observation without re-evaluating it."""
    unknown = {
        "schema": "required-context-closure-diagnostics.v1",
        "state": "UNKNOWN",
        "coverage_note_result": "UNKNOWN",
        "coverage_note_count": "UNKNOWN",
        "coverage_note_notes_examined_count": "UNKNOWN",
        "coverage_note_notes_unexamined_after_match_count": "UNKNOWN",
        "coverage_note_failure_counts": "UNKNOWN",
        "required_output_quarantine_count": "UNKNOWN",
        "required_output_quarantine_by_kind": "UNKNOWN",
        "unresolved_context_gap_count": "UNKNOWN",
        "unresolved_followup_gap_count": "UNKNOWN",
    }
    expected = set(unknown)
    if not isinstance(value, dict) or set(value) != expected:
        return unknown
    state = value.get("state")
    note_result = value.get("coverage_note_result")
    if (
        value.get("schema") != unknown["schema"]
        or not isinstance(state, str)
        or state not in {"OBSERVED", "UNKNOWN"}
        or not isinstance(note_result, str)
        or note_result not in {"COVERED", "NO_COVERING_NOTE", "NO_NOTES", "UNKNOWN"}
    ):
        return unknown

    def count_ok(item: Any, maximum: int = 10_000) -> bool:
        return item == "UNKNOWN" or (
            isinstance(item, int) and not isinstance(item, bool) and 0 <= item <= maximum
        )

    note_counts = value.get("coverage_note_failure_counts")
    quarantine_counts = value.get("required_output_quarantine_by_kind")
    if note_counts != "UNKNOWN" and (
        not isinstance(note_counts, dict) or set(note_counts) != _CLOSURE_NOTE_CODES
    ):
        return unknown
    if quarantine_counts != "UNKNOWN" and (
        not isinstance(quarantine_counts, dict) or set(quarantine_counts) != _CLOSURE_QUARANTINE_KINDS
    ):
        return unknown
    if (
        isinstance(note_counts, dict) and not all(count_ok(item) for item in note_counts.values())
    ) or (
        isinstance(quarantine_counts, dict) and not all(count_ok(item) for item in quarantine_counts.values())
    ) or (
        not count_ok(value.get("coverage_note_count"))
        or not count_ok(value.get("coverage_note_notes_examined_count"))
        or not count_ok(value.get("coverage_note_notes_unexamined_after_match_count"))
        or not count_ok(value.get("required_output_quarantine_count"))
        or not count_ok(value.get("unresolved_context_gap_count"))
        or not count_ok(value.get("unresolved_followup_gap_count"))
    ):
        return unknown
    if state == "OBSERVED":
        note_count = value["coverage_note_count"]
        examined = value["coverage_note_notes_examined_count"]
        unexamined = value["coverage_note_notes_unexamined_after_match_count"]
        quarantine_count = value["required_output_quarantine_count"]
        unresolved_gaps = value["unresolved_context_gap_count"]
        unresolved_followups = value["unresolved_followup_gap_count"]
        if (
            note_result == "UNKNOWN"
            or note_count == "UNKNOWN"
            or examined == "UNKNOWN"
            or unexamined == "UNKNOWN"
            or note_counts == "UNKNOWN"
            or quarantine_count == "UNKNOWN"
            or quarantine_counts == "UNKNOWN"
            or unresolved_gaps == "UNKNOWN"
            or unresolved_followups == "UNKNOWN"
            or any(item == "UNKNOWN" for item in note_counts.values())
            or any(item == "UNKNOWN" for item in quarantine_counts.values())
            or note_count != examined + unexamined
            or unresolved_followups > unresolved_gaps
            or sum(quarantine_counts.values()) != quarantine_count
        ):
            return unknown

        note_code_total = sum(
            count for code, count in note_counts.items() if code != "NO_COVERAGE_NOTES"
        )
        no_notes_sentinel = note_counts["NO_COVERAGE_NOTES"]
        if note_counts["UNKNOWN"] != 0 or note_counts["MATCH"] > 1:
            return unknown
        if note_count == 0:
            coherent_note_result = (
                note_result == "NO_NOTES"
                and examined == 0
                and unexamined == 0
                and note_code_total == 0
                and no_notes_sentinel == 1
            )
        else:
            matches = note_counts["MATCH"]
            coherent_note_result = (
                no_notes_sentinel == 0
                and note_code_total == examined
                and (
                    note_result == "COVERED"
                    and matches > 0
                    or note_result == "NO_COVERING_NOTE"
                    and matches == 0
                )
            )
        if not coherent_note_result:
            return unknown
    return {
        **value,
        "coverage_note_failure_counts": dict(note_counts) if isinstance(note_counts, dict) else "UNKNOWN",
        "required_output_quarantine_by_kind": dict(quarantine_counts) if isinstance(quarantine_counts, dict) else "UNKNOWN",
    }


def _project_context_followups(
    durable: dict[str, Any], *, include_closure_diagnostics: bool = False, include_handoff_observation: bool = False
) -> dict[str, Any]:
    """Project only bounded persisted follow-up metadata and ledger observations."""
    schema = (
        "context-followup-observation.v3"
        if include_handoff_observation
        else "context-followup-observation.v2"
        if include_closure_diagnostics
        else "context-followup-observation.v1"
    )
    ledger = durable.get("ledger")
    if not isinstance(ledger, dict):
        return {"schema": schema, "projection_state": "UNKNOWN", "reason": "LEDGER_NOT_SHOWN"}
    dynamic = ledger.get("dynamic_tasks")
    planned = ledger.get("planned_task_inputs")
    outputs = durable.get("task_results")
    gaps = durable.get("context_gaps")
    coverage = durable.get("coverage_ledger")
    budget_state = ledger.get("budget")
    if not all(isinstance(value, expected) for value, expected in (
        (dynamic, list), (planned, dict), (outputs, dict), (gaps, list), (coverage, list), (budget_state, dict)
    )):
        return {"schema": schema, "projection_state": "UNKNOWN", "reason": "DYNAMIC_LEDGER_FIELDS_NOT_SHOWN"}

    tasks = [
        item for item in dynamic
        if isinstance(item, dict) and ("context_followup" in item or isinstance(item.get("context_gap_followup_for"), str))
    ]
    gap_task_count = sum(1 for item in gaps if isinstance(item, dict) and isinstance(item.get("followup_task_id"), str))
    reservation_map = budget_state.get("reservations")
    settlement_map = budget_state.get("settlements")
    budget_maps_valid = isinstance(reservation_map, dict) and isinstance(settlement_map, dict)
    if not isinstance(reservation_map, dict):
        reservation_map = {}
    if not isinstance(settlement_map, dict):
        settlement_map = {}
    gap_by_id: dict[str, dict[str, Any]] = {}
    duplicate_gap_ids: set[str] = set()
    for item in gaps:
        key = item.get("proposal_id") if isinstance(item, dict) else None
        if isinstance(key, str):
            if key in gap_by_id:
                duplicate_gap_ids.add(key)
            gap_by_id[key] = item
    coverage_by_id: dict[str, dict[str, Any]] = {}
    duplicate_coverage_ids: set[str] = set()
    for item in coverage:
        key = item.get("obligation_id") if isinstance(item, dict) else None
        if isinstance(key, str):
            if key in coverage_by_id:
                duplicate_coverage_ids.add(key)
            coverage_by_id[key] = item
    partial = len(tasks) != gap_task_count or len(tasks) > 8 or bool(duplicate_gap_ids or duplicate_coverage_ids)
    rows: list[dict[str, Any]] = []
    for task in tasks[:8]:
        task_id = task.get("task_id")
        safe_task_id = _safe_followup_id(task_id)
        task_input = planned.get(task_id) if isinstance(task_id, str) else None
        task_output = outputs.get(task_id) if isinstance(task_id, str) else None
        metadata = task.get("context_followup")
        input_metadata = task_input.get("context_followup") if isinstance(task_input, dict) else None
        output_metadata = task_output.get("context_followup") if isinstance(task_output, dict) else None
        metadata_hash = _bounded_object_hash(metadata) if isinstance(metadata, dict) else None
        target = metadata.get("target") if isinstance(metadata, dict) else None
        target_kind = target.get("kind") if isinstance(target, dict) else None
        target_hash = _bounded_object_hash(target.get("value")) if isinstance(target, dict) and "value" in target else None
        rationale_hash = _bounded_object_hash(metadata.get("rationale")) if isinstance(metadata, dict) else None
        retrieved_ids = metadata.get("retrieved_evidence_ids") if isinstance(metadata, dict) else None
        metadata_shape_valid = (
            metadata_hash is not None
            and metadata.get("contract_version") == "context-followup.v1"
            and _safe_followup_id(metadata.get("proposal_id")) != "UNKNOWN"
            and _safe_followup_id(metadata.get("parent_task_id")) != "UNKNOWN"
            and _safe_followup_id(metadata.get("followup_obligation_id")) != "UNKNOWN"
            and isinstance(metadata.get("required_lens"), str) and metadata.get("required_lens") in _FOLLOWUP_LENSES
            and isinstance(target, dict) and set(target) == {"kind", "value"}
            and isinstance(target_kind, str) and target_kind in _FOLLOWUP_TARGET_KINDS
            and isinstance(target.get("value"), str) and target_hash is not None and rationale_hash is not None
            and isinstance(metadata.get("rationale"), str)
            and isinstance(retrieved_ids, list) and len(retrieved_ids) <= 100
            and all(_safe_followup_id(value) != "UNKNOWN" for value in retrieved_ids)
            and len(set(retrieved_ids)) == len(retrieved_ids)
        )
        metadata_copies_present = all(isinstance(value, dict) for value in (metadata, input_metadata, output_metadata))
        if metadata_shape_valid and metadata_copies_present and metadata == input_metadata == output_metadata:
            metadata_binding = "PERSISTED_RECORDS_MATCH"
        elif metadata_shape_valid and metadata_copies_present:
            metadata_binding = "PERSISTED_RECORDS_MISMATCH"
            partial = True
        else:
            metadata_binding = "UNKNOWN"
            partial = True

        task_bindings = task.get("unit_evidence_bindings")
        input_bindings = task_input.get("unit_evidence_bindings") if isinstance(task_input, dict) else None
        output_bindings = task_output.get("unit_evidence_bindings") if isinstance(task_output, dict) else None
        bindings_valid = (
            isinstance(task_bindings, list)
            and len(task_bindings) <= 100
            and all(
                isinstance(item, dict)
                and set(item) == {"unit_id", "binding_status", "evidence_ids"}
                and _safe_followup_id(item.get("unit_id")) != "UNKNOWN"
                and isinstance(item.get("binding_status"), str)
                and item.get("binding_status") in {"VERIFIED", "UNKNOWN"}
                and isinstance(item.get("evidence_ids"), list)
                and len(item["evidence_ids"]) <= 100
                and all(_safe_followup_id(ref) != "UNKNOWN" for ref in item["evidence_ids"])
                for item in task_bindings
            )
        )
        binding_hash = _bounded_object_hash(task_bindings) if bindings_valid else None
        bindings_copies_present = all(isinstance(value, list) for value in (task_bindings, input_bindings, output_bindings))
        if bindings_valid and bindings_copies_present and task_bindings == input_bindings == output_bindings:
            unit_binding = "PERSISTED_RECORDS_MATCH"
        elif bindings_valid and bindings_copies_present:
            unit_binding = "PERSISTED_RECORDS_MISMATCH"
            partial = True
        else:
            unit_binding = "UNKNOWN"
            partial = True

        proposal_id = metadata.get("proposal_id") if isinstance(metadata, dict) else None
        gap = gap_by_id.get(proposal_id) if isinstance(proposal_id, str) and proposal_id not in duplicate_gap_ids else None
        task_gap_marker = task.get("context_gap_followup_for")
        gap_task_id = gap.get("followup_task_id") if isinstance(gap, dict) else None
        if (
            isinstance(proposal_id, str)
            and isinstance(task_id, str)
            and isinstance(task_gap_marker, str)
            and isinstance(gap_task_id, str)
            and isinstance(gap, dict)
        ):
            gap_linkage = (
                "PERSISTED_RECORDS_MATCH"
                if task_gap_marker == proposal_id and gap_task_id == task_id
                else "PERSISTED_RECORDS_MISMATCH"
            )
            if gap_linkage != "PERSISTED_RECORDS_MATCH":
                partial = True
        else:
            gap_linkage = "UNKNOWN"
            partial = True
        gap_ids = gap.get("retrieved_evidence_ids") if isinstance(gap, dict) else None
        if (
            metadata_shape_valid
            and gap_linkage == "PERSISTED_RECORDS_MATCH"
            and isinstance(gap_ids, list)
            and isinstance(retrieved_ids, list)
        ):
            retrieval_binding = "PERSISTED_IDS_MATCH" if gap_ids == retrieved_ids else "PERSISTED_IDS_MISMATCH"
            if retrieval_binding == "PERSISTED_IDS_MISMATCH":
                partial = True
        else:
            retrieval_binding = "UNKNOWN"
        if retrieval_binding == "UNKNOWN":
            partial = True
        obligation_id = metadata.get("followup_obligation_id") if isinstance(metadata, dict) else None
        obligation = (
            coverage_by_id.get(obligation_id)
            if isinstance(obligation_id, str) and obligation_id not in duplicate_coverage_ids
            else None
        )
        obligation_task_ids = obligation.get("task_ids") if isinstance(obligation, dict) else None
        obligation_binding_fields_valid = (
            isinstance(obligation, dict)
            and isinstance(obligation.get("obligation_id"), str)
            and isinstance(obligation.get("obligation_kind"), str)
            and isinstance(obligation.get("context_gap_id"), str)
            and isinstance(obligation_task_ids, list)
            and len(obligation_task_ids) <= 100
            and all(isinstance(value, str) for value in obligation_task_ids)
        )
        if obligation_binding_fields_valid:
            obligation_binding = (
                "PERSISTED_RECORDS_MATCH"
                if obligation.get("obligation_id") == obligation_id
                and obligation.get("obligation_kind") == "REQUIRED_CONTEXT"
                and obligation.get("context_gap_id") == proposal_id
                and isinstance(task_id, str)
                and task_id in obligation_task_ids
                else "PERSISTED_RECORDS_MISMATCH"
            )
            if obligation_binding != "PERSISTED_RECORDS_MATCH":
                partial = True
        else:
            obligation_binding = "UNKNOWN"
            partial = True
        coverage_state = _safe_followup_enum(
            obligation.get("state") if obligation_binding == "PERSISTED_RECORDS_MATCH" else None,
            _FOLLOWUP_COVERAGE_STATES,
        )
        if coverage_state == "UNKNOWN":
            partial = True
        if include_closure_diagnostics:
            closure_raw = (
                obligation.get("closure_diagnostics")
                if obligation_binding == "PERSISTED_RECORDS_MATCH"
                else None
            )
            closure_diagnostics = _project_required_context_closure_diagnostics(closure_raw)
            if closure_diagnostics["state"] == "UNKNOWN":
                partial = True

        input_evidence_ids = task_output.get("input_evidence_ids") if isinstance(task_output, dict) else None
        input_evidence_valid = (
            isinstance(input_evidence_ids, list)
            and len(input_evidence_ids) <= 100
            and all(_safe_followup_id(value) != "UNKNOWN" for value in input_evidence_ids)
        )
        if not input_evidence_valid:
            partial = True

        outcome_status = _safe_followup_enum(task_output.get("status") if isinstance(task_output, dict) else None, _FOLLOWUP_TASK_STATUSES)
        if outcome_status == "UNKNOWN":
            partial = True

        handoff_state = "UNKNOWN"
        metadata_validation = "NOT_ASSESSED"
        constructed_evidence_ids: Any = None
        result_input_evidence_ids: Any = None
        if include_handoff_observation:
            metadata_validation = _followup_metadata_contract_state(metadata)
            constructed_evidence_ids = task.get("evidence_ids") if isinstance(task, dict) else None
            result_input_evidence_ids = task_output.get("input_evidence_ids") if isinstance(task_output, dict) else None
            constructed_contract = task.get("request_input_contract") if isinstance(task, dict) else None
            planned_contract = task_input.get("request_input_contract") if isinstance(task_input, dict) else None
            result_contract = task_output.get("request_input_contract") if isinstance(task_output, dict) else None
            contract_copies = (constructed_contract, planned_contract, result_contract)
            if any(isinstance(value, str) and value != "specialist-input.v2" for value in contract_copies):
                contract_binding = "MISMATCH"
            elif not all(isinstance(value, str) for value in contract_copies):
                contract_binding = "UNKNOWN"
            else:
                contract_binding = "MATCH"
            result_task_id = task_output.get("task_id") if isinstance(task_output, dict) else None
            retrieved_context = ledger.get("retrieved_context")
            retrieved_entry = (
                retrieved_context.get(proposal_id)
                if isinstance(retrieved_context, dict) and isinstance(proposal_id, str)
                else None
            )
            retrieved_entry_result = retrieved_entry.get("result") if isinstance(retrieved_entry, dict) else None
            retrieved_entry_evidence = retrieved_entry.get("evidence") if isinstance(retrieved_entry, dict) else None
            retrieved_entry_ids = (
                [item.get("evidence_id") for item in retrieved_entry_evidence]
                if isinstance(retrieved_entry_evidence, list)
                and len(retrieved_entry_evidence) <= 100
                and all(isinstance(item, dict) for item in retrieved_entry_evidence)
                else None
            )
            dynamic_obligations = ledger.get("dynamic_obligations")
            matching_dynamic_obligations = (
                [item for item in dynamic_obligations if isinstance(item, dict) and item.get("obligation_id") == obligation_id]
                if isinstance(dynamic_obligations, list) and isinstance(obligation_id, str)
                else []
            )
            dynamic_obligation = matching_dynamic_obligations[0] if len(matching_dynamic_obligations) == 1 else None
            if metadata_validation == "VALID":
                copies_available = all(isinstance(value, dict) for value in (metadata, input_metadata, output_metadata))
                lists_available = all(
                    _bounded_followup_evidence_ids(value)
                    for value in (
                        metadata.get("retrieved_evidence_ids"),
                        input_metadata.get("retrieved_evidence_ids") if isinstance(input_metadata, dict) else None,
                        output_metadata.get("retrieved_evidence_ids") if isinstance(output_metadata, dict) else None,
                        constructed_evidence_ids,
                        result_input_evidence_ids,
                    )
                )
                identity_available = isinstance(planned_contract, str) and isinstance(result_task_id, str)
                if copies_available and lists_available and identity_available:
                    if (
                        contract_binding == "MISMATCH"
                        or result_task_id != task_id
                        or metadata != input_metadata
                        or metadata != output_metadata
                    ):
                        handoff_state = "MISMATCH"
                    elif contract_binding != "MATCH":
                        handoff_state = "UNKNOWN"
                    elif retrieval_binding == "PERSISTED_IDS_MISMATCH" or gap_linkage == "PERSISTED_RECORDS_MISMATCH" or obligation_binding == "PERSISTED_RECORDS_MISMATCH":
                        handoff_state = "MISMATCH"
                    elif retrieval_binding != "PERSISTED_IDS_MATCH" or gap_linkage != "PERSISTED_RECORDS_MATCH" or obligation_binding != "PERSISTED_RECORDS_MATCH":
                        handoff_state = "UNKNOWN"
                    else:
                        retrieved = set(metadata["retrieved_evidence_ids"])
                        constructed = set(constructed_evidence_ids)
                        result_inputs = set(result_input_evidence_ids)
                        obligation_retrieved = dynamic_obligation.get("retrieved_evidence_ids") if isinstance(dynamic_obligation, dict) else None
                        obligation_fields_present = (
                            isinstance(dynamic_obligation, dict)
                            and isinstance(dynamic_obligation.get("obligation_id"), str)
                            and isinstance(dynamic_obligation.get("obligation_kind"), str)
                            and isinstance(dynamic_obligation.get("required"), bool)
                            and isinstance(dynamic_obligation.get("context_gap_id"), str)
                            and _bounded_followup_evidence_ids(obligation_retrieved)
                        )
                        obligation_fields_mismatch = (
                            isinstance(dynamic_obligation, dict)
                            and (
                                isinstance(dynamic_obligation.get("obligation_id"), str)
                                and dynamic_obligation.get("obligation_id") != obligation_id
                                or isinstance(dynamic_obligation.get("obligation_kind"), str)
                                and dynamic_obligation.get("obligation_kind") != "REQUIRED_CONTEXT"
                                or isinstance(dynamic_obligation.get("required"), bool)
                                and dynamic_obligation.get("required") is not True
                                or isinstance(dynamic_obligation.get("context_gap_id"), str)
                                and dynamic_obligation.get("context_gap_id") != proposal_id
                                or _bounded_followup_evidence_ids(obligation_retrieved)
                                and obligation_retrieved != metadata["retrieved_evidence_ids"]
                            )
                        )
                        entry_ids_valid = _bounded_followup_evidence_ids(retrieved_entry_ids)
                        entry_result_status = retrieved_entry_result.get("status") if isinstance(retrieved_entry_result, dict) else None
                        gap_status = gap.get("retrieval_status") if isinstance(gap, dict) else None
                        source_statuses = (gap_status, entry_result_status)
                        source_status_mismatch = any(
                            isinstance(value, str) and value != "RESOLVED" for value in source_statuses
                        )
                        source_status_missing = not all(isinstance(value, str) for value in source_statuses)
                        if source_status_mismatch or obligation_fields_mismatch:
                            handoff_state = "MISMATCH"
                        elif not obligation_fields_present or not entry_ids_valid or source_status_missing:
                            handoff_state = "UNKNOWN"
                        elif (
                            obligation_retrieved != metadata["retrieved_evidence_ids"]
                            or retrieved_entry_ids != metadata["retrieved_evidence_ids"]
                        ):
                            handoff_state = "MISMATCH"
                        else:
                            handoff_state = (
                                "VERIFIED"
                                if retrieved.issubset(constructed)
                                and result_inputs.issubset(constructed)
                                and retrieved.issubset(result_inputs)
                                else "MISMATCH"
                            )
                elif contract_binding == "MISMATCH" or (
                    isinstance(result_task_id, str) and result_task_id != task_id
                ):
                    handoff_state = "MISMATCH"
            if metadata_validation != "VALID" or handoff_state != "VERIFIED":
                partial = True
        provenance = task_output.get("provenance") if isinstance(task_output, dict) else None
        request_hash = provenance.get("request_hash") if isinstance(provenance, dict) else None
        response_hash = provenance.get("response_hash") if isinstance(provenance, dict) else None
        if not (isinstance(request_hash, str) and _CLAIM_DIMENSION_HASH.fullmatch(request_hash)):
            request_hash = "UNKNOWN"
        if not (isinstance(response_hash, str) and _CLAIM_DIMENSION_HASH.fullmatch(response_hash)):
            response_hash = "UNKNOWN"
        http_status = provenance.get("http_status") if isinstance(provenance, dict) else None
        if not (isinstance(http_status, int) and not isinstance(http_status, bool) and 100 <= http_status <= 599):
            http_status = "UNKNOWN"

        reservation_keys = [key for key in reservation_map if isinstance(key, str) and isinstance(task_id, str) and key.startswith(task_id + ":review:")]
        reserved_calls = 0
        reservations_with_settlement = 0
        settlement_statuses: list[str] = []
        row_budget_valid = budget_maps_valid
        for key in reservation_keys:
            reservation = reservation_map.get(key)
            count = reservation.get("provider_calls") if isinstance(reservation, dict) else None
            if not (isinstance(count, int) and not isinstance(count, bool) and 0 <= count <= 1):
                row_budget_valid = False
                continue
            reserved_calls += count
            settlement = settlement_map.get(key)
            if isinstance(settlement, dict):
                status = _safe_followup_enum(settlement.get("status"), _FOLLOWUP_SETTLEMENT_STATUSES)
                if status == "UNKNOWN":
                    row_budget_valid = False
                else:
                    settlement_statuses.append(status)
                    reservations_with_settlement += count
            else:
                settlement_statuses.append("UNSETTLED")
        if not row_budget_valid:
            partial = True

        row = {
            "task_id": safe_task_id,
            "proposal_id": _safe_followup_id(proposal_id),
            "parent_task_id": _safe_followup_id(metadata.get("parent_task_id") if isinstance(metadata, dict) else None),
            "followup_obligation_id": _safe_followup_id(obligation_id),
            "contract_version": "context-followup.v1" if isinstance(metadata, dict) and metadata.get("contract_version") == "context-followup.v1" else "UNKNOWN",
            "metadata_contract_validation": "NOT_ASSESSED",
            "required_lens": _safe_followup_enum(metadata.get("required_lens") if isinstance(metadata, dict) else None, _FOLLOWUP_LENSES),
            "target_kind": target_kind if isinstance(target_kind, str) and target_kind in _FOLLOWUP_TARGET_KINDS else "UNKNOWN",
            "metadata_sha256": metadata_hash or "UNKNOWN",
            "target_value_sha256": target_hash or "UNKNOWN",
            "rationale_sha256": rationale_hash or "UNKNOWN",
            "persisted_metadata_binding": metadata_binding,
            "unit_evidence_binding_sha256": binding_hash or "UNKNOWN",
            "persisted_unit_binding": unit_binding,
            "unit_binding_count": len(task_bindings) if bindings_valid else "UNKNOWN",
            "unit_binding_evidence_count": sum(len(item["evidence_ids"]) for item in task_bindings) if bindings_valid else "UNKNOWN",
            "dispatched_input_evidence_count": len(input_evidence_ids) if input_evidence_valid else "UNKNOWN",
            "dispatched_input_evidence_ids_sha256": _bounded_object_hash(input_evidence_ids) if input_evidence_valid else "UNKNOWN",
            "persisted_gap_task_binding": _safe_followup_enum(gap_linkage, _FOLLOWUP_LINK_STATES),
            "retrieved_evidence_count": len(retrieved_ids) if isinstance(retrieved_ids, list) else "UNKNOWN",
            "retrieved_evidence_ids_sha256": _bounded_object_hash(retrieved_ids) if isinstance(retrieved_ids, list) else "UNKNOWN",
            "persisted_retrieval_binding": retrieval_binding,
            "retrieval_status": _safe_followup_enum(gap.get("retrieval_status") if isinstance(gap, dict) else None, frozenset({"RESOLVED", "PARTIAL", "UNRESOLVED"})),
            "task_status": outcome_status,
            "persisted_obligation_binding": _safe_followup_enum(obligation_binding, _FOLLOWUP_LINK_STATES),
            "coverage_state": coverage_state,
            "adapter_request_hash": request_hash,
            "adapter_response_hash": response_hash,
            "adapter_http_status": http_status,
            "delivery_binding": "UNKNOWN",
            "provider_calls_reserved": reserved_calls if row_budget_valid else "UNKNOWN",
            "provider_call_reservations_with_settlement": reservations_with_settlement if row_budget_valid else "UNKNOWN",
            "actual_provider_calls": "UNKNOWN",
            "reservation_count": len(reservation_keys) if row_budget_valid else "UNKNOWN",
            "settlement_count": sum(1 for key in reservation_keys if key in settlement_map) if row_budget_valid else "UNKNOWN",
            "settlement_statuses": sorted(set(settlement_statuses)) if row_budget_valid else ["UNKNOWN"],
        }
        if include_closure_diagnostics:
            row["required_context_closure_diagnostics"] = closure_diagnostics
        if include_handoff_observation:
            row.update(
                {
                    "metadata_contract_validation": metadata_validation,
                    "retrieved_evidence_handoff_binding": _safe_followup_enum(handoff_state, _FOLLOWUP_HANDOFF_STATES),
                    "constructed_task_evidence_count": (
                        len(constructed_evidence_ids)
                        if _bounded_followup_evidence_ids(constructed_evidence_ids)
                        else "UNKNOWN"
                    ),
                    "constructed_task_evidence_ids_sha256": (
                        _bounded_object_hash(constructed_evidence_ids)
                        if _bounded_followup_evidence_ids(constructed_evidence_ids)
                        else "UNKNOWN"
                    ) or "UNKNOWN",
                    "task_result_input_evidence_count": (
                        len(result_input_evidence_ids)
                        if _bounded_followup_evidence_ids(result_input_evidence_ids)
                        else "UNKNOWN"
                    ),
                    "task_result_input_evidence_ids_sha256": (
                        _bounded_object_hash(result_input_evidence_ids)
                        if _bounded_followup_evidence_ids(result_input_evidence_ids)
                        else "UNKNOWN"
                    ) or "UNKNOWN",
                }
            )
        rows.append(row)
    if not tasks:
        projection_state = "NO_FOLLOWUP_TASKS_RECORDED" if gap_task_count == 0 else "PARTIAL"
    else:
        projection_state = "PARTIAL" if partial else "OBSERVED_WITH_LIMITATIONS"
    limitations = [
        "PERSISTED_METADATA_MATCH_DOES_NOT_PROVE_DISPATCH",
        "METADATA_CONTRACT_VALIDATION_NOT_PERFORMED",
        "FOLLOWUP_REQUEST_BODY_NOT_RETAINED",
        "PERSISTED_RETRIEVAL_ID_MATCH_DOES_NOT_PROVE_DELIVERY",
        "PERSISTED_GAP_AND_OBLIGATION_LINKS_ARE_STRUCTURAL_ONLY",
        "BUDGET_SETTLEMENT_IS_NOT_ACTUAL_PROVIDER_CALL_RECEIPT",
        "TASK_SUCCESS_DOES_NOT_PROVE_REQUIRED_CONTEXT_COVERAGE",
    ]
    if include_handoff_observation:
        limitations[1] = "METADATA_CONTRACT_VALIDATION_IS_SHAPE_ONLY"
        limitations.append("PERSISTED_HANDOFF_BINDING_DOES_NOT_PROVE_TRANSPORT_DELIVERY")
        limitations.append("UNIT_EVIDENCE_BINDING_VALIDITY_NOT_ASSESSED")
    return {
        "schema": schema,
        "projection_state": projection_state,
        "observed_followup_task_count": len(tasks),
        "projected_followup_task_count": len(rows),
        "omitted_followup_task_count": max(0, len(tasks) - len(rows)),
        "retrieval_followup_link_count": gap_task_count,
        "rows": rows,
        "delivery_binding": "UNKNOWN",
        "limitations": limitations,
    }


def _project_required_context_coverage_diagnostic(
    case_projection: dict[str, Any], durable: Any
) -> dict[str, Any]:
    """Join case projection rows to the corresponding in-memory durable records."""
    unknown = {
        "schema": "required-context-coverage-diagnostic.v1",
        "projection_state": "UNKNOWN",
        "case_id": "UNKNOWN",
        "base_sha": "UNKNOWN",
        "head_sha": "UNKNOWN",
        "source_followup_projection_schema": "UNKNOWN",
        "source_followup_projection_state": "UNKNOWN",
        "followup_source_completeness": "UNKNOWN",
        "observed_followup_task_count": "UNKNOWN",
        "projected_followup_task_count": "UNKNOWN",
        "omitted_followup_task_count": "UNKNOWN",
        "coverage_source_completeness": "UNKNOWN",
        "observed_required_context_row_count": "UNKNOWN",
        "projected_required_context_row_count": 0,
        "omitted_required_context_row_count": "UNKNOWN",
        "malformed_coverage_row_count": "UNKNOWN",
        "rows": [],
        "limitations": [
            "NOTE_TEXT_NOT_RETAINED",
            "PROJECTION_DOES_NOT_RECOMPUTE_COVERAGE_DECISIONS",
            "FOLLOWUP_HANDOFF_DOES_NOT_PROVE_COVERAGE",
        ],
    }
    durable_ledger = durable.get("ledger") if isinstance(durable, dict) else None
    coverage_source_rows = durable.get("coverage_ledger") if isinstance(durable, dict) else None
    if not isinstance(durable_ledger, dict) or not isinstance(durable.get("task_results"), dict):
        return unknown
    coverage = case_projection.get("coverage_ledger") if isinstance(case_projection, dict) else None
    if (
        not isinstance(coverage, list)
        or len(coverage) > _REQUIRED_CONTEXT_DIAGNOSTIC_MAX_ROWS
        or not isinstance(coverage_source_rows, list)
        or len(coverage_source_rows) > 10_000
    ):
        return unknown

    case_id = case_projection.get("case_id") if isinstance(case_projection, dict) else None
    base_sha = case_projection.get("base_sha") if isinstance(case_projection, dict) else None
    head_sha = case_projection.get("head_sha") if isinstance(case_projection, dict) else None
    safe_case_id = case_id if isinstance(case_id, str) and re.fullmatch(r"PR-[0-9]{1,12}", case_id) else "UNKNOWN"
    safe_base_sha = base_sha if isinstance(base_sha, str) and re.fullmatch(r"[0-9a-f]{40}", base_sha) else "UNKNOWN"
    safe_head_sha = head_sha if isinstance(head_sha, str) and re.fullmatch(r"[0-9a-f]{40}", head_sha) else "UNKNOWN"
    if "UNKNOWN" in {safe_case_id, safe_base_sha, safe_head_sha}:
        return unknown

    coverage_source_is_complete = (
        len(coverage_source_rows) < _REQUIRED_CONTEXT_DIAGNOSTIC_MAX_ROWS
        and all(isinstance(row, dict) for row in coverage_source_rows)
        and _project_coverage(coverage_source_rows) == coverage
    )

    required_rows = [
        row for row in coverage
        if isinstance(row, dict) and row.get("obligation_kind") == "REQUIRED_CONTEXT"
    ]
    known_obligation_kinds = {"CHANGED_UNIT_LENS", "PROJECT_CHECK", "REQUIRED_CONTEXT", "POLICY_LENS"}
    malformed_count = sum(
        1
        for row in coverage_source_rows
        if not isinstance(row, dict) or row.get("obligation_kind") not in known_obligation_kinds
    )
    coverage_source_completeness = "COMPLETE" if coverage_source_is_complete else "UNKNOWN"
    followup_projection = case_projection.get("context_followup_observations") if isinstance(case_projection, dict) else None
    followup_rows = (
        followup_projection.get("rows")
        if isinstance(followup_projection, dict)
        and followup_projection.get("schema") == "context-followup-observation.v3"
        else None
    )
    followup_projection_available = (
        isinstance(followup_rows, list)
        and len(followup_rows) <= _REQUIRED_CONTEXT_FOLLOWUP_SOURCE_MAX_ROWS
    )
    followup_state = (
        followup_projection.get("projection_state")
        if isinstance(followup_projection, dict)
        else "UNKNOWN"
    )
    observed_followups = (
        followup_projection.get("observed_followup_task_count")
        if isinstance(followup_projection, dict)
        else None
    )
    projected_followups = (
        followup_projection.get("projected_followup_task_count")
        if isinstance(followup_projection, dict)
        else None
    )
    omitted_followups = (
        followup_projection.get("omitted_followup_task_count")
        if isinstance(followup_projection, dict)
        else None
    )
    followup_counts_valid = (
        all(
            isinstance(value, int) and not isinstance(value, bool) and value >= 0
            for value in (observed_followups, projected_followups, omitted_followups)
        )
        and followup_projection_available
        and projected_followups == len(followup_rows)
        and observed_followups == projected_followups + omitted_followups
        and projected_followups <= _REQUIRED_CONTEXT_FOLLOWUP_SOURCE_MAX_ROWS
    )
    followup_source_is_complete = (
        followup_projection_available
        and followup_counts_valid
        and omitted_followups == 0
        and followup_state in {"OBSERVED_WITH_LIMITATIONS", "NO_FOLLOWUP_TASKS_RECORDED"}
        and (
            followup_state != "NO_FOLLOWUP_TASKS_RECORDED"
            or (observed_followups == 0 and projected_followups == 0)
        )
    )
    if not followup_projection_available:
        followup_rows = []
    rows: list[dict[str, Any]] = []
    partial = bool(
        malformed_count
        or len(required_rows) > _REQUIRED_CONTEXT_DIAGNOSTIC_MAX_ROWS
        or coverage_source_completeness == "UNKNOWN"
        or not followup_source_is_complete
    )
    duplicate_obligations: set[str] = set()
    seen_obligations: set[str] = set()
    for item in required_rows:
        obligation_id = item.get("obligation_id")
        if isinstance(obligation_id, str):
            if obligation_id in seen_obligations:
                duplicate_obligations.add(obligation_id)
            seen_obligations.add(obligation_id)

    for item in required_rows[:_REQUIRED_CONTEXT_DIAGNOSTIC_MAX_ROWS]:
        obligation_id_raw = item.get("obligation_id")
        obligation_id = _safe_followup_id(obligation_id_raw)
        if obligation_id == "UNKNOWN" or obligation_id in duplicate_obligations:
            partial = True
        state = _safe_followup_enum(item.get("state"), _FOLLOWUP_COVERAGE_STATES)
        reason_raw = item.get("reason_code")
        reason_code = (
            reason_raw
            if isinstance(reason_raw, str) and reason_raw in _REQUIRED_CONTEXT_COVERAGE_REASONS
            else "UNKNOWN"
        )
        if state == "UNKNOWN" or reason_code == "UNKNOWN":
            partial = True

        task_ids_raw = item.get("task_ids")
        task_ids_valid = (
            isinstance(task_ids_raw, list)
            and len(task_ids_raw) <= 100
            and all(_safe_followup_id(task_id) != "UNKNOWN" for task_id in task_ids_raw)
            and len(task_ids_raw) == len(set(task_ids_raw))
        )
        task_ids = list(task_ids_raw) if task_ids_valid else []
        if not task_ids_valid:
            partial = True

        same_obligation = [
            row for row in followup_rows
            if isinstance(row, dict) and row.get("followup_obligation_id") == obligation_id
        ] if obligation_id != "UNKNOWN" else []
        task_rows = [
            row for row in followup_rows
            if isinstance(row, dict) and row.get("task_id") in task_ids
        ]
        task_row_ids = [row.get("task_id") for row in same_obligation if isinstance(row.get("task_id"), str)]
        if (
            obligation_id == "UNKNOWN"
            or obligation_id in duplicate_obligations
            or not task_ids_valid
            or not followup_source_is_complete
        ):
            followup_binding = "UNKNOWN"
        elif same_obligation:
            if (
                any(_safe_followup_id(row.get("task_id")) == "UNKNOWN" for row in same_obligation)
                or len(task_row_ids) != len(set(task_row_ids))
            ):
                followup_binding = "UNKNOWN"
            elif set(task_row_ids) != set(task_ids):
                followup_binding = "MISMATCH"
            elif any(row.get("followup_obligation_id") != obligation_id for row in task_rows):
                followup_binding = "MISMATCH"
            else:
                followup_binding = "MATCH"
        elif task_rows:
            followup_binding = "MISMATCH"
        elif any(":followup:" in task_id for task_id in task_ids):
            followup_binding = "UNKNOWN"
        elif not followup_projection_available:
            followup_binding = "UNKNOWN"
        else:
            followup_binding = "NOT_APPLICABLE"
        if followup_binding in {"UNKNOWN", "MISMATCH"}:
            partial = True

        linked_rows = same_obligation if followup_binding == "MATCH" else []
        linked_closures = [
            _project_required_context_closure_diagnostics(row.get("required_context_closure_diagnostics"))
            for row in linked_rows
        ]
        if linked_closures and all(value == linked_closures[0] for value in linked_closures):
            closure = linked_closures[0]
            closure_binding = "MATCH" if closure["state"] != "UNKNOWN" else "UNKNOWN"
        elif linked_closures:
            closure = _project_required_context_closure_diagnostics(None)
            closure_binding = "MISMATCH"
        else:
            closure = _project_required_context_closure_diagnostics(None)
            closure_binding = "UNKNOWN"
        if closure_binding != "MATCH":
            partial = True

        linked_followups = [
            {
                "task_id": _safe_followup_id(row.get("task_id")),
                "task_status": _safe_followup_enum(row.get("task_status"), _FOLLOWUP_TASK_STATUSES),
                "handoff_binding": _safe_followup_enum(
                    row.get("retrieved_evidence_handoff_binding"), _FOLLOWUP_HANDOFF_STATES
                ),
            }
            for row in linked_rows
        ]
        if any(
            row["task_id"] == "UNKNOWN"
            or row["task_status"] == "UNKNOWN"
            or row["handoff_binding"] == "UNKNOWN"
            for row in linked_followups
        ):
            partial = True

        rows.append({
            "obligation_id": obligation_id,
            "coverage_state": state,
            "coverage_reason_code": reason_code,
            "task_ids": task_ids if task_ids_valid else "UNKNOWN",
            "followup_observation_binding": followup_binding,
            "closure_observation_binding": closure_binding,
            "linked_followups": linked_followups,
            "closure_diagnostics": closure,
        })

    omitted = max(0, len(required_rows) - len(rows))
    return {
        "schema": "required-context-coverage-diagnostic.v1",
        "projection_state": (
            "PARTIAL" if partial
            else "NOT_APPLICABLE" if not required_rows
            else "OBSERVED"
        ),
        "case_id": safe_case_id,
        "base_sha": safe_base_sha,
        "head_sha": safe_head_sha,
        "source_followup_projection_schema": (
            "context-followup-observation.v3" if followup_projection_available else "UNKNOWN"
        ),
        "source_followup_projection_state": (
            followup_state
            if isinstance(followup_state, str)
            and followup_state in {
                "OBSERVED_WITH_LIMITATIONS", "PARTIAL", "NO_FOLLOWUP_TASKS_RECORDED", "UNKNOWN"
            }
            else "UNKNOWN"
        ),
        "followup_source_completeness": "COMPLETE" if followup_source_is_complete else "UNKNOWN",
        "observed_followup_task_count": observed_followups if followup_counts_valid else "UNKNOWN",
        "projected_followup_task_count": projected_followups if followup_counts_valid else "UNKNOWN",
        "omitted_followup_task_count": omitted_followups if followup_counts_valid else "UNKNOWN",
        "coverage_source_completeness": coverage_source_completeness,
        "observed_required_context_row_count": len(required_rows),
        "projected_required_context_row_count": len(rows),
        "omitted_required_context_row_count": omitted,
        "malformed_coverage_row_count": malformed_count,
        "rows": rows,
        "limitations": [
            "NOTE_TEXT_NOT_RETAINED",
            "PROJECTION_DOES_NOT_RECOMPUTE_COVERAGE_DECISIONS",
            "FOLLOWUP_HANDOFF_DOES_NOT_PROVE_COVERAGE",
        ],
    }


def primary_receipts(prepared: dict[str, Any], input_contract: str = "specialist-input-v1") -> Any:
    value = prepared["value"]
    snapshot = value["snapshot"]
    if input_contract == "specialist-input-v2":
        evidence_index: dict[str, dict[str, Any]] = {}
        requests = []
        for row in value["primary_requests"]:
            request = {key: item for key, item in row.items() if key != "evidence_bindings"}
            request["snapshot_hash"] = snapshot["snapshot_hash"]
            bindings = row.get("evidence_bindings")
            if not isinstance(bindings, list):
                raise TrialError("v2_evidence_binding_receipt_invalid")
            for binding in bindings:
                if not isinstance(binding, dict) or not isinstance(binding.get("evidence_id"), str):
                    raise TrialError("v2_evidence_binding_receipt_invalid")
                evidence_id = binding["evidence_id"]
                previous = evidence_index.get(evidence_id)
                if previous is not None and previous != binding:
                    raise TrialError("v2_evidence_binding_metadata_conflict")
                evidence_index[evidence_id] = binding
            if any(evidence_id not in evidence_index for evidence_id in row.get("evidence_ids", [])):
                raise TrialError("v2_evidence_binding_receipt_incomplete")
            requests.append(request)
        return {
            "schema": "specialist-input-v2-primary-receipts.v1",
            "evidence_index": {key: evidence_index[key] for key in sorted(evidence_index)},
            "requests": requests,
        }
    if input_contract != "specialist-input-v1":
        raise TrialError("input_contract_invalid")
    return [
        {
            "task_id": row["task_id"],
            "lens": row["lens"],
            "unit_ids": row["unit_ids"],
            "obligation_ids": row["obligation_ids"],
            "evidence_ids": row["evidence_ids"],
            "input_bytes": row["input_bytes"],
            "input_sha256": row["input_sha256"],
            "snapshot_hash": snapshot["snapshot_hash"],
        }
        for row in value["primary_requests"]
    ]


def _primary_receipts_for_contract(prepared: dict[str, Any], input_contract: str) -> Any:
    # Keep the historical v1 call shape stable for existing integrations.
    primary_contract = _primary_input_contract(input_contract)
    if primary_contract == "specialist-input-v1":
        return primary_receipts(prepared)
    return primary_receipts(prepared, primary_contract)


def _scan(value: Any, secrets: list[str], limit: int = OUTPUT_CAP) -> bytes:
    raw = canonical(value)
    if len(raw) > limit:
        raise TrialError("sanitized_projection_limit_exceeded")

    def contains_secret(item: Any) -> bool:
        if isinstance(item, str):
            return any(secret and secret in item for secret in secrets)
        if isinstance(item, dict):
            return any(contains_secret(key) or contains_secret(child) for key, child in item.items())
        if isinstance(item, (list, tuple)):
            return any(contains_secret(child) for child in item)
        return False

    # Scan decoded strings so JSON escaping (quotes, backslashes, or non-ASCII
    # characters) cannot hide a configured credential from the byte-level scan.
    if contains_secret(value):
        raise TrialError("credential_scan_failed")
    return raw


def project_case(
    case: dict[str, Any], durable: dict[str, Any], secrets: list[str], *, include_context_followups: bool = False,
    include_closure_diagnostics: bool = False, include_context_handoff: bool = False,
    include_required_context_coverage_diagnostic: bool = False,
) -> dict[str, Any]:
    findings = durable.get("findings")
    records = durable.get("ledger", {}).get("candidate_records") if isinstance(durable.get("ledger"), dict) else None
    if not isinstance(records, list):
        raise TrialError("candidate_records_missing")
    if not isinstance(findings, list) or len(records) > 100:
        raise TrialError("candidate_projection_incomplete")
    finding_by_candidate = {
        item.get("candidate_id"): item
        for item in findings
        if isinstance(item, dict) and isinstance(item.get("candidate_id"), str)
    }
    jev = durable.get("advisory_assessment")
    claims = durable.get("claim_assessments")
    if not isinstance(claims, list):
        claims = []
    claims_by_candidate = {
        item.get("candidate_id"): item
        for item in claims
        if isinstance(item, dict) and isinstance(item.get("candidate_id"), str)
    }
    candidates = []
    candidate_projection_complete = True
    for record in records:
        if not isinstance(record, dict):
            raise TrialError("candidate_record_invalid")
        raw = record.get("raw") if isinstance(record.get("raw"), dict) else {}
        if not raw:
            candidate_projection_complete = False
        finding = finding_by_candidate.get(record.get("candidate_id"), {})
        if not isinstance(finding, dict):
            finding = {}
        location = raw.get("location") if isinstance(raw.get("location"), dict) else {}
        raw_refs = raw.get("evidence_refs") if isinstance(raw.get("evidence_refs"), list) else []
        finding_refs = finding.get("evidence_refs") if isinstance(finding.get("evidence_refs"), list) else []
        refs = sorted({ref for ref in [*raw_refs, *finding_refs] if isinstance(ref, str)})
        candidates.append(
            {
                "candidate_id": record.get("candidate_id", "UNKNOWN"),
                "finding_id": record.get("finding_id", "UNKNOWN"),
                "validation_state": record.get("validation_state", "UNKNOWN"),
                "validation_reason": record.get("validation_reason", "UNKNOWN"),
                "title": raw.get("title", "UNKNOWN"),
                "observation": raw.get("observation", "UNKNOWN"),
                "consequence": raw.get("consequence", "UNKNOWN"),
                "rule_or_contract": raw.get("rule_or_contract", "UNKNOWN"),
                "recommendation": {
                    "status": finding.get("status", "UNKNOWN"),
                    "blocking_class": finding.get("blocking_class", "UNKNOWN"),
                    "rationale": finding.get("blocking_rationale", "UNKNOWN"),
                    "introducedness": finding.get("introducedness", "UNKNOWN"),
                },
                "semantic_assessment": _project_semantic_assessment(finding.get("semantic_assessment")),
                "unit_id": raw.get("unit_id", "UNKNOWN"),
                "location": {key: location.get(key) for key in ("kind", "path", "line", "start_line", "end_line")},
                "evidence_refs": refs[:100],
                "reconciliation_status": finding.get("status", "UNKNOWN"),
                "claim_assessment": _project_claim(claims_by_candidate.get(record.get("candidate_id"))),
            }
        )
    evidence_index = durable.get("evidence_index")
    if not isinstance(evidence_index, dict):
        evidence_index = {}
    profile = None
    profile_path = case.get("profile_path")
    if isinstance(profile_path, str) and _safe_relative(profile_path):
        candidate = INPUT_ROOT / profile_path
        if (
            candidate.is_file()
            and not candidate.is_symlink()
            and sha256(candidate.read_bytes()) == case.get("profile_sha256")
        ):
            profile = read_json(candidate)
    task_outputs = durable.get("task_results") if isinstance(durable.get("task_results"), dict) else {}
    projection = {
        "case_id": case["case_id"],
        "historical_only": True,
        "pull_request_number": case["pull_request_number"],
        "base_sha": case["base_sha"],
        "head_sha": case["head_sha"],
        "disposition": durable.get("disposition", "UNKNOWN"),
        "coverage_state": durable.get("coverage_state", "UNKNOWN"),
        "freshness": "NOT_CURRENTLY_CHECKED_HISTORICAL_INPUT",
        "freshness_basis": "HISTORICAL_SNAPSHOT",
        "provider_identity": _project_identity(durable.get("provider_identity")),
        "candidate_projection_status": "COMPLETE" if candidate_projection_complete else "PARTIAL",
        "candidate_count": len(candidates),
        "candidates": candidates,
        "advisory_assessment": _project_jev(jev),
        "budget": _project_budget(durable.get("budget")),
        "coverage_ledger": _project_coverage(durable.get("coverage_ledger")),
        "context_gaps": _project_gaps(durable.get("context_gaps"), profile, task_outputs),
        "snapshot_gaps": _project_snapshot_gaps(durable.get("snapshot_gaps")),
        "evidence_index": _project_evidence_index(evidence_index, candidates),
    }
    if include_context_followups or include_context_handoff:
        projection["context_followup_observations"] = _project_context_followups(
            durable,
            include_closure_diagnostics=include_closure_diagnostics or include_context_handoff,
            include_handoff_observation=include_context_handoff,
        )
    if include_required_context_coverage_diagnostic:
        diagnostic_input = projection
        if not include_context_handoff:
            diagnostic_input = {
                **projection,
                "context_followup_observations": _project_context_followups(
                    durable, include_closure_diagnostics=True, include_handoff_observation=True
                ),
            }
        projection["required_context_coverage_diagnostic"] = _project_required_context_coverage_diagnostic(
            diagnostic_input, durable
        )
    _scan(projection, secrets)
    return projection


def project_case_for_contract(
    case: dict[str, Any], durable: dict[str, Any], secrets: list[str], input_contract: str
) -> dict[str, Any]:
    """Apply only the explicitly versioned projection selected by the experiment."""
    if _is_context_followup_v3(input_contract):
        return project_case(case, durable, secrets, include_context_handoff=True)
    if _is_context_followup_v2(input_contract):
        return project_case(case, durable, secrets, include_context_followups=True, include_closure_diagnostics=True)
    if _is_context_followup_experiment(input_contract):
        return project_case(case, durable, secrets, include_context_followups=True)
    return project_case(case, durable, secrets)


def _project_identity(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {"status": "UNKNOWN"}
    safe = {
        key: value.get(key)
        for key in ("provider_id", "native_contract", "adapter_version", "specialist_contract", "adjudication_contract")
        if isinstance(value.get(key), str)
    }
    safe["identity_sha256"] = sha256(canonical(value))
    return safe


def _project_claim(value: Any) -> dict[str, Any]:
    has_record = isinstance(value, dict)
    if not isinstance(value, dict):
        value = {"status": "NOT_RUN"}
    raw_status = value.get("status")
    row_status_valid = isinstance(raw_status, str) and raw_status in _CLAIM_ROW_STATUSES
    status = raw_status if row_status_valid else "UNKNOWN"
    contract_version = value.get("contract_version")
    contract_valid = isinstance(contract_version, str) and contract_version in _CLAIM_CONTRACT_VERSIONS
    candidate_id = _project_claim_id(value.get("candidate_id"))
    identity_valid = not has_record or (row_status_valid and contract_valid and candidate_id != "UNKNOWN")
    if not identity_valid:
        status = "UNKNOWN"
    result: dict[str, Any] = {
        "status": status,
        "candidate_id": candidate_id,
    }
    if contract_valid:
        result["contract_version"] = contract_version
    reason_code = value.get("reason_code")
    if isinstance(reason_code, str):
        result["reason_code"] = reason_code if reason_code in _SAFE_CLAIM_REASON_CODES else "UNKNOWN"
    if "error_code" in value:
        error_code = value.get("error_code")
        result["error_code"] = error_code if isinstance(error_code, str) and error_code in _SAFE_CLAIM_ERROR_CODES else "UNKNOWN"
    assessments = value.get("assessments")
    dimensions, projection_complete = _project_claim_dimensions(assessments)
    result["dimensions"] = dimensions
    result["dimension_projection_status"] = "COMPLETE" if projection_complete and identity_valid else "PARTIAL"
    if status == "COMPLETE" and isinstance(assessments, dict) and any(
        not isinstance(item, dict)
        or item.get("status") not in {"ANSWERED", "NOT_SHOWN"}
        or (item.get("status") == "NOT_SHOWN" and dimension != "introducedness")
        for dimension, item in assessments.items()
    ):
        result["dimension_projection_status"] = "PARTIAL"
    if isinstance(value.get("projection_valid"), bool):
        result["projection_valid"] = value["projection_valid"]
    provenance = value.get("provenance")
    if isinstance(provenance, dict):
        result["identity"] = {
            key: provenance[key]
            for key in ("provider_id", "native_contract", "contract_version", "model_identity_source")
            if isinstance(provenance.get(key), str) and len(provenance[key]) <= 80
        }
        result["identity"]["provider_model_sha256"] = sha256(canonical(provenance.get("provider_model_id")))
    return result


_CLAIM_ROW_STATUSES = frozenset(
    {"COMPLETE", "PARTIAL", "FAILED", "NOT_RUN", "INTERRUPTED_UNKNOWN", "PREPARING", "RESERVED", "DISPATCHING"}
)
_CLAIM_CONTRACT_VERSIONS = frozenset({"claim-assessment.1", "claim-assessment.2"})
_CLAIM_DIMENSION_CHOICES = {
    "observation_support": frozenset({"SUPPORTED", "NOT_ESTABLISHED", "CONTRADICTED", "UNCERTAIN"}),
    "consequence_support": frozenset({"SUPPORTED", "NOT_ESTABLISHED", "CONTRADICTED", "UNCERTAIN"}),
    "rule_connection_support": frozenset({"SUPPORTED", "NOT_ESTABLISHED", "CONTRADICTED", "UNCERTAIN"}),
    "materiality": frozenset({"MATERIAL", "NOT_MATERIAL", "NOT_ESTABLISHED", "UNCERTAIN"}),
    "missing_context": frozenset({"MISSING_CONTEXT_IDENTIFIED", "NO_MISSING_CONTEXT_IDENTIFIED", "UNCERTAIN"}),
    "introducedness": frozenset({"INTRODUCED", "REEXPOSED", "PRE_EXISTING", "UNKNOWN"}),
}
_CLAIM_ANSWER_STATUSES = frozenset({"NOT_RUN", "NOT_SHOWN", "ANSWERED", "OMITTED", "INVALID", "FAILED"})
_CLAIM_DIMENSION_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,255}\Z")
_CLAIM_DIMENSION_HASH = re.compile(r"[0-9a-f]{64}\Z")
def _project_claim_id(value: Any) -> str:
    return value if isinstance(value, str) and _CLAIM_DIMENSION_ID.fullmatch(value) else "UNKNOWN"


def _project_claim_dimensions(value: Any) -> tuple[dict[str, Any], bool]:
    source = value if isinstance(value, dict) else {}
    complete = isinstance(value, dict) and set(source) == set(_CLAIM_DIMENSION_CHOICES)
    projected: dict[str, Any] = {}
    for dimension, choices in _CLAIM_DIMENSION_CHOICES.items():
        item = source.get(dimension)
        if not isinstance(item, dict):
            projected[dimension] = {"status": "UNKNOWN"}
            complete = False
            continue
        status = item.get("status")
        if not isinstance(status, str) or status not in _CLAIM_ANSWER_STATUSES:
            projected[dimension] = {"status": "UNKNOWN"}
            complete = False
            continue
        question_id = item.get("question_id")
        refs = item.get("evidence_refs")
        safe_refs = (
            refs
            if isinstance(refs, list)
            and len(refs) <= 100
            and all(isinstance(ref, str) and _CLAIM_DIMENSION_ID.fullmatch(ref) for ref in refs)
            else None
        )
        interpretation = item.get("interpretation")
        safe_item: dict[str, Any] = {
            "status": status,
            "question_id": _project_claim_id(question_id),
            "native_primitive": "Choice" if item.get("native_primitive") == "Choice" else None,
            "interpretation": "advisory_uncalibrated" if interpretation == "advisory_uncalibrated" else None,
            "choice": None,
            "probabilities": None,
            "confidence": None,
            "evidence_refs": safe_refs if safe_refs is not None else [],
        }
        metadata_valid = (
            safe_item["question_id"] != "UNKNOWN"
            and safe_item["native_primitive"] is not None
            and safe_item["interpretation"] is not None
            and safe_refs is not None
        )
        if not metadata_valid:
            safe_item["status"] = "UNKNOWN"
            complete = False
        if status == "NOT_SHOWN" and dimension != "introducedness":
            safe_item["status"] = "UNKNOWN"
            complete = False
        if status == "ANSWERED" and metadata_valid:
            choice = item.get("choice")
            confidence = item.get("confidence")
            probabilities = item.get("probabilities")
            safe_probabilities = None
            if (
                isinstance(probabilities, dict)
                and set(probabilities) == set(choices)
                and all(
                    isinstance(number, (int, float))
                    and not isinstance(number, bool)
                    and math.isfinite(number)
                    and 0 <= number <= 1
                    for number in probabilities.values()
                )
                and abs(sum(probabilities.values()) - 1.0) <= 0.02
            ):
                safe_probabilities = {key: float(probabilities[key]) for key in sorted(choices)}
            if (
                isinstance(choice, str)
                and choice in choices
                and safe_probabilities is not None
                and safe_probabilities[choice] >= max(safe_probabilities.values()) - 1e-6
                and isinstance(confidence, (int, float))
                and not isinstance(confidence, bool)
                and math.isfinite(confidence)
                and 0 <= confidence <= 1
            ):
                safe_item.update(
                    choice=choice,
                    probabilities=safe_probabilities,
                    confidence=float(confidence),
                )
            else:
                safe_item["status"] = "UNKNOWN"
                complete = False
        error_code = item.get("error_code")
        if error_code is not None:
            safe_item["error_code"] = (
                error_code
                if isinstance(error_code, str)
                and error_code in _SAFE_CLAIM_DIMENSION_ERROR_CODES
                else "UNKNOWN"
            )
        invalid_hash = item.get("invalid_answer_hash")
        if invalid_hash is not None:
            safe_item["invalid_answer_hash"] = (
                invalid_hash if isinstance(invalid_hash, str) and _CLAIM_DIMENSION_HASH.fullmatch(invalid_hash) else None
            )
            if safe_item["invalid_answer_hash"] is None:
                complete = False
        projected[dimension] = safe_item
    return projected, complete


_SAFE_CLAIM_ERROR_CODES = frozenset(
    {
        "candidate_evidence_reference_missing",
        "claim_transport_estimator_required",
        "configured_model_required",
        "duplicate_evidence_id",
        "evidence_content_hash_mismatch",
        "evidence_snapshot_mismatch",
        "invalid_assessment_identity",
        "invalid_assessment_identity_fields",
        "invalid_assessment_identity_hash",
        "invalid_assessment_input",
        "invalid_candidate_evidence_refs",
        "invalid_candidate_fields",
        "invalid_candidate_id",
        "invalid_candidate_text",
        "invalid_claim_transport_estimate",
        "invalid_deadline",
        "invalid_evidence_collection",
        "invalid_evidence_content",
        "invalid_evidence_item",
        "invalid_evidence_source_kind",
        "invalid_evidence_trust",
        "invalid_input_byte_limit",
        "invalid_output_byte_limit",
        "invalid_prepared_assessment",
        "invalid_primary_assessment_causal_roles",
        "invalid_primary_assessment_contract",
        "invalid_primary_assessment_evidence_refs",
        "invalid_primary_assessment_fields",
        "invalid_primary_assessment_value",
        "invalid_revision_identity",
        "malformed_native_response",
        "native_transport_required",
        "question_limit_exceeded",
        "request_exceeds_intrinsic_limit",
        "request_exceeds_limit",
    }
)
_SAFE_CLAIM_REASON_CODES = _SAFE_CLAIM_ERROR_CODES | frozenset(
    {
        "PRIMARY_CANDIDATE_INVALID",
        "PRIMARY_ASSESSMENT_UNAVAILABLE",
        "CANDIDATE_EVIDENCE_BINDING_INVALID",
        "CLAIM_ASSESSMENT_CAP_EXHAUSTED",
        "PRIOR_SHADOW_ATTEMPT_UNSETTLED",
        "PRIOR_SHADOW_RESERVATION_EXISTS",
        "SHADOW_DISPATCH_UNCERTAIN",
        "RESPONSE_PROVENANCE_MISMATCH",
        "RESPONSE_SCHEMA_INVALID",
        "FRESHNESS_BUDGET_RESERVED",
        "DEADLINE_EXHAUSTED",
        "CONTEXT_BYTE_BUDGET_EXHAUSTED",
        "INPUT_BYTE_LIMIT_EXCEEDED",
        "MONETARY_BOUND_UNAVAILABLE",
        "MONETARY_BUDGET_EXHAUSTED",
        "OUTPUT_BYTE_BUDGET_EXHAUSTED",
        "OUTPUT_BYTE_LIMIT_EXCEEDED",
        "PROVIDER_CALL_BUDGET_EXHAUSTED",
        "CLAIM_ASSESSMENT_BUDGET_UNAVAILABLE",
    }
)
_SAFE_CLAIM_DIMENSION_ERROR_CODES = _SAFE_CLAIM_ERROR_CODES | frozenset(
    {
        "answer_omitted",
        "base_head_evidence_not_provided",
        "invalid_choice_answer",
        "native_call_deadline_exceeded",
        "native_call_failed",
        "native_response_exceeds_limit",
        "native_response_not_bytes",
    }
)


def _project_semantic_assessment(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {"status": "UNKNOWN"}
    keys = (
        "outcome",
        "observation_support",
        "consequence_support",
        "rule_connection_support",
        "introducedness",
        "material_consequence",
        "evidence_refs",
        "assumptions",
        "uncertainties",
        "summary",
        "contract_version",
        "causal_roles",
    )
    return {key: value[key] for key in keys if key in value}


def _project_jev(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {"status": "UNKNOWN"}
    result = {"status": value.get("status", "UNKNOWN")}
    payload = value.get("result")
    if isinstance(payload, dict):
        result["result"] = {
            key: payload.get(key)
            for key in ("choice", "probability", "rationale", "explanation", "status")
            if key in payload
        }
    provenance = value.get("provenance")
    if isinstance(provenance, dict):
        result["identity"] = {
            key: provenance[key]
            for key in ("provider_id", "native_contract", "contract_version", "model_identity_source")
            if isinstance(provenance.get(key), str)
        }
        result["identity"]["provider_model_sha256"] = sha256(canonical(provenance.get("provider_model_id")))
    usage = value.get("usage")
    if isinstance(usage, dict):
        result["usage"] = {
            key: usage[key]
            for key in ("prompt_tokens", "completion_tokens", "total_tokens")
            if isinstance(usage.get(key), (int, float)) and not isinstance(usage.get(key), bool)
        }
    return result


def _project_budget(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {"status": "UNKNOWN"}
    out = {
        key: value.get(key)
        for key in (
            "provider_calls_reserved",
            "provider_calls_settled",
            "context_bytes_reserved",
            "output_bytes_reserved",
            "output_bytes_settled",
            "retries_used",
            "deadline_seconds",
            "remaining_seconds",
        )
        if key in value and isinstance(value.get(key), (int, float, str)) and not isinstance(value.get(key), bool)
    }
    out["cost"] = "UNKNOWN"
    return out


def _project_coverage(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    fields = (
        "obligation_id",
        "obligation_kind",
        "required",
        "lens",
        "scope_unit_ids",
        "state",
        "reason_code",
        "task_ids",
        "context_gap_ids",
        "evidence_refs",
    )
    return [{key: row[key] for key in fields if key in row} for row in value[:200] if isinstance(row, dict)]


_SAFE_RETRIEVAL_REASONS = {
    "symbol_lookup_not_in_allowlist_contract",
    "target_unit_not_in_snapshot",
    "target_path_invalid",
    "target_path_not_allowlisted",
    "context_budget_exhausted",
    "binary_context_not_retrieved",
    "CONTEXT_BYTE_BUDGET_EXHAUSTED",
    "CONTEXT_RETRIEVAL_BUDGET_EXHAUSTED",
    "DEADLINE_EXHAUSTED",
    "FOLLOWUP_TASK_BUDGET_EXHAUSTED",
    "FRESHNESS_BUDGET_RESERVED",
    "INPUT_BYTE_LIMIT_EXCEEDED",
    "MONETARY_BOUND_UNAVAILABLE",
    "MONETARY_BUDGET_EXHAUSTED",
    "OUTPUT_BYTE_BUDGET_EXHAUSTED",
    "OUTPUT_BYTE_LIMIT_EXCEEDED",
    "PROVIDER_CALL_BUDGET_EXHAUSTED",
    "CONTEXT_RETRIEVAL_BYTE_LIMIT_EXCEEDED",
    "invalid_context_retrieval_result",
    "invalid_context_retrieval_evidence",
    "context_retrieval_evidence_binding_failed",
    "ipc_envelope_truncated",
    "retrieval_metadata_exceeds_ipc_limit",
    "retrieval_evidence_encoding_invalid",
}


def _project_gaps(
    value: Any, profile: dict[str, Any] | None = None, task_outputs: dict[str, Any] | None = None
) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    output_by_id = task_outputs if isinstance(task_outputs, dict) else {}
    output_statuses = {"SUCCEEDED", "FAILED", "TIMED_OUT", "SKIPPED", "INTERRUPTED_UNKNOWN"}
    patterns = None
    if isinstance(profile, dict):
        raw_patterns = profile.get("retrieval_context_patterns") or profile.get("context_paths")
        if isinstance(raw_patterns, str):
            patterns = [raw_patterns]
        elif isinstance(raw_patterns, list) and all(isinstance(item, str) for item in raw_patterns):
            patterns = raw_patterns
    projected = []
    for row in value[:200]:
        if not isinstance(row, dict):
            continue
        item = {
            key: row[key]
            for key in ("proposal_id", "status", "reason_code", "affected_obligation_ids", "affected_unit_ids", "required_lens")
            if key in row
        }
        proposal = row.get("proposal") if isinstance(row.get("proposal"), dict) else {}
        target = proposal.get("target") if isinstance(proposal.get("target"), dict) else {}
        target_keys = [key for key in ("target_unit_id", "target_path", "target_symbol") if target.get(key)]
        target_class = {"target_unit_id": "UNIT", "target_path": "PATH", "target_symbol": "SYMBOL"}.get(
            target_keys[0] if len(target_keys) == 1 else "", "UNKNOWN"
        )
        allowlist_match: bool | str = "UNKNOWN"
        if target_class == "PATH" and patterns is not None:
            import fnmatch

            path = target.get("target_path")
            allowlist_match = bool(
                isinstance(path, str) and any(fnmatch.fnmatchcase(path, pattern) for pattern in patterns)
            )
        reason = row.get("retrieval_reason")
        if "retrieval_reason" in row and reason is None:
            reason_code = "NONE"
        else:
            reason_code = reason if isinstance(reason, str) and reason in _SAFE_RETRIEVAL_REASONS else "UNKNOWN"
        retrieval_status = row.get("retrieval_status")
        if retrieval_status not in {"RESOLVED", "PARTIAL", "UNRESOLVED"}:
            retrieval_status = "UNKNOWN"
        retrieved_bytes = row.get("retrieved_bytes")
        if isinstance(retrieved_bytes, bool) or not isinstance(retrieved_bytes, int) or retrieved_bytes < 0:
            retrieved_bytes = "UNKNOWN"
        retrieval_envelope_bytes = row.get("retrieval_envelope_bytes")
        if (
            isinstance(retrieval_envelope_bytes, bool)
            or not isinstance(retrieval_envelope_bytes, int)
            or retrieval_envelope_bytes < 0
        ):
            retrieval_envelope_bytes = "UNKNOWN"
        evidence_ids = row.get("retrieved_evidence_ids")
        evidence_count = len(evidence_ids) if isinstance(evidence_ids, list) and all(
            isinstance(ref, str) for ref in evidence_ids
        ) else "UNKNOWN"
        followup_id = row.get("followup_task_id")
        followup_error = row.get("followup_error")
        followup_status = "NOT_SHOWN"
        followup_reason = "NOT_SHOWN"
        if isinstance(followup_id, str):
            outcome = output_by_id.get(followup_id)
            status = outcome.get("status") if isinstance(outcome, dict) else None
            followup_status = status if status in output_statuses else "UNKNOWN"
            if followup_status in {"FAILED", "TIMED_OUT", "SKIPPED", "INTERRUPTED_UNKNOWN"}:
                code = outcome.get("error_code") if isinstance(outcome, dict) else None
                followup_reason = code if isinstance(code, str) and code in _SAFE_RETRIEVAL_REASONS else "UNKNOWN"
            elif followup_status == "SUCCEEDED":
                followup_reason = "NONE"
            else:
                followup_reason = "UNKNOWN"
        elif isinstance(followup_error, str):
            followup_status = "NOT_ADMITTED_OR_UNKNOWN"
            followup_reason = followup_error if followup_error in _SAFE_RETRIEVAL_REASONS else "UNKNOWN"
        item["diagnostic"] = {
            "target_class": target_class,
            "profile_allowlist_match": allowlist_match,
            "retrieval_status": retrieval_status,
            "retrieval_reason_code": reason_code,
            "retrieved_bytes": retrieved_bytes,
            "retrieval_envelope_bytes": retrieval_envelope_bytes,
            "retrieved_evidence_count": evidence_count,
            "followup_status": followup_status,
            "followup_reason_code": followup_reason,
        }
        projected.append(item)
    return projected


def _project_snapshot_gaps(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    fields = (
        "proposal_id",
        "status",
        "reason_code",
        "path",
        "evidence_id",
        "affected_obligation_ids",
        "affected_unit_ids",
        "required_lens",
        "required",
        "retrievable",
    )
    known_reasons = {"context_truncated", "not_bound_by_context_selection"}
    projected = []
    for row in value[:200]:
        if not isinstance(row, dict):
            continue
        item = {key: row[key] for key in fields if key in row}
        reason = row.get("reason")
        if "reason" in row:
            item["reason"] = reason if isinstance(reason, str) and reason in known_reasons else "UNKNOWN"
        projected.append(item)
    return projected


def _project_evidence_index(value: dict[str, Any], candidates: list[dict[str, Any]]) -> dict[str, Any]:
    refs = {ref for item in candidates for ref in item.get("evidence_refs", []) if isinstance(ref, str)}
    return {
        ref: {
            key: value[ref][key]
            for key in ("path", "line_start", "line_end", "source_revision", "source_kind", "content_hash", "trust")
            if key in value[ref]
        }
        for ref in sorted(refs)
        if isinstance(value.get(ref), dict)
    }


def cleanup_private(path: Path) -> None:
    if path.is_symlink() or not path.is_dir():
        raise TrialError("private_cleanup_refused")
    shutil.rmtree(path)


def cleanup_optional_private(path: Path) -> None:
    """Remove an optional output directory when the command created one."""
    if not path.exists() and not path.is_symlink():
        return
    cleanup_private(path)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--mode", choices=("staged-pr464", "full-three-case"), required=True)
    result.add_argument("--input-contract", choices=INPUT_CONTRACTS, default="specialist-input-v1")
    run = result.add_mutually_exclusive_group(required=True)
    run.add_argument("--prepare-only", action="store_true")
    run.add_argument("--run-provider-trial", action="store_true")
    result.add_argument("--artifacts", type=Path, required=True)
    result.add_argument("--cli", type=Path, required=True)
    result.add_argument("--runtime-source", type=Path, required=True)
    result.add_argument("--target-bare", type=Path)
    return result


def _stable_failure_code(exc: BaseException) -> str:
    if isinstance(exc, TrialError) and exc.args:
        candidate = str(exc.args[0])
    elif isinstance(exc, RuntimeError) and exc.args:
        candidate = str(exc.args[0])
    elif isinstance(exc, subprocess.SubprocessError):
        candidate = "subprocess_failed"
    elif isinstance(exc, OSError):
        candidate = "trial_io_error"
    else:
        candidate = "trial_failed"
    return candidate if re.fullmatch(r"[a-z][a-z0-9_]{0,79}", candidate) else "trial_failed"


def _failure_rows(
    results: list[dict[str, Any]],
    cases: list[dict[str, Any]],
    active_case_id: str | None,
    stage: str,
    code: str,
) -> list[dict[str, Any]]:
    rows = list(results)
    if active_case_id:
        existing = next((row for row in rows if row.get("case_id") == active_case_id), None)
        if existing is None:
            active = next((case for case in cases if case.get("case_id") == active_case_id), {})
            existing = {
                "case_id": active_case_id,
                "scope_count": active.get("expected_scope_count"),
                "scope_sha256": active.get("expected_scope_sha256"),
            }
            rows.append(existing)
        existing.update({"status": "INCOMPLETE", "failure_stage": stage, "failure_code": code})
    completed_ids = {row.get("case_id") for row in rows}
    active_seen = active_case_id is None
    for case in cases:
        case_id = case.get("case_id")
        if case_id == active_case_id:
            active_seen = True
        if case_id in completed_ids:
            if case_id == active_case_id:
                active_seen = True
            continue
        if active_seen:
            rows.append(
                {
                    "case_id": case_id,
                    "status": "NOT_RUN",
                    "scope_count": case.get("expected_scope_count"),
                    "scope_sha256": case.get("expected_scope_sha256"),
                }
            )
    return rows


def _write_failure_artifacts(
    artifacts: Path,
    *,
    mode: str,
    prepare_only: bool,
    cases: list[dict[str, Any]],
    rows: list[dict[str, Any]],
    stage: str,
    code: str,
    runtime: dict[str, Any] | None,
    provider_call_attempted: bool,
    secrets: list[str],
    matrix_elapsed: float,
    input_contract: str = "specialist-input-v1",
) -> None:
    call_cap = 24 if mode == "staged-pr464" else 64
    provider_state = (
        "ZERO_PROVIDER_CALLS_PREPARE_ONLY"
        if prepare_only
        else "UNKNOWN_AFTER_FAILURE"
        if provider_call_attempted
        else "NO_PROVIDER_DISPATCH"
    )
    manifest = {
        "schema": _manifest_schema(input_contract),
        "runtime_provenance_version": _runtime_provenance_version(input_contract),
        "limits_version": "historical-real-case-limits.v2",
        "frozen_plan_manifest_sha256": _plan_identity(input_contract),
        "status": "FAILED",
        "historical_only": True,
        "current_pr_state_checked": False,
        "publication_enabled": False,
        "target_code_execution": False,
        "mode": mode,
        "failure": {"stage": stage, "code": code},
        "runtime_revision": runtime_identity(input_contract)[0],
        "runtime_module_proof": runtime or "NOT_VERIFIED",
        "runner_revision": os.environ.get("GITHUB_SHA", "local-uncommitted"),
        "workflow_matrix_started_epoch": os.environ.get("TRIAL_STARTED_EPOCH", "NOT_AVAILABLE"),
        "call_cap_per_case": call_cap,
        "max_retries_per_task": 0,
        "case_wall_seconds_including_setup": CASE_SECONDS,
        "matrix_wall_seconds_including_workflow_setup": MATRIX_SECONDS,
        "case_cleanup_reserve_seconds": CASE_CLEANUP_RESERVE_SECONDS,
        "matrix_finalization_reserve_seconds": MATRIX_CLEANUP_RESERVE_SECONDS,
        "engine_deadline_seconds": 600,
        "max_primary_concurrent_scopes": 4,
        "max_input_bytes_per_primary_task": 128_000,
        "primary_response_byte_cap_per_call": 16_000,
        "shared_task_response_reservation_cap_per_call": 32_768,
        "output_byte_cap_per_case": 2_097_152,
        "serialized_primary_context_cap_per_case": 8_000_000,
        "max_snapshot_context_bytes": 300_000,
        "provider_execution_state": provider_state,
        "provider_calls": 0 if prepare_only else "UNKNOWN" if provider_call_attempted else 0,
        "candidate_adjudication_followup_summary_and_jev_demand": "UNKNOWN_UNTIL_RUNTIME",
        "cost": "UNKNOWN" if provider_call_attempted else "NOT_INCURRED",
        "planned_case_ids": [case.get("case_id") for case in cases],
        "planned_scope_obligation_count": sum(case.get("expected_scope_count", 0) for case in cases),
        "cases": rows,
        "elapsed_seconds": matrix_elapsed,
    }
    if _uses_v2_primary(input_contract):
        manifest["fixed_case_manifest_sha256"] = V2_PLAN_SHA256
        manifest["runtime_module_tree_sha256"] = runtime_identity(input_contract)[1]
        manifest.update(_experiment_identity_fields(input_contract))
        if _is_context_followup_experiment(input_contract):
            manifest["primary_input_identity"] = "NOT_VERIFIED"
    _scan(manifest, secrets)
    if len(canonical(manifest)) > 4_000_000:
        raise TrialError("sanitized_manifest_limit_exceeded")
    if _uses_v2_primary(input_contract) and len(canonical(manifest)) > V2_ARTIFACT_MANIFEST_CAP:
        raise TrialError("sanitized_manifest_limit_exceeded")
    summary = {
        "schema": manifest["schema"],
        "status": "FAILED",
        "failure": manifest["failure"],
        "provider_execution_state": provider_state,
        "cases": [
            {
                key: value
                for key, value in row.items()
                if key != "projection" and not (_uses_v2_primary(input_contract) and key == "primary_request_receipts")
            }
            for row in rows
        ],
    }
    _scan(summary, secrets, 128_000)
    if _uses_v2_primary(input_contract) and len(canonical(summary)) > V2_ARTIFACT_SUMMARY_CAP:
        raise TrialError("sanitized_summary_limit_exceeded")
    write_json(artifacts / "summary.json", summary)
    write_json(artifacts / "manifest.json", manifest)


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    started = time.monotonic()
    private_root: Path | None = None
    artifact_root_created = False
    document: dict[str, Any] = {}
    cases: list[dict[str, Any]] = []
    runtime: dict[str, Any] | None = None
    results: list[dict[str, Any]] = []
    preflight_rows: list[dict[str, Any]] = []
    prepared_v2_cases: dict[str, dict[str, Any]] = {}
    secrets: list[str] = []
    active_case_id: str | None = None
    stage = "preflight"
    provider_call_attempted = False
    v2_provider_preflight = False
    try:
        matrix_deadline = _matrix_deadline(args.run_provider_trial)
        if args.run_provider_trial:
            stage = "dispatch_preflight"
            verify_dispatch_context(ROOT)
        stage = "fixed_input_validation"
        document, all_cases = load_locked_cases(args.input_contract)
        cases = selected_cases(args.mode, all_cases)
        stage = "artifact_setup"
        if args.artifacts.exists() or args.artifacts.is_symlink():
            raise TrialError("artifact_destination_already_exists")
        args.artifacts.mkdir(parents=True, mode=0o700)
        artifact_root_created = True
        os.chmod(args.artifacts, 0o700)
        stage = "runtime_identity_validation"
        if args.input_contract == "specialist-input-v1":
            runtime = verify_runtime(args.cli.resolve(strict=True), args.runtime_source.resolve(strict=True))
        else:
            runtime = verify_runtime(args.cli.resolve(strict=True), args.runtime_source.resolve(strict=True), args.input_contract)
        output = args.artifacts / "private"
        private_root = output
        output.mkdir(mode=0o700)
        v2_provider_preflight = _uses_v2_primary(args.input_contract) and args.run_provider_trial
        if args.prepare_only or v2_provider_preflight:
            stage = "prepare_configuration"
            # Guard the workflow process environment so prepare-only cannot read provider credentials.
            if args.prepare_only:
                for name in SECRET_NAMES:
                    os.environ.pop(name, None)
            provider_path, decision_path = build_prepare_configs(output)
        else:
            stage = "provider_configuration"
            provider_path, decision_path, secrets = build_configs(output / "configs")
        effective_env = _clean_git_env()
        # The CLI receives only known provider credentials; GitHub event/context variables are excluded.
        if not args.prepare_only and not v2_provider_preflight:
            for name in ("LLM_API_KEY", "JEV_API_KEY"):
                effective_env[name] = os.environ[name]
        projection_failure = False
        matrix_calls = 24 if args.mode == "staged-pr464" else 64
        if v2_provider_preflight:
            for case in cases:
                active_case_id = case["case_id"]
                case_started = time.monotonic()
                case_deadline = min(case_started + CASE_SECONDS, matrix_deadline)
                case_dir = output / case["case_id"]
                case_dir.mkdir(mode=0o700)
                bare = args.target_bare.resolve(strict=True) if args.target_bare else case_dir / "objects.git"
                stage = "target_object_acquisition"
                object_record = acquire_bare_case(
                    case, bare, case_deadline, matrix_deadline,
                    source_bare=bare if args.target_bare else None, auxiliary_dir=case_dir,
                )
                limits_path = case_dir / "limits.json"
                write_json(limits_path, limits_for(matrix_calls))
                profile_path = INPUT_ROOT / case["profile_path"]
                checks_path = INPUT_ROOT / case["checks_path"]
                stage = "prepare_cli"
                prep = run_cli(
                    args.cli, case, bare, profile_path, checks_path, provider_path, decision_path,
                    limits_path, case_dir / "prepared", True, effective_env,
                    _remaining(case_deadline, matrix_deadline),
                )
                validate_prepare_v2(case, prep, 8_000_000, matrix_calls)
                prepared_v2_cases[case["case_id"]] = {
                    "case_started": case_started,
                    "case_deadline": case_deadline,
                    "case_dir": case_dir,
                    "bare": bare,
                    "limits_path": limits_path,
                    "object_record": object_record,
                    "prep": prep,
                }
                preflight_rows.append({
                    "case_id": case["case_id"],
                    "status": "PREPARED_NOT_RUN",
                    "scope_count": case["expected_scope_count"],
                    "scope_sha256": case["expected_scope_sha256"],
                    "primary_calls": case["expected_primary_count"],
                    "primary_serialized_input_bytes": case["expected_primary_serialized_input_bytes"],
                    "immutable_patch_sha256": object_record["patch_sha256"],
                    "profile_sha256": case["profile_sha256"],
                    "checks_sha256": case["checks_sha256"],
                    "snapshot_hash": case["snapshot_hash"],
                    "evidence_index_sha256": case["evidence_index_sha256"],
                    "primary_descriptor_sha256": case["expected_primary_descriptor_sha256"],
                    "primary_request_receipts": _primary_receipts_for_contract(prep, args.input_contract),
                })
                active_case_id = None
            # No secret-bearing config or provider environment reaches the CLI
            # until every selected v2 case has matched its frozen request plan.
            stage = "provider_configuration"
            provider_path, decision_path, secrets = build_configs(output / "configs")
            for name in ("LLM_API_KEY", "JEV_API_KEY"):
                effective_env[name] = os.environ[name]
        for case in cases:
            active_case_id = case["case_id"]
            if v2_provider_preflight:
                cached = prepared_v2_cases[case["case_id"]]
                case_started = cached["case_started"]
                case_deadline = cached["case_deadline"]
                case_dir = cached["case_dir"]
                bare = cached["bare"]
                limits_path = cached["limits_path"]
                object_record = cached["object_record"]
                prep = cached["prep"]
            else:
                case_started = time.monotonic()
                case_deadline = min(case_started + CASE_SECONDS, matrix_deadline)
                _remaining(case_deadline, matrix_deadline)
                case_dir = output / case["case_id"]
                case_dir.mkdir(mode=0o700)
                bare = args.target_bare.resolve(strict=True) if args.target_bare else case_dir / "objects.git"
                stage = "target_object_acquisition"
                object_record = acquire_bare_case(
                    case,
                    bare,
                    case_deadline,
                    matrix_deadline,
                    source_bare=bare if args.target_bare else None,
                    auxiliary_dir=case_dir,
                )
                limits_path = case_dir / "limits.json"
                write_json(limits_path, limits_for(matrix_calls))
                profile_path = INPUT_ROOT / case["profile_path"]
                checks_path = INPUT_ROOT / case["checks_path"]
                stage = "prepare_cli"
                prep = run_cli(
                    args.cli,
                    case,
                    bare,
                    profile_path,
                    checks_path,
                    provider_path,
                    decision_path,
                    limits_path,
                    case_dir / "prepared",
                    True,
                    effective_env,
                    _remaining(case_deadline, matrix_deadline),
                )
                if _uses_v2_primary(args.input_contract):
                    validate_prepare_v2(case, prep, 8_000_000, matrix_calls)
                else:
                    validate_prepare(case, prep, 8_000_000)
            profile_path = INPUT_ROOT / case["profile_path"]
            checks_path = INPUT_ROOT / case["checks_path"]
            if args.prepare_only:
                prepared_row = {
                    "case_id": case["case_id"],
                    "status": "PREPARED_NOT_RUN",
                    "scope_count": case["expected_scope_count"],
                    "scope_sha256": case["expected_scope_sha256"],
                    "primary_calls": case["expected_primary_count"],
                    "primary_serialized_input_bytes": case["expected_primary_serialized_input_bytes"],
                    "immutable_patch_sha256": object_record["patch_sha256"],
                    "profile_sha256": case["profile_sha256"],
                    "checks_sha256": case["checks_sha256"],
                    "snapshot_hash": case["snapshot_hash"],
                    "evidence_index_sha256": case["evidence_index_sha256"],
                    "primary_descriptor_sha256": case["expected_primary_descriptor_sha256"],
                    "primary_request_receipts": _primary_receipts_for_contract(prep, args.input_contract),
                }
                _scan(prepared_row, secrets)
                results.append(prepared_row)
                if not args.target_bare:
                    shutil.rmtree(bare)
                active_case_id = None
                continue
            stage = "provider_cli"
            provider_call_attempted = True
            actual = run_cli(
                args.cli,
                case,
                bare,
                profile_path,
                checks_path,
                provider_path,
                decision_path,
                limits_path,
                case_dir / "result",
                False,
                effective_env,
                _remaining(case_deadline, matrix_deadline),
            )
            stage = "result_projection"
            result_path = case_dir / "result" / f"{actual['run_id']}.json"
            durable = read_result(result_path)
            try:
                projection = project_case_for_contract(case, durable, secrets, args.input_contract)
            except TrialError as exc:
                results.append(
                    {
                        "case_id": case["case_id"],
                        "status": "INCOMPLETE",
                        "projection_status": "OMITTED",
                        "projection_error": exc.args[0] if exc.args else "projection_incomplete",
                    }
                )
                projection_failure = True
                break
            row = {
                "case_id": case["case_id"],
                "status": "PROCESS_COMPLETED",
                "elapsed_seconds": round(time.monotonic() - case_started, 3),
                "immutable_patch_sha256": object_record["patch_sha256"],
                "target_objects": {
                    "total_object_count": object_record["isolated_object_count"],
                    "loose_object_count": object_record["isolated_loose_object_count"],
                    "in_pack_object_count": object_record["isolated_in_pack_object_count"],
                    "pack_size_kib": object_record["isolated_pack_kib"],
                },
                "durable_result_sha256": sha256(result_path.read_bytes()),
                "profile_sha256": case["profile_sha256"],
                "checks_sha256": case["checks_sha256"],
                "snapshot_hash": case["snapshot_hash"],
                "evidence_index_sha256": case["evidence_index_sha256"],
                "scope_count": case["expected_scope_count"],
                "scope_sha256": case["expected_scope_sha256"],
                "primary_calls": case["expected_primary_count"],
                "primary_serialized_input_bytes": case["expected_primary_serialized_input_bytes"],
                "primary_descriptor_sha256": case["expected_primary_descriptor_sha256"],
                "primary_request_receipts": _primary_receipts_for_contract(prep, args.input_contract),
                "projection": projection,
            }
            _scan(row, secrets)
            results.append(row)
            # Raw provider and CLI data is removed immediately after bounded projection.
            stage = "provider_result_cleanup"
            cleanup_private(case_dir / "result")
            stage = "prepare_workspace_cleanup"
            cleanup_optional_private(case_dir / "prepared")
            if not args.target_bare:
                stage = "owned_target_object_cleanup"
                cleanup_private(bare)
            active_case_id = None
            stage = "case_complete"
        if projection_failure:
            results = _failure_rows(results, cases, None, "result_projection", "projection_incomplete")
        stage = "manifest_finalization"
        if matrix_deadline - time.monotonic() <= MATRIX_CLEANUP_RESERVE_SECONDS:
            raise TrialError("matrix_deadline_exceeded")
        manifest = {
        "schema": _manifest_schema(args.input_contract),
            "runtime_provenance_version": _runtime_provenance_version(args.input_contract),
            "limits_version": "historical-real-case-limits.v2",
            "frozen_plan_manifest_sha256": _plan_identity(args.input_contract),
            "status": "PREPARED_NOT_RUN"
            if args.prepare_only
            else "INCOMPLETE"
            if projection_failure
            else "PROCESS_COMPLETED",
            "historical_only": True,
            "current_pr_state_checked": False,
            "publication_enabled": False,
            "target_code_execution": False,
            "mode": args.mode,
            "runtime_revision": runtime_identity(args.input_contract)[0],
            "runtime_wheel_sha256": os.environ.get("RUNTIME_WHEEL_SHA256", "UNKNOWN"),
            "runtime_module_proof": runtime,
            "runner_revision": os.environ.get("GITHUB_SHA", "local-uncommitted"),
            "workflow_matrix_started_epoch": os.environ.get("TRIAL_STARTED_EPOCH", "NOT_AVAILABLE"),
            "fixed_case_manifest_sha256": V2_PLAN_SHA256 if _uses_v2_primary(args.input_contract) else CASES_SHA256,
            "baseline_plan_sha256": document.get("baseline_plan_sha256"),
            "call_cap_per_case": matrix_calls,
            "call_cap_total_selected_cases": matrix_calls * len(cases),
            "max_primary_concurrent_scopes": 4,
            "max_retries_per_task": 0,
            "case_wall_seconds_including_setup": CASE_SECONDS,
            "matrix_wall_seconds_including_workflow_setup": MATRIX_SECONDS,
            "case_cleanup_reserve_seconds": CASE_CLEANUP_RESERVE_SECONDS,
            "matrix_finalization_reserve_seconds": MATRIX_CLEANUP_RESERVE_SECONDS,
            "engine_deadline_seconds": 600,
            "max_claim_assessments_per_case": 4,
            "max_input_bytes_per_primary_task": 128_000,
            "primary_output_token_cap_per_call": 1800,
            "primary_response_byte_cap_per_call": 16000,
            "shared_task_response_reservation_cap_per_call": 32768,
            "output_byte_cap_per_case": 2_097_152,
            "serialized_primary_context_cap_per_case": 8_000_000,
            "max_snapshot_context_bytes": 300_000,
            "serialized_bytes_per_case_total": "NOT_FORECAST; primary request bytes exact, runtime demand dynamic",
            "candidate_adjudication_followup_summary_and_jev_demand": "UNKNOWN_UNTIL_RUNTIME",
            "provider_execution_state": "ZERO_PROVIDER_CALLS_PREPARE_ONLY"
            if args.prepare_only
            else "UNKNOWN_UNLESS_REPORTED_BY_PROVIDER",
            "provider_calls": 0 if args.prepare_only else "UNKNOWN",
            "cost": "NOT_INCURRED" if args.prepare_only else "UNKNOWN",
            "cases": results,
            "planned_scope_obligation_count": sum(case["expected_scope_count"] for case in cases),
            "primary_request_demand": {
                "exact_calls": sum(case["expected_primary_count"] for case in cases),
                "exact_serialized_input_bytes": sum(case["expected_primary_serialized_input_bytes"] for case in cases),
                "required_scopes_preserved": all(case["expected_scope_count"] > 0 for case in cases),
            },
            "elapsed_seconds": round(time.monotonic() - started, 3),
            "matrix_elapsed_seconds": round(
                time.time() - float(os.environ["TRIAL_STARTED_EPOCH"])
                if re.fullmatch(r"[0-9]{10,12}", os.environ.get("TRIAL_STARTED_EPOCH", ""))
                else time.monotonic() - started,
                3,
            ),
        }
        if _uses_v2_primary(args.input_contract):
            manifest.update(_experiment_identity_fields(args.input_contract))
            manifest["runtime_module_tree_sha256"] = runtime_identity(args.input_contract)[1]
            if _is_context_followup_experiment(args.input_contract):
                rows_by_id = {row.get("case_id"): row for row in results if isinstance(row, dict)}
                primary_match = all(
                    isinstance(rows_by_id.get(case["case_id"]), dict)
                    and rows_by_id[case["case_id"]].get("primary_calls") == case["expected_primary_count"]
                    and rows_by_id[case["case_id"]].get("primary_serialized_input_bytes") == case["expected_primary_serialized_input_bytes"]
                    and rows_by_id[case["case_id"]].get("primary_descriptor_sha256") == case["expected_primary_descriptor_sha256"]
                    for case in cases
                )
                manifest["primary_input_identity"] = (
                    "MATCHED_ALL_FROZEN_V2_PRIMARY_DESCRIPTORS"
                    if primary_match and [case["case_id"] for case in cases] == ["PR-457", "PR-463", "PR-464"]
                    else "MATCHED_SELECTED_FROZEN_V2_CASES"
                    if primary_match
                    else "NOT_VERIFIED"
                )
                manifest["primary_request_identity_totals"] = {
                    "requests": sum(case["expected_primary_count"] for case in cases) if primary_match else "UNKNOWN",
                    "serialized_input_bytes": sum(case["expected_primary_serialized_input_bytes"] for case in cases) if primary_match else "UNKNOWN",
                    "required_obligations": sum(case["expected_scope_count"] for case in cases) if primary_match else "UNKNOWN",
                }
            manifest["serialized_artifact_caps"] = {
                "manifest_json_bytes_max": V2_ARTIFACT_MANIFEST_CAP,
                "summary_json_bytes_max": V2_ARTIFACT_SUMMARY_CAP,
            }
        _scan(manifest, secrets)
        if len(canonical(manifest)) > 4_000_000:
            raise TrialError("sanitized_manifest_limit_exceeded")
        summary = {
            "schema": manifest["schema"],
            "status": manifest["status"],
            "cases": [
                {
                    key: value for key, value in item.items()
                    if key != "projection"
                    and not (_uses_v2_primary(args.input_contract) and key == "primary_request_receipts")
                }
                | ({"case_id": item["case_id"], "status": item["status"]} if "projection" in item else {})
                for item in results
            ],
        }
        _scan(summary, secrets, 128_000)
        if _uses_v2_primary(args.input_contract) and (
            len(canonical(manifest)) > V2_ARTIFACT_MANIFEST_CAP
            or len(canonical(summary)) > V2_ARTIFACT_SUMMARY_CAP
        ):
            raise TrialError("sanitized_artifact_limit_exceeded")
        cleanup_private(output)
        private_root = None
        write_json(args.artifacts / "summary.json", summary)
        write_json(args.artifacts / "manifest.json", manifest)
        print(json.dumps({"status": manifest["status"], "case_count": len(results)}, separators=(",", ":")))
        return 1 if manifest["status"] == "INCOMPLETE" else 0
    except (TrialError, OSError, subprocess.SubprocessError, RuntimeError) as exc:
        code = _stable_failure_code(exc)
        cleanup_succeeded = True
        if private_root is not None and (private_root.exists() or private_root.is_symlink()):
            try:
                cleanup_private(private_root)
            except (OSError, TrialError):
                cleanup_succeeded = False
        failure_results = preflight_rows if v2_provider_preflight and not provider_call_attempted else results
        rows = _failure_rows(failure_results, cases, active_case_id, stage, code)
        if artifact_root_created and cleanup_succeeded:
            try:
                _write_failure_artifacts(
                    args.artifacts,
                    mode=args.mode,
                    prepare_only=args.prepare_only,
                    cases=cases,
                    rows=rows,
                    stage=stage,
                    code=code,
                    runtime=runtime,
                    provider_call_attempted=provider_call_attempted,
                    secrets=secrets,
                    matrix_elapsed=round(time.monotonic() - started, 3),
                    input_contract=args.input_contract,
                )
            except (OSError, RuntimeError, TrialError):
                pass
        # Errors are stable codes only; raw provider output, URLs, and credentials are never echoed.
        print(json.dumps({"status": "FAILED", "error": str(code)}, separators=(",", ":")))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
