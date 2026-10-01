#!/usr/bin/env python3
"""Run the frozen PR466 functional review through the production CLI."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CASE_DIR = ROOT / "docs/historical-functional-review-pr466-v1"
MANIFEST = CASE_DIR / "manifest.json"
CHECKS = CASE_DIR / "historical-checks.json"
LIMITS = CASE_DIR / "limits.json"
PROFILE = ROOT / "profiles/slopsearx.json"
REPOSITORY = "magnus919/SlopSearX"
BASE = "63e3ecd2f09d79c34e3594a3be74f017a1c5a12c"
HEAD = "7bce9dd246f141eb961c52ae96061203a98f083b"
PROFILE_SHA256 = "cc9c4631882662c27be5fb8534e65abbd352489afefa78e9dd3d3160fe0b1c65"
CHECKS_SHA256 = "c7d3a28b0e12583dceb0021b04814573706f202a188e4cbed2d1ebde821d5963"
LIMITS_SHA256 = "5b92e2381ba6c15e8afc2b77d7437d3cbb53a8ff6275e1b18617218753b364d6"
V2_CASE_DIR = ROOT / "docs/historical-functional-review-pr466-v2"
V2_MANIFEST = V2_CASE_DIR / "manifest.json"
V2_CHECKS = V2_CASE_DIR / "historical-checks.json"
V2_LIMITS = V2_CASE_DIR / "limits.json"
V2_PROFILE = ROOT / "profiles/slopsearx-v10-bounded-head-context-trial.json"
V2_PROFILE_VERSION = "slopsearx-production-v10-bounded-head-context-trial"
V2_PROFILE_SHA256 = "c2fefca40483bed31207f88fc1ae21f8c058098a207aca9ca987a54ff7abb34b"
V2_CHECKS_SHA256 = CHECKS_SHA256
V2_LIMITS_SHA256 = "964a11a8de3bfd47520ea62e358c954dceb1ac7da7f0648ef4db11d6f885870e"
V2_MANIFEST_SCHEMA = "historical-functional-review-pr466.v2"
V3_CASE_DIR = ROOT / "docs/historical-functional-review-pr466-v3"
V3_MANIFEST = V3_CASE_DIR / "manifest.json"
V3_CHECKS = V3_CASE_DIR / "historical-checks.json"
V3_LIMITS = V3_CASE_DIR / "limits.json"
V3_PROFILE = ROOT / "profiles/slopsearx-v11-related-implementation-context-candidate.json"
V3_PROFILE_VERSION = "slopsearx-production-v11-related-implementation-context-candidate"
V3_PROFILE_SHA256 = "5afcbf3cf5af235a97b59487303c28cb5c5f0942dc51cccc1ff84178617853d3"
V3_CHECKS_SHA256 = CHECKS_SHA256
V3_LIMITS_SHA256 = V2_LIMITS_SHA256
V3_MANIFEST_SCHEMA = "historical-functional-review-pr466.v3"
V4_CASE_DIR = ROOT / "docs/historical-functional-review-pr466-v4"
V4_MANIFEST = V4_CASE_DIR / "manifest.json"
V4_CHECKS = V4_CASE_DIR / "historical-checks.json"
V4_LIMITS = V4_CASE_DIR / "limits.json"
V4_PROFILE = ROOT / "profiles/slopsearx-v12-dependency-context-candidate.json"
V4_PROFILE_VERSION = "slopsearx-production-v12-head-dependency-context-candidate"
V4_PROFILE_SHA256 = "e2b1d9bbdafd6d054462b9abac48ce88fdc71400abcb7655902fcf3677c4d446"
V4_CHECKS_SHA256 = CHECKS_SHA256
V4_LIMITS_SHA256 = V2_LIMITS_SHA256
V4_MANIFEST_SCHEMA = "historical-functional-review-pr466.v4"
V4_PROJECTION = {
    "path": "pyproject.toml",
    "source_kind": "dependency_projection",
    "source_revision": HEAD,
    "trust": "repository_evidence",
    "evidence_id": "ev-7d389ea2e58de8c54ed68109",
    "content_bytes": 858,
    "content_hash": "75a555a088593a00fe5bea36ef4c819dd035eb55c72c25642052865d81e00b3a",
    "included_primary_task_ids": [
        "task-73422d1d4452c592:chunk-1",
        "task-43fc1554597a6096:chunk-1",
        "task-37d44cb9339851be:chunk-1",
        "task-6a0aad87db4d05a9:chunk-1",
        "task-1191806e0932af14:chunk-1",
    ],
}
DEFAULT_CASE = "pr466-v1"
CASE_CHOICES = ("pr466-v1", "pr466-v2", "pr466-v3", "pr466-v4")
CALL_CAP = 10
CONTEXT_CAP = 600_000
INPUT_CAP = 64_000
V2_INPUT_CAP = 80_000
V3_INPUT_CAP = 80_000
V4_INPUT_CAP = 80_000

V2_PREPARE_OBSERVATION = {
    "status": "PREPARED_ONLY",
    "source_revision": "1b4598b1ce2776104817d8a9a03040259abcf412",
    "profile_sha256": V2_PROFILE_SHA256,
    "historical_checks_sha256": V2_CHECKS_SHA256,
    "limits_sha256": V2_LIMITS_SHA256,
    "max_claim_assessments": 1,
    "max_provider_calls": CALL_CAP,
    "max_input_bytes_per_task": V2_INPUT_CAP,
    "max_context_bytes": CONTEXT_CAP,
    "no_provider_calls": True,
    "no_target_code_execution": True,
    "primary_scope_admission_complete": True,
    "admitted_obligations": 15,
    "planned_obligations": 15,
    "primary_request_count": 7,
    "total_primary_serialized_input_bytes": 394_539,
    "remaining_call_slots_after_primary": 3,
    "dynamic_stage_demand": "UNKNOWN_UNTIL_PRIMARY_RESULTS_AND_OPTIONAL_STAGE_ADMISSION",
    "primary_requests": [
        {
            "task_id": "task-f685da4711ebfae2:chunk-1",
            "lens": "correctness",
            "input_bytes": 49_602,
            "input_sha256": "c63b26e08a43974ac0c7b1761cf93022824e9a428c5a55d12019ed3f408b3cb1",
        },
        {
            "task_id": "task-813d7e8d2d627d7e:chunk-1",
            "lens": "tests",
            "input_bytes": 50_091,
            "input_sha256": "ab4fc773dae19e547d3f829950eaf037748034caf6e818611f214e693a9969c8",
        },
        {
            "task_id": "task-33993a52e194db73:chunk-1",
            "lens": "maintainability",
            "input_bytes": 49_571,
            "input_sha256": "85a985a26f5523879c54d1735686724437b66d5040a534858f6d45ef7d54309f",
        },
        {
            "task_id": "task-e297e02db7eb5e40:chunk-1",
            "lens": "correctness",
            "input_bytes": 69_190,
            "input_sha256": "4621e00ad19b84178073f77d93d082dae3d13d8f3397f5f834cafaaaebe4ea70",
        },
        {
            "task_id": "task-9f233e011829dd31:chunk-1",
            "lens": "tests",
            "input_bytes": 69_691,
            "input_sha256": "c2b16f9c71cca0027b429d8030fba42a4f0580435b77ad59a6b2eeeb8e03dd99",
        },
        {
            "task_id": "task-0e194f0ef7319e20:chunk-1",
            "lens": "maintainability",
            "input_bytes": 36_647,
            "input_sha256": "07dcc45da53cd409c1ee5a73c90bb0f2841419af05cc6d0f2de3199aaeeba041",
        },
        {
            "task_id": "task-a7e35017ef6c5491:chunk-1",
            "lens": "security",
            "input_bytes": 69_747,
            "input_sha256": "36135c4e9dc61d49d90ba1a9d391ea7dd18f2865242310fda3848a21e63fa278",
        },
    ],
}

V3_PREPARE_OBSERVATION = {
    "status": "PREPARED_ONLY",
    "profile_sha256": V3_PROFILE_SHA256,
    "historical_checks_sha256": V3_CHECKS_SHA256,
    "limits_sha256": V3_LIMITS_SHA256,
    "max_claim_assessments": 1,
    "max_provider_calls": CALL_CAP,
    "max_input_bytes_per_task": V3_INPUT_CAP,
    "max_context_bytes": CONTEXT_CAP,
    "no_provider_calls": True,
    "no_target_code_execution": True,
    "primary_scope_admission_complete": True,
    "admitted_obligations": 15,
    "planned_obligations": 15,
    "primary_request_count": 7,
    "total_primary_serialized_input_bytes": 417_632,
    "remaining_call_slots_after_primary": 3,
    "dynamic_stage_demand": "UNKNOWN_UNTIL_PRIMARY_RESULTS_AND_OPTIONAL_STAGE_ADMISSION",
    "primary_requests": [
        {
            "task_id": "task-7235c1a0b2742b75:chunk-1",
            "lens": "correctness",
            "input_bytes": 72_737,
            "input_sha256": "6824360fd3f4ebcd49d9fd53f2d3200d61722b346798ac980c52e6009a47af44",
        },
        {
            "task_id": "task-128b51c6d6a45b4e:chunk-1",
            "lens": "tests",
            "input_bytes": 50_084,
            "input_sha256": "c2930bbb95ddf98895493437dba2901d28142b2ae225d7ef3e0b428beba86270",
        },
        {
            "task_id": "task-f25690174a4821ea:chunk-1",
            "lens": "maintainability",
            "input_bytes": 49_564,
            "input_sha256": "502b3a6fb29dea305d0d2665084cd7645f02cad1b96a18a58de93b9e55b557dd",
        },
        {
            "task_id": "task-c18fc5c7712504f4:chunk-1",
            "lens": "correctness",
            "input_bytes": 69_183,
            "input_sha256": "6c0cac81c46bfaf8982ad50c7d8743f8549c89f11b132558b4df6479dfdcff20",
        },
        {
            "task_id": "task-e02ef3e302eebc8f:chunk-1",
            "lens": "tests",
            "input_bytes": 69_684,
            "input_sha256": "ec1a613521d088ef2ecdd00e94792968c9d0d938bf4b9377839176fc8dcaf923",
        },
        {
            "task_id": "task-96bd3831b4d55a43:chunk-1",
            "lens": "maintainability",
            "input_bytes": 36_640,
            "input_sha256": "8beef41bc1e3334ec58613deeb26462f03779a84ce021ac710c548196d8f1858",
        },
        {
            "task_id": "task-e737705989075b6c:chunk-1",
            "lens": "security",
            "input_bytes": 69_740,
            "input_sha256": "dc28cb669b2d8085501dc7fcfb7decda85a8fb4ece8cf85caf3b503eed2bda61",
        },
    ],
}

V4_PREPARE_OBSERVATION = {
    "status": "PREPARED_ONLY",
    "source_revision": "1f99d58eb5bd009da62a0537be7e7eed7cf88f5b",
    "profile_sha256": V4_PROFILE_SHA256,
    "historical_checks_sha256": V4_CHECKS_SHA256,
    "limits_sha256": V4_LIMITS_SHA256,
    "max_claim_assessments": 1,
    "max_provider_calls": CALL_CAP,
    "max_input_bytes_per_task": V4_INPUT_CAP,
    "max_context_bytes": CONTEXT_CAP,
    "no_provider_calls": True,
    "no_target_code_execution": True,
    "primary_scope_admission_complete": True,
    "admitted_obligations": 15,
    "planned_obligations": 15,
    "primary_request_count": 7,
    "total_primary_serialized_input_bytes": 441_227,
    "remaining_call_slots_after_primary": 3,
    "dynamic_stage_demand": "UNKNOWN_UNTIL_PRIMARY_RESULTS_AND_OPTIONAL_STAGE_ADMISSION",
    "dependency_projection": V4_PROJECTION,
    "installed_runtime_resolution": "UNKNOWN_FROM_DECLARATION_PROJECTION",
    "primary_requests": [
        {
            "task_id": "task-73422d1d4452c592:chunk-1",
            "lens": "correctness",
            "input_bytes": 77_234,
            "input_sha256": "867f8adea5c83a2e933791438442f54866dadfc912a8cbf0e36db17197010f6b",
        },
        {
            "task_id": "task-43fc1554597a6096:chunk-1",
            "lens": "tests",
            "input_bytes": 53_981,
            "input_sha256": "c713acc5dc433175ca4349bcf484fd339927aa7b48a4f0d9b337485f8c8b0149",
        },
        {
            "task_id": "task-825e221a4a67ace3:chunk-1",
            "lens": "maintainability",
            "input_bytes": 51_019,
            "input_sha256": "594c47813e1bc391a3f00b47089b7189ce29d0592d1b69d2ddc064ffc1c622a4",
        },
        {
            "task_id": "task-37d44cb9339851be:chunk-1",
            "lens": "correctness",
            "input_bytes": 73_530,
            "input_sha256": "923adccd993b6bc79ed1e4d1feb86868cc99d3a19e88f99920da4bad316365e1",
        },
        {
            "task_id": "task-6a0aad87db4d05a9:chunk-1",
            "lens": "tests",
            "input_bytes": 74_031,
            "input_sha256": "b2d33f5b2fd0d613b2645a209eb7ab6da9d8600979e83996c17cf91be01d683f",
        },
        {
            "task_id": "task-05c73b1f0fbc97b4:chunk-1",
            "lens": "maintainability",
            "input_bytes": 37_345,
            "input_sha256": "06c581a5e50badb39ee5b5f3bc52675e7af4816c5cba4f4d73c8eb73b235e865",
        },
        {
            "task_id": "task-1191806e0932af14:chunk-1",
            "lens": "security",
            "input_bytes": 74_087,
            "input_sha256": "06702f1bc05acc9d738eb0b75193decce38c8e6b8084e4113fcd5a2e51d0338d",
        },
    ],
}


class SafeFailure(Exception):
    """A fixed diagnostic that contains no supplied data or credential."""


def _sha(path: Path) -> str:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 2_000_000:
        raise SafeFailure("fixed_input_unavailable")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _git(repo: Path, *args: str) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(repo), *args],
            check=True,
            capture_output=True,
            text=True,
            timeout=15,
            env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "GIT_CONFIG_NOSYSTEM": "1"},
        )
    except (OSError, subprocess.SubprocessError):
        raise SafeFailure("git_identity_unavailable") from None
    value = result.stdout.strip()
    if args and args[0] == "cat-file" and args[1:2] == ("-e",):
        return "present"
    if not value or "\n" in value:
        raise SafeFailure("git_identity_invalid")
    return value


def _case_spec(case_id: str) -> dict:
    if case_id == "pr466-v1":
        return {
            "case_dir": CASE_DIR,
            "manifest": MANIFEST,
            "checks": CHECKS,
            "limits": LIMITS,
            "profile": PROFILE,
            "schema": "historical-functional-review-pr466.v1",
            "profile_version": "slopsearx-production-v8-static-review-boundaries",
            "profile_sha256": PROFILE_SHA256,
            "checks_sha256": CHECKS_SHA256,
            "limits_sha256": LIMITS_SHA256,
            "input_cap": INPUT_CAP,
            "prepare_observation": None,
        }
    if case_id == "pr466-v2":
        return {
            "case_dir": V2_CASE_DIR,
            "manifest": V2_MANIFEST,
            "checks": V2_CHECKS,
            "limits": V2_LIMITS,
            "profile": V2_PROFILE,
            "schema": V2_MANIFEST_SCHEMA,
            "profile_version": V2_PROFILE_VERSION,
            "profile_sha256": V2_PROFILE_SHA256,
            "checks_sha256": V2_CHECKS_SHA256,
            "limits_sha256": V2_LIMITS_SHA256,
            "input_cap": V2_INPUT_CAP,
            "prepare_observation": V2_PREPARE_OBSERVATION,
        }
    if case_id == "pr466-v3":
        return {
            "case_dir": V3_CASE_DIR,
            "manifest": V3_MANIFEST,
            "checks": V3_CHECKS,
            "limits": V3_LIMITS,
            "profile": V3_PROFILE,
            "schema": V3_MANIFEST_SCHEMA,
            "profile_version": V3_PROFILE_VERSION,
            "profile_sha256": V3_PROFILE_SHA256,
            "checks_sha256": V3_CHECKS_SHA256,
            "limits_sha256": V3_LIMITS_SHA256,
            "input_cap": V3_INPUT_CAP,
            "prepare_observation": V3_PREPARE_OBSERVATION,
        }
    if case_id == "pr466-v4":
        return {
            "case_dir": V4_CASE_DIR,
            "manifest": V4_MANIFEST,
            "checks": V4_CHECKS,
            "limits": V4_LIMITS,
            "profile": V4_PROFILE,
            "schema": V4_MANIFEST_SCHEMA,
            "profile_version": V4_PROFILE_VERSION,
            "profile_sha256": V4_PROFILE_SHA256,
            "checks_sha256": V4_CHECKS_SHA256,
            "limits_sha256": V4_LIMITS_SHA256,
            "input_cap": V4_INPUT_CAP,
            "prepare_observation": V4_PREPARE_OBSERVATION,
        }
    raise SafeFailure("case_not_supported")


def _validate_source_and_inputs(case_id: str = DEFAULT_CASE) -> dict:
    spec = _case_spec(case_id)
    if os.environ.get("GITHUB_ACTIONS") == "true":
        if (
            os.environ.get("GITHUB_REPOSITORY") != "groktopus/codereview"
            or os.environ.get("GITHUB_REF") != "refs/heads/main"
            or os.environ.get("GITHUB_WORKFLOW_REF")
            != "groktopus/codereview/.github/workflows/historical-functional-review.yml@refs/heads/main"
        ):
            raise SafeFailure("untrusted_source_context")
        expected = os.environ.get("GITHUB_SHA", "")
        actual = _git(ROOT, "rev-parse", "HEAD")
        if not re.fullmatch(r"[0-9a-f]{40}", expected) or actual != expected:
            raise SafeFailure("untrusted_source_revision")
    if (
        _sha(spec["profile"]) != spec["profile_sha256"]
        or _sha(spec["checks"]) != spec["checks_sha256"]
        or _sha(spec["limits"]) != spec["limits_sha256"]
    ):
        raise SafeFailure("case_input_hash_mismatch")
    try:
        manifest_path = spec["manifest"]
        stat_result = manifest_path.lstat()
        if manifest_path.is_symlink() or not manifest_path.is_file() or stat_result.st_size > 32_000:
            raise SafeFailure("case_manifest_invalid")
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        raise SafeFailure("case_manifest_invalid") from None
    if not isinstance(manifest, dict):
        raise SafeFailure("case_manifest_invalid")
    case = manifest.get("case", {})
    profile = manifest.get("profile", {})
    checks = manifest.get("historical_checks", {})
    limits = manifest.get("limits", {})
    if not all(isinstance(item, dict) for item in (case, profile, checks, limits)):
        raise SafeFailure("case_manifest_invalid")
    provider_identity = manifest.get("provider_identity", {})
    retained = manifest.get("retained_prepare_observation", {})
    scope = manifest.get("diagnostic_scope", {})
    if not all(isinstance(item, dict) for item in (provider_identity, retained, scope)):
        raise SafeFailure("case_manifest_invalid")
    expected_fields = (
        {
            "schema",
            "case",
            "profile",
            "historical_checks",
            "limits",
            "provider_identity",
            "retained_prepare_observation",
            "diagnostic_scope",
        }
        if spec["prepare_observation"] is None
        else {
            "schema",
            "case",
            "profile",
            "historical_checks",
            "limits",
            "provider_identity",
            "prepare_observation",
            "diagnostic_scope",
        }
    )
    if (
        set(manifest) != expected_fields
        or manifest.get("schema") != spec["schema"]
        or case != {"repository": REPOSITORY, "pull_request_number": 466, "base_sha": BASE, "head_sha": HEAD}
        or profile.get("path") != str(spec["profile"].relative_to(ROOT))
        or profile.get("version") != spec["profile_version"]
        or profile.get("sha256") != spec["profile_sha256"]
        or checks.get("path") != str(spec["checks"].relative_to(ROOT))
        or checks.get("sha256") != spec["checks_sha256"]
        or checks.get("freshness_basis") != "HISTORICAL_SNAPSHOT"
        or limits.get("path") != str(spec["limits"].relative_to(ROOT))
        or limits.get("sha256") != spec["limits_sha256"]
        or provider_identity.get("status") != "UNKNOWN"
        or provider_identity.get("primary") != {"base_url": None, "model": None}
        or provider_identity.get("decision") != {"endpoint": None, "model": None}
        or scope.get("effect_policy") != "READ_ONLY"
        or scope.get("target_code_execution") is not False
        or scope.get("provider_calls_in_retained_prepare") != 0
        or scope.get("case_total_call_ceiling") != 12
        or scope.get("claim_assessment_max") != 1
        or scope.get("source_auditor_calls") != 0
    ):
        raise SafeFailure("case_manifest_binding_mismatch")
    if spec["prepare_observation"] is None:
        if (
            retained.get("status") != "PREPARED_ONLY"
            or retained.get("primary_request_count") != 7
            or retained.get("total_primary_serialized_input_bytes") != 353963
            or retained.get("max_claim_assessments") != 0
        ):
            raise SafeFailure("case_manifest_binding_mismatch")
    elif manifest.get("prepare_observation") != spec["prepare_observation"]:
        raise SafeFailure("case_prepare_observation_mismatch")
    return manifest


def _validate_target(repo: Path, case_id: str = DEFAULT_CASE) -> None:
    _case_spec(case_id)
    if repo.is_symlink() or not repo.is_dir():
        raise SafeFailure("target_bare_repository_unavailable")
    if _git(repo, "rev-parse", "--is-bare-repository") != "true":
        raise SafeFailure("target_must_be_bare_repository")
    for revision in (BASE, HEAD):
        _git(repo, "cat-file", "-e", f"{revision}^{{commit}}")


def _limits_valid(case_id: str = DEFAULT_CASE) -> None:
    spec = _case_spec(case_id)
    try:
        limits = json.loads(spec["limits"].read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        raise SafeFailure("limits_invalid") from None
    if not isinstance(limits, dict):
        raise SafeFailure("limits_invalid")
    expected = {
        "deadline_seconds": 600,
        "max_concurrent_scopes": 4,
        "max_provider_calls": CALL_CAP,
        "max_retries_per_task": 0,
        "max_context_bytes": CONTEXT_CAP,
        "max_input_bytes_per_task": spec["input_cap"],
        "max_output_bytes_per_task": 16_000,
        "max_output_bytes": 192_000,
        "max_output_tokens": 1800,
        "max_context_retrievals": 8,
        "max_followup_tasks": 0,
    }
    if any(limits.get(key) != value for key, value in expected.items()):
        raise SafeFailure("limits_contract_mismatch")


def _configs(directory: Path, *, live: bool) -> tuple[Path, Path]:
    sys.path.insert(0, str(ROOT / "src"))
    sys.path.insert(0, str(ROOT / "scripts"))
    from provider_config_from_env import configurations_from_environment, write_config_files

    if live:
        env = {
            name: os.environ.get(name, "")
            for name in ("LLM_BASE_URL", "LLM_MODEL", "LLM_API_KEY", "JEV_BASE_URL", "JEV_MODEL", "JEV_API_KEY")
        }
    else:
        env = {
            "LLM_BASE_URL": "https://inference-api.nousresearch.com/v1",
            "LLM_MODEL": "openai/gpt-6-luna",
            "LLM_API_KEY": "SIZING_ONLY_NOT_A_CREDENTIAL",
            "JEV_BASE_URL": "https://api.typesafe.ai/v1",
            "JEV_MODEL": "jev-latest",
            "JEV_API_KEY": "SIZING_ONLY_NOT_A_CREDENTIAL",
        }
    try:
        provider, decision = configurations_from_environment(env)
        paths = write_config_files(directory, provider, decision)
    except Exception:
        raise SafeFailure("provider_configuration_invalid") from None
    return Path(paths["provider_config"]), Path(paths["decision_config"])


def _cli(
    target: Path, output: Path, provider: Path, decision: Path, *, prepare: bool, case_id: str = DEFAULT_CASE
) -> dict:
    spec = _case_spec(case_id)
    command = [
        sys.executable,
        "-c",
        "from pr_review_harness.cli import main; raise SystemExit(main())",
        "review",
        "--repo",
        str(target),
        "--profile",
        str(spec["profile"]),
        "--provider-config",
        str(provider),
        "--decision-config",
        str(decision),
        "--limits",
        str(spec["limits"]),
        "--base",
        BASE,
        "--head",
        HEAD,
        "--historical-checks-json",
        str(spec["checks"]),
        "--output",
        str(output),
        "--max-claim-assessments",
        "1",
        "--json",
    ]
    if prepare:
        command.append("--prepare-only")
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT / "src")
    for inherited in (
        "GITHUB_EVENT_PATH",
        "GITHUB_TOKEN",
        "GH_TOKEN",
        "ACTIONS_RUNTIME_TOKEN",
        "ACTIONS_RUNTIME_URL",
        "ACTIONS_RESULTS_URL",
    ):
        env.pop(inherited, None)
    try:
        completed = subprocess.run(command, cwd=ROOT, env=env, capture_output=True, text=True, timeout=630)
    except (OSError, subprocess.SubprocessError):
        raise SafeFailure("review_cli_failed") from None
    if completed.returncode:
        raise SafeFailure("review_cli_failed")
    try:
        result = json.loads(completed.stdout)
    except json.JSONDecodeError:
        raise SafeFailure("review_cli_output_invalid") from None
    if not isinstance(result, dict):
        raise SafeFailure("review_cli_output_invalid")
    return result


def _validate_prepare(result: dict, case_id: str = DEFAULT_CASE, *, reference_observation: bool = True) -> None:
    spec = _case_spec(case_id)
    if result.get("no_provider_calls") is not True or result.get("no_target_code_execution") is not True:
        raise SafeFailure("prepare_invariant_failed")
    capacity = result.get("capacity", {})
    calls = capacity.get("exact_primary_call_demand")
    total_bytes = capacity.get("exact_primary_serialized_input_bytes")
    requests = result.get("primary_requests")
    review_scope = result.get("scope")
    request_sizes_valid = (
        isinstance(requests, list)
        and len(requests) <= CALL_CAP
        and all(
            isinstance(item, dict)
            and isinstance(item.get("input_bytes"), int)
            and not isinstance(item.get("input_bytes"), bool)
            and item["input_bytes"] > 0
            and item["input_bytes"] <= spec["input_cap"]
            for item in requests
        )
    )
    if (
        isinstance(calls, bool)
        or not isinstance(calls, int)
        or calls < 1
        or calls > CALL_CAP
        or isinstance(total_bytes, bool)
        or not isinstance(total_bytes, int)
        or total_bytes > CONTEXT_CAP
        or not request_sizes_valid
        or calls != len(requests)
        or sum(item["input_bytes"] for item in requests) != total_bytes
        or not isinstance(review_scope, dict)
        or review_scope.get("primary_scope_admission_complete") is not True
    ):
        raise SafeFailure("primary_request_capacity_exceeded")
    if case_id == "pr466-v4":
        if review_scope.get("required_context_gaps") != []:
            raise SafeFailure("dependency_projection_required_context_invalid")
        expected_requests = V4_PREPARE_OBSERVATION["primary_requests"]
        actual_requests = [
            {key: row.get(key) for key in ("task_id", "lens", "input_bytes", "input_sha256")} for row in requests
        ]
        if reference_observation:
            if actual_requests != expected_requests:
                raise SafeFailure("case_prepare_observation_mismatch")
        else:
            expected_scopes = [(row["task_id"], row["lens"]) for row in expected_requests]
            actual_scopes = [(row["task_id"], row["lens"]) for row in actual_requests]
            if actual_scopes != expected_scopes or any(
                not isinstance(row.get("input_sha256"), str) or not re.fullmatch(r"[0-9a-f]{64}", row["input_sha256"])
                for row in actual_requests
            ):
                raise SafeFailure("case_prepare_observation_mismatch")
        projection_tasks = []
        for request in requests:
            bindings = request.get("evidence_bindings")
            if not isinstance(bindings, list):
                raise SafeFailure("dependency_projection_required_context_invalid")
            matches = [
                binding
                for binding in bindings
                if isinstance(binding, dict) and binding.get("source_kind") == "dependency_projection"
            ]
            task_id = request.get("task_id")
            if task_id in V4_PROJECTION["included_primary_task_ids"]:
                if len(matches) != 1:
                    raise SafeFailure("dependency_projection_required_context_invalid")
                binding = matches[0]
                if any(
                    binding.get(key) != value
                    for key, value in V4_PROJECTION.items()
                    if key != "included_primary_task_ids"
                ):
                    raise SafeFailure("dependency_projection_required_context_invalid")
                projection_tasks.append(task_id)
            elif matches:
                raise SafeFailure("dependency_projection_required_context_invalid")
        if projection_tasks != V4_PROJECTION["included_primary_task_ids"]:
            raise SafeFailure("dependency_projection_required_context_invalid")


def _args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("prepare", "run"):
        item = sub.add_parser(name)
        item.add_argument("--target-bare", required=True, type=Path)
        item.add_argument("--output-dir", required=True, type=Path)
        item.add_argument("--case", choices=CASE_CHOICES, default=DEFAULT_CASE)
        item.add_argument("--manifest-dir", type=Path)
    return parser.parse_args()


def main() -> int:
    args = _args()
    try:
        spec = _case_spec(args.case)
        # Preserve the legacy flag, but it may name only the selected committed case.
        if args.manifest_dir is not None and args.manifest_dir.resolve() != spec["case_dir"].resolve():
            raise SafeFailure("manifest_directory_not_trusted")
        if args.command == "run" and (
            os.environ.get("GITHUB_ACTIONS") != "true"
            or os.environ.get("GITHUB_REPOSITORY") != "groktopus/codereview"
            or os.environ.get("GITHUB_EVENT_NAME") != "workflow_dispatch"
            or os.environ.get("GITHUB_REF") != "refs/heads/main"
            or os.environ.get("GITHUB_WORKFLOW_REF")
            != "groktopus/codereview/.github/workflows/historical-functional-review.yml@refs/heads/main"
        ):
            raise SafeFailure("live_mode_requires_trusted_workflow_dispatch")
        _validate_source_and_inputs(args.case)
        _limits_valid(args.case)
        _validate_target(args.target_bare, args.case)
        args.output_dir.mkdir(parents=True, exist_ok=False, mode=0o700)
        os.chmod(args.output_dir, 0o700)
        with tempfile.TemporaryDirectory(prefix="pr466-provider-config-") as temp:
            config_dir = Path(temp) / "config"
            provider, decision = _configs(config_dir, live=args.command == "run")
            prepared = _cli(
                args.target_bare.resolve(),
                args.output_dir / "prepare",
                provider,
                decision,
                prepare=True,
                case_id=args.case,
            )
            _validate_prepare(prepared, args.case, reference_observation=args.command == "prepare")
            observation = {
                "status": "PREPARED_ONLY",
                "provider_calls": 0,
                "target_code_executed": False,
                "case_id": args.case,
                "source_revision": _git(ROOT, "rev-parse", "HEAD"),
                "target_repository": REPOSITORY,
                "base_sha": BASE,
                "head_sha": HEAD,
                "profile_sha256": spec["profile_sha256"],
                "historical_checks_sha256": spec["checks_sha256"],
                "limits_sha256": spec["limits_sha256"],
                "capacity": prepared["capacity"],
                "scope": prepared.get("scope"),
                "primary_requests": [
                    {key: row.get(key) for key in ("task_id", "lens", "input_bytes", "input_sha256")}
                    for row in prepared.get("primary_requests", [])
                    if isinstance(row, dict)
                ],
            }
            if args.case == "pr466-v4":
                observation["dependency_projection"] = V4_PROJECTION
                observation["installed_runtime_resolution"] = "UNKNOWN_FROM_DECLARATION_PROJECTION"
            (args.output_dir / "prepare-observation.json").write_text(
                json.dumps(observation, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8"
            )
            if args.command == "prepare":
                print(
                    json.dumps(
                        {
                            "status": "PREPARED_ONLY",
                            "provider_calls": 0,
                            "prepare_observation": "prepare-observation.json",
                        },
                        separators=(",", ":"),
                    )
                )
                return 0
            result = _cli(
                args.target_bare.resolve(),
                args.output_dir / "review",
                provider,
                decision,
                prepare=False,
                case_id=args.case,
            )
            artifacts = []
            for key, destination, limit in (
                ("artifact_path", args.output_dir / "review-result.json", 8_000_000),
                ("report_path", args.output_dir / "review-report.md", 1_000_000),
            ):
                raw_path = result.get(key)
                if not isinstance(raw_path, str):
                    raise SafeFailure("review_artifact_missing")
                source = Path(raw_path)
                if source.is_symlink() or source.resolve().parent != (args.output_dir / "review").resolve():
                    raise SafeFailure("review_artifact_path_invalid")
                if not source.is_file() or source.stat().st_size > limit:
                    raise SafeFailure("review_artifact_size_invalid")
                shutil.copyfile(source, destination)
                artifacts.append(destination.name)
            print(
                json.dumps(
                    {
                        "status": "REVIEW_FINISHED",
                        "result": result.get("artifact_path"),
                        "safe_artifacts": artifacts,
                        "provider_calls": "see bounded ledger",
                    },
                    separators=(",", ":"),
                )
            )
            return 0
    except SafeFailure as exc:
        print(f"historical-functional-review: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
