#!/usr/bin/env python3
"""Run only the fixed, read-only historical SlopSearX provider trial."""

from __future__ import annotations

import argparse
import hashlib
import json
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
except ModuleNotFoundError:
    from scripts.prepare_real_case_batch import _bounded_run, _clean_git_env, git_command

ROOT = Path(__file__).resolve().parents[1]
INPUT_ROOT = ROOT / "docs" / "real-case-trial-v1"
CASES_SHA256 = "702a83e0c1456a8881416b5767eeda1aa9aac711ff51a68aecd0b609593f594b"
RUNTIME_SHA = "6bd412b6fb1477677700fa6e36b38e77075b1701"
RUNTIME_MODULE_TREE_SHA256 = "ec760753df9060f8bc156c1b141f7b8b2d319b0416d4e1e3f28be8f05977b976"
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
EXPECTED_JEV_ENDPOINT = "https://api.typesafe.ai/v1/systemone"
EXPECTED_JEV_ALIAS = "jev-latest"
SECRET_NAMES = ("LLM_API_KEY", "JEV_API_KEY")
OUTPUT_CAP = 1_000_000
STDERR_CAP = 128_000
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


def load_locked_cases() -> tuple[dict[str, Any], list[dict[str, Any]]]:
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


def selected_cases(mode: str, cases: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if mode == "staged-pr464":
        return [case for case in cases if case["case_id"] == "PR-464"]
    if mode == "full-three-case":
        return cases
    raise TrialError("trial_mode_invalid")


def build_configs(directory: Path) -> tuple[Path, Path, list[str]]:
    expected = {
        "LLM_BASE_URL": EXPECTED_LLM_ENDPOINT,
        "LLM_MODEL": EXPECTED_LLM_MODEL,
        "JEV_BASE_URL": EXPECTED_JEV_ENDPOINT,
        "JEV_MODEL": EXPECTED_JEV_ALIAS,
    }
    values: dict[str, str] = {}
    for name, exact in expected.items():
        value = os.environ.get(name)
        if value != exact:
            raise TrialError("provider_identity_configuration_mismatch")
        values[name] = value
    secrets = []
    for name in SECRET_NAMES:
        value = os.environ.get(name)
        if not value or len(value) > 4096 or any(ch in value for ch in "\r\n\x00"):
            raise TrialError("provider_credential_unavailable")
        secrets.append(value)
    secrets.extend(expected.values())

    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    os.chmod(directory, 0o700)
    llm = {
        "kind": "openai_compatible",
        "provider_id": "operator_openai_compatible",
        "base_url": values["LLM_BASE_URL"],
        "model": values["LLM_MODEL"],
        "api_key_env": "LLM_API_KEY",
        "timeout_seconds": 75,
        "max_request_bytes": 128000,
        "max_response_bytes": 16000,
        "max_output_tokens": 1800,
        "max_output_items": 100,
        "semantic_adjudication": True,
    }
    jev = {
        "kind": "typesafe",
        "endpoint": values["JEV_BASE_URL"],
        "model": values["JEV_MODEL"],
        "api_key_env": "JEV_API_KEY",
    }
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


def verify_runtime(cli: Path, runtime_source: Path) -> dict[str, Any]:
    if not runtime_source.is_dir() or not re.fullmatch(r"[0-9a-f]{40}", RUNTIME_SHA):
        raise TrialError("trusted_runtime_source_unavailable")
    try:
        from prepare_real_case_batch import installed_module_proof
    except ModuleNotFoundError:
        from scripts.prepare_real_case_batch import installed_module_proof

    if git_command(["--no-lazy-fetch", "-C", str(runtime_source), "rev-parse", "HEAD"], timeout=10) != RUNTIME_SHA:
        raise TrialError("trusted_runtime_revision_mismatch")
    proof = installed_module_proof(cli, runtime_source)
    if proof.get("module_file_count") != 28 or proof.get("module_tree_sha256") != RUNTIME_MODULE_TREE_SHA256:
        raise TrialError("installed_runtime_identity_mismatch")
    module_root = runtime_source / "src" / "pr_review_harness"
    inventory = sorted(path.relative_to(module_root).as_posix() for path in module_root.rglob("*.py") if path.is_file())
    if inventory != list(RUNTIME_MODULE_INVENTORY):
        raise TrialError("installed_runtime_inventory_mismatch")
    proof["module_inventory"] = inventory
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


def primary_receipts(prepared: dict[str, Any]) -> list[dict[str, Any]]:
    value = prepared["value"]
    snapshot = value["snapshot"]
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


def project_case(case: dict[str, Any], durable: dict[str, Any], secrets: list[str]) -> dict[str, Any]:
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
        "context_gaps": _project_gaps(durable.get("context_gaps")),
        "snapshot_gaps": _project_gaps(durable.get("snapshot_gaps")),
        "evidence_index": _project_evidence_index(evidence_index, candidates),
    }
    _scan(projection, secrets)
    return projection


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
    if not isinstance(value, dict):
        return {"status": "NOT_RUN"}
    result = {
        key: value.get(key) for key in ("status", "reason_code", "contract_version", "projection_valid") if key in value
    }
    assessments = value.get("response_assessments")
    if isinstance(assessments, dict):
        result["dimensions"] = {
            str(name)[:80]: {
                key: item[key]
                for key in ("status", "choice", "probability", "rationale", "evidence_refs", "reason_code")
                if isinstance(item, dict) and key in item
            }
            for name, item in list(assessments.items())[:16]
        }
    provenance = value.get("provenance")
    if isinstance(provenance, dict):
        result["identity"] = {
            key: provenance[key]
            for key in ("provider_id", "native_contract", "contract_version", "model_identity_source")
            if isinstance(provenance.get(key), str)
        }
        result["identity"]["provider_model_sha256"] = sha256(canonical(provenance.get("provider_model_id")))
    result["candidate_id"] = value.get("candidate_id", "UNKNOWN")
    return result


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


def _project_gaps(value: Any) -> list[dict[str, Any]]:
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
        "target",
        "rationale",
        "reason",
        "required",
        "retrievable",
    )
    return [{key: row[key] for key in fields if key in row} for row in value[:200] if isinstance(row, dict)]


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


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--mode", choices=("staged-pr464", "full-three-case"), required=True)
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
        "schema": "historical-real-case-trial-manifest.v1",
        "runtime_provenance_version": "historical-real-case-runtime.v2",
        "limits_version": "historical-real-case-limits.v2",
        "frozen_plan_manifest_sha256": FROZEN_PLAN_MANIFEST_SHA256,
        "status": "FAILED",
        "historical_only": True,
        "current_pr_state_checked": False,
        "publication_enabled": False,
        "target_code_execution": False,
        "mode": mode,
        "failure": {"stage": stage, "code": code},
        "runtime_revision": RUNTIME_SHA,
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
    _scan(manifest, secrets)
    if len(canonical(manifest)) > 4_000_000:
        raise TrialError("sanitized_manifest_limit_exceeded")
    summary = {
        "schema": manifest["schema"],
        "status": "FAILED",
        "failure": manifest["failure"],
        "provider_execution_state": provider_state,
        "cases": [{key: value for key, value in row.items() if key != "projection"} for row in rows],
    }
    _scan(summary, secrets, 128_000)
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
    secrets: list[str] = []
    active_case_id: str | None = None
    stage = "preflight"
    provider_call_attempted = False
    try:
        matrix_deadline = _matrix_deadline(args.run_provider_trial)
        if args.run_provider_trial:
            stage = "dispatch_preflight"
            verify_dispatch_context(ROOT)
        stage = "fixed_input_validation"
        document, all_cases = load_locked_cases()
        cases = selected_cases(args.mode, all_cases)
        stage = "artifact_setup"
        if args.artifacts.exists() or args.artifacts.is_symlink():
            raise TrialError("artifact_destination_already_exists")
        args.artifacts.mkdir(parents=True, mode=0o700)
        artifact_root_created = True
        os.chmod(args.artifacts, 0o700)
        stage = "runtime_identity_validation"
        runtime = verify_runtime(args.cli.resolve(strict=True), args.runtime_source.resolve(strict=True))
        output = args.artifacts / "private"
        private_root = output
        output.mkdir(mode=0o700)
        if args.prepare_only:
            stage = "prepare_configuration"
            # Guard the workflow process environment so prepare-only cannot read provider credentials.
            for name in SECRET_NAMES:
                os.environ.pop(name, None)
            provider_path, decision_path = build_prepare_configs(output)
        else:
            stage = "provider_configuration"
            provider_path, decision_path, secrets = build_configs(output / "configs")
        effective_env = _clean_git_env()
        # The CLI receives only known provider credentials; GitHub event/context variables are excluded.
        if not args.prepare_only:
            for name in ("LLM_API_KEY", "JEV_API_KEY"):
                effective_env[name] = os.environ[name]
        projection_failure = False
        matrix_calls = 24 if args.mode == "staged-pr464" else 64
        for case in cases:
            active_case_id = case["case_id"]
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
            validate_prepare(case, prep, 8_000_000)
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
                    "primary_request_receipts": primary_receipts(prep),
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
                projection = project_case(case, durable, secrets)
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
                "primary_request_receipts": primary_receipts(prep),
                "projection": projection,
            }
            _scan(row, secrets)
            results.append(row)
            # Raw provider and CLI data is removed immediately after bounded projection.
            shutil.rmtree(case_dir / "result")
            shutil.rmtree(case_dir / "prepared")
            if not args.target_bare:
                shutil.rmtree(bare)
            active_case_id = None
            stage = "case_complete"
        if projection_failure:
            results = _failure_rows(results, cases, None, "result_projection", "projection_incomplete")
        stage = "manifest_finalization"
        if matrix_deadline - time.monotonic() <= MATRIX_CLEANUP_RESERVE_SECONDS:
            raise TrialError("matrix_deadline_exceeded")
        manifest = {
            "schema": "historical-real-case-trial-manifest.v1",
            "runtime_provenance_version": "historical-real-case-runtime.v2",
            "limits_version": "historical-real-case-limits.v2",
            "frozen_plan_manifest_sha256": FROZEN_PLAN_MANIFEST_SHA256,
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
            "runtime_revision": RUNTIME_SHA,
            "runtime_wheel_sha256": os.environ.get("RUNTIME_WHEEL_SHA256", "UNKNOWN"),
            "runtime_module_proof": runtime,
            "runner_revision": os.environ.get("GITHUB_SHA", "local-uncommitted"),
            "workflow_matrix_started_epoch": os.environ.get("TRIAL_STARTED_EPOCH", "NOT_AVAILABLE"),
            "fixed_case_manifest_sha256": CASES_SHA256,
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
        _scan(manifest, secrets)
        if len(canonical(manifest)) > 4_000_000:
            raise TrialError("sanitized_manifest_limit_exceeded")
        cleanup_private(output)
        private_root = None
        summary = {
            "schema": manifest["schema"],
            "status": manifest["status"],
            "cases": [
                {key: value for key, value in item.items() if key != "projection"}
                | ({"case_id": item["case_id"], "status": item["status"]} if "projection" in item else {})
                for item in results
            ],
        }
        _scan(summary, secrets, 128_000)
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
        rows = _failure_rows(results, cases, active_case_id, stage, code)
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
                )
            except (OSError, RuntimeError, TrialError):
                pass
        # Errors are stable codes only; raw provider output, URLs, and credentials are never echoed.
        print(json.dumps({"status": "FAILED", "error": str(code)}, separators=(",", ":")))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
