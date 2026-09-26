#!/usr/bin/env python3
"""Run bounded, deterministic review experiments against the free-model allowlist.

This runner never executes reviewed repository code. It calls the harness CLI in
READ_ONLY mode, keeps only a minimized summary, and never stores child stdout,
stderr, prompts, or raw model results.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[1]
PILOT_SAMPLE_ID = "slopsearx-final-pilot-1790412393110125000"
HISTORICAL_PAIRS = (
    ("1cbde5b07e5c546d955d23ca1eb01652e9f353d6", "c1de456402961cf7d90703a4d8acca1a005392dc"),
    ("3c8bc043fd96168a25246e56587f691996c5ac2d", "c355830512fa5bffc167926a6a167bace93d96c6"),
    ("9dc787e96df24fec2b1fbff901f2f5f52b185c93", "3c8bc043fd96168a25246e56587f691996c5ac2d"),
    ("63e3ecd2f09d79c34e3594a3be74f017a1c5a12c", "9dc787e96df24fec2b1fbff901f2f5f52b185c93"),
    ("606d695515a400e9a50b18d5cfb9ef0e177e7fc5", "63e3ecd2f09d79c34e3594a3be74f017a1c5a12c"),
    ("20a743f0434a1843aa00068483f608f1e213b2af", "606d695515a400e9a50b18d5cfb9ef0e177e7fc5"),
)
MODEL_ALLOWLIST = {
    "solar": {
        "config_path": ROOT / "examples/provider.nous-test-solar.json",
        "model_id": "upstage/solar-pro4:free",
    },
    "stepfun": {
        "config_path": ROOT / "examples/provider.nous-test-stepfun.json",
        "model_id": "stepfun/step-3.7-flash:free",
    },
}
FREE_ENDPOINT = "https://inference-api.nousresearch.com/v1"
DEFAULT_CATALOG_MAX_AGE_SECONDS = 300
LIMITS_TEMPLATE = {
    "deadline_seconds": 150,
    "max_concurrent_scopes": 2,
    "max_provider_calls": 12,
    "max_retries_per_task": 0,
    "max_context_bytes": 300_000,
    "max_input_bytes_per_task": 64_000,
    "max_output_bytes_per_task": 16_000,
    "max_output_bytes": 192_000,
    "max_output_tokens": 1800,
    "max_context_retrievals": 8,
    "max_followup_tasks": 8,
    "schema_version": "1.0",
}
MAX_PAIR_COUNT = 6
MAX_RUN_TIMEOUT_SECONDS = 300
MAX_MATRIX_TIMEOUT_SECONDS = 3_600
MAX_CAPTURE_BYTES = 2_000_000
MAX_CHECK_EVIDENCE_BYTES = 2_000_000
MAX_CHECK_RUNS = 2_000
SECRET_ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
SHA = re.compile(r"[0-9a-f]{40}\Z")
SHA_ANY = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")


class MatrixError(ValueError):
    """A safe preflight or matrix-runner error code."""


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def digest_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hash_file(path: Path) -> str:
    try:
        return digest_bytes(path.read_bytes())
    except OSError:
        raise MatrixError("input_file_unavailable") from None


def bounded_check_file_hash(path: Path) -> str | None:
    try:
        with path.open("rb") as stream:
            data = stream.read(MAX_CHECK_EVIDENCE_BYTES + 1)
    except OSError:
        return None
    if len(data) > MAX_CHECK_EVIDENCE_BYTES:
        return None
    return digest_bytes(data)


def safe_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        raise MatrixError(f"invalid_{label}_json") from None
    if not isinstance(value, dict):
        raise MatrixError(f"invalid_{label}_json")
    return value


def _git(repo: Path, *args: str, timeout: float = 10) -> str:
    try:
        completed = subprocess.run(
            ["git", "-C", str(repo), *args],
            check=True,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError):
        raise MatrixError("git_preflight_failed") from None
    return completed.stdout.strip()


def resolve_pairs(repo: Path, *, sample: str | None, explicit_pairs: list[str]) -> tuple[str, list[dict[str, str]]]:
    if bool(sample) == bool(explicit_pairs):
        raise MatrixError("select_one_sample_or_explicit_pairs")
    if sample:
        if sample != "historical-pilot-v1":
            raise MatrixError("unknown_historical_sample")
        source_kind = "PURPOSIVE_FIRST_PARENT_PILOT"
        source_id = PILOT_SAMPLE_ID
        raw_pairs = HISTORICAL_PAIRS
    else:
        if not 1 <= len(explicit_pairs) <= MAX_PAIR_COUNT:
            raise MatrixError("explicit_pair_count_out_of_range")
        source_kind = "EXPLICIT_REVISION_PAIRS"
        source_id = "operator-supplied"
        parsed = []
        for value in explicit_pairs:
            if not isinstance(value, str) or value.count("..") != 1:
                raise MatrixError("pair_must_be_BASE..HEAD")
            base, head = value.split("..", 1)
            if not SHA.fullmatch(base) or not SHA.fullmatch(head) or base == head:
                raise MatrixError("pair_revisions_must_be_distinct_full_shas")
            parsed.append((base, head))
        raw_pairs = parsed
    pairs = []
    for index, (base, head) in enumerate(raw_pairs):
        if not SHA.fullmatch(base) or not SHA.fullmatch(head) or base == head:
            raise MatrixError("invalid_frozen_revision_pair")
        for revision in (base, head):
            resolved = _git(repo, "rev-parse", "--verify", "--end-of-options", f"{revision}^{{commit}}")
            if resolved != revision:
                raise MatrixError("revision_resolution_mismatch")
        pairs.append({"pair_id": f"pair-{index + 1:02d}", "base_sha": base, "head_sha": head})
    return source_kind, [{"sample_id": source_id, **pair} for pair in pairs]


def _source_file(path: Path) -> bool:
    relative = path.relative_to(ROOT)
    parts = set(relative.parts)
    if parts & {"artifacts", "__pycache__", ".venv", "venv", ".pytest_cache", ".ruff_cache"}:
        return False
    if any(part.endswith(".egg-info") for part in relative.parts):
        return False
    return path.is_file() and path.suffix in {".py", ".toml", ".json"}


def source_fingerprint() -> dict[str, Any]:
    selected = []
    for folder in (ROOT / "src", ROOT / "scripts", ROOT / "profiles", ROOT / "examples"):
        if folder.exists():
            selected.extend(path for path in folder.rglob("*") if _source_file(path))
    pyproject = ROOT / "pyproject.toml"
    if pyproject.is_file():
        selected.append(pyproject)
    hashes = {str(path.relative_to(ROOT)): hash_file(path) for path in sorted(set(selected))}
    revision = _git(ROOT, "rev-parse", "HEAD")
    dirty = bool(_git(ROOT, "status", "--porcelain"))
    return {
        "git_revision": revision,
        "working_tree_dirty": dirty,
        "file_hashes": hashes,
        "tree_hash": digest_bytes(canonical_json(hashes)),
    }


def load_model(model_key: str) -> tuple[dict[str, Any], dict[str, Any]]:
    if model_key not in MODEL_ALLOWLIST:
        raise MatrixError("model_not_allowlisted")
    entry = MODEL_ALLOWLIST[model_key]
    path = entry["config_path"]
    config = safe_json(path, "provider_config")
    if (
        config.get("kind") != "openai"
        or config.get("base_url") != FREE_ENDPOINT
        or config.get("model") != entry["model_id"]
        or not str(config.get("model", "")).endswith(":free")
        or config.get("input_price_per_million") != 0
        or config.get("output_price_per_million") != 0
        or not SECRET_ENV_NAME.fullmatch(str(config.get("api_key_env", "")))
    ):
        raise MatrixError("allowlisted_model_config_mismatch")
    identity = {
        "allowlist_key": model_key,
        "provider_id": config.get("provider_id", "openai-compatible"),
        "endpoint_id": config["base_url"],
        "configured_model_alias": config["model"],
        "credential_reference_name": config["api_key_env"],
        "config_path": str(path.relative_to(ROOT)),
        "config_sha256": hash_file(path),
        "declared_price_input_per_million": 0,
        "declared_price_output_per_million": 0,
    }
    return config, identity


def verify_model_catalog(
    path: Path,
    model_keys: list[str],
    *,
    now: datetime | None = None,
    max_age_seconds: int = DEFAULT_CATALOG_MAX_AGE_SECONDS,
) -> dict[str, Any]:
    """Require fresh catalog evidence that every selected model is still free."""
    try:
        data = path.read_bytes()
        catalog = json.loads(data)
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        raise MatrixError("model_catalog_unavailable_or_invalid") from None
    if len(data) > 20_000_000 or not isinstance(catalog, dict):
        raise MatrixError("model_catalog_unavailable_or_invalid")
    source = catalog.get("source")
    retrieved = catalog.get("retrieved_at")
    models = catalog.get("catalog", {}).get("data") if isinstance(catalog.get("catalog"), dict) else None
    if source != FREE_ENDPOINT + "/models" or not isinstance(retrieved, str) or not isinstance(models, list):
        raise MatrixError("model_catalog_provenance_invalid")
    try:
        catalog_time = datetime.fromisoformat(retrieved.replace("Z", "+00:00"))
        if catalog_time.tzinfo is None:
            raise ValueError
    except ValueError:
        raise MatrixError("model_catalog_timestamp_invalid") from None
    now = now or datetime.now(timezone.utc)
    age = (now - catalog_time.astimezone(timezone.utc)).total_seconds()
    if age < 0 or age > max_age_seconds:
        raise MatrixError("model_catalog_stale")
    by_id: dict[str, list[dict[str, Any]]] = {}
    for row in models:
        if isinstance(row, dict) and isinstance(row.get("id"), str):
            by_id.setdefault(row["id"], []).append(row)
    selected: dict[str, dict[str, Any]] = {}
    for model_key in model_keys:
        entry = MODEL_ALLOWLIST.get(model_key)
        if not entry:
            raise MatrixError("model_not_allowlisted")
        rows = by_id.get(entry["model_id"], [])
        if len(rows) != 1:
            raise MatrixError("model_catalog_identity_missing_or_ambiguous")
        pricing = rows[0].get("pricing")
        if not isinstance(pricing, dict):
            raise MatrixError("model_catalog_pricing_unavailable")
        try:
            prompt = Decimal(str(pricing["prompt"]))
            completion = Decimal(str(pricing["completion"]))
        except (KeyError, InvalidOperation, ValueError):
            raise MatrixError("model_catalog_pricing_unavailable") from None
        if not prompt.is_finite() or not completion.is_finite() or prompt != 0 or completion != 0:
            raise MatrixError("allowlisted_model_not_free_in_catalog")
        selected[model_key] = {
            "model_id": entry["model_id"],
            "catalog_prompt_price": str(prompt),
            "catalog_completion_price": str(completion),
        }
    return {
        "path": str(path.resolve()),
        "source": source,
        "retrieved_at": catalog_time.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
        "age_seconds_at_preflight": round(age, 2),
        "max_age_seconds": max_age_seconds,
        "sha256": digest_bytes(data),
        "selected_models": selected,
    }


def minimal_child_env(parent: dict[str, str], *, secret_name: str, home: Path, module_mode: bool) -> dict[str, str]:
    allowed = {
        "PATH",
        "LANG",
        "LC_ALL",
        "TMPDIR",
        "TMP",
        "TEMP",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "SYSTEMROOT",
        "WINDIR",
    }
    child = {key: parent[key] for key in allowed if key in parent}
    child["HOME"] = str(home)
    if module_mode:
        child["PYTHONPATH"] = str(ROOT / "src")
    if parent.get(secret_name):
        child[secret_name] = parent[secret_name]
    return child


def terminate_group(process: Any) -> None:
    try:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGKILL)
        else:
            process.kill()
    except (OSError, ProcessLookupError):
        try:
            process.kill()
        except OSError:
            pass


def invoke_cli(
    command: list[str],
    *,
    env: dict[str, str],
    cwd: Path,
    timeout_seconds: float,
) -> dict[str, Any]:
    """Invoke CLI with a process-group deadline; return only hashes and sizes."""
    started = time.monotonic()
    try:
        process = subprocess.Popen(
            command,
            cwd=str(cwd),
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=(os.name == "posix"),
        )
    except OSError:
        return {"run_status": "SPAWN_FAILED", "exit_code": None, "elapsed_ms": 0, "stdout_bytes": 0, "stderr_bytes": 0}
    try:
        remaining = timeout_seconds - (time.monotonic() - started)
        if remaining <= 0 and process.poll() is None:
            raise subprocess.TimeoutExpired(command, timeout_seconds)
        stdout, stderr = process.communicate(timeout=max(remaining, 0))
        timed_out = False
    except subprocess.TimeoutExpired:
        terminate_group(process)
        stdout, stderr = process.communicate()
        timed_out = True
    elapsed_ms = round((time.monotonic() - started) * 1000, 2)
    oversize = len(stdout) + len(stderr) > MAX_CAPTURE_BYTES
    stdout_hash = digest_bytes(stdout)
    stderr_hash = digest_bytes(stderr)
    stdout_text = stdout.decode("utf-8", errors="replace") if len(stdout) <= MAX_CAPTURE_BYTES else ""
    try:
        cli_result = json.loads(stdout_text) if stdout_text and process.returncode == 0 and not timed_out else None
    except json.JSONDecodeError:
        cli_result = None
    if timed_out:
        run_status = "RUN_TIMEOUT"
    elif oversize:
        run_status = "OUTPUT_LIMIT_EXCEEDED"
    elif process.returncode != 0:
        run_status = "CLI_FAILED"
    elif not isinstance(cli_result, dict):
        run_status = "INVALID_CLI_OUTPUT"
    else:
        run_status = "CLI_COMPLETED"
    return {
        "run_status": run_status,
        "exit_code": process.returncode,
        "elapsed_ms": elapsed_ms,
        "stdout_bytes": len(stdout),
        "stderr_bytes": len(stderr),
        "stdout_sha256": stdout_hash,
        "stderr_sha256": stderr_hash,
        "cli_result": cli_result if isinstance(cli_result, dict) else None,
    }


def safe_result_summary(result: dict[str, Any], provider_config: dict[str, Any]) -> dict[str, Any]:
    """Reduce the detailed CLI result to bounded operational evidence only."""
    task_results = result.get("task_results") if isinstance(result.get("task_results"), dict) else {}
    usage = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0, "known": False}
    usage_seen = False
    usage_complete = True
    estimated_usd = Decimal(0)
    estimated_seen = False
    estimated_known = True
    billed_usd = Decimal(0)
    billed_seen = False
    billed_known = True
    check_coverage = []
    model_ids: set[str] = set()
    errors: dict[str, int] = {}
    task_statuses: dict[str, int] = {}
    quarantine_kinds: dict[str, int] = {}
    quarantine_reasons: dict[str, int] = {}
    for row in task_results.values():
        if not isinstance(row, dict):
            continue
        status = row.get("status")
        if isinstance(status, str):
            task_statuses[status] = task_statuses.get(status, 0) + 1
        error = row.get("provider_error_code", row.get("error_code"))
        if isinstance(error, str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", error):
            errors[error] = errors.get(error, 0) + 1
        quarantined = row.get("quarantined_items")
        if isinstance(quarantined, list):
            for item in quarantined:
                if not isinstance(item, dict):
                    continue
                kind = item.get("kind")
                reason = item.get("reason_code")
                if isinstance(kind, str) and re.fullmatch(r"[a-z_]{1,100}", kind):
                    quarantine_kinds[kind] = quarantine_kinds.get(kind, 0) + 1
                if isinstance(reason, str) and re.fullmatch(r"[a-z0-9_]{1,100}", reason):
                    quarantine_reasons[reason] = quarantine_reasons.get(reason, 0) + 1
        error_meta = row.get("provider_error_meta") if isinstance(row.get("provider_error_meta"), dict) else {}
        provenance = row.get("provenance") if isinstance(row.get("provenance"), dict) else error_meta.get("provenance")
        if isinstance(provenance, dict):
            model = provenance.get("provider_reported_model_id", provenance.get("provider_model_id"))
            if isinstance(model, str) and re.fullmatch(r"[A-Za-z0-9_./:@+-]{1,200}", model):
                model_ids.add(model)
            cost = provenance.get("estimated_cost_usd")
            try:
                parsed_cost = Decimal(str(cost))
                if parsed_cost.is_finite() and parsed_cost >= 0:
                    estimated_usd += parsed_cost
                    estimated_seen = True
                else:
                    estimated_known = False
            except (InvalidOperation, ValueError):
                estimated_known = False
            billed = provenance.get("billed_cost_usd")
            if provenance.get("billed_cost_known") is True and billed is not None:
                try:
                    parsed_billed = Decimal(str(billed))
                    if parsed_billed.is_finite() and parsed_billed >= 0:
                        billed_usd += parsed_billed
                        billed_seen = True
                    else:
                        billed_known = False
                except (InvalidOperation, ValueError):
                    billed_known = False
            else:
                billed_known = False
        source = row.get("usage") if isinstance(row.get("usage"), dict) else error_meta.get("usage")
        if isinstance(source, dict):
            usage_seen = True
            for key in ("prompt_tokens", "completion_tokens", "total_tokens"):
                value = source.get(key)
                if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
                    usage[key] += value
                else:
                    usage_complete = False
            if source.get("known") is False:
                usage_complete = False
    coverage = result.get("coverage_ledger") if isinstance(result.get("coverage_ledger"), list) else []
    for row in coverage:
        if not isinstance(row, dict) or row.get("obligation_kind") != "PROJECT_CHECK":
            continue
        check_coverage.append(
            {
                "obligation_id": row.get("obligation_id") if isinstance(row.get("obligation_id"), str) else None,
                "check_binding_id": row.get("check_binding_id")
                if isinstance(row.get("check_binding_id"), str)
                else None,
                "state": row.get("state") if isinstance(row.get("state"), str) else None,
                "reason_code": row.get("reason_code") if isinstance(row.get("reason_code"), str) else None,
                "evidence_reference_count": len(row.get("evidence_refs", []))
                if isinstance(row.get("evidence_refs"), list)
                else None,
            }
        )
    return {
        "disposition": result.get("disposition") if isinstance(result.get("disposition"), str) else None,
        "coverage_state": result.get("coverage_state") if isinstance(result.get("coverage_state"), str) else None,
        "snapshot_id": result.get("snapshot_id") if isinstance(result.get("snapshot_id"), str) else None,
        "finding_count": len(result.get("findings", [])) if isinstance(result.get("findings"), list) else None,
        "project_check_coverage": sorted(check_coverage, key=lambda row: row.get("obligation_id") or ""),
        "task_statuses": task_statuses,
        "provider_error_codes": errors,
        "quarantined_items_by_kind": quarantine_kinds,
        "quarantine_reason_codes": quarantine_reasons,
        "provider_reported_model_ids": sorted(model_ids),
        "usage": {**usage, "known": usage_seen and usage_complete},
        "provider_estimated_cost_usd": str(estimated_usd) if estimated_seen and estimated_known else None,
        "provider_billed_cost_usd": str(billed_usd) if billed_seen and billed_known else None,
        "provider_billed_cost_known": billed_seen and billed_known,
        "budget": result.get("budget") if isinstance(result.get("budget"), dict) else None,
        "configured_model_alias": provider_config.get("model"),
    }


def atomic_write(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False, allow_nan=False) + "\n"
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_name, path)
    finally:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass


def _check_timeout(value: float, label: str, ceiling: int) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or value <= 0
        or value > ceiling
    ):
        raise MatrixError(f"invalid_{label}")
    return float(value)


def _make_command(
    *,
    cli: list[str],
    repo: Path,
    base: str,
    head: str,
    profile: Path,
    provider_config: Path,
    limits_path: Path,
    output: Path,
    run_id: str,
    historical_checks_json: Path | None = None,
) -> list[str]:
    command = [
        *cli,
        "review",
        "--repo",
        str(repo),
        "--base",
        base,
        "--head",
        head,
        "--profile",
        str(profile),
        "--provider-config",
        str(provider_config),
        "--limits",
        str(limits_path),
        "--output",
        str(output),
        "--run-id",
        run_id,
        "--effect-policy",
        "READ_ONLY",
        "--mode",
        "AUTO",
        "--json",
    ]
    if historical_checks_json is not None:
        command.extend(("--historical-checks-json", str(historical_checks_json)))
    return command


def _strict_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise MatrixError("check_evidence_json_duplicate_key")
        result[key] = value
    return result


def _reject_json_constant(_value: str) -> Any:
    raise MatrixError("check_evidence_json_invalid")


def _parse_finite_json_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise MatrixError("check_evidence_json_invalid")
    return parsed


def _validate_bounded_json_tree(value: Any) -> None:
    pending = [(value, 0)]
    nodes = 0
    while pending:
        current, depth = pending.pop()
        nodes += 1
        if nodes > 100_000 or depth > 64:
            raise MatrixError("check_evidence_json_invalid")
        if isinstance(current, float) and not math.isfinite(current):
            raise MatrixError("check_evidence_json_invalid")
        if isinstance(current, dict):
            pending.extend((item, depth + 1) for item in current.values())
        elif isinstance(current, list):
            pending.extend((item, depth + 1) for item in current)


def load_check_evidence_by_pair(
    checks_json_by_pair: dict[str, Path] | None,
    pairs: list[dict[str, str]],
    profile: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    """Load explicit check fixtures, each bound to one selected immutable pair."""
    if checks_json_by_pair is None:
        return {}
    if not isinstance(checks_json_by_pair, dict):
        raise MatrixError("invalid_checks_json_mapping")
    pair_rows = {pair.get("pair_id"): pair for pair in pairs if isinstance(pair, dict)}
    if len(pair_rows) != len(pairs) or any(not isinstance(key, str) or not key for key in pair_rows):
        raise MatrixError("invalid_or_duplicate_pair_id")
    if any(pair_id not in pair_rows for pair_id in checks_json_by_pair):
        raise MatrixError("check_evidence_pair_id_unknown")
    repository = profile.get("repository")
    if not isinstance(repository, str) or not REPOSITORY.fullmatch(repository):
        raise MatrixError("check_evidence_requires_trusted_profile_repository")
    loaded: dict[str, dict[str, Any]] = {}
    for pair_id, supplied_path in checks_json_by_pair.items():
        if not isinstance(pair_id, str) or not pair_id or not isinstance(supplied_path, (str, Path)):
            raise MatrixError("invalid_checks_json_mapping")
        path = Path(supplied_path).resolve()
        try:
            with path.open("rb") as stream:
                data = stream.read(MAX_CHECK_EVIDENCE_BYTES + 1)
        except OSError:
            raise MatrixError("check_evidence_unavailable") from None
        if len(data) > MAX_CHECK_EVIDENCE_BYTES:
            raise MatrixError("check_evidence_size_limit_exceeded")
        try:
            document = json.loads(
                data.decode("utf-8"),
                object_pairs_hook=_strict_json_object,
                parse_constant=_reject_json_constant,
                parse_float=_parse_finite_json_float,
            )
        except MatrixError:
            raise
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError):
            raise MatrixError("check_evidence_json_invalid") from None
        _validate_bounded_json_tree(document)
        pair = pair_rows[pair_id]
        if (
            not isinstance(document, dict)
            or document.get("schema_version") != "1.0"
            or document.get("repository") != repository
            or not REPOSITORY.fullmatch(str(document.get("repository", "")))
            or document.get("head_sha") != pair.get("head_sha")
            or not isinstance(document.get("head_sha"), str)
            or not SHA_ANY.fullmatch(document.get("head_sha", ""))
        ):
            raise MatrixError("check_evidence_repository_or_head_mismatch")
        pull_number = document.get("pull_request_number")
        if isinstance(pull_number, bool) or not isinstance(pull_number, int) or pull_number < 1:
            raise MatrixError("check_evidence_pull_request_invalid")
        captured_base = document.get("base_sha")
        if captured_base is not None and (
            not isinstance(captured_base, str)
            or not SHA_ANY.fullmatch(captured_base)
            or captured_base != pair.get("base_sha")
        ):
            raise MatrixError("check_evidence_base_mismatch")
        if not isinstance(document.get("complete", True), bool):
            raise MatrixError("check_evidence_completeness_invalid")
        runs = document.get("runs")
        if not isinstance(runs, list) or len(runs) > MAX_CHECK_RUNS or any(not isinstance(row, dict) for row in runs):
            raise MatrixError("check_evidence_runs_invalid")
        captured_at = document.get("captured_at")
        try:
            parsed_time = datetime.fromisoformat(str(captured_at).replace("Z", "+00:00"))
        except ValueError:
            raise MatrixError("check_evidence_timestamp_invalid") from None
        if parsed_time.tzinfo is None or parsed_time.utcoffset() is None:
            raise MatrixError("check_evidence_timestamp_invalid")
        loaded[pair_id] = {
            "path": str(path),
            "bytes": data,
            "sha256": digest_bytes(data),
            "repository": repository,
            "pull_request_number": pull_number,
            "base_sha": pair["base_sha"],
            "head_sha": pair["head_sha"],
        }
    return loaded


def run_matrix(
    *,
    repo: Path,
    profile_path: Path,
    output: Path,
    pairs: list[dict[str, str]],
    sample_kind: str,
    model_keys: list[str],
    per_run_timeout: float,
    matrix_timeout: float,
    model_catalog_path: Path = ROOT / "artifacts/nous-model-catalog.json",
    model_catalog_max_age_seconds: int = DEFAULT_CATALOG_MAX_AGE_SECONDS,
    cli_executable: str | None = None,
    clock: Callable[[], float] = time.monotonic,
    invoke: Callable[..., dict[str, Any]] = invoke_cli,
    environment: dict[str, str] | None = None,
    matrix_id: str | None = None,
    source_probe: Callable[[], dict[str, Any]] = source_fingerprint,
    checks_json_by_pair: dict[str, Path] | None = None,
) -> dict[str, Any]:
    if (
        not 1 <= len(model_keys) <= len(MODEL_ALLOWLIST)
        or len(set(model_keys)) != len(model_keys)
        or any(key not in MODEL_ALLOWLIST for key in model_keys)
    ):
        raise MatrixError("models_not_allowlisted")
    per_run_timeout = _check_timeout(per_run_timeout, "run_timeout", MAX_RUN_TIMEOUT_SECONDS)
    matrix_timeout = _check_timeout(matrix_timeout, "matrix_timeout", MAX_MATRIX_TIMEOUT_SECONDS)
    repo, profile_path, output = repo.resolve(), profile_path.resolve(), output.resolve()
    if not repo.is_dir() or not profile_path.is_file():
        raise MatrixError("repo_or_profile_unavailable")
    profile = safe_json(profile_path, "profile")
    profile_hash = hash_file(profile_path)
    checks_by_pair = load_check_evidence_by_pair(checks_json_by_pair, pairs, profile)
    check_evidence_identity = {
        pair_id: {key: item[key] for key in ("repository", "pull_request_number", "base_sha", "head_sha", "sha256")}
        for pair_id, item in sorted(checks_by_pair.items())
    }
    if cli_executable:
        executable = shutil.which(cli_executable) if not Path(cli_executable).is_absolute() else cli_executable
        if not executable or not Path(executable).is_file():
            raise MatrixError("installed_cli_unavailable")
        cli = [str(Path(executable).resolve())]
        module_mode = False
    else:
        cli = [sys.executable, "-m", "pr_review_harness"]
        module_mode = True
    if not matrix_id:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        matrix_id = f"test-matrix-{stamp}-{uuid.uuid4().hex[:8]}"
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,100}", matrix_id):
        raise MatrixError("invalid_matrix_id")
    manifest_path = output / f"{matrix_id}.json"
    manifest: dict[str, Any] = {
        "manifest_version": "test-matrix.v1",
        "matrix_id": matrix_id,
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "sample_kind": sample_kind,
        "quality_labels": "none",
        "repo_path": str(repo),
        "profile": {"path": str(profile_path), "version": profile.get("version"), "sha256": profile_hash},
        "source": {},
        "limits": {
            **LIMITS_TEMPLATE,
            "deadline_seconds": min(LIMITS_TEMPLATE["deadline_seconds"], per_run_timeout - 1),
        },
        "per_run_timeout_seconds": per_run_timeout,
        "matrix_timeout_seconds": matrix_timeout,
        "models": [],
        "pairs": pairs,
        "runs": [],
        "status": "RUNNING",
        "limitations": [
            "Compatibility and harness-operation evidence only; no quality or cutover claim.",
            "Historical pilot pairs are not a representative held-out dataset or exact PR-only diffs.",
            "Operator-supplied pairs are immutable revision pairs; a PR identity is not verified by this runner.",
            "No target code is executed and no review is published.",
            "Catalog prices and configured zero prices are preflight observations, not authoritative proof of provider billing.",
            "Provider-billed cost remains UNKNOWN unless the provider supplies authoritative billed-usage metadata.",
        ],
    }
    loaded = {key: load_model(key) for key in model_keys}
    source = source_probe()
    input_identity_sha256 = digest_bytes(
        canonical_json(
            {
                "pairs": pairs,
                "profile_sha256": profile_hash,
                "models": {key: identity["config_sha256"] for key, (_config, identity) in loaded.items()},
                "checks_json_by_pair": check_evidence_identity,
            }
        )
    )
    manifest["source"] = source
    manifest["checks_json_by_pair"] = check_evidence_identity
    manifest["input_identity_sha256"] = input_identity_sha256
    manifest["source_integrity"] = "STABLE"
    last_source = source
    manifest["models"] = [identity for _, identity in loaded.values()]
    if (
        isinstance(model_catalog_max_age_seconds, bool)
        or not isinstance(model_catalog_max_age_seconds, int)
        or model_catalog_max_age_seconds < 1
        or model_catalog_max_age_seconds > 604_800
    ):
        raise MatrixError("invalid_model_catalog_max_age")
    manifest["model_catalog"] = verify_model_catalog(
        model_catalog_path, model_keys, max_age_seconds=model_catalog_max_age_seconds
    )
    runtime = {
        "mode": "workspace_module" if module_mode else "installed_executable",
        "command": cli,
        "workspace_source_tree_hash": source["tree_hash"],
        "actual_runtime_source": "workspace_source_tree" if module_mode else "UNKNOWN",
        "actual_runtime_source_hash": source["tree_hash"] if module_mode else None,
        "python_executable": str(Path(sys.executable).resolve()),
        "python_version": sys.version.split()[0],
    }
    if not module_mode:
        runtime["cli_executable_sha256"] = hash_file(Path(cli[0]))
    manifest["runtime"] = runtime
    env_parent = environment if environment is not None else dict(os.environ)
    required_credentials = {config["api_key_env"] for config, _identity in loaded.values()}
    available = {name: bool(env_parent.get(name)) for name in required_credentials}
    manifest["credential_references"] = {
        name: {"available": available[name], "value_recorded": False} for name in sorted(required_credentials)
    }
    if not all(available.values()):
        manifest["status"] = "PREFLIGHT_FAILED"
        manifest["preflight_error"] = "credential_unavailable"
        atomic_write(manifest_path, manifest)
        raise MatrixError("credential_unavailable")
    started_at = clock()
    matrix_deadline = started_at + matrix_timeout
    stop_scheduling = False
    for pair_index, pair in enumerate(pairs):
        # Rotate model order by pair while still evaluating each selected model on
        # each identical immutable pair.
        rotation = pair_index % len(model_keys)
        schedule = model_keys[rotation:] + model_keys[:rotation]
        for model_key in schedule:
            if stop_scheduling or clock() >= matrix_deadline:
                stop_scheduling = True
                break
            config, model_identity = loaded[model_key]
            run_id = f"{matrix_id}-{pair['pair_id']}-{model_key}"
            run_row = {
                "run_id": run_id,
                "sample_kind": sample_kind,
                "pair_id": pair["pair_id"],
                "sample_id": pair.get("sample_id"),
                "base_sha": pair["base_sha"],
                "head_sha": pair["head_sha"],
                "model": model_identity,
                "profile_sha256": profile_hash,
                "source_tree_hash": source["tree_hash"],
                "runtime_source_hash": runtime["actual_runtime_source_hash"],
                "input_identity_sha256": input_identity_sha256,
                "check_evidence": check_evidence_identity.get(pair["pair_id"]),
                "run_status": "PENDING",
            }
            current_source = source_probe()
            last_source = current_source
            current_profile_hash = hash_file(profile_path)
            current_config_hash = hash_file(MODEL_ALLOWLIST[model_key]["config_path"])
            check_evidence = checks_by_pair.get(pair["pair_id"])
            current_check_hash = bounded_check_file_hash(Path(check_evidence["path"])) if check_evidence else None
            if (
                current_source["tree_hash"] != source["tree_hash"]
                or current_source.get("git_revision") != source.get("git_revision")
                or current_profile_hash != profile_hash
                or current_config_hash != model_identity["config_sha256"]
                or (check_evidence and current_check_hash != check_evidence["sha256"])
            ):
                run_row["run_status"] = "SOURCE_OR_CONFIGURATION_MUTATED_BEFORE_RUN"
                run_row["observed_source_tree_hash"] = current_source["tree_hash"]
                manifest["runs"].append(run_row)
                manifest["source_integrity"] = "MUTATED"
                manifest["final_source"] = current_source
                manifest["status"] = "INCOMPLETE"
                stop_scheduling = True
                atomic_write(manifest_path, manifest)
                break
            remaining = matrix_deadline - clock()
            timeout = min(per_run_timeout, remaining)
            run_limits = {**LIMITS_TEMPLATE, "deadline_seconds": min(LIMITS_TEMPLATE["deadline_seconds"], timeout - 1)}
            if run_limits["deadline_seconds"] <= 0:
                run_row["run_status"] = "SKIPPED_MATRIX_DEADLINE"
                manifest["runs"].append(run_row)
                stop_scheduling = True
                atomic_write(manifest_path, manifest)
                break
            with tempfile.TemporaryDirectory(prefix="pr-review-matrix-") as work:
                tmp = Path(work)
                isolated_home = tmp / "home"
                isolated_home.mkdir()
                ephemeral_config = dict(config)
                config_path = tmp / "provider.json"
                limits_path = tmp / "limits.json"
                config_path.write_bytes(canonical_json(ephemeral_config))
                limits_path.write_bytes(canonical_json(run_limits))
                output_path = tmp / "output"
                output_path.mkdir()
                staged_checks = None
                if check_evidence:
                    staged_checks = tmp / "historical-checks.json"
                    staged_checks.write_bytes(check_evidence["bytes"])
                command = _make_command(
                    cli=cli,
                    repo=repo,
                    base=pair["base_sha"],
                    head=pair["head_sha"],
                    profile=profile_path,
                    provider_config=config_path,
                    limits_path=limits_path,
                    output=output_path,
                    run_id=run_id,
                    historical_checks_json=staged_checks,
                )
                child_env = minimal_child_env(
                    env_parent, secret_name=config["api_key_env"], home=isolated_home, module_mode=module_mode
                )
                invocation = invoke(command, env=child_env, cwd=ROOT, timeout_seconds=timeout)
                post_source = source_probe()
                last_source = post_source
                post_profile_hash = hash_file(profile_path)
                post_config_hash = hash_file(MODEL_ALLOWLIST[model_key]["config_path"])
                post_check_hash = bounded_check_file_hash(Path(check_evidence["path"])) if check_evidence else None
                cli_result = invocation.pop("cli_result", None)
                run_row.update(invocation)
                if (
                    post_source["tree_hash"] != source["tree_hash"]
                    or post_source.get("git_revision") != source.get("git_revision")
                    or post_profile_hash != profile_hash
                    or post_config_hash != model_identity["config_sha256"]
                    or (check_evidence and post_check_hash != check_evidence["sha256"])
                ):
                    run_row["observed_source_tree_hash"] = post_source["tree_hash"]
                    run_row["outcome_before_integrity_check"] = run_row.get("run_status")
                    run_row["run_status"] = "SOURCE_OR_CONFIGURATION_MUTATED_DURING_RUN"
                    manifest["source_integrity"] = "MUTATED"
                    manifest["final_source"] = post_source
                    stop_scheduling = True
                elif run_row.get("run_status") == "CLI_COMPLETED" and isinstance(cli_result, dict):
                    run_row["result"] = safe_result_summary(cli_result, config)
                    run_row["run_status"] = "COMPLETED" if run_row.get("exit_code") == 0 else "CLI_FAILED"
                elif run_row.get("run_status") == "CLI_COMPLETED":
                    run_row["run_status"] = "INVALID_CLI_OUTPUT"
                run_row["provider_config_sha256"] = model_identity["config_sha256"]
                run_row["ephemeral_provider_config_sha256"] = hash_file(config_path)
                run_row["limits_sha256"] = hash_file(limits_path)
            manifest["runs"].append(run_row)
            atomic_write(manifest_path, manifest)
        if stop_scheduling:
            break
    expected = len(pairs) * len(model_keys)
    completed = sum(row.get("run_status") == "COMPLETED" for row in manifest["runs"])
    if len(manifest["runs"]) < expected:
        for pair in pairs:
            for model_key in model_keys:
                if not any(
                    row["pair_id"] == pair["pair_id"] and row["model"].get("allowlist_key") == model_key
                    for row in manifest["runs"]
                ):
                    _config, identity = loaded[model_key]
                    skipped_status = (
                        "SKIPPED_SOURCE_MUTATION"
                        if manifest.get("source_integrity") == "MUTATED"
                        else "SKIPPED_MATRIX_DEADLINE"
                    )
                    manifest["runs"].append(
                        {
                            "run_id": f"{matrix_id}-{pair['pair_id']}-{model_key}",
                            "sample_kind": sample_kind,
                            "pair_id": pair["pair_id"],
                            "sample_id": pair.get("sample_id"),
                            "base_sha": pair["base_sha"],
                            "head_sha": pair["head_sha"],
                            "model": identity,
                            "run_status": skipped_status,
                            "provider_config_sha256": identity["config_sha256"],
                            "profile_sha256": profile_hash,
                            "source_tree_hash": source["tree_hash"],
                            "input_identity_sha256": input_identity_sha256,
                            "check_evidence": check_evidence_identity.get(pair["pair_id"]),
                        }
                    )
    for model_key in model_keys:
        rows = [row for row in manifest["runs"] if row.get("model", {}).get("allowlist_key") == model_key]
        manifest.setdefault("model_summaries", []).append(
            {
                "model": loaded[model_key][1],
                "scheduled_runs": len(rows),
                "completed_runs": sum(row.get("run_status") == "COMPLETED" for row in rows),
                "run_status_counts": _counts(row.get("run_status") for row in rows),
            }
        )
    manifest["summary"] = {
        "scheduled_runs": expected,
        "completed_runs": completed,
        "run_status_counts": _counts(row.get("run_status") for row in manifest["runs"]),
    }
    manifest["status"] = "COMPLETE" if completed == expected else "INCOMPLETE"
    manifest["final_source"] = last_source
    if profile_hash != hash_file(profile_path) or any(
        hash_file(MODEL_ALLOWLIST[key]["config_path"]) != loaded[key][1]["config_sha256"] for key in model_keys
    ):
        manifest["source_integrity"] = "MUTATED"
        manifest["status"] = "INCOMPLETE"
    manifest["finished_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    atomic_write(manifest_path, manifest)
    manifest["manifest_path"] = str(manifest_path)
    return manifest


def _counts(values: Any) -> dict[str, int]:
    counts: dict[str, int] = {}
    for value in values:
        if isinstance(value, str):
            counts[value] = counts.get(value, 0) + 1
    return counts


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--sample", choices=["historical-pilot-v1"], help="repeat the six exact frozen pilot base/head pairs"
    )
    group.add_argument("--pair", action="append", help="explicit immutable BASE..HEAD pair; repeat up to six times")
    parser.add_argument("--repo", required=True, help="local SlopSearX Git checkout or bare repository")
    parser.add_argument("--profile", default=str(ROOT / "profiles/slopsearx.json"), help="trusted profile JSON")
    parser.add_argument(
        "--output", default=str(ROOT / "artifacts/test-matrix"), help="directory for sanitized matrix manifest"
    )
    parser.add_argument(
        "--model",
        action="append",
        choices=sorted(MODEL_ALLOWLIST),
        help="allowlisted model; repeat to select order (default: solar, stepfun)",
    )
    parser.add_argument(
        "--model-catalog",
        default=str(ROOT / "artifacts/nous-model-catalog.json"),
        help="fresh captured Nous /models response with retrieval timestamp and source",
    )
    parser.add_argument("--model-catalog-max-age-seconds", type=int, default=DEFAULT_CATALOG_MAX_AGE_SECONDS)
    parser.add_argument("--run-timeout-seconds", type=float, default=180)
    parser.add_argument("--matrix-timeout-seconds", type=float, default=3600)
    parser.add_argument(
        "--cli-executable",
        help="absolute path or PATH name of installed pr-review; default invokes this source tree as a module",
    )
    parser.add_argument("--matrix-id", help="stable safe ID for the output manifest")
    parser.add_argument(
        "--checks-json",
        action="append",
        metavar="PAIR_ID=PATH",
        help="explicit captured historical check evidence bound to one selected pair; repeat per pair",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        repo = Path(args.repo).resolve()
        sample_kind, pairs = resolve_pairs(repo, sample=args.sample, explicit_pairs=args.pair or [])
        model_keys = args.model or ["solar", "stepfun"]
        checks_json_by_pair = {}
        for assignment in args.checks_json or []:
            if not isinstance(assignment, str) or assignment.count("=") < 1:
                raise MatrixError("checks_json_must_be_PAIR_ID_equals_PATH")
            pair_id, path = assignment.split("=", 1)
            if not pair_id or not path or pair_id in checks_json_by_pair:
                raise MatrixError("checks_json_pair_id_missing_or_duplicate")
            checks_json_by_pair[pair_id] = Path(path)
        result = run_matrix(
            repo=repo,
            profile_path=Path(args.profile),
            output=Path(args.output),
            pairs=pairs,
            sample_kind=sample_kind,
            model_keys=model_keys,
            per_run_timeout=args.run_timeout_seconds,
            matrix_timeout=args.matrix_timeout_seconds,
            model_catalog_path=Path(args.model_catalog),
            model_catalog_max_age_seconds=args.model_catalog_max_age_seconds,
            cli_executable=args.cli_executable,
            matrix_id=args.matrix_id,
            checks_json_by_pair=checks_json_by_pair or None,
        )
    except MatrixError as exc:
        print(json.dumps({"error": str(exc), "status": "PREFLIGHT_FAILED"}, separators=(",", ":")), file=sys.stderr)
        return 2
    print(
        json.dumps(
            {
                "matrix_id": result["matrix_id"],
                "status": result["status"],
                "manifest_path": result["manifest_path"],
                "summary": result["summary"],
                "models": [row["model"] for row in result["model_summaries"]],
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0 if result["status"] == "COMPLETE" else 1


if __name__ == "__main__":
    raise SystemExit(main())
