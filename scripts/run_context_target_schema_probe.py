#!/usr/bin/env python3
"""Compare two fixed target-schema encodings against one frozen PR305 task.

The workflow is manually gated and supplies only the configured LLM endpoint,
model, and credential. This script has no caller-controlled repository, commit,
profile, request, or URL inputs and makes at most two provider attempts.
"""

from __future__ import annotations

import copy
import hashlib
import io
import json
import math
import os
import re
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from pr_review_harness import contracts
from pr_review_harness.engine import _evidence_for, _hash, effective_task_input_ceiling, prepare_plan_tasks
from pr_review_harness.planner import plan_review
from pr_review_harness.providers import OpenAIProvider, ProviderError
from pr_review_harness.snapshot import collect_snapshot

REPOSITORY = "groktopus/codereview"
TARGET_REPOSITORY = "magnus919/SlopSearX"
BASE_SHA = "00accc58a42eaa470e12831498b572cab2483981"
HEAD_SHA = "90165dd65be3595006171d7abef34a082c90a71d"
PROFILE_SHA256 = "28725e806a87812386ff67f5c6e63320cc9f3f2b9c1a79c6942c7cf1be004dac"
LIMITS_SHA256 = "ec191dcde1672b4f86aac24ee6412752cd9a08871d1aba1b332d11341b6fd2a6"
TASK_ID = "task-0151e9e9cad39a3b:chunk-1"
TASK_INPUT_SHA256 = "5e9d85b07e220c49103a13d2e20ef77e5e9c8da0f392e9db84b46260b9f94b73"
MANIFEST_SHA256 = "6b342ead0b67b0ab9df1c100f249d12621d2d4894507dbc1ee82d1284c79f3e0"
LEGACY_PROVIDER_COMMIT = "b075e50db01154cbd996a5549afef62f065df2d9"
LEGACY_PROVIDER_FILE_SHA256 = "2044a9fed9fcbcab4846b842df3b725043f92ac37c85a05850976449de8ad4c8"
UNIT_IDS = [
    "unit-9ec6727d1355643feb4e",
    "unit-d857a6647fc0642fe459",
    "unit-a375830d2b400d606450",
]
TARGET_LENS = "maintainability"
HISTORICAL_OLD_ERROR = {"status": 400, "response_bytes": 211,
                        "response_sha256": "63770a1ce1eb574d5791e070af9a4caf18754328f806e076e7d2cac6ae0ccffc"}
PROFILE_PATH = "profiles/slopsearx-v17-context-target-manifest-candidate.json"
LIMITS_PATH = "profiles/ordinary-review-limits-v3.json"
OUTPUT_NAME = "context-target-schema-probe-summary.json"
PREPARATION_NAME = "context-target-schema-probe-preparation.json"


def _legacy_request_from_archived_provider(
    root: Path, task: dict, evidence: list[dict], limits: dict, model: str
) -> bytes:
    """Run the actual archived provider implementation against the fresh task."""
    provider_path = "src/pr_review_harness/providers.py"
    file_hash = subprocess.run(
        ["git", "-C", str(root), "show", f"{LEGACY_PROVIDER_COMMIT}:{provider_path}"],
        capture_output=True,
        timeout=20,
        check=True,
    ).stdout
    if hashlib.sha256(file_hash).hexdigest() != LEGACY_PROVIDER_FILE_SHA256:
        raise ValueError("probe_legacy_provider_source_mismatch")
    with tempfile.TemporaryDirectory(prefix="context-target-legacy-provider-") as temp_name:
        temp = Path(temp_name)
        archive = subprocess.run(
            ["git", "-C", str(root), "archive", LEGACY_PROVIDER_COMMIT, "src/pr_review_harness"],
            capture_output=True,
            timeout=30,
            check=True,
        ).stdout
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as tar:
            tar.extractall(temp, filter="data")
        child = r"""
import json, sys
from pr_review_harness.providers import OpenAIProvider
payload = json.load(sys.stdin)
provider = OpenAIProvider({
    "kind": "openai_compatible", "provider_id": "schema-compatibility-probe",
    "base_url": "https://offline.invalid/v1", "model": payload["model"],
    "api_key_env": "PROBE_UNUSED_KEY", "max_request_bytes": payload["limits"]["max_input_bytes_per_task"],
    "max_response_bytes": payload["limits"]["max_output_bytes_per_task"],
    "max_output_tokens": payload["limits"]["max_output_tokens"], "timeout_seconds": 30,
})
system, user, schema = provider._review_parts(payload["task"], payload["evidence"])
sys.stdout.write(provider._request_bytes(system, user, schema, payload["limits"]).decode("utf-8"))
"""
        env = dict(os.environ)
        env["PYTHONPATH"] = str(temp / "src")
        env.pop("LLM_API_KEY", None)
        completed = subprocess.run(
            [sys.executable, "-c", child],
            input=json.dumps(
                {"task": task, "evidence": evidence, "limits": limits, "model": model},
                separators=(",", ":"),
            ),
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
            env=env,
        )
        if completed.returncode:
            raise ValueError("probe_legacy_provider_prepare_failed")
        return completed.stdout.encode("utf-8")


def _request_schema_pair(root: Path, provider: OpenAIProvider, task: dict, evidence: list[dict], limits: dict):
    system, user, candidate_schema = provider._review_parts(task, evidence)
    candidate_body = provider._request_bytes(system, user, candidate_schema, limits)
    legacy_body = _legacy_request_from_archived_provider(root, task, evidence, limits, provider.model)

    legacy_doc, candidate_doc = json.loads(legacy_body), json.loads(candidate_body)
    legacy_schema = copy.deepcopy(legacy_doc["response_format"]["json_schema"])
    legacy_target = legacy_doc["response_format"]["json_schema"]["schema"]["properties"]
    candidate_target = candidate_doc["response_format"]["json_schema"]["schema"]["properties"]
    legacy_target["context_gap_proposals"]["items"]["properties"]["target"] = None
    candidate_target["context_gap_proposals"]["items"]["properties"]["target"] = None
    if legacy_doc != candidate_doc:
        raise ValueError("probe_request_diff_exceeds_target_schema")
    return system, user, legacy_schema, candidate_schema, legacy_body, candidate_body


def _exchange_receipt(metadata: Any) -> dict[str, Any] | None:
    if not isinstance(metadata, dict):
        return None
    exchange = metadata.get("local_http_exchange")
    if isinstance(exchange, dict) and exchange.get("contract_version") == "local-http-exchange.v1":
        return exchange
    provenance = metadata.get("provenance")
    exchange = provenance.get("local_http_exchange") if isinstance(provenance, dict) else None
    return (
        exchange
        if isinstance(exchange, dict) and exchange.get("contract_version") == "local-http-exchange.v1"
        else None
    )


def _safe_exchange_fields(exchange: dict[str, Any] | None) -> dict[str, Any]:
    def nonnegative_int(key: str) -> int | None:
        value = exchange.get(key) if exchange is not None else None
        return value if type(value) is int and value >= 0 else None

    def sha256(key: str) -> str | None:
        value = exchange.get(key) if exchange is not None else None
        return value if isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) else None

    elapsed = exchange.get("elapsed_ms") if exchange is not None else None
    elapsed = elapsed if (
        isinstance(elapsed, (int, float))
        and not isinstance(elapsed, bool)
        and math.isfinite(elapsed)
        and elapsed >= 0
    ) else None
    status = exchange.get("http_status") if exchange is not None else None
    status = status if type(status) is int and 100 <= status <= 599 else None
    attempted = exchange.get("request_attempted") if exchange is not None else None
    attempted = attempted if isinstance(attempted, bool) else None
    return {
        "receipt_state": "RECORDED" if exchange is not None else "UNKNOWN",
        "http_status": status,
        "request_attempted": attempted,
        "request_bytes": nonnegative_int("request_bytes"),
        "request_sha256": sha256("request_sha256"),
        "response_bytes": nonnegative_int("response_bytes"),
        "response_sha256": sha256("response_sha256"),
        "elapsed_ms": elapsed,
    }


def _run_variant(provider, *, system, user, schema, limits, body) -> dict:
    try:
        _parsed, metadata = provider._call(
            system=system,
            user=user,
            schema=schema,
            limits=limits,
            contract_version=contracts.SPECIALIST_V4,
            serialized_request_bytes=body,
        )
        return {
            "state": "HTTP_RESPONSE",
            **_safe_exchange_fields(_exchange_receipt(metadata)),
        }
    except ProviderError as exc:
        code = exc.code if isinstance(exc.code, str) and re.fullmatch(r"[a-z0-9_]{1,100}", exc.code) else "provider_error"
        return {
            "state": "PROVIDER_ERROR",
            "error_code": code,
            **_safe_exchange_fields(_exchange_receipt(exc.meta)),
        }
    except Exception as exc:
        metadata = getattr(exc, "meta", {})
        return {
            "state": "LOCAL_ERROR",
            "error_code": "unexpected_probe_error",
            **_safe_exchange_fields(_exchange_receipt(metadata)),
        }


def _require_runtime_context(prepare_only: bool = False) -> Path:
    if not prepare_only and (
        os.environ.get("GITHUB_EVENT_NAME") != "workflow_dispatch"
        or os.environ.get("GITHUB_REPOSITORY") != REPOSITORY
        or os.environ.get("GITHUB_REF") != "refs/heads/main"
        or not re.fullmatch(r"[0-9a-f]{40}", os.environ.get("GITHUB_SHA", ""))
    ):
        raise ValueError("probe_dispatch_context_invalid")
    root = Path(__file__).resolve().parents[1]
    if hashlib.sha256((root / PROFILE_PATH).read_bytes()).hexdigest() != PROFILE_SHA256:
        raise ValueError("probe_profile_hash_mismatch")
    if hashlib.sha256((root / LIMITS_PATH).read_bytes()).hexdigest() != LIMITS_SHA256:
        raise ValueError("probe_limits_hash_mismatch")
    source = Path(os.environ.get("TARGET_SOURCE_DIR", ""))
    if not source.is_dir():
        raise ValueError("probe_target_source_missing")
    bare = subprocess.run(
        ["git", "-C", str(source), "rev-parse", "--is-bare-repository"],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    if bare.returncode or bare.stdout.strip() != "true":
        raise ValueError("probe_target_source_must_be_bare")
    for revision in (BASE_SHA, HEAD_SHA):
        result = subprocess.run(
            ["git", "-C", str(source), "cat-file", "-e", f"{revision}^{{commit}}"],
            capture_output=True,
            timeout=10,
            check=False,
        )
        if result.returncode:
            raise ValueError("probe_target_revision_missing")
    merge_base = subprocess.run(
        ["git", "-C", str(source), "merge-base", BASE_SHA, HEAD_SHA],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    if merge_base.returncode or merge_base.stdout.strip() != BASE_SHA:
        raise ValueError("probe_target_comparison_base_mismatch")
    return root


def _provider_config_from_environment(limits: dict) -> dict:
    base_url = os.environ.get("LLM_BASE_URL", "")
    model = os.environ.get("LLM_MODEL", "")
    api_key = os.environ.get("LLM_API_KEY", "")
    try:
        parsed = urlsplit(base_url)
        _ = parsed.port
    except ValueError:
        raise ValueError("probe_provider_configuration_invalid") from None
    if (
        not base_url
        or len(base_url.encode("utf-8")) > 2048
        or base_url != base_url.strip()
        or parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.path.rstrip("/").endswith("/chat/completions")
        or any(ord(char) < 32 or ord(char) == 127 for char in base_url)
        or not model
        or len(model.encode("utf-8")) > 256
        or model != model.strip()
        or any(ord(char) < 32 or ord(char) == 127 for char in model)
        or not api_key
        or len(api_key.encode("utf-8")) > 8192
        or api_key != api_key.strip()
        or any(ord(char) < 32 or ord(char) == 127 for char in api_key)
    ):
        raise ValueError("probe_provider_configuration_invalid")
    return {
        "kind": "openai_compatible",
        "provider_id": "schema-compatibility-probe",
        "base_url": base_url.rstrip("/"),
        "model": model,
        "api_key_env": "LLM_API_KEY",
        "max_request_bytes": limits["max_input_bytes_per_task"],
        "max_response_bytes": limits["max_output_bytes_per_task"],
        "max_output_tokens": limits["max_output_tokens"],
        "timeout_seconds": min(limits["deadline_seconds"], 30),
    }


def _offline_provider_config(limits: dict) -> dict:
    """Provider shape for planning/serialization only; it cannot dispatch."""
    model = os.environ.get("LLM_MODEL")
    if not model and os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch":
        raise ValueError("probe_provider_configuration_missing")
    model = model or "offline-prepare-only"
    if (
        not model
        or len(model.encode("utf-8")) > 256
        or model != model.strip()
        or any(ord(char) < 32 or ord(char) == 127 for char in model)
    ):
        raise ValueError("probe_provider_configuration_invalid")
    return {
        "kind": "openai_compatible",
        "provider_id": "schema-compatibility-probe-offline-prepare",
        "base_url": "https://offline.invalid/v1",
        "model": model,
        "api_key_env": "PROBE_UNUSED_KEY",
        "max_request_bytes": limits["max_input_bytes_per_task"],
        "max_response_bytes": limits["max_output_bytes_per_task"],
        "max_output_tokens": limits["max_output_tokens"],
        "timeout_seconds": 30,
    }


def run_probe(prepare_only: bool = False) -> dict:
    root = _require_runtime_context(prepare_only)
    profile = json.loads((root / PROFILE_PATH).read_text(encoding="utf-8"))
    limits = json.loads((root / LIMITS_PATH).read_text(encoding="utf-8"))
    provider = OpenAIProvider(
        _offline_provider_config(limits) if prepare_only else _provider_config_from_environment(limits)
    )
    provider.preflight("SPECIALIST_FINDINGS")
    source = os.environ["TARGET_SOURCE_DIR"]
    snapshot = collect_snapshot(source, BASE_SHA, HEAD_SHA, profile, limits, pr_diff=True)
    plan = plan_review(snapshot, profile, "FOCUSED")
    prepared, _skipped = prepare_plan_tasks(snapshot, plan, profile, limits, provider)
    scoped = [
        row for row in prepared
        if row.get("unit_ids") == UNIT_IDS
        and row.get("obligation_ids")
        and all(f":lens:{TARGET_LENS}" in obligation for obligation in row["obligation_ids"])
    ]
    if len(scoped) != 1:
        raise ValueError("probe_fixed_scope_not_unique")
    task = scoped[0]
    manifest = task.get("context_target_manifest")
    if not isinstance(manifest, dict):
        raise ValueError("probe_manifest_missing")
    evidence = _evidence_for(task, snapshot, effective_task_input_ceiling(limits, provider))
    task_input_hash = _hash({"evidence": evidence, "context_target_manifest": manifest})
    system, user, old_schema, new_schema, old_body, new_body = _request_schema_pair(
        root, provider, task, evidence, limits
    )
    if max(len(old_body), len(new_body)) > limits["max_input_bytes_per_task"]:
        raise ValueError("probe_request_exceeds_fixed_input_cap")

    if not prepare_only:
        preparation_path = Path(os.environ.get("RUNNER_TEMP", "/tmp")) / PREPARATION_NAME
        try:
            preparation = json.loads(preparation_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            raise ValueError("probe_fresh_preparation_missing") from None
        expected_fresh_binding = {
            "base_sha": BASE_SHA,
            "head_sha": HEAD_SHA,
            "snapshot_id": snapshot.get("snapshot_id"),
            "profile_sha256": PROFILE_SHA256,
            "limits_sha256": LIMITS_SHA256,
            "task_id": task.get("task_id"),
            "task_input_sha256": task_input_hash,
            "manifest_sha256": manifest.get("manifest_sha256"),
            "probe_source_sha": os.environ.get("GITHUB_SHA"),
            "variants": {
                "whole_object_enum": {
                    "request_body_bytes": len(old_body),
                    "request_body_sha256": hashlib.sha256(old_body).hexdigest(),
                },
                "nested_anyof_by_kind": {
                    "request_body_bytes": len(new_body),
                    "request_body_sha256": hashlib.sha256(new_body).hexdigest(),
                },
            },
        }
        if not isinstance(preparation, dict) or preparation.get("state") != "PREPARED_ONLY":
            raise ValueError("probe_fresh_preparation_invalid")
        for key, value in expected_fresh_binding.items():
            actual = preparation.get(key)
            if key == "variants":
                actual = {
                    variant: {
                        field: preparation.get("variants", {}).get(variant, {}).get(field)
                        for field in fields
                    }
                    for variant, fields in value.items()
                }
            if actual != value:
                raise ValueError("probe_fresh_preparation_mismatch")

    if prepare_only:
        old_result = {"state": "NOT_CALLED"}
        new_result = {"state": "NOT_CALLED"}
    else:
        old_result = _run_variant(
            provider, system=system, user=user, schema=old_schema, limits=limits, body=old_body
        )
        new_result = _run_variant(
            provider, system=system, user=user, schema=new_schema, limits=limits, body=new_body
        )
    return {
        "contract_version": "context-target-schema-compatibility-probe.v1",
        "state": "PREPARED_ONLY" if prepare_only else "COMPLETE",
        "target_repository": TARGET_REPOSITORY,
        "base_sha": BASE_SHA,
        "head_sha": HEAD_SHA,
        "probe_source_sha": os.environ.get("GITHUB_SHA") if re.fullmatch(r"[0-9a-f]{40}", os.environ.get("GITHUB_SHA", "")) else None,
        "snapshot_id": snapshot.get("snapshot_id"),
        "profile_sha256": PROFILE_SHA256,
        "limits_sha256": LIMITS_SHA256,
        "task_id": task.get("task_id"),
        "task_input_sha256": task_input_hash,
        "manifest_sha256": manifest.get("manifest_sha256"),
        "unit_ids": UNIT_IDS,
        "lens": TARGET_LENS,
        "historical_task_match": task.get("task_id") == TASK_ID,
        "historical_manifest_match": manifest.get("manifest_sha256") == MANIFEST_SHA256,
        "historical_task_input_match": task_input_hash == TASK_INPUT_SHA256,
        "legacy_provider_source_commit": LEGACY_PROVIDER_COMMIT,
        "legacy_provider_file_sha256": LEGACY_PROVIDER_FILE_SHA256,
        "retry_limit": 0,
        "provider_call_limit": 2,
        "request_diff_scope": "context_gap_proposals.items.properties.target only",
        "variants": {
            "whole_object_enum": {
                **old_result,
                "request_body_bytes": len(old_body),
                "request_body_sha256": hashlib.sha256(old_body).hexdigest(),
            },
            "nested_anyof_by_kind": {
                **new_result,
                "request_body_bytes": len(new_body),
                "request_body_sha256": hashlib.sha256(new_body).hexdigest(),
            },
        },
        "historical_old_error_signature": HISTORICAL_OLD_ERROR,
    }


def main() -> int:
    prepare_only = sys.argv[1:] == ["--prepare-only"]
    if sys.argv[1:] and not prepare_only:
        print(json.dumps({"state": "REJECTED", "error_code": "probe_arguments_forbidden"}, separators=(",", ":")))
        return 2
    output = Path(os.environ.get("RUNNER_TEMP", "/tmp")) / (
        PREPARATION_NAME if prepare_only else OUTPUT_NAME
    )
    try:
        required = () if prepare_only else ("LLM_BASE_URL", "LLM_MODEL", "LLM_API_KEY")
        if any(not os.environ.get(name) for name in required):
            raise ValueError("probe_provider_configuration_missing")
        result = run_probe(prepare_only)
        exit_code = 0
    except Exception as exc:
        code = str(exc) if isinstance(exc, ValueError) and re.fullmatch(r"[a-z0-9_]{1,100}", str(exc)) else "probe_failed"
        result = {"contract_version": "context-target-schema-compatibility-probe.v1", "state": "NOT_RUN", "error_code": code}
        exit_code = 1
    output.write_text(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    os.chmod(output, 0o600)
    print(json.dumps({"summary_path": str(output), "state": result.get("state")}, separators=(",", ":")))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
