"""Prepared, configured Jev Choice diagnostic for two fixed synthetic inputs.

This versioned path is separate from the historical classifier allowlist. Its
classifications are advisory fixture observations, never security ground truth.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import os
import re
import subprocess
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from . import injection_trials, selected_model_trial
from .providers import (
    INJECTION_CHOICE_CONTRACT,
    INJECTION_CHOICE_CRITERIA,
    INJECTION_CHOICE_QUESTION,
    DecisionProvider,
    ProviderError,
    _endpoint_identity_hash,
    _json_bytes,
    make_decision_provider,
)

TRIAL_VERSION = "configured-jev-injection-classifier-trial.v1"
PREPARATION_VERSION = "configured-jev-injection-classifier-preparation.v1"
QUESTION_ID = "prompt_injection"
CALL_TIMEOUT_SECONDS = 20
GLOBAL_DEADLINE_SECONDS = 60
MAX_PROVIDER_CALLS = 2
MAX_INPUT_BYTES = 45_000
MAX_RESPONSE_BYTES = 16_000
MAX_REQUEST_BYTES = 48_000
MAX_PREPARATION_BYTES = 64_000
ATTACK_CASE_ID = "code-comment-attack"
BENIGN_CASE_ID = "code-comment-benign"
CASE_IDS = (ATTACK_CASE_ID, BENIGN_CASE_ID)
EXPECTED_CLASSIFICATION = {ATTACK_CASE_ID: "SUSPICIOUS", BENIGN_CASE_ID: "BENIGN"}
CHOICE_CLASSIFICATION = {"suspicious": "SUSPICIOUS", "benign": "BENIGN", "unknown": "UNKNOWN"}
VERSIONED_JEV_MODEL = re.compile(r"jev-[0-9]+\.[0-9]+\.[0-9]+\Z")
SUITE_RELATIVE = "examples/injection/fixture-suite.v2.json"


class ConfiguredJevTrialError(ValueError):
    """Stable error without fixture contents or credentials."""


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def _hash(value: Any) -> str:
    return _sha(_canonical(value))


def _hash_ok(value: Any) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _strict_json(raw: bytes, label: str) -> dict[str, Any]:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate")
            result[key] = value
        return result

    try:
        value = json.loads(raw, object_pairs_hook=pairs)
    except (ValueError, UnicodeDecodeError):
        raise ConfiguredJevTrialError(f"{label}_invalid") from None
    if not isinstance(value, dict):
        raise ConfiguredJevTrialError(f"{label}_invalid")
    return value


def _git_head(root: Path) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        raise ConfiguredJevTrialError("source_revision_unavailable") from None
    revision = result.stdout.strip()
    if result.returncode or not re.fullmatch(r"[0-9a-f]{40,64}", revision):
        raise ConfiguredJevTrialError("source_revision_unavailable")
    return revision


def _worktree_state(root: Path) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "status", "--porcelain", "--untracked-files=all"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        raise ConfiguredJevTrialError("source_worktree_state_unavailable") from None
    if result.returncode:
        raise ConfiguredJevTrialError("source_worktree_state_unavailable")
    return "CLEAN" if not result.stdout else "MODIFIED"


def _trusted_fixture(root: Path) -> tuple[dict[str, str], dict[str, Any]]:
    suite_path = root / SUITE_RELATIVE
    try:
        suite, suite_sha = injection_trials.load_suite(suite_path)
    except Exception:
        raise ConfiguredJevTrialError("trusted_fixture_unavailable") from None
    variants = suite.get("variants")
    selected: dict[str, dict[str, Any]] = {}
    if not isinstance(variants, list) or len(variants) > 100:
        raise ConfiguredJevTrialError("trusted_fixture_invalid")
    for variant in variants:
        if isinstance(variant, dict) and variant.get("case_id") in CASE_IDS:
            case_id = variant["case_id"]
            if case_id in selected:
                raise ConfiguredJevTrialError("trusted_fixture_invalid")
            selected[case_id] = variant
    if set(selected) != set(CASE_IDS):
        raise ConfiguredJevTrialError("trusted_fixture_case_set_invalid")
    if selected[ATTACK_CASE_ID].get("kind") != "attack" or selected[BENIGN_CASE_ID].get("kind") != "benign_lookalike":
        raise ConfiguredJevTrialError("trusted_fixture_case_kind_invalid")
    inputs: dict[str, str] = {}
    case_descriptors = []
    for case_id in CASE_IDS:
        text = selected[case_id].get("payload")
        if not isinstance(text, str) or not text or len(text.encode("utf-8")) > MAX_INPUT_BYTES:
            raise ConfiguredJevTrialError("trusted_fixture_input_invalid")
        inputs[case_id] = text
        case_descriptors.append(
            {
                "case_id": case_id,
                "fixture_kind": selected[case_id]["kind"],
                "input_sha256": _sha(text.encode("utf-8")),
                "input_bytes": len(text.encode("utf-8")),
                "expected_classification": EXPECTED_CLASSIFICATION[case_id],
            }
        )
    profile = injection_trials._profile(suite, repo_support_root=root)
    profile_sha = _sha(injection_trials.canonical_json(profile) + b"\n")
    metadata = {
        "suite_id": suite.get("suite_id"),
        "suite_sha256": suite_sha,
        "profile_version": profile.get("version"),
        "profile_sha256": profile_sha,
        "cases": case_descriptors,
    }
    return inputs, metadata


def prepared_request(text: str, model: str | None) -> bytes:
    if not isinstance(text, str):
        raise ConfiguredJevTrialError("classifier_input_invalid")
    try:
        raw = text.encode("utf-8")
    except UnicodeEncodeError:
        raise ConfiguredJevTrialError("classifier_input_invalid") from None
    if not raw or len(raw) > MAX_INPUT_BYTES:
        raise ConfiguredJevTrialError("classifier_input_out_of_bounds")
    payload: dict[str, Any] = {
        "state": {"review_evidence": text},
        "questions": {
            QUESTION_ID: {
                "type": "choice",
                "instructions": INJECTION_CHOICE_QUESTION,
                "criteria": INJECTION_CHOICE_CRITERIA,
            }
        },
    }
    if model is not None:
        if not isinstance(model, str) or not model.strip() or len(model) > 256:
            raise ConfiguredJevTrialError("configured_model_invalid")
        payload["model"] = model
    try:
        return _json_bytes(payload, MAX_REQUEST_BYTES, "request")
    except ProviderError as exc:
        raise ConfiguredJevTrialError(exc.code) from None


def _trial_source_identity(root: Path) -> dict[str, Any]:
    paths = (
        "src/pr_review_harness/configured_jev_injection_trial.py",
        "src/pr_review_harness/injection_trials.py",
        "src/pr_review_harness/providers.py",
        "scripts/run_configured_jev_injection_trial.py",
        SUITE_RELATIVE,
    )
    files = {}
    for relative in paths:
        try:
            raw = (root / relative).read_bytes()
        except OSError:
            raise ConfiguredJevTrialError("source_file_unavailable") from None
        if len(raw) > 8 * 1024 * 1024:
            raise ConfiguredJevTrialError("source_file_out_of_bounds")
        files[relative] = {"bytes": len(raw), "sha256": _sha(raw)}
    return {"git_head": _git_head(root), "worktree_state": _worktree_state(root), "trial_files": files}


def prepare_trial(
    *, root: Path, cli_executable: Path, expected_source_revision: str, output: Path
) -> dict[str, Any]:
    if not re.fullmatch(r"[0-9a-f]{40,64}", expected_source_revision):
        raise ConfiguredJevTrialError("expected_source_revision_invalid")
    source = _trial_source_identity(root)
    if source["git_head"] != expected_source_revision:
        raise ConfiguredJevTrialError("source_revision_mismatch")
    try:
        runtime = selected_model_trial._runtime_provenance(cli_executable, root)
    except Exception:
        raise ConfiguredJevTrialError("installed_runtime_mismatch") from None
    inputs, fixture = _trusted_fixture(root)
    template_cases = []
    for case in fixture["cases"]:
        text = inputs[case["case_id"]]
        template = prepared_request(text, "jev-latest")
        template_cases.append(
            {
                **case,
                "request_template_model": "jev-latest",
                "request_template_sha256": _sha(template),
                "request_template_bytes": len(template),
            }
        )
    runtime_receipt = {
        "source_fingerprint_sha256": _hash(runtime["source_fingerprint"]),
        "installed_source_match": True,
        "runtime_tree_sha256": runtime.get("runtime_tree_sha256"),
        "runtime_version": runtime.get("runtime_version"),
        "python_version": runtime.get("python_version"),
        "package_file_count": len(runtime["source_fingerprint"].get("file_hashes", {})),
        "cli_executable_sha256": runtime.get("cli_executable_sha256"),
    }
    manifest = {
        "contract_version": PREPARATION_VERSION,
        "state": "PREPARED_NO_PROVIDER_CALLS",
        "source": source,
        "installed_runtime": runtime_receipt,
        "fixture": {**fixture, "cases": template_cases},
        "classifier": {
            "contract": INJECTION_CHOICE_CONTRACT,
            "question_sha256": _sha(INJECTION_CHOICE_QUESTION.encode("utf-8")),
            "criteria_sha256": _sha(_json_bytes(INJECTION_CHOICE_CRITERIA, 16_000, "criteria")),
            "configured_model_binding": "prepared as jev-latest template; live request is rebuilt from trusted JEV_MODEL before dispatch",
        },
        "bounds": {
            "case_ids": list(CASE_IDS),
            "provider_calls_reserved": MAX_PROVIDER_CALLS,
            "retries_per_case": 0,
            "per_call_timeout_seconds": CALL_TIMEOUT_SECONDS,
            "global_deadline_seconds": GLOBAL_DEADLINE_SECONDS,
            "max_input_bytes": MAX_INPUT_BYTES,
            "max_request_bytes": MAX_REQUEST_BYTES,
            "max_response_bytes": MAX_RESPONSE_BYTES,
            "target_code_execution": "DISABLED",
            "publication": "DISABLED",
        },
    }
    raw = _canonical(manifest)
    if len(raw) > MAX_PREPARATION_BYTES:
        raise ConfiguredJevTrialError("preparation_exceeds_limit")
    try:
        output.mkdir(parents=True, exist_ok=False)
    except OSError:
        raise ConfiguredJevTrialError("preparation_output_unavailable") from None
    manifest_path = output / "manifest.json"
    manifest_path.write_bytes(raw + b"\n")
    summary = {
        "contract_version": PREPARATION_VERSION,
        "state": "PREPARED_NO_PROVIDER_CALLS",
        "manifest_sha256": _sha(raw),
        "source_revision": source["git_head"],
        "suite_sha256": fixture["suite_sha256"],
        "profile_sha256": fixture["profile_sha256"],
        "case_count": len(CASE_IDS),
        "provider_calls": 0,
        "target_code_execution": "NOT_RUN",
        "publication": "DISABLED",
    }
    (output / "summary.json").write_bytes(_canonical(summary) + b"\n")
    return summary


def _trusted_provider(env: dict[str, str]) -> DecisionProvider:
    endpoint = env.get("JEV_BASE_URL")
    model = env.get("JEV_MODEL")
    key = env.get("JEV_API_KEY")
    if not all(isinstance(value, str) and value.strip() for value in (endpoint, model, key)):
        raise ConfiguredJevTrialError("jev_configuration_required")
    try:
        lengths = tuple(len(value.encode("utf-8")) for value in (endpoint, model, key))
    except UnicodeEncodeError:
        raise ConfiguredJevTrialError("jev_configuration_invalid") from None
    if (
        lengths[0] > 2048
        or lengths[1] > 256
        or lengths[2] > 8192
        or any(ord(char) < 32 or ord(char) == 127 for value in (endpoint, model, key) for char in value)
        or any(value != value.strip() for value in (endpoint, model, key))
    ):
        raise ConfiguredJevTrialError("jev_configuration_invalid")
    try:
        parsed = urlsplit(endpoint)
        _ = parsed.port
    except ValueError:
        raise ConfiguredJevTrialError("jev_endpoint_invalid") from None
    normalized_endpoint = _normalized_jev_endpoint(endpoint)
    if normalized_endpoint is None or (
        parsed.scheme not in {"https", "http"}
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise ConfiguredJevTrialError("jev_endpoint_invalid")
    if parsed.scheme == "http":
        try:
            is_loopback = ipaddress.ip_address(parsed.hostname).is_loopback
        except ValueError:
            is_loopback = parsed.hostname.casefold() == "localhost"
        if not is_loopback:
            raise ConfiguredJevTrialError("jev_endpoint_invalid")
    config = {
        "kind": "typesafe",
        "endpoint": normalized_endpoint,
        "model": model,
        "api_key_env": "JEV_API_KEY",
        "primitive": "choice-injection-v1",
        "timeout_seconds": CALL_TIMEOUT_SECONDS,
        "max_response_bytes": MAX_RESPONSE_BYTES,
    }
    try:
        provider = make_decision_provider(config)
    except Exception:
        raise ConfiguredJevTrialError("jev_configuration_invalid") from None
    if not isinstance(provider, DecisionProvider) or not _provider_identity_valid(provider, model, endpoint):
        raise ConfiguredJevTrialError("jev_provider_identity_invalid")
    return provider


def _provider_identity_valid(provider: Any, model: str, configured_endpoint: str) -> bool:
    identity = getattr(provider, "identity", None)
    if not isinstance(identity, dict):
        return False
    endpoint_id = identity.get("endpoint_id")
    normalized_endpoint = _normalized_jev_endpoint(configured_endpoint)
    return (
        normalized_endpoint is not None
        and provider.kind == "typesafe"
        and provider.primitive == "choice-injection-v1"
        and provider.model == model
        and identity.get("provider_id") == "typesafe"
        and identity.get("model_id") == model
        and identity.get("injection_classifier_contract") == INJECTION_CHOICE_CONTRACT
        and identity.get("endpoint_id") == normalized_endpoint
        and isinstance(endpoint_id, str)
    )


def _normalized_jev_endpoint(endpoint: str) -> str | None:
    """Accept the configured API base or the exact endpoint, without duplication."""
    try:
        parsed = urlsplit(endpoint)
        _ = parsed.port
    except (TypeError, ValueError):
        return None
    if (
        parsed.scheme not in {"https", "http"}
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        return None
    path = parsed.path.rstrip("/")
    if path in {"", "/v1"}:
        path = f"{path}/systemone"
    elif path not in {"/systemone", "/v1/systemone"}:
        return None
    return f"{parsed.scheme}://{parsed.netloc}{path}"


def _validate_packet(packet: dict[str, Any], root: Path, expected_source_revision: str, cli: Path) -> tuple[dict[str, str], Any]:
    source = packet.get("source")
    if (
        packet.get("contract_version") != PREPARATION_VERSION
        or packet.get("state") != "PREPARED_NO_PROVIDER_CALLS"
        or not isinstance(source, dict)
        or source.get("git_head") != expected_source_revision
        or _git_head(root) != expected_source_revision
    ):
        raise ConfiguredJevTrialError("preparation_identity_mismatch")
    current_source = _trial_source_identity(root)
    if packet.get("source") != current_source:
        raise ConfiguredJevTrialError("preparation_source_changed")
    try:
        runtime = selected_model_trial._runtime_provenance(cli, root)
    except Exception:
        raise ConfiguredJevTrialError("installed_runtime_mismatch") from None
    runtime_receipt = packet.get("installed_runtime")
    if (
        not isinstance(runtime_receipt, dict)
        or runtime_receipt.get("installed_source_match") is not True
        or runtime_receipt.get("source_fingerprint_sha256") != _hash(runtime["source_fingerprint"])
        or runtime_receipt.get("runtime_tree_sha256") != runtime.get("runtime_tree_sha256")
        or runtime_receipt.get("cli_executable_sha256") != runtime.get("cli_executable_sha256")
    ):
        raise ConfiguredJevTrialError("installed_runtime_changed")
    inputs, fixture = _trusted_fixture(root)
    packet_fixture = packet.get("fixture")
    if not isinstance(packet_fixture, dict) or any(
        packet_fixture.get(key) != fixture.get(key) for key in ("suite_id", "suite_sha256", "profile_version", "profile_sha256")
    ):
        raise ConfiguredJevTrialError("fixture_identity_mismatch")
    expected_cases = packet_fixture.get("cases")
    if not isinstance(expected_cases, list) or len(expected_cases) != 2:
        raise ConfiguredJevTrialError("fixture_case_set_invalid")
    cases_by_id = {row.get("case_id"): row for row in expected_cases if isinstance(row, dict)}
    if set(cases_by_id) != set(CASE_IDS):
        raise ConfiguredJevTrialError("fixture_case_set_invalid")
    for case in fixture["cases"]:
        row = cases_by_id[case["case_id"]]
        if any(row.get(key) != case.get(key) for key in ("fixture_kind", "input_sha256", "input_bytes", "expected_classification")):
            raise ConfiguredJevTrialError("fixture_input_changed")
        template = prepared_request(inputs[case["case_id"]], "jev-latest")
        if row.get("request_template_sha256") != _sha(template) or row.get("request_template_bytes") != len(template):
            raise ConfiguredJevTrialError("request_template_changed")
    classifier = packet.get("classifier")
    if (
        not isinstance(classifier, dict)
        or classifier.get("contract") != INJECTION_CHOICE_CONTRACT
        or classifier.get("question_sha256") != _sha(INJECTION_CHOICE_QUESTION.encode("utf-8"))
        or classifier.get("criteria_sha256") != _sha(_json_bytes(INJECTION_CHOICE_CRITERIA, 16_000, "criteria"))
    ):
        raise ConfiguredJevTrialError("classifier_contract_changed")
    expected_bounds = {
        "case_ids": list(CASE_IDS),
        "provider_calls_reserved": MAX_PROVIDER_CALLS,
        "retries_per_case": 0,
        "per_call_timeout_seconds": CALL_TIMEOUT_SECONDS,
        "global_deadline_seconds": GLOBAL_DEADLINE_SECONDS,
        "max_input_bytes": MAX_INPUT_BYTES,
        "max_request_bytes": MAX_REQUEST_BYTES,
        "max_response_bytes": MAX_RESPONSE_BYTES,
        "target_code_execution": "DISABLED",
        "publication": "DISABLED",
    }
    if packet.get("bounds") != expected_bounds:
        raise ConfiguredJevTrialError("preparation_bounds_invalid")
    return inputs, fixture


def run_trial(
    *,
    root: Path,
    cli_executable: Path,
    expected_source_revision: str,
    preparation: Path,
    output: Path,
) -> dict[str, Any]:
    try:
        raw = preparation.read_bytes()
    except OSError:
        raise ConfiguredJevTrialError("preparation_unavailable") from None
    if len(raw) > MAX_PREPARATION_BYTES:
        raise ConfiguredJevTrialError("preparation_exceeds_limit")
    packet = _strict_json(raw, "preparation")
    inputs, fixture = _validate_packet(packet, root, expected_source_revision, cli_executable)
    trusted_env = dict(os.environ)
    provider = _trusted_provider(trusted_env)
    # Serialize both live requests under the actual trusted model configuration
    # before the first HTTP call; the preparation packet binds their input and
    # contract, while this receipt binds the configured-model variant.
    request_receipts = {}
    for case_id in CASE_IDS:
        request = prepared_request(inputs[case_id], provider.model)
        request_receipts[case_id] = {"request_sha256": _sha(request), "request_bytes": len(request)}
    try:
        output.mkdir(parents=True, exist_ok=False)
    except OSError:
        raise ConfiguredJevTrialError("result_output_unavailable") from None
    started = time.monotonic()
    result = run_two_case_trial(provider, inputs, request_receipts=request_receipts, started=started)
    result["source_revision"] = expected_source_revision
    result["suite_sha256"] = fixture["suite_sha256"]
    result["profile_sha256"] = fixture["profile_sha256"]
    result["preparation_sha256"] = _sha(raw)
    result["quality_claim"] = None
    result_bytes = _canonical(result)
    api_key = trusted_env.get("JEV_API_KEY", "").encode("utf-8")
    if api_key and api_key in result_bytes:
        raise ConfiguredJevTrialError("credential_echo_detected")
    result["credential_echo_detected"] = any(
        row.get("reason") == "provider_response_contains_credential" for row in result["cases"]
    )
    result_bytes = _canonical(result)
    (output / "result.json").write_bytes(result_bytes + b"\n")
    summary = {
        "contract_version": TRIAL_VERSION,
        "state": result["state"],
        "result_sha256": _sha(result_bytes),
        "case_count": len(CASE_IDS),
        "provider_http_attempts_observed": result["provider_http_attempts_observed"],
        "provider_calls_reserved": MAX_PROVIDER_CALLS,
        "quality_claim": None,
    }
    (output / "summary.json").write_bytes(_canonical(summary) + b"\n")
    return summary


def run_two_case_trial(
    provider: DecisionProvider,
    fixtures: dict[str, str],
    *,
    request_receipts: dict[str, dict[str, Any]],
    started: float,
) -> dict[str, Any]:
    if not _provider_identity_valid(provider, provider.model, provider.identity.get("endpoint_id", "").removesuffix("/systemone")):
        raise ConfiguredJevTrialError("jev_provider_identity_invalid")
    if set(fixtures) != set(CASE_IDS) or set(request_receipts) != set(CASE_IDS):
        raise ConfiguredJevTrialError("trial_inputs_invalid")
    if time.monotonic() - started >= GLOBAL_DEADLINE_SECONDS:
        return _deadline_result(started)
    deadline_at = started + GLOBAL_DEADLINE_SECONDS
    rows = []
    for case_id in CASE_IDS:
        text = fixtures[case_id]
        live = prepared_request(text, provider.model)
        expected = request_receipts[case_id]
        if expected != {"request_sha256": _sha(live), "request_bytes": len(live)}:
            raise ConfiguredJevTrialError("live_request_preflight_mismatch")
        row = classify_configured_jev(provider, case_id, text, deadline_at=deadline_at, expected_request=expected)
        rows.append(row)
        if row.get("reason") == "provider_response_contains_credential":
            next_case = CASE_IDS[len(rows)] if len(rows) < len(CASE_IDS) else None
            if next_case is not None:
                rows.append(
                    {
                        "case_id": next_case,
                        "status": "NOT_CALLED_SECURITY_STOP",
                        "classification": "UNKNOWN",
                        "reason": "prior_response_credential_echo",
                    }
                )
            break
    attempts = sum(
        1 for row in rows if isinstance(row.get("local_http_exchange"), dict) and row["local_http_exchange"].get("request_attempted") is True
    )
    elapsed = max(0.0, (time.monotonic() - started) * 1000)
    reported_models = {
        row.get("provider_reported_model_id")
        for row in rows
        if row.get("status") == "RECEIVED" and row.get("provider_reported_model_id") is not None
    }
    identity_consistency = "CONSISTENT" if len(reported_models) <= 1 else "REPORTED_MODEL_MISMATCH"
    complete = all(row["status"] == "RECEIVED" for row in rows) and identity_consistency == "CONSISTENT"
    return {
        "contract_version": TRIAL_VERSION,
        "state": "COMPLETE" if complete else "PARTIAL",
        "reported_model_identity_consistency": identity_consistency,
        "provider_http_attempts_observed": attempts,
        "provider_calls_reserved": MAX_PROVIDER_CALLS,
        "retry_limit_per_case": 0,
        "per_call_timeout_seconds": CALL_TIMEOUT_SECONDS,
        "global_deadline_seconds": GLOBAL_DEADLINE_SECONDS,
        "elapsed_ms": round(elapsed, 2),
        "cases": rows,
        "quality_claim": None,
    }


def _deadline_result(started: float) -> dict[str, Any]:
    return {
        "contract_version": TRIAL_VERSION,
        "state": "PARTIAL",
        "provider_http_attempts_observed": 0,
        "provider_calls_reserved": MAX_PROVIDER_CALLS,
        "retry_limit_per_case": 0,
        "per_call_timeout_seconds": CALL_TIMEOUT_SECONDS,
        "global_deadline_seconds": GLOBAL_DEADLINE_SECONDS,
        "elapsed_ms": round(max(0.0, (time.monotonic() - started) * 1000), 2),
        "cases": [],
        "quality_claim": None,
    }


def classify_configured_jev(
    provider: Any,
    case_id: str,
    text: str,
    *,
    deadline_at: float,
    expected_request: dict[str, Any],
) -> dict[str, Any]:
    if case_id not in EXPECTED_CLASSIFICATION or not isinstance(text, str) or not isinstance(provider, DecisionProvider):
        raise ConfiguredJevTrialError("trusted_classifier_configuration_invalid")
    if not _provider_identity_valid(provider, provider.model, provider.identity.get("endpoint_id", "").removesuffix("/systemone")):
        raise ConfiguredJevTrialError("trusted_classifier_configuration_invalid")
    text_raw = text.encode("utf-8")
    request_raw = prepared_request(text, provider.model)
    record = {
        "case_id": case_id,
        "fixture_input_sha256": _sha(text_raw),
        "fixture_input_bytes": len(text_raw),
        "expected_classification": EXPECTED_CLASSIFICATION[case_id],
        "configured_model_id": provider.model,
        "configured_model_identity_source": provider.identity.get("model_identity_source"),
        "endpoint_sha256": _endpoint_identity_hash(provider.identity["endpoint_id"]),
        "classifier_contract": INJECTION_CHOICE_CONTRACT,
        "question_sha256": _sha(INJECTION_CHOICE_QUESTION.encode("utf-8")),
        "criteria_sha256": _sha(_json_bytes(INJECTION_CHOICE_CRITERIA, 16_000, "criteria")),
        "prepared_request_sha256": _sha(request_raw),
        "prepared_request_bytes": len(request_raw),
    }
    if expected_request != {"request_sha256": _sha(request_raw), "request_bytes": len(request_raw)}:
        raise ConfiguredJevTrialError("live_request_preflight_mismatch")
    remaining = deadline_at - time.monotonic()
    if remaining <= 0:
        return {**record, "status": "NOT_CALLED_DEADLINE", "classification": "UNKNOWN", "reason": "global_deadline"}
    limits = {
        "deadline_seconds": min(float(CALL_TIMEOUT_SECONDS), remaining),
        "max_input_bytes_per_task": MAX_REQUEST_BYTES,
        "max_output_bytes_per_task": MAX_RESPONSE_BYTES,
        "max_provider_calls": 1,
        "max_retries_per_task": 0,
    }
    try:
        provider.preflight("SYSTEM_ONE_PROMPT_INJECTION_ADVISORY")
        response = provider.assess(INJECTION_CHOICE_CONTRACT, text, limits)
    except Exception as exc:
        meta = getattr(exc, "meta", {})
        exchange = meta.get("local_http_exchange") if isinstance(meta, dict) else None
        return {
            **record,
            "status": "PROVIDER_ERROR",
            "classification": "UNKNOWN",
            "reason": _stable_error_code(exc),
            "local_http_exchange": _safe_exchange(exchange),
        }
    payload = response.get("payload") if isinstance(response, dict) else None
    provenance = response.get("provenance") if isinstance(response, dict) else None
    usage = response.get("usage") if isinstance(response, dict) else None
    if not isinstance(payload, dict) or not isinstance(provenance, dict):
        return {**record, "status": "INVALID_RESPONSE", "classification": "UNKNOWN", "reason": "response_shape_invalid"}
    choice = payload.get("choice")
    classification = CHOICE_CLASSIFICATION.get(choice) if isinstance(choice, str) else None
    probabilities = payload.get("probabilities")
    valid_probabilities = (
        isinstance(probabilities, dict)
        and set(probabilities) == set(CHOICE_CLASSIFICATION)
        and all(isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value) and 0 <= value <= 1 for value in probabilities.values())
        and abs(sum(probabilities.values()) - 1.0) <= 0.02
        and choice in probabilities
        and probabilities[choice] >= max(probabilities.values()) - 1e-6
    )
    response_hash = provenance.get("response_hash")
    provider_model = provenance.get("provider_model_id")
    identity_source = provenance.get("model_identity_source")
    alias_valid = provider.model != "jev-latest" or (
        isinstance(provider_model, str) and VERSIONED_JEV_MODEL.fullmatch(provider_model) is not None
    )
    if provider_model is not None and identity_source != "endpoint_reported":
        alias_valid = False
    if provider_model is None and identity_source != provider.identity.get("model_identity_source"):
        alias_valid = False
    expected_hashes = {
        "question_hash": record["question_sha256"],
        "criteria_hash": record["criteria_sha256"],
        "input_hash": record["fixture_input_sha256"],
        "request_hash": record["prepared_request_sha256"],
    }
    exchange = _safe_exchange(provenance.get("local_http_exchange"))
    provenance_valid = (
        provenance.get("classifier_contract") == INJECTION_CHOICE_CONTRACT
        and provenance.get("native_contract") == "system-one-choice-score-noul-v1"
        and provenance.get("endpoint_id") == provider.identity.get("endpoint_id")
        and provenance.get("configured_model_id") == provider.model
        and all(provenance.get(key) == expected for key, expected in expected_hashes.items())
        and _hash_ok(response_hash)
        and isinstance(exchange, dict)
        and exchange.get("state") == "HTTP_RESPONSE_RECEIVED"
        and exchange.get("provider_id") == "typesafe"
        and exchange.get("endpoint_sha256") == _endpoint_identity_hash(provider.identity["endpoint_id"])
        and exchange.get("request_attempted") is True
        and exchange.get("request_sha256") == record["prepared_request_sha256"]
        and exchange.get("request_bytes") == record["prepared_request_bytes"]
        and exchange.get("response_sha256") == response_hash
        and exchange.get("http_status") == 200
        and exchange.get("response_complete") is True
        and alias_valid
        and payload.get("primitive") == "Choice"
        and payload.get("question_id") == QUESTION_ID
        and payload.get("recommendation") == "UNRESOLVED"
        and payload.get("interpretation") == "advisory_uncalibrated"
        and classification is not None
        and valid_probabilities
    )
    if not provenance_valid:
        return {
            **record,
            "status": "INVALID_RESPONSE",
            "classification": "UNKNOWN",
            "reason": "response_binding_invalid",
            "response_sha256": response_hash if _hash_ok(response_hash) else None,
        }
    return {
        **record,
        "status": "RECEIVED",
        "classification": classification,
        "choice": choice,
        "interpretation": "advisory_uncalibrated",
        "fixture_match_observation": classification == EXPECTED_CLASSIFICATION[case_id],
        "provider_reported_model_id": provider_model,
        "model_identity_source": provenance.get("model_identity_source"),
        "request_sha256": provenance.get("request_hash"),
        "response_sha256": response_hash,
        "usage": _safe_usage(usage),
        "local_http_exchange": exchange,
    }


def _stable_error_code(error: Exception) -> str:
    code = getattr(error, "code", None)
    return code if isinstance(code, str) and re.fullmatch(r"[a-z0-9_]{1,100}", code) else "provider_error"


def _safe_usage(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {"known": False, "tokens": None, "cost": None}
    known = value.get("known") is True
    tokens = value.get("tokens")
    cost = value.get("cost")
    return {
        "known": known,
        "tokens": tokens if known and isinstance(tokens, int) and not isinstance(tokens, bool) and tokens >= 0 else None,
        "cost": cost if known and isinstance(cost, (int, float)) and not isinstance(cost, bool) and math.isfinite(cost) and cost >= 0 else None,
    }


def _safe_exchange(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    endpoint_hash = value.get("endpoint_sha256")
    request_hash = value.get("request_sha256")
    response_hash = value.get("response_sha256")
    if not _hash_ok(endpoint_hash) or not _hash_ok(request_hash):
        return None
    if response_hash is not None and not _hash_ok(response_hash):
        return None
    status = value.get("http_status")
    elapsed = value.get("elapsed_ms")
    request_bytes = value.get("request_bytes")
    response_bytes = value.get("response_bytes")
    state = value.get("state")
    model = value.get("model_id")
    return {
        "state": state if isinstance(state, str) and re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", state) else "UNKNOWN",
        "provider_id": "typesafe" if value.get("provider_id") == "typesafe" else None,
        "model_id": model if isinstance(model, str) and len(model) <= 256 else None,
        "endpoint_sha256": endpoint_hash,
        "request_attempted": value.get("request_attempted") is True,
        "request_serialized": value.get("request_serialized") is True,
        "request_sha256": request_hash,
        "request_bytes": request_bytes if type(request_bytes) is int and 0 <= request_bytes <= MAX_REQUEST_BYTES else None,
        "http_status": status if type(status) is int and 100 <= status <= 599 else None,
        "response_sha256": response_hash,
        "response_bytes": response_bytes if type(response_bytes) is int and 0 <= response_bytes <= MAX_RESPONSE_BYTES else None,
        "response_complete": value.get("response_complete") is True,
        "elapsed_ms": round(elapsed, 2) if isinstance(elapsed, (int, float)) and not isinstance(elapsed, bool) and math.isfinite(elapsed) and elapsed >= 0 else None,
    }
