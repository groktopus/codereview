"""Bounded native TypeSafe System One HTTP transport for claim assessments."""

from __future__ import annotations

import hashlib
import json
import math
import re
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request

from .claim_assessment import (
    CONTRACT_VERSION,
    PR_COMPARISON_ASSESSMENT_CONTRACT_VERSION,
    PRIMARY_ASSESSMENT_CONTRACT_VERSION,
    _questions,
    _validate_primary_assessment,
)
from .providers import (
    _HTTP_OPENER,
    ProviderError,
    _bounded_response,
    _env_credential,
    _reject_literal_credentials,
    _safe_url,
)

_OFFICIAL_ENDPOINT = "https://api.typesafe.ai/v1/systemone"
_MAX_REQUEST_BYTES = 64_000
_MAX_RESPONSE_BYTES = 64_000
_MAX_DEADLINE_SECONDS = 120.0
_MAX_JSON_DEPTH = 64
_MAX_JSON_NODES = 20_000


def _positive_int(value: Any, code: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ProviderError(code)
    return value


def _deadline(value: Any, code: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
        raise ProviderError(code)
    if value > _MAX_DEADLINE_SECONDS:
        raise ProviderError(code)
    if isinstance(value, int):
        return float(value)
    if not math.isfinite(value):
        raise ProviderError(code)
    return float(value)


def _pairs_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key, value in pairs:
        if key in output:
            raise ValueError("duplicate_json_key")
        output[key] = value
    return output


def _reject_json_constant(_value: str) -> None:
    raise ValueError("invalid_json_constant")


def _parse_request(raw: bytes) -> dict[str, Any]:
    if not isinstance(raw, bytes) or len(raw) > _MAX_REQUEST_BYTES:
        raise ProviderError("request_exceeds_limit")
    try:
        value = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_pairs_no_duplicates, parse_constant=_reject_json_constant
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError):
        raise ProviderError("invalid_native_request") from None
    if not isinstance(value, dict) or set(value) != {"model", "state", "questions"}:
        raise ProviderError("invalid_native_request")
    if not isinstance(value.get("model"), str) or not value["model"].strip():
        raise ProviderError("invalid_native_request")
    if (
        not isinstance(value.get("state"), dict)
        or not isinstance(value.get("questions"), dict)
        or not value["questions"]
    ):
        raise ProviderError("invalid_native_request")
    stack = [(value, 0)]
    nodes = 0
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if depth > _MAX_JSON_DEPTH or nodes > _MAX_JSON_NODES:
            raise ProviderError("invalid_native_request")
        if isinstance(item, dict):
            stack.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            stack.extend((child, depth + 1) for child in item)
    _validate_claim_state(value["state"], value["questions"])
    return value


def _validate_claim_state(state: dict[str, Any], questions: dict[str, Any]) -> None:
    version = state.get("assessment_contract_version", CONTRACT_VERSION)
    expected_fields = {"assessment_identity", "candidate", "cited_evidence"}
    if version == PRIMARY_ASSESSMENT_CONTRACT_VERSION or (
        version == PR_COMPARISON_ASSESSMENT_CONTRACT_VERSION and "primary_assessment" in state
    ):
        expected_fields |= {"assessment_contract_version", "primary_assessment"}
    elif version == PR_COMPARISON_ASSESSMENT_CONTRACT_VERSION:
        expected_fields.add("assessment_contract_version")
    elif version != CONTRACT_VERSION:
        raise ProviderError("unsupported_native_operation")
    if set(state) != expected_fields:
        raise ProviderError("unsupported_native_operation")
    identity = state["assessment_identity"]
    identity_fields = {"snapshot_id", "snapshot_hash", "profile_id", "profile_hash", "base_sha", "head_sha"}
    if version == PR_COMPARISON_ASSESSMENT_CONTRACT_VERSION:
        identity_fields.add("change_base_sha")
    if not isinstance(identity, dict) or set(identity) != identity_fields:
        raise ProviderError("invalid_claim_identity")
    for key in ("snapshot_id", "profile_id"):
        if not isinstance(identity[key], str) or not identity[key].strip() or len(identity[key]) > 256:
            raise ProviderError("invalid_claim_identity")
    for key in ("snapshot_hash", "profile_hash"):
        if not isinstance(identity[key], str) or not re.fullmatch(r"[0-9a-f]{64}", identity[key]):
            raise ProviderError("invalid_claim_identity")
    for key in ("base_sha", "head_sha"):
        if not isinstance(identity[key], str) or not re.fullmatch(r"[0-9a-f]{40,64}", identity[key]):
            raise ProviderError("invalid_claim_identity")
    if identity["base_sha"] == identity["head_sha"]:
        raise ProviderError("invalid_claim_identity")
    if version == PR_COMPARISON_ASSESSMENT_CONTRACT_VERSION and (
        not isinstance(identity.get("change_base_sha"), str)
        or not re.fullmatch(r"[0-9a-f]{40,64}", identity["change_base_sha"])
    ):
        raise ProviderError("invalid_claim_identity")

    candidate = state["candidate"]
    candidate_fields = {"candidate_id", "title", "observation", "consequence", "rule_or_contract"}
    if version == PRIMARY_ASSESSMENT_CONTRACT_VERSION or (
        version == PR_COMPARISON_ASSESSMENT_CONTRACT_VERSION and "primary_assessment" in state
    ):
        candidate_fields.add("evidence_refs")
    if not isinstance(candidate, dict) or set(candidate) != candidate_fields:
        raise ProviderError("invalid_claim_candidate")
    candidate_id = candidate["candidate_id"]
    if not isinstance(candidate_id, str) or not candidate_id.strip() or len(candidate_id) > 256:
        raise ProviderError("invalid_claim_candidate")
    for key in candidate_fields - {"candidate_id", "evidence_refs"}:
        if (
            not isinstance(candidate[key], str)
            or not candidate[key].strip()
            or len(candidate[key].encode("utf-8")) > 16_000
        ):
            raise ProviderError("invalid_claim_candidate")

    cited = state["cited_evidence"]
    if not isinstance(cited, list) or not 1 <= len(cited) <= 32:
        raise ProviderError("invalid_claim_evidence")
    evidence_fields = {
        "evidence_id",
        "source_kind",
        "content_hash",
        "trust",
        "path",
        "side",
        "source_revision",
        "line",
        "content",
    }
    evidence_ids: list[str] = []
    revisions: set[str] = set()
    for item in cited:
        if not isinstance(item, dict) or set(item) != evidence_fields:
            raise ProviderError("invalid_claim_evidence")
        if (
            not isinstance(item["evidence_id"], str)
            or not item["evidence_id"].strip()
            or len(item["evidence_id"]) > 256
        ):
            raise ProviderError("invalid_claim_evidence")
        evidence_ids.append(item["evidence_id"])
        if not isinstance(item["source_kind"], str) or item["source_kind"] not in {
            "diff",
            "base_file",
            "head_file",
            "source_window",
            "profile_context",
            "repository_file",
            "test_result",
            "tool_result",
            "profile",
            "model_assessment",
            "human_note",
        }:
            raise ProviderError("invalid_claim_evidence")
        if not isinstance(item["trust"], str) or item["trust"] not in {
            "trusted_policy",
            "repository_evidence",
            "untrusted_pr_content",
            "generated_result",
        }:
            raise ProviderError("invalid_claim_evidence")
        if not isinstance(item["content"], str) or len(item["content"].encode("utf-8")) > 24_000:
            raise ProviderError("invalid_claim_evidence")
        if (
            not isinstance(item["content_hash"], str)
            or not re.fullmatch(r"[0-9a-f]{64}", item["content_hash"])
            or hashlib.sha256(item["content"].encode("utf-8")).hexdigest() != item["content_hash"]
        ):
            raise ProviderError("invalid_claim_evidence")
        if item["path"] is not None:
            if (
                not isinstance(item["path"], str)
                or not item["path"]
                or len(item["path"]) > 2048
                or item["path"].startswith("/")
                or ".." in item["path"].split("/")
            ):
                raise ProviderError("invalid_claim_evidence")
        if item["line"] is not None and (
            isinstance(item["line"], bool) or not isinstance(item["line"], int) or item["line"] < 1
        ):
            raise ProviderError("invalid_claim_evidence")
        revision = item["source_revision"]
        if revision is not None and (not isinstance(revision, str) or not re.fullmatch(r"[0-9a-f]{40,64}", revision)):
            raise ProviderError("invalid_claim_evidence")
        base_revisions = {identity["base_sha"]}
        if isinstance(identity.get("change_base_sha"), str):
            base_revisions.add(identity["change_base_sha"])
        expected_side = "BASE" if revision in base_revisions else "HEAD" if revision == identity["head_sha"] else None
        if item["side"] != expected_side:
            raise ProviderError("invalid_claim_evidence")
        if expected_side:
            revisions.add(revision)
    if len(set(evidence_ids)) != len(evidence_ids):
        raise ProviderError("invalid_claim_evidence")
    if version == PRIMARY_ASSESSMENT_CONTRACT_VERSION:
        candidate_refs = candidate.get("evidence_refs")
        if (
            not isinstance(candidate_refs, list)
            or not candidate_refs
            or any(not isinstance(ref, str) or not ref.strip() or len(ref) > 256 for ref in candidate_refs)
            or len(set(candidate_refs)) != len(candidate_refs)
            or any(ref not in evidence_ids for ref in candidate_refs)
        ):
            raise ProviderError("invalid_claim_evidence")
    expected_questions, _ids = _questions(
        candidate_id,
        {identity.get("change_base_sha", identity["base_sha"]), identity["head_sha"]} <= revisions,
        version,
    )
    if questions != expected_questions:
        raise ProviderError("unsupported_native_operation")
    if version == PRIMARY_ASSESSMENT_CONTRACT_VERSION or (
        version == PR_COMPARISON_ASSESSMENT_CONTRACT_VERSION and "primary_assessment" in state
    ):
        try:
            primary = _validate_primary_assessment(state.get("primary_assessment"), set(evidence_ids))
        except Exception:
            raise ProviderError("invalid_primary_assessment") from None
        if primary != state.get("primary_assessment"):
            raise ProviderError("invalid_primary_assessment")


def _endpoint(value: Any, *, operator_root: bool = False) -> str:
    endpoint = _safe_url(value)
    try:
        parsed = urlsplit(endpoint)
        port = parsed.port
    except ValueError:
        raise ProviderError("unsupported_native_endpoint") from None
    if parsed.query or parsed.fragment:
        raise ProviderError("unsupported_native_endpoint")
    if parsed.scheme == "https" and parsed.path == "/v1/systemone" and endpoint == _OFFICIAL_ENDPOINT:
        return endpoint
    host = parsed.hostname.lower() if parsed.hostname else ""
    loopback = host in {"localhost", "127.0.0.1", "::1"}
    if (
        loopback
        and parsed.scheme in {"http", "https"}
        and port is not None
        and (parsed.path == "/v1/systemone" or (operator_root and parsed.path.endswith("/systemone")))
    ):
        return endpoint
    if operator_root and parsed.scheme == "https" and parsed.path.endswith("/systemone"):
        return endpoint
    raise ProviderError("unsupported_native_endpoint")


class ClaimTransport:
    """Transport seam for `ClaimAssessmentAdapter` with finite HTTP bounds.

    The direct constructor accepts TypeSafe's official endpoint and explicit
    loopback endpoints for tests. ``from_decision_config`` accepts a validated
    operator-generated HTTPS route with an arbitrary API-root prefix. Both
    forms use an environment variable name for credentials. This class makes
    no retries and exposes raw bounded bytes only to the caller that validates
    the native response.
    """

    def __init__(self, config: dict[str, Any]):
        if not isinstance(config, dict):
            raise ProviderError("invalid_claim_transport_config")
        _reject_literal_credentials(config)
        allowed_keys = {
            "endpoint",
            "api_key_env",
            "model",
            "timeout_seconds",
            "max_request_bytes",
            "max_response_bytes",
        }
        if not set(config).issubset(allowed_keys):
            raise ProviderError("unsupported_claim_transport_config")
        self.endpoint = _endpoint(config.get("endpoint", _OFFICIAL_ENDPOINT))
        credential_env = config.get("api_key_env", "TYPESAFE_API_KEY")
        if not isinstance(credential_env, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", credential_env):
            raise ProviderError("invalid_credential_reference")
        self.api_key_env = credential_env
        self.model = config.get("model", "jev-latest")
        if not isinstance(self.model, str) or not self.model.strip() or len(self.model) > 256:
            raise ProviderError("invalid_model")
        self.timeout_seconds = _deadline(config.get("timeout_seconds", 20), "invalid_deadline")
        self.max_request_bytes = _positive_int(
            config.get("max_request_bytes", _MAX_REQUEST_BYTES), "invalid_request_limit"
        )
        self.max_response_bytes = _positive_int(
            config.get("max_response_bytes", _MAX_RESPONSE_BYTES), "invalid_response_limit"
        )
        self.last_dispatch_state = "unknown"
        if self.max_request_bytes > _MAX_REQUEST_BYTES or self.max_response_bytes > _MAX_RESPONSE_BYTES:
            raise ProviderError("invalid_transport_limit")
        self.identity = {
            "provider_id": "typesafe",
            "endpoint_id": self.endpoint,
            "configured_model_id": self.model,
            "model_identity_source": "operator_configured",
            "native_contract": "system-one-choice-v1",
            "credential_reference_name": self.api_key_env,
            "native_probability_calibration": "unknown",
        }

    @classmethod
    def from_decision_config(cls, config: dict[str, Any]) -> "ClaimTransport":
        """Load the generated operator decision config without accepting PR inputs.

        The caller must load this file from the trusted workflow configuration
        path. Its schema is the exact ``decision.json`` emitted by
        ``provider_config_from_env.py``; custom remote HTTPS roots are accepted
        only through this operator-config entry point.
        """
        if not isinstance(config, dict) or set(config) != {"kind", "endpoint", "model", "api_key_env"}:
            raise ProviderError("invalid_decision_config")
        _reject_literal_credentials(config)
        if config.get("kind") != "typesafe":
            raise ProviderError("unsupported_claim_transport_config")
        endpoint = _endpoint(config.get("endpoint"), operator_root=True)
        # Reuse the constructor's model, credential-reference, and finite-limit
        # validation while preventing this method from broadening the direct
        # constructor's endpoint allowlist.
        transport = cls(
            {
                "endpoint": _OFFICIAL_ENDPOINT,
                "api_key_env": config.get("api_key_env"),
                "model": config.get("model"),
            }
        )
        transport.endpoint = endpoint
        transport.identity["endpoint_id"] = endpoint
        transport.identity["endpoint_trust"] = "trusted_operator_decision_config"
        return transport

    def estimate_call(self, request_bytes: bytes, limits: dict[str, Any]) -> dict[str, Any]:
        """Return an exact serialized-byte quote; caller ceilings are dispatch policy.

        A measured request may exceed a caller's per-task cap so the planner can
        observe its actual size. The request is still rejected before HTTP if
        the final hard input cap is exceeded.
        """
        if not isinstance(limits, dict):
            raise ProviderError("invalid_limits")
        request = _parse_request(request_bytes)
        if request["model"] != self.model:
            raise ProviderError("configured_model_mismatch")
        caller_input_cap = limits.get("max_input_bytes_per_task", self.max_request_bytes)
        _positive_int(caller_input_cap, "invalid_input_byte_limit")
        caller_output_cap = limits.get("max_output_bytes_per_task", self.max_response_bytes)
        _positive_int(caller_output_cap, "invalid_output_byte_limit")
        deadline = min(
            self.timeout_seconds, _deadline(limits.get("deadline_seconds", self.timeout_seconds), "invalid_deadline")
        )
        return {
            "provider_calls": 1,
            "input_bytes": len(request_bytes),
            "max_output_bytes": min(self.max_response_bytes, caller_output_cap),
            "deadline_seconds": deadline,
            "estimated_input_tokens": None,
            "estimated_cost_microunits": None,
            "max_cost_microunits": None,
            "reservation_kind": "unknown",
            "usage": {"known": False, "input_tokens": None, "output_tokens": None, "cost": None},
        }

    def __call__(self, request_bytes: bytes, deadline_seconds: float, max_response_bytes: int) -> bytes:
        self.last_dispatch_state = "post_guard_pretransport"
        request = _parse_request(request_bytes)
        if request["model"] != self.model:
            raise ProviderError("configured_model_mismatch")
        if len(request_bytes) > self.max_request_bytes:
            raise ProviderError("request_exceeds_limit")
        timeout = min(self.timeout_seconds, _deadline(deadline_seconds, "invalid_deadline"))
        output_cap = min(self.max_response_bytes, _positive_int(max_response_bytes, "invalid_output_byte_limit"))
        token = _env_credential(self.api_key_env)
        request_hash = hashlib.sha256(request_bytes).hexdigest()
        http_request = Request(
            self.endpoint,
            data=request_bytes,
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            method="POST",
        )
        started = time.monotonic()
        deadline_at = started + timeout
        self.last_dispatch_state = "http_attempted"
        try:
            with _HTTP_OPENER.open(http_request, timeout=timeout) as response:
                raw = _bounded_response(response, output_cap, deadline_at)
                status = response.status
        except HTTPError as exc:
            try:
                status = exc.code
                exc.close()
            finally:
                raise ProviderError(
                    f"http_status_{status}", meta={"request_hash": request_hash, "http_status": status}
                ) from None
        except (URLError, TimeoutError, OSError):
            raise ProviderError(
                "provider_deadline_exceeded" if time.monotonic() >= deadline_at else "transport_failed",
                meta={"request_hash": request_hash},
            ) from None
        if token.encode("utf-8") in raw:
            raise ProviderError(
                "provider_response_contains_credential",
                meta={
                    "request_hash": request_hash,
                    "response_hash": hashlib.sha256(raw).hexdigest(),
                    "response_bytes": len(raw),
                    "http_status": status,
                },
            )
        return raw
