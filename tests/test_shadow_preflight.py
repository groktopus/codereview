from __future__ import annotations

import json

import pytest

from pr_review_harness.providers import OpenAIProvider, ProviderError
from pr_review_harness.shadow_preflight import AuditDispatchGuard, AuditPreflightError


def _limits():
    return {
        "max_input_bytes_per_task": 64_000,
        "max_output_bytes_per_task": 64_000,
        "max_output_tokens": 1_800,
        "deadline_seconds": 90,
        "max_provider_calls": 3,
        "max_retries": 0,
        "total_provider_deadline_seconds": 270,
    }


def _llm_request(tokens=1800):
    return json.dumps({"max_completion_tokens": tokens}, separators=(",", ":")).encode()


def test_stage_guard_accepts_bounded_ordered_stage_requests():
    guard = AuditDispatchGuard(_limits())
    guard.check("source_auditor", _llm_request())
    guard.check("jev", b'{"model":"jev-latest","questions":{"q":{}}}')
    guard.check("claim_auditor", _llm_request())


@pytest.mark.parametrize("mutate,code", [
    (lambda limits: limits.update(max_input_bytes_per_task=64_001), "audit_limits_invalid"),
    (lambda limits: limits.update(max_retries=1), "audit_limits_invalid"),
    (lambda limits: limits.update(total_provider_deadline_seconds=269), "audit_limits_invalid"),
])
def test_stage_guard_rejects_unbounded_global_limits(mutate, code):
    limits = _limits()
    mutate(limits)
    with pytest.raises(AuditPreflightError, match=code):
        AuditDispatchGuard(limits)


def test_dynamic_claim_request_is_checked_only_when_claim_stage_is_reached():
    now = [0.0]
    guard = AuditDispatchGuard(_limits(), clock=lambda: now[0])
    source = _llm_request()
    jev = b'{"model":"jev-latest","questions":{"q":{}}}'
    guard.check("source_auditor", source)
    guard.check("jev", jev)
    now[0] = 181
    with pytest.raises(AuditPreflightError, match="audit_total_deadline_exhausted"):
        guard.check("claim_auditor", _llm_request())


def test_invalid_exact_request_is_rejected_before_credential_lookup_or_http(monkeypatch):
    provider = OpenAIProvider({
        "kind": "openai_compatible", "base_url": "https://provider.invalid/v1",
        "model": "pinned-model", "api_key_env": "SHADOW_PREFLIGHT_MISSING_TOKEN",
        "timeout_seconds": 2, "max_response_bytes": 64_000, "max_request_bytes": 64_000,
    })
    def credential_lookup(_name):
        pytest.fail("credential lookup occurred before preflight rejection")
    def http_attempt(*_args, **_kwargs):
        pytest.fail("HTTP occurred before preflight rejection")
    monkeypatch.setattr("pr_review_harness.providers._env_credential", credential_lookup)
    monkeypatch.setattr("pr_review_harness.providers._HTTP_OPENER.open", http_attempt)

    def reject_exact_bytes(raw):
        assert isinstance(raw, bytes)
        raise AuditPreflightError("audit_request_exceeds_limit")
    with pytest.raises(ProviderError, match="audit_request_exceeds_limit"):
        provider.audit_json(
            system="bounded", user={"claim": "dynamic"}, schema={"type": "object"},
            limits={"max_input_bytes_per_task": 64_000, "max_output_bytes_per_task": 64_000,
                    "max_output_tokens": 1800, "deadline_seconds": 2},
            contract_version="test", before_dispatch=reject_exact_bytes,
        )


def test_guard_rejects_wrong_stage_order_and_token_overrun():
    guard = AuditDispatchGuard(_limits())
    with pytest.raises(AuditPreflightError, match="audit_stage_order_invalid"):
        guard.check("claim_auditor", _llm_request())
    guard = AuditDispatchGuard(_limits())
    with pytest.raises(AuditPreflightError, match="audit_token_cap_exceeded"):
        guard.check("source_auditor", _llm_request(1801))

