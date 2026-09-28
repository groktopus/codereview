"""Fail-closed, stage-local budget checks for the model-only shadow audit.

This module is provider-free. The guard sees exact serialized request bytes at
the dispatch boundary, before OpenAI or TypeSafe reads a credential. The claim
auditor request is deliberately checked only after the Jev result exists.
"""

from __future__ import annotations

import json
import time
from typing import Any

from .providers import ProviderError


class AuditPreflightError(ProviderError):
    """A bounded, sanitized shadow-stage preflight rejection."""

    def __init__(self, code: str):
        super().__init__(code)


class AuditDispatchGuard:
    """Enforce the three-stage no-retry budget against exact dispatch bytes."""

    _ORDER = ("source_auditor", "jev", "claim_auditor")

    def __init__(self, limits: dict[str, Any], *, clock=time.monotonic):
        self.input_cap = limits.get("max_input_bytes_per_task")
        self.output_cap = limits.get("max_output_bytes_per_task")
        self.token_cap = limits.get("max_output_tokens")
        self.call_deadline = limits.get("deadline_seconds")
        self.call_cap = limits.get("max_provider_calls", 3)
        self.retry_cap = limits.get("max_retries", 0)
        self.total_deadline = limits.get("total_provider_deadline_seconds", 270)
        self._clock = clock
        self._started = clock()
        self._next_stage = 0
        self._seen: set[str] = set()
        self._validate_limits()

    def _validate_limits(self) -> None:
        int_limits = (self.input_cap, self.output_cap, self.token_cap, self.call_cap, self.retry_cap)
        if any(isinstance(value, bool) or not isinstance(value, int) for value in int_limits):
            raise AuditPreflightError("audit_limits_invalid")
        if not (0 < self.input_cap <= 64_000 and 0 < self.output_cap <= 64_000):
            raise AuditPreflightError("audit_limits_invalid")
        if not (0 < self.token_cap <= 1_800 and self.call_cap == 3 and self.retry_cap == 0):
            raise AuditPreflightError("audit_limits_invalid")
        if (isinstance(self.call_deadline, bool) or not isinstance(self.call_deadline, (int, float))
                or not 0 < self.call_deadline <= 90):
            raise AuditPreflightError("audit_limits_invalid")
        if (isinstance(self.total_deadline, bool) or not isinstance(self.total_deadline, (int, float))
                or not 0 < self.total_deadline <= 270):
            raise AuditPreflightError("audit_limits_invalid")
        if self.call_deadline * self.call_cap > self.total_deadline:
            raise AuditPreflightError("audit_limits_invalid")

    def check(self, role: str, request_bytes: bytes) -> None:
        """Validate one stage's exact payload immediately before dispatch."""
        if role not in self._ORDER or role in self._seen or role != self._ORDER[self._next_stage]:
            raise AuditPreflightError("audit_stage_order_invalid")
        if not isinstance(request_bytes, bytes):
            raise AuditPreflightError("audit_request_invalid")
        if not request_bytes or len(request_bytes) > self.input_cap:
            raise AuditPreflightError("audit_request_exceeds_limit")
        remaining = self.total_deadline - (self._clock() - self._started)
        if remaining < self.call_deadline:
            raise AuditPreflightError("audit_total_deadline_exhausted")
        if role in {"source_auditor", "claim_auditor"}:
            try:
                request = json.loads(request_bytes)
            except (UnicodeDecodeError, json.JSONDecodeError):
                raise AuditPreflightError("audit_request_invalid") from None
            tokens = request.get("max_completion_tokens") if isinstance(request, dict) else None
            if isinstance(tokens, bool) or not isinstance(tokens, int) or not 0 < tokens <= self.token_cap:
                raise AuditPreflightError("audit_token_cap_exceeded")
        self._seen.add(role)
        self._next_stage += 1
