"""Synthetic provider fault matrix for VD-2 (no external provider/effects)."""

from __future__ import annotations

import json
import os
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from unittest.mock import patch

import pytest
from test_review_stages import LIMITS, make_profile, make_snapshot

from pr_review_harness.budget import BudgetLedger
from pr_review_harness.engine import run_review
from pr_review_harness.planner import plan_review
from pr_review_harness.providers import OpenAIProvider

FAULT_ACCEPTANCE = {
    "task_status": "FAILED",
    "disposition": "INCOMPLETE",
    "settlement_status": "FAILED",
    "provider_posts": 1,
    "publication_posts": 0,
}

FAULT_CASES = (
    ("VD2-PROVIDER-TIMEOUT", "timeout", 200, b"{}", "provider_deadline_exceeded"),
    ("VD2-PROVIDER-4XX", "normal", 429, b'{"error":"rate limited"}', "http_status_429"),
    ("VD2-PROVIDER-5XX", "normal", 503, b'{"error":"unavailable"}', "http_status_503"),
    ("VD2-PROVIDER-MALFORMED", "normal", 200, b"{not-json", "malformed_provider_response"),
    ("VD2-PROVIDER-TRUNCATED", "truncated", 200, b'{"choices":[]}', "malformed_provider_response"),
    (
        "VD2-PROVIDER-DUPLICATE",
        "normal",
        200,
        json.dumps({"choices": [{}, {}]}).encode(),
        "malformed_provider_response",
    ),
)


class LoopbackFaultProvider(OpenAIProvider):
    """Keep process-start allowance separate from the injected HTTP timeout."""

    def estimate_call(self, task_kind, task, evidence, limits):
        estimate = super().estimate_call(task_kind, task, evidence, limits)
        # The fixture tests the transport's timeout, not the parent's process
        # startup timeout. No production retry/deadline policy is changed.
        estimate["deadline_seconds"] = limits["deadline_seconds"]
        return estimate


@pytest.mark.parametrize("case_id,mode,status,body,error_code", FAULT_CASES, ids=[row[0] for row in FAULT_CASES])
def test_provider_transport_fault_matrix_is_typed_and_makes_one_request(
    tmp_path, case_id, mode, status, body, error_code
):
    seen = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length", "0")))
            seen.append(self.path)
            if mode == "timeout":
                time.sleep(0.2)
            self.send_response(status)
            self.send_header("Content-Length", str(len(body) + (100 if mode == "truncated" else 0)))
            self.end_headers()
            try:
                self.wfile.write(body)
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                pass

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        provider = LoopbackFaultProvider(
            {
                "kind": "openai_compatible",
                "base_url": f"http://127.0.0.1:{server.server_port}/v1",
                "model": "offline-vd2-fixture",
                "api_key_env": "VD2_FAULT_PROVIDER_KEY",
                "timeout_seconds": 0.05 if mode == "timeout" else 1,
                "max_response_bytes": 4096,
            }
        )
        limits = {
            **LIMITS,
            "max_concurrent_scopes": 1,
            "max_provider_calls": 1,
            "max_context_retrievals": 0,
            "max_followup_tasks": 0,
            "max_input_bytes_per_task": 20_000,
            "max_output_bytes_per_task": 4096,
            "max_output_tokens": 50,
            "deadline_seconds": 5,
        }
        snapshot, profile = make_snapshot(), make_profile()
        # Run the real coordinator and isolated provider invocation. These guards
        # observe both publication entry points; the only HTTP endpoint reachable
        # by the supplied provider is this secretless loopback fixture.
        with (
            patch.dict(os.environ, {"VD2_FAULT_PROVIDER_KEY": "non-secret-fixture-token"}, clear=True),
            patch("pr_review_harness.publisher.publish_review") as publish,
            patch("pr_review_harness.publisher.publish_review_stateless") as publish_stateless,
        ):
            result = run_review(
                snapshot,
                plan_review(snapshot, profile),
                profile,
                provider,
                None,
                limits,
                str(tmp_path / case_id),
                case_id,
            )
            publish.assert_not_called()
            publish_stateless.assert_not_called()

        assert seen == ["/v1/chat/completions"]
        assert len(seen) == FAULT_ACCEPTANCE["provider_posts"]
        assert publish.call_count == publish_stateless.call_count == FAULT_ACCEPTANCE["publication_posts"]
        assert result["disposition"] == FAULT_ACCEPTANCE["disposition"]
        assert len(result["task_results"]) == 1
        outcome = next(iter(result["task_results"].values()))
        assert outcome["status"] == FAULT_ACCEPTANCE["task_status"]
        assert outcome["error_code"] == error_code
        assert outcome["attempts"] == 1
        assert "payload" not in outcome
        budget = result["ledger"]["budget"]
        assert len(budget["reservations"]) == len(budget["settlements"]) == 1
        assert budget["reservations"].keys() == budget["settlements"].keys()
        assert next(iter(budget["settlements"].values()))["status"] == FAULT_ACCEPTANCE["settlement_status"]
        assert result["ledger"].get("dynamic_tasks", []) == []

    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_conflicting_duplicate_attempt_replay_cannot_replace_terminal_failure():
    state = {}
    budget = BudgetLedger(
        {
            "deadline_seconds": 30,
            "max_provider_calls": 1,
            "max_context_bytes": 100,
            "max_input_bytes_per_task": 100,
            "max_output_bytes_per_task": 100,
            "max_output_bytes": 100,
            "max_context_retrievals": 0,
            "max_followup_tasks": 0,
            "max_cost_microunits": None,
        },
        state,
        deadline_epoch=time.time() + 30,
    )
    budget.reserve("duplicate", {"provider_calls": 1, "input_bytes": 1, "max_output_bytes": 10})
    budget.settle("duplicate", output_bytes=None, usage={}, status="FAILED")
    before = dict(state["settlements"]["duplicate"])
    with pytest.raises(ValueError, match="conflicting settlement replay"):
        budget.settle("duplicate", output_bytes=1, usage={}, status="SUCCEEDED")
    assert state["settlements"]["duplicate"] == before
    assert state.get("outputs", {}) == {}
