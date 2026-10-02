"""Offline tests for the optional per-candidate claim-assessment shadow stage."""

from __future__ import annotations

import ast
import hashlib
import json
import os
import subprocess
import threading
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

import pr_review_harness.engine as engine_module
from pr_review_harness.budget import BudgetExhausted, IsolatedCallError
from pr_review_harness.claim_assessment import (
    CLAIM_ASSESSMENT_ERROR_CODES,
    ClaimAssessmentAdapter,
    ClaimAssessmentError,
)
from pr_review_harness.claim_reconciliation import classify_reconciliation
from pr_review_harness.claim_transport import ClaimTransport
from pr_review_harness.engine import run_review
from pr_review_harness.planner import plan_review
from pr_review_harness.snapshot import collect_snapshot

BASE = "b" * 40
HEAD = "c" * 40
LIMITS = {
    "deadline_seconds": 30,
    "max_concurrent_scopes": 1,
    "max_provider_calls": 8,
    "max_retries_per_task": 0,
    "max_context_bytes": 120_000,
    "max_input_bytes_per_task": 45_000,
    "max_output_bytes_per_task": 16_000,
    "max_output_bytes": 192_000,
    "max_context_retrievals": 0,
    "max_followup_tasks": 0,
}


def _snapshot() -> dict:
    content = "-old\n+new"
    content_hash = hashlib.sha256(content.encode()).hexdigest()
    evidence = {
        "diff:u0": {
            "evidence_id": "diff:u0",
            "snapshot_id": "snap",
            "path": "src/auth.py",
            "line_start": 1,
            "line_end": 1,
            "source_revision": HEAD,
            "content": content,
            "content_hash": content_hash,
            "source_kind": "diff",
            "trust": "untrusted_pr_content",
        }
    }
    return {
        "snapshot_id": "snap",
        "snapshot_hash": "d" * 64,
        "base_sha": BASE,
        "head_sha": HEAD,
        "profile_version": "profile-v1",
        "freshness_basis": "HISTORICAL_SNAPSHOT",
        "inventory": [
            {
                "unit_id": "u0",
                "path": "src/auth.py",
                "kind": "human_code",
                "change": "modified",
                "diff": content,
                "changed_lines": [[1, 1]],
                "evidence_ids": ["diff:u0"],
            }
        ],
        "evidence": evidence,
        "gaps": [],
    }


def _profile(*, reconciliation: bool = False, cap: int = 1) -> dict:
    profile = {"version": "profile-v1", "required_lenses": ["correctness"], "allow_empty_approval": True}
    if reconciliation:
        profile["claim_reconciliation"] = {
            "version": "claim-reconciliation.v1",
            "enabled": True,
            "required": True,
            "max_assessments": cap,
        }
    return profile


class PrimaryProvider:
    identity = {
        "kind": "offline-test",
        "model": "primary-fixture",
        "adjudication_rubric_version": "causal-roles.behavior-consumer-impact.v1",
    }

    def __init__(self, outcome: str = "NOT_SUPPORTED", evidence_ref: str | None = None):
        self.outcome = outcome
        self.evidence_ref = evidence_ref

    def review(self, task: dict, evidence: list[dict], limits: dict) -> dict:
        evidence_id = task["evidence_ids"][0]
        candidate_path = "src/auth.py"
        candidate_line = 1
        if self.evidence_ref is not None:
            selected = next(item for item in evidence if item["evidence_id"] == self.evidence_ref)
            evidence_id = self.evidence_ref
            candidate_path = selected["path"]
            candidate_line = selected.get("line", selected.get("line_start", 1))
            ranges = selected.get("changed_line_ranges")
            if isinstance(ranges, list) and ranges and isinstance(ranges[0], list):
                candidate_line = ranges[0][0]
        return {
            "finding_candidates": [
                {
                    "path": candidate_path,
                    "line": candidate_line,
                    "title": "Fixture candidate — café",
                    "observation": "The changed predicate admits the request.",
                    "consequence": "A caller can reach a protected operation.",
                    "rule_or_contract": "Protected operations require authorization.",
                    "severity": "high",
                    "reasoning_kind": "inferred",
                    "introducedness": "INTRODUCED",
                    "evidence_refs": [evidence_id],
                }
            ],
            "context_gap_proposals": [],
            "coverage_notes": [
                {
                    "unit_id": "u0",
                    "state": "COVERED",
                    "reason_code": "REVIEWED",
                    "evidence_refs": [evidence_id],
                    "coverage_basis": "STATIC_REVIEW",
                }
            ],
        }

    def adjudicate(self, candidate: dict, evidence: list[dict], limits: dict) -> dict:
        refs = [item["evidence_id"] for item in evidence]
        return {
            "contract_version": "semantic-adjudication.v3",
            "source_contract_version": "semantic-adjudication.v3",
            "outcome": self.outcome,
            "observation_support": "NOT_ESTABLISHED",
            "consequence_support": "NOT_ESTABLISHED",
            "rule_connection_support": "NOT_ESTABLISHED",
            "introducedness": "UNKNOWN",
            "assumptions": [],
            "uncertainties": [],
            "summary": "The fixture evidence does not establish the candidate claim.",
            "evidence_refs": refs,
            "causal_roles": {
                name: {
                    "support": "NOT_ESTABLISHED",
                    "assessment": "The bounded fixture evidence does not establish this link.",
                    "evidence_refs": [],
                }
                for name in ("behavior", "consumer", "impact")
            },
            "material_consequence": False,
        }


class SupportedPrimaryProvider(PrimaryProvider):
    def __init__(self, *, material: bool = True, introducedness: str = "INTRODUCED"):
        super().__init__(outcome="SUPPORTED")
        self.material = material
        self.introducedness = introducedness

    def adjudicate(self, candidate: dict, evidence: list[dict], limits: dict) -> dict:
        refs = [item["evidence_id"] for item in evidence]
        payload = {
            "contract_version": "semantic-adjudication.v3",
            "source_contract_version": "semantic-adjudication.v3",
            "outcome": "SUPPORTED",
            "observation_support": "SUPPORTED",
            "consequence_support": "SUPPORTED",
            "rule_connection_support": "SUPPORTED",
            "introducedness": self.introducedness,
            "assumptions": [],
            "uncertainties": [],
            "summary": "The bounded fixture supports the candidate.",
            "evidence_refs": refs,
            "causal_roles": {
                role: {
                    "support": "SUPPORTED",
                    "assessment": f"The fixture supports the {role} link.",
                    "evidence_refs": refs,
                }
                for role in ("behavior", "consumer", "impact")
            },
            "material_consequence": self.material,
        }
        return {
            "payload": payload,
            "usage": {},
            "provenance": {"provider_rubric_version": "causal-roles.behavior-consumer-impact.v1"},
        }


class TwoCandidatePrimaryProvider(SupportedPrimaryProvider):
    def review(self, task: dict, evidence: list[dict], limits: dict) -> dict:
        result = super().review(task, evidence, limits)
        second = dict(result["finding_candidates"][0])
        second["title"] = "A distinct fixture candidate"
        second["observation"] = "The second changed predicate also admits the request."
        result["finding_candidates"].append(second)
        return result


@dataclass(frozen=True)
class Prepared:
    contract_version: str
    request_bytes: bytes
    request_hash: str
    candidate_hash: str
    evidence_hash: str
    question_hash: str
    primary_assessment_hash: str
    question_ids: tuple[tuple[str, str], ...]
    evidence_refs: tuple[str, ...]
    introducedness_available: bool


def _claim_hash(value: object) -> str:
    raw = json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(raw).hexdigest()


class FakeClaimAssessor:
    """Importable spawn target; its result is test data, not semantic truth."""

    identity = {"contract_version": "claim-assessment.2", "provider": "offline-fake"}

    def __init__(
        self,
        sleep_seconds: float = 0,
        status: str = "COMPLETE",
        padding_bytes: int = 0,
        empty_assessments: bool = False,
        empty_question_metadata: bool = False,
        corrupt_provenance: bool = False,
        budget_error: str | None = None,
        estimated_dispatch_deadline: float | None = None,
        dispatch_marker_path: str | None = None,
    ):
        self.sleep_seconds = sleep_seconds
        self.status = status
        self.padding_bytes = padding_bytes
        self.empty_assessments = empty_assessments
        self.empty_question_metadata = empty_question_metadata
        self.corrupt_provenance = corrupt_provenance
        self.budget_error = budget_error
        self.estimated_dispatch_deadline = estimated_dispatch_deadline
        self.dispatch_marker_path = dispatch_marker_path
        self.prepare_calls = 0

    def prepare(
        self,
        candidate: dict,
        evidence: list[dict],
        identity: dict,
        limits: dict,
        *,
        primary_assessment: dict,
    ) -> Prepared:
        self.prepare_calls += 1
        cited = [
            {
                "evidence_id": item["evidence_id"],
                "source_kind": item["source_kind"],
                "content_hash": item["content_hash"],
                "trust": item["trust"],
                "path": item.get("path"),
                "side": "HEAD" if item.get("source_revision") == identity["head_sha"] else None,
                "source_revision": item.get("source_revision"),
                "line": item.get("line"),
                "content": item["content"],
            }
            for item in evidence
        ]
        state = {
            "assessment_contract_version": "claim-assessment.2",
            "assessment_identity": identity,
            "candidate": candidate,
            "primary_assessment": primary_assessment,
            "cited_evidence": cited,
        }
        dimensions = (
            "observation_support",
            "consequence_support",
            "rule_connection_support",
            "materiality",
            "missing_context",
            "introducedness",
        )
        question_ids = tuple((name, f"question-{name}") for name in dimensions)
        questions = {
            f"question-{name}": {"criteria": {"NOT_ESTABLISHED": "test"}}
            for name in dimensions
            if name != "introducedness"
        }
        request = json.dumps(
            {"model": "offline-fake", "state": state, "questions": questions},
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        return Prepared(
            contract_version="claim-assessment.2",
            request_bytes=request,
            request_hash=hashlib.sha256(request).hexdigest(),
            candidate_hash=_claim_hash(candidate),
            evidence_hash=_claim_hash(cited),
            question_hash=_claim_hash(questions),
            primary_assessment_hash=_claim_hash(primary_assessment),
            question_ids=() if self.empty_question_metadata else question_ids,
            evidence_refs=tuple(item["evidence_id"] for item in cited),
            introducedness_available=False,
        )

    def estimate_prepared(self, prepared: Prepared, limits: dict) -> dict:
        if self.budget_error is not None:
            raise BudgetExhausted(self.budget_error)
        return {
            "provider_calls": 1,
            "input_bytes": len(prepared.request_bytes),
            "max_output_bytes": limits["max_output_bytes_per_task"],
            "provider_response_bytes": 2_000,
            "deadline_seconds": min(
                limits["deadline_seconds"],
                self.estimated_dispatch_deadline
                if self.estimated_dispatch_deadline is not None
                else limits["deadline_seconds"],
            ),
            "reservation_kind": "unknown",
        }

    def assess_prepared(self, prepared: Prepared, limits: dict) -> dict:
        if self.dispatch_marker_path is not None:
            Path(self.dispatch_marker_path).write_text("dispatched\n", encoding="utf-8")
        if self.sleep_seconds:
            time.sleep(self.sleep_seconds)
        request = json.loads(prepared.request_bytes)
        assessments = {}
        for dimension, question_id in prepared.question_ids:
            not_shown = dimension == "introducedness" and not prepared.introducedness_available
            assessments[dimension] = {
                "question_id": question_id,
                "status": "NOT_SHOWN" if not_shown else "ANSWERED",
                "native_primitive": "Choice",
                "choice": None if not_shown else "NOT_ESTABLISHED",
                "probabilities": None,
                "confidence": None,
                "evidence_refs": list(prepared.evidence_refs),
                "interpretation": "advisory_uncalibrated",
            }
        provenance = {
            "contract_version": prepared.contract_version,
            "request_hash": prepared.request_hash,
            "candidate_hash": prepared.candidate_hash,
            "evidence_hash": prepared.evidence_hash,
            "question_hash": prepared.question_hash,
            "primary_assessment_hash": prepared.primary_assessment_hash,
            **request["state"]["assessment_identity"],
            "provider_model_id": "offline-fake",
            "raw_response_cap_received": limits["max_output_bytes_per_task"],
        }
        if self.corrupt_provenance:
            provenance["request_hash"] = "f" * 64
        return {
            "contract_version": "claim-assessment.2",
            "status": self.status,
            "decision": "ADVISORY_ONLY",
            "assessments": {} if self.empty_assessments else assessments,
            "provenance": provenance,
            "usage": {},
            "padding": "x" * self.padding_bytes,
        }


class LocalClaimPreparationError(FakeClaimAssessor):
    def prepare(self, *args, **kwargs):
        raise ClaimAssessmentError("invalid_prepared_assessment")


class WrappedClaimDispatchError(FakeClaimAssessor):
    def assess_prepared(self, prepared: Prepared, limits: dict) -> dict:
        raise ClaimAssessmentError("invalid_assessment_identity_hash")


class UnknownClaimCodeError(FakeClaimAssessor):
    def prepare(self, *args, **kwargs):
        raise ClaimAssessmentError('private-canary "credential-value"')


class DerivedClaimAssessmentError(ClaimAssessmentError):
    pass


class Freshness:
    def __init__(
        self,
        value: str,
        dispatch_marker_path: str | None = None,
        dispatch_observation_path: str | None = None,
    ):
        self.value = value
        self.dispatch_marker_path = dispatch_marker_path
        self.dispatch_observation_path = dispatch_observation_path

    def __call__(self) -> dict:
        if self.dispatch_observation_path is not None:
            marker_seen = bool(
                self.dispatch_marker_path is not None and Path(self.dispatch_marker_path).is_file()
            )
            Path(self.dispatch_observation_path).write_text(
                "dispatch_seen\n" if marker_seen else "dispatch_missing\n",
                encoding="utf-8",
            )
        return {
            "freshness": self.value,
            "expected_head_sha": HEAD,
            "observed_head_sha": HEAD if self.value == "CURRENT" else "e" * 40,
        }


class ClaimChoiceHandler(BaseHTTPRequestHandler):
    """Loopback-only System One fixture that answers the prepared Choice IDs."""

    seen: list[bytes] = []
    token = "claim-engine-loopback-test-token"
    choices: dict[str, str] | None = None
    http_status = 200

    def do_POST(self):
        request_bytes = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        type(self).seen.append(request_bytes)
        if type(self).http_status != 200:
            response = b'{"error":"fixture unavailable"}'
            self.send_response(type(self).http_status)
            self.send_header("Content-Length", str(len(response)))
            self.end_headers()
            self.wfile.write(response)
            return
        request = json.loads(request_bytes)
        answers = {}
        for question_id, question in request["questions"].items():
            choices = list(question["criteria"])
            probabilities = {choice: 0.0 for choice in choices}
            dimension = next(
                (name for name in _CLAIM_CHOICES if f"category for {name}" in question["instructions"]), None
            )
            selected = (type(self).choices or {}).get(dimension, choices[0])
            if selected not in choices:
                selected = choices[0]
            probabilities[selected] = 1.0
            answers[question_id] = {
                "type": "choice",
                "choice": selected,
                "probabilities": probabilities,
                "confidence": 1.0,
            }
        response = json.dumps(
            {
                "model": "jev-1.13.0",
                "request_id": "loopback-claim-engine-test",
                "answers": answers,
                "usage": {"input_tokens": 10, "output_tokens": 5},
            }
        ).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)

    def log_message(self, *_args):
        pass


_CLAIM_CHOICES = (
    "observation_support",
    "consequence_support",
    "rule_connection_support",
    "materiality",
    "missing_context",
    "introducedness",
)


def _run(
    tmp_path,
    *,
    assessor=None,
    cap=0,
    limits=None,
    freshness=None,
    run_id="r1",
    resume=False,
    snapshot=None,
    profile=None,
    primary=None,
):
    snapshot = snapshot or _snapshot()
    profile = profile or _profile()
    plan = plan_review(snapshot, profile, "AUTO")
    return run_review(
        snapshot,
        plan,
        profile,
        primary or PrimaryProvider(),
        None,
        limits or LIMITS,
        str(tmp_path),
        run_id,
        resume=resume,
        freshness_check=freshness,
        claim_assessor=assessor,
        max_claim_assessments=cap,
    )


def _source_window_case(tmp_path):
    repo = tmp_path / "source-window-repo"
    repo.mkdir()
    git_env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": str(tmp_path),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
    }

    def git(*args):
        return subprocess.run(
            ["git", "-C", str(repo), *args],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            env=git_env,
        ).stdout.strip()

    git("init")
    git("config", "user.email", "fixture@example.invalid")
    git("config", "user.name", "Fixture")
    (repo / "AGENTS.md").write_text("trusted base rules\n")
    (repo / "docs").mkdir()
    (repo / "docs/contract.md").write_text("Protected operations require authorization.\n")
    (repo / "app.py").write_text(
        "def authorize(request):\n    audit(request)\n    normalize(request)\n    return False\n    finish()\n"
    )
    git("add", "AGENTS.md", "docs/contract.md", "app.py")
    git("-c", "core.hooksPath=/dev/null", "commit", "-m", "base")
    base = git("rev-parse", "HEAD")
    (repo / "app.py").write_text(
        "def authorize(request):\n    audit(request)\n    normalize(request)\n    return True\n    finish()\n"
    )
    git("add", "app.py")
    git("-c", "core.hooksPath=/dev/null", "commit", "-m", "change")
    head = git("rev-parse", "HEAD")
    profile = {
        "version": "context-selection-test-v3",
        "context_paths": ["AGENTS.md", "docs/contract.md"],
        "trusted_policy_paths": ["AGENTS.md"],
        "retrieval_context_patterns": ["AGENTS.md", "docs/contract.md"],
        "required_lenses": ["correctness"],
        "context_selection": {
            "version": "context-selection.v1",
            "mandatory_policy_paths": ["AGENTS.md"],
            "max_total_context_bytes": 4096,
            "window": {
                "before_lines": 1,
                "after_lines": 1,
                "max_bytes": 1024,
                "max_windows_per_unit": 4,
                "max_scan_bytes": 4096,
            },
            "bindings": [
                {
                    "unit_patterns": ["app.py"],
                    "lenses": ["correctness"],
                    "context_paths": ["docs/contract.md"],
                    "max_context_bytes": 2048,
                }
            ],
        },
    }
    snapshot = collect_snapshot(str(repo), base, head, profile, {"max_context_bytes": 20_000})
    unit = next(item for item in snapshot["inventory"] if item["path"] == "app.py")
    window = next(
        snapshot["evidence"][evidence_id]
        for evidence_id in unit["review_context_evidence_ids"]
        if snapshot["evidence"][evidence_id].get("source_kind") == "source_window"
        and snapshot["evidence"][evidence_id].get("source_side") == "HEAD"
    )
    assert window["line_start"] == 3
    assert window["line_end"] == 5
    assert len(window["content"].splitlines()) < len((repo / "app.py").read_text().splitlines())
    return snapshot, profile, window


def test_disabled_shadow_preserves_legacy_identity_and_result_shape(tmp_path):
    legacy = _run(tmp_path / "legacy")
    explicit_zero = _run(tmp_path / "zero", assessor=FakeClaimAssessor(), cap=0)

    assert legacy["request_hash"] == explicit_zero["request_hash"]
    assert legacy["disposition"] == explicit_zero["disposition"]
    assert legacy["findings"] == explicit_zero["findings"]
    assert "claim_assessments" not in legacy["ledger"]
    assert "claim_assessments" not in legacy
    assert "claim_assessment" not in legacy["ledger"]["identity"]


def test_positive_cap_requires_assessor_before_any_run_artifact(tmp_path):
    with pytest.raises(ValueError, match="requires a claim assessor"):
        _run(tmp_path, cap=1)
    assert not (tmp_path / "r1.json").exists()


def test_required_reconciliation_profile_rejects_missing_or_wrong_cap_before_primary_dispatch(tmp_path):
    class CountingPrimary(PrimaryProvider):
        calls = 0

        def review(self, task, evidence, limits):
            self.calls += 1
            return super().review(task, evidence, limits)

    primary = CountingPrimary()
    profile = _profile(reconciliation=True, cap=1)
    with pytest.raises(ValueError, match="review request is invalid"):
        _run(tmp_path, profile=profile, primary=primary, cap=0, assessor=FakeClaimAssessor())
    assert primary.calls == 0
    assert not (tmp_path / "r1.json").exists()


def test_reconciliation_rejects_stale_primary_assessment_binding():
    primary = {
        "observation_support": "SUPPORTED",
        "consequence_support": "SUPPORTED",
        "rule_connection_support": "SUPPORTED",
        "material_consequence": True,
        "introducedness": "INTRODUCED",
    }
    assessments = {
        "observation_support": {"status": "ANSWERED", "choice": "SUPPORTED"},
        "consequence_support": {"status": "ANSWERED", "choice": "SUPPORTED"},
        "rule_connection_support": {"status": "ANSWERED", "choice": "SUPPORTED"},
        "materiality": {"status": "ANSWERED", "choice": "MATERIAL"},
        "missing_context": {"status": "ANSWERED", "choice": "NO_MISSING_CONTEXT_IDENTIFIED"},
        "introducedness": {"status": "ANSWERED", "choice": "INTRODUCED"},
    }
    row = {
        "status": "COMPLETE",
        "response_valid": True,
        "primary_assessment_hash": "0" * 64,
        "candidate_hash": "1" * 64,
        "evidence_hash": "2" * 64,
        "request_hash": "3" * 64,
        "assessments": assessments,
    }

    result = classify_reconciliation(primary, row, candidate_valid=True)

    assert result["state"] == "PARTIAL"
    assert result["reason_code"] == "PRIMARY_ASSESSMENT_BINDING_MISMATCH"


def test_reconciliation_uses_engine_hash_for_unicode_primary_assessment():
    primary = {
        "observation_support": "SUPPORTED",
        "consequence_support": "SUPPORTED",
        "rule_connection_support": "SUPPORTED",
        "material_consequence": True,
        "introducedness": "INTRODUCED",
        "summary": "Réponse sûre — café",
    }
    assessments = {
        "observation_support": {"status": "ANSWERED", "choice": "SUPPORTED"},
        "consequence_support": {"status": "ANSWERED", "choice": "SUPPORTED"},
        "rule_connection_support": {"status": "ANSWERED", "choice": "SUPPORTED"},
        "materiality": {"status": "ANSWERED", "choice": "MATERIAL"},
        "missing_context": {"status": "ANSWERED", "choice": "NO_MISSING_CONTEXT_IDENTIFIED"},
        "introducedness": {"status": "ANSWERED", "choice": "INTRODUCED"},
    }
    row = {
        "status": "COMPLETE",
        "response_valid": True,
        "primary_assessment_hash": engine_module._hash(primary),
        "candidate_hash": "1" * 64,
        "evidence_hash": "2" * 64,
        "request_hash": "3" * 64,
        "assessments": assessments,
    }

    result = classify_reconciliation(primary, row, candidate_valid=True)

    assert result["state"] == "AGREES"
    assert result["primary_assessment_hash"] == engine_module._hash(primary)


def _run_with_native_claim_choices(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    choices: dict[str, str],
    primary: PrimaryProvider,
    http_status: int = 200,
    include_revision_evidence: bool = True,
):
    snapshot = _snapshot()
    if include_revision_evidence:
        for evidence_id, source_kind, revision, content in (
            ("base:u0", "base_file", BASE, "def authorize(request): return False"),
            ("head:u0", "head_file", HEAD, "def authorize(request): return True"),
        ):
            snapshot["evidence"][evidence_id] = {
                "evidence_id": evidence_id,
                "snapshot_id": snapshot["snapshot_id"],
                "path": "src/auth.py",
                "source_revision": revision,
                "content": content,
                "content_hash": hashlib.sha256(content.encode()).hexdigest(),
                "source_kind": source_kind,
                "trust": "repository_evidence",
            }
            snapshot["inventory"][0]["evidence_ids"].append(evidence_id)
    server = ThreadingHTTPServer(("127.0.0.1", 0), ClaimChoiceHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    ClaimChoiceHandler.seen = []
    ClaimChoiceHandler.choices = choices
    ClaimChoiceHandler.http_status = http_status
    thread.start()
    monkeypatch.setenv("CLAIM_ENGINE_TEST_KEY", ClaimChoiceHandler.token)
    try:
        transport = ClaimTransport(
            {
                "endpoint": f"http://127.0.0.1:{server.server_port}/v1/systemone",
                "api_key_env": "CLAIM_ENGINE_TEST_KEY",
                "model": "jev-latest",
                "timeout_seconds": 2,
                "max_request_bytes": 64_000,
                "max_response_bytes": 64_000,
            }
        )
        result = _run(
            tmp_path,
            snapshot=snapshot,
            assessor=ClaimAssessmentAdapter(transport, "jev-latest"),
            cap=1,
            limits={**LIMITS, "max_input_bytes_per_task": 128_000},
            profile=_profile(reconciliation=True, cap=1),
            primary=primary,
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        ClaimChoiceHandler.choices = None
        ClaimChoiceHandler.http_status = 200
    return result, list(ClaimChoiceHandler.seen)


def _supported_choices(*, consequence: str = "SUPPORTED") -> dict[str, str]:
    return {
        "observation_support": "SUPPORTED",
        "consequence_support": consequence,
        "rule_connection_support": "SUPPORTED",
        "materiality": "MATERIAL",
        "missing_context": "NO_MISSING_CONTEXT_IDENTIFIED",
        "introducedness": "INTRODUCED",
    }


def test_native_jev_agreement_is_bound_and_reaches_deterministic_reducer(tmp_path, monkeypatch):
    result, requests = _run_with_native_claim_choices(
        tmp_path,
        monkeypatch,
        choices=_supported_choices(),
        primary=SupportedPrimaryProvider(),
    )

    assert len(requests) == 1
    request = json.loads(requests[0])
    state = request["state"]
    assert state["primary_assessment"]["outcome"] == "SUPPORTED"
    assert state["candidate"]["observation"] == "The changed predicate admits the request."
    assert {item["evidence_id"] for item in state["cited_evidence"]} == {"diff:u0", "base:u0", "head:u0"}
    finding = result["findings"][0]
    assert finding["status"] == "ACCEPTED"
    assert finding["blocking_class"] == "BLOCKING"
    assert finding["claim_reconciliations"][0]["state"] == "AGREES"
    assert finding["claim_reconciliations"][0]["uncompared_dimensions"] == ["missing_context"]
    assert finding["claim_reconciliations"][0]["primary_assessment_hash"] == result["claim_assessments"][0][
        "primary_assessment_hash"
    ]
    assert result["coverage_state"] == "COMPLETE"
    assert result["disposition"] == "REQUEST_CHANGES"


def test_native_jev_dissent_is_visible_partial_and_cannot_clear_accepted_blocker(tmp_path, monkeypatch):
    result, requests = _run_with_native_claim_choices(
        tmp_path,
        monkeypatch,
        choices=_supported_choices(consequence="CONTRADICTED"),
        primary=SupportedPrimaryProvider(),
    )

    assert len(requests) == 1
    finding = result["findings"][0]
    reconciliation = finding["claim_reconciliations"][0]
    assert reconciliation["state"] == "CONFLICT"
    assert reconciliation["disagreeing_dimensions"] == ["consequence_support"]
    assert reconciliation["uncompared_dimensions"] == ["missing_context"]
    assert finding["status"] == "ACCEPTED"
    assert finding["blocking_class"] == "BLOCKING"
    assert result["coverage_state"] == "PARTIAL"
    assert any(
        row["obligation_kind"] == "CLAIM_RECONCILIATION"
        and row["state"] == "PARTIAL"
        and row["reconciliation_state"] == "CONFLICT"
        for row in result["coverage_ledger"]
    )
    assert result["disposition"] == "REQUEST_CHANGES"


def test_native_jev_support_cannot_promote_primary_unsupported_candidate(tmp_path, monkeypatch):
    choices = _supported_choices()
    choices["introducedness"] = "UNKNOWN"
    result, requests = _run_with_native_claim_choices(
        tmp_path,
        monkeypatch,
        choices=choices,
        primary=PrimaryProvider(outcome="NOT_SUPPORTED"),
    )

    assert len(requests) == 1
    finding = result["findings"][0]
    assert finding["claim_reconciliations"][0]["state"] == "CONFLICT"
    assert finding["blocking_class"] != "BLOCKING"
    assert result["coverage_state"] == "PARTIAL"
    assert result["disposition"] == "INCOMPLETE"


def test_native_jev_http_failure_is_partial_and_preserves_existing_blocker(tmp_path, monkeypatch):
    result, requests = _run_with_native_claim_choices(
        tmp_path,
        monkeypatch,
        choices=_supported_choices(),
        primary=SupportedPrimaryProvider(),
        http_status=503,
    )

    assert len(requests) == 1
    assert result["claim_assessments"][0]["status"] == "FAILED"
    assert result["findings"][0]["claim_reconciliations"][0]["state"] == "PARTIAL"
    assert result["coverage_state"] == "PARTIAL"
    assert result["findings"][0]["blocking_class"] == "BLOCKING"
    assert result["disposition"] == "REQUEST_CHANGES"


def test_required_reconciliation_missing_revision_evidence_cannot_clear(tmp_path, monkeypatch):
    result, requests = _run_with_native_claim_choices(
        tmp_path,
        monkeypatch,
        choices=_supported_choices(),
        primary=SupportedPrimaryProvider(),
        include_revision_evidence=False,
    )

    assert len(requests) == 1
    relation = result["findings"][0]["claim_reconciliations"][0]
    assert relation["state"] == "PARTIAL"
    assert relation["reason_code"] == "CLAIM_ASSESSMENT_DIMENSION_UNAVAILABLE"
    assert relation["unassessed_dimensions"] == ["introducedness"]
    assert result["coverage_state"] == "PARTIAL"
    assert result["findings"][0]["blocking_class"] == "BLOCKING"
    assert result["disposition"] == "REQUEST_CHANGES"


@pytest.mark.parametrize("missing_context", ["MISSING_CONTEXT_IDENTIFIED", "UNCERTAIN"])
def test_native_jev_context_qualifier_never_counts_as_comparable_agreement(tmp_path, monkeypatch, missing_context):
    choices = _supported_choices()
    choices["missing_context"] = missing_context
    result, requests = _run_with_native_claim_choices(
        tmp_path,
        monkeypatch,
        choices=choices,
        primary=SupportedPrimaryProvider(),
    )

    assert len(requests) == 1
    relation = result["findings"][0]["claim_reconciliations"][0]
    assert relation["state"] == "PARTIAL"
    assert "missing_context" in relation["uncompared_dimensions"]
    assert relation["disagreeing_dimensions"] == []
    assert relation["qualifier_status"] in {"UNSATISFIED", "UNRESOLVED"}
    assert result["coverage_state"] == "PARTIAL"
    assert result["disposition"] == "REQUEST_CHANGES"


def test_comparable_mismatch_remains_conflict_with_unsatisfied_context_qualifier(tmp_path, monkeypatch):
    choices = _supported_choices(consequence="CONTRADICTED")
    choices["missing_context"] = "MISSING_CONTEXT_IDENTIFIED"
    result, requests = _run_with_native_claim_choices(
        tmp_path,
        monkeypatch,
        choices=choices,
        primary=SupportedPrimaryProvider(),
    )

    assert len(requests) == 1
    relation = result["findings"][0]["claim_reconciliations"][0]
    assert relation["state"] == "CONFLICT"
    assert relation["disagreeing_dimensions"] == ["consequence_support"]
    assert relation["uncompared_dimensions"] == ["missing_context"]
    assert relation["qualifier_status"] == "UNSATISFIED"
    assert relation["qualifier_reason"] == "MISSING_CONTEXT_IDENTIFIED"


@pytest.mark.parametrize(
    ("introducedness", "material", "materiality_choice"),
    [("PRE_EXISTING", True, "MATERIAL"), ("INTRODUCED", False, "NOT_MATERIAL")],
)
def test_consistent_jev_answers_cannot_create_blocker_for_nonqualifying_primary(
    tmp_path, monkeypatch, introducedness, material, materiality_choice
):
    choices = _supported_choices()
    choices["introducedness"] = introducedness
    choices["materiality"] = materiality_choice
    result, requests = _run_with_native_claim_choices(
        tmp_path,
        monkeypatch,
        choices=choices,
        primary=SupportedPrimaryProvider(material=material, introducedness=introducedness),
    )

    assert len(requests) == 1
    assert all(
        finding.get("status") != "ACCEPTED" or finding.get("blocking_class") != "BLOCKING"
        for finding in result["findings"]
    )
    assert result["disposition"] != "REQUEST_CHANGES"


def test_required_classifier_cap_exhaustion_is_explicit_partial(tmp_path, monkeypatch):
    result, requests = _run_with_native_claim_choices(
        tmp_path,
        monkeypatch,
        choices=_supported_choices(),
        primary=TwoCandidatePrimaryProvider(),
    )

    assert len(requests) == 1
    assert len(result["claim_assessments"]) == 2
    statuses = {row["status"] for row in result["claim_assessments"]}
    assert statuses == {"COMPLETE", "NOT_RUN"}
    assert any(
        row.get("reason_code") == "CLAIM_ASSESSMENT_CAP_EXHAUSTED" for row in result["claim_assessments"]
    )
    assert result["coverage_state"] == "PARTIAL"
    assert result["disposition"] == "REQUEST_CHANGES"


def test_shadow_runs_after_primary_and_records_exact_reservation_without_changing_disposition(tmp_path):
    legacy = _run(tmp_path / "legacy")
    shadow = _run(tmp_path / "shadow", assessor=FakeClaimAssessor(), cap=1)

    assert shadow["disposition"] == legacy["disposition"]
    assert shadow["findings"] == legacy["findings"]
    row = shadow["claim_assessments"][0]
    reservations = shadow["ledger"]["budget"]["reservations"]
    keys = list(reservations)
    shadow_key = row["reservation_key"]
    assert row["status"] == "COMPLETE"
    assert keys.index(shadow_key) > max(i for i, key in enumerate(keys) if ":adjudicate:" in key)
    assert reservations[shadow_key]["kind"] == "claim_assessment"
    assert reservations[shadow_key]["input_bytes"] == row["input_bytes_reserved"]
    assert reservations[shadow_key]["max_output_bytes"] == row["ipc_output_bytes_reserved"]
    assert row["request_hash"] == row["provenance"]["request_hash"]
    assert row["provenance"]["raw_response_cap_received"] == 2_000
    assert row["assessments"]["observation_support"]["choice"] == "NOT_ESTABLISHED"
    assert shadow["coverage_state"] == legacy["coverage_state"]


def test_real_claim_adapter_and_loopback_transport_bind_candidate_primary_and_result(tmp_path, monkeypatch):
    server = ThreadingHTTPServer(("127.0.0.1", 0), ClaimChoiceHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    ClaimChoiceHandler.seen = []
    thread.start()
    monkeypatch.setenv("CLAIM_ENGINE_TEST_KEY", ClaimChoiceHandler.token)
    try:
        transport = ClaimTransport(
            {
                "endpoint": f"http://127.0.0.1:{server.server_port}/v1/systemone",
                "api_key_env": "CLAIM_ENGINE_TEST_KEY",
                "model": "jev-latest",
                "timeout_seconds": 2,
                "max_request_bytes": 64_000,
                "max_response_bytes": 64_000,
            }
        )
        assessor = ClaimAssessmentAdapter(transport, "jev-latest")
        # The core's valid task allowance is larger than the native System One
        # wire cap; the adapter must validate the actual serialized request.
        limits = {**LIMITS, "max_input_bytes_per_task": 128_000}
        result = _run(tmp_path, assessor=assessor, cap=1, limits=limits)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    assert len(ClaimChoiceHandler.seen) == 1
    payload = json.loads(ClaimChoiceHandler.seen[0])
    state = payload["state"]
    assert state["assessment_contract_version"] == "claim-assessment.2"
    assert state["candidate"]["evidence_refs"] == ["diff:u0"]
    assert state["primary_assessment"]["outcome"] == "NOT_SUPPORTED"
    assert [item["evidence_id"] for item in state["cited_evidence"]] == ["diff:u0"]
    row = result["claim_assessments"][0]
    assert row["status"] == "COMPLETE"
    assert 0 < len(ClaimChoiceHandler.seen[0]) <= 64_000
    assert row["input_bytes_reserved"] == len(ClaimChoiceHandler.seen[0])
    assert row["request_hash"] == hashlib.sha256(ClaimChoiceHandler.seen[0]).hexdigest()
    assert row["response_valid"] is True
    assert row["provenance_valid"] is True
    assert row["provenance"]["primary_assessment_hash"] == row["primary_assessment_hash"]
    assert row["candidate_hash"] == row["provenance"]["candidate_hash"]
    assert row["assessments"]["introducedness"]["status"] == "NOT_SHOWN"


def test_context_selected_head_source_window_reaches_claim_transport_with_exact_binding(tmp_path, monkeypatch):
    snapshot, profile, window = _source_window_case(tmp_path)
    plan = plan_review(snapshot, profile, "AUTO")
    correctness_tasks = [task for task in plan["tasks"] if task.get("lens") == "correctness"]
    assert any(window["evidence_id"] in task["evidence_ids"] for task in correctness_tasks)
    assert window["source_kind"] == "source_window"
    assert window["source_side"] == "HEAD"
    assert window["source_revision"] == snapshot["head_sha"]

    server = ThreadingHTTPServer(("127.0.0.1", 0), ClaimChoiceHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    ClaimChoiceHandler.seen = []
    thread.start()
    monkeypatch.setenv("CLAIM_ENGINE_TEST_KEY", ClaimChoiceHandler.token)
    try:
        transport = ClaimTransport(
            {
                "endpoint": f"http://127.0.0.1:{server.server_port}/v1/systemone",
                "api_key_env": "CLAIM_ENGINE_TEST_KEY",
                "model": "jev-latest",
                "timeout_seconds": 2,
                "max_request_bytes": 64_000,
                "max_response_bytes": 64_000,
            }
        )
        result = _run(
            tmp_path / "run",
            assessor=ClaimAssessmentAdapter(transport, "jev-latest"),
            cap=1,
            limits={**LIMITS, "max_input_bytes_per_task": 128_000},
            snapshot=snapshot,
            profile=profile,
            primary=PrimaryProvider(evidence_ref=window["evidence_id"]),
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    assert len(ClaimChoiceHandler.seen) == 1
    request = json.loads(ClaimChoiceHandler.seen[0])
    state = request["state"]
    cited = next(
        item for item in state["cited_evidence"] if item["evidence_id"] == window["evidence_id"]
    )
    assert cited["source_kind"] == "source_window"
    assert cited["content"] == window["content"]
    assert cited["content_hash"] == window["content_hash"]
    assert cited["side"] == "HEAD"
    assert cited["source_revision"] == snapshot["head_sha"]
    assert cited["path"] == window["path"] == "app.py"
    assert result["claim_assessments"][0]["status"] == "COMPLETE"


def test_real_claim_adapter_rejects_caller_overage_before_reservation(tmp_path, monkeypatch):
    server = ThreadingHTTPServer(("127.0.0.1", 0), ClaimChoiceHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    ClaimChoiceHandler.seen = []
    thread.start()
    monkeypatch.setenv("CLAIM_ENGINE_TEST_KEY", ClaimChoiceHandler.token)
    try:
        transport = ClaimTransport(
            {
                "endpoint": f"http://127.0.0.1:{server.server_port}/v1/systemone",
                "api_key_env": "CLAIM_ENGINE_TEST_KEY",
                "model": "jev-latest",
                "timeout_seconds": 2,
                "max_request_bytes": 64_000,
                "max_response_bytes": 64_000,
            }
        )
        assessor = ClaimAssessmentAdapter(transport, "jev-latest")
        large_limits = {**LIMITS, "max_input_bytes_per_task": 128_000}
        measured = _run(tmp_path / "measure", assessor=assessor, cap=1, limits=large_limits)
        exact_request_bytes = len(ClaimChoiceHandler.seen[0])
        assert measured["claim_assessments"][0]["status"] == "COMPLETE"

        ClaimChoiceHandler.seen = []
        # Derive the lower ceiling from the exact successfully dispatched body
        # produced by this same fixture; one byte under must reject locally.
        limits = {**large_limits, "max_input_bytes_per_task": exact_request_bytes - 1}
        result = _run(tmp_path / "over", assessor=assessor, cap=1, limits=limits)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    row = result["claim_assessments"][0]
    reservations = result["ledger"]["budget"]["reservations"]
    assert row["status"] == "FAILED"
    assert row["error_code"] == "request_exceeds_limit"
    assert row["reservation_key"] is None
    assert not any(item.get("kind") == "claim_assessment" for item in reservations.values())
    assert ClaimChoiceHandler.seen == []


def test_complete_claim_result_requires_bound_provenance_and_all_answers(tmp_path):
    empty = _run(tmp_path / "empty", assessor=FakeClaimAssessor(empty_assessments=True), cap=1)
    corrupt = _run(tmp_path / "corrupt", assessor=FakeClaimAssessor(corrupt_provenance=True), cap=1)

    assert empty["claim_assessments"][0]["status"] == "FAILED"
    assert empty["claim_assessments"][0]["reason_code"] == "RESPONSE_SCHEMA_INVALID"
    assert corrupt["claim_assessments"][0]["status"] == "FAILED"
    assert corrupt["claim_assessments"][0]["reason_code"] == "RESPONSE_PROVENANCE_MISMATCH"
    assert empty["findings"] == corrupt["findings"]
    assert empty["disposition"] == corrupt["disposition"]


def test_empty_prepared_question_metadata_fails_before_reservation(tmp_path):
    result = _run(
        tmp_path,
        assessor=FakeClaimAssessor(empty_question_metadata=True),
        cap=1,
    )

    row = result["claim_assessments"][0]
    assert row["status"] == "FAILED"
    assert row["error_type"] == "ValueError"
    assert row["reservation_key"] is None
    assert not any(
        item.get("kind") == "claim_assessment" for item in result["ledger"]["budget"]["reservations"].values()
    )


@pytest.mark.parametrize("primary_outcome", ["SUPPORTED", "NOT_SUPPORTED", "UNCERTAIN", "CONTRADICTED"])
def test_shadow_assesses_each_valid_primary_outcome_without_rewriting_it(tmp_path, primary_outcome):
    snapshot = _snapshot()
    profile = _profile()
    plan = plan_review(snapshot, profile, "AUTO")
    result = run_review(
        snapshot,
        plan,
        profile,
        PrimaryProvider(primary_outcome),
        None,
        LIMITS,
        str(tmp_path),
        "r1",
        claim_assessor=FakeClaimAssessor(),
        max_claim_assessments=1,
    )
    assert result["claim_assessments"][0]["status"] == "COMPLETE"
    assert result["findings"][0]["semantic_assessment"]["outcome"] == primary_outcome


def test_claim_cap_and_shared_provider_budget_fail_closed(tmp_path):
    capped = _run(tmp_path / "capped", assessor=FakeClaimAssessor(), cap=1)
    assert capped["claim_assessments"][0]["status"] == "COMPLETE"

    no_call_capacity = _run(
        tmp_path / "no-capacity",
        assessor=FakeClaimAssessor(),
        cap=1,
        limits={**LIMITS, "max_provider_calls": 2},
    )
    row = no_call_capacity["claim_assessments"][0]
    assert row["status"] == "NOT_RUN"
    assert row["reason_code"] == "PROVIDER_CALL_BUDGET_EXHAUSTED"
    assert len(no_call_capacity["ledger"]["budget"]["reservations"]) == 2


def test_unknown_budget_exception_text_is_not_persisted(tmp_path):
    marker = "private-budget-marker-do-not-persist"
    result = _run(tmp_path, assessor=FakeClaimAssessor(budget_error=marker), cap=1)
    row = result["claim_assessments"][0]
    saved = (tmp_path / "r1.json").read_text(encoding="utf-8")

    assert row["status"] == "NOT_RUN"
    assert row["reason_code"] == "CLAIM_ASSESSMENT_BUDGET_UNAVAILABLE"
    assert marker not in saved


def test_shadow_failure_preserves_primary_and_oversized_ipc_fails_closed(tmp_path):
    baseline = _run(tmp_path / "baseline")
    failed = _run(tmp_path / "failed", assessor=FakeClaimAssessor(status="FAILED"), cap=1)
    oversized = _run(
        tmp_path / "oversized",
        assessor=FakeClaimAssessor(padding_bytes=20_000),
        cap=1,
    )

    assert failed["claim_assessments"][0]["status"] == "FAILED"
    assert oversized["claim_assessments"][0]["status"] == "FAILED"
    assert oversized["claim_assessments"][0]["actual_output_bytes_observed"] > LIMITS["max_output_bytes_per_task"]
    assert oversized["claim_assessments"][0]["observed_output_limit_violation"] == {
        "actual_bytes": oversized["claim_assessments"][0]["actual_output_bytes_observed"],
        "reserved_bytes": LIMITS["max_output_bytes_per_task"],
    }
    for result in (failed,):
        assert result["disposition"] == baseline["disposition"]
        assert result["findings"] == baseline["findings"]
        assert result["budget"]["budget_breaches"] == baseline["budget"]["budget_breaches"]
    assert oversized["findings"] == baseline["findings"]
    assert oversized["disposition"] == "INCOMPLETE"
    assert oversized["budget"]["budget_breaches"] == [
        {
            "key": oversized["claim_assessments"][0]["reservation_key"],
            "reason": "OUTPUT_RESERVATION_OVERRUN",
            "actual": oversized["claim_assessments"][0]["actual_output_bytes_observed"],
            "reserved": LIMITS["max_output_bytes_per_task"],
        }
    ]


def test_local_claim_error_code_is_allowlisted_without_changing_status_or_reservation(tmp_path):
    result = _run(tmp_path, assessor=LocalClaimPreparationError(), cap=1)
    row = result["claim_assessments"][0]
    assert row["status"] == "FAILED"
    assert row["reason_code"] == "ClaimAssessmentError"
    assert row["error_code"] == "invalid_prepared_assessment"
    assert row.get("reservation_key") is None
    assert result["budget"]["cost"] == "UNKNOWN"
    resumed = _run(tmp_path, assessor=LocalClaimPreparationError(), cap=1, resume=True)
    assert resumed["claim_assessments"][0]["status"] == "FAILED"
    assert resumed["claim_assessments"][0]["error_code"] == "invalid_prepared_assessment"


def test_wrapped_claim_error_code_requires_exact_remote_type_and_known_message(tmp_path):
    result = _run(tmp_path, assessor=WrappedClaimDispatchError(), cap=1)
    row = result["claim_assessments"][0]
    assert row["status"] == "FAILED"
    assert row["reason_code"] == "IsolatedCallError"
    assert row["error_code"] == "invalid_assessment_identity_hash"


def test_unknown_local_claim_error_code_is_generic_and_never_persists_canary(tmp_path):
    marker = 'private-canary "credential-value"'
    result = _run(tmp_path, assessor=UnknownClaimCodeError(), cap=1)
    row = result["claim_assessments"][0]
    saved = (tmp_path / "r1.json").read_text(encoding="utf-8")
    assert row["status"] == "FAILED"
    assert row["reason_code"] == "ClaimAssessmentError"
    assert row["error_code"] == "UNKNOWN"
    assert marker not in saved


def test_finite_claim_error_codes_cover_every_literal_engine_contract_code():
    source = Path(engine_module.__file__).with_name("claim_assessment.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    observed = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "ClaimAssessmentError":
            assert node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str)
            observed.add(node.args[0].value)
    assert observed == CLAIM_ASSESSMENT_ERROR_CODES


def test_wrapped_error_code_requires_allowlisted_message_and_exact_remote_type():
    assert engine_module._safe_claim_error_code(
        IsolatedCallError("ClaimAssessmentError", "invalid_prepared_assessment")
    ) == "invalid_prepared_assessment"
    assert engine_module._safe_claim_error_code(
        IsolatedCallError("ClaimAssessmentError", 'private-canary "credential-value"')
    ) == "UNKNOWN"
    assert engine_module._safe_claim_error_code(
        IsolatedCallError("ValueError", "invalid_prepared_assessment")
    ) == "UNKNOWN"
    assert engine_module._safe_claim_error_code(DerivedClaimAssessmentError("invalid_prepared_assessment")) == "UNKNOWN"


def test_enabled_claim_configuration_is_bound_to_resume_identity(tmp_path):
    first = _run(tmp_path, assessor=FakeClaimAssessor(), cap=1)
    assert first["claim_assessments"][0]["status"] == "COMPLETE"
    snapshot = _snapshot()
    profile = _profile()
    plan = plan_review(snapshot, profile, "AUTO")
    with pytest.raises(ValueError, match="resume request mismatch"):
        run_review(
            snapshot,
            plan,
            profile,
            PrimaryProvider(),
            None,
            LIMITS,
            str(tmp_path),
            "r1",
            resume=True,
            claim_assessor=FakeClaimAssessor(),
            max_claim_assessments=2,
        )


def test_unsettled_shadow_reservation_is_not_redispatched_on_resume(tmp_path, monkeypatch):
    class SimulatedControllerCrash(BaseException):
        pass

    original_reserve = engine_module.BudgetLedger.reserve

    def crash_after_claim_reservation(self, key, estimate, *, kind="provider"):
        reservation = original_reserve(self, key, estimate, kind=kind)
        if kind == "claim_assessment":
            raise SimulatedControllerCrash()
        return reservation

    assessor = FakeClaimAssessor()
    monkeypatch.setattr(engine_module.BudgetLedger, "reserve", crash_after_claim_reservation)
    with pytest.raises(SimulatedControllerCrash):
        _run(tmp_path, assessor=assessor, cap=1)

    monkeypatch.setattr(engine_module.BudgetLedger, "reserve", original_reserve)
    snapshot = _snapshot()
    profile = _profile()
    result = run_review(
        snapshot,
        plan_review(snapshot, profile, "AUTO"),
        profile,
        PrimaryProvider(),
        None,
        LIMITS,
        str(tmp_path),
        "r1",
        resume=True,
        claim_assessor=assessor,
        max_claim_assessments=1,
    )

    row = result["claim_assessments"][0]
    assert row["status"] == "INTERRUPTED_UNKNOWN"
    assert row["reason_code"] == "PRIOR_SHADOW_ATTEMPT_UNSETTLED"
    assert assessor.prepare_calls == 1
    assert result["ledger"]["budget"]["settlements"][row["reservation_key"]]["status"] == "INTERRUPTED_UNKNOWN"


def test_final_callable_freshness_runs_after_timed_out_shadow_and_stale_still_gates(tmp_path):
    # Give primary work ample time, then bound the actual shadow dispatch with
    # the fake assessor's finite quote. Its child marks dispatch before sleeping
    # past that deadline, so this exercises a post-dispatch timeout independent
    # of primary-stage timing. The final freshness callback remains authoritative.
    marker = tmp_path / "shadow-dispatched"
    freshness_observation = tmp_path / "freshness-observed-dispatch"
    current_freshness = Freshness("CURRENT", str(marker), str(freshness_observation))
    timeout = _run(
        tmp_path / "timeout",
        assessor=FakeClaimAssessor(
            sleep_seconds=10,
            estimated_dispatch_deadline=2,
            dispatch_marker_path=str(marker),
        ),
        cap=1,
        limits={**LIMITS, "deadline_seconds": 60},
        freshness=current_freshness,
    )
    assert timeout["claim_assessments"][0]["status"] == "INTERRUPTED_UNKNOWN"
    assert timeout["freshness"] == "CURRENT"
    assert freshness_observation.read_text(encoding="utf-8") == "dispatch_seen\n"

    stale = _run(
        tmp_path / "stale",
        assessor=FakeClaimAssessor(),
        cap=1,
        limits={**LIMITS, "deadline_seconds": 60},
        freshness=Freshness("STALE"),
    )
    assert stale["claim_assessments"][0]["status"] == "COMPLETE"
    assert stale["freshness"] == "STALE"
    assert stale["disposition"] == "INCOMPLETE"
