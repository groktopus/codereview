"""Ingest authoritative, immutable-revision check-run evidence."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any


class CheckEvidenceError(ValueError):
    """External check evidence failed its version or identity contract."""


class GitHubCheckAdapter:
    """Serve only previously ingested GitHub check evidence to planned tasks."""

    def __call__(self, task: dict, snapshot: dict, profile: dict | None = None, limits: dict | None = None) -> dict:
        binding = task.get("check_binding_id")
        result = snapshot.get("external_check_results", {}).get(binding, {})
        evidence_id = result.get("evidence_id") if isinstance(result, dict) else None
        evidence_map = snapshot.get("evidence", {})
        evidence = evidence_map.get(evidence_id) if isinstance(evidence_map, dict) and evidence_id else None
        outcome = result.get("outcome", "UNKNOWN") if isinstance(result, dict) else "UNKNOWN"
        if outcome not in {"PASS", "FINDINGS", "UNKNOWN", "ERROR"}:
            outcome = "UNKNOWN"
        return {
            "check_id": task.get("check_id", binding),
            "outcome": outcome,
            "finding_candidates": [],
            "evidence_refs": [evidence_id] if evidence else [],
            "diagnostics": [] if evidence else ["authoritative_check_run_evidence_unavailable"],
        }


def _hash(value: Any) -> str:
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    return hashlib.sha256(canonical).hexdigest()


def _timestamp(value: object) -> bool:
    if not isinstance(value, str) or not value:
        return False
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.tzinfo is not None and parsed.utcoffset() is not None


def ingest_check_runs(document: dict, request: dict, bindings: list[dict]) -> dict:
    """Bind a versioned check-runs document to its repository, PR, and head.

    A successful run is evidence only for the exact trusted profile binding,
    completed status, matching app identity when configured, and immutable PR
    head SHA. Missing or ambiguous evidence yields UNKNOWN, never PASS.
    """
    schema_version = document.get("schema_version") if isinstance(document, dict) else None
    if not isinstance(document, dict) or schema_version not in {"1.0", "2.0"}:
        raise CheckEvidenceError("unsupported check evidence schema")
    for key in ("repository", "pull_request_number", "head_sha", "runs"):
        if key not in document:
            raise CheckEvidenceError("check evidence is missing required identity")
    if (
        document.get("repository") != request.get("repository")
        or document.get("pull_request_number") != request.get("pull_request_number")
        or document.get("head_sha") != request.get("head_sha")
        or isinstance(document.get("pull_request_number"), bool)
        or not isinstance(document.get("pull_request_number"), int)
        or not isinstance(document.get("head_sha"), str)
        or not re.fullmatch(r"[0-9a-f]{40,64}", document.get("head_sha", ""))
    ):
        raise CheckEvidenceError("check evidence does not match review identity")
    if not isinstance(document["runs"], list) or not isinstance(bindings, list):
        raise CheckEvidenceError("check evidence collections are invalid")
    complete = document.get("complete", True)
    if not isinstance(complete, bool):
        raise CheckEvidenceError("check evidence completeness flag is invalid")
    captured_at = document.get("captured_at")
    if not _timestamp(captured_at):
        raise CheckEvidenceError("check evidence capture time is required")

    results = {}
    evidence = {}
    for binding in bindings:
        if not isinstance(binding, dict) or not isinstance(binding.get("id"), str) or not binding["id"]:
            raise CheckEvidenceError("check binding identity is invalid")
        check_name = binding.get("github_check_name")
        expected_app = binding.get("github_app_id")
        if not isinstance(check_name, str) or not check_name:
            results[binding["id"]] = {"outcome": "UNKNOWN", "reason": "github_check_name_not_configured"}
            continue
        if isinstance(expected_app, bool) or not isinstance(expected_app, int) or expected_app < 1:
            results[binding["id"]] = {"outcome": "UNKNOWN", "reason": "app_identity_not_configured"}
            continue
        if not complete:
            results[binding["id"]] = {"outcome": "UNKNOWN", "reason": "check_run_listing_incomplete"}
            continue
        matches = [
            run
            for run in document["runs"]
            if isinstance(run, dict) and run.get("name") == check_name and run.get("app_id") == expected_app
        ]
        if len(matches) != 1:
            results[binding["id"]] = {"outcome": "UNKNOWN", "reason": "check_run_missing_or_ambiguous"}
            continue
        run = matches[0]
        run_id = run.get("id")
        status = run.get("status")
        conclusion = run.get("conclusion")
        run_sha = run.get("head_sha")
        app_id = run.get("app_id")
        if (
            isinstance(run_id, bool)
            or not isinstance(run_id, int)
            or run_id < 1
            or isinstance(app_id, bool)
            or not isinstance(app_id, int)
            or app_id < 1
            or status not in {"completed", "in_progress", "queued", "pending"}
            or not isinstance(run_sha, str)
            or not re.fullmatch(r"[0-9a-f]{40,64}", run_sha)
            or run_sha != request.get("head_sha")
            or (expected_app is not None and app_id != expected_app)
            or (status == "completed" and not _timestamp(run.get("completed_at")))
        ):
            results[binding["id"]] = {"outcome": "UNKNOWN", "reason": "check_run_identity_or_status_invalid"}
            continue
        payload = {
            "repository": request["repository"],
            "pull_request_number": request["pull_request_number"],
            "head_sha": request["head_sha"],
            "binding_id": binding["id"],
            "check_name": check_name,
            "run_id": str(run_id),
            "app_id": app_id,
            "status": status,
            "conclusion": conclusion,
            "completed_at": run.get("completed_at"),
            "captured_at": captured_at,
        }
        if schema_version == "1.0":
            # Historical v1 inputs retain their original evidence-hash
            # semantics. New v2 captures exclude provider-owned identifiers
            # and URLs, which are unnecessary to determine check identity or
            # outcome and may contain sensitive data.
            payload["external_id"] = run.get("external_id")
            payload["details_url"] = run.get("details_url")
        else:
            payload["evidence_contract"] = "github-check-evidence.v2"
        evidence_id = "check-" + _hash(payload)[:24]
        payload["content_hash"] = _hash(payload)
        payload["evidence_id"] = evidence_id
        payload["source_kind"] = "github_check_run"
        payload["trust"] = "generated_result"
        evidence[evidence_id] = payload
        outcome = (
            "PASS"
            if status == "completed" and conclusion == "success"
            else "FINDINGS"
            if status == "completed"
            and conclusion in {"failure", "cancelled", "timed_out", "action_required", "startup_failure"}
            else "UNKNOWN"
        )
        results[binding["id"]] = {
            "outcome": outcome,
            "reason": None if outcome != "UNKNOWN" else "check_run_not_complete_or_conclusion_unknown",
            "evidence_id": evidence_id,
        }
    return {
        "schema_version": schema_version,
        "repository": request["repository"],
        "pull_request_number": request["pull_request_number"],
        "head_sha": request["head_sha"],
        "captured_at": captured_at,
        "results": results,
        "evidence": evidence,
        "evidence_hash": _hash({"results": results, "evidence": evidence}),
    }


def make_check_runs_document(
    repository: str,
    pull_request_number: int,
    head_sha: str,
    runs: list[dict],
    *,
    captured_at: str | None = None,
    complete: bool = True,
) -> dict:
    """Create the strict external ingestion envelope from GitHub API data."""
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise CheckEvidenceError("repository identity is invalid")
    if isinstance(pull_request_number, bool) or not isinstance(pull_request_number, int) or pull_request_number < 1:
        raise CheckEvidenceError("pull request number is invalid")
    if not isinstance(head_sha, str) or not re.fullmatch(r"[0-9a-f]{40,64}", head_sha):
        raise CheckEvidenceError("head SHA is invalid")
    if captured_at is not None and not _timestamp(captured_at):
        raise CheckEvidenceError("capture timestamp is invalid")
    if not isinstance(complete, bool):
        raise CheckEvidenceError("completeness flag is invalid")
    return {
        "schema_version": "2.0",
        "repository": repository,
        "pull_request_number": pull_request_number,
        "head_sha": head_sha,
        "captured_at": captured_at or datetime.now(timezone.utc).isoformat(),
        "complete": complete,
        "runs": runs,
    }
