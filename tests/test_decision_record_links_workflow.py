"""Tests for the GA-2 decision-record-links workflow and its documentation wiring."""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/decision-record-links.yml"
SCRIPT = ROOT / "scripts/check_decision_record_links.py"
DOC = ROOT / "docs/REVIEW-EVIDENCE.md"
ADR_INDEX = ROOT / "docs/adr/README.md"
CONTRIBUTING = ROOT / "CONTRIBUTING.md"
TEMPLATE = ROOT / ".github/pull_request_template.md"
PINNED_CHECKOUT = "11bd71901bbe5b1630ceea73d27597364c9af683"


def load_workflow() -> tuple[dict[str, Any], str]:
    raw = WORKFLOW.read_text(encoding="utf-8")
    workflow = yaml.safe_load(raw)
    assert isinstance(workflow, dict)
    return workflow, raw


def triggers(workflow: dict[str, Any]) -> dict[str, Any]:
    value = workflow.get("on", workflow.get(True))
    assert isinstance(value, dict)
    return value


def test_required_check_name_is_stable() -> None:
    workflow, _ = load_workflow()
    assert workflow["name"] == "Decision record links"
    assert workflow["jobs"]["decision-record-links"]["name"] == "Decision record links"


def test_workflow_triggers_only_on_pull_request_target_for_main() -> None:
    workflow, _ = load_workflow()
    trigger = triggers(workflow)
    assert set(trigger) == {"pull_request_target"}
    assert trigger["pull_request_target"]["branches"] == ["main"]
    assert trigger["pull_request_target"]["types"] == ["opened", "edited", "synchronize", "reopened"]
    for forbidden in ("push", "workflow_run", "workflow_dispatch", "schedule"):
        assert forbidden not in trigger


def test_workflow_is_read_only_and_has_no_secrets() -> None:
    workflow, raw = load_workflow()
    expected = {"contents": "read", "pull-requests": "read"}
    assert workflow["permissions"] == expected
    job = workflow["jobs"]["decision-record-links"]
    assert job["permissions"] == expected
    assert "secrets:" not in raw
    assert "${{ secrets." not in raw
    assert "write" not in raw
    assert "pull_request_target" in raw


def test_workflow_checks_out_the_base_revision_only() -> None:
    _, raw = load_workflow()
    assert "ref: ${{ github.event.pull_request.base.sha }}" in raw
    for forbidden in ("github.event.pull_request.head", "refs/pull/", "github.head_ref"):
        assert forbidden not in raw
    assert "persist-credentials: false" in raw


def test_workflow_uses_pinned_actions() -> None:
    _, raw = load_workflow()
    pins = re.findall(r"uses:\s*([^\s@]+)@(\S+)", raw)
    assert pins == [("actions/checkout", PINNED_CHECKOUT)]


def test_workflow_runs_the_checker_with_the_read_only_token() -> None:
    workflow, raw = load_workflow()
    job = workflow["jobs"]["decision-record-links"]
    run_steps = [step for step in job["steps"] if "run" in step]
    assert len(run_steps) == 1
    script = run_steps[0]["run"]
    assert "scripts/check_decision_record_links.py" in script
    assert "--base-ref" in script
    assert "--changed-files" not in script
    assert "--summary" in script
    assert run_steps[0]["env"]["GITHUB_TOKEN"] == "${{ github.token }}"
    assert "secrets" not in run_steps[0]["env"]
    assert "ghp_" not in raw


def test_checker_reads_network_only_with_the_stdlib() -> None:
    tree = ast.parse(SCRIPT.read_text(encoding="utf-8"))
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            modules.add(node.module.split(".")[0])
    assert "urllib" in modules
    assert modules.isdisjoint({"requests", "httpx", "aiohttp", "socket", "ssl", "http"})


def test_review_evidence_documents_decision_records_and_enforcement() -> None:
    doc = DOC.read_text(encoding="utf-8")
    assert "decision_records" in doc
    assert "Decision record links" in doc
    assert "safety-invariants.json" in doc
    assert "Accepted" in doc
    assert "Require status checks to pass before merging" in doc
    assert "branch protection" in doc.lower()
    for code in (
        "DECISION_RECORDS_MISSING",
        "RECORD_NOT_INDEXED",
        "RECORD_NOT_ACCEPTED",
        "RECORD_MISSING",
        "CHANGED_FILES_API_UNAVAILABLE",
    ):
        assert code in doc


def test_adr_index_records_active_enforcement_and_remaining_owner_action() -> None:
    index = ADR_INDEX.read_text(encoding="utf-8")
    assert "Decision record links" in index
    assert "decision_records" in index
    assert "safety-invariants.json" in index
    lowered = index.lower()
    assert "branch protection" in lowered
    assert "required" in lowered


def test_contributing_documents_the_enforced_check() -> None:
    contributing = CONTRIBUTING.read_text(encoding="utf-8")
    assert "Decision record links" in contributing
    assert "decision_records" in contributing
    assert "docs/adr/README.md" in contributing
    assert "safety-invariant" in contributing
    assert "decision record" in contributing
    assert "check_decision_record_links.py" in contributing


def test_template_requires_decision_records_in_the_receipt() -> None:
    template = TEMPLATE.read_text(encoding="utf-8")
    assert '"decision_records"' in template
    assert "Decision record links" in template
    assert "safety-invariants.json" in template
    assert "Accepted" in template
    assert "decision record" in template.lower()
    assert "safety invariant" in template.lower()
    assert "docs/adr/README.md" in template


def test_docs_index_still_links_the_review_protocol() -> None:
    index = (ROOT / "docs/README.md").read_text(encoding="utf-8")
    assert "(REVIEW-EVIDENCE.md)" in index
    assert "(adr/README.md)" in index
