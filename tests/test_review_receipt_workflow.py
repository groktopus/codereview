"""Tests for the review-receipt workflow, pull request template, and docs wiring."""

from __future__ import annotations

import ast
import json
import re
import sys
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import check_review_receipt as receipt_check  # noqa: E402

WORKFLOW = ROOT / ".github/workflows/review-receipt.yml"
TEMPLATE = ROOT / ".github/pull_request_template.md"
SCRIPT = ROOT / "scripts/check_review_receipt.py"
DOC = ROOT / "docs/REVIEW-EVIDENCE.md"


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
    assert workflow["name"] == "Review receipt"
    assert workflow["jobs"]["review-receipt"]["name"] == "Review receipt"


def test_workflow_triggers_only_on_pull_request_target() -> None:
    workflow, _ = load_workflow()
    trigger = triggers(workflow)
    assert set(trigger) == {"pull_request_target"}
    assert trigger["pull_request_target"]["types"] == ["opened", "edited", "synchronize", "reopened"]
    assert "pull_request" not in trigger


def test_workflow_is_read_only_and_has_no_secrets() -> None:
    workflow, raw = load_workflow()
    assert workflow["permissions"] == {"contents": "read"}
    job = workflow["jobs"]["review-receipt"]
    assert job["permissions"] == {"contents": "read"}
    assert "secrets:" not in raw
    assert "${{ secrets." not in raw
    assert "write" not in raw


def test_workflow_checks_out_base_revision_only() -> None:
    _, raw = load_workflow()
    assert "github.event.pull_request.base.sha" in raw
    assert "github.event.pull_request.head.sha" not in raw
    assert "github.head_ref" not in raw
    assert "ref: ${{ github.event.pull_request.base.sha }}" in raw
    assert "persist-credentials: false" in raw


def test_workflow_uses_pinned_checkout_action() -> None:
    _, raw = load_workflow()
    pins = re.findall(r"actions/checkout@([0-9a-f]{40})", raw)
    assert pins == ["11bd71901bbe5b1630ceea73d27597364c9af683"]


def test_workflow_runs_the_receipt_script() -> None:
    workflow, raw = load_workflow()
    job = workflow["jobs"]["review-receipt"]
    run_steps = [step["run"] for step in job["steps"] if "run" in step]
    assert len(run_steps) == 1
    assert "scripts/check_review_receipt.py" in run_steps[0]
    assert "--event" not in run_steps[0]
    assert SCRIPT.is_file()


def test_workflow_does_not_use_pull_request_head_checkout() -> None:
    _, raw = load_workflow()
    for forbidden in ("github.event.pull_request.head", "refs/pull/"):
        assert forbidden not in raw


def test_pull_request_template_has_one_receipt_block() -> None:
    template = TEMPLATE.read_text(encoding="utf-8")
    blocks, unclosed = receipt_check.extract_receipt_blocks(template)
    assert unclosed is False
    assert len(blocks) == 1
    decoded = json.loads(blocks[0])
    assert decoded["schema"] == "review-receipt.v1"
    assert set(decoded) == receipt_check.ROOT_FIELDS
    assert set(decoded["reviewer"]) <= receipt_check.REVIEWER_FIELDS
    assert template.count("```review-receipt") == 1


def test_pull_request_template_is_rejected_until_completed() -> None:
    template = TEMPLATE.read_text(encoding="utf-8")
    event = {
        "pull_request": {
            "body": template,
            "head": {"sha": "a" * 40},
            "user": {"login": "some-author"},
        }
    }
    report = receipt_check.validate_event(event)
    assert not report.ok
    codes = {failure.code for failure in report.failures}
    assert codes & {"FIELD_INVALID", "PLACEHOLDER", "VERDICT_NOT_CLEAR"}


def test_template_links_the_protocol() -> None:
    template = TEMPLATE.read_text(encoding="utf-8")
    assert "docs/REVIEW-EVIDENCE.md" in template
    assert "reviewed_sha" in template
    assert "post_merge_verification" in template


def test_docs_index_links_the_protocol() -> None:
    index = (ROOT / "docs/README.md").read_text(encoding="utf-8")
    assert "(REVIEW-EVIDENCE.md)" in index


def test_readme_and_contributing_link_the_protocol() -> None:
    assert "docs/REVIEW-EVIDENCE.md" in (ROOT / "README.md").read_text(encoding="utf-8")
    assert "docs/REVIEW-EVIDENCE.md" in (ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")


def test_doc_records_required_fields_rules_and_limits() -> None:
    doc = DOC.read_text(encoding="utf-8")
    for name in (
        "reviewer.identity",
        "reviewer.kind",
        "reviewed_sha",
        "independence",
        "scope",
        "verdict",
        "evidence",
        "reviewed_at",
        "post_merge_verification",
        "self_review",
    ):
        assert name in doc
    for section in ("Required receipt fields", "Rules", "Enforcement limits", "post-merge"):
        assert section in doc
    assert "Require status checks to pass before merging" in doc
    assert "Review receipt" in doc


def test_validator_has_no_network_or_process_imports() -> None:
    tree = ast.parse(SCRIPT.read_text(encoding="utf-8"))
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            modules.add(node.module.split(".")[0])
    assert modules.isdisjoint({"subprocess", "socket", "urllib", "http", "requests", "ssl", "asyncio", "ftplib"})
    source = SCRIPT.read_text(encoding="utf-8")
    assert "os.system" not in source
    assert "eval(" not in source
    assert "exec(" not in source
