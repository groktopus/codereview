from __future__ import annotations

import re
from pathlib import Path

WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/central-pilot-admission-canary.yml"


def _trigger_names(source: str) -> tuple[str, ...]:
    lines = source.splitlines()
    start = lines.index("  workflow_run:")
    workflow_line = lines.index("    workflows:", start + 1)
    names = []
    for line in lines[workflow_line + 1 :]:
        if line.startswith("      - "):
            names.append(line.removeprefix("      - ").strip().strip("'\""))
        elif line.startswith("    types:"):
            break
    return tuple(names)


def _step(source: str, name: str) -> str:
    marker = f"      - name: {name}\n"
    start = source.index(marker)
    end = source.find("\n      - ", start + len(marker))
    return source[start:] if end < 0 else source[start:end]


def test_only_exact_central_pilot_completions_trigger_the_automatic_canary():
    source = WORKFLOW.read_text(encoding="utf-8")
    assert _trigger_names(source) == ("SlopSearX read-only review pilot",)
    assert "    types:\n      - completed" in source
    assert "github.event.workflow_run.repository.full_name == 'groktopus/codereview'" in source
    assert "github.event.workflow_run.conclusion == 'success'" in source
    assert "github.ref == 'refs/heads/main'" in source


def test_manual_rehearsal_defaults_to_the_existing_run_and_preserves_attempt():
    source = WORKFLOW.read_text(encoding="utf-8")
    dispatch = source.split("  workflow_dispatch:\n", 1)[1].split("\npermissions:", 1)[0]
    assert re.search(r"source_run_id:\s*\n\s+description:.*\n\s+required: true\n\s+default: '36531683964'", dispatch)
    assert re.search(r"source_run_attempt:\s*\n\s+description:.*\n\s+required: true\n\s+default: '1'", dispatch)
    step = _step(source, "Verify source run and current PR using bounded read-only requests")
    assert "--event-name workflow_dispatch" in step
    assert '--run-id "$SOURCE_RUN_ID"' in step
    assert '--attempt "$SOURCE_RUN_ATTEMPT"' in step


def test_permissions_are_read_only_and_only_hash_receipt_is_retained():
    source = WORKFLOW.read_text(encoding="utf-8")
    top_permissions = source.split("permissions:\n", 1)[1].split("\n\nconcurrency:", 1)[0]
    job_permissions = source.split("    permissions:\n", 1)[1].split("\n    steps:", 1)[0]
    for permissions in (top_permissions, job_permissions):
        assert "actions: read" in permissions
        assert "contents: read" in permissions
        assert "pull-requests: read" in permissions
        assert "write" not in permissions
    upload = _step(source, "Retain only the hash-based candidate receipt for seven days")
    assert "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02" in upload
    assert "central-pilot-candidate-receipt.json" in upload
    assert "retention-days: 7" in upload
    assert "review-result.json" not in upload and "review.md" not in upload
    assert "LLM_API_KEY" not in source and "JEV_API_KEY" not in source


def test_checkout_is_protected_revision_without_persisted_credentials():
    source = WORKFLOW.read_text(encoding="utf-8")
    checkout = _step(source, "Check out only the protected canary workflow revision")
    assert "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683" in checkout
    assert "ref: ${{ github.sha }}" in checkout
    assert "persist-credentials: false" in checkout
