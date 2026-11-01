"""Focused tests for OE-3 generated status evidence and its CI checks."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from datetime import date
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import generate_status_evidence as status  # noqa: E402

INPUTS = "scripts/status-evidence.inputs.v1.json"
PAGE = "docs/STATUS-EVIDENCE.md"
MANIFEST = "scripts/documentation-status-evidence.v1.json"


def write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def git(root: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(root), *args], check=True, text=True, capture_output=True).stdout.strip()


def commit(root: Path, message: str) -> str:
    git(root, "add", "-A")
    git(root, "commit", "-qm", message)
    return git(root, "rev-parse", "HEAD")


def registry() -> dict[str, object]:
    return {
        "registry_version": "contract-registry.v1",
        "supported_combination": {
            "review_contract": "core-v1",
            "profile": "profile-v1",
            "limits": "limits-v1",
            "target_repository": "owner/repository",
        },
        "contracts": [
            {"name": "core-v1", "status": "supported", "replaced_by": None},
            {"name": "profile-v1", "status": "supported", "replaced_by": None},
            {"name": "limits-v1", "status": "supported", "replaced_by": None},
            {"name": "legacy-v14", "status": "deprecated", "replaced_by": "core-v1"},
            {"name": "old-v1", "status": "archived", "replaced_by": None},
        ],
    }


def decision(links: list[str]) -> dict[str, object]:
    return {
        "route": "harness CLI (`pr-review publish`)",
        "state": "UNAVAILABLE — preview only",
        "decision": "NO-GO",
        "evidence_class": "REPORTED",
        "decision_date": "2026-09-29",
        "evidence_links": links,
    }


def inputs(revision: str) -> dict[str, object]:
    return {
        "schema_version": status.INPUTS_SCHEMA,
        "observation": {"revision": revision},
        "contract_registry": "src/pr_review_harness/contract_registry.json",
        "last_verified_run": {
            "state": "NOT_RECORDED",
            "summary_schema": "review-run-summary.v1",
            "reason": "no retained review-run-summary.v1 artifact is checked in",
        },
        "publication_decisions": [decision(["docs/DECISION.md", "src/app.py"])],
        "owner_review_manifest": "scripts/documentation-truth-evidence.v1.json",
        "historical_snapshots": [{"label": "historical checkpoint", "path": "docs/history/checkpoints/checkpoint.md"}],
        "freshness_source_paths": ["src/app.py", "docs/STATUS.md"],
        "evidence_links": [
            "scripts/generate_status_evidence.py",
            "src/app.py",
            "docs/DECISION.md",
            "scripts/documentation-truth-evidence.v1.json",
        ],
    }


def build_repo(tmp_path: Path, *, stale_owner: bool = False) -> str:
    git(tmp_path, "init", "-q")
    git(tmp_path, "config", "user.email", "status-evidence@example.invalid")
    git(tmp_path, "config", "user.name", "Status evidence test")
    write(tmp_path / "src" / "app.py", "first\n")
    write(tmp_path / "src" / "pr_review_harness" / "contract_registry.json", json.dumps(registry(), indent=2) + "\n")
    write(tmp_path / "schemas" / "review-run-summary.v1.schema.json", "{}\n")
    write(tmp_path / "tests" / "test_status_evidence.py", "# synthetic evidence link\n")
    write(tmp_path / "scripts" / "generate_status_evidence.py", "# synthetic generator link\n")
    write(
        tmp_path / "scripts" / "documentation-contract-ids.v1.json",
        json.dumps({"schema_version": "documentation-contract-ids.v1", "contract_ids": ["legacy-v14"]}) + "\n",
    )
    write(tmp_path / "docs" / "STATUS.md", "# Status\n\nOwner-reviewed observation.\n")
    write(tmp_path / "docs" / "DECISION.md", "# Decision\n\nNO-GO.\n")
    write(tmp_path / "docs" / "VERIFICATION.md", "# Verification\n")
    write(tmp_path / "docs" / "history" / "checkpoints" / "checkpoint.md", "# Historical checkpoint\n")
    write(tmp_path / "scripts" / "documentation-truth-evidence.v1.json", "{}\n")
    head = commit(tmp_path, "base")
    evidence_revision = head
    if stale_owner:
        write(tmp_path / "src" / "app.py", "source change after the owner observation\n")
        commit(tmp_path, "post-observation source change")
    owner = {
        "schema_version": status.EVIDENCE_SCHEMA,
        "documents": [
            {
                "document": "docs/STATUS.md",
                "evidence_revision": evidence_revision,
                "evidence_date": "2026-11-01",
                "source_paths": ["src/app.py"],
                "evidence_links": ["../src/app.py"],
            }
        ],
    }
    write(tmp_path / "scripts" / "documentation-truth-evidence.v1.json", json.dumps(owner, indent=2) + "\n")
    observation = commit(tmp_path, "record owner evidence")
    write(tmp_path / INPUTS, json.dumps(inputs(observation), indent=2) + "\n")
    return commit(tmp_path, "record inputs")


def build_status(root: Path, head: str = "HEAD") -> status.Generated:
    return status.build(root, root / INPUTS, root / PAGE, root / MANIFEST, head)


def row_cells(markdown: str, section: str) -> list[list[str]]:
    cells: list[list[str]] = []
    inside = False
    for line in markdown.splitlines():
        if line.startswith("## "):
            inside = line.strip() == section
            continue
        if not inside or not line.startswith("|"):
            continue
        values = [value.strip() for value in line.strip().strip("|").split("|")]
        if values and values[0] == "Field":
            continue
        if values and set("".join(values)) <= {"-", ":"}:
            continue
        cells.append(values)
    return cells


def test_generator_builds_all_required_fields_with_links(tmp_path: Path) -> None:
    head = build_repo(tmp_path)
    generated = build_status(tmp_path)
    page = generated.page_text
    assert "Derived evidence, not an owner review" in page
    assert "does **not** refresh" in page
    for label in status.REQUIRED_FIELD_LABELS:
        assert f"| {label} |" in page
    rows = row_cells(page, status.STATUS_SECTION)
    assert len(rows) == len(status.REQUIRED_FIELD_LABELS)
    assert all(any("](" in cell for cell in row[1:]) for row in rows)
    commit_date = git(tmp_path, "show", "-s", "--format=%cs", head)
    assert f"| Evidence date | {commit_date} (observation revision commit date" in page
    assert "NOT RECORDED" in page
    assert "contract-registry.v1: 3 supported, 0 experimental, 1 deprecated, 1 archived" in page
    assert "legacy-v14" in page and "### Deprecated contracts (not current)" in page
    assert "NO-GO" in page and "REPORTED" in page
    assert "## Historical snapshots (immutable; not current)" in page
    assert "## Status owner-review observation" in page
    assert "NO FINDINGS" in page


def test_manifest_is_dt3_compatible_and_links_resolve(tmp_path: Path) -> None:
    build_repo(tmp_path)
    generated = build_status(tmp_path)
    manifest = json.loads(generated.manifest_text)
    assert manifest["schema_version"] == status.EVIDENCE_SCHEMA
    record = manifest["documents"][0]
    assert record["document"] == PAGE
    assert record["evidence_revision"] == generated.observation["full"]
    assert record["evidence_date"] == date.fromisoformat(generated.observation["date"]).isoformat()
    assert record["source_paths"] == ["src/app.py", "docs/STATUS.md"]
    for link in record["evidence_links"]:
        assert (tmp_path / PAGE).parent.joinpath(link).resolve().exists()
    write(tmp_path / PAGE, generated.page_text)
    write(tmp_path / MANIFEST, generated.manifest_text)
    assert status.check(tmp_path, tmp_path / INPUTS, tmp_path / PAGE, tmp_path / MANIFEST) == []


def test_generator_records_last_verified_run_from_artifact(tmp_path: Path) -> None:
    build_repo(tmp_path)
    summary = {
        "schema": "review-run-summary.v1",
        "identity": {"run_id": "pr-7-42", "head_sha": "b" * 40},
        "run": {
            "completed_at": "2026-11-01T10:03:00Z",
            "terminal_state": "INCOMPLETE",
            "coverage_state": "PARTIAL",
        },
        "contract": {
            "review_contract_name": "core-v1",
            "review_contract_version": "core-v1",
            "limits_name": "limits-v1",
            "limits_version": "limits-v1",
        },
    }
    write(tmp_path / "evidence" / "run-summary.json", json.dumps(summary) + "\n")
    data = inputs(git(tmp_path, "rev-parse", "HEAD"))
    data["last_verified_run"] = {
        "state": "RECORDED",
        "summary_schema": "review-run-summary.v1",
        "summary": "evidence/run-summary.json",
    }
    generated = status.build(
        tmp_path,
        write(tmp_path / INPUTS, json.dumps(data) + "\n"),
        tmp_path / PAGE,
        tmp_path / MANIFEST,
    )
    assert "pr-7-42 at bbbbbbb, terminal INCOMPLETE, coverage PARTIAL" in generated.page_text
    assert "| 2026-11-01 |" in generated.page_text


def test_invalid_run_summary_fails_closed(tmp_path: Path) -> None:
    build_repo(tmp_path)
    write(tmp_path / "evidence" / "run-summary.json", json.dumps({"schema": "review-run-summary.v1"}) + "\n")
    data = inputs(git(tmp_path, "rev-parse", "HEAD"))
    data["last_verified_run"] = {
        "state": "RECORDED",
        "summary_schema": "review-run-summary.v1",
        "summary": "evidence/run-summary.json",
    }
    inputs_path = write(tmp_path / INPUTS, json.dumps(data) + "\n")
    with pytest.raises(ValueError, match="identity and run"):
        status.build(tmp_path, inputs_path, tmp_path / PAGE, tmp_path / MANIFEST)


def test_owner_review_staleness_is_surfaced_not_refreshed(tmp_path: Path) -> None:
    build_repo(tmp_path, stale_owner=True)
    status_doc = tmp_path / "docs" / "STATUS.md"
    owner_manifest = tmp_path / "scripts" / "documentation-truth-evidence.v1.json"
    status_before = hashlib.sha256(status_doc.read_bytes()).hexdigest()
    owner_before = hashlib.sha256(owner_manifest.read_bytes()).hexdigest()
    generated = build_status(tmp_path)
    assert "STALE — not refreshed by this block" in generated.page_text
    assert "STATUS_STALE" in generated.page_text
    assert "does not rewrite it" in generated.page_text
    assert hashlib.sha256(status_doc.read_bytes()).hexdigest() == status_before
    assert hashlib.sha256(owner_manifest.read_bytes()).hexdigest() == owner_before


def test_evidence_date_comes_from_revision_not_file_edit_date(tmp_path: Path) -> None:
    head = build_repo(tmp_path)
    commit_date = git(tmp_path, "show", "-s", "--format=%cs", head)
    old = 946684800  # 2000-01-01
    for path in (tmp_path / "src" / "app.py", tmp_path / INPUTS, tmp_path / "docs" / "STATUS.md"):
        os.utime(path, (old, old))
    page = build_status(tmp_path).page_text
    assert f"| Evidence date | {commit_date} (observation revision commit date" in page
    assert "2000-01-01" not in page


def test_generator_refuses_status_page_historical_and_escaping_outputs(tmp_path: Path) -> None:
    build_repo(tmp_path)
    with pytest.raises(ValueError, match="refusing to write docs/STATUS.md"):
        status.build(tmp_path, tmp_path / INPUTS, tmp_path / "docs" / "STATUS.md", tmp_path / MANIFEST)
    historical = tmp_path / "docs" / "history" / "generated.md"
    with pytest.raises(ValueError, match="historical evidence paths"):
        status.build(tmp_path, tmp_path / INPUTS, historical, tmp_path / MANIFEST)
    with pytest.raises(ValueError, match="must be inside the repository"):
        status.build(tmp_path, tmp_path / INPUTS, tmp_path.parent / "outside.md", tmp_path / MANIFEST)


def test_missing_artifacts_and_invalid_inputs_fail_closed(tmp_path: Path) -> None:
    build_repo(tmp_path)
    base = inputs(git(tmp_path, "rev-parse", "HEAD"))
    for key, value, match in (
        ("contract_registry", "missing/registry.json", "contract_registry"),
        ("owner_review_manifest", "missing/owner.json", "owner_review_manifest"),
        ("historical_snapshots", [{"label": "missing", "path": "missing.md"}], "historical_snapshots"),
        ("freshness_source_paths", ["missing.py"], "freshness_source_paths"),
        ("evidence_links", ["missing.txt"], "evidence_links"),
    ):
        data = json.loads(json.dumps(base))
        data[key] = value
        path = write(tmp_path / "invalid-inputs.json", json.dumps(data) + "\n")
        with pytest.raises(ValueError, match=match):
            status.build(tmp_path, path, tmp_path / PAGE, tmp_path / MANIFEST)

    data = json.loads(json.dumps(base))
    data["observation"] = {"revision": "not-a-sha"}
    invalid = write(tmp_path / "invalid-inputs.json", json.dumps(data) + "\n")
    with pytest.raises(ValueError, match="full 40-character"):
        status.build(tmp_path, invalid, tmp_path / PAGE, tmp_path / MANIFEST)

    data = json.loads(json.dumps(base))
    data["publication_decisions"][0]["evidence_class"] = "GUESSED"
    invalid = write(tmp_path / "invalid-inputs.json", json.dumps(data) + "\n")
    with pytest.raises(ValueError, match="evidence_class"):
        status.build(tmp_path, invalid, tmp_path / PAGE, tmp_path / MANIFEST)


def test_check_detects_out_of_date_outputs_and_seeded_stale_source(tmp_path: Path) -> None:
    build_repo(tmp_path)
    generated = build_status(tmp_path)
    write(tmp_path / PAGE, generated.page_text)
    write(tmp_path / MANIFEST, generated.manifest_text)
    assert status.check(tmp_path, tmp_path / INPUTS, tmp_path / PAGE, tmp_path / MANIFEST) == []

    write(tmp_path / PAGE, generated.page_text + "\nhand edit\n")
    codes = {finding.code for finding in status.check(tmp_path, tmp_path / INPUTS, tmp_path / PAGE, tmp_path / MANIFEST)}
    assert "STATUS_EVIDENCE_OUT_OF_DATE" in codes

    write(tmp_path / PAGE, generated.page_text)
    write(tmp_path / "src" / "app.py", "source changed after evidence\n")
    commit(tmp_path, "post-evidence source change")
    findings = status.check(tmp_path, tmp_path / INPUTS, tmp_path / PAGE, tmp_path / MANIFEST)
    assert "STATUS_STALE" in {finding.code for finding in findings}
    assert any("refresh the evidence" in finding.message for finding in findings if finding.code == "STATUS_STALE")


def test_superseded_contract_reference_fails_only_when_unlabelled(tmp_path: Path) -> None:
    build_repo(tmp_path)
    generated = build_status(tmp_path)
    write(tmp_path / PAGE, generated.page_text)
    write(tmp_path / MANIFEST, generated.manifest_text)
    assert status.check(tmp_path, tmp_path / INPUTS, tmp_path / PAGE, tmp_path / MANIFEST) == []
    write(
        tmp_path / PAGE,
        generated.page_text.replace("## Evidence links", "Use legacy-v14 as the current contract.\n\n## Evidence links"),
    )
    codes = {finding.code for finding in status.check(tmp_path, tmp_path / INPUTS, tmp_path / PAGE, tmp_path / MANIFEST)}
    assert "SUPERSEDED_CONTRACT_UNMARKED" in codes


def test_unlinked_claim_and_inline_revision_are_rejected(tmp_path: Path) -> None:
    build_repo(tmp_path)
    generated = build_status(tmp_path)
    lines = generated.page_text.splitlines()
    unlinked = "\n".join(
        "| Current evidence revision | no link here | dropped | dropped |"
        if line.startswith("| Current evidence revision |")
        else line
        for line in lines
    )
    findings = status._validate_markdown(tmp_path, unlinked, tmp_path / PAGE)
    assert "STATUS_EVIDENCE_CLAIM_UNLINKED" in {finding.code for finding in findings}
    inline = generated.page_text + "\nEvidence at `abcdef1`.\n"
    inline_findings = status._validate_markdown(tmp_path, inline, tmp_path / PAGE)
    assert "STATUS_EVIDENCE_INLINE_REVISION" in {finding.code for finding in inline_findings}


def test_cli_check_json_and_write_mode(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    build_repo(tmp_path)
    args = ["--root", str(tmp_path), "--inputs", INPUTS, "--page", PAGE, "--manifest", MANIFEST]
    assert status.main(args + ["--json"]) == 0
    capsys.readouterr()
    assert status.main(args + ["--check", "--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["schema_version"] == status.REPORT_SCHEMA
    assert report["findings"] == []
    write(tmp_path / PAGE, (tmp_path / PAGE).read_text(encoding="utf-8") + "\nhand edit\n")
    assert status.main(args + ["--check", "--json"]) == 1
    report = json.loads(capsys.readouterr().out)
    assert {finding["code"] for finding in report["findings"]} == {"STATUS_EVIDENCE_OUT_OF_DATE"}
    assert status.main(["--root", str(tmp_path), "--inputs", "missing.json", "--page", PAGE, "--manifest", MANIFEST]) == 2


def test_historical_evidence_files_are_never_written(tmp_path: Path) -> None:
    build_repo(tmp_path)
    historical = tmp_path / "docs" / "history" / "checkpoints" / "checkpoint.md"
    before = hashlib.sha256(historical.read_bytes()).hexdigest()
    generated = build_status(tmp_path)
    write(tmp_path / PAGE, generated.page_text)
    write(tmp_path / MANIFEST, generated.manifest_text)
    assert hashlib.sha256(historical.read_bytes()).hexdigest() == before
    assert "immutable" in generated.page_text
    assert "checkpoint.md" in generated.page_text


def test_checked_in_generated_outputs_pass_the_same_gate() -> None:
    findings = status.check(ROOT, ROOT / INPUTS, ROOT / PAGE, ROOT / MANIFEST)
    assert findings == []
