#!/usr/bin/env python3
"""Generate derived status evidence and a DT-3 freshness record.

The generator reads checked-in artifacts (an observation revision, the contract
registry, an optional retained run summary, retained publication-decision
records, the DT-3 owner-review manifest, and labelled historical snapshots) and
renders two deterministic outputs:

* a Markdown status/evidence page, and
* a ``documentation-evidence.v1`` manifest consumable by
  ``scripts/check_docs_truth.py``.

It is deliberately not an owner review. ``docs/STATUS.md`` and its evidence
record are never written here; their freshness findings are surfaced verbatim
so a derived block cannot silently promote a stale review to fresh.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from collections import Counter
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path
from typing import Any

SCRIPTS_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPTS_DIR.parent
sys.path.insert(0, str(SCRIPTS_DIR))

from check_docs_truth import Finding, check_claims, check_status_freshness, check_superseded_contracts  # noqa: E402
from check_relative_links import check_paths  # noqa: E402

INPUTS_SCHEMA = "status-evidence-inputs.v1"
EVIDENCE_SCHEMA = "documentation-evidence.v1"
RUN_SUMMARY_SCHEMA = "review-run-summary.v1"
REPORT_SCHEMA = "status-evidence-report.v1"
CONTRACT_SCHEMA = "documentation-contract-ids.v1"
STATUS_SECTION = "## Derived evidence"
DEPRECATED_HEADING = "### Deprecated contracts (not current)"
SHA_RE = re.compile(r"[0-9a-fA-F]{40}\Z")
INLINE_HEX_RE = re.compile(r"`([0-9a-fA-F]{7,40})`")
EVIDENCE_CLASSES = {"OBSERVED", "REPORTED", "UNKNOWN"}
REQUIRED_FIELD_LABELS = (
    "Current evidence revision",
    "Last verified run",
    "Contract set",
    "Publication decision",
    "Status owner review",
    "Evidence date",
)
DEFAULT_INPUTS = "scripts/status-evidence.inputs.v1.json"
DEFAULT_PAGE = "docs/STATUS-EVIDENCE.md"
DEFAULT_MANIFEST = "scripts/documentation-status-evidence.v1.json"


@dataclass(frozen=True)
class Generated:
    """Rendered outputs plus the evidence data used to produce them."""

    page_text: str
    manifest_text: str
    observation: dict[str, Any]
    registry: dict[str, Any]
    run: dict[str, Any]
    decisions: list[dict[str, Any]]
    owner_records: list[dict[str, Any]]
    owner_findings: list[Finding]
    historical: list[dict[str, str]]
    freshness_sources: list[str]
    evidence_links: list[dict[str, str]]


def _read_json(path: Path, label: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot read {label} {path}: {error}") from error


def _nonempty(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be a non-empty string")
    return value.strip()


def _repo_path(root: Path, value: Any, label: str) -> Path:
    """Resolve a repository-relative path without allowing escape."""

    text = _nonempty(value, label)
    candidate = Path(text)
    if candidate.is_absolute():
        raise ValueError(f"{label} must be repository-relative: {text!r}")
    resolved = (root / candidate).resolve()
    if not resolved.is_relative_to(root.resolve()):
        raise ValueError(f"{label} escapes the repository: {text!r}")
    return resolved


def _existing_file(root: Path, value: Any, label: str) -> Path:
    path = _repo_path(root, value, label)
    if not path.is_file():
        raise ValueError(f"{label} does not name an existing file: {value!r}")
    return path


def _relative_link(page_path: Path, target_path: Path) -> str:
    return Path(os.path.relpath(target_path, start=page_path.parent)).as_posix()


def _repo_relative(root: Path, path: Path) -> str:
    return path.resolve().relative_to(root.resolve()).as_posix()


def _git(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["git", "-C", str(root), *args], check=False, text=True, capture_output=True)


def _commit(root: Path, value: Any) -> dict[str, str]:
    revision = _nonempty(value, "observation.revision")
    if not SHA_RE.fullmatch(revision):
        raise ValueError("observation.revision must be a full 40-character commit SHA")
    result = _git(root, "show", "-s", "--format=%H%n%cs%n%s", revision)
    if result.returncode:
        raise ValueError(f"observation.revision is not a commit in this checkout: {revision!r}")
    lines = result.stdout.splitlines()
    if len(lines) < 3 or not SHA_RE.fullmatch(lines[0]):
        raise ValueError(f"cannot read commit identity for observation.revision {revision!r}")
    if lines[0].lower() != revision.lower():
        raise ValueError(f"observation.revision did not resolve exactly: {revision!r}")
    try:
        date.fromisoformat(lines[1])
    except ValueError as error:
        raise ValueError(f"commit date for observation.revision is not an ISO-8601 date: {lines[1]!r}") from error
    return {"full": lines[0].lower(), "short": lines[0][:7], "date": lines[1], "subject": lines[2]}


def _path_evidence_date(root: Path, revision: str, repo_path: str) -> str:
    result = _git(root, "log", "-1", "--format=%cs", revision, "--", repo_path)
    value = result.stdout.strip()
    if result.returncode or not value:
        raise ValueError(f"cannot determine the last change date for {repo_path!r} at the observation revision")
    try:
        date.fromisoformat(value)
    except ValueError as error:
        raise ValueError(f"last change date for {repo_path!r} is not an ISO-8601 date: {value!r}") from error
    return value


def _registry(root: Path, rel: Any, observation: dict[str, str], page_path: Path) -> dict[str, Any]:
    path = _existing_file(root, rel, "contract_registry")
    data = _read_json(path, "contract registry")
    if not isinstance(data, dict) or not isinstance(data.get("registry_version"), str):
        raise ValueError("contract registry must be an object with a string registry_version")
    contracts = data.get("contracts")
    if not isinstance(contracts, list):
        raise ValueError("contract registry must contain a contracts array")
    entries: list[dict[str, str]] = []
    for index, entry in enumerate(contracts):
        if not isinstance(entry, dict):
            raise ValueError(f"contracts[{index}] must be an object")
        name = _nonempty(entry.get("name"), f"contracts[{index}].name")
        status = _nonempty(entry.get("status"), f"contracts[{index}].status")
        if status not in {"supported", "experimental", "deprecated", "archived"}:
            raise ValueError(f"contracts[{index}].status is not a recognised registry status: {status!r}")
        replaced_by = entry.get("replaced_by")
        entries.append(
            {
                "name": name,
                "status": status,
                "replaced_by": replaced_by if isinstance(replaced_by, str) else "",
            }
        )
    names = {entry["name"] for entry in entries}
    if len(names) != len(entries):
        raise ValueError("contract registry contains duplicate contract names")
    combination = data.get("supported_combination")
    if not isinstance(combination, dict) or not combination:
        raise ValueError("contract registry must contain a non-empty supported_combination object")
    effective = []
    for role, name in sorted(combination.items()):
        if not isinstance(name, str) or not name:
            raise ValueError(f"supported_combination.{role} must be a contract name")
        match = next((entry for entry in entries if entry["name"] == name), None)
        if match is None:
            if role == "target_repository":
                continue
            raise ValueError(f"supported_combination.{role} names an unknown contract: {name!r}")
        effective.append({"role": role, "name": name, "status": match["status"]})
    counts = Counter(entry["status"] for entry in entries)
    repo_rel = _repo_relative(root, path)
    return {
        "path": repo_rel,
        "link": _relative_link(page_path, path),
        "version": data["registry_version"],
        "counts": dict(counts),
        "effective": effective,
        "deprecated": [entry for entry in entries if entry["status"] == "deprecated"],
        "archived_count": counts.get("archived", 0),
        "evidence_date": _path_evidence_date(root, observation["full"], repo_rel),
    }


def _run_evidence(root: Path, spec: Any, page_path: Path) -> dict[str, Any]:
    if not isinstance(spec, dict):
        raise ValueError("last_verified_run must be an object")
    state = _nonempty(spec.get("state"), "last_verified_run.state")
    schema = _nonempty(spec.get("summary_schema", RUN_SUMMARY_SCHEMA), "last_verified_run.summary_schema")
    if schema != RUN_SUMMARY_SCHEMA:
        raise ValueError(f"last_verified_run.summary_schema must be {RUN_SUMMARY_SCHEMA!r}")
    schema_path = root / "schemas" / f"{RUN_SUMMARY_SCHEMA}.schema.json"
    schema_link = _relative_link(page_path, schema_path)
    if state == "NOT_RECORDED":
        if "summary" in spec:
            raise ValueError("last_verified_run.state NOT_RECORDED cannot also name a summary")
        reason = _nonempty(spec.get("reason"), "last_verified_run.reason")
        return {"state": state, "reason": reason, "schema": schema, "schema_link": schema_link}
    if state != "RECORDED":
        raise ValueError("last_verified_run.state must be RECORDED or NOT_RECORDED")
    path = _existing_file(root, spec.get("summary"), "last_verified_run.summary")
    data = _read_json(path, "run summary")
    if not isinstance(data, dict) or data.get("schema") != RUN_SUMMARY_SCHEMA:
        raise ValueError(f"run summary must use schema {RUN_SUMMARY_SCHEMA!r}")
    identity = data.get("identity")
    run = data.get("run")
    if not isinstance(identity, dict) or not isinstance(run, dict):
        raise ValueError("run summary must contain identity and run objects")
    run_id = _nonempty(identity.get("run_id"), "run summary identity.run_id")
    head_sha = _nonempty(identity.get("head_sha"), "run summary identity.head_sha")
    if not SHA_RE.fullmatch(head_sha):
        raise ValueError("run summary identity.head_sha must be a full 40-character SHA")
    completed_at = _nonempty(run.get("completed_at"), "run summary run.completed_at")
    try:
        completed = datetime.fromisoformat(completed_at.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(f"run summary run.completed_at is not an ISO-8601 timestamp: {completed_at!r}") from error
    contract = data.get("contract") if isinstance(data.get("contract"), dict) else {}
    contract_fields = {
        key: contract[key] for key in ("review_contract_name", "review_contract_version", "limits_name", "limits_version") if isinstance(contract.get(key), str)
    }
    return {
        "state": state,
        "run_id": run_id,
        "head_sha": head_sha,
        "head_short": head_sha[:7],
        "terminal_state": _nonempty(run.get("terminal_state", "UNKNOWN"), "run summary run.terminal_state"),
        "coverage_state": _nonempty(run.get("coverage_state", "UNKNOWN"), "run summary run.coverage_state"),
        "evidence_date": completed.date().isoformat(),
        "contract": contract_fields,
        "link": _relative_link(page_path, path),
        "schema": schema,
        "schema_link": schema_link,
    }


def _publication_decisions(root: Path, values: Any, page_path: Path) -> list[dict[str, Any]]:
    if not isinstance(values, list) or not values:
        raise ValueError("publication_decisions must be a non-empty array")
    records: list[dict[str, Any]] = []
    for index, row in enumerate(values):
        label = f"publication_decisions[{index}]"
        if not isinstance(row, dict):
            raise ValueError(f"{label} must be an object")
        route = _nonempty(row.get("route"), f"{label}.route")
        state = _nonempty(row.get("state"), f"{label}.state")
        decision = _nonempty(row.get("decision"), f"{label}.decision")
        evidence_class = _nonempty(row.get("evidence_class"), f"{label}.evidence_class")
        if evidence_class not in EVIDENCE_CLASSES:
            raise ValueError(f"{label}.evidence_class must be one of {sorted(EVIDENCE_CLASSES)}")
        decision_date = _nonempty(row.get("decision_date"), f"{label}.decision_date")
        try:
            date.fromisoformat(decision_date)
        except ValueError as error:
            raise ValueError(f"{label}.decision_date must be an ISO-8601 date") from error
        links = row.get("evidence_links")
        if not isinstance(links, list) or not links:
            raise ValueError(f"{label}.evidence_links must be a non-empty array")
        rendered_links = []
        for link_index, link in enumerate(links):
            target = _existing_file(root, link, f"{label}.evidence_links[{link_index}]")
            rendered_links.append({"path": _repo_relative(root, target), "link": _relative_link(page_path, target)})
        records.append(
            {
                "route": route,
                "state": state,
                "decision": decision,
                "evidence_class": evidence_class,
                "decision_date": decision_date,
                "links": rendered_links,
            }
        )
    return records


def _owner_records(
    root: Path, manifest_value: Any, head: str
) -> tuple[list[dict[str, Any]], list[Finding], Path]:
    path = _existing_file(root, manifest_value, "owner_review_manifest")
    data = _read_json(path, "owner-review evidence manifest")
    if not isinstance(data, dict) or data.get("schema_version") != EVIDENCE_SCHEMA:
        raise ValueError(f"owner_review_manifest must use schema_version {EVIDENCE_SCHEMA!r}")
    documents = data.get("documents")
    if not isinstance(documents, list) or not documents:
        raise ValueError("owner_review_manifest must contain a non-empty documents array")
    findings = check_status_freshness(root, path, head)
    unexpected = [finding for finding in findings if finding.code != "STATUS_STALE"]
    if unexpected:
        detail = "; ".join(f"{finding.code}: {finding.message}" for finding in unexpected)
        raise ValueError(f"owner_review_manifest is not derivable: {detail}")
    records = []
    for index, record in enumerate(documents):
        label = f"owner_review_manifest.documents[{index}]"
        if not isinstance(record, dict):
            raise ValueError(f"{label} must be an object")
        document = _existing_file(root, record.get("document"), f"{label}.document")
        revision = _nonempty(record.get("evidence_revision"), f"{label}.evidence_revision")
        evidence_date = _nonempty(record.get("evidence_date"), f"{label}.evidence_date")
        records.append(
            {
                "document": _repo_relative(root, document),
                "link": Path(document.name).as_posix(),
                "revision": revision,
                "short": revision[:7],
                "evidence_date": evidence_date,
                "findings": [finding for finding in findings if finding.file == _repo_relative(root, document)],
            }
        )
    return records, findings, path


def _historical(root: Path, values: Any, page_path: Path) -> list[dict[str, str]]:
    if not isinstance(values, list) or not values:
        raise ValueError("historical_snapshots must be a non-empty array")
    records = []
    for index, row in enumerate(values):
        label = f"historical_snapshots[{index}]"
        if not isinstance(row, dict):
            raise ValueError(f"{label} must be an object")
        path = _existing_file(root, row.get("path"), f"{label}.path")
        records.append(
            {
                "label": _nonempty(row.get("label"), f"{label}.label"),
                "path": _repo_relative(root, path),
                "link": _relative_link(page_path, path),
            }
        )
    return records


def _evidence_links(root: Path, values: Any, page_path: Path) -> list[dict[str, str]]:
    if not isinstance(values, list) or not values:
        raise ValueError("evidence_links must be a non-empty array")
    links = []
    for index, value in enumerate(values):
        target = _existing_file(root, value, f"evidence_links[{index}]")
        links.append({"path": _repo_relative(root, target), "link": _relative_link(page_path, target)})
    return links


def _freshness_sources(root: Path, values: Any) -> list[str]:
    if not isinstance(values, list) or not values:
        raise ValueError("freshness_source_paths must be a non-empty array")
    sources = []
    for index, value in enumerate(values):
        path = _existing_file(root, value, f"freshness_source_paths[{index}]")
        sources.append(_repo_relative(root, path))
    return sources


def _link_list(links: list[dict[str, str]]) -> str:
    return ", ".join(f"[{Path(item['path']).name}]({item['link']})" for item in links)


def _render_page(
    root: Path,
    page_path: Path,
    manifest_path: Path,
    inputs_path: Path,
    owner_manifest_path: Path,
    generated: Generated,
) -> str:
    observation = generated.observation
    registry = generated.registry
    run = generated.run
    manifest_link = _relative_link(page_path, manifest_path)
    inputs_link = _relative_link(page_path, inputs_path)
    generator_link = _relative_link(page_path, root / "scripts" / "generate_status_evidence.py")
    status_path = root / generated.owner_records[0]["document"]
    status_link = _relative_link(page_path, status_path)
    handoff_link = _relative_link(page_path, owner_manifest_path)

    counts = registry["counts"]
    count_text = ", ".join(f"{counts.get(key, 0)} {key}" for key in ("supported", "experimental", "deprecated", "archived"))
    if run["state"] == "RECORDED":
        run_value = (
            f"{run['run_id']} at {run['head_short']}, terminal {run['terminal_state']}, "
            f"coverage {run['coverage_state']}"
        )
        run_evidence = f"[run summary]({run['link']})"
        run_date = run["evidence_date"]
    else:
        run_value = f"NOT RECORDED — {run['reason']}"
        run_evidence = f"[run summary schema]({run['schema_link']})"
        run_date = "not applicable"

    owner_stale = any(finding.code == "STATUS_STALE" for finding in generated.owner_findings)
    owner_value = "STALE — not refreshed by this block" if owner_stale else "NO FINDINGS — still not an owner review"
    owner_links = f"[STATUS.md]({status_link}), [handoff manifest]({handoff_link})"
    decision_dates = sorted({row["decision_date"] for row in generated.decisions})
    decision_date_text = " / ".join(decision_dates)
    publication_value = "; ".join(f"{row['route']}: {row['state']}" for row in generated.decisions)

    lines = [
        "<!-- Generated status evidence. Edit scripts/status-evidence.inputs.v1.json and regenerate. Do not edit by hand. -->",
        "# Status evidence — generated from repository artifacts",
        "",
        "> **Derived evidence, not an owner review.** This page is generated from checked-in",
        "> artifacts at the observation revision. It does **not** refresh",
        f"> [STATUS.md]({status_link}) or promote a `REPORTED` record into an observed fact.",
        "> Evidence dates below are the dates the cited evidence was produced or recorded,",
        "> not the date this page was generated or edited.",
        "",
        STATUS_SECTION,
        "",
        "| Field | Value | Evidence | Evidence date |",
        "|---|---|---|---|",
        f"| Current evidence revision | {observation['short']} (full SHA in the evidence manifest) | [evidence manifest]({manifest_link}) | {observation['date']} |",
        f"| Last verified run | {run_value} | {run_evidence} | {run_date} |",
        f"| Contract set | {registry['version']}: {count_text} | [contract registry]({registry['link']}) | {registry['evidence_date']} |",
        f"| Publication decision | {publication_value} | [publication decisions](#publication-decisions) | {decision_date_text} |",
        f"| Status owner review | {owner_value} | {owner_links} | {generated.owner_records[0]['evidence_date']} |",
        f"| Evidence date | {observation['date']} (observation revision commit date; not this page's edit date) | [evidence manifest]({manifest_link}) | {observation['date']} |",
        "",
        "## Publication decisions",
        "",
        "Retained decision records. `REPORTED` means recorded by a dated document and not",
        "re-observed for this block; `UNKNOWN` means no retained evidence establishes the",
        "state. This block does not authorize publication.",
        "",
        "| Route | State | Decision | Evidence class | Decision date | Evidence |",
        "|---|---|---|---|---|---|",
    ]
    for row in generated.decisions:
        lines.append(
            f"| {row['route']} | {row['state']} | {row['decision']} | {row['evidence_class']} | "
            f"{row['decision_date']} | {_link_list(row['links'])} |"
        )
    lines.extend(
        [
            "",
            "The target-local route is recorded from target-repository documents. No target-side",
            "artifact is retained in this repository, and its current state is not re-observed here.",
            "",
            "## Contract set",
            "",
            f"The registry is [{registry['version']}]({registry['link']}) with {count_text}.",
            "The supported combination below is the registry's declared default surface; it is not",
            "a quality or acceptance claim.",
            "",
            "| Role | Contract | Status | Evidence |",
            "|---|---|---|---|",
        ]
    )
    for item in registry["effective"]:
        lines.append(f"| {item['role']} | {item['name']} | {item['status']} | [registry]({registry['link']}) |")
    lines.extend(
        [
            "",
            DEPRECATED_HEADING,
            "",
            "The registry marks these contracts deprecated. They are not current guidance; each",
            "names its replacement where one exists. Archived contracts remain in the registry.",
            "",
            "| Contract | Status | Replaced by | Evidence |",
            "|---|---|---|---|",
        ]
    )
    for item in registry["deprecated"]:
        lines.append(
            f"| {item['name']} | {item['status']} | {item['replaced_by'] or 'none'} | [registry]({registry['link']}) |"
        )
    lines.extend(
        [
            "",
            "## Status owner-review observation",
            "",
            "The owner-reviewed status page remains a human record. This generated block records",
            "its freshness verdict verbatim and does not rewrite it.",
            "",
            "| Document | Reviewed revision | Evidence date | Checker verdict | Evidence |",
            "|---|---|---|---|---|",
        ]
    )
    for record in generated.owner_records:
        verdict = "STALE" if any(finding.code == "STATUS_STALE" for finding in record["findings"]) else "NO FINDINGS"
        lines.append(
            f"| [{record['document']}]({record['link']}) | {record['short']} | {record['evidence_date']} | "
            f"{verdict} | [handoff manifest]({handoff_link}) |"
        )
    if generated.owner_findings:
        lines.extend(["", "Checker findings:", ""])
        for finding in generated.owner_findings:
            lines.append(f"- {finding.code} ({finding.file}:{finding.line}): {finding.message}")
    else:
        lines.extend(["", "No freshness findings at the checked-out head. This is still derived evidence, not an owner review."])
    lines.extend(
        [
            "",
            "## Historical snapshots (immutable; not current)",
            "",
            "These records are retained unchanged and are not current state. The generator writes",
            "only the status-evidence page and its manifest; it never rewrites historical evidence.",
            "",
            "| Record | Label | Evidence |",
            "|---|---|---|",
        ]
    )
    for record in generated.historical:
        lines.append(f"| [{record['path']}]({record['link']}) | {record['label']} | [record]({record['link']}) |")
    lines.extend(
        [
            "",
            "## Evidence links",
            "",
            f"- [Generator]({generator_link})",
            f"- [Inputs]({inputs_link})",
            f"- [Evidence manifest]({manifest_link})",
        ]
    )
    seen_paths = {
        _repo_relative(root, root / "scripts" / "generate_status_evidence.py"),
        _repo_relative(root, inputs_path),
        _repo_relative(root, manifest_path),
    }
    for link in generated.evidence_links:
        if link["path"] in seen_paths:
            continue
        lines.append(f"- [{link['path']}]({link['link']})")
    lines.extend(
        [
            "",
            "---",
            "",
            f"Generated by [generate_status_evidence.py]({generator_link}) from "
            f"[status-evidence.inputs.v1.json]({inputs_link}). This page is not an owner review;",
            f"owner refresh of [STATUS.md]({status_link}) remains a separate decision.",
            "",
        ]
    )
    return "\n".join(lines)


def _render_manifest(root: Path, page_path: Path, generated: Generated) -> str:
    document = _repo_relative(root, page_path)
    evidence_links = [link["link"] for link in generated.evidence_links]
    payload = {
        "schema_version": EVIDENCE_SCHEMA,
        "documents": [
            {
                "document": document,
                "evidence_revision": generated.observation["full"],
                "evidence_date": generated.observation["date"],
                "source_paths": generated.freshness_sources,
                "evidence_links": evidence_links,
            }
        ],
    }
    return json.dumps(payload, indent=2) + "\n"


def _load_inputs(path: Path) -> dict[str, Any]:
    data = _read_json(path, "status evidence inputs")
    if not isinstance(data, dict) or data.get("schema_version") != INPUTS_SCHEMA:
        raise ValueError(f"status evidence inputs must use schema_version {INPUTS_SCHEMA!r}")
    return data


def build(
    root: Path,
    inputs_path: Path,
    page_path: Path,
    manifest_path: Path,
    head: str = "HEAD",
) -> Generated:
    """Build rendered outputs and evidence data without writing files."""

    root = root.resolve()
    inputs_path = inputs_path.resolve()
    page_path = page_path.resolve()
    manifest_path = manifest_path.resolve()
    if not inputs_path.is_relative_to(root):
        raise ValueError("status evidence inputs must be inside the repository")
    for label, path in (("page", page_path), ("manifest", manifest_path)):
        if not path.is_relative_to(root):
            raise ValueError(f"{label} output must be inside the repository")
    if page_path == (root / "docs" / "STATUS.md").resolve():
        raise ValueError("refusing to write docs/STATUS.md: its owner review is a human record")
    if any(path.is_relative_to((root / "docs" / "history").resolve()) for path in (page_path, manifest_path)):
        raise ValueError("refusing to write historical evidence paths")
    inputs = _load_inputs(inputs_path)
    observation = _commit(root, (inputs.get("observation") or {}).get("revision") if isinstance(inputs.get("observation"), dict) else None)
    registry = _registry(root, inputs.get("contract_registry"), observation, page_path)
    run = _run_evidence(root, inputs.get("last_verified_run"), page_path)
    decisions = _publication_decisions(root, inputs.get("publication_decisions"), page_path)
    owner_records, owner_findings, owner_manifest_path = _owner_records(root, inputs.get("owner_review_manifest"), head)
    historical = _historical(root, inputs.get("historical_snapshots"), page_path)
    evidence_links = _evidence_links(root, inputs.get("evidence_links"), page_path)
    freshness_sources = _freshness_sources(root, inputs.get("freshness_source_paths"))
    generated = Generated(
        page_text="",
        manifest_text="",
        observation=observation,
        registry=registry,
        run=run,
        decisions=decisions,
        owner_records=owner_records,
        owner_findings=owner_findings,
        historical=historical,
        freshness_sources=freshness_sources,
        evidence_links=evidence_links,
    )
    generated = Generated(
        page_text=_render_page(root, page_path, manifest_path, inputs_path, owner_manifest_path, generated),
        manifest_text=_render_manifest(root, page_path, generated),
        observation=generated.observation,
        registry=generated.registry,
        run=generated.run,
        decisions=generated.decisions,
        owner_records=generated.owner_records,
        owner_findings=generated.owner_findings,
        historical=generated.historical,
        freshness_sources=generated.freshness_sources,
        evidence_links=generated.evidence_links,
    )
    return generated


def _contract_ids(root: Path) -> set[str]:
    data = _read_json(root / "scripts" / "documentation-contract-ids.v1.json", "contract identifier list")
    values = data.get("contract_ids") if isinstance(data, dict) else None
    if not isinstance(data, dict) or data.get("schema_version") != CONTRACT_SCHEMA or not isinstance(values, list):
        raise ValueError(f"contract identifier list must use schema_version {CONTRACT_SCHEMA!r}")
    return set(values)


def _validate_markdown(root: Path, markdown: str, page_path: Path) -> list[Finding]:
    findings: list[Finding] = []
    file = _repo_relative(root, page_path)
    if "Derived evidence, not an owner review" not in markdown:
        findings.append(Finding("STATUS_EVIDENCE_DERIVED_BANNER_MISSING", file, 1, "the page must state that it is derived evidence, not an owner review"))
    for match in INLINE_HEX_RE.finditer(markdown):
        findings.append(
            Finding(
                "STATUS_EVIDENCE_INLINE_REVISION",
                file,
                1,
                f"revision token `{match.group(1)}` is inline code; link the evidence manifest or add DT-3 provenance instead",
            )
        )
    lines = markdown.splitlines()
    inside = False
    labels: set[str] = set()
    for number, line in enumerate(lines, 1):
        if line.startswith("## "):
            inside = line.strip() == STATUS_SECTION
            continue
        if not inside or not line.startswith("|") or set(line.replace("|", "").strip()) <= {"-", ":"}:
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if cells and cells[0] == "Field":
            continue
        labels.add(cells[0])
        if not any("](" in cell for cell in cells[1:]):
            findings.append(Finding("STATUS_EVIDENCE_CLAIM_UNLINKED", file, number, f"status row {cells[0]!r} has no artifact or test link"))
    for label in REQUIRED_FIELD_LABELS:
        if label not in labels:
            findings.append(Finding("STATUS_EVIDENCE_FIELD_MISSING", file, 1, f"required status field {label!r} is missing"))
    historical_heading = "## Historical snapshots (immutable; not current)"
    if historical_heading not in markdown:
        findings.append(Finding("STATUS_EVIDENCE_HISTORICAL_UNLABELED", file, 1, "historical snapshots must be labelled immutable and not current"))
    broken = []
    if page_path.is_file():
        _, broken = check_paths(root, [page_path])
    for item in broken:
        findings.append(
            Finding(
                "STATUS_EVIDENCE_BROKEN_LINK",
                file,
                int(item.get("line", 1)),
                f"link does not resolve: {item.get('target')!r}",
            )
        )
    return findings


def check(
    root: Path,
    inputs_path: Path,
    page_path: Path,
    manifest_path: Path,
    head: str = "HEAD",
) -> list[Finding]:
    """Verify checked-in outputs are reproducible, linked, and fresh."""

    root = root.resolve()
    generated = build(root, inputs_path, page_path, manifest_path, head)
    findings: list[Finding] = []
    for label, path, expected in (("page", page_path, generated.page_text), ("manifest", manifest_path, generated.manifest_text)):
        if not path.is_file():
            findings.append(Finding("STATUS_EVIDENCE_MISSING", _repo_relative(root, path), 1, f"generated {label} is missing"))
        elif path.read_text(encoding="utf-8") != expected:
            findings.append(
                Finding(
                    "STATUS_EVIDENCE_OUT_OF_DATE",
                    _repo_relative(root, path),
                    1,
                    f"generated {label} differs from inputs; run python3 scripts/generate_status_evidence.py",
                )
            )
    if page_path.is_file():
        findings += _validate_markdown(root, page_path.read_text(encoding="utf-8"), page_path)
    if page_path.is_file():
        findings += check_claims(root, [page_path])
        findings += check_superseded_contracts(root, [page_path], contract_ids=_contract_ids(root))
    if manifest_path.is_file():
        findings += check_status_freshness(root, manifest_path, head)
    return findings


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=REPO_ROOT)
    parser.add_argument("--inputs", type=Path, default=Path(DEFAULT_INPUTS))
    parser.add_argument("--page", type=Path, default=Path(DEFAULT_PAGE))
    parser.add_argument("--manifest", type=Path, default=Path(DEFAULT_MANIFEST))
    parser.add_argument("--head", default="HEAD")
    parser.add_argument("--check", action="store_true", help="verify checked-in outputs instead of writing")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    root = args.root.resolve()
    inputs = args.inputs if args.inputs.is_absolute() else root / args.inputs
    page = args.page if args.page.is_absolute() else root / args.page
    manifest = args.manifest if args.manifest.is_absolute() else root / args.manifest
    try:
        if args.check:
            findings = check(root, inputs, page, manifest, args.head)
        else:
            generated = build(root, inputs, page, manifest, args.head)
            _write(page, generated.page_text)
            _write(manifest, generated.manifest_text)
            findings = []
    except (OSError, ValueError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2
    if args.json:
        payload = {
            "schema_version": REPORT_SCHEMA,
            "page": _repo_relative(root, page),
            "manifest": _repo_relative(root, manifest),
            "findings": [finding.as_dict() for finding in findings],
        }
        print(json.dumps(payload, indent=2, sort_keys=True))
    elif findings:
        print(f"Status evidence: {len(findings)} finding(s)")
        for finding in findings:
            print(f"  {finding.file}:{finding.line}: [{finding.code}] {finding.message}")
    elif not args.check:
        print(f"Wrote {_repo_relative(root, page)} and {_repo_relative(root, manifest)}")
    else:
        print("Status evidence: generated outputs are reproducible and fresh")
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
