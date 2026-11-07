"""Generate VD-2's bounded acceptance index from existing scenario metadata.

This module does not replay or duplicate fault scenarios. The referenced tests
own the behavioral assertions; collection verifies that their exact IDs exist.
"""

from __future__ import annotations

import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

import test_actions_publication as actions
import test_publication_effect_fault_matrix as publication
import test_vd2_provider_faults as providers

ROOT = Path(__file__).resolve().parents[1]
START = "<!-- BEGIN GENERATED VD2 FAULT ACCEPTANCE -->"
END = "<!-- END GENERATED VD2 FAULT ACCEPTANCE -->"
PROVIDER_TEST = "test_provider_transport_fault_matrix_is_typed_and_makes_one_request"
PUBLICATION_TEST = "test_se4_publication_effect_fault_matrix"
GITHUB_TEST = "test_stateless_publication_end_to_end_admits_bundle_persists_receipt_then_posts_once"
REDIRECT_TEST = "test_artifact_redirect_uses_https_allowlist_and_download_never_receives_api_token"


@dataclass(frozen=True)
class AcceptanceRow:
    case_id: str
    node_id: str
    layer: str
    terminal: str
    reason: str | None
    settlement: str
    posts: str
    receipts: str


def acceptance_rows() -> tuple[AcceptanceRow, ...]:
    """Project the contracts actually consumed by the existing scenario tests."""
    common = providers.FAULT_ACCEPTANCE
    rows = [
        AcceptanceRow(
            case_id=case[0],
            node_id=f"tests/test_vd2_provider_faults.py::{PROVIDER_TEST}[{case[0]}]",
            layer="run_review + loopback HTTP",
            terminal=f"task {common['task_status']}; result {common['disposition']}",
            reason=case[4],
            settlement=common["settlement_status"],
            posts=f"{common['provider_posts']} provider; {common['publication_posts']} publication",
            receipts="not exercised",
        )
        for case in providers.FAULT_CASES
    ]
    rows.extend(
        AcceptanceRow(
            case_id=case.case_id,
            node_id=f"tests/test_publication_effect_fault_matrix.py::{PUBLICATION_TEST}[{case.case_id}]",
            layer="stateless publisher / injected capabilities",
            terminal=case.terminal,
            reason=case.reason,
            settlement="not exercised",
            posts=f"{case.posts} review",
            receipts=str(case.receipts),
        )
        for case in publication.FAULT_MATRIX
    )
    for failure, contract in actions.GITHUB_FAULT_ACCEPTANCE.items():
        parameter_id = "github_rate_limit" if failure == "github_rate_limit" else f"{failure}-{contract['status']}"
        rows.append(
            AcceptanceRow(
                case_id=f"VD2-GITHUB-{'429' if failure == 'github_rate_limit' else '503'}",
                node_id=f"tests/test_actions_publication.py::{GITHUB_TEST}[{parameter_id}]",
                layer="stateless publisher + fake GitHub adapter transport",
                terminal=contract["status"],
                reason=contract["reason"],
                settlement="not exercised",
                posts=f"{contract['posts']} review",
                receipts=str(contract["receipts"]),
            )
        )
    rows.append(
        AcceptanceRow(
            case_id="VD2-GITHUB-REDIRECT",
            node_id=f"tests/test_actions_publication.py::{REDIRECT_TEST}",
            layer="artifact download adapter only",
            terminal="not asserted (exception then allowed download)",
            reason="artifact_download_location_untrusted",
            settlement="not exercised",
            posts="not asserted",
            receipts="not asserted",
        )
    )
    return tuple(rows)


def acceptance_table() -> str:
    lines = [
        START,
        "| Case ID / existing pytest ID | Asserted layer | Terminal state | Reason | Settlement | POSTs | Receipt writes |",
        "|---|---|---|---|---|---|---|",
    ]
    for row in acceptance_rows():
        filename, test_id = row.node_id.split("::", 1)
        evidence = f"{row.case_id}<br>[`{test_id}`](../../{filename})"
        reason = f"`{row.reason}`" if row.reason is not None else "none"
        lines.append(
            f"| {evidence} | {row.layer} | {row.terminal} | {reason} | "
            f"{row.settlement} | {row.posts} | {row.receipts} |"
        )
    lines.append(END)
    return "\n".join(lines)


def test_acceptance_table_matches_existing_evidence_note() -> None:
    document = (ROOT / "docs/issues/vd2-test-evidence.md").read_text(encoding="utf-8")
    assert document.count(START) == document.count(END) == 1
    actual = document[document.index(START) : document.index(END) + len(END)]
    assert actual == acceptance_table(), (
        "Regenerate the bounded table with acceptance_table(); do not edit rows by hand"
    )


def test_acceptance_index_preserves_required_cases_and_exact_pytest_ids() -> None:
    rows = acceptance_rows()
    case_ids = [row.case_id for row in rows]
    assert len(case_ids) == len(set(case_ids)) == 18
    assert {row[0] for row in providers.FAULT_CASES} == {
        "VD2-PROVIDER-TIMEOUT",
        "VD2-PROVIDER-4XX",
        "VD2-PROVIDER-5XX",
        "VD2-PROVIDER-MALFORMED",
        "VD2-PROVIDER-TRUNCATED",
        "VD2-PROVIDER-DUPLICATE",
    }
    assert {case.case_id for case in publication.FAULT_MATRIX} == {f"SE4-FM-{index:02d}" for index in range(1, 10)}
    assert set(actions.GITHUB_FAULT_ACCEPTANCE) == {"github_rate_limit", "lost_post_history_unknown"}
    files = sorted({row.node_id.split("::", 1)[0] for row in rows})
    collected = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q", *files],
        cwd=ROOT,
        env=os.environ | {"PYTHONPATH": str(ROOT / "src")},
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert collected.returncode == 0, collected.stdout + collected.stderr
    node_ids = set(collected.stdout.splitlines())
    assert {row.node_id for row in rows} <= node_ids
