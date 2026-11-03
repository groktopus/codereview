"""Regression tests for DT-3 documentation evidence checks."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import check_docs_truth as truth  # noqa: E402
import check_relative_links as links  # noqa: E402


def write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def git(root: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(root), *args], check=True, text=True, capture_output=True).stdout.strip()


def init_repo(root: Path) -> str:
    git(root, "init", "-q")
    git(root, "config", "user.email", "docs-check@example.invalid")
    git(root, "config", "user.name", "Docs check test")
    write(root / "source.txt", "first\n")
    git(root, "add", "source.txt")
    git(root, "commit", "-qm", "initial")
    return git(root, "rev-parse", "HEAD")


def test_link_checker_covers_root_docs_and_issue_files(tmp_path: Path) -> None:
    write(tmp_path / "README.md", "[ok](docs/issues/record.md)\n")
    write(tmp_path / "docs" / "README.md", "# index\n")
    write(tmp_path / "docs" / "issues" / "record.md", "[bad](missing.md)\n")
    files, broken = links.check_paths(tmp_path, [tmp_path / "README.md", tmp_path / "docs"])
    assert {p.relative_to(tmp_path).as_posix() for p in files} == {
        "README.md",
        "docs/README.md",
        "docs/issues/record.md",
    }
    assert [(item["file"].split("/")[-1], item["target"]) for item in broken] == [("record.md", "missing.md")]


def test_claim_lint_rejects_unqualified_limited_phrases_but_accepts_qualifiers_and_evidence(tmp_path: Path) -> None:
    doc = write(
        tmp_path / "README.md",
        "The harness is production ready.\n"
        "The system replaces reviewers.\n"
        "The system is accurate.\n"
        "The system is not accurate.\n"
        "The harness is not production ready.\n"
        "The harness is production ready ([test evidence](evidence.md)).\n",
    )
    findings = truth.check_claims(tmp_path, [doc])
    assert [finding.code for finding in findings] == ["PRODUCTION_READY", "REPLACES_REVIEWER", "ACCURACY_ASSERTION"]
    assert all(finding.line > 0 and "same-claim evidence link" in finding.message for finding in findings)


def test_claim_lint_does_not_let_compound_negation_waive_positive_claim(tmp_path: Path) -> None:
    doc = write(tmp_path / "README.md", "The harness is production ready, not merely a prototype.\n")
    findings = truth.check_claims(tmp_path, [doc])
    assert [finding.code for finding in findings] == ["PRODUCTION_READY"]


def test_claim_lint_does_not_share_qualifier_or_evidence_across_table_rows(tmp_path: Path) -> None:
    doc = write(
        tmp_path / "README.md",
        "| Claim | Evidence |\n"
        "|---|---|\n"
        "| The harness is production ready. | none |\n"
        "| The harness is not production ready. | [test evidence](test.md) |\n"
        "| The harness is production ready ([unrelated guide](guide.md)). | none |\n"
        "| The harness is production ready ([run evidence](run.json)). | none |\n",
    )
    findings = truth.check_claims(tmp_path, [doc])
    assert [(finding.code, finding.line) for finding in findings] == [("PRODUCTION_READY", 3), ("PRODUCTION_READY", 5)]


def test_claim_lint_rejects_unrelated_link_but_accepts_adjacent_evidence_link(tmp_path: Path) -> None:
    doc = write(
        tmp_path / "README.md",
        "The harness is production ready; see [the user guide](guide.md).\n"
        "The harness is production ready ([test evidence](tests/test_review.py)).\n"
        "The harness is production ready; see [test evidence](artifact.json) for parser coverage.\n"
        "The harness is production ready, see [test evidence](artifact.json).\n"
        "The harness is production ready but [test evidence](artifact.json) is available.\n"
        "[test evidence](artifact.json) supports that the harness is production ready.\n",
    )
    findings = truth.check_claims(tmp_path, [doc])
    assert [(finding.code, finding.line) for finding in findings] == [
        ("PRODUCTION_READY", 1),
        ("PRODUCTION_READY", 3),
        ("PRODUCTION_READY", 4),
        ("PRODUCTION_READY", 5),
        ("PRODUCTION_READY", 6),
    ]


def _sha_manifest(tmp_path: Path, rows: list[dict[str, str]]) -> Path:
    return write(tmp_path / "sha.json", json.dumps({"schema_version": truth.SHA_SCHEMA, "references": rows}))


def commit_ref(
    value: str, evidence: str, repository: str = "groktopus/codereview", scope: str = "local"
) -> dict[str, str]:
    return {"kind": "commit", "value": value, "repository": repository, "scope": scope, "evidence": evidence}


def test_local_existing_and_missing_sha_provenance(tmp_path: Path) -> None:
    head = init_repo(tmp_path)
    doc = write(tmp_path / "README.md", f"Source commit `{head}` and alleged commit `deadbee`.\n")
    manifest = _sha_manifest(
        tmp_path,
        [
            commit_ref(head, "seed existing local revision"),
            commit_ref("deadbee", "seed nonexistent local revision"),
        ],
    )
    findings = truth.check_shas(tmp_path, [doc], manifest)
    assert [finding.code for finding in findings] == ["SHA_NOT_IN_REPOSITORY"]
    assert "deadbee" in findings[0].message


def test_foreign_sha_is_explicitly_attributed_not_checked_locally(tmp_path: Path) -> None:
    doc = write(tmp_path / "README.md", "SlopSearX target commit `deadbee`.\n")
    manifest = _sha_manifest(
        tmp_path, [commit_ref("deadbee", "named target repository", "magnus919/SlopSearX", "foreign-target")]
    )
    assert truth.check_shas(tmp_path, [doc], manifest) == []


def test_unscoped_sha_fails_actionably(tmp_path: Path) -> None:
    doc = write(tmp_path / "README.md", "Revision `deadbee` is cited.\n")
    manifest = _sha_manifest(tmp_path, [])
    findings = truth.check_shas(tmp_path, [doc], manifest)
    assert len(findings) == 1
    assert findings[0].code == "UNSCOPED_SHA"
    assert "repository, scope, and attribution" in findings[0].message


def test_sha_tokens_require_full_hex_token_and_reject_41_character_value(tmp_path: Path) -> None:
    # Existing and digit-only 7-char refs are tokens; malformed full token
    # cannot be accepted by matching a 40-char prefix.
    malformed = "a" * 41
    digest = "b" * 64
    doc = write(
        tmp_path / "README.md",
        f"Existing `abcdef1` and `1234567`; malformed `{malformed}`; digest `{digest}` (SHA-256).\n",
    )
    manifest = _sha_manifest(
        tmp_path,
        [
            {
                "kind": "commit",
                "value": "abcdef1",
                "repository": "magnus919/SlopSearX",
                "scope": "foreign-target",
                "evidence": "seed foreign valid SHA",
            },
            {
                "kind": "commit",
                "value": "1234567",
                "repository": "magnus919/SlopSearX",
                "scope": "foreign-target",
                "evidence": "seed digit-only SHA",
            },
            {
                "kind": "artifact-digest",
                "value": digest,
                "repository": "groktopus/codereview",
                "scope": "external-artifact",
                "evidence": "seed labeled SHA-256 digest",
            },
        ],
    )
    findings = truth.check_shas(tmp_path, [doc], manifest)
    assert [(finding.code, "41 characters" in finding.message) for finding in findings] == [("MALFORMED_SHA", True)]
    # A digest outside explicitly labeled SHA-256 context remains a malformed
    # overlong token; classification requires evidence, not just length.
    unlabeled = write(tmp_path / "unlabeled.md", f"Unlabeled token `{digest}`.\n")
    unlabeled_manifest = _sha_manifest(tmp_path, [])
    unlabeled_findings = truth.check_shas(tmp_path, [unlabeled], unlabeled_manifest)
    assert [finding.code for finding in unlabeled_findings] == ["MALFORMED_SHA"]


def test_commit_manifest_rejects_invalid_repository_scope_pairings(tmp_path: Path) -> None:
    cases = [
        ("groktopus/codereview", "external-artifact"),
        ("groktopus/codereview", "foreign-target"),
        ("magnus919/SlopSearX", "local"),
    ]
    for repository, scope in cases:
        manifest = write(
            tmp_path / f"invalid-{repository.split('/')[-1]}-{scope}.json",
            json.dumps(
                {
                    "schema_version": truth.SHA_SCHEMA,
                    "references": [commit_ref("deadbee", "seed invalid pairing", repository, scope)],
                }
            ),
        )
        with pytest.raises(ValueError, match="invalid commit repository/scope pairing"):
            truth._sha_reference_records(manifest)


def test_sha_manifest_rejects_invalid_kind_or_malformed_typed_value(tmp_path: Path) -> None:
    invalid_kind = write(
        tmp_path / "invalid-kind.json",
        json.dumps(
            {
                "schema_version": truth.SHA_SCHEMA,
                "references": [
                    {
                        "kind": "unknown",
                        "value": "deadbee",
                        "repository": "groktopus/codereview",
                        "scope": "local",
                        "evidence": "seed",
                    }
                ],
            }
        ),
    )
    with pytest.raises(ValueError, match="kind must be commit, run-id, or artifact-digest"):
        truth._sha_reference_records(invalid_kind)
    invalid_run = write(
        tmp_path / "invalid-run.json",
        json.dumps(
            {
                "schema_version": truth.SHA_SCHEMA,
                "references": [
                    {
                        "kind": "run-id",
                        "value": "123",
                        "repository": "groktopus/codereview",
                        "scope": "local",
                        "evidence": "seed",
                    }
                ],
            }
        ),
    )
    with pytest.raises(ValueError, match="7-12 decimal digits"):
        truth._sha_reference_records(invalid_run)


def test_run_id_classification_supports_run_a_run_id_and_actions_run_hash_context(tmp_path: Path) -> None:
    tokens = ["36300000001", "36300000002", "36300000003"]
    doc = write(
        tmp_path / "README.md",
        f"Run A `{tokens[0]}` completed.\nRun ID `{tokens[1]}` retained.\nActions run #{tokens[2]} completed.\n",
    )
    manifest = _sha_manifest(
        tmp_path,
        [
            {
                "kind": "run-id",
                "value": token,
                "repository": "groktopus/codereview",
                "scope": "local",
                "evidence": "seed run ID",
            }
            for token in tokens
        ],
    )
    assert truth.check_shas(tmp_path, [doc], manifest) == []


def test_status_freshness_rejects_stale_evidence_revision(tmp_path: Path) -> None:
    old = init_repo(tmp_path)
    write(tmp_path / "source.txt", "second\n")
    git(tmp_path, "add", "source.txt")
    git(tmp_path, "commit", "-qm", "changed source after evidence")
    latest = git(tmp_path, "rev-parse", "HEAD")
    doc = write(tmp_path / "docs" / "STATUS.md", f"Reviewed at `{old}`.\n")
    manifest = write(
        tmp_path / "freshness.json",
        json.dumps(
            {
                "schema_version": truth.TRUTH_SCHEMA,
                "documents": [
                    {
                        "document": "docs/STATUS.md",
                        "evidence_revision": old,
                        "evidence_date": "2026-11-01",
                        "source_paths": ["source.txt"],
                        "evidence_links": ["../source.txt"],
                    }
                ],
            }
        ),
    )
    findings = truth.check_status_freshness(tmp_path, manifest)
    assert [(finding.code, finding.file) for finding in findings] == [("STATUS_STALE", "docs/STATUS.md")]
    assert latest[:12] in findings[0].message
    assert doc.exists()


def test_status_freshness_accepts_current_evidence(tmp_path: Path) -> None:
    head = init_repo(tmp_path)
    write(tmp_path / "docs" / "STATUS.md", f"Reviewed at `{head}`.\n")
    manifest = write(
        tmp_path / "freshness.json",
        json.dumps(
            {
                "schema_version": truth.TRUTH_SCHEMA,
                "documents": [
                    {
                        "document": "docs/STATUS.md",
                        "evidence_revision": head,
                        "evidence_date": "2026-11-01",
                        "source_paths": ["source.txt"],
                        "evidence_links": ["../source.txt"],
                    }
                ],
            }
        ),
    )
    assert truth.check_status_freshness(tmp_path, manifest) == []


def test_freshness_rejects_invalid_manifest_fields(tmp_path: Path) -> None:
    init_repo(tmp_path)
    manifest = write(tmp_path / "freshness.json", json.dumps({"schema_version": truth.TRUTH_SCHEMA, "documents": [{}]}))
    findings = truth.check_status_freshness(tmp_path, manifest)
    assert len(findings) == 1 and findings[0].code == "FRESHNESS_RECORD_INVALID"
    assert "evidence_revision must be an existing full" in findings[0].message


def test_superseded_contract_requires_visible_deprecation_label(tmp_path: Path) -> None:
    init_repo(tmp_path)
    doc = write(tmp_path / "README.md", "Use `legacy-v14` for this route.\n")
    registry = write(
        tmp_path / "registry.json", json.dumps({"contracts": [{"name": "legacy-v14", "status": "deprecated"}]})
    )
    findings = truth.check_superseded_contracts(tmp_path, [doc], registry)
    assert len(findings) == 1 and findings[0].code == "SUPERSEDED_CONTRACT_UNMARKED"
    write(doc, "Use deprecated `legacy-v14` for this route.\n")
    assert truth.check_superseded_contracts(tmp_path, [doc], registry) == []


def test_seeded_issue_failures_have_actionable_findings(tmp_path: Path) -> None:
    fixture = ROOT / "tests" / "fixtures" / "docs_truth"
    _, broken = links.check_paths(tmp_path, [fixture / "seeded-bad-link.md"])
    assert len(broken) == 1 and "not-present.md" in broken[0]["target"]
    claim = truth.check_claims(ROOT, [fixture / "seeded-unqualified-claim.md"])
    assert [finding.code for finding in claim] == ["PRODUCTION_READY"]
    sha_manifest = _sha_manifest(tmp_path, [commit_ref("deadbeef", "seeded missing object")])
    sha_doc = write(tmp_path / "sha.md", (fixture / "seeded-missing-sha.md").read_text(encoding="utf-8"))
    assert [finding.code for finding in truth.check_shas(tmp_path, [sha_doc], sha_manifest)] == [
        "SHA_NOT_IN_REPOSITORY"
    ]
    registry = write(
        tmp_path / "registry.json",
        json.dumps({"contracts": [{"name": "ordinary-review-limits-v2", "status": "deprecated"}]}),
    )
    contract_doc = write(
        tmp_path / "contract.md", (fixture / "seeded-superseded-contract.md").read_text(encoding="utf-8")
    )
    assert [finding.code for finding in truth.check_superseded_contracts(tmp_path, [contract_doc], registry)] == [
        "SUPERSEDED_CONTRACT_UNMARKED"
    ]


def test_ci_freshness_fixture_is_explicitly_stale() -> None:
    findings = truth.check_status_freshness(ROOT, ROOT / "tests/fixtures/docs_truth/freshness-stale.json")
    assert [finding.code for finding in findings] == ["STATUS_STALE"]
    assert truth.check_status_freshness(ROOT, ROOT / "tests/fixtures/docs_truth/freshness-current.json") == []


def test_checked_in_status_handoff_manifest_is_current_after_vd4_observation_refresh() -> None:
    findings = truth.check_status_freshness(ROOT, ROOT / "scripts/documentation-truth-evidence.v1.json")
    assert findings == []


def test_cli_main_rejects_combined_seeded_documentation_violations(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    init_repo(tmp_path)
    write(tmp_path / "README.md", "# Root\n")
    write(tmp_path / "docs" / "README.md", "# Index\n\n## Current\n\n[Status](STATUS.md)\n")
    write(
        tmp_path / "docs" / "STATUS.md",
        "The harness is production ready.\n"
        "Missing local revision `deadbeef`.\n"
        "Configured contract `ordinary-review-limits-v2`.\n"
        "[broken link](missing-target.md)\n",
    )
    write(
        tmp_path / "src" / "pr_review_harness" / "contract_registry.json",
        json.dumps({"contracts": [{"name": "ordinary-review-limits-v2", "status": "deprecated"}]}),
    )
    sha_manifest = _sha_manifest(
        tmp_path,
        [commit_ref("deadbeef", "seeded nonexistent local commit")],
    )
    contract_ids = write(
        tmp_path / "scripts" / "contract-ids.json",
        json.dumps({"schema_version": truth.CONTRACT_SCHEMA, "contract_ids": ["ordinary-review-limits-v2"]}),
    )

    truth_status = truth.main(
        [
            "--root",
            str(tmp_path),
            "--sha-manifest",
            str(sha_manifest),
            "--contract-ids",
            str(contract_ids),
            "--document",
            "docs/STATUS.md",
            "--json",
        ]
    )
    truth_report = json.loads(capsys.readouterr().out)
    codes = {finding["code"] for finding in truth_report["findings"]}
    assert truth_status == 1
    assert {"PRODUCTION_READY", "SHA_NOT_IN_REPOSITORY", "SUPERSEDED_CONTRACT_UNMARKED"} <= codes

    link_status = links.main(["--root", str(tmp_path), "README.md", "docs"])
    link_output = capsys.readouterr().out
    assert link_status == 1
    assert "docs/STATUS.md:4" in link_output and "missing-target.md" in link_output


def test_cli_exits_nonzero_on_seeded_status_freshness_failure(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    old = init_repo(tmp_path)
    write(tmp_path / "source.txt", "changed\n")
    git(tmp_path, "add", "source.txt")
    git(tmp_path, "commit", "-qm", "new source")
    write(tmp_path / "docs" / "README.md", "# Index\n\n## Current\n\n[Status](STATUS.md)\n")
    write(tmp_path / "README.md", "# Root\n")
    write(tmp_path / "docs" / "STATUS.md", f"Evidence `{old}`.\n")
    write(
        tmp_path / "scripts" / "sha.json",
        json.dumps({"schema_version": truth.SHA_SCHEMA, "references": [commit_ref(old, "seed")]}),
    )
    write(
        tmp_path / "scripts" / "contract-ids.json",
        json.dumps({"schema_version": truth.CONTRACT_SCHEMA, "contract_ids": []}),
    )
    write(
        tmp_path / "freshness.json",
        json.dumps(
            {
                "schema_version": truth.TRUTH_SCHEMA,
                "documents": [
                    {
                        "document": "docs/STATUS.md",
                        "evidence_revision": old,
                        "evidence_date": "2026-11-01",
                        "source_paths": ["source.txt"],
                        "evidence_links": ["../source.txt"],
                    }
                ],
            }
        ),
    )
    status = truth.main(
        [
            "--root",
            str(tmp_path),
            "--freshness-manifest",
            "freshness.json",
            "--sha-manifest",
            "scripts/sha.json",
            "--contract-ids",
            "scripts/contract-ids.json",
        ]
    )
    assert status == 1 and "STATUS_STALE" in capsys.readouterr().out
