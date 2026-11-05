"""Contract and engine tests for bounded evidence waivers."""

from __future__ import annotations

import copy
import hashlib
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from test_engine import LIMITS, EmptyProvider, make_snapshot, profile
from waiver_providers import PartialFindingProvider, PartialProvider, QuarantinedCoverageProvider

from pr_review_harness.completeness import build_completeness_summary
from pr_review_harness.engine import EnginePreflightError, _reduce, run_review
from pr_review_harness.planner import plan_review
from pr_review_harness.report import render_report
from pr_review_harness.waiver import WaiverError, apply_waivers, load_waiver, validate_waiver_targets

NOW = datetime.now(timezone.utc).replace(microsecond=0)
LATER = NOW + timedelta(days=31)


def waiver_document(target, *, base_sha="b" * 40, head_sha="c" * 40, repository="owner/repo"):
    return {
        "schema": "review-evidence-waiver.v1",
        "reviewer": "owner/reviewer",
        "reason": "Owner-approved exception for a specific unavailable evidence source.",
        "repository": repository,
        "base_sha": base_sha,
        "head_sha": head_sha,
        "issued_at": (NOW - timedelta(hours=1)).isoformat(),
        "expires_at": (NOW + timedelta(days=30)).isoformat(),
        "waivers": [target],
    }


def target_for(obligation_id, *, kind="coverage_note"):
    return {
        "kind": kind,
        "id": obligation_id,
        "justification": "The named evidence source is unavailable outside this review boundary.",
    }


def write_waiver(tmp_path: Path, document: dict) -> Path:
    path = tmp_path / "waiver.json"
    path.write_text(json.dumps(document, sort_keys=True), encoding="utf-8")
    return path


def snapshot_with_repository(units=1):
    snapshot = make_snapshot(units)
    snapshot["repository"] = "owner/repo"
    return snapshot


def plan_for(snapshot):
    return plan_review(snapshot, profile(), "AUTO")


def run(tmp_path: Path, run_id: str, provider, *, waiver_path=None, plan=None, snapshot=None, resume=False):
    snapshot = snapshot if snapshot is not None else snapshot_with_repository()
    plan = plan if plan is not None else plan_for(snapshot)
    return run_review(
        snapshot,
        plan,
        profile(),
        provider,
        None,
        LIMITS,
        str(tmp_path),
        run_id,
        resume=resume,
        waiver_path=waiver_path,
    )


def execution_target(*, obligation_id=None, reason_code=None):
    target = {
        "kind": "execution_failure",
        "justification": "The obligation is incomplete only because execution failed; evidence is not missing.",
    }
    if obligation_id is not None:
        target["id"] = obligation_id
    if reason_code is not None:
        target["reason_code"] = reason_code
    return target


def run_execution_waiver(tmp_path: Path, run_id: str, target: dict):
    snapshot = snapshot_with_repository()
    snapshot["pull_request_number"] = 7
    plan = plan_for(snapshot)
    path = write_waiver(tmp_path, waiver_document(target))
    result = run(
        tmp_path,
        run_id,
        QuarantinedCoverageProvider(),
        waiver_path=str(path),
        plan=plan,
        snapshot=snapshot,
    )
    return result, plan


def test_valid_waiver_resolves_exact_gap_and_stays_visible(tmp_path):
    snapshot = snapshot_with_repository()
    plan = plan_for(snapshot)
    obligation_id = plan["coverage_obligations"][0]["obligation_id"]
    document = waiver_document(target_for(obligation_id))
    path = write_waiver(tmp_path, document)

    result = run(tmp_path, "waiver-valid", PartialProvider(), waiver_path=str(path), plan=plan, snapshot=snapshot)
    row = result["coverage_ledger"][0]
    summary = result["completeness_summary"]

    assert row["state"] == "WAIVED"
    assert row["waived_from_state"] == "PARTIAL"
    assert row["waived_from_reason_code"] == "PARTIAL_REVIEW_COVERAGE"
    assert row["waiver"]["reviewer"] == "owner/reviewer"
    assert row["waiver"]["waiver_id"].startswith("wvr-")
    assert summary["waived"] == 1
    assert summary["complete"] == 0
    assert summary["waived_obligations"][0]["obligation_id"] == obligation_id
    assert result["coverage_state"] == "COMPLETE_WITH_WAIVERS"
    assert result["disposition"] == "COMMENT"
    applied = result["waivers_applied"][0]
    assert applied["target"]["id"] == obligation_id
    assert applied["reviewer"] == "owner/reviewer"
    assert applied["reason"] == document["reason"]
    assert applied["expires_at"] == document["expires_at"]
    assert applied["source_sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
    assert result["waiver_receipt"]["source_sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
    assert result["waiver_receipt"]["waived_obligation_count"] == 1
    rendered = render_report(result)
    assert "1 waived" in rendered
    assert f"WAIVED {obligation_id}" in rendered


def test_no_waiver_keeps_the_same_gap_incomplete(tmp_path):
    result = run(tmp_path, "waiver-default-deny", PartialProvider())

    assert result["coverage_ledger"][0]["state"] == "PARTIAL"
    assert result["completeness_summary"]["waived"] == 0
    assert result["coverage_state"] != "COMPLETE"
    assert result["disposition"] == "INCOMPLETE"
    assert result["waivers_applied"] == []
    assert result["waiver_receipt"] is None


def test_waiver_cannot_clear_a_finding_or_existing_blocker(tmp_path):
    snapshot = snapshot_with_repository()
    plan = plan_for(snapshot)
    obligation_id = plan["coverage_obligations"][0]["obligation_id"]
    path = write_waiver(tmp_path, waiver_document(target_for(obligation_id)))

    result = run(
        tmp_path,
        "waiver-findings",
        PartialFindingProvider(),
        waiver_path=str(path),
        plan=plan,
        snapshot=snapshot,
    )

    assert result["coverage_ledger"][0]["state"] == "WAIVED"
    assert result["findings"]
    assert any(item.get("blocking_class") == "BLOCKING" for item in result["findings"])
    assert result["disposition"] == "REQUEST_CHANGES"


def test_reason_code_target_is_scoped_to_its_kind_and_exact_reason():
    row = {
        "obligation_id": "unit:u0:lens:correctness",
        "obligation_kind": "CHANGED_UNIT_LENS",
        "required": True,
        "state": "PARTIAL",
        "reason_code": "PARTIAL_REVIEW_COVERAGE",
    }
    document = waiver_document(
        {
            "kind": "coverage_note",
            "reason_code": "SPECIALIST_COVERAGE_PARTIAL",
            "justification": "The partial static note is the exact documented gap.",
        }
    )
    document["source_sha256"] = "a" * 64
    applied, unapplied = apply_waivers([row], document, now=NOW)

    assert not unapplied
    assert applied[0]["target"]["reason_code"] == "SPECIALIST_COVERAGE_PARTIAL"
    assert row["state"] == "WAIVED"


def test_execution_failure_id_waiver_records_the_exact_obligation_and_preserves_audit(tmp_path):
    snapshot = snapshot_with_repository()
    plan = plan_for(snapshot)
    obligation_id = plan["coverage_obligations"][0]["obligation_id"]
    result, _ = run_execution_waiver(tmp_path, "waiver-execution-id", execution_target(obligation_id=obligation_id))
    row = result["coverage_ledger"][0]
    summary = result["completeness_summary"]

    assert row["state"] == "WAIVED"
    assert row["waived_from_state"] == "PARTIAL"
    assert row["waived_from_reason_code"] == "REQUIRED_OUTPUT_QUARANTINED"
    assert row["waiver"]["target"] == execution_target(obligation_id=obligation_id)
    assert summary["waived"] == 1
    assert summary["complete"] == 0
    assert summary["complete_ratio"] == 0.0
    assert summary["resolved_ratio"] == 1.0
    assert summary["waived_obligations"][0]["obligation_id"] == obligation_id
    assert result["coverage_state"] == "COMPLETE_WITH_WAIVERS"
    assert result["disposition"] == "COMMENT"
    assert "reason_code" not in result["waivers_applied"][0]["target"]
    assert result["waiver_receipt"]["applied_count"] == 1
    assert result["waiver_receipt"]["waived_obligation_count"] == 1
    rendered = render_report(result)
    assert "1 waived" in rendered
    assert f"WAIVED {obligation_id}: execution\\_failure {obligation_id}" in rendered


def test_execution_failure_reason_waiver_targets_one_exact_reported_reason(tmp_path):
    result, _ = run_execution_waiver(
        tmp_path,
        "waiver-execution-reason",
        execution_target(reason_code="REQUIRED_OUTPUT_QUARANTINED"),
    )
    row = result["coverage_ledger"][0]

    assert row["state"] == "WAIVED"
    assert row["waived_from_reason_code"] == "REQUIRED_OUTPUT_QUARANTINED"
    assert result["waivers_applied"][0]["target"] == execution_target(reason_code="REQUIRED_OUTPUT_QUARANTINED")
    assert result["coverage_state"] == "COMPLETE_WITH_WAIVERS"
    assert result["disposition"] == "COMMENT"


def test_execution_failure_id_waiver_does_not_apply_to_a_missing_evidence_reason():
    row = {
        "obligation_id": "unit:u0:lens:correctness",
        "obligation_kind": "CHANGED_UNIT_LENS",
        "required": True,
        "state": "PARTIAL",
        "reason_code": "PARTIAL_REVIEW_COVERAGE",
    }
    document = waiver_document(execution_target(obligation_id="unit:u0:lens:correctness"))
    document["source_sha256"] = "a" * 64
    applied, unapplied = apply_waivers([row], document, now=NOW)

    assert applied == []
    assert unapplied[0]["status"] == "NO_MATCHING_INCOMPLETE_OBLIGATION"
    assert row["state"] == "PARTIAL"


def test_execution_failure_reason_waiver_does_not_match_a_different_family():
    row = {
        "obligation_id": "unit:u0:lens:correctness",
        "obligation_kind": "CHANGED_UNIT_LENS",
        "required": True,
        "state": "PARTIAL",
        "reason_code": "REQUIRED_OUTPUT_QUARANTINED",
    }
    document = waiver_document(execution_target(reason_code="CONTEXT_EVIDENCE_TRUNCATED"))
    document["source_sha256"] = "a" * 64
    applied, unapplied = apply_waivers([row], document, now=NOW)

    assert applied == []
    assert unapplied[0]["status"] == "NO_MATCHING_INCOMPLETE_OBLIGATION"
    assert row["state"] == "PARTIAL"


@pytest.mark.parametrize(
    ("kind", "reason_code", "message"),
    [
        ("check", "REQUIRED_OUTPUT_QUARANTINED", "outside its target kind"),
        ("execution_failure", "CHECK_EVIDENCE_UNAVAILABLE", "not allowlisted"),
        ("execution_failure", "TASK_FAILED", "not allowlisted"),
        ("execution_failure", "PARTIAL_REVIEW_COVERAGE", "not allowlisted"),
    ],
)
def test_execution_failure_target_rejects_wrong_kind_and_nonallowlisted_reason(tmp_path, kind, reason_code, message):
    target = {
        "kind": kind,
        "reason_code": reason_code,
        "justification": "The named reason is asserted as the exact accepted failure.",
    }
    with pytest.raises(WaiverError, match=message):
        load_waiver(
            str(write_waiver(tmp_path, waiver_document(target))),
            repository="owner/repo",
            base_sha="b" * 40,
            head_sha="c" * 40,
            now=NOW,
        )


def test_execution_failure_id_and_reason_targets_overlap_the_same_obligation():
    snapshot = snapshot_with_repository()
    plan = plan_for(snapshot)
    obligation_id = plan["coverage_obligations"][0]["obligation_id"]
    plan["coverage_obligations"][0]["reason_code"] = "REQUIRED_OUTPUT_QUARANTINED"
    document = waiver_document(execution_target(obligation_id=obligation_id))
    document["waivers"].append(execution_target(reason_code="REQUIRED_OUTPUT_QUARANTINED"))

    with pytest.raises(WaiverError, match="overlaps"):
        validate_waiver_targets(document, plan)

    row = {
        "obligation_id": obligation_id,
        "obligation_kind": "CHANGED_UNIT_LENS",
        "required": True,
        "state": "PARTIAL",
        "reason_code": "REQUIRED_OUTPUT_QUARANTINED",
    }
    document["source_sha256"] = "a" * 64
    with pytest.raises(WaiverError, match="overlaps"):
        apply_waivers([row], document, now=NOW)
    assert row["state"] == "PARTIAL"


def test_execution_failure_waiver_expired_at_use_is_never_applied(tmp_path):
    document = waiver_document(execution_target(reason_code="DEADLINE_EXHAUSTED"))
    loaded = load_waiver(
        str(write_waiver(tmp_path, document)),
        repository="owner/repo",
        base_sha="b" * 40,
        head_sha="c" * 40,
        now=NOW,
    )
    row = {
        "obligation_id": "unit:u0:lens:correctness",
        "obligation_kind": "CHANGED_UNIT_LENS",
        "required": True,
        "state": "PARTIAL",
        "reason_code": "DEADLINE_EXHAUSTED",
    }
    applied, unapplied = apply_waivers([row], loaded, now=LATER)

    assert applied == []
    assert unapplied[0]["status"] == "EXPIRED_AT_USE"
    assert row["state"] == "PARTIAL"


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("head_sha", "d" * 40, "revision"),
        ("base_sha", "d" * 40, "revision"),
        ("repository", "other/repository", "repository"),
    ],
)
def test_wrong_revision_or_repository_is_rejected(tmp_path, field, value, message):
    document = waiver_document(target_for("unit:u0:lens:correctness"))
    document[field] = value
    path = write_waiver(tmp_path, document)

    with pytest.raises(WaiverError, match=message):
        load_waiver(
            str(path),
            repository="owner/repo",
            base_sha="b" * 40,
            head_sha="c" * 40,
            now=NOW,
        )


def test_expired_waiver_is_rejected_and_never_applied_after_expiry(tmp_path):
    document = waiver_document(target_for("unit:u0:lens:correctness"))
    document["issued_at"] = (NOW - timedelta(hours=2)).isoformat()
    document["expires_at"] = (NOW - timedelta(hours=1)).isoformat()
    path = write_waiver(tmp_path, document)
    with pytest.raises(WaiverError, match="expired"):
        load_waiver(
            str(path),
            repository="owner/repo",
            base_sha="b" * 40,
            head_sha="c" * 40,
            now=NOW,
        )

    document["expires_at"] = (NOW + timedelta(hours=1)).isoformat()
    path = write_waiver(tmp_path, document)
    loaded = load_waiver(
        str(path),
        repository="owner/repo",
        base_sha="b" * 40,
        head_sha="c" * 40,
        now=NOW,
    )
    row = {
        "obligation_id": "unit:u0:lens:correctness",
        "obligation_kind": "CHANGED_UNIT_LENS",
        "required": True,
        "state": "PARTIAL",
        "reason_code": "PARTIAL_REVIEW_COVERAGE",
    }
    applied, unapplied = apply_waivers([row], loaded, now=LATER)
    assert applied == []
    assert unapplied[0]["status"] == "EXPIRED_AT_USE"
    assert row["state"] == "PARTIAL"


def test_unknown_target_is_rejected_before_any_provider_dispatch(tmp_path):
    snapshot = snapshot_with_repository()
    plan = plan_for(snapshot)
    path = write_waiver(tmp_path, waiver_document(target_for("unit:not-planned:lens:correctness")))
    provider = PartialProvider()

    with pytest.raises(EnginePreflightError) as raised:
        run(tmp_path, "waiver-unknown", provider, waiver_path=str(path), plan=plan, snapshot=snapshot)

    assert raised.value.reason == "review_waiver_rejected"
    assert provider.calls == 0


def test_duplicate_and_overbroad_targets_are_rejected(tmp_path):
    target = target_for("unit:u0:lens:correctness")
    duplicate = waiver_document(target)
    duplicate["waivers"].append(dict(target))
    with pytest.raises(WaiverError, match="duplicated"):
        load_waiver(
            str(write_waiver(tmp_path, duplicate)),
            repository="owner/repo",
            base_sha="b" * 40,
            head_sha="c" * 40,
            now=NOW,
        )

    both = target_for("unit:u0:lens:correctness")
    both["reason_code"] = "PARTIAL_REVIEW_COVERAGE"
    with pytest.raises(WaiverError, match="overbroad"):
        load_waiver(
            str(write_waiver(tmp_path, waiver_document(both))),
            repository="owner/repo",
            base_sha="b" * 40,
            head_sha="c" * 40,
            now=NOW,
        )

    wrong_family = waiver_document(
        {
            "kind": "check",
            "reason_code": "PARTIAL_REVIEW_COVERAGE",
            "justification": "This reason belongs to the coverage-note category.",
        }
    )
    with pytest.raises(WaiverError, match="outside its target kind"):
        load_waiver(
            str(write_waiver(tmp_path, wrong_family)),
            repository="owner/repo",
            base_sha="b" * 40,
            head_sha="c" * 40,
            now=NOW,
        )


def test_plan_target_validation_rejects_wrong_kind_and_unknown_id():
    plan = {
        "coverage_obligations": [
            {
                "obligation_id": "check:ci",
                "obligation_kind": "PROJECT_CHECK",
                "required": True,
                "check_binding_id": "ci",
            }
        ]
    }
    wrong_kind = waiver_document(target_for("check:ci", kind="coverage_note"))
    with pytest.raises(WaiverError, match="out of scope"):
        validate_waiver_targets(wrong_kind, plan)

    unknown = waiver_document(target_for("check:other", kind="check"))
    with pytest.raises(WaiverError, match="unknown"):
        validate_waiver_targets(unknown, plan)


def test_summary_records_waived_without_counting_it_as_complete():
    row = {
        "obligation_id": "unit:u0:lens:correctness",
        "obligation_kind": "CHANGED_UNIT_LENS",
        "required": True,
        "state": "WAIVED",
        "reason_code": "WAIVED",
        "waived_from_state": "PARTIAL",
        "waived_from_reason_code": "PARTIAL_REVIEW_COVERAGE",
        "waiver": {
            "waiver_id": "wvr-test",
            "reviewer": "owner/reviewer",
            "reason": "Owner-approved exception.",
            "expires_at": "2099-11-04T12:00:00Z",
            "target": {"kind": "coverage_note", "id": "unit:u0:lens:correctness"},
        },
    }
    summary = build_completeness_summary([row])

    assert summary["required_total"] == 1
    assert summary["complete"] == 0
    assert summary["waived"] == 1
    assert summary["complete_ratio"] == 0.0
    assert summary["resolved_ratio"] == 1.0
    assert summary["incomplete_total"] == 0
    assert summary["reason_distribution"] == []
    assert summary["waived_obligations"][0]["waiver_id"] == "wvr-test"


def test_waiver_does_not_change_the_finding_reducer():
    result = {
        "findings": [
            {
                "status": "ACCEPTED",
                "blocking_class": "BLOCKING",
            }
        ],
        "coverage_state": "COMPLETE",
        "freshness": "CURRENT",
        "budget": {},
        "waivers_applied": [{"waiver_id": "wvr-test"}],
    }

    assert _reduce(result, True, True) == "REQUEST_CHANGES"


def test_cli_rejects_an_out_of_scope_waiver_with_preflight_exit_2(tmp_path, capsys, monkeypatch):
    from test_cli import fixture_repo

    from pr_review_harness import cli

    repo, base, head, profile_path = fixture_repo(tmp_path)
    profile_path.write_text(
        json.dumps(
            {
                "version": "waiver-cli-v1",
                "repository": "fixture/repo",
                "required_lenses": ["correctness"],
                "context_paths": [],
            }
        ),
        encoding="utf-8",
    )
    document = waiver_document(
        target_for("unit:not-planned:lens:correctness"),
        repository="fixture/repo",
        base_sha=base,
        head_sha="d" * 40,
    )
    path = write_waiver(tmp_path, document)
    for name in ("GITHUB_EVENT_PATH", "GITHUB_TOKEN", "GH_TOKEN"):
        monkeypatch.delenv(name, raising=False)
    for name in list(os.environ):
        if name.startswith("ACTIONS_"):
            monkeypatch.delenv(name, raising=False)

    code = cli.main(
        [
            "review",
            "--repo",
            str(repo),
            "--base",
            base,
            "--head",
            head,
            "--profile",
            str(profile_path),
            "--waiver",
            str(path),
            "--run-id",
            "waiver-cli-preflight",
            "--output",
            str(tmp_path / "artifacts"),
            "--json",
        ]
    )

    assert code == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["error"] == "review_waiver_rejected"
    assert payload["exit_code"] == 2
    assert not (tmp_path / "artifacts" / "waiver-cli-preflight.json").exists()


def test_publisher_accepts_a_sealed_result_with_waived_coverage(tmp_path):
    from pr_review_harness.publisher import preview_publication

    snapshot = snapshot_with_repository()
    snapshot["pull_request_number"] = 7
    plan = plan_for(snapshot)
    obligation_id = plan["coverage_obligations"][0]["obligation_id"]
    path = write_waiver(tmp_path, waiver_document(target_for(obligation_id)))
    result = run(tmp_path, "waiver-publish", PartialProvider(), waiver_path=str(path), plan=plan, snapshot=snapshot)

    preview = preview_publication(
        result,
        {
            "schema_version": "1.0",
            "allowed_repositories": ["owner/repo"],
            "allowed_dispositions": ["APPROVE", "COMMENT"],
        },
    )

    assert preview["review_payload"]["event"] == "COMMENT"
    assert result["coverage_state"] == "COMPLETE_WITH_WAIVERS"
    assert result["coverage_ledger"][0]["state"] == "WAIVED"


def test_schema_accepts_exact_id_and_reason_code_targets():
    from jsonschema import Draft202012Validator

    schema = json.loads(
        (Path(__file__).resolve().parents[1] / "schemas/review-evidence-waiver.v1.schema.json").read_text()
    )
    validator = Draft202012Validator(schema)

    id_document = waiver_document(target_for("unit:u0:lens:correctness"))
    validator.validate(id_document)

    reason_document = waiver_document(
        {
            "kind": "coverage_note",
            "reason_code": "PARTIAL_REVIEW_COVERAGE",
            "justification": "The exact reason is the only missing-evidence target.",
        }
    )
    validator.validate(reason_document)

    both = target_for("unit:u0:lens:correctness")
    both["reason_code"] = "PARTIAL_REVIEW_COVERAGE"
    assert list(validator.iter_errors(waiver_document(both)))


def test_schema_accepts_execution_failure_targets_only_with_an_allowlisted_reason():
    from jsonschema import Draft202012Validator

    schema = json.loads(
        (Path(__file__).resolve().parents[1] / "schemas/review-evidence-waiver.v1.schema.json").read_text()
    )
    validator = Draft202012Validator(schema)

    validator.validate(waiver_document(execution_target(obligation_id="unit:u0:lens:correctness")))
    validator.validate(waiver_document(execution_target(reason_code="REQUIRED_OUTPUT_QUARANTINED")))
    assert list(validator.iter_errors(waiver_document(execution_target(reason_code="TASK_FAILED"))))


def test_waiver_lifetime_is_capped_and_issued_time_cannot_be_in_the_future(tmp_path):
    document = waiver_document(target_for("unit:u0:lens:correctness"))
    document["issued_at"] = (NOW + timedelta(days=1)).isoformat()
    document["expires_at"] = (NOW + timedelta(days=2)).isoformat()
    with pytest.raises(WaiverError, match="future"):
        load_waiver(
            str(write_waiver(tmp_path, document)),
            repository="owner/repo",
            base_sha="b" * 40,
            head_sha="c" * 40,
            now=NOW,
        )

    document["issued_at"] = (NOW - timedelta(hours=1)).isoformat()
    document["expires_at"] = (NOW + timedelta(days=91)).isoformat()
    with pytest.raises(WaiverError, match="90 days"):
        load_waiver(
            str(write_waiver(tmp_path, document)),
            repository="owner/repo",
            base_sha="b" * 40,
            head_sha="c" * 40,
            now=NOW,
        )


def test_reason_code_target_rejects_multiple_matching_obligations():
    rows = [
        {
            "obligation_id": "unit:u0:lens:correctness",
            "obligation_kind": "CHANGED_UNIT_LENS",
            "required": True,
            "state": "PARTIAL",
            "reason_code": "PARTIAL_REVIEW_COVERAGE",
        },
        {
            "obligation_id": "unit:u1:lens:correctness",
            "obligation_kind": "CHANGED_UNIT_LENS",
            "required": True,
            "state": "PARTIAL",
            "reason_code": "PARTIAL_REVIEW_COVERAGE",
        },
    ]
    document = waiver_document(
        {
            "kind": "coverage_note",
            "reason_code": "PARTIAL_REVIEW_COVERAGE",
            "justification": "This reason must identify exactly one incomplete obligation.",
        }
    )
    document["source_sha256"] = "a" * 64

    with pytest.raises(WaiverError, match="overbroad"):
        apply_waivers(rows, document, now=NOW)
    assert {row["state"] for row in rows} == {"PARTIAL"}


def test_reducer_caps_waived_reviews_at_comment():
    result = {
        "findings": [],
        "coverage_state": "COMPLETE_WITH_WAIVERS",
        "freshness": "CURRENT",
        "budget": {},
        "completeness_summary": {"waived": 1},
        "waivers_applied": [{"waiver_id": "wvr-test"}],
    }
    assert _reduce(result, True, True) == "COMMENT"

    result["findings"] = [{"status": "ACCEPTED", "blocking_class": "BLOCKING"}]
    assert _reduce(result, True, True) == "REQUEST_CHANGES"


def test_publisher_rejects_approval_of_a_waived_review(tmp_path):
    from pr_review_harness.engine import _hash
    from pr_review_harness.publisher import PublicationRejected, preview_publication

    snapshot = snapshot_with_repository()
    snapshot["pull_request_number"] = 7
    plan = plan_for(snapshot)
    obligation_id = plan["coverage_obligations"][0]["obligation_id"]
    path = write_waiver(tmp_path, waiver_document(target_for(obligation_id)))
    result = run(
        tmp_path, "waiver-publish-reject", PartialProvider(), waiver_path=str(path), plan=plan, snapshot=snapshot
    )
    result["disposition"] = "APPROVE"
    result["result_hash"] = _hash({key: value for key, value in result.items() if key != "result_hash"})

    with pytest.raises(PublicationRejected, match="cannot approve"):
        preview_publication(
            result,
            {
                "schema_version": "1.0",
                "allowed_repositories": ["owner/repo"],
                "allowed_dispositions": ["APPROVE", "COMMENT"],
            },
        )


def test_publisher_rejects_approval_of_an_execution_failure_waived_review(tmp_path):
    from pr_review_harness.engine import _hash
    from pr_review_harness.publisher import PublicationRejected, preview_publication

    snapshot = snapshot_with_repository()
    snapshot["pull_request_number"] = 7
    plan = plan_for(snapshot)
    obligation_id = plan["coverage_obligations"][0]["obligation_id"]
    result, _ = run_execution_waiver(
        tmp_path, "waiver-execution-publish-reject", execution_target(obligation_id=obligation_id)
    )
    result["disposition"] = "APPROVE"
    result["result_hash"] = _hash({key: value for key, value in result.items() if key != "result_hash"})

    with pytest.raises(PublicationRejected, match="cannot approve"):
        preview_publication(
            result,
            {
                "schema_version": "1.0",
                "allowed_repositories": ["owner/repo"],
                "allowed_dispositions": ["APPROVE", "COMMENT"],
            },
        )


def test_publisher_rejects_a_forged_execution_failure_target_reason(tmp_path):
    from pr_review_harness.engine import _hash
    from pr_review_harness.publisher import PublicationRejected, preview_publication

    result, _ = run_execution_waiver(
        tmp_path,
        "waiver-execution-forged-target",
        execution_target(reason_code="REQUIRED_OUTPUT_QUARANTINED"),
    )
    forged = {"kind": "execution_failure", "reason_code": "TASK_FAILED", "justification": "forged target"}
    result["waivers_applied"][0]["target"] = forged
    result["coverage_ledger"][0]["waiver"]["target"] = forged
    result["result_hash"] = _hash({key: value for key, value in result.items() if key != "result_hash"})

    with pytest.raises(PublicationRejected, match="execution-failure reason"):
        preview_publication(
            result,
            {
                "schema_version": "1.0",
                "allowed_repositories": ["owner/repo"],
                "allowed_dispositions": ["COMMENT"],
            },
        )


def test_resume_rejects_changed_waiver_presence_and_hash(tmp_path):
    snapshot = snapshot_with_repository()
    plan = plan_for(snapshot)
    obligation_id = plan["coverage_obligations"][0]["obligation_id"]
    first = tmp_path / "first.json"
    first.write_text(json.dumps(waiver_document(target_for(obligation_id))), encoding="utf-8")
    result = run(
        tmp_path, "waiver-resume-presence", PartialProvider(), waiver_path=str(first), plan=plan, snapshot=snapshot
    )

    with pytest.raises(EnginePreflightError) as without:
        run(
            tmp_path,
            "waiver-resume-presence",
            PartialProvider(),
            waiver_path=None,
            plan=plan,
            snapshot=snapshot,
            resume=True,
        )
    assert without.value.reason == "resume_state_invalid"

    no_waiver_dir = tmp_path / "no-waiver"
    no_waiver_dir.mkdir()
    run(no_waiver_dir, "waiver-resume-added", PartialProvider(), plan=plan, snapshot=snapshot)
    with pytest.raises(EnginePreflightError) as added:
        run(
            no_waiver_dir,
            "waiver-resume-added",
            PartialProvider(),
            waiver_path=str(first),
            plan=plan,
            snapshot=snapshot,
            resume=True,
        )
    assert added.value.reason == "resume_state_invalid"

    changed = dict(waiver_document(target_for(obligation_id)))
    changed["reason"] = "A different owner-approved reason changes the waiver file digest."
    second = tmp_path / "second.json"
    second.write_text(json.dumps(changed), encoding="utf-8")
    with pytest.raises(EnginePreflightError) as changed_hash:
        run(
            tmp_path,
            "waiver-resume-presence",
            PartialProvider(),
            waiver_path=str(second),
            plan=plan,
            snapshot=snapshot,
            resume=True,
        )
    assert changed_hash.value.reason == "resume_state_invalid"
    assert result["waiver_receipt"]["source_sha256"] == hashlib.sha256(first.read_bytes()).hexdigest()


def test_resume_with_the_same_waiver_binding_is_allowed(tmp_path):
    snapshot = snapshot_with_repository()
    plan = plan_for(snapshot)
    obligation_id = plan["coverage_obligations"][0]["obligation_id"]
    path = write_waiver(tmp_path, waiver_document(target_for(obligation_id)))
    first = run(tmp_path, "waiver-resume-same", PartialProvider(), waiver_path=str(path), plan=plan, snapshot=snapshot)

    provider = PartialProvider()
    resumed = run(
        tmp_path,
        "waiver-resume-same",
        provider,
        waiver_path=str(path),
        plan=plan,
        snapshot=snapshot,
        resume=True,
    )

    assert resumed["request_hash"] == first["request_hash"]
    assert resumed["waiver_receipt"]["source_sha256"] == first["waiver_receipt"]["source_sha256"]
    assert provider.calls == 0


def test_id_and_reason_targets_cannot_overlap_the_same_obligation():
    snapshot = snapshot_with_repository()
    plan = plan_for(snapshot)
    obligation_id = plan["coverage_obligations"][0]["obligation_id"]
    document = waiver_document(target_for(obligation_id))
    document["waivers"].append(
        {
            "kind": "coverage_note",
            "reason_code": "PARTIAL_REVIEW_COVERAGE",
            "justification": "This reason is intended to match the same incomplete obligation.",
        }
    )

    with pytest.raises(WaiverError, match="overlaps"):
        validate_waiver_targets(document, plan)


def _reseal(result):
    from pr_review_harness.engine import _hash

    result["result_hash"] = _hash({key: value for key, value in result.items() if key != "result_hash"})
    return result


def _publisher_config():
    return {
        "schema_version": "1.0",
        "allowed_repositories": ["owner/repo"],
        "allowed_dispositions": ["APPROVE", "COMMENT"],
    }


def _sealed_waived_publish_result(tmp_path, run_id):
    snapshot = snapshot_with_repository()
    snapshot["pull_request_number"] = 7
    plan = plan_for(snapshot)
    obligation_id = plan["coverage_obligations"][0]["obligation_id"]
    path = write_waiver(tmp_path, waiver_document(target_for(obligation_id)))
    return run(tmp_path, run_id, PartialProvider(), waiver_path=str(path), plan=plan, snapshot=snapshot)


@pytest.mark.parametrize(
    "mutation",
    [
        "no_receipt",
        "count_mismatch",
        "source_hash_mismatch",
        "record_missing_obligation",
        "duplicate_record",
        "extra_record",
        "bogus_row_target",
        "bogus_row_justification",
    ],
)
def test_publisher_rejects_inconsistent_waiver_receipts(tmp_path, mutation):
    from pr_review_harness.publisher import PublicationRejected, preview_publication

    result = json.loads(json.dumps(_sealed_waived_publish_result(tmp_path, f"waiver-publish-{mutation}")))
    receipt = result["waiver_receipt"]
    applied = result["waivers_applied"]

    if mutation == "no_receipt":
        result.pop("waiver_receipt")
    elif mutation == "count_mismatch":
        receipt["applied_count"] += 1
    elif mutation == "source_hash_mismatch":
        receipt["source_sha256"] = "d" * 64
    elif mutation == "record_missing_obligation":
        applied[0]["obligation_ids"] = ["unit:other"]
    elif mutation == "duplicate_record":
        applied.append(dict(applied[0]))
        receipt["applied_count"] = len(applied)
    elif mutation == "extra_record":
        applied.append(
            {
                **applied[0],
                "waiver_id": "wvr-extra",
                "obligation_ids": ["unit:extra"],
            }
        )
        receipt["applied_count"] = len(applied)
    elif mutation == "bogus_row_target":
        result["coverage_ledger"][0]["waiver"]["target"]["id"] = "unit:forged"
    elif mutation == "bogus_row_justification":
        result["coverage_ledger"][0]["waiver"]["justification"] = "A forged row justification."
    _reseal(result)

    with pytest.raises(PublicationRejected, match="waiver"):
        preview_publication(result, _publisher_config())


def test_publisher_rejects_a_fabricated_waived_row_without_a_receipt(tmp_path):
    from pr_review_harness.publisher import PublicationRejected, preview_publication

    result = _sealed_waived_publish_result(tmp_path, "waiver-fabricated-row")
    result.pop("waiver_receipt")
    result.pop("waivers_applied")
    result["coverage_state"] = "COMPLETE_WITH_WAIVERS"
    result["disposition"] = "COMMENT"
    _reseal(result)

    with pytest.raises(PublicationRejected, match="waiver receipt"):
        preview_publication(result, _publisher_config())


def test_preflight_rejects_id_reason_overlap_before_any_provider_call(tmp_path):
    snapshot = snapshot_with_repository()
    plan = plan_for(snapshot)
    obligation_id = plan["coverage_obligations"][0]["obligation_id"]
    document = waiver_document(target_for(obligation_id))
    document["waivers"].append(
        {
            "kind": "coverage_note",
            "reason_code": "PARTIAL_REVIEW_COVERAGE",
            "justification": "This reason resolves to the same planned obligation as the id target.",
        }
    )
    path = write_waiver(tmp_path, document)
    provider = PartialProvider()

    with pytest.raises(EnginePreflightError) as raised:
        run(tmp_path, "waiver-overlap-preflight", provider, waiver_path=str(path), plan=plan, snapshot=snapshot)

    assert raised.value.reason == "review_waiver_rejected"
    assert provider.calls == 0


def test_preflight_rejects_ambiguous_check_alias_before_any_provider_call(tmp_path):
    snapshot = snapshot_with_repository()
    plan = plan_for(snapshot)
    plan["coverage_obligations"].extend(
        [
            {
                "obligation_id": "check:a",
                "obligation_kind": "PROJECT_CHECK",
                "required": True,
                "scope_unit_ids": ["u0"],
                "check_binding_id": "ambiguous",
            },
            {
                "obligation_id": "ambiguous",
                "obligation_kind": "PROJECT_CHECK",
                "required": True,
                "scope_unit_ids": ["u0"],
                "check_binding_id": "b",
            },
        ]
    )
    document = waiver_document(
        {
            "kind": "check",
            "id": "ambiguous",
            "justification": "The identifier is both an obligation id and another check alias.",
        }
    )
    path = write_waiver(tmp_path, document)
    provider = PartialProvider()

    with pytest.raises(EnginePreflightError) as raised:
        run(tmp_path, "waiver-ambiguous-check", provider, waiver_path=str(path), plan=plan, snapshot=snapshot)

    assert raised.value.reason == "review_waiver_rejected"
    assert provider.calls == 0


def test_publisher_rejects_stray_waiver_metadata_without_waived_rows(tmp_path):
    from pr_review_harness.publisher import PublicationRejected, preview_publication

    snapshot = snapshot_with_repository()
    snapshot["pull_request_number"] = 7
    plan = plan_for(snapshot)
    complete = run(tmp_path, "publisher-complete-no-waivers", EmptyProvider(), plan=plan, snapshot=snapshot)
    assert complete["coverage_state"] == "COMPLETE"
    assert complete["waiver_receipt"] is None

    stray_source = _sealed_waived_publish_result(tmp_path, "waiver-stray-source")
    complete["waiver_receipt"] = stray_source["waiver_receipt"]
    complete["waivers_applied"] = stray_source["waivers_applied"]
    complete["waivers_not_applied"] = []
    _reseal(complete)

    with pytest.raises(PublicationRejected, match="metadata is present"):
        preview_publication(complete, _publisher_config())


def test_publisher_waiver_integrity_rejects_inconsistent_metadata(tmp_path):
    from pr_review_harness import publisher

    snapshot = snapshot_with_repository()
    snapshot["pull_request_number"] = 7
    plan = plan_for(snapshot)
    obligation_id = plan["coverage_obligations"][0]["obligation_id"]
    path = write_waiver(tmp_path, waiver_document(target_for(obligation_id)))
    result = run(tmp_path, "waiver-integrity", PartialProvider(), waiver_path=str(path), plan=plan, snapshot=snapshot)

    mutations = [
        lambda r: r["waiver_receipt"].__setitem__("repository", "other/repo"),
        lambda r: r["waiver_receipt"].__setitem__("reviewer", ""),
        lambda r: r["coverage_ledger"][0].__setitem__("obligation_id", 7),
        lambda r: r["coverage_ledger"][0]["waiver"].__setitem__("waiver_id", "missing"),
        lambda r: r["coverage_ledger"][0]["waiver"].__setitem__("reason", "different"),
        lambda r: r["coverage_ledger"][0]["waiver"].__setitem__("target", {"kind": "coverage_note", "id": "bogus"}),
        lambda r: r["waivers_applied"][0].__setitem__("reviewer", ""),
        lambda r: r["waivers_applied"][0]["target"].__setitem__("kind", "bogus"),
        lambda r: r["waivers_applied"][0].__setitem__(
            "target",
            {
                "kind": "execution_failure",
                "id": "x",
                "reason_code": "DEADLINE_EXHAUSTED",
                "justification": "long enough text",
            },
        ),
        lambda r: r["waivers_applied"][0]["target"].__setitem__("justification", "short"),
        lambda r: r["waivers_applied"][0].__setitem__(
            "target", {"kind": "execution_failure", "reason_code": "BOGUS", "justification": "long enough text"}
        ),
    ]
    for mutate in mutations:
        candidate = copy.deepcopy(result)
        mutate(candidate)
        with pytest.raises(Exception):
            publisher._validate_waiver_integrity(candidate)


def test_publisher_rejects_reducer_contract_failure(tmp_path, monkeypatch):
    from pr_review_harness import engine as engine_module
    from pr_review_harness import publisher

    snapshot = snapshot_with_repository()
    snapshot["pull_request_number"] = 7
    plan = plan_for(snapshot)
    result = run(tmp_path, "waiver-reducer", PartialProvider(), plan=plan, snapshot=snapshot)
    result["disposition"] = "COMMENT"

    def broken(*args, **kwargs):
        raise TypeError("broken reducer")

    monkeypatch.setattr(engine_module, "_reduce", broken)
    with pytest.raises(publisher.PublicationRejected):
        publisher.preview_publication(
            result,
            {"schema_version": "1.0", "allowed_repositories": ["owner/repo"], "allowed_dispositions": ["COMMENT"]},
        )
