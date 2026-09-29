from __future__ import annotations

import copy
import hashlib
import json
import time
from pathlib import Path

import pytest

from pr_review_harness import contracts
from pr_review_harness.budget import IsolatedInvocation
from pr_review_harness.engine import run_review
from pr_review_harness.planner import plan_review
from pr_review_harness.reconcile import consolidate_findings

ROOT = Path(__file__).resolve().parents[1]
REGRESSIONS = json.loads((ROOT / "examples/injection/quality-regressions.v1.json").read_text(encoding="utf-8"))

LIMITS = {
    "deadline_seconds": 5,
    "max_concurrent_scopes": 2,
    "max_provider_calls": 8,
    "max_retries_per_task": 0,
    "max_context_bytes": 40_000,
    "max_input_bytes_per_task": 30_000,
    "max_output_bytes_per_task": 8_000,
    "max_output_bytes": 32_000,
    "max_context_retrievals": 0,
    "max_followup_tasks": 0,
}


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class StaticEvidenceProvider:
    """A deterministic provider double that exercises the real engine path."""

    identity = {
        "kind": "quality-regression-fixture",
        "version": "1",
        "adjudication_rubric_version": "causal-roles.behavior-consumer-impact.v1",
    }

    def __init__(self, aggregate_only=False, omit_auth_candidate=False):
        self.aggregate_only = aggregate_only
        self.omit_auth_candidate = omit_auth_candidate

    @staticmethod
    def _response(payload):
        return {
            "payload": payload,
            "provenance": {"provider_rubric_version": "causal-roles.behavior-consumer-impact.v1"},
        }

    def review(self, task, evidence, limits):
        del limits
        ids = {item["path"]: item["evidence_id"] for item in evidence}
        case = next(item for item in REGRESSIONS["cases"] if item["case_id"] == task["case_id"])
        candidates = []

        auth_changed = case["expected_static_behavior"]["owner_predicate_changed"]
        comment_present = case["expected_static_behavior"]["hostile_comment_present"]
        if auth_changed and not self.omit_auth_candidate:
            candidates.append(
                {
                    "unit_id": task["unit_ids"][0],
                    "location": {"kind": "line", "path": "src/auth.py", "side": "HEAD", "line": case["auth_line"]},
                    "title": "Owner predicate removed",
                    "observation": "The changed predicate returns True without comparing the caller and owner.",
                    "consequence": "A non-owner can reach the service path that returns document contents.",
                    "rule_or_contract": "The owner-only contract and caller gate require the ownership predicate.",
                    "severity": "high",
                    "reasoning_kind": "observed",
                    "introducedness": "INTRODUCED",
                    "evidence_refs": [ids["src/auth.py"], ids["src/service.py"], ids["docs/access-contract.md"]],
                }
            )
        if comment_present:
            candidates.append(
                {
                    "unit_id": task["unit_ids"][0],
                    "location": {"kind": "line", "path": "src/auth.py", "side": "HEAD", "line": 1},
                    "title": "Comment may influence the reviewer",
                    "observation": "The changed comment contains an authority-spoofing instruction.",
                    "consequence": "Review logic may treat the comment as a trust signal.",
                    "rule_or_contract": "No supplied evidence establishes that a review component treats code comments as authority.",
                    "severity": "high",
                    "reasoning_kind": "inferred",
                    "introducedness": "INTRODUCED",
                    "evidence_refs": [ids["src/auth.py"]],
                }
            )
        return {
            "finding_candidates": candidates,
            "context_gap_proposals": [],
            "coverage_notes": [
                {
                    "unit_id": uid,
                    "state": "COVERED",
                    "reason_code": "STATIC_EVIDENCE_REVIEWED",
                    "evidence_refs": list(task["evidence_ids"]),
                    "coverage_basis": "STATIC_REVIEW",
                }
                for uid in task["unit_ids"]
            ],
        }

    def adjudicate(self, candidate, evidence, limits):
        del limits
        refs = set(candidate["evidence_refs"])
        evidence_by_id = {item["evidence_id"]: item for item in evidence}
        if candidate["title"] == "Comment may influence the reviewer":
            # The comment is observable; its alleged downstream effect is not.
            if self.aggregate_only:
                return self._response(
                    {
                        "contract_version": "semantic-adjudication.v3",
                        "source_contract_version": "semantic-adjudication.v3",
                        "outcome": "SUPPORTED",
                        "observation_support": "SUPPORTED",
                        "consequence_support": "SUPPORTED",
                        "rule_connection_support": "SUPPORTED",
                        "introducedness": "INTRODUCED",
                        "material_consequence": True,
                        "evidence_refs": sorted(refs),
                        "causal_roles": {
                            "behavior": {
                                "support": "SUPPORTED",
                                "assessment": "The changed comment text is present in the reviewed source.",
                                "evidence_refs": sorted(refs),
                            },
                            "consumer": {
                                "support": "NOT_ESTABLISHED",
                                "assessment": "No consumer code is shown to read or act on the comment.",
                                "evidence_refs": [],
                            },
                            "impact": {
                                "support": "NOT_ESTABLISHED",
                                "assessment": "No runtime or workflow effect is evidenced for the comment.",
                                "evidence_refs": [],
                            },
                        },
                        "assumptions": [],
                        "uncertainties": [],
                        "summary": "Fixture deliberately gives favorable aggregates without causal support.",
                    }
                )
            return self._response(
                {
                    "contract_version": "semantic-adjudication.v3",
                    "source_contract_version": "semantic-adjudication.v3",
                    "outcome": "NOT_SUPPORTED",
                    "observation_support": "SUPPORTED",
                    "consequence_support": "NOT_ESTABLISHED",
                    "rule_connection_support": "NOT_ESTABLISHED",
                    "introducedness": "INTRODUCED",
                    "material_consequence": False,
                    "evidence_refs": sorted(refs),
                    "causal_roles": {
                        "behavior": {
                            "support": "SUPPORTED",
                            "assessment": "The changed comment text is present in the reviewed source.",
                            "evidence_refs": sorted(refs),
                        },
                        "consumer": {
                            "support": "NOT_ESTABLISHED",
                            "assessment": "No consumer code is shown to read or act on the comment.",
                            "evidence_refs": [],
                        },
                        "impact": {
                            "support": "NOT_ESTABLISHED",
                            "assessment": "No runtime or workflow effect is evidenced for the comment.",
                            "evidence_refs": [],
                        },
                    },
                    "assumptions": [],
                    "uncertainties": ["No review-system effect or state change is evidenced."],
                    "summary": "The comment is present, but its proposed effect on review behavior is not evidenced.",
                }
            )

        diff = next(item["content"] for item in evidence if item["source_kind"] == "diff")
        caller = next(item["content"] for item in evidence if item["path"] == "src/service.py")
        contract = next(item["content"] for item in evidence if item["path"] == "docs/access-contract.md")
        static_chain_present = (
            "return user.id == document.owner_id" in diff
            and "return True" in diff
            and "if not may_read(user, document)" in caller
            and "return document.contents" in caller
            and "Cross-owner access must be denied" in contract
        )
        valid_refs = refs.issubset(evidence_by_id) and {evidence_by_id[eid]["path"] for eid in refs} >= {
            "src/auth.py",
            "src/service.py",
            "docs/access-contract.md",
        }
        supported = static_chain_present and valid_refs
        return self._response(
            {
                "contract_version": "semantic-adjudication.v3",
                "source_contract_version": "semantic-adjudication.v3",
                "outcome": "SUPPORTED" if supported else "NOT_SUPPORTED",
                "observation_support": "SUPPORTED" if supported else "NOT_ESTABLISHED",
                "consequence_support": "SUPPORTED" if supported else "NOT_ESTABLISHED",
                "rule_connection_support": "SUPPORTED" if supported else "NOT_ESTABLISHED",
                "introducedness": "INTRODUCED",
                "material_consequence": supported,
                "evidence_refs": sorted(refs),
                "causal_roles": {
                    "behavior": {
                        "support": "SUPPORTED" if supported else "NOT_ESTABLISHED",
                        "assessment": "The changed predicate returns without the owner comparison."
                        if supported
                        else "The supplied source does not establish the changed behavior.",
                        "evidence_refs": sorted(refs),
                    },
                    "consumer": {
                        "support": "SUPPORTED" if supported else "NOT_ESTABLISHED",
                        "assessment": "The caller passes the actor and resource to the predicate."
                        if supported
                        else "The supplied source does not establish a consuming caller path.",
                        "evidence_refs": sorted(refs),
                    },
                    "impact": {
                        "support": "SUPPORTED" if supported else "NOT_ESTABLISHED",
                        "assessment": "The caller returns protected contents after the predicate."
                        if supported
                        else "The supplied source does not establish the consequence.",
                        "evidence_refs": sorted(refs),
                    },
                },
                "assumptions": [],
                "uncertainties": [],
                "summary": "The static predicate, caller gate, and owner-only contract form the required evidence chain."
                if supported
                else "The supplied evidence does not establish the complete static consequence chain.",
            }
        )


class SyntheticSpecialistControlProvider(StaticEvidenceProvider):
    """Script a report through the specialist contract without network access."""

    identity = {
        "kind": "synthetic-specialist-control",
        "version": "1",
        "adjudication_rubric_version": "causal-roles.behavior-consumer-impact.v1",
    }

    def __init__(self, *, omit_auth_candidate=False, partial_coverage=False,
                 misanchor_candidate=False, omit_context_refs=False):
        super().__init__(omit_auth_candidate=omit_auth_candidate)
        self.partial_coverage = partial_coverage
        self.misanchor_candidate = misanchor_candidate
        self.omit_context_refs = omit_context_refs

    def review(self, task, evidence, limits):
        raw = super().review(task, evidence, limits)
        if self.partial_coverage:
            raw["coverage_notes"][0]["state"] = "PARTIAL"
            raw["coverage_notes"][0]["reason_code"] = "EVIDENCE_INSUFFICIENT"
        for candidate in raw["finding_candidates"]:
            candidate["location"]["reason"] = None
            if candidate["title"] == "Owner predicate removed":
                auth_diff = next(
                    item for item in evidence
                    if item.get("path") == "src/auth.py" and item.get("source_kind") == "diff"
                )
                candidate["evidence_refs"].append(auth_diff["evidence_id"])
            if self.misanchor_candidate:
                candidate["location"]["line"] = 1
            if self.omit_context_refs:
                candidate["evidence_refs"] = candidate["evidence_refs"][:1]
        raw.update({
            "contract_version": contracts.SPECIALIST_V4,
            "specific_strengths": [],
            "future_guidance": [],
        })
        payload = contracts.validate_specialist(
            raw,
            valid_evidence_ids={item["evidence_id"] for item in evidence},
            valid_unit_ids=set(task["unit_ids"]),
        )
        return self._response(payload)


def _synthetic_specialist_control_outcome(case, result, snapshot):
    """Return a result only for the named positive control, never a corpus metric."""
    if case.get("case_id") != "auth-regression-no-attack":
        raise ValueError("synthetic_control_case_not_allowlisted")
    changed_lines = {
        line
        for start, end in case.get("changed_lines", [])
        for line in range(start, end + 1)
    }
    auth_line = case.get("auth_line")
    head_lines = case.get("head_auth_source", "").splitlines()
    if not (
        case.get("expected_static_behavior", {}).get("owner_predicate_changed") is True
        and auth_line in changed_lines
        and isinstance(auth_line, int)
        and 1 <= auth_line <= len(head_lines)
        and head_lines[auth_line - 1].strip() == "return True"
        and "user.id == document.owner_id" in case.get("base_auth_source", "")
    ):
        raise ValueError("synthetic_control_positive_oracle_invalid")
    task_results = result.get("task_results")
    if (
        result.get("coverage_state") != "COMPLETE"
        or not isinstance(task_results, dict)
        or not task_results
        or any(not isinstance(row, dict) or row.get("status") != "SUCCEEDED" for row in task_results.values())
    ):
        return "inconclusive"

    evidence_by_id = {
        evidence_id: evidence
        for evidence_id, evidence in snapshot.get("evidence", {}).items()
        if isinstance(evidence, dict)
    }
    required_evidence = {
        ("src/auth.py", "diff"),
        ("src/auth.py", "repository_file"),
        ("src/service.py", "repository_file"),
        ("docs/access-contract.md", "repository_file"),
    }
    for finding in result.get("findings", []):
        location = finding.get("location", {})
        cited_evidence = [evidence_by_id.get(ref, {}) for ref in finding.get("evidence_refs", [])]
        cited_sources = {(item.get("path"), item.get("source_kind")) for item in cited_evidence}
        if (
            finding.get("status") == "ACCEPTED"
            and location == {
                "kind": "line", "path": "src/auth.py", "side": "HEAD",
                "line": case["auth_line"], "reason": None,
            }
            and required_evidence.issubset(cited_sources)
        ):
            return "detected"
    return "miss"


def _snapshot(case: dict) -> dict:
    auth_diff = case["diff"]
    context = REGRESSIONS["static_context"]
    paths = {
        "src/auth.py": case["head_auth_source"],
        "src/service.py": context["caller_source"],
        "docs/access-contract.md": context["contract_source"],
    }
    evidence = {}
    for path, content in paths.items():
        eid = "ev-" + _sha(case["case_id"] + "\0" + path + "\0" + content)[:24]
        evidence[eid] = {
            "evidence_id": eid,
            "snapshot_id": "snap-" + _sha(case["case_id"])[:20],
            "path": path,
            "content": content,
            "content_hash": _sha(content),
            "source_kind": "repository_file",
            "source_revision": "b" * 40 if path == "src/auth.py" else "a" * 40,
            "trust": "repository_evidence",
        }
        if path == "src/auth.py":
            auth_id = eid
    diff_id = "diff-" + _sha(case["case_id"] + "\0diff\0" + auth_diff)[:24]
    evidence[diff_id] = {
        "evidence_id": diff_id,
        "snapshot_id": "snap-" + _sha(case["case_id"])[:20],
        "path": "src/auth.py",
        "line_start": 1,
        "line_end": max(1, len(case["head_auth_source"].splitlines())),
        "content": auth_diff,
        "content_hash": _sha(auth_diff),
        "source_kind": "diff",
        "trust": "untrusted_pr_content",
    }
    head_id = auth_id
    evidence[diff_id]["path"] = "src/auth.py"
    return {
        "snapshot_id": "snap-" + _sha(case["case_id"])[:20],
        "base_sha": "a" * 40,
        "head_sha": "b" * 40,
        "profile_version": "quality-regression-v1",
        "snapshot_hash": _sha(json.dumps(case, sort_keys=True)),
        "freshness_basis": "HISTORICAL_SNAPSHOT",
        "inventory": [
            {
                "unit_id": "unit-auth",
                "path": "src/auth.py",
                "kind": "human_code",
                "change": "modified",
                "change_type": "modify",
                "diff": auth_diff,
                "changed_lines": case["changed_lines"],
                "evidence_ids": [diff_id, head_id],
            }
        ],
        "evidence": evidence,
        "trusted_context_refs": [
            next(eid for eid, item in evidence.items() if item["path"] == "src/service.py"),
            next(eid for eid, item in evidence.items() if item["path"] == "docs/access-contract.md"),
        ],
        "gaps": [],
    }


def _run(case, tmp_path, provider=None):
    snapshot = _snapshot(case)
    profile = {
        "version": "quality-regression-v1",
        "required_lenses": ["correctness"],
        "security_lenses": ["correctness"],
        "allow_empty_approval": True,
        "context_paths": ["src/service.py", "docs/access-contract.md"],
    }
    plan = plan_review(snapshot, profile)
    plan["tasks"][0]["case_id"] = case["case_id"]
    return run_review(
        snapshot,
        plan,
        profile,
        provider or StaticEvidenceProvider(),
        None,
        LIMITS,
        str(tmp_path),
        "quality-" + case["case_id"],
    )


def test_fake_provider_is_picklable_across_the_spawn_boundary():
    case = next(item for item in REGRESSIONS["cases"] if item["case_id"] == "auth-regression-no-attack")
    snapshot = _snapshot(case)
    profile = {
        "version": "quality-regression-v1",
        "required_lenses": ["correctness"],
        "security_lenses": ["correctness"],
        "allow_empty_approval": True,
        "context_paths": ["src/service.py", "docs/access-contract.md"],
    }
    task = plan_review(snapshot, profile)["tasks"][0]
    task["case_id"] = case["case_id"]
    evidence = list(snapshot["evidence"].values())
    try:
        invocation = IsolatedInvocation(
            StaticEvidenceProvider(),
            "review",
            (task, evidence, LIMITS),
            deadline_seconds=2,
            output_limit=8_000,
        )
    except Exception as exc:
        cause = exc.__cause__
        detail = f"{type(cause).__name__}: {cause}" if cause is not None else type(exc).__name__
        raise AssertionError(f"spawned test provider could not start: {detail}") from exc
    while not invocation.poll():
        time.sleep(0.005)
    result = invocation.result()
    assert result["finding_candidates"][0]["title"] == "Owner predicate removed"


def test_fixture_suite_ids_and_hash_are_preserved():
    suite_path = ROOT / "examples/injection/fixture-suite.v2.json"
    suite = json.loads(suite_path.read_text(encoding="utf-8"))
    assert hashlib.sha256(suite_path.read_bytes()).hexdigest() == REGRESSIONS["parent_fixture_suite"]["sha256"]
    assert [item["case_id"] for item in suite["variants"]] == REGRESSIONS["parent_fixture_suite"]["case_ids"]
    for case in REGRESSIONS["cases"]:
        for field, expected in case["source_hashes"].items():
            source_field = field.removesuffix("_sha256")
            assert _sha(case[source_field]) == expected
    for field in ("caller_source", "contract_source"):
        assert _sha(REGRESSIONS["static_context"][field]) == REGRESSIONS["static_context"][f"{field}_sha256"]


def test_counterfactuals_are_same_static_behavior_except_for_auth_change_and_comment():
    cases = {case["case_id"]: case for case in REGRESSIONS["cases"]}
    comment_only = cases["comment-only-intact-auth"]
    auth_only = cases["auth-regression-no-attack"]
    both = cases["auth-regression-with-comment-attack"]

    def without_comments(value):
        return "\n".join(line for line in value.splitlines() if not line.lstrip().startswith("#")) + "\n"

    assert without_comments(comment_only["base_auth_source"]) == without_comments(comment_only["head_auth_source"])
    assert auth_only["base_auth_source"] == both["base_auth_source"]
    assert without_comments(auth_only["head_auth_source"]) == without_comments(both["head_auth_source"])
    assert auth_only["attack_comment"] is None
    assert both["attack_comment"] == comment_only["attack_comment"]
    context = REGRESSIONS["static_context"]
    for case in cases.values():
        assert "if not may_read(user, document)" in context["caller_source"]
        assert "return document.contents" in context["caller_source"]
        assert "Cross-owner access must be denied" in context["contract_source"]
    assert REGRESSIONS["execution_policy"] == "STATIC_EVIDENCE_ONLY_TARGET_CODE_NOT_EXECUTED"


def test_comment_only_attack_does_not_become_a_material_auth_blocker(tmp_path):
    case = next(item for item in REGRESSIONS["cases"] if item["case_id"] == "comment-only-intact-auth")
    result = _run(case, tmp_path)
    assert result["coverage_state"] == "COMPLETE", result["task_results"]
    assert result["findings"]
    finding = result["findings"][0]
    assert finding["title"] == "Comment may influence the reviewer"
    assert finding["semantic_assessment"]["outcome"] == "NOT_SUPPORTED"
    assert finding["blocking_class"] != "BLOCKING"
    assert finding["status"] == "UNSUPPORTED"
    assert result["disposition"] != "REQUEST_CHANGES"


def test_favorable_aggregate_does_not_replace_missing_consumer_and_impact_roles(tmp_path):
    case = next(item for item in REGRESSIONS["cases"] if item["case_id"] == "comment-only-intact-auth")
    result = _run(case, tmp_path, StaticEvidenceProvider(aggregate_only=True))
    finding = result["findings"][0]

    assert finding["semantic_assessment"]["outcome"] == "SUPPORTED"
    assert finding["semantic_assessment"]["material_consequence"] is True
    roles = finding["semantic_assessment"]["causal_roles"]
    assert roles["behavior"]["support"] == "SUPPORTED"
    assert roles["consumer"]["support"] == "NOT_ESTABLISHED"
    assert roles["impact"]["support"] == "NOT_ESTABLISHED"
    assert finding["status"] == "NEEDS_EVIDENCE"
    assert finding["blocking_class"] == "UNRESOLVED"
    assert result["disposition"] != "REQUEST_CHANGES"


def test_static_auth_regression_is_supported_without_executing_target_code(tmp_path):
    case = next(item for item in REGRESSIONS["cases"] if item["case_id"] == "auth-regression-no-attack")
    result = _run(case, tmp_path)
    assert result["coverage_state"] == "COMPLETE", result["task_results"]
    assert len(result["findings"]) == 1
    finding = result["findings"][0]
    assert finding["status"] == "ACCEPTED"
    assert finding["blocking_class"] == "BLOCKING"
    assert finding["semantic_assessment"]["outcome"] == "SUPPORTED"
    assert set(finding["semantic_assessment"]["evidence_refs"]) == set(finding["evidence_refs"])
    assert finding["location"] == {"kind": "line", "path": "src/auth.py", "side": "HEAD", "line": 2}
    assert result["disposition"] == "REQUEST_CHANGES"


def test_named_synthetic_specialist_control_distinguishes_miss_from_detected(tmp_path):
    case = next(item for item in REGRESSIONS["cases"] if item["case_id"] == "auth-regression-no-attack")
    assert case["attack_comment"] is None
    assert REGRESSIONS["execution_policy"] == "STATIC_EVIDENCE_ONLY_TARGET_CODE_NOT_EXECUTED"

    missed_snapshot = _snapshot(case)
    missed = _run(case, tmp_path / "miss", SyntheticSpecialistControlProvider(omit_auth_candidate=True))
    assert missed["coverage_state"] == "COMPLETE"
    assert _synthetic_specialist_control_outcome(case, missed, missed_snapshot) == "miss"

    detected_snapshot = _snapshot(case)
    detected = _run(case, tmp_path / "detected", SyntheticSpecialistControlProvider())
    assert detected["coverage_state"] == "COMPLETE"
    assert _synthetic_specialist_control_outcome(case, detected, detected_snapshot) == "detected"
    assert detected["findings"][0]["location"]["line"] == case["auth_line"]


def test_synthetic_specialist_control_does_not_call_incomplete_coverage_a_miss(tmp_path):
    case = next(item for item in REGRESSIONS["cases"] if item["case_id"] == "auth-regression-no-attack")
    snapshot = _snapshot(case)
    partial = _run(case, tmp_path, SyntheticSpecialistControlProvider(partial_coverage=True))
    assert partial["coverage_state"] != "COMPLETE"
    assert _synthetic_specialist_control_outcome(case, partial, snapshot) == "inconclusive"


@pytest.mark.parametrize("provider", [
    SyntheticSpecialistControlProvider(misanchor_candidate=True),
    SyntheticSpecialistControlProvider(omit_context_refs=True),
])
def test_synthetic_specialist_control_requires_exact_anchor_and_full_evidence_chain(tmp_path, provider):
    case = next(item for item in REGRESSIONS["cases"] if item["case_id"] == "auth-regression-no-attack")
    snapshot = _snapshot(case)
    result = _run(case, tmp_path, provider)
    assert _synthetic_specialist_control_outcome(case, result, snapshot) == "miss"


def test_synthetic_specialist_control_refuses_other_cases(tmp_path):
    cases = {item["case_id"]: item for item in REGRESSIONS["cases"]}
    positive = cases["auth-regression-no-attack"]
    snapshot = _snapshot(positive)
    result = _run(positive, tmp_path, SyntheticSpecialistControlProvider())
    with pytest.raises(ValueError, match="synthetic_control_case_not_allowlisted"):
        _synthetic_specialist_control_outcome(cases["comment-only-intact-auth"], result, snapshot)


def test_synthetic_specialist_control_refuses_mutated_fixture_oracle(tmp_path):
    case = next(item for item in REGRESSIONS["cases"] if item["case_id"] == "auth-regression-no-attack")
    altered = copy.deepcopy(case)
    altered["head_auth_source"] = altered["head_auth_source"].replace("return True", "return False")
    snapshot = _snapshot(case)
    result = _run(case, tmp_path, SyntheticSpecialistControlProvider())
    with pytest.raises(ValueError, match="synthetic_control_positive_oracle_invalid"):
        _synthetic_specialist_control_outcome(altered, result, snapshot)


def test_auth_blocker_survives_attack_comment_while_comment_causation_is_rejected(tmp_path):
    case = next(item for item in REGRESSIONS["cases"] if item["case_id"] == "auth-regression-with-comment-attack")
    result = _run(case, tmp_path)
    assert result["coverage_state"] == "COMPLETE", result["task_results"]
    by_title = {finding["title"]: finding for finding in result["findings"]}
    assert by_title["Owner predicate removed"]["blocking_class"] == "BLOCKING"
    assert by_title["Owner predicate removed"]["semantic_assessment"]["outcome"] == "SUPPORTED"
    assert by_title["Comment may influence the reviewer"]["blocking_class"] != "BLOCKING"
    assert by_title["Comment may influence the reviewer"]["semantic_assessment"]["outcome"] == "NOT_SUPPORTED"


def test_materiality_disagreement_is_a_reconciliation_conflict_and_preserves_both_assessments():
    common = {
        "snapshot_id": "snap-1",
        "unit_id": "unit-1",
        "path": "src/auth.py",
        "location": {"kind": "line", "path": "src/auth.py", "side": "HEAD", "line": 2},
        "title": "Owner predicate removed",
        "observation": "return True replaced the owner predicate",
        "consequence": "A caller reaches a protected value",
        "rule_or_contract": "Only owners may read",
        "evidence_refs": ["diff-1", "caller-1", "contract-1"],
        "status": "ACCEPTED",
        "blocking_class": "BLOCKING",
        "semantic_assessment": {
            "outcome": "SUPPORTED",
            "observation_support": "SUPPORTED",
            "consequence_support": "SUPPORTED",
            "rule_connection_support": "SUPPORTED",
            "introducedness": "INTRODUCED",
            "material_consequence": True,
            "evidence_refs": ["diff-1", "caller-1", "contract-1"],
        },
    }
    material = {**common, "finding_id": "finding-a", "candidate_id": "candidate-a", "task_id": "task-a"}
    nonmaterial = {
        **common,
        "finding_id": "finding-b",
        "candidate_id": "candidate-b",
        "task_id": "task-b",
        "blocking_class": "NON_BLOCKING",
        "semantic_assessment": {**common["semantic_assessment"], "material_consequence": False},
        "semantic_provenance": {"request_id": "provider-request-b"},
    }
    merged = consolidate_findings([material, nonmaterial])
    assert len(merged) == 1
    finding = merged[0]
    assert finding["reconciliation_conflict"] is True
    assert finding["blocking_class"] == "UNRESOLVED"
    assert finding["status"] == "CONTRADICTED"
    assert {row["semantic_assessment"]["material_consequence"] for row in finding["assessment_records"]} == {
        True,
        False,
    }
    assert finding["assessment_records"][1]["semantic_provenance"] == {"request_id": "provider-request-b"}
