import json
import os
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest


def git(path: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(path), *args], check=True, text=True, stdout=subprocess.PIPE).stdout.strip()


def fixture_repo(tmp_path: Path):
    repo = tmp_path / "repo"
    subprocess.run(["git", "init", str(repo)], check=True, stdout=subprocess.DEVNULL)
    git(repo, "config", "user.email", "fixture@example.invalid")
    git(repo, "config", "user.name", "Fixture")
    (repo / "a.py").write_text("x = 1\n")
    git(repo, "add", "a.py")
    git(repo, "-c", "core.hooksPath=/dev/null", "commit", "-m", "base")
    base = git(repo, "rev-parse", "HEAD")
    (repo / "a.py").write_text("x = 2\n")
    git(repo, "add", "a.py")
    git(repo, "-c", "core.hooksPath=/dev/null", "commit", "-m", "head")
    head = git(repo, "rev-parse", "HEAD")
    profile = tmp_path / "profile.json"
    profile.write_text(json.dumps({"version": "pilot-v1", "context_paths": []}))
    return repo, base, head, profile


class _InertContextProvider:
    identity = {"kind": "test-inert", "model": "no-network"}

    def review(self, task, evidence, limits):
        refs = [item["evidence_id"] for item in evidence]
        return {
            "payload": {
                "contract_version": "specialist-findings.v4",
                "finding_candidates": [],
                "context_gap_proposals": [],
                "coverage_notes": [
                    {
                        "unit_id": unit_id,
                        "state": "COVERED",
                        "reason_code": "TEST_INERT_EVIDENCE_BOUND",
                        "evidence_refs": refs,
                        "coverage_basis": "STATIC_REVIEW",
                    }
                    for unit_id in task["unit_ids"]
                ],
            },
            "usage": {"test_inert_invocation": 1},
            "provenance": {"network_calls": 0, "semantic_review_performed": False},
        }


class _FakeFreshness:
    def __init__(self, head):
        self.head = head

    def __call__(self):
        return {"freshness": "CURRENT", "observed_head_sha": self.head, "freshness_basis": "TEST_FAKE"}


def context_selection_repo(tmp_path: Path):
    repo = tmp_path / "context-selection-repo"
    subprocess.run(["git", "init", str(repo)], check=True, stdout=subprocess.DEVNULL)
    git(repo, "config", "user.email", "fixture@example.invalid")
    git(repo, "config", "user.name", "Fixture")
    (repo / "AGENTS.md").write_text("Review each change against its selected source evidence.\n")
    (repo / "src").mkdir()
    (repo / "src" / "auth.py").write_text("def allowed(user):\n    return user.active\n")
    git(repo, "add", "AGENTS.md", "src/auth.py")
    git(repo, "-c", "core.hooksPath=/dev/null", "commit", "-m", "base")
    base = git(repo, "rev-parse", "HEAD")
    (repo / "src" / "auth.py").write_text(
        "def allowed(user):\n    return user.active and user.tenant_id == owner.tenant_id\n"
    )
    git(repo, "add", "src/auth.py")
    git(repo, "-c", "core.hooksPath=/dev/null", "commit", "-m", "head")
    head = git(repo, "rev-parse", "HEAD")
    profile = {
        "version": "context-rebind-test-v1",
        "repository": "owner/project",
        "required_lenses": ["correctness"],
        "allow_empty_approve": True,
        "context_paths": ["AGENTS.md"],
        "trusted_policy_paths": ["AGENTS.md"],
        "context_selection": {
            "version": "context-selection.v1",
            "mandatory_policy_paths": ["AGENTS.md"],
            "max_total_context_bytes": 10_000,
            "window": {
                "before_lines": 1,
                "after_lines": 1,
                "max_bytes": 1_000,
                "max_windows_per_unit": 2,
                "max_scan_bytes": 10_000,
            },
            "bindings": [
                {
                    "unit_patterns": ["src/*.py"],
                    "lenses": ["correctness"],
                    "context_paths": [],
                    "max_context_bytes": 1_000,
                }
            ],
        },
    }
    return repo, base, head, profile


def run_cli(*argv, env=None):
    project = Path(__file__).parents[1]
    merged = dict(os.environ)
    merged["PYTHONPATH"] = str(project / "src")
    if env:
        merged.update(env)
    return subprocess.run(
        ["python3", "-m", "pr_review_harness", *map(str, argv)],
        cwd=project,
        env=merged,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def sealed_review(*, disposition="REQUEST_CHANGES", completed_at="2026-09-26T12:00:00Z", run_id="publish-cli-fixture"):
    from pr_review_harness.engine import _hash
    from pr_review_harness.reconcile import stable_candidate_id
    from pr_review_harness.report import render_report

    task_id = "task-review"
    evidence_id = "ev-1"
    candidate = {
        "unit_id": "unit-a",
        "location": {"kind": "line", "path": "src/a.py", "side": "HEAD", "line": 4, "reason": None},
        "title": "Unicode anchor: café",
        "observation": "The validated branch blocks unsafe input.",
        "consequence": "Malformed input can cross the trust boundary.",
        "rule_or_contract": "Input contract",
        "severity": "high",
        "evidence_refs": [evidence_id],
    }
    candidate_id = _hash({"task_id": task_id, "index": 0, "raw": candidate})[:24]
    normalized_candidate = {
        **candidate,
        "candidate_id": candidate_id,
        "task_id": task_id,
        "snapshot_id": "snapshot-publish-cli",
        "validation_state": "VALID",
        "validation_reason": "snapshot_location_and_evidence_validated",
    }
    finding_id = stable_candidate_id("snapshot-publish-cli", normalized_candidate)
    value = {
        "run_id": run_id,
        "snapshot_id": "snapshot-publish-cli",
        "repository": "owner/project",
        "pull_request_number": 7,
        "repository_url": "https://github.com/owner/project",
        "base_sha": "a" * 40,
        "head_sha": "b" * 40,
        "freshness": "CURRENT",
        "disposition": disposition,
        "merge_eligibility": "NOT_EVALUATED",
        "project_profile_version": "pilot-v1",
        "policy_valid": True,
        "allow_empty_approve": False,
        "coverage_state": "COMPLETE",
        "coverage_ledger": [{"obligation_id": "obligation-a", "required": True, "state": "COMPLETE"}],
        "completed_at": completed_at,
        "budget": {},
        "findings": [
            {
                "finding_id": finding_id,
                "candidate_id": candidate_id,
                "candidate_ids": [candidate_id],
                "task_id": task_id,
                "task_ids": [task_id],
                "snapshot_id": "snapshot-publish-cli",
                "unit_id": "unit-a",
                "status": "ACCEPTED",
                "blocking_class": "BLOCKING",
                "severity": "high",
                "location": candidate["location"],
                "path": "src/a.py",
                "evidence_refs": [evidence_id],
                "observation": candidate["observation"],
                "consequence": candidate["consequence"],
                "rule_or_contract": candidate["rule_or_contract"],
                "title": candidate["title"],
                "blocking_rationale": "Supported by source evidence.",
            }
        ],
        "report_sections": {
            "blockers": [
                {
                    "finding_id": finding_id,
                    "title": "Unicode anchor: café",
                    "path": "src/a.py",
                    "location": {"kind": "line", "path": "src/a.py", "side": "HEAD", "line": 4},
                    "observation": "The validated branch blocks unsafe input.",
                    "consequence": "Malformed input can cross the trust boundary.",
                    "rule_or_contract": "Input contract",
                    "evidence_refs": [evidence_id],
                }
            ],
            "suggested_improvements": [],
            "specific_strengths": [],
            "future_guidance": [],
        },
        "evidence_index": {
            evidence_id: {
                "path": "src/a.py",
                "line_start": 1,
                "line_end": 10,
                "source_revision": "b" * 40,
                "source_kind": "source_window",
                "content_hash": "c" * 64,
            }
        },
        "task_results": {
            task_id: {
                "status": "SUCCEEDED",
                "input_evidence_ids": [evidence_id],
                "payload": {"finding_candidates": [candidate]},
            }
        },
        "ledger": {
            "candidate_records": [
                {
                    "candidate_id": candidate_id,
                    "finding_id": finding_id,
                    "task_id": task_id,
                    "snapshot_id": "snapshot-publish-cli",
                    "validation_state": "VALID",
                    "raw": normalized_candidate,
                }
            ]
        },
    }
    value["rendered_review"] = render_report(value)
    value["result_hash"] = _hash(value)
    return value


def publisher_config(**extra):
    return {
        "schema_version": "1.0",
        "allowed_repositories": ["owner/project"],
        "allowed_dispositions": ["REQUEST_CHANGES"],
        "allowed_profile_versions": ["pilot-v1"],
        "max_review_body_bytes": 60000,
        **extra,
    }


def invoke_publish(tmp_path: Path, result: dict, config: dict, *flags: str, env=None):
    result_path = tmp_path / "result.json"
    config_path = tmp_path / "publisher.json"
    result_path.write_text(json.dumps(result), encoding="utf-8")
    config_path.write_text(json.dumps(config), encoding="utf-8")
    return run_cli(
        "publish",
        "--result",
        result_path,
        "--publisher-config",
        config_path,
        *flags,
        "--json",
        env=env,
    )


def test_module_help_and_dry_run_are_real_cli_paths(tmp_path):
    repo, base, head, profile = fixture_repo(tmp_path)
    help_run = run_cli("--help")
    assert help_run.returncode == 0 and "review" in help_run.stdout
    publish_help = run_cli("publish", "--help")
    assert publish_help.returncode == 0
    assert "Live publication currently fails closed" in publish_help.stdout
    assert "--effect-store" not in publish_help.stdout
    preview = run_cli(
        "review", "--repo", repo, "--base", base, "--head", head, "--profile", profile, "--dry-run", "--json"
    )
    assert preview.returncode == 0
    value = json.loads(preview.stdout)
    assert value["base"] == base and value["head"] == head
    assert value["profile_path"] == str(profile.resolve())
    assert not (tmp_path / "artifacts").exists()
    bad = run_cli("review", "--repo", repo, "--json")
    assert bad.returncode == 2 and json.loads(bad.stdout)["error"] == "invalid_arguments"


def test_github_event_metadata_is_checked_and_publish_is_rejected(tmp_path):
    repo, base, head, profile = fixture_repo(tmp_path)
    event_path = tmp_path / "event.json"
    event_path.write_text(json.dumps({"number": 7, "pull_request": {"base": {"sha": base}, "head": {"sha": head}}}))
    gh = tmp_path / "bin" / "gh"
    gh.parent.mkdir()
    gh.write_text(
        "#!/bin/sh\n"
        'case "$*" in\n'
        f"  *check-runs*) printf '%s\\n' '{{\"total_count\":0,\"check_runs\":[]}}' ;;\n"
        f'  *) printf \'%s\\n\' \'{{"number":7,"state":"open","draft":false,'
        f'"base":{{"sha":"{base}","repo":{{"full_name":"owner/project","html_url":"https://github.com/owner/project"}}}},'
        f'"head":{{"sha":"{head}"}}}}\' ;;\n'
        "esac\n"
    )
    gh.chmod(0o755)
    env = {
        "GITHUB_EVENT_PATH": str(event_path),
        "GITHUB_REPOSITORY": "owner/project",
        "GITHUB_RUN_ID": "9",
        "PATH": f"{gh.parent}:{os.environ['PATH']}",
    }
    good = run_cli(
        "review",
        "--repo",
        repo,
        "--base",
        base,
        "--head",
        head,
        "--profile",
        profile,
        "--run-id",
        "event-9",
        "--output",
        tmp_path / "out",
        "--json",
        env=env,
    )
    assert good.returncode == 0
    result = json.loads(good.stdout)
    assert result["run_id"] == "event-9" and result["freshness"] == "CURRENT"
    assert result["freshness_details"]["freshness_basis"] == "GITHUB_API"
    assert result["snapshot_id"] and Path(result["artifact_path"]).is_file()
    assert Path(result["report_path"]).is_file()
    wrong = run_cli(
        "review",
        "--repo",
        repo,
        "--base",
        base,
        "--head",
        base,
        "--profile",
        profile,
        "--event-file",
        event_path,
        "--json",
        env=env,
    )
    assert wrong.returncode == 2
    assert json.loads(wrong.stdout)["error"] == "requested revisions do not match the GitHub event"
    publish = run_cli(
        "review",
        "--repo",
        repo,
        "--base",
        base,
        "--head",
        head,
        "--profile",
        profile,
        "--effect-policy",
        "PUBLISH_REVIEW",
        "--json",
    )
    assert publish.returncode == 2 and json.loads(publish.stdout)["exit_code"] == 2


def test_publish_is_stateless_preview_without_sqlite_fields_or_github_reads(tmp_path):
    result = sealed_review()
    config = publisher_config()
    config.pop("allowed_profile_versions")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    gh_calls = tmp_path / "gh-calls"
    fake_gh = bin_dir / "gh"
    fake_gh.write_text(
        f"#!/bin/sh\necho call >> {gh_calls}\nexit 97\n",
        encoding="utf-8",
    )
    fake_gh.chmod(0o755)
    env = {"PATH": f"{bin_dir}:{os.environ['PATH']}", "GITHUB_ACTIONS": "true", "GITHUB_ACTOR": "attacker"}

    run = invoke_publish(tmp_path, result, config, env=env)
    assert run.returncode == 0, run.stderr
    preview = json.loads(run.stdout)
    assert preview["status"] == "PREVIEW_ONLY"
    assert preview["dry_run"] is True
    assert preview["live_effects_performed"] is False
    assert preview["publication_capability"] == "UNAVAILABLE"
    assert preview["actor_identity"] == "NOT_CHECKED"
    assert preview["freshness"] == "NOT_CHECKED"
    assert preview["effect_store_accessed"] is False
    assert preview["request"]["review_payload"]["event"] == "REQUEST_CHANGES"
    assert "Unicode anchor" in preview["request"]["review_payload"]["body"]
    assert "café" in preview["request"]["review_payload"]["body"]
    assert "pr-review-harness:" in preview["request"]["review_payload"]["body"]
    assert "effect_store_path" not in config
    assert "serialization_mode" not in config
    assert not gh_calls.exists()
    assert not (tmp_path / "effects.sqlite").exists()


def test_publish_authorization_flag_fails_closed_in_any_environment(tmp_path):
    result = sealed_review()
    config = publisher_config()
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    gh_calls = tmp_path / "gh-calls"
    fake_gh = bin_dir / "gh"
    fake_gh.write_text(f"#!/bin/sh\necho call >> {gh_calls}\nexit 97\n", encoding="utf-8")
    fake_gh.chmod(0o755)
    for actions_value in ("false", "true"):
        env = {"PATH": f"{bin_dir}:{os.environ['PATH']}", "GITHUB_ACTIONS": actions_value}
        run = invoke_publish(tmp_path, result, config, "--authorize-publish", env=env)
        assert run.returncode == 2
        assert json.loads(run.stdout) == {
            "error": "stateless publication capability is unavailable",
            "exit_code": 2,
        }
    assert not gh_calls.exists()
    assert not (tmp_path / "effects.sqlite").exists()


def test_publish_rejects_legacy_sqlite_configuration_instead_of_implying_it_is_used(tmp_path):
    result = sealed_review()
    config = publisher_config(effect_store_path=str(tmp_path / "effects.sqlite"))
    run = invoke_publish(tmp_path, result, config)
    assert run.returncode == 2
    assert json.loads(run.stdout)["error"] == "preflight_rejected"
    assert not (tmp_path / "effects.sqlite").exists()


def test_incomplete_result_preview_preserves_disposition_and_uses_comment_event(tmp_path):
    from pr_review_harness.engine import _hash
    from pr_review_harness.report import render_report

    reviewed = sealed_review()
    reviewed["coverage_state"] = "PARTIAL"
    reviewed["coverage_ledger"][0]["state"] = "PARTIAL"
    reviewed["findings"][0]["blocking_class"] = "NON_BLOCKING"
    reviewed["report_sections"]["suggested_improvements"].append(reviewed["report_sections"]["blockers"].pop())
    reviewed["disposition"] = "INCOMPLETE"
    reviewed["rendered_review"] = render_report(reviewed)
    reviewed.pop("result_hash")
    reviewed["result_hash"] = _hash(reviewed)

    run = invoke_publish(
        tmp_path,
        reviewed,
        publisher_config(allowed_dispositions=["COMMENT"]),
    )
    assert run.returncode == 0, run.stderr
    request = json.loads(run.stdout)["request"]
    assert request["disposition"] == "INCOMPLETE"
    assert request["review_event"] == "COMMENT"
    assert request["review_payload"]["event"] == "COMMENT"


def test_publish_rejects_tampered_and_incompatible_results_without_github_reads(tmp_path):
    tampered = sealed_review()
    tampered["disposition"] = "APPROVE"
    run = invoke_publish(tmp_path, tampered, publisher_config())
    assert run.returncode == 2
    assert json.loads(run.stdout)["error"] == "preflight_rejected"

    incompatible = sealed_review()
    config = publisher_config(allowed_profile_versions=["other-profile"])
    run = invoke_publish(tmp_path, incompatible, config)
    assert run.returncode == 2
    assert not (tmp_path / "effects.sqlite").exists()


@pytest.mark.parametrize("mutation", ["empty_required_coverage", "unbound_accepted_finding"])
def test_publish_rejects_rehashed_but_semantically_unproven_result(mutation, tmp_path):
    from pr_review_harness.engine import _hash
    from pr_review_harness.report import render_report

    reviewed = sealed_review()
    if mutation == "empty_required_coverage":
        reviewed["coverage_ledger"] = []
    else:
        reviewed["findings"][0]["evidence_refs"] = ["unbound-evidence"]
    reviewed["rendered_review"] = render_report(reviewed)
    reviewed.pop("result_hash")
    reviewed["result_hash"] = _hash(reviewed)
    run = invoke_publish(tmp_path, reviewed, publisher_config())
    assert run.returncode == 2
    assert json.loads(run.stdout)["error"] == "preflight_rejected"


def test_publish_result_must_resolve_inside_optional_trusted_artifact_root(tmp_path):
    other = tmp_path / "elsewhere"
    other.mkdir()
    result_path = other / "review.json"
    result_path.write_text(json.dumps(sealed_review()), encoding="utf-8")
    trusted_root = tmp_path / "trusted"
    trusted_root.mkdir()
    config_path = tmp_path / "publisher.json"
    config_path.write_text(
        json.dumps(publisher_config(trusted_result_root=str(trusted_root.resolve()))), encoding="utf-8"
    )
    run = run_cli("publish", "--result", result_path, "--publisher-config", config_path, "--json")
    assert run.returncode == 2
    assert json.loads(run.stdout)["error"] == "preflight_rejected"


def test_cli_ingests_head_bound_external_check_evidence(tmp_path):
    repo, base, head, profile_path = fixture_repo(tmp_path)
    profile = json.loads(profile_path.read_text())
    profile["required_checks"] = [
        {
            "id": "tests",
            "binding": "github:tests",
            "patterns": ["a.py"],
            "github_check_name": "unit-tests",
            "github_app_id": 42,
        }
    ]
    profile_path.write_text(json.dumps(profile))
    event_path = tmp_path / "event.json"
    event_path.write_text(json.dumps({"number": 7, "pull_request": {"base": {"sha": base}, "head": {"sha": head}}}))
    checks_path = tmp_path / "checks.json"
    checks_path.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "repository": "owner/project",
                "pull_request_number": 7,
                "head_sha": head,
                "captured_at": "2026-09-26T12:01:00Z",
                "complete": True,
                "runs": [
                    {
                        "id": 99,
                        "name": "unit-tests",
                        "status": "completed",
                        "conclusion": "success",
                        "head_sha": head,
                        "app_id": 42,
                        "completed_at": "2026-09-26T12:00:00Z",
                    }
                ],
            }
        )
    )
    gh = tmp_path / "bin" / "gh"
    gh.parent.mkdir()
    gh.write_text(
        "#!/bin/sh\n"
        f'printf \'%s\\n\' \'{{"number":7,"state":"open","base":{{"sha":"{base}",'
        f'"repo":{{"full_name":"owner/project","html_url":"https://github.com/owner/project"}}}},'
        f'"head":{{"sha":"{head}"}}}}\'\n'
    )
    gh.chmod(0o755)
    env = {
        "GITHUB_EVENT_PATH": str(event_path),
        "GITHUB_REPOSITORY": "owner/project",
        "GITHUB_RUN_ID": "10",
        "PATH": f"{gh.parent}:{os.environ['PATH']}",
    }
    run = run_cli(
        "review",
        "--repo",
        repo,
        "--base",
        base,
        "--head",
        head,
        "--profile",
        profile_path,
        "--checks-json",
        checks_path,
        "--run-id",
        "check-10",
        "--output",
        tmp_path / "out",
        "--json",
        env=env,
    )
    assert run.returncode == 0, run.stdout
    result = json.loads(run.stdout)
    check_results = [
        task_result["payload"]
        for task_result in result["task_results"].values()
        if task_result.get("payload", {}).get("check_id") == "tests"
    ]
    assert len(check_results) == 1
    assert check_results[0]["outcome"] == "PASS"
    assert check_results[0]["evidence_refs"]


def test_historical_check_evidence_cli_uses_historical_freshness_without_event_api(tmp_path, monkeypatch, capsys):
    from pr_review_harness import cli, github
    from pr_review_harness.checks import make_check_runs_document

    repo, base, head, profile_path = fixture_repo(tmp_path)
    profile_path.write_text(
        json.dumps(
            {
                "version": "historical-check-v1",
                "repository": "owner/project",
                "allow_empty_approve": True,
                "required_lenses": [],
                "required_checks": [
                    {
                        "id": "tests",
                        "patterns": ["a.py"],
                        "binding": "external:tests",
                        "github_check_name": "unit-tests",
                        "github_app_id": 42,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    check_path = tmp_path / "checks.json"
    check_path.write_text(
        json.dumps(
            make_check_runs_document(
                "owner/project",
                7,
                head,
                [
                    {
                        "id": 99,
                        "name": "unit-tests",
                        "status": "completed",
                        "conclusion": "success",
                        "head_sha": head,
                        "app_id": 42,
                        "completed_at": "2026-09-26T12:00:00Z",
                    }
                ],
                captured_at="2026-09-26T12:01:00Z",
            )
        ),
        encoding="utf-8",
    )

    def forbidden_api_adapter(*_args, **_kwargs):
        raise AssertionError("historical check mode must not construct GitHub API adapters")

    monkeypatch.delenv("GITHUB_EVENT_PATH", raising=False)
    monkeypatch.delenv("GITHUB_REPOSITORY", raising=False)
    monkeypatch.setattr(github, "GitHubPRAdapter", forbidden_api_adapter)
    monkeypatch.setattr(github, "GitHubFreshnessCheck", forbidden_api_adapter)
    exit_code = cli.main(
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
            "--historical-checks-json",
            str(check_path),
            "--run-id",
            "historical-check-7",
            "--output",
            str(tmp_path / "historical-out"),
            "--json",
        ]
    )

    assert exit_code == 0
    result = json.loads(capsys.readouterr().out)
    assert result["repository"] == "owner/project"
    assert result["pull_request_number"] == 7
    assert result["freshness"] == "CURRENT"
    assert result["freshness_details"]["freshness_basis"] == "HISTORICAL_SNAPSHOT"
    check = next(row for row in result["coverage_ledger"] if row["obligation_kind"] == "PROJECT_CHECK")
    assert check["state"] == "COMPLETE"
    assert len(check["evidence_refs"]) == 1


@pytest.mark.parametrize("binding_mode", ["event", "historical"])
def test_cli_identity_rebinding_preserves_selected_evidence_and_file_anchor(tmp_path, monkeypatch, binding_mode):
    from pr_review_harness import cli, engine
    from pr_review_harness.checks import make_check_runs_document

    repo, base, head, profile = context_selection_repo(tmp_path)
    args = SimpleNamespace(
        effect_policy="READ_ONLY",
        repo=str(repo),
        mode="AUTO",
        output=str(tmp_path / f"out-{binding_mode}"),
        resume=False,
    )
    limits = {
        "deadline_seconds": 2,
        "max_concurrent_scopes": 2,
        "max_provider_calls": 8,
        "max_retries_per_task": 0,
        "max_context_bytes": 64_000,
        "max_input_bytes_per_task": 32_000,
        "max_output_bytes_per_task": 8_000,
        "max_output_bytes": 16_000,
        "max_context_retrievals": 0,
        "max_followup_tasks": 0,
    }
    event = None
    check_document = None
    historical_identity = None
    if binding_mode == "event":
        event = {
            "repository": "owner/project",
            "pull_request_number": 7,
            "event_id": "offline-context-event",
            "base_sha": base,
            "head_sha": head,
            "repository_url": "https://github.com/owner/project",
        }
    else:
        historical_identity = {
            "repository": "owner/project",
            "pull_request_number": 7,
            "head_sha": head,
            "base_sha": base,
        }
        check_document = make_check_runs_document("owner/project", 7, head, [], captured_at="2026-09-26T12:00:00Z")

    monkeypatch.setattr(
        cli, "_freshness", lambda current_event, expected: _FakeFreshness(expected) if current_event else None
    )
    captured = {}
    real_run_review = engine.run_review

    def capture_run_review(snapshot, plan, *call_args, **call_kwargs):
        captured["snapshot"] = snapshot
        captured["plan"] = plan
        return real_run_review(snapshot, plan, *call_args, **call_kwargs)

    monkeypatch.setattr(engine, "run_review", capture_run_review)
    result = cli._run_one(
        args,
        base,
        head,
        profile,
        limits,
        _InertContextProvider(),
        None,
        f"context-{binding_mode}",
        event,
        check_document,
        historical_identity,
    )

    snapshot = captured["snapshot"]
    assert result["snapshot_id"] == snapshot["snapshot_id"]
    assert snapshot["snapshot_id"] != ""
    if binding_mode == "historical":
        assert snapshot["freshness_basis"] == "HISTORICAL_SNAPSHOT"
    assert len(snapshot["inventory"]) == 1
    unit = snapshot["inventory"][0]
    evidence = snapshot["evidence"]
    for field in ("evidence_ids", "review_context_evidence_ids"):
        assert unit[field]
        for evidence_id in unit[field]:
            assert evidence_id in evidence
            assert evidence[evidence_id]["evidence_id"] == evidence_id
            assert evidence[evidence_id]["snapshot_id"] == snapshot["snapshot_id"]
    anchor = unit["file_level_location"]
    assert anchor["evidence_id"] in unit["evidence_ids"]
    anchor_record = evidence[anchor["evidence_id"]]
    assert anchor["evidence_hash"] == anchor_record["content_hash"]
    assert anchor["path"] == anchor_record["path"]
    expected_revision = snapshot["base_sha"] if anchor["side"] == "BASE" else snapshot["head_sha"]
    assert anchor_record["source_revision"] == expected_revision
    assert snapshot["trusted_context_refs"]
    for evidence_id in snapshot["trusted_context_refs"]:
        assert evidence_id in evidence
        assert evidence[evidence_id]["evidence_id"] == evidence_id
        assert evidence[evidence_id]["snapshot_id"] == snapshot["snapshot_id"]

    selected_ids = set(unit["review_context_evidence_ids"])
    assert any(evidence[eid]["source_kind"] == "source_window" for eid in selected_ids)
    planned_tasks = [task for task in captured["plan"]["tasks"] if unit["unit_id"] in task.get("unit_ids", [])]
    assert planned_tasks and any(selected_ids.issubset(set(task["evidence_ids"])) for task in planned_tasks)
    successful_tasks = [
        row
        for row in result["task_results"].values()
        if row.get("status") == "SUCCEEDED" and unit["unit_id"] in row.get("unit_ids", [])
    ]
    assert successful_tasks
    assert any(selected_ids.issubset(set(row["input_evidence_ids"])) for row in successful_tasks)
    assert result["coverage_state"] == "COMPLETE"


@pytest.mark.parametrize(
    "mutation",
    [
        "repository",
        "head",
        "base",
        "boolean_pr",
        "no_base",
        "no_head",
        "profile_repository_missing",
        "too_many_runs",
        "duplicate_key",
        "nonfinite",
        "overflow_float",
        "deep_json",
        "oversize",
        "event_env",
        "event_file",
        "github_pr",
        "both_check_flags",
    ],
)
def test_historical_check_evidence_cli_rejects_unbound_identity_before_run(tmp_path, mutation):
    from pr_review_harness.checks import make_check_runs_document

    repo, base, head, profile_path = fixture_repo(tmp_path)
    profile_value = {
        "version": "historical-check-v1",
        "repository": "owner/project",
        "required_lenses": [],
        "required_checks": [],
    }
    if mutation == "profile_repository_missing":
        profile_value.pop("repository")
    profile_path.write_text(json.dumps(profile_value), encoding="utf-8")
    document = make_check_runs_document("owner/project", 7, head, [], captured_at="2026-09-26T12:01:00Z")
    if mutation == "repository":
        document["repository"] = "owner/other"
    elif mutation == "head":
        document["head_sha"] = "d" * 40
    elif mutation == "base":
        document["base_sha"] = "e" * 40
    elif mutation == "boolean_pr":
        document["pull_request_number"] = True
    elif mutation == "too_many_runs":
        document["runs"] = [{}] * 2_001
    checks_path = tmp_path / "checks.json"
    if mutation == "duplicate_key":
        checks_path.write_text('{"schema_version":"1.0","schema_version":"1.0"}', encoding="utf-8")
    elif mutation == "nonfinite":
        checks_path.write_text('{"value":NaN}', encoding="utf-8")
    elif mutation == "overflow_float":
        checks_path.write_text('{"value":1e9999}', encoding="utf-8")
    elif mutation == "deep_json":
        checks_path.write_text("[" * 2_000 + "0" + "]" * 2_000, encoding="utf-8")
    elif mutation == "oversize":
        checks_path.write_text(" " * 2_000_001, encoding="utf-8")
    else:
        checks_path.write_text(json.dumps(document), encoding="utf-8")
    args = ["review", "--repo", str(repo)]
    if mutation != "no_base":
        args.extend(("--base", base))
    if mutation != "no_head":
        args.extend(("--head", head))
    args.extend(
        [
            "--profile",
            str(profile_path),
            "--historical-checks-json",
            str(checks_path),
            "--output",
            str(tmp_path / "never-created"),
            "--json",
        ]
    )
    if mutation == "both_check_flags":
        args.extend(("--checks-json", str(checks_path)))
    env = {"GITHUB_EVENT_PATH": "", "GITHUB_REPOSITORY": ""}
    if mutation == "event_env":
        env["GITHUB_EVENT_PATH"] = str(tmp_path / "event.json")
    if mutation == "event_file":
        args.extend(("--event-file", str(tmp_path / "event.json")))
    if mutation == "github_pr":
        args.extend(("--github-pr", "owner/project#7"))

    completed = run_cli(*args, env=env)

    assert completed.returncode == 2
    assert '"error":"preflight_rejected"' in completed.stdout
    assert not (tmp_path / "never-created").exists()


def test_historical_check_evidence_is_not_accepted_by_recent_command(tmp_path):
    repo, _base, _head, profile_path = fixture_repo(tmp_path)
    profile_path.write_text(json.dumps({"version": "pilot-v1", "repository": "owner/project"}), encoding="utf-8")
    checks_path = tmp_path / "checks.json"
    checks_path.write_text("{}", encoding="utf-8")
    completed = run_cli(
        "recent",
        "--repo",
        repo,
        "--profile",
        profile_path,
        "--historical-checks-json",
        checks_path,
        "--json",
        env={"GITHUB_EVENT_PATH": ""},
    )
    assert completed.returncode == 2
    assert '"error":"preflight_rejected"' in completed.stdout
