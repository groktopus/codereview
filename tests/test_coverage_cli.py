"""Targeted refusal/validation coverage for :mod:`pr_review_harness.cli`.

These tests exercise cheap, in-process guard branches (typed errors and emitted
output shape) without dispatch, network access, credentials, or production
effects. Reusable review/publisher fixtures come from ``test_cli``.
"""

import json
import os
import stat
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from test_cli import publisher_config, sealed_review

from pr_review_harness import cli

BASE = "a" * 40


@pytest.fixture(autouse=True)
def _local_cli_environment(monkeypatch):
    """These branch tests exercise local CLI behavior, not GitHub Actions."""
    for name in (
        "GITHUB_ACTIONS",
        "GITHUB_EVENT_PATH",
        "GITHUB_REPOSITORY",
        "GITHUB_SHA",
        "GITHUB_RUN_ID",
        "GITHUB_RUN_ATTEMPT",
        "GITHUB_REF",
    ):
        monkeypatch.delenv(name, raising=False)


HEAD = "b" * 40


def _write_json(path: Path, value) -> Path:
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def _profile_file(tmp_path: Path) -> Path:
    return _write_json(tmp_path / "profile.json", {"version": "coverage-v1", "context_paths": []})


def _event_file(tmp_path: Path, *, number=7, base=BASE, head=HEAD) -> Path:
    return _write_json(
        tmp_path / "event.json",
        {"number": number, "pull_request": {"base": {"sha": base}, "head": {"sha": head}}},
    )


# ---------------------------------------------------------------------------
# bounded JSON readers
# ---------------------------------------------------------------------------


def test_load_json_rejects_unreadable_and_non_object_documents(tmp_path):
    with pytest.raises(ValueError, match="cannot read limits JSON"):
        cli._load_json(str(tmp_path / "missing.json"), "limits")
    invalid = tmp_path / "invalid.json"
    invalid.write_text("{", encoding="utf-8")
    with pytest.raises(ValueError, match="cannot read limits JSON"):
        cli._load_json(str(invalid), "limits")
    array = _write_json(tmp_path / "array.json", [])
    with pytest.raises(ValueError, match="limits must be a JSON object"):
        cli._load_json(str(array), "limits")


def test_read_private_json_bounds_regular_files_and_json_shape(tmp_path):
    valid = _write_json(tmp_path / "plan.json", {"ok": True})
    parsed, digest = cli._read_private_json(str(valid), 1024)
    assert parsed == {"ok": True}
    assert len(digest) == 64

    with pytest.raises(ValueError, match="private shadow plan unavailable"):
        cli._read_private_json(str(tmp_path / "absent.json"), 1024)
    with pytest.raises(ValueError, match="private shadow plan unavailable"):
        cli._read_private_json(str(tmp_path), 1024)
    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b"x" * 10)
    with pytest.raises(ValueError, match="private shadow plan unavailable"):
        cli._read_private_json(str(oversized), 5)
    link = tmp_path / "link.json"
    link.symlink_to(valid)
    with pytest.raises(ValueError, match="private shadow plan unavailable"):
        cli._read_private_json(str(link), 1024)

    for name, payload in (
        ("invalid.json", b"{"),
        ("array.json", b"[]"),
        ("duplicate.json", b'{"a":1,"a":2}'),
        ("nonfinite.json", b'{"a":Infinity}'),
    ):
        candidate = tmp_path / name
        candidate.write_bytes(payload)
        with pytest.raises(ValueError, match="private shadow plan invalid"):
            cli._read_private_json(str(candidate), 1024)


def test_read_private_json_rejects_identity_change_and_size_overrun(tmp_path, monkeypatch):
    valid = _write_json(tmp_path / "plan.json", {"ok": True})
    original_fstat = os.fstat
    monkeypatch.setattr(
        cli.os,
        "fstat",
        lambda _fd: SimpleNamespace(st_mode=stat.S_IFREG, st_dev=0, st_ino=0, st_size=1),
    )
    with pytest.raises(ValueError, match="private shadow plan unavailable"):
        cli._read_private_json(str(valid), 1024)
    monkeypatch.setattr(cli.os, "fstat", original_fstat)

    original_read = os.read
    monkeypatch.setattr(cli.os, "read", lambda _fd, _size: b"y" * 200)
    with pytest.raises(ValueError, match="private shadow plan unavailable"):
        cli._read_private_json(str(valid), 100)
    monkeypatch.setattr(cli.os, "read", original_read)


def test_load_historical_checks_rejects_unbounded_or_malformed_documents(tmp_path):
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text('{"a":1,"a":2}', encoding="utf-8")
    with pytest.raises(ValueError, match="cannot read bounded historical check evidence JSON"):
        cli._load_historical_checks(str(duplicate))

    for name, payload in (
        ("nan.json", '{"a":NaN}'),
        ("inf.json", '{"a":1e999}'),
        ("invalid-utf8.json", None),
        ("invalid.json", "{"),
    ):
        candidate = tmp_path / name
        if payload is None:
            candidate.write_bytes(b"\xff")
        else:
            candidate.write_text(payload, encoding="utf-8")
        with pytest.raises(ValueError, match="cannot read bounded historical check evidence JSON"):
            cli._load_historical_checks(str(candidate))

    huge = tmp_path / "huge.json"
    huge.write_bytes(b"{" + b" " * cli.MAX_HISTORICAL_CHECKS_BYTES + b"}")
    with pytest.raises(ValueError, match="cannot read bounded historical check evidence JSON"):
        cli._load_historical_checks(str(huge))

    array = _write_json(tmp_path / "array.json", [])
    with pytest.raises(ValueError, match="historical check evidence must be a JSON object"):
        cli._load_historical_checks(str(array))


def test_bounded_json_tree_rejects_depth_node_and_nonfinite_limits(tmp_path):
    deep = tmp_path / "deep.json"
    deep.write_text("[" * 70 + "0" + "]" * 70, encoding="utf-8")
    with pytest.raises(ValueError, match="JSON structure exceeds limits"):
        cli._load_historical_checks(str(deep))
    wide = _write_json(tmp_path / "wide.json", [0] * 100_001)
    with pytest.raises(ValueError, match="JSON structure exceeds limits"):
        cli._load_historical_checks(str(wide))
    with pytest.raises(ValueError, match="non-finite JSON number"):
        cli._validate_bounded_json_tree([float("nan")])


# ---------------------------------------------------------------------------
# private shadow plan/preflight path guards
# ---------------------------------------------------------------------------


def test_private_shadow_pins_current_source_requires_trusted_workflow(tmp_path, monkeypatch):
    from pr_review_harness import current_source_capture as capture

    plan = _write_json(tmp_path / "plan.json", {})
    receipt = _write_json(tmp_path / "receipt.json", {})
    for name in (
        "GITHUB_ACTIONS",
        "GITHUB_REPOSITORY",
        "GITHUB_EVENT_NAME",
        "GITHUB_REF",
        "GITHUB_WORKFLOW_REF",
    ):
        monkeypatch.delenv(name, raising=False)
    with pytest.raises(ValueError, match="current source capture requires the trusted main-branch workflow"):
        cli._load_private_shadow_pins(str(plan), str(receipt), current_source=True)

    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_REPOSITORY", "groktopus/codereview")
    monkeypatch.setenv("GITHUB_EVENT_NAME", "workflow_dispatch")
    monkeypatch.setenv("GITHUB_REF", "refs/heads/main")
    monkeypatch.setenv("GITHUB_WORKFLOW_REF", cli.TRUSTED_CURRENT_SOURCE_CAPTURE_WORKFLOW_REF)
    monkeypatch.setattr(capture, "installed_module_inventory", lambda: {})

    def mismatch(*_args, **_kwargs):
        raise capture.CurrentSourceCaptureError("plan_source_invalid")

    monkeypatch.setattr(capture, "validate_plan", mismatch)
    with pytest.raises(ValueError, match="current source plan or receipt mismatch"):
        cli._load_private_shadow_pins(str(plan), str(receipt), current_source=True)

    pins = {"task-1": {"task_id": "task-1"}}
    snapshot_pin = {"case_id": "PR-457"}
    monkeypatch.setattr(capture, "validate_plan", lambda *_a, **_k: (pins, snapshot_pin))
    assert cli._load_private_shadow_pins(str(plan), str(receipt), current_source=True) == (pins, snapshot_pin)


def test_canonical_private_input_path_rejects_relative_symlink_and_missing(tmp_path):
    with pytest.raises(ValueError, match="trusted private preflight paths required"):
        cli._canonical_private_input_path("relative/path")
    with pytest.raises(ValueError, match="trusted private preflight paths required"):
        cli._canonical_private_input_path(str(tmp_path / "missing.json"))
    target = tmp_path / "target.json"
    target.write_text("{}", encoding="utf-8")
    link = tmp_path / "link.json"
    link.symlink_to(target)
    with pytest.raises(ValueError, match="trusted private preflight paths required"):
        cli._canonical_private_input_path(str(link))
    assert cli._canonical_private_input_path(str(target)) == target


def test_trusted_private_plan_paths_require_exact_workflow_locations(tmp_path, monkeypatch):
    workspace = tmp_path / "workspace"
    runner_temp = tmp_path / "runner-temp"
    workspace.mkdir()
    runner_temp.mkdir()
    plan = _write_json(workspace / "plan.json", {})
    receipt = _write_json(runner_temp / "receipt.json", {})

    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.delenv("GITHUB_WORKSPACE", raising=False)
    monkeypatch.delenv("RUNNER_TEMP", raising=False)
    with pytest.raises(ValueError, match="trusted private preflight paths unavailable"):
        cli._validate_trusted_private_plan_paths(str(plan), str(receipt), "PR-457")

    monkeypatch.setenv("GITHUB_WORKSPACE", str(workspace))
    monkeypatch.setenv("RUNNER_TEMP", str(runner_temp))
    monkeypatch.setenv("GITHUB_WORKFLOW_REF", "untrusted/workflow.yml@refs/heads/main")
    with pytest.raises(ValueError, match="current source plan paths require the fixed PR-457 workflow"):
        cli._validate_trusted_private_plan_paths(str(plan), str(receipt), "PR-464", current_source=True)

    with pytest.raises(ValueError, match="trusted private preflight paths required"):
        cli._validate_trusted_private_plan_paths(str(plan), str(receipt), "PR-457")

    trusted_plan = _write_json(runner_temp / "pr457-current-source-plan.json", {})
    trusted_receipt = _write_json(runner_temp / "pr457-current-source-receipt.json", {})
    monkeypatch.setenv("GITHUB_WORKFLOW_REF", cli.TRUSTED_CURRENT_SOURCE_CAPTURE_WORKFLOW_REF)
    assert (
        cli._validate_trusted_private_plan_paths(str(trusted_plan), str(trusted_receipt), "PR-457", current_source=True)
        is None
    )


# ---------------------------------------------------------------------------
# limits, run ids, diagnostics, emit
# ---------------------------------------------------------------------------


def test_limits_schema_and_run_id_validation(tmp_path):
    limits = _write_json(tmp_path / "limits.json", {"schema_version": "9.9"})
    with pytest.raises(ValueError, match="unsupported limits schema version"):
        cli._read_limits(SimpleNamespace(limits=str(limits)))
    with pytest.raises(ValueError, match="run_id must be 1 to 128 safe filename characters"):
        cli._validate_run_id("bad/id")


def test_diagnostic_artifact_path_only_returns_derived_regular_files(tmp_path):
    assert cli._diagnostic_artifact_path(str(tmp_path) + "\n", "run") is None
    assert cli._diagnostic_artifact_path(tmp_path, "run") is None
    directory = tmp_path / "run.json"
    directory.mkdir()
    assert cli._diagnostic_artifact_path(tmp_path, "run") is None
    result = tmp_path / "done.json"
    result.write_text("{}", encoding="utf-8")
    assert cli._diagnostic_artifact_path(tmp_path, "done") == str(result)


def test_emit_selects_json_summary_and_pretty_shapes(capsys):
    cli._emit(SimpleNamespace(json=True), {"b": 1, "a": 2})
    assert capsys.readouterr().out == '{"a":2,"b":1}\n'
    cli._emit(SimpleNamespace(json=False), {"summary": "done", "other": 1})
    assert capsys.readouterr().out == "done\n"
    cli._emit(SimpleNamespace(json=False), {"a": 1})
    assert '"a": 1' in capsys.readouterr().out


# ---------------------------------------------------------------------------
# event and GitHub PR parsing
# ---------------------------------------------------------------------------


def test_event_parsing_refusals_and_success(tmp_path, monkeypatch):
    args = SimpleNamespace(event_file=None, github_pr=None, base=None, head=None)
    monkeypatch.delenv("GITHUB_EVENT_PATH", raising=False)
    assert cli._event(args, None, None) is None

    invalid = _write_json(tmp_path / "no-pr.json", {"number": 1})
    with pytest.raises(ValueError, match="GitHub event is not a pull_request event"):
        cli._event(SimpleNamespace(event_file=str(invalid), github_pr=None, base=None, head=None), None, None)
    boolean = _write_json(
        tmp_path / "boolean.json",
        {"number": True, "pull_request": {"base": {"sha": BASE}, "head": {"sha": HEAD}}},
    )
    with pytest.raises(ValueError, match="GitHub event is not a pull_request event"):
        cli._event(SimpleNamespace(event_file=str(boolean), github_pr=None, base=None, head=None), None, None)

    path = _event_file(tmp_path)
    event_args = SimpleNamespace(event_file=str(path), github_pr=None, base=None, head=None)
    monkeypatch.delenv("GITHUB_REPOSITORY", raising=False)
    with pytest.raises(ValueError, match="GITHUB_REPOSITORY is required for event mode"):
        cli._event(event_args, None, None)
    monkeypatch.setenv("GITHUB_REPOSITORY", "owner/project")
    monkeypatch.setenv("GITHUB_RUN_ID", "42")
    with pytest.raises(ValueError, match="requested revisions do not match the GitHub event"):
        cli._event(event_args, "c" * 40, None)
    event = cli._event(event_args, None, None)
    assert event["repository"] == "owner/project"
    assert event["pull_request_number"] == 7
    assert event["event_id"] == "42"
    assert event["base_sha"] == BASE and event["head_sha"] == HEAD


def test_github_pr_parsing_refusals_and_revision_mismatch(tmp_path, monkeypatch):
    from pr_review_harness import github

    args = SimpleNamespace(github_pr=None, event_file=None, base=None, head=None)
    assert cli._github_pr(args) is None
    combined = SimpleNamespace(github_pr="owner/project#7", event_file=str(tmp_path / "e.json"), base=None, head=None)
    with pytest.raises(ValueError, match=r"--github-pr cannot be combined with a GitHub event"):
        cli._github_pr(combined)
    with pytest.raises(ValueError, match=r"--github-pr must use owner/repository#number"):
        cli._github_pr(SimpleNamespace(github_pr="not-a-pr", event_file=None, base=None, head=None))

    class _Adapter:
        def pull_request(self, repository, number):
            assert (repository, number) == ("owner/project", 7)
            return {"repository": repository, "pull_request_number": number, "base_sha": BASE, "head_sha": HEAD}

    monkeypatch.setattr(github, "GitHubPRAdapter", _Adapter)
    event = cli._github_pr(SimpleNamespace(github_pr="owner/project#7", event_file=None, base=None, head=None))
    assert event["head_sha"] == HEAD
    with pytest.raises(ValueError, match="requested revisions do not match the GitHub PR"):
        cli._github_pr(SimpleNamespace(github_pr="owner/project#7", event_file=None, base=None, head="c" * 40))


def test_event_file_input_prefers_explicit_then_historical_mode(tmp_path):
    explicit = SimpleNamespace(event_file="explicit.json", historical_checks_json=None)
    assert cli._event_file_input(explicit) == "explicit.json"
    historical = SimpleNamespace(event_file=None, historical_checks_json="checks.json")
    assert cli._event_file_input(historical) is None


# ---------------------------------------------------------------------------
# historical check evidence validation
# ---------------------------------------------------------------------------


def _check_document(**overrides):
    document = {
        "schema_version": "2.0",
        "repository": "owner/project",
        "pull_request_number": 7,
        "head_sha": HEAD,
        "captured_at": "2026-09-26T12:00:00Z",
        "runs": [],
    }
    document.update(overrides)
    return document


def test_historical_check_identity_refusals(tmp_path):
    profile = {"repository": "owner/project", "required_checks": []}
    document = _check_document()
    for base, head, message in (
        ("short", HEAD, "explicit full base SHA"),
        (BASE, "short", "explicit full head SHA"),
    ):
        with pytest.raises(ValueError, match=f"historical check evidence requires an {message}"):
            cli._validate_historical_checks(profile, document, base, head)
    with pytest.raises(ValueError, match="trusted profile repository"):
        cli._validate_historical_checks({"repository": "not-a-repository"}, document, BASE, HEAD)
    with pytest.raises(ValueError, match="does not match the profile repository and selected head"):
        cli._validate_historical_checks(profile, _check_document(head_sha="c" * 40), BASE, HEAD)
    with pytest.raises(ValueError, match="positive captured pull request number"):
        cli._validate_historical_checks(profile, _check_document(pull_request_number=True), BASE, HEAD)
    with pytest.raises(ValueError, match="does not match the selected base"):
        cli._validate_historical_checks(profile, _check_document(base_sha="c" * 40), BASE, HEAD)
    with pytest.raises(ValueError, match="exceeds the bounded run count"):
        cli._validate_historical_checks(profile, _check_document(runs={}), BASE, HEAD)


def test_historical_check_bindings_skip_non_mapping_entries():
    identity = cli._validate_historical_checks(
        {"repository": "owner/project", "required_checks": [None]}, _check_document(), BASE, HEAD
    )
    assert identity["repository"] == "owner/project"
    assert identity["base_sha"] == BASE
    assert identity["head_sha"] == HEAD
    assert len(identity["check_document_sha256"]) == 64


# ---------------------------------------------------------------------------
# private shadow evidence binding
# ---------------------------------------------------------------------------


def test_private_shadow_evidence_snapshot_binding_refusals():
    with pytest.raises(ValueError, match="private shadow snapshot evidence is invalid"):
        cli._bind_private_shadow_evidence_snapshot({"evidence": [], "snapshot_id": "snap-1"})
    with pytest.raises(ValueError, match="private shadow snapshot evidence is invalid"):
        cli._bind_private_shadow_evidence_snapshot({"evidence": {"ev-1": []}, "snapshot_id": "snap-1"})
    with pytest.raises(ValueError, match="private shadow evidence snapshot binding mismatch"):
        cli._bind_private_shadow_evidence_snapshot(
            {"evidence": {"ev-1": {"snapshot_id": "snap-2"}}, "snapshot_id": "snap-1"}
        )
    snapshot = {"evidence": {"ev-1": {}}, "snapshot_id": "snap-1"}
    cli._bind_private_shadow_evidence_snapshot(snapshot)
    assert snapshot["evidence"]["ev-1"]["snapshot_id"] == "snap-1"


def test_snapshot_rebinding_refuses_malformed_and_dangling_references():
    with pytest.raises(ValueError, match="snapshot evidence_ids must be a list of evidence IDs"):
        cli._rebind_snapshot_evidence_references({"inventory": [{"evidence_ids": "ev-1"}]}, {})
    with pytest.raises(ValueError, match="snapshot evidence_ids contains an unbound evidence ID"):
        cli._rebind_snapshot_evidence_references({"inventory": [{"evidence_ids": ["ev-1"]}]}, {})
    with pytest.raises(ValueError, match="snapshot file-level location is malformed"):
        cli._rebind_snapshot_evidence_references({"inventory": [{"file_level_location": "x"}]}, {})
    with pytest.raises(ValueError, match="snapshot file-level location is malformed"):
        cli._rebind_snapshot_evidence_references({"inventory": [{"file_level_location": {"kind": "line"}}]}, {})
    with pytest.raises(ValueError, match="snapshot file-level location has an unbound evidence ID"):
        cli._rebind_snapshot_evidence_references(
            {"inventory": [{"file_level_location": {"kind": "file", "evidence_id": "old"}}]}, {}
        )
    malformed = {
        "inventory": [
            {
                "file_level_location": {
                    "kind": "file",
                    "evidence_id": "old",
                    "side": "HEAD",
                    "path": "src/a.py",
                    "evidence_hash": "h" * 64,
                }
            }
        ],
        "evidence": {"new": {"path": "src/a.py", "content_hash": "x" * 64, "source_revision": HEAD}},
        "head_sha": HEAD,
    }
    with pytest.raises(ValueError, match="snapshot file-level location does not match its immutable evidence"):
        cli._rebind_snapshot_evidence_references(malformed, {"old": "new"})


def test_snapshot_rebinding_updates_anchors_and_trusted_refs():
    snapshot = {
        "inventory": [
            {
                "evidence_ids": ["old"],
                "review_context_evidence_ids": ["old"],
                "file_level_location": {
                    "kind": "file",
                    "evidence_id": "old",
                    "side": "BASE",
                    "path": "src/a.py",
                    "evidence_hash": "h" * 64,
                },
            }
        ],
        "evidence": {"new": {"path": "src/a.py", "content_hash": "h" * 64, "source_revision": BASE}},
        "change_base_sha": BASE,
        "head_sha": HEAD,
        "trusted_context_refs": ["old"],
    }
    cli._rebind_snapshot_evidence_references(snapshot, {"old": "new"})
    unit = snapshot["inventory"][0]
    assert unit["evidence_ids"] == ["new"]
    assert unit["review_context_evidence_ids"] == ["new"]
    assert unit["file_level_location"]["evidence_id"] == "new"
    assert snapshot["trusted_context_refs"] == ["new"]


# ---------------------------------------------------------------------------
# claim and provider configuration guards
# ---------------------------------------------------------------------------


def test_claim_assessment_cap_rejects_non_integer_values():
    with pytest.raises(ValueError, match="max claim assessments must be between 0 and 4"):
        cli._claim_assessment_cap(SimpleNamespace(max_claim_assessments=True))


def test_claim_transport_unavailable_is_a_typed_preflight_error(monkeypatch):
    monkeypatch.setitem(sys.modules, "pr_review_harness.claim_transport", None)
    with pytest.raises(ValueError, match="claim assessment adapter is unavailable"):
        cli._claim_transport_from_config({})


def test_configs_maps_provider_import_failures_to_typed_errors(monkeypatch):
    from pr_review_harness import providers

    args = SimpleNamespace(
        profile="unused.json",
        limits=None,
        provider_config="provider.json",
        decision_config=None,
        max_claim_assessments=0,
    )
    monkeypatch.setattr(providers, "load_provider_config", lambda _path: {"provider": "stub"})
    monkeypatch.setattr(providers, "make_provider", lambda _config: (_ for _ in ()).throw(ImportError()))
    with pytest.raises(ValueError, match="provider adapter is unavailable"):
        cli._configs(args, profile={})

    monkeypatch.setitem(sys.modules, "pr_review_harness.providers", None)
    offline_args = SimpleNamespace(
        profile="unused.json",
        limits=None,
        provider_config=None,
        decision_config=None,
        max_claim_assessments=0,
    )
    profile, limits, provider, decision_provider, claim_assessor = cli._configs(offline_args, profile={})
    assert profile == {} and isinstance(limits, dict)
    assert provider is None and decision_provider is None and claim_assessor is None


# ---------------------------------------------------------------------------
# _run_one cross-argument refusals
# ---------------------------------------------------------------------------


def _run_one_args(**overrides):
    values = {
        "private_shadow_capture": None,
        "private_shadow_case_id": None,
        "private_shadow_preflight_case_id": None,
        "private_shadow_current_source_preflight": False,
        "private_shadow_current_source_plan": False,
        "private_shadow_plan": None,
        "private_shadow_preflight_receipt": None,
        "command": "review",
        "resume": False,
        "prepare_only": False,
        "dry_run": False,
        "output": "artifacts",
        "effect_policy": "READ_ONLY",
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def _invoke_run_one(args, **kwargs):
    return cli._run_one(args, BASE, HEAD, {}, {}, None, None, "run-1", max_claim_assessments=0, **kwargs)


def test_run_one_refuses_private_capture_flag_combinations(tmp_path):
    with pytest.raises(ValueError, match="private shadow plan and preflight receipt must be provided together"):
        _invoke_run_one(_run_one_args(private_shadow_plan="plan.json"))
    with pytest.raises(ValueError, match="current source capture is restricted to PR-457"):
        _invoke_run_one(
            _run_one_args(
                private_shadow_capture=str(tmp_path / "capture"),
                private_shadow_case_id="PR-464",
                private_shadow_current_source_plan=True,
                private_shadow_plan="plan.json",
                private_shadow_preflight_receipt="receipt.json",
            )
        )
    with pytest.raises(ValueError, match="private shadow case ID requires private shadow capture"):
        _invoke_run_one(_run_one_args(private_shadow_case_id="PR-457"))
    with pytest.raises(ValueError, match="private shadow preflight case requires matching prepare-only"):
        _invoke_run_one(_run_one_args(private_shadow_preflight_case_id="PR-457"))
    with pytest.raises(ValueError, match="current source preflight requires prepare-only PR-457"):
        _invoke_run_one(_run_one_args(private_shadow_current_source_preflight=True))
    with pytest.raises(ValueError, match="private shadow capture requires a fresh local non-resume review"):
        _invoke_run_one(_run_one_args(private_shadow_capture=str(tmp_path / "capture"), resume=True))


def test_run_one_refuses_case_mismatch_and_actions_without_pins(tmp_path, monkeypatch):
    monkeypatch.setattr(
        cli,
        "_load_private_shadow_pins",
        lambda *_args, **_kwargs: ({}, {"case_id": "PR-464"}),
    )
    with pytest.raises(ValueError, match="private shadow case does not match plan"):
        _invoke_run_one(
            _run_one_args(
                private_shadow_capture=str(tmp_path / "capture"),
                private_shadow_case_id="PR-457",
                private_shadow_plan="plan.json",
                private_shadow_preflight_receipt="receipt.json",
            )
        )
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    with pytest.raises(ValueError, match="trusted private capture requires exact request pins"):
        _invoke_run_one(_run_one_args(private_shadow_capture=str(tmp_path / "capture")))


def test_run_one_refuses_publish_effect_and_invalid_claim_cap(tmp_path):
    with pytest.raises(ValueError, match="PUBLISH_REVIEW is disabled"):
        _invoke_run_one(
            _run_one_args(
                private_shadow_capture=str(tmp_path / "capture"),
                effect_policy="PUBLISH_REVIEW",
            )
        )
    with pytest.raises(ValueError, match="max claim assessments must be between 0 and 4"):
        cli._run_one(
            _run_one_args(),
            BASE,
            HEAD,
            {},
            {},
            None,
            None,
            "run-1",
            max_claim_assessments=True,
        )


# ---------------------------------------------------------------------------
# publisher configuration and preview
# ---------------------------------------------------------------------------


def _root_is_file(config, tmp_path):
    path = tmp_path / "trusted-file"
    path.write_text("{}", encoding="utf-8")
    return {**config, "trusted_result_root": str(path)}


PUBLISHER_CASES = [
    ("schema", lambda c, t: {**c, "schema_version": "2.0"}, "publish preview configuration schema is invalid"),
    ("unknown-key", lambda c, t: {**c, "effect_store_path": "x"}, "publish preview configuration schema is invalid"),
    ("enabled", lambda c, t: {**c, "enabled": "yes"}, "publish preview enabled flag is invalid"),
    ("repositories-empty", lambda c, t: {**c, "allowed_repositories": []}, "publisher repository scope is invalid"),
    (
        "repositories-shape",
        lambda c, t: {**c, "allowed_repositories": ["owner"]},
        "publisher repository scope is invalid",
    ),
    ("dispositions-empty", lambda c, t: {**c, "allowed_dispositions": []}, "publisher disposition scope is invalid"),
    (
        "dispositions-value",
        lambda c, t: {**c, "allowed_dispositions": ["MERGE"]},
        "publisher disposition scope is invalid",
    ),
    ("profiles-empty", lambda c, t: {**c, "allowed_profile_versions": []}, "publisher profile scope is invalid"),
    ("profiles-shape", lambda c, t: {**c, "allowed_profile_versions": [1]}, "publisher profile scope is invalid"),
    (
        "root-relative",
        lambda c, t: {**c, "trusted_result_root": "relative/root"},
        "trusted result root must be an absolute path",
    ),
    (
        "root-missing",
        lambda c, t: {**c, "trusted_result_root": str(t / "missing")},
        "trusted result root is unavailable",
    ),
    ("root-file", _root_is_file, "trusted result root must be a directory"),
    ("body-bool", lambda c, t: {**c, "max_review_body_bytes": True}, "publisher review body limit is invalid"),
    ("body-range", lambda c, t: {**c, "max_review_body_bytes": 0}, "publisher review body limit is invalid"),
]


@pytest.mark.parametrize("case_id, mutate, message", PUBLISHER_CASES, ids=[case[0] for case in PUBLISHER_CASES])
def test_validate_publisher_config_refuses_out_of_scope_values(tmp_path, case_id, mutate, message):
    config = mutate(publisher_config(), tmp_path)
    with pytest.raises(ValueError, match=message):
        cli._validate_publisher_config(config)


def test_validate_publisher_config_accepts_trusted_absolute_root(tmp_path):
    trusted = tmp_path / "trusted"
    trusted.mkdir()
    config = publisher_config(trusted_result_root=str(trusted), enabled=True)
    assert cli._validate_publisher_config(config) is config


def _publish_inputs(tmp_path: Path, *, config=None, result=None) -> tuple[Path, Path]:
    result_path = _write_json(tmp_path / "result.json", result if result is not None else sealed_review())
    config_path = _write_json(tmp_path / "publisher.json", config or publisher_config())
    return result_path, config_path


def test_publish_main_emits_preview_and_refuses_authorization(tmp_path, capsys):
    result_path, config_path = _publish_inputs(tmp_path)
    base_argv = [
        "publish",
        "--result",
        str(result_path),
        "--publisher-config",
        str(config_path),
        "--json",
    ]
    assert cli.main(base_argv) == 0
    preview = json.loads(capsys.readouterr().out)
    assert preview["status"] == "PREVIEW_ONLY"
    assert preview["live_effects_performed"] is False
    assert preview["publication_capability"] == "UNAVAILABLE"
    assert "pr-review-harness:" in preview["request"]["review_payload"]["body"]

    assert cli.main([*base_argv, "--authorize-publish"]) == 2
    captured = capsys.readouterr()
    assert json.loads(captured.out) == {
        "error": "stateless publication capability is unavailable",
        "exit_code": 2,
    }


def test_publish_main_refuses_results_outside_scope_or_not_files(tmp_path, capsys):
    trusted = tmp_path / "trusted"
    trusted.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    result_path = _write_json(outside / "review.json", sealed_review())
    config_path = _write_json(
        tmp_path / "publisher.json",
        publisher_config(trusted_result_root=str(trusted.resolve())),
    )
    assert cli.main(["publish", "--result", str(result_path), "--publisher-config", str(config_path), "--json"]) == 2
    assert json.loads(capsys.readouterr().out)["error"] == "preflight_rejected"

    directory_result = trusted / "directory.json"
    directory_result.mkdir()
    assert (
        cli.main(["publish", "--result", str(directory_result), "--publisher-config", str(config_path), "--json"]) == 2
    )
    assert json.loads(capsys.readouterr().out)["error"] == "preflight_rejected"


def test_publish_main_refuses_profile_outside_authorization_scope(tmp_path, capsys):
    result = sealed_review()
    result["project_profile_version"] = "other-profile"
    result_path, config_path = _publish_inputs(tmp_path, result=result)
    assert cli.main(["publish", "--result", str(result_path), "--publisher-config", str(config_path), "--json"]) == 2
    assert json.loads(capsys.readouterr().out)["error"] == "preflight_rejected"


# ---------------------------------------------------------------------------
# main() argument and error mapping branches
# ---------------------------------------------------------------------------


def test_main_invalid_arguments_without_json_writes_stderr(capsys):
    assert cli.main(["review"]) == 2
    assert "pr-review: invalid arguments" in capsys.readouterr().err


def test_main_dry_run_review_and_recent_output_shapes(tmp_path, capsys):
    profile = _profile_file(tmp_path)
    assert (
        cli.main(
            [
                "review",
                "--repo",
                str(tmp_path / "repo"),
                "--profile",
                str(profile),
                "--base",
                BASE,
                "--head",
                HEAD,
                "--run-id",
                "dry-run-1",
                "--dry-run",
                "--json",
            ]
        )
        == 0
    )
    review_preview = json.loads(capsys.readouterr().out)
    assert review_preview["command"] == "review"
    assert review_preview["base"] == BASE and review_preview["head"] == HEAD
    assert review_preview["run_id"] == "dry-run-1"

    assert (
        cli.main(
            [
                "recent",
                "--repo",
                str(tmp_path / "repo"),
                "--profile",
                str(profile),
                "--count",
                "3",
                "--dry-run",
                "--json",
            ]
        )
        == 0
    )
    recent_preview = json.loads(capsys.readouterr().out)
    assert recent_preview["command"] == "recent"
    assert recent_preview["count"] == 3 and recent_preview["head"] == "HEAD"


def test_main_dry_run_reports_claim_cap_and_refuses_invalid_run_id(tmp_path, capsys):
    profile = _profile_file(tmp_path)
    assert (
        cli.main(
            [
                "review",
                "--repo",
                str(tmp_path / "repo"),
                "--profile",
                str(profile),
                "--decision-config",
                "unused.json",
                "--max-claim-assessments",
                "2",
                "--dry-run",
                "--json",
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["max_claim_assessments"] == 2

    assert (
        cli.main(
            [
                "review",
                "--repo",
                str(tmp_path / "repo"),
                "--profile",
                str(profile),
                "--run-id",
                "bad/id",
                "--dry-run",
                "--json",
            ]
        )
        == 2
    )
    assert json.loads(capsys.readouterr().out)["error"] == "preflight_rejected"

    assert (
        cli.main(
            [
                "recent",
                "--repo",
                str(tmp_path / "repo"),
                "--profile",
                str(profile),
                "--count",
                "0",
                "--dry-run",
                "--json",
            ]
        )
        == 2
    )
    assert json.loads(capsys.readouterr().out)["error"] == "preflight_rejected"


def test_main_prepare_only_refusals(tmp_path, capsys):
    profile = _profile_file(tmp_path)
    common = ["review", "--repo", str(tmp_path / "repo"), "--profile", str(profile), "--json"]

    assert cli.main([*common, "--prepare-only", "--dry-run"]) == 2
    assert json.loads(capsys.readouterr().out)["error"] == "preflight_rejected"

    assert cli.main([*common, "--prepare-only", "--event-file", str(_event_file(tmp_path))]) == 2
    assert json.loads(capsys.readouterr().out)["error"] == "preflight_rejected"

    assert cli.main([*common, "--prepare-only"]) == 2
    assert json.loads(capsys.readouterr().out)["error"] == "preflight_rejected"


def test_main_effect_policy_and_private_capture_argument_refusals(tmp_path, capsys):
    profile = _profile_file(tmp_path)
    common = ["review", "--repo", str(tmp_path / "repo"), "--profile", str(profile), "--json"]

    assert cli.main([*common, "--effect-policy", "PUBLISH_REVIEW"]) == 2
    captured = capsys.readouterr()
    assert json.loads(captured.out) == {"error": "PUBLISH_REVIEW is disabled", "exit_code": 2}

    assert (
        cli.main(
            [
                *common,
                "--private-shadow-capture",
                str(tmp_path / "capture"),
                "--private-shadow-plan",
                "plan.json",
            ]
        )
        == 2
    )
    assert json.loads(capsys.readouterr().out)["error"] == "preflight_rejected"


def test_main_current_source_plan_requires_fresh_capture_and_matching_provider(tmp_path, monkeypatch, capsys):
    from pr_review_harness import current_source_capture as capture

    profile = _profile_file(tmp_path)
    common = ["review", "--repo", str(tmp_path / "repo"), "--profile", str(profile), "--json"]
    assert cli.main([*common, "--private-shadow-current-source-plan"]) == 2
    assert json.loads(capsys.readouterr().out)["error"] == "preflight_rejected"

    plan = _write_json(tmp_path / "plan.json", {})
    receipt = _write_json(tmp_path / "receipt.json", {})
    monkeypatch.setattr(cli, "_configs", lambda args: ({}, {}, None, None, None))
    monkeypatch.setattr(capture, "installed_module_inventory", lambda: {})
    monkeypatch.setattr(capture, "validate_plan", lambda *_a, **_k: ({}, {"provider_identity_sha256": "z" * 64}))
    assert (
        cli.main(
            [
                *common,
                "--private-shadow-current-source-plan",
                "--private-shadow-capture",
                str(tmp_path / "capture"),
                "--private-shadow-case-id",
                "PR-457",
                "--private-shadow-plan",
                str(plan),
                "--private-shadow-preflight-receipt",
                str(receipt),
            ]
        )
        == 2
    )
    assert json.loads(capsys.readouterr().out)["error"] == "preflight_rejected"


@pytest.fixture
def offline_configs(monkeypatch):
    monkeypatch.setattr(cli, "_configs", lambda args: ({}, {}, None, None, None))


def test_main_recovery_input_refusals(tmp_path, monkeypatch, capsys, offline_configs):
    profile = _profile_file(tmp_path)
    common = ["review", "--repo", str(tmp_path / "repo"), "--profile", str(profile), "--json"]

    assert cli.main([*common, "--capture-recovery-inputs", "packet.json", "--resume"]) == 2
    assert json.loads(capsys.readouterr().out)["error"] == "preflight_rejected"

    assert cli.main([*common, "--recovery-inputs", "packet.json"]) == 2
    assert json.loads(capsys.readouterr().out)["error"] == "preflight_rejected"

    assert (
        cli.main(
            [*common, "--capture-recovery-inputs", "packet.json", "--private-shadow-capture", str(tmp_path / "capture")]
        )
        == 2
    )
    assert json.loads(capsys.readouterr().out)["error"] == "preflight_rejected"

    monkeypatch.delenv("GITHUB_REPOSITORY", raising=False)
    assert (
        cli.main(
            [
                *common,
                "--recovery-inputs",
                "packet.json",
                "--resume",
                "--run-id",
                "run-1",
            ]
        )
        == 2
    )
    assert json.loads(capsys.readouterr().out)["error"] == "preflight_rejected"


def test_main_historical_checks_argument_refusals(tmp_path, capsys, offline_configs):
    profile = _profile_file(tmp_path)
    common = ["review", "--repo", str(tmp_path / "repo"), "--profile", str(profile), "--json"]
    checks = _write_json(tmp_path / "checks.json", {})

    assert cli.main([*common, "--checks-json", str(checks), "--historical-checks-json", str(checks)]) == 2
    assert json.loads(capsys.readouterr().out)["error"] == "preflight_rejected"

    assert (
        cli.main(
            [
                *common,
                "--event-file",
                str(_event_file(tmp_path)),
                "--historical-checks-json",
                str(checks),
            ]
        )
        == 2
    )
    assert json.loads(capsys.readouterr().out)["error"] == "preflight_rejected"

    assert cli.main(common) == 2
    captured = capsys.readouterr()
    assert json.loads(captured.out)["error"] == "explicit base and head revisions are required without a PR/event input"

    assert cli.main([*common, "--base", BASE, "--head", HEAD, "--checks-json", str(checks)]) == 2
    assert json.loads(capsys.readouterr().out)["error"] == "preflight_rejected"


def test_main_recovery_capture_requires_event_and_matching_run_id(tmp_path, monkeypatch, capsys, offline_configs):
    from pr_review_harness import github

    profile = _profile_file(tmp_path)
    common = ["review", "--repo", str(tmp_path / "repo"), "--profile", str(profile), "--json"]

    assert cli.main([*common, "--base", BASE, "--head", HEAD, "--capture-recovery-inputs", "packet.json"]) == 2
    assert json.loads(capsys.readouterr().out)["error"] == "preflight_rejected"

    class _NoCheckRuns:
        def check_runs(self, *_args, **_kwargs):
            raise RuntimeError("offline")

    monkeypatch.setattr(github, "GitHubPRAdapter", _NoCheckRuns)
    monkeypatch.setenv("GITHUB_REPOSITORY", "owner/project")
    monkeypatch.setenv("GITHUB_RUN_ID", "42")
    event_file = _event_file(tmp_path)
    assert (
        cli.main(
            [
                *common,
                "--event-file",
                str(event_file),
                "--run-id",
                "wrong-run",
                "--capture-recovery-inputs",
                "packet.json",
            ]
        )
        == 2
    )
    assert json.loads(capsys.readouterr().out)["error"] == "preflight_rejected"

    from pr_review_harness import recovery_inputs

    monkeypatch.setattr(
        recovery_inputs,
        "write_packet",
        lambda *_a, **_k: (_ for _ in ()).throw(recovery_inputs.RecoveryInputError("offline")),
    )
    assert (
        cli.main(
            [
                *common,
                "--event-file",
                str(event_file),
                "--run-id",
                "pr-7-42",
                "--capture-recovery-inputs",
                "packet.json",
            ]
        )
        == 2
    )
    assert json.loads(capsys.readouterr().out)["error"] == "preflight_rejected"


def test_main_recent_refuses_historical_checks(tmp_path, capsys, offline_configs):
    profile = _profile_file(tmp_path)
    assert (
        cli.main(
            [
                "recent",
                "--repo",
                str(tmp_path / "repo"),
                "--profile",
                str(profile),
                "--historical-checks-json",
                "checks.json",
                "--json",
            ]
        )
        == 2
    )
    assert json.loads(capsys.readouterr().out)["error"] == "preflight_rejected"


def test_main_recent_reports_diagnostic_artifact_for_runtime_failure(tmp_path, monkeypatch, capsys, offline_configs):
    profile = _profile_file(tmp_path)
    monkeypatch.setattr(
        cli,
        "recent_commits",
        lambda repo, count: [{"base": BASE, "head": HEAD, "subject": "subject"}],
    )

    def fail(*_args, **_kwargs):
        raise cli._ReviewRuntimeFailure("artifacts/run.json")

    monkeypatch.setattr(cli, "_run_one", fail)
    assert cli.main(["recent", "--repo", str(tmp_path / "repo"), "--profile", str(profile)]) == 1
    captured = capsys.readouterr()
    assert "Completed 0 of 1 historical review runs." in captured.out
    assert "review_runtime_failed; diagnostic artifact" in captured.err
    assert "artifacts/run.json" in captured.err


# ---------------------------------------------------------------------------
# small direct guards retained for branch completeness
# ---------------------------------------------------------------------------


def test_historical_freshness_check_reports_historical_basis():
    value = cli.HistoricalFreshnessCheck(HEAD)()
    assert value == {
        "freshness": "CURRENT",
        "freshness_basis": "HISTORICAL_SNAPSHOT",
        "expected_head_sha": HEAD,
        "observed_head_sha": HEAD,
    }


def test_freshness_selects_historical_or_github_adapter(monkeypatch):
    from pr_review_harness import github

    assert isinstance(cli._freshness(None, HEAD), cli.HistoricalFreshnessCheck)
    seen = {}

    class _Freshness:
        def __init__(self, repository, pull_request_number, expected_head):
            seen.update(
                repository=repository,
                pull_request_number=pull_request_number,
                expected_head=expected_head,
            )

    monkeypatch.setattr(github, "GitHubFreshnessCheck", _Freshness)
    assert isinstance(cli._freshness({"repository": "owner/project", "pull_request_number": 7}, HEAD), _Freshness)
    assert seen == {"repository": "owner/project", "pull_request_number": 7, "expected_head": HEAD}


def test_public_error_maps_engine_and_snapshot_rejections():
    from pr_review_harness.engine import EnginePreflightError
    from pr_review_harness.snapshot import SnapshotError

    assert cli._public_error(EnginePreflightError("invalid_review_request")) == "invalid_review_request"
    assert cli._public_error(SnapshotError("cannot resolve")) == "snapshot_preflight_failed"


def test_snapshot_rebinding_skips_units_without_file_location():
    snapshot = {"inventory": [{}]}
    cli._rebind_snapshot_evidence_references(snapshot, {})
    assert snapshot == {"inventory": [{}]}


def test_historical_checks_accepts_finite_floats(tmp_path):
    document = _write_json(tmp_path / "checks.json", {"ratio": 1.5, "nested": [{"value": 2.25}]})
    loaded = cli._load_historical_checks(str(document))
    assert loaded["ratio"] == 1.5
    assert loaded["nested"][0]["value"] == 2.25


def test_main_private_capture_incompatible_with_resume(tmp_path, capsys, offline_configs):
    profile = _profile_file(tmp_path)
    assert (
        cli.main(
            [
                "review",
                "--repo",
                str(tmp_path / "repo"),
                "--profile",
                str(profile),
                "--private-shadow-capture",
                str(tmp_path / "capture"),
                "--resume",
                "--json",
            ]
        )
        == 2
    )
    assert json.loads(capsys.readouterr().out)["error"] == "preflight_rejected"


def test_main_loads_explicit_checks_json_with_event_identity(tmp_path, monkeypatch, capsys, offline_configs):
    profile = _profile_file(tmp_path)
    checks = _write_json(tmp_path / "checks.json", {"schema_version": "2.0"})
    monkeypatch.setenv("GITHUB_REPOSITORY", "owner/project")

    def stop(*_args, **_kwargs):
        raise ValueError("stop after check evidence load")

    monkeypatch.setattr(cli, "_run_one", stop)
    assert (
        cli.main(
            [
                "review",
                "--repo",
                str(tmp_path / "repo"),
                "--profile",
                str(profile),
                "--event-file",
                str(_event_file(tmp_path)),
                "--checks-json",
                str(checks),
                "--json",
            ]
        )
        == 2
    )
    assert json.loads(capsys.readouterr().out)["error"] == "preflight_rejected"
