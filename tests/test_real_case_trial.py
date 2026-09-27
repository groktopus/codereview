from __future__ import annotations

import hashlib
import json
import subprocess
import sys

import pytest

from scripts import run_real_case_trial as trial
from scripts.provider_config_from_env import configurations_from_environment

sys.path.insert(0, str(trial.ROOT / "src"))
from pr_review_harness.claim_transport import ClaimTransport
from pr_review_harness.providers import load_provider_config, make_decision_provider, make_provider


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def digest(value):
    return hashlib.sha256(value).hexdigest()


def test_frozen_case_manifest_binds_profiles_checks_and_exact_primary_demands():
    document, cases = trial.load_locked_cases()
    assert [case["case_id"] for case in trial.selected_cases("full-three-case", cases)] == [
        "PR-457",
        "PR-463",
        "PR-464",
    ]
    assert [case["case_id"] for case in trial.selected_cases("staged-pr464", cases)] == ["PR-464"]
    assert sum(case["expected_primary_count"] for case in cases) == 47
    assert sum(case["expected_primary_serialized_input_bytes"] for case in cases) == 3_962_264
    assert [case["expected_scope_count"] for case in cases] == [30, 72, 22]
    assert [case["expected_primary_count"] for case in cases] == [10, 27, 10]
    assert [case["expected_primary_serialized_input_bytes"] for case in cases] == [870_424, 2_206_107, 885_733]
    assert len(trial.RUNTIME_MODULE_INVENTORY) == 28
    limits = trial.limits_for(64)
    assert limits["max_snapshot_context_bytes"] == 300_000
    assert limits["max_context_bytes"] == 8_000_000
    assert limits["max_input_bytes_per_task"] == 128_000
    assert all(case["expected_scope_count"] > 0 for case in cases)
    assert document["baseline_plan_sha256"] == "5c98ea8d66723bae0092c16dd062cdc77640d6912da3ae90dde7ec5fc805baef"


def test_case_manifest_rejects_modified_frozen_profile(tmp_path, monkeypatch):
    source = trial.INPUT_ROOT
    target = tmp_path / "inputs"
    target.mkdir()
    document = json.loads((source / "cases.json").read_text())
    (target / "cases.json").write_text(json.dumps(document))
    (target / "profiles").mkdir()
    (target / "checks").mkdir()
    for case in document["cases"]:
        (target / case["profile_path"]).write_bytes((source / case["profile_path"]).read_bytes())
        (target / case["checks_path"]).write_bytes((source / case["checks_path"]).read_bytes())
    cases_bytes = (target / "cases.json").read_bytes()
    monkeypatch.setattr(trial, "INPUT_ROOT", target)
    monkeypatch.setattr(trial, "CASES_SHA256", digest(cases_bytes))
    profile = target / document["cases"][0]["profile_path"]
    profile.write_bytes(profile.read_bytes() + b"\n")
    with pytest.raises(trial.TrialError, match="fixed_profile_hash_mismatch"):
        trial.load_locked_cases()


def test_prepare_gate_accepts_exact_scope_and_primary_body_commitment():
    case = {
        "base_sha": "a" * 40,
        "head_sha": "b" * 40,
        "snapshot_hash": "c" * 64,
        "evidence_index_sha256": "d" * 64,
        "profile_sha256": "e" * 64,
        "primary_provider_identity_sha256": "f" * 64,
        "expected_scope_count": 2,
        "expected_scope_sha256": "g" * 64,
        "expected_primary_count": 1,
        "expected_primary_serialized_input_bytes": 19,
        "expected_primary_descriptor_sha256": "h" * 64,
        "profile_version": "profile-v1",
    }
    scope_rows = [
        {
            "obligation_id": "z-obligation",
            "obligation_kind": "UNIT_LENS",
            "lens": "security",
            "scope_unit_ids": ["u-2", "u-1"],
            "check_binding_id": None,
        },
        {
            "obligation_id": "a-obligation",
            "obligation_kind": "PROJECT_CHECK",
            "lens": None,
            "scope_unit_ids": ["u-4", "u-3"],
            "check_binding_id": "external:check",
        },
    ]
    scope_projection = [
        {
            "obligation_id": "a-obligation",
            "obligation_kind": "PROJECT_CHECK",
            "lens": None,
            "scope_unit_ids": ["u-3", "u-4"],
            "check_binding_id": "external:check",
        },
        {
            "obligation_id": "z-obligation",
            "obligation_kind": "UNIT_LENS",
            "lens": "security",
            "scope_unit_ids": ["u-1", "u-2"],
            "check_binding_id": None,
        },
    ]
    scope_hash = digest(canonical(scope_projection))
    evidence = [
        {"evidence_id": "ev-b", "content_hash": "b" * 64, "path": "b.py", "source_revision": "b" * 40},
        {"evidence_id": "ev-a", "content_hash": "a" * 64, "path": "a.py", "source_revision": "a" * 40},
    ]
    evidence_hash = digest(canonical(sorted(evidence, key=lambda row: row["evidence_id"])))
    primary = [
        {
            "task_id": "task-1",
            "lens": "security",
            "unit_ids": ["u"],
            "obligation_ids": ["unit:u:lens:security"],
            "evidence_ids": ["ev-1"],
            "input_bytes": 19,
            "input_sha256": "0" * 64,
        }
    ]
    descriptors = [
        {
            key: row.get(key)
            for key in ("task_id", "lens", "unit_ids", "obligation_ids", "evidence_ids", "input_bytes", "input_sha256")
        }
        for row in primary
    ]
    case["expected_scope_sha256"] = scope_hash
    case["expected_primary_descriptor_sha256"] = digest(canonical(descriptors))
    prepared = {
        "value": {
            "status": "PREPARED_ONLY",
            "disposition": None,
            "snapshot": {
                "base_sha": case["base_sha"],
                "head_sha": case["head_sha"],
                "snapshot_hash": case["snapshot_hash"],
                "evidence_index_sha256": evidence_hash,
                "evidence_index": evidence,
                "profile_file_sha256": case["profile_sha256"],
                "provider_identity_sha256": case["primary_provider_identity_sha256"],
                "profile_version": case["profile_version"],
            },
            "scope": {
                "primary_scope_admission_complete": True,
                "required_unadmitted_obligation_ids": [],
                "planned_obligations": 2,
                "coverage_obligations": scope_rows,
            },
            "primary_requests": primary,
        }
    }
    case["evidence_index_sha256"] = evidence_hash
    trial.validate_prepare(case, prepared, 8_000_000)


@pytest.mark.parametrize("mutation", ["disposition", "snapshot", "scope", "body", "input_cap"])
def test_prepare_gate_fails_closed_on_changed_plan(mutation):
    case = {
        "base_sha": "a" * 40,
        "head_sha": "b" * 40,
        "snapshot_hash": "c" * 64,
        "evidence_index_sha256": digest(canonical([])),
        "profile_sha256": "e" * 64,
        "primary_provider_identity_sha256": "f" * 64,
        "expected_scope_count": 1,
        "expected_scope_sha256": "g" * 64,
        "expected_primary_count": 1,
        "expected_primary_serialized_input_bytes": 129_000,
        "expected_primary_descriptor_sha256": "h" * 64,
        "profile_version": "profile-v1",
    }
    scope = [
        {
            "obligation_id": "unit:u:lens:security",
            "obligation_kind": None,
            "lens": None,
            "scope_unit_ids": None,
            "check_binding_id": None,
        }
    ]
    case["expected_scope_sha256"] = digest(canonical(scope))
    primary = [
        {
            "task_id": "task-1",
            "lens": "security",
            "unit_ids": ["u"],
            "obligation_ids": ["unit:u:lens:security"],
            "evidence_ids": ["ev-1"],
            "input_bytes": 129_000,
            "input_sha256": "0" * 64,
        }
    ]
    desc = [
        {
            key: primary[0].get(key)
            for key in ("task_id", "lens", "unit_ids", "obligation_ids", "evidence_ids", "input_bytes", "input_sha256")
        }
    ]
    case["expected_primary_descriptor_sha256"] = digest(canonical(desc))
    prepared = {
        "value": {
            "status": "PREPARED_ONLY",
            "disposition": None,
            "snapshot": {
                "base_sha": case["base_sha"],
                "head_sha": case["head_sha"],
                "snapshot_hash": case["snapshot_hash"],
                "evidence_index_sha256": case["evidence_index_sha256"],
                "evidence_index": [],
                "profile_file_sha256": case["profile_sha256"],
                "provider_identity_sha256": case["primary_provider_identity_sha256"],
                "profile_version": case["profile_version"],
            },
            "scope": {
                "primary_scope_admission_complete": True,
                "required_unadmitted_obligation_ids": [],
                "planned_obligations": 1,
                "coverage_obligations": scope,
            },
            "primary_requests": primary,
        }
    }
    if mutation == "disposition":
        prepared["value"]["disposition"] = "APPROVE"
    elif mutation == "snapshot":
        prepared["value"]["snapshot"]["snapshot_hash"] = "9" * 64
    elif mutation == "scope":
        prepared["value"]["scope"]["coverage_obligations"] = []
    elif mutation == "body":
        prepared["value"]["primary_requests"][0]["input_sha256"] = "1" * 64
    elif mutation == "input_cap":
        prepared["value"]["primary_requests"][0]["input_bytes"] = 128_001
    with pytest.raises(trial.TrialError):
        trial.validate_prepare(case, prepared, 8_000_000)


def test_candidate_projection_preserves_bounded_narrative_and_evidence_binding():
    candidate_id = "candidate-1"
    durable = {
        "disposition": "INCOMPLETE",
        "coverage_state": "PARTIAL",
        "freshness": "CURRENT",
        "provider_identity": {
            "provider_id": "adapter",
            "endpoint_id": "https://private.invalid",
            "model_id": "private-model",
        },
        "findings": [
            {
                "candidate_id": candidate_id,
                "status": "ACCEPTED",
                "blocking_class": "BLOCKING",
                "blocking_rationale": "supported",
                "introducedness": "INTRODUCED",
            }
        ],
        "ledger": {
            "candidate_records": [
                {
                    "candidate_id": candidate_id,
                    "finding_id": "finding-1",
                    "validation_state": "VALID",
                    "validation_reason": "anchor_and_evidence_valid",
                    "raw": {
                        "title": "Guard missing auth",
                        "observation": "The route omits the guard.",
                        "consequence": "Private data is exposed.",
                        "rule_or_contract": "Base security policy",
                        "unit_id": "unit-1",
                        "location": {"kind": "line", "path": "x.py", "line": 12},
                        "evidence_refs": ["ev-1"],
                    },
                }
            ]
        },
        "claim_assessments": [
            {
                "candidate_id": candidate_id,
                "status": "COMPLETE",
                "response_assessments": {
                    "grounding": {"status": "ANSWERED", "choice": "supported", "rationale": "linked evidence"}
                },
            }
        ],
        "advisory_assessment": {
            "status": "RECEIVED",
            "result": {"choice": "high", "rationale": "Inspect evidence."},
            "provenance": {"provider_id": "typesafe", "provider_model_id": "jev-2026-09"},
        },
        "budget": {"provider_calls_reserved": 3, "output_bytes_settled": 400},
        "coverage_ledger": [{"obligation_id": "ob-1", "required": True, "status": "PARTIAL"}],
        "evidence_index": {
            "ev-1": {
                "path": "x.py",
                "source_revision": "a" * 40,
                "content_hash": "b" * 64,
                "trust": "untrusted_pr_content",
            }
        },
    }
    projected = trial.project_case(
        {"case_id": "PR-464", "pull_request_number": 464, "base_sha": "a" * 40, "head_sha": "c" * 40},
        durable,
        ["secret-key"],
    )
    assert projected["candidates"][0]["observation"] == "The route omits the guard."
    assert projected["candidates"][0]["recommendation"]["blocking_class"] == "BLOCKING"
    assert projected["evidence_index"]["ev-1"]["path"] == "x.py"
    assert "endpoint_id" not in projected["provider_identity"]
    assert projected["advisory_assessment"]["identity"]["provider_model_sha256"]


def test_candidate_projection_omits_unsafe_projection_on_canary_match():
    durable = {
        "findings": [],
        "ledger": {"candidate_records": [{"candidate_id": "c1", "raw": {"title": "sensitive-canary"}}]},
        "provider_identity": {},
        "advisory_assessment": {"status": "NOT_CONFIGURED"},
        "claim_assessments": [],
    }
    with pytest.raises(trial.TrialError, match="credential_scan_failed"):
        trial.project_case(
            {"case_id": "PR-464", "pull_request_number": 464, "base_sha": "a" * 40, "head_sha": "b" * 40},
            durable,
            ["sensitive-canary"],
        )


@pytest.mark.parametrize(
    ("secret", "projection"),
    [
        ('quote"key', {"nested": {'prefix-quote"key-suffix': "clean"}}),
        ("slash\\key", {"nested": {"clean": "prefix-slash\\key-suffix"}}),
        ("päss🔐", {"nested": {"clean": "prefix-päss🔐-suffix"}}),
        ('quote"value', {"nested": [{"clean": 'prefix-quote"value-suffix'}]}),
        ("slash\\value", {"nested": [{"clean": "prefix-slash\\value-suffix"}]}),
        ("päss🔑", {"nested": [{"clean": "prefix-päss🔑-suffix"}]}),
    ],
)
def test_projection_scan_rejects_escaped_credentials_in_nested_keys_and_values(secret, projection):
    with pytest.raises(trial.TrialError, match="credential_scan_failed"):
        trial._scan(projection, [secret])


def test_projection_scan_accepts_clean_nested_metadata():
    projection = {"nested": [{"path": "src/module.py", "status": "REVIEWED"}]}
    assert trial._scan(projection, ["private-secret"]) == trial.canonical(projection)


def test_private_configuration_contains_only_credential_references(tmp_path, monkeypatch):
    monkeypatch.setenv("LLM_BASE_URL", trial.EXPECTED_LLM_ENDPOINT)
    monkeypatch.setenv("LLM_MODEL", trial.EXPECTED_LLM_MODEL)
    monkeypatch.setenv("LLM_API_KEY", "llm-secret-canary")
    monkeypatch.setenv("JEV_BASE_URL", trial.EXPECTED_JEV_BASE_URL)
    monkeypatch.setenv("JEV_MODEL", trial.EXPECTED_JEV_ALIAS)
    monkeypatch.setenv("JEV_API_KEY", "jev-secret-canary")
    provider, decision, scan_values = trial.build_configs(tmp_path / "private")
    assert "llm-secret-canary" not in provider.read_text()
    assert "jev-secret-canary" not in decision.read_text()
    assert json.loads(provider.read_text())["api_key_env"] == "LLM_API_KEY"
    assert "llm-secret-canary" in scan_values
    assert trial.EXPECTED_LLM_MODEL in scan_values


def test_prepare_and_live_decision_configs_match_claim_transport_contract(tmp_path, monkeypatch):
    prepare_dir = tmp_path / "prepare"
    prepare_dir.mkdir(mode=0o700)
    prepare_provider, prepare_decision = trial.build_prepare_configs(prepare_dir)
    prepare_decision_data = trial.read_json(prepare_decision)
    ClaimTransport.from_decision_config(prepare_decision_data)
    assert set(prepare_decision_data) == {"kind", "endpoint", "model", "api_key_env"}
    assert make_provider(load_provider_config(str(prepare_provider))).max_response_bytes == 16_000
    assert make_decision_provider(prepare_decision_data) is not None

    for name, value in {
        "LLM_BASE_URL": trial.EXPECTED_LLM_ENDPOINT,
        "LLM_MODEL": trial.EXPECTED_LLM_MODEL,
        "LLM_API_KEY": "llm-contract-test-key",
        "JEV_BASE_URL": trial.EXPECTED_JEV_BASE_URL,
        "JEV_MODEL": trial.EXPECTED_JEV_ALIAS,
        "JEV_API_KEY": "jev-contract-test-key",
    }.items():
        monkeypatch.setenv(name, value)
    live_provider, live_decision, _ = trial.build_configs(tmp_path / "live")
    live_decision_data = trial.read_json(live_decision)
    ClaimTransport.from_decision_config(live_decision_data)
    assert set(live_decision_data) == {"kind", "endpoint", "model", "api_key_env"}
    assert make_provider(load_provider_config(str(live_provider))).max_response_bytes == 16_000
    assert make_decision_provider(live_decision_data) is not None


def test_live_configs_use_production_translator_and_allow_its_trailing_slash_normalization(tmp_path, monkeypatch):
    environment = {
        "LLM_BASE_URL": trial.EXPECTED_LLM_ENDPOINT + "/",
        "LLM_MODEL": trial.EXPECTED_LLM_MODEL,
        "LLM_API_KEY": "llm-contract-test-key",
        "JEV_BASE_URL": trial.EXPECTED_JEV_BASE_URL + "/",
        "JEV_MODEL": trial.EXPECTED_JEV_ALIAS,
        "JEV_API_KEY": "jev-contract-test-key",
    }
    for name, value in environment.items():
        monkeypatch.setenv(name, value)

    translated_provider, translated_decision = configurations_from_environment(environment)
    provider_path, decision_path, scan_values = trial.build_configs(tmp_path / "private")
    assert trial.read_json(provider_path)["base_url"] == translated_provider["base_url"] == trial.EXPECTED_LLM_ENDPOINT
    assert trial.read_json(decision_path)["endpoint"] == translated_decision["endpoint"] == trial.EXPECTED_JEV_ENDPOINT
    assert trial.EXPECTED_JEV_BASE_URL + "/" in scan_values
    for configured_value in (trial.EXPECTED_JEV_BASE_URL, trial.EXPECTED_JEV_BASE_URL + "/"):
        with pytest.raises(trial.TrialError, match="credential_scan_failed"):
            trial._scan({"candidate_text": f"configured value: {configured_value}"}, scan_values)


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("LLM_BASE_URL", "https://wrong.example.invalid/v1"),
        ("LLM_BASE_URL", "not a url"),
        ("JEV_BASE_URL", "https://wrong.example.invalid/v1"),
        ("JEV_BASE_URL", "https://api.typesafe.ai/v1/systemone"),
        ("JEV_BASE_URL", "https://[malformed/v1"),
        ("LLM_MODEL", "openai/gpt-6-luna-paid"),
        ("JEV_MODEL", "jev-other"),
    ],
)
def test_live_configs_reject_invalid_or_non_pinned_translated_identity(tmp_path, monkeypatch, name, value):
    for key, item in {
        "LLM_BASE_URL": trial.EXPECTED_LLM_ENDPOINT,
        "LLM_MODEL": trial.EXPECTED_LLM_MODEL,
        "LLM_API_KEY": "llm-contract-test-key",
        "JEV_BASE_URL": trial.EXPECTED_JEV_BASE_URL,
        "JEV_MODEL": trial.EXPECTED_JEV_ALIAS,
        "JEV_API_KEY": "jev-contract-test-key",
    }.items():
        monkeypatch.setenv(key, item)
    monkeypatch.setenv(name, value)

    with pytest.raises(trial.TrialError, match="provider_identity_configuration_mismatch"):
        trial.build_configs(tmp_path / "private")
    assert not (tmp_path / "private").exists()


def test_shared_case_and_matrix_deadline_uses_smaller_remaining_budget(monkeypatch):
    monkeypatch.setattr(trial.time, "monotonic", lambda: 100.0)
    assert trial._remaining(120.0, 140.0) == 5.0
    monkeypatch.setattr(trial.time, "monotonic", lambda: 106.0)
    with pytest.raises(trial.TrialError, match="case_deadline_exceeded"):
        trial._remaining(120.0, 140.0)


def test_full_matrix_deadline_includes_checkout_and_wheel_setup(monkeypatch):
    monkeypatch.setenv("TRIAL_STARTED_EPOCH", "1000000000")
    monkeypatch.setattr(trial.time, "time", lambda: 1_000_000_100.0)
    monkeypatch.setattr(trial.time, "monotonic", lambda: 500.0)
    assert trial._matrix_deadline(provider_run=True) == 2_380.0
    monkeypatch.setattr(trial.time, "time", lambda: 1_000_001_980.0)
    with pytest.raises(trial.TrialError, match="matrix_deadline_exceeded"):
        trial._matrix_deadline(provider_run=True)


def test_object_store_cap_counts_loose_and_packed_objects():
    loose, packed, pack_kib = trial._parse_object_store_counts("count: 7\nin-pack: 113\nsize-pack: 2048\n")
    assert loose == 7
    assert packed == 113
    assert loose + packed == 120
    assert pack_kib == 2048


def test_python_patch_reconstruction_has_scoped_function_and_class_headings(tmp_path):
    repo = tmp_path / "repo"
    env = trial._clean_git_env(
        {
            "GIT_AUTHOR_NAME": "fixture",
            "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
            "GIT_COMMITTER_NAME": "fixture",
            "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
        }
    )

    def git(*args):
        return (
            subprocess.run(
                ["git", "-C", str(repo), *args],
                env=env,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=10,
            )
            .stdout.decode()
            .strip()
        )

    subprocess.run(
        ["git", "init", "-q", str(repo)],
        env=env,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=10,
    )
    source = ["class Worker:"]
    source.extend(f"    # class header padding {index}" for index in range(8))
    source.append('    marker = "before"')
    source.extend(f"    # class padding {index}" for index in range(10))
    source.extend(["    def run(self):"])
    source.extend(f"        # method padding {index}" for index in range(8))
    source.extend(['        return "before"', ""])
    source.extend(f"# padding {index}" for index in range(12))
    source.extend(["", "def dispatch():"])
    source.extend(f"    # function padding {index}" for index in range(8))
    source.extend(["    return 1", ""])
    module = repo / "fixture.py"
    module.write_text("\n".join(source), encoding="utf-8")
    git("add", "fixture.py")
    git("commit", "-q", "-m", "base")
    base = git("rev-parse", "HEAD")
    module.write_text(
        "\n".join(line.replace('"before"', '"after"').replace("return 1", "return 2") for line in source),
        encoding="utf-8",
    )
    git("add", "fixture.py")
    git("commit", "-q", "-m", "head")
    head = git("rev-parse", "HEAD")

    attributes = tmp_path / "python-diff.attributes"
    trial._write_python_attributes(attributes)
    command = trial._python_diff_command(repo / ".git", attributes, base, head)
    output = subprocess.run(
        command,
        env=env,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=10,
    ).stdout.decode()
    headers = [line for line in output.splitlines() if line.startswith("@@")]
    assert any(header.endswith("class Worker:") for header in headers)
    assert any(header.endswith("def run(self):") for header in headers)
    assert any(header.endswith("def dispatch():") for header in headers)
    assert f"core.attributesFile={attributes}" in command
    assert f"diff.codereview-python.xfuncname={trial.PYTHON_XFUNCNAME}" in command
    # The custom attributes config is limited to this verification argv; it is not inherited by the CLI.
    assert "GIT_ATTR_SOURCE" not in env
    assert "GIT_CONFIG_PARAMETERS" not in env
    assert not any("codereview-python" in value for value in env.values())


def test_expired_deadline_starts_neither_git_fetch_nor_cli_call(tmp_path, monkeypatch):
    invoked = []
    monkeypatch.setattr(trial.time, "monotonic", lambda: 100.0)
    monkeypatch.setattr(trial, "_bounded_run", lambda *args, **kwargs: invoked.append(args) or (b"", b""))
    case = {"base_sha": "a" * 40, "head_sha": "b" * 40, "patch_sha256": "c" * 64}
    with pytest.raises(trial.TrialError, match="case_deadline_exceeded"):
        trial.acquire_bare_case(case, tmp_path / "case.git", 110.0, 120.0)
    with pytest.raises(trial.TrialError, match="case_deadline_exceeded"):
        trial.run_cli(
            tmp_path / "cli",
            case,
            tmp_path / "repo",
            tmp_path / "profile",
            tmp_path / "checks",
            tmp_path / "provider",
            tmp_path / "decision",
            tmp_path / "limits",
            tmp_path / "out",
            True,
            {},
            0.0,
        )
    assert invoked == []


def test_main_failure_keeps_completed_row_and_marks_failed_and_unstarted_cases(tmp_path, monkeypatch, capsys):
    artifact_dir = tmp_path / "artifacts"
    repo_root = trial.ROOT
    _, cases = trial.load_locked_cases()
    monkeypatch.setattr(trial, "_matrix_deadline", lambda provider_run: trial.time.monotonic() + 10_000)
    monkeypatch.setattr(trial, "verify_runtime", lambda cli, source: {"module_file_count": 28})
    monkeypatch.setattr(trial, "validate_prepare", lambda case, prepared, cap: None)
    monkeypatch.setattr(trial, "primary_receipts", lambda prepared: [])
    acquisitions = []

    def acquire(case, path, case_deadline, matrix_deadline, **kwargs):
        acquisitions.append(case["case_id"])
        if len(acquisitions) == 2:
            raise trial.TrialError("target_git_identity_mismatch")
        path.mkdir()
        return {
            "patch_sha256": case["patch_sha256"],
            "isolated_object_count": 1,
            "isolated_loose_object_count": 1,
            "isolated_in_pack_object_count": 0,
            "isolated_pack_kib": 0,
        }

    monkeypatch.setattr(trial, "acquire_bare_case", acquire)
    monkeypatch.setattr(
        trial,
        "run_cli",
        lambda *args, **kwargs: {"value": {"primary_requests": []}, "run_id": "prepared"},
    )
    monkeypatch.setattr(trial, "primary_receipts", lambda prepared: [])

    code = trial.main(
        [
            "--mode",
            "full-three-case",
            "--prepare-only",
            "--artifacts",
            str(artifact_dir),
            "--cli",
            str(repo_root / "scripts" / "run_real_case_trial.py"),
            "--runtime-source",
            str(repo_root),
        ]
    )

    assert code == 2
    assert json.loads(capsys.readouterr().out) == {"status": "FAILED", "error": "target_git_identity_mismatch"}
    summary = json.loads((artifact_dir / "summary.json").read_text())
    manifest = json.loads((artifact_dir / "manifest.json").read_text())
    assert [row["status"] for row in manifest["cases"]] == ["PREPARED_NOT_RUN", "INCOMPLETE", "NOT_RUN"]
    assert manifest["cases"][1]["failure_stage"] == "target_object_acquisition"
    assert manifest["cases"][1]["failure_code"] == "target_git_identity_mismatch"
    assert summary["provider_execution_state"] == "ZERO_PROVIDER_CALLS_PREPARE_ONLY"
    assert not (artifact_dir / "private").exists()


def test_early_failure_emits_typed_unstarted_rows_after_private_cleanup(tmp_path, monkeypatch):
    artifact_dir = tmp_path / "artifacts"
    repo_root = trial.ROOT
    _, cases = trial.load_locked_cases()
    monkeypatch.setattr(trial, "_matrix_deadline", lambda provider_run: trial.time.monotonic() + 10_000)
    monkeypatch.setattr(
        trial,
        "verify_runtime",
        lambda cli, source: (_ for _ in ()).throw(trial.TrialError("installed_runtime_identity_mismatch")),
    )
    code = trial.main(
        [
            "--mode",
            "full-three-case",
            "--prepare-only",
            "--artifacts",
            str(artifact_dir),
            "--cli",
            str(repo_root / "scripts" / "run_real_case_trial.py"),
            "--runtime-source",
            str(repo_root),
        ]
    )
    assert code == 2
    manifest = json.loads((artifact_dir / "manifest.json").read_text())
    assert [row["case_id"] for row in manifest["cases"]] == [case["case_id"] for case in cases]
    assert {row["status"] for row in manifest["cases"]} == {"NOT_RUN"}
    assert manifest["failure"] == {
        "stage": "runtime_identity_validation",
        "code": "installed_runtime_identity_mismatch",
    }
    assert not (artifact_dir / "private").exists()


def test_provider_failure_marks_actual_usage_unknown_and_keeps_no_secret_values(tmp_path, monkeypatch, capsys):
    artifact_dir = tmp_path / "artifacts"
    repo_root = trial.ROOT
    monkeypatch.setattr(trial, "_matrix_deadline", lambda provider_run: trial.time.monotonic() + 10_000)
    monkeypatch.setattr(trial, "verify_dispatch_context", lambda root: "a" * 40)
    monkeypatch.setattr(trial, "verify_runtime", lambda cli, source: {"module_file_count": 28})
    monkeypatch.setattr(trial, "validate_prepare", lambda case, prepared, cap: None)
    monkeypatch.setattr(trial, "primary_receipts", lambda prepared: [])

    def acquire(case, path, *_, **kwargs):
        path.mkdir()
        return {
            "patch_sha256": case["patch_sha256"],
            "isolated_object_count": 1,
            "isolated_loose_object_count": 1,
            "isolated_in_pack_object_count": 0,
            "isolated_pack_kib": 0,
        }

    monkeypatch.setattr(trial, "acquire_bare_case", acquire)
    llm_key = "llm-private-canary"
    jev_key = "jev-private-canary"
    for name, value in {
        "LLM_BASE_URL": trial.EXPECTED_LLM_ENDPOINT,
        "LLM_MODEL": trial.EXPECTED_LLM_MODEL,
        "LLM_API_KEY": llm_key,
        "JEV_BASE_URL": trial.EXPECTED_JEV_BASE_URL,
        "JEV_MODEL": trial.EXPECTED_JEV_ALIAS,
        "JEV_API_KEY": jev_key,
    }.items():
        monkeypatch.setenv(name, value)
    cli_calls = []
    caught_errors = []
    provider_calls = 0
    candidate_projection = {"findings": [{"candidate_id": "c1", "title": "bounded safe narrative"}]}
    real_run_cli = trial.run_cli
    monkeypatch.setattr(trial, "read_result", lambda path: {"disposition": "INCOMPLETE"})
    monkeypatch.setattr(trial, "project_case", lambda case, durable, secrets: candidate_projection)

    def run_cli(*args, **kwargs):
        nonlocal provider_calls
        prepare = args[9]
        case = args[1]
        output = args[8]
        cli_calls.append((case["case_id"], prepare))
        if prepare:
            output.mkdir()
            return {"value": {"primary_requests": []}, "run_id": "prepared"}
        provider_calls += 1
        if provider_calls == 1:
            output.mkdir()
            (output / "reviewed.json").write_text("{}", encoding="utf-8")
            return {"value": {"artifact_path": str(output)}, "run_id": "reviewed"}
        fake_cli = tmp_path / "timeout-cli"
        fake_cli.write_text(
            "#!/bin/sh\nprintf '%s\\n' \"$LLM_API_KEY\" >&2\nsleep 10\n",
            encoding="utf-8",
        )
        fake_cli.chmod(0o700)
        call = [str(fake_cli), *args[1:]]
        call[-1] = 0.1
        try:
            return real_run_cli(*call)
        except Exception as exc:
            caught_errors.append((type(exc).__name__, repr(exc.args)))
            raise

    monkeypatch.setattr(trial, "run_cli", run_cli)
    code = trial.main(
        [
            "--mode",
            "full-three-case",
            "--run-provider-trial",
            "--artifacts",
            str(artifact_dir),
            "--cli",
            str(repo_root / "scripts" / "run_real_case_trial.py"),
            "--runtime-source",
            str(repo_root),
        ]
    )
    assert code == 2
    assert json.loads(capsys.readouterr().out) == {"status": "FAILED", "error": "subprocess_deadline_exceeded"}, (
        caught_errors
    )
    assert cli_calls == [
        ("PR-457", True),
        ("PR-457", False),
        ("PR-463", True),
        ("PR-463", False),
    ]
    manifest_bytes = (artifact_dir / "manifest.json").read_bytes()
    summary_bytes = (artifact_dir / "summary.json").read_bytes()
    assert llm_key.encode() not in manifest_bytes + summary_bytes
    assert jev_key.encode() not in manifest_bytes + summary_bytes
    manifest = json.loads(manifest_bytes)
    assert manifest["provider_execution_state"] == "UNKNOWN_AFTER_FAILURE"
    assert manifest["provider_calls"] == "UNKNOWN"
    assert manifest["cost"] == "UNKNOWN"
    assert manifest["failure"] == {"stage": "provider_cli", "code": "subprocess_deadline_exceeded"}
    assert manifest["cases"][0]["status"] == "PROCESS_COMPLETED"
    assert manifest["cases"][0]["projection"] == candidate_projection
    assert manifest["cases"][1]["failure_code"] == "subprocess_deadline_exceeded"
    assert [row["status"] for row in manifest["cases"]] == ["PROCESS_COMPLETED", "INCOMPLETE", "NOT_RUN"]
    assert b"bounded safe narrative" not in summary_bytes
    assert not (artifact_dir / "private").exists()
