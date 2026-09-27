from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import run_recovery_rehearsal as rehearsal


def test_fake_specialist_response_cites_delivered_units_and_is_static_only():
    request = {
        "messages": [
            {"role": "system", "content": "ignored"},
            {
                "role": "user",
                "content": json.dumps(
                    {
                        "task": {"unit_ids": ["u-a", "u-b"]},
                        "evidence": [{"evidence_id": "ev-a"}, {"evidence_id": "ev-b"}],
                    }
                ),
            },
        ]
    }
    result = rehearsal._specialist_payload(request)
    assert result["contract_version"] == "specialist-findings.v4"
    assert result["finding_candidates"] == []
    assert [note["unit_id"] for note in result["coverage_notes"]] == ["u-a", "u-b"]
    assert all(note["coverage_basis"] == "STATIC_REVIEW" for note in result["coverage_notes"])
    assert result["specific_strengths"] == result["future_guidance"] == []


def test_child_environment_excludes_real_credentials_and_event_identity(monkeypatch, tmp_path):
    for name in ("GITHUB_TOKEN", "GH_TOKEN", "OPENAI_API_KEY", "TYPESAFE_API_KEY", "PYTHONPATH", "GITHUB_EVENT_PATH"):
        monkeypatch.setenv(name, "must-not-propagate")
    env = rehearsal._clean_env(tmp_path, provider_key=True, event_repo=True)
    assert env["RECOVERY_FAKE_PROVIDER_KEY"] == rehearsal.FAKE_API_KEY
    assert env["GITHUB_REPOSITORY"] == rehearsal.FIXTURE_REPOSITORY
    for name in ("GITHUB_TOKEN", "GH_TOKEN", "OPENAI_API_KEY", "TYPESAFE_API_KEY", "PYTHONPATH", "GITHUB_EVENT_PATH"):
        assert name not in env


def test_local_gh_shim_proves_stale_and_unknown_without_real_gh(tmp_path):
    fake_bin = tmp_path / "bin"
    log = tmp_path / "calls.log"
    base, head = "a" * 40, "b" * 40
    rehearsal._write_fake_gh(fake_bin, "STALE", base, head, log)
    stale = subprocess.run(
        [str(fake_bin / "gh"), "api", f"repos/{rehearsal.FIXTURE_REPOSITORY}/pulls/{rehearsal.FIXTURE_PR}"],
        check=False,
        capture_output=True,
        text=True,
        env={"PATH": os.environ.get("PATH", "")},
        timeout=2,
    )
    payload = json.loads(stale.stdout)
    assert stale.returncode == 0
    assert payload["head"]["sha"] != head
    rehearsal._write_fake_gh(fake_bin, "UNKNOWN", base, head, log)
    unknown = subprocess.run(
        [str(fake_bin / "gh"), "api", f"repos/{rehearsal.FIXTURE_REPOSITORY}/pulls/{rehearsal.FIXTURE_PR}"],
        check=False,
        capture_output=True,
        text=True,
        env={"PATH": os.environ.get("PATH", "")},
        timeout=2,
    )
    assert unknown.returncode == 1
    assert log.read_text(encoding="utf-8").splitlines() == ["freshness", "freshness"]


def test_run_cli_bounds_timeout_and_output(tmp_path):
    cli = tmp_path / "fake-cli"
    cli.write_text('#!/usr/bin/env python3\nprint(\'{"status":"ok"}\')\n', encoding="utf-8")
    cli.chmod(0o700)
    result = rehearsal._run_cli(
        cli,
        [],
        cwd=tmp_path,
        env={"PATH": os.environ.get("PATH", "")},
        timeout_seconds=1,
        deadline_at=__import__("time").monotonic() + 2,
    )
    assert result == {"status": "ok"}

    cli.write_text("#!/usr/bin/env python3\nimport time; time.sleep(2)\n", encoding="utf-8")
    cli.chmod(0o700)
    with pytest.raises(rehearsal.RehearsalError, match="cli_deadline_exceeded"):
        rehearsal._run_cli(
            cli,
            [],
            cwd=tmp_path,
            env={"PATH": os.environ.get("PATH", "")},
            timeout_seconds=0.1,
            deadline_at=__import__("time").monotonic() + 1,
        )

    cli.write_text("#!/usr/bin/env python3\nprint('x' * 300000)\n", encoding="utf-8")
    cli.chmod(0o700)
    with pytest.raises(rehearsal.RehearsalError, match="cli_output_exceeds_limit"):
        rehearsal._run_cli(
            cli,
            [],
            cwd=tmp_path,
            env={"PATH": os.environ.get("PATH", "")},
            timeout_seconds=2,
            deadline_at=__import__("time").monotonic() + 3,
        )


def test_run_cli_rejects_mismatched_process_exit_even_with_preflight_json(tmp_path):
    cli = tmp_path / "wrong-exit"
    cli.write_text(
        "#!/usr/bin/env python3\n"
        "import json, sys\n"
        "print(json.dumps({'error':'resume_state_invalid','exit_code':2}))\n"
        "sys.exit(1)\n",
        encoding="utf-8",
    )
    cli.chmod(0o700)
    with pytest.raises(rehearsal.RehearsalError, match="cli_exit_mismatch"):
        rehearsal._run_cli(
            cli,
            [],
            cwd=tmp_path,
            env={"PATH": os.environ.get("PATH", "")},
            expected_exit=2,
            deadline_at=__import__("time").monotonic() + 2,
        )


@pytest.mark.parametrize("error_code", ["preflight_rejected", "resume_state_invalid"])
def test_profile_drift_accepts_only_known_preflight_codes_and_preserves_checkpoint(tmp_path, error_code):
    checkpoint = tmp_path / "run.json"
    checkpoint.write_bytes(b'{"disposition":"INCOMPLETE"}\n')
    digest = rehearsal._hash_file(checkpoint)
    result = rehearsal._validate_profile_drift_rejection(
        {"error": error_code, "exit_code": 2},
        checkpoint_path=checkpoint,
        checkpoint_sha256=digest,
        calls_before=2,
        calls_after=2,
    )
    assert result == error_code
    assert rehearsal._hash_file(checkpoint) == digest


@pytest.mark.parametrize(
    ("drift", "calls_after", "mutate_checkpoint", "expected_error"),
    [
        ({"error": "resume_state_invalid", "exit_code": 1}, 2, False, "profile_drift_not_rejected"),
        ({"error": "resume_state_invalid", "exit_code": 2.0}, 2, False, "profile_drift_not_rejected"),
        ({"error": "resume_state_invalid"}, 2, False, "profile_drift_not_rejected"),
        ({"error": "review_runtime_failed", "exit_code": 2}, 2, False, "profile_drift_not_rejected"),
        ({"error": ["resume_state_invalid"], "exit_code": 2}, 2, False, "profile_drift_not_rejected"),
        ({"error": "resume_state_invalid", "exit_code": 2}, 3, False, "profile_drift_dispatched_provider"),
        ({"error": "resume_state_invalid", "exit_code": 2}, 2, True, "profile_drift_checkpoint_mutated"),
    ],
)
def test_profile_drift_rejects_wrong_exit_code_diagnostic_calls_or_checkpoint(
    tmp_path, drift, calls_after, mutate_checkpoint, expected_error
):
    checkpoint = tmp_path / "run.json"
    checkpoint.write_bytes(b'{"disposition":"INCOMPLETE"}\n')
    digest = rehearsal._hash_file(checkpoint)
    if mutate_checkpoint:
        checkpoint.write_bytes(b'{"disposition":"COMPLETE"}\n')
    with pytest.raises(rehearsal.RehearsalError, match=expected_error):
        rehearsal._validate_profile_drift_rejection(
            drift,
            checkpoint_path=checkpoint,
            checkpoint_sha256=digest,
            calls_before=2,
            calls_after=calls_after,
        )


def test_profile_drift_summary_uses_counts_captured_before_later_resume_calls():
    observed_calls = ["interrupted request", "reserved uncertain request"]
    drift_calls_before = len(observed_calls)
    drift_calls_after = len(observed_calls)
    row = rehearsal._profile_drift_row(
        "resume_state_invalid",
        calls_before=drift_calls_before,
        calls_after=drift_calls_after,
        checkpoint_sha256="a" * 64,
    )
    observed_calls.append("later successful resume request")
    assert len(observed_calls) > drift_calls_after
    assert row["fake_provider_calls_before"] == 2
    assert row["fake_provider_calls_after"] == 2
@pytest.mark.skipif(os.name != "posix", reason="isolated process-group behavior is POSIX-specific")
def test_run_cli_stops_pipe_holding_descendant_after_parent_exits(tmp_path):
    cli = tmp_path / "parent-exits"
    pid_file = tmp_path / "child.pid"
    term_marker = tmp_path / "child.term"
    child_code = (
        "import os,signal,sys,time; "
        f"open({str(pid_file)!r},'w').write(str(os.getpid())); "
        f"signal.signal(signal.SIGTERM,lambda *_: (open({str(term_marker)!r},'w').write('term'),sys.exit(0))); "
        "time.sleep(30)"
    )
    cli.write_text(
        f"#!{sys.executable}\nimport subprocess,sys\nsubprocess.Popen([sys.executable, '-c', {child_code!r}])\n",
        encoding="utf-8",
    )
    cli.chmod(0o700)

    with pytest.raises(rehearsal.RehearsalError, match="cli_deadline_exceeded"):
        rehearsal._run_cli(
            cli,
            [],
            cwd=tmp_path,
            env={"PATH": os.environ.get("PATH", "")},
            timeout_seconds=0.2,
            deadline_at=__import__("time").monotonic() + 1,
        )

    child_pid = int(pid_file.read_text(encoding="utf-8"))
    assert term_marker.read_text(encoding="utf-8") == "term"
    if sys.platform.startswith("linux"):
        proc_stat = Path(f"/proc/{child_pid}/stat")
        if proc_stat.exists():
            assert proc_stat.read_text(encoding="utf-8").split()[2] == "Z"
    else:
        with pytest.raises(ProcessLookupError):
            os.kill(child_pid, 0)


def test_summary_preserves_partial_task_and_unknown_reservation_outcomes(tmp_path):
    result_path = tmp_path / "result.json"
    result_path.write_text("{}\n", encoding="utf-8")
    result = {
        "task_results": {
            "task-a": {"status": "SUCCEEDED"},
            "task-b": {"status": "FAILED", "error_code": "INTERRUPTED_UNKNOWN"},
            "task-c": {"status": "ATTACKER_CONTROLLED", "error_code": "Bearer secret"},
        },
        "budget": {"provider_calls_reserved": 2},
        "ledger": {
            "budget": {
                "settlements": {
                    "reservation-a": {"status": "SUCCEEDED"},
                    "reservation-b": {"status": "INTERRUPTED_UNKNOWN"},
                    "reservation-c": {"status": "attacker secret"},
                }
            }
        },
    }

    row = rehearsal._summary_row("resume", result_path, result, status="observed")

    assert sorted(item["status"] for item in row["task_outcomes"]) == ["FAILED", "SUCCEEDED", "UNKNOWN"]
    failed = next(item for item in row["task_outcomes"] if item["status"] == "FAILED")
    assert failed["error_code"] == "INTERRUPTED_UNKNOWN"
    assert "attacker secret" not in json.dumps(row)
    assert sorted(item["status"] for item in row["reservation_settlements"]) == [
        "INTERRUPTED_UNKNOWN",
        "SUCCEEDED",
    ]


def test_rehearsal_rejects_nonempty_output_directory(tmp_path):
    output = tmp_path / "out"
    output.mkdir()
    (output / "existing").write_text("preserve", encoding="utf-8")
    with pytest.raises(rehearsal.RehearsalError, match="output_directory_not_empty"):
        rehearsal.run_rehearsal(Path("/does/not/matter"), output, source_root=Path(__file__).resolve().parents[1])
    assert (output / "existing").read_text(encoding="utf-8") == "preserve"
    assert not (output / "recovery-rehearsal-summary.json").exists()


def test_failure_after_first_artifact_writes_safe_summary_and_retains_partial_outputs(monkeypatch, tmp_path):
    class FakeServer:
        endpoint = "http://127.0.0.1:1/v1"

        def __init__(self, _state):
            pass

        def serve_forever(self):
            return

        def shutdown(self):
            return

        def server_close(self):
            return

    def write_fixture(root, _endpoint, _deadline):
        repo = root / "fixture.git"
        repo.mkdir()
        profile = root / "profile.json"
        profile.write_text('{"version":"fixture"}\n', encoding="utf-8")
        limits = root / "limits.json"
        limits.write_text("{}\n", encoding="utf-8")
        provider = root / "provider.json"
        provider.write_text("{}\n", encoding="utf-8")
        return repo, "a" * 40, "b" * 40, profile, limits, provider

    def fail_after_durable_result(_cli, args, **_kwargs):
        output = Path(args[args.index("--output") + 1])
        run_id = args[args.index("--run-id") + 1]
        (output / f"{run_id}.json").write_text('{"status":"partial"}\n', encoding="utf-8")
        (output / f"{run_id}.md").write_text("Synthetic partial report\n", encoding="utf-8")
        raise rehearsal.RehearsalError("provider_failure_not_incomplete: MUST_NOT_LEAK_SECRET")

    monkeypatch.setattr(
        rehearsal,
        "_installed_cli",
        lambda *_args, **_kwargs: {"cli": "/installed/pr-review", "version": "0.1.0"},
    )
    monkeypatch.setattr(rehearsal, "_FakeProvider", FakeServer)
    monkeypatch.setattr(rehearsal, "_write_fixture", write_fixture)
    monkeypatch.setattr(rehearsal, "_run_cli", fail_after_durable_result)
    output = tmp_path / "output"

    summary = rehearsal.run_rehearsal(Path("/unused/cli"), output, source_root=tmp_path)

    assert summary["status"] == "failed"
    assert summary["failure_reason_code"] == "provider_failure_not_incomplete"
    assert summary["active_scenario"] == "provider_failure"
    assert summary["active_scenario_outcome"] == "UNKNOWN"
    assert summary["installed_runtime"] == {"cli": "/installed/pr-review", "version": "0.1.0"}
    assert summary["artifacts"]["state"] == "COMPLETE"
    assert {item["name"] for item in summary["artifacts"]["files"]} == {
        "recovery-http-failure.json",
        "recovery-http-failure.md",
    }
    assert (output / "artifacts/recovery-http-failure.json").read_text(encoding="utf-8") == '{"status":"partial"}\n'
    summary_path = output / "recovery-rehearsal-summary.json"
    assert summary_path.is_file()
    assert "MUST_NOT_LEAK_SECRET" not in summary_path.read_text(encoding="utf-8")


def test_early_setup_failure_writes_typed_summary_in_empty_output(monkeypatch, tmp_path):
    def fail_install(_cli, *_args, **_kwargs):
        raise rehearsal.RehearsalError("installed_cli_not_executable")

    monkeypatch.setattr(rehearsal, "_installed_cli", fail_install)
    output = tmp_path / "output"

    summary = rehearsal.run_rehearsal(Path("/unused/cli"), output, source_root=tmp_path)

    assert summary["status"] == "failed"
    assert summary["failure_reason_code"] == "installed_cli_not_executable"
    assert summary["active_scenario"] == "setup"
    assert summary["installed_runtime"] is None
    assert summary["provider_mode"] == "NOT_STARTED"
    assert summary["artifacts"]["state"] == "NONE"
    saved = json.loads((output / "recovery-rehearsal-summary.json").read_text(encoding="utf-8"))
    assert saved == summary


def test_cli_exits_nonzero_after_writing_failure_summary(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(
        rehearsal,
        "run_rehearsal",
        lambda *_args, **_kwargs: {
            "schema_version": "recovery-rehearsal.v1",
            "status": "failed",
            "failure_reason_code": "provider_failure_not_incomplete",
        },
    )

    code = rehearsal.main(["--cli", "/unused/cli", "--output-dir", str(tmp_path / "out")])

    assert code == 1
    assert json.loads(capsys.readouterr().out)["failure_reason_code"] == "provider_failure_not_incomplete"


@pytest.mark.skipif(os.name != "posix", reason="symlink boundary uses POSIX filesystem semantics")
def test_partial_artifact_collector_skips_symlinks_unknown_names_and_oversized_files(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    destination = tmp_path / "retained"
    safe = source / "recovery-http-failure.json"
    safe.write_text('{"status":"incomplete"}\n', encoding="utf-8")
    outside = tmp_path / "outside.txt"
    outside.write_text("must not be copied", encoding="utf-8")
    (source / "recovery-provider-timeout.md").symlink_to(outside)
    (source / "unexpected.txt").write_text("not an artifact", encoding="utf-8")
    oversized = source / "recovery-historical.json"
    with oversized.open("wb") as stream:
        stream.truncate(rehearsal.MAX_ARTIFACT_BYTES + 1)

    retained = rehearsal._collect_artifacts(source, destination)

    assert retained == {
        "state": "PARTIAL",
        "files": [
            {
                "name": "recovery-http-failure.json",
                "size_bytes": safe.stat().st_size,
                "sha256": rehearsal._hash_file(safe),
            }
        ],
        "total_bytes": safe.stat().st_size,
        "omitted_count": 3,
    }
    assert (destination / safe.name).read_bytes() == safe.read_bytes()
    assert not (destination / "recovery-provider-timeout.md").exists()
    assert not (destination / "unexpected.txt").exists()
    assert not (destination / "recovery-historical.json").exists()


def test_installed_wheel_workflow_runs_rehearsal_and_always_uploads_bounded_artifacts():
    source = (Path(__file__).resolve().parents[1] / ".github/workflows/test.yml").read_text(encoding="utf-8")
    top_level_jobs = list(re.finditer(r"(?m)^  ([A-Za-z0-9_-]+):\s*$", source))
    installed = next(match for match in top_level_jobs if match.group(1) == "installed-wheel")
    end = next((match.start() for match in top_level_jobs if match.start() > installed.start()), len(source))
    job = source[installed.start() : end]
    run_marker = "      - name: Run installed CLI recovery rehearsal with local fakes\n"
    upload_marker = "      - name: Retain bounded recovery rehearsal evidence\n"
    smoke_marker = "      - name: Install wheel in a fresh environment and smoke it outside the checkout\n"
    run = job[job.index(run_marker) : job.index(upload_marker)]
    upload = job[job.index(upload_marker) :]
    assert "python-version: ['3.11', '3.14']" in job
    assert "timeout-minutes: 10" in job
    assert job.index(smoke_marker) < job.index(run_marker) < job.index(upload_marker)
    assert '"$WHEEL_ENV/bin/python" scripts/run_recovery_rehearsal.py' in run
    assert '--cli "$WHEEL_ENV/bin/pr-review"' in run
    assert '--output-dir "$RECOVERY_OUTPUT_DIR"' in run
    assert "secrets." not in job and "OPENAI_API_KEY" not in job and "GITHUB_TOKEN" not in job
    assert "if: always()" in upload
    assert "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02" in upload
    assert "name: pr-review-recovery-${{ github.run_id }}-${{ matrix.python-version }}" in upload
    assert "recovery-rehearsal-summary.json" in upload and "/artifacts/" in upload
    assert "retention-days: 7" in upload and "if-no-files-found: warn" in upload
    assert "path: ${{ runner.temp }}" not in upload
