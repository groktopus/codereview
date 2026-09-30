import json
import os
import subprocess
import textwrap
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

WORKFLOW = Path(__file__).parents[1] / ".github/workflows/slopsearx-direct-diagnostic.yml"
REUSABLE = Path(__file__).parents[1] / ".github/workflows/pr-analysis.yml"
PIN = "109a3bcba09362c5c808c86d029be0c6d0b521fa"
SECRETS = (
    "LLM_BASE_URL",
    "LLM_MODEL",
    "LLM_API_KEY",
    "JEV_BASE_URL",
    "JEV_MODEL",
    "JEV_API_KEY",
)


def _source(path: Path = WORKFLOW) -> str:
    return path.read_text(encoding="utf-8")


def _step(source: str, name: str) -> str:
    marker = f"      - name: {name}\n"
    start = source.index(marker)
    following = source.find("\n      - ", start + len(marker))
    return source[start:] if following < 0 else source[start:following] + "\n"


def _python_script(step: str) -> str:
    block = step.split("        run: |\n", 1)[1]
    lines = block.removeprefix("          python - <<'PY'\n").splitlines()
    script = []
    for line in lines:
        if line.strip() == "PY":
            break
        if line.strip() and not line.startswith("          "):
            break
        script.append(line[10:] if line else "")
    if not script:
        raise AssertionError("embedded_python_missing")
    return textwrap.dedent("\n".join(script))


def _record(number=477):
    return {
        "number": number,
        "state": "open",
        "draft": False,
        "base": {
            "ref": "main",
            "sha": "c355830512fa5bffc167926a6a167bace93d96c6",
            "repo": {"full_name": "magnus919/SlopSearX"},
        },
        "head": {"sha": "c8496b74d8e1da05a2ed654772fc4b1b1fcff56b"},
    }


def _pull_request_event(number=477):
    record = _record(number)
    return {
        "number": number,
        "pull_request": {
            "base": {"sha": record["base"]["sha"]},
            "head": {"sha": record["head"]["sha"]},
        },
    }


def _run_resolver(monkeypatch, tmp_path, raw_number="477", record=None):
    source = _source()
    resolver = _step(source, "Resolve current open SlopSearX PR identity using read-only GitHub API")
    namespace = {"__name__": "test_direct_pilot_metadata"}
    exec(compile(_python_script(resolver), "direct diagnostic resolver", "exec"), namespace)
    output = tmp_path / "github-output"
    output.write_text("", encoding="utf-8")
    monkeypatch.setenv("GITHUB_REPOSITORY", "groktopus/codereview")
    monkeypatch.setenv("GITHUB_REF", "refs/heads/main")
    monkeypatch.setenv("GITHUB_EVENT_NAME", "workflow_dispatch")
    monkeypatch.setenv("PR_NUMBER", raw_number)
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))

    def fake_run(command, **kwargs):
        assert command[:4] == ["gh", "api", f"repos/magnus919/SlopSearX/pulls/{int(raw_number)}", "--jq"]
        assert kwargs["timeout"] == 15
        return SimpleNamespace(returncode=0, stdout=json.dumps(record or _record(int(raw_number))))

    with patch.object(subprocess, "run", side_effect=fake_run):
        namespace["main"]()
    return output.read_text(encoding="utf-8")


def _run_event_validator(tmp_path, document=None, raw=None):
    source = _source()
    step = _step(source, "Validate generated PR event against the read-only resolver identity")
    namespace = {"__name__": "test_direct_pilot_event_validation"}
    exec(compile(_python_script(step), "direct diagnostic event validation", "exec"), namespace)
    path = tmp_path / "pr-event.json"
    path.write_bytes(raw if raw is not None else json.dumps(document or _pull_request_event()).encode("utf-8"))
    with patch.dict(
        os.environ,
        {
            "PR_EVENT_PATH": str(path),
            "EXPECTED_PR_NUMBER": "477",
            "EXPECTED_BASE_SHA": _record()["base"]["sha"],
            "EXPECTED_HEAD_SHA": _record()["head"]["sha"],
        },
    ):
        namespace["main"]()


def test_generated_event_is_checked_against_api_resolver_outputs_before_config_or_inference(tmp_path):
    source = _source()
    resolver = _step(source, "Resolve current open SlopSearX PR identity using read-only GitHub API")
    validator = _step(source, "Validate generated PR event against the read-only resolver identity")
    config = _step(source, "Materialize private provider configuration from the six trusted secrets")
    assert 'stream.write(f"number={number}\\nbase_ref=main\\nbase_sha={base_sha}\\nhead_sha={head_sha}\\n")' in resolver
    assert "EXPECTED_PR_NUMBER: ${{ steps.resolve-target.outputs.number }}" in validator
    assert "EXPECTED_BASE_SHA: ${{ steps.resolve-target.outputs.base_sha }}" in validator
    assert "EXPECTED_HEAD_SHA: ${{ steps.resolve-target.outputs.head_sha }}" in validator
    assert source.index(validator) < source.index(config)
    assert "MAX_EVENT_BYTES = 16_384" in validator
    assert "stream.read(MAX_EVENT_BYTES + 1)" in validator
    assert "object_pairs_hook=reject_duplicates" in validator
    assert 'set(document) != {"number", "pull_request"}' in validator
    assert 'base.get("sha") != base_sha or head.get("sha") != head_sha' in validator
    assert "print(" not in validator
    _run_event_validator(tmp_path)


@pytest.mark.parametrize(
    "document",
    [
        {**_pull_request_event(), "action": "opened"},
        {**_pull_request_event(), "number": 478},
        {
            "number": 477,
            "pull_request": {
                "base": {"sha": "1" * 40},
                "head": {"sha": _record()["head"]["sha"]},
            },
        },
        {
            "number": 477,
            "pull_request": {
                "base": {"sha": _record()["base"]["sha"]},
                "head": {"sha": "2" * 40},
            },
        },
    ],
)
def test_generated_event_rejects_unexpected_or_resolver_mismatched_metadata(tmp_path, document):
    with pytest.raises(SystemExit, match="generated_pull_request_event_invalid"):
        _run_event_validator(tmp_path, document=document)


def test_generated_event_rejects_oversized_and_duplicate_key_json(tmp_path):
    with pytest.raises(SystemExit, match="generated_pull_request_event_invalid"):
        _run_event_validator(tmp_path, raw=b"{" + b" " * 16_384 + b"}")
    with pytest.raises(SystemExit, match="generated_pull_request_event_invalid"):
        _run_event_validator(tmp_path, raw=b'{"number":477,"number":477,"pull_request":{}}')


def test_cli_entrypoint_uses_explicit_generated_event_not_native_dispatch_payload(monkeypatch, tmp_path, capsys):
    monkeypatch.syspath_prepend(str(Path(__file__).parents[1] / "src"))
    from pr_review_harness import cli, github

    dispatch_event = tmp_path / "workflow-dispatch-event.json"
    dispatch_event.write_text(
        json.dumps({"workflow": "workflow_dispatch", "inputs": {"pull_request_number": "477"}}),
        encoding="utf-8",
    )
    pull_request_event = tmp_path / "resolved-pr-event.json"
    pull_request_event.write_text(json.dumps(_pull_request_event()), encoding="utf-8")
    profile = tmp_path / "profile.json"
    profile.write_text(
        json.dumps({"version": "direct-event-regression-v1", "repository": "magnus919/SlopSearX", "context_paths": []}),
        encoding="utf-8",
    )
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(dispatch_event))
    monkeypatch.setenv("GITHUB_REPOSITORY", "magnus919/SlopSearX")
    monkeypatch.setenv("GITHUB_RUN_ID", "diagnostic-run-42")
    checks = []
    calls = []

    def fake_check_runs(_self, repository, head_sha):
        checks.append((repository, head_sha))
        return {"runs": [], "complete": False}

    def fake_run_one(*args):
        calls.append(args)
        return {"disposition": "INCOMPLETE", "run_id": args[7]}

    monkeypatch.setattr(github.GitHubPRAdapter, "check_runs", fake_check_runs)
    monkeypatch.setattr(cli, "_run_one", fake_run_one)
    code = cli.main(
        [
            "review",
            "--repo",
            str(tmp_path),
            "--event-file",
            str(pull_request_event),
            "--profile",
            str(profile),
            "--output",
            str(tmp_path / "reports"),
            "--run-id",
            "diag-477-42",
            "--json",
        ]
    )

    assert code == 0
    assert len(calls) == 1
    assert calls[0][1] == _record()["base"]["sha"]
    assert calls[0][2] == _record()["head"]["sha"]
    event = calls[0][8]
    assert event["repository"] == "magnus919/SlopSearX"
    assert event["pull_request_number"] == 477
    assert event["base_sha"] == _record()["base"]["sha"]
    assert event["head_sha"] == _record()["head"]["sha"]
    assert checks == [("magnus919/SlopSearX", _record()["head"]["sha"])]
    assert json.loads(capsys.readouterr().out)["disposition"] == "INCOMPLETE"


def test_workflow_is_manual_main_only_and_accepts_only_a_bounded_pr_number():
    source = _source()
    dispatch = source.split("on:\n", 1)[1].split("\npermissions:\n", 1)[0]
    assert "workflow_dispatch:" in dispatch
    assert "pull_request_number:" in dispatch
    assert "default: 477" in dispatch
    assert "type: number" in dispatch
    assert "target_repository:" not in dispatch
    assert "base_sha:" not in dispatch and "head_sha:" not in dispatch
    assert "LLM_BASE_URL:" not in dispatch and "JEV_BASE_URL:" not in dispatch
    assert "if: github.event_name == 'workflow_dispatch'" in source
    assert "github.repository == 'groktopus/codereview'" in source
    assert "github.ref == 'refs/heads/main'" in source


def test_harness_is_checked_out_at_the_approved_sha_and_verified_before_install():
    source = _source()
    checkout = _step(source, "Check out the approved immutable harness source")
    verify = _step(source, "Verify the approved harness revision before install or import")
    acquire = _step(source, "Revalidate PR identity and acquire immutable target objects in a bare store")
    assert "repository: groktopus/codereview" in checkout
    assert f"ref: {PIN}" in checkout
    assert "persist-credentials: false" in checkout
    assert f"EXPECTED_HARNESS_SHA: {PIN}" in verify
    assert f"HARNESS_SHA: {PIN}" in acquire
    assert source.count(PIN) == 3
    assert '"$ACTUAL_HARNESS_SHA" != "$EXPECTED_HARNESS_SHA"' in verify
    assert source.index("Verify the approved harness revision") < source.index("python -m pip install .")
    assert f"{PIN}" not in _step(source, "Resolve current open SlopSearX PR identity using read-only GitHub API")


def test_resolution_is_read_only_fixed_target_and_rejects_bad_numbers_before_api(monkeypatch, tmp_path):
    source = _source()
    resolver = _step(source, "Resolve current open SlopSearX PR identity using read-only GitHub API")
    assert "GH_TOKEN: ${{ github.token }}" in resolver
    assert "LLM_API_KEY" not in resolver and "JEV_API_KEY" not in resolver
    assert '"GITHUB_REPOSITORY") != "groktopus/codereview"' in resolver
    assert '"GITHUB_REF") != "refs/heads/main"' in resolver
    assert '"GITHUB_EVENT_NAME") != "workflow_dispatch"' in resolver
    assert "repos/magnus919/SlopSearX/pulls/{number}" in resolver
    assert "[1-9][0-9]{0,8}" in resolver
    assert _run_resolver(monkeypatch, tmp_path) == (
        "number=477\n"
        "base_ref=main\n"
        "base_sha=c355830512fa5bffc167926a6a167bace93d96c6\n"
        "head_sha=c8496b74d8e1da05a2ed654772fc4b1b1fcff56b\n"
    )

    namespace = {"__name__": "test_direct_pilot_bad_number"}
    exec(compile(_python_script(resolver), "direct diagnostic resolver", "exec"), namespace)
    monkeypatch.setenv("PR_NUMBER", "477; echo unsafe")
    monkeypatch.setenv("GITHUB_OUTPUT", str(tmp_path / "invalid-output"))
    with patch.object(subprocess, "run") as run:
        with pytest.raises(SystemExit, match="pull_request_number_invalid"):
            namespace["main"]()
    run.assert_not_called()


@pytest.mark.parametrize(
    ("variable", "value", "reason"),
    [
        ("GITHUB_REPOSITORY", "untrusted/fork", "caller_repository_mismatch"),
        ("GITHUB_REF", "refs/heads/feature", "dispatch_ref_not_main"),
        ("GITHUB_EVENT_NAME", "pull_request_target", "dispatch_event_invalid"),
    ],
)
def test_resolver_rejects_untrusted_repo_ref_or_event_before_api_or_output(
    monkeypatch, tmp_path, variable, value, reason
):
    resolver = _step(_source(), "Resolve current open SlopSearX PR identity using read-only GitHub API")
    namespace = {"__name__": "test_direct_pilot_invocation_boundary"}
    exec(compile(_python_script(resolver), "direct diagnostic resolver", "exec"), namespace)
    output = tmp_path / "github-output"
    output.write_text("", encoding="utf-8")
    monkeypatch.setenv("GITHUB_REPOSITORY", "groktopus/codereview")
    monkeypatch.setenv("GITHUB_REF", "refs/heads/main")
    monkeypatch.setenv("GITHUB_EVENT_NAME", "workflow_dispatch")
    monkeypatch.setenv("PR_NUMBER", "477")
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))
    monkeypatch.setenv(variable, value)

    with patch.object(subprocess, "run") as run:
        with pytest.raises(SystemExit, match=reason):
            namespace["main"]()

    run.assert_not_called()
    assert output.read_bytes() == b""


def test_revalidated_target_is_bare_fetched_and_never_checked_out_or_executed():
    source = _source()
    acquire = _step(source, "Revalidate PR identity and acquire immutable target objects in a bare store")
    script = _python_script(acquire)
    assert "GitHubPRAdapter().pull_request(target, number)" in script
    assert "current['base_sha'] != base_sha or current['head_sha'] != head_sha" in script
    assert "git('git', 'init', '--bare', store)" in script
    assert "refs/pull/{number}/head:refs/pr/head" in script
    assert "f'+{base_sha}:refs/pr/base'" in script
    assert "git('git', 'checkout'" not in script
    assert "git('git', 'clone'" not in script
    assert "subprocess.run(['git', '-C', store, 'checkout'" not in script
    assert "python -m pytest" not in source
    assert "npm install" not in source
    assert "npm test" not in source


def test_only_six_step_scoped_secrets_and_read_permissions_no_publication():
    source = _source()
    assert "pull-requests: read" in source
    assert "checks: read" in source
    assert "contents: read" in source
    for denied in ("contents: write", "pull-requests: write", "checks: write", "actions: write"):
        assert denied not in source
    assert "pr-publish" not in source
    assert "pr-review publish" not in source
    assert "review.create" not in source
    assert "createReview" not in source

    config = _step(source, "Materialize private provider configuration from the six trusted secrets")
    review = _step(source, "Produce the bounded read-only review report")
    for name in SECRETS:
        assert f"{name}: ${{{{ secrets.{name} }}}}" in config
    assert "LLM_API_KEY: ${{ secrets.LLM_API_KEY }}" in review
    assert "JEV_API_KEY: ${{ secrets.JEV_API_KEY }}" in review
    assert "secrets: inherit" not in source
    for forbidden in ("NOUS_API_KEY", "MODEL_CATALOG", "llm_base_url:", "jev_endpoint:"):
        assert forbidden not in source
    assert "GITHUB_EVENT_PATH:" not in source
    assert "GITHUB_REPOSITORY:" not in source
    assert "GITHUB_RUN_ID:" not in source
    assert "GITHUB_SERVER_URL:" not in source
    assert "--max-claim-assessments" not in source


def test_direct_diagnostic_uses_same_config_helper_and_bounded_review_command():
    direct = _source()
    reusable = _source(REUSABLE)
    direct_config = _step(direct, "Materialize private provider configuration from the six trusted secrets")
    reusable_config = _step(reusable, "Materialize private provider configuration from trusted secrets")
    assert (
        direct_config.split("        run: |\n", 1)[1].rstrip()
        == reusable_config.split("        run: |\n", 1)[1].rstrip()
    )

    direct_review = _step(direct, "Produce the bounded read-only review report")
    reusable_review = _step(reusable, "Produce a bounded read-only report from the bare target object store")
    direct_command = direct_review.split("        run: |\n", 1)[1]
    direct_command = direct_command.replace(
        "env GITHUB_REPOSITORY=magnus919/SlopSearX pr-review review",
        'env GITHUB_REPOSITORY="$TARGET_REPOSITORY" pr-review review',
        1,
    )
    reusable_command = reusable_review.split("        run: |\n", 1)[1]
    reusable_command = reusable_command.replace(
        '          test "$(sha256sum "$PROFILE" | cut -d\' \' -f1)" = "$EXPECTED_PROFILE_SHA256"\n',
        "",
        1,
    )
    reusable_command = reusable_command.replace(
        "            --capture-recovery-inputs artifacts/recovery-inputs.json \\\n",
        "",
        1,
    )
    # Keep the historical diagnostic's default limits and zero candidate cap;
    # remove only the two explicit ordinary-path additions.
    bounded_claim_cap = "            --max-claim-assessments 1 \\\n"
    assert reusable_command.count(bounded_claim_cap) == 1
    reusable_command = reusable_command.replace(bounded_claim_cap, "", 1)
    review_limits = "            --limits profiles/ordinary-review-limits-v2.json \\\n"
    assert reusable_command.count(review_limits) == 1
    reusable_command = reusable_command.replace(review_limits, "", 1)
    assert direct_command.rstrip() == reusable_command.rstrip()
    assert "PR_EVENT_PATH: ${{ runner.temp }}/pr-event.json" in direct_review
    assert "env GITHUB_REPOSITORY=magnus919/SlopSearX pr-review review" in direct_review
    assert '--event-file "$PR_EVENT_PATH"' in direct_review
    assert "PR_EVENT_PATH: ${{ runner.temp }}/pr-event.json" in reusable_review
    assert "TARGET_REPOSITORY: ${{ inputs.target_repository }}" in reusable_review
    assert 'env GITHUB_REPOSITORY="$TARGET_REPOSITORY" pr-review review' in reusable_command
    assert '--event-file "$PR_EVENT_PATH"' in reusable_command
    assert "PROFILE: profiles/slopsearx.json" in direct_review
    assert "--mode AUTO" in direct_review
    assert "--json > artifacts/review-result.json" in direct_review
    assert "--limits" not in direct_review
    assert "--max-claim-assessments" not in direct_review
    assert "--capture-recovery-inputs artifacts/recovery-inputs.json" not in direct_review
    assert "--capture-recovery-inputs artifacts/recovery-inputs.json" in reusable_review


def test_workflow_does_not_invoke_the_unobservable_reusable_job_or_any_writer():
    source = _source()
    assert "uses: groktopus/codereview/.github/workflows/pr-analysis.yml@" not in source
    assert "workflow_call:" not in source
    assert "pr-publish.yml" not in source
    assert "github.event.workflow_run" not in source
    assert "actions/upload-artifact@" in source
    assert "pull-requests: write" not in source
