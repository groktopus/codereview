import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit

import pytest

from pr_review_harness.actions_publication import ArtifactUploadResult, HTTPResponse
from pr_review_harness.actions_runtime import (
    ActionsRuntimeError,
    CanaryExpectation,
    OfficialActionsArtifactUploader,
    canary_expectation_from_environment,
    run_actions_canary,
    verify_read_only_actions_context,
)

PUBLISH_SHA = "a" * 40
BASE = "b" * 40
HEAD = "c" * 40
CALLER_SHA = "d" * 40


def expectation(**overrides):
    values = {
        "repository": "owner/repo",
        "repository_id": 8123,
        "publisher_run_id": 900001,
        "publisher_run_attempt": 2,
        "publisher_workflow_id": 904,
        "publisher_workflow_path": ".github/workflows/pr-publish.yml",
        "publisher_workflow_ref": "refs/heads/main",
        "publisher_workflow_sha": PUBLISH_SHA,
        "upstream_run_id": 731245,
        "upstream_run_attempt": 3,
        "caller_workflow_id": 563,
        "caller_workflow_path": ".github/workflows/pr-analysis-caller.yml",
        "caller_workflow_ref": "refs/heads/main",
        "pull_request_number": 44,
        "base_sha": BASE,
        "head_sha": HEAD,
        "expected_actor_login": "review-agent[bot]",
    }
    values.update(overrides)
    return CanaryExpectation(**values)


def api_record(endpoint):
    if endpoint == "authenticated_actor":
        return {"login": "review-agent[bot]"}
    if endpoint == "repository":
        return {"id": 8123, "full_name": "owner/repo"}
    if endpoint == "publisher_run":
        return {
            "id": 900001,
            "run_attempt": 2,
            "workflow_id": 904,
            "repository": {"id": 8123},
            "head_sha": PUBLISH_SHA,
            "path": ".github/workflows/pr-publish.yml@main",
        }
    if endpoint == "upstream_run":
        return {
            "id": 731245,
            "run_attempt": 3,
            "workflow_id": 563,
            "repository": {"id": 8123},
            "head_sha": "e" * 40,
            "path": ".github/workflows/pr-analysis-caller.yml@main",
            "event": "pull_request",
            "status": "completed",
            "conclusion": "success",
            "pull_requests": [{"number": 44, "base": {"sha": BASE}, "head": {"sha": HEAD}}],
        }
    if endpoint == "pull_request":
        return {
            "number": 44,
            "state": "open",
            "base": {"sha": BASE, "repo": {"id": 8123}},
            "head": {"sha": HEAD},
        }
    raise AssertionError(endpoint)


class FakeReadTransport:
    def __init__(self, *, overrides=None, statuses=None):
        self.overrides = overrides or {}
        self.statuses = statuses or {}
        self.calls = []

    def request(self, method, url, *, token, json_body, timeout_seconds, max_response_bytes):
        path = urlsplit(url).path
        endpoint = "authenticated_actor" if url.endswith("/user") else path.rsplit("/", 1)[-1]
        if path == "/repos/owner/repo":
            endpoint = "repository"
        if "/pulls/" in path:
            endpoint = "pull_request"
        if "/actions/runs/" in url:
            endpoint = "publisher_run" if "/attempts/2" in url else "upstream_run"
        self.calls.append((method, url, token, json_body, timeout_seconds, max_response_bytes))
        value = self.overrides.get(endpoint, api_record(endpoint))
        return HTTPResponse(self.statuses.get(endpoint, 200), {}, json.dumps(value).encode())


def test_read_only_canary_binds_current_default_branch_run_upstream_pr_and_actor_without_write_capability():
    transport = FakeReadTransport()
    result = verify_read_only_actions_context(expectation(), "short-lived-test-token", transport=transport)

    assert result.state == "READ_ONLY_CONTEXT_VERIFIED"
    assert result.actor_binding == "MATCHED_TRUSTED_POLICY"
    assert result.api_actor_login == "review-agent[bot]"
    assert result.verified_reads == (
        "authenticated_actor",
        "repository",
        "publisher_run",
        "upstream_run",
        "pull_request",
    )
    assert result.publication_capability == "UNAVAILABLE"
    assert result.write_permission == "NOT_TESTED"
    assert api_record("upstream_run")["head_sha"] != HEAD
    assert result.as_dict()["safe_to_publish"] is False
    assert all(call[0] == "GET" and call[3] is None for call in transport.calls)
    assert all("/attempts/" in call[1] for call in transport.calls if "/actions/runs/" in call[1])
    assert all(call[2] == "short-lived-test-token" for call in transport.calls)


def test_github_token_may_not_identify_an_actor_and_never_becomes_verified_writer():
    transport = FakeReadTransport(statuses={"authenticated_actor": 401})
    result = verify_read_only_actions_context(expectation(), "installation-token", transport=transport)

    assert result.state == "READ_ONLY_CONTEXT_VERIFIED"
    assert result.api_actor_login is None
    assert result.actor_binding == "UNAVAILABLE"
    assert result.publication_capability == "UNAVAILABLE"
    assert result.write_permission == "NOT_TESTED"


def test_upstream_head_mismatch_is_unknown_even_when_pr_event_summary_matches():
    upstream = api_record("upstream_run")
    upstream["pull_requests"][0]["head"]["sha"] = "e" * 40
    result = verify_read_only_actions_context(
        expectation(),
        "read-token",
        transport=FakeReadTransport(overrides={"upstream_run": upstream}),
    )
    assert result.state == "UNKNOWN"
    assert result.reason == "upstream_run_identity_mismatch"
    assert "pull_request" not in result.verified_reads
    assert result.publication_capability == "UNAVAILABLE"


def test_publisher_run_must_match_protected_workflow_sha_not_pr_head():
    publisher = api_record("publisher_run")
    publisher["head_sha"] = HEAD
    result = verify_read_only_actions_context(
        expectation(),
        "read-token",
        transport=FakeReadTransport(overrides={"publisher_run": publisher}),
    )
    assert result.state == "UNKNOWN"
    assert result.reason == "publisher_run_identity_mismatch"


@pytest.mark.parametrize(
    ("field", "value"),
    [("base_sha", "f" * 40), ("head_sha", "e" * 40)],
)
def test_canary_rejects_a_pr_that_moved_after_the_upstream_run(field, value):
    pull = api_record("pull_request")
    pull["base" if field == "base_sha" else "head"]["sha"] = value
    transport = FakeReadTransport(overrides={"pull_request": pull})

    result = verify_read_only_actions_context(expectation(), "read-token", transport=transport)

    assert result.state == "UNKNOWN"
    assert result.reason == "pull_request_identity_mismatch"
    assert [call[1] for call in transport.calls].count("https://api.github.com/repos/owner/repo/pulls/44") == 1


def test_canary_does_not_retry_failed_read_or_claim_freshness():
    transport = FakeReadTransport(statuses={"publisher_run": 503})

    result = verify_read_only_actions_context(expectation(), "read-token", transport=transport)

    assert result.state == "UNKNOWN"
    assert result.reason == "github_read_unavailable"
    assert len(transport.calls) == 3
    assert sum("/actions/runs/900001/attempts/2" in call[1] for call in transport.calls) == 1


def test_api_json_duplicate_keys_nonfinite_and_excessive_nesting_fail_closed():
    class RawTransport(FakeReadTransport):
        def __init__(self, body):
            super().__init__()
            self.body = body

        def request(self, method, url, **kwargs):
            if url.endswith("/user"):
                return HTTPResponse(200, {}, self.body)
            return super().request(method, url, **kwargs)

    for body, reason in (
        (b'{"login":"ok","login":"review-agent[bot]"}', "github_response_invalid_json"),
        (b'{"login":NaN}', "github_response_invalid_json"),
        (b'{"login":' + b"[" * 100 + b"0" + b"]" * 100 + b"}", "github_response_complexity_exceeded"),
    ):
        result = verify_read_only_actions_context(expectation(), "read-token", transport=RawTransport(body))
        assert result.state == "UNKNOWN"
        assert result.reason == reason
        assert result.publication_capability == "UNAVAILABLE"


def test_canary_input_uses_platform_event_and_repository_policy_not_actor_context(tmp_path):
    event = {
        "repository": {"id": 8123},
        "workflow_run": {
            "name": "PR Review Analysis",
            "id": 731245,
            "run_attempt": 3,
            "pull_requests": [{"number": 44, "base": {"sha": BASE}, "head": {"sha": HEAD}}],
        },
    }
    event_path = tmp_path / "event.json"
    event_path.write_text(json.dumps(event))
    environ = {
        "GITHUB_REPOSITORY": "owner/repo",
        "GITHUB_RUN_ID": "900001",
        "GITHUB_RUN_ATTEMPT": "2",
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_SHA": PUBLISH_SHA,
        "GITHUB_EVENT_PATH": str(event_path),
        "GITHUB_TOKEN": "read-only-token",
        "GITHUB_ACTOR": "attacker-chosen-context",
        "PR_REVIEW_PUBLISHER_WORKFLOW_ID": "904",
        "PR_REVIEW_ANALYSIS_WORKFLOW_ID": "563",
        "PR_REVIEW_ANALYSIS_WORKFLOW_NAME": "PR Review Analysis",
        "PR_REVIEW_ANALYSIS_WORKFLOW_PATH": ".github/workflows/pr-analysis-caller.yml",
        "PR_REVIEW_ANALYSIS_WORKFLOW_REF": "refs/heads/main",
        "PR_REVIEW_PUBLISHER_ACTOR": "review-agent[bot]",
    }

    class FakeUploader:
        def upload(self, **kwargs):
            assert kwargs["run_id"] == 900001
            assert kwargs["filename"] == "canary.json"
            return ArtifactUploadResult("UPLOADED", artifact_id=73)

    result = run_actions_canary(environ, transport=FakeReadTransport(), uploader=FakeUploader())
    assert result["api_actor_login"] == "review-agent[bot]"
    assert result["api_actor_login"] != environ["GITHUB_ACTOR"]
    assert result["artifact_upload_state"] == "UPLOADED"
    assert result["artifact_id"] == 73
    assert result["safe_to_publish"] is False


def test_canary_rejects_workflow_name_that_does_not_match_trigger_contract():
    environ = {
        "GITHUB_REPOSITORY": "owner/repo",
        "GITHUB_RUN_ID": "900001",
        "GITHUB_RUN_ATTEMPT": "2",
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_SHA": PUBLISH_SHA,
        "PR_REVIEW_PUBLISHER_WORKFLOW_ID": "904",
        "PR_REVIEW_ANALYSIS_WORKFLOW_ID": "563",
        "PR_REVIEW_ANALYSIS_WORKFLOW_NAME": "PR Review Analysis",
        "PR_REVIEW_ANALYSIS_WORKFLOW_PATH": ".github/workflows/pr-analysis-caller.yml",
        "PR_REVIEW_ANALYSIS_WORKFLOW_REF": "refs/heads/main",
    }
    event = {
        "repository": {"id": 8123},
        "workflow_run": {
            "name": "Renamed or unrelated workflow",
            "id": 731245,
            "run_attempt": 3,
            "pull_requests": [{"number": 44, "base": {"sha": BASE}, "head": {"sha": HEAD}}],
        },
    }
    with pytest.raises(ActionsRuntimeError, match="workflow_event_name_mismatch"):
        canary_expectation_from_environment(environ, json.dumps(event).encode())


def test_untrusted_or_missing_runtime_policy_only_produces_unknown_artifact(tmp_path):
    event_path = tmp_path / "event.json"
    event_path.write_text('{"repository":{"id":8123},"workflow_run":{"pull_requests":[]}}')
    environ = {"GITHUB_EVENT_PATH": str(event_path), "GITHUB_RUN_ID": "900001"}

    class FakeUploader:
        def upload(self, **kwargs):
            assert json.loads(kwargs["content"])["state"] == "UNKNOWN"
            return ArtifactUploadResult("UNAVAILABLE", reason_code="artifact_runtime_unavailable")

    result = run_actions_canary(environ, uploader=FakeUploader())
    assert result["state"] == "UNKNOWN"
    assert result["publication_capability"] == "UNAVAILABLE"
    assert result["artifact_upload_state"] == "UNAVAILABLE"


def test_environment_event_rejects_duplicate_or_malformed_identity_fields():
    env = {
        "GITHUB_REPOSITORY": "owner/repo",
        "GITHUB_RUN_ID": "900001",
        "GITHUB_RUN_ATTEMPT": "2",
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_SHA": PUBLISH_SHA,
        "PR_REVIEW_PUBLISHER_WORKFLOW_ID": "904",
        "PR_REVIEW_ANALYSIS_WORKFLOW_ID": "563",
        "PR_REVIEW_ANALYSIS_WORKFLOW_NAME": "PR Review Analysis",
        "PR_REVIEW_ANALYSIS_WORKFLOW_PATH": ".github/workflows/pr-analysis-caller.yml",
        "PR_REVIEW_ANALYSIS_WORKFLOW_REF": "refs/heads/main",
    }
    with pytest.raises(ActionsRuntimeError, match="workflow_event_invalid_json"):
        canary_expectation_from_environment(env, b'{"workflow_run":{},"workflow_run":{}}')
    with pytest.raises(ActionsRuntimeError, match="workflow_event_pr_binding_missing_or_ambiguous"):
        canary_expectation_from_environment(env, b'{"repository":{"id":8123},"workflow_run":{"pull_requests":[]}}')


def fake_artifact_package(helper_dir: Path) -> None:
    package = helper_dir / "node_modules/@actions/artifact"
    package.mkdir(parents=True)
    (package / "package.json").write_text('{"name":"@actions/artifact","type":"module","exports":"./index.js"}')
    (package / "index.js").write_text(
        "import {readFileSync} from 'node:fs';\n"
        "import path from 'node:path';\n"
        "export class DefaultArtifactClient { async uploadArtifact(name, files, root, options) {\n"
        " if (!process.env.ACTIONS_RUNTIME_TOKEN || !process.env.ACTIONS_RESULTS_URL) throw new Error('runtime missing');\n"
        " if (name !== 'test-canary' || files.length !== 1 || path.basename(files[0]) !== 'exact-name.json' || root !== path.dirname(files[0]) || options.retentionDays !== 7) throw new Error('arguments invalid');\n"
        " const data = readFileSync(files[0]);\n"
        " process.stdout.write('SDK LOG MUST NOT PARSE AS RESPONSE\\n');\n"
        " process.stderr.write('credential-free SDK diagnostics\\n');\n"
        " return {id: 77, size: data.length};\n"
        "} }\n"
    )


def uploader_environment(**overrides):
    values = {
        "GITHUB_RUN_ID": "900001",
        "GITHUB_RUN_ATTEMPT": "2",
        "PATH": os.environ.get("PATH", os.defpath),
        "ACTIONS_RUNTIME_TOKEN": "runner-runtime-secret",
        "ACTIONS_RESULTS_URL": "https://results-receiver.actions.githubusercontent.com/",
        "ACTIONS_RUNTIME_URL": "https://pipelines.actions.githubusercontent.com/",
        "GITHUB_TOKEN": "api-token-must-not-forward",
        "GH_TOKEN": "gh-token-must-not-forward",
        "NOUS_API_KEY": "provider-secret-must-not-forward",
        "NODE_OPTIONS": "--require=/tmp/untrusted.js",
    }
    values.update(overrides)
    return values


def test_official_sdk_bridge_uses_exact_filename_real_subprocess_and_scoped_env(tmp_path):
    if not shutil.which("node"):
        pytest.skip("Node.js is not available")
    helper_dir = tmp_path / "bridge"
    helper_dir.mkdir()
    script = Path(__file__).parents[1] / "scripts/actions-artifact-uploader/upload.mjs"
    test_script = helper_dir / "upload.mjs"
    test_script.write_bytes(script.read_bytes())
    fake_artifact_package(helper_dir)
    child_environments = []
    real_popen = subprocess.Popen

    def capture_popen(argv, **kwargs):
        child_environments.append(dict(kwargs["env"]))
        manifest = json.loads(Path(kwargs["env"]["PR_REVIEW_UPLOAD_INPUT"]).read_text())
        assert manifest["filename"] == "exact-name.json"
        assert manifest["content_file"] == "exact-name.json"
        content_path = Path(kwargs["env"]["PR_REVIEW_UPLOAD_INPUT"]).parent / manifest["content_file"]
        assert content_path.name == "exact-name.json"
        assert content_path.read_bytes() == b'{"canary":true}\n'
        return real_popen(argv, **kwargs)

    result = OfficialActionsArtifactUploader(
        script_path=test_script,
        environ=uploader_environment(),
        popen=capture_popen,
    ).upload(
        run_id=900001,
        artifact_name="test-canary",
        filename="exact-name.json",
        content=b'{"canary":true}\n',
        timeout_seconds=3,
    )

    assert result.status == "UPLOADED"
    assert result.artifact_id == 77
    assert len(child_environments) == 1
    child_env = child_environments[0]
    assert child_env["ACTIONS_RUNTIME_TOKEN"] == "runner-runtime-secret"
    assert child_env["ACTIONS_RESULTS_URL"] == "https://results-receiver.actions.githubusercontent.com/"
    assert not {"GITHUB_TOKEN", "GH_TOKEN", "NOUS_API_KEY", "NODE_OPTIONS"} & child_env.keys()
    assert child_env["PR_REVIEW_UPLOAD_INPUT"].endswith("/input.json")


def test_official_sdk_bridge_rejects_receipt_bytes_that_change_after_hashing(tmp_path):
    if not shutil.which("node"):
        pytest.skip("Node.js is not available")
    helper_dir = tmp_path / "bridge"
    helper_dir.mkdir()
    script = Path(__file__).parents[1] / "scripts/actions-artifact-uploader/upload.mjs"
    test_script = helper_dir / "upload.mjs"
    test_script.write_bytes(script.read_bytes())
    fake_artifact_package(helper_dir)
    marker = tmp_path / "artifact-sdk-called"
    package_source = helper_dir / "node_modules/@actions/artifact/index.js"
    package_source.write_text(
        "import {writeFileSync} from 'node:fs';\n"
        f"export class DefaultArtifactClient {{ async uploadArtifact() {{ writeFileSync({json.dumps(str(marker))}, 'called'); return {{id:77,size:1}} }} }}\n"
    )
    real_popen = subprocess.Popen

    def mutate_then_spawn(argv, **kwargs):
        manifest = json.loads(Path(kwargs["env"]["PR_REVIEW_UPLOAD_INPUT"]).read_text())
        content = Path(kwargs["env"]["PR_REVIEW_UPLOAD_INPUT"]).parent / manifest["content_file"]
        content.write_bytes(b"tampered")
        return real_popen(argv, **kwargs)

    result = OfficialActionsArtifactUploader(
        script_path=test_script,
        environ=uploader_environment(),
        popen=mutate_then_spawn,
    ).upload(
        run_id=900001,
        artifact_name="test-canary",
        filename="exact-name.json",
        content=b'{"canary":true}\n',
        timeout_seconds=3,
    )

    assert result.status == "UNAVAILABLE"
    assert result.reason_code == "artifact_upload_failed"
    assert not marker.exists()


@pytest.mark.parametrize(
    "changes",
    [
        {"GITHUB_RUN_ID": "900002"},
        {"ACTIONS_RESULTS_URL": "https://evil.example.test/"},
        {"ACTIONS_RESULTS_URL": "http://results-receiver.actions.githubusercontent.com/"},
    ],
)
def test_official_sdk_bridge_fails_closed_on_run_or_runtime_endpoint_mismatch(changes, tmp_path):
    helper = tmp_path / "missing.mjs"
    helper.write_text("")
    result = OfficialActionsArtifactUploader(script_path=helper, environ=uploader_environment(**changes)).upload(
        run_id=900001,
        artifact_name="test-canary",
        filename="canary.json",
        content=b"{}",
        timeout_seconds=1,
    )
    assert result.status == "UNAVAILABLE"


def test_official_sdk_bridge_bounds_payload_and_never_echoes_child_errors(tmp_path):
    helper = tmp_path / "upload.mjs"
    helper.write_text("process.stderr.write(process.env.ACTIONS_RUNTIME_TOKEN); process.exit(4)\n")
    result = OfficialActionsArtifactUploader(script_path=helper, environ=uploader_environment()).upload(
        run_id=900001,
        artifact_name="test-canary",
        filename="canary.json",
        content=b"x" * (128 * 1024 + 1),
        timeout_seconds=1,
    )
    assert result.status == "UNAVAILABLE"
    assert result.reason_code == "artifact_upload_input_invalid"


def test_official_sdk_bridge_deadline_kills_child_and_returns_safe_unknown(tmp_path):
    if not shutil.which("node"):
        pytest.skip("Node.js is not available")
    helper = tmp_path / "hang.mjs"
    helper.write_text("await new Promise(resolve => setInterval(resolve, 1000));\n")
    started = time.monotonic()
    result = OfficialActionsArtifactUploader(script_path=helper, environ=uploader_environment()).upload(
        run_id=900001,
        artifact_name="test-canary",
        filename="canary.json",
        content=b"{}",
        timeout_seconds=0.25,
    )
    assert result.status == "UNAVAILABLE"
    assert result.reason_code == "artifact_upload_deadline_exhausted"
    assert time.monotonic() - started < 2


@pytest.mark.skipif(os.name != "posix", reason="process-group cancellation is POSIX-specific")
def test_official_sdk_bridge_deadline_kills_ready_descendant_process(tmp_path):
    if not shutil.which("node"):
        pytest.skip("Node.js is not available")
    helper = tmp_path / "descendant.mjs"
    pid_path = tmp_path / "descendant.pid"
    ready_path = tmp_path / "descendant.ready"
    child_program = (
        "const fs=require('node:fs');"
        f"fs.writeFileSync({json.dumps(str(pid_path))},String(process.pid));"
        "process.on('SIGTERM',()=>{});"
        f"fs.writeFileSync({json.dumps(str(ready_path))},'ready');"
        "setInterval(()=>{},1000);"
    )
    helper.write_text(
        "import {spawn} from 'node:child_process';\n"
        "import {existsSync} from 'node:fs';\n"
        f"spawn(process.execPath,['-e',{json.dumps(child_program)}],{{stdio:'ignore'}});\n"
        f"while(!existsSync({json.dumps(str(ready_path))})) await new Promise(r=>setTimeout(r,5));\n"
        "await new Promise(()=>{});\n"
    )
    result = OfficialActionsArtifactUploader(script_path=helper, environ=uploader_environment()).upload(
        run_id=900001,
        artifact_name="test-canary",
        filename="canary.json",
        content=b"{}",
        timeout_seconds=2,
    )
    assert result.status == "UNAVAILABLE"
    assert result.reason_code == "artifact_upload_deadline_exhausted"
    assert pid_path.is_file() and ready_path.is_file()
    descendant_pid = int(pid_path.read_text())
    if sys.platform.startswith("linux"):
        stat_path = Path(f"/proc/{descendant_pid}/stat")

        def descendant_running():
            try:
                state = stat_path.read_text().split()[2]
            except FileNotFoundError:
                return False
            return state != "Z"
    else:

        def descendant_running():
            try:
                os.kill(descendant_pid, 0)
            except ProcessLookupError:
                return False
            return True

    deadline = time.monotonic() + 2
    while descendant_running() and time.monotonic() < deadline:
        time.sleep(0.02)
    assert not descendant_running()
