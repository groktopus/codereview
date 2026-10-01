import json
from pathlib import Path
from urllib.parse import urlsplit

import pytest

from pr_review_harness.actions_publication import HTTPResponse
from scripts.protected_source_context_probe import ProbeError, run_probe

REPOSITORY = "owner/repo"
RUN_ID = 701
ATTEMPT = 2
PR_NUMBER = 44
BASE_SHA = "b" * 40
HEAD_SHA = "a" * 40
CONTEXT_SHA = "c" * 40
WORKFLOW_SHA = "d" * 40
API_HEAD_SHA = "e" * 40
TOKEN = "actions-read-secret-sentinel"


def fixture(tmp_path: Path, **overrides):
    event_path = tmp_path / "event.json"
    event_path.write_text(
        json.dumps(
            {
                "repository": {"id": 8123, "full_name": REPOSITORY},
                "pull_request": {
                    "number": PR_NUMBER,
                    "base": {"ref": "main", "sha": BASE_SHA},
                    "head": {"ref": "topic/issue-42", "sha": HEAD_SHA},
                },
            }
        ),
        encoding="utf-8",
    )
    values = {
        "GITHUB_TOKEN": TOKEN,
        "GITHUB_REPOSITORY": REPOSITORY,
        "GITHUB_RUN_ID": str(RUN_ID),
        "GITHUB_RUN_ATTEMPT": str(ATTEMPT),
        "GITHUB_EVENT_NAME": "pull_request_target",
        "GITHUB_EVENT_PATH": str(event_path),
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_SHA": CONTEXT_SHA,
        "GITHUB_WORKFLOW_REF": f"{REPOSITORY}/.github/workflows/protected-source-context-probe.yml@refs/heads/main",
        "GITHUB_WORKFLOW_SHA": WORKFLOW_SHA,
        "PR_NUMBER": str(PR_NUMBER),
    }
    values.update(overrides)
    return values


class FakeTransport:
    def __init__(self, *, responses=None, fail=None, clock=None):
        self.responses = responses or {}
        self.fail = fail
        self.clock = clock
        self.calls = []

    def request(self, method, url, *, token, json_body, timeout_seconds, max_response_bytes):
        self.calls.append((method, url, token, json_body, timeout_seconds, max_response_bytes))
        if self.clock is not None:
            self.clock.advance_after_call()
        if self.fail:
            raise RuntimeError(self.fail)
        path = urlsplit(url).path
        return HTTPResponse(200, {}, json.dumps(self.responses[path]).encode("utf-8"))


def api_responses(*, base_ref="main", head_ref="topic/issue-42", pr_state="open"):
    return {
        "/repos/owner/repo": {"id": 8123, "full_name": REPOSITORY, "default_branch": "main"},
        f"/repos/owner/repo/actions/runs/{RUN_ID}/attempts/{ATTEMPT}": {
            "id": RUN_ID,
            "run_attempt": ATTEMPT,
            "event": "pull_request_target",
            "workflow_id": 802,
            "path": ".github/workflows/protected-source-context-probe.yml@refs/heads/main",
            "head_branch": "feature/review-target",
            "head_sha": API_HEAD_SHA,
            "repository": {"id": 8123},
        },
        f"/repos/owner/repo/pulls/{PR_NUMBER}": {
            "number": PR_NUMBER,
            "state": pr_state,
            "base": {"ref": base_ref, "sha": BASE_SHA, "repo": {"id": 8123}},
            "head": {"ref": head_ref, "sha": HEAD_SHA},
        },
    }


def test_probe_reports_differences_as_observations_not_identity_proof(tmp_path):
    transport = FakeTransport(responses=api_responses())

    result = run_probe(fixture(tmp_path), transport=transport, clock=lambda: 10.0)

    assert result["status"] == "OBSERVED"
    assert result["authorization"] == "NONE"
    assert result["evidence_class"] == "runner_context_and_read_only_api_observations"
    assert result["context"]["sha"] == CONTEXT_SHA
    assert result["context"]["workflow_sha"] == WORKFLOW_SHA
    assert result["workflow_run_api"]["head_sha"] == API_HEAD_SHA
    assert result["pull_request_api"]["base_sha"] == BASE_SHA
    assert result["pull_request_api"]["head_sha"] == HEAD_SHA
    assert result["comparisons"] == {
        "event_repository_id_equals_api_repository_id": True,
        "context_ref_is_default_branch": True,
        "pr_base_ref_is_default_branch": True,
        "context_sha_equals_workflow_sha": False,
        "context_sha_equals_current_pr_base_sha": False,
        "workflow_sha_equals_current_pr_base_sha": False,
        "api_run_head_sha_equals_current_pr_head_sha": False,
        "api_run_head_branch_equals_current_pr_head_ref": False,
        "event_base_sha_equals_current_pr_base_sha": True,
        "event_head_sha_equals_current_pr_head_sha": True,
    }
    assert result["interpretation"].startswith("observations_only")
    assert len(transport.calls) == 3
    assert all(call[0] == "GET" and call[2] == TOKEN and call[3] is None for call in transport.calls)
    assert all(call[4] <= 5.0 and call[5] == 128 * 1024 for call in transport.calls)


def test_probe_records_equalities_when_they_happen_without_promoting_them(tmp_path):
    env = fixture(tmp_path, GITHUB_SHA=BASE_SHA, GITHUB_WORKFLOW_SHA=BASE_SHA)
    transport = FakeTransport(responses=api_responses())

    result = run_probe(env, transport=transport, clock=lambda: 5.0)

    assert result["comparisons"]["context_sha_equals_workflow_sha"] is True
    assert result["comparisons"]["workflow_sha_equals_current_pr_base_sha"] is True
    assert result["authorization"] == "NONE"
    assert "identity proof" in result["interpretation"]


def test_probe_bounds_each_response_and_deadline(tmp_path):
    oversized = api_responses()

    class Oversized(FakeTransport):
        def request(self, *args, **kwargs):
            self.calls.append((args, kwargs))
            return HTTPResponse(200, {}, b" " * (128 * 1024 + 1))

    with pytest.raises(ProbeError, match="github_read_unavailable"):
        run_probe(fixture(tmp_path), transport=Oversized(), clock=lambda: 1.0)

    class LateClock:
        value = 1.0

        def __call__(self):
            return self.value

        def advance_after_call(self):
            self.value += 21.0

    late_clock = LateClock()
    late_transport = FakeTransport(responses=oversized, clock=late_clock)
    with pytest.raises(ProbeError, match="probe_deadline_exhausted"):
        run_probe(fixture(tmp_path), transport=late_transport, clock=late_clock)
    assert len(late_transport.calls) == 1


@pytest.mark.parametrize(
    ("override", "expected"),
    [
        ({"GITHUB_EVENT_NAME": "pull_request"}, "probe_context_invalid"),
        ({"GITHUB_RUN_ID": "1/../../x"}, "probe_environment_invalid"),
        ({"GITHUB_TOKEN": TOKEN + "\n"}, "probe_environment_invalid"),
    ],
)
def test_probe_rejects_untrusted_context_shapes_before_api(tmp_path, override, expected):
    transport = FakeTransport(responses=api_responses())
    with pytest.raises(ProbeError, match=expected):
        run_probe(fixture(tmp_path, **override), transport=transport, clock=lambda: 1.0)
    assert transport.calls == []


def test_probe_sanitizes_transport_errors(tmp_path):
    transport = FakeTransport(fail=f"request failed with {TOKEN}")

    with pytest.raises(ProbeError) as exc:
        run_probe(fixture(tmp_path), transport=transport, clock=lambda: 1.0)

    assert str(exc.value) == "github_read_unavailable"
    assert TOKEN not in str(exc.value)
    assert len(transport.calls) == 1


def test_probe_rejects_ambiguous_or_stale_pr_context_without_claiming_identity(tmp_path):
    stale = api_responses(base_ref="release")
    result = run_probe(fixture(tmp_path), transport=FakeTransport(responses=stale), clock=lambda: 1.0)
    assert result["status"] == "OBSERVED"
    assert result["comparisons"]["pr_base_ref_is_default_branch"] is False
    assert result["authorization"] == "NONE"

    bad_head = api_responses(head_ref="bad\nfield")
    with pytest.raises(ProbeError, match="github_observation_invalid"):
        run_probe(fixture(tmp_path), transport=FakeTransport(responses=bad_head), clock=lambda: 1.0)


def test_workflow_is_disabled_read_only_and_checks_out_only_the_protected_sha():
    root = Path(__file__).resolve().parents[1]
    source = (root / ".github/workflows/protected-source-context-probe.yml").read_text(encoding="utf-8")

    assert "if: false" in source
    assert "pull_request_target:" in source
    assert "ref: ${{ github.sha }}" in source
    assert "persist-credentials: false" in source
    assert "actions: read" in source
    assert "contents: read" in source
    assert "pull-requests: read" in source
    assert "uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683" in source
    assert "uses: actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065" in source
    assert "github.event.pull_request.head.sha" not in source
    assert "permissions:\n  actions: write" not in source
    assert "APP_PRIVATE_KEY" not in source
    assert "LLM_API_KEY" not in source
    assert "JEV_API_KEY" not in source
