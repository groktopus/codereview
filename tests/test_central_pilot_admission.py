from __future__ import annotations

import hashlib
import io
import json
import os
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))
import central_pilot_admission as admission  # noqa: E402
import pr_analysis_artifact_manifest as manifest  # noqa: E402
import test_pr_analysis_artifact_manifest as fixtures  # noqa: E402


def _archive(root: Path) -> bytes:
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("review/", b"")
        for path in sorted(root.rglob("*")):
            if path.is_file():
                archive.write(path, path.relative_to(root).as_posix())
    return out.getvalue()


class FakeTransport:
    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    def get(self, url, *, headers, limit):
        self.calls.append((url, dict(headers), limit))
        response = self.responses[url]
        assert len(response.body) <= limit
        return response


def _candidate(tmp_path):
    root, identity, checkpoint, profile, provider, decision = fixtures._fixture(tmp_path, central_pilot=True)
    identity.update({"called_workflow_sha": admission.REUSABLE_SHA,
                     "harness_sha": admission.REUSABLE_SHA,
                     "called_workflow_ref": f"{admission.CALLER}/{admission.REUSABLE_PATH}@{admission.REUSABLE_SHA}"})
    manifest.create_manifest(root, identity, checkpoint=checkpoint, profile=profile,
                             provider_config=provider, decision_config=decision)
    archive = _archive(root)
    run = {
        "id": 42, "run_attempt": 2, "event": "workflow_dispatch", "path": admission.CALLER_PATH,
        "head_branch": "main", "head_sha": "e" * 40, "status": "completed", "conclusion": "success",
        "workflow_id": 123, "repository": {"id": 99, "full_name": admission.CALLER},
        "referenced_workflows": [{"path": f"{admission.CALLER}/{admission.REUSABLE_PATH}@{admission.REUSABLE_SHA}", "sha": admission.REUSABLE_SHA}],
    }
    pr = {"number": 7, "state": "open", "draft": False,
          "base": {"ref": "main", "sha": "a" * 40, "repo": {"full_name": admission.TARGET}},
          "head": {"sha": "b" * 40}}
    artifact = {"id": 55, "name": "pr-review-7-42-2", "expired": False,
                "size_in_bytes": len(archive), "digest": "sha256:" + hashlib.sha256(archive).hexdigest(),
                "workflow_run": {"id": 42, "repository_id": 99, "head_sha": "e" * 40}}
    api = "https://api.github.com"
    paths = {
        f"{api}/repos/groktopus/codereview/actions/runs/42/attempts/2": run,
        f"{api}/repos/magnus919/SlopSearX/pulls/7": pr,
        f"{api}/repos/groktopus/codereview/actions/runs/42/artifacts?per_page=100": {"total_count": 1, "artifacts": [artifact]},
    }
    responses = {url: admission.fetch.HttpResponse(200, {}, json.dumps(value).encode()) for url, value in paths.items()}
    artifact_url = f"{api}/repos/groktopus/codereview/actions/artifacts/55/zip"
    storage_url = "https://productionresultssa1.blob.core.windows.net/signed.zip?sig=fixture"
    responses[artifact_url] = admission.fetch.HttpResponse(302, {"Location": storage_url}, b"")
    responses[storage_url] = admission.fetch.HttpResponse(200, {}, archive)
    event = {"repository": {"id": 99, "full_name": admission.CALLER}, "workflow_run": {
        "id": 42, "run_attempt": 2, "workflow_id": 123, "event": "workflow_dispatch",
        "path": admission.CALLER_PATH, "head_branch": "main", "head_sha": "e" * 40}}
    return json.dumps(event).encode(), FakeTransport(responses)


def test_central_dispatch_candidate_yields_hash_only_receipt_without_writes(tmp_path):
    event, transport = _candidate(tmp_path)
    receipt = admission.verify_candidate(event_bytes=event, pull_request_number=7, token="fake-read-token", transport=transport)
    assert receipt["status"] == "CONSISTENCY_VALIDATED"
    assert receipt["publication_authorized"] is False
    assert all("sha256" in key for key in receipt if key.endswith("_sha256"))
    assert not any("review" in key.lower() or "text" in key.lower() for key in receipt)
    assert all(call[1]["Authorization"] == "Bearer fake-read-token" for call in transport.calls if "blob.core" not in call[0])
    assert len(transport.calls) == 5


def test_source_checkout_entrypoint_loads_recovery_validator_without_pythonpath(tmp_path):
    root, identity, checkpoint, profile, provider, decision = fixtures._fixture(tmp_path, central_pilot=True)
    manifest.create_manifest(
        root, identity, checkpoint=checkpoint, profile=profile,
        provider_config=provider, decision_config=decision,
    )
    identity_path = tmp_path / "identity.json"
    identity_path.write_text(json.dumps(identity), encoding="utf-8")
    code = """
import json
import sys
from pathlib import Path
sys.path.insert(0, 'scripts')
import central_pilot_admission
import pr_analysis_artifact_manifest
record = pr_analysis_artifact_manifest._recovery_input_record(
    Path(sys.argv[1]), json.loads(Path(sys.argv[2]).read_text(encoding='utf-8'))
)
print(json.dumps(record, sort_keys=True, separators=(',', ':')))
"""
    environment = os.environ.copy()
    environment.pop("PYTHONPATH", None)
    completed = subprocess.run(
        [sys.executable, "-S", "-c", code, str(root), str(identity_path)],
        cwd=ROOT, env=environment, capture_output=True, text=True, timeout=15, check=False,
    )
    assert completed.returncode == 0, completed.stderr
    record = json.loads(completed.stdout)
    assert record["source_event_id"] == identity["workflow_run_id"]
    assert record["packet_sha256"] == hashlib.sha256((root / "recovery-inputs.json").read_bytes()).hexdigest()
    assert record["checks_document_sha256"]


@pytest.mark.parametrize("change", [
    {"event": "pull_request"}, {"head_branch": "attacker"},
    {"path": ".github/workflows/other.yml@refs/heads/main"},
])
def test_dispatch_event_binding_fails_closed(change):
    event = {"repository": {"full_name": admission.CALLER}, "workflow_run": {
        "id": 42, "run_attempt": 1, "workflow_id": 123, "event": "workflow_dispatch",
        "path": admission.CALLER_PATH, "head_branch": "main", "head_sha": "e" * 40}}
    event["repository"]["id"] = 99
    event["workflow_run"].update(change)
    with pytest.raises(admission.AdmissionError):
        admission._event_binding(json.dumps(event).encode(), 7)


def test_wrong_reusable_sha_is_rejected_before_artifact_fetch(tmp_path):
    event, transport = _candidate(tmp_path)
    run_url = "https://api.github.com/repos/groktopus/codereview/actions/runs/42/attempts/2"
    run_response = transport.responses[run_url]
    run = json.loads(run_response.body)
    run["referenced_workflows"][0]["sha"] = "f" * 40
    transport.responses[run_url] = admission.fetch.HttpResponse(200, {}, json.dumps(run).encode())
    with pytest.raises(admission.AdmissionError, match="reusable_workflow_binding_mismatch"):
        admission.verify_candidate(event_bytes=event, pull_request_number=7, token="fake", transport=transport)
    assert len(transport.calls) == 1


def test_stale_target_head_is_rejected_before_artifact_listing(tmp_path):
    event, transport = _candidate(tmp_path)
    pr_url = "https://api.github.com/repos/magnus919/SlopSearX/pulls/7"
    pr = json.loads(transport.responses[pr_url].body)
    pr["head"]["sha"] = "c" * 40
    transport.responses[pr_url] = admission.fetch.HttpResponse(200, {}, json.dumps(pr).encode())
    with pytest.raises(admission.AdmissionError, match="recovery_trusted_identity_mismatch"):
        admission.verify_candidate(event_bytes=event, pull_request_number=7, token="fake", transport=transport)
    # The retained packet's target binding is visible only after its archive is
    # downloaded; the verifier still rejects it before producing a receipt.
    assert len(transport.calls) == 5


def test_duplicate_retained_artifact_is_rejected(tmp_path):
    event, transport = _candidate(tmp_path)
    artifacts_url = "https://api.github.com/repos/groktopus/codereview/actions/runs/42/artifacts?per_page=100"
    listing = json.loads(transport.responses[artifacts_url].body)
    listing["artifacts"].append(dict(listing["artifacts"][0], id=56))
    listing["total_count"] = 2
    transport.responses[artifacts_url] = admission.fetch.HttpResponse(200, {}, json.dumps(listing).encode())
    with pytest.raises(admission.AdmissionError, match="recovery_artifact_not_unique"):
        admission.verify_candidate(event_bytes=event, pull_request_number=7, token="fake", transport=transport)
    assert len(transport.calls) == 3


@pytest.mark.parametrize("field,value", [
    ("id", "42"), ("workflow_id", True), ("repository_id", "99"),
])
def test_source_run_rejects_malformed_numeric_identity(tmp_path, field, value):
    event, transport = _candidate(tmp_path)
    run_url = "https://api.github.com/repos/groktopus/codereview/actions/runs/42/attempts/2"
    run = json.loads(transport.responses[run_url].body)
    if field == "repository_id":
        run["repository"]["id"] = value
    else:
        run[field] = value
    transport.responses[run_url] = admission.fetch.HttpResponse(200, {}, json.dumps(run).encode())
    with pytest.raises(admission.AdmissionError, match="source_run_binding_mismatch"):
        admission.verify_candidate(event_bytes=event, pull_request_number=7, token="fake", transport=transport)
    assert len(transport.calls) == 1


@pytest.mark.parametrize("field,value", [
    ("base_full_name", 99), ("base_sha", 99), ("head_sha", True),
])
def test_target_pr_rejects_malformed_identity_types(tmp_path, field, value):
    event, transport = _candidate(tmp_path)
    pr_url = "https://api.github.com/repos/magnus919/SlopSearX/pulls/7"
    pr = json.loads(transport.responses[pr_url].body)
    if field == "base_full_name":
        pr["base"]["repo"]["full_name"] = value
    elif field == "base_sha":
        pr["base"]["sha"] = value
    else:
        pr["head"]["sha"] = value
    transport.responses[pr_url] = admission.fetch.HttpResponse(200, {}, json.dumps(pr).encode())
    with pytest.raises(admission.AdmissionError, match="target_pr_not_current_open_candidate"):
        admission.verify_candidate(event_bytes=event, pull_request_number=7, token="fake", transport=transport)
    assert len(transport.calls) == 2


def test_token_with_internal_whitespace_is_rejected_before_transport(tmp_path):
    event, transport = _candidate(tmp_path)
    with pytest.raises(admission.AdmissionError, match="read_only_token_required"):
        admission.verify_candidate(event_bytes=event, pull_request_number=7, token="fake token", transport=transport)
    assert transport.calls == []


def test_artifact_name_is_the_only_pr_number_source_and_must_be_unique(tmp_path):
    event, transport = _candidate(tmp_path)
    assert admission.discover_pr_number(event_bytes=event, token="fake", transport=transport) == 7
    artifacts_url = "https://api.github.com/repos/groktopus/codereview/actions/runs/42/artifacts?per_page=100"
    listing = json.loads(transport.responses[artifacts_url].body)
    listing["artifacts"].append(dict(listing["artifacts"][0], id=56, name="pr-review-8-42-2"))
    listing["total_count"] = 2
    transport.responses[artifacts_url] = admission.fetch.HttpResponse(200, {}, json.dumps(listing).encode())
    with pytest.raises(admission.AdmissionError, match="recovery_artifact_not_unique"):
        admission.discover_pr_number(event_bytes=event, token="fake", transport=transport)


@pytest.mark.parametrize(("event_name", "expected"), [
    ("workflow_run", "OBSERVED_EVENT_PAYLOAD"),
    ("workflow_dispatch", "NOT_ESTABLISHED_BY_MANUAL_REHEARSAL"),
])
def test_manual_rehearsal_receipt_is_distinct_from_trigger_evidence(tmp_path, event_name, expected):
    event, transport = _candidate(tmp_path)
    receipt_path = tmp_path / "candidate-receipt.json"
    kwargs = ({"event_bytes": event, "run_id": None, "attempt": None}
              if event_name == "workflow_run"
              else {"event_bytes": None, "run_id": "42", "attempt": "2"})
    receipt = admission.run_canary(
        event_name=event_name, token="fake", transport=transport, receipt_path=receipt_path, **kwargs,
    )
    assert receipt["trigger_mode"] == ("workflow_run" if event_name == "workflow_run" else "manual_rehearsal")
    assert receipt["workflow_run_trigger_evidence"] == expected
    assert receipt["publication_authorized"] is False
    saved = json.loads(receipt_path.read_bytes())
    assert saved == receipt
    assert len(receipt_path.read_bytes()) < 4096
