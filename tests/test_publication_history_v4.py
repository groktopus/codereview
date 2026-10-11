import base64
import hashlib
import io
import json
import zipfile
from urllib.parse import parse_qs, urlsplit

import pytest
from test_actions_publication import FakeTransport, Provider, make_policy, response
from test_protected_publication_runtime import (
    actions_environment,
    api_location_policy_document,
    protected_checkout,
)

import pr_review_harness.protected_publication_runtime as runtime
from pr_review_harness.actions_publication import (
    ArtifactUploadResult,
    GitHubActionsPublicationAdapter,
    GitHubPublicationError,
    HTTPResponse,
    _read_receipt_archive,
)
from pr_review_harness.protected_publication_runtime import ProtectedPublicationPolicy, ProtectedRuntimeError
from pr_review_harness.publication_receipts import (
    EffectSlot,
    NoEffectReceipt,
    ReceiptContractError,
    RunIdentity,
    ScanLimits,
)


def _run_identity(run_id=900001, attempt=1, sha="f" * 40):
    return RunIdentity(
        repository_id=8123,
        workflow_id=904,
        workflow_path=".github/workflows/pr-publish.yml",
        workflow_ref="refs/heads/main",
        workflow_sha=sha,
        run_id=run_id,
        run_attempt=attempt,
    )


def _history():
    return {
        "schema": "publisher-history-reconciliation.v1",
        "max_historical_exceptions": 4,
        "historical_exceptions": [],
    }


def _blob_sha(content):
    return hashlib.sha1(b"blob " + str(len(content)).encode("ascii") + b"\0" + content).hexdigest()


def test_no_effect_receipt_roundtrips_unknown_target_without_claiming_pr_absence():
    original = NoEffectReceipt(publisher_run=_run_identity(), policy_hash="a" * 64)
    assert NoEffectReceipt.from_bytes(original.to_bytes()) == original
    assert json.loads(original.to_bytes())["state"] == "NO_POST"
    value = json.loads(original.to_bytes())
    value["post_started"] = True
    with pytest.raises(ReceiptContractError, match="submission start"):
        NoEffectReceipt.from_bytes(json.dumps(value).encode())
    value = json.loads(original.to_bytes())
    value["pull_request_number"] = 44
    with pytest.raises(ReceiptContractError, match="target binding"):
        NoEffectReceipt.from_bytes(json.dumps(value).encode())


def test_no_effect_archive_uses_its_exact_filename_and_receipt_parser():
    receipt = NoEffectReceipt(publisher_run=_run_identity(), policy_hash="a" * 64)

    def archive(filename):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as zipped:
            zipped.writestr(filename, receipt.to_bytes())
        return stream.getvalue()

    assert _read_receipt_archive(
        archive("no-effect-receipt.json"),
        expected_filename="no-effect-receipt.json",
        expected_type=NoEffectReceipt,
    ) == receipt.to_bytes()
    with pytest.raises(GitHubPublicationError, match="receipt_archive_member_invalid"):
        _read_receipt_archive(
            archive("attempt-receipt.json"),
            expected_filename="no-effect-receipt.json",
            expected_type=NoEffectReceipt,
        )


def test_historical_workflow_pin_is_git_blob_sha1_not_policy_sha256():
    content = b"name: trusted workflow\n"
    blob = _blob_sha(content)
    assert len(blob) == 40
    policy = make_policy(history_reconciliation=_history(), no_effect_policy_hash="b" * 64)

    def respond(_method, _url, _body):
        return response(
            {
                "sha": blob,
                "encoding": "base64",
                "content": base64.b64encode(content).decode("ascii"),
            }
        )

    adapter = GitHubActionsPublicationAdapter(policy, Provider(), transport=FakeTransport(respond))
    assert adapter._historical_workflow_blob(policy.publisher_workflow_path, "c" * 40, blob, 5) == content
    with pytest.raises(GitHubPublicationError, match="historical_workflow_blob_mismatch"):
        adapter._historical_workflow_blob(policy.publisher_workflow_path, "c" * 40, "d" * 64, 5)


def test_historical_content_blob_accepts_wrapped_base64_and_rejects_bad_api_identity():
    content = b"historical policy with wrapped base64\n"
    blob_sha = _blob_sha(content)

    def metadata(**overrides):
        result = {
            "sha": blob_sha,
            "encoding": "base64",
            "content": base64.encodebytes(content).decode("ascii"),
        }
        result.update(overrides)
        return result

    value = metadata()
    adapter = GitHubActionsPublicationAdapter(
        make_policy(),
        Provider(),
        transport=FakeTransport(lambda *_: response(value)),
    )
    assert adapter._historical_content_blob(
        ".github/pr-review-publisher-policy.json", "f" * 40, 5, 64
    ) == (content, blob_sha)

    invalid_values = [
        metadata(sha="d" * 40),
        metadata(sha=None),
        metadata(encoding="utf-8"),
    ]
    for invalid in invalid_values:
        adapter.transport = FakeTransport(lambda *_args, value=invalid: response(value))
        with pytest.raises(GitHubPublicationError):
            adapter._historical_content_blob(
                ".github/pr-review-publisher-policy.json", "f" * 40, 5, 64
            )


def test_historical_exception_accepts_bound_v3_policy_without_requiring_v4():
    publisher_content = b"name: publisher\n"
    source_content = b"name: analysis\n"
    policy_content = json.dumps(
        api_location_policy_document(enabled=True), sort_keys=True, separators=(",", ":")
    ).encode()
    runtime_pin = "e" * 40
    publisher_blob = _blob_sha(publisher_content)
    source_blob = _blob_sha(source_content)
    record = {
        "run_id": 900001,
        "attempt": 1,
        "publisher_workflow_id": 904,
        "publisher_run_head_sha": "f" * 40,
        "runtime_pin": runtime_pin,
        "publisher_workflow_blob_sha": publisher_blob,
        "analysis_workflow_blob_sha": source_blob,
        "publisher_job_id": 222,
        "publisher_job_name": "publisher",
        "runtime_step": 8,
        "log_sha256": "a" * 64,
        "log_bytes": 123,
        "outcome": "UNKNOWN",
        "reason_code": "source_artifact_redirect_untrusted",
        "proof_kind": "TRUSTED_PRE_POST_RECONCILIATION",
    }
    policy = make_policy(
        history_reconciliation={
            **_history(),
            "historical_exceptions": [record],
        },
        no_effect_policy_hash="b" * 64,
    )
    run_record = {
        "id": 900001,
        "run_attempt": 1,
        "workflow_id": 904,
        "head_sha": "f" * 40,
        "event": "workflow_run",
        "status": "completed",
        "conclusion": "success",
    }
    job = {
        "id": 222,
        "name": "publisher",
        "run_id": 900001,
        "run_attempt": 1,
        "status": "completed",
        "conclusion": "success",
        "steps": [{"number": index, "conclusion": "success"} for index in range(1, 9)],
    }
    job_count = [1]

    def content_response(content):
        return response(
            {
                "sha": _blob_sha(content),
                "encoding": "base64",
                "content": base64.encodebytes(content).decode("ascii"),
            }
        )

    def responder(_method, url, _body):
        path = urlsplit(url).path
        if path.endswith("/contents/.github/workflows/pr-publish.yml"):
            return content_response(publisher_content)
        if path.endswith("/contents/.github/workflows/pr-analysis.yml"):
            return content_response(source_content)
        if path.endswith("/contents/.github/pr-review-publisher-policy.json"):
            return content_response(policy_content)
        if path.endswith("/actions/runs/900001/jobs"):
            return response({"total_count": job_count[0], "jobs": [job]})
        raise AssertionError((url, _method))

    adapter = GitHubActionsPublicationAdapter(policy, Provider(), transport=FakeTransport(responder))
    assert adapter._verify_historical_no_effect(run_record, 20)
    job_count[0] = True
    with pytest.raises(GitHubPublicationError, match="historical_no_effect_jobs_invalid"):
        adapter._verify_historical_no_effect(run_record, 20)


def test_v4_normal_policy_still_requires_full_target_context():
    with pytest.raises(GitHubPublicationError, match="publication_policy_context_invalid"):
        make_policy(
            pull_request_number=None,
            upstream_run_id=None,
            upstream_run_attempt=None,
            history_reconciliation=_history(),
            no_effect_policy_hash="b" * 64,
        )


def test_v4_policy_binds_historical_workflow_blob_ids_as_git_sha1():
    value = api_location_policy_document(enabled=True)
    value["schema"] = "pr-review-protected-publication-policy.v4"
    record = {
        "run_id": 111,
        "attempt": 1,
        "publisher_workflow_id": 904,
        "publisher_run_head_sha": "a" * 40,
        "runtime_pin": "b" * 40,
        "publisher_workflow_blob_sha": "c" * 40,
        "analysis_workflow_blob_sha": "d" * 40,
        "publisher_job_id": 222,
        "publisher_job_name": "publisher",
        "runtime_step": 8,
        "log_sha256": "e" * 64,
        "log_bytes": 123,
        "outcome": "UNKNOWN",
        "reason_code": "source_artifact_redirect_untrusted",
        "proof_kind": "TRUSTED_PRE_POST_RECONCILIATION",
    }
    value["history_reconciliation"] = {
        **_history(),
        "historical_exceptions": [record],
    }
    assert ProtectedPublicationPolicy.parse(value).raw["history_reconciliation"]["historical_exceptions"] == [record]
    record["publisher_workflow_blob_sha"] = "c" * 64
    with pytest.raises(ProtectedRuntimeError, match="protected_policy_history_invalid"):
        ProtectedPublicationPolicy.parse(value)


def test_v4_created_floor_is_sent_to_api_and_old_returned_rows_fail_closed():
    policy = make_policy(history_reconciliation=_history(), no_effect_policy_hash="b" * 64)
    slot = EffectSlot(policy.repository_id, policy.repository, policy.pull_request_number, "a" * 40)
    observed_query = []
    run = {
        "id": 700001,
        "run_attempt": 1,
        "workflow_id": policy.publisher_workflow_id,
        "head_sha": "c" * 40,
        "event": "workflow_run",
        "repository": {"id": policy.repository_id},
        "created_at": "2026-10-01T00:00:00Z",
    }

    def responder(_method, url, _body):
        parsed = urlsplit(url)
        if parsed.path.endswith("/pulls/44"):
            return response(
                {
                    "number": 44,
                    "state": "open",
                    "base": {"sha": "b" * 40, "repo": {"id": policy.repository_id}},
                    "head": {"sha": "a" * 40},
                    "created_at": "2026-10-01T00:00:00Z",
                }
            )
        observed_query.append(parse_qs(parsed.query))
        return response({"total_count": 1, "workflow_runs": [run]})

    adapter = GitHubActionsPublicationAdapter(policy, Provider(), transport=FakeTransport(responder))
    rows, count, complete = adapter._publisher_runs(slot, ScanLimits(max_runs=20, max_pages=2, max_reviews=100, deadline_seconds=10))
    assert rows == [run] and count == 1 and complete
    assert observed_query[0]["created"] == [">=2026-10-01T00:00:00Z"]

    old_run = dict(run, created_at="2026-09-30T23:59:59Z")
    adapter.transport = FakeTransport(
        lambda _method, url, _body: response(
            {
                "number": 44,
                "state": "open",
                "base": {"sha": "b" * 40, "repo": {"id": policy.repository_id}},
                "head": {"sha": "a" * 40},
                "created_at": "2026-10-01T00:00:00Z",
            }
        )
        if urlsplit(url).path.endswith("/pulls/44")
        else response({"total_count": 1, "workflow_runs": [old_run]})
    )
    with pytest.raises(GitHubPublicationError, match="publisher_run_before_authenticated_floor"):
        adapter._publisher_runs(slot, ScanLimits(max_runs=20, max_pages=2, max_reviews=100, deadline_seconds=10))


@pytest.mark.parametrize("job_name", ["publisher-disabled", "publisher"])
def test_skipped_publisher_run_accepts_only_exact_zero_step_job(job_name):
    policy = make_policy(history_reconciliation=_history(), no_effect_policy_hash="a" * 64)
    run = {"id": 900001, "run_attempt": 1, "conclusion": "skipped"}
    job = {
        "id": 712,
        "name": job_name,
        "run_id": run["id"],
        "run_attempt": run["run_attempt"],
        "status": "completed",
        "conclusion": "skipped",
        "steps": [],
    }
    adapter = GitHubActionsPublicationAdapter(
        policy,
        Provider(),
        transport=FakeTransport(lambda *_: response({"total_count": 1, "jobs": [job]})),
    )
    assert adapter._verify_skipped_publisher_run(run, 10)


@pytest.mark.parametrize(
    "jobs_payload",
    [
        {"total_count": True, "jobs": [{"name": "publisher", "status": "completed", "conclusion": "skipped", "steps": []}]},
        {"total_count": 1, "jobs": [{"name": "publisher", "status": "in_progress", "conclusion": "skipped", "steps": []}]},
        {"total_count": 1, "jobs": [{"name": "publisher", "status": "completed", "conclusion": "skipped"}]},
        {"total_count": 1, "jobs": [{"name": "unexpected-job", "status": "completed", "conclusion": "skipped", "steps": []}]},
        {"total_count": 2, "jobs": [{"name": "publisher", "status": "completed", "conclusion": "skipped", "steps": []}, {}]},
    ],
)
def test_skipped_publisher_run_rejects_unproven_job_shape(jobs_payload):
    policy = make_policy(history_reconciliation=_history(), no_effect_policy_hash="a" * 64)
    adapter = GitHubActionsPublicationAdapter(
        policy,
        Provider(),
        transport=FakeTransport(lambda *_: response(jobs_payload)),
    )
    with pytest.raises(GitHubPublicationError):
        adapter._verify_skipped_publisher_run(
            {"id": 900001, "run_attempt": 1, "conclusion": "skipped"}, 10
        )


def test_v4_early_identity_failure_reports_no_ack_as_unknown_without_write(tmp_path):
    value = api_location_policy_document(enabled=True)
    value["schema"] = "pr-review-protected-publication-policy.v4"
    value["history_reconciliation"] = _history()
    workspace, revision, event_path = protected_checkout(tmp_path, policy_value=value)
    event_path.write_text("{}", encoding="utf-8")
    environ = actions_environment(workspace, revision, event_path)
    publisher_run = {
        "id": 900001,
        "run_attempt": 1,
        "workflow_id": 904,
        "head_sha": revision,
        "path": ".github/workflows/pr-publish.yml",
        "event": "workflow_run",
        "status": "in_progress",
        "repository": {"id": 8123},
    }

    class UnavailableUploader:
        calls = 0

        def upload(self, **_kwargs):
            self.calls += 1
            return ArtifactUploadResult("UNAVAILABLE")

    uploader = UnavailableUploader()
    calls = []

    def responder(_method, url, _body):
        calls.append(urlsplit(url).path)
        path = urlsplit(url).path
        if path.endswith("/actions/runs/900001/artifacts"):
            return response({"total_count": 0, "artifacts": []})
        if path.endswith("/actions/runs/900001"):
            return response(dict(publisher_run, run_attempt=1))
        return response(publisher_run)

    outcome = runtime.run_protected_publication(
        environ,
        transport=FakeTransport(responder),
        artifact_uploader=uploader,
    )
    assert outcome["status"] == "UNKNOWN"
    assert outcome["reason"] == "workflow_event_identity_invalid"
    assert outcome["no_effect_receipt"] == {
        "status": "UNKNOWN",
        "reason": "no_effect_upload_unconfirmed",
    }
    assert uploader.calls == 1
    assert any(path.endswith("/actions/runs/900001/attempts/1") for path in calls)

    client = FakeTransport(responder)
    protected = runtime._policy_from_workspace(environ)
    readonly = runtime._early_no_effect_adapter(
        environ,
        protected,
        client,
        uploader,
        runtime.time.monotonic() + 30,
        runtime.time.monotonic,
    )
    before_submit = len(client.calls)
    with pytest.raises(GitHubPublicationError, match="no_effect_adapter_read_only"):
        readonly.submit_review({"event": "COMMENT"}, "effect-" + "a" * 64, 5)
    assert len(client.calls) == before_submit


def test_no_effect_ack_accepts_metadata_without_attempt_only_for_latest_attempt_one():
    policy = make_policy(history_reconciliation=_history(), no_effect_policy_hash="a" * 64)
    receipt = NoEffectReceipt(publisher_run=_run_identity(), policy_hash="a" * 64)

    class Uploader:
        def __init__(self):
            self.archive = None
            self.filename = None

        def upload(self, *, filename, content, **_kwargs):
            self.filename = filename
            stream = io.BytesIO()
            with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as zipped:
                zipped.writestr(filename, content)
            self.archive = stream.getvalue()
            return ArtifactUploadResult("UPLOADED", artifact_id=55)

    class Transport(FakeTransport):
        def __init__(self, uploader, latest_attempt=1):
            self.uploader = uploader
            self.latest_attempt = latest_attempt
            super().__init__(self.respond)

        def respond(self, method, url, _body):
            path = urlsplit(url).path
            if path.endswith("/actions/runs/900001/attempts/1"):
                return response(
                    {
                        "id": 900001,
                        "run_attempt": 1,
                        "workflow_id": 904,
                        "head_sha": "f" * 40,
                        "path": ".github/workflows/pr-publish.yml",
                        "event": "workflow_run",
                        "status": "in_progress",
                        "repository": {"id": 8123},
                    }
                )
            if path.endswith("/actions/runs/900001"):
                return response(
                    {
                        "id": 900001,
                        "run_attempt": self.latest_attempt,
                        "workflow_id": 904,
                        "repository": {"id": 8123},
                    }
                )
            if path.endswith("/actions/artifacts/55/zip"):
                return HTTPResponse(302, {"location": "https://downloads.example.test/receipt?sig=ephemeral"}, b"")
            if path.endswith("/actions/runs/900001/artifacts"):
                name = parse_qs(urlsplit(url).query).get("name", [None])[0]
                artifacts = []
                if name and self.uploader.archive is not None:
                    artifacts = [
                        {
                            "id": 55,
                            "name": name,
                            "size_in_bytes": len(self.uploader.archive),
                            "digest": "sha256:" + hashlib.sha256(self.uploader.archive).hexdigest(),
                            "expired": False,
                            "expires_at": "2999-01-01T00:00:00Z",
                            # GitHub artifact metadata does not expose run_attempt.
                            "workflow_run": {"id": 900001, "repository_id": 8123},
                        }
                    ]
                return response({"total_count": len(artifacts), "artifacts": artifacts})
            raise AssertionError((method, path))

        def download(self, url, *, timeout_seconds, max_response_bytes):
            self.download_calls.append((url, timeout_seconds, max_response_bytes))
            return HTTPResponse(200, {}, self.uploader.archive)

    uploader = Uploader()
    transport = Transport(uploader)
    adapter = GitHubActionsPublicationAdapter(policy, Provider(), transport=transport, artifact_uploader=uploader)
    result = adapter.persist_no_effect(
        receipt,
        ScanLimits(max_runs=20, max_pages=2, max_reviews=100, deadline_seconds=20),
    )
    assert uploader.filename == "no-effect-receipt.json"
    assert result.acknowledges(receipt)

    later_uploader = Uploader()
    later_transport = Transport(later_uploader, latest_attempt=2)
    later_adapter = GitHubActionsPublicationAdapter(
        policy, Provider(), transport=later_transport, artifact_uploader=later_uploader
    )
    later_result = later_adapter.persist_no_effect(
        receipt,
        ScanLimits(max_runs=20, max_pages=2, max_reviews=100, deadline_seconds=20),
    )
    assert later_result.status.value == "UNKNOWN"
    assert later_uploader.filename is None


def test_no_effect_ack_uses_remaining_global_deadline_without_fresh_window(tmp_path):
    value = api_location_policy_document(enabled=True)
    value["schema"] = "pr-review-protected-publication-policy.v4"
    value["history_reconciliation"] = _history()
    value["limits"]["deadline_seconds"] = 1
    workspace, revision, event_path = protected_checkout(tmp_path, policy_value=value)
    event_path.write_text("{}", encoding="utf-8")
    environ = actions_environment(workspace, revision, event_path)
    now = [0.0]
    calls = []

    class Uploader:
        def __init__(self):
            self.calls = 0

        def upload(self, **_kwargs):
            self.calls += 1
            return ArtifactUploadResult("UPLOADED", artifact_id=55)

    uploader = Uploader()
    publisher_run = {
        "id": 900001,
        "run_attempt": 1,
        "workflow_id": 904,
        "head_sha": revision,
        "path": ".github/workflows/pr-publish.yml",
        "event": "workflow_run",
        "status": "in_progress",
        "repository": {"id": 8123},
    }

    def responder(_method, url, _body):
        calls.append(urlsplit(url).path)
        now[0] = 1.1  # The initial identity request consumes the whole run budget.
        return response(publisher_run)

    outcome = runtime.run_protected_publication(
        environ,
        transport=FakeTransport(responder),
        artifact_uploader=uploader,
        clock=lambda: now[0],
    )

    assert outcome["status"] == "UNKNOWN"
    assert outcome["no_effect_receipt"]["status"] == "UNKNOWN"
    assert calls == ["/repos/owner/repo/actions/runs/900001/attempts/1"]
    assert uploader.calls == 0


def test_history_reader_binds_no_effect_receipt_to_run_commit_policy_not_current_policy():
    policy_a = api_location_policy_document(enabled=True)
    policy_a["schema"] = "pr-review-protected-publication-policy.v4"
    policy_a["history_reconciliation"] = _history()
    policy_a_bytes = json.dumps(policy_a, sort_keys=True, separators=(",", ":")).encode()
    policy_a_hash = runtime._canonical_hash(policy_a)
    policy_b = json.loads(policy_a_bytes)
    policy_b["profile"]["version"] = "later-profile"
    policy_b_hash = runtime._canonical_hash(policy_b)
    policy = make_policy(
        history_reconciliation=_history(),
        no_effect_policy_hash=policy_b_hash,
    )
    workflow_bytes = b"name: protected publisher\n"
    expected = NoEffectReceipt(
        publisher_run=_run_identity(),
        policy_hash=policy_a_hash,
        pull_request_number=44,
        base_sha="b" * 40,
        head_sha="a" * 40,
    )
    run_record = {
        "id": 900001,
        "run_attempt": 1,
        "workflow_id": 904,
        "path": ".github/workflows/pr-publish.yml",
        "head_sha": "f" * 40,
        "event": "workflow_run",
        "repository": {"id": 8123},
        "status": "completed",
        "conclusion": "success",
    }

    def read_receipt(*, receipt=expected, historic_policy=policy_a, missing_policy=False):
        archive_stream = io.BytesIO()
        with zipfile.ZipFile(archive_stream, "w", compression=zipfile.ZIP_DEFLATED) as zipped:
            zipped.writestr("no-effect-receipt.json", receipt.to_bytes())
        archive = archive_stream.getvalue()
        artifact_name = policy.no_effect_artifact_name(policy.publisher_run_id, 1)
        metadata = {
            "id": 55,
            "name": artifact_name,
            "size_in_bytes": len(archive),
            "digest": "sha256:" + hashlib.sha256(archive).hexdigest(),
            "expired": False,
            "expires_at": "2999-01-01T00:00:00Z",
            "workflow_run": {"id": policy.publisher_run_id, "repository_id": policy.repository_id},
        }
        historic_bytes = json.dumps(historic_policy, sort_keys=True, separators=(",", ":")).encode()

        class Transport(FakeTransport):
            def respond(self, method, url, _body):
                path = urlsplit(url).path
                if path.endswith("/actions/runs/900001/attempts/1"):
                    return response(run_record)
                if path.endswith("/actions/runs/900001"):
                    return response({"id": 900001, "run_attempt": 1, "workflow_id": 904, "repository": {"id": 8123}})
                if path.endswith("/actions/runs/900001/artifacts"):
                    return response({"total_count": 1, "artifacts": [metadata]})
                if path.endswith("/actions/artifacts/55/zip"):
                    return HTTPResponse(302, {"location": "https://downloads.example.test/no-effect?sig=ephemeral"}, b"")
                if path.endswith("/contents/.github/pr-review-publisher-policy.json"):
                    if missing_policy:
                        return response({"message": "Not Found"}, status=404)
                    content = historic_bytes
                elif path.endswith("/contents/.github/workflows/pr-publish.yml"):
                    content = workflow_bytes
                else:
                    raise AssertionError((method, path))
                return response(
                    {
                        "sha": _blob_sha(content),
                        "encoding": "base64",
                        "content": base64.b64encode(content).decode("ascii"),
                    }
                )

            def download(self, url, *, timeout_seconds, max_response_bytes):
                self.download_calls.append((url, timeout_seconds, max_response_bytes))
                return HTTPResponse(200, {}, archive)

        transport = Transport(lambda *_: None)
        transport.responder = transport.respond
        adapter = GitHubActionsPublicationAdapter(policy, Provider(), transport=transport)
        return adapter._receipt_for_publisher_run(
            EffectSlot(8123, "owner/repo", 44, "a" * 40), run_record, 20
        )

    # Policy A remains valid on its run commit after today's policy has changed to B.
    assert read_receipt() == expected
    with pytest.raises(GitHubPublicationError, match="publisher_no_effect_binding_mismatch"):
        read_receipt(receipt=NoEffectReceipt(**{**expected.__dict__, "policy_hash": "c" * 64}))
    foreign_policy = json.loads(policy_a_bytes)
    foreign_policy["repository"] = {"name": "other/repo", "id": 999}
    foreign_policy["publisher_workflow"]["ref"] = "other/repo/.github/workflows/pr-publish.yml@refs/heads/main"
    with pytest.raises(GitHubPublicationError):
        read_receipt(
            receipt=NoEffectReceipt(**{**expected.__dict__, "policy_hash": runtime._canonical_hash(foreign_policy)}),
            historic_policy=foreign_policy,
        )
    with pytest.raises(GitHubPublicationError):
        read_receipt(missing_policy=True)
