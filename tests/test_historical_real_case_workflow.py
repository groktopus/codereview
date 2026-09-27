import os
import subprocess
import textwrap
from pathlib import Path

from scripts import run_real_case_trial as trial

WORKFLOW = Path(__file__).parents[1] / ".github" / "workflows" / "historical-real-case-provider-trial.yml"


def test_historical_trial_workflow_is_manual_read_only_and_has_fixed_modes():
    text = WORKFLOW.read_text()
    assert "workflow_dispatch:" in text
    assert "pull_request:" not in text
    assert "permissions:\n  contents: read" in text
    assert "contents: write" not in text
    assert "checks: read" not in text
    assert "pull-requests: read" not in text
    assert "default: prepare-only" in text
    assert "default: staged-pr464" in text
    assert "provider-trial" in text
    assert "full-three-case" in text
    assert "github.ref == 'refs/heads/main'" in text
    assert "ref: ${{ steps.runtime-pins.outputs.sha }}" in text
    assert "default: specialist-input-v1" in text
    assert "specialist-input-v2" in text
    assert trial.CONTEXT_FOLLOWUP_V2_SELECTOR in text
    assert trial.RUNTIME_MODULE_TREE_SHA256 == "e21b1686bc3ccb485e389d6fc04f5aea0b0d4d6425e2809de570945b841258b3"


def test_provider_secrets_are_only_mapped_to_the_explicit_run_step():
    text = WORKFLOW.read_text()
    names = ("LLM_BASE_URL", "LLM_MODEL", "LLM_API_KEY", "JEV_BASE_URL", "JEV_MODEL", "JEV_API_KEY")
    run_marker = "- name: Run the frozen provider trial"
    before, after = text.split(run_marker, maxsplit=1)
    assert "secrets." not in before
    for name in names:
        assert after.count(f"{name}: ${{{{ secrets.{name} }}}}") == 1
    assert "--prepare-only" in before
    assert "--run-provider-trial" in after


def test_only_sanitized_outputs_are_uploaded_and_trial_time_is_bounded():
    text = WORKFLOW.read_text()
    upload = text.split("- name: Upload only the sanitized summary and manifest", maxsplit=1)[1]
    assert "summary.json" in upload
    assert "manifest.json" in upload
    assert "private/" not in upload
    assert "55" in text
    assert '--mode "$TRIAL_SCOPE"' in text


def test_runtime_pin_resolver_selects_only_exact_trusted_input_contract_identities(tmp_path):
    text = WORKFLOW.read_text()
    marker = "      - name: Resolve only a fixed trusted runtime for the selected input contract"
    block = text.split(marker, maxsplit=1)[1].split("      - name:", maxsplit=1)[0]
    script = block.split("run: |\n", maxsplit=1)[1]
    script = textwrap.dedent(script)
    script = script.split("python3 - <<'PY'\n", maxsplit=1)[1].rsplit("\nPY", maxsplit=1)[0]
    expected = {
        "specialist-input-v1": (
            trial.RUNTIME_SHA,
            trial.RUNTIME_MODULE_TREE_SHA256,
            "",
        ),
        "specialist-input-v2": (
            trial.V2_RUNTIME_SHA,
            trial.V2_RUNTIME_MODULE_TREE_SHA256,
            "-v2",
        ),
        trial.CONTEXT_FOLLOWUP_SELECTOR: (
            trial.CONTEXT_FOLLOWUP_RUNTIME_SHA,
            trial.CONTEXT_FOLLOWUP_MODULE_TREE_SHA256,
            "-context-followup-v1",
        ),
        trial.CONTEXT_FOLLOWUP_V2_SELECTOR: (
            trial.CONTEXT_FOLLOWUP_V2_RUNTIME_SHA,
            trial.CONTEXT_FOLLOWUP_V2_MODULE_TREE_SHA256,
            "-context-followup-v2",
        ),
    }
    for contract, (revision, tree, suffix) in expected.items():
        output = tmp_path / f"{contract}.out"
        result = subprocess.run(
            ["python3", "-c", script],
            env={**os.environ, "INPUT_CONTRACT": contract, "GITHUB_OUTPUT": str(output)},
            text=True,
            capture_output=True,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        fields = dict(line.split("=", 1) for line in output.read_text().splitlines())
        assert fields == {
            "contract": contract,
            "sha": revision,
            "module_tree": tree,
            "artifact_suffix": suffix,
        }
        assert len(fields["sha"]) == 40
        assert len(fields["module_tree"]) == 64
        artifact_path = f"historical-real-case-trial{fields['artifact_suffix']}"
        artifact_name = f"historical-real-case-trial-123{fields['artifact_suffix']}"
        if contract == "specialist-input-v1":
            assert (artifact_path, artifact_name) == (
                "historical-real-case-trial",
                "historical-real-case-trial-123",
            )
        elif contract == "specialist-input-v2":
            assert (artifact_path, artifact_name) == (
                "historical-real-case-trial-v2",
                "historical-real-case-trial-123-v2",
            )
        else:
            if contract == trial.CONTEXT_FOLLOWUP_SELECTOR:
                expected_paths = (
                "historical-real-case-trial-context-followup-v1",
                "historical-real-case-trial-123-context-followup-v1",
                )
            else:
                expected_paths = (
                    "historical-real-case-trial-context-followup-v2",
                    "historical-real-case-trial-123-context-followup-v2",
                )
            assert (artifact_path, artifact_name) == expected_paths

    output = tmp_path / "invalid.out"
    result = subprocess.run(
        ["python3", "-c", script],
        env={**os.environ, "INPUT_CONTRACT": "${{ github.event.inputs.input_contract }}", "GITHUB_OUTPUT": str(output)},
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode != 0
    assert not output.exists()

    # V1 keeps the original operator-facing paths and artifact name; each
    # experiment gets only the fixed suffix emitted by the trusted resolver.
    assert 'historical-real-case-trial$ARTIFACT_SUFFIX' in text
    assert 'historical-real-case-trial-${{ github.run_id }}${{ steps.runtime-pins.outputs.artifact_suffix }}' in text
    assert "historical-real-case-trial-v2" not in text
