# Native Claim Screen Runner

`scripts/run_claim_screen.py` prepares three bounded advisory assessments from
the preserved e22a085 development experiment. It reopens the sealed result
artifacts, rebuilds each snapshot with the normal bounded Git collector, and
requires every cited evidence hash and recorded source identity to match before
any provider request is prepared. It screens the control authorization finding,
the attack authorization finding, and the accepted attack-comment finding.

The runner makes three candidate calls at most. Each uses the native TypeSafe
Choice contract, with at most 64 KB serialized input, 8 KB response, one
8-second killable subprocess deadline, and zero retries. It continues after a
failed assessment and records the failure row. Billing and provider usage stay
`UNKNOWN` unless the endpoint reports usage; estimated price is not a hard spend
bound. The saved summary retains typed judgments, evidence references, hashes,
model identity, status, and latency. It excludes free-form provider rationale,
raw responses, stdout/stderr, credentials, and prompts beyond the referenced
source-bound candidate and evidence supplied to the assessment.

Supply a strict TypeSafe transport config containing only an HTTPS endpoint,
model ID, finite caps, and a credential environment-variable **name**. For
example:

```json
{
  "endpoint": "https://api.typesafe.ai/v1/systemone",
  "api_key_env": "TYPESAFE_API_KEY",
  "model": "jev-latest",
  "timeout_seconds": 8,
  "max_request_bytes": 64000,
  "max_response_bytes": 8000
}
```

With the e22a085 artifact bundle available locally, run:

```sh
PYTHONPATH=src python3 scripts/run_claim_screen.py \
  --artifact-dir /path/to/pr-review-output-experiment-e22a085-results \
  --transport-config /path/to/typesafe-claim-screen.json \
  --output /path/to/claim-screen-summary.json
```

The process passes only runtime environment variables and the configured
credential variable to each short-lived worker. Do not put credential values
in the config file or command line. The artifact directory is read-only input;
the summary is written with owner-only permissions.

These cases are development examples, not held-out cases or truth labels.
Choice distributions and confidence values are model-reported judgments with
unknown calibration. The output is advisory data only: it does not alter the
review result, blockers, disposition, or publication decisions, and it makes
no quality, security, or release-gate claim.
