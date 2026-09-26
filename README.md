# PR Review Harness

A reusable, read-only code review CLI with deterministic planning, bounded specialist reviews, immutable Git evidence, reconciliation, and auditable reports. Its `publish` command currently validates and renders a read-only review preview; live publication is unavailable. It is still an experimental candidate, not an established Droid replacement: the initial six-commit pilot produced incomplete reviews and exposed model-contract, context, and provider issues. See `docs/PILOT-RESULTS.md` and `docs/PRODUCTION-DELIVERY.md`.

The harness owns review depth, scopes, budgets, coverage, freshness, and disposition. An OpenAI-compatible inference provider supplies candidate findings and separate semantic assessments. Optional native Laya or Typesafe/Jev calls supply advisory risk observations; their probabilities do not authorize approval or choose control flow.

## Try it

Python 3.11+ and Git are required. GitHub PR mode also requires the `gh` CLI authenticated with read-only access to pull requests and checks.

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .
pr-review --help
export NOUS_API_KEY='your inference key'
git clone --bare https://github.com/magnus919/SlopSearX.git /tmp/slopsearx.git
pr-review recent --repo /tmp/slopsearx.git --count 2 \
  --profile profiles/slopsearx.json \
  --provider-config examples/provider.nous.json \
  --output artifacts/reviews --json
```

Each run saves JSON and Markdown. A terminal `INCOMPLETE` result is a successful report operation, not a passed review. Read disposition, coverage, freshness basis, unresolved gaps, and task status together. Historical snapshots never establish the current status of a live PR.

## Provider configuration

The reusable analysis workflow accepts `LLM_BASE_URL`, `LLM_MODEL`, `LLM_API_KEY`, `JEV_BASE_URL`, `JEV_MODEL`, and `JEV_API_KEY` only as required trusted `workflow_call` secrets. A pull request cannot choose either destination or model. The first intended inference deployment is NousPortal, but the endpoint and model are operator-configured; the Jev endpoint and model are operator-configured as well. Only the two `*_API_KEY` values are authentication credentials. Store keys in the deployment secret store, never in provider JSON or command-line arguments. The quick-start command above remains a separate historical `NOUS_API_KEY` test configuration.

The `scripts/provider_config_from_env.py` helper validates the six values and writes separate private provider and decision config files. It keeps key values out of the JSON and prints only config paths. The LLM API root may use a provider-specific path; the adapter appends `/chat/completions`. The native Jev API root may use a provider-specific path; the adapter appends `/systemone`. Remote HTTP is rejected; loopback HTTP is allowed for local adapters. The reusable workflow now invokes this helper and passes both generated files to the CLI, but no hosted provider run has verified runtime connectivity or review quality. The historical free-model workflow remains separate. See [Deployment configuration](docs/DEPLOYMENT-CONFIGURATION.md) for the exact generated config shape and boundaries.

For a particular change use `pr-review review --repo REPO --base SHA --head SHA` with the same profile/provider/output options. `--dry-run` previews arguments without reading credentials or contacting providers. For another project, start from `profiles/generic.json` and explicitly review its context, risk rules, lenses, and required checks. Profile files are trusted operator inputs.

`pr-review publish` validates a sealed result against repository/disposition policy and prints the exact review body without GitHub reads or a local effect store. Live publication is unavailable; `--authorize-publish` fails closed. See the [publication preview migration](docs/CLI-PUBLISH-PREVIEW-MIGRATION.md). No production write has been verified.

For reproducible packaging checks, build a wheel and run the installed entry point from outside the checkout:

```sh
python -m pip install build
python -m build --wheel --sdist
python -m venv /tmp/pr-review-wheel
/tmp/pr-review-wheel/bin/python -m pip install dist/*.whl
/tmp/pr-review-wheel/bin/python scripts/package_smoke.py --cli /tmp/pr-review-wheel/bin/pr-review
```

## What is included

| Path | Purpose |
|---|---|
| `src/pr_review_harness/` | Snapshot collector, planner, scheduler, provider adapters, reducer, report renderer, CLI |
| `profiles/` | Candidate SlopSearX and generic project policies |
| `examples/` | Environment-only provider configuration examples |
| `tests/` | Git, HTTP boundary, scheduler, reducer, and CLI regressions |
| `docs/design/` | Discovery, architecture, contracts, spec, research, evaluation design |
| `docs/VERIFICATION.md` | Implemented behavior and explicit spec gaps |
| `docs/PILOT-RESULTS.md` | Actual recent-commit experiment and its limitations |
| `docs/OPERATIONS.md` | Safe local and GitHub Actions operation, evidence handling, and recovery |
| `docs/PACKAGING-VERIFICATION.md` | Wheel, source distribution, matrix, and installed-entry-point checks |
| `.github/workflows/` | Python support matrix, wheel verification, and read-only review artifacts |

## Boundaries

No target code, hooks, tests, or builds execute during review. The current CLI has no live publication path; merging and repairs are unsupported. Missing, failed, or untrusted required-check evidence stays incomplete. GitHub Actions uses trusted harness/profile files from the base revision and acquires pull-request objects into a bare repository; it never checks out the pull-request head. Context retrieval is limited to immutable Git objects and explicitly allowlisted paths. It does not establish calibrated model quality, complete spec coverage, or production suitability.

The reusable Actions analysis is inactive until a trusted target-repository workflow calls it at a reviewed full commit SHA. It takes trusted harness/profile source separately from the target PR and fetches target objects to a bare store. It uses a configured inference provider and sends selected repository evidence to that provider. The workflow uses a read-only token and uploads a short-lived report artifact; it does not publish a review or change the PR. Historical free-model comparisons are manual, bounded, and tied to frozen commit pairs. See [Operations](docs/OPERATIONS.md) before enabling repository secrets or relying on artifacts.

```sh
pytest -q
ruff check src tests
```

Reports retain source excerpts and should be handled according to the target repository's confidentiality and retention requirements. Credentials belong in environment variables, never configuration files. Runtime limits and source provenance are recorded; model assessments remain fallible advisory evidence.

The fixed pilot can be repeated with `python scripts/run-pilot.py --repo /tmp/slopsearx.git` after installing the package and setting the inference environment key. It writes a manifest with exact commit pairs and source/config hashes before recording each outcome.
