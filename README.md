# PR Review Harness

A command-line tool for producing evidence-backed reviews of pull-request changes. It combines bounded review tasks with model-assisted analysis, reconciles the results, and saves a report with findings, coverage, and any unresolved gaps.

The review is read-only: it does not run the target repository's code or tests, merge changes, or publish a review. Analysis sends selected source context to the model provider configured by the operator. This is an experimental tool, not a substitute for human review: model-assisted analysis can miss issues. Treat reports as decision support and inspect their evidence and limitations before acting on them.

## Get started

Requires Python 3.11 or later and Git. Install from a checkout:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .
pr-review --help
```

Configure an OpenAI-compatible model provider. Put the API key in the environment (or load it from your secret manager); do not put the key itself in the configuration file:

```json
{
  "kind": "openai_compatible",
  "provider_id": "my_provider",
  "base_url": "https://api.example.com/v1",
  "model": "your-model",
  "api_key_env": "LLM_API_KEY"
}
```

Set `LLM_API_KEY` in your environment, then review two commits available in a local Git repository:

```sh
pr-review review \
  --repo /path/to/repository \
  --base BASE_SHA \
  --head HEAD_SHA \
  --profile profiles/generic.json \
  --provider-config provider.json \
  --output artifacts/review
```

Replace the example endpoint, model, repository path, and commit IDs with values for your setup. The command writes JSON and Markdown reports to the output directory. Check the report's disposition, coverage, freshness, findings, and unresolved gaps; an incomplete review is not a clean review.

For a provider-free argument preview, add `--dry-run`. For preparation against an explicit commit pair without dispatching model requests, see `--prepare-only` in `pr-review review --help`.

## What it does

- Reviews an explicit base/head revision pair from a local Git repository.
- Applies a trusted review profile to choose review lenses, context, and project rules.
- Uses configurable model providers for analysis; findings and semantic assessments remain advisory.
- Produces reports that record findings, evidence, review coverage, and incomplete work.
- Provides `recent` for reviewing recent first-parent commit pairs, `stats` for aggregating saved reports, and `publish` for validating and rendering a review preview. The CLI does not submit reviews to GitHub.

## Configuration and documentation

Profiles and provider configurations are supplied explicitly; the generic starter profile is [`profiles/generic.json`](profiles/generic.json). Keep provider credentials in environment variables or a secret manager. Before sending repository context to a provider, make sure that use is permitted by your project's data-handling requirements.

- [Operations guide](docs/OPERATIONS.md) — review modes, reports, and examples
- [Support and installation details](docs/SUPPORT-MATRIX.md)
- [Public CLI and package interface](docs/PUBLIC-API.md)
- [Review evidence and contribution receipt protocol](docs/REVIEW-EVIDENCE.md)
- [Provenance and evidence boundaries](docs/PROVENANCE.md)
- [Documentation index](docs/README.md)

## Contributing

Contributions are welcome. Start with [`CONTRIBUTING.md`](CONTRIBUTING.md) for development setup, project conventions, and the checks expected for a change.

## Security

See [`SECURITY.md`](SECURITY.md) for vulnerability reporting guidance. Do not include credentials or private repository content in public reports.

## License

This project is licensed under the [MIT License](LICENSE).
