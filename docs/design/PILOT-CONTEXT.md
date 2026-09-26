# SlopSearX pilot discovery

Read-only inspection on 26 September 2026. Target: `magnus919/SlopSearX`, public, default branch `main`; observed head `c1de456402961cf7d90703a4d8acca1a005392dc`. GitHub metadata and committed guidance/configuration were inspected, not the complete runtime or branch protection. No tests, inference, review posting, or repository mutation were performed. Remote main may evolve; refresh before implementation.

## Verified integration context

- Python package requires Python >=3.12. Configured tests target Python 3.12/3.13; FastAPI, Pydantic, HTTPX, FastMCP/MCP and Valkey are represented in package configuration.
- Existing review workflow invokes Droid with `review_depth: deep` and automatic security review. It triggers on PR opened/ready-for-review/reopened; this is evidence of existing wiring, not assurance of its review quality or cost.
- Committed Droid model settings use `general` through an OpenAI-like LiteLLM endpoint, authenticated via the workflow's `GPUSLUT_API_KEY` binding. The backend behind that routing alias was not verified. It must not be described as a confirmed direct Nous Portal deployment.
- Repository-secret metadata currently lists `DEEPSEEK_API_KEY`, `FACTORY_API_KEY`, and `GPUSLUT_API_KEY`. Values were neither requested nor exposed. No repository secret named Nous or TypeSafe appeared in this listing. This does not resolve environment secrets or an indirect provider binding; credential/model setup remains an implementation prerequisite.
- CI `jev-optional-modes` sets `TYPESAFE_API_KEY` to an empty string or `ci-synthetic-key` for deterministic optional-mode tests. This is not evidence of a live Jev credential or successful inference.
- Existing checks include Ruff, mypy, import-linter, vulture, deptry, duplication/complexity diagnostics, pip-audit, pytest/coverage, Valkey integration, SearXNG API contracts, portal contracts and deterministic browser journeys, Jev optional-mode tests, CodeQL workflow, and other release/deployment workflows. Job presence does not mean a required branch check, nor prove a particular PR passed.

## Project-profile candidates from committed guidance

These are documented repository policies to validate against current code when building the pilot profile, not independently verified implementation facts:

- Engine adapters return classified errors instead of leaking exceptions; normalized internal models remain distinct from external wire formats.
- Valkey owns shared durable state; asynchronous/research and cursor flows need recovery and consistency review.
- MCP search paths must pass a shared fail-closed policy gate; specialist grants do not independently grant sensitive-engine access, and mixed forbidden requests fail atomically.
- Search filtering must report actual enforcement, rather than infer it from parameter support.
- Search/policy/cache/serialization/config changes require portal impact review and relevant portal contract/browser evidence.
- Engine Jev routing metadata describes retrieval fit only; live policy, credentials, cost and health remain eligibility gates. Metadata completeness has a named test.
- Import-linter defines architecture layering and projection boundaries; local formatting/type/contribution rules should inform review instead of generic book rules overriding them.

Good initial evaluation slices include an adapter addition, a one-line MCP permission change, filter-enforcement claims, cursor/snapshot behavior, asynchronous job replay/recovery, Jev optional-mode/fallback changes, portal contract changes, and CI/provider configuration changes. These are proposed slices; real historical PRs and independent labels have not been selected or reviewed yet.

## Sources

- [Repository](https://github.com/magnus919/SlopSearX)
- [Agent guide](https://github.com/magnus919/SlopSearX/blob/c1de456402961cf7d90703a4d8acca1a005392dc/AGENTS.md)
- [Package and quality configuration](https://github.com/magnus919/SlopSearX/blob/c1de456402961cf7d90703a4d8acca1a005392dc/pyproject.toml)
- [Existing Droid review](https://github.com/magnus919/SlopSearX/blob/c1de456402961cf7d90703a4d8acca1a005392dc/.github/workflows/droid-review.yml)
- [Provider routing settings](https://github.com/magnus919/SlopSearX/blob/c1de456402961cf7d90703a4d8acca1a005392dc/.github/droid-settings.json)
- [CI](https://github.com/magnus919/SlopSearX/blob/c1de456402961cf7d90703a4d8acca1a005392dc/.github/workflows/ci.yml)

Unresolved: first pilot cost/latency budget; acceptable missed-blocker/false-positive/false-approval rates; shadow versus published reviews; exact generative and decision checkpoints and provider authentication binding; local inference reachability from hosted Actions; final storage/retention and permanent project-repository location.
