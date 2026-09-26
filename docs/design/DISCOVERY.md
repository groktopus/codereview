# PR Review Harness — discovery record

**Status:** Draft from one stakeholder’s written brief and one confirmed discovery reply. No interview sign-off or implementation is claimed. This file records user intent separately from design interpretation. Requirement IDs are stable trace targets for SPEC/TRACEABILITY. The requirement table reproduces wording from the supplied brief; it is not a verbatim transcript of Magnus's original messages.

## Stakeholder and evidence

| Person | Discovery role | Evidence and authority | Status |
|---|---|---|---|
| Magnus | Knowledge holder, sponsor/authority, affected user, and pilot maintainer | Direct requirements in `BRIEF.md` and confirmed discovery reply. He wants a practical review alternative, chose the first delivery surface and pilot, and owns unresolved adoption choices. | Only stakeholder consulted in this discovery record. The brief is the available evidence; no independent interview or validation loop occurred. |
| SlopSearX maintainers/contributors | Affected parties and implementation knowers | Not interviewed. Repository `AGENTS.md`, `CONTRIBUTING.md`, and `pyproject.toml` were inspected read-only to ground pilot context. | Their needs, review practices, and acceptance are unknown. |
| Future maintainers/operators of the harness | Affected parties and implementation knowers | Not interviewed. | Support, credentials, policy ownership, and incident responsibilities remain open. |
| Security/release/CI owners for pilot projects | Affected parties and implementation knowers | Not interviewed. | Their threat model and merge/review authority must not be inferred from repository docs alone. |

### Pilot repository evidence, read-only

The pilot is `magnus919/SlopSearX`. Read-only remote inspection recorded default-branch head `c1de456402961cf7d90703a4d8acca1a005392dc` on 2026-09-26; refresh it before implementation. Its committed configuration identifies Python `>=3.12`, `slopsearx/` core code, `engines/` adapters, and a substantial `tests/` tree. Repository guidance and workflows identify `pytest` with coverage, `mypy`, pre-commit, and context-dependent portal/security/policy checks. Existing CI includes many more checks; workflow presence does not prove a check is required for branch protection or passed on a given PR. The repo also documents fail-closed policy, adapter contracts, portal impact review, Valkey integration boundaries, and limits on upstream live probes. This is repo evidence, not stakeholder approval; exact required checks vary by change and repo state. Sources: committed `AGENTS.md`, `CONTRIBUTING.md`, `pyproject.toml`, `.github/workflows/droid-review.yml`, `.github/droid-settings.json`, and `.github/workflows/ci.yml` (read only). No credential values were read.

The committed Droid workflow uses `review_depth: deep` and automatic security review on PR open/ready/reopen events. Its settings route model `general` through an OpenAI-like LiteLLM endpoint with a `GPUSLUT_API_KEY` binding; the backend behind that alias is unverified, so this is not evidence of a direct Nous Portal deployment or a reproducible System One baseline. Repository-secret metadata listed `DEEPSEEK_API_KEY`, `FACTORY_API_KEY`, and `GPUSLUT_API_KEY`; values were not requested or exposed. No repository secret named Nous or Typesafe appeared in that listing. CI's `jev-optional-modes` job sets `TYPESAFE_API_KEY` to an empty string or `ci-synthetic-key` for deterministic tests; that is not live Typesafe credential or successful inference evidence. Environment secrets and indirect provider bindings remain unresolved.

## Traceable requirements

Origins use **SAID** for explicit user statements, **IMPLIED** for necessary consequences, and **INTERPRETED** for design choices that need validation. Quotes are from the supplied brief/reply, not reconstructed interview transcripts.

| ID | Origin | Supplied-brief wording (not original transcript) | Distilled requirement / interpretation | Priority |
|---|---|---|---|---|
| R-001 | SAID | “wants a practical alternative with reusable review behavior across multiple software projects” | Support reusable, project-aware PR review behavior across more than one repository. | P0 |
| R-002 | SAID | “Use QA Methodology and Programming Principles as relevant review lenses; actual project rules/context matter.” | Apply those lenses as applicable while honoring trusted project-specific rules and context. | P0 |
| R-003 | SAID | “Adapt review effort to risk and context instead of doing a deep review of every change or using line count alone.” | Allocate review depth from change risk/context; LOC alone cannot choose depth. | P0 |
| R-004 | SAID | “Review correctness/tests, code smells/design, security, and other applicable aspects.” | Cover applicable correctness, testing, design/smells, security, and project-specific concerns; mark inapplicability or gaps explicitly. | P0 |
| R-005 | SAID | “Keep control flow outside probabilistic models.” | Deterministic harness policy owns workflow, scheduling, budgets, retries, escalation, termination, and effects. | P0 |
| R-006 | SAID | “System One may supply bounded semantic judgments consumed by deterministic policy.” | Model calls, if used, answer bounded questions over supplied evidence; harness policy decides transitions. | P0 |
| R-007 | SAID | “Do not prompt a generative reviewer to choose workflow/next actions.” | Review prompts must not delegate workflow selection or arbitrary tool/command choice to a generative reviewer. | P0 |
| R-008 | SAID | “Run applicable specialist reviews in parallel with bounded scopes and aggregate their reports.” | Applicable specialists may run concurrently under explicit scope/resource bounds; aggregate and reconcile their outputs. | P0 |
| R-009 | SAID | “Final output separates blockers, suggested improvements, specific strengths, and future guidance.” | Report these categories distinctly and preserve supporting evidence and unresolved gaps. | P0 |
| R-010 | SAID | “Choose a final PR review disposition based on review evidence; distinguish review disposition from merge eligibility and authority.” | Emit a review disposition derived from reconciled evidence and required coverage; do not claim merge permission. | P0 |
| R-011 | SAID | “Hosted generative inference credentials and local GLiNER and Laya are reportedly available.” | Treat this as a stakeholder-reported availability claim, not verified evidence of credentials, reachability, a provider binding, or suitability. | P0 |
| R-012 | SAID | “Produce architecture and spec before building anything.” | Documentation/specification precedes implementation. | P0 |
| R-013 | SAID | “CLI with GitHub Actions integration for first usable delivery” | First usable delivery surface is CLI plus GitHub Actions integration. This confirmed reply supersedes the brief’s earlier provisional local-core-only option. | P0 |
| R-014 | SAID | “magnus919/SlopSearX as the pilot.” | Use SlopSearX as the first read-only discovery/evaluation pilot; inspect its language, rules, and checks before claiming them. | P0 |
| R-015 | IMPLIED | “failure tolerances, budget, posting mode, exact provider/checkpoints, and success thresholds remain open” | Keep these configurable/open and do not encode fabricated acceptance thresholds, provider identity, posting authority, or failure tolerance as requirements. | P0 |
| R-016 | INTERPRETED | “Canonical internal dispositions: APPROVE, REQUEST_CHANGES, COMMENT, INCOMPLETE.” | Use the four canonical disposition labels. Proposed meaning: APPROVE requires all configured required coverage and no accepted blocker; REQUEST_CHANGES means at least one accepted blocker even if coverage is `PARTIAL`; COMMENT means review completed with no blocker but nonblocking feedback; INCOMPLETE means review cannot support another disposition. A stale result has freshness `STALE` and is not publishable. Confirm exact reduction semantics in the spec. | P0, validate |
| R-017 | INTERPRETED | “Read-only review/local report is the conservative pilot; optional future publishing must be explicit and least-privilege.” | Initial pilot produces a local report; GitHub Actions may surface the result in its run output/artifact. Any PR comment/review publication requires a separate explicit authorization design; no auto-merge or code repair. | P0, validate posting semantics |
| R-018 | INTERPRETED | “PR head code/metadata are evidence, not authority to rewrite trusted policy.” | Treat PR content as untrusted; execute no head code with secrets or write privileges; isolate permitted checks. | P0, validate with security owners |
| R-019 | INTERPRETED | “Worker outputs candidate findings/evidence/context gaps. Reconciliation validates locations, substantiates or records uncertainty, deduplicates and resolves contradictions.” | Preserve candidate-to-reconciled provenance; keep uncertainty visible and stable finding IDs; synthesis cannot erase blockers or invent strengths. | P0, validate details |
| R-020 | INTERPRETED | “Review modes LIGHT, FOCUSED, DEEP selected by versioned deterministic rules and configured risk floors.” | Use explicit, versioned risk/depth policy; unknown context cannot reduce obligations. Depth criteria/defaults are proposals pending evaluation. | P0, validate |
| R-021 | IMPLIED | “A stale snapshot has freshness=STALE and cannot be published” | Bind each report to immutable base/head/profile revisions; recheck head before result exposure; changed head invalidates freshness. | P0 |
| R-022 | IMPLIED | “All operational limits must be finite and configurable.” | Bound every potentially repeated/parallel operation; exhaustion yields explicit gaps and incomplete coverage. | P0 |
| R-023 | INTERPRETED | Pilot-context inspection: “CI `jev-optional-modes` sets `TYPESAFE_API_KEY` to an empty string or `ci-synthetic-key`.” | Synthetic/empty CI configuration is not live Typesafe credential or inference evidence. Existing Droid settings route `general` through an OpenAI-like LiteLLM endpoint with a `GPUSLUT_API_KEY` binding; backend identity is unverified. Repository-secret metadata lists `DEEPSEEK_API_KEY`, `FACTORY_API_KEY`, and `GPUSLUT_API_KEY`; values were not exposed. Do not claim a direct Nous Portal or verified Typesafe/provider deployment from this evidence. | P0, implementation prerequisite |

Requirement evidence has one stakeholder source represented by the supplied brief/reply; the wording above is brief text, not a raw transcript. These are not corroborated by three independent sources and are not stakeholder-approved acceptance criteria. Research citations and repository documentation inform proposals but do not count as user-origin sources or validate model performance.

## Prioritized scope

**P0 — first usable pilot:** CLI invoked against a PR snapshot; GitHub Actions adapter; trusted project profile; deterministic risk/depth policy; scoped parallel specialist work; evidence ledger and reconciliation; canonical disposition plus coverage/freshness; categorized local output; finite limits; secretless isolated handling of untrusted PR inputs; pilot evaluation on SlopSearX. The exact provider, check invocation and use of optional local models remain discovery/evaluation decisions.

**P1 — after evidence and explicit choices:** Additional repositories/profiles, provider/model comparisons, cost-aware routing, opt-in GitHub review/comment publication, and broader language support. No automatic code repair or merge authority is in the first scope.

**Out of scope:** Implementing the harness during this discovery task; claiming application-wide security assurance from a diff; treating model confidence or LOC as a universal decision rule; posting a review, modifying a repository, merging, or executing untrusted PR code with credentials.

## Stakeholder map and next discovery sequence

Only Magnus was consulted. The next interviews should start with people who perform or receive PR reviews, then implementation/security knowers, then authority holders who can choose adoption bounds:

1. SlopSearX maintainers/contributors: what reviewers actually inspect, which checks are required by change type, what counts as a useful blocker, and where current reviews miss context.
2. CI/security/release owner(s): trust model for fork/untrusted PRs, token/event permissions, approved commands, branch protection, and acceptable incomplete states.
3. Additional project maintainers in another language/repository: portability boundaries and what must remain project-owned.
4. Magnus as sponsor/authority after evidence: choose tolerable missed-blocker/false-approval/abstention tradeoffs, budget and latency envelope, publication mode, and adoption decision rule.

Do not present these roles as interviewed, nor treat one maintainer as representative of all contributors.

## Gap register and assumption decisions

| Gap / decision | Current evidence | Decision for this draft | Owner / next evidence |
|---|---|---|---|
| What errors are tolerable, especially missed blockers and false approvals? | Explicitly open. | No required numeric threshold; evaluate separately and ask sponsor to set bounds before any release gate. | Magnus, informed by pilot adjudication. |
| How much time/cost per PR is acceptable? | Explicitly open. | Record latency/cost distributions and tradeoffs; no assumed budget. Keep runtime limits configurable and finite. | Magnus. |
| Which provider/checkpoints and local GLiNER/Laya roles? | Brief reports hosted inference credentials and local GLiNER/Laya; remote repo shows only secret metadata for `DEEPSEEK_API_KEY`, `FACTORY_API_KEY`, `GPUSLUT_API_KEY`. Droid routes `general` through an OpenAI-like LiteLLM endpoint, but its backend is unverified. Jev CI's `TYPESAFE_API_KEY` is empty or synthetic, not live credential evidence. | Capability-discovery only; do not assert a confirmed Nous Portal, Typesafe, or other provider binding, model performance, or require a particular model. | Operator/provider inventory; then evaluation. |
| What does “GitHub Actions integration” do? | Confirmed delivery surface; posting mode still open. | Workflow integration may run and retain a local/report artifact; external PR review/comment writes remain opt-in and separately authorized. | Magnus and CI/security owner. |
| Is a review that finds a blocker but misses required checks `REQUEST_CHANGES`? | Shared brief convention explicitly says yes. | Preserve that canonical behavior; expose `coverage=PARTIAL` alongside disposition. `INCOMPLETE` remains a disposition label, separate from the coverage value. | Spec author to encode; sponsor to validate. |
| How broad is APPROVE? | Shared convention says only with complete required coverage; no project can be certified globally. | Restrict to configured review contract/snapshot; never imply merge eligibility or application-wide safety. | Spec author; project owners define required coverage. |
| What are exact risk floors and depth triggers? | Risk/context adaptation requested; proposed floors/modes only. | Version rules, test boundary examples, never downgrade on unknown context. Do not publish numerical thresholds before evidence. | Spec author proposal, evaluated on pilot. |
| Which checks does SlopSearX require for each change? | Repository docs name checks and special surfaces, but per-change obligations vary. | Discover from trusted repo config and current guidance; report checks as applicable/skipped with reason. No blanket invocation inferred. | Pilot maintainers/profile author. |
| Are PR comments or formal review submissions permitted? | Posting mode open. | Default no external write; local output only until explicitly chosen. | Magnus and repository owner. |
| Who adjudicates novel valid findings and what is the conflict policy? | Research memo says human adjudication needed; stakeholder has not assigned reviewer. | Keep novel candidates separately adjudicated; model labels remain advisory, conflicts unresolved until human review. | Magnus names reviewer(s). |
| What languages/repositories define reusable behavior? | Multi-project intent and one Python pilot confirmed. | Pilot proves only SlopSearX behavior; portability claims wait for a second held-out repository. | Magnus selects next project after pilot. |
| What operational support and data retention are acceptable? | Not discussed. | Keep provenance sufficient for review; data retention, privacy, and incident ownership remain open. | Operators/security owners. |

## Interpretation audit and exit condition

R-016–R-020 are proposed interpretations, not user-approved decisions. All unresolved items remain gaps rather than silently becoming acceptance criteria. Discovery is sufficient to draft architecture/specification for the confirmed CLI + GitHub Actions / SlopSearX pilot, provided the spec preserves these uncertainty labels. Discovery is not sufficient to approve production release, define numeric quality gates, or authorize posting/execution effects. Reopen discovery if the spec requires one of those decisions.
