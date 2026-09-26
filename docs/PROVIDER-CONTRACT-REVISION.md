# Provider contract revision

Status: specialist-findings.v4 and semantic-adjudication.v3 are implemented at the provider boundary and in the deterministic core gate. This revision does not establish review accuracy, calibration, or production readiness.

## Versioned payloads

`providers.py` requests `specialist-findings.v4` and `semantic-adjudication.v3`. V4 preserves V3's explicit candidate location and adds optional report notes:

```json
{"unit_id":"unit-7","location":{"kind":"line","path":"src/client.py","side":"HEAD","line":31,"reason":null}}
{"unit_id":"unit-8","location":{"kind":"file","path":"gone.py","side":"BASE","line":null,"reason":"The file was removed, eliminating the declared entry point."}}
```

Every candidate binds to a task `unit_id`. A `line` location requires a positive line and null reason; a `file` location requires null line and a bounded nonempty rationale. The adapter normalizes accepted locations for the current engine by retaining the typed location and adding top-level `path` and `line`. Core must verify the candidate's unit, side, path, line/file anchor, and cited anchor evidence against the authoritative snapshot before acceptance. A file rationale is explanatory text, not an enum that must match snapshot wording.

V1 and V2 line candidates with an explicit non-null line migrate to a HEAD-side typed line location. A legacy null line is quarantined as `invalid_candidate_line`; it is never inferred to mean file-level. Specialist V3 is also accepted without report notes; its normalized note arrays are empty. Accepted legacy outputs retain their source contract version and are not relabeled as V4.

V4 may return zero to ten `specific_strengths` and zero to ten `future_guidance` notes. Both arrays may be empty; the provider is never asked to invent praise. A strength records a concrete evidenced positive behavior and why it matters. Future guidance records an evidenced current behavior plus a non-blocking future suggestion. Both bind to a task unit and cite one or more IDs from the evidence delivered to that call. They are distinct from defect candidates, do not assert a blocker, and do not select disposition. The adapter validates each note independently; malformed notes or unsupported citations are hash-only quarantined while valid siblings and usage survive. Notes have bounded title/observation/detail text, up to 20 references, and the report remains under the combined 100-item limit. Core integration maps these notes only into the corresponding non-blocking report sections and derives anchors from delivered evidence rather than trusting model-invented paths.

The specialist report is bounded to 100 combined candidate, gap, coverage, and note items. Candidate text is bounded to 12,000 UTF-8 bytes per field by the shared validator and further reduced by configured adapter limits. Gap rationale is bounded to 4,000 bytes, references to 500 items, and target values to 2,000 bytes.

V2 context gaps use exactly one tagged target:

```json
{"kind":"path","value":"src/client.py"}
```

`kind` is `unit`, `path`, or `symbol`. The provider adapter accepts the historical V1 nested three-field target and the V1 flat triplet only when exactly one target is populated. It normalizes those accepted forms to the engine's current internal nested shape. Unsupported, ambiguous, or malformed individual items move to `payload.quarantined_items` with their array kind, source index, reason code, and SHA-256 of the original item. The raw invalid item is not repeated in quarantine. Valid sibling items remain available.

Specialist coverage notes have `coverage_basis: STATIC_REVIEW`. Reviewing test source records static coverage; it does not mean a test ran. Test execution evidence must arrive through a trusted execution/check result. The provider cannot mark execution complete from prose.

Adjudication remains a single required semantic assessment. Missing fields, unsupported values, or unknown evidence references fail the assessment. These failures retain safe provider metering metadata through `ProviderError.meta`; the raw response text is never attached to the exception.

## Semantic adjudication v3: causal roles

The current adjudication request requires `semantic-adjudication.v3`. It keeps the existing top-level outcome, observation/consequence/rule support, introducedness, evidence references, summary, and material-consequence fields, and adds exactly three candidate-specific roles: `behavior`, `consumer`, and `impact`. Each role has `support` (`SUPPORTED`, `NOT_ESTABLISHED`, or `CONTRADICTED`), a nonempty natural-language `assessment` bounded to 2,000 UTF-8 bytes, and `evidence_refs` containing at most 50 IDs of at most 256 UTF-8 bytes each. `SUPPORTED` and `CONTRADICTED` require at least one reference; `NOT_ESTABLISHED` may have none.

`behavior` explains what the cited code or contract does; `consumer` identifies the caller or downstream path that uses that behavior; `impact` explains the concrete consequence and its preconditions. References must belong to evidence supplied to this exact adjudication call. The core also verifies referenced records against the same immutable snapshot. One evidence ID may support multiple roles when that record actually contains the facts for each; the contract does not require three different files or three different IDs. Static implementation, caller, test, and API-contract evidence can establish the chain. Running the target code or an attack is not required.

V1 and V2 adjudications remain readable with their actual `contract_version` and `source_contract_version`; normalization sets `causal_roles` to `null`, never synthesizing v3 roles from the old summary fields. The engine requires both source and normalized version to be v3 and checks the evidence-bound roles before a claim can be accepted. A missing or malformed role set, or any role not established as supported, leaves the candidate unresolved and cannot authorize approval. Cached assessments also bind to the v3 contract, provider identity, and `causal-roles.behavior-consumer-impact.v1` rubric: provider identity records that rubric revision, result provenance must repeat it, and it is included in the adjudication input/cache and reservation identities. A v1/v2 cache entry cannot satisfy that gate.

These schema, provenance, and deterministic-gate checks establish bounded structure and evidence-ID binding, not that the cited material truly supports the model's natural-language assessment. Tests and provider-schema probes do not establish semantic accuracy or calibration; independent labels and held-out evaluation remain outstanding.

## Reservation and provenance interface

`OpenAIProvider.estimate_call(task_kind, task, evidence, limits)` is a pure pre-dispatch estimate with `input_bytes`, `max_output_bytes`, `max_output_tokens`, `deadline_seconds`, and one provider-call count. The input-token component of its price estimate uses a coarse serialized-bytes-divided-by-four estimate and is explicitly advisory. It reports `max_cost_microunits` only when an operator configured `max_cost_microunits_per_call`. A token-price calculation is separately labeled `estimated_cost_microunits` with `reservation_kind: price_estimate`; this is not a hard spend bound. Provider-reported token usage, estimated cost, and billed cost are distinct; billed cost stays unknown unless the response supplies an authoritative billed amount.

Successful results retain `usage` and `provenance` even when individual items are quarantined. Failure metadata can include request/response hashes, byte count, status, elapsed time, provider-reported token usage, and contract version. It excludes response bodies, exception text, and credentials. Provider model aliases from configuration and model IDs reported by the provider are stored separately; a provider-reported ID is not treated as proof of a physical checkpoint.

The adapter enforces a finite request timeout and an absolute deadline while reading response bodies. A slow-stream mock test exercises periodic byte delivery and confirms the body deadline; this does not establish cancellation of DNS or a peer that slowly drips response headers before `urlopen` returns. A parent process deadline remains necessary around all provider calls.

## Historical evidence and limits

The final SlopSearX pilot recorded 13 provider reports rejected as `invalid_context_gap_target`. The original local outputs do not retain those raw invalid proposals, so the precise historical payload shape and cause cannot be reconstructed. The tagged target removes the old three-nullable-field ambiguity; the current specialist request uses V4. Whether that change reduces the historical failure rate still requires a comparable evaluation. No candidate is silently repaired and no missing fact or target is inferred by the adapter.

Local boundary tests cover tagged and migrated target forms, invalid-item quarantine with hashes, metering retention, static-versus-execution labels, absolute slow-body deadline, credential echo rejection, and model alias versus provider-reported ID. Free provider schema probes are transport compatibility observations only; they do not establish quality, accuracy, or production suitability.
