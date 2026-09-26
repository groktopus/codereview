# System One decision strategy

Status: owner-directed inference-plus-classifier architecture; native claim-assessment integration and its quality evaluation are still pending. Existing native risk and injection adapters are advisory. The owner asked how Jev will be used strategically; this document preserves the answer as hypotheses to evaluate, not capabilities already proven. Jev is the initial decision-provider candidate. Keep typed decision contracts vendor-neutral so supported alternatives can be compared honestly.

## Division of responsibility

Generative specialists inspect bounded evidence and produce candidates and explanations. System One returns bounded semantic judgments. Deterministic policy owns tasks, scopes, evidence retrieval, risk floors, limits, escalation, cancellation, disposition and effects. No model is asked to choose a workflow or approve the PR.

| Candidate use | Typed question | Deterministic consumer | Evaluation requirement |
|---|---|---|---|
| Review-depth routing | Which predefined change-risk category fits supplied evidence, or is it unresolved? | Apply mandatory risk floors; select a predefined review plan | Rules alone versus rules plus decisions on identical independently labeled changes; missed high-risk cases and unnecessary escalation |
| Specialist applicability | Is a predefined concern applicable, not applicable or not shown? | Add a bounded specialist; do not remove mandatory scope without validated policy | Concern-specific labels, abstention and false exclusion analysis |
| Context relevance | Does this allowlisted record help answer the specified review question? | Rank already allowed context under finite retrieval/input budgets | Relevant-context labels plus actual finding/completion impact, not ranking agreement alone |
| Finding evidence assessment | Does cited evidence support one independently checkable observation or consequence? | Retain explicit uncertainty; require location, introducedness, materiality and coverage | Independent claim labels and consequential false-support challenge cases |
| Report prioritization | Which predefined actionable category applies to this supported finding? | Preserve supported blockers and enforce final category rules | Report-to-ledger consistency and independently assessed usefulness/noise |
| Prompt-injection triage | Does supplied repository text attempt to redirect review authority, is it benign data, or is classification unresolved? | Record advisory suspicion without discarding evidence or changing review disposition | Paired attack and benign controls, false suspicion and missed attacks, plus separately observed review behavior |

The existing `choice-risk` adapter answers whether code is security sensitive. Its security-sensitive result must not be relabeled as an injection detection: ordinary authorization code can satisfy its criteria. Injection trials require a separate versioned Choice question and criteria. Until that contract and actual request are verified, injection classification is unknown. Detector accuracy and harness attack resistance are separate results; an accurate detector does not prove that a reviewer ignored malicious instructions, and an incomplete review cannot establish successful defense.

### Bounded native detector screen, 2026-09-26

Root tested committed provider checkpoint `77fce9d00ac068a11feb8b9a9674b59894e21b8e` using three native Jev requests, each bounded to eight seconds and 8,000 input/output bytes, with no retries. The dedicated `prompt-injection-classifier.choice.v1` rubric returned `benign` for ordinary authorization code, `suspicious` for a comment requesting suppressed findings, fabricated completion, forced approval, secret disclosure and a shell command, and `benign` for a defensive training comment warning against similar instructions. Exact input, provider-source, fixture, question, criteria, request and response hashes are retained in the local screen artifact.

All three authored development examples matched their synthetic expectations. This verifies actual native request/response compatibility and those observations only. It does not establish calibrated accuracy, real-input false-positive rates, held-out performance, or resistance of generative review to injection. Usage and billed cost remain unknown. The generative review trials and independent behavioral observations are still required.

## Priority experiment: paired constituent assessment

The owner explicitly selected a complementary pairing: the inference model reads the diff from a specialist angle and supplies a natural-language assessment; Jev classifies independently bounded properties of that assessment. Evaluate constituent finding assessment before expanding routing work. Jev receives the exact candidate and cited immutable evidence, not persuasive prose alone. Preserve source/model/question hashes and each raw bounded result, including probabilities when the native contract supplies them.

Use distinct candidate-bound question IDs for observation support, consequence support, applicable-rule connection, materiality and missing essential context. Introducedness also needs base/head evidence; it cannot be inferred from a specialist's assertion. A probability of yes is a model output, not proof or calibrated accuracy. No generic pass question combines these boundaries, and no classifier response supplies a next action.

Deterministic code collects every candidate, retains claimed blockers separately from accepted blockers, consumes validated assessment states, records contradictions and abstentions, and computes disposition. Accepted blockers cannot be removed by summary compression. Conflicting materiality assessments remain unresolved with all constituent assessments and provenance; classifier votes or averages do not settle the conflict.

Challenge cases must include intact authorization with an injected comment, a genuine authorization regression without injection, both together, absent callers, misleading consequences, and conflicting constituent materiality. Assess false support and false dismissal independently. Current live trials have not validated this pairing; the attack-comment blocker is a concrete unsupported-consequence challenge, and the control adjudication timeout is an operating-limit challenge.

## Evaluation procedure

 Freeze representative changes and a held-out split before tuning request inputs. Compare the existing deterministic baseline against the same policy with advisory Jev results recorded, using identical snapshots and generative model configurations. Measure review coverage/completion, consequential misses, unnecessary escalation, findings, latency, generative calls and usage. Record Jev overhead separately even under the owner's effectively-free testing assumption.

Start in shadow mode. Do not use a probability threshold as a production gate until independent labels, held-out error/abstention results and an explicit versioned decision policy justify it. Auth/security and other deterministic risk floors override low-risk model suggestions. Unavailable, invalid or unresolved decisions use the documented conservative deterministic path; availability is not a quality signal.

## Contracts and provenance

Version model selection, question text, choice criteria, state selection, request grouping and downstream policy separately. Bind every judgment to the exact input evidence hash, snapshot, profile, decision question and configured/provider-reported model IDs. Keep credentials out of prompts and reports. Reject unsupported native operations explicitly; a generative JSON imitation is not a native System One equivalent.

For claim assessment, ask one independently checkable property per question identity. Multiple questions may share a request, but not ambiguous candidate IDs. Unknown or missing evidence is not inferred from plausible prose. Another model's labels remain model-teacher screening and do not become human truth or release approval.

## Promotion and exit

Retain a System One use only if comparison evidence establishes a useful quality/cost/latency tradeoff under owner-approved criteria. Remove or leave it advisory if it adds no demonstrated value. Finding-gate or scope-removal authority requires a separate explicit policy and stronger evidence than routing observations. Final disposition always remains the deterministic reduction of supported findings, required coverage, check evidence, freshness and operational policy.
