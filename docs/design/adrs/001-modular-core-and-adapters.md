# ADR-001: Keep a reusable modular core behind CLI and Actions adapters

- Status: Proposed; acceptance not recorded
- Scope: initial local CLI and GitHub Actions integration, SlopSearX pilot
- Decision authority: unresolved; product owner and maintainers must accept implementation scope
- Primary contact: architecture/specification authors, to be assigned for implementation
- Evidence: BRIEF.md direct selection of CLI plus Actions and SlopSearX; research memo; ARCHITECTURE.md scenarios

## Context

The selected first delivery combines a CLI with GitHub Actions integration and is intended to reuse review behavior across projects. No confirmed workload requires a hosted service or independent scaling. A workflow-only implementation would bind policy to YAML and reduce local reuse. The pilot profile, GitHub settings, and provider behavior remain unverified.

## Decision

Propose a local modular core with CLI and Actions adapters. The core owns review policy and canonical contracts; adapters map invocation and platform data. Provider, repository-context, deterministic-check, and publication interfaces remain replaceable modules within one deployment until evidence supports a service boundary.

## Considered options

- Modular core plus CLI and Actions adapters: supports local and CI use while keeping first deployment simple; requires disciplined contracts so adapters do not fork policy.
- Actions-only workflow: direct GitHub fit; increases workflow-specific coupling and limits local reuse.
- Hosted service with queue and worker fleet: independent operation may later help at scale; currently adds ownership, credentials, network, consistency, and recovery burdens without evidence.

## Consequences

The core remains portable and one controller owns state transitions. Internal bounded concurrency is supported. Service decomposition is deferred until measured workload or isolation needs justify deployment coupling. The first implementation must prove the CLI and Actions adapter call the same reducer and contract versions.

## Confirmation plan

Inspect SlopSearX workflow conventions and run the same representative request through local and Actions adapters with matching snapshot/profile inputs. Compare canonical results and adapter-only metadata. This is planned evidence, not completed validation. Revisit if Actions restrictions block safe read-only retrieval or observed concurrency exceeds local bounded execution.
