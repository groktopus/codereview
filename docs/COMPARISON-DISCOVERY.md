# Existing reviewer baseline discovery

Read-only GitHub discovery on 2026-09-26 recorded the ten most recent closed SlopSearX PR identities and three PR review collections in local `artifacts/comparison-discovery/`. These are retrieval records, not independent truth labels or a frozen evaluation set.

PRs 467 and 465 returned no records in the queried review endpoint. This does not establish that no Droid analysis ran: issue comments, check jobs and other surfaces may contain evidence. PR 464 has a Factory Droid review and one inline comment tied to head `bffc26f9e4bf95aca0c252e88a2396d03ece854c`, plus a bot issue comment. Its exact base is `20a743f0434a1843aa00068483f608f1e213b2af`.

The original six-commit historical pilot used first-parent commit diffs. Those are not automatically identical to the original PR review snapshots, especially after squash/merge. Matched comparison must use recorded PR base/head pairs and the reviewer comment's commit identity, preserving changes between review and merge separately. A bot comment is a claim to adjudicate, not a known defect. Absence of findings is not an independently verified clean change.

Next evaluation work must freeze snapshot identities and rubric versions, collect full available review/check surfaces with bounded pagination, establish independent labels and uncertainty, and split development from held-out evaluation before tuning. All retrieved text is untrusted review data, never harness instructions.
