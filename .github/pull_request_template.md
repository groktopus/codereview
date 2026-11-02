## Summary

<!-- What changes, and why? Link the issue. -->

## Validation

<!-- Commands, tests, or checks you ran and their observed results. -->

## Decision record (GA-2)

**Enforced.** The `Decision record links` check reads this pull request's
changed files from the GitHub API. If any changed path — including a rename or
deletion — matches a path or glob in
[safety-invariants.json](https://github.com/groktopus/codereview/blob/main/docs/adr/safety-invariants.json),
or changes that manifest itself, the review receipt below must carry a
non-empty `decision_records` list. Every cited record must already exist on
`main`, be listed in the
[decision-record index](https://github.com/groktopus/codereview/blob/main/docs/adr/README.md),
and have Status **Accepted**. Land the accepted record first, then cite it here;
a record added by this same pull request is not on the base revision yet.

- [ ] Decision record: <`NNNN` or `docs/adr/NNNN-*.md` link, or `not required — no safety-invariant path changed`>

## Review receipt

Every pull request needs a review record in the fenced `review-receipt` block
below. The reviewer fills it in, not the author, and not CI. Replace every
placeholder; the `Review receipt` check fails on placeholders, a reviewed SHA
that is not the current head, `NOT CLEAR`, undeclared self-review, and agent
reviews without a recorded protocol. See
[docs/REVIEW-EVIDENCE.md](https://github.com/groktopus/codereview/blob/main/docs/REVIEW-EVIDENCE.md)
for the field contract and the evidence rules.

```review-receipt
{
  "schema": "review-receipt.v1",
  "reviewer": {
    "identity": "<GitHub login or recorded agent identity>",
    "kind": "<human or agent>",
    "protocol": "<required for agents: harness, model, and review protocol>"
  },
  "reviewed_sha": "<full 40-character head SHA that was reviewed>",
  "independence": "<state whether the reviewer is independent of the author and what was independent about the review>",
  "scope": [
    "<diff range, files, or behavior actually examined>"
  ],
  "verdict": "NOT CLEAR",
  "evidence": [
    {"kind": "link", "value": "<https://... durable evidence link>"},
    {"kind": "command", "value": "<command run and its observed result>"}
  ],
  "reviewed_at": "<ISO 8601 timestamp with time zone, e.g. 2026-11-02T12:00:00Z>",
  "self_review": false,
  "post_merge_verification": "<how the merge commit and required checks will be verified after merge>",
  "decision_records": ["<NNNN or docs/adr/NNNN-*.md; required only when a safety-invariant path changes>"]
}
```

Reviewer checklist:

- [ ] `reviewed_sha` equals the pull request head SHA at the time of review.
- [ ] I examined the code and evidence named in `scope`; the verdict is mine.
- [ ] `self_review` is `true` only when I am also the author, and the independence statement says so.
- [ ] An agent review records `kind: "agent"` and a non-empty `protocol`.
- [ ] Evidence entries are durable links or exact commands, not claims.
- [ ] `decision_records` names accepted, indexed records when a safety invariant path changed.

## Merge checklist

- [ ] Required checks are green at the exact reviewed head.
- [ ] The review receipt passes the `Review receipt` check on that head.
- [ ] The `Decision record links` check passes on that head.
- [ ] After merge, the merge commit and its post-merge required checks are verified and recorded.
