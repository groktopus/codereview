## Summary

<!-- What changes, and why? Link the issue. -->

## Validation

<!-- Commands, tests, or checks you ran and their observed results. -->

## Decision record (GA-2)

Required when this change alters a safety invariant or an external effect. Link
the specific accepted record, or add/amend one, in the
[decision-record index](https://github.com/groktopus/codereview/blob/main/docs/adr/README.md).
The protected surfaces are listed in
[safety-invariants.json](https://github.com/groktopus/codereview/blob/main/docs/adr/safety-invariants.json).

- [ ] Decision record: <link, or `not required — no safety invariant or external effect changed`>

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
  "post_merge_verification": "<how the merge commit and required checks will be verified after merge>"
}
```

Reviewer checklist:

- [ ] `reviewed_sha` equals the pull request head SHA at the time of review.
- [ ] I examined the code and evidence named in `scope`; the verdict is mine.
- [ ] `self_review` is `true` only when I am also the author, and the independence statement says so.
- [ ] An agent review records `kind: "agent"` and a non-empty `protocol`.
- [ ] Evidence entries are durable links or exact commands, not claims.

## Merge checklist

- [ ] Required checks are green at the exact reviewed head.
- [ ] The review receipt passes the `Review receipt` check on that head.
- [ ] After merge, the merge commit and its post-merge required checks are verified and recorded.
