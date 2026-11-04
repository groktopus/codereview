# Canary-only live review publication

This is a **one-shot canary procedure**, not a general publisher. It publishes
exactly one `COMMENT` review to `magnus919/SlopSearX` pull request 1097 from the
`codereview-canary` GitHub App installation. It is not wired into the CLI, the
Actions runtime, the protected publication runtime, or any review pipeline, and
it is not evidence that general publication integration exists.

The adapter is [`scripts/canary_publish_review.py`](../scripts/canary_publish_review.py).
It has no retries and refuses to post unless `--authorize-publish` is present.

## Fixed identities

| Item | Value |
|---|---|
| Repository | `magnus919/SlopSearX` |
| Repository id | `1263452316` |
| Pull request | `1097` |
| App | `codereview-canary` (id `5605904`) |
| Installation | `178426239` |
| Marker | `<!-- codereview-canary:v1 -->` |
| Requested permissions | `pull_requests:write` (`actions:read` is deliberately not requested; the adapter never reads Actions data) |

The repository and pull request are pinned in the script. Any other
`--repo`/`--pr` value is refused with exit code 2.

## Preconditions

1. The private key exists at
   `~/.config/codereview-credentials/github-app.pem` with mode `0600`, or at the
   path named by `PR_REVIEW_GITHUB_APP_PRIVATE_KEY_FILE`. The script opens it
   with `O_NOFOLLOW`, requires a regular file owned by the effective user, and
   refuses symlinks, foreign ownership, or group/world-readable modes.
2. The App installation still grants `pull_requests:write` on
   `magnus919/SlopSearX`. The script rejects any returned token permission
   outside `{actions:read, metadata:read, pull_requests:write}`, requires
   `pull_requests:write`, and requires a valid future `expires_at` no more than
   two hours ahead.
3. The review body is already written to a UTF-8 file. It must not contain the
   marker; the script appends the marker exactly once.
4. The exact current pull request head SHA is known from a trusted read, not
   from the body file or a receipt.
5. The `--receipt-out` parent directory exists and is writable. The script
   proves this by creating and removing a temporary file before it mints a
   token or posts anything.
6. `PyJWT[crypto]` is importable by the interpreter running the script.

Optional environment overrides (defaults are the canary constants):

| Variable | Meaning |
|---|---|
| `PR_REVIEW_GITHUB_APP_PRIVATE_KEY_FILE` | PEM path |
| `PR_REVIEW_GITHUB_APP_ID` | App id |
| `PR_REVIEW_GITHUB_APP_INSTALLATION_ID` | Installation id |

## One-shot procedure

Set the expected head from a trusted read of the pull request, then run exactly
once:

```bash
HEAD=$(gh api repos/magnus919/SlopSearX/pulls/1097 --jq .head.sha)

python3 scripts/canary_publish_review.py \
  --repo magnus919/SlopSearX \
  --pr 1097 \
  --expected-head "$HEAD" \
  --body-file /secure/path/canary-review.md \
  --receipt-out /secure/path/canary-receipt.json \
  --authorize-publish
```

The script performs these steps in order, stopping at the first failure:

1. Refuse unless `--authorize-publish` is present.
2. Validate the pinned repository, pull request, and 40-character head SHA.
3. Read the body file and append the marker.
4. Load the PEM and sign an RS256 App JWT (9-minute lifetime, 60-second
   backdate).
5. Mint a single installation token scoped to repository id `1263452316` with
   only `pull_requests:write`; the token is held in memory only.
6. `GET` the pull request and require `state == "open"` and
   `head.sha == --expected-head`. Anything else is refused before a review is
   posted.
7. `GET` reviews with bounded pagination (100 per page, at most 10 pages) and
   search for the marker.
8. If exactly one marker review exists, require `commit_id == expected head`,
   `user.login == "codereview-canary[bot]"`, `user.type == "Bot"`,
   `state == "COMMENTED"`, and an exact SHA-256 match of the review body against
   the composed body file plus marker. On success report `ALREADY_PUBLISHED`,
   post nothing, and write an `ALREADY_PUBLISHED` receipt. Any mismatch is
   refused or exits 3 without posting.
9. Otherwise `POST` exactly one review with `event: COMMENT` and
   `commit_id: <expected head>`; there are no retries.
10. Re-read reviews, locate the exact returned review id, and verify
    `commit_id`, `state == "COMMENTED"`, the marker, and an exact SHA-256 body
    hash match against the composed body.
11. Atomically write the verification receipt with mode `0600` and fsync the
    receipt directory after the rename.

Expected output:

```text
canary_publish_review status=VERIFIED review_id=<id> receipt=<path>
```

or, when a marker review already exists:

```text
canary_publish_review status=ALREADY_PUBLISHED review_id=<id> receipt=<path>
```

Failures print only a fixed code, for example
`canary_publish_review error=pull_request_head_mismatch`, to standard error.
Tokens, the private key, API response bodies, and review content are never
printed.

## Receipt

The receipt is written after a newly posted review is read back and verified,
and also when an existing marker review passes every identity and body-hash
check:

```json
{
  "repo": "magnus919/SlopSearX",
  "pr": 1097,
  "head": "<40-character head SHA>",
  "review_id": 123456789,
  "html_url": "https://github.com/magnus919/SlopSearX/pull/1097#pullrequestreview-123456789",
  "published_at": "2026-11-04T12:01:00Z",
  "status": "VERIFIED"
}
```

`published_at` is the review's `submitted_at` normalized to UTC. `status` is
`VERIFIED` for a new review and `ALREADY_PUBLISHED` for a verified idempotent
match. The file is written with `fsync` to a temporary file in the destination
directory, atomically replaced at `--receipt-out`, and the directory is fsynced
after the rename. The destination directory must already exist and be writable.

## Exit codes and safe failure behavior

| Exit | Meaning | Safe action |
|---|---|---|
| `0` | New review verified, or an existing marker review passed every identity and body-hash check | Keep the receipt |
| `2` | Refused by a local or server-side precondition; no review was posted | Fix the precondition and re-run deliberately |
| `3` | Transport, token, receipt, or verification state is unknown | Do not assume publication succeeded; inspect the pull request and review list manually before any retry |

Specific rules:

- Any non-zero exit is a stop. Do not wrap this script in a retry loop.
- Exit `2` means no review POST occurred. Typical causes are a missing
  authorization flag, a moved or mismatched head, a closed pull request, an
  unreadable or over-permissive key, an oversized/empty body, or an
  unsupported repository or pull request.
- Exit `3` can occur after a POST, for example when read-back verification or
  the receipt write fails. The review may exist even though no receipt was
  written. Inspect the pull request before re-running.
- Re-running is marker-idempotent only when the existing review is exactly
  ours: matching commit, bot author, `COMMENTED` state, and body hash. It then
  reports `ALREADY_PUBLISHED`, posts nothing, and writes an
  `ALREADY_PUBLISHED` receipt. A marker at a different commit is refused with
  exit 2; a marker with a different author, state, or body exits 3. Neither
  case posts a second review.
- If pagination exceeds 10 pages of 100 reviews, absence of the marker cannot
  be established and the script exits 3 without posting.

## Limits

- No rollback, deletion, update, dismissal, or approval path exists here.
- No retry, queue, workflow, CLI, or Actions integration exists here.
- Only one repository and one pull request are accepted.
- Review bodies are limited to the GitHub review-body bound (65,536
  characters including the appended marker).
- Redirects are refused so a token-bearing request cannot be replayed to
  another host.

Any broader publication use requires a separate design, authorization, and
review; this procedure must not be treated as that implementation.
