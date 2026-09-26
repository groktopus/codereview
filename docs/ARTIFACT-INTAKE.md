# Publication artifact intake boundary

`pr_review_harness.artifact_intake.intake_artifact_bundle` is a pure parser
and cross-check for the fixed publication bundle described by
[Actions publication design](ACTIONS-PUBLICATION-DESIGN.md). It accepts an
already acquired binary stream plus independently supplied expected identity
and transport-digest records. It does not make network calls, stage files,
write publication state, verify signatures itself, authorize a review, execute
artifact content, or submit a GitHub effect. It is compatible with a stateless
protected-workflow intake path and has no dependency on a local service or
SQLite.

The ZIP must contain exactly these two regular data files:

- `review-result.json`
- `provenance.json`

The manifest is schema `1.0` and has a closed field set: repository numeric ID
and name, PR number, exact base/head SHAs, upstream workflow run ID/attempt,
caller workflow ID/path/ref/SHA, called harness repository/path/SHA, profile
version/hash, provider configuration identity, review-run ID, result file
SHA-256 and result hash, timezone-aware creation time, and the exact supported
contract-version map. The expected values must come from the trusted caller's
operator policy and independent GitHub run/PR/artifact reads, never from the
bundle alone. The result's repository, PR, base/head, profile version, and
review-run ID are cross-checked against the manifest and expected identity.
Both its canonical internal result hash and exact result-file digest must
match. This does not replace the publisher's semantic `preview_publication`
validation or a fresh GitHub target-state check.

Default hard limits are 8 MiB compressed ZIP, 16 MiB total expanded data,
15 MiB for the result, 64 KiB for the manifest, 128 UTF-8 bytes per member
path, a 1000:1 declared compression ratio, and a 20-second intake deadline.
The parser reads the input stream in bounded chunks into a spooled temporary
file, checks the compressed cap as it reads, then checks each member size and
total expansion while decompressing. It permits only stored or deflated ZIP
members. It rejects directories, symlinks, devices, encrypted entries,
duplicate normalized paths, path traversal/absolute/backslash paths, extra
files, duplicate JSON keys at any depth, non-finite JSON numbers, invalid
UTF-8, JSON nesting over 64, and more than 200,000 structural tokens. Limits
may be lowered for tests or a more restrictive caller; they cannot exceed the
defaults.

The expected artifact transport digest is SHA-256 over the exact downloaded
ZIP bytes. The intake verifies the bytes against that expected digest. The
`source` label on `ArtifactTransportDigest` is provenance metadata, not proof
that the upstream API defines its digest over these exact bytes. The GitHub
adapter must verify that API contract before describing its value as an exact
ZIP digest; until then production admission based on that API field is
unavailable. ZIP transport digest and attested file-subject digests are
separate identities and are never equated.

Attestation is deliberately injected through `TrustedAttestationVerifier`.
The verifier receives the exact result/manifest SHA-256 subject map, the
transport ZIP digest, and a trusted expected signer/run identity. It must
perform signature, issuer, signer workflow, repository, workflow revision,
run/attempt, reusable-workflow identity, and subject-digest verification before
returning a structured `VerifiedAttestation`. The intake then checks that the
proof contains exactly those two subjects and the exact trusted identity. A
boolean, truthy object, mismatched digest, or mismatched run is rejected. No
production verifier implementation is currently supplied. With no verifier,
the parser may return validated bytes with `attestation_state=UNAVAILABLE`;
that state is not eligible for production admission. Do not accept a verifier
chosen by untrusted input, and do not treat the returned state alone as review
validity or publication authorization.

The 20-second value bounds work between stream reads and parsing stages; a
blocking `BinaryIO.read()` or a verifier implementation can outlive it. The
network downloader must have its own finite transport timeout, and any external
verifier must run under a caller-enforced process deadline/cancellation
boundary. This function does not claim to interrupt arbitrary blocking code.
Verifier exceptions are reduced to a stable safe error code without copying
exception details into logs or reports.

The fixed caps and field names are an initial contract proposal. There is no
checked-in trusted production attestation verifier, no verified live GitHub
artifact-digest semantic in this module, and no live artifact attestation
canary. Tests use generated local ZIPs and a fixture verifier only; they do
not establish API contract compatibility, signer identity correctness, review
quality, or readiness to publish.
