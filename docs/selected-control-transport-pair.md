# Selected control HTTP/TLS trace pair

`--transport-pair` is an opt-in, secretless Linux diagnostic for comparing scoped trace volume through the normal installed `pr-review` CLI. It prepares the fixed `r1-control` fixture once, runs one HTTP loopback arm, and runs one HTTPS loopback arm only if the HTTP arm completed with a reconciled trace below the existing 1 MiB cap. It does not run the attack variants.

The separate **Selected control HTTP TLS transport probe** GitHub Actions workflow is manual-only. Dispatch it from `main` in `groktopus/codereview`; it checks out the exact dispatched commit, builds and installs that commit's wheel, verifies the complete source module map against the installed wheel, and runs in a loopback-only network namespace. It uses no provider secrets and makes no calls to a target repository. Existing pull-request measurement workflows do not run this pair.

Transport receipt v1 remains bound to its historical 35-module source inventory. Current runs emit receipt v2, which records the complete module-name-to-SHA-256 map and count for the exact dispatched source commit; the validator recomputes that map from the checked-out source and requires exact equality. This version change preserves the historical v1 contract and hashes.

For a local reproduction, run it only inside an equivalent loopback-only network namespace with the exact CLI installed from the source checkout whose identity is recorded in the receipt:

```sh
python scripts/selected_control_trace_attribution.py \
  --cli "$TRACE_CLI" \
  --workdir "$ARTIFACT_DIR" \
  --transport-pair
```

The command fails closed when Linux `strace` is unavailable, the installed runtime does not match the complete source module map, certificate generation or trust setup fails, the HTTP arm is incomplete/capped, or the paired inputs and payload hashes do not match. A complete result requires both arms to have complete traces under 1 MiB, the same six settled fake exchanges, identical per-stage request and response body hashes and sizes, identical fixture/profile/limits/snapshot/task/run/event identities, and matching normalized endpoint configuration. The only expected treatment difference is loopback transport (`http` versus `https`, including the ephemeral port), server-side TLS, and the declared trust bundle.

Limits remain the existing values per arm: nine provider calls maximum, zero retries, 64,000-byte task input, 32,768-byte task response, four claim assessments, 270-second engine deadline, 300-second observer timeout, the existing syscall scope, and a 1 MiB trace cap. The same fixed snapshot object is reused; `run_id` remains `r1-control` and no GitHub event identity is supplied. Provider-shaped requests go only to the fake loopback handlers with synthetic credentials. The isolated child environment adds only the temporary CA path as `SSL_CERT_FILE` for both arms so verification remains enabled.

The self-signed loopback CA and private key are generated through a bounded argv-only OpenSSL call outside the traced CLI process. They are stored in a private temporary directory, excluded from the JSON summary, and removed during cleanup. The receipt includes the public CA hash, actual diagnostic checkout head/script hash, installed runtime/module provenance, and bounded syscall/payload summaries; it retains no raw request or response body, key, certificate, or raw trace.

The reported difference is a single synthetic observation of TLS plus local certificate-verification overhead under this exact harness and runner. It cannot establish production HTTPS parity, model quality, absence of all external effects, or the cause of a separate live/provider trace failure. If either arm is incomplete, the output is `INCOMPLETE`; there is no TLS retry, third arm, trace-cap increase, or reduced workload.
