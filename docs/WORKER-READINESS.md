# Worker readiness wait and Linux comparison

The review controller now waits for worker readiness instead of repeatedly polling idle child processes. A child is watched through its result pipe and process sentinel; multiple workers are waited together, with the wait bounded by the nearest child or run deadline. After wake-up, the controller processes ready results before classifying a deadline, then uses the existing isolated-process cleanup path for cancellation and exit. Timeout inputs must be finite and nonnegative. This follows Python's documented [`multiprocessing.connection.wait`](https://docs.python.org/3/library/multiprocessing.html#multiprocessing.connection.wait) interface for waiting on connections and process sentinels.

A local four-worker, two-second fake measured 636 readiness polls before the change and 12 after it (about 2.10 seconds in each run). This is a poll-count observation only: it does not establish Linux syscall-byte reduction, provider behavior, review quality, or target safety.

## Bounded Linux probe

The dedicated `scripts/effect_observer_long_wait_smoke.py` probe invokes the installed CLI against the same fixed synthetic four-lens review fixture. Its loopback fake delays successful responses by 75 seconds. The bounded settings are:

| Setting | Long probe | Existing short smoke |
|---|---:|---:|
| Fake response delay | 75 s | 0 s |
| Provider timeout | 120 s | 5 s |
| Engine deadline | 150 s | 20 s |
| Observer timeout | 180 s | 30 s |
| Provider-call ceiling | 8 | 8 |
| Retries | 0 | 0 |
| Trace byte ceiling | 1 MiB | 1 MiB |

The probe keeps the existing observer syscall scope and review input/output limits. The CLI checks its inert target-execution marker; the fixture does not request external provider dispatch and uses no provider credentials. A successful run demonstrates only that this synthetic installed-CLI path completes under the measured trace cap. A failed run retains bounded status, partial event counters, and observer identity when available; partial aggregates are labeled partial.

Run it from any working directory using the Python environment for the installed wheel and its CLI path:

```sh
cd /tmp
python3 /path/to/candidate-source/scripts/effect_observer_long_wait_smoke.py \
  --cli /path/to/installed-venv/bin/pr-review
```

The script loads the observer helper and fixture from the script's source tree, while `--cli` selects the installed runtime being exercised. In the comparison workflow, baseline `94d35b43d6441e412e3c6123d354c5e78d6c12e9` and the candidate PR head are built and installed into separate environments. Before either probe, the workflow compares the complete 28-module source inventory with the corresponding installed wheel inventory. Only after both identities match does it run the same fixture and bounds against each CLI.

The [PR44 Linux comparison](https://github.com/groktopus/codereview/pull/44) completed in [workflow run 36320521501](https://github.com/groktopus/codereview/actions/runs/36320521501). It verified 28 source modules against 28 installed-wheel modules for both baseline `94d35b43d6441e412e3c6123d354c5e78d6c12e9` and candidate `e5e4d301808db0154270ba346cf9cbf8cdbe8191`, using the same fixture, syscall scope, and 1 MiB trace cap. The baseline reached a typed trace-cap failure at 1,048,543 bytes after 13.992 seconds. The candidate completed four tasks and four fake-provider calls, using 708,834 trace bytes in 76.617 seconds. The selected provider-trial workflow now pins `54b8fb5e8bb3b1ac8681dff1d0ff7143b7318215`; that runtime change has not been exercised by a provider-trial dispatch.

This is bounded infrastructure evidence for the synthetic long-wait fixture. It is not provider-quality evidence, a live-provider result, or release approval; the other historical cases were not exercised by this comparison.
