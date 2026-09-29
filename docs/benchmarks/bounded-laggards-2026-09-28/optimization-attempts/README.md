# Buffer reclamation optimization experiments

Follow-up to the initial investigation, 2026-09-28. Three implementations were
built and measured against the same final #726 baseline. All three were
reverted; only experiment artifacts remain. No runtime optimization was
committed or pushed.

## Implementations

- **bulk128:** reduce the bulk allocation size from 256 KiB to 128 KiB.
  This reduces the idle cache byte limit as well as the allocation size.
- **bulk512:** increase the bulk allocation size to 512 KiB and reduce the
  cached count from 64 to 32, retaining the 16 MiB idle cache limit.
  This experimental patch doubles the maximum virtual reservation to 2 GiB;
  it is not a finalized pool sizing change. Larger nodes also change the
  receive granularity and maximum read-ahead overshoot.
- **incremental-zero:** preserve 256 KiB nodes but clear each consumed bulk
  body range after send completion. Release clears only the remaining body
  suffix and node header, then returns the fully zeroed node. No clearing is
  removed; in-flight direct receives address the uncommitted tail beyond len.
  This is experimental code, not a verified asynchronous-lifetime change.

## Results

The first 1 MiB comparison against baseline-r1 measured:

| Variant | Close c32 RPS delta | Close c128 RPS delta |
|---|---:|---:|
| 128 KiB bulk | -5.65% | -7.52% |
| 512 KiB bulk | +2.26% | +2.37% |
| Incremental clearing | -0.99% | -3.74% |

The 512 KiB result is provisional: baseline-to-candidate CPU time rose from
346.5 to 350.6 us/request at c32 and from 408.4 to 412.9 at c128.
The contemporaneous nginx control also sped up (2320.6 to 2351.8 RPS at c32;
2304.0 to 2334.0 at c128), so its Rut/nginx improvement is about 1%, smaller
than the raw Rut RPS gain.

A fresh baseline plus 512 KiB confirmation at 64 KiB measured -0.46% close/c1
and -1.38% keepalive/c1. These small differences are not a statistical claim.
The subsequent 1 MiB confirmation was contaminated by external compilation
and is excluded from performance conclusions. Concurrent clang++/clang-format
processes were observed; compiler cwd was
`/home/hurricane/private/code/rut_enovy/build`. Both nginx and Rut slowed.
Those external tasks subsequently began running tests. No external process
was stopped or modified, and no quiet confirmation could be obtained during
this investigation. The contaminated rows remain in the evidence.

## Decision and validation

No candidate established a sufficiently reliable overall improvement to
retain a production change. Smaller allocations and incremental clearing
regressed in these measurements. 512 KiB remains a candidate for a quiet,
reversed-order confirmation and broader HTTP/TLS and memory validation.
This investigation does not establish that buffer reclamation cannot be
optimized, or that changing buffer size alone closes the nginx gap.

All three candidates compiled successfully. All completed benchmark response
preflights passed and all recorded warmup/measured error counters were zero.
Network/integration suites were not run for these discarded candidates.
Runtime source was restored to the baseline; draft changes were preserved as
patches with binary SHA-256 provenance. No glibc settings were changed.
The build-rel runtime executable was also restored from the baseline snapshot.
Every measured binary remains separately snapshotted in the evidence directory.

See samples.json and summary.json for all repeated measurements; the original
report documents hardware, CPU pinning, engine order, and benchmark controls.
Raw commands, logs, configurations and binaries remain in
`/tmp/rut-bounded-followup-20260928`.
