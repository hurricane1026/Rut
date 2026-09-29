# Pinned nginx comparison and optimization record (2026-09-29)

This record separates measured behavior, rejected experiments, and remaining
work. The comparison uses a frozen Rut executable (SHA256
`f194e0a912c8a5162317a25b95cd4107ebdfdd3f90b7e71b5682828dd2ffdea0`),
converter (`2e19980ca539377c968bed8347d6b9dcf1907debbf8b5437d469a94c0de5659f`),
wrk (`d7866c40dcb47f67138cdc420c346272d06b7b5dfc2705161178c996b6e7cf30`),
and nginx image `nginx@sha256:1854da86e82d5dfb49a8f3d78b099adcc7e36608b207146ed95cd47937938a40`.
These hashes belong to the measurements, not to the benchmark-only PR head.
The Rut executable contains the byte-verified response-header parse cache
from research commit `96ebc026`; that runtime change is not in this PR.

## How the comparison was run

The single-worker matrix pinned the frontend to CPU 2, the nginx origin to CPU
3, and the client to CPUs 4 and 5. It covered HTTP and HTTPS, HTTP/1.1,
16 B / 1 KiB / 64 KiB / 1 MiB bodies, static close/keepalive and proxy
close/keepalive, and concurrency 1/32/128. Each coordinate had three repeats,
two-second warmup, and at least five seconds of measured load per engine.
Static used `native-body`; proxy used `converter-strict`. Response preflight
checked exact bodies. Every included sample had zero warmup/load errors.
nginx ran first twice and Rut first once. The last three HTTPS 1 MiB proxy
keepalive coordinates came from a separate completed run after an unrelated
compiler interrupted the original run; the interrupted samples were not
promoted to valid measurements. See [the 96-coordinate audit](single-worker-96-audit.json).

Of 96 valid coordinates, Rut had higher median throughput in **94** and met
the 1.05 Rut/nginx target in **84**. The two throughput losses were HTTP
64 KiB proxy close c1 (0.9880) and keepalive c1 (0.9865). A separate run
reversed the process order and confirmed the same direction: close **0.9901**,
keepalive **0.9802**, with valid samples and zero errors. See
[the reverse-order audit](single-worker-64k-reverse.json). Twelve coordinates
remain below the 1.05 target even though ten of those twelve are throughput
wins. The 96-coordinate result supports only the stated single-worker scope;
it does not establish a universal performance or correctness claim.

## Equal-CPU two-worker comparison

The benchmark tooling in this PR gives each frontend two workers on the same
CPU set, CPUs 2 and 6. The origin remains one nginx worker on CPU 3; the
client uses CPUs 4 and 5. This follow-up held the frozen Rut binary, converter,
wrk, and nginx image fixed. It measured 64 KiB converter-strict proxy
keepalive at c32 and c128, separately over HTTP and HTTPS, with three repeats,
two-second warmup, at least five measured seconds, exact-body preflight, and
zero warmup/load errors. All 12 engine/repeat/concurrency rows in each run
were valid. The summaries retain the per-engine medians; raw rows and
environment metadata are also included.

| Transport | Concurrency | Rut/nginx median RPS | Rut/nginx median p99 | Rut RSS | nginx RSS |
| --- | ---: | ---: | ---: | ---: | ---: |
| HTTP | 32 | 1.2458 | 0.6479 | 251 MB | 24 MB |
| HTTP | 128 | 1.2544 | 0.7884 | 260 MB | 25 MB |
| HTTPS | 32 | 1.3016 | 0.5648 | 254 MB | 35 MB |
| HTTPS | 128 | 1.3680 | 0.7759 | 266 MB | 39 MB |

See [HTTP audit](two-worker-http-audit.json), [HTTP rows](two-worker-http-results.json),
[HTTP environment](two-worker-http-environment.json), [HTTPS audit](two-worker-https-audit.json),
[HTTPS rows](two-worker-https-results.json), and
[HTTPS environment](two-worker-https-environment.json). The harness sums RSS
for the frontend parent and direct children; this is not proportional set size
and can double-count shared nginx pages. The single origin worker used roughly
62–79% CPU in HTTP and 46–61% CPU in HTTPS, depending on engine, so it was
not pegged at one full core in these runs. These are two concurrency points for
one payload/profile, not a general multi-worker result.

## Optimization decisions

The accepted response-header cache reuses a complete parse only after checking
the response bytes; the frozen binary includes it. The research branch also
tested a global request parser cache, a Bounded no-copy header prefix, and a
combined first header/body send. The focused controls did not establish a
repeatable throughput improvement on the lagging proxy coordinates, so those
candidates were rejected. Removing duplicate owner-policy validation had
previously helped close but hurt keepalive on an older baseline and was not
repeated without a new mechanism.

One later isolated candidate skipped a stash-specific proof whose result was
unused when the pipeline stash was empty. Independent review found no behavior
change; the complete network suite passed 1,460 tests and 391,497 checks.
It was rejected for performance: an interleaved candidate/baseline run gave
64 KiB close +1.71%, but the reversed-order run gave **-0.58%**, with both
adjacent pairs negative. The small 16 B and 64 KiB keepalive differences did
not establish a stable gain. See [both-order control](rejected-stash-guard-control.json).
The rejected commit `ad6c41c6` is retained on an isolated local research
branch; it is not in this PR or the frozen Rut binary.

The larger Rut RSS remains an open resource-efficiency issue. A read-only
code/ELF audit found a 3,664-byte `ConnectionBase` stride and 16,384 slots
per shard, about 57.25 MiB per shard. Initialization touches all slots;
provided buffers account for another 8 MiB per shard. Those facts explain a
substantial allocation, but no mapping-level PSS audit or safe lazy-commit
change has been validated. Lowering configured connection capacity would
change the workload contract and is not treated as a fix.

Remaining coverage includes other worker counts, connection levels, uploads,
HTTP/2, native streaming, the epoll backend, and a broader correctness audit.
In particular, an explicit first-response-deadline capability gate currently
closes some epoll Bounded cases; an io_uring pass does not prove epoll parity.
