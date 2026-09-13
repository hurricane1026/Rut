# Connection lifecycle correctness follow-up to #644

This is correctness evidence for the stacked runtime fix, not a performance
comparison. The original 72-group record in `../nginx-2026-09-13/` remains
unchanged: its timeout counters were zero, while RUT reported premature EOF /
read failures. Do not label those failures as measured timeouts.

## Fixes

1. A sequential client's next request could arrive after the kernel sent the
   response but before userspace dispatched its Send completion. Eager CQ
   harvesting copied that receive into the old request, and strict admission
   then rejected it as pipelining. Stop harvesting before that receive and
   dispatch the earlier send first. The same boundary separates a following
   FIN from a completed-body deadline batch. Active tagged deadlines and the
   prebuilt header/retirement rendezvous retain whole-batch arbitration;
   receive-before-send remains a real pipelined arrival.
2. After a client disconnected during a send, its close target/cancel ledger
   could drain while the backend proactor still retained unsent bytes. A new
   connection on the same slot then failed strict upstream retirement because
   those bytes appeared to belong to a live send. Reset both backend send
   proactors when allocating a fully reclaimed slot. No live operation or
   generation fence is cleared early.

Temporary diagnostics identified the second rejection at the
`downstream_send.remaining != 0` retirement guard (1024 stale bytes), not a
response timer expiry. Broadly weakening retirement or deadline validation
was unnecessary and is not part of the fix.

## Reproduction and scope

Build the source recorded in `build-provenance.json` with Clang, Release,
`RUT_ENABLE_JIT=ON`, `RUT_ENABLE_IPO=OFF`. Then run from the repository root:

```sh
python3 scripts/nginx_benchmark/run.py \
  --rut /path/to/build/src/rut \
  --converter /path/to/build/src/rut-nginx-convert --wrk /path/to/wrk \
  --output /tmp/rut-lifecycle-matrix \
  --server-cpu 2 --origin-cpu 3 --client-cpus 4,5 \
  --concurrency 1 32 128 --duration 3 --warmup 1 --repeats 1 \
  --keepalive-header implicit
```

Use available distinct physical cores. The origin is pinned nginx with a
1024-byte response; the frontend configuration is converted by the standalone
converter and its stdout is the RUT program. Every frontend startup validates
100 exact, Date-normalized responses, including 100 requests on one socket for
keepalive. Both measured and warmup counters gate validity.

`implicit` means HTTP/1.1 default persistence, with no Connection header. The
original explicit `Connection: keep-alive` proxy request remains outside the
bounded admitted profile. The harness default is still `explicit`; this fix
adds an opt-in profile and consistently applies it to all three clients. An
implicit-profile pass does not prove explicit keep-alive compatibility or
expand the nginx compatibility matrix. Close requests always retain their
explicit `Connection: close` header.

## Verification

- `matrix-results.json`: final production code, 24/24 groups valid (two engines,
  four scenarios, concurrency 1/32/128); all warmup and measured connect/read/
  write/status/timeout counters zero. `matrix-status.json` confirms cleanup and
  completion. No throughput ratio is asserted; compilation also ran on this
  machine during some checks.
- `independent-results.json`: eight engine/scenario checks pass after a wrk burst;
  the independent asyncio client verifies 276,000 complete RUT responses with
  exact bodies and expected EOF/persistence, with no exception. Reproduce with
  the same command plus `--mode diagnose --concurrency 32 --duration 5 --warmup 2`.
- `explicit-results.json` and `explicit-preflight-failure.log`: static explicit
  keepalive passes for both engines at concurrency 32; the proxy's explicit
  keepalive RUT preflight fails with EOF before headers, as expected for the
  unsupported shape. Its incomplete/invalid status is preserved separately.
- `regressions-fixed.log`: seven focused tests, 137 checks, no failures. Five
  raw-CQ tests cover the new receive boundary and negative controls. The
  existing prebuilt composition test preserves whole-batch behavior. The
  close-ledger test now checks both cancellation orders through slot reuse and
  the actual strict retirement gate.
- `receive-baseline-failures.log`: the five new raw-CQ tests against the old
  backend fail three receive-boundary cases; two negative controls pass.
- `reuse-baseline-failure.log`: the extended close-ledger test with the parent
  allocator fails at strict retirement on the successor. Restoring the fix
  passes both cancellation orders. Filter-excluded tests in these focused logs
  are not environment skips.
- Full Release network suite: **1238 passed, 0 failed, 143587 checks, zero
  skips**. The complete local log hash and test-binary hash are retained in
  `build-provenance.json`.
- `harness-tests.log`: eight tool tests pass. Runtime-state structural checks
  and TLC pass (221 distinct states, no remaining states).

`matrix-environment.json` was captured before the source commit; its parent
harness HEAD does not identify the runtime binary. `build-provenance.json`
records the committed production/test source hashes and the final binary
hashes. Earlier exploratory artifacts remain locally under
`/tmp/rut-lifecycle-debug`; the original public failed benchmark is preserved
in #644 and its historical directory.
