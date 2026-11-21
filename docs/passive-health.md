# Passive HTTP upstream health

This implementation adds explicit, bounded passive health policies to HTTP/1
origins. It complements weighted balancing, consistent hashing, active probes
and the healthy-weight capacity floor. The source contract is in the
[language card](language-card.md#passive-http-upstream-health-checks).

## Compatibility

[Kong's health-check contract](https://developer.konghq.com/gateway/traffic-control/health-checks-circuit-breakers/)
separates connection failures, timeouts, unhealthy HTTP statuses and healthy HTTP
statuses. A healthy response resets failure counters; failures in distinct
categories do not reset one another. Passive checks do not probe or automatically
restore an unhealthy target. Rut implements those properties with shard-owned
fixed-size counters and final-status bit sets.

This is behavior compatibility for the documented subset, not Kong configuration
import or complete Kong health-check parity. Rut's thresholds are explicitly
configured (0–255), its status universe is 200–599, and its pre-existing default
all-unhealthy behavior is fail-open. Set `minimum_healthy_weight_percent` above
zero to reject when healthy capacity is exhausted. Native gRPC upstreams reject
this policy. Health is per shard, not shared across workers or machines. HTTP
status evaluation does not wait for a complete response body, and the option does
not add retry-on-status or retry budgets.

## Ownership and lifecycle

The compiler validates all six fields, duplicate and overlapping status entries,
integer bounds, and unsupported protocol combinations. Seven 64-bit words cover
400 final statuses; no request-owned string or source view survives into policy
configuration. The policy travels through every IR and into the owned runtime
configuration. Both source-to-config and native artifact loading validate it;
native ABI 24 rejects older artifacts.

Connect success is neutral for explicit policies, so a successful TCP handshake
cannot erase preceding HTTP failures. A connection timeout counts only in the
timeout category. Final response observations use the connection's monotonic
upstream episode token to count once, even when parsers reread buffered headers.
A separate token deduplicates timeout observations. Fresh connect submission and idle-pool borrowing clear the observation markers:
io_uring pooling can retain the same I/O episode across requests. The markers do
not acquire I/O or timer ownership.

All health state remains shard-local. The existing configuration adoption reset
clears counters and verdicts. Pinned old responses are ignored when the current
or pinned configuration enables passive health. Active recovery clears a passive
verdict only when the configured active success streak is complete. Passive
successes clear failure counters but do not clear a latched verdict.

Omitting the option keeps legacy connection-only ejection. The policy does not
alter current upstream callback transitions, cancellation, connection pooling,
response bodies, or response forwarding/retry decisions.

## Verification

- Frontend tests cover explicit and addressless declarations, thresholds, required
  fields, status bounds, duplicates, overlap, overflow, and HTTP/2 rejection.
- Native-program tests compile, unlink source, activate, and inspect the policy.
- Network tests exercise independent categories, zero thresholds, saturation,
  capacity weighting, once-per-episode accounting, stale config rejection,
  active recovery, reload reset, and retired-attempt timeout rejection.
- `test_passive_health.py` uses real origin sockets and the gateway on epoll and
  io_uring. It checks HTTP/1 and HTTP/2 clients, all three balancing policies,
  repeated failures around neutral/success statuses, large/informational replies,
  connect refusal thresholds, healthy-peer failover, and active-probe recovery. It compares origin
  contact counts as well as client status, so a locally generated 503 cannot be
  mistaken for a forwarded 503.

The live suite does not claim native gRPC, cross-shard health synchronization,
production load/soak performance or live timeout/reload race coverage. Focused
network tests cover timeout and generation bookkeeping without wall-clock sleeps.

See [the runnable configuration](../examples/passive-health.rut).
