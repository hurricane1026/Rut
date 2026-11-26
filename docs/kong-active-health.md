# Active HTTP and TCP upstream health checks

Rut supports periodic active probes with shard-local ejection and recovery,
following the documented HTTP/TCP distinction in
[Kong's health-check contract](https://developer.konghq.com/gateway/traffic-control/health-checks-circuit-breakers/).
It adds no plugin language, keyword or dependency.

```swift
upstream api {
    backends: ["127.0.0.1:9001": 3, "127.0.0.1:9002": 1]
    minimum_healthy_weight_percent: 50
    health_check: {
        path: "/healthz", interval: 1s, status: 200, timeout: 2s,
        failure_threshold: 3, success_threshold: 2
    }
}
route GET "/" { return forward(api, load_balance: .roundRobin) }
```

## Probe modes

- HTTP is the default, optionally spelled `type: .http`. Linux epoll and io_uring
  send an HTTP/1.1 GET to the configured path and compare complete response
  headers against the configured expected status or healthy status set. HTTP/1 TLS upstreams use the configured
  CA and server name for the handshake before sending the probe. The path must be origin-form and cannot inject request-line bytes.
- `type: .tcp` requires an interval and forbids both `path` and `status`.
  A successful TCP connect counts as success; failure or deadline expiry counts
  as failure. It sends no application bytes and immediately closes the socket.
  TCP mode supports plaintext, TLS and HTTP/2/gRPC origin declarations. It does
  not verify certificates, negotiate TLS/ALPN, or call gRPC Health Checking.
  Business TLS connections retain their original trust and identity checks.
- Consecutive `failure_threshold` / `success_threshold` values (1–255, default 1)
  eject and restore a target; an opposite result resets the streak. Business
  connect success cannot clear an active ejection.
- The optional timeout is an exact whole-second duration, 1–60 seconds.
  `1000ms` and `1m` are accepted; zero, fractional seconds, duplicate fields,
  unsupported modes and overflowing durations reject. Omission retains the host
  loop's upstream timeout, normally 30 seconds. The one-second wheel dispatches
  expiration within the following tick; progress does not extend the deadline.

```swift
upstream greeter {
    host: "127.0.0.1", port: 50051, protocol: .http2
    health_check: { type: .tcp, interval: 1s, timeout: 2s }
}
```

## Ownership and resource limits

Each shard/target owns at most one in-flight probe, including cancellation drain.
`health_check: { ..., concurrency: 1 }` optionally limits an upstream to 1–8
in-flight probes per shard, also counting cancellation drain. Deferred targets
remain due and rotate fairly; other upstreams can still issue probes. Omission
retains existing scheduling. This shard-local bound and its default differ from
[Kong 3.9.1](https://github.com/Kong/kong/blob/3.9.1/kong/db/schema/entities/upstreams.lua).
Zero-weight targets receive neither probes nor business traffic. A sweep issues
at most 32 probes, retains 64 free connection slots for business traffic and, on
io_uring, reserves 16 SQ entries. Resource/submission failures are local errors,
not evidence that the target is unhealthy.

Connect addresses live in connection-owned storage; the kernel never borrows a
reloadable configuration's sockaddr. The launch-owned TCP/HTTP flag survives
configuration retirement. TCP probes allocate no HTTP response receive slice and
bypass automatic TLS setup without changing business TLS admission. Both modes
use the same close/cancellation ledger; target/cancel completions must drain
before releasing slots, buffers or the in-flight guard. Probes do not increment
client connection or request metrics.

Reload resets health and schedules fresh deadlines. Results must match both the
configuration pointer and its identity, including replacement at the same
address. Drain starts no probes; force-close and shutdown cancel existing ones.

`minimum_healthy_weight_percent` defaults to 0, preserving all-unhealthy fail-open
selection. Positive values count active and passive health over enabled weights
and reject new forwarding/explicit upstream connections with 503 below the floor.
Health remains shard-local. This is a bounded data-plane contract, not complete
Kong health schema or control-plane compatibility. Application-level HTTP/2 and gRPC probes and cross-shard health synchronization
remain outside this implementation. An optional `unhealthy_interval` sets a
separate cadence for latched unhealthy targets.

## Verification

```bash
cmake --build build --target test_health_probes rut test_frontend test_native_program
ctest --test-dir build -R '^test_(health_probes|active_health_|tcp_health_)' --output-on-failure
```

The dedicated C++ probe suite uses real loopback sockets and both Linux backends
for HTTP/TCP failure/recovery, explicit timeout, late-connect cancellation,
force-close, zero weight, slot reserve, generation replacement, SQ-pressure cancel
retry, and asynchronous addresses after configuration destruction. The public
configuration API also rejects invalid combinations and deadlines. Frontend and
native-program cases verify syntax, metadata propagation and activation after
source removal.

`test_tcp_health.py` observes TCP EOF with zero bytes at HTTP/2 and TLS target
ports, disabled targets, ejection before any business traffic, the healthy-weight
floor and recovery. Existing HTTP live tests remain registered independently.
macOS execution, production soak/throughput and a live Kong comparison are not
claimed by these checks.

Native artifact ABI 36 carries the concurrency bound. Old artifacts must be
rebuilt; the source/configuration fingerprint additionally prevents mixing
compiler and server builds from different source trees.
