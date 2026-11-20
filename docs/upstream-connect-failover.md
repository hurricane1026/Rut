# Upstream connect failover

HTTP/1 forwarding and HTTP/2 downstream streams forwarding to HTTP/1 origins
use the same bounded connect failover policy on Linux epoll and io_uring.
A failed TCP connect can try another eligible endpoint before any application
request bytes are sent. The total budget is `min(endpoint_count, 3)`, including
the initial attempt. Each endpoint can be attempted at most once per request.

```swift
upstream api {
    backends: ["127.0.0.1:9001": 1, "127.0.0.1:9002": 3]
}
route POST "/jobs" {
    return forward(api, load_balance: .roundRobin,
        target_transform: { strip_prefix: "/", replace_prefix: "/", mode: .rawPrefix })
}
```

The retry uses the original forward site's policy, including its owned digest
for `.consistentHash`. It excludes attempted and zero-weight endpoints, applies
existing health selection and the minimum healthy weight floor, and retains the
original request bytes. Consistent hashing reselects over the remaining eligible
endpoints; it does not change the request's key. A POST is safe to switch after
a refused connection because no application bytes have reached that endpoint.
HTTP/2 request bodies still require an existing buffered forwarding profile,
such as the identity `.rawPrefix` transform above; this change does not enable
body forwarding on legacy unbuffered routes. The existing 16 KiB synthesized
request bound applies.

The HTTP/2 stream keeps its configuration epoch, synthesized request and upstream
admission slot throughout retries. Each failed endpoint releases its active gauge
and socket before the next is selected. The new endpoint's gauge belongs to the
same pinned configuration, even when the connection's HTTP/1 request-config slot
is empty. A configuration replacement stops HTTP/2 failover for that retired
snapshot. Normal event dispatch rejects stale upstream episode completions.

Exhaustion returns the existing framed HTTP 502 response. No new retry is started
for cancellation, a local completion submission error, or a stream whose request
send or response has started. Allocation or submission failure terminates with
502 and releases the socket and gauges. A configured healthy-capacity floor may
prevent selection; failover does not bypass it.

This is connect-establishment failover only. It does not retry HTTP statuses,
response resets, timeouts, or failed/partial request sends. It does not add
configurable retry counts, backoff, TLS handshake retries, or native HTTP/2/gRPC
origin retries. The separate existing HTTP/1 pooled-socket replay policy remains
restricted to its existing idempotency and buffering checks.

## Validation

`test_h2_failover` exercises callback ownership, distinct endpoints, the three
attempt limit, disabled targets, request preservation, backend gauges, retired
configuration rejection, cancellation and local/submission failure. The live
`test_h2_failover_epoll` and `test_h2_failover_io_uring` cases use bound,
non-listening sockets to force refusal, and real origins to check weighted
round-robin, least-requests, consistent hashing, multiple streams on one
connection, POST body delivery exactly once, budget exhaustion, no response-error
replay and HTTP/1 regression behavior.
