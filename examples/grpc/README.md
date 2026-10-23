# Native gRPC through Rut

Run these commands from the repository root on Linux. The example uses a
standard Python gRPC backend and client to exercise unary, server-streaming,
client-streaming and bidirectional calls through [grpc.rut](../grpc.rut).
The unary call exceeds the initial HTTP/2 window; the interactive chat waits
for each response before sending its next request. Binary metadata and response
trailers are checked too.

```text
Python gRPC client → Rut :50052 → Python gRPC backend :50051
                    h2c          pooled h2c
```

## Setup

Build Rut with its normal JIT-enabled configuration (`./dev.sh build`). Python
3.10+ with `venv`/`pip` is needed only for this example. The SDK supplies standard
protobuf serialization and gRPC stubs; it is isolated from Rut's runtime and
build dependencies. Generated files are ignored by Git.

```bash
python3 -m venv examples/grpc/.venv
examples/grpc/.venv/bin/python -m pip install -r examples/grpc/requirements.txt
examples/grpc/.venv/bin/python -m grpc_tools.protoc \
  -I examples/grpc --python_out=examples/grpc --grpc_python_out=examples/grpc \
  examples/grpc/echo.proto
```

## Run

Start the backend in one terminal:

```bash
examples/grpc/.venv/bin/python examples/grpc/server.py
```

Start the gateway in a second terminal. One shard keeps the demo small and
avoids depending on CPU affinity or a large locked-memory limit:

```bash
build/src/rut 50052 examples/grpc.rut --shards 1 --no-pin
```

Run the client in a third terminal:

```bash
examples/grpc/.venv/bin/python examples/grpc/client.py
```

All four calls should print `OK`. To compare with the backend directly, use
`--target 127.0.0.1:50051`. Stop the gateway and backend with Ctrl-C.

`protocol: .http2` selects a prior-knowledge h2c upstream by default. `forward(echo)` routes
by the ordinary `/package.Service/Method` path; Rut neither loads the proto nor
decodes messages. Streaming and compressed payloads stay opaque. HTTP/2
multiplexing and pooling do not require TLS.

## Optional downstream TLS

Stop the plaintext gateway, then start it with the repository's **local test**
certificate and HTTP/2 ALPN enabled:

```bash
build/src/rut 50052 examples/grpc.rut --shards 1 --no-pin --h2 \
  --tls-cert tests/fixtures/localhost_cert.pem \
  --tls-key tests/fixtures/localhost_key.pem
examples/grpc/.venv/bin/python examples/grpc/client.py \
  --target localhost:50052 --ca tests/fixtures/localhost_cert.pem
```

The listener is selected on the CLI; the shared route file deliberately omits a
source `listen` declaration (which selects cleartext transport).

The backend command stays the same: Rut terminates TLS and forwards over h2c.
Use your own certificate and key for deployment. JSON transcoding and gRPC
health probes are outside this implementation.
Body-reading middleware and HTTP/1-specific forwarding policies are not
supported on this streaming path.

The C++ integration test (`build/tests/test_grpc_proxy`) additionally checks
multiplexing across clients, stalled response windows, cancellation, deadlines,
upstream failures/reconnection and graceful GOAWAY, on epoll and io_uring with
both plaintext and TLS downstreams. It uses the repository's existing test-only
nghttp2 reference library and does not need the Python packages.

## Upstream TLS/mTLS

To connect to a backend offering TLS with h2 ALPN, add this field inside the
upstream declaration in `grpc.rut` (and change its port to the backend TLS port):

```swift
tls: {
    ca: "/certs/ca.pem"
    server_name: "backend.example.com"
    cert: "/certs/client.pem"
    key: "/certs/client.key"
}
```

`ca` and `server_name` are required; `cert` and `key` are optional as a pair for
mTLS. The explicit CA and server identity are always verified, and h2 ALPN is
required. DNS server names also send SNI. The Python example backend remains
plaintext; point this configuration at your own TLS backend. Paths are resolved
from the gateway working directory. Files are loaded when each new upstream
session is established; pooled sessions retain their TLS context until close.
TLS failures return gRPC UNAVAILABLE and calls are never automatically replayed.
The integration suite tests TLS/mTLS pooling and streaming on both I/O backends,
including failure cases for identity, trust, ALPN and client credentials.

## RPC telemetry

The existing metrics endpoint exports `rut_grpc_started_total`,
`rut_grpc_active`, `rut_grpc_completed_total{grpc_status="..."}` and
`rut_grpc_duration_seconds`. Counters cover admitted RPCs, including cancellation,
deadline expiry and upstream failure; they are separate from HTTP request
counters. Status labels are bounded to 0–16, avoiding method-label cardinality.

When the existing access log is enabled, each admitted RPC produces an entry
with its `/package.Service/Method` path, request/response DATA byte counts,
lifetime and `grpc_status=...` alongside HTTP status 200. Byte counts include
gRPC framing but exclude HTTP/2 framing. Completion means final response staging
into owned output, not client delivery acknowledgement. Client disconnects
before completion are CANCELLED. Long paths use the existing over-limit marker.
The source live-log bytes-only writer keeps its existing output format.

Native gRPC upstream sessions with active RPCs send an HTTP/2 PING every five
minutes after connection establishment or the previous probe. Only an ACK with
the same eight-byte payload completes a probe. The existing upstream timeout
(in seconds, checked by the one-second session timer) bounds the ACK wait;
timeout closes the session and fails unfinished RPCs with UNAVAILABLE without
replay. Idle pooled sessions, handshakes and GOAWAY-draining sessions do not
start probes. PING does not implement the protobuf gRPC Health service.

To bound individual messages without loading a proto, set
`max_request_message_bytes: 1048576` and/or
`max_response_message_bytes: 4194304` on the `.http2` upstream. Values must be
positive 32-bit integers; omitted directions retain opaque forwarding. Limits
count payload wire bytes per message (compressed bytes when compressed), not
whole-stream totals or decompressed size. Oversize fails the RPC with status 8;
malformed or truncated gRPC envelopes fail with status 13. No protobuf fields
are decoded and no replay occurs.

## Browser gRPC-Web example

The same opaque messages can use binary or base64-text gRPC-Web through
[grpc-web.rut](../grpc-web.rut). Run the Python backend from the setup above,
then start Rut with that route file:

```bash
build/src/rut 50052 examples/grpc-web.rut --shards 1 --no-pin
```

Serve the browser client in another terminal:

```bash
python3 -m http.server 8080 --bind 127.0.0.1 --directory examples/grpc
```

Open <http://127.0.0.1:8080/web_client.html>. The default hex bytes encode the
example protobuf message with text `hello`. Select binary or text, then send.
The page displays each response message as hex and the final inline trailers.
Change the RPC URL to `/example.Echo/ServerStream` to see streamed responses;
Cancel aborts the fetch. The page is a wire-format example, not a generated
protobuf client. A typed application can generate its own gRPC-Web SDK from
`echo.proto`; Rut still does not load that file.

The example explicitly allows only the demo origin `http://127.0.0.1:8080`.
Change both the preflight route and response headers for your application's
origin and request headers. CORS is configured through ordinary routes and
response middleware; the gateway does not automatically reflect origins.
The HTTP/1.1 bridge closes its downstream connection after each response.


## Local unary RPC

The endpoint in `examples/grpc-local.rut` handles a native unary RPC locally:
it uses `grpc.decode` and `grpc.encode` bound to the proto declaration
`/example.BatchEcho/Unary` to decode the request and encode the response, then
returns grpc-status trailers. The route remains explicit. No backend or generated
stubs are needed.
Using the existing pinned Python development requirements, run:

```sh
build/src/rut 50052 examples/grpc-local.rut --backend epoll --shards 1 --no-pin
python examples/grpc/local_client.py 127.0.0.1:50052
```

The generic grpcio client sends raw protobuf; grpcio handles the wire envelopes.
It checks a successful echo, INTERNAL for malformed protobuf, and a subsequent
successful call on the same channel. For io_uring use `--backend io_uring` on a
supported Linux host. This example supports one uncompressed message up to 8 KiB;
it does not implement local deadline scheduling or streaming message handlers.

## Local standard health Check

[grpc-health.rut](../grpc-health.rut) serves the standard unary
`/grpc.health.v1.Health/Check` method directly in Rut. It decodes the standard
request with the built-in protobuf compiler and encodes a typed response; no
Python backend, generated bindings, or additional runtime dependency is needed.
The empty service and `grpc.health.v1.Health` return `SERVING`. The legacy
`example.BatchEcho` name and other unknown services return gRPC `NOT_FOUND` (5);
malformed protobuf returns `INVALID_ARGUMENT` (3).
This is a static readiness example: replace its policy with your application's
readiness decision before deploying it. It does not implement streaming `Watch`
or a dynamic service registry.

From the repository root, start a listener and use the existing optional SDK:

```bash
build/src/rut 50052 examples/grpc-health.rut --backend epoll --shards 1 --no-pin --h2
examples/grpc/.venv/bin/python examples/grpc/health_client.py
```

The client checks the empty and advertised service names, rejects the legacy
`example.BatchEcho` name and other unknown or malformed requests, and makes a
successful call after failures on the same channel. For TLS,
use the listener certificate/key arguments from above and run the client with
`--target localhost:50052 --ca tests/fixtures/localhost_cert.pem`.
The source schema includes the unary subset of the standard health protocol;
ordinary generated Health `Check` stubs interoperate with the same wire format.
This local service is separate from upstream `health_check` probing.
