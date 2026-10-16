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

`protocol: .http2` selects a prior-knowledge h2c upstream. `forward(echo)` routes
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
Use your own certificate and key for deployment. Upstream TLS/mTLS, gRPC-Web,
JSON transcoding and gRPC health probes are outside this implementation.
Body-reading middleware and HTTP/1-specific forwarding policies are not
supported on this streaming path.

The C++ integration test (`build/tests/test_grpc_proxy`) additionally checks
multiplexing across clients, stalled response windows, cancellation, deadlines,
upstream failures/reconnection and graceful GOAWAY, on epoll and io_uring with
both plaintext and TLS downstreams. It uses the repository's existing test-only
nghttp2 reference library and does not need the Python packages.
