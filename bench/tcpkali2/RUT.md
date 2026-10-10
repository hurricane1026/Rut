# tcpkali2 for Rut benchmarks

Vendored from https://github.com/limpo1989/tcpkali2 at commit
`e70f077ab642426088ad2383d78d906d9bb792a0` (version 0.4.0).
Upstream source remains licensed under Apache-2.0; see [LICENSE](LICENSE).
Rut modifications in this directory are also licensed under Apache-2.0.
Original attribution and the upstream README are retained. Upstream contains
no NOTICE file at this revision.

This optional, standalone load generator is not linked into Rut and is not
part of its default CMake build. Cargo dependencies are pinned in Cargo.lock;
their sources and compiled binaries are not vendored here.

## Changes

- `command.rs`, `utils.rs`: read binary message files without silently replacing
  invalid UTF-8 with a default payload; preserve explicit message precedence.
- `stats.rs`: opt-in full response latency sampling and payload verification flags.
- `websocket_worker.rs`: verify binary echoes and count unexpected EOF as an error
  in ping-pong mode; tests cover corrupted echoes.
- `main.rs`: report benchmark sampling and verification settings.
- `csv_export.rs`: export sampling count, shift and verification setting.

## Build and test

Rust 1.88 or newer is required (upstream requirement). From the Rut repository:

```sh
cargo test --locked --manifest-path bench/tcpkali2/Cargo.toml
cargo build --release --locked --manifest-path bench/tcpkali2/Cargo.toml
```

The executable is `bench/tcpkali2/target/release/tcpkali2`.
For the verified plaintext WebSocket benchmark mode:

```sh
TCPKALI2_BENCH_FULL_LATENCY=1 TCPKALI2_BENCH_VERIFY=1 \
  bench/tcpkali2/target/release/tcpkali2 \
  --websocket ws://127.0.0.1:8080/ws --workers 3 --connections 192 \
  --warmup 2s --duration 8s --message-size 65536 -q --output result.csv
```

Verification is supported for WebSocket ping-pong only; do not use `--pipeline`
for verified results. Without the environment flags, upstream sampling defaults
remain. These results measure closed-loop RTT, including client frame preparation;
they do not establish fixed-arrival-rate tail latency. This build does not enable
TLS features. Run nginx and Rut serially with identical client and origin settings.

When distributing a compiled binary, review the included Cargo dependencies'
licenses and provide their required notices as well.
