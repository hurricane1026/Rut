# Rut nginx/BoringSSL acceptance archive — 2026-09-24

Performance gate: **FAIL**. The raw measurements are complete and valid, but 33 of 96 cells were below the configured Rut/nginx 1.10 ratio; 63 cells passed. There were 576 raw samples, three repeats per cell, with HTTP and HTTPS, four body sizes (16, 1,024, 65,536, and 1,048,576 bytes), four scenarios (static-close, static-keepalive, proxy-close, proxy-keepalive), and concurrency 1, 32, and 128. Each accepted sample ran for at least five seconds with zero reported errors.

The measured production source and binaries are from commit `e2866fe02a0d921be6e24a6eb1ccc768c492441c`. `bd362f8813a33c009ffa793aba5c4612d3de035d` is its descendant containing only the test-helper formatting change; it is the archive checkout base. The independent check-only verification reported 96 cells, 576 raw samples, no problems, and four matching provenance hashes. `e2866fe` is an ancestor of the current head.

Hardware, operating system, CPU pinning, and Docker/network details are retained as measurement context in `environment.json`, `command.json`, `provenance.json`, `wall-time.json`, and the per-cell evidence archive. They are context only, not tuning claims.

The prior BoringSSL native-body archive is preserved at [`docs/benchmarks/nginx-runtime-acceptance-boringssl-2026-09-23/`](../nginx-runtime-acceptance-boringssl-2026-09-23/). The converter-return archive is preserved separately at [`docs/benchmarks/nginx-acceptance-2026-09-23/`](../nginx-acceptance-2026-09-23/). This archive does not overwrite either one. The included certificate is public only; the compressed BoringSSL handshake patch is included for provenance. No private key is included.

The matrix runner returned exit code 2 because the performance gate failed. The verifier archive/check-only run returned exit code 0.
