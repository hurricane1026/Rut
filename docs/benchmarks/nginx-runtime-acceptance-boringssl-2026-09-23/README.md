# BoringSSL native-body full-96 acceptance — 2026-09-23

This is the canonical BoringSSL **native-body** acceptance archive for Rut source `12bd10e9e84a7f3a6df9af54a4c543416f470dfd` (PR source; base main was `f53401d7`). The source is reachable from `refs/heads/perf/quick-nginx-benchmark`; [verification.json](verification.json) records the independent ancestry and hash checks.

The raw evidence is complete and valid: **96/96 cells, 576/576 samples**, three repetitions per engine, every sample measured for at least 5 seconds, zero warmup/measurement errors, and all four recorded executable/patch hashes match. The performance gate is **FAIL**: **63 cells passed** the Rut/nginx median ratio target of 1.10, **33 were below target**, and **0 were invalid**. This is a measurement result, not an acceptance pass.

The complete coordinate and median table is [cells.csv](cells.csv). Independent raw recomputation and every cell's ratio check are in [verification.json](verification.json). Representative ratios include `https static-close / 1 MiB / c1 = 0.012053`, `http static-keepalive / 1 MiB / c1 = 0.006899`, and a passing `http static-close / 16 B / c32 = 1.316712`.

## Measurement conditions

- Workload: HTTP/HTTPS × static-close/static-keepalive/proxy-close/proxy-keepalive × 16/1024/65536/1048576-byte bodies × concurrency 1/32/128.
- Rut uses the canonical `native-body` profile; proxy cells use `converter-strict`. Older converter/native archives remain historical records and are not replaced by this archive.
- Rut and converter were built with clang 22.1.8, Release, `-O3 -DNDEBUG`. The measured nginx image is `nginx@sha256:1854da86e82d5dfb49a8f3d78b099adcc7e36608b207146ed95cd47937938a40` (version 1.29.7).
- HTTPS used [wrk-boringssl-full-handshake.patch.gz](wrk-boringssl-full-handshake.patch.gz), BoringSSL revision `7f5a43945aab78fe4e71459ac4881ff9033d73d8`, and the public [certificate.pem](certificate.pem). Certificate SHA-256: `001c832bac2f123795ff7cfa7a653150959bed02faa8d4abbb48b69adb3e86e4`. The tracked archive is gzip-compressed for clean repository whitespace handling; decompress it with `gzip -dc wrk-boringssl-full-handshake.patch.gz > wrk-boringssl-full-handshake.patch`. The decompressed patch SHA-256 is `00de42ee31f3cc910303a4d49881d150880bb8cae2c91e0336255b9ffab6d1f4`. No private key is included in the archive or evidence tarball.
- CPU placement and host details are retained in [environment.json](environment.json). They describe measurement context and were not runtime tuning parameters. The launcher and timing are in [command.json](command.json) and [wall-time.json](wall-time.json).

The archive contains [evidence.tar.gz](evidence.tar.gz), the matrix input, provenance, verification script, and machine-readable verdict files. Older runtime and converter/native directories remain historical and unchanged.
