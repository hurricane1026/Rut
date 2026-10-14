# Linkerd / Rut / nginx / Envoy: single-hop HTTP/1.1 benchmark

Date: 2026-10-14. All 48 formal samples passed; warmup and measurement error counters are zero. Each entry summarizes three 10-second measurements, each preceded by a 2-second warmup. These are short repeated measurements of the configurations below, not a general product ranking or a full service-mesh benchmark.

| Body | Rut io_uring RPS | nginx RPS | Linkerd RPS | Envoy RPS | Rut / Linkerd |
|---|---:|---:|---:|---:|---:|
| 4 KiB | 83,010 | 45,588 | 24,657 | 13,117 | 3.37x |
| 64 KiB | 48,479 | 29,248 | 17,348 | 10,568 | 2.79x |
| 256 KiB | 25,176 | 13,661 | 8,963 | 6,335 | 2.81x |
| 1 MiB | 5,490 | 3,898 | 2,862 | 2,410 | 1.92x |

RPS values are medians. The ratio is the ratio of medians.

| Body | Engine | RPS range | Payload Gbit/s (median) | p99 ms (median) | p99 ms range |
|---|---|---:|---:|---:|---:|
| 4 KiB | rut-rps | 81,918–85,312 | 2.720 | 1.699 | 1.628–1.719 |
| 4 KiB | nginx | 45,554–45,933 | 1.494 | 2.962 | 2.929–3.010 |
| 4 KiB | envoy | 13,077–13,215 | 0.430 | 10.733 | 10.448–10.795 |
| 4 KiB | linkerd | 24,500–24,692 | 0.808 | 6.316 | 6.259–6.496 |
| 64 KiB | rut-throughput | 47,907–48,787 | 25.417 | 3.727 | 3.691–3.730 |
| 64 KiB | nginx | 29,099–29,632 | 15.335 | 4.610 | 4.533–4.660 |
| 64 KiB | envoy | 10,539–10,583 | 5.541 | 13.623 | 13.499–13.806 |
| 64 KiB | linkerd | 17,262–17,535 | 9.095 | 8.907 | 8.859–9.162 |
| 256 KiB | rut-throughput | 24,239–26,725 | 52.799 | 5.572 | 5.543–5.965 |
| 256 KiB | nginx | 13,471–13,833 | 28.650 | 10.153 | 10.150–10.307 |
| 256 KiB | envoy | 6,301–6,404 | 13.286 | 23.164 | 21.999–23.329 |
| 256 KiB | linkerd | 8,883–9,108 | 18.797 | 17.636 | 17.252–18.022 |
| 1 MiB | rut-throughput | 5,484–5,767 | 46.050 | 24.002 | 22.426–27.399 |
| 1 MiB | nginx | 3,894–3,912 | 32.700 | 47.330 | 47.017–52.096 |
| 1 MiB | envoy | 2,400–2,438 | 20.218 | 59.931 | 59.106–60.141 |
| 1 MiB | linkerd | 2,859–2,865 | 24.010 | 55.440 | 55.117–55.713 |

Payload throughput is derived from RPS × response-body bytes; it excludes headers and is not physical-NIC throughput. p99 values are medians/ranges of per-run p99 values, not a pooled latency percentile.

## Configuration and scope

- Temporary two-node kind v0.33.0 cluster, Kubernetes v1.35.8; official Linkerd edge-26.10.1 control plane and stock injected proxy, with real identity bootstrap.
- Unmeshed client in the worker-node network namespace → server PodIP:8080. Linkerd intercepts inbound traffic and forwards to the same Pod’s nginx origin. Controls expose port 8080 and forward to their same-Pod nginx origin at 8081.
- One server-side Linkerd proxy only. HTTP/1.1 plaintext and keepalive; no client-side proxy, data-plane mTLS, ingress, or kubectl port-forward in the traffic path. Identity/control-plane traffic is separate from the measured plaintext application traffic.
- All frontend processes/threads pinned to CPU2; origin workers CPU3,4,8,9; client two threads on CPU5,7; concurrency 128. Control plane and node helper processes pinned to CPU6,14. CPU quotas removed; per-container cpu.max checked.
- Rut uses the previously verified runtime/compiler pair from commit 9543573a; its runtime source matches PR805 head defea4bb. 4 KiB uses .rps; larger bodies use .throughput. Actual startup logs verify io_uring and one shard. The original binary files were not modified.
- nginx 1.29.7 and Envoy 1.39.1 RELEASE use the same pinned images as the preceding comparison. Envoy has HTTP/1 on both hops and a router-only static origin configuration. Image IDs, manifests, binary/library hashes, and commands are retained locally.
- Only the current benchmark Pod is active during each sample. Engine order varies by round. Each sample has its own fresh deployment and raw logs.

## Validation and limitations

- Exact response-body hash, HTTP status and HTTP version checked before each sample. Each engine also passed a 100-request same-connection preflight, with source logs proving HTTP/1.1 and upstream connection reuse.
- A read-only /proc snapshot of the active Linkerd proxy during the 256 KiB second round found four eventpoll descriptors and no io_uring descriptor. The main and admin threads were both pinned to CPU2. This identifies the measured backend, but does not attribute the performance gap to that backend alone; no CPU profile was taken.
- Linkerd HTTP request counters for the actual application target increase after preflight; admin-port traffic is excluded. This verifies real L7 processing rather than opaque TCP forwarding or direct-origin bypass.
- Every formal warmup and measurement includes a successfully loaded Lua script and a METRICS record. All five error counters are zero. Slow but valid samples are retained.
- The exploratory series in `samples/formal/` used default nginx response buffers and is excluded from the main table. After restoring the preceding nginx tuning, the entire four-engine matrix was rerun; samples from the two configurations are not mixed.
- nginx uses proxy_buffering off, a 1 MiB proxy_buffer_size, 8 × 1 MiB proxy_buffers, a 1 MiB busy-buffer limit, no temporary files, upstream keepalive 4096, and upstream/downstream keepalive_requests 1000000000.
- Setup failures and the earlier standalone Linkerd smoke samples are excluded. A first manual wrk attempt failed to load its Lua script and is not used despite printing a throughput number.
- This topology and two-thread client differ from the previous isolated loopback comparison. Do not combine their numbers or infer a regression from absolute differences across the two runs.
- No saturation sweep or long-duration stability test was performed. The result measures this host, topology, concurrency and feature configuration; it does not establish unlimited origin/client capacity or functional equivalence of the products.

## Published evidence and reproduction

- [kind-samples.csv](kind-samples.csv) contains all 48 formal measurements and their 48 warmups, including raw request/duration counters, latency percentiles, and all five wrk error counters.
- [loopback-samples.csv](loopback-samples.csv) contains the 36 observations from the preceding three-engine loopback run; do not pool these with the kind samples.
- [Benchmark tools](../../../scripts/proxy_benchmark/README.md) describe the prerequisites and repeatable matrix workflow. This extraction was validated separately from the measured checkpoint scripts; the table records the original measured run, not a subsequent run of the extracted tools.
- Large raw logs, kubeconfig, identity secrets, downloaded executables, and runtime dependency bundles are not checked in. Full checkpoints were retained locally. The temporary measurement cluster was removed after completion.

## Why this differs from the preceding nginx comparison

The earlier run used a shared network namespace and loopback, with three client threads on CPUs 5,6,7. The kind run uses the worker-node-to-Pod path, with two client threads on CPUs 5,7 and control-plane/node helpers on CPUs 6,14. The Rut binary and hint choices stayed the same, but this is not a single-variable experiment. The source and client capacity limits have not been isolated.

| Body | Previous loopback Rut RPS | Previous nginx RPS | Rut gain over nginx | Kind Rut gain over nginx |
|---|---:|---:|---:|---:|
| 4 KiB | 126,388 | 74,334 | +70.0% | +82.1% |
| 64 KiB | 66,075 | 36,715 | +80.0% | +65.7% |
| 256 KiB | 31,020 | 14,539 | +113.4% | +84.3% |
| 1 MiB | 10,938 | 4,542 | +140.8% | +40.8% |

The earlier 256 KiB and 1 MiB results did exceed twice nginx throughput. The new topology does not reproduce that margin; the 1 MiB Linkerd comparison is also 1.92x rather than 2x. Neither run establishes a universal performance guarantee or a code regression. The earlier nginx 1 MiB p99 ranged from 30.015 to 336.786 ms; all three observations are retained in the CSV.

## Executable size and memory reporting

The following sizes were measured from the exact Rut artifacts and pinned proxy images used above. `strip --strip-all` was applied to separate copies only; the measured runtime binaries were not modified. This normalizes removable debug/symbol information, not build flags, linkage, enabled features, or functionality.

| Executable | Original bytes | Original MiB | Stripped bytes | Stripped MiB |
|---|---:|---:|---:|---:|
| nginx | 1,660,648 | 1.58 | 1,660,648 | 1.58 |
| envoy | 105,039,832 | 100.17 | 105,039,832 | 100.17 |
| rut | 13,282,752 | 12.67 | 3,514,688 | 3.35 |
| rut-compile | 7,420,872 | 7.08 | 6,386,640 | 6.09 |
| linkerd | 23,005,488 | 21.94 | 23,005,488 | 21.94 |

Rut's original executable contains debug information; the three proxy image executables were already stripped. These are ELF file sizes, **not image size, total deployment size, or resident memory**. Shared libraries and external assets are excluded. Rut's separate `rut-compile` helper is reported separately and needs its own dependencies. The exact file paths, image digests, SHA-256 hashes and ELF descriptions are in [binary-sizes.json](binary-sizes.json).

The original 48-sample run did **not** capture RSS/PSS. There is no defensible retrospective memory figure for those samples, and none is filled in. The extracted harness adds separate idle, post-warmup and load-time resource snapshots for future runs; these must be validated in a fresh live-cluster run before publishing a memory ranking. Proxy and origin memory must be reported separately, with each process counted once. Summed RSS can count shared pages more than once; PSS apportions those pages. Sampled maxima are not guaranteed true peaks.

The Rut link manifest includes static BoringSSL (`libssl.a`, `libcrypto.a`), Vectorscan runtime (`libhs_runtime.a`), and Zstd compression. The nginx executable dynamically references `libssl.so.3`, `libcrypto.so.3`, `libpcre2-8.so.0`, and `libz.so.1`, among other libraries. Thus the executable-only comparison is not a comparison of complete deployment footprints. Rut's `.text` is 2,822,812 bytes and `.rodata` is 489,016 bytes; the standalone runtime does not dynamically depend on LLVM. ELF `DT_NEEDED` lists are retained in the size manifest.

### Executable plus startup shared libraries

For each pinned image the ELF loader's `--list` output was resolved inside that image. For Rut, dependencies were resolved to the frozen library bundle used by the benchmark. Each unique library file (including the ELF loader and transitive dependencies) is counted once per executable; paths, sizes and hashes are recorded in `binary-sizes.json`. The executable uses its stripped size; shared libraries retain their measured on-disk size.

| Executable | Shared libraries MiB | Stripped executable + shared libraries MiB |
|---|---:|---:|
| nginx | 11.16 | 12.75 |
| envoy | 3.29 | 103.47 |
| rut | 7.35 | 10.70 |
| rut-compile | 150.83 | 156.92 |
| linkerd | 3.96 | 25.90 |

This includes libc and loader for every engine, but is still not a total container/deployment footprint: configuration, dynamic modules loaded later, certificates, control-plane services and other assets are excluded. The images use different distributions/library versions. The separate `rut-compile` row includes LLVM and is **not** additive to the Rut row without deduplicating shared files; clang/linker executables and their dependencies are not included. Thus the smaller Rut runtime closure does not mean source-mode deployment needs only glibc or has a 10.70 MiB total footprint.
