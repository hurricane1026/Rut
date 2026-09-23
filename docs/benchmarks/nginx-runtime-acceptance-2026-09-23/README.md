# nginx / Rut full performance acceptance — 2026-09-23

**FAIL: all 96 comparisons are valid and error-free, but only 65 meet the
Rut/nginx throughput target of 1.10.** The other 31 are below target; none
were omitted. The runner exited 2 after 3,748.90 seconds (62m 28.90s).
This is a completed performance acceptance run, not a passing acceptance.

| Transport | Body | Passed | Below 1.10 | Invalid |
|---|---:|---:|---:|---:|
| HTTP | 16 B | 10 | 2 | 0 |
| HTTP | 1 KiB | 11 | 1 | 0 |
| HTTP | 64 KiB | 6 | 6 | 0 |
| HTTP | 1 MiB | 0 | 12 | 0 |
| HTTPS | 16 B | 12 | 0 | 0 |
| HTTPS | 1 KiB | 12 | 0 | 0 |
| HTTPS | 64 KiB | 11 | 1 | 0 |
| HTTPS | 1 MiB | 3 | 9 | 0 |
| **Total** | | **65** | **31** | **0** |

The [96-cell report](REPORT.md) and [CSV](cells.csv) include both engines'
median requests per second, their ratio, and each verdict. All 576 raw
measurement samples (three per engine per cell), warmups, wrk output, error
counts, generated configs, and server logs are retained in the
[evidence archive](evidence.tar.gz). [verification.json](verification.json)
independently recomputes every verdict: all 96 coordinates are unique and
present, all samples lasted at least 5.000106 seconds, all warmup and
measurement error counters are zero, and all 32 child runs used the same clean
source revision and binary hashes. [acceptance.json](acceptance.json) records
the runner verdict, wall time, and archive SHA-256.

## Workload and interpretation

The fixed gate is HTTP/HTTPS × static-close/static-keepalive/proxy-close/
proxy-keepalive × 16/1024/65536/1048576 bytes × concurrency 1/32/128. Each
engine gets a 1-second warmup and three measurements of at least 5 seconds
per cell. Every measurement must be valid and error-free, and the median
Rut/nginx throughput ratio must be at least 1.10 in **every** cell.

Static cells use the separately approved **native large-static comparison**:
nginx serves a static file with its open-file cache warmed by preflight;
Rut serves a pinned, shared, read-only response body. This is not the nginx
converter's `return` directive, whose 4093-byte limit invalidated large static
cells in the [original converter-return acceptance run](../nginx-acceptance-2026-09-23/README.md).
That original result and its raw evidence remain unchanged. Proxy cells keep
the converter-strict profile with origin connection reuse disabled. For 1 MiB
proxy responses, nginx uses `proxy_buffer_size 16k`, `proxy_buffers 8 16k`,
and `proxy_busy_buffers_size 32k`; these fixed comparison settings are recorded
in the archive. The native-static result should not be treated as a rerun of
the original converter-return static workload.

The result has meaningful gaps. All HTTP 1 MiB cells miss the target, as do
nine HTTPS 1 MiB cells. HTTP 1 MiB static-keepalive/c1 has a 0.007 ratio:
Rut's first repeat is about 2,644 requests/s, while repeats two and three
are about 23 requests/s, with zero recorded errors. HTTPS 1 MiB static-close/c1
is consistently about 11 requests/s versus nginx's 447 requests/s median.
Those outliers are exposed in the raw evidence; they are not smoothed or
discarded. After the TLS record drain change, this run has complete 1 MiB
HTTPS proxy/c1 measurements where an earlier diagnostic run did not, but its
three proxy-close ratios
remain 0.914, 0.867, and 0.767. Passing small-body or keepalive cells does not
compensate for these misses. The measurements do not isolate a single cause
for every throughput gap.

## Implementation and portability

The runtime now retains multishot upstream reads and reuses adjacent fragment
ownership proofs; it chains large response bodies through bounded reusable
16 KiB slices. Native static bodies are shared rather than copied into each
connection, with direct sends submitted in 64 KiB chunks. The io_uring TLS
drain can submit one complete TLS record; the existing ciphertext and
per-connection send-buffer capacities were not increased. The changes follow
response framing and buffer ownership, not CPU model, NIC speed, distro, or
kernel-version heuristics. The benchmark's bounded preflight avoids spending
measurement-scale time on correctness checks, while still checking complete
bodies. The acceptance sampling and thresholds were not weakened.

This host has a consumer Intel Core i7-10700, Fedora 44 Linux 6.19, and
ordinary host networking. The frontend, origin, and wrk were pinned to
separate physical cores (2, 3, and 4/5); Rut used one shard, nginx one worker,
and nginx access logging was disabled. CPU frequency was not fixed and the
host was not exclusively reserved. These numbers establish this local run's
verdict. They are not a cross-machine performance guarantee, and the extreme
low-concurrency values deserve replication on other hardware and mainstream
server distributions before attributing them to a general runtime limit.

Both frontends used the same TLS certificate. HTTPS close used full TLS 1.3
handshakes with the retained [wrk handshake patch](../../../scripts/nginx_benchmark/wrk-tls-full-handshake.patch).
The build was fresh clang 22.1.8, Release `-O2 -DNDEBUG`, JIT on, IPO off.
[provenance.json](provenance.json) records source/submodule/compiler and binary
hashes. No build or test ran during the acceptance measurement.

## Reproduction and checks

Build the recorded source and submodules, then use a locally valid certificate
and the patched wrk executable:

```sh
python3 scripts/nginx_benchmark/matrix.py --profile acceptance \
  --static-profile native-body --rut ./build/src/rut \
  --converter ./build/src/rut-nginx-convert --wrk /path/to/patched/wrk \
  --output /tmp/nginx-runtime-acceptance --server-cpu 2 --origin-cpu 3 \
  --client-cpus 4,5 --keepalive-header implicit \
  --tls-cert /path/to/cert.pem --tls-key /path/to/key.pem
```

The exact invocation, including ports, is in [command.json](command.json).
Docker group access was activated with `sg docker`; on the SELinux host the
output and certificate directories received `container_file_t` labels for
read-only container mounts. The archive contains generated configuration,
commands and logs, but excludes executables and the TLS private key.

Before measurement, 1,326 network, 61 loader, 64 arena, and 25 benchmark-tool
tests passed, with zero failures. Their logs are retained alongside this
report. The final source and executables matched the pre-run hashes; the
independent audit found 576 valid samples, no errors, and no missing cells.
