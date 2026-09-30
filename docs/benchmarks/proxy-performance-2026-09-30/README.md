# Pinned nginx comparison after landing perf/ebpf-investigation (2026-09-30)

This record measures the runtime that #737 lands: main `ff276165` plus #735,
#736 and the 20 `perf/ebpf-investigation` runtime commits, built from
`3732fb0b` (Rut executable SHA256 `f7cdbf0c…`, converter `2e19980c…`, the
same converter bytes as the 2026-09-29 record). The nginx image, wrk binary,
host, kernel and harness profile are the ones in [provenance.json](provenance.json).
The three matrices ran back to back on an otherwise idle host; the 1-minute
load never exceeded 3.51 across 2,162 samples.

## Why this record exists

The 2026-09-29 record described its frozen binary as main plus the
response-header parse cache. The binary was in fact built from
`perf/ebpf-investigation`, which carried 20 unmerged runtime commits. The same
matrix run on main itself earlier on 2026-09-30 (`main ff276165` + #735; see
`main_before_landing_ratio` in each summary) won 77 of 96 single-worker cells
and lost 1 MiB proxy at 0.68–0.88× nginx, with nginx's absolute throughput
unchanged. This record shows what landing those commits restores.

## Results

| Matrix | Valid cells | Rut throughput > nginx | ≥ 1.05× | p99 ≤ nginx | Median ratio | Lowest ratio |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Single worker, no `Connection` header ([sw-implicit.json](sw-implicit.json)) | 96/96 | 94 | 84 | 76 | 1.292 | 0.978 |
| Single worker, explicit `Connection: keep-alive`, keepalive scenarios ([sw-explicit.json](sw-explicit.json)) | 48/48 | 45 | 40 | 44 | 1.398 | 0.977 |
| Two workers on CPUs 2,6 ([mw-implicit.json](mw-implicit.json)) | 96/96 | 87 | 69 | 69 | 1.162 | 0.829 |

The single-worker matrix reproduces the 2026-09-29 record cell for cell: 94
wins and 84 cells at or above 1.05, with a median per-cell ratio change of
×0.998 against that record. The two remaining single-worker throughput losses
are the same 64 KiB proxy keepalive c1 (0.978) and, marginally, HTTPS 1 MiB
proxy close c128 (0.998).

Against main before landing, the largest gains are the 1 MiB proxy cells:
HTTP proxy close c32 0.681 → 1.316, c128 0.676 → 1.302; HTTP proxy keepalive
c32 0.744 → 1.404, c128 0.857 → 1.436. The explicit keep-alive matrix could
not run at all before #735 (every proxy cell closed the connection); it now
wins 45 of 48 cells at a median of 1.398.

Two-worker cells still below 1.05 are dominated by large close-mode proxy:
HTTP 1 MiB proxy close c32/c128 (0.83/0.84), HTTPS 1 MiB proxy close c128
(0.92), and 64 KiB static close c32/c128 (0.95/0.94). The single origin worker
on CPU 3 serves both frontends, so two-worker proxy cells partly measure the
origin. Some two-worker static ratios are lower than in the earlier main run
even though Rut's absolute throughput rose 0–8% on every such cell; nginx's
two-worker throughput varied 6–41% between the two runs on those cells.

Memory is unchanged and remains the open resource gap: median frontend RSS is
140 MiB for Rut against 20 MiB for nginx with one worker, and 213 MiB against
31 MiB with two. Every sample in all three matrices passed the exact-body
preflight with zero warmup and load errors.

## Scope

These are three HTTP/1.1 matrices over 16 B, 1 KiB, 64 KiB and 1 MiB bodies
at concurrency 1, 32 and 128, with `native-body` static and
`converter-strict` proxy profiles. They do not cover uploads, HTTP/2, native
streaming, the epoll backend, pipelined load, or other worker counts. The
single origin worker limits what two-worker proxy cells can show.
