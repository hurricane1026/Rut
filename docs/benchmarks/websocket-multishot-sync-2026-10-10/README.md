# WebSocket multishot + immediate-send study

The winner for small messages is the existing bounded-cache multishot receive with asynchronous sends (`cache_async`), rather than the new immediate-send combination (`multi`). Preserve all experiments, keep defaults unchanged, and choose the existing copy/splice profile for larger messages.

## Repeated comparison

Three repeats per configuration, 8 s measured + 2 s warmup, rotating `cache_async`, `copy`, nginx order. Same frozen Rut/compiler pair and verified tcpkali2, 192 connections, frontend CPU2, four origin workers on CPUs3,4,8,9, three client workers on CPUs5,6,7. Frontends run serially; no build/tidy/tests during measurement. IO diagnostic timing disabled in confirmation. Every echo validated, all measured client errors zero, all cache shutdown live counts zero.

| Payload | Mode | Median messages/s | Observed range | Median p99 ms |
|---|---|---:|---:|---:|
| 64 | cache_async | 97574 | 96698–99421 | 2.517 |
| 64 | copy | 84041 | 83281–84157 | 2.645 |
| 64 | nginx | 83986 | 82925–84427 | 2.729 |

64B: throughput +16.2% versus nginx; p99 median change -7.8%.

| 1024 | cache_async | 88480 | 87271–88908 | 2.767 |
| 1024 | copy | 79179 | 78934–79551 | 2.797 |
| 1024 | nginx | 77808 | 76904–78307 | 2.777 |

1024B: throughput +13.7% versus nginx; p99 median change -0.4%.


Throughput ranges do not overlap in these three repeats. 64B p99 improves; 1KiB p99 is effectively unchanged and its ranges overlap. These conclusions apply to this plaintext WebSocket fixture and host, not all workloads/kernels/TLS.

## Screening

Single screens, 6 s measured + 2 s warmup, identical IO diagnostics enabled for Rut. `multi` combines existing multishot receive cache with immediate synchronous sends and original async fallback for short writes/EAGAIN. `poll` is the previous one-shot + immediate-send + POLL_FIRST experiment. `copy` is existing poll + copy-first/splice.

| Payload | Mode | Messages/s | Receive MiB/s | p99 ms |
|---|---|---:|---:|---:|
| 64 | cache_async | 102411 | 6.3 | 2.31 |
| 64 | multi | 84664 | 5.2 | 2.60 |
| 64 | poll | 78279 | 4.8 | 2.75 |
| 64 | copy | 85586 | 5.2 | 2.59 |
| 64 | nginx | 85730 | 5.2 | 2.63 |
| 1024 | cache_async | 87673 | 85.6 | 2.54 |
| 1024 | multi | 75604 | 73.8 | 2.74 |
| 1024 | poll | 70313 | 68.7 | 3.02 |
| 1024 | copy | 78546 | 76.7 | 2.70 |
| 1024 | nginx | 77408 | 75.6 | 2.76 |
| 16384 | cache_async | 19320 | 301.9 | 10.27 |
| 16384 | multi | 18514 | 289.3 | 10.84 |
| 16384 | poll | 15822 | 247.2 | 13.47 |
| 16384 | copy | 56129 | 877.0 | 4.00 |
| 16384 | nginx | 42337 | 661.5 | 4.89 |

Immediate sending loses to asynchronous sends at 64B and 1KiB; do not promote that experiment. At 16KiB, cache_async remains far behind copy/splice. Its observed cached-block peak is 496, shutdown live count zero, measured clients report no errors; this does not establish buffer exhaustion as the reason for its low throughput. Further work should study receive block size and send/batch progression.

## Reproduction modes

For small-message study: `RUT_STUDY_WS_RECV=cache RUT_STUDY_WS_SYNC_SEND=off RUT_STUDY_WS_SPLICE=off`, explicit `--backend io_uring`. This is an experimental process-wide setting, not automatic route/message classification.

For current larger-message profile: `RUT_STUDY_WS_RECV=once RUT_STUDY_WS_SPLICE=on RUT_STUDY_WS_COPY=on RUT_STUDY_WS_CALLS=2 RUT_STUDY_WS_FAST_BATCH=on RUT_STUDY_WS_FAST_SCAN=off`. All modes use WS TCP_NODELAY on. No SEND_ZC or predicted-size policy.

## Implementation and validation

New immediate-send eligibility permits an armed multishot receive only with the existing bounded selected-buffer cache. The kernel writes independent provided buffers; pending send ownership makes wait() retain subsequent blocks instead of mutating the connection buffer. Short writes keep the original source buffer intact until the original async suffix ledger completes. No new per-connection buffers or allocators. Counters prove actual cached-mode immediate-send use and capture cache peak/live state before backend shutdown.

Native WebSocket/splice CTests pass: small messages, forced short writes, slow readers, async suffix close, cached block reclamation and FIN injected while cache is nonempty with byte-exact duplex drain. Network filters (upstream recv, response-read, io_uring boundary, WebSocket) pass: 254 tests, 26,218 checks. clang-format and changed-line clang-tidy checked; full CI/sanitizers/other kernels not run.

A newly added test initially crashed because it reused the splice-only reverse-after-FIN fixture without allocating splice state. GDB identified the fixture dereference. The fixture now rejects that combination and has a distinct cached-FIN drain/close case; all data and lifetime assertions pass. Failed test/GDB logs are archived, not counted as successful runs. This was not a demonstrated runtime crash. Benchmark runtime code is unchanged after freezing except comment wrapping; later changes strengthen tests only.

Raw CSVs, logs, exact benchmark study.patch and source-manifest.json are retained. Counter totals cover process lifetime rather than just the timed interval; wait enters exclude other flush paths.
