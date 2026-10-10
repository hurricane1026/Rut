# WebSocket one-shot receive POLL_FIRST study

Opt-in `RUT_STUDY_WS_POLL_FIRST=on`: kernel polls for readability before the first recv attempt. Opaque plaintext WebSocket one-shot receive only, both legs; default off. Existing cancellation identity and destination lifetime remain unchanged. Selected-buffer and direct receive APIs accept the flag; ordinary HTTP callers default to false.

Same frozen Rut/compiler pair; frontend CPU2 (one worker), four origin workers on CPUs3,4,8,9, three tcpkali2 workers on CPUs5,6,7, 192 connections. Frontends measured serially. Verified fixed payloads, full latency sampling, zero client errors. No SEND_ZC, history-based size prediction or new buffers.

## Repeated comparison

Three repeats of 8 s measured + 2 s warmup, alternating sync/poll order. IO diagnostic timing disabled for both variants. These compare the same provided-buffer one-shot receive plus immediate-send mode, changing only POLL_FIRST.

| Payload | Mode | Median messages/s | Observed rate range | Median p99 ms |
|---|---|---:|---:|---:|
| 64 | sync | 74245 | 73703–74514 | 3.311 |
| 64 | poll | 77023 | 76837–77027 | 3.159 |
| 1024 | sync | 68212 | 67892–68376 | 3.533 |
| 1024 | poll | 70810 | 70352–70961 | 3.347 |

Observed throughput ranges do not overlap within these three-repeat comparisons. This is evidence for a modest improvement to the one-shot experiment on this host, not a cross-host guarantee. It still does not replace current copy/splice, which is faster in screening.

## Screening

One screen each, 6 s measured + 2 s warmup, IO diagnostics enabled for all Rut modes. `copy` is existing poll + copy-first/splice; `sync` is one-shot recv plus immediate send; `poll` is sync + POLL_FIRST. Keep screen and confirm numbers separate.

| Payload | Mode | Messages/s | Receive MiB/s | p99 ms |
|---|---|---:|---:|---:|
| 64 | sync | 77008 | 4.7 | 3.23 |
| 64 | poll | 78641 | 4.8 | 3.13 |
| 64 | copy | 84734 | 5.2 | 2.94 |
| 64 | nginx | 85007 | 5.2 | 2.92 |
| 1024 | sync | 69337 | 67.7 | 3.43 |
| 1024 | poll | 71840 | 70.2 | 3.29 |
| 1024 | copy | 81485 | 79.6 | 2.62 |
| 1024 | nginx | 78959 | 77.1 | 3.10 |
| 16384 | sync | 16130 | 252.0 | 13.38 |
| 16384 | poll | 15794 | 246.8 | 13.31 |
| 16384 | copy | 55117 | 861.2 | 5.13 |
| 16384 | nginx | 42271 | 660.5 | 5.13 |

16KiB shows no screening throughput gain from POLL_FIRST. Current copy/splice remains much faster. Do not enable this globally or infer a nginx win from the modest one-shot improvement.

POLL_FIRST arms counters confirm actual activation; IO wait counters cover process lifetime and exclude other flush paths. Exact benchmark source patch, base commit and frozen binary hashes are archived alongside raw tcpkali2 CSVs and frontend logs. The later native direct-receive transfer test changes only tests, not benchmark binaries.

## Validation

Rebuilt Release runtime/compiler, native WebSocket/splice and network test binaries. WebSocket/splice CTests pass, including slow readers, forced short-write suffix ownership, selected-buffer POLL_FIRST close and direct POLL_FIRST transfer/idle cancellation. Network filters for upstream recv, response-read, io_uring boundary and WebSocket: 254 tests and 26,218 checks pass. clang-format and changed-line clang-tidy checks pass; existing unrelated warnings remain filtered. Benchmark manifest Python syntax passes. Full CI, sanitizers and other kernels not validated.

Keep the flag off by default and preserve the current copy/splice configuration. Next investigation: multishot receive with immediate sending using the existing bounded cache/ownership protections, to remove per-message rearming rather than just its initial transfer attempt.
