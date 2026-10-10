# WebSocket upstream direct receive study

Same frozen Rut/compiler pair; one frontend core, four origin workers, three client cores, 192 connections. Frontends measured serially, 6 s measured + 2 s warmup. All Rut variants enable identical IO diagnostics. One screen per combination, no repeated-run significance claim.

- copy: previous poll + copy-first/splice configuration.
- sync: one-shot provided-buffer receive + immediate send, previous experiment.
- direct4/direct16: sync plus upstream direct receive into existing connection buffer, capped at 4KiB/16KiB. Downstream receive unchanged; no SEND_ZC or prediction.

| Payload | Mode | Messages/s | Receive MiB/s | p99 ms |
|---|---|---:|---:|---:|
| 64 | copy | 85267 | 5.2 | 2.59 |
| 64 | sync | 75814 | 4.6 | 2.96 |
| 64 | direct4 | 75589 | 4.6 | 3.02 |
| 64 | direct16 | 74276 | 4.5 | 3.35 |
| 64 | nginx | 82805 | 5.1 | 3.02 |
| 1024 | copy | 78333 | 76.5 | 3.05 |
| 1024 | sync | 68208 | 66.6 | 3.49 |
| 1024 | direct4 | 69524 | 67.9 | 3.42 |
| 1024 | direct16 | 70659 | 69.0 | 3.00 |
| 1024 | nginx | 77070 | 75.3 | 2.79 |
| 16384 | copy | 54331 | 848.9 | 4.63 |
| 16384 | sync | 16120 | 251.9 | 12.78 |
| 16384 | direct4 | 12391 | 193.6 | 16.40 |
| 16384 | direct16 | 16650 | 260.2 | 12.08 |
| 16384 | nginx | 42671 | 666.7 | 5.02 |

All measured clients verified payloads and reported zero errors. Direct receive arms counter confirms actual activation. Both direct configurations lose to current copy/splice on all screened sizes. Keep experimental knobs disabled; do not replace current implementation.

At 64B, removing upstream provided-buffer selection/copy does not close the throughput gap. This rejects that copy as the primary explanation for this configuration; it does not isolate the downstream copy or kernel receive/rearm cost. At 16KiB, increasing upstream cap helps relative to direct4 but remains far behind the existing path. Further work should isolate kernel receive rearming/polling rather than adding copy optimizations.

CTest test_ws_tunnel_iouring and test_splice passed, including byte-exact duplex, forced short writes/slow readers, async suffix close and close while kernel owns direct destination. Full CI and sanitizers not run. Counter totals cover process lifetime; IO wait enter counters exclude other flush paths. Candidate hashes and base commit are in source-manifest.json; exact study patch preserved.

Final validation: rebuilt test_network on fixed sources and ran upstream receive, response-read, io_uring boundary and WebSocket filters: 254 tests, 26,218 checks passed. Native WebSocket/splice CTests passed after strengthening the direct-close case to submit the idle receive to the kernel before close. Changed-line clang-tidy and clang-format checks pass. Initial concurrent-header-edit build failed with Bus error; fixed-source rebuild passed. Only diagnostic const/name corrections and the strengthened close test differ from the frozen benchmark source patch.
