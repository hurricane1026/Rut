# Prevent io_uring relay FIFO starvation

Fix commit 5abaf6e0. A CQ callback could start a new response synchronously and spend the entire relay quantum before the older ready FIFO was flushed at batch end. Under sustained 100KiB persistent traffic, new completions repeatedly overtook the ready owners. Pipe read/write EAGAIN counters were zero in both diagnostics; old ready-queue maximum wait was 3.609s, causing client timeouts. This was also reproduced with all new ring/chunk/byte-yield experiments disabled.

A healthy RelayRead dispatched inside a CQ batch now joins the existing ready FIFO if older runnable owners exist. Existing overflow poll, episode validation, cancellation, close and copy fallback paths remain. No new container, allocation or response-size prediction. The first read when the FIFO is empty remains synchronous.

A regression with real socket pairs and pipe splice queues an old owner with exhausted budget, replenishes the budget, then starts a newcomer inside CQ dispatch. It checks that the newcomer cannot consume that budget, and that the next two-call quantum progresses the old owner while retaining the new owner.

Three 12-second repeats after 2-second warmup, single frontend CPU2, four pinned reuseport origins3/4/8/9, clients5/7, 128 persistent connections. All nine performance rows and warmups are valid with zero errors.

| Workload | Median RPS | Median p99 ms |
| --- | ---: | ---: |
| 100KiB, current default study parameters | 31,546 | 4.443 |
| 1MiB, 256KiB/ring/byte-yield experiment | 6,962 | 20.969 |
| 1KiB, current default study parameters | 108,519 | 1.522 |

Earlier 100KiB rows were invalid (timeouts, median p99 about 905ms), so their approximately35k RPS is not a valid performance baseline. Tuned nginx median23,739 RPS from the earlier same-host campaign gives an indicative1.33× ratio; no fresh paired nginx run in this confirmation. Previous valid 1MiB median7,131 RPS/p9919.270ms: about2.4% lower throughput and8.8% higher p99 here, with substantial run-to-run ranges and different durations. Previous1KiB median109,960 RPS: about1.3% lower. Do not claim zero performance cost or universal1.5×.

Separate stats-enabled diagnostic: queue maximum wait reduced to11.828ms, no client errors. Diagnostic counters include warmup/preflight/drain and are not throughput confirmation. Queue wait sum does not represent exclusive CPU time.

Validation: rebuilt Release rut, test_ws_tunnel_iouring, test_network and test_splice; four related CTests pass, with network/splice repeated after their rebuild. Changed-file clang-format22 and diff check pass. Full sanitizer, GCC, macOS and remote CI not run. Existing build warnings remain. No merge or push.

Full raw logs/configs/frozen binaries: /home/hurricane/private/code/rut-performance-checkpoints/http-relay-fifo-starvation-fix-20261010. Diagnostic raw records are in the sibling before/after directories named in the archived logs.

Raw performance summary SHA256: `01ed69fc6a69b36608ba551e921b41a0aa47707d0b23f3969d29c664fee9c352`.
