# Indexed doubly linked HTTP relay queue study

Candidate `be446c89`; optional `RUT_STUDY_HTTP_RELAY_LIST=on`.
Nodes occupy one fixed array with u16 next/previous handles, not individually
allocated pointer nodes. A mmap-backed per-connection-slot u16 owner head
lets duplicate admission and close removal inspect only the same slot's
episodes. The regular case has one node per owner; distinct old/new episodes
remain separate until pop/close. No cross-shard synchronization.

Release build; changed-file clang-format 22; network/splice/CLI/native io_uring
CTests pass. New native FIFO invariants test covers capacity, wrap/reuse,
duplicates, arbitrary deletion, same-ID distinct episodes. Three real-network
variants cover budget deferred progression/fairness, close without CQE, and
initial readiness-SQE failure fallback. Full sanitizer/remote CI not run.

1MiB static-origin proxy, 128 implicit keep-alive connections, one frontend
CPU 2, four origins CPUs 3,4,8,9, clients CPUs 5,7, 2s warmup / 6s timing.
Three serial rotated orders linear/ring/list, ring/list/linear, list/linear/ring,
with both 128KiB and 256KiB splice limits. Same frozen binary across cells.
All other experimental flags and stats off.

| Segment | Queue | Median RPS | RPS range | Median p99 ms | p99 range ms |
|---|---|---:|---:|---:|---:|
| 128k | linear | 5554 | 5506–5557 | 26.499 | 26.382–27.827 |
| 128k | ring | 5506 | 5351–5575 | 26.499 | 26.204–27.483 |
| 128k | list | 5492 | 5354–5563 | 26.796 | 26.691–27.294 |
| 256k | linear | 6873 | 6826–7085 | 24.380 | 23.707–24.718 |
| 256k | ring | 7225 | 6951–7235 | 19.031 | 18.995–24.243 |
| 256k | list | 7192 | 6928–7345 | 19.148 | 19.058–24.328 |

All 18 timed rows and warmups report zero errors. List does not consistently
outperform ring: with 256KiB its median rate is slightly lower, and its third
rotation is ~4% slower than ring. With 128KiB no queue variant improves the
linear baseline consistently. The indexed list's extra allocation, owner
chains and cleanup complexity are therefore removed from the active branch
per the user's instruction to prefer simpler structures without clear benefit.
The exact code is retained in commit be446c89 and archived study branch.

Ring remains opt-in and simpler (two fixed arrays plus head), with no extra
owner map. 256KiB ring has ~5% higher median rate than linear in this campaign,
but do not generalize it beyond this local workload. Larger segments remain
the main measured gain; defaults are unchanged until mixed traffic, kernel
pipe page pressure and wider regression validation. No new nginx comparison.

Raw logs, frozen binaries, SHA256 manifest and runner are in the matching
checkpoint directory under `/home/hurricane/private/code/rut-performance-checkpoints`.
