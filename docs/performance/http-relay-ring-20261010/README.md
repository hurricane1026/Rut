# Continuous-array HTTP relay FIFO experiment

Candidate `5be5001a`; default off; `RUT_STUDY_HTTP_RELAY_RING=on`.
The existing fixed contiguous ID/episode arrays become a circular FIFO.
Hot dequeue advances head rather than shifting every remaining element.
No linked list, per-element allocation or change to turn budgets.
Duplicate admission still scans the queue; arbitrary close removal still
compacts the remaining logical FIFO. Stale episode validation is unchanged.

Release build, changed-file clang-format 22, diff check and four CTests
(network/splice/CLI/native io_uring) passed. New test covers full capacity
duplicate publication, wraparound, middle/wrapped removal and distinct episodes
for the same identity. Full sanitizer/remote CI have not run on this branch.

Serial four origins on CPUs 3,4,8,9, one frontend CPU 2, client CPUs 5,7,
128 implicit HTTP keep-alive connections, static bodies, 2s warmup / 6s timing,
three paired orders off/on, on/off, off/on. Terminal scan and boundary bitmap
experiments are off. Same frozen binary for both configurations, stats off.

| Body | Off median RPS | On median RPS | Off median p99 ms | On median p99 ms |
|---|---:|---:|---:|---:|
| 512 | 101108 | 101065 | 1.949 | 1.890 |
| 4096 | 89999 | 94514 | 1.990 | 1.748 |
| 1048576 | 5520 | 5539 | 26.804 | 26.689 |

1MiB gains only about 0.3%, with overlapping ranges. Do not claim a stable
throughput gain or promote to default. Small bodies do not admit splice, so
their positive/negative differences do not demonstrate a queue benefit.
All 18 measurement rows and warmups have zero reported errors.

Pre-change diagnostic (`99803674`, stats on) established 1MiB active splice:
45592 admissions, 371849 reads, 370014 writes, 1835 read EAGAIN, zero write
EAGAIN, 643875 splice calls in ready-queue flushing. Flush wall time ~6.32s
includes syscalls and scheduling; it is not exclusive queue CPU time. Most
1/64 sampled write splices fall into 8–15us histogram bucket. Empty returned
IoEvent batches can still follow internal CQE consumption or deliberate
nonblocking waits while relay owners remain runnable; they are not all useless
spins. Next isolate segment size with the same aggregate byte/call turn limits.

Raw results/runners/logs/frozen binaries are in the matching checkpoint
directory under `/home/hurricane/private/code/rut-performance-checkpoints`.
Pre-change full diagnostic logs are in `http-splice-wait-20261010-diagnostics`.
