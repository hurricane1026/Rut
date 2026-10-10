# HTTP splice segment size isolation

Candidate `72d1ba9d`; `RUT_STUDY_HTTP_SPLICE_CHUNK=256k|512k`. Current
profile default remains 128KiB. Same 16-call / 1MiB aggregate read+write turn
budgets and 80us ordinary-CQ observation rule. No response-size prediction.
All queue, terminal scan and boundary bitmap experiments off.

Serial four origins CPUs 3,4,8,9; one frontend CPU 2; client CPUs 5,7;
128 HTTP/1 implicit keep-alive connections; static bodies; 2s warmup / 6s
measurement. First 9-cell screen also included 512B and 4KiB controls, which
do not admit splice. Their order-related variations are not segment benefits.

1MiB confirmation rotates orders 128/256/512, 256/512/128, 512/128/256:

| Segment | Median RPS | RPS range | Median p99 ms | p99 range ms |
|---|---:|---:|---:|---:|
| 128k | 5475 | 5469–5504 | 27.111 | 26.989–27.561 |
| 256k | 7142 | 7054–7280 | 23.945 | 18.829–24.081 |
| 512k | 7283 | 7233–7347 | 23.311 | 18.284–26.319 |

256KiB gains about 30% median throughput; 512KiB about 33%. Neither worsens
the three-sample p99 median; p99 varies substantially within each larger size.
All 18 screen+confirmation rows and warmups have zero reported errors.
These are local 1MiB proxy results, not API/streaming/TLS/mixed-size validation
or a fresh nginx comparison. Defaults are unchanged pending wider validation.

Bigger pipes consume more kernel pages. Host pipe-user-pages-soft is 16384,
pipe-user-pages-hard is 0, pipe-max-size is 1048576. Existing admission
falls back to 64KiB if a larger pipe cannot be allocated, and falls back to
copy if even 64KiB cannot be allocated. Diagnose actual admissions/short reads
before selecting a global default or raising concurrency. Process RSS does
not include pipe page memory.

Release rut rebuild and CLI smoke CTest passed. Existing runtime tests already
cover segment limit larger than actual 64KiB pipe capacity; no new runtime
state-machine code changed for this knob. Full sanitizer/remote CI not run.
Raw logs, frozen binaries and runners reside in matching checkpoint directories
under `/home/hurricane/private/code/rut-performance-checkpoints`.

## Post-simplification operation-count check

After removing the indexed list (`23dc2130`), rebuild, changed-file
clang-format 22 and the four related CTests passed. The list implementation
and exact measurement head are archived on
`study/http-relay-indexed-list-20261010`; current branch retains only the
simpler ring experiment plus segment-size knob.

Separate stats-enabled runs (not performance confirmation), all queues off,
same 1MiB scenario. Counts cover warmup/preflight/measurement/drain together.

| Segment | Admissions | Read calls | Write calls | Calls/admission | Read EAGAIN | Large/small pipe allocations |
|---|---:|---:|---:|---:|---:|---|
| 128k | 45084 | 369063 | 367793 | 16.34 | 1270 | 260/0 |
| 256k | 58586 | 246598 | 260506 | 8.66 | 1561 | 260/0 |
| 512k | 58807 | 1024976 | 771820 | 30.55 | 256684 | 256/4 |

256KiB approximately halves read/write calls per admitted response. This
supports the syscall-amortization mechanism behind its measured throughput
gain. Do not claim every larger segment reduces calls: 512KiB has many short
reads and read EAGAIN and increases calls/admission. Four pipe allocations
use 64KiB fallback there. Existing counters do not record the initial fcntl
errno, so the exact fallback cause is not established; the host page quota
is a possible factor, not a proven diagnosis.

Prefer further validation of 256KiB with the simple ring. Mixed traffic p99,
high concurrency/page pressure, fragmented origins and TLS remain required
before changing production defaults. These diagnostic runs themselves have
zero reported request/warmup errors.
