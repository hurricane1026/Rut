# Follow-up probes after PR #730

Base: `60396bc5` (same tested tree as `c84bb0b5`, rebased onto the squash
merge of #726). PR: https://github.com/hurricane1026/Rut/pull/730.

Both candidates were compiled and measured independently against the PR
binary. Neither experimental source change is retained. The production
runtime snapshot was restored after these probes.

## Method

HTTP 1 MiB close, concurrency 32 and 128. Per cell, candidate/baseline/
baseline/candidate order; each process has 2 s warmup and 6 s measurement.
Server CPU 2, origin CPU 3, clients 4–5; one shard and upstream reuse off.
Runs are serialized with the benchmark lock; no concurrent local compilation.
The host is not reserved or frequency-locked. These are process-stat probes,
not the formal acceptance harness: no exact-body preflight or full test
suite was run for these experimental binaries. All measured wrk error
counters are zero; warmup stdout/error counts were not retained.

## Results

Arithmetic means of the two runs per engine/cell:

| Experiment | Concurrency | Baseline RPS | Candidate RPS | Change | Baseline user/system us per request | Candidate user/system us per request |
|---|---:|---:|---:|---:|---:|---:|
| recv64k | 32 | 2093.1 | 1951.2 | -6.78% | 23.1 / 318.5 | 36.0 / 333.8 |
| recv64k | 128 | 2034.3 | 1933.4 | -4.96% | 27.8 / 322.1 | 39.5 / 340.7 |
| bulk-thp | 32 | 2091.0 | 2122.6 | +1.51% | 24.3 / 317.5 | 23.6 / 312.0 |
| bulk-thp | 128 | 2022.7 | 2068.5 | +2.26% | 27.9 / 321.4 | 26.5 / 315.3 |

### Smaller direct receives: rejected

Cap direct upstream receive SQEs at 64 KiB while retaining 256 KiB bulk
allocations and the 64 MiB idle-cache limit. Both concurrency levels regress;
user and system CPU/request both rise. This does not support reducing receive
batch size as the next optimization. No protocol or timeout policy changed.

### Transparent huge pages: promising, not promoted

Apply MADV_HUGEPAGE only to the bulk mmap reservation. smaps confirms 16 MiB
of anonymous huge pages at c32 and 62 MiB at c128 (zero for baseline). The
small 1.5–2.3% throughput improvement warrants a longer controlled acceptance
experiment, not an immediate production policy change. No global THP settings
were modified: this host uses `madvise` for both enabled and defrag.

The [kernel THP documentation](https://docs.kernel.org/admin-guide/mm/transhuge.html)
explains both TLB benefits and potential memory/first-touch compaction costs.
These short warm runs do not measure cold-start latency, memory pressure,
burst return beyond the idle cache, or TLS. Large pages can allocate untouched
portions of a bulk reservation, so the existing resident-memory accounting
and reclaim behavior need validation before adopting this hint.

## Evidence

JSON files preserve each measured run and process CPU accounting. Patches
contain the exact experimental changes; drivers retain the local fixture paths.
`provenance.json` records binary hashes. Full build/server/wrk logs and binaries
remain in `/tmp/rut-bounded-followup-20260928/gap`.
