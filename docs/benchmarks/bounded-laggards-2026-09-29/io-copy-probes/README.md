# Ordinary-page I/O copy probes

All experiments use ordinary pages. No THP advice or global kernel setting
was added. Baseline production tree is PR #730, whose binary hash is recorded
in provenance.json. The parent commit adds only the preceding probe report.

## Experiments

- **recviov:** replace direct upstream RECV with RECVMSG and two contiguous
  iovecs covering exactly the original destination/length. Metadata lives in
  a per-connection MappedArray until completion, not on the submission stack.
- **recviov16:** same submission, with up to sixteen 16 KiB iovecs (the final
  vector covers any remaining bytes). No receive-length cap or new payload copy.
- **align64:** retain the original RECV path and 256 KiB allocations, but align
  ResponseBodyChain payload to 64 bytes instead of placing it after its 16-byte
  node header. The ordinary and bulk usable capacities decrease by 48 bytes.

The earlier profiles showed nginx readv and Rut recv at different offsets in
_copy_to_iter. This motivated an experiment, not a conclusion that one API
was inherently faster. Linux's [iov_iter implementation](https://raw.githubusercontent.com/torvalds/linux/master/lib/iov_iter.c)
contains different iterator paths, but source inspection alone cannot predict
the cost on the running kernel or explain the measured nginx gap.

## Measurement

HTTP 1 MiB close; one shard, upstream reuse off; server/origin/client CPUs
2/3/4–5. Per cell candidate/baseline/baseline/candidate; 2 s warmup and 6 s
measurement per process. These are process-stat probes, not formal acceptance:
no exact-body preflight or regression suite was run on the discarded variants.
Measured wrk errors are all zero; warmup error counters are not retained.
Builds and timed probes were serialized. The host is not reserved or
frequency-locked. Reported deltas use arithmetic means of two repetitions.

| Experiment | Concurrency | Baseline RPS | Candidate RPS | Change |
|---|---:|---:|---:|---:|
| recviov | 32 | 2104.9 | 2099.4 | -0.26% |
| recviov | 128 | 2044.2 | 2030.2 | -0.69% |
| recviov16 | 32 | 2091.2 | 2074.5 | -0.80% |
| recviov16 | 128 | 2022.9 | 2000.5 | -1.10% |
| align64 | 32 | 2078.0 | 2042.4 | -1.71% |
| align64-repeat | 128 | 2018.5 | 2033.5 | +0.74% |

The initial align64 c128 baseline was unstable (1302.5 and 1815.0 RPS).
The slowest run had about 79 us/request of runqueue wait, versus approximately
2–3 us normally. Its apparent +29% candidate gain is excluded. No cause of
the transient host disturbance was established. Both baseline and candidate
were rerun; the repeat above does not reproduce a substantial gain.

## Decision

All three runtime experiments were reverted. These probes establish no
repeatable useful throughput gain; small differences have no confidence
interval. In particular, switching receive API or splitting one receive into
small iovecs did not close the gap. No conclusion is drawn about send-side
vectored I/O, which these variants did not change.

Patches, drivers and raw diagnostic rows are retained here. Full binaries,
build logs and wrk logs remain in /tmp/rut-bounded-followup-20260928/gap.

## Retained parser change

Response parsing previously matched Content-Length inside semantic handling,
then repeated a suffix-only comparison to increment content_length_count.
The second comparison omitted the first character: Xontent-Length incorrectly
incremented the counter, including when a real Content-Length also existed.
The regression test fails twice on the previous implementation (see
parser-before.log). Counting now occurs in the already fully matched semantic
branch after successful length validation, preserving conflict rejection and
u8 saturation. The duplicate name comparison is removed.

This is a verified correctness fix and a reduction in parsing work; no new
end-to-end throughput gain is claimed for it. During validation an independent
bench_routing_matrix process was observed in /home/hurricane/private/code/rut_enovy;
no throughput run for the parser change was attempted concurrently with it.
The observation occurred after the copy probes and does not establish the
cause of their earlier transient disturbance.

Validation of the retained change:
- Release runtime, test_http_parser and test_network built successfully.
- Complete HTTP parser suite: 216 passed, 3851 checks, zero failures.
- Complete network suite: 1423 passed, 339764 checks, zero failures.
- clang-format 20 and git diff whitespace checks passed.
- Full integration and the throughput acceptance matrix were not rerun.
