# Response Content-Length counting: throughput check

Candidate `c108b5f3` merges response Content-Length counting into its semantic
header match and fixes suffix-only matching of Xontent-Length. Baseline is
the PR #730 runtime tree. Both use ordinary pages; no I/O experiment is present.

## Method and validity

Repository nginx benchmark acceptance profile, pinned nginx 1.29.7 image
`sha256:1854da86e82d5dfb49a8f3d78b099adcc7e36608b207146ed95cd47937938a40`.
One shard/worker, upstream reuse off, implicit keepalive headers; server CPU 2,
origin CPU 3, clients CPUs 4–5. Three repetitions per engine/cell; 1 s warmup
and 5 s measurement, exact-body response preflight. nginx/Rut order alternates.
The host is not reserved or frequency-locked.

The initial order was baseline (64 KiB, 1 MiB), candidate (64 KiB, 1 MiB).
The earlier routing benchmark had ended and the shared benchmark lock was
available when this started. Spot checks during the 64 KiB runs observed no
external compiler/test/benchmark task. Its two comparisons are retained.

An external clang++ process was observed during the candidate 1 MiB phase,
with depressed individual samples also visible in the nginx control. The
1 MiB comparison was rerun in candidate/baseline order. A process monitor
sampling every 2 s recorded repeated compilation under
/home/hurricane/private/code/rut_enovy during that repeat, including test_jit
and bench_routing_matrix compilation. Both 1 MiB comparisons are excluded
from throughput conclusions, regardless of whether their medians look normal.
No external process was stopped or changed. The monitor log remains at
/tmp/rut-bounded-followup-20260928/gap/parser-repeat-processes.jsonl.

All **72 samples** passed harness validity checks with zero measured/warmup
errors. This verifies the exercised responses, not performance isolation:
only the **24 samples** from the 64 KiB comparisons support the table below.
The other 48 remain in samples.csv with performance_comparison_usable=false.

## Accepted results

Medians of three repetitions:

| HTTP body / connection / concurrency | Rut before RPS | Rut after RPS | Change | Before / nginx | After / nginx |
|---|---:|---:|---:|---:|---:|
| 64 KiB / close / 1 | 5827.6 | 5834.7 | +0.12% | 94.85% | 95.35% |
| 64 KiB / keepalive / 1 | 7709.0 | 7667.4 | -0.54% | 95.76% | 95.87% |

These short runs establish no meaningful throughput improvement or regression.
The parser change remains justified by the regression test and removal of a
duplicate name comparison; it does not close the nginx throughput gap.
No clean 1 MiB performance conclusion, TLS result or full-matrix result is
claimed. The previous complete parser/network test results remain documented
in ../io-copy-probes/README.md. No runtime source changed during this measurement.
