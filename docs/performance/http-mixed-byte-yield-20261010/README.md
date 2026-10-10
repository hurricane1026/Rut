# Mixed HTTP byte-budget completion observation

Candidate f157a285, default off. `RUT_STUDY_HTTP_BYTE_YIELD=on` checks both
half the call budget and half the byte budget before applying the existing
ordinary-CQ age limit. Optional `RUT_STUDY_HTTP_CQ_WAIT=20us|40us`; unchanged
current limit 80us otherwise. Real splice test demonstrates byte-half
observation with call budget still available, including unchanged default
behavior. Full related network/splice/CLI/native CTests and formatting pass.
Benchmark tooling 43 unit tests pass. No full sanitizer/remote CI yet.

Same 96 large /proxy + 32 small /small connections, 1MiB/4KiB, frontend CPU 2,
four origins 3,4,8,9, large clients 5,7, small client 6. Three rotated serial
8s + 2s comparisons. nginx small URL now uses 16KiB buffers; large URL
retains the previously selected 1MiB streamed proxy buffer. All sampled
frontends report zero warmup/measurement errors.

| Profile | Payload GiB/s median | Ratio to nginx | Small p99 median ms |
|---|---:|---:|---:|
| uring128 | 3.118 | 0.828 | 1.799 |
| uring256ring | 3.733 | 0.991 | 1.830 |
| byte80 | 5.956 | 1.581 | 6.566 |
| byte20 | 3.509 | 0.931 | 1.734 |
| nginx | 3.768 | 1.000 | 52.352 |

byte80 meets the 1.5x-nginx median throughput target on this mixed workload
(~1.58x), and beats nginx small tail, but regresses Rut's own small tail from
~1.8ms to ~6.6ms. Do not adopt it as a general default. byte20 keeps a similar
small-tail median but its mixed byte rate remains below the target. These
closed-loop clients generate different completion mixes: retain both client
rates and tails, not just aggregate byte rate.

Per-core counters show frontend CPU 2 effectively fully busy: process CPU
~60% plus softirq ~36–40%. Process CPU alone did not indicate spare capacity.
Snapshots surround client commands including short tool setup/teardown;
per-core accounting is diagnostic rather than cycle-exact profiling.

Next investigate cooperative TASKRUN readiness, which can precede CQ
publication. The scheduler only peeks CQ today; backend.wait already services
TASKRUN/CQ_OVERFLOW correctly. Experiment will observe those real flags
without clearing or consuming them, and validate whether it actually helps.

Full raw JSON, effective configurations, wrk logs, frozen binaries and runner
are in the matching checkpoint directory. Raw summary SHA256:
12092bcc9352c11ae7c1feee83830f6a4f606a9ae4174a8ed0c2ac5081c128ba
