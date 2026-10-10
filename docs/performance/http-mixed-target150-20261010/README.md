# Mixed HTTP target: 1.5 times nginx

Pilot head `0b7f71dc`; runtime tree matches `23dc2130`. Exact binaries have
SHA256 manifest. Twelve serial samples, three rotated engine orders, 8s
measurement + 2s warmup. One frontend CPU 2, four static nginx origin workers
on CPUs 3,4,8,9, two large-client cores 5,7 and small-client core 6.
96 persistent large connections use /proxy (1MiB); 32 small connections use
/small (4KiB). Different URL handlers forward to the same shared origin pool.
Payload byte rate weights each client's actual completed requests by body
size; raw total RPS is insufficient to compare mixed throughput.

| Frontend | Median payload GiB/s | Median small p99 ms |
|---|---:|---:|
| uring128 | 2.999 | 1.207 |
| uring256ring | 3.877 | 1.936 |
| nginx | 3.750 | 54.906 |
| epoll | 3.624 | 6.493 |

All measurements and warmups report zero errors. Optimized io_uring median
rate is only ~1.03x nginx; it does not meet the requested 1.5x mixed-traffic
target. Its small-client p99 median also exceeds the 128KiB Rut baseline,
with substantial run-to-run variability. Do not generalize pure-large-body
results or promote the 256KiB configuration without mixed-tail validation.

Pilot nginx uses 1MiB proxy buffers for both URLs. Subsequent campaigns tune
/small independently to 16KiB to avoid an unsuitable API baseline. Pilot
values remain intact but are not the final tuned-nginx comparison.

Next candidate: the relay scheduler observes ordinary CQ age only after half
the call budget. Large chunks exhaust bytes before that condition fires.
An opt-in byte-half threshold will be tested with actual queued-owner
progress, while retaining normal CQ ownership/dispatch and cancellation.
Host per-core CPU/softirq counters will supplement process CPU accounting.

Raw effective configurations, client logs, preflight evidence, binaries and
runner are in the matching checkpoint directory under
`/home/hurricane/private/code/rut-performance-checkpoints`.
