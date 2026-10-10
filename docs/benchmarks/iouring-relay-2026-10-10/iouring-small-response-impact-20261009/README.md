# Small-response impact of the current 128 KiB relay candidate

Single frontend worker on CPU 2; origin two workers CPUs 3/4; clients CPUs 5/7. No eBPF tracing, no SEND_ZC. 15 s measurements, 3 s warmup, three rotated serial repeats per configuration. Pure workloads: 128 keepalive clients at 4/16/64 KiB. Mixed: 96 clients at 1 MiB plus 32 at the stated smaller size. Closed-loop concurrency; offered request-size proportions are not fixed rates.

Current runtime is the saved 128 KiB chunk + paired read/write reservation + 80 us observed-CQ-window candidate. Compare matched prior diagnostic variants at 64 KiB, with and without semantic yielding. These are experimental binaries; no URL-specific policies were implemented.

| Pure size | Variant | RPS median | p99 ms median |
| --- | --- | ---: | ---: |
| 4 KiB | 128 KiB + 80 us | 96617 | 1.832 |
| 4 KiB | 64 KiB + 80 us | 95986 | 1.676 |
| 4 KiB | Original 64 KiB eight segments | 95322 | 1.827 |
| 16 KiB | 128 KiB + 80 us | 55763 | 2.561 |
| 16 KiB | 64 KiB + 80 us | 56022 | 2.501 |
| 16 KiB | Original 64 KiB eight segments | 55784 | 2.535 |
| 64 KiB | 128 KiB + 80 us | 21772 | 6.163 |
| 64 KiB | 64 KiB + 80 us | 21961 | 6.032 |
| 64 KiB | Original 64 KiB eight segments | 21801 | 6.188 |

| Mixed smaller size | Variant | Large RPS | Large p99 ms | Small RPS | Small p99 ms |
| --- | --- | ---: | ---: | ---: | ---: |
| 4 KiB | 128 KiB + 80 us | 4612 | 29.755 | 21267 | 3.402 |
| 4 KiB | 64 KiB + 80 us | 2754 | 40.846 | 38670 | 1.532 |
| 4 KiB | Original 64 KiB eight segments | 2869 | 38.539 | 35480 | 1.722 |
| 16 KiB | 128 KiB + 80 us | 2865 | 35.764 | 28544 | 1.598 |
| 16 KiB | 64 KiB + 80 us | 2311 | 49.936 | 25992 | 1.709 |
| 16 KiB | Original 64 KiB eight segments | 2491 | 45.535 | 23914 | 2.029 |
| 64 KiB | 128 KiB + 80 us | 2025 | 58.339 | 14432 | 2.565 |
| 64 KiB | 64 KiB + 80 us | 1538 | 73.900 | 13694 | 2.698 |
| 64 KiB | Original 64 KiB eight segments | 1750 | 65.640 | 12604 | 3.152 |

All 54 measurements valid, zero request errors, payload preflights passed. All 27 pure-small server logs have zero relay admissions; their actual remaining response length does not enter the changed relay path in this setup. Pure throughput differences versus original-eight are within about 1.5%; pure p99 essentially unchanged. Do not treat these small median differences as statistically established improvements.

Mixed 4 KiB: candidate small RPS 21267 vs 35480 (-40%); small p99 3.402 vs 1.722 ms (+98%). Candidate samples: 18.148, 1.921, 3.402 ms. Large RPS 4612 vs 2869 (+61%). This is a material small-request fairness/tail cost and a variable service balance; candidate is not a universal low-latency default.

Mixed 16 KiB: small RPS 28544 vs 23914 (+19%); p99 1.598 vs 2.029 ms. Mixed 64 KiB: small RPS 14432 vs 12604 (+15%); p99 2.565 vs 3.152 ms. Different response/request-flow shapes behave differently; measured size correlations are not a license to predict the next response or infer URL policy.

Next investigation: count body bytes moved inside CQ callbacks versus deferred queues; compare byte-based minimum progress and whole-turn elapsed work against current call-based minimum/local-flush observation. With a 128 KiB chunk, four full segments move 512 KiB, versus 256 KiB for 64 KiB chunks. Initial header/poll callbacks can also advance body data before the deferred queue timer. These are code-level mechanisms to test, not proven attribution of the 18 ms spike.

Route policy direction: record request SLO (interactive latency vs bulk transfer throughput), observed response-size distribution, request frequency and I/O phases by route template. Use shared route policy and shard fairness caps; do not copy large policy/stat blocks into connections. Current experiments do not implement this surface. Prior runtime validation: 1593 network tests / 490407 checks passed; no code change in this measurement matrix.
