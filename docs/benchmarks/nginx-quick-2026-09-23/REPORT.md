# Local nginx / RUT benchmark

Medians of per-run metrics; p99 values are not merged histograms. Errored, zero-throughput, missing-repeat or incomplete groups have no capacity ratio.

| Workload | Connection | Concurrency | nginx req/s | RUT req/s | RUT/nginx | nginx p99 µs | RUT p99 µs |
|---|---|---:|---:|---:|---:|---:|---:|
| proxy | close | 1 | 7,200 | 7,494 | 1.04× | 124 | 130 |
| proxy | close | 32 | 12,665 | 13,614 | 1.07× | 2,690 | 2,418 |
| proxy | close | 128 | 12,479 | 13,492 | 1.08× | 10,736 | 9,727 |
| proxy | keepalive | 1 | 10,495 | 10,263 | 0.98× | 128 | 133 |
| proxy | keepalive | 32 | 15,562 | 18,676 | 1.20× | 2,223 | 1,832 |
| proxy | keepalive | 128 | 15,184 | 19,194 | 1.26× | 8,690 | 6,900 |
| static | close | 1 | 14,154 | 14,214 | 1.00× | 37 | 37 |
| static | close | 32 | 41,437 | 37,937 | 0.92× | 642 | 886 |
| static | close | 128 | 41,162 | 41,430 | 1.01× | 2,332 | 2,536 |
| static | keepalive | 1 | 49,976 | 51,388 | 1.03× | 33 | 31 |
| static | keepalive | 32 | 133,167 | 189,122 | 1.42× | 310 | 254 |
| static | keepalive | 128 | 129,985 | 190,436 | 1.47× | 1,280 | 4,448 |

Raw values, warmup/measurement errors, repeat counts, CPU and RSS are in summary.csv. Raw values from invalid groups are diagnostic only. Socket errors are not a request failure rate. Each frontend process persists across concurrency levels within a repeat. See environment.json for conditions and status.json for completion/cleanup status.
