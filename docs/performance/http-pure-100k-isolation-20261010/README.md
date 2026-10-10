# http-pure-100k-isolation-20261010

Local single-core plaintext native proxy. Four explicitly pinned reuseport origin workers. 128 downstream connections; 8 seconds after 2-second warmup, three rotated repeats. All frontends serial. These are screening measurements, not the nginx published 180-second cross-machine methodology. No default changes.

Transparent Rut forwards downstream Connection: close upstream; nginx strips it and reuses origin sockets. Short-connection results therefore include a persistence-policy difference and are not isolated backend comparisons. Exact preflight origin IDs are archived in raw logs.

| Campaign | Mode | Engine | Median RPS | Median p99 ms | Valid rows | Timeouts |
| --- | --- | --- | ---: | ---: | ---: | ---: |
| chunk256 | keepalive | uring | 35209 | 1291.299 | 0/3 | 414 |
| default | keepalive | uring | 35616 | 0.855 | 0/3 | 369 |
| nginx-tuned | keepalive | nginx | 23739 | 5.945 | 3/3 | 0 |
| ring256 | keepalive | uring | 35544 | 193.410 | 0/3 | 367 |

100KiB io_uring persistent rows are INVALID and must not be used to claim throughput superiority. All three default-control repeats also time out: neither ring nor larger segments alone explain the failure. No root cause established yet.

Full logs/configs/frozen binaries: `/home/hurricane/private/code/rut-performance-checkpoints/http-pure-100k-isolation-20261010`.
Raw summary SHA256: `09cc8fb2c2ff0d2905f168f4a0e8012577d6f2853848408e153205e00e031558`.

For isolation, default = current profile/128KiB/ring off/byte gate off; chunk256 = 256KiB/ring off/byte gate off; ring256 = 256KiB/ring on/byte gate off. The runner is authoritative for per-cell overrides. All controls preserve current CQ wait and turn budgets.
