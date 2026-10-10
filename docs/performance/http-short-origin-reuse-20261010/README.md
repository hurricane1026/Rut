# Matched upstream reuse with short downstream connections

Single frontend core, four pinned reuseport origin workers, two separate physical client cores. 1KiB pure proxy body, 128 downstream connections, 8-second measurements after 2-second warmup, three rotated serial repeats. Existing request_policy ID1 omits Connection upstream and strips the declared hop-by-hop headers, preserving downstream close. This also rewrites Host to upstream, so the delta is not exclusively header omission. Body preflights verify responses and closure; origin-side connection ID preflights require actual reuse across fresh downstream sockets. All nine measured rows and warmups report zero errors.

| Engine | Transparent RPS | Matched-policy RPS | Matched p99 ms |
| --- | ---: | ---: | ---: |
| uring | 14824 | 18098 | 15.409 |
| epoll | 13139 | 25350 | 9.322 |
| nginx | 27351 | 27140 | 8.373 |

This explains most epoll loss but leaves an io_uring short-connection deficit. Connection initialization, peer getpeername, receive/close cancellation and CQ processing are hypotheses for follow-up profiling, not proven cost attribution. Route workload policies cannot tune pre-route accept retroactively.

Full evidence/frozen binaries: `/home/hurricane/private/code/rut-performance-checkpoints/http-short-origin-reuse-20261010`.
Raw summary SHA256: `cacf1b41b39ff7978427cf433fb22a338a8826aff3c47f9187836629f9f0a17e`.

No runtime defaults changed; no new language syntax introduced. Runtime binaries unchanged. Benchmark tool tests cover strict reuse gating; real preflight covers ID1 rewrite, actual origin reuse and downstream response semantics.
