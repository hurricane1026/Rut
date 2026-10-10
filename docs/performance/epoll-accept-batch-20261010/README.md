# Bounded epoll accept batches

Keep a bounded multi-accept experiment. EpollBackend processes several queued connections from a single listener readiness record, stopping at the configured cap, output-event capacity, or an accept error/EAGAIN. Every accepted descriptor gets its own existing IoEvent with owned peer address. No connection fields, new allocation, language features or dependencies. Listener remains level-triggered; remaining accepts are retried by subsequent readiness. Default cap stays 1; RUT_STUDY_EPOLL_ACCEPT_BATCH=4|8|16|32 selects an experiment. Benchmark coalescing is also enabled with RUT_STUDY_HTTP_COALESCE_CLOSE=on.

Real TCP test queues three clients: an output capacity of one emits only one accept despite cap 2; the next call with output capacity three emits exactly two, proving the configured cap. Saved accept events are checked against their own socket peers. Full test_network/test_splice/test_ws_tunnel_iouring/test_cli_backend pass. Release build and changed-file formatting/diff checks pass; clang-tidy-22 on backend completes with existing warnings. No full ASan/GCC/macOS/remote CI run.

BPF diagnostic, 1KiB proxy-close, 128 clients, one frontend core, four pinned origin workers: batch16 epoll_wait 0.1307/request vs previous batch1 about 1/request. accept4 1.0026/request with 227 EAGAIN returns (~0.0016/request); no other syscall errors or BPF warnings. The ratio includes late outstanding accepts after the load counter stops. BPF throughput is not acceptance performance.

Untraced 3 rotated 8-second measurements per close setting, 2-second warmup; all use complete-response coalescing and the same current binary. Nginx is explicitly configured with multi_accept on, and its effective configuration is saved. Frontends run serially. This updates the comparator: earlier nginx results with default multi_accept off are not comparable as a fully tuned baseline.

| Median | batch1 | batch8 | batch16 | nginx multi_accept on |
| --- | ---: | ---: | ---: | ---: |
| Close RPS | 31200 | 34286 | 35197 | 33760 |
| Close p99 ms | 6.406 | 3.964 | 3.932 | 3.939 |

Batch16 gains about 12.8% over batch1, about 4.3% over this nginx configuration; not 1.5x. Three local rotations are not broad workload/statistical proof. One keepalive control: batch1 64298/p99 2.156ms, batch8 65725/2.130ms, batch16 64118/2.182ms, nginx 60195/2.328ms. Do not infer a steady-state persistent throughput gain from accept batching; it mainly affects connection churn. All 16 cells/preflights zero load errors.

Reference implementation reviewed: https://github.com/nginx/nginx/blob/release-1.29.7/src/event/ngx_event_accept.c loops accepting when multi_accept is enabled. Rut adds an explicit cap to preserve scheduling fairness rather than accepting until empty without a bound.

Full source snapshot, binary hash, logs/configs and raw BPF maps: /home/hurricane/private/code/rut-performance-checkpoints/epoll-accept-batch-20261010. The shared upstream pool MSG_PEEK and DEL/ADD pair remain: changing them requires stable transport ownership and idle-event handling rather than blindly skipping protection.
