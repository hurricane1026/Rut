# Epoll complete close-response coalescing

Epoll now exposes the same per-shard study flag/counter as io_uring, so the shared callback can use the existing coalesce_complete_native_close_response helper. Default remains off; enable with RUT_STUDY_HTTP_COALESCE_CLOSE=on. This is a two-field per-shard change, no connection memory allocation or language feature.

Only the existing explicit request-policy/downstream-close shape, fully received Content-Length body, throttle-free response and adequate existing owned header buffer qualify. Incomplete/overlong bodies, insufficient capacity and other policy shapes retain the old path. Coalescing copies already-received bytes into the owned rewritten-header buffer and sends once using the existing completion callback. It does not wait for body bytes or infer future response size. Existing helper boundary tests and backend partial-send ownership tests are reused; actual proxy preflights verify wire response and upstream reuse.

BPF diagnostic, 1KiB proxy-close, 128 clients, single frontend core, four pinned origins: frontend sendto approximately 3/request before versus 2.0018/request after (one request upstream + one combined response downstream). epoll_ctl remains 3.0028/request after earlier ADD-first optimization. getpeername absent after accept-address change. No syscall errors/BPF loss warnings in retained trace. Log RUT_HTTP_COALESCE_CLOSE responses=196175 includes warmup/preflight; syscall maps cover measured phase plus late terminal requests. BPF throughput is not performance acceptance.

Untraced three rotated 8s close measurements, 2s warmup, frozen accept-address epoll baseline, matched upstream policy, serial frontends:

| Median | Baseline epoll | Coalescing epoll | nginx 1.29.7 |
| --- | ---: | ---: | ---: |
| RPS | 25571 | 32077 | 27334 |
| p99 ms | 11.977 | 5.169 | 7.141 |

About 25.4% higher throughput than baseline and 1.174x nginx for this narrow 1KiB short-connection workload. Does not establish 1.5x nginx or generalize to all payloads. One keepalive control: baseline 66255/p99 2.147ms, candidate 66222/2.174ms, nginx 60226/2.354ms. All 12 cells and response preflights error-free; keepalive path unchanged by this experiment.

Validation: Release build and test_network/test_splice/test_ws_tunnel_iouring/test_cli_backend passed. Prior accept-address changes passed clang-tidy-22 with existing warnings; this step adds only the per-shard flag/counter. Changed-file clang-format-22 and diff checks passed. Full sanitizer/GCC/remote CI not run.

Nginx comparison sources, reviewed at release-1.29.7:
- https://github.com/nginx/nginx/blob/release-1.29.7/src/os/unix/ngx_writev_chain.c : coalesces output into iovec and writev, handles partial progress. Rut's retained experiment uses existing owned-buffer coalescing, not an imported implementation.
- https://github.com/nginx/nginx/blob/release-1.29.7/src/http/modules/ngx_http_upstream_keepalive_module.c : preserves idle read handling and invokes MSG_PEEK on ready events, rather than always probing each borrow. Next candidate needs stable upstream transport ownership and correct unexpected-data/FIN handling before reducing registration churn.

Raw results/logs/configs/binary hashes/source snapshot: /home/hurricane/private/code/rut-performance-checkpoints/epoll-coalesce-close-20261010.
