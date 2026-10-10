# Prefer ADD for unrecorded epoll registrations

Keep the optimization: select MOD when the existing per-side FdInterest record matches the fd; otherwise try ADD. Recover MOD/ENOENT with ADD and ADD/EEXIST with MOD. Invalidated cache entries are not proof of kernel absence. Identical recorded interest still skips the syscall; registration errors still invalidate the cache and propagate the same error. No connection fields, allocation, policy prediction or backend dispatch changes.

The actual-socket network test invalidates a live registration, replaces its kernel token, and verifies ADD/EEXIST recovery restores the current owner. Existing tests cover fd/slot reuse, stale harvested readiness and upstream episode/detach boundaries.

BPF syscall validation, 1KiB plaintext proxy, 128 clients, one frontend core and four pinned origin workers:

| Per-request epoll_ctl | Before | After |
| --- | ---: | ---: |
| Downstream close | 5.006 | 3.003 |
| Keepalive | 3.003 | 2.002 |

Before, failed MOD/ENOENT costs roughly twice per close request and once per keepalive request. After, both traces report zero epoll_ctl errors and no BPF stderr/loss warnings. BPF changes scheduling; these are syscall counts, not acceptance throughput numbers. The window includes late outstanding completions, so per-completed-request ratios are approximate. The remaining ADD/DEL pair includes upstream detach/rebind ownership and must not be removed without protecting stale events and fd reuse.

Untraced three rotated runs per mode (8-second measurement, 2-second warmup), frozen pre-change binary vs candidate vs nginx 1.29.7, same upstream persistence policy and serial frontends:

| Median | Before epoll | Candidate epoll | nginx |
| --- | ---: | ---: | ---: |
| Keepalive RPS | 64,382 | 65,000 | 59,848 |
| Keepalive p99 ms | 2.162 | 2.139 | 2.324 |
| Close RPS | 25,254 | 25,049 | 26,667 |
| Close p99 ms | 12.081 | 10.835 | 9.440 |

All 18 cells and response preflights passed without load errors. Keepalive throughput median improves about 1%; close throughput median is about 0.8% lower, with improved p99. Small local samples do not prove statistically significant throughput gains or regressions. Retain for measured syscall reduction and preserved recovery behavior, not a claim of reaching 1.5x nginx.

Validation: Release build; test_network, test_splice, test_ws_tunnel_iouring and test_cli_backend passed; changed C++ files clang-format-22 and git diff --check passed. clang-tidy-22 on epoll_backend.cc completed with existing warnings (including unrelated header/compiler and const-correctness diagnostics); no full-repository tidy/ASan/GCC/remote CI run.

Complete binary hashes, source diff, configs, logs, untraced result rows and BPF per-process raw maps are archived at /home/hurricane/private/code/rut-performance-checkpoints/epoll-add-first-20261010. Scripts here reproduce the original local campaign paths; no new external dependency. Baseline contains the earlier io_uring experiments, all disabled for these epoll comparisons. Candidate also includes the separately tested io_uring half-close patch, which does not affect epoll.
