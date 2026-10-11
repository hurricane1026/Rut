# Accept returns the IPv4 peer without a second syscall

Epoll accept4 now fills a sockaddr_in and copies the actual IPv4 address/port into its IoEvent. The accept callback uses the event payload instead of getpeername. Unsupported/legacy producers retain the getpeername fallback. The payload owns its values, so later accepts cannot overwrite an earlier event. IoEvent remains 48 bytes (both original and candidate measured); connection size is unchanged. Non-accept events leave fields neutral; strict ResponseReadTimer validation requires them neutral too.

Real TCP test queues two clients, saves both accepts, and verifies each event against the peer of its accepted socket. Full related network, splice, native io_uring and CLI tests pass; changed-file format and diff checks pass. clang-tidy-22 completed with existing warnings; full sanitizer/GCC/macOS/CI checks not run.

BPF 1KiB proxy-close, 128 clients, one frontend core, four pinned origins: 115384 completed requests, 115513 accept4 calls, zero frontend getpeername, no syscall errors or BPF loss warnings. Window includes terminal outstanding requests; trace throughput is diagnostic only.

Untraced 3 rotated close runs, 8s measurement + 2s warmup, prior ADD-first epoll frozen baseline:

| Median | Baseline | Candidate | nginx |
| --- | ---: | ---: | ---: |
| Close RPS | 25021 | 25187 | 26466 |
| Close p99 ms | 12.052 | 10.402 | 8.875 |

One keepalive control: baseline 66288 / p99 2.127ms, candidate 64652 / 2.182ms, nginx 60325 / 2.340ms. That single control does not establish a regression; this optimization amortizes away on persistent connections. All 12 cells/preflights error-free. Retain for eliminating one redundant syscall per accepted IPv4 connection, not a claim of significant throughput improvement or achieving 1.5x nginx.

Full data/binary hashes/configs/logs at /home/hurricane/private/code/rut-performance-checkpoints/epoll-accept-peer-20261010.
