# Rut ET versus nginx: eBPF comparison — 2026-10-11

Frozen Rut candidate: `epoll-et-stable-20261011/candidate`, full ET + stable upstream on, accept batch 16 and bounded 32-I/O accept service, coalesce-close/validation-reuse on; direct-close/initial-recv-once off. nginx 1.29.7 multi_accept on, buffering off, 16 KiB buffers. HTTP 1 KiB proxy, C128, frontend CPU 2, four origins CPUs 3/4/8/9, clients 5/7. Rut/nginx run strictly serially, no concurrent builds/tests. No runtime implementation changed in this comparison.

Syscall tracing: 5 s measurement plus up to 3 s tail; CPU profiling separately: 997 Hz for 20 s load plus idle tail. Warmup/preflight excluded. All eight diagnostic cells valid, zero warmup/load errors; no BPF stderr warnings or lost-event/helper errors observed. Instrumented rates are not untraced performance acceptance evidence.

## Syscalls per completed request

| Syscall | Rut ET close | nginx close | Rut ET keep-alive | nginx keep-alive |
|---|---:|---:|---:|---:|
| recvfrom | 3.0022 | 2.0013 | 3.0017 | 2.0016 |
| sendto / writev | 2.0014 | 2.0011 | 2.0009 | 2.0010 |
| epoll_ctl | 1.0008 | 2.0018 | 0.0004 | 0.0012 |
| epoll_wait | 0.1301 | 0.0282 | 0.1255 | 0.0164 |
| accept4 | 1.0040 | 1.0288 | 0.0008 | 0.0010 |
| close | 1.0008 | 1.0015 | 0.0004 | 0.0005 |
| getsockopt | — | 1.0014 | — | 1.0005 |

Dash means not a material measured frontend count. Frontend epoll_ctl errors zero. Rut short connections add the downstream watch once; stable pooled upstreams no longer cause DEL/ADD per request. nginx performs an ADD and MOD per short connection. Rut's extra recvfrom is the EAGAIN MSG_PEEK probe in UpstreamPool::take_idle, preserving rejection of EOF or unsolicited idle bytes. Removing it requires a replacement correctness argument/tests, not just fewer syscalls.

Rut's 16-record kernel harvest batch and approximately two read-ready records/request explain the roughly 0.125 epoll_wait/request at C128. nginx amortizes waits over more events in this workload. The measured count alone does not establish nginx's effective configured batch size or guarantee gains from increasing Rut's batch. Any batch experiment must preserve bounded accept admission and callback fairness rather than increasing their quotas unintentionally.

Raw syscall elapsed spans include blocking, scheduling, idle tail and Rut's signal-wait thread. In particular aggregate epoll_wait/rt_sigtimedwait elapsed must not be presented as CPU utilization or request latency. Separate on-CPU samples below avoid that error. sendto and writev have different APIs but both have approximately two frontend send syscalls per request here.

## Frontend on-CPU samples

Percentages use all frontend on-CPU samples as denominator. Kernel stack categories use up to eight frames and exclude work outside frontend TGIDs; softirq executed in frontend context is included. User stacks retain one instruction frame; unresolved libc addresses/inlining limit attribution. Ratios between percentages are not relative CPU cost per completed request because frontend throughputs differ.

| Category | Rut ET close | nginx close | Rut ET keep-alive | nginx keep-alive |
|---|---:|---:|---:|---:|
| Total samples | 19,864 | 19,894 | 19,943 | 19,948 |
| User mode | 25.5% | 22.5% | 22.1% | 29.6% |
| Kernel mode | 74.5% | 77.5% | 77.9% | 70.4% |
| TCP sendmsg stack | 11.4% | 11.7% | 16.8% | 15.4% |
| TCP recvmsg stack | 3.0% | 2.4% | 5.3% | 4.2% |
| epoll stack | 3.7% | 5.0% | 2.0% | 1.3% |

Rut keep-alive EpollBackend::wait instruction-frame samples are 238 (1.19% total); short connections 190 (0.96%). Short-connection user hotspots include memset (928, 4.67%) and response-header building/copying lambda (625, 3.15%); persistent requests distribute user work across parsing, policy, dispatch and memcmp. These one-frame samples identify further attribution targets, not proof that every memset is redundant.

The ET registration optimization already removes a cost nginx still pays on short connections. Larger harvest batches are a bounded experiment, but epoll is a modest fraction of CPU and cannot alone plausibly deliver the 150% throughput target. Follow-up should inspect syscall batching, send/packet processing and short-connection initialization/header copies while preserving protocol semantics and p99.

## Artifacts

Compact frontend summaries and local reproduction scripts are alongside this file. Scripts depend on existing `/tmp/rut-syscall-audit` and `/tmp/rut-cpu-profile` harness copies; they are local provenance, not standalone portable tools. Raw configurations, trace programs, process identities, syscall maps, CPU stacks and preflight/load logs remain in:

- `/home/hurricane/private/code/rut-performance-checkpoints/epoll-et-nginx-bpf-20261011/{proxy-close,proxy-keepalive}`
- `/home/hurricane/private/code/rut-performance-checkpoints/epoll-et-nginx-profile-20261011/{proxy-close,proxy-keepalive}`

This comparison covers 1 KiB plaintext proxy only, not large responses, TLS, static files, WebSocket or multi-shard performance. No commit/push/merge performed.
