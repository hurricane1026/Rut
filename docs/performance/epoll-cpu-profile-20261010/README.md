# Epoll CPU sampling, 2026-10-10

997 Hz bpftrace on-CPU profile, 20 seconds load after 2 seconds warmup. Rut and nginx ran serially. Plaintext HTTP proxy, 1 KiB response, 128 persistent clients, one frontend CPU 2; four pinned origin workers on CPUs 3,4,8,9, clients on CPUs 5,7. Rut uses coalesce-close on, accept batch 16, stable-upstream on. nginx 1.29.7 uses multi_accept on. Original request policy omit-connection and buffering off retained.

| On-CPU samples | Rut | nginx |
|---|---:|---:|
| Total | 19,929 | 19,941 |
| User mode | 21.4% | 29.1% |
| Kernel mode | 78.6% | 70.9% |
| Kernel stack includes TCP sendmsg | 17.5% | 14.9% |
| Kernel stack includes TCP recvmsg | 5.3% | 4.1% |
| Kernel stack classified epoll | 2.2% | 1.4% |
| Kernel stack includes nft / conntrack / nf_hook | 20.7% | 17.9% |

Percentages use all frontend on-CPU samples as denominator. Firewall category overlaps send/receive/other; do not add it to those categories. Network work in frontend context includes softirq processing; origin/client processes and work performed asynchronously outside frontend TGIDs are excluded. Eight-frame kernel stacks may omit deeper ancestry. User sampling records only the instruction frame, avoids requiring frame-pointer unwinding; inlined callers and unresolved addresses are not attributed further.

Rut user hotspots are distributed across HTTP parsing, memcmp, wait/dispatch, request policy, metadata and control polling; no single event queue hotspot dominates this run. Epoll wait user function is 203 samples (1.0%), dispatch 195 (1.0%), poll_command 119 (0.6%). Kernel sending and packet processing are stronger candidates than queue restructuring alone. The firewall cost is shared benchmark environment overhead; no firewall configuration was changed.

Both final traces have no helper errors, lost-event records or stderr warnings; preflight, warmup and load errors are zero. Earlier pilots had insufficient stack-map capacity and are excluded. The final map capacity is 65,536. Profiled throughput (75,101 vs 57,786 RPS) is diagnostic only, not a new uninstrumented acceptance benchmark. Default production settings and runtime source were unchanged.

Full logs, configurations, trace programs, process IDs and response preflight artifacts: `/home/hurricane/private/code/rut-performance-checkpoints/epoll-cpu-profile-20261010/results`. Scripts use existing absolute harness paths; run under the docker group via sg docker and the authorized sudo bpftrace command. Raw trace filenames retain syscalls.jsonl from the reused harness but contain CPU profiles, not syscall counts.
