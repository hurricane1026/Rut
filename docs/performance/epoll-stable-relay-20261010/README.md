# Stable epoll relay registration experiment

User priority: reduce syscalls first. SIMD deferred to https://github.com/hurricane1026/Rut/issues/788 . Default-off RUT_STUDY_EPOLL_STABLE_RELAY=on requires RUT_STUDY_EPOLL_STABLE_UPSTREAM=on. No dependencies, heap-on-I/O, prediction or Connection size change.

UpstreamRecv and RelayRead both need EPOLLIN. Extend the existing stable socket identity with a relay_read mode bit in its former padding; translate raw readiness to the existing public IoEvent based on explicit current ownership/mode. Mode switch increments owner version so old harvested records are discarded. Ordinary receive still waits for submission, relay readiness validates current episode/fds/phase, EOF and error go through existing relay handling. Writing/EAGAIN still parks the upstream with the original mask change; downstream masks and backpressure,64KiB pipe chunks and four-syscall owner budget remain unchanged. No inline completions or new IoEvent enum.

Also use the existing fd-interest cache to choose MOD for a recorded registration and ADD otherwise when creating a stable registration. Keep ENOENT/EEXIST opposite-operation recovery. This removes cold/reactivation ADD/EEXIST retries without trusting cache as infallible.

Initial BPF 1MiB persistent proxy: epoll_ctl5.0418 ->2.0349/request (-59.6%); splice32.1407 ->32.108, epoll_wait0.6361 ->0.6323. Final cache-aware on trace confirms epoll_ctl2.032/request with no epoll_ctl errors. Final same-binary off trace: epoll_ctl5.0358/request,also no registration errors; on2.032 is a59.6% reduction. The1KiB guard has no new relay calls and preserves its low-control-call path; see final-syscall-summary.json. All final traces/preflight/warmup/load have zero harness errors and no BPF helper/lost-event diagnostics. BPF includes short measurement-tail shutdowns, so receive/send/splice errors can occur after clients terminate despite zero load errors; BPF throughput is not acceptance evidence.

Uninstrumented campaign BEFORE the final cold/reactivation selector: three8s rotations+2s warmup, serial same-binary off/on/nginx,1MiB persistent HTTP proxy,128clients,one frontendCPU2,four origin workersCPUs3,4,8,9,clientCPUs5,7,transparent upstream policy,buffering off,nginx1.29.7 multi_accept on. Both Rut variants stable upstream on,accept batch16. Metadata and policy-parse experiments remain off.

| Median | Off | On | nginx |
|---|---:|---:|---:|
| RPS |4362|4330|3965|
| p99 ms |31.389|31.512|37.025|

Throughput-0.73%,p99+0.39%,paired RPS changes fluctuate; performance is effectively similar in this screen, not an established throughput win. Retain the syscall reduction as a default-off candidate, do not claim universal1.5x nginx. Final selector was applied after this campaign; exact final-binary uninstrumented performance is not claimed.

Final4 Release CTests(test_network,test_splice,test_ws_tunnel_iouring,test_cli_backend),ASan+UBSan no-JIT Debug test_splice(no LSan),affected clang-format22 and diff checks pass. Real socket relay test verifies unchanged kernel token,retired old-mode readiness,readiness-only RelayRead without consuming response bytes,and return to ordinary receive. Existing tests cover fd reuse,version exhaustion,registration errors,partial writes,close and idle transport rejection. Large campaign/trace preflight verifies response integrity,slow reads and origin reuse. Source/binaries/full logs: /home/hurricane/private/code/rut-performance-checkpoints/epoll-stable-relay-20261010.
