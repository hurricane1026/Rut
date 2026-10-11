# Stable epoll upstream socket identity

Keep the experiment behind `RUT_STUDY_EPOLL_STABLE_UPSTREAM=on`. A readable upstream socket uses an internal kernel token identifying its descriptor and registration generation, while a shard-local record identifies its current request owner and upstream episode. Normal pooling retires request ownership and installs an idle owner without deleting the socket watch. Borrowing still calls the existing MSG_PEEK liveness/surplus probe, then claims a new owner without changing the kernel token. Public IoEvent completions retain their existing connection/episode semantics; io_uring is unchanged.

This removes healthy per-request DEL/ADD, not the borrow probe. Idle readability triggers a peek and rejects EOF, unexpected data or errors. Pool close/sweep/reload invokes an unregister hook before closing; shutdown clears the hook before destroying backend state. Requests cannot consume response bytes before a receive is submitted. Partial-send/write-interest, pause, relay polling, exhausted versions and out-of-range fds use the existing full registration path.

Two independent fences protect reuse: registration generation rejects an old socket/token, and owner version rejects readiness harvested for a previous request owner. Retaining a watch also preserves the legacy detach's cache-generation fence for BOTH sides of the connection, including downstream readiness. The initial prototype lacked this downstream fence; it was fixed and the primary performance campaign rerun. Do not substitute the earlier prototype campaign's higher ratios for the final results below.

State is per shard using existing MappedArray, approximately 1.5 MiB for 65536 fd records when enabled. No Connection fields or hot-path allocation are added. Fds >=65536 fall back to legacy handling. Pool entries remain endpoint-keyed; hot reload still drains idle connections and existing request-config admission checks remain intact.

## Final untraced results

Final fence-preserving runtime, same binary with experiment off/on; 1KiB plaintext native HTTP proxy, 128 clients, single frontend core, four pinned nginx origin workers, matched explicit upstream persistence policy. Three rotated measurements per mode (8s + 2s warmup), serial frontends. Both Rut cells enable prior coalescing/accept16 studies; nginx explicitly enables multi_accept on.

| Median | Stable off | Stable on | nginx 1.29.7 |
| --- | ---: | ---: | ---: |
| Keepalive RPS | 66408 | 79699 | 62017 |
| Keepalive p99 ms | 2.126 | 2.488 | 2.546 |
| Close RPS | 35512 | 38024 | 33854 |
| Close p99 ms | 3.774 | 3.682 | 3.969 |

Keepalive improves about 20%, about 1.285x nginx. p99 increases about 0.362ms versus off, and is slightly below this nginx comparator. Close improves about 7%, about 1.123x nginx. All 18 measured cells, warmups and response preflights have zero load errors. This is local evidence, not a statistical/all-workload proof; 1.5x nginx is not achieved.

Final raw syscall audit is separate from these untraced numbers:

| Per-request epoll_ctl | Prior optimized backend | Stable on |
| --- | ---: | ---: |
| Keepalive | about 2 | 0.0004 |
| Close | about 3 | 1.0008 |

No epoll_ctl errors or BPF loss warnings in final retained traces. Borrow MSG_PEEK still costs about one EAGAIN/request. Trace window excludes warmup but includes late outstanding completions, so normalized counts are approximate. BPF overhead changes throughput; never use traced RPS as performance acceptance.

## Bulk controls and limits

Single-run preliminary controls at 100KiB and 1MiB covered both omit-connection and transparent request-policy routes, before the final downstream-fence correction. These are development screens, not final bulk acceptance or a reason to generalize the 1KiB result. All 12 cells/preflights passed without load errors. 100KiB throughput improved 6–9% but remained below nginx; 1MiB was approximately unchanged (about -0.5% to +1.1%). Splice is VERIFIED by the transparent 1MiB BPF trace: about 32.15 splice calls/response, pipe2/fcntl once per persistent connection. That path still has about five epoll_ctl calls/response because relay polling changes interest; stable identity does not yet eliminate that churn. Header/request policy alone is not proof that splice is disabled.

## Validation and reproduction

Release runtime build; test_network, test_splice, test_ws_tunnel_iouring and test_cli_backend passed. Nine new real-socket stable-event tests cover transfer, delayed receive enablement, harvested old owner, idle FIN/data, borrow probe/reload, generation mismatch, exhausted owner version, registration failure, actual fd reuse and partial-write recovery (FIN/data and probe/reload each contain multiple cases).

A separate Debug, no-JIT ASan+UBSan runtime/test_splice build passed, including the stable cases and existing splice suite. Environment matches CI: ASAN_OPTIONS=halt_on_error=1:detect_leaks=0, UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1. LeakSanitizer was not enabled. Changed-file clang-format-22 and diff checks passed. clang-tidy-22 completed with residual existing naming/include/const warnings; this is not a clean whole-repository tidy claim. Full sanitizer network suite, GCC, macOS and remote CI were not run.

Enable the measured experimental combination:

```bash
RUT_STUDY_HTTP_COALESCE_CLOSE=on \
RUT_STUDY_EPOLL_ACCEPT_BATCH=16 \
RUT_STUDY_EPOLL_STABLE_UPSTREAM=on \
build/src/rut your-config.rut --backend epoll
```

All three remain development opt-ins; stable identity is not silently enabled in production defaults. No language keywords, external dependencies, merge or deployment were added.

Final raw results/configs/logs/frozen binaries/source snapshot: `/home/hurricane/private/code/rut-performance-checkpoints/epoll-stable-upstream-fence-20261010`. Earlier prototype, bulk and splice screens live in neighboring `epoll-stable-upstream-*` checkpoints. Final style cleanup used direct type/event headers, constant names and an explicit bounded fd cast. Latest .text is byte-identical to the measured binary; .rodata differs only in the 64-byte generated native build fingerprint. Both hashes and the final source diff are in final-validation-source.json; the exact measured binary remains archived.

Next work: profile remaining CPU/queue costs and examine idle-event-driven validation separately. Do not delete MSG_PEEK merely because normal runs return EAGAIN: the borrow-before-idle-dispatch test demonstrates its protection of pending unexpected bytes.
