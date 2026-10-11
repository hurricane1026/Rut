# Stack-local request parse reuse experiment

Default-off epoll flag: RUT_STUDY_REQUEST_POLICY_PARSE_REUSE=on. It includes previous synchronous validation reuse for the same narrow ID1 / legacy request ownership / no response-read-deadline path. The previous validation-reuse flag stays independent. io_uring and kqueue keep their original self-validating path.

The inspector publishes a small stack-local RequestPolicyParseWitness only when admission is Complete: original buffer address and extent, header boundary, non-owning raw target, Content-Length and presence. Materialization checks source/extent/header bounds and ID1, then uses these fields instead of invoking HttpParser again. Raw policy validation is preserved; the materializer still scans and rewrites headers into its existing scratch storage, checks capacity and framing, and preserves any successor suffix. No whole header-table copy, persistent cache, prediction, connection layout change or hot-path heap allocation. Views are consumed synchronously before recv_buf reset. Their address/extent check is not a content hash; safety depends on the proven absence of intervening mutations/callbacks/I/O. Async waiting-body, retry and other entry points never retain this witness.

BPF on enabled persistent 1 KiB workload: inspector282,131; HttpParser846,393, exactly1 inspection /3 parses. Previous validation-only path is1 inspection /4 parses; original was2 /5. Probe throughput is diagnostic only.

Three uninstrumented rotations, same binary with validation-reuse on for both variants; parse-reuse off/on then tuned nginx in rotated order, strictly serial. One frontendCPU2, four origin workersCPUs3,4,8,9,128clientsCPUs5,7,1KiB HTTP persistent response,8s load+2s warmup, coalesce on/accept batch16/stable upstream on. nginx1.29.7 multi_accept on, buffering off, origin reuse enabled and explicit omit-connection request policy retained. No builds/tests/probes during timed cells.

| Median | Validation only | Parse reuse | nginx |
|---|---:|---:|---:|
| RPS |79,682|79,953|58,623|
| p99 ms |2.430|2.463|2.490|

Paired RPS deltas -0.59%,+0.09%,+0.34%; median+0.34%, median p99+1.36%. This does not establish a meaningful performance gain. Retain as a default-off research candidate; do not promote solely because parse count decreased. Overall CPU was dominated by kernel/network in the previous profile. Absolute results from earlier campaigns must not be added to these percentage gains. All9cells have zero request/preflight/warmup errors.

Release tests: test_network,test_splice,test_ws_tunnel_iouring,test_cli_backend pass. Added2 meaningful witness tests verify exact query/header output, rejected buffer/extent mismatch without request mutation, and no witness publication for waiting/invalid requests. TCP off/on controls match7cases: ordinary GET, incomplete body/no early response, complete body, CL0, identical duplicate Content-Length, chunked upload, Expect (200/200/200/200/400/400/400). Existing benchmark preflight additionally validates slow-read and origin reuse. Affected clang-format22 and diff checks pass. ASan+UBSan no-JIT Debug test_splice also passes, including both new witness tests; ASAN_OPTIONS=halt_on_error=1:detect_leaks=0, UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1; full remoteCI,GCC/macOS and leak detection not exercised.

Scripts, raw logs, configs, candidate sibling binaries and source snapshot: /home/hurricane/private/code/rut-performance-checkpoints/epoll-policy-parse-reuse-20261010. Remaining candidate: reuse initial admission parser result for capture_request_metadata, which currently invokes HttpParser again; preserve malformed-method fallback and capture/accounting semantics before implementation.
