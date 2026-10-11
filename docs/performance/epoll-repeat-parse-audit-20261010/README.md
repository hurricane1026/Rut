# Repeated request parsing audit

Current experimental epoll Release binary, 1 KiB persistent proxy response, 128 clients, one frontend core, four origin workers, explicit request policy ID1. Same coalesce/batch16/stable-upstream settings as preceding CPU sample. bpftrace uprobes count actual out-of-line entries; load duration 5s plus 3s tracer tail. No runtime source changes.

| Function | Entries | Entries per policy application |
|---|---:|---:|
| apply_request_policy | 254,577 | 1 |
| inspect_request_policy_body | 509,154 | 2 |
| HttpParser::parse | 1,272,885 | 5 |

Completed client requests: 254,451. The 126 extra applications reflect in-flight/measurement-tail requests; ratios use actual application count rather than completed requests. Preflight and warmup excluded; zero request errors, no BPF helper errors or stderr warnings. Uprobes substantially change throughput and these measured RPS/p99 are not acceptance numbers.

Source confirms ordinary Forward handling calls inspect_request_policy_body, then apply_request_policy calls that inspector again before its own HttpParser invocation. Thus three of the five parse calls are directly explained by this policy sequence; remaining parse callers should be attributed before attempting broader parser reuse.

Candidate 1: preserve existing public apply_request_policy entry as self-validating; introduce internal materialization with a local validated proof only for ordinary synchronous forwarding. Prove input byte extent/address, request framing, policy ID and relevant connection state unchanged since admission. There is backend selection between validation points but no async wait on the Complete path. Waiting-body, retry, direct callers, deadline/pipeline custody and host-preserve paths retain their validation until independently audited. Do not persist a bare validated bool across requests or add per-URL prediction. This can remove a second inspector plus parse, but must keep every original rejection and failure timing.

Candidate 2: EpollEventLoop::poll_command performs three acq_rel exchanges every iteration even with empty control slots. Acquire-load before exchange could reduce empty-slot RMW traffic while leaving exchange and producer release-store synchronization on nonempty slots intact. Updates arriving after a null load are seen next iteration, as updates arriving after current exchange already are. Capture disable sentinel/retry, config drain/health re-arm and shutdown delivery need tests; avoid unrelated timer changes. CPU sample attributed 119/19,929 samples (0.6%) directly to poll_command, so this is a smaller candidate, not a promised large gain.

Candidate 3: parsed-request reuse for metadata/policy serialization. First attribute the other two parse calls and audit transformations, nonowning path/header views, incomplete body, pipelining, hot reload and direct-RIR inputs. Avoid putting a large ParsedRequest in every connection; local proof/value passing is preferable when lifetime allows it.

Prioritize candidate 1 with malformed Content-Length, transfer-encoding, Connection nomination, Expect/Upgrade, fragmented bodies, route rewrites and pipeline tests. Measure same-binary on/off then tuned nginx serially, with BPF counts separate from untraced performance. No performance gain or code implementation claimed yet. Full reproducible artifacts: /home/hurricane/private/code/rut-performance-checkpoints/epoll-repeat-parse-audit-20261010.
