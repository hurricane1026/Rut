# Synchronous request-policy validation reuse experiment

Default-off epoll flag: `RUT_STUDY_REQUEST_POLICY_VALIDATION_REUSE=on`. Ordinary synchronous Forward admission already obtains Complete from inspect_request_policy_body. For ID1, legacy pipeline ownership and no response-read-deadline state, proceed directly to the existing materialization body without repeating that inspector. No callback, I/O or byte/state mutation lies between Complete inspection and the new continuation call. The result lives only on the current stack: no URL history, prediction or persistent connection cache.

Public apply_request_policy still validates every request. Its host-preserve branch stays unchanged. Other policy IDs, asynchronous body completion, retries, deadline custody and nonlegacy pipeline paths retain original checking. Materialization itself still reparses and checks serialization boundaries, scratch capacities and pipeline suffix preservation. No allocator, Connection-size or IoEvent change. io_uring/kqueue do not have the experiment field and retain the validating call.

BPF entries on enabled 1 KiB persistent proxy load: inspector 261,336; HttpParser parse 1,045,344, exactly 1 inspection and 4 parses per policy request, compared to 2 and 5 before. Public apply_request_policy probe has zero entries for the eligible path. Trace duration 5s plus tail; counts are diagnostic, not performance numbers.

Three uninstrumented rotations, serial off/on/nginx, same candidate binary: one frontend CPU 2, four origins CPUs 3,4,8,9, 128 clients CPUs5,7, 1 KiB HTTP persistent responses, 8s load plus 2s warmup. Native origin reuse/omit-connection, nginx1.29.7 multi_accept on/buffering off; both Rut variants coalesce on, accept batch16, stable upstream on. No builds, tests or probes ran during timed cells.

| Median | Off | On | nginx |
|---|---:|---:|---:|
| Requests/s | 77,105 | 78,861 | 58,446 |
| p99 milliseconds | 2.514 | 2.464 | 2.384 |

On/off median +2.3%; paired changes +0.24%, +2.29%, -0.14%. This is a small noisy candidate, not evidence of a robust large improvement. Rut on is about1.35x nginx in this campaign, not the1.5x target. No short-connection or bulk acceptance claim for this change. All nine cells, preflight and warmup report zero errors.

Validation: test_network, test_splice, test_ws_tunnel_iouring, test_cli_backend all pass; affected clang-format22 check and git diff --check pass. Additional real TCP on/off checks cover ordinary GET, fragmented Content-Length body (no response before remainder), duplicate Content-Length, chunked upload and Expect; expected200/200/400/400/400 results and body lengths match. Existing relay preflight also verifies downstream wire and origin socket reuse, including slow-read behavior. Sanitizers and remote CI were not rerun for this incremental callback change.

Reproduction and complete logs/binaries/configuration/source patch: /home/hurricane/private/code/rut-performance-checkpoints/epoll-policy-reuse-20261010. Experiment retained default-off. Next opportunity is passing the already parsed request into materialization or metadata capture; audit all nonowning views and mutations before doing so.
