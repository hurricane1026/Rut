# Route workload performance policy — proposal

Status: design notes, not an implemented language feature. Existing `workload(bytes:)` generates synthetic test responses and does not select runtime strategy. Do not use invented DSL syntax as supported configuration. Follow the language card and Swift-exact constraints before implementing syntax.

User goal: at least 1.5× tuned nginx throughput with reasonable tail latency. Choose policy by declared route semantics, without response-size prediction or per-URL history.

| Declared workload | Primary objective | Candidate controls |
| --- | --- | --- |
| API | Small response tail latency and RPS | Short CQ wait, bounded bulk turns, prompt ordinary submissions |
| Bulk transfer | Sustained byte throughput | Larger splice segments for eligible cleartext, larger byte budgets |
| Streaming | Prompt progress and fairness | Bounded chunks, prompt flush, backpressure |
| WebSocket | Bidirectional message latency and throughput | Existing tunnel callbacks and eligible cleartext splice; independently tested TCP_NODELAY |

Connection persistence is an independent explicit protocol policy, not inferred from workload. A downstream `Connection: close` may coexist with persistent upstream HTTP/1.1 only when the request is rewritten appropriately and response framing and downstream close behavior remain correct. Existing request_policy can express the narrow header-only rewrite. Transparent forward preserves current behavior. TLS, chunked framing, upgrade, cancellation and unsupported shapes retain their validated paths.

Implementation direction: compile the route declaration to an immutable configuration entry in the shard config epoch. At route selection, select callbacks/strategy and limits; reuse them through that request. Avoid a second container for every workload or repeated string classification per I/O. A request must hold its config epoch for asynchronous work. A keepalive connection may visit a different route on its next request: refresh request policy then, rather than permanently classifying the connection by its first URL.

Accept occurs before route identification. Accept, peer-address acquisition, initial buffers and safe close/reclaim need common runtime optimization; a route declaration cannot remove their cost retrospectively. Existing io_uring accept is already multishot. Avoid adding per-connection copies of policy tables; account for any handle storage and lifetimes explicitly.

Evidence from 2026-10-10 pure proxy campaign: short downstream preflights show distinct origin IDs for transparent Rut and the same origin ID for nginx configured to omit Connection. Hence that comparison includes different upstream connection churn. The matched request-policy experiment must prove reuse for both before interpreting residual backend cost.

A separate 100KiB persistent io_uring test times out even with the new queue/chunk/yield experiments disabled. This correctness/tail issue must be resolved before declaring the general policy ready or promoting defaults.
