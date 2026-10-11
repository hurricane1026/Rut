# Plaintext WebSocket bidirectional splice experiment

One frontend worker on CPU 2, 128 persistent connections, four origin workers on CPUs 3,4,8,9, clients on CPUs 5,7. Serial runs, 2 s warmup + 8 s measurement, three repetitions. Frozen candidate binary toggles RUT_STUDY_WS_SPLICE=on/off. All 30 confirmation measurements are valid with zero payload errors. Both modes use TCP_NODELAY.

## Results (three-run medians)

|Payload|Engine/path|Received application MiB/s|Message RTT p99 ms|Frontend CPU % of one core|
|---|---|---:|---:|---:|
|websocket-interactive-64|uring splice off|5.3|2.093|62.2|
|websocket-interactive-64|uring splice on|5.3|2.063|62.4|
|websocket-interactive-64|epoll|5.0|2.072|61.4|
|websocket-interactive-64|nginx|5.2|2.086|55.9|
|websocket-bulk-64k|uring splice off|339.8|24.341|65.1|
|websocket-bulk-64k|uring splice on|687.5|12.701|28.2|
|websocket-bulk-64k|epoll|530.1|18.966|70.1|
|websocket-bulk-64k|nginx|675.3|12.677|57.8|

64 KiB io_uring: throughput +102.3%; RTT p99 -47.8%; frontend CPU 65.1% -> 28.2%. nginx median difference +1.8%, but observed rate ranges overlap, so this demonstrates comparable throughput, not a reliable nginx win. Small-message medians are effectively unchanged and ranges overlap.

## Implementation and eligibility

io_uring supplies one-shot readiness polls; synchronous nonblocking splice moves socket -> pipe -> socket. This is not IORING_OP_SPLICE and does not use SEND_ZC. Two independent directions each own a pipe, buffered byte count, readiness target and cancel ledger. Each progress pass applies the configured syscall budget across all owners and directions; queued IDs and a per-owner direction cursor carry unfinished work forward in FIFO order. Admission has a separate one-owner-per-pass budget. That fixed setup unit includes both pipe creation attempts, pipe sizing/capacity queries, optional TCP_NODELAY setup, and fallback receive submissions after pipe failure. The sender drains the pipe before more input is pulled.

Admission uses actual successful upgrade and neutral receive/send owners. Existing user-space prefix bytes drain through original callbacks before takeover. Plaintext HTTP/1.1 transparent tunnels only: TLS, inspection/terminate routes, throttle and response-policy configurations retain the original path. Each connection requires two pipes (four extra descriptors); pipe creation failure falls back before consuming socket bytes. Pipe growth is best-effort. The first EOF is terminal for the tunnel: both reads stop, bytes already buffered in either pipe drain, and the connection closes after poll/cancel ownership retires. New reverse-direction data after that EOF is not forwarded. Close cancels exact episode/direction poll tokens; an owner pin prevents slot reuse until target/cancel retirement.

The experiment is disabled by default and only enabled in the study branch by RUT_STUDY_WS_SPLICE=on. No production CLI or language keyword was added. epoll comparator retains its existing copy path.

## Verification and limitations

Native tests cover full duplex >64 KiB bursts, slow readers, closing with polls, first-EOF termination after buffered bytes drain, buffered-prefix handoff, descriptor-limit pipe failure fallback, and TLS/inspection/throttle exclusion. Existing splice regression and 40 benchmark-tool tests pass. Protocol preflight covers upgrade, binary fragmentation, ping/pong and close. Full CI, SQ-saturation cancellation fault injection, RST injection, TLS-offloader integration, higher connection counts and other cores/concurrency still require validation before production promotion.

The candidate/, candidate-final/, and failed-startup-readiness-race/ artifact directories and their source/binary/harness evidence were not retained with this checkout. The measured numbers and provenance cannot be independently audited from the available artifacts; no claim is made here that a particular preserved binary produced them. No timed measurement is represented for the failed startup preflight.

An earlier startup-preflight race was reported: the listen socket was connectable before shard initialization logging completed. Its failed-startup-readiness-race/ evidence was not retained. The harness now waits for complete runtime readiness; no timed measurement ran for that failed startup.
