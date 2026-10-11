# Epoll scatter/gather sending research

## Evidence and applicable paths

The current 1 KiB persistent native-streaming benchmark does not rewrite response headers. `on_upstream_response` sends the original header and available body from contiguous `upstream_recv_buf`, reaching `on_proxy_response_sent` when Content-Length is complete. The preceding syscall audit recorded 2.0008 frontend sendto calls per request: upstream request plus downstream response. They use different sockets and cannot be combined by writev. Replacing these single-buffer sends with an iovec does not reduce syscall count.

Rewritten headers live in `response_header_buf`, while original response bytes/body remain in `upstream_recv_buf`. Without close coalescing, header completion consumes only the original upstream header, then streams the body in a second send. This is the meaningful two-buffer opportunity. Existing close coalescing already reduces complete small close responses to one send, but copies body bytes and requires header buffer headroom. Vector sending could eliminate that copy and support larger already-buffered complete bodies. It cannot combine bytes not yet received and must not wait for future bytes simply to fill a vector.

nginx release-1.29.7 `ngx_writev_chain.c` builds bounded stack iovecs, coalesces neighboring memory ranges, advances its output chain by the actual returned byte count, retries EINTR and retains unfinished bytes on EAGAIN. Source: https://raw.githubusercontent.com/nginx/nginx/release-1.29.7/src/os/unix/ngx_writev_chain.c . Adapt the behavior, not nginx container types or third-party code.

## Initial experiment design

Use a two-range epoll downstream send API. A stack `iovec[2]` with `sendmsg(MSG_NOSIGNAL)` preserves existing per-call signal suppression and possible MSG_MORE behavior while providing writev-style gathering. Retain single-range send unchanged. TLS remains on its existing SSL_write path.

Initially admit only ordinary rewritten HTTP/1 responses with a complete, nonzero Content-Length body already present; no throttling, response policy or response-read deadline ownership. Validate exact original header/body bounds and exclude surplus bytes. No payload-size prediction, route history or new language syntax. Both short and persistent downstream connections may qualify. Existing framing, upstream reuse and terminal request-boundary decisions remain authoritative.

Set `upstream_send_len` to original header plus body; `resp_body_sent` to rewritten header plus body; after full vector completion call existing `on_proxy_response_sent` once. Preserve the existing completion queue rather than inline callbacks. Do not route a vector completion through `on_response_header_sent`: deadline logic validates an exact header-only completion and would incorrectly consume/count body bytes.

The kernel copies iovec descriptors during each sendmsg, but buffer ranges must remain valid until all partial sends drain. They remain owned by the connection; do not consume/reset either buffer or submit another receive into it while the send is outstanding. Close/cancel must retire state before connection ID/fd reuse. Continue to reject stale epoll tokens using existing owner generations.

For partial progress, maintain a cumulative byte cursor over the two ranges: before first length, emit suffix(first) plus second; at first length, emit only second; after it, emit suffix(second). Completion result is total bytes across both ranges, emitted only once. EINTR retries without moving cursor; EAGAIN parks current cursor; zero write is failure. Check combined length against signed IoEvent result limits. Initialize and clear vector state on every scalar submission, error and close path.

Avoid adding two iovecs to every Connection or enlarging both backend SendState arrays blindly. An opt-in MappedArray holding only a second pointer/first length can be allocated once per enabled shard, leaving scalar and upstream storage unchanged; report its measured size/capacity overhead before implementation. Reconstruct descriptors on the stack for each retry. This experiment has no heap allocation on send paths.

## Required verification and decision

Real socket tests must cover full drain, partial first range, exact boundary and partial second range, EAGAIN/retry, peer close, close/fd reuse, buffer byte integrity and exactly one total completion. Integration cases: rewritten complete responses, incomplete response fallback, surplus upstream bytes, pipelined successor, throttled/TLS/deadline fallbacks and large-body splice controls. Verify both epoll and io_uring existing callbacks remain unchanged outside the admission path.

Run the same binary on/off, then tuned nginx, serially with controlled rewritten-response workloads. Include 1 KiB, intermediate complete-body sizes, fragmented origin delivery and original transparent keepalive/close controls. Compare syscall counts separately from untraced RPS/p99. Existing transparent 1 KiB baseline should not gain a sendmsg replacement or extra per-request vector work.

Conclusion: vector sending has a concrete use for separate rewritten headers and already-buffered bodies, but is not supported as a major-throughput fix for the current transparent 1 KiB persistent benchmark. No runtime implementation or performance gain is claimed by this research.
