# nginx compatibility matrix

This matrix records behavior claims, not syntax coverage. `SUPPORTED` requires
behavioral equivalence evidence. Golden output alone is insufficient.

Allowed states are `SUPPORTED`, `PARTIAL`, `BLOCKED_BY_RUT`,
`NOT_IMPLEMENTED`, and `NOT_PLANNED`.

| nginx feature | parser | converter | RUT capability | behavior test | status |
| --- | --- | --- | --- | --- | --- |
| exact minimal fragment: one wildcard listener, root location, literal IPv4 no-URI proxy, bounded H1 domain | yes | yes | yes for declared bounds | committed pinned `%7E` success and explicit-close gateway differentials; pinned fixed-CL POST and keep-alive evidence | SUPPORTED |
| server fragment, exactly one server | yes | yes | partial: exact single-server model only; no server selection model | bounded pinned generated-RUT GET and POST differentials | PARTIAL |
| `listen <port>` IPv4 wildcard | yes | yes | yes: one source `listen :<port>` declaration | pinned nginx/generated-RUT bind and request | SUPPORTED |
| ordinary prefix `location /` | yes | yes | partial: root catch-all exists | bounded pinned generated-RUT GET differential | PARTIAL |
| location applies to every method | yes | yes | yes: method-omitted route source form | RUT route tests; pinned GET and POST differentials | PARTIAL |
| fixed IPv4 HTTP `proxy_pass`, no URI suffix | yes | yes | partial: fixed `forward` plus bounded policies | pinned generated-RUT GET/query/header and fixed-CL POST differentials | PARTIAL |
| preserve raw request-target and query | implicit | yes | partial: origin-form forward sends original bytes | pinned query differential; broader normalization untested | PARTIAL |
| preserve request method and body | implicit | yes | partial: fixed-CL body is staged before connect within one 16 KiB composite slice | RUT exact binary/segmented/boundary tests and pinned generated-RUT binary POST differential | PARTIAL |
| nginx default upstream HTTP version and request headers | implicit | yes | partial: explicit fixed HTTP/1.1 policy with bounded fixed-CL buffering; #252 | exact RUT tests plus pinned generated-RUT GET and POST differentials | PARTIAL |
| proxied response status and body | implicit | yes, including method-isolated root HEAD lowering | partial: strict final H1.1 exact-Content-Length streaming plus paired explicit-close HEAD success/connect-failure serialization; keep-alive HEAD rejected | exact public-source production-JIT HEAD success/failure and non-HEAD sibling wires, internal lifecycle tests, pinned generated-RUT GET/POST plus explicit-close HEAD success/unavailable-upstream differentials, and exact nginx-only two-request keep-alive HEAD baselines | PARTIAL |
| nginx default proxied response header policy | implicit | yes, including method-isolated root HEAD lowering | partial: bounded strict H1.1 final-response/content-length serializer and paired explicit-close HEAD success/connect-failure policy; keep-alive HEAD gap in #253 | exact public-source production-JIT HEAD success/failure/no-pool tests, internal token/lifecycle tests, pinned generated-RUT GET/POST/close plus explicit-close HEAD success/unavailable-upstream differentials, and exact nginx-only keep-alive HEAD success/502 baselines | PARTIAL |
| single unavailable upstream gateway error | implicit | yes | yes for bounded H1 single-IPv4 connect failures; #256 | committed pinned close/EOF differential plus pinned keep-alive and split-POST evidence | SUPPORTED |
| exact, `^~`, regex, or nested locations | no | no | no nginx selection semantics | no | NOT_PLANNED |
| exact `/api/` + proxy URI `/`, clean bounded H1 request domain | yes | yes | yes: bounded prefix replacement; #259 closed | pinned converter-generated `/api/`, `/api/x`, and query differentials; four out-of-domain targets fail before upstream | SUPPORTED |
| broader `proxy_pass` URI replacement and nginx URI normalization | partial | no | partial: clean raw-target transform only | nginx baselines only for repeated slash/dot/percent forms | PARTIAL |
| automatic slash redirect for exact accepted `/api/` + proxy URI `/`, bounded GET/cleartext-H1/close domain (`/api` → `/api/`) | implicit in accepted location/proxy model | yes | yes for declared bounds; #261 closed | pinned converter-generated two-vector full-wire/EOF differential with zero upstream activity; #260 closed | SUPPORTED |
| multiple servers / `server_name` / `default_server` | no | no | no virtual-server selection | no | NOT_PLANNED |
| variables, rewrite, or internal redirects | no | no | insufficient nginx phase semantics | no | NOT_PLANNED |
| HTTPS/DNS/IPv6/Unix-socket upstreams | no | no | fixed IPv4 HTTP only | no | NOT_PLANNED |

## Semantic risks already observed

- nginx route matching normalizes percent escapes, dot segments, and (by
  default) repeated slashes. RUT routing has different canonicalization rules.
- With `location /api/` and a `/` URI in `proxy_pass`, pinned nginx sends `/`,
  `/x`, and `/x?y=1` upstream for `/api/`, `/api/x`, and `/api/x?y=1`.
  It redirects `/api`, collapses repeated slash/dot-segment inputs, and decodes
  `%7E` to `~` before replacement. Closed #259 provides only a clean,
  fail-closed first transform slice; normalization and slash redirect behavior
  remain outside it, so #258 cannot become broadly `SUPPORTED` from clean-vector
  evidence alone.
- The automatic slash-redirect `SUPPORTED` row is limited to GET, cleartext
  H1, explicit close, and the exact accepted `/api/` model. It does not cover
  HEAD/POST, keep-alive Redirect, TLS/H2, arbitrary prefixes, or broader nginx
  URI normalization.
- nginx prefix matching is byte-prefix based; RUT routing is segment-aware.
  The root `/` case overlaps, but broader prefix support cannot reuse that fact.
- A `proxy_pass` without a URI suffix must not accidentally forward the
  normalized routing path instead of the original request target.
- nginx proxy request defaults are version-dependent beginning at 1.29.7.
- Default request and response hop-by-hop/header behavior is not transparent
  byte forwarding.
- Pinned nginx 1.29.7 forwards an explicit-close HEAD upstream as HEAD and
  retains an upstream `Content-Length: 5` in the downstream headers while
  emitting no body bytes and closing the client. Public RUT source can now
  select only a paired success/failure disposition for this bounded slice, and
  source→JIT→production success/failure wires are proven, and the root converter
  now emits the method-isolated pair. The pinned nginx-vs-generated-RUT
  differential proves the exact Date-normalized downstream response, EOF, and
  rebuilt upstream HEAD request for this explicit-close slice. #253 remains
  `PARTIAL` because RUT keep-alive HEAD support and broader response domains are
  absent.
- Pinned nginx also suppresses the 157-byte generated 502 body for an
  explicit-close HEAD when the single upstream connect fails, while retaining
  `Content-Length: 157`. RUT now carries a public paired HEAD disposition in
  response and failure metadata. Legacy policies remain
  `Reject`; only paired `SuppressBody` enters a bounded fresh-connect path that
  emits header-only strict success or configured 502, forces EOF, and never
  pools/replays the upstream. Mismatches fail before upstream effects. Public
  source selection enforces the pairing, its production path is proven, and the
  root converter emits it only on HEAD. The pinned generated-RUT differential
  now matches the exact header-only 502/EOF baseline while a single reserved
  non-listening endpoint is held across both implementations; it does not claim
  an unobserved RUT syscall count.
- Pinned nginx keep-alive HEAD behavior is now exact: a default-keepalive HEAD
  emits a header-only 200 retaining `Content-Length: 5` and keeps the downstream
  quiet/reusable; a second close-intent HEAD emits the exact close headers and
  EOF. nginx uses two distinct upstream connections and sends one exact rebuilt
  HEAD wire on each. With the upstream unavailable, the first header-only 502
  retains `Content-Length: 157` and downstream keep-alive, while the second
  close-intent request emits the exact close 502/EOF and produces the second
  scoped connect-failure record. Current RUT rejects this reusable HEAD domain,
  so the evidence defines the next #253 capability gap rather than support.
- The reusable HEAD gap previously depended on the generic epoll transport
  capability tracked in #262. Epoll now exposes at most one logical completion
  per wait
  with bounded pending-versus-kernel fairness, removing the former whole-batch
  pre-dispatch I/O window. It now also transports explicit upstream episodes and
  rejects stale or malformed records before fd-map/socket/TLS/state access and
  before concrete callback dispatch. Centralized production owners now begin,
  detach, retire, or quarantine fresh, retry, pooled, health-probe, timeout, and
  terminal episodes. Real tests prove pool return/borrow with the same numeric fd
  and terminal close/allocation with the same Connection slot: old readiness does
  no socket I/O and old completion dispatch does no timer/callback/state mutation,
  while current-token controls progress. A production failed-connect retry also
  proves episode 1 is detached/retired before episode 2 begins on the same
  Connection and numeric fd; replaying its old failure cannot mutate the replacement,
  while the current completion sends the exact request to a real peer. Two real
  active-health probes additionally prove production begin/terminal retirement,
  same-slot/same-fd reprobe, stale-completion isolation, and a current-token wire
  control. A production-owned active-episode regression now also proves upstream
  quiesce removes genuine HUP readiness while owner/token/map remain current, then
  retires cleanly. A kernel-produced raw connect record, held in the test harness,
  is also rejected before I/O after production same-slot/same-fd reuse while the
  current completion progresses. A second captured kernel record proves the same
  boundary for receive: the episode-2 bytes remain unread after stale replay,
  then the current record reads the exact payload and dispatches once. A third
  captured kernel record proves the boundary for a genuinely backpressured
  partial send, including zero old wire bytes and exact current payload through
  FIN/EOF. The requirement-by-requirement audit proves all five capability and
  nine acceptance bullets, so #262 is closed. These tests explicitly hold raw
  records already harvested into userspace and do not claim kernel retention
  after successful `EPOLL_CTL_DEL`. This transport work alone does not imply
  keep-alive HEAD support;
  io_uring episode cancellation/drain and deferred request admission are tracked
  in #264. Its first recv-only retirement slice now protects the existing
  explicit-close strict-abandon path, including cancel retry, token exhaustion,
  provided-buffer isolation, and deferred close/reclaim. Its second bounded
  runtime slice now completes request-1 bookkeeping before parking the generic
  HTTP/1 boundary, buffers request-2 bytes without parse/route/timer/callback
  effects, and resumes exactly once after the retirement-final CQE batch. Exact
  successor ownership also fences provided-buffer/partial-send mutation and
  survives close through a per-type target/cancel ledger. Public reusable HEAD
  admission remains rejected. A third bounded runtime slice now persists and
  atomically replaces the latest fully drained tombstone, proving two production
  strict callbacks, two batch-end boundary resumes, older-record isolation,
  close/reclaim composition, and token-exhaustion quarantine. #264 remains open
  until public reusable HEAD admission and a real two-request io_uring behavior
  test pass; converter-generated nginx differential evidence and the remaining
  response semantics stay under #253.
- The first request-policy slice rejects body/framing inputs (including
  `Content-Length` and every `Transfer-Encoding` value), HTTP/2, and
  non-origin-form targets before upstream connect. These are intentional
  fail-closed `PARTIAL` limits; nginx absolute-form/body normalization remains
  a follow-up.
- Pinned nginx 1.29.7 waits for a fixed-Content-Length request body to complete
  before accepting the upstream connection under the minimal default config.
  The planned RUT body slice must therefore stage the complete body before
  upstream slot/connect; transparent early-connect streaming is not equivalent.
- The first RUT body increment now stages a complete fixed-CL request within the
  existing 16 KiB connection slice, preserves a pipeline suffix, and tracks
  local buffering separately from successful upstream upload. Exact-cap and
  cap+1 behavior are tested. Larger bodies and file-backed buffering remain
  unsupported, so the feature stays `PARTIAL`.
- A converter-generated split binary POST now matches pinned nginx in exact
  upstream bytes and Date-normalized downstream bytes. Both delay backend
  accept until the complete body is locally available. This proves only the
  bounded fixed-CL vector, not larger or alternate-framing bodies.
- Valid downstream Upgrade requests are intentionally rejected before upstream
  connect in this header-only slice; nginx 1.29.7 strips and proxies Upgrade,
  so that behavior remains PARTIAL.
- The converter-generated differentials cover an origin-form header-only GET
  and a split fixed-CL binary POST with a query, custom Host, duplicate ordinary
  request headers, one final
  exact-Content-Length upstream response, custom reason, hidden/synthesized
  headers, duplicate response headers, and preserved trailing value whitespace.
  Dynamic Date is the only normalized response field. The `%7E`
  encoded-unreserved vector is now a committed serial pinned-nginx CTest; it
  preserves the complete raw upstream target and matches the downstream
  response. Encoded slash/dot/malformed cases remain open.
- Pinned nginx consumes an upstream `Connection` header for absent,
  `keep-alive`, `close`, and token-list vectors, synthesizes one downstream
  connection field, and preserves token-nominated ordinary response headers.
  The bounded strict serializer matches one such field and rejects duplicates;
  other hop-by-hop response behavior remains unclaimed.
- Pinned nginx success responses follow the downstream HTTP/1.1 request intent:
  default/explicit keep-alive remains reusable, while explicit close emits
  `Connection: close` and EOF after the body. Converter-generated RUT now matches
  the close vector and continues stripping the client Connection upstream.
- For one unavailable fixed upstream, pinned nginx waits for the complete
  fixed-CL request and emits a 157-byte HTML 502 with Server, Date,
  Content-Type, and request-derived keep-alive. Before #256, RUT emitted an
  11-byte close response; converter-generated RUT now matches the complete
  response after normalizing only Date, preserves keep-alive for a second
  request, closes on explicit client intent, and waits through the split-body
  window. The explicit-close 502/EOF vector is now a committed serial CTest.
  The claim remains limited to the bounded H1 single-IPv4 connect-failure
  domain.
- Response policy is intentionally limited to bounded non-HEAD HTTP/1.1
  requests plus one bodyless explicit-close HEAD slice, and one final HTTP/1.1
  response with exact Content-Length. Keep-alive HEAD, Upgrade, absolute-form
  targets, HTTP/1.0, HTTP/2, interim/no-body statuses, chunking, close-delimited
  framing, and response mutations remain fail-closed PARTIAL limits.
- RUT's current unmatched-route response is not nginx's normal 404 behavior.
