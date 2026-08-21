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
| proxied response status and body | implicit | yes | partial: strict final H1.1 exact-Content-Length streaming plus internal-only explicit-close HEAD success; HEAD failure serialization absent | exact RUT tests, pinned generated-RUT GET/POST differentials, and nginx-only HEAD success/gateway baselines | PARTIAL |
| nginx default proxied response header policy | implicit | yes | partial: bounded strict H1.1 final-response/content-length serializer; internal-only explicit-close HEAD success; HEAD failure/source paths absent; #253 | exact RUT/token/HEAD tests, pinned generated-RUT GET/POST/close differentials, and nginx-only HEAD success/gateway baselines | PARTIAL |
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
  emitting no body bytes and closing the client. Internal RUT metadata/runtime
  now covers only that success slice; public source, failure policy, and the
  converter cannot select it yet, so #253 remains `PARTIAL`.
- Pinned nginx also suppresses the 157-byte generated 502 body for an
  explicit-close HEAD when the single upstream connect fails, while retaining
  `Content-Length: 157`. Current RUT failure-policy serialization does not yet
  express that behavior.
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
- Response policy is intentionally limited to non-HEAD HTTP/1.1 requests and
  one final HTTP/1.1 response with exact Content-Length. Bodies, Upgrade,
  absolute-form targets, HTTP/1.0, HTTP/2, interim/no-body statuses, chunking,
  close-delimited framing, and response mutations remain fail-closed PARTIAL
  limits.
- RUT's current unmatched-route response is not nginx's normal 404 behavior.
