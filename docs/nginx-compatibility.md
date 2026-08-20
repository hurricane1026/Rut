# nginx compatibility matrix

This matrix records behavior claims, not syntax coverage. `SUPPORTED` requires
behavioral equivalence evidence. Golden output alone is insufficient.

Allowed states are `SUPPORTED`, `PARTIAL`, `BLOCKED_BY_RUT`,
`NOT_IMPLEMENTED`, and `NOT_PLANNED`.

| nginx feature | parser | converter | RUT capability | behavior test | status |
| --- | --- | --- | --- | --- | --- |
| server fragment, exactly one server | yes | no | partial: no server selection model | no | NOT_IMPLEMENTED |
| `listen <port>` IPv4 wildcard | yes | no | no source/config listener; #250 | no | BLOCKED_BY_RUT |
| ordinary prefix `location /` | yes | no | partial: root catch-all exists | no | NOT_IMPLEMENTED |
| location applies to every method | yes | no | yes: method-omitted route source form; converter not yet | no | NOT_IMPLEMENTED |
| fixed IPv4 HTTP `proxy_pass`, no URI suffix | yes | no | partial: fixed `forward` exists | no | NOT_IMPLEMENTED |
| preserve raw request-target and query | no | no | partial: forward currently sends original bytes | RUT-only tests, no nginx diff | PARTIAL |
| preserve request method and body | no | no | partial: proxy streaming exists | RUT-only tests, no nginx diff | PARTIAL |
| nginx default upstream HTTP version and request headers | no | no | missing request policy; #252 | no | BLOCKED_BY_RUT |
| proxied response status and body | no | no | partial: streaming proxy exists | RUT-only tests, no nginx diff | PARTIAL |
| nginx default proxied response header policy | no | no | missing response policy; #253 | no | BLOCKED_BY_RUT |
| single unavailable upstream gateway error | no | no | partial: 502/504 paths exist | RUT-only tests, no nginx diff | PARTIAL |
| exact, `^~`, regex, or nested locations | no | no | no nginx selection semantics | no | NOT_PLANNED |
| `proxy_pass` with URI replacement | no | no | literal path rewrite only | no | NOT_PLANNED |
| multiple servers / `server_name` / `default_server` | no | no | no virtual-server selection | no | NOT_PLANNED |
| variables, rewrite, or internal redirects | no | no | insufficient nginx phase semantics | no | NOT_PLANNED |
| HTTPS/DNS/IPv6/Unix-socket upstreams | no | no | fixed IPv4 HTTP only | no | NOT_PLANNED |

## Semantic risks already observed

- nginx route matching normalizes percent escapes, dot segments, and (by
  default) repeated slashes. RUT routing has different canonicalization rules.
- nginx prefix matching is byte-prefix based; RUT routing is segment-aware.
  The root `/` case overlaps, but broader prefix support cannot reuse that fact.
- A `proxy_pass` without a URI suffix must not accidentally forward the
  normalized routing path instead of the original request target.
- nginx proxy request defaults are version-dependent beginning at 1.29.7.
- Default request and response hop-by-hop/header behavior is not transparent
  byte forwarding.
- RUT's current unmatched-route response is not nginx's normal 404 behavior.
