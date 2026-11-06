# OPA external authorization

Rut can delegate request authorization to an OPA Data API rule through the
existing bounded `httpCall` primitive. Import `middleware/opa.rut` from the
[example library](../examples/middleware/opa.rut). The helper is ordinary Rut;
it adds no keyword, interpreter or runtime dependency. It implements the
[OPA Data API POST contract](https://www.openpolicyagent.org/docs/rest-api/#get-a-document-with-input),
independently of Kong configuration syntax.

`opa.request(input)` returns an optional callout request with method `POST`,
`Content-Type: application/json`, and a serialized `{"input": ...}` body.
`input` may be any valid JSON value. Serialization preserves JSON types and
escapes strings; a pre-serialized JSON string remains a string, not an object.
A construction/storage failure returns nil. Identity, action, resource and any
additional context are explicitly chosen by the application. Do not populate a
trusted subject from an unverified client identity header.

Configure `OPA_ENDPOINT` before compiling/loading, for example:

```json
{"address":"127.0.0.1","port":8181,"serverName":"opa.internal","caFile":"/etc/rut/opa-ca.pem","path":"/v1/data/rut/allow"}
```

This endpoint must actually serve verified HTTPS (OPA or a trusted TLS frontend).
The destination, path and TLS identity are configuration-owned. There is no
redirect following or plaintext fallback. See the language card's
[callout contract](language-card.md#composable-https-calls) for limits.

```rut
import "middleware/opa.rut"
route GET "/example" {
    guard let input = json.value({subject: "trusted-service", action: "read", resource: "reports"}) else { return 503 }
    guard let request = opa.request(input) else { return 503 }
    let pending = httpCall(env("OPA_ENDPOINT"), request, 1000)
    guard let reply = pending else { return 503 }
    let allowed = opa.requireAllow(reply)
    return 204
}
```

`requireAllow` requires HTTP 200 with `ok: true` and an object response body
containing an exact Boolean `result`. True returns the parsed OPA document;
false or an omitted `result` terminates with 403. OPA uses an omitted result for
an undefined rule, so HTTP 200 alone never authorizes. A wrong result type,
malformed/duplicate JSON, non-object document, non-200 HTTP status, transport
error, capacity failure or timeout produces 503. Policy-service HTTP 401/403
is a service failure, distinct from an evaluated false decision. No failure
forwards the protected request. Callers must pass the real `httpCall` result;
the helper cannot prove provenance for arbitrary JSON.

`opa.requireDecision(reply)` selects a structured rule instead:

```json
{"result":{"allow":true,"tenant":"accounts","role":"reader"},"decision_id":"trace-id"}
```

The result must be an object with an exact Boolean `allow`. False or an omitted
result gives 403; a missing/mistyped `allow` gives 503. Success returns the result
object, including additional fields, only after authorization. Use ordinary
`json.get`/`json.decode` to validate explicitly selected fields before mapping
them to an upstream request. The Boolean and structured profiles are separate;
neither treats a nonempty string, array, number or object as truthy. Other
metadata is allowed but never supplies identity implicitly. There is no field
fallback between the two profiles.

The [authenticated proxy example](../examples/opa-auth.rut) verifies a local
Bearer credential first, sends only the verified subject and selected action
and resource to OPA, strips Authorization before forwarding, and replaces the
upstream identity header from the authenticated identity. Client cookies and
credentials are not sent to OPA. Ordinary upstream request headers otherwise
follow the route's existing forwarding policy; add explicit stripping where
needed. OPA response headers, cookies and identity fields are never copied.

Every protected request evaluates the current remote decision: there is no
local authorization cache, fallback allow, or automatic retry. Remote policy
and data updates therefore need no Rut policy-cache invalidation. The caller
selects a total per-call timeout; bounds, suspension, cancellation and worker
shutdown reuse `httpCall`. Native programs retain imported helper/policy bytes
after the compiler exits and source files are removed. Existing eight route
guards remain bounded; MIR now reserves 32 blocks so a supported guard chain,
call continuation and terminal match can compose.

`test_opa_auth` uses an independent local Data API protocol fixture over real
verified TLS and a protected HTTP upstream. It checks the shipped authenticated
example, both decision profiles, malformed/duplicate responses, undefined rules,
HTTP/transport/timeouts, wrong TLS identity, JSON escaping and input types,
source/module removal, non-propagation of credentials/identity headers, no
forwarding after denial and concurrent decision isolation on epoll/io_uring.
It also exercises a body-less HTTP/2 request. It tests the gateway protocol,
not a bundled Rego evaluator. The existing
`test_http_call` suite supplies additional HTTP/2, reset/disconnect and sequential
call lifecycle coverage. No OPA binary/container is required for these tests.

This slice does not embed Rego, administer OPA policies, implement distributed
identity/session state, or automatically map arbitrary decision fields. Endpoint
authentication, if needed, is supplied explicitly using existing JSON request
header editing; downstream credentials are never forwarded automatically.
