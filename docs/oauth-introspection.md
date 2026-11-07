# OAuth2 token introspection

Rut can authenticate opaque access tokens using an RFC 7662 HTTPS introspection
endpoint. This composes the existing `httpCall` lifecycle with ordinary
`middleware/introspection.rut` helpers and two bounded native operations.
No Kong configuration syntax, new language keyword or dependency is introduced.
See [the authenticated proxy example](../examples/oauth-introspection.rut).
Serve client traffic over TLS using gateway TLS flags or a trusted terminating frontend.

The request follows [RFC 7662 section 2.1](https://www.rfc-editor.org/rfc/rfc7662.html#section-2.1):
POST form data containing `token` and `token_type_hint=access_token`, with
`Content-Type: application/x-www-form-urlencoded` and `Accept: application/json`.
Percent encoding preserves plus, slash and padding bytes exactly. Tokens cannot
inject another form parameter or select the destination. Endpoint authentication
uses a separate, explicitly configured Basic or Bearer authorization value.
Client credentials, cookies and identity headers never supply that value.

Endpoint and response bounds follow the existing
[HTTPS callout contract](language-card.md#composable-https-calls).

Configure these values before compiling/loading:

- `INTROSPECTION_ENDPOINT`: the existing fixed HTTPS `httpCall` policy with
  address, port, serverName, caFile and path. All endpoint/TLS selection remains
  configuration-owned; redirects and plaintext fallback are unavailable.
- `INTROSPECTION_AUTH`: an authorization value for the resource server itself,
  for example `Basic <base64(client-id:client-secret)>` or a separate service
  Bearer credential. It is not the presented client token. A nonempty visible
  ASCII value with either scheme is required; the AS validates the credential.

`introspection.request(authorization, serviceAuthorization)` reads a singleton
Authorization value supplied by the route. Missing/malformed Bearer credentials
return challenged 401 before a call. The request builder accepts at most 1024
raw token bytes and 2048 service-authorization bytes. Invalid configuration,
request-size or JSON-storage failure returns 503 without contacting the AS.
It returns an unwrapped Json request for `httpCall`.

After binding and unwrapping the callout result, use
`introspection.requireActive(reply, expectedAudience)`. HTTP non-200, transport,
TLS, timeout, capacity and malformed JSON failures return 503. A valid JSON
response that fails the resource-server metadata policy returns challenged 401.
HTTP 200 alone does not authenticate. A service-level HTTP 401/403 is an AS
access failure (503), distinct from a response containing `active: false`.

This deliberately strict access-token profile requires:

- Exact Boolean `active: true`.
- Integer Unix-seconds `exp`, strictly later than the current wall clock.
- Exact audience membership in a string or nonempty array of nonempty strings.
  Every array member is validated, even after a match. Expected audience is
  nonempty and at most 1024 bytes.
- Optional `nbf`/`iat` are nonnegative integers no later than now. No skew is
  allowed, and a clock failure denies access.
- Optional `scope` is a nonempty valid OAuth scope list; optional `token_type`
  is case-insensitive Bearer. Unknown token types do not gain access.
- Optional `sub` is a nonempty string without control bytes. Subject mapping
  remains explicit; the proxy example also denies when it is absent.

RFC 7662 makes most metadata optional. Requiring `exp` and audience here is a
local resource policy, not a claim that every valid RFC response contains them.
Unlike the existing JWT policy, this profile does not require `iss`, `sub` or
`iat` to be present: trust comes from the authenticated fixed AS endpoint, and
an application can apply additional issuer/client/subject restrictions. The AS
must restrict introspection grants and audience/scope to access tokens suitable
for this resource; `token_type_hint` alone is not proof of token purpose.

Success returns the metadata Json. `introspection.requireScope(document, scope)`
then applies the existing exact scope membership primitive, returning challenged
403 when the permission is missing. `introspection.subject(document)` projects a
nonempty subject after validation, or returns challenged 401 if it is absent.
The example obtains the subject only after both checks, removes upstream
Authorization, and replaces `X-Consumer-ID` from
trusted metadata. It never uses the AS's identity HTTP header or copies its
cookies. Other upstream headers retain the route's ordinary forwarding behavior.

The low-level builtins are `oauthIntrospectionRequest(token, serviceAuthorization)
-> Json?` and `oauthIntrospectionValid(document, expectedAudience) -> bool`.
The latter validates metadata only; it cannot prove the source of arbitrary
Json supplied by a caller. Never use client JSON as an introspection response.
Builders and validators borrow inputs only for their call; the generated request
uses the bounded request arena. Runtime primitives have no heap allocation or
LLVM dependency, and builtins are available in JIT and native-loaded programs.

Every protected request calls the AS. There is no local allow cache, so an AS
revocation is visible on the next request without a Rut invalidation operation.
The existing per-shard eight-slot service, fixed monotonic deadline, cancellation,
source ownership and joined shutdown are unchanged. No automatic retry occurs.
This does not add OAuth authorization/token endpoints, OIDC login, refresh or
session state, discovery, mTLS client authentication, or distributed caching.

Validation uses native parser/form-boundary tests, compiler/JIT type checks and
an independent RFC 7662 protocol fixture over real verified TLS. The integration
suite runs the shipped example after removing source/helper files, verifies
HTTP/1 and HTTP/2 forwarding, authenticated form encoding, expiry/audience/scope,
AS outage, wrong certificate identity, immediate revocation, concurrency and
credential/identity non-propagation on epoll and io_uring. It does not run a full
OAuth provider. Existing callout tests cover reset/disconnect cancellation.
