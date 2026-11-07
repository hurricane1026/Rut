# Upstream OAuth client credentials

Import `middleware/oauth_client.rut` and use the
[upstream example](../examples/upstream-oauth.rut). This implements a bounded,
per-request [RFC 6749 client credentials](https://www.rfc-editor.org/rfc/rfc6749#section-4.4)
profile using existing `httpCall` infrastructure. The gateway is a confidential
OAuth client for its upstream; downstream authentication remains separate.

## Request and endpoint ownership

`oauth_client.clientCredentials(serviceAuthorization)` builds a POST request
with the exact form body `grant_type=client_credentials`, JSON Accept and form
Content-Type headers, and a trusted pre-encoded Basic Authorization field.
The configured field must begin with canonical `Basic ` and contain a payload.
JSON encoding escapes it safely; the existing callout validator rejects unsafe
HTTP header bytes or exceeded storage bounds before network I/O. The AS validates
the actual credential. Malformed configuration/construction fails with 503.
Provision the Basic value using OAuth's client-authentication encoding rules;
the library neither accepts raw client secrets nor implements their provisioning.

`TOKEN_ENDPOINT` fixes the IPv4 address, HTTPS server identity, CA and token path.
The caller cannot choose these through request headers, URL or body. TLS
verification, fixed deadlines and queue capacity are the existing callout policy.
The request carries no client cookie or downstream authentication credential.
The default scope must be configured for this client at the AS: this slice omits
the optional request scope. For an explicit scope list, use the scoped helper below.
A single HTTPS resource indicator is supported as described below. Provider-specific
`audience` parameters and token exchange remain outside this profile.

## Explicit configured scopes

`oauth_client.clientCredentialsForScope(serviceAuthorization, scopes)` builds the
same request with an additional `scope` field. The
[scoped example](../examples/upstream-oauth-scoped.rut) reads `UPSTREAM_SCOPE` from
trusted configuration, separately from downstream caller authentication. Never
populate it from an untrusted request header or query parameter.

The native `oauthClientCredentialsRequest(scopes, serviceAuthorization) -> Json?`
uses the [RFC 6749 scope-list grammar](https://www.rfc-editor.org/rfc/rfc6749#section-3.3):
a nonempty list of ASCII scope tokens separated by single spaces, excluding
quotes, backslashes and control bytes. Scope input is bounded to 1024 bytes;
Basic service authorization is bounded to 2048 visible ASCII bytes with a
nonempty payload. The scheme is case-insensitive; the AS validates the credential.
Invalid input or exhausted output storage returns nil; the source helper responds
503 before contacting the AS.

The form encoder preserves token order, duplicates and case. It percent-encodes
spaces and reserved characters, including `+`, `&`, `=`, `/` and `%`, so they
cannot introduce additional form parameters. For example, `read a+b&x=y` becomes
`scope=read%20a%2Bb%26x%3Dy`. The original default-scope helper is unchanged.

The AS may grant fewer scopes than requested. Both helpers still require
`oauth_client.authorization(reply, requiredScope)` to check the explicit response
scope against the route's configured permission. Requesting a scope is not proof
that it was granted; the helper does not require the whole requested list back.

## Configured target resource

`oauth_client.clientCredentialsForResource(serviceAuthorization, scopes, resource)`
adds one [RFC 8707 resource indicator](https://www.rfc-editor.org/rfc/rfc8707#section-2.2)
to the scoped request. It uses the three-string overload
`oauthClientCredentialsRequest(scopes, serviceAuthorization, resource) -> Json?`;
the existing two-string overload and default-scope helper retain their behavior.
See [the resource example](../examples/upstream-oauth-resource.rut).

`UPSTREAM_RESOURCE` is trusted configuration, separate from both `TOKEN_ENDPOINT`
and the fixed forwarding upstream. It is an identifier sent to the AS; Rut never
fetches it or uses it to select a connection destination. Caller `Resource` headers
and query parameters do not control it. Provision an identifier recognized by the
AS for the configured upstream API.

This bounded profile accepts one HTTPS URI of at most 1024 ASCII bytes, with a
nonempty DNS-label hostname (labels at most 63 bytes, total at most 253, no trailing
dot), or a bracketed IPv6 address. Optional ports are 1–65535. Scheme matching is
case-insensitive; identifier bytes, case, port and percent-escape spelling are
preserved. Userinfo, fragments (including an empty `#`), raw whitespace/controls,
non-ASCII bytes, backslashes, invalid path/query characters and malformed percent
escapes fail. Queries are supported when required by the deployment, though RFC
8707 recommends omitting them. URNs, HTTP and other schemes, IPvFuture/zone IDs,
multiple resources and provider-specific `audience` parameters are outside this
profile. Do not put secrets in the identifier.

Scope, Basic authorization and output bounds still apply; the combined encoded
form body must fit the existing 4096-byte callout limit. Each field is encoded
separately: an existing `%2F` in the identifier becomes `%252F` in the form and
decodes back to the original `%2F`, never to `/`. `&`, `+` and `=` cannot introduce
additional form fields. Invalid configuration/construction produces 503 before I/O;
`invalid_target` and other AS errors also fail with 503 without forwarding.

Sending `resource` does not validate an opaque token's audience. The AS must bind
the issued token to the resource, and the upstream must enforce that restriction.
Rut continues to validate the token response's type, lifetime and required granted
scope, and forwards the token only to the configured backend. It neither derives
an `aud` claim from this parameter nor trusts a nonstandard echoed resource field.
The fixture demonstrates upstream rejection of both a token for another resource
and an AS response that ignores the requested binding.

## Token response policy

Unwrap the `httpCall` result and pass it to
`oauth_client.authorization(reply, requiredScope)`. It returns a canonical
`Bearer <access_token>` string only after all of these checks:

- Completed HTTP 200, with a strictly parsed JSON object and no duplicate decoded
  names. Redirects, transport errors and malformed/oversized responses fail.
- A nonempty string `access_token` with the existing Bearer token grammar. Leading,
  internal or trailing whitespace, control bytes, bad padding and non-ASCII token
  bytes fail; decoded JSON escapes are handled normally.
- String `token_type` is case-insensitive Bearer, without added whitespace.
- Integer `expires_in` is strictly positive. Missing, negative, Boolean, string,
  fractional or i64-overflowing values fail.
- A valid explicit response scope list contains the exact configured required
  scope token. Empty configuration, missing/typed/malformed scope or insufficient
  permission fails. No prefix or case normalization grants permission.
- No `error` field, even when it is null or accompanied by otherwise valid token
  fields. Token endpoint failures never fall back to downstream credentials.

Every failure returns 503: these are gateway service-token acquisition failures,
not a request for the downstream user to authenticate at the token endpoint.
Requiring expiry and scope is a local profile stricter than universally required
[successful response fields](https://www.rfc-editor.org/rfc/rfc6749#section-5.1).
`refresh_token` and other unused extension fields are not consumed or propagated.

The example separately authenticates its caller with `DOWNSTREAM_KEY`, returning
a Bearer challenge on failure before contacting the AS. After token acceptance,
`req.set("Authorization", authorization)` replaces/deduplicates the upstream
field. Token endpoint headers, cookies and response bodies are not returned to
the caller. Other original request headers follow ordinary forwarding policy;
remove them explicitly when the upstream should not receive them.

## Lifetime and limits

A fresh exchange occurs for every protected request. No token cache, refresh
worker, retry, distributed state or long-lived token handle is created. A positive
relative lifetime is validated at receipt, not converted into a persistent lease
or a proof that a token remains valid for an arbitrarily long upstream request;
the upstream remains responsible for token validity when it receives the request.
Do not reuse the returned header in a cache without a separate expiry design.

Storage remains bounded by existing JSON/callout/request-header limits. All values
belong to the current request and existing cancellation/generation handling fences
late responses after disconnect. The scoped constructor adds a builtin through
the existing JSON operation ABI, without a new syntax keyword or dependency.
The source library reuses `introspection.replyDocument` for
completed-response parsing; it does not introspect the acquired access token.

## Validation

`test_upstream_oauth_epoll` and `test_upstream_oauth_io_uring` use an independent
TLS token endpoint fixture and real upstream through a two-shard native-loaded
server. Source and both imported modules are deleted before requests execute.
The matrix covers HTTP/1 and HTTP/2 with default/explicit scopes and a configured resource; exact
percent-encoded form bodies, invalid scope bounds/grammar, caller scope injection
isolation, resource URI/body bounds, invalid-target responses, upstream audience
enforcement, grant/service headers; strict token,
expiry, scope and error fields; duplicate JSON/Authorization; missing caller
credentials; wrong TLS identity; AS denial/outage/redirect/truncation; unsafe
configuration; timeout; disconnected callers; fresh concurrent tokens and no
secret logging or implicit token-endpoint response propagation. Unavailable
io_uring is explicitly skipped with code 77. The fixture implements this protocol
profile, not a full OAuth provider or a persistent authorization server.
