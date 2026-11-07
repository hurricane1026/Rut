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
the optional request scope and does not negotiate an arbitrary scope list,
resource indicator, audience parameter or token exchange.

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
late responses after disconnect. No builtin, runtime ABI, grammar or dependency
change is introduced. The source library reuses `introspection.replyDocument` for
completed-response parsing; it does not introspect the acquired access token.

## Validation

`test_upstream_oauth_epoll` and `test_upstream_oauth_io_uring` use an independent
TLS token endpoint fixture and real upstream through a two-shard native-loaded
server. Source and both imported modules are deleted before requests execute.
The matrix covers HTTP/1 and HTTP/2; exact grant/service headers; strict token,
expiry, scope and error fields; duplicate JSON/Authorization; missing caller
credentials; wrong TLS identity; AS denial/outage/redirect/truncation; unsafe
configuration; timeout; disconnected callers; fresh concurrent tokens and no
secret logging or implicit token-endpoint response propagation. Unavailable
io_uring is explicitly skipped with code 77. The fixture implements this protocol
profile, not a full OAuth provider or a persistent authorization server.
