# OAuth token revocation client

Import `middleware/oauth_revocation.rut` and see the
[executable example](../examples/oauth-revocation.rut). Rut acts as a client of a
configured authorization server's [RFC 7009 revocation endpoint](https://www.rfc-editor.org/rfc/rfc7009#section-2).
This does not add an authorization server, local JWT blacklist or durable session
store to the gateway.

## Request profile

`oauth_revocation.revokeRequest(authorization, serviceAuthorization)` extracts
one Bearer token from the supplied authorization field and constructs an
`application/x-www-form-urlencoded` POST with `token` and
`token_type_hint=access_token`. It reuses the existing bounded
`oauthIntrospectionRequest` form builder because the two protocols have the same
request fields. Token bytes are percent-encoded, not concatenated into the form.
The operation still sends to the separate, explicitly configured revocation URL.

The token is nonempty and follows the existing Bearer syntax, with a 1024-byte
form-builder bound. Missing, duplicate or malformed Authorization returns a
Bearer-challenged 401 with valid service configuration; construction/storage
failure returns 503. Service authorization is trusted pre-encoded Basic client
authentication, at most 2048 bytes; canonical `Basic ` plus a nonempty payload is
required. Unsafe HTTP header bytes fail callout admission. Service credentials
are never inferred from the client token, cookie or request header.

`REVOCATION_ENDPOINT` fixes the HTTPS address, verified server identity, CA and
path. The AS must authenticate the configured client and verify token ownership.
The hint is not proof of token purpose or ownership; actual lookup, cascading
revocation and propagation policy belong to the AS. Provision credentials using
the provider's OAuth client-authentication encoding rules. This bounded profile
does not implement public-client authentication, client-assertion signing,
refresh-token-specific policy, discovery or arbitrary caller-selected endpoints.

## Acknowledgement and failure

Unwrap the fixed endpoint's `httpCall` result and call
`oauth_revocation.requireSuccess(reply)`. It accepts only completed transport
(`ok: true`) with integer status 200. All other statuses, TLS/timeout/queue errors
and malformed framing return 503. It never follows redirects or automatically
retries. The helper cannot authenticate arbitrary JSON passed by a caller.

The success body is not parsed or inspected: empty, text and malformed JSON bodies
all have the same meaning once admitted by the transport. RFC 7009 uses 200 for
both successful revocation and invalid/unrecognized tokens; Rut exposes the same
204 empty response for both, with `Cache-Control: no-store`. It does not expose
AS cookies, response bodies or token-existence headers to the caller. An error
field inside a 200 body does not override the status-based protocol.

This reuses the existing bounded `httpCall` UTF-8 envelope. HTTP headers and body
are each limited to 8192 bytes, total wire to 16384 and the complete JSON envelope
to 8192 bytes. Unsupported encodings, invalid UTF-8 and oversized/ambiguous framing
fail before the status helper can accept the result, even when the wire status
is 200. This is a bounded transport profile, not arbitrary-body RFC coverage.

A timeout or client disconnect is not proof that the AS left the token active:
revocation may already have committed before its acknowledgement was lost.
Rut reports no confirmed success in that case and performs no local rollback or
automatic retry. Operators must use AS state or subsequent introspection to
observe the outcome. Request cancellation still fences late gateway responses
and service shutdown joins existing worker activity before releasing storage.

## Introspection composition

The example performs revocation only on `POST /logout` and explicitly rejects
`GET /logout` with 405 before calling the AS. It consumes Bearer Authorization rather
than cookie-based identity, and uses configured service credentials to call the AS.
The `/protected` route independently introspects the token on each request,
checks active/expiry/audience/scope and maps the checked subject. Once the AS
reports the token inactive, the next protected request returns challenged 401.
No local cached allow hides that update. The AS owns authoritative membership,
durability and replication; a locally verified JWT route that never consults
that state is not automatically invalidated by this helper.

## Validation

Native-loaded two-shard TLS tests on epoll and io_uring remove source and imported
modules before execution. They check exact form/service credential separation,
percent encoding, invalid/duplicate credentials and token bounds, POST-only routing,
known/unknown/repeated revocation, status-only acknowledgement, transport limits,
AS errors and ownership refusal, TLS identity, timeout and disconnect uncertainty,
concurrent tokens, HTTP/2 and the revocation-to-introspection lifecycle. The local
fixture simulates the AS protocol/state; it is not a production OAuth provider.
No builtin, runtime ABI, dependency, keyword or gateway persistence is added.
