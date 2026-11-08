# Upstream OAuth token exchange

Rut can act as a confidential AS client for a bounded
[RFC 8693 access-token exchange](https://www.rfc-editor.org/rfc/rfc8693#section-2).
Import `middleware/oauth_client.rut` and use the
[exchange example](../examples/upstream-oauth-exchange.rut). It exchanges the
caller's Bearer access token for an AS-issued token suitable for the configured
upstream. This is an AS-client profile, not an authorization server or an OIDC
login/session implementation.

## Request and trust ownership

`oauth_client.tokenExchange(authorization, serviceAuthorization, policy)` extracts
the subject token from a singleton Bearer Authorization field and calls
`oauthTokenExchangeRequest(subjectToken, serviceAuthorization, policy) -> Json?`.
The first two builtin arguments are unwrapped strings; `policy` is unwrapped Json
with exactly two string fields: `scope` and `resource`. Missing, unknown or
duplicate decoded field names, incorrect types and malformed JSON fail.

The constructor builds a POST form with these fixed fields:

| Field | Value |
| --- | --- |
| `grant_type` | `urn:ietf:params:oauth:grant-type:token-exchange` |
| `subject_token_type` | `urn:ietf:params:oauth:token-type:access_token` |
| `requested_token_type` | `urn:ietf:params:oauth:token-type:access_token` |
| `subject_token` | Extracted caller access token |
| `scope` | Trusted configured scope list |
| `resource` | One trusted configured HTTPS resource identifier |

Each value is encoded independently. Form metacharacters cannot add fields;
existing resource percent escapes are preserved after form decoding. Only the
configured Basic service credential goes in AS Authorization. Caller cookies,
identity, scope/resource and actor-token headers are not copied into the AS call.

`TOKEN_ENDPOINT` fixes the verified HTTPS endpoint, server name, CA and path.
`TOKEN_SERVICE_AUTH`, `UPSTREAM_SCOPE` and `UPSTREAM_RESOURCE` are trusted
configuration. Resource is an identifier, never a network destination; the
forwarding backend is independently fixed. Caller headers or query parameters
cannot select the grant, token types, target resource, requested permissions,
service credentials or endpoint. Unwrap fallible policy construction before
passing it to the helper.

The AS must authenticate the service, validate the subject token (including its
issuer, expiry, revocation and original audience as appropriate), and authorize
this service's exchange of that subject for the configured scope/resource. Bearer
syntax extraction in Rut does not verify the subject's identity or authorize
impersonation. The upstream must enforce the issued token's audience and its own
access policy; sending a resource parameter is not proof of an audience binding.
The fixture includes an AS that ignores the binding and an upstream that refuses
its token.

## Bounds and failure behavior

- Subject token: nonempty Bearer token grammar, at most 1024 bytes. Service
  authorization: configured Basic header, at most 2048 visible ASCII bytes.
- Policy JSON: existing 8192-byte JSON bound. Decoded scope and resource each fit
  1024 bytes. Scope follows the existing strict single-space ASCII grammar;
  resource follows the [HTTPS resource profile](upstream-oauth.md#configured-target-resource),
  including IPv6/NUL, fragments, userinfo, port and percent-escape checks.
- Combined encoded form body: at most 4096 bytes. Inputs that individually fit
  may still exceed this total after encoding. Output uses caller-owned storage;
  temporary decoded values never escape into the returned message.
- Missing, duplicate or malformed Bearer credentials return 401 with a Bearer
  challenge before an AS call. Constructor/configuration failures, including an
  otherwise syntactically valid subject above the 1024-byte profile limit, return
  503 before an AS call. The source helper has no fallback to another credential.
- AS failures (including invalid subjects or disallowed exchanges), TLS failures,
  timeouts and malformed token responses all return 503 without forwarding. This
  local profile deliberately does not map AS OAuth errors to downstream identity
  or permission statuses, and never exposes AS response headers/body to callers.

## Issued-token policy

After unwrapping `httpCall`, use
`oauth_client.exchangeAuthorization(reply, requiredScope)`. It first requires a
completed HTTP 200 with strictly parsed JSON and exact string
`issued_token_type` equal to `urn:ietf:params:oauth:token-type:access_token`.
Missing, typed, case-changed, JWT/ID-token or other issued types fail even if the
response also contains otherwise usable-looking token fields.

The shared [upstream token policy](upstream-oauth.md#token-response-policy) then
requires a nonempty valid Bearer access token, case-insensitive Bearer usage type,
positive integer `expires_in`, an explicit valid scope list containing the route's
exact required scope, and no `error` field. Duplicate decoded JSON keys fail.
Requiring explicit scope and lifetime is a local profile; it does not claim that
all these fields are universally mandatory in RFC 8693 responses. Unused refresh
tokens and extension metadata are ignored. Metadata helpers consume only a trusted
AS result; `authorizationDocument` alone does not authenticate arbitrary JSON.

The selected success arm replaces/deduplicates upstream Authorization with the
AS-returned token. It never falls back to the caller's original token on failure.
Other caller headers retain ordinary forwarding behavior; remove them explicitly
if the upstream should not receive them.

## Lifecycle and supported scope

Every protected request performs a fresh exchange. Request arenas and the existing
callout generation/cancellation handling own results; disconnects and timeouts do
not forward late completions. No token cache, retry, refresh worker or persistent
session state is created. Exchanging a token does not itself revoke the subject;
this implementation adds no input/output revocation linkage.

This profile excludes actor tokens/actor chains, other subject or requested token
types, SAML/JWE exchange, multiple resources, other URI schemes, `audience`
parameters and generalized delegation policy. The AS owns token claims and
impersonation/delegation semantics. No new language keyword, dependency or generic
helper C ABI is introduced; the bounded constructor uses an appended JSON op.

## Validation

`test_oauth_exchange_epoll` and `test_oauth_exchange_io_uring` use an independent
TLS AS fixture, real upstream and two-shard native-loaded gateway. Source and
imported modules are deleted before requests execute. Cases cover HTTP/1 and
HTTP/2; exact grant/type/subject/scope/resource fields; service/caller credential
separation; malformed/duplicate credentials; policy and body overflow; issued-type
confusion, malformed/duplicate JSON and strict shared token policy; AS rejection,
wrong TLS identity, redirect/outage/truncation; upstream audience refusal;
concurrent subjects with fresh isolated tokens; deadlines, disconnects, recovery,
and no token/secret logging or AS-response propagation. Unavailable io_uring is
reported as skip 77. The fixture implements this bounded protocol contract, not a
full external OAuth provider or a durable authorization service.
