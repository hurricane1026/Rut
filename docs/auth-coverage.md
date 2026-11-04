# Gateway authentication and authorization coverage

This ledger extends the existing M4 scope. A matching plugin name or successful
HTTP request is insufficient evidence of protocol equivalence. Status describes the implementation and tests on this branch. Open integration
PRs are tracked separately below; native-only APIs do not count as executable Rut
features, and this ledger does not claim the whole auth milestone is complete.

Sources: [Kong authentication](https://developer.konghq.com/gateway/authentication/),
[Kong plugin catalog](https://developer.konghq.com/plugins/),
[APISIX plugin catalog](https://apisix.apache.org/plugins/),
[APISIX multi-auth](https://apisix.apache.org/docs/apisix/plugins/multi-auth/).
Enterprise-only capabilities are within the comparison scope, independently of
whether a competing open-source edition includes them.

| Capability | Current evidence | Remaining acceptance scope |
| --- | --- | --- |
| API Key / Basic | Static identity helpers, singleton credential fields, exact matching, rotating Bearer/Basic/custom-header key windows, two-Consumer custom-header key matching; absence-only custom-header guests; explicit header credential stripping and verified identity header replacement | Dynamic Consumer registry/credential lifecycle and query/body credential hiding |
| Password storage | Native C++ fixed-cost PBKDF2-HMAC-SHA256 record hashing and verification; OS-generated or caller-provided 16-byte salt, an offline hash/verify provisioning CLI with private no-replace files, bounded password bytes, strict canonical records, constant-time derived-key comparison and an eight-slot off-shard verification worker with deadline/completion-FD adapters, HTTP/1 + HTTP/2 timer bridges, a bounded Rut/JIT/native-artifact header prefix and automatic shard lifecycle | User registry, password lifecycle and durable sessions |
| Password/JWT login | Fixed-account Rut composition: strict terminal-result Identity mapping, process-shared peer-IP admission before KDF, UUID jti, short-lived scoped HS256 token and strict protected-route policy; native-loaded two-shard TLS tests | User/account registry, durable registration/reset/change, account policies, refresh/logout and persistent session/revocation state |
| Bearer and multi-auth | Basic/Bearer OR for one Consumer or a bounded pair; required header-key AND Basic policy; disabled slots and ambiguous ownership rejection; absence-only guest access for the bounded pair without invalid-credential downgrade | Dynamic Consumer registry and credential lifecycle |
| JWT verification and issuance | HS256/384/512 policy helpers with static two-secret rotation; configured RS256/JWKS and ES256/P-256 verification through Rut, JIT and native programs; approved kid selection, bounded remote TLS refresh, static rotation and policy revocation snapshots; strict claims policy through Rut, JIT and native programs with mandatory `iat` and bounded age/lifetime; two-ID static JWT revocation helper; exact scope and `groups` authorization after verification; fixed-profile native and Rut/JIT HS256 issuance with five, six or seven claims and request-owned Rut/JIT results | Other EC profiles, DNS/discovery and broader JWKS refresh profiles, live and durable token revocation; arbitrary claims and non-HS256 signing |
| HMAC and webhooks | Generic MD5/SHA-1/SHA-2 digest/HMAC primitives, fixed SHA-256 verification, exact binary bytes, two-key rotation including the strict GitHub sha256 profile; native bounded Standard Webhooks v1 verification and freshness; fixed APISIX-style HMAC-SHA256 signed-request native verifier plus Rut/JIT `auth.signedRequest` and static two-key `auth.rotatingSignedRequest` policies | Full Kong/APISIX plugin compatibility, dynamic key registry/refresh, nonce/replay persistence |
| ACL / Consumer restriction | Exact Consumer allow/deny and two-Consumer allow union; static two-Consumer/two-group membership, single/either/both-group allow, single/either-group deny, deny-before-allow composition and unknown-Consumer default deny | Dynamic registry and membership lifecycle, larger policy sets |
| JWE | Pending | Algorithm/enc allowlists, authenticated decryption, nested JWT policy, malformed/truncated ciphertext vectors |
| JWT signing / re-signing | Fixed-profile five-claim HS256 issuance through native and Rut/JIT APIs; six-claim `jti` variant through native and Rut/JIT; static two-ID revocation helper | General token re-signing, arbitrary claims, non-HS256 signing, live or durable revocation |
| Forward auth / OPA | Pending | Consume bounded external response, identity allowlist, strip spoofed identity, deny vs unavailable, timeout/cancellation/close in both backends |
| OAuth2 introspection | Pending | RFC 7662 active/expiry/audience checks, authenticated TLS endpoint, bounded cache, invalidation and fail-closed outage policy |
| OIDC login / session | Pending | Discovery validation, authorization-code + PKCE, state/nonce, redirect validation, ID-token verification, secure cookies, logout and refresh |
| Gateway OAuth2 endpoints | Pending | Authorization/token grants, client authentication, consent/redirect binding, code single use, token expiry/revocation and persistent state |
| Upstream OAuth token | Pending | Client credentials/token exchange, audience/scope, per-shard cache with bounded refresh coordination, cancellation and secret-safe logs |
| mTLS identity | Inbound mandatory client certificate verification with startup CA bundle; verified SHA-256 fingerprint exposed to Rut/JIT/native requests; static pinned identity helper; epoll and io_uring HTTP/1 and HTTP/2 loopback tests; TLS 1.2/1.3 valid, absent, wrong-CA and expired certificate cases; ordinary TLS and cleartext spoof-header rejection; keepalive/reset, pin RCU update, bounded HTTP/2 refusal/retry, and source-unlinked native artifact evidence | Dynamic identity mapping, CRL/OCSP and durable revocation |
| LDAP | Pending | Direct LDAP protocol, TLS, bind/search escaping, limits/timeouts, credential hygiene; an HTTP bridge does not satisfy this row |
| SAML / CAS | Pending | Full SP flow, signed assertions/tickets, audience/destination/time checks, XML entity restrictions, signature wrapping and replay protection |
| Keycloak / Casdoor | Pending | Explicit supported OIDC/OAuth2 or provider protocols and conformance fixtures, role mapping and outage behavior |
| Casbin / Wolf RBAC | Pending | Named access model, trusted identity/policy mapping, policy update semantics and deny/error behavior |
| Shared identity / sessions | Pending | Session lifecycle, fixation/CSRF defenses, rotation/revocation, shard ownership and explicit cross-node consistency |

`auth.rotatingBasic` provides a static current/previous Basic credential window
for one configured Consumer. Both slots are evaluated, current wins a tie, and
removing the previous credential revokes it. Empty slots are disabled; empty
metadata or two disabled slots are configuration errors. Authentication still
uses singleton Authorization headers and rejects malformed or duplicate fields.

## Audit of executable gaps

The 2026-10-27 audit separates these layers:

- Header stripping is implemented: `req.remove` removes every case-insensitive
  occurrence before forwarding while auth reads the original request. See
  `examples/auth-proxy.rut` and the language card's credential-stripping section.
  Verified identity values can be explicitly replaced in a selected match arm.
- `apiKeyOrBasic` supports one Consumer. `multiAuth` now checks four configured
  slots (Bearer/Basic for each of two Consumers), rejects ambiguous ownership,
  and returns metadata from the matched configuration. This is a static bounded
  policy, not a persistent Consumer registry or a claim of plugin equivalence.
- RS256/JWK/JWKS now has a trusted static Rut policy surface, configuration-owned
  keys and shard-local activation. Public-key parsing stays off the request path.
  Remote discovery/refresh and live token revocation remain outstanding.
- Anonymous access needs a presence distinction: singleton Authorization reads
  return nil for both absence and duplicates. Falling back on nil would turn
  malformed duplicate credentials into anonymous access. No anonymous helper is
  advertised until absence can be distinguished safely.
- External authorization needs bounded response-consuming callouts with tested
  cancellation/close behavior; redirects or fire-and-forget proxying do not
  implement forward-auth, OPA or introspection.

The Standard Webhooks identity middleware is integrated here; its freshness
checks do not implement persistent replay protection. The bounded Consumer
policy work from #924, required credentials from #925, and header-count
primitive from #926 are already present in this main base.

### Signed-request HMAC-SHA256 subprofile

`signed_request_hmac_sha256_valid` verifies a fixed native profile inspired by
APISIX HMAC Authentication. `auth.signedRequest(keyId, key, consumerId,
credentialId)` is the Rut policy helper. It reads the implicit request context,
binding the parsed request's actual method and original target, unique
Authorization/Date/Digest fields, and full
body; it rejects chunked HTTP/1 bodies and requires body completion before
handler execution. Rut/JIT exposes a 16 KiB body limit and fails closed above
it; the native verifier limit remains 1 MiB. It does not claim full APISIX or
Kong plugin compatibility.

The caller supplies the exact method, origin-form request target, singleton
Authorization/Date/Digest values, exact raw body bytes, trusted key ID/secret,
and trusted UTC epoch seconds. `Authorization` must contain exactly four
quoted parameters, in any order:

```text
Signature keyId="...",algorithm="hmac-sha256",headers="@request-target date digest",signature="..."
```

Unknown, duplicate, missing, malformed, or trailing parameters fail closed.
The only accepted method tokens are uppercase GET, POST, PUT, DELETE, PATCH,
HEAD, OPTIONS, and TRACE; CONNECT is rejected because this profile signs only
origin-form targets. The target must start with `/`, may include its original
query bytes, and is never decoded or normalized; whitespace, controls, `#`,
and targets over 8192 bytes are rejected.

Date must be a canonical 29-byte IMF-fixdate in GMT with a valid calendar date
and matching weekday. Its timestamp must be within 300 seconds of the supplied
clock, inclusive. Digest is mandatory even for an empty body and must equal
`SHA-256=` followed by canonical padded Base64 of SHA-256 over the exact raw
body. The signature is canonical padded Base64 of the HMAC-SHA256 result over
these exact bytes (each line ends in LF):

```text
trusted-key-id
UPPERCASE-METHOD exact-origin-form-target
date: exact-Date-value
digest: SHA-256=canonical-padded-Base64-body-hash
```

Trusted key IDs are 1–128 visible ASCII bytes excluding quote, backslash, and
comma; secrets are 1–4096 bytes; native bodies are at most 1 MiB; Authorization
is at most 4096 bytes. Verification uses fixed stack buffers and existing
crypto primitives, with no heap allocation or retained input views; the native
verifier returns only a boolean. The Rut `auth.signedRequest` policy returns
503 for empty configured key or identity metadata and 401 with
`WWW-Authenticate: Signature` for rejected requests. Successful identity
fields come only from trusted configuration. Freshness checks do not prevent replay; callers
processing non-idempotent actions need durable replay state. The signed fields
do not include Host/authority or a nonce. Configure trusted keys for a bounded
endpoint/route scope and use durable deduplication if an authenticated request
can trigger a replay-sensitive side effect. This is not full HTTP Message
Signatures, APISIX, or Kong equivalence. See
[`signed-request-auth.rut`](../examples/signed-request-auth.rut).

`auth.rotatingSignedRequest` adds a static two-slot key-ID/key window for the
same signed-request profile. It validates all metadata and slot pairing before
examining the request, rejects duplicate enabled key IDs, verifies both slots
against one captured request, and returns the matched configured credential
ID. Clearing the previous slot revokes it. This does not add dynamic key
refresh or replay persistence. See
[`signed-request-rotation.rut`](../examples/signed-request-rotation.rut).

## Bounded multi-Consumer authentication

`auth.ConsumerCredentials` contains trusted `consumerId`, `key`, `credentials`
(`user:password`), `keyId` and `passwordId` strings. Pass two configurations and
`req.authorization.or("")` to `auth.multiAuth`. Both Consumers must have distinct,
nonempty IDs, and all credential IDs must be nonempty, even for disabled slots.
Empty secrets disable individual slots; at least one slot must remain enabled.
A shared nonempty Bearer key or Basic credential across the two Consumers is a
503 configuration error, independently of the presented request. This prevents
configuration order from deciding credential ownership.

Each enabled method retains its native syntax/size validation. Matching uses
only one singleton Authorization field, with no query/header fallback. Invalid,
missing, duplicate or unknown credentials return 401 with Bearer and Basic
challenges. Successful identity/credential IDs come only from the matched
configuration, including when the client supplies spoofed identity headers.
Disabled Consumer slots cannot authenticate. Configuration is compiled in; change
and restart to rotate/revoke credentials. See `examples/multi-consumer-auth.rut`.

The JIT request matrix checks both methods for both Consumers, exact identity
mapping, cross-method confusion, duplicate Authorization, disabled slots,
ambiguous ownership and bad metadata. Consumer authorization remains a separate
step after verification.

## Two-Consumer custom-header key policy

`auth.multiHeaderKey(presented, first, second)` checks one raw singleton custom
header key against two `auth.HeaderKeyConsumer(consumerId: ..., key: ...,
credentialId: ...)` records. Consumer IDs must be nonempty and distinct, both
credential IDs must be nonempty, at least one key must be enabled, and duplicate
nonempty keys are rejected as ambiguous configuration with 503 before checking
the request. Empty keys disable their slots. A missing, wrong, duplicate or
otherwise unmatched key returns 401 with `WWW-Authenticate: ApiKey`; success
publishes the matched configuration's identity metadata and method `apiKey`.
The helper does not retry Authorization, query or body values. Authenticate
before Consumer/group authorization, and call `req.remove("X-API-Key")` before
forwarding when the upstream must not receive the key. The JIT matrix covers
both Consumers, disabled/conflicting configurations, exact value matching,
spoofed identity headers, duplicate fields, authorization order and removal
from forwarded requests. See
[the runnable example](../examples/multi-header-key-auth.rut).

## Required credentials and bounded authorization union

`auth.headerKeyAndBasic(presentedKey, authorization, key, credentials, consumerId,
policyId)` requires both an exact opaque header key and valid Basic credentials.
There are no disabled slots or fallback methods. Pass the header key from
`req.uniqueHeader("X-API-Key").or("")` and the Basic field from
`req.authorization.or("")`. Missing, malformed, duplicate or wrong input in either
source returns 401, even when the other source verifies. Empty trusted keys,
credentials, Consumer IDs or policy IDs return 503. The published Identity uses
method `apiKeyAndBasic` and the configured policy ID as its credential ID, naming
the required pair. This is an explicit pair of shared credentials, not a claim
of independent multi-factor assurance. Both verifiers reuse the existing runtime.

`auth.requireAnyConsumer(identity, first, second)` allows either of two exact,
case-sensitive configured Consumer IDs and preserves the verified Identity.
Empty policy IDs return 503; an identity outside the set returns 403. A case or
prefix match does not count. Repeating `requireConsumer` applies intersection,
so it cannot implement this union. Authenticate before either policy helper:
missing/invalid credentials remain 401. Chained explicit deny checks still take
precedence when they occur first. No group membership is inferred from client
headers, and these ordinary functions do not prove the origin of a constructed
Identity. See the `/both-credentials` and `/allowed-consumers` example routes.

The JIT matrix covers each missing/wrong/duplicate factor, both valid factors,
configuration failures, each allow-set member, case/prefix mismatches, invalid
auth before authorization, and deny-before-allow composition.

## Current audit: executable optional authentication

The missing-versus-duplicate distinction is now available through
`req.headerCount("Authorization")`: 0 proves absence, 1 includes an empty field,
2+ reports duplicates, and -1 reports parsing failure. The field name is a
literal HTTP token, counts use original headers, and header overflow cannot
silently report absence. A nil singleton value alone is still insufficient.

`auth.apiKeyOrAnonymous(count, authorization, key, consumerId, credentialId,
anonymousId)` takes that count and `req.authorization.or("")` from the same
request. Only count 0 with an empty value returns the explicit anonymous
Consumer with method `anonymous` and no credential ID. Count 1 must verify the
configured Bearer key. Empty or malformed presented fields, wrong schemes/keys,
duplicates, parse failures and inconsistent count/value combinations return
401, with no retry using a different source. Empty configuration or equal guest
and authenticated Consumer IDs returns 503 even when credentials are absent.
The guest ID is intentionally distinct, and all metadata comes from configuration.

This is optional authentication for an explicitly public route, not a session
or permission to bypass authorization. Applying `requireConsumer` afterward can
reject the guest with 403; invalid authentication still returns 401. Leading
credential-removal effects cannot turn a presented credential into absence.
See `examples/anonymous-auth.rut`. The JIT matrix covers identity spoofing,
empty/duplicate/malformed input, body/header separation, config errors, private
route authorization and original reads after removal.

The audit retains these separate outstanding gates:

- Remote JWKS discovery/refresh and token-level revocation remain separate from
  the implemented configuration-owned RS256 integration.
- Forward-auth/OPA/introspection need reusable bounded response-consuming callouts
  with both-backend failure/cancel/close and buffer-lifetime evidence.
- OAuth/OIDC login, replay prevention and dynamic identity lifecycle require
  persistent state and explicit shard/node consistency, not local best-effort cache.
- mTLS identity mapping, LDAP and SAML/CAS need complete protocol-specific evidence.

This branch is based on main with the bounded Consumer policy work from
[#924](https://github.com/hurricane1026/Rut/pull/924), required credential pairs
and the exact Consumer allow union from
[#925](https://github.com/hurricane1026/Rut/pull/925), and the header-count
primitive from [#926](https://github.com/hurricane1026/Rut/pull/926). The
Standard Webhooks middleware still has a separate main integration tracked by
[#934](https://github.com/hurricane1026/Rut/pull/934), which is not included here.
## Optional multi-Consumer authentication

`auth.multiAuthOrAnonymous(count, authorization, first, second, anonymousId)`
extends absence-only optional access to both Bearer and Basic across the two
configured Consumers. Count and singleton value must come from the same original
Authorization field. Only count 0 with an empty value returns the configured
guest, with no credential ID and method `anonymous`. A presented field must
verify through `multiAuth`: empty/wrong/malformed input, duplicates, parse
failures and inconsistent count/value combinations return 401 with ordered
Bearer and Basic challenges. Disabled credentials cannot fall back to guests.

Consumer-pair validation applies even to absent credentials. An empty or colliding
guest ID, ambiguous secret ownership, duplicate/empty Consumer IDs, missing
credential IDs or all methods disabled returns 503. Identities and credential
metadata come only from configuration; client identity headers have no authority.
Private routes still authorize explicitly and can deny a valid guest with 403.
Removing Authorization before calling the helper cannot manufacture absence.

The JIT request matrix covers both methods for both Consumers, guest metadata,
spoofed identity, duplicates, malformed input, body/header separation, disabled
Consumer slots, configuration failure before fallback, challenge fields and
public/private authorization on HTTP/1.0 and HTTP/1.1 request buffers. This is
handler-level coverage; the existing network backends are unchanged. See
[optional-multi-auth.rut](../examples/optional-multi-auth.rut).

## Custom-header API Key rotation and optional access

`auth.rotatingHeaderKey` adds a current/previous opaque key window for a single
configured Consumer. Use `req.uniqueHeader("X-API-Key").or("")`; disabled slots
never authenticate an empty value. Both credential IDs stay nonempty even when
a slot is disabled. Current wins a tie; removing the previous key revokes it
after configuration reload/restart. Successful metadata comes only from the
configured Consumer and selected credential ID. Invalid credentials receive an
ApiKey challenge with 401; invalid configuration returns 503.

`auth.headerKeyOrAnonymous` requires count and singleton value from the same
original custom header. Only count 0 with an empty value grants the explicit,
distinct guest Identity with empty credential ID and method `anonymous`.
Empty/wrong/duplicate fields, parser errors and inconsistent arguments receive
401, never guest fallback. Empty trusted configuration or colliding Consumer IDs
returns 503 even when the field is absent. Authenticate before applying explicit
Consumer/group authorization; a guest can still receive 403.

Both functions select exactly the configured header source. Authorization,
query and body values do not supply fallback credentials. Reads continue to use
the original request after leading credential-removal effects. The JIT matrix
covers both HTTP/1 versions, disabled and revoked slots, equal keys, opaque
values, metadata spoofing, duplicate/malformed input, configuration failures,
inconsistent presence evidence and denial of guests on private routes. See
[the runnable example](../examples/header-key-policies-auth.rut). These are
compiled-in policies, not a dynamic credential registry.

## Static Consumer groups

`auth.ConsumerGroups` binds one verified Consumer ID to up to two exact,
case-sensitive group names. `auth.requireGroup(identity, group, first, second)`
checks one group, while `auth.requireAnyGroup(identity, first, second, member1,
member2)` allows either exact group. `auth.requireAllGroups(identity, first,
second, member1, member2)` requires both distinct exact groups in the same
Consumer record. None combines memberships across Consumers, and every helper
preserves the full verified identity on success; empty membership slots are
disabled. Empty group names, equal `requireAllGroups` required names, or invalid
membership configuration return 503. Equal required names remain valid for
`requireAnyGroup`. Missing, malformed, duplicate or invalid credentials remain
authentication failures, while a valid identity outside the requested groups is
denied with 403. Empty or duplicate Consumer IDs are configuration failures.
Group membership comes only from trusted configuration, not client identity or
group headers, and is compiled in until restart.

The JIT matrix covers successful single, either-group and both-group membership
in either slot order; rejects groups split across Consumers, empty slots,
case/prefix mismatches, unknown Consumers, malformed group configuration,
spoofed identity/group headers, invalid and duplicate credentials, and deny
before allow. See `examples/consumer-group-auth.rut` and
`examples/consumer-group-all-auth.rut`.

### Explicit group denial and precedence

`auth.denyGroup(identity, denied, first, second)` rejects a single exact group;
`auth.denyAnyGroup(identity, firstDenied, secondDenied, first, second)` rejects
either group. Both use the same trusted membership snapshot and preserve the
verified Consumer, credential ID and method on success. Unknown Consumers deny
with 403 rather than bypassing the policy; a registered Consumer with no groups
can pass. Empty denied names and invalid membership records return 503, even if
the invalid record belongs to a different Consumer. Repeated denied names are
idempotent; names remain case-sensitive with no prefix or wildcard matching.

Run authentication first and denial before an allow check. A Consumer belonging
to both a denied and allowed group receives 403; missing, malformed or duplicate
credentials still receive 401. Anonymous identities are not implicitly added to
the membership registry. Removing a denied membership can permit a registered
Consumer again; removing the Consumer record does not grant access. This remains
a compiled-in, bounded policy, not a dynamic registry or membership lifecycle.

The JIT request matrix covers Bearer/Basic metadata preservation, both Consumer
positions and membership slots, case/prefix distinctions, empty slots, malformed
configuration, spoofed identity/group headers, deny-before-allow composition,
unknown verified Consumers and optional-auth guests. See
[the runnable example](../examples/consumer-group-deny-auth.rut).

## Static HS JWT secret rotation

`auth.rotatingJwtDocumentHs256` / `Hs384` / `Hs512` verify against an explicit
current/previous secret window, preserving a fixed trusted algorithm. Empty
secrets disable slots; both disabled returns 503. Nonempty keys retain the
existing 32/48/64-byte verifier minimums. Removing the previous secret revokes
that slot after configuration reload/restart. Token `kid`/URL hints do not select
or fetch keys, and no algorithm fallback is performed.

Both bounded decoders run, with independently request-owned claims bytes; their
first successful result is selected. A failed second decode cannot erase a
successful first result. This is signature verification only. The example
composes issuer/audience/time/subject validation and exact scope authorization;
signed but expired, premature or wrong-recipient tokens remain 401, and missing
scope returns 403. The policy credential ID comes from trusted configuration,
not token headers or the matched key. Live rotation and durable revocation remain
separate work.

The JIT matrix uses independently Python-signed tokens for all three algorithms
and covers slot disabling/revocation, equal keys, wrong-key/algorithm signatures,
malformed JOSE/claims, duplicate Authorization, spoofed identity headers and
claims preservation after the second verification. See
[the native-capable example](../examples/jwt-secret-rotation-auth.rut).

## Implementation order and gates

1. Complete local credential foundations and signed-message primitives. Add
   independent RFC vectors, binary/empty/oversize inputs, duplicate fields,
   rotation/revocation and JIT-to-runtime evidence.
2. Complete signed-request freshness/replay policy, remaining asymmetric algorithms,
   and remote JWKS refresh.
   Canonicalization and supported algorithms must be explicit profiles, with
   negative interoperability vectors; do not accept token-controlled algorithms.
3. Build reusable bounded response-consuming callouts, then forward-auth, OPA
   and introspection. Both epoll and io_uring must cover failure, cancellation,
   close and buffer lifetime before authentication depends on the response.
4. Build sessions and persistent single-use state, then OIDC/OAuth2/upstream
   tokens. Test concurrent refresh, rotation, replay and IdP outages.
5. Add direct LDAP, mTLS mapping and SAML/CAS/provider adapters with full protocol
   fixtures. Existing TLS server support is insufficient proof of client identity.

Use Rut modules for policy; add only reusable bounded primitives to C++.
Preserve shard-owned state and RCU configuration. No new keywords, external
libraries, synchronous network calls or secret-bearing logs are introduced.
Every completed row needs focused negative tests and actual end-to-end evidence.

## HMAC profile delivered here

The builtin verifies full lowercase hexadecimal HMAC-SHA256 over exact bytes.
Input limits are 4096 key bytes and 1 MiB message bytes; the request-body ingress
limit remains independent. Empty messages are valid, empty keys disable a slot,
and no arbitrary algorithm is accepted by the primitive. An optional fourth argument
sets the exact trusted prefix (up to 64 bytes); omitted means no prefix. The GitHub
Rut helper separately requires `sha256=` and a unique signature header.

Fixtures: [RFC 4231](https://www.rfc-editor.org/rfc/rfc4231) cases 1/2/6 and the
[published GitHub vector](https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries).
Tests cover tampering, canonical signature syntax, binary/empty inputs, bounds,
ambiguous fields, configuration errors and previous-key revocation. Verification
alone intentionally makes no delivery replay guarantee. A duplicate delivery can
still verify successfully; receiving applications must deduplicate durable side
effects until a complete gateway replay policy is implemented.

### GitHub Webhook secret rotation

`auth.rotatingGithubWebhook` evaluates trusted current/previous keys against the
same raw body and singleton `X-Hub-Signature-256` value. Both slots retain the
exact `sha256=` prefix and full lowercase SHA-256 digest requirement. Empty keys
disable slots, while Consumer and both credential IDs must be nonempty. Current
wins a tie; removing the previous key revokes it after configuration reload or
restart. Both disabled keys or empty metadata returns 503, and verification
failures return 401. Successful identity uses configured Consumer/credential IDs
and method `hmac`, never client identity headers.

The JIT matrix uses independently Python-signed ordinary, empty and binary body
fixtures. It covers both HTTP/1 versions, disabled/revoked/equal keys, metadata
errors and spoofing, duplicate signature fields, wrong algorithms/prefixes,
noncanonical/truncated hex and body tampering. The native-capable
[example](../examples/github-webhook-rotation-auth.rut) verifies before JSON
processing. Repeated authenticated deliveries can still verify during the
window: this adds no timestamp policy, delivery-ID binding or durable replay
store, and does not complete the signed-request/replay acceptance gates.
HTTP/1 delivery in the example retains the current buffered-body profile:
chunked requests are rejected with 400 at admission, before verification.

## Native fixed-profile HS256 issuance

`jwt_hs256_issue` and the Rut/JIT `jwtIssueHs256(subject, issuer, audience,
key, ttl)` builtin emit a compact token with exactly `sub`, `iss`, `aud`, `iat`
and `exp`, using the fixed `{"alg":"HS256","typ":"JWT"}` protected header.
It accepts only a 32–4096-byte HMAC key, nonempty valid UTF-8 claim strings,
positive caller-supplied Unix seconds, and TTL 1–86400 seconds with checked
expiry addition. NUL and ASCII controls reject; quotes and backslashes are
escaped. Claims and output are bounded to 8192 and 11004 bytes respectively.
The native APIs use existing pinned static SHA-256 HMAC support, write only to
caller-owned buffers, retain no views and reject buffer aliasing. The native
`jwt_hs256_issue_with_id` adds exactly one caller-supplied `jti` string under
the same validation and size bounds; the caller is responsible for ID
uniqueness. The Rut/JIT five-claim builtin samples realtime once and stores a
successful token in the request JSON arena; failure returns nil.
`Crypto.issueJwtHs256` is its qualified wrapper. `auth.jwtForIdentityHs256`
uses `identity.consumerId` as `sub`, but Identity values carry no authentication
provenance, so call it only after successful authentication.

The Rut/JIT `jwtIssueHs256WithId` and `Crypto.issueJwtHs256WithId` variant adds
one caller-supplied `jti` string; `auth.jwtForIdentityHs256WithId` provides the
same identity-based subject convenience. Issuance does not guarantee
uniqueness or prevent replay. `auth.requireUnrevokedJwt` checks only its
configured static two-ID snapshot. Tests cover strict claims round-trip,
failures, tampering, zero allocations, and JIT request-arena ownership.
Arbitrary claims and other signing algorithms are not supported.

The native and Rut/JIT `jwtIssueHs256WithIdAndScope` APIs add exactly one
trusted single-token `scope` claim to the `jti` profile. The value shares the
ASCII OAuth scope-token grammar used by `jwtHasScope`; invalid or non-ASCII
values fail issuance. Identity helpers require callers to authenticate first.
Consumers verify signature and issuer/audience/lifetime, apply the static jti
snapshot check, then authorize scope. There is no live revocation or replay
protection.

## Asymmetric key ownership foundation

The internal `RsaPublicKey` owner loads one canonical SubjectPublicKeyInfo DER
object during configuration preparation. It bounds input to 8192 bytes and
accepts ordinary RSA public keys with 2048–4096-bit odd moduli and exponent
65537. Wrong key types, RSA-PSS-restricted keys, trailing data, noncanonical
encodings and unsupported parameters fail before publication. Input storage
may be released after loading; crypto resources remain with the owner.

An owner cannot be copied or overwritten while loaded. Build a new owner for a
replacement configuration generation; retain the old generation until its last
reader drains, then destroy it. Parsing and destruction are configuration work,
never request-path operations. Failure does not leave a partially published key
or pollute the caller's crypto error queue.

The native `RsaSha256Verifier` retains a key reference and initializes mutable
BN/Montgomery scratch before activation. Each shard initializes its own verifier on that shard before serving requests,
including warming crypto thread-local state.
It verifies raw fixed-width RSASSA-PKCS1-v1_5 SHA-256 signatures over exact bytes
(up to 1 MiB), comparing the entire canonical encoded message. It rejects
out-of-range representatives, malformed padding and DigestInfo, and mismatches.
Tests cover the RFC 7515 A.2 vector, 2048/2049/3072/4096-bit generated keys,
empty/binary/bounded messages, owner release, and crypto allocation hooks that
observe zero request-path allocations after initialization.

The native decoder and trusted configuration importers below build on this
foundation. A Rut key type, request-driven key selection and JWKS refresh remain
acceptance work; the native slices do not complete asymmetric authorization.

## Fixed-key RS256 compact JWT decoding

The native `jwt_rs256_decode` verifies compact JWS with a caller-selected,
shard-owned RSA verifier. It requires RS256, canonical unpadded base64url, an
object protected header (1024 bytes maximum) and object claims (8192 bytes
maximum). Duplicate decoded JSON names fail closed. `crit` and `b64` extensions
are rejected; `kid`, `jku` and other hints never select or fetch a key. The exact
encoded header and payload are authenticated before claims are published.

The caller supplies output and JSON workspace. On failure output length is zero
and the document is invalidated; on success the document borrows the output.
Signature verification alone is not authorization: apply issuer/audience/time
and subject policy using `jwt_claims_valid`. This is native coverage, with RFC
7515 A.2 and authenticated negative-profile tests. Rut configuration/JIT wiring,
request-driven key selection and JWKS refresh remain pending.

### Fixed RS256 public JWK configuration

The native configuration-only `RsaPublicKey::load_rs256_jwk` imports one public
RSA JWK into the existing owning key object. This deliberately restricted profile
requires `kty: "RSA"`, `alg: "RS256"`, minimally encoded unpadded base64urlUInt
`n`, and `e: "AQAB"` (65537). It retains the DER loader’s 2048–4096-bit odd
modulus bounds. Optional `use` must be `"sig"`; optional `key_ops` must be
exactly `["verify"]`. RSA private parameters, duplicate decoded JSON names,
noncanonical integers and inputs above 8192 bytes are rejected. A loaded owner
cannot be replaced without reset, and does not borrow the JSON input.

Unknown metadata is ignored and never establishes trust: no `kid` selection,
certificate processing, URL fetching, JWK-set handling or JWKS refresh occurs.
The caller must supply trusted configuration. Import allocates only during
configuration; request verification continues through the existing shard-owned
verifier. The configured RS256 integration below supplies the Rut/JIT
authorization surface around this native importer.
The representation follows [RFC 7518 §6.3.1](https://www.rfc-editor.org/rfc/rfc7518.html#section-6.3.1)
and the usage fields follow [RFC 7517 §4](https://www.rfc-editor.org/rfc/rfc7517.html#section-4),
with the stricter mandatory algorithm policy described above.

### Trusted configuration selection from JWK Sets

`RsaPublicKey::load_rs256_jwks` selects one key from a trusted, locally supplied
JWK Set by an explicitly configured, case-sensitive `kid`. Input is bounded to
8192 bytes and 16 key objects. Every entry must have a nonempty decoded string
`kid` of at most 128 bytes; duplicate decoded IDs anywhere in the set reject
the whole configuration, including duplicate IDs unrelated to the selected key.
Unknown IDs fail without fallback. Selected keys must pass the fixed public
RSA/RS256 importer; unselected objects need only satisfy the ID constraints and
may represent other algorithms. The whole set is checked before publication.

This is configuration work with independent key ownership, not request-driven
selection or remote JWKS retrieval. Token header hints cannot trigger import,
fetching, fallback or refresh. Rotation still requires preparing a replacement
configuration generation and draining readers of the old generation. No Rut/JIT
key API or live JWKS lifecycle is added.

The native integration fixture exercises JWK Set import, verifier activation,
configuration/owner release, compact JWT verification, issuer/audience/expiry
policy and exact scope checks together. It also confirms that signed token key
hints do not change the configured key and observes no crypto allocations on
that verification path. This is native integration evidence, not Rut/JIT or HTTP
end-to-end coverage.

### Approved multi-key ownership and per-shard activation

The native `Rs256KeySet` prepares an explicitly approved subset of a local JWK
Set: 1–16 unique, nonempty decoded IDs, each at most 128 bytes, with source JSON
at most 8192 bytes. Every approved entry must satisfy the existing fixed RSA/
RS256 public-key importer. Unapproved entries never become trusted merely by
appearing in the source; the existing whole-set ID shape/uniqueness checks still
apply. A missing approved key or any invalid selected key rolls back all prepared
entries. A loaded set cannot be overwritten without explicit reset.

`Rs256VerifierSet` initializes separate mutable verification workspaces on each
execution shard before serving requests. Each retains independent key references
and copies the canonical IDs. Configuration JSON, approval-list storage and the
source key owner may then be released. Selection compares exact decoded ID bytes
with no case folding, prefix match, empty/default key or unknown-key fallback.
The returned pointer and ID view belong to that verifier set and expire at its
reset/destruction; a selection is not proof of authentication.

Generation changes require preparing new owners and shard-local workspaces,
then retaining old ones until their readers drain. This foundation adds no live
JWKS refresh, Rut key/configuration surface or automatic token `kid` selection.
Tests cover subset trust, failure rollback/reuse, source lifetime, 16-key/128-byte
bounds, embedded-NUL IDs, the independent RFC 7515 verification vector, and two
concurrent threads activating their own verification state.

## RS256 verification and claims publication

The native `jwt_rs256_validate` entry point verifies the fixed-key compact JWS
and applies the existing strict `jwt_claims_valid` policy before publishing its
claims document and output length. Caller-configured issuer/audience, nonempty
subject, integer expiry, optional nbf/iat and a positive caller-supplied clock
are mandatory policy checks with zero skew. Signed but expired, premature or
wrong-recipient tokens fail with an invalid document and zero output length.
The caller must still enforce scopes, revocation and replay policy, and must
not use unspecified output bytes after failure. Tests cover signed claim-policy
failures, malformed/tampered tokens, stale-publication invalidation and crypto
allocation hooks. The configured Rut/JIT/native integration below uses this same
profile with approved protected-header kid selection.

## Standard Webhooks symmetric verification

The native `standard_webhook_valid` implements a bounded HMAC-SHA256 `v1`
profile over the exact `id.timestamp.body` bytes, following the
[Standard Webhooks specification](https://github.com/standard-webhooks/standard-webhooks/blob/main/spec/standard-webhooks.md).
The caller supplies trusted decoded secret bytes (1–4096 bytes, not a `whsec_`
string), a positive Unix clock and a tolerance of 0–300 seconds. Both past and
future boundaries are inclusive. Use endpoint-specific strong keys; signature
headers never supply keys or select an algorithm.

The ID is 1–256 visible ASCII bytes without a period; timestamps are canonical
positive signed-64-bit decimal seconds. Raw bodies may be empty or binary and
are bounded to 1 MiB. Signature headers are bounded to 4096 bytes and 16 entries
separated by exactly one space. `v1` entries require canonical padded standard
Base64; unknown alphanumeric version tags with nonempty visible opaque values
are ignored. Malformed entries anywhere reject the entire header, including
suffixes after an otherwise valid signature. Multiple valid-format signatures
support sender key rotation. Callers may independently try another trusted key
within their configured rotation window.

`auth.rotatingStandardWebhook` accepts current and previous decoded keys and
their configured credential IDs. Both slots are checked; the current slot wins
when both match. Empty keys disable slots, and removing the previous key revokes
that slot. Empty identity metadata or two disabled slots returns 503; invalid
signatures and malformed or duplicate headers return 401. Freshness is not
replay protection: verified IDs still need durable deduplication.

`hash_digest_parts` reuses existing stack digest/HMAC contexts over at most 16
borrowed spans, avoiding a body-sized concatenation buffer or request allocation.
Inputs are borrowed synchronously; no body JSON parsing or network operation
is needed. Rut callers must obtain singleton
`webhook-id`, `webhook-timestamp` and `webhook-signature` fields and reject
ambiguous HTTP fields before invoking the primitive.

Freshness does not guarantee uniqueness: a repeated ID can still verify inside
the time window. Applications must durably deduplicate authenticated IDs before
side effects, including cross-shard/node coordination. This slice adds no replay
store. Tests use fixed Python HMAC/Base64 oracle outputs with upstream Python
fixture inputs, tampering and malformed lists, rotation, size/clock boundaries,
and zero observed crypto allocations after warmup. HTTP/Rut end-to-end tests
exercise the identity helpers; persisted replay handling remains pending.

## Request-owned identity header storage foundation

The internal `rut_helper_req_set_owned_header` copies header names and values to
request-arena storage before recording a replace/dedupe operation. It validates
HTTP bytes and framing-reserved names before copying, limits copies to 8192 bytes
per request and retains the existing 16-operation limit. Invalid values, exhausted
storage or overflow poison forwarding rather than silently omitting an identity
header. Source buffers may be released or overwritten after recording; the
request arena must live through forwarding. HTTP/1 request and HTTP/2 stream
boundaries reset the copy budget. No inline per-connection byte buffer or new
allocator/dependency is added.

Rut `req.set` accepts non-optional runtime strings and uses this storage for
nonliteral values. A selected match arm after an authentication helper can replace
spoofed identity fields with verified metadata. Credential stripping remains
explicit, and callers choose the identity fields they trust and forward.


## Configured RS256 end-to-end integration

The native configuration-time `Rs256Policy::load_jwks` additionally accepts
JWKS bytes separately from trusted issuer, audience and approved key IDs. It
reuses the bounded key importer, rejects malformed or ambiguous key sets, and
owns the selected keys and trust metadata after a successful load. Failed
preparation leaves the key set invalid; a loaded policy is not overwritten.
This is an import boundary for a future refresh path: it does not fetch a URL,
authenticate a server, schedule refresh, publish an RCU generation, or expose
remote JWKS to Rut programs.

`jwtVerifyRs256(token, policy)` now connects approved public JWK Sets to Rut,
JIT handlers and exported native programs. The static policy binds issuer,
audience, approved kids and public JWKS. Invalid policies fail at compilation or
loading. Mutable verification state belongs to individual shards, activates
before accepts/config adoption, and is retained with its configuration generation
until readers retire. Unactivated/failed rows reject without lazy key import.

`auth.jwtDocumentRs256` verifies the Bearer signature and mandatory claims;
`auth.jwtIdentityRs256` additionally authorizes scope before publishing subject
and a trusted policy credential ID. HTTP tests cover valid tokens, signature
modification, wrong algorithms, unknown/missing kid, wrong issuer/audience,
expiry/future nbf, empty subject, scope rejection, duplicate Authorization and
clock failure. Native artifact tests remove the source after compiler exit and
verify against reconstructed configuration owners. Native crypto tests cover
approved multi-key rotation, removed-key rejection, independent generations and
zero crypto allocations during warmed verification.

See [the language card](language-card.md#rs256-with-a-configured-trust-policy)
for exact bounds and [the runnable example](../examples/jwt-rs256-auth.rut).
The bounded remote-JWKS and revocation-snapshot extensions are described below.
OAuth/OIDC and persistent online revocation/replay state remain separate work.


## Configuration-owned RS256 token revocation

The trusted policy accepts optional `revokedJtis` (up to 64 distinct, nonempty
IDs of at most 128 decoded bytes) and `issuedAfter` (positive i64 Unix seconds).
Supplying `revokedJtis`, even `[]`, requires a bounded nonempty string `jti`;
exact decoded matches reject. Supplying `issuedAfter` independently requires
integer `iat` strictly later than the cutoff, in addition to the existing
no-future-issuance rule. Configuration errors fail before activation. Signature,
claims and revocation must all pass before claims or identity are published.

Native tests cover escaped and binary IDs, exact case/prefix behavior, missing
and malformed claims, duplicate decoded IDs, bounds, cutoff equality, zero
observed warmed crypto allocations, independent shard rows, owned configuration
bytes and old/new generations. HTTP/JIT tests check 401 Bearer challenges and no
identity-body publication after revocation; native artifact tests apply the same
policy after compiler exit and source removal.

This is immutable snapshot revocation through the existing configuration/RCU
lifecycle. It does not add an online mutation API, distributed persistence,
remote JWKS refresh, or token replay protection. Old readers retain old policy;
operators must durably retain and distribute the source revocation configuration.
The complete JSON policy remains bounded to 8192 bytes. See the language card
for syntax and rollout semantics.



## Bounded remote JWKS refresh

Compiled RS256 and ES256 policies accept a trusted `remoteJwks` endpoint with
fixed IPv4, TLS hostname, CA, path, refresh interval, maximum cache age and total
fetch timeout. The initial JWKS defines approved IDs but does not authenticate
remote-mode requests before the first successful fetch. Only configured approved
kids can be imported. A valid empty intersection immediately removes cached keys.
There is no token-triggered fetch, DNS, discovery or redirect following.

The reusable bounded HTTPS state machine and existing HTTP/chunk parsers accept
200 JSON bodies with strict framing, byte limits and authenticated transport.
Each shard prepares a separate verifier bank before replacing its cache. Failures
retain old keys only until monotonic maximum age; no failed response renews it.
Verification performs no I/O/import, and config adoption/shutdown cancel the
retired task. TLS/socket ownership has no in-flight kernel buffer dependency.

Unit tests cover fragmentation, framing ambiguity, media/size limits, TLS hostname
and CA failures, timeout/cancel, cache expiry, HTTP/JSON failures, key replacement,
authoritative removal and shard isolation. Real gateway tests are registered
separately for each algorithm on epoll and io_uring; unavailable io_uring is
explicitly skipped. They execute compiled native policy after source removal,
fetch from a local certificate-authenticated HTTPS origin and verify idle-shard
rotation, empty-set removal, outage/malformed-response expiry, recovery and
shutdown while a fetch is waiting on the origin. Control-plane tests verify
config adoption cancels only the retiring shard's fetch and activates only its
new verifier row. See the language card for exact supported scope.

This closes the fixed-endpoint/approved-kid refresh slice, not remote discovery,
automatic new-kid admission, conditional revalidation, HTTP/2/compression,
cross-node synchronization, online Token revocation, signing or JWE.

## Native password-storage primitive

`rut::password_hash` and `rut::password_verify` in
[`password.h`](../include/rut/runtime/password.h) are synchronous native C++
primitives for offline provisioning or an independently scheduled worker. Hash creation remains native; request verification uses the bounded Rut header
prefix described below. These synchronous primitives are not Basic auth helpers.
Do not invoke them on an event-loop shard: 600,000 HMAC rounds can block other
connections. `PasswordWorker` supplies the bounded worker used by the gateway timer bridge.

The fixed profile is PBKDF2-HMAC-SHA256 (RFC 8018), 600,000 iterations, a
16-byte salt and a 32-byte derived key. No dependency or
language keyword is added: it reuses the existing stack-only HMAC and pinned
static OpenSSL constant-time comparison/cleansing utilities. All scratch is
stack-owned and derived-key/HMAC scratch is wiped before return.

Passwords are 1–1024 exact bytes, including embedded NUL; there is no implicit
truncation, Unicode normalization or NUL termination. The preferred
`password_hash(password, output, capacity, output_len)` overload
generates a fresh 16-byte salt using the OS CSPRNG. Linux uses one nonblocking
`getrandom` call; macOS uses one `getentropy` call. Entropy failure, interruption
or a short read fails closed with zero output length and unchanged output. No
retry, partial-salt acceptance or fallback PRNG is used. Invalid input/output
is rejected before requesting entropy. The explicit-salt overload remains for
trusted callers, which must provide a fresh cryptographically random salt per
password. The deterministic test salt is exclusively a fixture, not an example
production salt. Hashing does
not enforce password strength or persist credentials.

The 123-byte ASCII record (without a terminating NUL) is:

```text
$rut-pbkdf2-sha256$600000$<32 lowercase salt hex digits>$<64 lowercase key hex digits>
```

Only this exact profile is accepted: uppercase hex, alternate costs or
algorithms, extra fields, embedded NUL and trailing bytes are rejected before
performing the expensive derivation. The record is project-specific, not a
claim of compatibility with PHC, modular crypt or another application's record
format. `password_hash` sets the length to zero on failure and leaves the
output buffer unchanged; `password_verify` returns false for invalid records
and wrong passwords. Their timings differ for malformed and valid records;
only the derived-key comparison is constant-time. Account enumeration, abuse
controls and uniform authentication responses belong to the application policy.

The existing `test_hash` target includes independent Python `hashlib` PBKDF2
vectors, binary and long-key passwords, rejection/buffer bounds, and incorrect
password cases. User registration, password changes/resets, automatic rehash,
pepper management, a durable user registry and persistent sessions/refresh remain
unimplemented. The fixed-account password/JWT composition below is supported.

The salt-generating overload is exercised through the same internal callback
pattern as `generate_uuid`: deterministic entropy and partial/error injection
verify the stored record and unchanged-output failure contract. A real OS
entropy smoke test verifies that the generated record authenticates correctly;
no probabilistic distribution or collision assertions are used.

## Bounded native password verification worker

[`PasswordWorker`](../include/rut/runtime/password_worker.h) provides one private
background thread and eight fixed-capacity slots per caller-owned instance.
Exactly one producer shard uses `submit`, `poll` and `cancel`; a lifecycle owner
starts the instance before transfer to the shard, reclaims it after the shard
quiesces, and stops it off the request path. No mutex wait or heap allocation
occurs in the shard API. Startup reports thread-creation errors through the
existing `Expected<void, Error>` type. No worker is attached to gateway loops
or created automatically by a connection or request.

Submission copies a 1–1024-byte password and a fixed-length record into owned
slot storage before release-publishing the job. A full or stopped worker and
invalid spans return an invalid token. Completed but unpolled results retain
their slot, so neither queue nor result storage grows. Tokens carry their
worker owner, slot and a monotonically increasing generation, preserved across
restart; stale or foreign tokens cannot observe or cancel reused slots. Token
validity ends at worker destruction. Generation exhaustion rejects further
submissions instead of wrapping to a reusable generation.

The worker verifies only copied bytes, wipes inputs before publishing its
boolean result, and never touches a connection, request arena, policy object
or shard allocator. Only the owning shard consumes results. `poll` returns
Queued/Running while pending, and consumes Matched/Rejected exactly once.
Malformed records and incorrect passwords both produce Rejected.

Cancellation makes the token invalid immediately. Queued work is skipped if it
has not started; an already running fixed-cost KDF is allowed to finish on the
background thread, its result is discarded and its inputs are wiped before
capacity is released. There is no unsafe pthread cancellation or slot reuse
while the worker owns inputs. Stop rejects future submissions, skips queued
work, joins at most the currently executing fixed-cost KDF and wipes all slots.
It is idempotent and must run off-shard with the producer quiescent. Violating
exclusive lifecycle ownership such that join fails is fatal rather than
releasing storage still potentially used by a worker. No wall-clock completion
bound is promised when the OS deschedules the thread.

The idle worker scans at one-millisecond intervals, following the existing
background flusher polling model. A borrowed nonblocking, close-on-exec pipe FD
now signals completion and cancellation cleanup. The gateway bridge supplies timer suspension,
deadlines and connection/stream cancellation. The Rut prefix adds automatic
shard ownership and explicit status mapping as described below. Password
hash creation remains an offline synchronous operation, not a worker job.

`test_hash` covers copied-input lifetime, queue saturation, cancellation of
pending/running/completed work, result consumption, stale and foreign tokens,
shutdown with pending work, restart and invalid submissions. Running-cancel
coverage permits an already-completed result if the producer was descheduled,
without relying on a fragile fixed sleep.

## Native request completion and deadline adapter

[`PasswordRequest`](../include/rut/runtime/password_request.h) provides a native
single-shard request state machine around the worker. It owns only a worker
token and a monotonic deadline; the worker never accesses the adapter. A begin
must use a 1–60,000 ms budget and reject overflowing deadlines. Queue pressure,
invalid input or a stopped worker becomes Unavailable. A deadline check runs
before result consumption: at equality or later, even a completed matching
result is cancelled and reported as TimedOut. Terminal results are consumed
once through `take`; active requests cannot be overwritten by another begin.
Explicit `reset` is the close/reload detach operation, cancelling pending work
before forgetting the worker. Destruction also cancels pending work.

The owner must keep the worker alive through pending adapter use, reset adapters
before worker stop/replacement, and arm a separate deadline timer. The adapter
accepts caller-supplied CLOCK_MONOTONIC milliseconds; it does not itself register
callbacks, store connection pointers or extend any configuration lifetime.

`PasswordWorker::completion_fd()` exposes a borrowed readable notification FD.
The worker release-publishes completion or cancellation cleanup before a
nonblocking one-byte write. A full pipe coalesces notifications instead of
blocking the worker. The producer drains notifications before scanning pending
requests; signal bytes are not task IDs or an exact count of results. The FD
is owned by the worker and must be unregistered before stop; callers must not
close it or change flags. Stop joins before closing both pipe ends, avoiding
writes after reader destruction. Restart creates new pipe endpoints. Setup
failure returns a Pipe error; thread-creation failure closes both endpoints.

Tests block on the real notification FD while no gateway traffic or active task
polling occurs, verify success and cancellation cleanup wakeups, exact-deadline
rejection of already-completed success, pending timeout, saturation, once-only
consumption, close/reset reuse and descriptor closure across restarts. This is
native adapter coverage, not a claim of epoll/io_uring handler integration.
The optional native HTTP/1 bridge below reuses existing timers for resume/close
wiring; direct gateway FD registration and the Rut/JIT/native-artifact API remain
outstanding.

## Optional native gateway bridge

[`PasswordGateway`](../include/rut/runtime/password_gateway.h) connects the native
worker/request adapters to trusted native HTTP/1 and HTTP/2 `HandlerFn` routes. The lifecycle
owner starts one service, binds `loop.password_gateway` after loop init and
before run, and keeps it alive until the loop and all connections are stopped.
It is independent of RCU configuration objects; task inputs are copied rather
than retaining policy records or request views. Native embedders can bind a service explicitly; requiring compiled Rut routes
automatically create one per shard, as described below.

Shared HTTP/1 dispatch and resume establish an invocation-local service binding
using POD thread-local pointers, restoring the previous binding on every exit.
Explicit nested scopes can mask the service and restore it on exit. Ordinary
handlers with no bound service retain their original path without TLS binding
work. No handler ABI or
connection layout changes are made. A helper call for a foreign connection,
without a binding, or with invalid request/stream identity returns Unavailable.
There is no shared cross-shard password service or worker-global request state.

`verify_password_for_request(connection, password, record, timeout_ms)` returns
an explicit status and, for Pending, a bounded retry interval (at most 10 ms,
clamped to the remaining deadline). The native handler returns the existing
Timer yield and calls the helper again when resumed. Epoll/io_uring retain their
existing millisecond timer semantics, including idle wakeups and stale timer
filtering; no new IoEvent type or yield ABI is introduced. Gateway completion
FD registration is not used by this profile: signals are drained during helper
polls, while timers guarantee progress without unrelated gateway traffic.

Entries are keyed by loop-local connection ID and handler generation. Resuming
an existing task polls its copied inputs and original deadline; changing helper
arguments cannot replace the credentials or extend the budget. Shared dispatch
cancels leftover tasks before a new HTTP/1 request generation, when a handler
returns a non-Timer outcome, on timer scheduling failure, and when the CRTP
close/free paths retire a connection. A peer disconnect not yet observed by
the existing transport may complete verification before send/close detects it;
results cannot migrate to a later request or reused connection slot.

Only Matched authorizes. Rejected, TimedOut and Unavailable remain distinct for
the caller's response policy; the bridge neither chooses an identity nor emits
a login/session token. Worker backpressure and input/lifecycle failure do not
become credential success. Native handlers must not proxy or busy-loop while
pending. The test handler uses a local fixture header solely to exercise runtime
behavior; it is not a shipped credential-extraction policy.

This is not a Rut built-in, middleware function or an exported native-artifact
helper. Those require compiler/loader integration and explicit async semantics.
Automatic application lifecycle/configuration remains unimplemented. HTTP/2
native verification follows the bounded extension below.

Runtime validation for the bridge is registered in the existing `test_network`
target: real quiet epoll and io_uring HTTP/1 success/rejection, timeout, abandoned
work, disconnect and slot reuse; mock tests cover invocation binding, HTTP/2
refusal, timer failure cancellation and generation/deadline fencing. The full
network/hash regression passed. A complete no-JIT ASan/UBSan runtime build passed
the nine gateway tests; focused TSan testing instruments the new service, worker,
hash/password code and gateway fixture while linking ordinary runtime/OpenSSL
archives for the other components. macOS/kqueue and compiler/JIT exposure were
not validated locally.

## Native HTTP/2 password verification

The optional native bridge also supports HTTP/2 `HandlerFn` invocations. Dispatch
binds the actual stream ID, and resume reuses the same stream binding and original
deadline. Service keys are widened to 64 bits: HTTP/1 generations occupy the low
32-bit domain, while HTTP/2 uses a separate protocol tag plus the 31-bit stream
ID. A live, odd client stream is mandatory. The worker still retains only copied
credentials and an opaque token, not an Http2Stream/Connection pointer.

The runtime's existing single suspended-stream contract remains in force.
With the service enabled, a competing native handler is refused before resetting
the connection-owned handler context. The helper independently rejects a stream
binding that conflicts with the existing async owner. Another stream cannot
replace a pending task's password, deadline, synthesized request or frame slots.

An H2 task guard cancels only the current stream's task on terminal or failed
invocation. Successful Timer suspension/re-arm retains the task; RST_STREAM
cancels only the reset stream. Thus a reset/503 on another stream cannot cancel
the current owner. Connection close/free still cancels every task for that
connection. Stream reset is acted on when the existing transport observes it:
control frames coalesced after the suspending HEADERS are processed immediately,
while later network frames follow the runtime's existing parked-stream read
behavior. The existing async slot pins the RCU config epoch and synthesized
request across waits. No new stream/connection fields or packed handler ABI
values are introduced.

The gateway fixture exercises HTTP/1 and HTTP/2 over real epoll and io_uring:
verified success, wrong password, timeout, terminal abandonment, disconnect and
stream/slot reuse. HTTP/2 additionally sends HEADERS + RST_STREAM + another
stream's wrong credentials in one batch and requires no response for the reset
stream. Focused tests cover stream-binding restoration, busy-context integrity
and unrelated-stream reset isolation. Rut/JIT/native-artifact helper exposure
and automatic service configuration remain outstanding.

## Rut password verification and worker lifecycle

`passwordVerifyHeader(header, record, timeoutMs) -> i32` is a bounded asynchronous
prefix, supported by Rut, ORC JIT and relocated native artifacts. The
[language card](language-card.md#password-verification-prefix) defines its exact
placement, compile-time policy, transport and status contract. The compiler
requires the first route `let` and no explicit waits. The independent RIR
verifier and code generator also require a single constant-only entry prefix,
valid canonical policy, scalar i32 result and no branch back into entry. Pending
returns the existing Timer yield with state zero; later effects execute only
once a terminal result is consumed. Parse-cache and time-latch scopes are
released on both suspension and ordinary return. The packed handler ABI is
unchanged. Native artifact version 16 records the route's worker requirement;
the helper is in the shared ORC/native relocation allowlist.

`Shard` lazily starts its embedded service on the lifecycle/control thread before
spawning a requiring config or publishing the first requiring reload. The loop
consumes the config mailbox before the service mailbox, then binds the service
before adopting that config. This preserves publication ordering even if a reload
races with a maintenance pass. `join()` also drains unconsumed mailboxes. The
worker survives reload, disabling routes and stop/join so older RCU readers and
pending request deadlines retain their service. Final shutdown cancels tasks,
joins the active KDF, wipes slots and closes descriptors after shard termination.
Ordinary shards that never require password verification start no extra worker.

Tests cover frontend placement/policy rejection, forged RIR and independent
codegen rejection, no route effects while suspended, correct and incorrect
credentials, duplicate/missing fields, automatic startup/reload/join/shutdown,
and relocated execution after compiler exit and source removal. A real CLI
smoke test covers epoll and io_uring without manual service binding. Existing
native bridge tests cover HTTP/2 stream isolation, cancellation and deadlines.

This is a fixed-record verifier, not a durable account system. Provision hashes
offline using the random-salt native API; use TLS for credential transport and
apply application abuse controls. Registration, lookup, password reset/change,
rehash migration and persistent session/refresh orchestration remain open work.
The fixed-account JWT composition below is supported.

## Fixed-account password-to-JWT login

The shipped [password/JWT example](../examples/password-jwt-login.rut) combines
the existing prefix, `auth.passwordIdentity`, UUID generation, scoped HS256
issuance and strict resource-server checks. The [language card](language-card.md#fixed-account-passwordjwt-composition)
records its transport, status mapping, identity provenance and lifetime contract.
No keyword, dependency, worker mechanism or token algorithm is added.

The login decorator shares one peer-IP quota across this process's shards. It
runs before worker submission, so rejected requests do not allocate a password
task. Missing, duplicate and incorrect credentials also spend admission budget;
spoofed `X-Forwarded-For` and identity headers do not select the bucket/account.
The built-in limiter remains bounded and process-local; account lockout and
cross-node abuse controls are separate acceptance work.

`test_password_login_epoll` and `test_password_login_io_uring` start the actual
CLI with two shards and verified local TLS using the pinned-library certificate
fixture. They compile the shipped program and import, remove both source files,
then verify login and protected access. Python's standard-library HMAC and JSON
code independently checks the issued signature, exact claims, UUID v4 jti,
trusted subject, scope and 300-second lifetime. Repeated login must issue
different IDs. Tests also cover invalid/missing/duplicate credentials, aggregate
quota and Retry-After, spoofed identity/forwarding fields, tampered signatures,
algorithm pinning, issuer/audience/time/lifetime rejection, insufficient scope,
duplicate Authorization, empty configured subject, short signing key and password
timeout. Failed login never emits a token response. JIT policy tests require
unknown result values to fail closed and validate both configured IDs.

Password replacement only changes future password verification. Previously
issued JWTs keep their original expiry unless separately revoked or their
signing key is removed. This profile adds no refresh token, cookie, logout,
registration or password-change endpoint, account database, persistent session
or durable token-revocation state.

## Offline password provisioning

[`rut-password`](password-provisioning.md) exposes the existing native hash/verify
profile as a standalone administrative command, also in no-JIT builds. It reads
passwords only from stdin, hides/restores terminal echo for interactive input,
preserves exact redirected bytes, and cleanses bounded input storage. Verification
accepts only bounded canonical regular record files, refusing final symlinks and
special files. Exit codes distinguish mismatch from input/OS/crypto failure.

Optional file output uses a protected owned parent directory, 0600 temporary
records, file sync, atomic no-replace hard-link publication and directory sync.
Concurrent creators cannot overwrite a winner or an existing symlink/file. Errors
after publication explicitly report that the destination may already exist.
No plaintext is written to files, placed in arguments or logged. This is an
offline provisioning interface, not a user registry or password-change endpoint.

`test_password_cli` independently derives PBKDF2 records with Python's standard
library and covers binary/whitespace/newline passwords, bounds, malformed records,
symlink/FIFO rejection, file permissions, concurrent creation, occupied targets,
closed output pipes, hidden terminal echo, terminal erase/kill/EOF handling,
valid 1024-byte input, rejected oversized input with delayed-tail echo checks,
and SIGINT restoration. It is registered with CTest and the `check` target.
Linux ELF tests verify the ordinary executable has no C++ runtime dependencies;
sanitizer builds exercise the same CLI suite separately.

## Local ES256 verification

The ES256 profile adds configuration-owned P-256 public JWK/SPKI import,
approved-kid selection, compact JWT verification, claims and revocation snapshots,
shard activation, and Rut/JIT/native-artifact entry points. The language card's
[ES256 contract](language-card.md#configured-es256-resource-server-verification)
defines bounds and lifecycle. It reuses pinned static OpenSSL field/bignum
operations with preallocated shard scratch; it adds no crypto dependency.

Public-key tests use RFC 7515 A.3's independent vector and reject wrong algorithms,
curves, private fields, malformed points/encodings and signature integer bounds.
Allocation hooks check the first request and adversarial signatures after shard
activation. JWT tests use the library's independent signer for authenticated
header/claims rejection. Frontend and relocated native tests cover static policy,
compiler exit/source removal, shard activation, scope/group denial and revocation.
ES256 also supports the bounded remote JWKS refresh described above. Signing,
discovery, online revocation and durable sessions remain open; no full JWT/OIDC
milestone completion is claimed.



## RS256 protected token type binding

Optional trusted `requiredType` binds a route's RS256 policy to an exact signed
protected-header `typ`. This helps separate token uses under an issuer/key trust
domain, following [RFC 8725 section 3.11](https://www.rfc-editor.org/rfc/rfc8725.html#section-3.11).
The type is 1–128 decoded visible ASCII bytes; matching is case-sensitive with
no media-type normalization or alias expansion. Omission preserves prior behavior.
It is not a complete OAuth access-token or OIDC ID-token profile.

Runtime tests cover two approved keys, two shards, independent typed/untyped
policies, escaped names/values, duplicate keys, absent/non-string/wrong types,
case/prefix/media-type mismatches, forged signatures, strict configuration bounds,
owned bytes and warmed allocation-free verification. HTTP/JIT tests verify 401
Bearer challenges and no identity publication; payload/HTTP `typ` and JOSE `cty`
cannot substitute for the protected field. Native artifacts preserve type checks
after compiler exit and source removal. All ordinary signature, claims, snapshot
revocation and token time limits still apply, including remote-JWKS mode.

## ES256 protected token type binding

The ES256 policy supports optional trusted `requiredType`, an exact signed
protected-header `typ` of 1–128 decoded visible ASCII bytes. No payload, HTTP
field or JOSE `cty` fallback applies. Case and media-type aliases remain distinct;
omission preserves the original untyped profile. This is application type
binding, not full OAuth/OIDC profile support.

Focused ES256 tests cover typed/untyped policies, shard isolation, escaped and
duplicate field names, missing/non-string/mismatching types, forged signatures,
strict configuration bounds and ownership, and zero observed crypto allocations
during verification. HTTP/JIT tests verify Bearer challenges and absence of
identity publication on rejection. Native artifact tests retain the rule after
compiler exit/source removal. The two-shard TLS gateway tests exercise configured
types, wrong/missing/duplicate types, signature and ordinary claims failures for
epoll and io_uring; unavailable backends are reported as skips.

The configured type stays with the policy during remote key replacement.
Signature, approved keys, issuer/audience/time, snapshot revocation and scope/group
checks continue to compose. Persistent replay state remains outstanding.
