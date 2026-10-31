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
| API Key / Basic | Static identity helpers, singleton credential fields, exact matching, rotating key window; explicit header credential stripping and verified identity header replacement | Dynamic Consumer registry/credential lifecycle and query/body credential hiding |
| Bearer and multi-auth | Basic/Bearer OR for one Consumer or a bounded pair; required header-key AND Basic policy; disabled slots and ambiguous ownership rejection; absence-only guest access for the bounded pair without invalid-credential downgrade | Dynamic Consumer registry and credential lifecycle |
| JWT verification | HS256/384/512 policy helpers with static two-secret rotation; configured RS256/JWKS verification through Rut, JIT and native programs; approved kid selection and static rotation; two-ID static JWT revocation helper | ES keys, remote JWKS refresh/cache, live and durable token revocation |
| HMAC and webhooks | Generic MD5/SHA-1/SHA-2 digest/HMAC primitives, fixed SHA-256 verification, exact binary bytes, two-key rotation including the strict GitHub sha256 profile; native bounded Standard Webhooks v1 verification and freshness | Kong/APISIX canonical signed request profile, body digest and mandatory signed fields, timestamp/nonce checks; durable delivery replay persistence |
| ACL / Consumer restriction | Exact Consumer allow/deny and two-Consumer allow union; static two-Consumer/two-group membership, single/either-group allow and deny with deny-before-allow composition and unknown-Consumer default deny | Dynamic registry and membership lifecycle, larger policy sets |
| JWE | Pending | Algorithm/enc allowlists, authenticated decryption, nested JWT policy, malformed/truncated ciphertext vectors |
| JWT signing / re-signing | Pending | Trusted claim mapping, fixed algorithm, protected private keys, bounded lifetime and rotation |
| Forward auth / OPA | Pending | Consume bounded external response, identity allowlist, strip spoofed identity, deny vs unavailable, timeout/cancellation/close in both backends |
| OAuth2 introspection | Pending | RFC 7662 active/expiry/audience checks, authenticated TLS endpoint, bounded cache, invalidation and fail-closed outage policy |
| OIDC login / session | Pending | Discovery validation, authorization-code + PKCE, state/nonce, redirect validation, ID-token verification, secure cookies, logout and refresh |
| Gateway OAuth2 endpoints | Pending | Authorization/token grants, client authentication, consent/redirect binding, code single use, token expiry/revocation and persistent state |
| Upstream OAuth token | Pending | Client credentials/token exchange, audience/scope, per-shard cache with bounded refresh coordination, cancellation and secret-safe logs |
| mTLS identity | Pending full chain | Client cert verification, trust bundles, SAN/issuer mapping, expiry/revocation, verified identity to API authorization |
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

## Static Consumer groups

`auth.ConsumerGroups` binds one verified Consumer ID to up to two exact,
case-sensitive group names. `auth.requireGroup(identity, group, first, second)`
checks one group, while `auth.requireAnyGroup(identity, first, second, member1,
member2)` allows either exact group. Both preserve the full verified identity
only when its Consumer is configured for the required membership; empty
membership slots are disabled. Empty required group names or invalid membership
configuration return 503. Missing, malformed, duplicate or invalid credentials
remain authentication failures, while a valid identity outside the requested
groups is denied with 403. Empty or duplicate Consumer IDs are configuration
failures. Group membership comes only from trusted configuration, not client
identity or group headers, and is compiled in until restart.

The JIT matrix covers successful single and either-group membership, default
deny, invalid and duplicate credentials, empty slots and required names,
duplicate groups or Consumer IDs, Consumer ID case mismatches and spoofed
identity/group headers. See `examples/consumer-group-auth.rut`.

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
Remote key refresh, OAuth/OIDC and persistent revocation/replay state remain
outside this implemented static resource-server profile.
