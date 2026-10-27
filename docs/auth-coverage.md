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
| API Key / Basic | Static identity helpers, singleton credential fields, exact matching, rotating key window; explicit header credential stripping | Dynamic Consumer registry/credential lifecycle, query/body credential hiding and verified identity forwarding |
| Bearer and multi-auth | Basic/Bearer OR for one Consumer or a bounded pair; required header-key AND Basic policy; disabled slots and ambiguous ownership rejection | Dynamic Consumer registry, anonymous only for absent credentials, no invalid-credential downgrade |
| JWT verification | HS256/384/512 policy helpers; native fixed-key RS256 decoder and trusted configured JWK Set selection | Rut/JIT asymmetric key wiring, ES keys, request-key selection, JWKS rotation/cache, revocation and unknown-key policy |
| HMAC and webhooks | Generic MD5/SHA-1/SHA-2 digest/HMAC primitives, fixed SHA-256 verification, exact binary bytes, two-key rotation, GitHub sha256 prefix; native bounded Standard Webhooks v1 verification and freshness | Kong/APISIX canonical signed request profile, body digest and mandatory signed fields, timestamp/nonce checks; Standard Webhooks HTTP/Rut wiring and replay persistence |
| ACL / Consumer restriction | Exact single-consumer allow/deny and two-consumer allow union after verification | Multiple groups, membership lifecycle, registry-backed default deny, no client identity spoofing |
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

## Audit of executable gaps

The 2026-10-27 audit separates these layers:

- Header stripping is implemented: `req.remove` removes every case-insensitive
  occurrence before forwarding while auth reads the original request. See
  `examples/auth-proxy.rut` and the language card's credential-stripping section.
  Dynamic verified-identity forwarding is still separate work.
- `apiKeyOrBasic` supports one Consumer. `multiAuth` now checks four configured
  slots (Bearer/Basic for each of two Consumers), rejects ambiguous ownership,
  and returns metadata from the matched configuration. This is a static bounded
  policy, not a persistent Consumer registry or a claim of plugin equivalence.
- Native RS256/JWK/JWKS verification and claims validation exist, but no Rut key
  owner/configuration surface publishes shard verifiers. HTTP asymmetric auth
  remains pending; parsing keys on each request would violate the hot-path goal.
- Anonymous access needs a presence distinction: singleton Authorization reads
  return nil for both absence and duplicates. Falling back on nil would turn
  malformed duplicate credentials into anonymous access. No anonymous helper is
  advertised until absence can be distinguished safely.
- External authorization needs bounded response-consuming callouts with tested
  cancellation/close behavior; redirects or fire-and-forget proxying do not
  implement forward-auth, OPA or introspection.

Standard Webhooks middleware integration remains separate from this branch and
is tracked by [#934](https://github.com/hurricane1026/Rut/pull/934). Its freshness
checks do not implement persistent replay protection.

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

- Native RS256/JWK/JWKS and claims validation still need trusted Rut configuration
  ownership and shard-verifier publication; key import must not move onto the
  request path.
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
## Static Consumer groups

`auth.ConsumerGroups` binds one verified Consumer ID to up to two exact,
case-sensitive group names. `auth.requireGroup(identity, group, first, second)`
preserves the verified identity only when the Consumer is configured for the
requested group; empty group slots are disabled. An empty required group is a
503 configuration failure. Missing, malformed, duplicate or invalid credentials
remain authentication failures, while a valid identity outside the group is
denied with 403. Empty Consumer IDs are configuration failures. Group membership comes only from trusted configuration,
not client identity or group headers, and is compiled in until restart.

The JIT matrix covers successful membership, default deny, invalid and duplicate
credentials, empty slots, duplicate groups, Consumer ID case mismatches and
spoofed identity headers. See `examples/consumer-group-auth.rut`.

## Implementation order and gates

1. Complete local credential foundations and signed-message primitives. Add
   independent RFC vectors, binary/empty/oversize inputs, duplicate fields,
   rotation/revocation and JIT-to-runtime evidence.
2. Complete signed-request freshness/replay policy and asymmetric JWT/JWKS.
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
verifier. This adds no Rut/JIT API or complete asymmetric authorization flow.
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
allocation hooks. This is a native API; Rut/JIT wiring remains pending.

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

`hash_digest_parts` reuses existing stack digest/HMAC contexts over at most 16
borrowed spans, avoiding a body-sized concatenation buffer or request allocation.
Inputs are borrowed synchronously; no HTTP parser, body JSON parsing, network
operation or Rut/JIT surface is added. Callers must obtain singleton
`webhook-id`, `webhook-timestamp` and `webhook-signature` fields and reject
ambiguous HTTP fields before invoking the primitive.

Freshness does not guarantee uniqueness: a repeated ID can still verify inside
the time window. Applications must durably deduplicate authenticated IDs before
side effects, including cross-shard/node coordination. This slice adds no replay
store. Tests use fixed Python HMAC/Base64 oracle outputs with upstream Python
fixture inputs, tampering and malformed lists, rotation, size/clock boundaries,
and zero observed crypto allocations after warmup. HTTP/Rut end-to-end evidence
and persisted replay handling remain pending.

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

This is storage groundwork, not a new Rut mutation surface or a complete
verified-identity forwarding policy. The language integration must still enforce
literal header names, unwrapped runtime values, replacement of spoofed headers,
credential stripping and correct ordering after authentication.
