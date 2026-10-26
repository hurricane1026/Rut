# Gateway authentication and authorization coverage

This ledger extends the existing M4 scope. A matching plugin name or successful
HTTP request is insufficient evidence of protocol equivalence. Status describes
this branch (based on the auth policy composition work in #901), not an older
checkout or a claim that the whole auth milestone is complete.

Sources: [Kong authentication](https://developer.konghq.com/gateway/authentication/),
[Kong plugin catalog](https://developer.konghq.com/plugins/),
[APISIX plugin catalog](https://apisix.apache.org/plugins/),
[APISIX multi-auth](https://apisix.apache.org/docs/apisix/plugins/multi-auth/).
Enterprise-only capabilities are within the comparison scope, independently of
whether a competing open-source edition includes them.

| Capability | Current evidence | Remaining acceptance scope |
| --- | --- | --- |
| API Key / Basic | Static identity helpers, singleton credential fields, exact matching, rotating key window | Consumer registry, credential lifecycle and safe upstream credential hiding |
| Bearer and multi-auth | Basic/Bearer OR composition, disabled-slot handling, configuration failures | Multiple consumers, explicit AND/OR policy, anonymous only for absent credentials, no invalid-credential downgrade |
| JWT verification | HS256/384/512 policy helpers; native fixed-key RS256 decoder and trusted configured JWK Set selection | Rut/JIT asymmetric key wiring, ES keys, request-key selection, JWKS rotation/cache, revocation and unknown-key policy |
| HMAC and webhooks | Generic MD5/SHA-1/SHA-2 digest/HMAC primitives, fixed SHA-256 verification, exact binary bytes, two-key rotation, GitHub sha256 prefix | Kong/APISIX canonical signed request profile, body digest and mandatory signed fields, timestamp/nonce checks; Standard Webhooks profile and replay persistence |
| ACL / Consumer restriction | Exact verified-consumer allow/deny helpers | Multiple groups, membership lifecycle, default deny, no client identity spoofing |
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
