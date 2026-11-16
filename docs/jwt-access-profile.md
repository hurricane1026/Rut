# Bounded RS256/ES256 OAuth JWT access-token resource profile

[`examples/middleware/jwt_access.rut`](../examples/middleware/jwt_access.rut)
composes the existing RS256 or ES256 verifier (static or remote JWKS) with a strict
resource-server claims profile. The [RS256 example](../examples/jwt-access-auth.rut)
and [ES256 example](../examples/jwt-access-es256-auth.rut) accept the supported
RFC 9068 protected-header type spellings and return only the verified subject
after client and scope authorization.

Remote-ready entry points are also available for [RS256](../examples/jwt-access-remote-rs256-auth.rut)
and [ES256](../examples/jwt-access-remote-es256-auth.rut). They use the same
profile module; only the algorithm-specific verifier and trusted policy variable
differ.

This is an RFC 9068-inspired bounded profile, not full RFC 9068 conformance. It
adds no token endpoint, OAuth/OIDC login, authorization-server issuance,
introspection, refresh, or online revocation service. It uses existing
RS256/ES256 verification, claims-lifetime, scope and revocation-snapshot code
without new runtime, compiler or crypto changes.

## Trusted RS256 or ES256 policy and header type

`jwt_access.requireRs256(...)` and `jwt_access.requireEs256(...)` take their
algorithm-specific trusted compile/load-time policies: exact issuer and
resource audience, approved `kids`, and public `jwks`. The policy must include
`requiredType` as exactly one of `at+jwt` or `application/at+jwt`, the two
protected-header values described by [RFC 9068 sections 2.1, 2.2 and 4](https://www.rfc-editor.org/rfc/rfc9068.html). These are
separate accepted configuration spellings; the verifier pins the signed JOSE
protected-header `typ` to the configured value exactly. There is no aliasing,
case folding or media-type normalization. A payload `typ`, `cty`, HTTP header or
query value cannot replace the protected-header type. Duplicate Authorization
fields fail closed when the caller passes `req.authorization.or("")`.

Invalid positive-age/lifetime settings, or an otherwise valid RS256 or ES256
policy with a missing/unsupported `requiredType`, return 503 before token verification. A
structurally invalid algorithm policy (for example, malformed required fields
or a non-string `requiredType`) can instead fail during compilation/loading,
before a listener starts. A signature, algorithm, approved-kid, issuer,
audience, expiry, optional time, revocation, header-type or Authorization
failure returns a Bearer `invalid_token` 401. The selected `Crypto.jwtRs256` or
`Crypto.jwtEs256` builtin owns cryptographic verification and key-policy
activation. The wrapper parses trusted policy metadata to enforce the profile;
it does not build or modify the key policy.

## Remote JWKS configuration

The wrapper accepts the same trusted `remoteJwks` policy extension as the
underlying verifier. For example, `JWT_ACCESS_RS256_POLICY` (or
`JWT_ACCESS_ES256_POLICY`) can contain:

```json
{
  "issuer": "https://issuer.example",
  "audience": "orders-api",
  "requiredType": "at+jwt",
  "kids": ["orders-2026-01"],
  "jwks": {"keys": [{"kid":"orders-2026-01","kty":"RSA","alg":"RS256","n":"<approved-modulus>","e":"AQAB"}]},
  "remoteJwks": {
    "address": "192.0.2.10", "port": 443,
    "serverName": "issuer.example", "ca": "/etc/rut/issuer-ca.pem",
    "path": "/oauth/keys", "refreshSeconds": 60,
    "maxAgeSeconds": 300, "timeoutSeconds": 10,
    "dnsAddress": "192.0.2.53", "allowedAddresses": ["192.0.2.10", "192.0.2.11"],
    "discoveryPath": "/.well-known/openid-configuration",
    "discoveryIssuer": "https://issuer.example"
  }
}
```

The example modulus is a placeholder; replace it with the real public key for
`orders-2026-01`. For ES256, use an approved P-256 public JWK (`kty` EC, `alg` ES256,
`crv` P-256, `x`, and `y`). The initial JWKS defines approved IDs; remote mode
denies tokens until an authenticated fetch succeeds. DNS and discovery fields
are optional trusted configuration and follow the bounded rules in
[JWKS DNS/discovery](jwks-discovery.md). Future IDs must be preapproved in
`kids` and the initial JWKS before remote rotation can use them.

Run either remote example with the corresponding policy environment variable,
for example `JWT_ACCESS_RS256_POLICY`, plus `JWT_ACCESS_CLIENT_ID` and
`JWT_ACCESS_REQUIRED_SCOPE`, then start `rut` with the example path. Keep policy
JSON in trusted deployment configuration; do not accept it from a request or
place private signing material in the resource-server policy. For example:

```bash
export JWT_ACCESS_RS256_POLICY="$(cat /etc/rut/orders-rs256-policy.json)"
export JWT_ACCESS_CLIENT_ID=orders-web
export JWT_ACCESS_REQUIRED_SCOPE=orders:read
./build/src/rut 8080 --shards 1 examples/jwt-access-remote-rs256-auth.rut
```

Use `JWT_ACCESS_ES256_POLICY` and the ES256 example for P-256 keys. The policy
file must contain the complete trusted schema above, with real approved public
keys and deployment-specific CA/resolver settings.

## Required claims and lifetime

After algorithm verification, the matching helper requires:

- the verifier's existing nonempty `sub`, exact issuer and audience, integer
  unexpired `exp`, and valid optional `nbf`/`iat` rules;
- a nonempty string `client_id` of at most 1024 decoded UTF-8 bytes;
- a nonempty string `jti` of at most 128 decoded UTF-8 bytes; and
- mandatory positive integer `iat`, `iat <= now < exp`, with caller-configured
  positive `maxAge` and `maxLifetime` bounds through
  `jwtClaimsValidWithLifetime`.

Malformed, missing, oversized, fractional, future or stale required claims fail
with the same Bearer `invalid_token` 401. Existing configured `revokedJtis` and
`issuedAfter` policy remains active. This does not add replay tracking or live
revocation.

## Client and scope authorization

`jwt_access.requireClient(document, clientId)` compares the signed `client_id`
exactly and case-sensitively to the trusted configured client. Empty or
oversized client configuration returns 503; a valid token for another client
returns 403. The signed client identifier does not replace `sub`.

`jwt_access.requireScope(document, scope)` accepts one trusted scope token of at
most 128 bytes and uses the existing complete `jwtHasScope` validator. Empty,
malformed or oversized configured scope returns 503. Missing, malformed or
nonmatching signed scope returns 403 with Bearer `insufficient_scope`. The
example does not read client, scope or subject identity from request fields.
JSON values have no compiler-enforced verification provenance: pass only the
document returned by the matching `requireRs256` or `requireEs256` helper, never
arbitrary parsed JSON.

## Tests and limits

The native integration fixture signs RSA tokens with the public RFC 7515
Appendix A.2 test key and ES256 tokens with the existing test-only P-256
fixture. It makes no provider calls. It tests both algorithms and each
supported `requiredType` in separate policy snapshots, including genuinely
signed cross-algorithm tokens, then loads through `rut` and removes source/module
files before requests. The matrix covers both backends at O0/O2 and HTTP/1.0,
HTTP/1.1 and HTTP/2. It verifies the claims contract and existing configured
revocation behavior; it is not a live authorization-server conformance test.

Remote-profile integration tests use generated ephemeral RSA/EC keys and a
local authenticated HTTPS JWKS origin. Both backends run after deleting the
source and copied module. They prove cold denial, discovery, A-only DNS and
allowlisted address movement, key rotation, unapproved-kid rejection, protected
type and required `iat`/`jti`, client/scope status ordering, issuer/URI/rebinding
rejection, maximum-age expiry and recovery. They make no provider calls.

## Binding the access token to mTLS

The [RS256](../examples/mtls-access-bound-rs256-auth.rut) and
[ES256](../examples/mtls-access-bound-es256-auth.rut) examples compose this
profile with `jwt_binding.requireMtls`. They verify signature and access
claims, bind the exact `cnf.x5t#S256` to the verified TLS client certificate,
then check client and scope authorization. Start with `--tls-cert`, `--tls-key`
and mandatory `--tls-client-ca`. Forwarded certificate headers never supply
binding evidence. This adds no token issuance or proxy trust; see the
[certificate-binding contract](mtls-bound-jwt.md).
