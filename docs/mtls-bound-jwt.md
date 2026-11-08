# Certificate-bound JWT resource policy

Rut can require a verified JWT to be bound to the TLS client certificate used
on the current request. This implements a bounded resource-server policy for
[RFC 8705 sections 3 and 3.1](https://www.rfc-editor.org/rfc/rfc8705.html#section-3),
not authorization-server token issuance or mutual-TLS OAuth client authentication.

See [the executable example](../examples/mtls-bound-jwt.rut). Start the gateway
with `--tls-cert`, `--tls-key` and mandatory `--tls-client-ca`. Set trusted
`JWT_BINDING_KEY`, `JWT_BINDING_ISSUER` and `JWT_BINDING_AUDIENCE` values. The
example uses existing HS256 signature verification; other existing verifiers can
supply verified claims to the same binding helper.

## Policy order

```rut
import "middleware/auth.rut"
import "middleware/jwt_binding.rut"

route GET "/private" {
    let document = auth.jwtDocumentHs256(req.authorization.or(""), env("JWT_BINDING_KEY"))
    let bound = jwt_binding.requireMtls(document)
    let identity = auth.jwtIdentity(bound, env("JWT_BINDING_ISSUER"), env("JWT_BINDING_AUDIENCE"), "mtls-jwt")
    let subject = identity.consumerId
    return response(200, body: subject)
}
```

Verify the JWT signature before applying binding policy. Issuer, audience, expiry,
subject and application permissions remain separate checks; the shipped example
also requires `reports:read`. Binding preserves the verified metadata and subject.
It does not replace the token subject with a certificate fingerprint or Consumer ID.

`jwt_binding.requireMtls(document)` reads `req.tlsClientCertSha256`, which comes
only from a verified client certificate on the actual TLS connection. Ordinary
TLS without client verification, cleartext requests, absent certificates and
certificate mismatches fail closed. HTTP-level failures return 401 with
`WWW-Authenticate: Bearer error="invalid_token"`; mandatory client authentication
can reject an absent or untrusted certificate earlier during the TLS handshake.
Forwarded certificate and identity headers cannot satisfy this policy.

## Confirmation profile

The signed JWT payload must contain a top-level confirmation object:

```json
{"cnf":{"x5t#S256":"base64url-encoded-SHA256-of-client-certificate-DER"}}
```

`cnf` must be an object containing exactly one member, `x5t#S256`, whose value
decodes as a JSON string. The thumbprint must equal the canonical unpadded
Base64url encoding of the certificate's 32-byte SHA-256 digest: exactly 43
characters, no whitespace, padding, standard Base64 alphabet or nonzero unused
padding bits. Comparison uses the existing constant-time byte comparison.
JSON escapes in names and values are decoded before comparison. Duplicate
decoded keys, including escaped aliases, fail the shared JSON parser. Missing,
wrongly typed, nested or malformed confirmation claims fail closed.

This profile rejects additional confirmation methods or unknown members inside
`cnf`, including a simultaneous `jkt`; it does not choose among alternatives.
Unrelated top-level JWT claims remain available to normal claims policy. The
certificate hash covers the complete DER certificate, not only its public key:
two certificates reusing a key still have distinct bindings. A certificate
renewal therefore requires tokens issued for the replacement certificate.

## Low-level operation and limits

`jwtCertificateBound(document: Json, fingerprint: str) -> bool` is a metadata-only
operation. Its Json and str arguments must be unwrapped. The fingerprint must be
exactly 64 lowercase hexadecimal bytes. Invalid input returns false. The operation
uses the existing bounded JSON scratch and stack digest buffers, retains no
views, allocates no heap storage, and performs no I/O. It reuses the existing JSON
operation carrier and statically linked crypto primitives; no dependency, keyword
or separate call ABI is added. Existing JSON byte, depth and node limits apply.

The low-level function cannot establish the provenance of arbitrary JSON or a
caller-supplied fingerprint. Production routes should use the helper after JWT
verification, and obtain the fingerprint from the TLS connection. Never use
request headers or request JSON as evidence of a verified certificate or token.

No certificate-bound token issuance, endpoint discovery, refresh-token binding,
TLS-terminating proxy certificate assertions, DPoP, CRL/OCSP or distributed
revocation state is added. Certificate trust remains the startup CA policy.

## Validation

Native vectors check zero, all-one and mixed digest bytes, escaped fields,
malformed and ambiguous confirmation methods, strict encodings, invalid
fingerprints and scratch reuse. Compiler tests cover argument types, optional
rejection and ordinary user-function shadowing; JIT tests exercise the operation.

Two-shard native TLS integration tests use an independent Python HMAC/DER-hash
oracle and two distinct fixture certificates sharing a key. After removing the
source and imported modules they verify allowed pairs, cross-certificate token
replay refusal, JWT tampering and claims/scope denial, duplicate Authorization,
concurrent identity isolation, HTTP/2 success and mismatch rejection, and spoofed
certificate headers over ordinary TLS and cleartext. Both epoll and io_uring are
registered in CMake; unavailable io_uring is an explicit skip.
