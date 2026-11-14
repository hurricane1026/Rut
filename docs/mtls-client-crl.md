# Inbound mTLS leaf-certificate CRL profile

The listener can require a local CRL in addition to its existing mandatory
client-CA verification:

```bash
rut gateway.rut --tls-cert server.pem --tls-key server-key.pem \
  --tls-client-ca clients-ca.pem --tls-client-crl clients.crl.pem
```

`--tls-client-crl` requires `--tls-client-ca`, which already requires the server
certificate and key. Omitting CRL configuration preserves the existing CA-only
profile. This option configures downstream client-certificate verification; it
does not change upstream TLS, OCSP stapling or Rut syntax.

## Supported trust input

The CRL file must be a regular file, at most 65,536 bytes, containing exactly one
PEM `X509 CRL` block starting at byte zero, followed only by ASCII spaces, tabs or
line endings. Empty, unreadable, non-regular, oversized, malformed, concatenated
and trailing-content files prevent listener startup. Parsing occurs once in the
startup path with bounded temporary input storage. The parsed CRL is owned by
the OpenSSL store; no file/BIO/stack views survive loading.

This is a complete direct-issuer CRL profile. `lastUpdate` and `nextUpdate` are
mandatory, must parse, and must describe the current time at startup. Missing,
expired or future validity prevents startup. Delta CRLs and all
issuing-distribution-point extensions are rejected; indirect/partitioned CRLs
and CRL bundles are unsupported. Deploy one client-leaf issuer per such listener.
The issuer may be an intermediate in an otherwise valid trusted chain; this
option does not check revocation of intermediate or root certificates.

The configured CA file must contain certificate trust without CRLs when this
option is used. A CRL already imported by the CA loader prevents startup, so it
cannot compete with the explicit CRL. The CRL loader imports only a CRL and can
never add a trusted CA certificate. A CA certificate in place of, or appended to,
the CRL is rejected. Operator-owned CA and CRL paths remain trust configuration,
not client-controlled URLs or HTTP fields.

## Handshake and authorization

The existing pinned static OpenSSL verifier applies
[`X509_V_FLAG_CRL_CHECK`](https://docs.openssl.org/3.5/man3/X509_VERIFY_PARAM_set_flags/#verification-flags)
to the client leaf. A revoked serial, unsuitable issuer, invalid CRL signature,
unsupported critical extension, missing suitable CRL or expired CRL fails the TLS
handshake before HTTP authorization. A structurally valid CRL with an unknown
issuer or invalid signature may load at startup; its cryptographic suitability
is checked against the actual peer chain during each full handshake, and cannot
produce a verified client identity. No soft-fail or CA-only fallback applies.

Only after successful chain and CRL verification may the existing connection
fingerprint be published to `req.tlsClientCertSha256` and Consumer mapping.
Normal route pin/group policies still apply; a non-revoked certificate does not
by itself select an authorized Consumer. Missing client certificates remain a
handshake failure. TLS 1.2 and TLS 1.3 retain the existing mTLS restrictions:
session caching, tickets and renegotiation are disabled, so a resumed session
cannot inherit an earlier CRL decision.

## Freshness and replacement

OpenSSL checks CRL time against realtime on each new full handshake. Even when a
CRL was current at startup, new connections fail after `nextUpdate`; there is no
stale-forever cache or automatic URL fetch. Operators must provide a fresh signed
CRL and replace/restart the listener before expiration. Replacing or deleting the
file alone does not mutate the already-installed snapshot or extend validity.
No online refresh, in-process CRL reload, CRL-number rollback registry or
cross-node synchronization is provided.

Existing TLS connections keep their established authentication. Keep-alive and
HTTP/2 requests admitted on those connections can continue after CRL expiry or
a replacement listener's revocation. Route reload does not re-run a TLS
handshake. This is not an immediate connection-cancellation or per-request
certificate-status protocol. Coordinate connection draining separately when a
cutover must retire established sessions.

## Validation

A test helper generates signed client leaves and CRLs using the same pinned
OpenSSL libraries as the runtime; tests do not invoke a system OpenSSL CLI or add
Python crypto dependencies. Native tests register epoll and io_uring coverage
for TLS 1.2/1.3, HTTP/1.0, HTTP/1.1 and negotiated HTTP/2. They exercise revoked
versus non-revoked serials, absent certificates, wrong issuer, forged signatures,
startup input/time rejection, delta CRLs, no TLS resumption, source/CRL removal
after loading, file replacement and old keep-alive connection continuity, plus
new-handshake rejection after `nextUpdate`. These are local CRL fixtures, not an
OCSP responder or live PKI refresh conformance suite. A separate context test
runs without JIT, including ASan/UBSan builds, checking CRL ownership,
issuer/signature/revocation rejection, session settings and CA-only compatibility.
