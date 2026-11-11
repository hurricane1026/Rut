# Trusted JWKS DNS and metadata discovery

RS256 and ES256 use the same optional cold maintenance profile. It extends the
existing `remoteJwks` object; its eight original fields and fixed-address mode
remain supported. New fields are all trusted compile/load-time configuration:

```json
{
  "address": "192.0.2.10", "port": 443, "serverName": "issuer.example",
  "ca": "/etc/rut/issuer-ca.pem", "path": "/keys",
  "refreshSeconds": 30, "maxAgeSeconds": 120, "timeoutSeconds": 10,
  "dnsAddress": "192.0.2.53", "dnsPort": 53,
  "allowedAddresses": ["192.0.2.10", "192.0.2.11"],
  "discoveryPath": "/.well-known/openid-configuration",
  "discoveryIssuer": "https://issuer.example"
}
```

`dnsAddress` and a nonempty `allowedAddresses` list must appear together. Resolver
and allowed destinations are IPv4 literals; at most eight destination addresses
are accepted. `dnsPort` is optional (default 53), otherwise 1–65535. The original
`address` remains a mandatory valid configuration field but is **never a fallback**
when DNS is enabled. Each refresh attempt resolves the configured TLS server name
again, through one connected nonblocking UDP socket to the configured resolver.
No blocking libc resolver, system search list, request-selected name or new DNS
library is used.

The deliberately bounded DNS profile sends one random-ID IN A query (labels at
most 63 bytes) without EDNS. It accepts one echoed question and 1–8 A answers,
with positive TTL, exact question ownership (literal or pointer to offset 12),
transaction match and no trailing authority/additional sections. Every returned
address must be allowed; it does not select a convenient allowed answer from a
mixed poisoned set. Truncation, DNS errors, unrelated owners, CNAME, AAAA,
arbitrary compression chains and replies over 512 bytes fail this attempt.
There is no TCP fallback or independent DNS cache: refresh controls bound retries,
and resolved addresses are used only within that attempt's total deadline.
The configured resolver must provide this A-only response profile.

TLS SNI/certificate hostname and CA remain fixed even when an allowed address
changes. DNS is not claimed to be DNSSEC-authenticated; address allowlisting plus
mandatory HTTPS identity validation preserves the configured destination trust
boundary and prevents rebinding to an unconfigured internal service.

## Discovery contract

`discoveryPath` and `discoveryIssuer` must appear together. The issuer is a bounded
HTTPS URI with no credentials, query or fragment, and must equal the enclosing
JWT policy's issuer exactly. Discovery uses the same configured HTTPS origin and
resolved address. A completed 200 JSON object must contain exact string `issuer`
and `jwks_uri` fields, with duplicate-name rejection. Extra provider metadata is
ignored; this is JWKS discovery, not OIDC login or validation of all OP metadata.

`jwks_uri` must name exactly the pre-authorized `https://serverName:port/path`;
port 443 may be omitted. No redirect, alternative host, attacker-provided URI,
`jku`, `x5u`, URI normalization or unconfigured port/path is followed. The metadata
therefore confirms the configured JWKS endpoint instead of delegating destination
trust to remote input. Configure issuer-specific well-known paths explicitly.
The trust rule follows the exact issuer comparison in
[OpenID Connect Discovery](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationValidation).
The bounded wire format derives from [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035).

One shard-owned `JwksFetch` coordinates DNS, discovery and the key GET under one
timeout. At most one stage is in flight per policy/shard. No token, unknown kid,
or concurrent verification creates another request. Successful key import still
uses only configuration-approved kid/algorithm inventory; discovery cannot admit
new kids or algorithms. A failed DNS/metadata/TLS attempt neither installs keys
nor renews last-success time. Existing trusted keys remain usable only until the
original monotonic maximum age. Empty authoritative key sets remove all keys;
configuration retirement and shutdown close resolver and HTTPS workspaces.

## Evidence and limits

Tests cover deterministic malformed/truncated DNS and metadata, allowlisted
address changes, prohibited rebinding, issuer/URI mismatch, redirects, resolver
outage, TLS key rotation, empty-set removal, cache expiry, recovery and shutdown.
Real native-loaded RS256 and ES256 gateways run after source removal on both
Linux backends. The existing fixed-endpoint tests remain registered separately.
No new keyword, dependency, dynamic trust source or per-request resolver is added.
Other DNS transports, CNAME/IPv6/discovery origins, automatic kid inventory and
full OIDC provider workflows remain outside this profile (#1077).
