# Trusted JWKS DNS and metadata discovery

RS256 and ES256 use the same optional cold maintenance profile. It extends the
existing `remoteJwks` object; its eight original fields and fixed-address mode
remain supported. New fields are all trusted compile/load-time configuration:

```json
{
  "address": "192.0.2.10", "port": 443, "serverName": "issuer.example",
  "ca": "/etc/rut/issuer-ca.pem", "path": "/keys",
  "refreshSeconds": 30, "retrySeconds": 5, "maxRetryAfterSeconds": 30,
  "maxAgeSeconds": 120, "timeoutSeconds": 10,
  "conditionalRequests": true,
  "dnsAddress": "192.0.2.53", "dnsPort": 53, "dnsCacheSeconds": 15,
  "allowedAddresses": ["192.0.2.10", "192.0.2.11"],
  "discoveryPath": "/.well-known/openid-configuration",
  "discoveryIssuer": "https://issuer.example"
}
```

`retrySeconds` is optional, an integer from 1 through 3600. When omitted it
uses `refreshSeconds`, regardless of field order. Omission preserves the interval
value; failed attempts now measure it from completion, so slow failures no longer
retry immediately when their prior start-based interval has elapsed.
Successful refreshes, including valid empty key sets, schedule the next attempt
from completion plus `refreshSeconds`. Setup, DNS, metadata, HTTPS, parsing and verifier-import failures
schedule from their completion plus `retrySeconds`. A slow failure still waits
the full retry interval after its timeout. Both algorithms use the same rule;
there is no jitter, exponential backoff or token-triggered retry. Deadlines
saturate instead of wrapping on integer overflow. An invalid maintenance clock
cancels the attempt and clears cache freshness before a later cold attempt.

Retry delay does not extend `maxAgeSeconds` and may exceed it. Failures never
renew last-success time; requests fail closed after the original maximum age
while maintenance continues its bounded retry cadence. The attempt's total
`timeoutSeconds` deadline still begins at attempt start and spans all stages.

Optional `maxRetryAfterSeconds` (integer 1–3600) permits the authenticated key
endpoint to delay retries after HTTP 429 or 503. A fully framed response can
supply one canonical decimal delay in seconds within the unsigned 32-bit range.
The gateway caps that delay at `maxRetryAfterSeconds` and waits the greater of
the resulting hint and its local retry interval, measured from completion.
Absent, duplicate, malformed, overflowing and HTTP-date values use the local
interval. Discovery and successful key responses ignore this header. These
throttle responses are failures and do not update the keys, validators or
last-success time.

`dnsAddress` and a nonempty `allowedAddresses` list must appear together. Resolver
and allowed destinations are IPv4 literals; at most eight destination addresses
are accepted. `dnsPort` is optional (default 53), otherwise 1–65535. The original
`address` remains a mandatory valid configuration field but is **never a fallback**
when DNS is enabled. By default each attempt resolves the configured TLS server
name again through one connected nonblocking UDP socket to the configured resolver.
No blocking libc resolver, system search list, request-selected name or new DNS
library is used.

The deliberately bounded DNS profile sends one random-ID IN A query (labels at
most 63 bytes) without EDNS. It accepts one echoed question and 1–8 total answer
records in a single reply of at most 512 bytes. Answers must form exactly one
chain from the echoed question, with at most four CNAME hops followed by one or
more A records. Chain validation accepts records in any order and compares names
case-insensitively. Every record must have a positive 31-bit TTL. Before making
any HTTPS connection, the gateway validates the whole reply and requires each
terminal A address to be allowlisted, including later answers.

Names are bounded to 253 expanded bytes and 63 bytes per label. Compression may
only point backwards to a previously decoded valid label boundary, with bounded
pointer traversal. Forks, duplicate CNAMEs, cycles, an owner with both A and CNAME,
missing terminal A records, unrelated answers, malformed or trailing RDATA/bytes,
AAAA, truncation, DNS errors and authority/additional sections fail the attempt.
The configured resolver must provide this bounded UDP A/CNAME profile.

Optional `dnsCacheSeconds` (integer 1–3600) requires DNS mode. It enables one
owned address set per policy and shard. A validated reply may be reused until
the earlier of its shortest record TTL and this local cap, measured from DNS
completion on the monotonic clock. Cache hits still run authenticated discovery
and key fetch within their own attempt timeout. These requests never extend
DNS expiry. Cancel, clock failure or reversal, and exhaustion of the cached
address set on a TCP connect failure discard it. A reply rejected by the
resolver policy never enters the cache.

Within an attempt the gateway tries distinct terminal A addresses in their
original answer order. It moves to the next address only when TCP establishment
reports a connection refusal or another definitive network error. TLS, HTTP,
metadata and key validation failures end the attempt. The next address uses
the same total deadline and starts at discovery when discovery is configured.
The remaining addresses are discarded when the deadline expires, including when
an earlier address stalls. Each attempt uses at most one DNS query.

TLS SNI/certificate hostname and CA remain fixed to the configured original
server name even when a CNAME target or an allowed address changes. DNS is not
claimed to be DNSSEC-authenticated; address allowlisting plus mandatory HTTPS
identity validation preserves the configured destination trust
boundary and prevents rebinding to an unconfigured internal service.

## Conditional key refresh

Optional `conditionalRequests` is a Boolean, defaulting to false. The default
keeps unconditional 200-only refresh and ignores optional ETag metadata. Enabling
it permits a bounded strong ETag on an authenticated 200 key response. The tag is
committed with the successfully imported approved keys, including authoritative
empty sets. Invalid JSON, keys or import leave the prior validator unchanged.
A successful 200 without ETag clears the prior validator. Duplicate, weak,
malformed or oversized ETags reject the entire enabled-profile attempt.

This profile accepts one strong quoted tag of at most 128 bytes including quotes.
Inside the quotes only ASCII `!` and `#` through `~` are allowed. It excludes weak
validators and non-ASCII bytes. See the general
[RFC 9110 ETag syntax](https://www.rfc-editor.org/rfc/rfc9110.html#name-etag).
The tag and selected IPv4 address are owned by one policy/shard and tied to that
accepted representation. A later key GET sends `If-None-Match` only on its initial
candidate, at that same address, while the accepted cache remains fresh. Changed
addresses and failover candidates always receive unconditional GETs. TLS name,
CA, issuer, path and approved kid inventory remain configuration-owned.

An authenticated 304 must contain exactly one strong ETag matching the exact
validator actually sent. A 304 is bodyless. Transfer-Encoding is rejected and
Content-Type is optional. Content-Length may carry representation metadata. This bounded
contract uses [If-None-Match](https://www.rfc-editor.org/rfc/rfc9110.html#name-if-none-match)
and [304 semantics](https://www.rfc-editor.org/rfc/rfc9110.html#name-304-not-modified)
with additional local eligibility checks. An unsolicited, mismatching or malformed
304 is a failed refresh. A valid 304 keeps the current verifier bank/empty state,
renews last-success at completion, and uses `refreshSeconds` for its next attempt.

Hard maximum age still applies: the cache must remain fresh both when emitting
the conditional GET after DNS/discovery and when accepting the 304. Expiry during
an in-flight request rejects its 304. The next attempt requires a full 200 and
cannot revive old keys through revalidation. Failure never renews age. Clock
failure/reset and configuration retirement discard validators. Attempt cleanup
clears its own copied state. Discovery requests never send `If-None-Match` and
remain 200-only. All stages retain the original attempt timeout and retry cadence.
No request traffic, token or unknown kid creates extra work.

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
TTL interpretation and alias ownership are informed by
[RFC 2181 section 8](https://www.rfc-editor.org/rfc/rfc2181#section-8) and
[section 10.1](https://www.rfc-editor.org/rfc/rfc2181#section-10.1). This profile
deliberately rejects zero and high-bit-set TTLs instead of accepting zero or
normalizing a high-bit-set value to zero as described by the RFC.

One shard-owned `JwksFetch` coordinates DNS, discovery and the key GET under one
timeout. At most one stage is in flight per policy/shard. No token, unknown kid,
or concurrent verification creates another request. Successful key import still
uses only configuration-approved kid/algorithm inventory; discovery cannot admit
new kids or algorithms. A failed DNS/metadata/TLS attempt neither installs keys
nor renews last-success time. Existing trusted keys remain usable only until the
original monotonic maximum age. Empty authoritative key sets remove all keys;
configuration retirement and shutdown close resolver and HTTPS workspaces.

## Evidence and limits

Tests cover deterministic malformed/truncated DNS and metadata, bounded compressed
and reordered CNAME chains, alias poisoning, HTTP/1.1 and HTTP/2 denial/recovery,
allowlisted TCP failover, authoritative HTTP failure, prohibited rebinding,
issuer/URI mismatch, redirects, resolver outage, TLS key rotation, empty-set
removal, cache expiry, recovery and shutdown.
Fixed-endpoint fixtures also measure immediate and slow-timeout failure retry
spacing, with HTTP/1.1 and HTTP/2 maximum-age denial and recovery. Conditional
fixtures cover repeated 304, rotation/empty sets, strict validator failures, hard
expiry at emission/completion, and unconditional changed-IP/failover requests.
Real native-loaded RS256 and ES256 gateways run after source removal on both
Linux backends. The existing fixed-endpoint tests remain registered separately.
No new keyword, dependency, dynamic trust source or per-request resolver is added.
Other DNS transports, IPv6, alternative discovery origins, automatic kid inventory
and full OIDC provider workflows remain outside this profile. #1077 remains open.
