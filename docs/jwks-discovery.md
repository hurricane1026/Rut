# Trusted JWKS DNS and metadata discovery

RS256 and ES256 use the same optional cold maintenance profile. It extends the
existing `remoteJwks` object; its eight original fields and fixed-address mode
remain supported. New fields are all trusted compile/load-time configuration:

```json
{
  "address": "192.0.2.10", "port": 443, "serverName": "issuer.example",
  "ca": "/etc/rut/issuer-ca.pem", "path": "/keys",
  "refreshSeconds": 30, "retrySeconds": 5, "maxRetrySeconds": 60, "maxRetryAfterSeconds": 30,
  "maxAgeSeconds": 120, "timeoutSeconds": 10,
  "dnsTimeoutSeconds": 2, "discoveryTimeoutSeconds": 3,
  "conditionalRequests": true, "conditionalDiscovery": true,
  "admitNewKids": true,
  "discoveryCacheSeconds": 30,
  "dnsAddress": "192.0.2.53", "dnsPort": 53, "dnsCacheSeconds": 15,
  "dnsTransport": "tls", "dnsTlsPort": 853,
  "dnsTlsServerName": "resolver.example", "dnsTlsCa": "/etc/rut/resolver-ca.pem",
  "allowedAddresses": ["192.0.2.10", "192.0.2.11"],
  "discoveryPath": "/.well-known/openid-configuration",
  "discoveryIssuer": "https://issuer.example",
  "discoveryAddress": "192.0.2.20", "discoveryPort": 443,
  "discoveryServerName": "idp.example", "discoveryCa": "/etc/rut/idp-ca.pem"
}
```

`retrySeconds` is optional, an integer from 1 through 3600. When omitted it
uses `refreshSeconds`, regardless of field order. Omission preserves the interval
value; failed attempts now measure it from completion, so slow failures no longer
retry immediately when their prior start-based interval has elapsed.
Successful refreshes, including valid empty key sets, schedule the next attempt
from completion plus `refreshSeconds`. By default, setup, DNS, metadata, HTTPS,
parsing and verifier-import failures schedule from completion plus
`retrySeconds`. A slow failure still waits the full retry interval after its
timeout. Both algorithms use the same rule. Deadlines saturate on overflow.
An invalid maintenance clock cancels the attempt and clears cache freshness
before a later cold attempt.

Optional `maxRetrySeconds` (integer `retrySeconds`–3600) enables capped
exponential retry backoff. The first failure waits `retrySeconds` and each
consecutive failure doubles the local interval up to the cap. A successful
key refresh, accepted 304, or a maintenance reset clears the progression.
Server hints can extend the scheduled delay without changing the next local
backoff step. Request traffic never triggers a refresh.

Optional `dnsTimeoutSeconds` and `discoveryTimeoutSeconds` limit those
stages to a positive integer number of seconds no greater than
`timeoutSeconds`. Each requires its corresponding DNS or discovery profile
and is measured from stage entry. The earlier of the stage limit and total
deadline wins. Stage timeout ends the attempt through the normal failure and
retry path, without trying another address or issuing another DNS query. If a
definitive TCP connection error triggers failover, the next discovery GET has
its own stage limit under the same total attempt deadline. Omitting either
setting gives that stage the full remaining attempt budget.

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

`address` and `dnsAddress` accept bare IPv4 or IPv6 literals. IPv6 transport
continues to authenticate the configured TLS hostname and CA. Brackets, zone IDs
and IPv4-mapped IPv6 literals are rejected. The DNS resolver and HTTPS origin may
use different address families.

`dnsAddress` and a nonempty `allowedAddresses` list must appear together. The
optional `dnsRecordType` defaults to `"A"` (IPv4). Use `"AAAA"` for IPv6 or
`"A+AAAA"` for an explicitly dual-stack origin. Use `dnsRecordType` only with DNS
enabled. A single-family allowlist accepts only its selected family. A dual-stack
allowlist must contain at least one address of each family. At most eight
destinations are accepted, and duplicate entries (including equivalent IPv6
spellings) are rejected. `dnsPort` defaults to 53 and accepts 1–65535. The
original `address` remains mandatory and is **never a fallback** in DNS mode.
By default each attempt resolves the configured TLS hostname through one
connected nonblocking UDP socket to the configured resolver. No blocking libc
resolver, system search list, request-selected name or new library is used.

Optional `dnsTransport` selects `"udp"` (default), `"tcp"` or `"tls"`. TCP and
TLS use the RFC 7766 two-byte length prefix on one connected nonblocking stream
per query; they never fall back to UDP, and UDP never falls back to a stream.
All transports share the configured resolver literal, query construction,
response validation, address allowlist, timeout and retry rules. The client
reads exactly one framed response and then closes the connection; short,
oversized, zero-length, malformed or abruptly closed frames fail the attempt.

`"tls"` additionally requires `dnsTlsServerName` and `dnsTlsCa`, with an
optional `dnsTlsPort` defaulting to 853. The resolver certificate is verified
against that CA and exact server name with the pinned OpenSSL client; the DNS
profile sends no ALPN and does not fall back to plaintext. `dnsPort` is reserved
for UDP/TCP and is rejected with TLS. These fields are trusted configuration,
never request data. Plain TCP is not encrypted, and neither TCP nor TLS is
claimed to be DNSSEC-authenticated; keep the resolver address trusted and use
the configured TLS/issuer bounds for the JWKS origin.

Each query uses a fresh random ID and one IN A or IN AAAA question without EDNS.
Dual-stack attempts require a positive, fully validated reply to both queries
within the shared DNS and attempt deadlines. The gateway queries AAAA first and
uses the validated IPv6 candidates before the IPv4 candidates. Both replies
together may supply at most eight unique addresses. A rejected, empty or missing
second response prevents the attempt from opening an HTTPS connection. If both
replies pass, the existing TCP connection failover may continue to the other
family. The DNS cache uses the shorter TTL measured from the attempt start. The
response must echo the question and contain 1–8 total answers within 512 bytes.
Answers must form exactly one chain from the echoed question, with at most four
CNAME hops followed by one or more records of the requested type. The gateway
validates the whole reply, including a positive 31-bit TTL for every record,
and requires every terminal address to be allowlisted before opening HTTPS.

Names are bounded to 253 expanded bytes and 63 bytes per label. Compression may
only point backwards to a previously decoded valid label boundary, with bounded
pointer traversal. Forks, duplicate CNAMEs, cycles, an owner with both A and CNAME,
missing terminal A records, unrelated answers, malformed or trailing RDATA/bytes,
answers of another address family, truncation, DNS errors and authority/additional
sections fail the attempt.

Optional `dnsCacheSeconds` (integer 1–3600) requires DNS mode. It enables one
owned address set per policy and shard. A validated reply may be reused until
the earlier of its shortest record TTL and this local cap, measured from DNS
completion on the monotonic clock. Cache hits still run authenticated discovery
and key fetch within their own attempt timeout. These requests never extend
DNS expiry. Cancel, clock failure or reversal, and exhaustion of the cached
address set on a TCP connect failure discard it. A reply rejected by the
resolver policy never enters the cache.

Within an attempt the gateway tries distinct terminal addresses in their
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

## Optional nonempty key refresh

`requireNonEmptyKeys` is an optional Boolean, default false. When true, a valid
JWKS with no configured approved kids is a failed refresh, including a nonempty
JWKS containing only unapproved kids. It leaves the previous keys, validator and
last-success time unchanged and uses the normal failure retry schedule. Existing
keys remain usable only until their original hard `maxAgeSeconds` deadline;
a cold or expired cache remains unavailable until a nonempty approved refresh.
The default accepts an empty intersection and immediately removes existing keys.
This option delays the effect of an authoritative empty set until expiry, so use
it only when that availability and revocation tradeoff is intended. It never
admits unapproved kids or extends maximum age.

## Optional new-kid admission

`admitNewKids` is an optional Boolean, default false, and is valid only with the
remote key profile. When true, the authenticated refresh response defines the
trusted inventory: every entry whose `kty` and `alg` match this policy
(`RSA`/`RS256` or `EC`/`ES256`) is imported, whether or not its decoded `kid`
appeared in the bootstrap `kids`. Entries for other algorithms in the same
provider set are ignored rather than admitted. A matching entry that fails the
fixed key profile rejects the whole refresh; it never partially expands trust.

With admission enabled, the bootstrap `kids` array may be empty and the local
`jwks` object supplies no keys. Remote mode still rejects every token until the
first successful authenticated fetch installs the initial verifier bank. A
nonempty bootstrap list keeps the previous behavior as a cold-start seed.
Admission never relaxes the exact HTTPS endpoint, TLS server-name/CA
authentication, issuer/JWKS-URI discovery checks, the 8192-byte/16-entry set
bound, unique nonempty `kid` bytes, or the fixed public-key profile. Fetch
failures, malformed sets, ambiguous IDs and empty intersections remain failures;
the last accepted bank is used only within its original maximum age.
`requireNonEmptyKeys` still applies, and removed keys disappear with the next
authoritative set. Tokens never select keys, trigger a fetch, add algorithms or
extend cache lifetime. See the tests for mixed-algorithm sets, opt-in
validation and a bootstrap-free first refresh.

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
The tag and selected IP address are owned by one policy/shard and tied to that
accepted representation. A later key GET sends `If-None-Match` only on its initial
candidate, at that same address, while the accepted cache remains fresh. Changed
addresses and failover candidates always receive unconditional GETs. TLS name,
CA, issuer, path and the approved or opt-in algorithm-bounded key inventory
remain configuration-owned.

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
clears its own copied state. Discovery has a separate opt-in validator. All stages retain the original attempt timeout and retry cadence.
No request traffic, token or unknown kid creates extra work.

## Discovery contract

`discoveryPath` and `discoveryIssuer` must appear together. The issuer is a bounded
HTTPS URI with no credentials, query or fragment, and must equal the enclosing
JWT policy's issuer exactly. By default discovery uses the same configured HTTPS
origin and resolved address.

Optional `discoveryAddress`, `discoveryServerName`, `discoveryCa` and
`discoveryPort` move only the discovery GET to a separately trusted fixed TLS
origin. The address is a bare IPv4 or IPv6 literal; the port defaults to 443.
The three fields `discoveryAddress`, `discoveryServerName` and `discoveryCa`
must appear together, and any of the four requires `discoveryPath` and
`discoveryIssuer`. This fixed origin does not use the JWKS DNS resolver or its
address allowlist, has no failover candidates and never follows redirects. TLS
SNI/CA authentication, the exact issuer check and the pre-authorized JWKS URI
check are unchanged. A completed 200 JSON object must contain exact string `issuer`
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

## Conditional discovery

Optional Boolean `conditionalDiscovery` defaults to false and requires configured
discovery when true. Discovery normally uses unconditional GETs and expects 200.
With the option enabled, an authenticated 200 that passes exact issuer and
endpoint checks can commit its own strong ETag under the same 128-byte syntax as
key ETags. Missing ETag clears the discovery validator. Duplicate, weak or
malformed ETags fail the discovery attempt.

The exact selected IP address and the immutable configured discovery endpoint
bind the owned validator to that representation. The initial candidate can send
this tag while the metadata remains younger than `maxAgeSeconds`. Address changes
and TCP failover candidates always fetch full metadata. A 304 must be bodyless,
match the exact sent strong ETag and finish before the metadata hard age expires.
Accepting it renews metadata age only. Every successful discovery still proceeds
to a separate key GET within the original attempt deadline. The discovery tag
never becomes a key tag, and accepting metadata does not renew key age.
Clock failure or reversal, cancellation and configuration retirement discard
the stored discovery validator.

### Fresh discovery reuse

Optional `discoveryCacheSeconds` (integer 1–3600 and at most
`maxAgeSeconds`) requires discovery and defaults to disabled. It remembers the
last accepted metadata and exact selected IP address. While younger than this
limit, a later attempt with the same initial address may skip the discovery GET
and proceed directly to the key GET. The entry remains bound to the configured
issuer, discovery endpoint and TLS trust. Changed addresses and failover require
full discovery before a key GET.

Cache reuse never slides the metadata timestamp. An accepted 200, or an
accepted 304 with `conditionalDiscovery` enabled, can refresh it. Metadata can
be accepted independently of a later key failure. Once discovery is needed
again, a failed response ends the attempt without reviving expired metadata or
renewing key age. Only successful key refresh can renew keys. Cancellation,
clock reset and configuration retirement discard the remembered metadata.

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
Separate native profiles cover discovery conditional requests, strict expiry and
same-address reuse without suppressing key rotation. They also verify DNS and
metadata stage timeouts preserve the normal retry path.
Real native-loaded RS256 and ES256 gateways run after source removal on both
Linux backends. The existing fixed-endpoint tests remain registered separately.
No new keyword, dependency, dynamic trust source or per-request resolver is added.
The IPv6 fixture uses an IPv6 resolver and HTTPS origin, a CNAME-to-AAAA answer,
a disallowed destination and recovery with rotated keys on both Linux backends.
TCP and DNS-over-TLS resolver fixtures check RFC 7766 framing, a short frame,
cache expiry and recovery after a resolver fault on both Linux backends. A
missing TLS trust file prevents remote activation.
DNS-over-HTTPS and full OIDC workflows remain
open under #1077. New-kid admission is opt-in and limited to algorithm-matching
entries from the authenticated set; it does not expand the destination or
algorithm trust boundary. A discovery origin with a rotating DNS name is not part
of the separately configured fixed-address profile.
