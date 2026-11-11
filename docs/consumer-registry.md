# Bounded Consumer registry snapshots

`consumerAuthenticate(presented, configuration, method) -> Json?` authenticates a
singleton header credential against an immutable, trusted configuration snapshot.
`configuration` and `method` must resolve to compile-time strings, including `env()` or a
helper parameter that resolves to one at its route use. Request-supplied registry
JSON is rejected by the compiler. An invalid snapshot fails compilation/loading,
with a fixed diagnostic that contains no registry bytes.

```json
{
  "version": 1,
  "consumers": [{"id": "alice", "enabled": true, "groups": ["staff"]}],
  "credentials": [
    {"id": "alice-key-v2", "consumerId": "alice", "method": "bearer",
     "secret": "configured-secret", "enabled": true}
  ]
}
```

The version-1 schema is exact: unknown/missing fields, wrong types and duplicate
JSON names fail. Up to 32 Consumers, 64 credentials and 16 groups per Consumer fit
within the shared 8192-byte/2048-node JSON budget. Consumer/credential IDs are
nonempty printable ASCII up to 64 bytes; group names up to 128 bytes. IDs and group
membership must be unique. Every credential references an existing Consumer;
even disabled records are validated. Reusing a secret within a method is rejected
across all credentials, preventing ambiguous ownership and slot-order selection.
An empty registry is a valid deny-all snapshot.

Methods are `bearer`, `basic` and `header`. Bearer and Basic retain existing strict
syntax/canonical encoding and constant-time equal-length secret comparison.
`header` admits the bounded Bearer-key byte grammar as an exact custom-header key.
Use `req.authorization.or("")` for Authorization or `req.uniqueHeader(name).or("")`
for a custom header: duplicates become absent, never an anonymous grant. These
methods never implicitly extract query, cookie or body credentials. Explicit
query/form admission is available through the separate functions below.

A successful result owns only `consumerId`, `credentialId`, `method`, and `groups`
in the request arena. It contains no secret or full registry. Missing, malformed,
wrong, disabled or revoked credentials return nil; authorization remains separate
(e.g. `jwtHasGroup(identity, "staff")`). There is no guest fallback. Match results
never accept client identity/group headers as proof.

## Explicit query and form credentials

`consumerAuthenticateQuery(target, configuration, name) -> Json?` accepts the raw
origin-form `req.path` (including its query); `consumerAuthenticateForm(body,
configuration, name) -> Json?` accepts an application/x-www-form-urlencoded body.
Both use raw-key registry records with method `header`. Registry and field name
must resolve to compile-time configuration; name is 1–64 ASCII letters, digits,
`_`, `-` or `.`. Routes explicitly select one source. Authorization, cookies and
other headers are never fallback credentials. Form routes must additionally
require exactly one expected Content-Type before calling the function; the example
admits the exact `application/x-www-form-urlencoded` spelling without parameters.

The finite ASCII profile accepts at most 4096 input bytes and 64 fields. Every
field requires a nonempty valid name followed by `=`. Percent triplets decode
once and `+` becomes space. All decoded names must be unique, including encoded
aliases such as `api_key` / `api%5Fkey`; duplicates of business fields reject too.
Malformed escapes, controls/NUL, non-ASCII decoded bytes, raw semicolons/fragments,
empty segments and trailing `&` reject the entire input. The decoded credential
must be nonempty, at most 512 bytes, and pass the existing raw-key grammar.
Unknown, disabled, wrong or ambiguous keys return nil without a partial identity.

On success the identity additionally contains `remaining`: URL-encoded fields
with the credential field removed, preserving every other field's exact encoded
bytes and order. Empty remaining content is an empty string. Neither the decoded
credential nor the full registry appears in this result. The remaining fields
are still untrusted application input; this is not general secret classification.
The original request bytes are unchanged. Do **not** pass the original request to
transparent `forward` and claim it was sanitized. Build a new outbound message
from `remaining` and the verified identity instead.

[consumer-fields-auth.rut](../examples/consumer-fields-auth.rut) demonstrates this
contract: both source-specific routes submit sanitized fields as a new form POST
to one configuration-owned verified HTTPS `httpCall` endpoint. The downstream
query target and original body/headers are not copied, and client identity headers
cannot select the forwarded Consumer. This is a bounded callout adapter, not a
transparent body/target rewriting proxy. Its remote success is required before
returning 204. Native H1/H2 tests inspect the actual upstream wire contents on both
backends after deleting the source, and verify invalid requests make no callout.

Keep credentials out of custom logs/traces. The supported downstreamRequestBytes
and downstreamHost access-log formats do not include query/form content; this API
does not retroactively redact external capture systems or arbitrary user logging.

## Lifecycle and publication

Create/update a Consumer by preparing a replacement snapshot with the same stable
ID. Rotate by adding a distinct credential ID/secret, publish the overlap, then
disable/remove the old record in a subsequent snapshot. Disable a Consumer to
reject every owned credential; replace its groups to change later authorization.
Credential removal expunges its secret from the replacement configuration.

The configuration host uses the existing `Shard::reload_config` publication path
and retains each native program until its old RCU readers retire. Authentication
and subsequent group checks within an already admitted request use the captured
request-owned identity. New requests select the newly published handler/snapshot.
The native regression pins dispatch to the old program across publication and
proves old-group completion while new dispatches reject the retired key and lose
old group rights. This synchronous registry API does not introduce a new timer
continuation or promise arbitrary live JSON values across legacy `wait` routes. Invalid replacement compilation does not publish a new program.
This slice does not add a CLI file watcher, administrative HTTP endpoint or a new
RCU reclamation manager. Standalone CLI deployments can install a new program by
restart; embedding hosts already own configuration publication and retirement.

Protect source/configuration and compiled artifacts containing secrets with
appropriate filesystem permissions. This API exposes no registry dump/management
query and diagnostics never interpolate configuration. Before proxy forwarding,
strip all configured credential headers with `req.remove`, and replace spoofable
identity headers from the authenticated result. Ordinary query/body/access-log
redaction is not implied by a header-only policy. See
[consumer-registry-auth.rut](../examples/consumer-registry-auth.rut).

## Product scope

This bounded registry, ordinary rotation/revocation and authorization correctness
are proposed free foundations (#1072). Multi-tenant administration, delegated
management and distributed identity governance remain separate commercial
candidates. No third-party registry, dynamic collection syntax, keyword or external
library is introduced. Parsing/matching is bounded and allocation-free apart from
the normal request-arena identity result; this is not a constant-cost indexed
lookup or a promise of unbounded directory size.
