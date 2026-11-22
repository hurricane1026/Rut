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

A credential may optionally include `groups`. When absent, its successful
identity inherits all groups from its owning Consumer. An explicit empty array
grants no groups; a nonempty array narrows the identity to at most 16 unique
1–128 byte printable ASCII names already present in that Consumer's `groups`.
This field only removes authority from the Consumer's group list. Adding groups
to a Consumer does not expand a credential with an explicit subset; the
credential must be updated separately. Removing a Consumer group still used by
an explicit credential makes the entire replacement snapshot invalid until the
credential is narrowed or removed. All entries are checked even when the
credential or Consumer is disabled.

Bearer and header records contain exactly one of `secret` or `secretSha256`.
`secretSha256` is the lowercase 64-hex SHA-256 digest of the exact presented
textual key bytes (the key text is not hex-decoded). The runtime hashes a
validated presented key once and compares the digest in constant time. Basic
and mTLS records continue to require their existing raw `secret` field and
reject `secretSha256`. Duplicate raw keys, duplicate verifiers, and raw/verifier
cross-collisions within a method are invalid across all records, including
disabled or time-windowed credentials.

This verifier format is for unpredictable API keys, not passwords. SHA-256 is
not a password hashing or stretching scheme: a low-entropy key can be guessed
offline. Treat verifier digests as sensitive configuration. The `hash-keys`
CLI conversion below accepts only raw bearer/header keys in the generated
64-lowercase-hex profile; this format check does not prove that a key was
generated with sufficient entropy.

Each credential may add integer `notBefore` and/or `expiresAt` Unix-second
fields. Both default to `0`, meaning unbounded; nonzero values must be positive
signed-64-bit integers, and when both are finite `expiresAt` must be greater
than `notBefore`. The complete credential object still allows only its common
required fields, exactly one key field, and the optional `notBefore`, `expiresAt`
and `groups` fields; duplicate or unknown names and
wrong numeric forms invalidate the whole snapshot, including disabled records.
At authentication, a finite start is inclusive (`now >= notBefore`) and a finite
expiry is exclusive (`now < expiresAt`).

Any snapshot with at least one nonzero window bound requires one successful
`CLOCK_REALTIME` read for each authentication attempt; a failed, nonpositive or
malformed clock sample denies authentication, including otherwise unbounded
credentials in that snapshot. Version-1 snapshots whose credentials all omit
the fields or specify zero retain the prior no-clock behavior. Time is sampled
from the host clock, never from the request. Clock corrections can move a
credential into or out of its configured interval; this feature adds no monotonic
rollback pin, activation scheduler or reload timer. Expiry is checked on each
new authentication, so it applies without reloading the program.

The generic method accepts `bearer`, `basic` and `header`. Bearer and Basic retain existing strict
syntax/canonical encoding and constant-time equal-length secret comparison.
`header` admits the bounded Bearer-key byte grammar as an exact custom-header key.
Use `req.authorization.or("")` for Authorization or `req.uniqueHeader(name).or("")`
for a custom header: duplicates become absent, never an anonymous grant. These
methods never implicitly extract query, cookie or body credentials. Explicit
query/form admission is available through the separate functions below.

A successful result owns only `consumerId`, `credentialId`, `method`, and the
effective `groups` list
in the request arena. It contains no secret or full registry. Missing, malformed,
wrong, disabled or revoked credentials return nil; authorization remains separate
(e.g. `jwtHasGroup(identity, "staff")`). There is no guest fallback. Match results
never accept client identity/group headers as proof.

## mTLS Consumer authentication

The `mtls` method's existing `secret` field holds a public SHA-256 certificate
fingerprint pin, exactly 64 lowercase hexadecimal characters. Disabled pins are
still validated, and duplicate pins are rejected regardless of credential or
Consumer state. Authenticate with `consumerAuthenticateMtls(configuration) ->
Json?`; the runtime reads only the connection's verified fingerprint, never a
caller-supplied value. Missing certificates, cleartext, ordinary server-only
TLS, unknown pins and disabled credentials or Consumers return nil. Results use
the same identity/group projection as other methods. On an existing TLS
connection, each new request matches its unchanged verified fingerprint against
the adopted snapshot.

The generic `consumerAuthenticate(presented, configuration, method)` API only
accepts `bearer`, `basic` and `header`; `"mtls"` is a compile-time error and the
runtime generic matcher also denies it. Query/form credential APIs only match
`header` records. This keeps public certificate fingerprints away from ordinary
credential extraction and prevents forwarded identity headers from satisfying
the mTLS policy. The runnable
[Consumer mTLS registry example](../examples/consumer-mtls-registry-auth.rut)
demonstrates projection and explicit group authorization.

## Explicit query and form credentials

`consumerAuthenticateQuery(target, configuration, name) -> Json?` accepts the raw
origin-form `req.path` (including its query); `consumerAuthenticateForm(body,
configuration, name) -> Json?` accepts an application/x-www-form-urlencoded body.
Both use registry records with method `header` and support raw and SHA-256
key verifiers. Registry and field name must resolve to compile-time
configuration. The field name is 1–64 ASCII letters, digits,
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
Authentication leaves the original request bytes unchanged. Use the sanitized
fields to build an outbound message or explicitly replace the forwarded query
target.

[consumer-fields-auth.rut](../examples/consumer-fields-auth.rut) demonstrates this
contract: both source-specific routes submit sanitized fields as a new form POST
to one configuration-owned verified HTTPS `httpCall` endpoint. The downstream
query target and original body/headers are not copied, and client identity headers
cannot select the forwarded Consumer. This is a bounded callout adapter, not a
transparent body/target rewriting proxy. Its remote success is required before
returning 204. Native H1/H2 tests inspect the actual upstream wire contents on both
backends after deleting the source, and verify invalid requests make no callout.

### Forwarding without the query credential

[consumer-query-forward-auth.rut](../examples/consumer-query-forward-auth.rut)
authenticates the original query, checks the verified Consumer group, and uses
the existing owned `forward(..., set_path: target)` effect. The
[`forwardingTarget` helper](../examples/middleware/consumer_query.rut) takes
the same request's `req.pathOnly` and successful `consumerAuthenticateQuery`
identity. It joins the original path to `remaining` and omits `?` when no
fields remain. The original path spelling and remaining field bytes and order
are preserved. A missing or wrongly typed `remaining` member yields nil.

The route returns 401 for failed authentication, 403 for a missing required
group, and 503 if it cannot project the target. The forward effect validates
and owns the target before connecting upstream. Other parts of the request
follow ordinary forwarding rules. The example explicitly drops Authorization,
X-API-Key and client-supplied X-Consumer-ID before forwarding. It leaves the
method and body intact.

The example selects the `downstreamRequestBytes` access-log format, which
records lengths without targets. `downstreamHost` also omits the target.
For a legacy CLI sink, run `--access-log PATH --access-log-path-only` to omit
the entire query before recording the original encoded path. This process-wide
option also covers requests denied by authentication or group policy. It
affects only the log. Forwarding still needs the explicit target replacement
above. Keep query credentials out of custom raw-target logging and captures.
For form credentials use the explicitly rebuilt callout above.

Native H1/H2 fixtures read the exact upstream request and inspect the
target-free access log on epoll and io_uring at O0 and O2.
The legacy CLI fixture verifies plain and compressed path-only logs on both
backends.

## Lifecycle and publication

Create/update a Consumer by preparing a replacement snapshot with the same stable
ID. Rotate by adding a distinct credential ID/secret, publish the overlap, then
disable/remove the old record in a subsequent snapshot. Disable a Consumer to
reject every owned credential; replace its groups to change later authorization.
Credential removal expunges its secret from the replacement configuration.
For mTLS, use a distinct credential ID and fingerprint pin for each certificate
in the overlap window, then disable or remove the previous pin. A verified
fingerprint remains attached to its connection; new requests on an existing TLS
connection use the adopted Consumer snapshot against that same verified
fingerprint.

The [verified certificate deny example](../examples/consumer-mtls-deny-auth.rut)
checks one or two configured SHA-256 certificate pins before Consumer mapping.
Use lowercase 64-digit hexadecimal pins and leave an unused slot empty. A denied
fingerprint or missing verified client certificate returns 403. Invalid or
duplicate pins, or two empty slots, return 503. This policy acts at request
admission, including on existing TLS connections, and does not replace the
listener's [issuer-signed CRL verification](mtls-client-crl.md).

The configuration host uses the existing `Shard::reload_config` publication path
and retains each native program until its old RCU readers retire. Authentication
and subsequent group checks within an already admitted request use the captured
request-owned identity. New requests select the newly published handler/snapshot.
The native regression pins dispatch to the old program across publication and
proves old-group completion while new dispatches reject the retired key and lose
old group rights. This synchronous registry API does not introduce a new timer
continuation or promise arbitrary live JSON values across legacy `wait` routes. Invalid replacement compilation does not publish a new program.
The offline administration tool below prepares validated replacement files.
It does not add a CLI file watcher, administrative HTTP endpoint or a new
RCU reclamation manager. Standalone CLI deployments can install a new program by
restart; embedding hosts already own configuration publication and retirement.

Protect source/configuration and compiled artifacts containing secrets with
appropriate filesystem permissions. This API exposes no registry dump/management
query and diagnostics never interpolate configuration. Before proxy forwarding,
strip all configured credential headers with `req.remove`, and replace spoofable
identity headers from the authenticated result. Ordinary query/body/access-log
redaction is not implied by a header-only policy. See
[consumer-registry-auth.rut](../examples/consumer-registry-auth.rut).

## Offline administration

`build/src/rut-consumers` manages version-1 snapshots using the same runtime
validator as `consumerAuthenticate`. It requires no LLVM, network service or new
library. It provides these commands:

`diff BEFORE AFTER` compares two existing snapshots without creating files or
publishing configuration. Both inputs must pass the same private-file guards and
full runtime validation before any stdout is written. Successful comparisons
return 0, including an empty diff; usage, input or output failure returns 2.
The command emits one structured JSON object followed by a newline:

```json
{"consumers":{"added":[],"removed":[],"changed":[]},
 "credentials":{"added":[],"removed":[],"changed":[]}}
```

Added and removed arrays contain records. Changed Consumer entries contain
`before` and `after` records; changed credential entries additionally contain
boolean `keyChanged` and `keyRepresentationChanged`. Credential records in all
arrays omit both `secret` and `secretSha256`. Key text and digests are never
included in diagnostics or the report. The complete report is buffered within
32 KiB before writing, so invalid input or a comparison failure emits no partial
JSON. Input snapshots remain unchanged.

Stable IDs and strings compare by decoded bytes. JSON whitespace, object-member
order, escape spelling, record-array order and group-set order do not create
changes. Optional field presence is preserved: omitted `groups` differs from
`[]`, and omitted time bounds differ from explicit zero. Integer bounds compare
by value. Added records follow AFTER order; removed and changed records follow
BEFORE order, so output is deterministic for a given input pair.

`keyChanged` reports different decoded raw key material, different effective
SHA-256 material when either bearer/header record is hashed, or a method change.
`keyRepresentationChanged` reports a switch between `secret` and `secretSha256`.
Converting a raw bearer/header key to its equivalent SHA-256 verifier therefore
sets only the representation flag. Basic/mTLS raw keys compare by decoded bytes.
These flags also apply to disabled records; metadata-only changes set both false.

```sh
build/src/rut-consumers diff consumer-config/v1.json consumer-config/v2.json
```

The audit compares supplied immutable snapshots; deployment and historical
retention remain host responsibilities. #1072 remains open.

`generate-key INPUT CONSUMER_ID CREDENTIAL_ID METHOD OUTPUT` adds one generated
credential to a new snapshot. Only `bearer` and `header` methods are accepted.
The Consumer must already exist, and the credential ID must not appear in the
input, including on disabled records. Consumer and credential IDs follow the
registry's printable ASCII, 1–64 byte label rule; the tool JSON-quotes them
before constructing the validated change. A disabled Consumer may be staged;
its enabled state is preserved while the new credential is enabled.

The CLI reads the existing private snapshot, obtains exactly 32 bytes from the
operating-system CSPRNG (one Linux `getrandom` call with `GRND_NONBLOCK`; one
`getentropy` call on other supported hosts), and stores the key as 64 lowercase
hexadecimal characters. An entropy error, interruption, or short Linux read
fails closed without retry or fallback. Temporary random bytes, encoded secret
buffers, parsed documents and snapshot buffers are cleared before return.
Success emits no stdout or stderr, and the secret never
appears in command arguments or diagnostics. The immutable output uses the same
0600, synced, atomic no-replace publication path as `apply`; the complete
resulting snapshot is validated against runtime schema and capacity first.
Generation does not activate the snapshot.

For a rotation overlap, generate a distinct credential ID from the current
snapshot, publish and activate that version through the host's normal trusted
configuration path, then use `apply` to disable or remove the old ID in a later
snapshot. `inspect` redacts the credential secret; the 0600 snapshot itself
contains it and must be protected and retired as sensitive configuration.

```sh
umask 077
mkdir -m 700 consumer-config
build/src/rut-consumers init consumer-config/empty.json
# Write the trusted changes below to consumer-config/changes.json with mode 0600.
build/src/rut-consumers plan consumer-config/empty.json consumer-config/changes.json
build/src/rut-consumers apply consumer-config/empty.json consumer-config/changes.json consumer-config/v1.json
build/src/rut-consumers validate consumer-config/v1.json
build/src/rut-consumers inspect consumer-config/v1.json
```

To provision a new bearer key without placing secret material in a changes file:

```sh
build/src/rut-consumers generate-key consumer-config/v1.json alice alice-key-v2 bearer consumer-config/v2.json
build/src/rut-consumers validate consumer-config/v2.json
build/src/rut-consumers inspect consumer-config/v2.json
```

`generate-key-verifier INPUT CONSUMER_ID CREDENTIAL_ID METHOD SNAPSHOT_OUTPUT
KEY_OUTPUT` provisions a bearer/header key without placing its raw text in the
snapshot. It adds a `secretSha256` verifier to the new credential in the
snapshot and writes the corresponding generated 64-byte lowercase-hex text to a
separate key file with mode 0600 and no trailing newline. The key file is the
one-time delivery material; the new snapshot record contains only its verifier.
Other existing records are preserved, so raw secrets already present in the
input may remain in the replacement snapshot. The input is unchanged, and both
outputs are new files under the same owned directory, which must not be
group/other-writable. The CLI opens and retains both verified directory
descriptors and rejects equal basenames, directory mismatches, and existing
outputs before requesting randomness.

The complete replacement snapshot is built and validated before publication.
The key file is published first, then the snapshot, each by synced 0600
temporary file and atomic no-replace link. These are two publications, not one
atomic transaction: if key publication fails, no snapshot is published; if
snapshot publication fails after the key is linked, the key may remain without
its snapshot. Fixed errors identify the stage and instruct operators to inspect
the directory before retrying. A sync or temporary-file cleanup failure can
leave publication state uncertain, so do not assume rollback or delete files
automatically. Neither key nor verifier is written to stdout, stderr, or
command arguments.

```sh
build/src/rut-consumers generate-key-verifier consumer-config/v1.json alice alice-key-v2 bearer consumer-config/v2.json consumer-config/alice-key-v2.txt
```

### Targeted state and group updates

Three commands update existing records without requiring a complete secret-bearing
record in a changes file:

```sh
build/src/rut-consumers set-consumer-enabled INPUT CONSUMER_ID false OUTPUT
build/src/rut-consumers set-credential-enabled INPUT CREDENTIAL_ID true OUTPUT
build/src/rut-consumers set-consumer-groups INPUT CONSUMER_ID GROUPS_FILE OUTPUT
```

The state commands accept only exact `true` or `false`. The Consumer command
changes only that Consumer's enabled state and retains every credential's own
state. The credential command changes only the selected credential for all four
existing methods, preserving its supported raw/verifier key representation. Reactivation does not bypass a
disabled owner, renew expiry, change activation bounds or regenerate key material.
Both commands require an existing stable ID, including on disabled records.

`GROUPS_FILE` is an owned private JSON file containing one complete array of group
names, for example `["readers","writers"]`. Existing schema bounds apply: at most
16 unique nonempty visible ASCII names (`0x21`–`0x7e`), each at most 128 bytes. `[]` removes all
owner groups when the resulting snapshot remains valid. Credentials with omitted
groups inherit the new owner set, so adding owner groups expands their authority.
Explicit credential subsets and explicit empty arrays remain unchanged. Removing
a group still referenced by an explicit credential rejects the entire update,
even if that credential or owner is disabled. Use a coordinated `apply` transaction
when both owner and credential membership must change together.

The whole source and replacement are validated. Record order, raw/verifier key
representation, optional fields and time bounds are preserved. No clock is read.
A no-op still publishes a new private 0600 snapshot through the existing atomic
no-replace path. Input files remain unchanged, diagnostics include no record/key
bytes, and success is silent. Deployment remains explicit. Loaded programs keep
their adopted snapshots, and these commands add no durable revocation history or
online administration. #1072 remains open.

### Registering Consumers and provisioning constrained keys

`provision-key-verifier INPUT PROFILE SNAPSHOT_OUTPUT KEY_OUTPUT` reads a private
JSON profile and generates a new bearer/header key. This provides two workflows:
register a Consumer with its first key, or add a key with explicit groups and time
bounds to an existing Consumer. The exact profile shape is:

```json
{
  "consumer": {"id": "alice", "enabled": true, "groups": ["staff", "readers"]},
  "credential": {"id": "alice-read-v1", "consumerId": "alice", "method": "bearer",
                 "enabled": true, "groups": ["readers"],
                 "notBefore": 1800000000, "expiresAt": 1800003600}
}
```

`consumer` is optional. When present, it is one complete new Consumer record,
its ID must be unused even on disabled records, and it must match the credential's
`consumerId`. Existing Consumers are never updated by this command. When omitted,
the credential must reference an existing Consumer.

`credential` requires `id`, `consumerId`, `method` and boolean `enabled`. Its only
optional fields are `groups`, `notBefore` and `expiresAt`. Only `bearer` and
`header` methods are accepted. The credential ID must be unused across enabled and
disabled records. Raw secrets, verifier fields, unknown names and duplicate names
are rejected. Explicit groups must be a subset of the owning Consumer's groups.
Omitted groups retain inheritance, while `[]` grants no groups. Time bounds retain
the exact supplied values and optional-field presence. No clock is read and no
expiry is renewed. Disabled Consumers and credentials may be staged explicitly.

The source, profile and complete replacement use the existing bounded private-file
and runtime-schema checks. Input files remain unchanged. Outputs reuse the
0600, no-replace key-first/snapshot-second publication contract above, including
its partial-publication and uncertain-durability errors. The generated key is
written only to the separate key output, with only its SHA-256 verifier added to
the snapshot. Existing raw secrets in the source remain sensitive. Success is
silent, and failures contain no profile or key material.

```sh
# For an existing Consumer, omit the consumer member from the private profile.
build/src/rut-consumers provision-key-verifier consumer-config/empty.json consumer-config/alice-profile.json consumer-config/alice.json consumer-config/alice-read-v1.key
```

Deployment remains explicit. This command does not publish to running gateways,
distribute keys, preserve a durable revocation history or provide online
administration. Those lifecycle requirements remain open in #1072.

`rotate-key-verifier INPUT OLD_CREDENTIAL_ID NEW_CREDENTIAL_ID SNAPSHOT_OUTPUT
KEY_OUTPUT` replaces an existing enabled bearer/header credential with a freshly
generated key and SHA-256 verifier. The old credential may contain raw `secret`
or `secretSha256`; its complete record remains in the replacement snapshot with
`enabled: false`. The new enabled record inherits its exact `consumerId`, method,
optional `groups`, `notBefore` and `expiresAt`. Omitted fields remain omitted;
explicit empty groups and zero bounds remain explicit. Rotation does not widen
groups or renew time bounds, including already expired or future windows. The
CLI does not read the clock. A disabled Consumer remains disabled and may have
new credentials staged under it.

Both IDs must be valid, and the new ID must be unused across all credentials,
including disabled records. Rotation retains the old record, so the input needs
one free slot within the 64-credential limit and the resulting snapshot must fit
the existing byte/node bounds. Unknown or disabled source credentials and
Basic/mTLS sources are rejected. The original input is unchanged. Output
preflight, private key delivery, redaction and key-first/snapshot-second failure
semantics are exactly those described above for `generate-key-verifier`.

```sh
build/src/rut-consumers rotate-key-verifier consumer-config/v2.json alice-key-v2 alice-key-v3 consumer-config/v3.json consumer-config/alice-key-v3.txt
```

Deploy the replacement snapshot explicitly; this offline command does not revoke
keys in already running programs or publish to gateways. Broader Consumer
administration, distribution and durable lifecycle work remains open in #1072.

`prune-credentials INPUT CUTOFF_UNIX_SECONDS OUTPUT` writes a new snapshot
without credentials that are explicitly disabled or have a finite positive
`expiresAt` less than or equal to the supplied cutoff. The cutoff is a canonical
positive decimal integer from 1 through 9223372036854775807: signs, leading zeros,
whitespace, fractions, exponents and overflow are rejected. The CLI never reads
the clock; the operator may deliberately choose a past or future cutoff.

All Consumers remain, including disabled ones. A disabled Consumer alone does
not remove its enabled credentials. Missing or zero expiry is unbounded, and
`notBefore` does not select records for pruning. Retained credentials keep their
original order, full metadata, optional-field presence and raw/hash key form.
The whole input, including records selected for removal, and the complete result
must pass runtime validation before existing private 0600 atomic no-replace
publication. A no-op still publishes a new validated copy; success is silent.
Invalid input, cutoff or output leaves the source unchanged and reports no key
material. Existing destinations are never replaced.

```sh
build/src/rut-consumers prune-credentials consumer-config/v3.json 1800000000 consumer-config/v4.json
```

Pruning frees credential slots and removes those IDs from the new snapshot, so a
later snapshot can reuse them. It is not a durable revocation list or history
store. Existing input files still contain their old records and secrets;
retention and secure retirement remain host responsibilities. Running gateways
keep their loaded snapshots until explicit deployment. #1072 remains open.

An apply transaction has exactly four required arrays:

```json
{
  "consumers": [{"id": "alice", "enabled": true, "groups": ["staff"]}],
  "credentials": [{"id": "alice-key-v1", "consumerId": "alice",
                   "method": "bearer", "secret": "replace-with-provisioned-secret", "enabled": true}],
  "removeConsumers": [],
  "removeCredentials": []
}
```

The first two arrays upsert **complete records** by decoded stable ID; omitted
records are preserved, while an updated Consumer's groups replace its old groups.
Add a distinct credential ID for a rotation overlap, then disable or remove the
old credential in a later transaction. Set a Consumer's `enabled` to false to
disable all its credentials. Removal arrays contain existing IDs. To remove a
Consumer, remove or reassign all owned credentials in the same transaction.
Duplicate operation IDs, an ID both updated and removed, unknown removals,
orphaned credentials, ambiguous secrets, invalid schema and excess capacity reject
the entire transaction. Every nonremoved record is validated, including disabled
ones. The resulting snapshot must fit the runtime's 8192-byte/2048-node limits.

Input and changes files must be regular, owned by the invoking effective user,
without any group/other permissions and at most 8192 bytes. Symlinks, FIFOs,
directories and publicly readable files reject. Secrets come from these files,
never command arguments. `inspect` writes Consumer metadata and credential
ID/owner/method/enabled fields and any `notBefore`/`expiresAt` metadata to
stdout, omitting every credential `secret` and `secretSha256`. `plan` uses the
same redaction. `inspect` also shows optional window and group metadata.
`apply` and `generate-key` preserve existing window and group fields; newly
generated credentials have no time window (and are therefore unbounded) and
omit `groups`, inheriting their Consumer's groups. `hash-keys` preserves group
metadata.
Validation and mutation commands produce no stdout. Fixed errors contain no
configuration values. Exit status is 0 on success and 2 on any failure.

`plan INPUT CHANGES` performs the same full transaction and replacement-snapshot
validation as `apply`, then writes the resulting metadata in the same redacted
format as `inspect`. It creates no files and emits no partial preview on invalid
input. This includes validation of secrets even though they are omitted from the
preview. A preview does not reserve an output or pin either input file: keep the
reviewed inputs unchanged until `apply`, which validates them again.

`hash-keys INPUT OUTPUT` converts every raw bearer/header key in the snapshot
from exactly 64 lowercase hexadecimal characters to a `secretSha256` verifier.
It rejects the whole operation if any such raw key falls outside that profile,
validates the converted complete snapshot (including cross-collisions), and
publishes only a new private output file. Existing verifiers are retained,
making conversion idempotent; Basic and mTLS secrets remain raw in the output.
The input is never modified or erased, and output records for other methods may
still contain raw secrets. The command prints no secrets or verifier digests.

Output must be a **new filename** in an owned directory without group/other write
permission. A private 0600 temporary file is written and synced before atomic
no-replace hard-link publication and directory sync. Existing paths, including
input aliases and symlinks, stay untouched. Competing writers to the same output
have at most one winner. Preparation/validation failure leaves no new snapshot;
a post-publication sync/cleanup failure reports that the destination needs
inspection, without claiming rollback. Abrupt process termination can leave a
private temporary file. Input, output and parsed secret-bearing buffers are
cleared on ordinary exit; these files and compiled artifacts still require
operator protection and retention/removal policy.

These are immutable administrative files, not a live multiwriter registry.
Administrators must select the intended base version and coordinate which
replacement is installed; a new filename alone is not compare-and-swap against
the currently running gateway. `apply` never activates configuration. For the
standalone server, pass the selected file's contents through trusted
`AUTH_REGISTRY` configuration when compiling/loading or restarting. Embedding
hosts use the existing RCU publication/retirement boundary described above.

The CLI regression covers creation, generated bearer/header keys, exact
lowercase-hex formatting, distinct outputs, escaped IDs, disabled-Consumer
staging, collision/method/bounds/capacity rejection, zero-output secret
handling, rotation/disable/removal, redacted preflight, competing output
writers, all-or-nothing/idempotent verifier conversion, and separate key/verifier
provisioning with preflight and publication-fault checks. Native HTTP fixtures
consume generated snapshots on
epoll/io_uring with HTTP/1 and HTTP/2, verify overlap, then reject a disabled
old generated key while retaining the new one. Transparent
request-target/body mutation and online administrative HTTP APIs remain separate.

### Targeted lifecycle commands

All commands take a validated private input snapshot.

| Command after `rut-consumers` | Effect |
| --- | --- |
| `inspect-consumer INPUT CONSUMER_ID` | Print the selected Consumer's metadata as one JSON object. |
| `inspect-credential INPUT CREDENTIAL_ID` | Print one credential's metadata with secret and verifier fields omitted. |
| `remove-credential INPUT CREDENTIAL_ID OUTPUT` | Remove exactly one existing credential and publish a private candidate. All Consumers and remaining credentials are preserved. |
| `remove-consumer INPUT CONSUMER_ID OUTPUT` | Remove a Consumer that owns no credential records. |
| `remove-consumer-with-credentials INPUT CONSUMER_ID OUTPUT` | Explicitly remove a Consumer and all of its credential records in one private snapshot transaction. |
| `set-credential-groups INPUT CREDENTIAL_ID GROUPS_FILE OUTPUT` | Set one credential's explicit group subset from a private JSON array. An empty array grants no groups. |
| `inherit-credential-groups INPUT CREDENTIAL_ID OUTPUT` | Remove the explicit subset so the credential inherits its Consumer's groups. |

Both group commands preserve the credential's owner, verifier, enabled state,
and validity window. They validate the entire candidate before publishing a
new private file. Applying the candidate to a running gateway uses the normal
deployment path.

## Product scope

This bounded registry, ordinary rotation/revocation and authorization correctness
are proposed free foundations (#1072). Multi-tenant administration, delegated
management and distributed identity governance remain separate commercial
candidates. No third-party registry, dynamic collection syntax, keyword or external
library is introduced. Parsing/matching is bounded and allocation-free apart from
the normal request-arena identity result; this is not a constant-cost indexed
lookup or a promise of unbounded directory size.

## Deployment policy checks

`rut-consumers check-policy INPUT POLICY NOW_UNIX_SECONDS` validates a registry
and evaluates a private, nonempty JSON policy object before deployment. Both
files use the normal private-input rules. Supply a positive Unix second
explicitly. A credential counts as active when its Consumer and credential are
enabled, its start has been reached, and its finite expiry has not been reached.

Rules combine with AND. Omitted rules have no effect. Boolean rules accept
`true` to enforce the check and `false` to disable it. Unknown or duplicate rule
names, malformed policy values and rule violations all produce exit status 2.
The command emits no stdout or input values, creates no files and does not
activate a snapshot. Use the same snapshot for deployment that passed the check.

`rut-consumers apply-checked INPUT CHANGES POLICY NOW_UNIX_SECONDS OUTPUT`
applies the same transaction as `apply`, evaluates the deployment policy
against the validated replacement in memory and then publishes those exact
bytes as a private no-replace file. A malformed policy, rejected rule or
invalid timestamp prevents publication. The current snapshot may violate the
policy, so a transaction can bring it into compliance. The running gateway
continues to adopt snapshots through its existing deployment path.

| Policy field | Effect |
| --- | --- |
| `requireHashedKeys` | Require a SHA-256 verifier for every bearer or header key, including disabled records. |
| `allowedMethods` | Allow only the named methods among bearer, header, basic and mtls. The array must be nonempty and unique. The rule checks disabled records too. |
| `requireExpiryForEnabledCredentials` | Require a positive expiry on every enabled credential record, including records staged under disabled Consumers. |
| `maxCredentialLifetimeSeconds` | Require finite activation and expiry on every enabled credential. The full window must be no longer than the positive number of seconds configured here. |

### Targeted credential validity windows

`rut-consumers set-credential-window INPUT CREDENTIAL_ID NOT_BEFORE EXPIRES_AT OUTPUT`
updates the two Unix-second bounds of one existing credential without exposing or
re-entering its secret. Each bound is a canonical nonnegative decimal integer
up to `9223372036854775807`; zero means unbounded. If both are nonzero, the
activation time must precede expiry. Activation is inclusive and expiry is
exclusive. The command preserves the owner, enabled state, method, groups and
raw or hashed verifier, and works for disabled credentials too. It validates the
complete candidate and publishes a new private, no-replace snapshot through the
same offline path as the other lifecycle commands. It reads no clock and does
not change any running gateway; deployment still requires a separate adoption.
