# Casdoor DefaultJWT access-token policy

The [runnable resource example](../examples/casdoor-access-auth.rut) composes
Rut's configured RS256 verifier with
[`middleware/casdoor.rut`](../examples/middleware/casdoor.rut). It selectively
imports `auth.jwtDocumentRs256` as `verifyRs256`; importing all of `auth` would
also bring its same-named `requireGroup` helpers into the import set. This
adapter is
pinned to Casdoor v4.27.1 commit
[`2213c440aa2ce100f4d47efc1c0be3d7d47417fe`](https://github.com/casdoor/casdoor/tree/2213c440aa2ce100f4d47efc1c0be3d7d47417fe).
In that revision, [DefaultJWT claims embed `User`](https://github.com/casdoor/casdoor/blob/2213c440aa2ce100f4d47efc1c0be3d7d47417fe/object/token_jwt.go),
whose JSON fields include `owner` and `groups` in
[`user.go`](https://github.com/casdoor/casdoor/blob/2213c440aa2ce100f4d47efc1c0be3d7d47417fe/object/user.go).
The default token builder emits `tokenType: "access-token"` and the refresh
builder changes it to `"refresh-token"` in that same pinned token source.

This adapter supports only Casdoor's `TokenFormat: "JWT"` source profile with
its default/ID group format, which emits fully qualified `owner/group` names.
It does not inspect a signed `TokenFormat` claim; that application setting is
not represented as a token claim. The separately configured `Name` and `Path`
group formats are outside this contract. The pinned
[`JWT-Standard` shape uses `UserStandard`](https://github.com/casdoor/casdoor/blob/2213c440aa2ce100f4d47efc1c0be3d7d47417fe/object/token_standard_jwt.go),
which does not include `groups`; this contract does not claim JWT-Standard
group support. It also does not implement login, refresh, provider APIs, account
status lookup or live revocation. It is a bounded claim adapter, not a live
Casdoor conformance suite.

## Authentication and token use

The example first calls `auth.jwtDocumentRs256` with trusted
`JWT_RS256_POLICY`. The existing verifier owns signature, RS256/key binding,
issuer, audience, subject, time and configured revocation checks. Duplicate or
malformed Authorization, bad signatures, wrong issuer/audience and invalid time
claims fail with a Bearer-challenged 401 before the Casdoor policy helpers run.
The helpers accept a verified document; they do not authenticate arbitrary
JSON. Configure the expected issuer, resource audience and approved keys in the
trusted verifier policy.

`casdoor.requireAccessToken(document, org)` additionally requires the signed
payload's `tokenType` to equal `access-token` and `owner` to equal the trusted,
exact organization selector. Missing, non-string, differently cased, ID-token,
refresh-token or other token types and wrong/missing owners receive a challenged
401. Each policy helper validates all of its trusted selectors before checking
the provider token type/owner and responds 503 for invalid selectors after the
route's cryptographic verification. Thus an invalid JWT still fails 401 in
`auth.jwtDocumentRs256`; a validly signed ID token with invalid group config
fails 503.
Caller-supplied headers and query parameters never choose the organization or
token type.

## Qualified groups

The pinned default-token builder calls `GetGroupsForToken`; for the supported
default/ID group format it emits the fully qualified spelling
`<owner>/<group>`. Policy passes
the org and an unqualified group component separately, and compares the exact
qualified string `org/group` against the signed top-level `groups` array.
Matching is case-sensitive; there is no prefix, splitting, coercion, roles,
scope, header or query fallback.

Organization and group selectors must each be 1–128 ASCII bytes matching
`[A-Za-z0-9._:-]+`. Slash and all other characters are rejected so a selector
cannot change the qualified-group boundary. Invalid selectors receive 503.
After a valid access-token/owner check, a missing group, missing or empty
`groups`, non-array groups or any non-string/empty array element receives 403.
The existing `jwtHasGroup` validator checks the complete array, including
elements after a match. Repeated well-formed group strings are harmless.

`requireGroup(document, org, group)` requires one exact membership.
`requireAllGroups(document, org, first, second)` requires both memberships from
the same verified token; it validates both predicates and does not merge group
names from another source. Both return the unchanged verified document on
success. Their 403 is authorization denial, while authentication remains the
verifier's 401.

`requireAnyGroup(document, org, first, second)` accepts either configured
membership after checking the access-token type and owner. The example exposes
it at `/any`.

`requireGroupWithout(document, org, allowed, forbidden)` requires a positive
membership and rejects the configured forbidden group even when the allowed
group is present. Both comparisons use the same signed array and exact
organization-qualified names. The example exposes it at `/restricted` and
takes the forbidden selector from `CASDOOR_FORBIDDEN_GROUP`. Configuring the
same allowed and forbidden group returns 503.

The native integration tests sign independent RS256 fixtures from the public
RFC 7515 test key, then load the example through `rut` and remove its source and
middleware files before requests. They exercise both backends at O0/O2 and
HTTP/1.0, HTTP/1.1 and HTTP/2. These tests verify the documented claims adapter;
they do not contact a Casdoor server or establish provider conformance.

`requirePrincipal(document, org, subject)` additionally pins the signed stable
`sub` exactly within the configured owner and requires the DefaultJWT access
token type. It returns the unchanged verified document. The trusted subject
must be nonempty and at most 128 UTF-8 bytes; invalid owner or subject
configuration returns 503. Missing, non-string or mismatching subjects, owners
or token types return a Bearer-challenged 401. Call it after the configured
signature, issuer, audience and time verifier. Names and request metadata do not
substitute for the signed subject. The native fixture exercises this policy using trusted `CASDOOR_SUBJECT` configuration.

`requireGroupUnionWithout(document, org, first, second, forbidden)` accepts
either exact owner-qualified allowed group and vetoes the forbidden group. All
three group selectors must be valid and distinct. The selected signed group
array must be fully valid; malformed arrays deny. Invalid configuration returns
503, failed access-token or owner checks return challenged 401, and a failed
group policy returns 403. The verified document is returned unchanged.

`requireAllGroupsWithout(document, org, first, second, forbidden)` requires both
exact qualified groups and rejects the forbidden group in the same complete,
valid groups claim. All selectors must be valid and the three group names must
be distinct, or the policy returns 503. Invalid access-token claims return 401;
missing, malformed or nonmatching groups return 403.

## Pinned provider integration

The Docker integration fixture starts the official Casdoor v4.27.1 image pinned
by digest, seeds an isolated SQLite database and obtains a DefaultJWT access
token through its password grant. It checks the provider's issuer, audience,
organization, groups and access-token type, configures the verifier from the
provider's JWKS, and exercises HTTP/1.1 and HTTP/2 on both backends. It also
checks provider-issued ID and refresh tokens, invalid signatures, wrong
audience or organization, and denied group policies. The refresh token has no
`kid` in this provider version, so the configured verifier rejects it before
the token-type policy. The fixture uses local test credentials and certificates;
it is not a full provider conformance or production deployment test.
