# Keycloak access-token role policies

The [resource-server example](../examples/keycloak-role-auth.rut) composes the
existing configured RS256 verifier with [Keycloak role helpers](../examples/middleware/keycloak.rut).
It accepts Keycloak's default access-token role claim layout, described in the
[Keycloak 26.2.5 administration guide](https://www.keycloak.org/docs/26.2.5/server_admin/#_token_role_mappings):

```json
{
  "realm_access": {"roles": ["member"]},
  "resource_access": {"orders": {"roles": ["read"]}}
}
```

This is a bounded claim adapter. The tests use independently signed RS256 tokens
with this documented layout, not a live Keycloak deployment or a full provider
conformance suite. It adds no OAuth grant, OIDC browser login, refresh flow,
management API, Casdoor adapter or external role lookup. The token-use gate
follows [Keycloak 26.2.5 token generation](https://github.com/keycloak/keycloak/blob/26.2.5/services/src/main/java/org/keycloak/protocol/oidc/TokenManager.java).

## Authentication and trust

`JWT_RS256_POLICY` is the existing trusted compile/load-time JSON policy: exact
realm issuer, intended resource audience, approved key IDs and public JWKS.
The example calls `auth.jwtDocumentRs256` before any role policy. Signature,
algorithm/key binding, issuer, audience, subject, time and configured revocation
policy must succeed first. Duplicate/missing/malformed Authorization returns a
Bearer-challenged 401. Role checks cannot authenticate an arbitrary JSON document.

The example additionally calls `keycloak.requireBearerAccessToken(document)`
after RS256 validation: the signed payload `typ` must equal `Bearer` exactly.
Missing, non-string, ID-token and refresh-token types receive a challenged 401,
regardless of matching roles. This provider gate is separate from the JWS header
`typ` policy, and neither gate replaces signature/issuer/audience/time checks.
The role metadata helpers alone do not enforce token use.

Configure the resource's actual `aud` in the issuer and gateway policy. A matching
client role or `azp` does not substitute for audience validation. Each realm has
its own issuer trust. A token for another realm or audience cannot authorize a
role even when it contains identically named roles. Existing approved-kid,
remote-JWKS freshness and failure behavior remain with the RS256 policy; this
adapter introduces no fetch or positive decision cache.

`KEYCLOAK_CLIENT`, `KEYCLOAK_REALM_ROLE` and `KEYCLOAK_CLIENT_ROLE` are explicit
trusted configuration snapshots. Requests cannot select them through headers,
query parameters, body fields, `azp` or another claim. Bearer clients should use
HTTPS. The example defines authorization responses, not an application backend.

## Exact independent role namespaces

| Route | Required signed membership |
| --- | --- |
| `GET /realm` | Configured role in `realm_access.roles` |
| `GET /client` | Configured role in `resource_access[configured client].roles` |
| `GET /both` | Both of the above, in the same verified token |

A realm role does not become a client role, and another client's role cannot
satisfy the selected client. Top-level `groups`, OAuth `scope`, realm roles,
`X-Role` headers and client metadata supply no fallback. Composite/inherited
roles count only when the issuer includes them in the selected signed array;
the gateway does not traverse a role graph or infer administrator privileges.

Required roles are nonempty, at most 128 UTF-8 bytes, and compared exactly with
case sensitivity. No splitting, normalization, prefix, wildcard or coercion is
performed. Selected role arrays must be nonempty arrays of nonempty strings;
every element is validated, including suffixes after a matching role. A malformed
selected array denies. Duplicate role names do not increase privilege. Unselected
role namespaces do not affect a route's independent policy.

Realm and resource containers must be objects; a selected client entry must also
be an object. Arrays cannot masquerade as a map when a numeric client ID is
configured. This profile restricts client IDs to 1–128 ASCII bytes from
`A–Z a–z 0–9 . _ : -`. Slash, tilde and all other characters reject configuration
with 503, so dynamic JSON-pointer construction cannot select another path.
Deployments with other client-ID spellings need a separately validated escaped
lookup profile; they must not rename client IDs based on request input.

`hasRealmRole(document, role)` and `hasClientRole(document, client, role)` return
bool and deny invalid policy inputs. `requireRealmRole`, `requireClientRole` and
`requireRealmAndClientRole` return the same verified document on success, respond
503 for invalid required configuration, and respond 403 for missing/nonmatching
or malformed selected claims. The example authenticates before policy validation,
so invalid credentials still return 401. Role denial is plain 403 and does not
mislabel a Keycloak role as an OAuth scope. JSON/storage projection failures deny;
no identity or allow is published from an unchecked intermediate value.

## Snapshots and validation

Helpers use ordinary Rut JSON projection and the existing whole-array group
validator. They introduce no keywords, builtins, external libraries, service
calls or shared mutable state. The verified document and projections are
request-owned. Role changes become visible only in newly issued tokens or
explicit revocation, not through an online directory query. New trusted policy
snapshots affect newly admitted requests; in-flight requests can finish with
their original policy. There is no cross-node synchronization guarantee.

Registered native tests exercise epoll/io_uring at O0/O2, two shards, both HTTP/1
versions and HTTP/2. They delete the source/modules after native loading, verify
independent realm/client/intersection matrices, cross-client and cross-realm
isolation, audience-versus-azp separation, exact names, malformed suffixes and
containers, signature/algorithm/kid rejection, credential duplication and policy
replacement. Replacement tests load successive gateway snapshots; they do not
claim to exercise in-process RCU publication or a live IdP outage. Existing
RS256/JWKS tests own key activation, refresh, TLS and remote-service failures.
