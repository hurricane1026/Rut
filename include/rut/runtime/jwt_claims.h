#pragma once

#include "rut/common/types.h"

namespace rut::json {
struct Document;
}

namespace rut {

// Strict resource-server claims profile, separate from signature verification.
// Require nonempty sub/iss/aud and exp; aud may be a string or nonempty string
// array. Dates are signed i64 integer seconds with zero clock skew. Optional
// nbf/iat must not be in the future. Invalid input/config/clock fails closed.
// The caller owns scratch and all views; no allocation or retained references.
bool jwt_claims_valid(
    json::Document& scratch, Str claims, Str issuer, Str audience, i64 unix_seconds);

// Strict claims profile with mandatory positive iat and bounded token age and
// lifetime. This validates claims only; callers must verify the JWT signature
// separately before trusting or authorizing its contents.
bool jwt_claims_valid_with_lifetime(json::Document& scratch,
                                    Str claims,
                                    Str issuer,
                                    Str audience,
                                    i64 unix_seconds,
                                    i64 max_age_seconds,
                                    i64 max_lifetime_seconds);

// Exact OAuth scope-token membership in a verified JWT scope string. Does not
// verify signatures or claims policy. Invalid documents/tokens fail closed.
bool jwt_has_scope(json::Document& scratch, Str claims, Str required);

// RFC 8705 cnf.x5t#S256 match against a verified TLS certificate's canonical
// lowercase SHA-256 hex fingerprint. Metadata only, not JWT/peer verification.
// Exactly one confirmation method is admitted. No allocation or retained views.
bool jwt_certificate_bound(json::Document& scratch, Str claims, Str certificate_sha256);

// Validate one OAuth scope-token using the same ASCII grammar as jwt_has_scope.
bool jwt_scope_token_valid(Str token);

// Validate a nonempty OAuth scope list: scope-token *( SP scope-token ).
// Only single ASCII spaces separate tokens. Order and duplicates are preserved.
// Uses the same bounded ASCII profile as jwt_has_scope; no allocation.
bool jwt_scope_list_valid(Str scopes);

// Exact membership in a nonempty top-level JWT groups string array. Does not
// verify signatures or claims policy. Every array entry must be a nonempty
// string; malformed/invalid entries fail the whole check, even after a match.
bool jwt_has_group(json::Document& scratch, Str claims, Str required);

}  // namespace rut
