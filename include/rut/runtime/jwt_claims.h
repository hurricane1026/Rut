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

}  // namespace rut
