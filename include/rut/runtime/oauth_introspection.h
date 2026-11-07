#pragma once

#include "rut/common/types.h"

namespace rut::json {
struct Document;
struct Writer;
}  // namespace rut::json

namespace rut {
// Bounded RFC 7662 access-token request. Both inputs are borrowed only during
// this call; service authorization comes from trusted configuration. No I/O.
bool oauth_introspection_request(Str token, Str service_authorization, json::Writer& output);

// Metadata validation, not signature verification. Accept only a trusted HTTPS
// introspection response: active=true, future integer exp, exact aud membership,
// optional nonfuture nbf/iat, optional valid scope list and Bearer token_type.
// No allocation or retained views. Subject mapping remains an explicit policy.
bool oauth_introspection_valid(json::Document& scratch, Str claims, Str audience, i64 unix_seconds);
}  // namespace rut
