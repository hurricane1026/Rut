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

// Explicit RFC 6749 client-credentials scopes, at most 1024 ASCII bytes using
// the strict scope-list grammar. Only configured Basic service auth is accepted.
// Caller-owned output; no I/O, allocation or retained input views.
bool oauth_client_credentials_request(Str scopes, Str service_authorization, json::Writer& output);

// Single configured HTTPS resource identifier, at most 1024 bytes. It is never
// fetched. Invalid URI syntax/fragments or combined encoded body >4096 fail.
bool oauth_client_credentials_request(Str scopes,
                                      Str service_authorization,
                                      Str resource,
                                      json::Writer& output);

// Fixed RFC 8693 access-token -> access-token request. policy_json is exactly
// {"scope": string, "resource": string}; scratch may retain its borrowed view
// until the next parse. Existing subject/scope/resource/auth/body bounds apply.
bool oauth_token_exchange_request(json::Document& scratch,
                                  Str subject_token,
                                  Str service_authorization,
                                  Str policy_json,
                                  json::Writer& output);

// Metadata validation, not signature verification. Accept only a trusted HTTPS
// introspection response: active=true, future integer exp, exact aud membership,
// optional nonfuture nbf/iat, optional valid scope list and Bearer token_type.
// No allocation or retained views. Subject mapping remains an explicit policy.
bool oauth_introspection_valid(json::Document& scratch, Str claims, Str audience, i64 unix_seconds);
}  // namespace rut
