#pragma once

#include "rut/runtime/json.h"

namespace rut {
// Configuration-owned, bounded registry snapshot. Parsing retains no input views
// outside this call. Output contains only identity and groups, never secrets.
bool consumer_registry_valid(json::Document& document, Str configuration);
bool consumer_registry_authenticate(
    json::Document& document, Str configuration, Str method, Str presented, json::Writer& output);
// Trusted native callers may provide a Unix-seconds sample. Rut and request
// authentication paths use the OS realtime clock through the wrappers below.
bool consumer_registry_authenticate_at(json::Document& document,
                                       Str configuration,
                                       Str method,
                                       Str presented,
                                       i64 realtime_seconds,
                                       json::Writer& output);
// Uses only the verified TLS client fingerprint supplied by the request runtime.
bool consumer_registry_authenticate_mtls(json::Document& document,
                                         Str configuration,
                                         Str fingerprint,
                                         json::Writer& output);
bool consumer_registry_authenticate_mtls_at(json::Document& document,
                                            Str configuration,
                                            Str fingerprint,
                                            i64 realtime_seconds,
                                            json::Writer& output);
// Explicit, single-source URL-encoded credentials. Output adds only sanitized
// remaining fields, never the credential. Query input is an origin-form target.
bool consumer_credential_name_valid(Str name);
bool consumer_registry_authenticate_fields(json::Document& document,
                                           Str configuration,
                                           Str name,
                                           Str input,
                                           bool query,
                                           json::Writer& output);
bool consumer_registry_authenticate_fields_at(json::Document& document,
                                              Str configuration,
                                              Str name,
                                              Str input,
                                              bool query,
                                              i64 realtime_seconds,
                                              json::Writer& output);
}  // namespace rut
