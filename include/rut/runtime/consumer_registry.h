#pragma once

#include "rut/runtime/json.h"

namespace rut {
// Configuration-owned, bounded registry snapshot. Parsing retains no input views
// outside this call. Output contains only identity and groups, never secrets.
bool consumer_registry_valid(json::Document& document, Str configuration);
bool consumer_registry_authenticate(
    json::Document& document, Str configuration, Str method, Str presented, json::Writer& output);
}  // namespace rut
