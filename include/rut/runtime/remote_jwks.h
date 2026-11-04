#pragma once

#include "rut/runtime/https_fetch.h"
#include "rut/runtime/json.h"

namespace rut {
// Trusted, fixed-endpoint refresh controls shared by asymmetric JWT policies.
// Parsing occurs before configuration publication, never from token metadata.
struct RemoteJwks {
    HttpsEndpoint endpoint{};
    u32 refresh_seconds = 0;
    u32 max_age_seconds = 0;
    u32 timeout_seconds = 0;
    bool enabled() const { return refresh_seconds != 0; }
    bool load(json::Document& document, u32 node);
};
}  // namespace rut
