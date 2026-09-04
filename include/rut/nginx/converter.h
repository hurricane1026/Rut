#pragma once

#include "rut/compiler/diagnostic.h"
#include "rut/nginx/parser.h"

namespace rut::nginx {

// The converter deliberately returns owned, bounded source text rather than a
// view into the nginx input. This keeps the generated program usable after the
// parsed nginx source is released and makes overflow a diagnostic rather than
// a truncated program.
struct RutSource {
    // The root model emits three method-keyed routes plus three bounded
    // unmatched policies and one bounded exact action. Every accepted root
    // model additionally emits the implicit pre-route TRACE policy. The
    // The accepted terminal shape is the exact-loopback root proxy with maximum
    // listen/upstream values, explicit `proxy_read_timeout 63s`, and an exact
    // 301 composition. It measures 7027 payload bytes; the final NUL therefore
    // requires kCapacity == 7028. Other accepted local-return, no-content, and
    // transformed-location shapes are smaller non-terminal subshapes. Writer
    // completion remains strict (`len < kCapacity`).
    static constexpr u32 kCapacity = 7028;
    char data[kCapacity]{};
    u32 len = 0;

    [[nodiscard]] Str view() const { return {data, len}; }
};

// Owned output for the bounded request-length http profile. The accessLog
// declaration contributes at most 329 bytes (19-byte prefix, 255-byte path,
// 55-byte suffix). With the terminal Server shape this gives 7356 payload
// bytes; one final NUL therefore requires kCapacity == 7357.
struct HttpProfileRutSource {
    static constexpr u32 kMaxAccessLogDeclarationLen = 329u;
    static constexpr u32 kCapacity = 7357u;
    char data[kCapacity]{};
    u32 len = 0;

    [[nodiscard]] Str view() const { return {data, len}; }
};

static_assert(HttpProfileRutSource::kMaxAccessLogDeclarationLen == 19u + 255u + 55u);
static_assert(HttpProfileRutSource::kCapacity ==
              RutSource::kCapacity + HttpProfileRutSource::kMaxAccessLogDeclarationLen);

// Lower only the parser's exact minimal semantic model to deterministic RUT
// source. The output is intentionally nginx-independent RUT policy syntax;
// unsupported/forged model values fail closed with the model's source span.
FrontendResult<RutSource> lower_to_rut(const Server& server);

// Lower the exact bounded http profile to an ordinary RUT accessLog declaration
// followed by the unchanged Server lowering. `profile.source` must remain
// readable and byte-stable until this call returns. The returned source owns
// every emitted byte and is independent of the nginx input afterward.
FrontendResult<HttpProfileRutSource> lower_to_rut(const HttpProfile& profile);

}  // namespace rut::nginx
