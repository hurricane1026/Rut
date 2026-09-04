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
    // exact-redirect measured wildcard maximum uses listen and upstream port
    // 65535 and IPv4 255.255.255.255: 5936 bytes for 301 and 5912 bytes for
    // 302. The prospective bounded exact-loopback 301 shape differs only by
    // the nine-byte listener prefix and measures 5945 bytes. The inline value
    // therefore reserves one additional byte for the mandatory trailing zero.
    // exact-local-return maximum is 5681 bytes for any 62-byte clean path, a
    // 64-byte body containing internal ASCII spaces, and the slash_normalized
    // exact-path view keyword. The fixed `/static` no-content action measures 5564
    // bytes at maximum ports/address; a maximum 62-byte no-content path measures
    // 5619 bytes with 327 bytes of capacity headroom. The bounded
    // transformed-location maximum uses a 63-byte path, 128-byte replacement
    // URI, maximum ports and IPv4 address and measures 3700 bytes. Writer
    // completion remains strict (`len < kCapacity`), so the prospective exact
    // 301 shape fixes the generic owned-source bound without admitting that
    // still-unsupported nginx semantic composition.
    static constexpr u32 kCapacity = 7028;
    char data[kCapacity]{};
    u32 len = 0;

    [[nodiscard]] Str view() const { return {data, len}; }
};

// Owned output for the bounded request-length http profile. The accessLog
// declaration contributes at most 329 bytes (19-byte prefix, 255-byte path,
// 55-byte suffix); the existing Server lowering contributes at most 5945
// payload bytes. One final byte remains zero for termination.
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
