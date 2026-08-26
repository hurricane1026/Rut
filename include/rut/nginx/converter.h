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
    // exact-redirect measured maximum uses listen and upstream port 65535 and
    // IPv4 255.255.255.255: 5936 bytes for 301 and 5912 bytes for 302. The
    // exact-local-return maximum is 5681 bytes for a 62-byte trailing-slash
    // path, a 64-byte body containing one internal ASCII space, and the
    // slash_normalized exact-path view keyword. The equivalent raw exact shape
    // remains 5664 bytes. The bounded
    // transformed-location maximum uses a 63-byte path, 128-byte replacement
    // URI, maximum ports and IPv4 address and measures 3700 bytes. Writer
    // completion remains strict
    // (`len < kCapacity`), so the largest 301 shape fixes the bound.
    static constexpr u32 kCapacity = 5937;
    char data[kCapacity]{};
    u32 len = 0;

    [[nodiscard]] Str view() const { return {data, len}; }
};

// Lower only the parser's exact minimal semantic model to deterministic RUT
// source. The output is intentionally nginx-independent RUT policy syntax;
// unsupported/forged model values fail closed with the model's source span.
FrontendResult<RutSource> lower_to_rut(const Server& server);

}  // namespace rut::nginx
