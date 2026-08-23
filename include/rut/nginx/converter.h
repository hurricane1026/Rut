#pragma once

#include "rut/compiler/diagnostic.h"
#include "rut/nginx/parser.h"

namespace rut::nginx {

// The converter deliberately returns owned, bounded source text rather than a
// view into the nginx input. This keeps the generated program usable after the
// parsed nginx source is released and makes overflow a diagnostic rather than
// a truncated program.
struct RutSource {
    // The API model emits three bounded unmatched policies, one explicit
    // redirect policy, plus the existing forward policy bundle.  4096 bytes
    // bounds the largest currently accepted output (3324 bytes) while leaving
    // overflow fail-closed for future model growth.
    static constexpr u32 kCapacity = 4096;
    char data[kCapacity]{};
    u32 len = 0;

    [[nodiscard]] Str view() const { return {data, len}; }
};

// Lower only the parser's exact minimal semantic model to deterministic RUT
// source. The output is intentionally nginx-independent RUT policy syntax;
// unsupported/forged model values fail closed with the model's source span.
FrontendResult<RutSource> lower_to_rut(const Server& server);

}  // namespace rut::nginx
