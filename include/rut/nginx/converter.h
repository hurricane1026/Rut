#pragma once

#include "rut/compiler/diagnostic.h"
#include "rut/nginx/parser.h"

namespace rut::nginx {

// The converter deliberately returns owned, bounded source text rather than a
// view into the nginx input. This keeps the generated program usable after the
// parsed nginx source is released and makes overflow a diagnostic rather than
// a truncated program.
struct RutSource {
    // The root model emits three method-keyed forward routes (HEAD, GET, and
    // method-omitted ANY) plus three bounded unmatched policies and one bounded
    // exact local response. The legacy root maximum remains 4899 bytes and the
    // maximum-port, 64-byte-body exact source is 5200 bytes; 5440 leaves a
    // measured margin while preserving fail-closed overflow.
    static constexpr u32 kCapacity = 5440;
    char data[kCapacity]{};
    u32 len = 0;

    [[nodiscard]] Str view() const { return {data, len}; }
};

// Lower only the parser's exact minimal semantic model to deterministic RUT
// source. The output is intentionally nginx-independent RUT policy syntax;
// unsupported/forged model values fail closed with the model's source span.
FrontendResult<RutSource> lower_to_rut(const Server& server);

}  // namespace rut::nginx
