#pragma once

#include "rut/compiler/diagnostic.h"
#include "rut/envoy/parser.h"

namespace rut::envoy {

// The converter deliberately returns owned, bounded source text rather than a
// view into the Envoy bootstrap input. This keeps the generated program usable
// after the parsed bootstrap is released and makes overflow a diagnostic
// rather than a truncated program (mirrors rut::nginx::RutSource).
struct RutSource {
    // Strict completion rule: `len < kCapacity`, NUL-terminated, overflow is a
    // diagnostic rather than a truncated program.
    static constexpr u32 kCapacity = 16384;
    char data[kCapacity]{};
    u32 len = 0;

    [[nodiscard]] Str view() const { return {data, len}; }
};

// One flag per RUT surface the lowering needs beyond today's grammar. Each
// flag is flipped only by the PR that lands the corresponding runtime
// capability (docs/envoy-converter.md, "Known capability dependencies"); the
// converter itself never flips one on its own. The shipped table is
// deliberately all-false, so `lower_to_rut(model)` fails closed with a
// `BLOCKED_BY_RUT` diagnostic until those PRs land.
struct RutCapabilities {
    bool request_envoy_h1 = false;      // PR3: host preserve + lowercase request headers
    bool response_envoy_h1 = false;     // PR4: upstream header order + lowercase + preserved date
    bool local_reply_envoy_h1 = false;  // PR5: lowercase local_response / failure_policy layout
};

inline constexpr RutCapabilities kShippedRutCapabilities{};

// Lower the milestone Envoy semantic model to deterministic RUT source using
// the capabilities this binary actually ships. Fails closed with a
// source-located `BLOCKED_BY_RUT` diagnostic whenever the model needs a RUT
// surface `capabilities` does not have.
FrontendResult<RutSource> lower_to_rut(const Bootstrap& model);

// Same lowering with an explicit capability set. Used by tests to pin the
// target RUT text (all capabilities true) ahead of the runtime PRs that make
// it real; production code must not construct a non-default
// `RutCapabilities`.
FrontendResult<RutSource> lower_to_rut(const Bootstrap& model, const RutCapabilities& capabilities);

}  // namespace rut::envoy
