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
// converter itself never flips one on its own. `kShippedRutCapabilities`
// below now ships `request_envoy_h1` (PR3) and `response_envoy_h1` (PR4) as
// true; only `local_reply_envoy_h1` (PR5) remains false, so
// `lower_to_rut(model)` fails closed with a `BLOCKED_BY_RUT` diagnostic only
// for a model that needs the still-missing local_reply surface.
struct RutCapabilities {
    bool request_envoy_h1 = false;      // PR3: host preserve + lowercase request headers
    bool response_envoy_h1 = false;     // PR4: upstream header order + lowercase + preserved date
    bool local_reply_envoy_h1 = false;  // PR5: lowercase local_response / failure_policy layout
};

inline constexpr RutCapabilities kShippedRutCapabilities{
    .request_envoy_h1 = true, .response_envoy_h1 = true, .local_reply_envoy_h1 = true};

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

// PR #692 round-7 review: whether `model`'s accepted bootstrap requires the
// h2c-preface disclaimer that `rut-envoy-convert` prints on stderr after a
// successful conversion (src/envoy/main.cc). `codec_type: "HTTP1"` is
// required by the parser (`Bootstrap::listener.filter_chain.hcm.codec_type`
// is always `CodecType::Http1` after a successful parse — see
// `include/rut/envoy/parser.h`), so this is always true today; it stays an
// explicit predicate rather than an unconditional print so a future codec
// type (or a listener-protocol capability, if one is ever added) has
// somewhere to change the answer, and so tests can assert the condition
// without needing the shipped `RutCapabilities` (`request_envoy_h1 = true`
// as of PR3 and `response_envoy_h1 = true` as of PR4; `local_reply_envoy_h1`
// still false) to be true.
//
// This is deliberately NOT a `RutCapabilities` gate: Rut's cleartext `listen`
// has no knob to disable h2c-preface detection at all
// (`include/rut/runtime/callbacks_impl.h`, `on_header_received`), so gating
// would fail closed on every milestone bootstrap for a per-connection client
// shape, not a configuration Rut cannot express. The divergence is recorded
// as `BLOCKED_BY_RUT` in docs/envoy-compatibility.md, "HTTP1-only HCM rejects
// a client that opens with the h2c connection preface", and closing it needs
// a listener protocol option in Rut, not a capability flag here.
bool needs_h2c_preface_warning(const Bootstrap& model);

// Text of the stderr warning described above. Exposed (rather than kept a
// literal `static` in src/envoy/main.cc, the way the sibling
// `connect_timeout` warning is) so tests can assert its exact wording.
inline constexpr const char* kH2cPrefaceWarningText =
    "warning: generated listen still accepts the h2c connection preface and serves HTTP/2 even "
    "though this bootstrap's codec_type is \"HTTP1\"; Envoy's HTTP1 codec would reject such a "
    "client before routing (see docs/envoy-compatibility.md, \"HTTP1-only HCM rejects a client "
    "that opens with the h2c connection preface\")\n";

}  // namespace rut::envoy
