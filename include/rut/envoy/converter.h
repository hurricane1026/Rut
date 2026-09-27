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
    //
    // Sized for the increment-4 ordered route-list lowering (envoy-pr-plan.md,
    // PR 8 "Capacity"). Codex sweep-1 review: the original estimate assumed
    // each of the `kMaxEnvoyRoutes` routes contributes at most one HEAD and
    // one non-HEAD forward() block (16 total), but `build_node_plan`
    // (src/envoy/converter.cc) duplicates a forwarding action once per NODE
    // that reaches it, not once per declared route -- every non-root node's
    // arm chain is exactly its own conditional `own-prefix` arm plus one
    // unconditional `nearest-declared-ancestor` terminal arm (the "Remainder"
    // algorithm doc comment above `build_node_plan`), and root's chain is
    // always exactly its own single terminal arm. The true worst case is
    // `kMaxEnvoyRoutes` prefix routes declared narrowest-to-broadest (no two
    // shadow each other, so all `kMaxEnvoyRoutes` register as nodes): the
    // `kMaxEnvoyRoutes - 1` non-root nodes each contribute 2 arms (2 forward()
    // blocks + 1 if/else wrapper) and the root node contributes 1 arm (1
    // forward() block, no wrapper) --
    //   total arms   = 2 * (kMaxEnvoyRoutes - 1) + 1 = 2 * kMaxEnvoyRoutes - 1
    //   total wraps  = kMaxEnvoyRoutes - 1
    // -- each duplicated across both the HEAD and non-HEAD method variants
    // (`put_route_node`). Using exact `path` routes instead of prefix routes
    // to pack more arms into one node is never better: an exact route buys
    // exactly 1 arm per route-list slot, versus 2 for a non-root prefix
    // route, so spreading routes across the maximum number of distinct nodes
    // (all prefixes) always dominates (verified: `capacity_covers_worst_case
    // _node_arm_duplication`, tests/test_envoy_convert.cc, builds this exact
    // 8-node nested-prefix shape and checks the emitted size against both
    // `kCapacity` and this assertion's bound). `route exact "N"` 404
    // fallbacks are NOT counted: `put_route_exact_404` is never called
    // (`build_node_plan` fails closed with `BLOCKED_BY_RUT` instead whenever
    // that shape would be needed), so that term is dropped rather than kept
    // as dead margin. Byte estimates (~1500 bytes per forward() block, see
    // the golden in tests/fixtures/envoy_milestone_s.inc; ~100 bytes per
    // if/else wrapper) plus fixed listen/upstream/unmatched overhead:
    //   2 * (2 * 8 - 1) * 1500 + 2 * (8 - 1) * 100 + 2048 = 48448 bytes,
    // comfortably under the 256 KiB ceiling the plan sets as the point where
    // `kMaxEnvoyRoutes` itself would need to shrink. kCapacity is set with
    // generous headroom above that bound for later increments (PR 9/10 add
    // `direct_response`/`redirect` bodies).
    static constexpr u32 kCapacity = 131072;  // 128 KiB
    // Named so tests/test_envoy_convert.cc's
    // `capacity_covers_worst_case_node_arm_duplication` can check the emitted
    // size of the actual worst-case model against the same bound the
    // static_assert below enforces, rather than duplicating the arithmetic.
    static constexpr u32 kWorstCaseOrderedRouteListBytes =
        2u * (2u * kMaxEnvoyRoutes - 1u) * 1500u + 2u * (kMaxEnvoyRoutes - 1u) * 100u + 2048u;
    static_assert(kCapacity >= kWorstCaseOrderedRouteListBytes,
                  "RutSource::kCapacity must cover the true per-node arm-duplication worst case "
                  "of the ordered route-list lowering");
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

// Test-only: the same validation and emission as `lower_to_rut` above, but
// without its final lexer token-budget gate (`LexedTokens::kMaxTokens`,
// src/envoy/converter.cc). `RutSource::kCapacity` and the token budget are
// two independent, separately-tested bounds (docs/envoy-converter.md,
// "Emitted program size is separately capped..."); a model built purely to
// stress the byte-capacity worst case (many declared routes, each
// contributing its own duplicated forwarding action -- see
// `RutSource::kWorstCaseOrderedRouteListBytes`) also trips the unrelated
// token budget long before `RutSource::kCapacity`, so `lower_to_rut` itself
// can never return a successful `RutSource` for it to measure. This lets
// `tests/test_envoy_convert.cc`'s `capacity_covers_worst_case_node_arm_
// duplication` measure the real emitted byte count against `kCapacity`
// directly. Production code must never call this: it is missing a check
// `lower_to_rut` treats as load-bearing.
FrontendResult<RutSource> lower_to_rut_ignoring_token_budget_for_test(
    const Bootstrap& model, const RutCapabilities& capabilities);

// PR #692 round-7 review: whether `model`'s accepted bootstrap requires the
// h2c-preface disclaimer that `rut-envoy-convert` prints on stderr after a
// successful conversion (src/envoy/main.cc). `codec_type: "HTTP1"` is
// required by the parser (`Bootstrap::listener.filter_chain.hcm.codec_type`
// is always `CodecType::Http1` after a successful parse — see
// `include/rut/envoy/parser.h`), so this is always true today; it stays an
// explicit predicate rather than an unconditional print so a future codec
// type (or a listener-protocol capability, if one is ever added) has
// somewhere to change the answer, and so tests can assert the condition
// without needing the shipped, still-all-false `RutCapabilities` to be true.
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
