#pragma once

#include "rut/common/types.h"

namespace rut {

// Compiler-derived timing for response-read-deadline preflight. This is
// deliberately generic route metadata: it describes when a forward's policy
// bundle may be armed, independent of the source configuration language.
enum class ForwardPreflightMode : u8 {
    None = 0,
    EagerDirect = 1,
    AfterCanonicalSelection = 2,
    AfterRequestFramingSelection = 3,
};

inline constexpr bool forward_preflight_mode_valid(ForwardPreflightMode mode) {
    return mode == ForwardPreflightMode::None || mode == ForwardPreflightMode::EagerDirect ||
           mode == ForwardPreflightMode::AfterCanonicalSelection ||
           mode == ForwardPreflightMode::AfterRequestFramingSelection;
}

inline constexpr bool forward_preflight_metadata_is_eager_runtime_safe(ForwardPreflightMode mode,
                                                                       u16 bundle_id) {
    return (mode == ForwardPreflightMode::None && bundle_id == 0) ||
           (mode == ForwardPreflightMode::EagerDirect && bundle_id != 0);
}

// Typed metadata admitted only at the verified RIR publication boundary.
// Native/legacy registration deliberately continues to use the eager-only
// predicate above, so it cannot opt itself into post-selection execution.
inline constexpr bool forward_preflight_metadata_is_verified_runtime_safe(ForwardPreflightMode mode,
                                                                          u16 bundle_id) {
    return forward_preflight_metadata_is_eager_runtime_safe(mode, bundle_id) ||
           ((mode == ForwardPreflightMode::AfterCanonicalSelection ||
             mode == ForwardPreflightMode::AfterRequestFramingSelection) &&
            bundle_id != 0);
}

// Once a preflight has actually been armed, all compiler-proven timings share
// the same downstream ownership invariants. The connection deadline state,
// rather than this metadata alone, distinguishes armed deferred routes.
inline constexpr bool forward_preflight_mode_can_own_runtime_deadline(ForwardPreflightMode mode) {
    return mode == ForwardPreflightMode::EagerDirect ||
           mode == ForwardPreflightMode::AfterCanonicalSelection ||
           mode == ForwardPreflightMode::AfterRequestFramingSelection;
}

}  // namespace rut
