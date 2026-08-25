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
};

inline constexpr bool forward_preflight_mode_valid(ForwardPreflightMode mode) {
    return mode == ForwardPreflightMode::None || mode == ForwardPreflightMode::EagerDirect ||
           mode == ForwardPreflightMode::AfterCanonicalSelection;
}

// Phase-1 publication/runtime contract. Deferred selection is represented so
// every layer can reject forged metadata now; a later atomic capability change
// will extend this predicate only alongside its verifier and runtime behavior.
inline constexpr bool forward_preflight_metadata_is_eager_runtime_safe(ForwardPreflightMode mode,
                                                                       u16 bundle_id) {
    return (mode == ForwardPreflightMode::None && bundle_id == 0) ||
           (mode == ForwardPreflightMode::EagerDirect && bundle_id != 0);
}

}  // namespace rut
