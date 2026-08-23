#pragma once

#include "rut/common/types.h"

namespace rut {

// The first explicit upstream request policy. Zero means transparent forwarding;
// the non-zero values are immutable source-level policy ids carried by the RIR
// forward terminator and interpreted by the runtime before an upstream connect.
enum class RequestPolicyId : u16 {
    None = 0,
    Http11FixedStrip = 1,
    // Reserved in the 16-bit forward-result slot for invalid direct-RIR values.
    Invalid = 0xffffu,
};

inline bool request_policy_is_supported(u16 id) {
    return id == static_cast<u16>(RequestPolicyId::Http11FixedStrip);
}

// Closed admission set for the bounded complete-content-length response
// buffering profile. Keep this separate from request_policy_is_supported():
// adding a future request policy must not silently widen this profile.
inline bool complete_content_length_request_policy_is_admitted(u16 id) {
    return id == static_cast<u16>(RequestPolicyId::None) ||
           id == static_cast<u16>(RequestPolicyId::Http11FixedStrip);
}

inline const char* request_policy_version(u16 id) {
    return id == static_cast<u16>(RequestPolicyId::Http11FixedStrip) ? "HTTP/1.1" : nullptr;
}

}  // namespace rut
