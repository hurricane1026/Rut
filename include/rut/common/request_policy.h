#pragma once

#include "rut/common/types.h"

namespace rut {

// The first explicit upstream request policy. Zero means transparent forwarding;
// the non-zero values are immutable source-level policy ids carried by the RIR
// forward terminator and interpreted by the runtime before an upstream connect.
enum class RequestPolicyId : u8 {
    None = 0,
    Http11FixedStrip = 1,
};

inline bool request_policy_is_supported(u8 id) {
    return id == static_cast<u8>(RequestPolicyId::Http11FixedStrip);
}

inline const char* request_policy_version(u8 id) {
    return id == static_cast<u8>(RequestPolicyId::Http11FixedStrip) ? "HTTP/1.1" : nullptr;
}

}  // namespace rut
