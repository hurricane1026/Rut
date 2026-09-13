#pragma once

#include "rut/common/types.h"

namespace rut {

// Common disposition metadata for forward response and connect-failure
// policies.  The aliases below keep the policy-specific names readable while
// ensuring both tables use the same wire-stable numeric values.
enum class ForwardPolicyHeadMode : u8 {
    Invalid = 0,
    Reject = 1,
    SuppressBody = 2,
};

using ResponsePolicyHeadMode = ForwardPolicyHeadMode;
using FailurePolicyHeadMode = ForwardPolicyHeadMode;

}  // namespace rut
