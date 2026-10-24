#pragma once

#include "rut/common/types.h"

namespace rut {
// None is internal absence for non-forward operations and native compatibility.
// The language never supplies a default.
enum class LoadBalancePolicy : u8 { None, RoundRobin, LeastRequests, Invalid = 255 };
inline constexpr u32 kMaxForwardSites = 512;
inline bool load_balance_policy_valid(LoadBalancePolicy policy) {
    return policy == LoadBalancePolicy::None || policy == LoadBalancePolicy::RoundRobin ||
           policy == LoadBalancePolicy::LeastRequests;
}
struct ForwardLoadBalance {
    u16 site;  // 1-based compiled operation identity; zero for native compatibility
    LoadBalancePolicy policy;
};
inline bool forward_load_balance_valid(ForwardLoadBalance spec) {
    return spec.policy == LoadBalancePolicy::None
               ? spec.site == 0
               : (load_balance_policy_valid(spec.policy) && spec.site != 0 &&
                  spec.site <= kMaxForwardSites);
}
// Disjoint shard-owned sidecars. Configuration RCU pins cover both metadata and
// these gauges; old requests never decrement counters in a replacement config.
struct alignas(64) BackendSelectionState {
    u32 active[64][8]{};
    u16 cursor[kMaxForwardSites]{};
};
}  // namespace rut
