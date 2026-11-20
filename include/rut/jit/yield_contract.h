#pragma once

#include "rut/jit/handler_abi.h"

namespace rut::jit {

enum class YieldArm : u8 {
    None,
    Timer,
    DownstreamRecv,
    DownstreamSend,
    UpstreamConnect,
    UpstreamRecv,
    UpstreamSend,
};

struct YieldContract {
    YieldArm primary;
    YieldArm secondary;

    constexpr bool requires_target() const {
        return primary == YieldArm::UpstreamConnect || primary == YieldArm::UpstreamRecv ||
               primary == YieldArm::UpstreamSend;
    }
};

// Every ABI kind must explicitly declare the operations that can settle its wait.
// Unknown wire bytes and reserved ABI kinds are rejected.
#pragma GCC diagnostic push
#pragma GCC diagnostic error "-Wswitch-enum"
#pragma GCC diagnostic error "-Wswitch"
constexpr YieldContract yield_contract(YieldKind kind, u32 payload) {
    using enum YieldArm;
    switch (kind) {
        case YieldKind::Timer:
            return {Timer, None};
        case YieldKind::Any:
            return {DownstreamRecv, payload ? Timer : None};
        case YieldKind::Recv:
            return {DownstreamRecv, None};
        case YieldKind::Send:
            return {DownstreamSend, None};
        case YieldKind::UpstreamConnect:
            return {UpstreamConnect, None};
        case YieldKind::UpstreamRecv:
            return {UpstreamRecv, None};
        case YieldKind::UpstreamSend:
            return {UpstreamSend, None};
        case YieldKind::HttpGet:
        case YieldKind::HttpPost:
        case YieldKind::Forward:
            return {None, None};
    }
    return {None, None};
}
#pragma GCC diagnostic pop

}  // namespace rut::jit
