#pragma once

#include "rut/common/ebpf_bytecode.h"
#include "rut/common/ebpf_handoff_bytecode.h"

namespace rut::ebpf {
constexpr u32 kPlanVersion = 2;
constexpr u32 kMaxRoutes = 128;
enum class Decision : u8 { UserSpace, BodyCandidate };
enum class Reason : u8 {
    None,
    NotForward,
    RequestBody,
    Regex,
    ControlFlow,
    UserComputation,
    Yield,
    Metering,
    PolicyBundle,
    DynamicForward,
    Tls,
    Http2Upstream,
    WebSocket,
};
struct RoutePlan {
    Decision decision = Decision::UserSpace;
    Reason reason = Reason::NotForward;
    u16 upstream_id = 0;
    u16 request_policy_id = 0;
    u16 response_policy_id = 0;
};
struct Plan {
    u32 version = kPlanVersion;
    u32 route_count = 0;
    u32 candidate_count = 0;
    u32 parser_instructions = 0;
    u32 verdict_instructions = 0;
    RoutePlan routes[kMaxRoutes]{};
    BodyBytecode bytecode{};
    HandoffCode handoff{};
};
inline const char* reason_name(Reason reason) {
    switch (reason) {
        case Reason::None:
            return "body-candidate";
        case Reason::NotForward:
            return "not-a-terminal-forward";
        case Reason::RequestBody:
            return "request-body-access";
        case Reason::Regex:
            return "regex-in-user-space";
        case Reason::ControlFlow:
            return "control-flow-not-proven";
        case Reason::UserComputation:
            return "user-computation-or-side-effects";
        case Reason::Yield:
            return "yield-or-buffered-forward";
        case Reason::Metering:
            return "rate-limit-or-throttle";
        case Reason::PolicyBundle:
            return "forward-policy-bundle";
        case Reason::DynamicForward:
            return "dynamic-forward-metadata";
        case Reason::Tls:
            return "tls-sockmap-incompatible";
        case Reason::Http2Upstream:
            return "http2-upstream-framing";
        case Reason::WebSocket:
            return "websocket-frame-processing";
    }
    return "invalid";
}
}  // namespace rut::ebpf
