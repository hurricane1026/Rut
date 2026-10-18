#pragma once

#include "rut/common/ebpf_plan.h"
#include "rut/common/request_policy.h"
#include "rut/runtime/route_table.h"

#include <string.h>

namespace rut {
inline bool validate_ebpf_plan(const ebpf::Plan& plan, const RouteConfig& config) {
    if (plan.version != ebpf::kPlanVersion || plan.route_count != config.route_count ||
        plan.route_count > ebpf::kMaxRoutes)
        return false;
    u32 candidates = 0;
    for (u32 i = 0; i < plan.route_count; ++i) {
        const auto& route = plan.routes[i];
        if (route.decision == ebpf::Decision::BodyCandidate) {
            const auto& entry = config.routes[i];
            if (route.reason != ebpf::Reason::None || route.upstream_id >= config.upstream_count ||
                config.upstreams[route.upstream_id].http2 ||
                entry.action != RouteAction::JitHandler || entry.needs_req_body ||
                entry.rate_limit.count || entry.throttle_down_bps || entry.ws_terminate ||
                (route.request_policy_id != 0 &&
                 !request_policy_is_supported(route.request_policy_id)) ||
                (route.response_policy_id != 0 &&
                 !config.response_policy_id_is_valid(route.response_policy_id)))
                return false;
            ++candidates;
        } else if (route.decision != ebpf::Decision::UserSpace ||
                   route.reason == ebpf::Reason::None || route.reason > ebpf::Reason::WebSocket)
            return false;
    }
    if (candidates != plan.candidate_count) return false;
    ebpf::BodyBytecode expected{};
    ebpf::HandoffCode handoff{};
    if (candidates) {
        if (plan.parser_instructions != ebpf::kParserInstructions ||
            plan.verdict_instructions != ebpf::kVerdictInstructions)
            return false;
        ebpf::emit_body_bytecode(expected);
        ebpf::emit_packet_handoff_bytecode(handoff);
    } else if (plan.parser_instructions || plan.verdict_instructions)
        return false;
    // Includes relocation placeholders: live FDs/ports must never enter an artifact.
    return memcmp(&plan.bytecode, &expected, sizeof(expected)) == 0 &&
           memcmp(&plan.handoff, &handoff, sizeof(handoff)) == 0;
}
}  // namespace rut
