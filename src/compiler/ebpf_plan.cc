#include "rut/compiler/ebpf_plan.h"

#include "rut/common/ebpf_bytecode.h"
#include "rut/common/ebpf_handoff_bytecode.h"
#include "rut/common/ebpf_plan.h"
#include "rut/common/types.h"
#include "rut/compiler/rir.h"
#include "rut/compiler/verifier.h"
#include "rut/runtime/ebpf_plan.h"
#include "rut/runtime/route_table.h"

#include <string.h>

namespace rut {
namespace {
bool constant(const rir::Function& fn, rir::ValueId value, i32& out) {
    for (u32 b = 0; b < fn.block_count; ++b) {
        for (u32 i = 0; i < fn.blocks[b].inst_count; ++i) {
            const auto& instruction = fn.blocks[b].insts[i];
            if (instruction.result == value && instruction.op == rir::Opcode::ConstI32) {
                out = instruction.imm.i32_val;
                return true;
            }
        }
    }
    return false;
}
ebpf::RoutePlan classify(const rir::Function& fn, const rir::Module& module, bool tls) {
    using ebpf::Reason;
    ebpf::RoutePlan plan;
    auto reject = [&](Reason reason) {
        plan.reason = reason;
        return plan;
    };
    if (tls) return reject(Reason::Tls);
    if (fn.rate_limit.count || fn.throttle_down_bps) return reject(Reason::Metering);
    for (u32 b = 0; b < fn.block_count; ++b) {
        for (u32 i = 0; i < fn.blocks[b].inst_count; ++i) {
            const auto kOp = fn.blocks[b].insts[i].op;
            if (kOp == rir::Opcode::ReqBody) return reject(Reason::RequestBody);
            if (kOp == rir::Opcode::StrRegexMatch) return reject(Reason::Regex);
        }
    }
    if (fn.yield_count) return reject(Reason::Yield);
    if (fn.block_count != 1) return reject(Reason::ControlFlow);
    const auto& block = fn.blocks[0];
    const auto* end = block.terminator();
    if (!end) return reject(Reason::NotForward);
    if (end->op == rir::Opcode::RetForwardBundle) return reject(Reason::PolicyBundle);
    if (end->op != rir::Opcode::RetForward) return reject(Reason::NotForward);
    // Conservatively reject even pure computations until their whole-path
    // semantics have a dedicated proof. Inlined middleware appears here too.
    for (u32 i = 0; i + 1 < block.inst_count; ++i)
        if (block.insts[i].op != rir::Opcode::ConstI32) return reject(Reason::UserComputation);
    if (end->operand_count == 0 || end->operand_count > 3) return reject(Reason::DynamicForward);
    i32 upstream = -1, request = 0, response = 0;
    if (!constant(fn, end->operand(0), upstream) || upstream < 0 ||
        static_cast<u32>(upstream) >= module.upstream_count ||
        !module.upstreams[upstream].has_address ||
        (end->operand_count > 1 && !constant(fn, end->operand(1), request)) ||
        (end->operand_count > 2 && !constant(fn, end->operand(2), response)) || request < 0 ||
        request > 0xffff || response < 0 || response > 0xffff)
        return reject(Reason::DynamicForward);
    if (module.upstreams[upstream].http2) return reject(Reason::Http2Upstream);
    plan.decision = ebpf::Decision::BodyCandidate;
    plan.reason = Reason::None;
    plan.upstream_id = static_cast<u16>(upstream);
    plan.request_policy_id = static_cast<u16>(request);
    plan.response_policy_id = static_cast<u16>(response);
    return plan;
}
}  // namespace
bool build_ebpf_plan(const rir::Module& module,
                     const RouteConfig& config,
                     bool tls,
                     ebpf::Plan& out) {
    out = {};
    if (config.route_count > ebpf::kMaxRoutes || !rir::verify_module(module).ok) return false;
    ebpf::Plan staged{};
    staged.route_count = config.route_count;
    u32 route = 0;
    for (u32 i = 0; i < module.func_count; ++i) {
        const auto& fn = module.functions[i];
        if (fn.is_timer) continue;
        if (route >= config.route_count) return false;
        const auto& entry = config.routes[route];
        if (entry.action != RouteAction::JitHandler || entry.method != fn.http_method ||
            entry.path_len != fn.route_pattern.len ||
            memcmp(entry.path, fn.route_pattern.ptr, entry.path_len) != 0)
            return false;
        staged.routes[route] = classify(fn, module, tls);
        if (staged.routes[route].decision == ebpf::Decision::BodyCandidate)
            ++staged.candidate_count;
        ++route;
    }
    // Terminate-mode WebSocket routes are appended separately by the loader.
    for (; route < config.route_count; ++route) {
        if (!config.routes[route].ws_terminate) return false;
        staged.routes[route].reason = ebpf::Reason::WebSocket;
    }
    if (staged.candidate_count) {
        staged.parser_instructions = ebpf::kParserInstructions;
        staged.verdict_instructions = ebpf::kVerdictInstructions;
        ebpf::emit_body_bytecode(staged.bytecode);
        ebpf::emit_packet_handoff_bytecode(staged.handoff);
    }
    if (!validate_ebpf_plan(staged, config)) return false;
    out = staged;
    return true;
}
}  // namespace rut
