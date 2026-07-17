#include "rut/harness/scripted_environment.h"

namespace rut::harness {

namespace {

bool is_upstream_kind(jit::YieldKind kind) {
    return kind == jit::YieldKind::UpstreamConnect || kind == jit::YieldKind::UpstreamRecv ||
           kind == jit::YieldKind::UpstreamSend || kind == jit::YieldKind::HttpGet ||
           kind == jit::YieldKind::HttpPost;
}

bool target_matches(u32 expected, u32 actual) {
    return expected == DeterministicCompletion::kAnyTarget || expected == actual;
}

}  // namespace

bool ScriptedEnvironment::add_completion(jit::YieldKind kind,
                                         i32 result,
                                         u64 at_us,
                                         u32 target_id) {
    if (completion_count >= kMaxCompletions) return false;
    if (completion_count != 0 && at_us < base_completions[completion_count - 1].at_us) return false;
    auto& completion = base_completions[completion_count++];
    completion = {};
    completion.kind = kind;
    completion.result = result;
    completion.at_us = at_us;
    completion.order = next_order++;
    completion.target_id = target_id;
    completion.logical_fault_point = true;
    return true;
}

bool ScriptedEnvironment::add_upstream_recv(u32 upstream_id, const u8* bytes, u32 len, u64 at_us) {
    if ((len != 0 && bytes == nullptr) || len > kMaxDataBytes - data_len) return false;
    const u32 offset = data_len;
    for (u32 i = 0; i < len; i++) data[data_len++] = bytes[i];
    if (!add_upstream(jit::YieldKind::UpstreamRecv, upstream_id, static_cast<i32>(len), at_us)) {
        data_len = offset;
        return false;
    }
    auto& completion = base_completions[completion_count - 1];
    completion.data = data + offset;
    completion.data_len = len;
    return true;
}

bool ScriptedEnvironment::add_upstream(jit::YieldKind operation,
                                       u32 upstream_id,
                                       i32 result,
                                       u64 at_us) {
    if (!is_upstream_kind(operation)) return false;
    return add_completion(operation, result, at_us, upstream_id);
}

bool ScriptedEnvironment::inject_fault(jit::YieldKind kind,
                                       u32 occurrence,
                                       i32 result,
                                       u32 target_id) {
    if (fault_count >= kMaxFaults || occurrence == 0) return false;
    faults[fault_count++] = {kind, occurrence, result, target_id};
    return true;
}

bool ScriptedEnvironment::prepare_run() {
    for (u32 i = 0; i < completion_count; i++) run_completions[i] = base_completions[i];

    for (u32 f = 0; f < fault_count; f++) {
        u32 occurrence = 0;
        for (u32 i = 0; i < completion_count; i++) {
            auto& completion = run_completions[i];
            const auto& fault = faults[f];
            if (completion.kind != fault.kind ||
                !target_matches(fault.target_id, completion.target_id))
                continue;
            occurrence++;
            if (occurrence != fault.occurrence) continue;
            completion.result = fault.result;
            if (fault.result < 0) {
                completion.data = nullptr;
                completion.data_len = 0;
            }
            completion.injected_fault = true;
            break;
        }
    }

    runtime.reset(run_completions, completion_count);
    return runtime.schedule_valid;
}

void ScriptedEnvironment::clear() {
    completion_count = 0;
    fault_count = 0;
    data_len = 0;
    next_order = 1;
    runtime.reset();
}

bool ScriptedEnvironment::has_upstream_steps() const {
    for (u32 i = 0; i < completion_count; i++) {
        if (is_upstream_kind(base_completions[i].kind)) return true;
    }
    return false;
}

}  // namespace rut::harness
