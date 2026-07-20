#pragma once

#include "rut/harness/deterministic_environment.h"

namespace rut::harness {

struct LogicalFault {
    jit::YieldKind kind = jit::YieldKind::UpstreamConnect;
    u32 occurrence = 1;
    i32 result = -1;
    u32 target_id = DeterministicCompletion::kAnyTarget;
};

// Typed, bounded builder for handler/connection-layer effects. It scripts
// logical completions rather than sockets, so failures are reproducible and do
// not depend on kernel timing. prepare_run() rebuilds all mutable run state.
struct ScriptedEnvironment {
    static constexpr u32 kMaxCompletions = 256;
    static constexpr u32 kMaxFaults = 32;
    static constexpr u32 kMaxDataBytes = 64u * 1024u;

    DeterministicCompletion base_completions[kMaxCompletions]{};
    DeterministicCompletion run_completions[kMaxCompletions]{};
    LogicalFault faults[kMaxFaults]{};
    u8 data[kMaxDataBytes]{};
    u32 completion_count = 0;
    u32 fault_count = 0;
    u32 data_len = 0;
    u32 next_order = 1;
    DeterministicEnvironment runtime{};

    bool add_completion(jit::YieldKind kind,
                        i32 result,
                        u64 at_us,
                        u32 target_id = DeterministicCompletion::kAnyTarget);

    bool add_upstream(jit::YieldKind operation, u32 upstream_id, i32 result, u64 at_us);

    bool add_upstream_recv(u32 upstream_id, const u8* bytes, u32 len, u64 at_us);

    bool inject_fault(jit::YieldKind kind,
                      u32 occurrence,
                      i32 result,
                      u32 target_id = DeterministicCompletion::kAnyTarget);

    bool prepare_run();
    void clear();

    bool has_upstream_steps() const;
    bool has_faults() const { return fault_count != 0; }
};

}  // namespace rut::harness
