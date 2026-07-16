#pragma once

#include "rut/common/types.h"

namespace rut::harness {

enum class ExecutionLayer : u8 {
    Compile = 0,
    Handler,
    Connection,
    EventLoop,
    Loopback,
    Process,
};

enum class Phase : u8 {
    Created = 0,
    Prepare,
    Start,
    Drive,
    Quiesce,
    Observe,
    Destroy,
    Complete,
};

enum class Outcome : u8 {
    Passed = 0,
    Mismatched,
    Failed,
    Unsupported,
    Stalled,
    Invalid,
};

enum class CleanupOutcome : u8 {
    NotRun = 0,
    Clean,
    Failed,
};

enum class Capability : u8 {
    VirtualTime = 0,
    RealTime,
    SyntheticIo,
    Epoll,
    IoUring,
    Http1,
    Http2,
    WebSocket,
    Tls,
    SingleShard,
    MultiShard,
    ScriptedUpstream,
    LoopbackUpstream,
    ExternalUpstream,
    ScriptedFaults,
    SyscallFaults,
    Count,
};

struct CapabilitySet {
    u64 bits = 0;

    static constexpr CapabilitySet one(Capability capability) {
        return CapabilitySet{u64{1} << static_cast<u8>(capability)};
    }

    constexpr bool has(Capability capability) const { return (bits & one(capability).bits) != 0; }

    constexpr bool contains(CapabilitySet required) const {
        return (bits & required.bits) == required.bits;
    }

    constexpr void add(Capability capability) { bits |= one(capability).bits; }
};

constexpr CapabilitySet operator|(Capability lhs, Capability rhs) {
    return CapabilitySet{CapabilitySet::one(lhs).bits | CapabilitySet::one(rhs).bits};
}

constexpr CapabilitySet operator|(CapabilitySet lhs, Capability rhs) {
    lhs.add(rhs);
    return lhs;
}

enum class LimitKind : u8 {
    SourceBytes = 0,
    InputBytes,
    OutputBytes,
    ArtifactBytes,
    HandlerResumes,
    BackendCompletions,
    SemanticEvents,
    VirtualDuration,
    QuiesceWork,
};

struct RunLimits {
    u64 max_source_bytes = 4u * 1024u * 1024u;
    u64 max_input_bytes = 16u * 1024u * 1024u;
    u64 max_output_bytes = 16u * 1024u * 1024u;
    u64 max_artifact_bytes = 64u * 1024u * 1024u;
    u64 max_virtual_time_us = 60u * 1000u * 1000u;
    u32 max_handler_resumes = 32;
    u32 max_backend_completions = 4096;
    u32 max_semantic_events = 4096;
    u32 max_quiesce_work = 4096;
};

enum class ObservationKind : u8 {
    PhaseChanged = 0,
    CompileFailed,
    RouteSelected,
    HandlerEntered,
    HandlerYielded,
    HandlerResumed,
    HandlerTerminated,
    WaitArmed,
    WaitCompleted,
    UpstreamSelected,
    ResponseProduced,
    ConnectionTransition,
    FaultReached,
    FaultInjected,
    LimitReached,
    InvariantViolation,
    CleanupFinished,
};

struct Observation {
    ObservationKind kind = ObservationKind::PhaseChanged;
    Phase phase = Phase::Created;
    u32 sequence = 0;
    u64 timestamp_us = 0;
    u64 value0 = 0;
    u64 value1 = 0;
    Str label{};
};

using ObserveFn = bool (*)(void* context, const Observation& event);

struct ObservationSink {
    void* context = nullptr;
    ObserveFn observe = nullptr;

    bool publish(const Observation& event) const {
        return observe == nullptr || observe(context, event);
    }
};

struct HarnessSpec {
    ExecutionLayer layer = ExecutionLayer::Compile;
    CapabilitySet required_capabilities{};
    CapabilitySet environment_capabilities{};
    RunLimits limits{};
    ObservationSink observations{};
};

struct HarnessResult {
    Outcome outcome = Outcome::Invalid;
    Phase phase = Phase::Created;
    CleanupOutcome cleanup = CleanupOutcome::NotRun;
    LimitKind reached_limit = LimitKind::SemanticEvents;
    bool has_reached_limit = false;
    CapabilitySet missing_capabilities{};
    u32 semantic_events = 0;
    u32 handler_resumes = 0;
    u32 backend_completions = 0;
    u32 fault_points_reached = 0;
    u32 faults_injected = 0;
    u32 state_resets = 0;
    u64 input_bytes = 0;
    u64 output_bytes = 0;
    u64 virtual_time_us = 0;
    char detail[256]{};
};

// Checks only the common harness contract. Target-, driver-, and
// environment-specific validation stays in their adapters.
HarnessResult validate_spec(const HarnessSpec& spec);

// Stable names are shared by human and machine reporters.
const char* layer_name(ExecutionLayer layer);
const char* phase_name(Phase phase);
const char* outcome_name(Outcome outcome);
const char* capability_name(Capability capability);
const char* limit_name(LimitKind limit);

}  // namespace rut::harness
