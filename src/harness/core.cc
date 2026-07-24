#include "rut/harness/core.h"

namespace rut::harness {
namespace {

void copy_detail(char* dst, u32 cap, const char* src) {
    if (cap == 0) return;
    u32 i = 0;
    while (src[i] != '\0' && i + 1 < cap) {
        dst[i] = src[i];
        i++;
    }
    dst[i] = '\0';
}

bool limits_are_valid(const RunLimits& limits) {
    return limits.max_source_bytes != 0 && limits.max_input_bytes != 0 &&
           limits.max_output_bytes != 0 && limits.max_artifact_bytes != 0 &&
           limits.max_virtual_time_us != 0 && limits.max_handler_resumes != 0 &&
           limits.max_backend_completions != 0 && limits.max_semantic_events != 0 &&
           limits.max_quiesce_work != 0;
}

}  // namespace

HarnessResult validate_spec(const HarnessSpec& spec) {
    HarnessResult result{};
    result.phase = Phase::Prepare;

    const u64 kKnownBits = static_cast<u8>(Capability::Count) == 64
                               ? ~u64{0}
                               : (u64{1} << static_cast<u8>(Capability::Count)) - 1;
    if ((spec.required_capabilities.bits & ~kKnownBits) != 0 ||
        (spec.environment_capabilities.bits & ~kKnownBits) != 0) {
        copy_detail(result.detail, sizeof(result.detail), "unknown capability bit");
        return result;
    }
    if (!limits_are_valid(spec.limits)) {
        copy_detail(result.detail, sizeof(result.detail), "run limits must be non-zero");
        return result;
    }

    result.missing_capabilities.bits =
        spec.required_capabilities.bits & ~spec.environment_capabilities.bits;
    if (result.missing_capabilities.bits != 0) {
        result.outcome = Outcome::Unsupported;
        copy_detail(result.detail, sizeof(result.detail), "environment capability missing");
        return result;
    }

    result.outcome = Outcome::Passed;
    result.phase = Phase::Complete;
    result.cleanup = CleanupOutcome::Clean;
    return result;
}

const char* layer_name(ExecutionLayer layer) {
    switch (layer) {
        case ExecutionLayer::Compile:
            return "compile";
        case ExecutionLayer::Handler:
            return "handler";
        case ExecutionLayer::Connection:
            return "connection";
        case ExecutionLayer::EventLoop:
            return "event-loop";
        case ExecutionLayer::Loopback:
            return "loopback";
        case ExecutionLayer::Process:
            return "process";
    }
    return "unknown";
}

const char* phase_name(Phase phase) {
    switch (phase) {
        case Phase::Created:
            return "created";
        case Phase::Prepare:
            return "prepare";
        case Phase::Start:
            return "start";
        case Phase::Drive:
            return "drive";
        case Phase::Quiesce:
            return "quiesce";
        case Phase::Observe:
            return "observe";
        case Phase::Destroy:
            return "destroy";
        case Phase::Complete:
            return "complete";
    }
    return "unknown";
}

const char* outcome_name(Outcome outcome) {
    switch (outcome) {
        case Outcome::Passed:
            return "passed";
        case Outcome::Mismatched:
            return "mismatched";
        case Outcome::Failed:
            return "failed";
        case Outcome::Unsupported:
            return "unsupported";
        case Outcome::Stalled:
            return "stalled";
        case Outcome::Invalid:
            return "invalid";
    }
    return "unknown";
}

const char* capability_name(Capability capability) {
    static const char* const kNames[] = {
        "virtual-time",
        "real-time",
        "synthetic-io",
        "epoll",
        "io-uring",
        "http1",
        "http2",
        "websocket",
        "tls",
        "single-shard",
        "multi-shard",
        "scripted-upstream",
        "loopback-upstream",
        "external-upstream",
        "scripted-faults",
        "syscall-faults",
        "control-plane-snapshot",
        "control-plane-mutation",
    };
    const u8 kIndex = static_cast<u8>(capability);
    if (kIndex >= static_cast<u8>(Capability::Count)) return "unknown";
    return kNames[kIndex];
}

const char* limit_name(LimitKind limit) {
    switch (limit) {
        case LimitKind::SourceBytes:
            return "source-bytes";
        case LimitKind::InputBytes:
            return "input-bytes";
        case LimitKind::OutputBytes:
            return "output-bytes";
        case LimitKind::ArtifactBytes:
            return "artifact-bytes";
        case LimitKind::HandlerResumes:
            return "handler-resumes";
        case LimitKind::BackendCompletions:
            return "backend-completions";
        case LimitKind::SemanticEvents:
            return "semantic-events";
        case LimitKind::VirtualDuration:
            return "virtual-duration";
        case LimitKind::QuiesceWork:
            return "quiesce-work";
    }
    return "unknown";
}

}  // namespace rut::harness
