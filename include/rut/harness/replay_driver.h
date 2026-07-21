#pragma once

#include "rut/harness/core.h"
#include "rut/runtime/traffic_replay.h"

namespace rut::harness {

struct ReplayItemResult {
    HarnessResult harness{};
    ReplayResult replay{};
};

struct ReplayDriverResult {
    HarnessResult harness{};
    ReplaySummary replay{};
};

namespace detail {

inline void set_detail(HarnessResult& result, const char* detail) {
    u32 i = 0;
    while (detail[i] != '\0' && i + 1 < sizeof(result.detail)) {
        result.detail[i] = detail[i];
        i++;
    }
    result.detail[i] = '\0';
}

inline bool publish_replay_result(const HarnessSpec& spec,
                                  HarnessResult& result,
                                  u32 sequence,
                                  const ReplayResult& replay) {
    if (result.semantic_events >= spec.limits.max_semantic_events) {
        result.outcome = Outcome::Failed;
        result.has_reached_limit = true;
        result.reached_limit = LimitKind::SemanticEvents;
        set_detail(result, "semantic-events limit reached");
        return false;
    }

    Observation event{};
    event.kind = ObservationKind::ResponseProduced;
    event.phase = Phase::Observe;
    event.sequence = sequence;
    event.value0 = replay.expected_status;
    event.value1 = replay.actual_status;
    event.label = replay.replayed ? Str{"replayed", 8}
                                  : (replay.skipped ? Str{"unsupported", 11} : Str{"failed", 6});
    result.semantic_events++;
    if (!spec.observations.publish(event)) {
        if (result.outcome == Outcome::Passed) {
            result.outcome = Outcome::Mismatched;
            set_detail(result, "observation rejected by oracle");
        }
        return false;
    }

    if (!replay.response_body_observed) return true;
    if (result.semantic_events >= spec.limits.max_semantic_events) {
        result.outcome = Outcome::Failed;
        result.has_reached_limit = true;
        result.reached_limit = LimitKind::SemanticEvents;
        set_detail(result, "semantic-events limit reached");
        return false;
    }

    Observation body{};
    body.kind = ObservationKind::ResponseBodyProduced;
    body.phase = Phase::Observe;
    body.sequence = result.semantic_events;
    body.value0 = replay.response_body_len;
    body.value1 = replay.response_body_truncated ? 1 : 0;
    body.label = {reinterpret_cast<const char*>(replay.observed_body), replay.observed_body_len};
    result.semantic_events++;
    if (spec.observations.publish(body)) return true;

    if (result.outcome == Outcome::Passed) {
        result.outcome = Outcome::Mismatched;
        set_detail(result, "observation rejected by oracle");
    }
    return false;
}

inline Outcome replay_outcome(const ReplayResult& replay) {
    if (replay.replayed) return replay.status_match ? Outcome::Passed : Outcome::Mismatched;
    return replay.skipped ? Outcome::Unsupported : Outcome::Failed;
}

inline void merge_outcome(Outcome item, Outcome& aggregate) {
    if (item == Outcome::Failed || item == Outcome::Invalid || item == Outcome::Stalled) {
        aggregate = item;
    } else if (item == Outcome::Mismatched &&
               (aggregate == Outcome::Passed || aggregate == Outcome::Unsupported)) {
        aggregate = item;
    } else if (item == Outcome::Unsupported && aggregate == Outcome::Passed) {
        aggregate = item;
    }
}

}  // namespace detail

// Compatibility adapter over the current synthetic SmallLoop replay path. It
// preserves ReplayResult while making unsupported, mismatch, failure, limits,
// observations, and cleanup visible through the common harness envelope.
template <typename Loop>
ReplayItemResult drive_replay_one(Loop& loop,
                                  const CaptureEntry& entry,
                                  i32 fake_fd,
                                  const HarnessSpec& spec) {
    ReplayItemResult out{};
    out.harness = validate_spec(spec);
    if (out.harness.outcome != Outcome::Passed) return out;
    out.harness.phase = Phase::Drive;
    out.harness.cleanup = CleanupOutcome::NotRun;

    if (spec.layer != ExecutionLayer::Connection && spec.layer != ExecutionLayer::EventLoop) {
        out.harness.outcome = Outcome::Invalid;
        out.harness.cleanup = CleanupOutcome::Clean;
        detail::set_detail(out.harness, "replay requires connection or event-loop layer");
        return out;
    }
    if (!spec.required_capabilities.has(Capability::SyntheticIo)) {
        out.harness.outcome = Outcome::Invalid;
        out.harness.cleanup = CleanupOutcome::Clean;
        detail::set_detail(out.harness, "mock replay must declare synthetic-io");
        return out;
    }
    if (entry.raw_header_len > spec.limits.max_input_bytes) {
        out.harness.outcome = Outcome::Failed;
        out.harness.cleanup = CleanupOutcome::Clean;
        out.harness.has_reached_limit = true;
        out.harness.reached_limit = LimitKind::InputBytes;
        detail::set_detail(out.harness, "input-bytes limit reached");
        return out;
    }
    out.harness.input_bytes = entry.raw_header_len;

    out.replay = replay_one(loop, entry, fake_fd);
    out.harness.output_bytes = out.replay.output_bytes;
    out.harness.backend_completions = out.replay.backend_completions;
    if (out.harness.output_bytes > spec.limits.max_output_bytes) {
        out.harness.outcome = Outcome::Failed;
        out.harness.has_reached_limit = true;
        out.harness.reached_limit = LimitKind::OutputBytes;
        detail::set_detail(out.harness, "output-bytes limit reached");
        out.harness.cleanup = CleanupOutcome::Clean;
        return out;
    }
    if (out.harness.backend_completions > spec.limits.max_backend_completions) {
        out.harness.outcome = Outcome::Failed;
        out.harness.has_reached_limit = true;
        out.harness.reached_limit = LimitKind::BackendCompletions;
        detail::set_detail(out.harness, "backend-completions limit reached");
        out.harness.cleanup = CleanupOutcome::Clean;
        return out;
    }
    out.harness.outcome = detail::replay_outcome(out.replay);
    out.harness.phase = Phase::Observe;
    if (!detail::publish_replay_result(spec, out.harness, 0, out.replay)) {
        out.harness.cleanup = CleanupOutcome::Clean;
        return out;
    }
    out.harness.cleanup = CleanupOutcome::Clean;
    return out;
}

template <typename Loop>
ReplayDriverResult drive_replay_file(Loop& loop, ReplayReader& reader, const HarnessSpec& spec) {
    ReplayDriverResult out{};
    out.harness = validate_spec(spec);
    if (out.harness.outcome != Outcome::Passed) return out;
    out.harness.outcome = Outcome::Passed;
    out.harness.phase = Phase::Drive;
    out.harness.cleanup = CleanupOutcome::NotRun;

    if (spec.layer != ExecutionLayer::Connection && spec.layer != ExecutionLayer::EventLoop) {
        out.harness.outcome = Outcome::Invalid;
        out.harness.cleanup = CleanupOutcome::Clean;
        detail::set_detail(out.harness, "replay requires connection or event-loop layer");
        return out;
    }
    if (!spec.required_capabilities.has(Capability::SyntheticIo)) {
        out.harness.outcome = Outcome::Invalid;
        out.harness.cleanup = CleanupOutcome::Clean;
        detail::set_detail(out.harness, "mock replay must declare synthetic-io");
        return out;
    }
    if (reader.fd < 0) {
        out.harness.outcome = Outcome::Invalid;
        out.harness.cleanup = CleanupOutcome::Clean;
        detail::set_detail(out.harness, "replay reader is not open");
        return out;
    }

    CaptureEntry entry{};
    i32 fake_fd = 10000;
    u64 input_bytes = 0;
    bool stopped_by_observer = false;
    while (reader.next(entry) == 0) {
        if (entry.raw_header_len > spec.limits.max_input_bytes - input_bytes) {
            out.harness.outcome = Outcome::Failed;
            out.harness.has_reached_limit = true;
            out.harness.reached_limit = LimitKind::InputBytes;
            detail::set_detail(out.harness, "input-bytes limit reached");
            break;
        }
        out.replay.total++;
        input_bytes += entry.raw_header_len;
        out.harness.input_bytes = input_bytes;

        const ReplayResult replay = replay_one(loop, entry, fake_fd++);
        const Outcome item_outcome = detail::replay_outcome(replay);
        detail::merge_outcome(item_outcome, out.harness.outcome);
        if (replay.replayed) {
            out.replay.replayed++;
            if (replay.status_match)
                out.replay.matched++;
            else
                out.replay.mismatched++;
        } else if (replay.skipped) {
            out.replay.skipped++;
        } else {
            out.replay.failed++;
        }

        if (replay.output_bytes > spec.limits.max_output_bytes - out.harness.output_bytes) {
            out.harness.output_bytes += replay.output_bytes;
            out.harness.backend_completions += replay.backend_completions;
            out.harness.outcome = Outcome::Failed;
            out.harness.has_reached_limit = true;
            out.harness.reached_limit = LimitKind::OutputBytes;
            detail::set_detail(out.harness, "output-bytes limit reached");
            break;
        }
        out.harness.output_bytes += replay.output_bytes;
        if (replay.backend_completions >
            spec.limits.max_backend_completions - out.harness.backend_completions) {
            out.harness.backend_completions += replay.backend_completions;
            out.harness.outcome = Outcome::Failed;
            out.harness.has_reached_limit = true;
            out.harness.reached_limit = LimitKind::BackendCompletions;
            detail::set_detail(out.harness, "backend-completions limit reached");
            break;
        }
        out.harness.backend_completions += replay.backend_completions;

        if (!detail::publish_replay_result(spec, out.harness, out.replay.total - 1, replay)) {
            stopped_by_observer = !out.harness.has_reached_limit;
            break;
        }
    }

    const bool truncated = !out.harness.has_reached_limit && !stopped_by_observer &&
                           reader.entries_read < reader.entry_count();
    if (truncated) {
        out.harness.outcome = Outcome::Failed;
        detail::set_detail(out.harness, "capture ended before declared entry count");
    }
    if (!out.harness.has_reached_limit && !truncated) out.harness.phase = Phase::Observe;
    out.harness.cleanup = CleanupOutcome::Clean;
    return out;
}

}  // namespace rut::harness
