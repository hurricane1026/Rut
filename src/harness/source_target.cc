#include "rut/harness/source_target.h"

#include <sys/stat.h>

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

bool publish(
    const HarnessSpec& spec, ObservationKind kind, Phase phase, u64 value0 = 0, Str label = {}) {
    Observation event{};
    event.kind = kind;
    event.phase = phase;
    event.value0 = value0;
    event.label = label;
    return spec.observations.publish(event);
}

}  // namespace

HarnessResult SourceTarget::prepare(const SourceTargetSpec& target, const HarnessSpec& harness) {
    (void)destroy();

    HarnessResult result = validate_spec(harness);
    if (result.outcome != Outcome::Passed) return result;
    result.phase = Phase::Prepare;
    result.cleanup = CleanupOutcome::NotRun;

    if (target.path == nullptr || target.path[0] == '\0') {
        result.outcome = Outcome::Invalid;
        result.cleanup = CleanupOutcome::Clean;
        copy_detail(result.detail, sizeof(result.detail), "source target path is empty");
        return result;
    }

    struct stat st{};
    if (::stat(target.path, &st) != 0 || st.st_size < 0) {
        result.outcome = Outcome::Failed;
        result.cleanup = CleanupOutcome::Clean;
        copy_detail(result.detail, sizeof(result.detail), "source target is unreadable");
        return result;
    }
    if (static_cast<u64>(st.st_size) > harness.limits.max_source_bytes) {
        result.outcome = Outcome::Failed;
        result.cleanup = CleanupOutcome::Clean;
        result.has_reached_limit = true;
        result.reached_limit = LimitKind::SourceBytes;
        copy_detail(result.detail, sizeof(result.detail), "source-bytes limit reached");
        (void)publish(harness,
                      ObservationKind::LimitReached,
                      Phase::Prepare,
                      static_cast<u64>(st.st_size),
                      {"source-bytes", 12});
        return result;
    }

    if (!load_rut_program(
            target.path, program, load_error, target.opt, harness.limits.max_source_bytes)) {
        result.outcome = Outcome::Failed;
        if (load_error.source_limit_exceeded) {
            result.has_reached_limit = true;
            result.reached_limit = LimitKind::SourceBytes;
            copy_detail(result.detail, sizeof(result.detail), "source-bytes limit reached");
            (void)publish(harness,
                          ObservationKind::LimitReached,
                          Phase::Prepare,
                          harness.limits.max_source_bytes,
                          {"source-bytes", 12});
            program.destroy();
            result.cleanup = CleanupOutcome::Clean;
            return result;
        }
        char detail[LoadError::kMaxDetail + 128]{};
        (void)format_load_error(load_error, detail, sizeof(detail));
        copy_detail(result.detail, sizeof(result.detail), detail);
        (void)publish(harness,
                      ObservationKind::CompileFailed,
                      Phase::Prepare,
                      static_cast<u64>(load_error.stage));
        program.destroy();
        result.cleanup = CleanupOutcome::Clean;
        return result;
    }

    prepared = true;
    result.outcome = Outcome::Passed;
    result.phase = Phase::Start;
    return result;
}

CleanupOutcome SourceTarget::destroy() {
    program.destroy();
    prepared = false;
    load_error = LoadError{};
    return CleanupOutcome::Clean;
}

}  // namespace rut::harness
