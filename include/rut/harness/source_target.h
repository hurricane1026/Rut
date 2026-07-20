#pragma once

#include "rut/harness/core.h"
#include "rut/serve_loader.h"

namespace rut::harness {

struct SourceTargetSpec {
    const char* path = nullptr;
    jit::OptLevel opt = jit::OptLevel::O0;
};

// Owns the complete production source -> RouteConfig/JIT image. The explicit
// destroy contract mirrors LoadedProgram and makes cleanup observable to the
// harness even on failed preparation.
struct SourceTarget {
    LoadedProgram program{};
    LoadError load_error{};
    u64 generation = 0;
    bool prepared = false;

    SourceTarget() = default;
    SourceTarget(const SourceTarget&) = delete;
    SourceTarget& operator=(const SourceTarget&) = delete;
    SourceTarget(SourceTarget&&) = delete;
    SourceTarget& operator=(SourceTarget&&) = delete;

    HarnessResult prepare(const SourceTargetSpec& target, const HarnessSpec& harness);
    CleanupOutcome destroy();
};

}  // namespace rut::harness
