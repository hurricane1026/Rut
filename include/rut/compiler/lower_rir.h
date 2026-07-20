#pragma once

#include "rut/compiler/diagnostic.h"
#include "rut/compiler/mir.h"
#include "rut/compiler/rir.h"
#include "rut/runtime/arena.h"

namespace rut {

struct FrontendRirModule {
    MmapArena arena;
    rir::Module module{};
    Str source_name{};
    // RIR string immediates are non-owning views. Keep analyzer-generated and
    // imported string storage alive after the MIR is released and until codegen
    // (or any other RIR consumer) has finished reading those immediates.
    std::shared_ptr<std::deque<std::string>> owned_strings;

    bool init(u32 func_cap, u32 struct_cap = 1);
    void destroy();
};

FrontendResult<void> lower_to_rir(const MirModule& mir, FrontendRirModule& out);

}  // namespace rut
