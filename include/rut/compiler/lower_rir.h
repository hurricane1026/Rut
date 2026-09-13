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

    bool init(u32 func_cap, u32 struct_cap = 1);
    void destroy();
};

FrontendResult<void> lower_to_rir(const MirModule& mir, FrontendRirModule& out);
FrontendResult<void> lower_to_rir_for_internal_propagation(const MirModule& mir,
                                                           FrontendRirModule& out);

}  // namespace rut
