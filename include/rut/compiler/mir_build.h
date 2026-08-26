#pragma once

#include "rut/compiler/hir.h"
#include "rut/compiler/mir.h"

namespace rut {

FrontendResult<MirModule*> build_mir(const HirModule& module);
FrontendResult<MirModule*> build_mir_for_internal_propagation(const HirModule& module);
}  // namespace rut
