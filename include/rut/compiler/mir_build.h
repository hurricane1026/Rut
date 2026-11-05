#pragma once

#include "rut/compiler/hir.h"
#include "rut/compiler/mir.h"

namespace rut {

FrontendResult<MirModule*> build_mir(const HirModule& module);
// Lower one entry with the same type, policy and state environment as its owning
// module. Synchronous protocol callbacks can reuse route lowering without being
// registered as HTTP routes or consuming HTTP/timer capacity.
FrontendResult<MirModule*> build_mir_route(const HirModule& module, const HirRoute& route);
FrontendResult<MirModule*> build_mir_for_internal_propagation(const HirModule& module);
}  // namespace rut
