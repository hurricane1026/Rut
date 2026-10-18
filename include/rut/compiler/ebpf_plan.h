#pragma once

#include "rut/common/ebpf_plan.h"
#include "rut/compiler/rir.h"

namespace rut {
struct RouteConfig;
// Classifies body-only candidates after inlining/verification. Routing, headers,
// failure handling and socket handoff remain userspace responsibilities.
bool build_ebpf_plan(const rir::Module& module,
                     const RouteConfig& config,
                     bool tls_listener,
                     ebpf::Plan& out);
}  // namespace rut
