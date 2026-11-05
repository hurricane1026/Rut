#pragma once

#include "rut/common/types.h"

namespace rut {

// Compiler/JIT-only targets. No encoded target is returned by a runtime handler.
inline constexpr u32 kWsControlNext = 0xffffffffu;
inline constexpr u32 kWsControlDefault = 0xfffffffeu;
inline constexpr u32 kWsControlReturn = 0x80000000u;
inline constexpr u32 kWsControlAfter = 0x40000000u;

constexpr u32 ws_control_return(u8 action) {
    return kWsControlReturn | action;
}
constexpr u32 ws_control_after(u32 node_count) {
    return kWsControlAfter | node_count;
}
constexpr bool ws_control_is_return(u32 target) {
    return (target & 0xffffff00u) == kWsControlReturn;
}
constexpr bool ws_control_is_after(u32 target) {
    return (target & 0xffffff00u) == kWsControlAfter;
}
constexpr u32 ws_control_value(u32 target) {
    return target & 0xffu;
}

}  // namespace rut
