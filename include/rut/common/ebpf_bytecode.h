#pragma once

#include "rut/common/types.h"

namespace rut::ebpf {
// Same-build eBPF instruction encoding. No process addresses or live map FDs.
struct Instruction {
    u8 code;
    u8 registers;
    i16 offset;
    i32 immediate;
};
static_assert(sizeof(Instruction) == 8);
constexpr Instruction instruction(u8 code, u8 dst, u8 src, i16 offset, i32 value) {
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    const u8 kRegisters = static_cast<u8>((dst << 4u) | src);
#else
    const u8 kRegisters = static_cast<u8>(dst | (src << 4u));
#endif
    return {code, kRegisters, offset, value};
}
constexpr u32 kParserInstructions = 22;
constexpr u32 kVerdictInstructions = 31;
constexpr u32 kFrameBytes = 4096;
constexpr u32 kPortRelocation = 3;
constexpr u32 kBudgetMapRelocation = 6;
constexpr u32 kSocketMapRelocation = 22;
// Stable __sk_buff UAPI offsets and helper numbers, not internal kernel layout.
constexpr i16 kLocalPortOffset = 136;
constexpr i32 kMapLookupHelper = 1;
constexpr i32 kSocketRedirectHelper = 52;
struct BodyBytecode {
    Instruction parser[kParserInstructions]{};
    Instruction verdict[kVerdictInstructions]{};
};
inline void emit_body_bytecode(BodyBytecode& out) {
    const Instruction kPrefix[] = {instruction(0xbf, 6, 1, 0, 0),
                                   instruction(0x61, 3, 6, kLocalPortOffset, 0),
                                   instruction(0xb7, 7, 0, 0, 0),
                                   instruction(0x15, 3, 0, 1, 0),
                                   instruction(0xb7, 7, 0, 0, 1),
                                   instruction(0x63, 10, 7, -4, 0),
                                   instruction(0x18, 1, 1, 0, 0),
                                   instruction(0, 0, 0, 0, 0),
                                   instruction(0xbf, 2, 10, 0, 0),
                                   instruction(0x07, 2, 0, 0, -4),
                                   instruction(0x85, 0, 0, 0, kMapLookupHelper),
                                   instruction(0x15, 0, 0, 0, 0),
                                   instruction(0x61, 8, 0, 0, 0)};
    for (u32 i = 0; i < 13; ++i) out.parser[i] = out.verdict[i] = kPrefix[i];
    out.parser[11].offset = 8;
    const Instruction kParserTail[] = {instruction(0xb7, 0, 0, 0, kFrameBytes),
                                       instruction(0x15, 8, 0, 3, 0),
                                       instruction(0xbd, 0, 8, 1, 0),
                                       instruction(0xbf, 0, 8, 0, 0),
                                       instruction(0x95, 0, 0, 0, 0),
                                       instruction(0xb7, 0, 0, 0, 1),
                                       instruction(0x95, 0, 0, 0, 0),
                                       instruction(0xb7, 0, 0, 0, -1),
                                       instruction(0x95, 0, 0, 0, 0)};
    for (u32 i = 0; i < 9; ++i) out.parser[i + 13] = kParserTail[i];
    out.verdict[11].offset = 17;
    const Instruction kVerdictTail[] = {instruction(0x15, 8, 0, 13, 0),
                                        instruction(0xb7, 9, 0, 0, kFrameBytes),
                                        instruction(0xbd, 9, 8, 1, 0),
                                        instruction(0xbf, 9, 8, 0, 0),
                                        instruction(0x1f, 8, 9, 0, 0),
                                        instruction(0x63, 0, 8, 0, 0),
                                        instruction(0xbf, 1, 6, 0, 0),
                                        instruction(0xbf, 3, 7, 0, 0),
                                        instruction(0xa7, 3, 0, 0, 1),
                                        instruction(0x18, 2, 1, 0, 0),
                                        instruction(0, 0, 0, 0, 0),
                                        instruction(0xb7, 4, 0, 0, 0),
                                        instruction(0x85, 0, 0, 0, kSocketRedirectHelper),
                                        instruction(0x95, 0, 0, 0, 0),
                                        instruction(0xb7, 0, 0, 0, 1),
                                        instruction(0x95, 0, 0, 0, 0),
                                        instruction(0xb7, 0, 0, 0, 0),
                                        instruction(0x95, 0, 0, 0, 0)};
    for (u32 i = 0; i < 18; ++i) out.verdict[i + 13] = kVerdictTail[i];
}
}  // namespace rut::ebpf
