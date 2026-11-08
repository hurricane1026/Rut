#pragma once
#include "rut/compiler/http_call_profile.h"
#include "rut/runtime/arena.h"

namespace rut::rir {
// Mark only values used after a suspension. Phi inputs belong to predecessor
// edges, not to the block containing the phi. Compiler scratch is arena-owned;
// this does not enlarge the runtime's bounded continuation frame.
inline bool call_live_values(const Function& fn, MmapArena& arena, u32* saved) {
    if (!saved || !fn.values || !fn.blocks || fn.value_count > 1048576 || fn.block_count > 4096)
        return false;
    // Only cross-block values and values in call-containing blocks can cross
    // a suspension. Compact them before building the liveness bitsets; large
    // pure parsers otherwise multiply compiler scratch by all local temporaries.
    auto* indices = arena.alloc_array<u32>(fn.value_count);
    auto* candidates = arena.alloc_array<u32>(fn.value_count);
    if (!indices || !candidates) return false;
    u32 candidate_count = 0;
    const auto admit = [&](ValueId id) {
        if (id == kNoValue || id.id >= fn.value_count) return false;
        if (!indices[id.id]) {
            candidates[candidate_count] = id.id;
            indices[id.id] = ++candidate_count;
        }
        return true;
    };
    for (u32 b = 0; b < fn.block_count; ++b) {
        const auto& block = fn.blocks[b];
        bool call = false;
        for (u32 i = 0; i < block.inst_count; ++i) call |= is_http_call(block.insts[i]);
        for (u32 i = 0; i < block.inst_count; ++i) {
            const auto& inst = block.insts[i];
            for (u32 o = 0; o < inst.operand_count; ++o) {
                const auto id = inst.operand(o);
                if (id == kNoValue || id.id >= fn.value_count) return false;
                if ((call || inst.op == Opcode::Phi || fn.values[id.id].def_block.id != b) &&
                    !admit(id))
                    return false;
            }
            if (call && inst.result != kNoValue && !admit(inst.result)) return false;
        }
    }
    const u32 words = (candidate_count + 63) / 64;
    if (!words) return true;
    const u32 cells = words * fn.block_count;
    if (cells > 8388608) return false;  // bounded compiler scratch, at most 256 MiB
    auto* uses = arena.alloc_array<u64>(cells);
    auto* defs = arena.alloc_array<u64>(cells);
    auto* inputs = arena.alloc_array<u64>(cells);
    auto* outputs = arena.alloc_array<u64>(cells);
    auto* live = arena.alloc_array<u64>(words);
    if (!uses || !defs || !inputs || !outputs || !live) return false;
    const auto set = [&](u64* bits, u32 value) {
        if (!indices[value]) return;
        const u32 id = indices[value] - 1;
        bits[id / 64] |= u64(1) << (id % 64);
    };
    for (u32 b = 0; b < fn.block_count; ++b) {
        auto* used = uses + static_cast<u64>(b) * words;
        auto* defined = defs + static_cast<u64>(b) * words;
        const auto& block = fn.blocks[b];
        for (u32 i = 0; i < block.inst_count; ++i) {
            const auto& inst = block.insts[i];
            if (inst.op != Opcode::Phi) {
                for (u32 o = 0; o < inst.operand_count; ++o) {
                    const auto id = inst.operand(o);
                    if (id == kNoValue || id.id >= fn.value_count) return false;
                    if (indices[id.id]) {
                        const u32 compact = indices[id.id] - 1;
                        if (!(defined[compact / 64] & (u64(1) << (compact % 64)))) set(used, id.id);
                    }
                }
            }
            if (inst.result != kNoValue) {
                if (inst.result.id >= fn.value_count) return false;
                set(defined, inst.result.id);
            }
        }
    }
    bool changed = true;
    while (changed) {
        changed = false;
        for (u32 n = fn.block_count; n > 0; --n) {
            const u32 b = n - 1;
            for (u32 w = 0; w < words; ++w) live[w] = 0;
            const auto* term = fn.blocks[b].terminator();
            if (!term) return false;
            const u32 successors = term->op == Opcode::Br ? 2 : term->op == Opcode::Jmp ? 1 : 0;
            for (u32 edge = 0; edge < successors; ++edge) {
                const u32 target = term->imm.block_targets[edge].id;
                if (target >= fn.block_count) return false;
                for (u32 w = 0; w < words; ++w) live[w] |= inputs[target * words + w];
                const auto& next = fn.blocks[target];
                for (u32 i = 0; i < next.inst_count; ++i) {
                    const auto& phi = next.insts[i];
                    if (phi.op != Opcode::Phi) continue;
                    for (u32 incoming = 0; incoming < 2; ++incoming)
                        if (phi.imm.block_targets[incoming].id == b) {
                            const auto id = phi.operands[incoming];
                            if (id == kNoValue || id.id >= fn.value_count) return false;
                            set(live, id.id);
                        }
                }
            }
            for (u32 w = 0; w < words; ++w) {
                outputs[b * words + w] = live[w];
                const u64 value = uses[b * words + w] | (live[w] & ~defs[b * words + w]);
                if (inputs[b * words + w] != value) {
                    inputs[b * words + w] = value;
                    changed = true;
                }
            }
        }
    }
    for (u32 b = 0; b < fn.block_count; ++b) {
        for (u32 w = 0; w < words; ++w) live[w] = outputs[b * words + w];
        const auto& block = fn.blocks[b];
        for (u32 n = block.inst_count; n > 0; --n) {
            const auto& inst = block.insts[n - 1];
            if (inst.result != kNoValue && indices[inst.result.id]) {
                const u32 compact = indices[inst.result.id] - 1;
                live[compact / 64] &= ~(u64(1) << (compact % 64));
            }
            if (inst.op != Opcode::Phi)
                for (u32 o = 0; o < inst.operand_count; ++o) set(live, inst.operand(o).id);
            // Poll/resume reuses the call arguments too, even when no later
            // source instruction refers to them.
            if (is_http_call(inst))
                for (u32 v = 0; v < candidate_count; ++v)
                    if (live[v / 64] & (u64(1) << (v % 64))) saved[candidates[v]] = 1;
        }
    }
    return true;
}
}  // namespace rut::rir
