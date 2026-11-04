#pragma once

#include "rut/compiler/rir.h"
#include "rut/runtime/json.h"
#include "rut/runtime/password.h"

namespace rut::rir {
inline bool is_password_prefix(const Instruction& inst) {
    return inst.op == Opcode::JsonOp &&
           inst.imm.i32_val == static_cast<i32>(json::Op::PasswordVerifyHeader);
}
inline bool function_uses_password(const Function& fn) {
    if (!fn.blocks) return false;
    for (u32 b = 0; b < fn.block_count; ++b) {
        const auto& block = fn.blocks[b];
        if (!block.insts) continue;
        for (u32 i = 0; i < block.inst_count; ++i)
            if (is_password_prefix(block.insts[i])) return true;
    }
    return false;
}
// The only re-entered code is a constant-only prefix in block zero. No explicit
// waits, timer functions, duplicate checks or branch/jump back into the prefix.
// Used independently by the RIR verifier and JIT/native codegen boundary.
inline bool password_prefix_valid(const Function& fn) {
    if (!function_uses_password(fn)) return true;
    if (fn.is_timer || fn.yield_count || fn.route_pattern.len == 0 || !fn.values) return false;
    u32 found = 0;
    for (u32 b = 0; b < fn.block_count; ++b) {
        const auto& block = fn.blocks[b];
        if (!block.insts && block.inst_count) return false;
        for (u32 i = 0; i < block.inst_count; ++i) {
            const auto& inst = block.insts[i];
            if (inst.op == Opcode::Jmp && inst.imm.block_targets[0].id == 0) return false;
            if (inst.op == Opcode::Br &&
                (inst.imm.block_targets[0].id == 0 || inst.imm.block_targets[1].id == 0))
                return false;
            if (!is_password_prefix(inst)) continue;
            if (++found != 1 || b != 0 || inst.operand_count != 3 || inst.extra_operands ||
                inst.result == kNoValue || inst.result.id >= fn.value_count)
                return false;
            const auto* result = fn.values[inst.result.id].type;
            if (!result || result->kind != TypeKind::I32 || result->inner || result->struct_def)
                return false;
            for (u32 p = 0; p < i; ++p)
                if (block.insts[p].op != Opcode::ConstStr && block.insts[p].op != Opcode::ConstI32)
                    return false;
            const Instruction* args[3]{};
            for (u32 a = 0; a < 3; ++a) {
                const auto id = inst.operand(a);
                if (id == kNoValue || id.id >= fn.value_count) return false;
                const auto& value = fn.values[id.id];
                if (!value.type || value.type->inner || value.type->struct_def ||
                    value.type->kind != (a == 2 ? TypeKind::I32 : TypeKind::Str) ||
                    value.def_block.id != 0 || value.def_inst >= i)
                    return false;
                args[a] = &block.insts[value.def_inst];
                if (args[a]->result != id ||
                    args[a]->op != (a == 2 ? Opcode::ConstI32 : Opcode::ConstStr))
                    return false;
            }
            if (args[2]->imm.i32_val < 1 ||
                !password_header_policy_valid(args[0]->imm.str_val,
                                              args[1]->imm.str_val,
                                              static_cast<u32>(args[2]->imm.i32_val)))
                return false;
        }
    }
    return found == 1;
}
}  // namespace rut::rir
