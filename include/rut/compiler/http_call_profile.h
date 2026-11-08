#pragma once
#include "rut/compiler/password_profile.h"
#include "rut/runtime/http_call.h"
#include "rut/runtime/net_client.h"

namespace rut::rir {
inline bool is_net_call(const Instruction& inst) {
    return inst.op == Opcode::JsonOp && inst.imm.i32_val >= static_cast<i32>(json::Op::NetTcp) &&
           inst.imm.i32_val <= static_cast<i32>(json::Op::NetClose);
}
inline bool is_http_call(const Instruction& inst) {
    return inst.op == Opcode::JsonOp &&
           (inst.imm.i32_val == static_cast<i32>(json::Op::HttpCall) || is_net_call(inst));
}
inline bool net_call_profile_valid(const Function& fn, const Instruction& inst) {
    const auto op = static_cast<json::Op>(inst.imm.i32_val);
    const bool open = op == json::Op::NetTcp || op == json::Op::NetUdp;
    const bool close = op == json::Op::NetClose;
    const bool scalar = open || op == json::Op::NetSend;
    if (inst.operand_count != (close  ? 1u
                               : open ? 2u
                                      : 3u) ||
        inst.extra_operands || inst.result == kNoValue || inst.result.id >= fn.value_count)
        return false;
    const auto* type = fn.values[inst.result.id].type;
    if (!type || type->struct_def) return false;
    if (close) {
        if (type->kind != TypeKind::Bool || type->inner) return false;
    } else if (type->kind != TypeKind::Optional || !type->inner ||
               type->inner->kind != (scalar ? TypeKind::I32 : TypeKind::Str) ||
               type->inner->inner || type->inner->struct_def)
        return false;
    const Instruction* definitions[3]{};
    for (u32 i = 0; i < inst.operand_count; ++i) {
        const auto id = inst.operand(i);
        if (id == kNoValue || id.id >= fn.value_count) return false;
        const auto& value = fn.values[id.id];
        const auto wanted =
            (open && i == 0) || (op == json::Op::NetSend && i == 1) ? TypeKind::Str : TypeKind::I32;
        if (!value.type || value.type->kind != wanted || value.type->inner ||
            value.type->struct_def || value.def_block.id >= fn.block_count ||
            !fn.blocks[value.def_block.id].insts ||
            value.def_inst >= fn.blocks[value.def_block.id].inst_count)
            return false;
        definitions[i] = &fn.blocks[value.def_block.id].insts[value.def_inst];
        if (definitions[i]->result != id) return false;
    }
    if (open) {
        NetEndpoint endpoint;
        if (definitions[0]->op != Opcode::ConstStr ||
            !net_endpoint(definitions[0]->imm.str_val, op == json::Op::NetUdp, endpoint))
            return false;
    }
    if (!close) {
        const auto* timeout = definitions[inst.operand_count - 1];
        if (timeout->op != Opcode::ConstI32 || timeout->imm.i32_val < 1 ||
            timeout->imm.i32_val > 60000)
            return false;
    }
    return true;
}
inline bool function_uses_http_call(const Function& fn) {
    if (!fn.blocks) return false;
    for (u32 b = 0; b < fn.block_count; ++b) {
        if (!fn.blocks[b].insts) continue;
        for (u32 i = 0; i < fn.blocks[b].inst_count; ++i)
            if (is_http_call(fn.blocks[b].insts[i])) return true;
    }
    return false;
}
inline bool http_call_profile_valid(const Function& fn) {
    if (!function_uses_http_call(fn)) return true;
    if (fn.is_timer || fn.yield_count || fn.route_pattern.len == 0 || function_uses_password(fn) ||
        !fn.values || fn.value_count > 1048576)
        return false;
    u32 calls = 0;
    for (u32 b = 0; b < fn.block_count; ++b) {
        const auto& block = fn.blocks[b];
        if (!block.insts && block.inst_count) return false;
        for (u32 i = 0; i < block.inst_count; ++i) {
            const auto& inst = block.insts[i];
            // Slot zero belongs exclusively to the callout continuation frame.
            // Forged RIR must not combine it with the explicit-wait ABI.
            if (inst.is_yield() || inst.op == Opcode::CtxStoreSlotI32 ||
                inst.op == Opcode::CtxLoadSlotI32 || inst.op == Opcode::ResumeEventKind ||
                inst.op == Opcode::ResumeEventResult || inst.op == Opcode::WsMessageField)
                return false;
            if (!is_http_call(inst)) continue;
            if (is_net_call(inst)) {
                if (++calls > 16 || !net_call_profile_valid(fn, inst)) return false;
                continue;
            }
            if (++calls > 16 || inst.operand_count != 3 || inst.extra_operands ||
                inst.result == kNoValue || inst.result.id >= fn.value_count)
                return false;
            const auto* result = fn.values[inst.result.id].type;
            if (!result || result->kind != TypeKind::Optional || !result->inner ||
                result->struct_def || result->inner->kind != TypeKind::Str ||
                result->inner->inner || result->inner->struct_def)
                return false;
            const Instruction* args[3]{};
            for (u32 a = 0; a < 3; ++a) {
                const auto id = inst.operand(a);
                if (id == kNoValue || id.id >= fn.value_count) return false;
                const auto& value = fn.values[id.id];
                if (!value.type || value.type->kind != (a == 2 ? TypeKind::I32 : TypeKind::Str) ||
                    value.type->inner || value.type->struct_def)
                    return false;
                if (value.def_block.id >= fn.block_count || !fn.blocks[value.def_block.id].insts ||
                    value.def_inst >= fn.blocks[value.def_block.id].inst_count)
                    return false;
                args[a] = &fn.blocks[value.def_block.id].insts[value.def_inst];
                if (args[a]->result != id) return false;
            }
            HttpsEndpoint endpoint;
            if (args[0]->op != Opcode::ConstStr ||
                !http_call_policy(args[0]->imm.str_val, endpoint) ||
                args[2]->op != Opcode::ConstI32 || args[2]->imm.i32_val < 1 ||
                args[2]->imm.i32_val > 60000)
                return false;
        }
    }
    return true;
}
}  // namespace rut::rir
