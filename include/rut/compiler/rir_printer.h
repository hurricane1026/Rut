#pragma once

#include "rut/compiler/rir.h"

namespace rut {
namespace rir {

// ── RIR Printer ─────────────────────────────────────────────────────
// Produces human-readable --emit-rir text output. Writes directly to
// a file descriptor (no stdio, no stdlib).
//
// Output format (differs from DESIGN.md §11.2.5 in several ways):
// 1. All operands are SSA references — string/numeric literals are
//    materialized as const.str/const.i32 instructions, not inlined.
// 2. Header uses "route:" instead of "params:".
// 3. Nil checks use explicit "opt.is_nil %v" instructions, not the
//    "%v.is_nil" sugar shown in DESIGN.md.
// 4. Domain immediates (Duration, ByteSize, Method) print as raw
//    numeric values, not pretty-printed units.
//
//   === handle_get_users_id ===
//     route: /users/:id
//     io_points: 0 (all sync)
//     states: 1
//     blocks: 7
//     instructions: 18
//
//   entry:
//     %0 = req.header "Authorization"    // line 42
//     %1 = opt.is_nil %0                 // line 42
//     br %1, block_reject_401, block_1   // line 42

struct PrintBuf {
    char* data;
    u32 len;
    u32 cap;
    i32 fd;         // output file descriptor (-1 for in-memory)
    bool overflow;  // true if put() dropped data due to full buffer

    void init(char* buf, u32 buf_cap, i32 out_fd) {
        data = buf;
        len = 0;
        cap = buf_cap;
        fd = out_fd;
        overflow = false;
    }

    void flush();
    void put(char c);
    void put_str(const char* s, u32 n);
    void put_str(Str s) { put_str(s.ptr, s.len); }
    void put_cstr(const char* s);
    void put_u32(u32 val);
    void put_i32(i32 val);
    void put_i64(i64 val);
    void newline() { put('\n'); }
    void indent(u32 level);
};

// Print the opcode mnemonic (e.g., "req.header", "cmp.eq").
void print_opcode(PrintBuf& buf, Opcode op);

// Print a type (e.g., "str", "Optional(str)", "Struct(User)").
void print_type(PrintBuf& buf, const Type* type);

// Print a single instruction.
void print_instruction(PrintBuf& buf, const Instruction& inst, const Function& fn);

// Print a single block.
void print_block(PrintBuf& buf, const Block& block, const Function& fn);

// Print a function with header summary.
void print_function(PrintBuf& buf, const Function& fn);

// Print the entire module.
void print_module(PrintBuf& buf, const Module& mod);
void print_module_for_internal_propagation(PrintBuf& buf, const Module& mod);

}  // namespace rir
}  // namespace rut
