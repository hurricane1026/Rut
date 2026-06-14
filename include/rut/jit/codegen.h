/*
 * Copyright (C) 2026 Rut Contributors
 *
 * This file is part of Rut.
 *
 * Rut is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * Rut is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public
 * License along with Rut. If not, see <https://www.gnu.org/licenses/>.
 */

#pragma once

#include "rut/common/types.h"

// Forward declarations — avoid pulling LLVM headers into other code.
using LLVMModuleRef = struct LLVMOpaqueModule*;
using LLVMContextRef = struct LLVMOpaqueContext*;

namespace rut::rir {
struct Module;
}

namespace rut::jit {

// ── Codegen ────────────────────────────────────────────────────────
// Translates an RIR Module into an LLVM IR Module via the LLVM C API.
//
// Phase 1: handles sync handlers only (no yields). Each RIR Function
// becomes a single LLVM function with the HandlerFn signature.
//
// The returned LLVMModuleRef and LLVMContextRef are owned by the caller.
// Pass both to JitEngine::compile() which takes ownership.

struct CodegenResult {
    LLVMModuleRef mod;
    LLVMContextRef ctx;
    bool ok;
};

// Format the JIT handler symbol for an RIR function name.
// Returns the output length excluding the trailing '\0'.
u32 format_handler_symbol(Str name, char* out, u32 out_size);

// Translate all functions in the RIR module to LLVM IR.
// Returns {module, context, true} on success, {null, null, false} on error.
CodegenResult codegen(const rir::Module& rir_mod);

}  // namespace rut::jit
