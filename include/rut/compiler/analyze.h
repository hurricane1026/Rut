#pragma once

#include "rut/compiler/ast.h"
#include "rut/compiler/hir.h"

namespace rut {

struct SourceBudget {
    u64 max_bytes = ~u64{0};
    u64 used_bytes = 0;
    bool exceeded = false;
};

// Large HIR route and guard scratch objects live outside the recursive frame,
// leaving the GCC Release analyze_file_internal frame at ~170 KiB. Each active
// recursive analysis also owns a fixed-capacity HirModule on the heap (currently
// about 126 MiB), so a deeper chain can exceed common process memory limits even
// though the stack frames fit. Keep the limit conservative until route storage is
// made lazy; exceeding it is diagnosed at the offending import, never by overflow.
inline constexpr u32 kMaxImportNestingDepth = 2;

FrontendResult<HirModule*> analyze_file(const AstFile& file);
FrontendResult<HirModule*> analyze_file(const AstFile& file, Str source_path);
FrontendResult<HirModule*> analyze_file(const AstFile& file,
                                        Str source_path,
                                        SourceBudget* source_budget);
FrontendResult<HirModule*> analyze_file_for_internal_propagation(const AstFile& file);
void reset_import_analysis_counter();
u32 get_import_analysis_counter();

}  // namespace rut
