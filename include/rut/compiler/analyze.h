#pragma once

#include "rut/compiler/ast.h"
#include "rut/compiler/hir.h"

namespace rut {

struct SourceBudget {
    u64 max_bytes = ~u64{0};
    u64 used_bytes = 0;
    bool exceeded = false;
};

// Maximum import nesting depth: the number of imported files that may be
// open below the main source at once (main -> a -> b is depth 2). Each level
// re-enters analyze_file_internal, whose frame is dominated by HIR scratch
// locals, and load_imported_modules stays live across the recursion. x86-64
// frame per import level (`sub rsp` at entry, analyze_file_internal +
// load_imported_modules):
//   clang Release     1,307,976 + 1,144 ~= 1.25 MiB
//   gcc   Release     2,343,048 + 1,496 ~= 2.24 MiB
//   gcc   Debug (-O0) 1,341,672 + 2,120 ~= 1.28 MiB
//   clang Debug+ASan  2,976,032 + 2,432 ~= 2.84 MiB
// gcc Release is the worst non-sanitized build: main + 2 imports is three
// frames = 6.71 MiB of Linux's default 8 MiB stack, leaving ~1.29 MiB for the
// deepest file's non-recursive callees (largest analyzer helper frame ~62 KiB)
// and the caller; a third import (8.94 MiB) cannot fit. Sanitized builds need
// a larger stack regardless (three ASan frames are 8.52 MiB). Exceeding the
// limit is a diagnostic at the offending `import`, never a stack overflow.
// Raise this only after shrinking the analyzer frame (issue #701).
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
