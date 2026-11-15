#include "rut/runtime/regex_capture.h"

#include "core/placement_new.h"
#include "rut/common/types.h"
#include "rut/runtime/arena.h"

#include <stddef.h>

#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>
#include <sys/mman.h>

namespace rut {
namespace {
constexpr u64 kProgramBytes = u64{1024} * 1024;
constexpr u64 kMatchBytes = u64{64} * 1024;
struct CaptureProgram {
    u64 used = (sizeof(CaptureProgram) + 15) & ~u64{15};
    pcre2_code* code = nullptr;
    Str pattern{};
    u32 groups = 0;
};
void* program_allocate(size_t size, void* context) {
    auto& program = *static_cast<CaptureProgram*>(context);
    if (size > kProgramBytes || program.used > kProgramBytes - size) return nullptr;
    const u64 kRounded = (static_cast<u64>(size) + 15) & ~u64{15};
    if (kRounded > kProgramBytes - program.used) return nullptr;
    auto* result = reinterpret_cast<u8*>(&program) + program.used;
    program.used += kRounded;
    return result;
}
void arena_release(void*, void*) {}
struct MatchBudget {
    SliceArena* arena;
    u64 used = 0;
};
void* match_allocate(size_t size, void* context) {
    auto& budget = *static_cast<MatchBudget*>(context);
    const u64 kRounded = (static_cast<u64>(size) + 7) & ~u64{7};
    if (size > kMatchBytes || kRounded > kMatchBytes || budget.used > kMatchBytes - kRounded ||
        budget.arena->space_used() > 262144 - size)
        return nullptr;
    void* result = budget.arena->alloc(size);
    if (result) budget.used += kRounded;
    return result;
}
}  // namespace

void* capture_regex_compile(Str pattern) {
    if (!pattern.ptr || pattern.len == 0 || pattern.len > 1024) return nullptr;
    void* region =
        mmap(nullptr, kProgramBytes, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (region == MAP_FAILED) return nullptr;
    auto* program = new (region) CaptureProgram{};
    auto* general = pcre2_general_context_create(program_allocate, arena_release, program);
    auto* context = general ? pcre2_compile_context_create(general) : nullptr;
    if (!context) {
        munmap(region, kProgramBytes);
        return nullptr;
    }
    pcre2_set_parens_nest_limit(context, 64);
    int error = 0;
    PCRE2_SIZE offset = 0;
    program->code = pcre2_compile(reinterpret_cast<PCRE2_SPTR>(pattern.ptr),
                                  pattern.len,
                                  PCRE2_NEVER_UTF | PCRE2_NEVER_UCP,
                                  &error,
                                  &offset,
                                  context);
    if (!program->code ||
        pcre2_pattern_info(program->code, PCRE2_INFO_CAPTURECOUNT, &program->groups) != 0 ||
        program->groups > 8) {
        munmap(region, kProgramBytes);
        return nullptr;
    }
    auto* copy = static_cast<char*>(program_allocate(pattern.len, program));
    if (!copy) {
        munmap(region, kProgramBytes);
        return nullptr;
    }
    __builtin_memcpy(copy, pattern.ptr, pattern.len);
    program->pattern = {copy, pattern.len};
    return program;
}
void capture_regex_destroy(void* program) {
    if (program) munmap(program, kProgramBytes);
}
Str capture_regex_pattern(const void* program) {
    return program ? static_cast<const CaptureProgram*>(program)->pattern : Str{};
}
u32 capture_regex_group_count(const void* program) {
    return program ? static_cast<const CaptureProgram*>(program)->groups : 0;
}
u8 capture_regex_match(void* raw, SliceArena& arena, Str subject, u32 group, Str* output) {
    *output = {};
    if (!raw || !subject.ptr || subject.len > 8192 || !arena.backend.pool) return 2;
    const auto& program = *static_cast<const CaptureProgram*>(raw);
    if (group > program.groups) return 2;
    if (!arena.current && !arena.init(arena.backend.pool)) return 2;
    MatchBudget budget{&arena};
    auto* general = pcre2_general_context_create(match_allocate, arena_release, &budget);
    auto* context = general ? pcre2_match_context_create(general) : nullptr;
    auto* match = general ? pcre2_match_data_create(program.groups + 1, general) : nullptr;
    if (!context || !match) return 2;
    pcre2_set_match_limit(context, 100000);
    pcre2_set_depth_limit(context, 64);
    // A PCRE frame vector must fit a 16 KiB Arena slice. The initial
    // 20 KiB default is clamped by this explicit 12 KiB heap limit.
    pcre2_set_heap_limit(context, 12);
    const int kResult = pcre2_match(
        program.code, reinterpret_cast<PCRE2_SPTR>(subject.ptr), subject.len, 0, 0, match, context);
    if (kResult == PCRE2_ERROR_NOMATCH) return 0;
    if (kResult <= 0) return 2;
    const PCRE2_SIZE* offsets = pcre2_get_ovector_pointer(match);
    const PCRE2_SIZE kBegin = offsets[static_cast<PCRE2_SIZE>(group) * 2];
    const PCRE2_SIZE kEnd = offsets[static_cast<PCRE2_SIZE>(group) * 2 + 1];
    if (kBegin == PCRE2_UNSET || kEnd == PCRE2_UNSET) return 0;
    if (kBegin > kEnd || kEnd > subject.len) return 2;
    *output = {subject.ptr + kBegin, static_cast<u32>(kEnd - kBegin)};
    return 1;
}
}  // namespace rut
