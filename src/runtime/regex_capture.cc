#include "rut/runtime/regex_capture.h"

#include "core/placement_new.h"
#include "rut/common/range_int.h"
#include "rut/common/types.h"
#include "rut/runtime/arena.h"
#include "rut/runtime/string_ops.h"

#include <re2/re2.h>
#include <sys/mman.h>

namespace rut {
namespace {
// Only this translation unit knows the engine or its C++ types. The engine's
// runtime-free ABI still uses C heap allocation; mmap owns this adapter object.
struct CaptureProgram {
    re2::RE2 regex;
    explicit CaptureProgram(Str pattern) : regex(view(pattern), options()) {}
    static re2::StringView view(Str value) { return {value.ptr, value.len}; }
    static re2::RE2::Options options() {
        re2::RE2::Options result;
        result.set_encoding(re2::RE2::Options::EncodingLatin1);
        result.set_log_errors(false);
        result.set_max_mem(i64{1024} * 1024);
        return result;
    }
};
}  // namespace

void* capture_regex_compile(Str pattern) {
    if (!pattern.ptr || pattern.len == 0 || pattern.len > 1024) return nullptr;
    void* region = mmap(nullptr,
                        sizeof(CaptureProgram),
                        PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS,
                        -1,
                        0);
    if (region == MAP_FAILED) return nullptr;
    auto* program = new (region) CaptureProgram(pattern);
    if (!program->regex.ok() || program->regex.NumberOfCapturingGroups() > 8) {
        program->~CaptureProgram();
        munmap(region, sizeof(CaptureProgram));
        return nullptr;
    }
    return program;
}
void capture_regex_destroy(void* raw) {
    if (!raw) return;
    auto* program = static_cast<CaptureProgram*>(raw);
    program->~CaptureProgram();
    munmap(program, sizeof(CaptureProgram));
}
Str capture_regex_pattern(const void* raw) {
    if (!raw) return {};
    const auto& pattern = static_cast<const CaptureProgram*>(raw)->regex.pattern();
    return {pattern.data(), static_cast<u32>(pattern.size())};
}
u32 capture_regex_group_count(const void* raw) {
    return raw ? static_cast<u32>(
                     static_cast<const CaptureProgram*>(raw)->regex.NumberOfCapturingGroups())
               : 0;
}
u8 capture_regex_match(void* raw, SliceArena& arena, Str subject, u32 group, Str* output) {
    *output = {};
    if (!raw || !subject.ptr || subject.len > 8192 || !arena.backend.pool) return 2;
    const auto& regex = static_cast<const CaptureProgram*>(raw)->regex;
    if (group > static_cast<u32>(regex.NumberOfCapturingGroups())) return 2;
    re2::StringView captures[9];
    if (!regex.Match(CaptureProgram::view(subject),
                     0,
                     subject.len,
                     re2::RE2::UNANCHORED,
                     captures,
                     static_cast<int>(static_cast<i64>(group) + 1)))
        return 0;
    const auto kCapture = captures[group];
    if (!kCapture.data()) return 0;
    *output = {kCapture.data(), static_cast<u32>(kCapture.size())};
    return 1;
}
u8 capture_regex_replace(void* raw, SliceArena& arena, Str subject, Str replacement, Str* output) {
    *output = {};
    if (!raw || !arena.backend.pool || subject.len > kStringInputLimit ||
        replacement.len > kStringInputLimit || (subject.len && !subject.ptr) ||
        (replacement.len && !replacement.ptr))
        return 0;
    const auto& regex = static_cast<CaptureProgram*>(raw)->regex;
    const Str text{subject.ptr ? subject.ptr : "", subject.len};
    struct Match {
        u32 start;
        u32 end;
    };
    Match matches[64]{};
    u32 count = 0;
    u32 search = 0;
    i64 size = static_cast<i64>(subject.len);
    while (search <= subject.len) {
        re2::StringView found;
        if (!regex.Match(
                CaptureProgram::view(text), search, text.len, re2::RE2::UNANCHORED, &found, 1))
            break;
        if (count == 64 || !found.data()) return 0;
        const i64 start_offset = found.data() - text.ptr;
        if (start_offset < search || start_offset > text.len) return 0;
        const u32 start = static_cast<u32>(start_offset);
        const auto available = range_int(text.len) - range_int(start);
        if (found.size() > static_cast<u64>(available.value())) return 0;
        const auto length = range_int(static_cast<u32>(found.size()));
        const u32 end = static_cast<u32>((range_int(start) + length).value());
        matches[count++] = {start, end};
        size += (range_int(replacement.len) - length).value();
        if (end == start) {
            if (end == text.len) break;
            search = static_cast<u32>(i64{end} + 1);
        } else
            search = end;
    }
    const i64 budget_remaining = static_cast<i64>(kStringArenaBudget) - (size ? size : i64{1});
    if (size > static_cast<i64>(kStringOutputLimit) ||
        arena.space_used() > static_cast<u64>(budget_remaining) ||
        (!arena.current && !arena.init(arena.backend.pool)))
        return 0;
    auto* data = static_cast<char*>(arena.alloc(static_cast<u64>(size ? size : 1)));
    if (!data) return 0;
    i64 copied = 0;
    i64 written = 0;
    for (u32 i = 0; i < count; ++i) {
        const auto match = matches[i];
        const i64 length = static_cast<i64>(match.start) - static_cast<i64>(copied);
        if (length) __builtin_memcpy(data + written, text.ptr + copied, length);
        written += length;
        if (replacement.len) __builtin_memcpy(data + written, replacement.ptr, replacement.len);
        written += static_cast<i64>(replacement.len);
        copied = static_cast<i64>(match.end);
    }
    if (static_cast<i64>(text.len) > copied)
        __builtin_memcpy(data + written, text.ptr + copied, static_cast<i64>(text.len) - copied);
    *output = {data, static_cast<u32>(size)};
    return 1;
}
}  // namespace rut
