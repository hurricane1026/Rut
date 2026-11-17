#include "rut/runtime/regex_capture.h"

#include "core/placement_new.h"
#include "rut/common/types.h"
#include "rut/runtime/arena.h"

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
                     static_cast<int>(group + 1)))
        return 0;
    const auto kCapture = captures[group];
    if (!kCapture.data()) return 0;
    *output = {kCapture.data(), static_cast<u32>(kCapture.size())};
    return 1;
}
}  // namespace rut
