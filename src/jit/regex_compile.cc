#include "rut/jit/runtime_helpers.h"

#include <hs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

using namespace rut;
namespace {
thread_local char t_regex_compile_error[256] = "";
static void set_regex_compile_error(const char* msg) {
    if (!msg) msg = "regex compilation failed";
    snprintf(t_regex_compile_error, sizeof(t_regex_compile_error), "%s", msg);
}

}  // namespace

void* rut_helper_regex_compile(const char* pattern, u32 pattern_len) {
    t_regex_compile_error[0] = '\0';
    if (!pattern) {
        set_regex_compile_error("missing regex pattern");
        return nullptr;
    }
    char* nul_pattern = static_cast<char*>(malloc(static_cast<size_t>(pattern_len) + 7));
    if (!nul_pattern) {
        set_regex_compile_error("out of memory while preparing regex pattern");
        return nullptr;
    }
    nul_pattern[0] = '^';
    nul_pattern[1] = '(';
    nul_pattern[2] = '?';
    nul_pattern[3] = ':';
    memcpy(nul_pattern + 4, pattern, pattern_len);
    nul_pattern[pattern_len + 4] = ')';
    nul_pattern[pattern_len + 5] = '$';
    nul_pattern[pattern_len + 6] = '\0';

    hs_database_t* db = nullptr;
    hs_compile_error_t* compile_error = nullptr;
    hs_error_t rc =
        hs_compile(nul_pattern, HS_FLAG_SINGLEMATCH, HS_MODE_BLOCK, nullptr, &db, &compile_error);
    free(nul_pattern);
    if (rc != 0 || !db) {
        set_regex_compile_error(compile_error ? compile_error->message : nullptr);
        if (compile_error) hs_free_compile_error(compile_error);
        return nullptr;
    }
    void* handle = rut_helper_regex_adopt(db);
    if (!handle) set_regex_compile_error("cannot allocate regex handle");
    return handle;
}

const char* rut_helper_regex_last_compile_error() {
    return t_regex_compile_error[0] ? t_regex_compile_error : nullptr;
}
