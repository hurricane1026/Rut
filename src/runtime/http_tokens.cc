#include "rut/runtime/http_tokens.h"

#include "rut/common/http_header_validation.h"
#include "rut/common/types.h"

namespace rut {
namespace {

struct Tokens {
    Str values[kMaxHttpTokenListItems];
    u32 count = 0;
};
bool parse_tokens(Str text, Tokens& tokens) {
    if (text.len > kMaxHttpTokenListBytes || (text.len && !text.ptr)) return false;
    u32 offset = 0;
    while (offset < text.len && (text.ptr[offset] == ' ' || text.ptr[offset] == '\t')) ++offset;
    if (offset == text.len) return true;
    while (offset < text.len) {
        const u32 kStart = offset;
        while (offset < text.len && is_http_tchar(static_cast<u8>(text.ptr[offset]))) ++offset;
        if (offset == kStart || tokens.count == kMaxHttpTokenListItems) return false;
        tokens.values[tokens.count++] = {text.ptr + kStart, offset - kStart};
        while (offset < text.len && (text.ptr[offset] == ' ' || text.ptr[offset] == '\t')) ++offset;
        if (offset == text.len) return true;
        if (text.ptr[offset++] != ',') return false;
        while (offset < text.len && (text.ptr[offset] == ' ' || text.ptr[offset] == '\t')) ++offset;
        if (offset == text.len) return false;
    }
    return true;
}

}  // namespace

bool http_token_list_allows(Str allowed, Str requested, bool case_sensitive) {
    Tokens allow{}, request{};
    if (!parse_tokens(allowed, allow) || !parse_tokens(requested, request)) return false;
    for (u32 i = 0; i < request.count; ++i) {
        bool found = false;
        for (u32 j = 0; j < allow.count; ++j) {
            const Str kA = allow.values[j];
            const Str kB = request.values[i];
            found |=
                case_sensitive ? kA.eq(kB) : http_header_name_eq_ci(kA.ptr, kA.len, kB.ptr, kB.len);
        }
        if (!found) return false;
    }
    return true;
}

}  // namespace rut
