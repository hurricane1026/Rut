#include "rut/runtime/http_tokens.h"

#include "rut/common/http_header_validation.h"
#include "rut/common/range_int.h"
#include "rut/common/types.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

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
        while (offset < text.len && is_http_tchar(byte_value(text.ptr[offset]))) ++offset;
        if (offset == kStart || tokens.count == kMaxHttpTokenListItems) return false;
        tokens.values[tokens.count++] = text.slice(kStart, offset);
        while (offset < text.len && (text.ptr[offset] == ' ' || text.ptr[offset] == '\t')) ++offset;
        if (offset == text.len) return true;
        if (text.ptr[offset++] != ',') return false;
        while (offset < text.len && (text.ptr[offset] == ' ' || text.ptr[offset] == '\t')) ++offset;
        if (offset == text.len) return false;
    }
    return true;
}

bool valid_origin(Str origin) {
    if (!origin.ptr || !origin.len || origin.len > 2048) return false;
    if (origin.eq(lit_str("null"))) return true;
    u32 start = 0;
    if (origin.len > 7 && Str{origin.ptr, 7}.eq(lit_str("http://"))) start = 7;
    if (origin.len > 8 && Str{origin.ptr, 8}.eq(lit_str("https://"))) start = 8;
    if (!start) return false;
    u32 end = start;
    if (origin.ptr[start] == '[') {
        while (end < origin.len && origin.ptr[end] != ']') ++end;
        if (end == origin.len) return false;
        ++start;
        const Str literal = origin.slice(start, end);
        if (literal.empty() || literal.len >= INET6_ADDRSTRLEN) return false;
        for (u32 i = 0; i < literal.len; ++i) {
            const char kC = literal.ptr[i];
            const bool kHex =
                (kC >= '0' && kC <= '9') || (kC >= 'a' && kC <= 'f') || (kC >= 'A' && kC <= 'F');
            if (!kHex && kC != ':' && kC != '.') return false;
        }
        char address[INET6_ADDRSTRLEN]{};
        __builtin_memcpy(address, literal.ptr, literal.len);
        in6_addr parsed{};
        if (inet_pton(AF_INET6, address, &parsed) != 1) return false;
        ++end;
    } else {
        u32 label_start = start;
        while (end < origin.len && origin.ptr[end] != ':') {
            const char kC = origin.ptr[end];
            if (kC == '.') {
                if (end == label_start || *(origin.ptr + range_int{end}.index() - 1) == '-')
                    return false;
                label_start = end;
                ++label_start;
            } else {
                const bool kAlnum = (kC >= 'a' && kC <= 'z') || (kC >= 'A' && kC <= 'Z') ||
                                    (kC >= '0' && kC <= '9');
                if (!kAlnum && (kC != '-' || end == label_start)) return false;
            }
            ++end;
        }
        if (end == start || end == label_start) return false;
        if (*(origin.ptr + range_int{end}.index() - 1) == '-') return false;
    }
    if (end == origin.len) return true;
    if (origin.ptr[end] != ':') return false;
    if (++end == origin.len) return false;
    u16 port = 0;
    for (; end < origin.len; ++end) {
        using Digit = range_int<0, 10>;
        Digit digit;
        const auto byte = range_int{byte_value(origin.ptr[end])};
        if (!Digit::try_from_i64((byte - range_int<'0', '0' + 1>{}).value(), &digit) ||
            !(range_int{port}.scaled_by<10>() + digit).to(&port))
            return false;
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

bool http_origin_list_allows(Str allowed, Str origin, bool credentials) {
    if (!allowed.ptr || !allowed.len || allowed.len > kMaxHttpTokenListBytes ||
        (origin.len && !origin.ptr))
        return false;
    if (origin.len && !valid_origin(origin)) return false;
    if (allowed.eq(lit_str("*"))) return !credentials;
    bool found = origin.len == 0;
    u32 offset = 0;
    u32 count = 0;
    while (offset < allowed.len) {
        while (offset < allowed.len && (allowed.ptr[offset] == ' ' || allowed.ptr[offset] == '\t'))
            ++offset;
        const u32 kStart = offset;
        while (offset < allowed.len && allowed.ptr[offset] != ',') ++offset;
        u32 end = offset;
        while (end > kStart) {
            const char last = *(allowed.ptr + range_int{end}.index() - 1);
            if (last != ' ' && last != '\t') break;
            --end;
        }
        const Str kItem = allowed.slice(kStart, end);
        if (++count > 32 || !valid_origin(kItem)) return false;
        found |= kItem.eq(origin);
        if (offset == allowed.len) return found;
        if (++offset == allowed.len) return false;
    }
    return false;
}

}  // namespace rut
