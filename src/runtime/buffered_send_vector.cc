#include "rut/runtime/buffered_send_vector.h"

#include "rut/common/types.h"

namespace rut {
namespace {

// The oracle describes the unsent suffix from an absolute byte position. The
// production cursor advances relative to its previous iovec and remaining length.
consteval bool suffix_matches(
    const BufferedSendVector& v, const u8* first, u32 n, const u8* second, u32 m, u32 sent) {
    const i64 total = i64{n} + i64{m};
    if (v.first_source != first || v.first_size != n || v.second_source != second ||
        v.total_size != total)
        return false;
    if (sent < n)
        return v.message.msg_iov == v.parts && v.message.msg_iovlen == 2 &&
               v.parts[0].iov_base == first + i64{sent} &&
               v.parts[0].iov_len == static_cast<u64>(i64{n} - i64{sent}) &&
               v.parts[1].iov_base == second && v.parts[1].iov_len == m;
    if (sent < total)
        return v.message.msg_iov == v.parts + 1 && v.message.msg_iovlen == 1 &&
               v.parts[1].iov_base == second + (i64{sent} - i64{n}) &&
               v.parts[1].iov_len == static_cast<u64>(total - i64{sent});
    return v.message.msg_iov == v.parts + 2 && v.message.msg_iovlen == 0;
}

consteval bool vector_cursor_contract() {
    u8 first[4]{};
    u8 second[4]{};
    for (u32 n = 1; n <= sizeof(first); ++n) {
        for (u32 m = 1; m <= sizeof(second); ++m) {
            for (u32 start = 0; start <= i64{n} + i64{m}; ++start) {
                for (u32 end = start; end <= i64{n} + i64{m}; ++end) {
                    BufferedSendVector v{};
                    if (!v.bind(first, n, second, m)) return false;
                    if (!v.matches(first,
                                   static_cast<u32>(static_cast<i64>(n) + static_cast<i64>(m))))
                        return false;
                    if (!v.advance(start)) return false;
                    if (!suffix_matches(v, first, n, second, m, start)) return false;
                    if (!v.advance(
                            static_cast<u32>(static_cast<i64>(end) - static_cast<i64>(start))))
                        return false;
                    if (!suffix_matches(v, first, n, second, m, end)) return false;
                }
            }
        }
    }
    return true;
}
// advance() derives addresses from the pinned sources. A stale descriptor
// must therefore be rejected before relying on those sources for resubmission.
consteval bool vector_binding_contract() {
    u8 first[2]{};
    u8 second[2]{};
    BufferedSendVector v{};
    if (!v.bind(first, 2, second, 2)) return false;
    v.parts[1].iov_base = first;
    if (v.matches(first, 4)) return false;
    if (!v.bind(first, 2, second, 2)) return false;
    v.parts[0].iov_len = 1;
    v.parts[1].iov_len = 3;
    if (v.matches(first, 4)) return false;
    if (!v.bind(nullptr, 2, second, 2)) return false;
    return !v.matches(nullptr, 4);
}

consteval bool vector_overflow_is_reported() {
    u8 first[2]{};
    u8 second[2]{};
    BufferedSendVector v{};
    if (v.bind(first, UINT32_MAX, second, 1)) return false;
    if (!v.bind(first, 2, second, 2)) return false;
    v.parts[0].iov_len = 4;
    return !v.advance(1) && v.parts[0].iov_len == 4 && v.parts[0].iov_base == first;
}

static_assert(vector_overflow_is_reported());
static_assert(vector_binding_contract(), "Buffered send spans disagree with pinned sources");
static_assert(vector_cursor_contract(), "Buffered send cursor violates suffix contract");
}  // namespace
}  // namespace rut
