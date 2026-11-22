#include "rut/runtime/buffered_send_vector.h"

#include "rut/common/types.h"

namespace rut {
namespace {

// The oracle describes the unsent suffix from an absolute byte position. The
// production cursor advances relative to its previous iovec and remaining length.
consteval bool suffix_matches(
    const BufferedSendVector& v, const u8* first, u32 n, const u8* second, u32 m, u32 sent) {
    const u64 total = static_cast<u64>(n) + m;
    if (v.first_source != first || v.first_size != n || v.second_source != second ||
        v.total_size != total)
        return false;
    if (sent < n)
        return v.message.msg_iov == v.parts && v.message.msg_iovlen == 2 &&
               v.parts[0].iov_base == first + sent && v.parts[0].iov_len == n - sent &&
               v.parts[1].iov_base == second && v.parts[1].iov_len == m;
    if (sent < total)
        return v.message.msg_iov == v.parts + 1 && v.message.msg_iovlen == 1 &&
               v.parts[1].iov_base == second + (sent - n) && v.parts[1].iov_len == total - sent;
    return v.message.msg_iov == v.parts + 2 && v.message.msg_iovlen == 0;
}

consteval bool vector_cursor_contract() {
    u8 first[4]{};
    u8 second[4]{};
    for (u32 n = 1; n <= sizeof(first); ++n) {
        for (u32 m = 1; m <= sizeof(second); ++m) {
            for (u32 start = 0; start <= n + m; ++start) {
                for (u32 end = start; end <= n + m; ++end) {
                    BufferedSendVector v{};
                    v.bind(first, n, second, m);
                    if (!v.matches(first, n + m)) return false;
                    v.advance(start);
                    if (!suffix_matches(v, first, n, second, m, start)) return false;
                    v.advance(end - start);
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
    v.bind(first, 2, second, 2);
    v.parts[1].iov_base = first;
    if (v.matches(first, 4)) return false;
    v.bind(first, 2, second, 2);
    v.parts[0].iov_len = 1;
    v.parts[1].iov_len = 3;
    if (v.matches(first, 4)) return false;
    v.bind(nullptr, 2, second, 2);
    return !v.matches(nullptr, 4);
}

static_assert(vector_binding_contract(), "Buffered send spans disagree with pinned sources");
static_assert(vector_cursor_contract(), "Buffered send cursor violates suffix contract");
}  // namespace
}  // namespace rut
