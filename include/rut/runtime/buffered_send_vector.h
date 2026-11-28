#pragma once
#include "rut/common/checked_arithmetic.h"
#include "rut/common/range_int.h"
#include "rut/common/types.h"

#include <sys/socket.h>
#include <sys/uio.h>
namespace rut {
// Two committed spans, pinned by the connection's existing Send owner.
struct BufferedSendVector {
    msghdr message{};
    iovec parts[2]{};
    const u8* first_source = nullptr;
    const u8* second_source = nullptr;
    u32 first_size = 0;
    u32 total_size = 0;
    [[nodiscard]] constexpr bool bind(const u8* first,
                                      u32 first_len,
                                      const u8* second,
                                      u32 second_len) {
        first_source = first;
        second_source = second;
        first_size = first_len;
        const auto total = range_int(first_len) + range_int(second_len);
        if (!total.to(&total_size)) {
            first_source = nullptr;
            second_source = nullptr;
            first_size = 0;
            total_size = 0;
            message = {};
            parts[0] = {};
            parts[1] = {};
            return false;
        }
        message = {};
        parts[0] = {const_cast<u8*>(first), first_len};
        parts[1] = {const_cast<u8*>(second), second_len};
        message.msg_iov = parts;
        message.msg_iovlen = 2;
        return true;
    }
    [[nodiscard]] constexpr bool matches(const u8* first, u32 total) const {
        u32 second_size;
        return first != nullptr && first_source == first && first_size == parts[0].iov_len &&
               second_source == parts[1].iov_base && total_size == total &&
               message.msg_iov == parts && message.msg_iovlen == 2 && parts[0].iov_base == first &&
               parts[0].iov_len != 0 && parts[1].iov_base != nullptr && parts[1].iov_len != 0 &&
               !sub_overflow(total, parts[0].iov_len, &second_size) &&
               parts[1].iov_len == second_size;
    }
    [[nodiscard]] constexpr bool advance(u32 n) {
        while (n && message.msg_iovlen) {
            auto& part = *message.msg_iov;
            const auto requested = range_int{n};
            const size_t kStep =
                part.iov_len < requested.to_u64() ? part.iov_len : requested.to_u64();
            const bool kFirst = &part == parts;
            const u8* source = kFirst ? first_source : second_source;
            u32 original_size = first_size;
            if (!kFirst && !(range_int{total_size} - range_int{first_size}).to(&original_size))
                return false;
            size_t remaining;
            u32 offset;
            u32 unsent;
            if (sub_overflow(part.iov_len, kStep, &remaining) ||
                sub_overflow(original_size, remaining, &offset) || sub_overflow(n, kStep, &unsent))
                return false;
            part.iov_len = remaining;
            part.iov_base = const_cast<u8*>(source + range_int{offset}.index());
            n = unsent;
            if (part.iov_len == 0) {
                ++message.msg_iov;
                --message.msg_iovlen;
            }
        }
        return n == 0;
    }
};
}  // namespace rut
