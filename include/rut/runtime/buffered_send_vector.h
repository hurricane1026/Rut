#pragma once
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
    constexpr void bind(const u8* first, u32 first_len, const u8* second, u32 second_len) {
        first_source = first;
        second_source = second;
        first_size = first_len;
        const i64 total = static_cast<i64>(first_len) + static_cast<i64>(second_len);
        if (total > static_cast<i64>(UINT32_MAX)) {
            first_source = nullptr;
            second_source = nullptr;
            first_size = 0;
            total_size = 0;
            message = {};
            parts[0] = {};
            parts[1] = {};
            return;
        }
        total_size = static_cast<u32>(total);
        message = {};
        parts[0] = {const_cast<u8*>(first), first_len};
        parts[1] = {const_cast<u8*>(second), second_len};
        message.msg_iov = parts;
        message.msg_iovlen = 2;
    }
    constexpr bool matches(const u8* first, u32 total) const {
        return first != nullptr && first_source == first && first_size == parts[0].iov_len &&
               second_source == parts[1].iov_base && total_size == total &&
               message.msg_iov == parts && message.msg_iovlen == 2 && parts[0].iov_base == first &&
               parts[0].iov_len != 0 && parts[1].iov_base != nullptr && parts[1].iov_len != 0 &&
               parts[0].iov_len <= total &&
               parts[1].iov_len ==
                   static_cast<u64>(static_cast<i64>(total) - static_cast<i64>(parts[0].iov_len));
    }
    constexpr void advance(u32 n) {
        while (n && message.msg_iovlen) {
            auto& part = *message.msg_iov;
            const u32 step = part.iov_len < n ? static_cast<u32>(part.iov_len) : n;
            part.iov_len -= step;
            const bool first = &part == parts;
            const u8* source = first ? first_source : second_source;
            const u32 size = first ? first_size : total_size - first_size;
            // bind() gives this span its full size. Only the remaining length shrinks.
            part.iov_base = const_cast<u8*>(source + (size - part.iov_len));
            n -= step;
            if (part.iov_len == 0) {
                ++message.msg_iov;
                --message.msg_iovlen;
            }
        }
    }
};
}  // namespace rut
