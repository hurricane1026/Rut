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
    void bind(const u8* first, u32 first_len, const u8* second, u32 second_len) {
        first_source = first;
        second_source = second;
        first_size = first_len;
        total_size = first_len + second_len;
        message = {};
        parts[0] = {const_cast<u8*>(first), first_len};
        parts[1] = {const_cast<u8*>(second), second_len};
        message.msg_iov = parts;
        message.msg_iovlen = 2;
    }
    bool matches(const u8* first, u32 total) const {
        return message.msg_iov == parts && message.msg_iovlen == 2 && parts[0].iov_base == first &&
               parts[0].iov_len != 0 && parts[1].iov_base != nullptr && parts[1].iov_len != 0 &&
               parts[0].iov_len <= total && parts[1].iov_len == total - parts[0].iov_len;
    }
    void advance(u32 n) {
        while (n && message.msg_iovlen) {
            auto& part = *message.msg_iov;
            const u32 step = part.iov_len < n ? static_cast<u32>(part.iov_len) : n;
            part.iov_base = static_cast<u8*>(part.iov_base) + step;
            part.iov_len -= step;
            n -= step;
            if (part.iov_len == 0) {
                ++message.msg_iov;
                --message.msg_iovlen;
            }
        }
    }
};
}  // namespace rut
