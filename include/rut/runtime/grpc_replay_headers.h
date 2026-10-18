#pragma once

#include "rut/runtime/hpack.h"

namespace rut {

// Own the final outbound metadata independently of a connection's HPACK table
// and the decoded input's lifetime. Views returned by materialize are used only
// while encoding an attempt; capture/clear invalidates them.
struct GrpcReplayHeaders {
    static constexpr u32 kMaxHeaders = 64;
    static constexpr u32 kBytes = 16384;
    struct Field {
        u16 name_offset;
        u16 name_len;
        u16 value_offset;
        u16 value_len;
    };
    Field fields[kMaxHeaders]{};
    u8 bytes[kBytes]{};
    u32 count = 0;
    u32 size = 0;
    bool valid = false;

    void clear() {
        count = size = 0;
        valid = false;
    }

    bool capture(const hpack::Header* headers, u32 n) {
        clear();
        if (n > kMaxHeaders) return false;
        for (u32 i = 0; i < n; ++i) {
            const auto& h = headers[i];
            if (h.name.len > kBytes - size || h.value.len > kBytes - size - h.name.len) {
                clear();
                return false;
            }
            auto& field = fields[i];
            field.name_offset = static_cast<u16>(size);
            field.name_len = static_cast<u16>(h.name.len);
            if (h.name.len) __builtin_memcpy(bytes + size, h.name.ptr, h.name.len);
            size += h.name.len;
            field.value_offset = static_cast<u16>(size);
            field.value_len = static_cast<u16>(h.value.len);
            if (h.value.len) __builtin_memcpy(bytes + size, h.value.ptr, h.value.len);
            size += h.value.len;
        }
        count = n;
        valid = true;
        return true;
    }

    bool materialize(hpack::Header* out, u32 capacity, u32& written) const {
        written = 0;
        if (!valid || count > kMaxHeaders || count > capacity || size > kBytes) return false;
        // Validate the whole snapshot before publishing any borrowed views.
        for (u32 i = 0; i < count; ++i) {
            const auto& f = fields[i];
            if (f.name_offset > size || f.name_len > size - f.name_offset ||
                f.value_offset > size || f.value_len > size - f.value_offset)
                return false;
        }
        for (u32 i = 0; i < count; ++i) {
            const auto& f = fields[i];
            out[i] = {{reinterpret_cast<const char*>(bytes + f.name_offset), f.name_len},
                      {reinterpret_cast<const char*>(bytes + f.value_offset), f.value_len}};
        }
        written = count;
        return true;
    }
};

}  // namespace rut
