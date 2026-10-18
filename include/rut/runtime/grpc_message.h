#pragma once

#include "rut/common/types.h"

namespace rut {
// Incremental gRPC envelope accounting. Payloads (including compressed bytes)
// are skipped without buffering or decoding protobuf. A zero limit disables it.
struct GrpcMessageLimit {
    u32 limit;
    u32 remaining;
    u8 header_bytes;

    void init(u32 maximum = 0) {
        limit = maximum;
        remaining = 0;
        header_bytes = 0;
    }
    // gRPC status: RESOURCE_EXHAUSTED for size, INTERNAL for invalid/truncated framing.
    u8 feed(const u8* data, u32 len, bool end) {
        if (!limit) return 0;
        while (len) {
            if (header_bytes < 5) {
                const u8 byte = *data++;
                len--;
                if (!header_bytes) {
                    if (byte > 1) return 13;
                } else {
                    remaining = (remaining << 8) | byte;
                }
                header_bytes++;
                if (header_bytes < 5) continue;
                if (remaining > limit) return 8;
            }
            const u32 amount = len < remaining ? len : remaining;
            data += amount;
            len -= amount;
            remaining -= amount;
            if (!remaining) header_bytes = 0;
        }
        // A zero-length message may finish on the last byte of its header.
        if (header_bytes == 5 && !remaining) header_bytes = 0;
        return end && (header_bytes || remaining) ? 13 : 0;
    }
};
}  // namespace rut
