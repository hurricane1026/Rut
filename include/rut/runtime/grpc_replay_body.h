#pragma once

#include "rut/runtime/response_body_chain.h"

namespace rut {

// An optional immutable copy of native request bytes. Retention failure only
// disables replay: the original streaming request keeps its own flow control.
// The cursor stays inside its owner so release cannot leave a dangling reader.
struct GrpcReplayBody {
    ResponseBodyChain storage{};
    const ResponseBodyChain::Node* cursor = nullptr;
    u32 cursor_offset = 0;
    u32 remaining = 0;
    u32 limit = 0;
    bool replayable = false;
    bool sealed = false;

    void release() {
        cursor = nullptr;
        cursor_offset = remaining = limit = 0;
        replayable = sealed = false;
        storage.release();
    }

    bool init(u32 cap) {
        release();
        if (cap == 0 || cap > ResponseBodyChain::kMaxBody) return false;
        limit = cap;
        replayable = true;
        return true;
    }

    bool append(SlicePool& pool, const u8* bytes, u32 len) {
        if (!replayable || sealed) return false;
        if (len > limit - storage.size || !storage.append(pool, bytes, len)) {
            release();
            return false;
        }
        return true;
    }

    bool rewind() {
        if (!replayable || !sealed) return false;
        cursor = storage.head;
        cursor_offset = 0;
        remaining = storage.size;
        return true;
    }

    // Caller seals only after the complete downstream request has ended.
    bool seal() {
        if (!replayable) return false;
        if (sealed) return true;
        sealed = true;
        return rewind();
    }

    u32 copy(u8* out, u32 capacity) {
        if (!replayable || !sealed) return 0;
        const u32 count = capacity < remaining ? capacity : remaining;
        u32 copied = 0;
        while (copied < count) {
            const u32 available = cursor->len - cursor_offset;
            const u32 n = count - copied < available ? count - copied : available;
            __builtin_memcpy(out + copied, ResponseBodyChain::payload(cursor) + cursor_offset, n);
            copied += n;
            cursor_offset += n;
            if (cursor_offset == cursor->len) {
                cursor = cursor->next;
                cursor_offset = 0;
            }
        }
        remaining -= copied;
        return copied;
    }
};

}  // namespace rut
