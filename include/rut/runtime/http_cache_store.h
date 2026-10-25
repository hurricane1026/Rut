#pragma once

#include "rut/common/types.h"

namespace rut {

// Shared data contract for HTTP response storage. Stores treat response bytes and
// freshness metadata as opaque; HTTP parsing and policy live in HttpCachePolicy.
struct HttpCacheStorage {
    static constexpr u32 kMaxKey = 2048;
    static constexpr u32 kMaxResponse = 16 * 1024;
    struct Token {
        u64 generation = 0;
        u32 slot = 0;
    };
    struct KeyView {
        const char* bytes;
        u32 len;
        u64 hash;
        u64 config;
        u64 host;
    };
    struct Fill {
        u64 started_us;
        u32 ttl;
    };
    struct Record {
        const u8* response;
        u32 response_len;
        u64 stored_us;
        u64 expires_us;
        u64 initial_age_us;
    };
};

// Compile-time Store contract (all calls are nonblocking and complete inline):
//   bool find(KeyView, Record&) const       -- miss/unavailable => false
//   Token reserve(KeyView, u32 ttl, u64 now)-- copy key; failure => zero token
//   bool inspect(Token, Fill&) const       -- true only for a live fill
//   bool publish(Token, const Record&)     -- copy bytes before returning
//   void cancel(Token)                     -- cancel fill, preserve prior record
//   void discard(Token)                    -- cancel fill and discard prior record
//   void invalidate_host(u64 config, u64 host) -- invalidate records AND fills
//
// A find result borrows storage until the next non-const store operation. The
// HTTP layer copies it into caller-owned output before then. KeyView and publish
// inputs are borrowed only for the duration of their calls. Implementations must
// reject stale tokens on every mutation, including after eviction/invalidation.
// Each instance belongs to one shard. This inline contract does not permit
// blocking disk/network I/O: external stores will need an asynchronous submission
// and completion adapter with owned buffers and connection cancellation handling.

}  // namespace rut
