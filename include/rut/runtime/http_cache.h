#pragma once

#include "rut/common/types.h"

namespace rut {

// Public GET cache. All storage is shard-owned and bounded; cache bytes never
// become async I/O sources: lookup copies into the caller's owned send buffer.
struct HttpCache {
    static constexpr u32 kCapacity = 64;
    static constexpr u32 kWays = 4;
    static constexpr u32 kMaxKey = 2048;
    static constexpr u32 kMaxResponse = 16 * 1024;
    static constexpr u32 kMaxTtl = 86400;
    struct Key {
        char bytes[kMaxKey];
        u32 len = 0;
        u64 hash = 0;
        u64 config = 0;
        u64 host = 0;
        bool eligible = false;
        bool http10 = false;
        bool unsafe = false;
        bool only_cached = false;
        u32 max_age = 0xffffffffu;
        u32 min_fresh = 0;
    };
    struct Token {
        u64 generation = 0;
        u32 slot = 0;
    };
    enum class Result : u8 { Bypass, Miss, Hit, OnlyCachedMiss };
    struct Entry {
        u64 generation = 0;
        u64 hash = 0;
        u64 config = 0;
        u64 host = 0;
        u64 started_us = 0;
        u64 stored_us = 0;
        u64 expires_us = 0;
        u64 initial_age_us = 0;
        u32 ttl = 0;
        u32 key_len = 0;
        u32 response_len = 0;
        bool pending = false;
        bool ready = false;
        char key[kMaxKey];
        u8 response[kMaxResponse];
    };
    Entry entries[kCapacity]{};
    u64 generation = 0;

    static bool make_key(
        const u8* request, u32 length, u64 config, u32 route, bool tls, u32 peer, Key& key);
    static bool response_can_buffer(const u8* response, u32 length, u32& total);
    Result begin(const Key& key,
                 u32 ttl,
                 u64 now_us,
                 bool keep_alive,
                 u8* output,
                 u32 capacity,
                 u32& output_len,
                 Token& token);
    bool commit(Token token, const u8* response, u32 length, u64 now_us, u64 wall_us);
    void cancel(Token token);
    void invalidate_host(u64 config, u64 host);
    bool pending(Token token) const;
};

HttpCache& local_http_cache();
u64 http_cache_config_identity();
u64 http_cache_wall_us();

}  // namespace rut
