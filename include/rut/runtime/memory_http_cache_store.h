#pragma once

#include "rut/runtime/http_cache_store.h"

namespace rut {

// Fixed bounded storage; no HTTP parsing or freshness decisions here.
struct MemoryHttpCacheStore : HttpCacheStorage {
    static constexpr u32 kCapacity = 64;
    static constexpr u32 kWays = 4;

private:
    struct Entry {
        u64 generation = 0;
        u64 hash = 0;
        u64 config = 0;
        u64 host = 0;
        Fill fill{};
        u64 stored_us = 0;
        u64 expires_us = 0;
        u64 initial_age_us = 0;
        u32 key_len = 0;
        u32 response_len = 0;
        bool pending = false;
        bool ready = false;
        char key[kMaxKey];
        u8 response[kMaxResponse];
    };
    Entry entries_[kCapacity]{};
    u64 generation_ = 0;
    static bool matches(const Entry& entry, KeyView key);

public:
    bool find(KeyView key, Record& record) const;
    Token reserve(KeyView key, u32 ttl, u64 now_us);
    bool inspect(Token token, Fill& fill) const;
    bool publish(Token token, const Record& record);
    void cancel(Token token);
    void discard(Token token);
    void invalidate_host(u64 config, u64 host);
};

}  // namespace rut
