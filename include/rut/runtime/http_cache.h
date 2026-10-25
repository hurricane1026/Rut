#pragma once

#include "rut/runtime/memory_http_cache_store.h"

namespace rut {

// HTTP semantics are independent of storage layout and eviction policy.
struct HttpCachePolicy : HttpCacheStorage {
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
    enum class Result : u8 { Bypass, Miss, Hit, OnlyCachedMiss };
    static bool make_key(
        const u8* request, u32 length, u64 config, u32 route, bool tls, u32 peer, Key& key);
    static bool response_can_buffer(const u8* response, u32 length, u32& total);
    static bool read_response(const Key& key,
                              const Record& record,
                              u64 now_us,
                              bool keep_alive,
                              u8* output,
                              u32 capacity,
                              u32& written);
    static bool prepare_record(
        const Fill& fill, const u8* response, u32 length, u64 now_us, u64 wall_us, Record& record);
};

// Store implements the contract in http_cache_store.h. Selection is compile-time:
// no virtual dispatch, allocation or backend I/O is introduced by this wrapper.
template <typename Store>
class HttpResponseCache : public HttpCachePolicy {
    Store storage_{};

public:
    Result begin(const Key& key,
                 u32 ttl,
                 u64 now_us,
                 bool keep_alive,
                 u8* output,
                 u32 capacity,
                 u32& written,
                 Token& token) {
        written = 0;
        token = {};
        if (!key.eligible || !ttl || ttl > kMaxTtl || !output)
            return key.only_cached && ttl ? Result::OnlyCachedMiss : Result::Bypass;
        const KeyView kStorageKey{key.bytes, key.len, key.hash, key.config, key.host};
        Record record;
        if (storage_.find(kStorageKey, record) &&
            read_response(key, record, now_us, keep_alive, output, capacity, written))
            return Result::Hit;
        written = 0;
        if (key.only_cached) return Result::OnlyCachedMiss;
        token = storage_.reserve(kStorageKey, ttl, now_us);
        return token.generation ? Result::Miss : Result::Bypass;
    }
    bool commit(Token token, const u8* response, u32 length, u64 now_us, u64 wall_us) {
        Fill fill;
        if (!storage_.inspect(token, fill)) return false;
        Record record;
        if (!prepare_record(fill, response, length, now_us, wall_us, record) ||
            !storage_.publish(token, record)) {
            storage_.discard(token);
            return false;
        }
        return true;
    }
    bool pending(Token token) const {
        Fill fill;
        return storage_.inspect(token, fill);
    }
    void cancel(Token token) { storage_.cancel(token); }
    void invalidate_host(u64 config, u64 host) { storage_.invalidate_host(config, host); }
};

using HttpCache = HttpResponseCache<MemoryHttpCacheStore>;
HttpCache& local_http_cache();
u64 http_cache_config_identity();
u64 http_cache_wall_us();

}  // namespace rut
