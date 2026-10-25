#include "rut/runtime/memory_http_cache_store.h"

namespace rut {

bool MemoryHttpCacheStore::matches(const Entry& entry, KeyView key) {
    return entry.config == key.config && entry.hash == key.hash && entry.key_len == key.len &&
           __builtin_memcmp(entry.key, key.bytes, key.len) == 0;
}
bool MemoryHttpCacheStore::find(KeyView key, Record& record) const {
    if (!key.bytes || key.len > kMaxKey) return false;
    const u32 kStart = static_cast<u32>(key.hash % (kCapacity / kWays)) * kWays;
    for (u32 i = kStart; i < kStart + kWays; ++i) {
        const auto& entry = entries_[i];
        if (entry.ready && matches(entry, key)) {
            record = {entry.response,
                      entry.response_len,
                      entry.stored_us,
                      entry.expires_us,
                      entry.initial_age_us};
            return true;
        }
    }
    return false;
}
MemoryHttpCacheStore::Token MemoryHttpCacheStore::reserve(KeyView key, u32 ttl, u64 now_us) {
    if (!key.bytes || key.len > kMaxKey || generation_ == ~u64{0}) return {};
    const u32 kStart = static_cast<u32>(key.hash % (kCapacity / kWays)) * kWays;
    u32 victim = kStart;
    for (u32 i = kStart; i < kStart + kWays; ++i) {
        const auto& entry = entries_[i];
        if (entry.ready && matches(entry, key)) {
            victim = i;
            break;
        }
        if ((!entry.ready && !entry.pending) || entry.generation < entries_[victim].generation)
            victim = i;
    }
    auto& entry = entries_[victim];
    entry.ready = entry.ready && matches(entry, key);
    entry.pending = true;
    entry.generation = ++generation_;
    entry.hash = key.hash;
    entry.config = key.config;
    entry.host = key.host;
    entry.fill = {now_us, ttl};
    entry.key_len = key.len;
    __builtin_memcpy(entry.key, key.bytes, key.len);
    return {entry.generation, victim};
}
bool MemoryHttpCacheStore::inspect(Token token, Fill& fill) const {
    if (!token.generation || token.slot >= kCapacity) return false;
    const auto& entry = entries_[token.slot];
    if (entry.generation != token.generation || !entry.pending) return false;
    fill = entry.fill;
    return true;
}
bool MemoryHttpCacheStore::publish(Token token, const Record& record) {
    Fill fill;
    if (!inspect(token, fill) || !record.response || record.response_len > kMaxResponse)
        return false;
    auto& entry = entries_[token.slot];
    __builtin_memcpy(entry.response, record.response, record.response_len);
    entry.response_len = record.response_len;
    entry.stored_us = record.stored_us;
    entry.expires_us = record.expires_us;
    entry.initial_age_us = record.initial_age_us;
    entry.pending = false;
    entry.ready = true;
    return true;
}
void MemoryHttpCacheStore::cancel(Token token) {
    Fill fill;
    if (inspect(token, fill)) entries_[token.slot].pending = false;
}
void MemoryHttpCacheStore::discard(Token token) {
    Fill fill;
    if (inspect(token, fill)) {
        entries_[token.slot].pending = false;
        entries_[token.slot].ready = false;
    }
}
void MemoryHttpCacheStore::invalidate_host(u64 config, u64 host) {
    for (auto& entry : entries_)
        if (entry.config == config && entry.host == host) {
            entry.ready = false;
            entry.pending = false;
        }
}

}  // namespace rut
