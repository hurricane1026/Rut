#pragma once

#include "rut/common/types.h"
#include <atomic>

#include <sys/mman.h>
#include <sys/random.h>
#include <time.h>

// Cache<K, i64> substrate — per-shard lossy per-key state slots
// (docs/state-types.md). This is deliberately NOT a general hash map:
// under fixed capacity a colliding `set` may evict a neighbor at any
// occupancy, so a miss on `get` means "never seen OR evicted" and callers
// must treat the two identically (the .rut surface enforces this via the
// Optional return — there is no way to skip the miss branch).
//
// Organization: 4-way set-associative, one set = 4 × 16 B slots = exactly
// one cache line, so lookup/update touch a single line — the same cost as
// direct mapping — while two hot keys resetting each other ("ping-pong",
// which for rate limiting is a bypass) needs a five-way pile-up instead of
// a birthday collision. Victim on a full set: the min-value slot — for
// GCRA the smallest tat is the most-idle key, for packed sliding windows
// the smallest value is the oldest window; deterministic and metadata-free.
//
// The key mix is seeded per process (getrandom at first publish) so an
// attacker cannot precompute colliding key sets — a hash-flood defense,
// not an optimization.
namespace rut {

struct CacheTable {
    struct Slot {
        u64 key_hash;  // full mixed hash; 0 = empty (mix() never returns 0)
        i64 value;
    };
    static constexpr u32 kWays = 4;  // set = 64 B = one cache line

    Slot* slots = nullptr;  // mmap'd; value-zeroed = all-empty
    u32 slot_count = 0;     // power of two, >= kWays
    u32 set_count = 0;      // slot_count / kWays, power of two
    u64 seed = 0;

    // capacity == slot count, rounded UP to the next power of two (min 4).
    // Provisioning headroom (e.g. 2× the expected key count) is the
    // declarer's job — the table never grows.
    static u32 round_capacity(u32 requested) {
        u32 c = requested < kWays ? kWays : requested;
        c--;
        c |= c >> 1;
        c |= c >> 2;
        c |= c >> 4;
        c |= c >> 8;
        c |= c >> 16;
        return c + 1;
    }

    bool init(u32 requested_capacity, u64 mix_seed) {
        destroy();
        const u32 count = round_capacity(requested_capacity);
        void* mem = ::mmap(nullptr,
                           static_cast<u64>(count) * sizeof(Slot),
                           PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS,
                           -1,
                           0);
        if (mem == MAP_FAILED) return false;
        slots = static_cast<Slot*>(mem);
        slot_count = count;
        set_count = count / kWays;
        seed = mix_seed;
        return true;
    }

    void destroy() {
        if (slots != nullptr) ::munmap(slots, static_cast<u64>(slot_count) * sizeof(Slot));
        slots = nullptr;
        slot_count = 0;
        set_count = 0;
    }

    // Seeded multiply-mix (splitmix64 finalizer shape). Forced non-zero so
    // 0 stays the empty-slot sentinel.
    static u64 mix(u32 key, u64 mix_seed) {
        u64 h = (static_cast<u64>(key) ^ mix_seed) * 0x9E3779B97F4A7C15ull;
        h ^= h >> 29;
        h *= 0xBF58476D1CE4E5B9ull;
        h ^= h >> 32;
        return h == 0 ? 1 : h;
    }

    bool get(u32 key, i64* out) const {
        if (slots == nullptr) return false;
        const u64 h = mix(key, seed);
        Slot* set = slots + (h & (set_count - 1)) * kWays;
        for (u32 w = 0; w < kWays; w++) {
            if (set[w].key_hash == h) {
                *out = set[w].value;
                return true;
            }
        }
        return false;
    }

    void set(u32 key, i64 value) {
        if (slots == nullptr) return;
        const u64 h = mix(key, seed);
        Slot* set = slots + (h & (set_count - 1)) * kWays;
        u32 victim = 0;
        for (u32 w = 0; w < kWays; w++) {
            if (set[w].key_hash == h) {  // match → update in place
                set[w].value = value;
                return;
            }
            if (set[w].key_hash == 0) {  // empty → insert
                set[w].key_hash = h;
                set[w].value = value;
                return;
            }
            if (set[w].value < set[victim].value) victim = w;
        }
        // Full set → evict the min-value slot (most-idle under GCRA tats,
        // oldest window under packed sliding windows).
        set[victim].key_hash = h;
        set[victim].value = value;
    }
};

// Process-global descriptors for the declared Cache instances. Published by
// the loader after a config compiles; each shard thread lazily (re)builds
// its thread_local tables against these on first touch.
//
// Ordering contract: publish stores seed, identities, capacities and count
// first, then release-stores `generation`; readers acquire-load `generation`
// FIRST, so a reader that observes a generation observes every descriptor
// published with it (never a nonzero count with a zero seed or a stale
// capacity). The generation also gives thread-local tables an invalidation
// signal: on a new generation each shard drops tables whose instance
// disappeared, changed identity (rename/reorder), or changed capacity —
// state persists across reloads only for declarations that stayed
// identical, and stale tables are unmapped instead of leaking.
struct CacheRegistry {
    static constexpr u32 kMaxInstances = 8;
    std::atomic<u32> generation{0};  // 0 = never published
    std::atomic<u32> count{0};
    std::atomic<u32> capacities[kMaxInstances]{};
    std::atomic<u64> identities[kMaxInstances]{};  // FNV-1a of the decl name
    std::atomic<u64> seed{0};                      // 0 = unseeded sentinel
};

inline CacheRegistry& cache_registry() {
    static CacheRegistry reg;
    return reg;
}

// FNV-1a of the declaration name — the instance's identity across reloads.
// Never returns 0 (0 marks an empty thread-local identity slot).
inline u64 cache_instance_identity(const char* name, u32 name_len) {
    u64 h = 0xCBF29CE484222325ull;
    for (u32 i = 0; i < name_len; i++) {
        h ^= static_cast<u8>(name[i]);
        h *= 0x100000001B3ull;
    }
    return h == 0 ? 1 : h;
}

// Test hook — must run before any shard touches its tables.
inline void cache_registry_set_seed(u64 seed) {
    cache_registry().seed.store(seed, std::memory_order_relaxed);
}

inline void cache_registry_publish(const u32* capacities, const u64* identities, u32 count) {
    auto& reg = cache_registry();
    if (count > CacheRegistry::kMaxInstances) count = CacheRegistry::kMaxInstances;
    if (reg.seed.load(std::memory_order_relaxed) == 0) {
        // getrandom can be interrupted (EINTR) — retry; it only blocks
        // pre-entropy-pool-init on ancient boots. If it still fails, mix
        // ASLR'd addresses with the clock rather than publishing a public
        // constant (a fixed seed would let colliding key sets be
        // precomputed against Cache-backed rate limits).
        u64 s = 0;
        for (int tries = 0; tries < 16 && s == 0; tries++) {
            if (::getrandom(&s, sizeof(s), 0) != static_cast<long>(sizeof(s))) s = 0;
        }
        if (s == 0) {
            struct timespec ts{};
            clock_gettime(CLOCK_MONOTONIC, &ts);
            const u64 a = reinterpret_cast<u64>(&reg);
            const u64 b = reinterpret_cast<u64>(&reg.seed);
            s = CacheTable::mix(static_cast<u32>(a ^ (a >> 32)),
                                b ^ (static_cast<u64>(ts.tv_nsec) * 0x9E3779B97F4A7C15ull));
        }
        reg.seed.store(s, std::memory_order_relaxed);
    }
    for (u32 i = 0; i < count; i++) {
        reg.capacities[i].store(capacities[i], std::memory_order_relaxed);
        reg.identities[i].store(identities[i], std::memory_order_relaxed);
    }
    reg.count.store(count, std::memory_order_relaxed);
    // Release-publish: pairs with the acquire load in cache_table_for.
    reg.generation.fetch_add(1, std::memory_order_release);
}

}  // namespace rut
