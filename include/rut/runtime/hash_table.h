#pragma once

#include "rut/common/types.h"
#include <initializer_list>

#include <sys/mman.h>

namespace rut {

enum class HashSetResult : u8 { Inserted, Updated, Full, PlacementLimit, Uninitialized };

// Fixed-capacity strict table substrate. Unlike CacheTable, insertion never
// evicts an unrelated key. Relocations are recorded in bounded stack storage
// and committed only after the search reaches a free slot.
struct HashTable {
    struct Slot {
        u32 key = 0;
        u32 occupied = 0;
        i64 value = 0;
    };

    static constexpr u32 kWays = 4;
    static constexpr u32 kRelocationNodes = 64;
    Slot* slots = nullptr;
    u32 slot_count = 0;
    u32 bucket_count = 0;
    u32 size = 0;
    u64 seed = 0;

    HashTable() = default;
    ~HashTable() { destroy(); }
    HashTable(const HashTable&) = delete;
    HashTable& operator=(const HashTable&) = delete;

    static u32 round_capacity(u32 requested) {
        if (requested > (1u << 30)) return 0;
        const u32 needed_buckets = (requested + kWays - 1) / kWays;
        u32 buckets = needed_buckets < 2 ? 2 : needed_buckets;
        buckets--;
        buckets |= buckets >> 1;
        buckets |= buckets >> 2;
        buckets |= buckets >> 4;
        buckets |= buckets >> 8;
        buckets |= buckets >> 16;
        return (buckets + 1) * kWays;
    }

    bool init(u32 requested_capacity, u64 hash_seed) {
        destroy();
        if (requested_capacity == 0 || hash_seed == 0) return false;
        const u32 count = round_capacity(requested_capacity);
        if (count == 0 || count < requested_capacity) return false;
        void* mem = ::mmap(nullptr,
                           static_cast<u64>(count) * sizeof(Slot),
                           PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS,
                           -1,
                           0);
        if (mem == MAP_FAILED) return false;
        slots = static_cast<Slot*>(mem);
        slot_count = count;
        bucket_count = count / kWays;
        seed = hash_seed;
        return true;
    }

    void destroy() {
        if (slots != nullptr) ::munmap(slots, static_cast<u64>(slot_count) * sizeof(Slot));
        slots = nullptr;
        slot_count = 0;
        bucket_count = 0;
        size = 0;
        seed = 0;
    }

    static u64 mix(u32 key, u64 hash_seed) {
        u64 h = static_cast<u64>(key) ^ hash_seed;
        h ^= h >> 30;
        h *= 0xBF58476D1CE4E5B9ull;
        h ^= h >> 27;
        h *= 0x94D049BB133111EBull;
        h ^= h >> 31;
        return h;
    }

    void candidate_buckets(u32 key, u32* first, u32* second) const {
        const u64 h1 = mix(key, seed);
        const u64 h2 = mix(key, seed ^ 0x9E3779B97F4A7C15ull);
        *first = static_cast<u32>(h1) & (bucket_count - 1);
        *second = static_cast<u32>(h2) & (bucket_count - 1);
        if (*second == *first) *second = (*first + 1) & (bucket_count - 1);
    }

    bool get(u32 key, i64* out) const {
        if (slots == nullptr || out == nullptr) return false;
        u32 first = 0;
        u32 second = 0;
        candidate_buckets(key, &first, &second);
        return find_in_bucket(first, key, out) || find_in_bucket(second, key, out);
    }

    bool remove(u32 key) {
        if (slots == nullptr) return false;
        u32 first = 0;
        u32 second = 0;
        candidate_buckets(key, &first, &second);
        for (u32 bucket : {first, second}) {
            Slot* base = slots + bucket * kWays;
            for (u32 way = 0; way < kWays; way++) {
                if (base[way].occupied != 0 && base[way].key == key) {
                    base[way] = {};
                    size--;
                    return true;
                }
            }
        }
        return false;
    }

    HashSetResult set(u32 key, i64 value) {
        if (slots == nullptr) return HashSetResult::Uninitialized;
        u32 first = 0;
        u32 second = 0;
        candidate_buckets(key, &first, &second);
        for (u32 bucket : {first, second}) {
            Slot* base = slots + bucket * kWays;
            for (u32 way = 0; way < kWays; way++) {
                if (base[way].occupied != 0 && base[way].key == key) {
                    base[way].value = value;
                    return HashSetResult::Updated;
                }
            }
        }
        if (size == slot_count) return HashSetResult::Full;

        struct SearchNode {
            u32 bucket;
            u32 parent;
            u32 parent_way;
        };
        SearchNode nodes[kRelocationNodes]{};
        u32 node_count = 0;
        nodes[node_count++] = {first, 0xffffffffu, 0};
        nodes[node_count++] = {second, 0xffffffffu, 0};

        for (u32 cursor = 0; cursor < node_count; cursor++) {
            Slot* base = slots + nodes[cursor].bucket * kWays;
            for (u32 way = 0; way < kWays; way++) {
                if (base[way].occupied == 0) {
                    u32 free_bucket = nodes[cursor].bucket;
                    u32 free_way = way;
                    u32 node = cursor;
                    while (nodes[node].parent != 0xffffffffu) {
                        const u32 parent = nodes[node].parent;
                        Slot* parent_slot =
                            slots + nodes[parent].bucket * kWays + nodes[node].parent_way;
                        slots[free_bucket * kWays + free_way] = *parent_slot;
                        free_bucket = nodes[parent].bucket;
                        free_way = nodes[node].parent_way;
                        node = parent;
                    }
                    slots[free_bucket * kWays + free_way] = {key, 1, value};
                    size++;
                    return HashSetResult::Inserted;
                }
            }
            for (u32 way = 0; way < kWays && node_count < kRelocationNodes; way++) {
                const Slot& resident = base[way];
                u32 resident_first = 0;
                u32 resident_second = 0;
                candidate_buckets(resident.key, &resident_first, &resident_second);
                const u32 alternate =
                    resident_first == nodes[cursor].bucket ? resident_second : resident_first;
                bool seen = false;
                for (u32 i = 0; i < node_count; i++) {
                    if (nodes[i].bucket == alternate) {
                        seen = true;
                        break;
                    }
                }
                if (!seen) nodes[node_count++] = {alternate, cursor, way};
            }
        }
        return HashSetResult::PlacementLimit;
    }

private:
    bool find_in_bucket(u32 bucket, u32 key, i64* out) const {
        const Slot* base = slots + bucket * kWays;
        for (u32 way = 0; way < kWays; way++) {
            if (base[way].occupied != 0 && base[way].key == key) {
                *out = base[way].value;
                return true;
            }
        }
        return false;
    }
};

}  // namespace rut
