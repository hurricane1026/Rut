// Tests for runtime/cache_table.h: the Cache<K, i64> per-shard slot table
// (docs/state-types.md) — 4-way set-associative, min-value victim,
// seeded mix, mmap'd fixed capacity.
#include "rut/runtime/cache_table.h"
#include "test.h"

using namespace rut;

TEST(cache_table, capacity_rounds_up_to_pow2_min_4) {
    CHECK_EQ(CacheTable::round_capacity(1), 4u);
    CHECK_EQ(CacheTable::round_capacity(4), 4u);
    CHECK_EQ(CacheTable::round_capacity(5), 8u);
    CHECK_EQ(CacheTable::round_capacity(1024), 1024u);
    CHECK_EQ(CacheTable::round_capacity(100000), 131072u);
}

TEST(cache_table, miss_then_set_get_roundtrip_and_update) {
    CacheTable t{};
    REQUIRE(t.init(1024, 0x1234u));
    i64 v = 0;
    CHECK(!t.get(0x0a000001u, &v));
    t.set(0x0a000001u, 42);
    REQUIRE(t.get(0x0a000001u, &v));
    CHECK_EQ(v, 42);
    t.set(0x0a000001u, -7);  // update in place
    REQUIRE(t.get(0x0a000001u, &v));
    CHECK_EQ(v, -7);
    t.destroy();
}

TEST(cache_table, four_way_evicts_min_value_slot) {
    // capacity 4 → exactly one set: every key lands in it.
    CacheTable t{};
    REQUIRE(t.init(4, 0x9999u));
    CHECK_EQ(t.set_count, 1u);
    t.set(1, 50);
    t.set(2, 10);  // the min-value entry
    t.set(3, 70);
    t.set(4, 60);
    t.set(5, 80);  // full set → evicts key 2 (value 10)
    i64 v = 0;
    CHECK(!t.get(2, &v));
    REQUIRE(t.get(1, &v));
    CHECK_EQ(v, 50);
    REQUIRE(t.get(3, &v));
    CHECK_EQ(v, 70);
    REQUIRE(t.get(4, &v));
    CHECK_EQ(v, 60);
    REQUIRE(t.get(5, &v));
    CHECK_EQ(v, 80);
    t.destroy();
}

TEST(cache_table, seed_changes_slot_assignment) {
    // The seeded mix must actually depend on the seed (hash-flood defense):
    // some key out of a small sample must map to a different set under a
    // different seed.
    CacheTable a{};
    CacheTable b{};
    REQUIRE(a.init(1024, 0x1111u));
    REQUIRE(b.init(1024, 0x2222u));
    bool any_differs = false;
    for (u32 key = 1; key <= 64 && !any_differs; key++) {
        const u64 ha = CacheTable::mix(key, a.seed) & (a.set_count - 1);
        const u64 hb = CacheTable::mix(key, b.seed) & (b.set_count - 1);
        any_differs = ha != hb;
    }
    CHECK(any_differs);
    a.destroy();
    b.destroy();
}

TEST(cache_table, reinit_resets_state) {
    CacheTable t{};
    REQUIRE(t.init(64, 7));
    t.set(9, 123);
    REQUIRE(t.init(128, 7));  // capacity change → fresh table
    i64 v = 0;
    CHECK(!t.get(9, &v));
    CHECK_EQ(t.slot_count, 128u);
    t.destroy();
}

TEST(cache_table, registry_publish_seeds_once) {
    cache_registry_set_seed(0xDEADBEEFu);
    const u32 caps[2] = {64, 128};
    const u64 idents[2] = {cache_instance_identity("a", 1), cache_instance_identity("b", 1)};
    cache_registry_publish(caps, idents, 2);
    auto& reg = cache_registry();
    CHECK_EQ(reg.count.load(std::memory_order_relaxed), 2u);
    CHECK_EQ(reg.capacities[0].load(std::memory_order_relaxed), 64u);
    CHECK_EQ(reg.capacities[1].load(std::memory_order_relaxed), 128u);
    CHECK_EQ(reg.seed.load(std::memory_order_relaxed), 0xDEADBEEFull);
}

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
