#include "rut/runtime/hash_table.h"
#include "test.h"

using namespace rut;

static bool has_bucket(const HashTable& table, u32 key, u32 bucket) {
    u32 first = 0;
    u32 second = 0;
    table.candidate_buckets(key, &first, &second);
    return first == bucket || second == bucket;
}

static bool has_pair(const HashTable& table, u32 key, u32 a, u32 b) {
    u32 first = 0;
    u32 second = 0;
    table.candidate_buckets(key, &first, &second);
    return (first == a && second == b) || (first == b && second == a);
}

TEST(hash_table, capacity_rounds_to_power_of_two_buckets) {
    CHECK_EQ(HashTable::round_capacity(1), 8u);
    CHECK_EQ(HashTable::round_capacity(8), 8u);
    CHECK_EQ(HashTable::round_capacity(9), 16u);
    CHECK_EQ(HashTable::round_capacity(0xffffffffu), 0u);
}

TEST(hash_table, rejects_invalid_initialization_and_uninitialized_ops) {
    HashTable table;
    i64 value = 7;
    CHECK_FALSE(table.init(0, 1));
    CHECK_FALSE(table.init(8, 0));
    CHECK_FALSE(table.get(1, &value));
    CHECK_FALSE(table.remove(1));
    CHECK_EQ(table.set(1, 2), HashSetResult::Uninitialized);
}

TEST(hash_table, set_get_update_and_remove) {
    HashTable table;
    REQUIRE(table.init(8, 0x1234));
    CHECK_EQ(table.set(7, 11), HashSetResult::Inserted);
    CHECK_EQ(table.set(7, 22), HashSetResult::Updated);
    i64 value = 0;
    CHECK(table.get(7, &value));
    CHECK_EQ(value, 22);
    CHECK_FALSE(table.get(8, &value));
    CHECK_FALSE(table.get(7, nullptr));
    CHECK(table.remove(7));
    CHECK_FALSE(table.remove(7));
    CHECK_FALSE(table.get(7, &value));
}

TEST(hash_table, full_insert_fails_without_eviction) {
    HashTable table;
    REQUIRE(table.init(8, 0x5678));
    for (u32 key = 0; key < table.slot_count; key++)
        REQUIRE_EQ(table.set(key, static_cast<i64>(key) + 100), HashSetResult::Inserted);
    REQUIRE_EQ(table.size, table.slot_count);
    CHECK_EQ(table.set(1000, 1), HashSetResult::Full);
    for (u32 key = 0; key < table.slot_count; key++) {
        i64 value = 0;
        CHECK(table.get(key, &value));
        CHECK_EQ(value, static_cast<i64>(key) + 100);
    }
    CHECK_EQ(table.set(3, 999), HashSetResult::Updated);
}

TEST(hash_table, relocation_preserves_every_committed_entry) {
    HashTable table;
    REQUIRE(table.init(64, 0x9abc));
    constexpr u32 first = 2;
    constexpr u32 second = 7;
    u32 target = 0;
    for (u32 key = 1; key < 100000; key++) {
        if (has_pair(table, key, first, second)) {
            target = key;
            break;
        }
    }
    REQUIRE(target != 0);

    u32 keys[8]{};
    u32 key_count = 0;
    for (u32 key = target + 1; key < 100000 && key_count < 8; key++) {
        if (has_bucket(table, key, key_count < 4 ? first : second) &&
            !has_pair(table, key, first, second))
            keys[key_count++] = key;
    }
    REQUIRE_EQ(key_count, 8u);
    for (u32 i = 0; i < key_count; i++) {
        const u32 bucket = i < 4 ? first : second;
        table.slots[bucket * HashTable::kWays + (i % 4)] = {keys[i], 1, static_cast<i64>(i + 10)};
    }
    table.size = 8;

    REQUIRE_EQ(table.set(target, 99), HashSetResult::Inserted);
    i64 value = 0;
    CHECK(table.get(target, &value));
    CHECK_EQ(value, 99);
    for (u32 i = 0; i < key_count; i++) {
        i64 value = 0;
        CHECK(table.get(keys[i], &value));
        CHECK_EQ(value, static_cast<i64>(i + 10));
    }
}

TEST(hash_table, placement_limit_does_not_mutate_connected_component) {
    HashTable table;
    REQUIRE(table.init(64, 0xdef0));
    constexpr u32 first = 4;
    constexpr u32 second = 11;
    u32 keys[9]{};
    u32 count = 0;
    for (u32 key = 1; key < 1000000 && count < 9; key++) {
        if (has_pair(table, key, first, second)) keys[count++] = key;
    }
    REQUIRE_EQ(count, 9u);
    for (u32 i = 0; i < 8; i++) {
        const u32 bucket = i < 4 ? first : second;
        table.slots[bucket * HashTable::kWays + (i % 4)] = {keys[i], 1, static_cast<i64>(i)};
    }
    table.size = 8;
    CHECK_EQ(table.set(keys[8], 100), HashSetResult::PlacementLimit);
    CHECK_EQ(table.size, 8u);
    for (u32 i = 0; i < 8; i++) {
        i64 value = -1;
        CHECK(table.get(keys[i], &value));
        CHECK_EQ(value, static_cast<i64>(i));
    }
    i64 value = 0;
    CHECK_FALSE(table.get(keys[8], &value));
}

TEST(hash_table, destroy_resets_metadata_and_allows_reinit) {
    HashTable table;
    REQUIRE(table.init(8, 77));
    REQUIRE_EQ(table.set(1, 2), HashSetResult::Inserted);
    table.destroy();
    CHECK_EQ(table.slots, nullptr);
    CHECK_EQ(table.slot_count, 0u);
    CHECK_EQ(table.bucket_count, 0u);
    CHECK_EQ(table.size, 0u);
    CHECK_EQ(table.seed, 0u);
    REQUIRE(table.init(16, 88));
    i64 value = 0;
    CHECK_FALSE(table.get(1, &value));
}

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
