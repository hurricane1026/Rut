// Tests for common/types.h: Str, FixedVec, ListNode
#include "rut/common/byte_span.h"
#include "rut/common/types.h"
#include "test.h"

using namespace rut;

TEST(byte_span, checks_pool_boundaries) {
    const char bytes[10]{};
    const char* pool = bytes + 1;
    CHECK(byte_span_within(pool, u32{8}, pool, u32{8}));
    CHECK_FALSE(byte_span_within(pool, u32{8}, pool, u32{9}));
    CHECK_FALSE(byte_span_within(pool, u32{8}, pool + 1, u32{8}));
    CHECK(byte_span_within(pool, u32{8}, pool + 8, u32{0}));
    CHECK_FALSE(byte_span_within(pool, u32{8}, pool + 8, u32{1}));
    CHECK_FALSE(byte_span_within(pool, u32{8}, bytes, u32{1}));
    CHECK_FALSE(byte_span_within(pool, u32{8}, nullptr, u32{0}));
    CHECK(byte_span_within(pool, u16{8}, pool + 7, u16{1}));
}

TEST(byte_span, publishes_only_contained_offsets) {
    const char bytes[10]{};
    const char* buffer = bytes + 1;
    u32 offset = UINT32_MAX;
    CHECK(byte_span_offset_within(buffer, 8u, buffer + 1, 7u, &offset));
    CHECK_EQ(offset, 1u);
    CHECK_FALSE(byte_span_offset_within(buffer, 8u, buffer + 1, u32{UINT32_MAX}, &offset));
    CHECK_FALSE(byte_span_offset_within(buffer, 8u, bytes, 1u, &offset));
    CHECK_EQ(offset, 1u);
    CHECK(byte_span_offset_within(buffer, 8u, buffer + 8, 0u, &offset));
    CHECK_EQ(offset, 8u);
}

#if UINTPTR_MAX > UINT32_MAX
TEST(byte_span, publishes_offsets_above_four_gibibytes) {
    // Model a wide address interval without allocating or reading memory.
    constexpr uintptr_t kBase = 4096;
    constexpr size_t kOffset = (u64{1} << 32) + 1;
    const auto* buffer = reinterpret_cast<const void*>(kBase);
    const auto* data = reinterpret_cast<const void*>(kBase + kOffset);
    size_t offset = 0;
    CHECK(byte_span_offset_within(buffer, kOffset + 1, data, size_t{1}, &offset));
    CHECK_EQ(offset, kOffset);
    CHECK_FALSE(byte_span_offset_within(buffer, kOffset, data, size_t{1}, &offset));
    CHECK_FALSE(byte_span_offset_within(buffer, size_t{SIZE_MAX}, data, size_t{SIZE_MAX}, &offset));
    CHECK_EQ(offset, kOffset);
}
#endif

TEST(byte_span, checks_64_bit_length_arithmetic) {
    const char pool[3]{};
    constexpr u64 kLimit32 = u64{1} << 32;
    constexpr u64 kLimit64Signed = u64{1} << 63;
    constexpr u64 kLargest = UINT64_MAX;
    CHECK(byte_span_within(pool, kLimit32, pool + 1, kLimit32 - 1));
    CHECK_FALSE(byte_span_within(pool, kLimit32, pool + 2, kLimit32 - 1));
    CHECK(byte_span_within(pool, kLimit64Signed, pool + 1, u64{1}));
    CHECK_FALSE(byte_span_within(pool, kLimit64Signed - 1, pool, kLimit64Signed));
    CHECK(byte_span_within(pool, kLargest, pool, kLargest));
    CHECK_FALSE(byte_span_within(pool, kLargest, pool + 1, kLargest));
    CHECK_FALSE(byte_span_within(pool + 1, kLargest, pool, u64{0}));
    CHECK(byte_span_within(pool, size_t{3}, pool + 2, size_t{1}));
}

#if UINTPTR_MAX == UINT64_MAX
TEST(byte_span, compares_full_width_integer_offsets) {
    // Model numeric addresses without allocating or dereferencing memory.
    const auto* base = reinterpret_cast<const char*>(uintptr_t{1});
    const auto* data = reinterpret_cast<const char*>(UINTPTR_MAX);
    constexpr u64 kCapacity = UINT64_MAX;
    CHECK(byte_span_within(base, kCapacity, data, u64{1}));
    CHECK_FALSE(byte_span_within(base, kCapacity, data, u64{2}));

    u64 offset = 0;
    CHECK(byte_span_offset_within(base, kCapacity, data, u64{1}, &offset));
    CHECK_EQ(offset, kCapacity - 1);
    CHECK_FALSE(byte_span_offset_within(base, kCapacity, data, u64{2}, &offset));
    CHECK_EQ(offset, kCapacity - 1);
}
#endif

// === Str ===

TEST(str, eq_same) {
    Str a = {"hello", 5};
    Str b = {"hello", 5};
    CHECK(a.eq(b));
    CHECK(b.eq(a));
}

TEST(str, eq_different_content) {
    Str a = {"hello", 5};
    Str b = {"world", 5};
    CHECK(!a.eq(b));
}

TEST(str, eq_different_length) {
    Str a = {"hello", 5};
    Str b = {"hell", 4};
    CHECK(!a.eq(b));
    CHECK(!b.eq(a));
}

TEST(str, eq_empty) {
    Str a = {"", 0};
    Str b = {"", 0};
    CHECK(a.eq(b));
}

TEST(str, eq_prefix_mismatch) {
    Str a = {"abc", 3};
    Str b = {"abd", 3};
    CHECK(!a.eq(b));
}

TEST(str, empty) {
    Str a = {"", 0};
    CHECK(a.empty());
    Str b = {"x", 1};
    CHECK(!b.empty());
}

TEST(str, slice_middle) {
    Str s = {"hello world", 11};
    Str sub = s.slice(6, 11);
    CHECK_EQ(sub.len, 5u);
    CHECK_EQ(sub.ptr[0], 'w');
    CHECK_EQ(sub.ptr[4], 'd');
}

TEST(str, slice_prefix) {
    Str s = {"abcdef", 6};
    Str sub = s.slice(0, 3);
    CHECK_EQ(sub.len, 3u);
    CHECK_EQ(sub.ptr[0], 'a');
    CHECK_EQ(sub.ptr[2], 'c');
}

TEST(str, slice_empty) {
    Str s = {"abc", 3};
    Str sub = s.slice(1, 1);
    CHECK_EQ(sub.len, 0u);
    CHECK(sub.empty());
}

TEST(str, slice_full) {
    Str s = {"abc", 3};
    Str sub = s.slice(0, 3);
    CHECK(sub.eq(s));
}

TEST(str, slice_invalid_range_is_empty) {
    Str s = {"abc", 3};
    Str reversed = s.slice(2, 1);
    CHECK(reversed.ptr == nullptr);
    CHECK_EQ(reversed.len, 0u);
    Str beyond = s.slice(0, 4);
    CHECK(beyond.ptr == nullptr);
    CHECK_EQ(beyond.len, 0u);
    Str empty = {nullptr, 0};
    Str empty_slice = empty.slice(0, 0);
    CHECK(empty_slice.ptr == nullptr);
    CHECK_EQ(empty_slice.len, 0u);
}

// === FixedVec ===

TEST(fixedvec, push_and_access) {
    FixedVec<i32, 4> v;
    CHECK(v.empty());
    CHECK(!v.full());
    CHECK(v.push(10));
    CHECK(v.push(20));
    CHECK(v.push(30));
    CHECK_EQ(v.len, 3u);
    CHECK_EQ(v[0], 10);
    CHECK_EQ(v[1], 20);
    CHECK_EQ(v[2], 30);
}

TEST(fixedvec, push_at_capacity) {
    FixedVec<i32, 2> v;
    CHECK(v.push(1));
    CHECK(v.push(2));
    CHECK(v.full());
    CHECK(!v.push(3));  // rejected
    CHECK_EQ(v.len, 2u);
}

TEST(fixedvec, const_access) {
    FixedVec<i32, 4> v;
    v.push(42);
    const auto& cv = v;
    CHECK_EQ(cv[0], 42);
}

TEST(fixedvec, begin_end_iteration) {
    FixedVec<i32, 8> v;
    v.push(1);
    v.push(2);
    v.push(3);
    i32 sum = 0;
    for (i32* it = v.begin(); it != v.end(); ++it) sum += *it;
    CHECK_EQ(sum, 6);
}

TEST(fixedvec, empty_and_full) {
    FixedVec<u8, 1> v;
    CHECK(v.empty());
    CHECK(!v.full());
    v.push(0xFF);
    CHECK(!v.empty());
    CHECK(v.full());
}

TEST(fixedvec, mutate_via_index) {
    FixedVec<i32, 4> v;
    v.push(0);
    v[0] = 99;
    CHECK_EQ(v[0], 99);
}

// === ListNode ===

TEST(listnode, init_is_self_loop) {
    ListNode n;
    n.init();
    CHECK_EQ(n.prev, &n);
    CHECK_EQ(n.next, &n);
    CHECK(n.empty());
}

TEST(listnode, insert_after_one) {
    ListNode head;
    head.init();
    ListNode a;
    a.init();
    head.insert_after(&a);
    CHECK(!head.empty());
    CHECK_EQ(head.next, &a);
    CHECK_EQ(a.prev, &head);
    CHECK_EQ(a.next, &head);
    CHECK_EQ(head.prev, &a);
}

TEST(listnode, insert_after_two) {
    ListNode head;
    head.init();
    ListNode a, b;
    a.init();
    b.init();
    head.insert_after(&a);
    head.insert_after(&b);
    // Order: head → b → a → head
    CHECK_EQ(head.next, &b);
    CHECK_EQ(b.next, &a);
    CHECK_EQ(a.next, &head);
}

TEST(listnode, remove_middle) {
    ListNode head;
    head.init();
    ListNode a, b;
    a.init();
    b.init();
    head.insert_after(&a);
    head.insert_after(&b);
    // head → b → a → head. Remove b.
    b.remove();
    CHECK_EQ(head.next, &a);
    CHECK_EQ(a.prev, &head);
}

TEST(listnode, remove_last_makes_empty) {
    ListNode head;
    head.init();
    ListNode a;
    a.init();
    head.insert_after(&a);
    a.remove();
    CHECK(head.empty());
}

TEST(listnode, insert_three_remove_middle) {
    ListNode head;
    head.init();
    ListNode a, b, c;
    a.init();
    b.init();
    c.init();
    head.insert_after(&a);
    a.insert_after(&b);
    b.insert_after(&c);
    // head → a → b → c → head
    CHECK_EQ(head.next, &a);
    CHECK_EQ(a.next, &b);
    CHECK_EQ(b.next, &c);
    CHECK_EQ(c.next, &head);

    b.remove();
    // head → a → c → head
    CHECK_EQ(a.next, &c);
    CHECK_EQ(c.prev, &a);
}

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
