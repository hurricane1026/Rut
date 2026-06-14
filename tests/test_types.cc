/*
 * Copyright (C) 2026 Rut Contributors
 *
 * This file is part of Rut.
 *
 * Rut is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * Rut is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public
 * License along with Rut. If not, see <https://www.gnu.org/licenses/>.
 */

// Tests for common/types.h: Str, FixedVec, ListNode
#include "rut/common/types.h"
#include "test.h"

using namespace rut;

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
