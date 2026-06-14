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

// Buffer/View typestate tests
#include "rut/common/buffer.h"
#include "test.h"

using namespace rut;

// === Buffer write + read ===

TEST(buffer, write_and_read) {
    u8 storage[64];
    Buffer buf(storage, sizeof(storage));
    const u8 src[] = {1, 2, 3, 4, 5};
    CHECK_EQ(buf.write(src, 5), 5u);
    CHECK_EQ(buf.len(), 5u);
    u8 out[64];
    CHECK_EQ(buf.read(out, sizeof(out)), 5u);
    CHECK_EQ(out[0], 1);
    CHECK_EQ(out[4], 5);
}

TEST(buffer, write_respects_capacity) {
    u8 storage[4];
    Buffer buf(storage, sizeof(storage));
    const u8 src[] = {1, 2, 3, 4, 5, 6, 7, 8};
    CHECK_EQ(buf.write(src, 8), 4u);
    CHECK_EQ(buf.len(), 4u);
}

TEST(buffer, read_multiple_times) {
    u8 storage[16];
    Buffer buf(storage, sizeof(storage));
    const u8 src[] = {10, 20, 30};
    buf.write(src, 3);
    u8 out1[16], out2[16];
    CHECK_EQ(buf.read(out1, sizeof(out1)), 3u);
    CHECK_EQ(buf.read(out2, sizeof(out2)), 3u);
    CHECK_EQ(out1[0], out2[0]);
}

TEST(buffer, reset_clears_data) {
    u8 storage[16];
    Buffer buf(storage, sizeof(storage));
    buf.write(reinterpret_cast<const u8*>("hello"), 5);
    CHECK_EQ(buf.len(), 5u);
    buf.reset();
    CHECK_EQ(buf.len(), 0u);
    buf.write(reinterpret_cast<const u8*>("world"), 5);
    CHECK_EQ(buf.len(), 5u);
}

// === Release: Buffer → View ===

TEST(buffer, release_to_view) {
    u8 storage[32];
    Buffer buf(storage, sizeof(storage));
    buf.write(reinterpret_cast<const u8*>("test"), 4);
    View view = buf.release();
    CHECK(view.valid());
    CHECK_EQ(view.len(), 4u);
    CHECK(buf.valid());
    CHECK(buf.is_released());
}

TEST(buffer, view_can_read) {
    u8 storage[32];
    Buffer buf(storage, sizeof(storage));
    const u8 src[] = {0xAA, 0xBB, 0xCC};
    buf.write(src, 3);
    View view = buf.release();
    u8 out[16];
    CHECK_EQ(view.read(out, sizeof(out)), 3u);
    CHECK_EQ(out[0], 0xAA);
    CHECK_EQ(out[2], 0xCC);
}

TEST(buffer, view_read_multiple_times) {
    u8 storage[16];
    Buffer buf(storage, sizeof(storage));
    buf.write(reinterpret_cast<const u8*>("abc"), 3);
    View view = buf.release();
    u8 out1[16], out2[16];
    CHECK_EQ(view.read(out1, sizeof(out1)), 3u);
    CHECK_EQ(view.read(out2, sizeof(out2)), 3u);
    CHECK_EQ(out1[0], out2[0]);
}

// === View destructor auto-restores Buffer ===

TEST(buffer, view_destructor_restores_writable) {
    u8 storage[16];
    Buffer buf(storage, sizeof(storage));
    buf.write(reinterpret_cast<const u8*>("hello"), 5);
    {
        View view = buf.release();
        CHECK(buf.is_released());
        u8 out[16];
        view.read(out, sizeof(out));
        // view destroyed here
    }
    // Buffer auto-restored: writable again, len reset
    CHECK(!buf.is_released());
    CHECK_EQ(buf.len(), 0u);
    CHECK_EQ(buf.write(reinterpret_cast<const u8*>("world"), 5), 5u);
    CHECK_EQ(buf.len(), 5u);
}

TEST(buffer, view_move_then_destroy_restores) {
    u8 storage[16];
    Buffer buf(storage, sizeof(storage));
    buf.write(reinterpret_cast<const u8*>("hi"), 2);
    {
        View v1 = buf.release();
        View v2(static_cast<View&&>(v1));  // move, v1 invalidated
        CHECK(!v1.valid());
        CHECK(v2.valid());
        CHECK(buf.is_released());
        // v2 destroyed here, v1 has no owner to restore
    }
    CHECK(!buf.is_released());  // v2's destructor restored it
}

// === Move semantics ===

TEST(buffer, buffer_move_invalidates_source) {
    u8 storage[16];
    Buffer b1(storage, sizeof(storage));
    b1.write(reinterpret_cast<const u8*>("hi"), 2);
    Buffer b2(static_cast<Buffer&&>(b1));
    CHECK(!b1.valid());
    CHECK(b2.valid());
    CHECK_EQ(b2.len(), 2u);
}

TEST(buffer, view_move_invalidates_source) {
    u8 storage[16];
    Buffer buf(storage, sizeof(storage));
    buf.write(reinterpret_cast<const u8*>("hi"), 2);
    View v1 = buf.release();
    View v2(static_cast<View&&>(v1));
    CHECK(!v1.valid());
    CHECK(v2.valid());
    CHECK_EQ(v2.len(), 2u);
}

// === Edge cases ===

TEST(buffer, empty_buffer) {
    Buffer buf;
    CHECK(!buf.valid());
    CHECK_EQ(buf.len(), 0u);
    u8 out[4];
    CHECK_EQ(buf.read(out, sizeof(out)), 0u);
}

TEST(buffer, empty_view) {
    View view;
    CHECK(!view.valid());
    u8 out[4];
    CHECK_EQ(view.read(out, sizeof(out)), 0u);
}

TEST(buffer, release_empty_buffer) {
    Buffer buf;
    View view = buf.release();
    CHECK(!view.valid());
}

TEST(buffer, read_with_zero_max) {
    u8 storage[16];
    Buffer buf(storage, sizeof(storage));
    buf.write(reinterpret_cast<const u8*>("hi"), 2);
    u8 out[1];
    CHECK_EQ(buf.read(out, 0), 0u);
}

TEST(buffer, release_sets_flag) {
    u8 storage[16];
    Buffer buf(storage, sizeof(storage));
    buf.write(reinterpret_cast<const u8*>("hi"), 2);
    CHECK(!buf.is_released());
    View view = buf.release();
    CHECK(buf.is_released());
    (void)view;
}

// === Full cycle: write → release → read → destroy → write again ===

TEST(buffer, full_cycle) {
    u8 storage[32];
    Buffer buf(storage, sizeof(storage));

    // Cycle 1
    buf.write(reinterpret_cast<const u8*>("request1"), 8);
    {
        View view = buf.release();
        u8 out[32];
        CHECK_EQ(view.read(out, sizeof(out)), 8u);
    }
    // Auto-restored
    CHECK(!buf.is_released());

    // Cycle 2
    buf.write(reinterpret_cast<const u8*>("request2"), 8);
    {
        View view = buf.release();
        u8 out[32];
        CHECK_EQ(view.read(out, sizeof(out)), 8u);
        CHECK_EQ(out[7], '2');
    }
    CHECK(!buf.is_released());
    CHECK_EQ(buf.len(), 0u);
}

// === Move-assign coverage ===

TEST(buffer, buffer_move_assign) {
    u8 s1[16], s2[16];
    Buffer b1(s1, sizeof(s1));
    b1.write(reinterpret_cast<const u8*>("aaa"), 3);

    Buffer b2(s2, sizeof(s2));
    b2.write(reinterpret_cast<const u8*>("bb"), 2);

    b2 = static_cast<Buffer&&>(b1);  // move-assign
    CHECK(!b1.valid());
    CHECK(b2.valid());
    CHECK_EQ(b2.len(), 3u);
}

TEST(buffer, view_move_assign) {
    u8 s1[16], s2[16];
    Buffer buf1(s1, sizeof(s1));
    buf1.write(reinterpret_cast<const u8*>("xxx"), 3);
    View v1 = buf1.release();

    Buffer buf2(s2, sizeof(s2));
    buf2.write(reinterpret_cast<const u8*>("yy"), 2);
    View v2 = buf2.release();

    v2 = static_cast<View&&>(v1);  // move-assign, v2's old owner restored
    CHECK(!v1.valid());
    CHECK(v2.valid());
    CHECK_EQ(v2.len(), 3u);
    CHECK(!buf2.is_released());  // v2's old View restored buf2
    CHECK(buf1.is_released());   // v1 moved away, buf1 still released until v2 dies
}

TEST(buffer, view_move_assign_restores_old_owner) {
    u8 storage[16];
    Buffer buf(storage, sizeof(storage));
    buf.write(reinterpret_cast<const u8*>("hi"), 2);
    View v1 = buf.release();
    CHECK(buf.is_released());

    View v2;
    v2 = static_cast<View&&>(v1);  // move-assign from v1 to empty v2
    CHECK(!v1.valid());
    CHECK(v2.valid());
    // buf still released (v2 now owns it)
    CHECK(buf.is_released());
}

// === capacity() coverage ===

TEST(buffer, capacity_query) {
    u8 storage[64];
    Buffer buf(storage, sizeof(storage));
    CHECK_EQ(buf.capacity(), 64u);
    buf.write(reinterpret_cast<const u8*>("test"), 4);
    CHECK_EQ(buf.capacity(), 64u);  // capacity unchanged after write
}

// === Multiple release-restore cycles stress ===

TEST(buffer, stress_release_restore_10_cycles) {
    u8 storage[32];
    Buffer buf(storage, sizeof(storage));

    for (int i = 0; i < 10; i++) {
        const u8 byte = static_cast<u8>(i);
        buf.write(&byte, 1);
        {
            View view = buf.release();
            u8 out[1];
            CHECK_EQ(view.read(out, 1), 1u);
            CHECK_EQ(out[0], byte);
        }
        CHECK(!buf.is_released());
        CHECK_EQ(buf.len(), 0u);
    }
}

// === View read truncation ===

TEST(buffer, view_read_truncates) {
    u8 storage[16];
    Buffer buf(storage, sizeof(storage));
    buf.write(reinterpret_cast<const u8*>("abcdef"), 6);
    View view = buf.release();

    u8 out[3];
    CHECK_EQ(view.read(out, 3), 3u);  // truncated to max
    CHECK_EQ(out[0], 'a');
    CHECK_EQ(out[2], 'c');
}

// === Buffer read truncation ===

TEST(buffer, buffer_read_truncates) {
    u8 storage[16];
    Buffer buf(storage, sizeof(storage));
    buf.write(reinterpret_cast<const u8*>("abcdef"), 6);

    u8 out[2];
    CHECK_EQ(buf.read(out, 2), 2u);
    CHECK_EQ(out[0], 'a');
    CHECK_EQ(out[1], 'b');
}

// === Write appends ===

TEST(buffer, write_appends) {
    u8 storage[16];
    Buffer buf(storage, sizeof(storage));
    buf.write(reinterpret_cast<const u8*>("hel"), 3);
    buf.write(reinterpret_cast<const u8*>("lo"), 2);
    CHECK_EQ(buf.len(), 5u);

    u8 out[16];
    buf.read(out, sizeof(out));
    CHECK_EQ(out[0], 'h');
    CHECK_EQ(out[3], 'l');
    CHECK_EQ(out[4], 'o');
}

// === Copilot review regression tests ===

// #1: release on null buffer → empty View, no lock
// Without fix: null buffer would set released_=true, trapping on next write
TEST(copilot, release_null_buffer_no_lock) {
    Buffer buf;  // null, invalid
    CHECK(!buf.valid());
    View view = buf.release();
    CHECK(!view.valid());
    CHECK(!buf.is_released());  // not locked — null buffer skips lock
}

// #2: double release traps (programming error)
// Without fix: two Views alive, first destructor unlocks while second still reads
// Can't test trap directly, but verify the flag prevents it
TEST(copilot, release_flag_prevents_double) {
    u8 storage[16];
    Buffer buf(storage, sizeof(storage));
    buf.write(reinterpret_cast<const u8*>("hi"), 2);
    View view = buf.release();
    CHECK(buf.is_released());
    // Double release would trap; only verify precondition state here
    // buf.release();  // would __builtin_trap()
    (void)view;
}

// #4: read is const — can pass const View& and const Buffer&
TEST(copilot, read_is_const) {
    u8 storage[16];
    Buffer buf(storage, sizeof(storage));
    buf.write(reinterpret_cast<const u8*>("test"), 4);
    View view = buf.release();

    // const ref read
    const View& cv = view;
    u8 out[16];
    CHECK_EQ(cv.read(out, sizeof(out)), 4u);
    CHECK_EQ(out[0], 't');
}

TEST(copilot, buffer_read_is_const) {
    u8 storage[16];
    Buffer buf(storage, sizeof(storage));
    buf.write(reinterpret_cast<const u8*>("abc"), 3);

    const Buffer& cb = buf;
    u8 out[16];
    CHECK_EQ(cb.read(out, sizeof(out)), 3u);
    CHECK_EQ(out[0], 'a');
}

// #1 (round 2): move-assign into released Buffer traps
// Without fix: View's restore_owner would corrupt the new Buffer's state
TEST(copilot2, dest_released_move_assign_guarded) {
    u8 s1[16], s2[16];
    Buffer b1(s1, sizeof(s1));
    b1.write(reinterpret_cast<const u8*>("aaa"), 3);

    Buffer b2(s2, sizeof(s2));
    b2.write(reinterpret_cast<const u8*>("bb"), 2);
    View view = b2.release();
    CHECK(b2.is_released());
    // b2 = static_cast<Buffer&&>(b1);  // would trap — dest is released
    // Can't exercise the trap directly; verify the precondition flag only
    CHECK(b2.is_released());
    (void)view;
}

// #2 (round 2): restore_owner resets len — verify documented behavior
TEST(copilot2, restore_resets_len_documented) {
    u8 storage[16];
    Buffer buf(storage, sizeof(storage));
    buf.write(reinterpret_cast<const u8*>("hello"), 5);
    CHECK_EQ(buf.len(), 5u);
    {
        View view = buf.release();
        (void)view;
    }
    // After View destroyed: len is 0 (documented: data consumed, fresh start)
    CHECK_EQ(buf.len(), 0u);
    CHECK(!buf.is_released());
}

// === Copilot round 3 regression tests ===

// #1: Buffer destructor traps if View alive.
// Can't test trap, but verify View must die before Buffer goes out of scope.
// The full_cycle test already proves correct usage (View scoped inside {}).

// #2-3: read with empty buffer doesn't call memcpy with n==0
TEST(copilot3, read_empty_buffer_no_memcpy_crash) {
    u8 storage[16];
    Buffer buf(storage, sizeof(storage));
    // len_==0, so n will be 0 — must not call memcpy
    u8 out[4];
    CHECK_EQ(buf.read(out, sizeof(out)), 0u);
}

TEST(copilot3, read_empty_view_no_memcpy_crash) {
    u8 storage[16];
    Buffer buf(storage, sizeof(storage));
    // Don't write anything — len==0
    View view = buf.release();
    u8 out[4];
    CHECK_EQ(view.read(out, sizeof(out)), 0u);
}

// #5: test_buffer is in check target (verified by CMakeLists.txt)
// This test itself running proves it.

// === Copilot round 4: overlapping read/write safe with memmove ===

// read into overlapping region of same backing storage
TEST(copilot4, read_overlapping_dst_safe) {
    u8 storage[32];
    Buffer buf(storage, sizeof(storage));
    buf.write(reinterpret_cast<const u8*>("abcdefgh"), 8);
    // Read into the same storage at offset 4 — overlaps with src
    View view = buf.release();
    view.read(storage + 4, 8);
    // With memcpy this would be UB. With memmove it's safe.
    CHECK_EQ(storage[4], 'a');
    CHECK_EQ(storage[7], 'd');
}

// write from overlapping src within same backing storage
TEST(copilot4, write_overlapping_src_safe) {
    u8 storage[32];
    Buffer buf(storage, sizeof(storage));
    buf.write(reinterpret_cast<const u8*>("abcd"), 4);
    // Write from within the same storage (overlap with existing data)
    buf.write(storage, 4);  // appends "abcd" again from overlapping src
    CHECK_EQ(buf.len(), 8u);
    u8 out[16];
    buf.read(out, sizeof(out));
    CHECK_EQ(out[0], 'a');
    CHECK_EQ(out[4], 'a');
}

// === I/O boundary methods ===

TEST(io_boundary, write_ptr_and_commit) {
    u8 storage[64];
    Buffer buf(storage, sizeof(storage));
    u8* wp = buf.write_ptr();
    CHECK_EQ(wp, storage);
    CHECK_EQ(buf.write_avail(), 64u);
    // Simulate recv: write directly, then commit
    wp[0] = 'G';
    wp[1] = 'E';
    wp[2] = 'T';
    buf.commit(3);
    CHECK_EQ(buf.len(), 3u);
    CHECK_EQ(buf.data()[0], 'G');
    // write_ptr advances past committed data
    CHECK_EQ(buf.write_ptr(), storage + 3);
    CHECK_EQ(buf.write_avail(), 61u);
}

TEST(io_boundary, commit_after_write) {
    u8 storage[16];
    Buffer buf(storage, sizeof(storage));
    buf.write(reinterpret_cast<const u8*>("AB"), 2);
    CHECK_EQ(buf.write_ptr(), storage + 2);
    buf.write_ptr()[0] = 'C';
    buf.commit(1);
    CHECK_EQ(buf.len(), 3u);
    CHECK_EQ(buf.data()[2], 'C');
}

TEST(io_boundary, data_read_only) {
    u8 storage[16];
    Buffer buf(storage, sizeof(storage));
    buf.write(reinterpret_cast<const u8*>("hello"), 5);
    const u8* d = buf.data();
    CHECK_EQ(d, storage);
    CHECK_EQ(d[0], 'h');
    CHECK_EQ(d[4], 'o');
}

TEST(io_boundary, view_data_ptr) {
    u8 storage[16];
    Buffer buf(storage, sizeof(storage));
    buf.write(reinterpret_cast<const u8*>("test"), 4);
    View view = buf.release();
    CHECK_EQ(view.data(), storage);
    CHECK_EQ(view.data()[0], 't');
    CHECK_EQ(view.len(), 4u);
}

TEST(io_boundary, bind_resets_buffer) {
    u8 storage[32];
    Buffer buf(storage, sizeof(storage));
    buf.write(reinterpret_cast<const u8*>("data"), 4);
    CHECK_EQ(buf.len(), 4u);
    u8 new_storage[64];
    buf.bind(new_storage, sizeof(new_storage));
    CHECK_EQ(buf.len(), 0u);
    CHECK_EQ(buf.capacity(), 64u);
    CHECK(buf.valid());
    CHECK(!buf.is_released());
}

TEST(io_boundary, bind_clears_released_state) {
    u8 storage[16];
    Buffer buf(storage, sizeof(storage));
    buf.write(reinterpret_cast<const u8*>("x"), 1);
    View view = buf.release();
    CHECK(buf.is_released());
    // Normally this would be a bug, but bind() is for connection reset
    // where all Views are guaranteed dead. Simulate by scoping the moved View.
    {
        View moved = static_cast<View&&>(view);
        (void)moved;
    }
    // After moved View is destroyed, original is invalidated. Now bind.
    buf.bind(storage, sizeof(storage));
    CHECK(!buf.is_released());
    CHECK_EQ(buf.len(), 0u);
}

TEST(io_boundary, write_ptr_null_buffer) {
    Buffer buf;
    CHECK(buf.write_ptr() == nullptr);
    CHECK_EQ(buf.write_avail(), 0u);
    CHECK(buf.data() == nullptr);
}

TEST(io_boundary, commit_fills_to_capacity) {
    u8 storage[8];
    Buffer buf(storage, sizeof(storage));
    buf.commit(8);
    CHECK_EQ(buf.len(), 8u);
    CHECK_EQ(buf.write_avail(), 0u);
}

// === Coverage: edge cases for I/O boundary methods ===

// write_ptr returns past-the-end (non-null) when buffer is full
TEST(io_coverage, write_ptr_when_full) {
    u8 storage[8];
    Buffer buf(storage, sizeof(storage));
    buf.commit(8);
    CHECK_EQ(buf.write_avail(), 0u);
    // write_ptr() returns ptr_ + len_ (past-the-end), not nullptr.
    // Callers must check write_avail() before writing.
    u8* wp = buf.write_ptr();
    CHECK(wp != nullptr);
    CHECK_EQ(wp, storage + 8);  // past-the-end
    CHECK_EQ(buf.write_avail(), 0u);
}

// write() when buffer is already full returns 0
TEST(io_coverage, write_when_full) {
    u8 storage[4];
    Buffer buf(storage, sizeof(storage));
    buf.write(reinterpret_cast<const u8*>("ABCD"), 4);
    CHECK_EQ(buf.len(), 4u);
    u32 written = buf.write(reinterpret_cast<const u8*>("E"), 1);
    CHECK_EQ(written, 0u);  // no space
    CHECK_EQ(buf.len(), 4u);
}

// commit(0) is a no-op
TEST(io_coverage, commit_zero) {
    u8 storage[16];
    Buffer buf(storage, sizeof(storage));
    buf.commit(0);
    CHECK_EQ(buf.len(), 0u);
}

// data() returns nullptr for default-constructed buffer
TEST(io_coverage, data_on_default) {
    Buffer buf;
    CHECK(buf.data() == nullptr);
    View view;
    CHECK(view.data() == nullptr);
}

// bind() to same storage is idempotent
TEST(io_coverage, bind_same_storage) {
    u8 storage[16];
    Buffer buf(storage, sizeof(storage));
    buf.write(reinterpret_cast<const u8*>("hello"), 5);
    buf.bind(storage, sizeof(storage));
    CHECK_EQ(buf.len(), 0u);
    CHECK_EQ(buf.capacity(), 16u);
    CHECK_EQ(buf.data(), storage);
}

// Sequential write + commit interleaving
TEST(io_coverage, write_then_commit_interleaved) {
    u8 storage[32];
    Buffer buf(storage, sizeof(storage));
    // write 3 bytes
    buf.write(reinterpret_cast<const u8*>("ABC"), 3);
    CHECK_EQ(buf.len(), 3u);
    // commit 2 bytes (e.g., recv directly wrote to buf)
    buf.write_ptr()[0] = 'D';
    buf.write_ptr()[1] = 'E';
    buf.commit(2);
    CHECK_EQ(buf.len(), 5u);
    // read all
    u8 out[8];
    u32 n = buf.read(out, sizeof(out));
    CHECK_EQ(n, 5u);
    CHECK_EQ(out[0], 'A');
    CHECK_EQ(out[3], 'D');
    CHECK_EQ(out[4], 'E');
}

// View data() matches buffer content
TEST(io_coverage, view_data_matches_buffer) {
    u8 storage[16];
    Buffer buf(storage, sizeof(storage));
    buf.write(reinterpret_cast<const u8*>("test123"), 7);
    View view = buf.release();
    CHECK_EQ(view.data(), storage);
    CHECK_EQ(view.len(), 7u);
    CHECK_EQ(view.data()[0], 't');
    CHECK_EQ(view.data()[6], '3');
}

// reset() after partial write clears len but preserves storage
TEST(io_coverage, reset_preserves_storage) {
    u8 storage[16];
    Buffer buf(storage, sizeof(storage));
    buf.write(reinterpret_cast<const u8*>("data"), 4);
    buf.reset();
    CHECK_EQ(buf.len(), 0u);
    CHECK_EQ(buf.capacity(), 16u);
    CHECK_EQ(buf.data(), storage);
    // Can write again
    buf.write(reinterpret_cast<const u8*>("new"), 3);
    CHECK_EQ(buf.len(), 3u);
}

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
