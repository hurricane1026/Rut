// Arena tests — comprehensive code path coverage for both backends.
// MmapArena: mmap-backed, variable-size blocks (compiler use).
// SliceArena: SlicePool-backed, fixed 16KB blocks (runtime hot path).
#include "fault_injection.h"
#include "rut/runtime/arena.h"
#include "rut/runtime/slice_pool.h"
#include "test.h"

using namespace rut;
using rut::test_fault::ScopedMemoryFault;

// ============================================================
// Block internals
// ============================================================

TEST(block, data_starts_after_header) {
    MmapArena a;
    REQUIRE(a.init(4096).has_value());
    auto* b = a.current;
    u64 hdr = (sizeof(MmapArena::Block) + 15) & ~u64(15);
    u8* expected = reinterpret_cast<u8*>(b) + hdr;
    CHECK_EQ(b->data(), expected);
    a.destroy();
}

TEST(block, capacity_equals_size_minus_header) {
    MmapArena a;
    REQUIRE(a.init(4096).has_value());
    auto* b = a.current;
    u64 hdr = (sizeof(MmapArena::Block) + 15) & ~u64(15);
    CHECK_EQ(b->capacity(), b->size - hdr);
    a.destroy();
}

TEST(block, remaining_decreases_after_alloc) {
    MmapArena a;
    REQUIRE(a.init(4096).has_value());
    u64 r0 = a.current->remaining();
    a.alloc(100);
    u64 r1 = a.current->remaining();
    CHECK_EQ(r0 - r1, 104u);  // 100 aligned to 104
    a.destroy();
}

TEST(block, chain_integrity) {
    MmapArena a;
    REQUIRE(a.init(256).has_value());
    MmapArena::Block* first = a.current;
    CHECK(first->prev == nullptr);

    // Force new block
    a.alloc(first->capacity());
    a.alloc(64);

    MmapArena::Block* second = a.current;
    CHECK(second != first);
    CHECK_EQ(second->prev, first);
    CHECK(first->prev == nullptr);
    a.destroy();
}

TEST(block, three_block_chain) {
    MmapArena a;
    REQUIRE(a.init(256).has_value());
    MmapArena::Block* b0 = a.current;

    // Force 3 blocks by allocating more than one block can hold each time
    a.alloc(b0->capacity() + 64);  // overflow → b1
    MmapArena::Block* b1 = a.current;
    CHECK_NE(b1, b0);

    a.alloc(b1->capacity() + 64);  // overflow → b2
    MmapArena::Block* b2 = a.current;
    CHECK_NE(b2, b1);

    // Verify chain: b2→b1→b0→nullptr
    CHECK_EQ(b2->prev, b1);
    CHECK_EQ(b1->prev, b0);
    CHECK(b0->prev == nullptr);
    a.destroy();
}

// ============================================================
// Basic allocation (from clapdb ArenaTest.AllocateTest)
// ============================================================

TEST(arena, init_succeeds) {
    MmapArena a;
    CHECK(a.init(4096).has_value());
    CHECK(a.current != nullptr);
    CHECK_GT(a.space_allocated(), 0u);
    a.destroy();
}

TEST(arena, init_reports_mmap_failure) {
    ScopedMemoryFault fault(1);
    MmapArena a;
    auto rc = a.init(4096);
    CHECK(!rc.has_value());
    CHECK_EQ(rc.error().code, ENOMEM);
    CHECK(rc.error().source == Error::Source::Arena);
    CHECK(a.current == nullptr);
    CHECK_EQ(a.space_allocated(), 0u);
}

TEST(arena, init_min_256) {
    MmapArena a;
    REQUIRE(a.init(1).has_value());
    CHECK_GE(a.current->size, 256u);
    a.destroy();
}

TEST(arena, small_alloc) {
    MmapArena a;
    REQUIRE(a.init(4096).has_value());
    void* p = a.alloc(64);
    CHECK(p != nullptr);
    CHECK_EQ(a.space_used(), 64u);
    a.destroy();
}

TEST(arena, alloc_returns_sequential_addresses) {
    MmapArena a;
    REQUIRE(a.init(4096).has_value());
    u8* p1 = static_cast<u8*>(a.alloc(16));
    u8* p2 = static_cast<u8*>(a.alloc(32));
    u8* p3 = static_cast<u8*>(a.alloc(8));
    CHECK_EQ(p2 - p1, 16);
    CHECK_EQ(p3 - p2, 32);
    a.destroy();
}

TEST(arena, multiple_allocs_in_one_block) {
    MmapArena a;
    REQUIRE(a.init(4096).has_value());
    void* p1 = a.alloc(100);
    void* p2 = a.alloc(200);
    void* p3 = a.alloc(300);
    CHECK(p1 && p2 && p3);
    CHECK_NE(p1, p2);
    CHECK_NE(p2, p3);
    // 100→104, 200→200, 300→304 (aligned)
    CHECK_EQ(a.space_used(), 104u + 200u + 304u);
    a.destroy();
}

// ============================================================
// Alignment (from clapdb AlignTest)
// ============================================================

TEST(arena, alignment_8byte) {
    MmapArena a;
    REQUIRE(a.init(4096).has_value());
    void* p1 = a.alloc(1);
    void* p2 = a.alloc(1);
    CHECK_EQ(reinterpret_cast<u64>(p1) % 8, 0u);
    CHECK_EQ(reinterpret_cast<u64>(p2) % 8, 0u);
    CHECK_EQ(static_cast<u8*>(p2) - static_cast<u8*>(p1), 8);
    a.destroy();
}

TEST(arena, alignment_various_sizes) {
    MmapArena a;
    REQUIRE(a.init(4096).has_value());
    for (u64 sz = 1; sz <= 64; sz++) {
        void* p = a.alloc(sz);
        CHECK_EQ(reinterpret_cast<u64>(p) % 8, 0u);
    }
    a.destroy();
}

TEST(arena, zero_size_alloc) {
    MmapArena a;
    REQUIRE(a.init(4096).has_value());
    void* p = a.alloc(0);
    CHECK(p != nullptr);
    a.destroy();
}

// ============================================================
// Block overflow (from clapdb ArenaTest.NewBlockTest)
// ============================================================

TEST(arena, overflow_to_new_block) {
    MmapArena a;
    REQUIRE(a.init(256).has_value());
    u64 cap = a.current->capacity();
    a.alloc(cap);
    a.alloc(64);
    CHECK(a.current->prev != nullptr);
    CHECK_GE(a.space_allocated(), 256u * 2);
    a.destroy();
}

TEST(arena, overflow_mmap_failure_keeps_existing_block_usable) {
    MmapArena a;
    REQUIRE(a.init(256).has_value());
    MmapArena::Block* first = a.current;
    const u64 initial_allocated = a.space_allocated();
    REQUIRE(a.alloc(first->capacity()) != nullptr);

    {
        ScopedMemoryFault fault(1);
        CHECK(a.alloc(64) == nullptr);
    }

    CHECK_EQ(a.current, first);
    CHECK_EQ(a.space_allocated(), initial_allocated);
    a.reset();
    CHECK_EQ(a.current, first);
    CHECK(a.alloc(32) != nullptr);
    a.destroy();
}

TEST(arena, large_alloc_gets_own_block) {
    MmapArena a;
    REQUIRE(a.init(256).has_value());
    void* p = a.alloc(1024);
    CHECK(p != nullptr);
    CHECK_GE(a.current->size, 1024u + sizeof(MmapArena::Block));
    a.destroy();
}

TEST(arena, many_blocks) {
    MmapArena a;
    REQUIRE(a.init(256).has_value());
    for (int i = 0; i < 100; i++) CHECK(a.alloc(200) != nullptr);
    int blocks = 0;
    for (MmapArena::Block* b = a.current; b; b = b->prev) blocks++;
    CHECK_GT(blocks, 1);
    a.destroy();
}

TEST(arena, alloc_exact_block_capacity) {
    MmapArena a;
    REQUIRE(a.init(4096).has_value());
    u64 cap = a.current->capacity();
    u64 aligned_cap = cap & ~static_cast<u64>(7);
    void* p = a.alloc(aligned_cap);
    CHECK(p != nullptr);
    CHECK_EQ(a.current->remaining(), cap - aligned_cap);
    a.destroy();
}

// ============================================================
// Reset (from clapdb ArenaTest.ResetTest, FreeBlocksExceptFirstTest)
// ============================================================

TEST(arena, reset_single_block_only) {
    MmapArena a;
    REQUIRE(a.init(4096).has_value());
    MmapArena::Block* first = a.current;
    a.alloc(100);
    a.alloc(200);
    CHECK_GT(a.space_used(), 0u);
    a.reset();
    CHECK_EQ(a.current, first);
    CHECK_EQ(a.current->used, 0u);
    CHECK_EQ(a.space_used(), 0u);
    a.destroy();
}

TEST(arena, reset_reuses_first_block) {
    MmapArena a;
    REQUIRE(a.init(4096).has_value());
    MmapArena::Block* first = a.current;
    a.alloc(100);
    a.reset();
    // Alloc again — should use same first block
    void* p = a.alloc(64);
    CHECK(p != nullptr);
    CHECK_EQ(a.current, first);
    a.destroy();
}

TEST(arena, reset_frees_extra_blocks) {
    MmapArena a;
    REQUIRE(a.init(256).has_value());
    u64 initial = a.space_allocated();
    for (int i = 0; i < 10; i++) a.alloc(4000);
    CHECK_GT(a.space_allocated(), initial);
    a.reset();
    CHECK_EQ(a.space_allocated(), initial);
    CHECK(a.current->prev == nullptr);
    a.destroy();
}

TEST(arena, reset_total_allocated_tracking) {
    MmapArena a;
    REQUIRE(a.init(256).has_value());
    u64 initial = a.space_allocated();
    // Create 3 extra blocks
    for (int i = 0; i < 3; i++) {
        a.alloc(a.current->capacity());
        a.alloc(64);
    }
    u64 peak = a.space_allocated();
    CHECK_GT(peak, initial);
    a.reset();
    CHECK_EQ(a.space_allocated(), initial);
    a.destroy();
}

TEST(arena, reset_then_alloc_10_cycles) {
    MmapArena a;
    REQUIRE(a.init(4096).has_value());
    for (int cycle = 0; cycle < 10; cycle++) {
        for (int i = 0; i < 20; i++) CHECK(a.alloc(100) != nullptr);
        a.reset();
        CHECK_EQ(a.space_used(), 0u);
    }
    a.destroy();
}

// ============================================================
// Typed alloc (from clapdb ArenaTest.CreateTest, CreateArrayTest)
// ============================================================

struct Point {
    i32 x, y;
};

TEST(arena, alloc_t_pod) {
    MmapArena a;
    REQUIRE(a.init(4096).has_value());
    auto* p = a.alloc_t<Point>(10, 20);
    CHECK(p != nullptr);
    CHECK_EQ(p->x, 10);
    CHECK_EQ(p->y, 20);
    a.destroy();
}

struct Counter {
    i32 value;
    Counter() : value(42) {}
};

TEST(arena, alloc_t_with_constructor) {
    MmapArena a;
    REQUIRE(a.init(4096).has_value());
    auto* c = a.alloc_t<Counter>();
    CHECK(c != nullptr);
    CHECK_EQ(c->value, 42);
    a.destroy();
}

struct Large {
    u8 data[512];
};

TEST(arena, alloc_t_large_struct) {
    MmapArena a;
    REQUIRE(a.init(4096).has_value());
    auto* l = a.alloc_t<Large>();
    CHECK(l != nullptr);
    // Write pattern and verify
    for (int i = 0; i < 512; i++) l->data[i] = static_cast<u8>(i & 0xFF);
    for (int i = 0; i < 512; i++) CHECK_EQ(l->data[i], static_cast<u8>(i & 0xFF));
    a.destroy();
}

TEST(arena, alloc_t_multiple_types) {
    MmapArena a;
    REQUIRE(a.init(4096).has_value());
    auto* p = a.alloc_t<Point>(1, 2);
    auto* c = a.alloc_t<Counter>();
    auto* l = a.alloc_t<Large>();
    CHECK(p && c && l);
    CHECK_EQ(p->x, 1);
    CHECK_EQ(c->value, 42);
    a.destroy();
}

TEST(arena, alloc_array_int) {
    MmapArena a;
    REQUIRE(a.init(4096).has_value());
    auto* arr = a.alloc_array<i32>(10);
    CHECK(arr != nullptr);
    for (int i = 0; i < 10; i++) CHECK_EQ(arr[i], 0);
    for (int i = 0; i < 10; i++) arr[i] = i * 10;
    for (int i = 0; i < 10; i++) CHECK_EQ(arr[i], i * 10);
    a.destroy();
}

TEST(arena, alloc_array_struct) {
    MmapArena a;
    REQUIRE(a.init(4096).has_value());
    auto* arr = a.alloc_array<Point>(5);
    CHECK(arr != nullptr);
    for (int i = 0; i < 5; i++) {
        CHECK_EQ(arr[i].x, 0);
        CHECK_EQ(arr[i].y, 0);
    }
    a.destroy();
}

TEST(arena, alloc_array_zero_count) {
    MmapArena a;
    REQUIRE(a.init(4096).has_value());
    auto* arr = a.alloc_array<i32>(0);
    CHECK(arr != nullptr);  // zero-count returns valid pointer
    a.destroy();
}

// ============================================================
// Destroy (from clapdb ArenaTest.DstrTest, FreeBlocksTest)
// ============================================================

TEST(arena, destroy_frees_all) {
    MmapArena a;
    REQUIRE(a.init(256).has_value());
    for (int i = 0; i < 20; i++) a.alloc(200);
    a.destroy();
    CHECK(a.current == nullptr);
    CHECK_EQ(a.total_allocated, 0u);
}

TEST(arena, double_destroy_safe) {
    MmapArena a;
    REQUIRE(a.init(4096).has_value());
    a.alloc(100);
    a.destroy();
    a.destroy();
    CHECK(a.current == nullptr);
}

TEST(arena, destroy_single_block) {
    MmapArena a;
    REQUIRE(a.init(4096).has_value());
    a.alloc(64);
    a.destroy();
    CHECK(a.current == nullptr);
    CHECK_EQ(a.total_allocated, 0u);
}

// ============================================================
// Metrics (from clapdb ArenaTest.SpaceTest, RemainsTest)
// ============================================================

TEST(arena, space_used_single_block) {
    MmapArena a;
    REQUIRE(a.init(4096).has_value());
    a.alloc(100);  // → 104
    a.alloc(8);
    CHECK_EQ(a.space_used(), 104u + 8u);
    a.destroy();
}

TEST(arena, space_used_across_blocks) {
    MmapArena a;
    REQUIRE(a.init(256).has_value());
    u64 cap = a.current->capacity();
    a.alloc(cap);  // fill first block
    a.alloc(64);   // second block
    // First block: cap used. Second block: 64 used.
    CHECK_EQ(a.space_used(), cap + 64u);
    a.destroy();
}

TEST(arena, space_allocated_grows_with_blocks) {
    MmapArena a;
    REQUIRE(a.init(256).has_value());
    u64 a0 = a.space_allocated();
    a.alloc(a.current->capacity());
    a.alloc(64);
    u64 a1 = a.space_allocated();
    CHECK_GT(a1, a0);
    a.destroy();
}

TEST(arena, space_used_zero_after_reset) {
    MmapArena a;
    REQUIRE(a.init(4096).has_value());
    a.alloc(500);
    CHECK_GT(a.space_used(), 0u);
    a.reset();
    CHECK_EQ(a.space_used(), 0u);
    a.destroy();
}

// ============================================================
// Stress tests
// ============================================================

TEST(arena, stress_10k_small_allocs) {
    MmapArena a;
    REQUIRE(a.init(4096).has_value());
    for (int i = 0; i < 10000; i++) CHECK(a.alloc(8) != nullptr);
    CHECK_EQ(a.space_used(), 80000u);
    a.destroy();
}

TEST(arena, stress_mixed_sizes) {
    MmapArena a;
    REQUIRE(a.init(1024).has_value());
    for (int i = 0; i < 1000; i++) {
        u64 sz = static_cast<u64>((i % 7 + 1) * 8);  // 8,16,24,32,40,48,56
        CHECK(a.alloc(sz) != nullptr);
    }
    a.destroy();
}

TEST(arena, stress_alloc_reset_1000_cycles) {
    MmapArena a;
    REQUIRE(a.init(4096).has_value());
    for (int cycle = 0; cycle < 1000; cycle++) {
        a.alloc(128);
        a.alloc(256);
        a.alloc(64);
        a.reset();
    }
    CHECK_EQ(a.space_used(), 0u);
    a.destroy();
}

TEST(arena, stress_large_allocs_across_blocks) {
    MmapArena a;
    REQUIRE(a.init(256).has_value());
    // Each alloc forces a new block
    for (int i = 0; i < 50; i++) CHECK(a.alloc(4000) != nullptr);
    int blocks = 0;
    for (MmapArena::Block* b = a.current; b; b = b->prev) blocks++;
    CHECK_GE(blocks, 50);
    a.destroy();
}

TEST(arena, stress_reset_preserves_first_block_across_cycles) {
    MmapArena a;
    REQUIRE(a.init(4096).has_value());
    MmapArena::Block* first = a.current;
    for (int cycle = 0; cycle < 100; cycle++) {
        for (int i = 0; i < 10; i++) a.alloc(100);
        a.reset();
        CHECK_EQ(a.current, first);
    }
    a.destroy();
}

// ============================================================
// Data integrity — write then read back
// ============================================================

TEST(arena, data_integrity_after_alloc) {
    MmapArena a;
    REQUIRE(a.init(4096).has_value());
    auto* buf = static_cast<u8*>(a.alloc(256));
    REQUIRE(buf != nullptr);
    for (int i = 0; i < 256; i++) buf[i] = static_cast<u8>(i);
    for (int i = 0; i < 256; i++) CHECK_EQ(buf[i], static_cast<u8>(i));
    a.destroy();
}

TEST(arena, data_integrity_across_blocks) {
    MmapArena a;
    REQUIRE(a.init(256).has_value());
    // Fill first block, force second
    u64 cap = a.current->capacity();
    auto* buf1 = static_cast<u8*>(a.alloc(cap));
    for (u64 i = 0; i < cap; i++) buf1[i] = static_cast<u8>(i & 0xFF);

    auto* buf2 = static_cast<u8*>(a.alloc(128));
    for (int i = 0; i < 128; i++) buf2[i] = static_cast<u8>(i + 100);

    // Verify first block data still intact
    for (u64 i = 0; i < cap; i++) CHECK_EQ(buf1[i], static_cast<u8>(i & 0xFF));
    // Verify second block
    for (int i = 0; i < 128; i++) CHECK_EQ(buf2[i], static_cast<u8>(i + 100));
    a.destroy();
}

// === Null guard tests (Copilot round 6) ===

// alloc() on uninitialized MmapArena (current==nullptr) must return nullptr, not crash.
// Without the null guard, this would segfault.
TEST(arena, alloc_before_init_returns_null) {
    MmapArena a;
    a.current = nullptr;
    CHECK(a.alloc(64) == nullptr);
}

// alloc() after destroy (current==nullptr) must return nullptr.
TEST(arena, alloc_after_destroy_returns_null) {
    MmapArena a;
    REQUIRE(a.init(4096).has_value());
    a.destroy();
    CHECK(a.alloc(64) == nullptr);
}

// reset() after destroy (current==nullptr) must not crash.
TEST(arena, reset_after_destroy_no_crash) {
    MmapArena a;
    REQUIRE(a.init(4096).has_value());
    a.destroy();
    a.reset();  // must be a no-op, not a crash
    CHECK(a.current == nullptr);
}

// reset() on uninitialized MmapArena must not crash.
TEST(arena, reset_before_init_no_crash) {
    MmapArena a;
    a.current = nullptr;
    a.reset();
    CHECK(a.current == nullptr);
}

// ============================================================
// SliceArena tests (Arena<SlicePoolBackend>)
// ============================================================

// Helper: create a small SlicePool for tests.
// 16 slices = 256KB — enough for arena tests.
struct PoolCtx {
    SlicePool pool;

    bool init() {
        return pool.init(16, 16).has_value();  // 16 slices, all precommitted
    }
    void destroy() { pool.destroy(); }
};

// Fixture: manages PoolCtx + SliceArena lifecycle.
// Tests that need custom pool sizes or pre-init pool counts stay as TEST().
struct SliceArenaF {
    PoolCtx pc;
    SliceArena a;
    bool ok;

    void SetUp() {
        ok = pc.init();
        if (ok) ok = a.init(&pc.pool).has_value();
    }
    void TearDown() {
        a.destroy();
        pc.destroy();
    }
};

TEST_F(SliceArenaF, basic_alloc) {
    REQUIRE(self.ok);
    CHECK(self.a.current != nullptr);

    void* p = self.a.alloc(64);
    CHECK(p != nullptr);
}

TEST_F(SliceArenaF, alloc_t) {
    REQUIRE(self.ok);

    struct Foo {
        u32 x;
        u32 y;
    };
    auto* f = self.a.alloc_t<Foo>(42, 99);
    REQUIRE(f != nullptr);
    CHECK_EQ(f->x, 42u);
    CHECK_EQ(f->y, 99u);
}

TEST_F(SliceArenaF, alloc_array) {
    REQUIRE(self.ok);

    auto* arr = self.a.alloc_array<u64>(100);
    REQUIRE(arr != nullptr);
    for (u32 i = 0; i < 100; i++) CHECK_EQ(arr[i], 0ull);

    arr[0] = 42;
    arr[99] = 99;
    CHECK_EQ(arr[0], 42ull);
    CHECK_EQ(arr[99], 99ull);
}

TEST_F(SliceArenaF, chain_to_second_slice) {
    REQUIRE(self.ok);

    auto* first_block = self.a.current;
    u64 cap = first_block->capacity();

    void* p1 = self.a.alloc(cap - 8);
    REQUIRE(p1 != nullptr);
    CHECK(self.a.current == first_block);

    void* p2 = self.a.alloc(64);
    REQUIRE(p2 != nullptr);
    CHECK(self.a.current != first_block);
    CHECK_EQ(self.a.current->prev, first_block);
}

TEST_F(SliceArenaF, chain_three_slices) {
    REQUIRE(self.ok);

    u64 cap = self.a.current->capacity();

    self.a.alloc(cap);
    auto* s1 = self.a.current;
    self.a.alloc(cap);
    auto* s2 = self.a.current;

    CHECK_NE(s1, s2);
    CHECK_EQ(s2->prev, s1);
}

TEST_F(SliceArenaF, single_alloc_exceeding_slice_fails) {
    REQUIRE(self.ok);

    // 16KB slice minus header ≈ 16368 bytes usable.
    void* p = self.a.alloc(SlicePool::kSliceSize);  // 16384 > usable capacity
    CHECK(p == nullptr);

    // Arena should still be usable after failed alloc
    void* p2 = self.a.alloc(32);
    CHECK(p2 != nullptr);
}

TEST_F(SliceArenaF, reset_then_reuse) {
    REQUIRE(self.ok);

    // Alloc, reset, alloc again — simulates request cycle
    for (int cycle = 0; cycle < 10; cycle++) {
        auto* v = self.a.alloc_t<u32>(static_cast<u32>(cycle));
        REQUIRE(v != nullptr);
        CHECK_EQ(*v, static_cast<u32>(cycle));
        self.a.reset();
    }
}

// --- Tests that need pre-init pool counts or custom pool configs stay as TEST() ---

TEST(slice_arena, reset_returns_slices_to_pool) {
    PoolCtx pc;
    REQUIRE(pc.init());

    u32 free_before = pc.pool.available();

    SliceArena a;
    REQUIRE(a.init(&pc.pool).has_value());
    CHECK_EQ(pc.pool.available(), free_before - 1);

    u64 cap = a.current->capacity();
    a.alloc(cap);
    a.alloc(64);
    CHECK_EQ(pc.pool.available(), free_before - 2);

    a.reset();
    CHECK_EQ(pc.pool.available(), free_before - 1);
    CHECK(a.current != nullptr);
    CHECK(a.current->prev == nullptr);
    CHECK_EQ(a.current->used, 0ull);

    void* p = a.alloc(32);
    CHECK(p != nullptr);

    a.destroy();
    CHECK_EQ(pc.pool.available(), free_before);
    pc.destroy();
}

TEST(slice_arena, destroy_returns_all_slices) {
    PoolCtx pc;
    REQUIRE(pc.init());

    u32 free_before = pc.pool.available();

    SliceArena a;
    REQUIRE(a.init(&pc.pool).has_value());

    u64 cap = a.current->capacity();
    a.alloc(cap);
    a.alloc(64);

    a.destroy();
    CHECK_EQ(pc.pool.available(), free_before);
    CHECK(a.current == nullptr);

    pc.destroy();
}

TEST(slice_arena, pool_exhaustion) {
    // Pool with only 2 slices
    SlicePool pool;
    REQUIRE(pool.init(2, 2).has_value());

    SliceArena a;
    REQUIRE(a.init(&pool).has_value());

    u64 cap = a.current->capacity();
    a.alloc(cap);
    void* p = a.alloc(64);
    CHECK(p != nullptr);

    a.alloc(cap - 64);
    void* p2 = a.alloc(64);  // pool empty → nullptr
    CHECK(p2 == nullptr);

    a.destroy();
    pool.destroy();
}

TEST(slice_arena, multiple_arenas_same_pool) {
    PoolCtx pc;
    REQUIRE(pc.init());

    SliceArena a1, a2;
    REQUIRE(a1.init(&pc.pool).has_value());
    REQUIRE(a2.init(&pc.pool).has_value());

    auto* p1 = a1.alloc_t<u64>(111);
    auto* p2 = a2.alloc_t<u64>(222);
    REQUIRE(p1 != nullptr);
    REQUIRE(p2 != nullptr);
    CHECK_EQ(*p1, 111ull);
    CHECK_EQ(*p2, 222ull);

    a1.reset();
    CHECK_EQ(*p2, 222ull);  // a2's data still valid

    a1.destroy();
    a2.destroy();
    pc.destroy();
}

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
