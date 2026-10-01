// Locked-memory accounting for one io_uring shard. The 4 KiB-page reference
// values were measured on Linux 7.2.7 (x86-64) by creating rings / registering
// provided-buffer rings and watching the per-user locked-memory charge.
#include "rut/runtime/connection_capacity.h"
#include "rut/runtime/io_backend.h"
#include "rut/runtime/io_uring_memlock.h"
#include "test.h"

using namespace rut;

static constexpr u64 kKiB = 1024;
static constexpr u64 kPage4K = 4 * kKiB;
static constexpr u64 kPage16K = 16 * kKiB;
static constexpr u64 kPage64K = 64 * kKiB;

// --- 4 KiB pages: measured on x86-64 ---

TEST(io_uring_memlock, ring_matches_measured_charge) {
    CHECK_EQ(io_uring_ring_locked_bytes(1024, 2048, kPage4K), 104 * kKiB);
    CHECK_EQ(io_uring_ring_locked_bytes(4096, 8192, kPage4K), 404 * kKiB);
    CHECK_EQ(io_uring_ring_locked_bytes(16384, 32768, kPage4K), 1604 * kKiB);
    CHECK_EQ(io_uring_ring_locked_bytes(16384, 16384, kPage4K), 1348 * kKiB);
}

TEST(io_uring_memlock, pbuf_ring_matches_measured_charge) {
    CHECK_EQ(io_uring_pbuf_ring_locked_bytes(2048, kPage4K), 32 * kKiB);
    CHECK_EQ(io_uring_pbuf_ring_locked_bytes(1024, kPage4K), 16 * kKiB);
}

TEST(io_uring_memlock, startup_minimum_accounts_for_earlier_optional_rings) {
    const u64 required = 1636 * kKiB;
    const u64 optional = 16 * kKiB;
    CHECK_EQ(io_uring_startup_min_locked_bytes(2, required, optional), 3288 * kKiB);
    CHECK_EQ(io_uring_startup_min_locked_bytes(1, required, optional), required);
    CHECK_EQ(io_uring_startup_min_locked_bytes(0, required, optional), 0u);
}

TEST(io_uring_memlock, startup_minimum_saturates_on_overflow) {
    const u64 max = ~u64(0);
    CHECK_EQ(io_uring_startup_min_locked_bytes(2, max, 1), max);
    CHECK_EQ(io_uring_startup_min_locked_bytes(2, 1, max), max);
}

// The default capacity gets SQ 1024 / CQ 32768 (was SQ 16384 / CQ 32768 =
// 1652 KiB per shard); capacity 1024 gets SQ 1024 / CQ 2048.
TEST(io_uring_memlock, default_capacity_costs_632_kib_per_shard) {
    const IoUringRingSizes sizes = io_uring_ring_sizes(kDefaultConnectionCapacity);
    CHECK_EQ(
        io_uring_shard_locked_bytes(
            sizes.sq_entries, sizes.cq_entries, kProvidedBufCount, kLargeProvidedBufCount, kPage4K),
        632 * kKiB);
}

TEST(io_uring_memlock, small_capacity_costs_152_kib_per_shard) {
    const IoUringRingSizes sizes = io_uring_ring_sizes(1024);
    CHECK_EQ(
        io_uring_shard_locked_bytes(
            sizes.sq_entries, sizes.cq_entries, kProvidedBufCount, kLargeProvidedBufCount, kPage4K),
        152 * kKiB);
}

TEST(io_uring_memlock, default_capacity_costs_632_kib_required_616_kib_with_primary_ring) {
    const IoUringRingSizes sizes = io_uring_ring_sizes(kDefaultConnectionCapacity);
    CHECK_EQ(io_uring_shard_required_locked_bytes(
                 sizes.sq_entries, sizes.cq_entries, kProvidedBufCount, kPage4K),
             616 * kKiB);
    CHECK_EQ(
        io_uring_shard_locked_bytes(
            sizes.sq_entries, sizes.cq_entries, kProvidedBufCount, kLargeProvidedBufCount, kPage4K),
        632 * kKiB);
}

// --- 16 KiB / 64 KiB pages: derived from the kernel's whole-page rounding,
// not measured. Each region rounds up separately, so the charge grows. ---

TEST(io_uring_memlock, ring_rounds_each_region_to_the_page_size) {
    // SQEs 1024 KiB (already page-aligned) + rings 576 KiB and a 320-byte header.
    CHECK_EQ(io_uring_ring_locked_bytes(16384, 32768, kPage16K), (1024 + 592) * kKiB);
    CHECK_EQ(io_uring_ring_locked_bytes(16384, 32768, kPage64K), (1024 + 640) * kKiB);
    // Small ring: SQEs 64 KiB + rings 36 KiB and the header.
    CHECK_EQ(io_uring_ring_locked_bytes(1024, 2048, kPage16K), (64 + 48) * kKiB);
    CHECK_EQ(io_uring_ring_locked_bytes(1024, 2048, kPage64K), (64 + 64) * kKiB);
}

TEST(io_uring_memlock, pbuf_ring_never_costs_less_than_one_page) {
    CHECK_EQ(io_uring_pbuf_ring_locked_bytes(2048, kPage16K), 32 * kKiB);
    CHECK_EQ(io_uring_pbuf_ring_locked_bytes(1024, kPage16K), 16 * kKiB);
    CHECK_EQ(io_uring_pbuf_ring_locked_bytes(2048, kPage64K), 64 * kKiB);
    CHECK_EQ(io_uring_pbuf_ring_locked_bytes(1024, kPage64K), 64 * kKiB);
}

TEST(io_uring_memlock, default_capacity_costs_more_on_larger_pages) {
    const IoUringRingSizes sizes = io_uring_ring_sizes(kDefaultConnectionCapacity);
    // SQEs 64 KiB + rings 528704 bytes rounded up, plus the provided-buffer rings.
    CHECK_EQ(io_uring_shard_locked_bytes(sizes.sq_entries,
                                         sizes.cq_entries,
                                         kProvidedBufCount,
                                         kLargeProvidedBufCount,
                                         kPage16K),
             (64 + 528 + 32 + 16) * kKiB);
    CHECK_EQ(io_uring_shard_locked_bytes(sizes.sq_entries,
                                         sizes.cq_entries,
                                         kProvidedBufCount,
                                         kLargeProvidedBufCount,
                                         kPage64K),
             (64 + 576 + 64 + 64) * kKiB);
}

// --- Ring sizing from the connection capacity ---

TEST(io_uring_ring_sizes, matches_the_documented_rule) {
    // CQ is 2 x capacity rounded up to a power of two, floored at 2048.
    CHECK_EQ(io_uring_ring_sizes(1).cq_entries, 2048u);
    CHECK_EQ(io_uring_ring_sizes(1024).cq_entries, 2048u);
    CHECK_EQ(io_uring_ring_sizes(1025).cq_entries, 4096u);
    CHECK_EQ(io_uring_ring_sizes(4096).cq_entries, 8192u);
    // The default capacity keeps the 32768-entry CQ the fixed sizing gave it.
    CHECK_EQ(io_uring_ring_sizes(kDefaultConnectionCapacity).cq_entries, 32768u);
    // The kernel's IORING_MAX_CQ_ENTRIES caps larger capacities.
    CHECK_EQ(io_uring_ring_sizes(32768).cq_entries, 65536u);
    CHECK_EQ(io_uring_ring_sizes(65536).cq_entries, 65536u);
    CHECK_EQ(io_uring_ring_sizes(1000000).cq_entries, 65536u);
    CHECK_EQ(io_uring_ring_sizes(kMaxConnectionCapacity).cq_entries, 65536u);
    // The SQ does not scale with the capacity (it was 16384 entries before sizing).
    CHECK_EQ(io_uring_ring_sizes(1).sq_entries, 1024u);
    CHECK_EQ(io_uring_ring_sizes(kDefaultConnectionCapacity).sq_entries, 1024u);
    CHECK_EQ(io_uring_ring_sizes(1000000).sq_entries, 1024u);
}

TEST(io_uring_ring_sizes, powers_of_two_with_cq_at_least_sq) {
    static constexpr u32 caps[] = {
        1,     2,     3,     255,   256,   1023,  1024,  1025,  4095,    4096,
        16383, 16384, 16385, 32767, 32768, 32769, 65535, 65536, 1000000, kMaxConnectionCapacity};
    for (const u32 cap : caps) {
        const IoUringRingSizes s = io_uring_ring_sizes(cap);
        CHECK_EQ(s.sq_entries & (s.sq_entries - 1), 0u);
        CHECK_EQ(s.cq_entries & (s.cq_entries - 1), 0u);
        CHECK_GE(s.cq_entries, s.sq_entries);
        CHECK_LE(s.cq_entries, kMaxIoUringCqEntries);
        // Never below twice the capacity until the kernel limit binds.
        if (cap <= kMaxIoUringCqEntries / 2) CHECK_GE(s.cq_entries, 2 * cap);
    }
}

static_assert(io_uring_next_pow2(0) == 1 && io_uring_next_pow2(1) == 1 &&
              io_uring_next_pow2(3) == 4 && io_uring_next_pow2(4096) == 4096 &&
              io_uring_next_pow2(4097) == 8192 && io_uring_next_pow2(0x80000000u) == 0x80000000u &&
              io_uring_next_pow2(0xFFFFFFFFu) == 0x80000000u);

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
