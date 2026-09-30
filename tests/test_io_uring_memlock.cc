// Locked-memory accounting for one io_uring shard. The 4 KiB-page reference
// values were measured on Linux 7.2.7 (x86-64) by creating rings / registering
// provided-buffer rings and watching the per-user locked-memory charge.
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

// The large ring is optional at startup (setup_extra_buf_ring), so the
// required figure excludes it and the all-rings figure adds it back.
TEST(io_uring_memlock, current_constants_cost_1636_kib_required_1652_kib_all_rings) {
    CHECK_EQ(io_uring_shard_required_locked_bytes(
                 kIoUringSqEntries, kIoUringCqEntries, kProvidedBufCount, kPage4K),
             1636 * kKiB);
    CHECK_EQ(io_uring_shard_locked_bytes(kIoUringSqEntries,
                                         kIoUringCqEntries,
                                         kProvidedBufCount,
                                         kLargeProvidedBufCount,
                                         kPage4K),
             1652 * kKiB);
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

TEST(io_uring_memlock, current_constants_cost_more_on_larger_pages) {
    CHECK_EQ(io_uring_shard_required_locked_bytes(
                 kIoUringSqEntries, kIoUringCqEntries, kProvidedBufCount, kPage16K),
             1648 * kKiB);
    CHECK_EQ(io_uring_shard_locked_bytes(kIoUringSqEntries,
                                         kIoUringCqEntries,
                                         kProvidedBufCount,
                                         kLargeProvidedBufCount,
                                         kPage16K),
             1664 * kKiB);
    CHECK_EQ(io_uring_shard_required_locked_bytes(
                 kIoUringSqEntries, kIoUringCqEntries, kProvidedBufCount, kPage64K),
             1728 * kKiB);
    CHECK_EQ(io_uring_shard_locked_bytes(kIoUringSqEntries,
                                         kIoUringCqEntries,
                                         kProvidedBufCount,
                                         kLargeProvidedBufCount,
                                         kPage64K),
             1792 * kKiB);
}

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
