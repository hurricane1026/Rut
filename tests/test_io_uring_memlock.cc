// Locked-memory accounting for one io_uring shard. The reference values were
// measured on Linux 7.2.7 by creating rings / registering provided-buffer
// rings and watching the per-user locked-memory charge.
#include "rut/runtime/io_backend.h"
#include "rut/runtime/io_uring_memlock.h"
#include "test.h"

using namespace rut;

static constexpr u64 kKiB = 1024;

TEST(io_uring_memlock, ring_matches_measured_charge) {
    CHECK_EQ(io_uring_ring_locked_bytes(1024, 2048), 104 * kKiB);
    CHECK_EQ(io_uring_ring_locked_bytes(4096, 8192), 404 * kKiB);
    CHECK_EQ(io_uring_ring_locked_bytes(16384, 32768), 1604 * kKiB);
    CHECK_EQ(io_uring_ring_locked_bytes(16384, 16384), 1348 * kKiB);
}

TEST(io_uring_memlock, pbuf_ring_matches_measured_charge) {
    CHECK_EQ(io_uring_pbuf_ring_locked_bytes(2048), 32 * kKiB);
    CHECK_EQ(io_uring_pbuf_ring_locked_bytes(1024), 16 * kKiB);
}

TEST(io_uring_memlock, current_constants_cost_1652_kib_per_shard) {
    CHECK_EQ(io_uring_shard_locked_bytes(
                 kIoUringSqEntries, kIoUringCqEntries, kProvidedBufCount, kLargeProvidedBufCount),
             1652 * kKiB);
}

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
