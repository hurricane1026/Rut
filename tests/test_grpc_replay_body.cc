#include "rut/runtime/grpc_replay_body.h"
#include "test.h"

#include <string.h>

using namespace rut;

TEST(grpc_replay_body, immutable_slice_and_bulk_cursor_rewinds) {
    SlicePool pool;
    REQUIRE(pool.init(80, 0, 0, 4).has_value());
    GrpcReplayBody body{};
    REQUIRE(body.init(ResponseBodyChain::kMaxBody));
    static u8 input[ResponseBodyChain::kMaxBody];
    for (u32 i = 0; i < sizeof(input); ++i) input[i] = static_cast<u8>(i * 37u + i / 251u);
    REQUIRE(body.append(pool, input, 17));
    REQUIRE(body.append(pool, input + 17, sizeof(input) - 17));
    CHECK_EQ(body.copy(input, 0), 0u);
    CHECK_FALSE(body.rewind());
    REQUIRE(body.seal());
    for (u32 pass = 0; pass < 3; ++pass) {
        REQUIRE(body.rewind());
        u8 output[7919];
        u32 total = 0;
        while (const u32 n = body.copy(output, sizeof(output))) {
            CHECK(memcmp(output, input + total, n) == 0);
            total += n;
        }
        CHECK_EQ(total, sizeof(input));
        CHECK_EQ(body.remaining, 0u);
        for (auto* node = body.storage.head; node; node = node->next) CHECK_EQ(node->offset, 0u);
    }
    body.release();
    CHECK_EQ(pool.in_use(), 0u);
    CHECK_EQ(pool.bulk_available(), 4u);
    pool.destroy();
}

TEST(grpc_replay_body, empty_request_and_seal_are_idempotent) {
    SlicePool pool;
    REQUIRE(pool.init(1).has_value());
    GrpcReplayBody body{};
    REQUIRE(body.init(1));
    REQUIRE(body.append(pool, nullptr, 0));
    REQUIRE(body.seal());
    REQUIRE(body.seal());
    CHECK_EQ(body.copy(nullptr, 1024), 0u);
    CHECK(body.rewind());
    CHECK_FALSE(body.append(pool, nullptr, 0));
    CHECK(body.replayable);
    body.release();
    body.release();
    CHECK_FALSE(body.seal());
    CHECK_FALSE(body.rewind());
    CHECK_EQ(body.copy(nullptr, 1024), 0u);
    CHECK_EQ(pool.in_use(), 0u);
    pool.destroy();
}

TEST(grpc_replay_body, cap_overflow_permanently_releases_retention) {
    SlicePool pool;
    REQUIRE(pool.init(3).has_value());
    GrpcReplayBody body{};
    REQUIRE(body.init(10));
    const u8 input[] = "0123456789";
    REQUIRE(body.append(pool, input, 9));
    CHECK_EQ(body.storage.size, 9u);
    REQUIRE(body.append(pool, input + 9, 1));
    CHECK_EQ(body.storage.size, 10u);
    CHECK_FALSE(body.append(pool, input, 1));
    CHECK_EQ(pool.in_use(), 0u);
    CHECK_FALSE(body.replayable);
    CHECK_FALSE(body.append(pool, input, 0));
    CHECK_FALSE(body.seal());
    CHECK_EQ(body.storage.size, 0u);
    body.release();
    CHECK_FALSE(body.init(0));
    CHECK_FALSE(body.init(ResponseBodyChain::kMaxBody + 1));
    CHECK(body.init(10));
    body.release();
    pool.destroy();
}

TEST(grpc_replay_body, allocation_failure_releases_old_and_reserved_nodes) {
    SlicePool pool;
    REQUIRE(pool.init(2, 0, 0).has_value());
    GrpcReplayBody body{};
    REQUIRE(body.init(ResponseBodyChain::kMaxBody));
    static u8 input[3 * SlicePool::kSliceSize]{};
    REQUIRE(body.append(pool, input, 1));
    CHECK_FALSE(body.append(pool, input, sizeof(input)));
    CHECK_FALSE(body.replayable);
    CHECK_EQ(pool.in_use(), 0u);
    // Retention failure leaves the pool usable by the original request path.
    u8* first = pool.alloc();
    u8* second = pool.alloc();
    CHECK(first != nullptr);
    CHECK(second != nullptr);
    if (first) pool.free(first);
    if (second) pool.free(second);
    body.release();
    pool.destroy();
}

TEST(grpc_replay_body, different_pool_rejected_without_leaking_either_owner) {
    SlicePool first;
    SlicePool second;
    REQUIRE(first.init(2).has_value());
    REQUIRE(second.init(2).has_value());
    GrpcReplayBody body{};
    const u8 input[] = "abc";
    REQUIRE(body.init(100));
    REQUIRE(body.append(first, input, 3));
    CHECK_FALSE(body.append(second, input, 3));
    CHECK_EQ(first.in_use(), 0u);
    CHECK_EQ(second.in_use(), 0u);
    CHECK_FALSE(body.seal());
    body.release();
    first.destroy();
    second.destroy();
}

TEST(grpc_replay_body, reset_invalidates_the_previous_read_cursor) {
    SlicePool pool;
    REQUIRE(pool.init(2).has_value());
    GrpcReplayBody body{};
    const u8 input[] = "abcdef";
    u8 output[8]{};
    REQUIRE(body.init(10));
    REQUIRE(body.append(pool, input, 6));
    REQUIRE(body.seal());
    CHECK_EQ(body.copy(output, 2), 2u);
    CHECK(memcmp(output, input, 2) == 0);
    CHECK(body.init(10));
    CHECK_EQ(body.copy(output, sizeof(output)), 0u);
    CHECK_EQ(pool.in_use(), 0u);
    REQUIRE(body.append(pool, input + 3, 3));
    REQUIRE(body.seal());
    CHECK_EQ(body.copy(output, sizeof(output)), 3u);
    CHECK(memcmp(output, "def", 3) == 0);
    body.release();
    CHECK_EQ(body.copy(output, sizeof(output)), 0u);
    pool.destroy();
}

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
