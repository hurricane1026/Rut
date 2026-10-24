#include "rut/runtime/rate_limit.h"
#include "test.h"

using namespace rut;

// These distinct keys collide in the current 8192-slot table. Keeping the
// regression inputs fixed makes a change to collision behavior observable.
static constexpr u64 kFirst = 1;
static constexpr u64 kCollision = 131;

TEST(rate_limit_table, colliding_key_cannot_reset_an_active_bucket) {
    RateLimiter limiter{};
    REQUIRE(limiter.allow_key(kFirst, 10, 20, 1000));
    for (u32 i = 0; i < 16; ++i) {
        CHECK(!limiter.allow_key(kCollision, 10, 20, 1000));
    }
    // Exactly two tokens from the original burst remain.
    CHECK(limiter.allow_key(kFirst, 10, 20, 1000));
    CHECK(limiter.allow_key(kFirst, 10, 20, 1000));
    CHECK(!limiter.allow_key(kFirst, 10, 20, 1000));
    for (u32 i = 0; i < 16; ++i) {
        CHECK(!limiter.allow_key(kCollision, 10, 20, 1000));
        CHECK(!limiter.allow_key(kFirst, 10, 20, 1000));
    }
}

TEST(rate_limit_table, colliding_slot_reusable_only_after_full_recovery) {
    RateLimiter limiter{};
    REQUIRE(limiter.allow_key(kFirst, 10, 20, 1000));
    REQUIRE(limiter.allow_key(kFirst, 10, 20, 1000));
    REQUIRE(limiter.allow_key(kFirst, 10, 20, 1000));
    CHECK(!limiter.allow_key(kCollision, 10, 20, 1029));
    CHECK(limiter.allow_key(kCollision, 10, 20, 1030));
    CHECK(limiter.allow_key(kCollision, 10, 20, 1030));
    CHECK(limiter.allow_key(kCollision, 10, 20, 1030));
    CHECK(!limiter.allow_key(kCollision, 10, 20, 1030));
    CHECK(!limiter.allow_key(kFirst, 10, 20, 1030));
}

TEST(rate_limit_table, disabled_rule_does_not_replace_bucket_and_reset_releases_it) {
    RateLimiter limiter{};
    REQUIRE(limiter.allow_key(kFirst, 10, 0, 1000));
    CHECK(limiter.allow_key(kCollision, 0, 0, 1000));
    CHECK(!limiter.allow_key(kFirst, 10, 0, 1000));
    limiter.reset();
    CHECK(limiter.allow_key(kCollision, 10, 0, 1000));
    CHECK(!limiter.allow_key(kCollision, 10, 0, 1000));
}

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
