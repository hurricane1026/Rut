#include "rut/runtime/local_grpc_deadline_timer.h"
#include "test.h"

using namespace rut;

TEST(local_grpc_deadline_timer, target_then_cancel_cqes_reclaim_in_either_order) {
    LocalGrpcDeadlineTimerOwner owner;
    REQUIRE(owner.arm(1234567));
    CHECK_EQ(owner.timespec_sec, 1);
    CHECK_EQ(owner.timespec_nsec, 234567000);
    const u32 generation = owner.owner_generation;
    CHECK(owner.request_cancel());
    CHECK_FALSE(owner.reusable());
    CHECK(owner.reclaim_cancel(generation));
    CHECK_FALSE(owner.reusable());
    CHECK(owner.reclaim_target(generation));
    CHECK(owner.reusable());

    REQUIRE(owner.arm(2000000));
    const u32 second = owner.owner_generation;
    CHECK(owner.request_cancel());
    CHECK(owner.reclaim_target(second));
    CHECK_FALSE(owner.reusable());
    CHECK(owner.reclaim_cancel(second));
    CHECK(owner.reusable());
}

TEST(local_grpc_deadline_timer, stale_cqes_and_rearm_while_owned_are_rejected) {
    LocalGrpcDeadlineTimerOwner owner;
    REQUIRE(owner.arm(1));
    const u32 generation = owner.owner_generation;
    CHECK_FALSE(owner.arm(2));
    CHECK_FALSE(owner.reclaim_target(generation + 1));
    CHECK_FALSE(owner.reclaim_cancel(generation));
    CHECK(owner.request_cancel());
    CHECK_FALSE(owner.request_cancel());
    CHECK_FALSE(owner.arm(3));
}

TEST(local_grpc_deadline_timer, cancel_before_submit_is_represented_without_reuse) {
    LocalGrpcDeadlineTimerOwner owner;
    REQUIRE(owner.arm(9000000));
    const u32 generation = owner.owner_generation;
    REQUIRE(owner.request_cancel());
    CHECK_EQ(owner.cancel_generation, generation);
    CHECK_FALSE(owner.reusable());
    CHECK(owner.reclaim_cancel(generation));
    CHECK(owner.reclaim_target(generation));
    CHECK(owner.reusable());
    CHECK_EQ(owner.timespec_sec, 0);
    CHECK_EQ(owner.timespec_nsec, 0);
}

TEST(local_grpc_deadline_timer, refuses_generation_wrap_and_preserves_owned_timespec) {
    LocalGrpcDeadlineTimerOwner owner;
    owner.generation = LocalGrpcDeadlineTimerOwner::kGenerationMask - 1;
    REQUIRE(owner.arm(1234567));
    const u32 generation = owner.owner_generation;
    REQUIRE(owner.request_cancel());
    REQUIRE(owner.reclaim_target(generation));
    CHECK_EQ(owner.timespec_sec, 1);
    CHECK_EQ(owner.timespec_nsec, 234567000);
    CHECK_FALSE(owner.arm(2000000));
    REQUIRE(owner.reclaim_cancel(generation));
    CHECK(owner.reusable());
    CHECK_FALSE(owner.arm(2000000));
    CHECK_FALSE(owner.reclaim_target(generation));
}

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
