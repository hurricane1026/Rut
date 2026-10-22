#include "rut/runtime/grpc_web.h"
#include "rut/runtime/local_grpc_deadline.h"
#include "test.h"

using namespace rut;

TEST(local_grpc_deadline, parses_units_and_zero_without_early_expiry) {
    struct Case {
        const char* value;
        u64 micros;
    } cases[] = {
        {"0n", 0},
        {"1n", 1},
        {"1u", 1},
        {"1m", 1000},
        {"1S", 1000000},
        {"1M", 60000000},
        {"1H", 3600000000ull},
    };
    for (const auto& test_case : cases) {
        LocalGrpcDeadline deadline;
        CHECK_EQ(local_grpc_deadline_from_value(
                     {test_case.value, static_cast<u32>(__builtin_strlen(test_case.value))},
                     100,
                     deadline),
                 LocalGrpcDeadlineParse::Present);
        CHECK_EQ(deadline.deadline_us, 100 + test_case.micros);
        if (test_case.micros != 0) CHECK_FALSE(deadline.expired(99 + test_case.micros));
        CHECK(deadline.expired(100 + test_case.micros));
    }
}

TEST(local_grpc_deadline, rejects_invalid_and_duplicate_values) {
    const char* invalid[] = {"", "1", "xS", "1X", "1234567890S"};
    for (const char* value : invalid) {
        LocalGrpcDeadline deadline;
        CHECK_EQ(local_grpc_deadline_from_value(
                     {value, static_cast<u32>(__builtin_strlen(value))}, 0, deadline),
                 LocalGrpcDeadlineParse::Invalid);
        CHECK_FALSE(deadline.present);
    }
    LocalGrpcDeadline deadline;
    CHECK_EQ(local_grpc_deadline_from_value({"1S", 2}, 10, deadline),
             LocalGrpcDeadlineParse::Present);
    CHECK_EQ(local_grpc_deadline_from_value({"2S", 2}, 10, deadline),
             LocalGrpcDeadlineParse::Duplicate);
    deadline.reset();
    CHECK_FALSE(deadline.present);
    CHECK_EQ(deadline.deadline_us, 0u);
}

TEST(local_grpc_deadline, enforces_digit_limit_and_nanosecond_rounding) {
    u64 micros = 0;
    CHECK(grpc_timeout({"99999999S", 9}, &micros));
    CHECK_FALSE(grpc_timeout({"100000000S", 10}, &micros));
    CHECK(grpc_timeout({"999n", 4}, &micros));
    CHECK_EQ(micros, 1u);
    CHECK(grpc_timeout({"1000n", 5}, &micros));
    CHECK_EQ(micros, 1u);
    CHECK(grpc_timeout({"1001n", 5}, &micros));
    CHECK_EQ(micros, 2u);
}

TEST(local_grpc_deadline, saturates_absolute_deadline) {
    LocalGrpcDeadline deadline;
    CHECK_EQ(local_grpc_deadline_from_value({"99999999H", 9}, UINT64_MAX - 1, deadline),
             LocalGrpcDeadlineParse::Present);
    CHECK_EQ(deadline.deadline_us, UINT64_MAX);
}

TEST(local_grpc_deadline, grpc_web_status_four_trailer_envelope_is_wire_stable) {
    GrpcWebTrailer trailers[] = {{{"grpc-status", 11}, {"4", 1}}};
    u8 envelope[64]{};
    u32 envelope_len = 0;
    REQUIRE(
        grpc_web_encode_trailer_envelope(trailers, 1, envelope, sizeof(envelope), envelope_len));
    CHECK_EQ(envelope[0], 0x80u);
    CHECK_EQ((static_cast<u32>(envelope[1]) << 24) | (static_cast<u32>(envelope[2]) << 16) |
                 (static_cast<u32>(envelope[3]) << 8) | envelope[4],
             envelope_len - 5);
    CHECK(envelope_len >= 19);
    if (envelope_len >= 19) CHECK(__builtin_memcmp(envelope + 5, "grpc-status: 4", 14) == 0);
}

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
