#include "rut/runtime/slice_pool.h"
#include "rut/runtime/ws_deflate.h"
#include "rut/runtime/ws_frame.h"
#include "rut/runtime/ws_terminate.h"
#include "test.h"
#include <cstring>
#include <vector>

using namespace rut;

#if RUT_ENABLE_WEBSOCKET
namespace {
struct Owner {
    SlicePool pool;
    WsDeflateCodec* codec = nullptr;
    ~Owner() {
        ws_deflate_destroy(pool, codec);
        pool.destroy();
    }
    bool init(WsDeflateOptions options = {}) {
        return pool.init(16, 0, 0, 1).has_value() &&
               (codec = ws_deflate_create(pool, options)) != nullptr;
    }
};
constexpr u8 kHello[] = {0xf2, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00};
// RFC 7692 section 7.2.3.2: the second message refers to the first one's history.
constexpr u8 kHelloAgain[] = {0xf2, 0x00, 0x11, 0x00, 0x00};
}  // namespace

TEST(ws_deflate, rfc_vectors_decode_with_split_input_and_frame_relative_masking) {
    const std::vector<std::vector<u8>> vectors = {
        {kHello, kHello + sizeof(kHello)},
        {0xf3, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00, 0x00},  // BFINAL=1
        {0x00, 0x05, 0x00, 0xfa, 0xff, 'H', 'e', 'l', 'l', 'o', 0x00},
        {0xf2, 0x48, 0x05, 0x00, 0x00, 0x00, 0xff, 0xff, 0xca, 0xc9, 0xc9, 0x07, 0x00},
    };
    for (const auto& bytes : vectors) {
        for (u32 stride : {1u, 3u, 32u}) {
            for (bool masked : {false, true}) {
                Owner owner;
                REQUIRE(owner.init());
                REQUIRE(ws_inflate_begin(*owner.codec, 32));
                u8 output[32]{};
                u32 length = 0;
                const u8 key[] = {4, 3, 2, 1};
                auto wire = bytes;
                if (masked) ws_unmask(wire.data(), wire.size(), key);
                for (u32 offset = 0; offset < wire.size();) {
                    const u32 take = wire.size() - offset < stride
                                         ? static_cast<u32>(wire.size()) - offset
                                         : stride;
                    REQUIRE_EQ(ws_inflate_chunk(*owner.codec,
                                                wire.data() + offset,
                                                take,
                                                false,
                                                output,
                                                sizeof(output),
                                                &length,
                                                masked ? key : nullptr,
                                                offset),
                               WsDeflateStatus::Ok);
                    offset += take;
                }
                REQUIRE_EQ(ws_inflate_chunk(*owner.codec, nullptr, 0, true, output, 32, &length),
                           WsDeflateStatus::Ok);
                CHECK_EQ(length, 5u);
                CHECK_EQ(memcmp(output, "Hello", 5), 0);
            }
        }
    }
}

TEST(ws_deflate, receive_history_survives_message_boundaries_unless_negotiated_away) {
    for (bool reset : {false, true}) {
        Owner owner;
        REQUIRE(owner.init({15, 15, reset}));
        u8 output[32]{};
        u32 length = 0;
        REQUIRE(ws_inflate_begin(*owner.codec, 32));
        REQUIRE_EQ(
            ws_inflate_chunk(*owner.codec, kHello, sizeof(kHello), true, output, 32, &length),
            WsDeflateStatus::Ok);
        CHECK_EQ(length, 5u);
        REQUIRE(ws_inflate_begin(*owner.codec, 32));
        const auto status = ws_inflate_chunk(
            *owner.codec, kHelloAgain, sizeof(kHelloAgain), true, output, 32, &length);
        CHECK_EQ(status, reset ? WsDeflateStatus::Error : WsDeflateStatus::Ok);
        if (!reset) {
            CHECK_EQ(length, 5u);
            CHECK_EQ(memcmp(output, "Hello", 5), 0);
        }
    }
}

TEST(ws_deflate, bfinal_streams_preserve_history_inside_and_between_messages) {
    Owner owner;
    REQUIRE(owner.init());
    const u8 wire[] = {0xf3, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00, 0xf2, 0x00, 0x11, 0x00, 0x00};
    u8 output[32]{};
    u32 length = 0;
    REQUIRE(ws_inflate_begin(*owner.codec, 32));
    REQUIRE_EQ(ws_inflate_chunk(*owner.codec, wire, sizeof(wire), true, output, 32, &length),
               WsDeflateStatus::Ok);
    CHECK_EQ(length, 10u);
    CHECK_EQ(memcmp(output, "HelloHello", 10), 0);
    REQUIRE(ws_inflate_begin(*owner.codec, 32));
    REQUIRE_EQ(
        ws_inflate_chunk(*owner.codec, kHelloAgain, sizeof(kHelloAgain), true, output, 32, &length),
        WsDeflateStatus::Ok);
    CHECK_EQ(length, 5u);
    CHECK_EQ(memcmp(output, "Hello", 5), 0);
}

TEST(ws_deflate, decoded_and_wire_work_limits_fail_without_publishing_partial_output) {
    {
        Owner owner;
        REQUIRE(owner.init());
        REQUIRE(ws_inflate_begin(*owner.codec, 4));
        u8 output[32]{};
        u32 length = 99;
        CHECK_EQ(ws_inflate_chunk(*owner.codec, kHello, sizeof(kHello), true, output, 32, &length),
                 WsDeflateStatus::Limit);
        CHECK_EQ(length, 0u);
        CHECK_FALSE(ws_inflate_begin(*owner.codec, 32));
    }
    {
        Owner owner;
        REQUIRE(owner.init());
        REQUIRE(ws_inflate_begin(*owner.codec, 32));
        std::vector<u8> wire(ws_deflate_wire_limit(32) + 1, 0);
        u8 output[32]{};
        u32 length = 99;
        CHECK_EQ(ws_inflate_chunk(*owner.codec,
                                  wire.data(),
                                  static_cast<u32>(wire.size()),
                                  true,
                                  output,
                                  32,
                                  &length),
                 WsDeflateStatus::Limit);
        CHECK_EQ(length, 0u);
    }
    for (const auto& wire : {std::vector<u8>{0xff}, std::vector<u8>{0xf2, 0x48, 0xcd}}) {
        Owner owner;
        REQUIRE(owner.init());
        REQUIRE(ws_inflate_begin(*owner.codec, 32));
        u8 output[32]{};
        u32 length = 99;
        CHECK_EQ(ws_inflate_chunk(*owner.codec,
                                  wire.data(),
                                  static_cast<u32>(wire.size()),
                                  true,
                                  output,
                                  32,
                                  &length),
                 WsDeflateStatus::Error);
        CHECK_EQ(length, 0u);
    }
}

TEST(ws_deflate, all_window_sizes_and_large_incompressible_payloads_fit_one_codec_slice) {
    for (u8 window = 8; window <= 15; ++window) {
        Owner owner;
        REQUIRE(owner.init({window, window, false}));
        std::vector<u8> input(kWsMaxMessageCapacity);
        u32 random = 0x12345678;
        for (u8& byte : input) {
            random ^= random << 13;
            random ^= random >> 17;
            random ^= random << 5;
            byte = static_cast<u8>(random);
        }
        std::vector<u8> compressed(ws_deflate_wire_limit(kWsMaxMessageCapacity));
        std::vector<u8> output(input.size());
        u32 compressed_length = 0;
        u32 output_length = 0;
        u32 storage_after_first_message = 0;
        for (u32 round = 0; round < 3; ++round) {
            REQUIRE_EQ(ws_deflate_payload(*owner.codec,
                                          input.data(),
                                          static_cast<u32>(input.size()),
                                          compressed.data(),
                                          static_cast<u32>(compressed.size()),
                                          &compressed_length),
                       WsDeflateStatus::Ok);
            REQUIRE(ws_inflate_begin(*owner.codec, kWsMaxMessageCapacity));
            REQUIRE_EQ(ws_inflate_chunk(*owner.codec,
                                        compressed.data(),
                                        compressed_length,
                                        true,
                                        output.data(),
                                        static_cast<u32>(output.size()),
                                        &output_length),
                       WsDeflateStatus::Ok);
            CHECK_EQ(output_length, input.size());
            CHECK_EQ(memcmp(output.data(), input.data(), input.size()), 0);
            CHECK(ws_deflate_storage_used(*owner.codec) < SlicePool::kBulkSliceSize);
            if (round == 0)
                storage_after_first_message = ws_deflate_storage_used(*owner.codec);
            else
                CHECK_EQ(ws_deflate_storage_used(*owner.codec), storage_after_first_message);
        }
    }
}

TEST(ws_deflate, encoder_recovers_after_bounded_output_fallback_and_preserves_empty_messages) {
    Owner owner;
    REQUIRE(owner.init());
    u8 wire[64]{};
    u8 output[32]{};
    u32 length = 0;
    CHECK_EQ(
        ws_deflate_payload(*owner.codec, reinterpret_cast<const u8*>("Hello"), 5, wire, 4, &length),
        WsDeflateStatus::Limit);
    CHECK_EQ(length, 0u);
    for (u32 size : {5u, 0u}) {
        REQUIRE_EQ(ws_deflate_payload(*owner.codec,
                                      reinterpret_cast<const u8*>("Hello"),
                                      size,
                                      wire,
                                      sizeof(wire),
                                      &length),
                   WsDeflateStatus::Ok);
        if (size == 5) {
            CHECK_EQ(length, sizeof(kHello));
            CHECK_EQ(memcmp(wire, kHello, sizeof(kHello)), 0);
        }
        REQUIRE(ws_inflate_begin(*owner.codec, 32));
        REQUIRE_EQ(ws_inflate_chunk(*owner.codec, wire, length, true, output, 32, &length),
                   WsDeflateStatus::Ok);
        CHECK_EQ(length, size);
        CHECK_EQ(memcmp(output, "Hello", size), 0);
    }
}

TEST(ws_deflate, creation_failure_and_destroy_restore_the_bulk_pool_budget) {
    Owner owner;
    REQUIRE(owner.pool.init(16, 0, 0, 1));
    CHECK(ws_deflate_create(owner.pool, {7, 15, false}) == nullptr);
    CHECK(ws_deflate_create(owner.pool, {15, 16, false}) == nullptr);
    CHECK_EQ(owner.pool.bulk_available(), 1u);
    owner.codec = ws_deflate_create(owner.pool, {});
    REQUIRE(owner.codec != nullptr);
    CHECK_EQ(owner.pool.bulk_available(), 0u);
    CHECK(ws_deflate_create(owner.pool, {}) == nullptr);
    ws_deflate_destroy(owner.pool, owner.codec);
    owner.codec = nullptr;
    CHECK_EQ(owner.pool.bulk_available(), 1u);
}
#endif

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
