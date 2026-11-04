#include "rut/compiler/analyze.h"
#include "rut/compiler/lexer.h"
#include "rut/compiler/parser.h"
#include "rut/runtime/connection.h"
#include "rut/runtime/slice_pool.h"
#include "rut/runtime/ws_frame.h"
#include "rut/runtime/ws_terminate.h"
#include "test.h"
#include <cstring>
#include <memory>
#include <string>
#include <vector>

using namespace rut;

#if RUT_ENABLE_WEBSOCKET
namespace {
struct Buffers {
    SlicePool pool;
    Connection conn{};
    Buffers() { conn.reset(); }
    ~Buffers() {
        if (conn.ws_c2u_msg) pool.free(conn.ws_c2u_msg);
        if (conn.ws_u2c_msg) pool.free(conn.ws_u2c_msg);
        if (conn.ws_c2u_out) pool.free(conn.ws_c2u_out);
        if (conn.ws_u2c_out) pool.free(conn.ws_u2c_out);
        pool.destroy();
    }
};
struct Probe {
    Connection* conn;
    const std::vector<u8>* expected;
    WsOpcode opcode;
    bool from_client;
    bool dynamic;
    u32 calls = 0;
    bool valid = true;
};
WsFrameAction inspect_payload(
    void* value, WsOpcode opcode, const u8* payload, u64 length, bool from_client) {
    auto& probe = *static_cast<Probe*>(value);
    ++probe.calls;
    probe.valid &= opcode == probe.opcode && from_client == probe.from_client &&
                   length == probe.expected->size() &&
                   memcmp(payload, probe.expected->data(), length) == 0;
    if (!probe.dynamic) return WsFrameAction::Forward;
    probe.conn->ws_handler_output = {
        {reinterpret_cast<const char*>(payload), static_cast<u32>(length)}, 1000, opcode, true};
    return WsFrameAction::ForwardDynamic;
}
}  // namespace

TEST(ws_bulk, allocation_is_atomic_and_never_falls_back_to_a_smaller_limit) {
    for (u32 budget : {3u, 4u}) {
        Buffers owner;
        REQUIRE(owner.pool.init(16, 0, 0, budget));
        owner.conn.ws_max_message_size = 65536;
        const u32 kOrdinary = owner.pool.available();
        const bool kAllocated = owner.conn.alloc_ws_buffers(owner.pool);
        CHECK_EQ(kAllocated, budget == 4u);
        CHECK_EQ(owner.pool.available(), kOrdinary);
        CHECK_EQ(owner.pool.bulk_available(), budget == 4u ? 0u : budget);
        if (!kAllocated) {
            CHECK(owner.conn.ws_c2u_msg == nullptr);
            CHECK(owner.conn.ws_u2c_msg == nullptr);
            CHECK(owner.conn.ws_c2u_out == nullptr);
            CHECK(owner.conn.ws_u2c_out == nullptr);
        } else {
            CHECK_EQ(owner.conn.ws_buffer_capacity(), SlicePool::kBulkSliceSize);
            CHECK(owner.pool.is_bulk(owner.conn.ws_c2u_msg));
            CHECK(owner.pool.is_bulk(owner.conn.ws_u2c_msg));
            CHECK(owner.pool.is_bulk(owner.conn.ws_c2u_out));
            CHECK(owner.pool.is_bulk(owner.conn.ws_u2c_out));
            CHECK(owner.conn.alloc_ws_buffers(owner.pool));
            CHECK_EQ(owner.pool.bulk_available(), 0u);
            // Existing send storage cannot be rebound under a live owner.
            owner.conn.ws_max_message_size = kWsTerminateMessageCapacity;
            CHECK_FALSE(owner.conn.alloc_ws_buffers(owner.pool));
            CHECK_EQ(owner.pool.bulk_available(), 0u);
        }
    }
}

TEST(ws_bulk, default_storage_remains_ordinary_and_invalid_limits_do_not_allocate) {
    Buffers owner;
    REQUIRE(owner.pool.init(16, 0, 0, 4));
    const u32 kBefore = owner.pool.available();
    owner.conn.ws_max_message_size = kWsMaxMessageCapacity + 1;
    CHECK_FALSE(owner.conn.alloc_ws_buffers(owner.pool));
    CHECK_EQ(owner.pool.available(), kBefore);
    CHECK_EQ(owner.pool.bulk_available(), 4u);
    owner.conn.ws_max_message_size = kWsTerminateMessageCapacity;
    REQUIRE(owner.conn.alloc_ws_buffers(owner.pool));
    CHECK_EQ(owner.conn.ws_buffer_capacity(), SlicePool::kSliceSize);
    CHECK_EQ(owner.pool.available(), 12u);
    CHECK_EQ(owner.pool.bulk_available(), 4u);
    CHECK_FALSE(owner.pool.is_bulk(owner.conn.ws_c2u_msg));
}

TEST(ws_bulk, complete_payloads_span_io_slices_in_both_directions_without_truncation) {
    for (u32 size : {65536u, kWsMaxMessageCapacity}) {
        for (bool client : {false, true}) {
            for (bool binary : {false, true}) {
                for (bool dynamic : {false, true}) {
                    Buffers owner;
                    REQUIRE(owner.pool.init(16, 0, 0, 4));
                    owner.conn.ws_max_message_size = size;
                    REQUIRE(owner.conn.alloc_ws_buffers(owner.pool));
                    std::vector<u8> payload(size, static_cast<u8>('a'));
                    payload[16383] = 0xe2;
                    payload[16384] = 0x82;
                    payload[16385] = 0xac;
                    payload[32770] = 0;
                    if (binary) payload[size - 1] = 0xff;
                    const WsOpcode kOpcode = binary ? WsOpcode::Binary : WsOpcode::Text;
                    std::vector<u8> wire(size + kWsMaxHeaderSize);
                    const u8 kKey[] = {1, 2, 3, 4};
                    const u32 kHeader =
                        ws_write_header(wire.data(), kOpcode, true, client, kKey, size);
                    REQUIRE(kHeader != 0);
                    memcpy(wire.data() + kHeader, payload.data(), size);
                    if (client) ws_unmask(wire.data() + kHeader, size, kKey);
                    wire.resize(size + kHeader);
                    WsInspector inspector{};
                    inspector.masked = client;
                    inspector.from_client = client;
                    inspector.max_message_size = size;
                    inspector.dynamic_output = &owner.conn.ws_handler_output;
                    inspector.forward_text.source =
                        dynamic ? WsTextSource::Dynamic : WsTextSource::Literal;
                    Probe probe{&owner.conn, &payload, kOpcode, client, dynamic};
                    u32 offset = 0, produced = 0;
                    while (offset < wire.size()) {
                        const u32 kRemaining = static_cast<u32>(wire.size()) - offset;
                        const u32 kTake = kRemaining > 8191u ? 8191u : kRemaining;
                        u32 consumed = 0;
                        const auto kStatus = ws_inspect(inspector,
                                                        wire.data() + offset,
                                                        kTake,
                                                        owner.conn.ws_c2u_out,
                                                        owner.conn.ws_buffer_capacity(),
                                                        owner.conn.ws_c2u_msg,
                                                        size,
                                                        inspect_payload,
                                                        &probe,
                                                        &consumed,
                                                        &produced);
                        REQUIRE(kStatus == WsInspectStatus::Ok);
                        REQUIRE_EQ(consumed, kTake);
                        offset += consumed;
                        if (offset != wire.size()) {
                            CHECK_EQ(produced, 0u);
                            CHECK_EQ(probe.calls, 0u);
                        }
                    }
                    CHECK_EQ(probe.calls, 1u);
                    CHECK(probe.valid);
                    WsFrameHeader header{};
                    REQUIRE(ws_parse_header(owner.conn.ws_c2u_out, produced, client, &header) ==
                            ParseStatus::Complete);
                    CHECK(header.opcode == kOpcode);
                    CHECK(header.fin);
                    CHECK_EQ(header.payload_len, size);
                    CHECK_EQ(produced, header.header_len + size);
                    std::vector<u8> actual(size);
                    memcpy(actual.data(), owner.conn.ws_c2u_out + header.header_len, size);
                    if (client) ws_unmask(actual.data(), size, header.mask_key);
                    CHECK(actual == payload);
                }
            }
        }
    }
}

TEST(ws_bulk, compiler_accepts_bulk_limits_and_keeps_the_default_output_limit) {
    for (const char* limit : {"16371b", "16kb", "64kb", "262130b"}) {
        std::string source =
            std::string("upstream ws\nroute GET \"/\" { return websocket(ws, maxMessageSize: ") +
            limit + ") { msg in msg.forward(msg.payload) } }";
        auto tokens = lex({source.data(), static_cast<u32>(source.size())});
        REQUIRE(tokens);
        auto parsed = parse_file(tokens.value());
        REQUIRE(parsed);
        std::unique_ptr<AstFile> ast(parsed.value());
        auto result = analyze_file(*ast);
        REQUIRE(result);
        delete result.value();
    }
    for (bool explicit_limit : {false, true}) {
        std::string source = "upstream ws\nroute GET \"/\" { return websocket(ws";
        if (explicit_limit) source += ", maxMessageSize: 64kb";
        source += ") { msg in msg.forward(\"";
        source.append(20000, 'x');
        source += "\") } }";
        auto tokens = lex({source.data(), static_cast<u32>(source.size())});
        REQUIRE(tokens);
        auto parsed = parse_file(tokens.value());
        REQUIRE(parsed);
        std::unique_ptr<AstFile> ast(parsed.value());
        auto result = analyze_file(*ast);
        CHECK_EQ(static_cast<bool>(result), explicit_limit);
        if (result) delete result.value();
    }
}
#endif

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
