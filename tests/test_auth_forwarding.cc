#include "rut/common/buffer.h"
#include "rut/common/types.h"
#include "rut/runtime/callbacks_h2.h"
#include "rut/runtime/callbacks_impl.h"
#include "rut/runtime/connection.h"
#include "rut/runtime/io_event.h"
#include "test.h"
#include "test_helpers.h"

#include <string.h>

TEST(remove_header, strips_all_credentials_preserving_body_and_pipeline_tail) {
    SmallLoop loop;
    loop.setup();
    auto* c = loop.alloc_conn();
    REQUIRE(c != nullptr);
    const char kRequest[] =
        "POST / HTTP/1.1\r\nHost: client\r\nAuthorization: Bearer one\r\n"
        "authorization: Bearer two\r\nX-API-Key: first\r\nx-api-key: second\r\n"
        "Content-Length: 4\r\nX-Keep: yes\r\n\r\nbodyGET /next HTTP/1.1\r\nHost: "
        "client\r\nAuthorization: next-secret\r\n\r\n";
    const char kExpected[] =
        "POST / HTTP/1.1\r\nHost: client\r\nContent-Length: 4\r\nX-Keep: yes\r\n\r\n"
        "bodyGET /next HTTP/1.1\r\nHost: client\r\nAuthorization: next-secret\r\n\r\n";
    const char kExpectedHead[] =
        "POST / HTTP/1.1\r\nHost: client\r\nContent-Length: 4\r\nX-Keep: yes\r\n\r\n";
    REQUIRE_EQ(c->recv_buf.write(reinterpret_cast<const u8*>(kRequest), sizeof(kRequest) - 1),
               sizeof(kRequest) - 1);
    const char* body = strstr(kRequest, "\r\n\r\n") + 4;
    c->req_header_end = static_cast<u32>(body - kRequest);
    c->req_initial_send_len = c->req_header_end + 4;
    c->req_header_overrides[0] = {lit_str("Authorization"), lit_str("")};
    c->req_header_overrides[1] = {lit_str("X-API-Key"), lit_str("")};
    c->req_header_override_count = 2;
    c->req_header_remove_mask = 3;
    REQUIRE(apply_request_header_overrides(*c));
    CHECK_EQ(c->recv_buf.len(), sizeof(kExpected) - 1);
    CHECK(__builtin_memcmp(c->recv_buf.data(), kExpected, sizeof(kExpected) - 1) == 0);
    CHECK_EQ(c->req_header_end, sizeof(kExpectedHead) - 1);
    CHECK_EQ(c->req_initial_send_len, sizeof(kExpectedHead) - 1 + 4);
    loop.free_conn(*c);
}

TEST(remove_header, honors_order_with_set_add_empty_values_and_missing_fields) {
    SmallLoop loop;
    loop.setup();
    auto* c = loop.alloc_conn();
    REQUIRE(c != nullptr);
    const char kRequest[] = "GET / HTTP/1.1\r\nHost: client\r\nAuthorization: client\r\n\r\n";
    REQUIRE_EQ(c->recv_buf.write(reinterpret_cast<const u8*>(kRequest), sizeof(kRequest) - 1),
               sizeof(kRequest) - 1);
    c->req_header_end = sizeof(kRequest) - 1;
    c->req_initial_send_len = c->req_header_end;
    c->req_header_overrides[0] = {lit_str("Authorization"), lit_str("")};
    c->req_header_overrides[1] = {lit_str("Authorization"), lit_str("set")};
    c->req_header_overrides[2] = {lit_str("Authorization"), lit_str("append")};
    c->req_header_overrides[3] = {lit_str("authorization"), lit_str("")};
    c->req_header_overrides[4] = {lit_str("Authorization"), lit_str("final")};
    c->req_header_overrides[5] = {lit_str("X-Empty"), lit_str("")};
    c->req_header_overrides[6] = {lit_str("X-Missing"), lit_str("")};
    c->req_header_override_count = 7;
    c->req_header_append_mask = (1u << 2) | (1u << 4);
    c->req_header_remove_mask = (1u << 0) | (1u << 3) | (1u << 6);
    REQUIRE(apply_request_header_overrides(*c));
    const char kExpected[] =
        "GET / HTTP/1.1\r\nHost: client\r\nAuthorization: final\r\nX-Empty: \r\n\r\n";
    CHECK_EQ(c->recv_buf.len(), sizeof(kExpected) - 1);
    CHECK(__builtin_memcmp(c->recv_buf.data(), kExpected, sizeof(kExpected) - 1) == 0);
    loop.free_conn(*c);
}

TEST(remove_header, invalid_or_conflicting_direct_ir_effects_fail_closed) {
    const Str kNames[] = {lit_str(""),
                          lit_str("Bad Header"),
                          lit_str("X\r\nInjected"),
                          lit_str("Content-Length"),
                          lit_str("Transfer-Encoding"),
                          lit_str("Connection"),
                          {nullptr, 5}};
    for (const Str kName : kNames) {
        SmallLoop loop;
        loop.setup();
        auto* c = loop.alloc_conn();
        REQUIRE(c != nullptr);
        const char kRequest[] = "GET / HTTP/1.1\r\nHost: client\r\nAuthorization: secret\r\n\r\n";
        REQUIRE_EQ(c->recv_buf.write(reinterpret_cast<const u8*>(kRequest), sizeof(kRequest) - 1),
                   sizeof(kRequest) - 1);
        c->req_header_end = sizeof(kRequest) - 1;
        c->req_initial_send_len = c->req_header_end;
        c->req_header_overrides[0] = {kName, lit_str("")};
        c->req_header_override_count = 1;
        c->req_header_remove_mask = 1;
        CHECK(!apply_request_header_overrides(*c));
        CHECK_EQ(c->recv_buf.len(), sizeof(kRequest) - 1);
        CHECK(__builtin_memcmp(c->recv_buf.data(), kRequest, sizeof(kRequest) - 1) == 0);
        c->req_header_overrides[0].name = lit_str("Authorization");
        c->req_header_append_mask = 1;
        CHECK(!apply_request_header_overrides(*c));
        c->req_header_append_mask = 0;
        c->req_header_overrides[0].value = lit_str("ambiguous");
        CHECK(!apply_request_header_overrides(*c));
        loop.free_conn(*c);
    }
}

TEST(http2, forward_request_removes_credentials_and_reset_clears_removal_modes) {
    Connection conn;
    conn.reset();
    conn.req_header_overrides[0] = {lit_str("Authorization"), lit_str("")};
    conn.req_header_overrides[1] = {lit_str("X-API-Key"), lit_str("")};
    conn.req_header_override_count = 2;
    conn.req_header_remove_mask = 3;
    static const char kRequest[] =
        "GET / HTTP/1.1\r\nHost: upstream\r\nAuthorization: Bearer secret\r\n"
        "authorization: duplicate\r\nX-API-Key: key\r\nX-Keep: yes\r\n\r\n";
    static const char kExpected[] = "GET / HTTP/1.1\r\nHost: upstream\r\nX-Keep: yes\r\n\r\n";
    u8 out[512]{};
    u32 out_len = 0;
    REQUIRE(h2_prepare_forward_request(conn,
                                       reinterpret_cast<const u8*>(kRequest),
                                       sizeof(kRequest) - 1,
                                       out,
                                       sizeof(out),
                                       &out_len));
    CHECK_EQ(out_len, sizeof(kExpected) - 1);
    CHECK(__builtin_memcmp(out, kExpected, sizeof(kExpected) - 1) == 0);
    conn.req_header_owned_bytes = 42;
    h2_reset_request_mutations(conn);
    CHECK_EQ(conn.req_header_owned_bytes, 0u);
    CHECK_EQ(conn.req_header_override_count, 0u);
    CHECK_EQ(conn.req_header_remove_mask, 0u);
    CHECK_EQ(conn.req_header_append_mask, 0u);
    REQUIRE(h2_prepare_forward_request(conn,
                                       reinterpret_cast<const u8*>(kRequest),
                                       sizeof(kRequest) - 1,
                                       out,
                                       sizeof(out),
                                       &out_len));
    CHECK_EQ(out_len, sizeof(kRequest) - 1);
    CHECK(__builtin_memcmp(out, kRequest, sizeof(kRequest) - 1) == 0);
    conn.req_header_remove_mask = 3;
    conn.req_header_owned_bytes = 42;
    conn.reset();
    CHECK_EQ(conn.req_header_owned_bytes, 0u);
    CHECK_EQ(conn.req_header_remove_mask, 0u);
}

TEST(remove_header, http1_new_request_boundary_discards_old_removal_modes) {
    SmallLoop loop;
    loop.setup();
    auto* c = loop.alloc_conn();
    REQUIRE(c != nullptr);
    c->req_header_override_count = 1;
    c->req_header_owned_bytes = 42;
    c->req_header_remove_mask = 1;
    c->req_header_overrides[0] = {lit_str("Authorization"), lit_str("")};
    static const char kRequest[] = "GET / HTTP/1.1\r\nHost: client\r\nAuthorization: next\r\n\r\n";
    REQUIRE_EQ(c->recv_buf.write(reinterpret_cast<const u8*>(kRequest), sizeof(kRequest) - 1),
               sizeof(kRequest) - 1);
    on_header_received<SmallLoop>(
        &loop, *c, make_ev(c->id, IoEventType::Recv, sizeof(kRequest) - 1));
    CHECK_EQ(c->req_header_override_count, 0u);
    CHECK_EQ(c->req_header_owned_bytes, 0u);
    CHECK_EQ(c->req_header_remove_mask, 0u);
    loop.free_conn(*c);
}

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
