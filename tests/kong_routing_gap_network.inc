// Production materializer witnesses under the existing deterministic SmallLoop.
// These do not claim live TLS handshakes, H2 stream forwarding or Kong oracle runs.
static void kong_gap_transform_witness(rut::test::TestCase* _tc,
                                       const char* request,
                                       const char* expected_target) {
    SmallLoop loop;
    loop.setup();
    RouteConfig config{};
    REQUIRE(config.add_upstream("backend", 0x7f000001, 8080).has_value());
    REQUIRE_EQ(config.add_target_transform({{"/api/", 5}, {"/v1/", 4}}), 1u);
    auto* conn = setup_target_transform_request(loop, config, request, strlen(request));
    REQUIRE(conn != nullptr);
    u8 original[SmallLoop::kBufSize];
    const u32 original_len = conn->recv_buf.len();
    const u32 original_header_end = conn->req_header_end;
    const u32 original_send_len = conn->req_initial_send_len;
    __builtin_memcpy(original, conn->recv_buf.data(), original_len);
    loop.backend.clear_ops();
    const bool accepted = materialize_request_target_transform(*conn, config);
    if (expected_target != nullptr) {
        REQUIRE(accepted);
        HttpParser parser;
        ParsedRequest parsed{};
        parser.reset();
        REQUIRE(parser.parse(conn->recv_buf.data(), conn->recv_buf.len(), &parsed) ==
                ParseStatus::Complete);
        CHECK(parsed.path.eq({expected_target, static_cast<u32>(strlen(expected_target))}));
    } else {
        CHECK_FALSE(accepted);
        CHECK_EQ(conn->recv_buf.len(), original_len);
        CHECK_EQ(conn->req_header_end, original_header_end);
        CHECK_EQ(conn->req_initial_send_len, original_send_len);
        CHECK_EQ(__builtin_memcmp(original, conn->recv_buf.data(), original_len), 0);
        CHECK_EQ(loop.backend.op_count, 0u);
        // Verify ordinary Forward dispatch refuses it before upstream effects.
        JitDispatchOutcome outcome{};
        outcome.kind = JitDispatchOutcome::Kind::Forward;
        outcome.upstream_id = 0;
        handle_jit_outcome<SmallLoop>(&loop, *conn, outcome, nullptr, true);
        CHECK_EQ(conn->resp_status, 400u);
        CHECK_EQ(conn->upstream_fd, -1);
        CHECK_FALSE(conn->upstream_slot_held);
        CHECK_EQ(loop.backend.count_ops(MockOp::Connect), 0u);
        CHECK_EQ(__builtin_memcmp(original, conn->recv_buf.data(), original_len), 0);
    }
    loop.free_conn(*conn);
}

TEST(kong_routing_gap, clean_prefix_transform_preserves_runtime_suffix_and_raw_query) {
    kong_gap_transform_witness(
        _tc, "GET /api/users?x=1&x=2 HTTP/1.1\r\nHost: client\r\n\r\n", "/v1/users?x=1&x=2");
    // The restriction is about body/framing, not a blanket POST prohibition.
    kong_gap_transform_witness(
        _tc, "POST /api/users HTTP/1.1\r\nHost: client\r\n\r\n", "/v1/users");
}

TEST(kong_routing_gap, normalization_sensitive_targets_refuse_before_upstream_contact) {
    kong_gap_transform_witness(_tc, "GET /api/%75sers HTTP/1.1\r\nHost: client\r\n\r\n", nullptr);
    kong_gap_transform_witness(_tc, "GET /api//users HTTP/1.1\r\nHost: client\r\n\r\n", nullptr);
    kong_gap_transform_witness(_tc, "GET /api/../admin HTTP/1.1\r\nHost: client\r\n\r\n", nullptr);
}

TEST(kong_routing_gap, request_body_and_explicit_zero_length_refuse_prefix_transform) {
    kong_gap_transform_witness(
        _tc, "POST /api/users HTTP/1.1\r\nHost: client\r\nContent-Length: 1\r\n\r\na", nullptr);
    kong_gap_transform_witness(
        _tc, "GET /api/users HTTP/1.1\r\nHost: client\r\nContent-Length: 0\r\n\r\n", nullptr);
}

TEST(kong_routing_gap, tls_and_h2_connection_flags_refuse_prefix_materialization_atomically) {
    SmallLoop loop;
    loop.setup();
    RouteConfig config{};
    REQUIRE_EQ(config.add_target_transform({{"/api/", 5}, {"/v1/", 4}}), 1u);
    const char request[] = "GET /api/users HTTP/1.1\r\nHost: client\r\n\r\n";
    for (u32 mode = 0; mode < 2; mode++) {
        auto* conn = setup_target_transform_request(loop, config, request, sizeof(request) - 1);
        REQUIRE(conn != nullptr);
        const auto original_protocol = conn->protocol;
        conn->tls_active = mode == 0;
        if (mode == 1) conn->protocol = ConnProtocol::Http2;
        loop.backend.clear_ops();
        CHECK_FALSE(materialize_request_target_transform(*conn, config));
        CHECK_EQ(conn->recv_buf.len(), sizeof(request) - 1);
        CHECK_EQ(__builtin_memcmp(conn->recv_buf.data(), request, sizeof(request) - 1), 0);
        CHECK_EQ(loop.backend.op_count, 0u);
        conn->tls_active = false;
        conn->protocol = original_protocol;
        loop.free_conn(*conn);
    }
}

TEST(kong_routing_gap, dispatch_does_not_normalize_dot_segments_or_unreserved_escapes) {
    RouteConfig config{};
    REQUIRE(config.add_static("/", 0, 404));
    REQUIRE(config.add_static("/api", 0, 201));
    REQUIRE(config.add_static("/admin", 0, 202));
    REQUIRE(config.add_static("/api/users", 0, 203));
    struct Vector {
        const char* target;
        u16 status;
    };
    const Vector vectors[] = {
        {"/admin", 202},
        {"/api/users", 203},
        {"/api/../admin", 201},
        {"/api/%75sers", 201},
        {"/api//users", 201},
    };
    for (const auto& vector : vectors) {
        const auto* route =
            config.match(reinterpret_cast<const u8*>(vector.target), strlen(vector.target), 0);
        REQUIRE(route != nullptr);
        CHECK_EQ(route->status_code, vector.status);
    }
}
