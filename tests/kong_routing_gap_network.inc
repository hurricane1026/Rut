// Production materializer witnesses under the existing deterministic SmallLoop.
// These do not claim live TLS handshakes, H2 stream forwarding or Kong oracle runs.
static void kong_gap_transform_witness(
    rut::test::TestCase* _tc,
    const char* request,
    const char* expected_target,
    ForwardTargetTransformMode mode = ForwardTargetTransformMode::CleanPrefix) {
    SlicePool arena_pool;
    if (mode != ForwardTargetTransformMode::CleanPrefix) REQUIRE(arena_pool.init(8));
    SmallLoop loop;
    loop.setup();
    RouteConfig config{};
    REQUIRE(config.add_upstream("backend", 0x7f000001, 8080).has_value());
    REQUIRE_EQ(config.add_target_transform({{"/api/", 5}, {"/v1/", 4}, mode}), 1u);
    auto* conn = setup_target_transform_request(loop, config, request, strlen(request));
    REQUIRE(conn != nullptr);
    if (mode != ForwardTargetTransformMode::CleanPrefix)
        conn->json_arena.backend.pool = &arena_pool;
    u8 original[SmallLoop::kBufSize];
    const u32 kOriginalLen = conn->recv_buf.len();
    const u32 kOriginalHeaderEnd = conn->req_header_end;
    const u32 kOriginalSendLen = conn->req_initial_send_len;
    __builtin_memcpy(original, conn->recv_buf.data(), kOriginalLen);
    loop.backend.clear_ops();
    const bool kAccepted = materialize_request_target_transform(*conn, config);
    if (expected_target != nullptr) {
        REQUIRE(kAccepted);
        HttpParser parser;
        ParsedRequest parsed{};
        parser.reset();
        REQUIRE(parser.parse(conn->recv_buf.data(), conn->recv_buf.len(), &parsed) ==
                ParseStatus::Complete);
        CHECK(parsed.path.eq({expected_target, static_cast<u32>(strlen(expected_target))}));
    } else {
        CHECK_FALSE(kAccepted);
        CHECK_EQ(conn->recv_buf.len(), kOriginalLen);
        CHECK_EQ(conn->req_header_end, kOriginalHeaderEnd);
        CHECK_EQ(conn->req_initial_send_len, kOriginalSendLen);
        CHECK_EQ(__builtin_memcmp(original, conn->recv_buf.data(), kOriginalLen), 0);
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
        CHECK_EQ(__builtin_memcmp(original, conn->recv_buf.data(), kOriginalLen), 0);
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

TEST(kong_routing_gap, legacy_clean_profile_refuses_normalization_sensitive_targets) {
    kong_gap_transform_witness(_tc, "GET /api/%75sers HTTP/1.1\r\nHost: client\r\n\r\n", nullptr);
    kong_gap_transform_witness(_tc, "GET /api//users HTTP/1.1\r\nHost: client\r\n\r\n", nullptr);
    kong_gap_transform_witness(_tc, "GET /api/../admin HTTP/1.1\r\nHost: client\r\n\r\n", nullptr);
}

TEST(kong_routing_gap, legacy_clean_profile_refuses_body_and_explicit_length) {
    kong_gap_transform_witness(
        _tc, "POST /api/users HTTP/1.1\r\nHost: client\r\nContent-Length: 1\r\n\r\na", nullptr);
    kong_gap_transform_witness(
        _tc, "GET /api/users HTTP/1.1\r\nHost: client\r\nContent-Length: 0\r\n\r\n", nullptr);
}

TEST(kong_routing_gap, legacy_clean_profile_refuses_tls_and_h2_materialization) {
    SmallLoop loop;
    loop.setup();
    RouteConfig config{};
    REQUIRE_EQ(config.add_target_transform({{"/api/", 5}, {"/v1/", 4}}), 1u);
    const char kRequest[] = "GET /api/users HTTP/1.1\r\nHost: client\r\n\r\n";
    for (u32 mode = 0; mode < 2; mode++) {
        auto* conn = setup_target_transform_request(loop, config, kRequest, sizeof(kRequest) - 1);
        REQUIRE(conn != nullptr);
        const auto kOriginalProtocol = conn->protocol;
        conn->tls_active = mode == 0;
        if (mode == 1) conn->protocol = ConnProtocol::Http2;
        loop.backend.clear_ops();
        CHECK_FALSE(materialize_request_target_transform(*conn, config));
        CHECK_EQ(conn->recv_buf.len(), sizeof(kRequest) - 1);
        CHECK_EQ(__builtin_memcmp(conn->recv_buf.data(), kRequest, sizeof(kRequest) - 1), 0);
        CHECK_EQ(loop.backend.op_count, 0u);
        conn->tls_active = false;
        conn->protocol = kOriginalProtocol;
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
    const Vector kVectors[] = {
        {"/admin", 202},
        {"/api/users", 203},
        {"/api/../admin", 201},
        {"/api/%75sers", 201},
        {"/api//users", 201},
    };
    for (const auto& vector : kVectors) {
        const auto* route =
            config.match(reinterpret_cast<const u8*>(vector.target), strlen(vector.target), 0);
        REQUIRE(route != nullptr);
        CHECK_EQ(route->status_code, vector.status);
    }
}

TEST(kong_routing_gap, explicit_general_prefix_preserves_body_and_encoded_targets) {
    kong_gap_transform_witness(
        _tc,
        "POST /api/users HTTP/1.1\r\nHost: client\r\nContent-Length: 7\r\n\r\npayload",
        "/v1/users",
        ForwardTargetTransformMode::RawPrefix);
    kong_gap_transform_witness(
        _tc,
        "GET /api/users HTTP/1.1\r\nHost: client\r\nContent-Length: 0\r\n\r\n",
        "/v1/users",
        ForwardTargetTransformMode::RawPrefix);
    kong_gap_transform_witness(_tc,
                               "GET /api/%75sers?x=%2f HTTP/1.1\r\nHost: client\r\n\r\n",
                               "/v1/%75sers?x=%2f",
                               ForwardTargetTransformMode::RawPrefix);
    kong_gap_transform_witness(_tc,
                               "GET /api//a/../%75sers?x=%2f HTTP/1.1\r\nHost: client\r\n\r\n",
                               "/v1/users?x=%2f",
                               ForwardTargetTransformMode::NormalizedPrefix);
}

TEST(kong_routing_gap,
     general_prefix_capacity_failure_preserves_request_and_releases_arena_on_close) {
    SlicePool arena_pool;
    REQUIRE(arena_pool.init(8));
    SmallLoop loop;
    loop.setup();
    RouteConfig config{};
    char replacement[96];
    __builtin_memset(replacement, 'x', sizeof(replacement));
    replacement[0] = '/';
    replacement[sizeof(replacement) - 1] = '/';
    REQUIRE_EQ(config.add_target_transform({{"/api/", 5},
                                            {replacement, sizeof(replacement)},
                                            ForwardTargetTransformMode::RawPrefix}),
               1u);
    const u32 kInUse = arena_pool.count - arena_pool.available();
    char request[SmallLoop::kBufSize];
    const u32 kBody = sizeof(request) - 96;
    const int kHeader =
        snprintf(request,
                 sizeof(request),
                 "POST /api/x HTTP/1.1\r\nHost: client\r\nContent-Length: %u\r\n\r\n",
                 kBody);
    REQUIRE_GT(kHeader, 0);
    REQUIRE_LT(static_cast<u32>(kHeader) + kBody, sizeof(request));
    __builtin_memset(request + kHeader, 'b', kBody);
    const u32 kLength = static_cast<u32>(kHeader) + kBody;
    for (u32 attempt = 0; attempt < 4; attempt++) {
        auto* conn = setup_target_transform_request(loop, config, request, kLength);
        REQUIRE(conn != nullptr);
        conn->json_arena.backend.pool = &arena_pool;
        CHECK_FALSE(materialize_request_target_transform(*conn, config));
        CHECK_EQ(conn->recv_buf.len(), kLength);
        CHECK_EQ(__builtin_memcmp(conn->recv_buf.data(), request, kLength), 0);
        CHECK_FALSE(conn->req_path_overridden);
        CHECK(conn->target_transform_recorded);
        loop.close_conn(*conn);
        CHECK_EQ(arena_pool.count - arena_pool.available(), kInUse);
    }
}

TEST(kong_routing_gap,
     general_prefix_preserves_borrowed_after_header_and_disables_raw_snapshot_replay) {
    SlicePool pool;
    REQUIRE(pool.init(8));
    SmallLoop loop;
    loop.setup();
    RouteConfig config{};
    REQUIRE_EQ(config.add_target_transform(
                   {{"/api/", 5}, {"/v1/", 4}, ForwardTargetTransformMode::RawPrefix}),
               1u);
    const char kRequest[] = "GET /api/users?x=1 HTTP/1.1\r\nHost: client\r\n\r\n";
    auto* conn = setup_target_transform_request(loop, config, kRequest, sizeof(kRequest) - 1);
    REQUIRE(conn != nullptr);
    conn->json_arena.backend.pool = &pool;
    conn->resp_header_mutation_count = 1;
    conn->resp_header_mutation_pending_count = 1;
    conn->resp_header_mutations[0] = {
        {"X-Path", 6},
        {reinterpret_cast<const char*>(conn->recv_buf.data() + 4), sizeof("/api/users?x=1") - 1},
        Connection::RespHeaderMutationMode::Set};
    REQUIRE(materialize_request_target_transform(*conn, config));
    CHECK(
        conn->resp_header_mutations[0].value.eq({"/api/users?x=1", sizeof("/api/users?x=1") - 1}));
    CHECK(conn->response_mutations_snapshotted);
    CHECK_FALSE(conn->retry_req_snapshot_replayable);
    CHECK_FALSE(conn->target_transform_recorded);
    loop.close_conn(*conn);
    CHECK_EQ(pool.count - pool.available(), 0u);
}
