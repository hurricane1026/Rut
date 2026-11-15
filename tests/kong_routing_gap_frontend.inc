// Executable capability ledger, not a specification of desired restrictions.
// When a gap closes, replace its rejection assertion with a positive witness.
// Included by test_frontend.cc to reuse its owning frontend fixtures.
namespace {
enum class KongGapStage : u8 {
    LexRejected,
    ParseRejected,
    AnalyzeRejected,
    LowerRejected,
    Verified
};

static KongGapStage kong_gap_stage(rut::test::TestCase* _tc,
                                   const char* source,
                                   Str expected_detail = {}) {
    auto tokens = lex(lit(source));
    if (!tokens) return KongGapStage::LexRejected;
    auto ast = parse_file_heap(tokens.value());
    if (!ast) return KongGapStage::ParseRejected;
    auto hir = analyze_file_heap(ast.value());
    if (!hir) {
        if (expected_detail.len != 0) CHECK(hir.error().detail.eq(expected_detail));
        return KongGapStage::AnalyzeRejected;
    }
    auto mir = build_mir_heap(hir.value());
    if (!mir) return KongGapStage::LowerRejected;
    FrontendRirModule rir{};
    if (!lower_to_rir(mir.value(), rir)) return KongGapStage::LowerRejected;
    if (!rir::verify_module(rir.module).ok) return KongGapStage::LowerRejected;
    return KongGapStage::Verified;
}
}  // namespace

TEST(kong_routing_gap, expression_routing_controls_reach_verified_rir) {
    const char* sources[] = {
        "route GET \"/\" { if req.pathOnly == \"/api\" { return 201 } else { return 404 } }",
        "route GET \"/\" { if req.pathOnly.hasPrefix(\"/catalog\") { return 201 } else { return "
        "404 } }",
        "route GET \"/\" { if req.pathOnly.matches(re\"^/v[0-9]+/users/.*$\") { return 201 } else "
        "{ return 404 } }",
        "route GET \"/\" { guard let host = req.host else { return 400 } if host == \"a.example\" "
        "{ return 201 } else { return 202 } }",
        "route GET \"/\" { guard let region = req.header(\"Region\") else { return 400 } if region "
        "== \"north\" { return 201 } else { return 202 } }",
        "route GET \"/\" { guard let version = req.query(\"version\") else { return 400 } if "
        "version == \"v1\" { return 201 } else { return 202 } }",
        "route \"/\" { if req.method == GET || req.method == HEAD { return 201 } else { return 405 "
        "} }",
    };
    for (const char* source : sources) CHECK(kong_gap_stage(_tc, source) == KongGapStage::Verified);
}

TEST(kong_routing_gap, dynamic_captured_path_reaches_verified_rir) {
    CHECK(kong_gap_stage(_tc, R"rut(
upstream b at "127.0.0.1:9000"
route GET "/users/:id" { return forward(b, load_balance: .roundRobin, set_path: "/internal/accounts/fixed") }
)rut") == KongGapStage::Verified);
    CHECK(kong_gap_stage(_tc, R"rut(
upstream b at "127.0.0.1:9000"
route GET "/users/:id" {
    let target = "/internal/accounts/" + req.params.id
    return forward(b, load_balance: .roundRobin, set_path: target)
}
)rut") == KongGapStage::Verified);
}

TEST(kong_routing_gap, dynamic_target_expression_and_branch_types) {
    CHECK(kong_gap_stage(_tc, R"rut(
upstream b at "127.0.0.1:9000"
route GET "/users/:id" {
    if req.pathOnly.hasPrefix("/users/") {
        return forward(b, load_balance: .roundRobin, set_path: "/internal/" + req.params.id)
    } else { return 404 }
}
)rut") == KongGapStage::Verified);
    const char* invalid[] = {
        "upstream b\nroute GET \"/\" { return forward(b, load_balance: .roundRobin, set_path: 42) "
        "}",
        "upstream b\nroute GET \"/\" { return forward(b, load_balance: .roundRobin, set_path: "
        "req.header(\"X-Target\")) }",
    };
    for (const char* source : invalid)
        CHECK(kong_gap_stage(_tc, source) == KongGapStage::AnalyzeRejected);
}

TEST(kong_routing_gap, dynamic_target_rir_requires_owned_string_effect) {
    auto tokens = lex(lit(R"rut(
upstream b at "127.0.0.1:9000"
route GET "/" { return forward(b, load_balance: .roundRobin, set_path: req.pathOnly) }
)rut"));
    REQUIRE(tokens);
    auto ast = parse_file_heap(tokens.value());
    REQUIRE(ast);
    auto hir = analyze_file_heap(ast.value());
    REQUIRE(hir);
    auto mir = build_mir_heap(hir.value());
    REQUIRE(mir);
    FrontendRirModule rir{};
    REQUIRE(lower_to_rir(mir.value(), rir));
    auto* effect = find_nth_op(rir.module.functions[0], rir::Opcode::ReqSetPath, 0);
    REQUIRE(effect != nullptr);
    CHECK_EQ(effect->imm.i32_val, 1);
    CHECK(rir::verify_module(rir.module).ok);
    effect->imm.i32_val = 0;
    CHECK_FALSE(rir::verify_module(rir.module).ok);
    effect->imm.i32_val = 2;
    CHECK_FALSE(rir::verify_module(rir.module).ok);
    effect->imm.i32_val = 1;
    CHECK(rir::verify_module(rir.module).ok);
}

TEST(kong_routing_gap, legacy_clean_prefix_requires_slash_boundary) {
    CHECK(kong_gap_stage(_tc, R"rut(
upstream b at "127.0.0.1:9000"
route GET "/" { return forward(b, load_balance: .roundRobin, target_transform: { strip_prefix: "/catalog/", replace_prefix: "/" }) }
)rut") == KongGapStage::Verified);
    CHECK(kong_gap_stage(_tc, R"rut(
upstream b at "127.0.0.1:9000"
route GET "/" { return forward(b, load_balance: .roundRobin, target_transform: { strip_prefix: "/catalog", replace_prefix: "/" }) }
)rut") == KongGapStage::ParseRejected);
}

TEST(kong_routing_gap, general_prefix_modes_enable_byte_strip_and_after_headers) {
    CHECK(kong_gap_stage(_tc, R"rut(
upstream b at "127.0.0.1:9000"
func stamp(_ resp: Response) -> i32 { resp.set("X-Gateway", "rut") 0 }
chain policy { after stamp(resp) }
route GET "/" use chain policy {
    return forward(b, load_balance: .roundRobin,
        target_transform: { strip_prefix: "/catalog", replace_prefix: "/", mode: .rawPrefix })
}
)rut") == KongGapStage::Verified);
    CHECK(kong_gap_stage(_tc, R"rut(
upstream b at "127.0.0.1:9000"
route POST "/" { return forward(b, load_balance: .roundRobin,
    target_transform: { mode: .normalizedPrefix, strip_prefix: "/api/", replace_prefix: "/v1/" }) }
)rut") == KongGapStage::Verified);
    CHECK(kong_gap_stage(_tc, R"rut(
upstream b at "127.0.0.1:9000"
route GET "/" { return forward(b, load_balance: .roundRobin, request_policy: {
    version: .http11, host: .preserve, connection: .omit,
    header_names: .lowercase, forwarded_proto: .http,
    strip_headers: [.connection, .keepAlive, .te, .expect, .upgrade, .proxyConnection]
}, target_transform: { mode: .rawPrefix, strip_prefix: "/api/", replace_prefix: "/v1/" }) }
)rut") == KongGapStage::Verified);
}

TEST(kong_routing_gap, regex_capture_accessor_rejected_after_boolean_control) {
    CHECK(kong_gap_stage(_tc, R"rut(
route GET "/" { if req.pathOnly.matches(re"^/v([0-9]+)/users/(.*)$") { return 200 } else { return 404 } }
)rut") == KongGapStage::Verified);
    // Probe the documented target spelling; this is not a claim that a bool
    // matcher lacks regex support or that ordinary :param captures are absent.
    CHECK(kong_gap_stage(_tc, R"rut(
route GET "/" { let captures = req.pathOnly.match(re"^/v([0-9]+)/users/(.*)$") return 200 }
)rut") == KongGapStage::ParseRejected);
}

TEST(kong_routing_gap, connection_metadata_accessor_probes_are_not_http_fields) {
    CHECK(kong_gap_stage(_tc, "route GET \"/\" { let version = req.httpVersion return 200 }") ==
          KongGapStage::Verified);
    const char* sources[] = {
        "route GET \"/\" { let name = req.sni return 200 }",
        "route GET \"/\" { let port = req.remotePort return 200 }",
        "route GET \"/\" { let port = req.localPort return 200 }",
        "route GET \"/\" { let secure = req.isTls return 200 }",
    };
    for (const char* source : sources)
        CHECK(kong_gap_stage(_tc, source) == KongGapStage::AnalyzeRejected);
}

TEST(kong_routing_gap, distinct_host_routes_collide_but_merged_branch_is_supported) {
    CHECK(kong_gap_stage(_tc,
                         R"rut(
route GET "/api" { guard let host = req.host else { return 400 } guard host == "a.example" else { return 404 } return 201 }
route GET "/api" { guard let host = req.host else { return 400 } guard host == "b.example" else { return 404 } return 202 }
)rut",
                         lit("duplicate route path and method")) == KongGapStage::AnalyzeRejected);
    CHECK(kong_gap_stage(_tc, R"rut(
route GET "/api" {
    guard let host = req.host else { return 400 }
    if host == "a.example" { return 201 } else { return 202 }
}
)rut") == KongGapStage::Verified);
}

TEST(kong_routing_gap, legacy_preserve_host_rejects_clean_transform_combination) {
    CHECK(kong_gap_stage(_tc, R"rut(
upstream b at "127.0.0.1:9000"
route GET "/" { return forward(b, load_balance: .roundRobin, request_policy: {
    version: .http11, host: .preserve, connection: .omit,
    header_names: .lowercase, forwarded_proto: .http,
    strip_headers: [.connection, .keepAlive, .te, .expect, .upgrade, .proxyConnection]
}) }
)rut") == KongGapStage::Verified);
    CHECK(kong_gap_stage(
              _tc,
              R"rut(
upstream b at "127.0.0.1:9000"
route GET "/" { return forward(b, load_balance: .roundRobin, request_policy: {
    version: .http11, host: .preserve, connection: .omit,
    header_names: .lowercase, forwarded_proto: .http,
    strip_headers: [.connection, .keepAlive, .te, .expect, .upgrade, .proxyConnection]
}, target_transform: { strip_prefix: "/api/", replace_prefix: "/" }) }
)rut",
              lit("request_policy host: .preserve does not support this forward option")) ==
          KongGapStage::AnalyzeRejected);
}

TEST(kong_routing_gap, legacy_clean_transform_rejects_after_headers) {
    CHECK(kong_gap_stage(_tc, R"rut(
upstream b at "127.0.0.1:9000"
func stamp(_ resp: Response) -> i32 { resp.set("X-Gateway", "rut") 0 }
chain policy { after stamp(resp) }
route GET "/" use chain policy { return forward(b, load_balance: .roundRobin) }
)rut") == KongGapStage::Verified);
    CHECK(
        kong_gap_stage(_tc,
                       R"rut(
upstream b at "127.0.0.1:9000"
func stamp(_ resp: Response) -> i32 { resp.set("X-Gateway", "rut") 0 }
chain policy { after stamp(resp) }
route GET "/" use chain policy { return forward(b, load_balance: .roundRobin, target_transform: { strip_prefix: "/api/", replace_prefix: "/" }) }
)rut",
                       lit("target_transform cannot be combined with response header mutations")) ==
        KongGapStage::AnalyzeRejected);
}
