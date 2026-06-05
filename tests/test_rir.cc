#include "rut/compiler/rir.h"
#include "rut/compiler/rir_builder.h"
#include "rut/compiler/rir_printer.h"
#include "rut/compiler/verifier.h"
#include "test.h"

using namespace rut;
using namespace rut::rir;

// ── Helpers ─────────────────────────────────────────────────────────

static Str lit(const char* s) {
    u32 n = 0;
    while (s[n]) n++;
    return {s, n};
}

// Unwrap Expected in tests: check success then extract value.
// __extension__ suppresses -Wgnu-statement-expression-from-macro-expansion.
#define V(expr)                                                \
    __extension__({                                            \
        auto&& _v_result = (expr);                             \
        REQUIRE(static_cast<bool>(_v_result));                 \
        static_cast<decltype(_v_result)&&>(_v_result).value(); \
    })

// For void Expected results.
#define VOK(expr) REQUIRE(static_cast<bool>(expr))

// MmapArena-backed module initialization.
struct TestContext {
    MmapArena arena;
    Module mod;

    bool init() {
        if (!arena.init(4096)) return false;
        mod.name = lit("test.rut");
        mod.arena = &arena;

        static constexpr u32 kMaxFuncs = 8;
        mod.functions = arena.alloc_array<Function>(kMaxFuncs);
        if (!mod.functions) {
            arena.destroy();
            return false;
        }
        mod.func_count = 0;
        mod.func_cap = kMaxFuncs;
        static constexpr u32 kMaxStructs = 64;
        mod.struct_defs = arena.alloc_array<StructDef*>(kMaxStructs);
        if (!mod.struct_defs) {
            arena.destroy();
            return false;
        }
        mod.struct_count = 0;
        mod.struct_cap = kMaxStructs;
        return true;
    }

    void destroy() { arena.destroy(); }
};

// ── Type System Tests ───────────────────────────────────────────────

TEST(RirTypes, PrimitiveTypes) {
    TestContext ctx;
    REQUIRE(ctx.init());

    Builder b;
    b.init(&ctx.mod);

    auto* t_bool = V(b.make_type(TypeKind::Bool));
    auto* t_str = V(b.make_type(TypeKind::Str));
    auto* t_i32 = V(b.make_type(TypeKind::I32));

    CHECK_EQ(static_cast<u8>(t_bool->kind), static_cast<u8>(TypeKind::Bool));
    CHECK_EQ(static_cast<u8>(t_str->kind), static_cast<u8>(TypeKind::Str));
    CHECK_EQ(static_cast<u8>(t_i32->kind), static_cast<u8>(TypeKind::I32));
    CHECK(t_bool->inner == nullptr);

    ctx.destroy();
}

TEST(RirTypes, OptionalType) {
    TestContext ctx;
    REQUIRE(ctx.init());

    Builder b;
    b.init(&ctx.mod);

    auto* t_str = V(b.make_type(TypeKind::Str));
    auto* t_opt_str = V(b.make_type(TypeKind::Optional, t_str));

    CHECK_EQ(static_cast<u8>(t_opt_str->kind), static_cast<u8>(TypeKind::Optional));
    CHECK(t_opt_str->inner == t_str);
    CHECK_EQ(static_cast<u8>(t_opt_str->inner->kind), static_cast<u8>(TypeKind::Str));

    ctx.destroy();
}

TEST(RirTypes, StructType) {
    TestContext ctx;
    REQUIRE(ctx.init());

    Builder b;
    b.init(&ctx.mod);

    auto* t_str = V(b.make_type(TypeKind::Str));
    FieldDef fields[2] = {{lit("id"), t_str}, {lit("role"), t_str}};
    auto* sd = V(b.create_struct(lit("User"), fields, 2));

    CHECK(sd->name.eq(lit("User")));
    CHECK_EQ(sd->field_count, 2u);
    CHECK(sd->fields()[0].name.eq(lit("id")));
    CHECK(sd->fields()[1].name.eq(lit("role")));

    ctx.destroy();
}

// ── Builder Tests ───────────────────────────────────────────────────

TEST(RirBuilder, CreateFunctionAndBlocks) {
    TestContext ctx;
    REQUIRE(ctx.init());

    Builder b;
    b.init(&ctx.mod);

    auto* fn = V(b.create_function(lit("handle_get_users_id"), lit("/users/:id"), 1));
    CHECK(fn->name.eq(lit("handle_get_users_id")));
    CHECK_EQ(ctx.mod.func_count, 1u);

    auto entry = V(b.create_block(fn, lit("entry")));
    auto blk1 = V(b.create_block(fn, lit("block_check")));

    CHECK_EQ(entry.id, 0u);
    CHECK_EQ(blk1.id, 1u);
    CHECK_EQ(fn->block_count, 2u);

    ctx.destroy();
}

TEST(RirBuilder, ConstantInstructions) {
    TestContext ctx;
    REQUIRE(ctx.init());

    Builder b;
    b.init(&ctx.mod);

    auto* fn = V(b.create_function(lit("test_fn"), lit("/test"), 1));
    auto entry = V(b.create_block(fn, lit("entry")));
    b.set_insert_point(fn, entry);

    auto v0 = V(b.emit_const_str(lit("hello"), {1, 0}));
    auto v1 = V(b.emit_const_i32(42, {2, 0}));
    auto v2 = V(b.emit_const_bool(true, {3, 0}));
    auto v3 = V(b.emit_const_duration(300, {4, 0}));

    CHECK_EQ(v0.id, 0u);
    CHECK_EQ(v1.id, 1u);
    CHECK_EQ(v2.id, 2u);
    CHECK_EQ(v3.id, 3u);

    CHECK_EQ(fn->value_count, 4u);
    CHECK_EQ(fn->entry()->inst_count, 4u);

    auto& inst0 = fn->entry()->insts[0];
    CHECK_EQ(static_cast<u8>(inst0.op), static_cast<u8>(Opcode::ConstStr));
    CHECK(inst0.imm.str_val.eq(lit("hello")));
    CHECK_EQ(inst0.loc.line, 1u);

    auto& inst1 = fn->entry()->insts[1];
    CHECK_EQ(inst1.imm.i32_val, 42);

    ctx.destroy();
}

TEST(RirBuilder, RequestAccess) {
    TestContext ctx;
    REQUIRE(ctx.init());

    Builder b;
    b.init(&ctx.mod);

    auto* fn = V(b.create_function(lit("test_fn"), lit("/test"), 1));
    auto entry = V(b.create_block(fn, lit("entry")));
    b.set_insert_point(fn, entry);

    auto v_hdr = V(b.emit_req_header(lit("Authorization"), {1, 0}));
    auto v_param = V(b.emit_req_param(lit("id"), {2, 0}));
    auto v_method = V(b.emit_req_method({3, 0}));

    CHECK_EQ(static_cast<u8>(fn->values[v_hdr.id].type->kind), static_cast<u8>(TypeKind::Optional));
    CHECK_EQ(static_cast<u8>(fn->values[v_hdr.id].type->inner->kind),
             static_cast<u8>(TypeKind::Str));
    CHECK_EQ(static_cast<u8>(fn->values[v_param.id].type->kind), static_cast<u8>(TypeKind::Str));
    CHECK_EQ(static_cast<u8>(fn->values[v_method.id].type->kind),
             static_cast<u8>(TypeKind::Method));

    ctx.destroy();
}

TEST(RirBuilder, BinaryOperations) {
    TestContext ctx;
    REQUIRE(ctx.init());

    Builder b;
    b.init(&ctx.mod);

    auto* fn = V(b.create_function(lit("test_fn"), lit("/test"), 1));
    auto entry = V(b.create_block(fn, lit("entry")));
    b.set_insert_point(fn, entry);

    auto v0 = V(b.emit_const_str(lit("Bearer ")));
    auto v1_opt = V(b.emit_req_header(lit("Authorization")));
    auto* t_s = V(b.make_type(TypeKind::Str));
    auto v1 = V(b.emit_opt_unwrap(v1_opt, t_s));
    auto v2 = V(b.emit_str_has_prefix(v1, v0));

    CHECK_EQ(static_cast<u8>(fn->values[v2.id].type->kind), static_cast<u8>(TypeKind::Bool));

    // Insts: const.str, req.header, opt.unwrap, str.has_prefix
    auto& inst = fn->entry()->insts[3];
    CHECK_EQ(inst.operand_count, 2u);
    CHECK_EQ(inst.operands[0].id, v1.id);
    CHECK_EQ(inst.operands[1].id, v0.id);

    ctx.destroy();
}

TEST(RirBuilder, Terminators) {
    TestContext ctx;
    REQUIRE(ctx.init());

    Builder b;
    b.init(&ctx.mod);

    auto* fn = V(b.create_function(lit("test_fn"), lit("/test"), 1));
    auto entry = V(b.create_block(fn, lit("entry")));
    auto then_blk = V(b.create_block(fn, lit("then")));
    auto else_blk = V(b.create_block(fn, lit("else")));

    b.set_insert_point(fn, entry);
    auto cond = V(b.emit_const_bool(true));
    VOK(b.emit_br(cond, then_blk, else_blk));

    b.set_insert_point(fn, then_blk);
    VOK(b.emit_ret_status(200));

    b.set_insert_point(fn, else_blk);
    VOK(b.emit_ret_status(404));

    auto* term = fn->entry()->terminator();
    REQUIRE(term != nullptr);
    CHECK_EQ(static_cast<u8>(term->op), static_cast<u8>(Opcode::Br));
    CHECK(term->is_terminator());
    CHECK_EQ(term->imm.block_targets[0].id, then_blk.id);
    CHECK_EQ(term->imm.block_targets[1].id, else_blk.id);

    ctx.destroy();
}

TEST(RirBuilder, YieldCountsStates) {
    TestContext ctx;
    REQUIRE(ctx.init());

    Builder b;
    b.init(&ctx.mod);

    auto* fn = V(b.create_function(lit("test_fn"), lit("/test"), 1));
    auto entry = V(b.create_block(fn, lit("entry")));
    b.set_insert_point(fn, entry);

    CHECK_EQ(fn->yield_count, 0u);

    V(b.emit_yield_http_get(lit("http://auth/verify"), kNoValue));
    CHECK_EQ(fn->yield_count, 1u);

    ctx.destroy();
}

TEST(RirBuilder, VariadicStrInterpolate) {
    TestContext ctx;
    REQUIRE(ctx.init());

    Builder b;
    b.init(&ctx.mod);

    auto* fn = V(b.create_function(lit("test_fn"), lit("/test"), 1));
    auto entry = V(b.create_block(fn, lit("entry")));
    b.set_insert_point(fn, entry);

    ValueId parts[5];
    parts[0] = V(b.emit_const_str(lit("GET")));
    parts[1] = V(b.emit_const_str(lit(" ")));
    parts[2] = V(b.emit_const_str(lit("/users")));
    parts[3] = V(b.emit_const_str(lit(" ")));
    parts[4] = V(b.emit_const_str(lit("HTTP/1.1")));

    auto result = V(b.emit_str_interpolate(parts, 5));
    CHECK(result != kNoValue);

    auto& inst = fn->entry()->insts[5];
    CHECK_EQ(inst.operand_count, 5u);
    CHECK_EQ(inst.operand(0).id, parts[0].id);
    CHECK_EQ(inst.operand(1).id, parts[1].id);
    CHECK_EQ(inst.operand(2).id, parts[2].id);
    CHECK_EQ(inst.operand(3).id, parts[3].id);
    CHECK_EQ(inst.operand(4).id, parts[4].id);

    ctx.destroy();
}

// ── Integration Test: simplified DESIGN.md auth example ─────────────
// Based on §11.2.3 but simplified: omits block_check_exp/
// block_reject_401_expired, and models claims as Optional(str)
// rather than Optional(Struct(Claims)). Tests the builder's ability
// to construct a realistic multi-block handler, not exact fidelity.

TEST(RirIntegration, AuthHandlerFromDesignDoc) {
    TestContext ctx;
    REQUIRE(ctx.init());

    Builder b;
    b.init(&ctx.mod);

    auto* fn = V(b.create_function(lit("handle_get_users_id"), lit("/users/:id"), 1));

    auto entry = V(b.create_block(fn, lit("entry")));
    auto blk_check_prefix = V(b.create_block(fn, lit("block_check_prefix")));
    auto blk_decode_jwt = V(b.create_block(fn, lit("block_decode_jwt")));
    auto blk_check_role = V(b.create_block(fn, lit("block_check_role")));
    auto blk_auth_ok = V(b.create_block(fn, lit("block_auth_ok")));
    auto blk_proxy = V(b.create_block(fn, lit("block_proxy")));
    auto blk_reject_401 = V(b.create_block(fn, lit("block_reject_401")));
    auto blk_reject_403 = V(b.create_block(fn, lit("block_reject_403")));
    auto blk_reject_429 = V(b.create_block(fn, lit("block_reject_429")));

    // entry
    b.set_insert_point(fn, entry);
    auto token = V(b.emit_req_header(lit("Authorization"), {42, 0}));
    auto is_nil = V(b.emit_opt_is_nil(token, {42, 0}));
    VOK(b.emit_br(is_nil, blk_reject_401, blk_check_prefix, {42, 0}));

    // block_check_prefix — unwrap Optional(str) before string ops
    b.set_insert_point(fn, blk_check_prefix);
    auto* t_str_early = V(b.make_type(TypeKind::Str));
    auto token_str = V(b.emit_opt_unwrap(token, t_str_early, {43, 0}));
    auto bearer = V(b.emit_const_str(lit("Bearer ")));
    auto has_pfx = V(b.emit_str_has_prefix(token_str, bearer, {43, 0}));
    VOK(b.emit_br(has_pfx, blk_decode_jwt, blk_reject_401, {43, 0}));

    // block_decode_jwt
    b.set_insert_point(fn, blk_decode_jwt);
    auto* t_str = V(b.make_type(TypeKind::Str));
    // For this IR test, model decoded JWT claims via the X-Claims request header,
    // treated as Optional(Str) rather than invoking a dedicated jwt_decode built-in.
    auto claims = V(b.emit_req_header(lit("X-Claims"), {45, 0}));
    auto claims_nil = V(b.emit_opt_is_nil(claims, {45, 0}));
    VOK(b.emit_br(claims_nil, blk_reject_401, blk_check_role, {45, 0}));

    // block_check_role — unwrap Optional(Str), compare to expected role
    b.set_insert_point(fn, blk_check_role);
    auto role = V(b.emit_opt_unwrap(claims, t_str, {46, 0}));
    auto role_lit = V(b.emit_const_str(lit("user"), {46, 0}));
    auto role_ok = V(b.emit_cmp(Opcode::CmpEq, role, role_lit, {46, 0}));
    VOK(b.emit_br(role_ok, blk_auth_ok, blk_reject_403, {46, 0}));

    // block_auth_ok — in real code would extract Claims.sub; simplified for test
    b.set_insert_point(fn, blk_auth_ok);
    auto sub = V(b.emit_const_str(lit("user-123")));
    VOK(b.emit_req_set_header(lit("X-User-ID"), sub));
    auto remote_addr = V(b.emit_req_remote_addr());
    auto count = V(b.emit_counter_incr(remote_addr, 60));
    auto limit = V(b.emit_const_i32(100));
    auto over = V(b.emit_cmp(Opcode::CmpGt, count, limit));
    VOK(b.emit_br(over, blk_reject_429, blk_proxy));

    // block_proxy
    b.set_insert_point(fn, blk_proxy);
    auto id = V(b.emit_req_param(lit("id")));
    VOK(b.emit_req_set_header(lit("X-User-ID"), id));
    auto upstream = V(b.emit_const_i32(0));  // upstream id 0
    VOK(b.emit_ret_forward(upstream));

    // Rejection blocks.
    b.set_insert_point(fn, blk_reject_401);
    VOK(b.emit_ret_status(401));
    b.set_insert_point(fn, blk_reject_403);
    VOK(b.emit_ret_status(403));
    b.set_insert_point(fn, blk_reject_429);
    VOK(b.emit_ret_status(429));

    // Verify structure.
    CHECK_EQ(fn->block_count, 9u);
    CHECK_EQ(fn->yield_count, 0u);
    CHECK_EQ(fn->entry()->inst_count, 3u);
    auto* term = fn->entry()->terminator();
    CHECK(term->is_terminator());
    CHECK_EQ(static_cast<u8>(term->op), static_cast<u8>(Opcode::Br));
    CHECK_EQ(fn->blocks[blk_reject_401.id].inst_count, 1u);
    CHECK_EQ(fn->blocks[blk_reject_403.id].inst_count, 1u);
    CHECK_EQ(fn->blocks[blk_reject_429.id].inst_count, 1u);

    char print_buf[4096];
    PrintBuf pb;
    pb.init(print_buf, sizeof(print_buf), -1);
    print_function(pb, *fn);

    ctx.destroy();
}

// ── Printer Tests ───────────────────────────────────────────────────

TEST(RirPrinter, OpcodeNames) {
    char buf_data[256];
    PrintBuf buf;
    buf.init(buf_data, sizeof(buf_data), -1);

    print_opcode(buf, Opcode::ReqHeader);
    CHECK_EQ(buf.len, 10u);
    Str got0 = {buf.data, buf.len};
    CHECK(got0.eq(lit("req.header")));

    buf.len = 0;
    print_opcode(buf, Opcode::CmpEq);
    Str got1 = {buf.data, buf.len};
    CHECK(got1.eq(lit("cmp.eq")));

    buf.len = 0;
    print_opcode(buf, Opcode::YieldHttpGet);
    Str got2 = {buf.data, buf.len};
    CHECK(got2.eq(lit("yield.http_get")));
}

TEST(RirPrinter, TypeNames) {
    TestContext ctx;
    REQUIRE(ctx.init());

    Builder b;
    b.init(&ctx.mod);

    char buf_data[256];
    PrintBuf buf;
    buf.init(buf_data, sizeof(buf_data), -1);

    auto* t_str = V(b.make_type(TypeKind::Str));
    print_type(buf, t_str);
    Str got_str = {buf.data, buf.len};
    CHECK(got_str.eq(lit("str")));

    buf.len = 0;
    auto* t_opt = V(b.make_type(TypeKind::Optional, t_str));
    print_type(buf, t_opt);
    Str got_opt = {buf.data, buf.len};
    CHECK(got_opt.eq(lit("Optional(str)")));

    ctx.destroy();
}

TEST(RirBuilder, InstructionIsTerminator) {
    Instruction inst{};

    inst.op = Opcode::ConstI32;
    CHECK(!inst.is_terminator());
    CHECK(!inst.is_yield());

    inst.op = Opcode::Br;
    CHECK(inst.is_terminator());
    CHECK(!inst.is_yield());

    inst.op = Opcode::YieldHttpGet;
    CHECK(inst.is_terminator());
    CHECK(inst.is_yield());
}

TEST(RirVerifier, AcceptsReturnAndBranchRouteGraph) {
    TestContext ctx;
    REQUIRE(ctx.init());

    Builder b;
    b.init(&ctx.mod);

    auto* fn = V(b.create_function(lit("test_fn"), lit("/test"), 1));
    auto entry = V(b.create_block(fn, lit("entry")));
    auto ok = V(b.create_block(fn, lit("ok")));
    auto reject = V(b.create_block(fn, lit("reject")));

    b.set_insert_point(fn, entry);
    auto cond = V(b.emit_const_bool(true));
    VOK(b.emit_br(cond, ok, reject));

    b.set_insert_point(fn, ok);
    VOK(b.emit_ret_status(204));

    b.set_insert_point(fn, reject);
    VOK(b.emit_ret_status(403));

    auto result = verify_function(fn);
    REQUIRE(result.ok);
    CHECK_EQ(result.summary.block_count, 3u);
    CHECK_EQ(result.summary.reachable_block_count, 3u);
    CHECK_EQ(result.summary.terminal_block_count, 2u);
    CHECK_EQ(result.summary.branch_edge_count, 2u);
    CHECK_EQ(result.summary.yield_count, 0u);

    ctx.destroy();
}

TEST(RirVerifier, RejectsMissingTerminator) {
    TestContext ctx;
    REQUIRE(ctx.init());

    Builder b;
    b.init(&ctx.mod);

    auto* fn = V(b.create_function(lit("test_fn"), lit("/test"), 1));
    auto entry = V(b.create_block(fn, lit("entry")));
    b.set_insert_point(fn, entry);
    V(b.emit_const_i32(1));

    auto result = verify_function(fn);
    REQUIRE(!result.ok);
    CHECK_EQ(static_cast<u8>(result.issue.code),
             static_cast<u8>(VerifyIssueCode::MissingTerminator));
    CHECK_EQ(result.issue.block_index, entry.id);

    ctx.destroy();
}

TEST(RirVerifier, RejectsInvalidBranchTarget) {
    TestContext ctx;
    REQUIRE(ctx.init());

    Builder b;
    b.init(&ctx.mod);

    auto* fn = V(b.create_function(lit("test_fn"), lit("/test"), 1));
    auto entry = V(b.create_block(fn, lit("entry")));
    auto ok = V(b.create_block(fn, lit("ok")));
    auto reject = V(b.create_block(fn, lit("reject")));

    b.set_insert_point(fn, entry);
    auto cond = V(b.emit_const_bool(true));
    VOK(b.emit_br(cond, ok, reject));
    fn->blocks[entry.id].insts[1].imm.block_targets[1] = BlockId{99};

    b.set_insert_point(fn, ok);
    VOK(b.emit_ret_status(204));

    b.set_insert_point(fn, reject);
    VOK(b.emit_ret_status(403));

    auto result = verify_function(fn);
    REQUIRE(!result.ok);
    CHECK_EQ(static_cast<u8>(result.issue.code),
             static_cast<u8>(VerifyIssueCode::InvalidBranchTarget));
    CHECK_EQ(result.issue.block_index, entry.id);
    CHECK_EQ(result.issue.target_index, 99u);

    ctx.destroy();
}

TEST(RirVerifier, RejectsYieldCountMismatch) {
    TestContext ctx;
    REQUIRE(ctx.init());

    Builder b;
    b.init(&ctx.mod);

    auto* fn = V(b.create_function(lit("test_fn"), lit("/test"), 1));
    auto entry = V(b.create_block(fn, lit("entry")));
    u32 payloads[2] = {50, 100};
    u8 kinds[2] = {static_cast<u8>(jit::YieldKind::Timer), static_cast<u8>(jit::YieldKind::Timer)};
    VOK(b.set_yield_payload(fn, payloads, 2, kinds));

    b.set_insert_point(fn, entry);
    VOK(b.emit_yield_event(static_cast<u8>(jit::YieldKind::Timer), 50, 1));

    auto result = verify_function(fn);
    REQUIRE(!result.ok);
    CHECK_EQ(static_cast<u8>(result.issue.code),
             static_cast<u8>(VerifyIssueCode::YieldCountMismatch));
    CHECK_EQ(result.issue.inst_index, 1u);
    CHECK_EQ(result.issue.target_index, 2u);

    ctx.destroy();
}

TEST(RirVerifier, RejectsNonLoweredYieldTerminator) {
    TestContext ctx;
    REQUIRE(ctx.init());

    Builder b;
    b.init(&ctx.mod);

    auto* fn = V(b.create_function(lit("test_fn"), lit("/test"), 1));
    auto entry = V(b.create_block(fn, lit("entry")));

    b.set_insert_point(fn, entry);
    V(b.emit_yield_http_get(lit("http://auth/verify"), kNoValue));

    u32 payloads[1] = {0};
    u8 kinds[1] = {static_cast<u8>(jit::YieldKind::HttpGet)};
    VOK(b.set_yield_payload(fn, payloads, 1, kinds));

    auto result = verify_function(fn);
    REQUIRE(!result.ok);
    CHECK_EQ(static_cast<u8>(result.issue.code),
             static_cast<u8>(VerifyIssueCode::UnsupportedYieldTerminator));
    CHECK_EQ(result.issue.block_index, entry.id);
    CHECK_EQ(result.issue.target_index, static_cast<u32>(Opcode::YieldHttpGet));

    ctx.destroy();
}

TEST(RirVerifier, TreatsExplicitYieldResumeBlockAsReachable) {
    TestContext ctx;
    REQUIRE(ctx.init());

    Builder b;
    b.init(&ctx.mod);

    auto* fn = V(b.create_function(lit("test_fn"), lit("/test"), 1));
    auto entry = V(b.create_block(fn, lit("entry")));
    auto resume = V(b.create_block(fn, lit("resume")));

    u32 payloads[1] = {50};
    u8 kinds[1] = {static_cast<u8>(jit::YieldKind::Timer)};
    VOK(b.set_yield_payload(fn, payloads, 1, kinds));
    BlockId resume_blocks[2] = {entry, resume};
    VOK(b.set_explicit_resume_blocks(fn, resume_blocks, 2));

    b.set_insert_point(fn, entry);
    VOK(b.emit_yield_event(static_cast<u8>(jit::YieldKind::Timer), 50, 1));

    b.set_insert_point(fn, resume);
    VOK(b.emit_ret_status(204));

    auto result = verify_function(fn);
    REQUIRE(result.ok);
    CHECK_EQ(result.summary.reachable_block_count, 2u);
    CHECK_EQ(result.summary.branch_edge_count, 1u);

    ctx.destroy();
}

TEST(RirVerifier, AcceptsExplicitStateZeroPreludeThatReachesEntry) {
    TestContext ctx;
    REQUIRE(ctx.init());

    Builder b;
    b.init(&ctx.mod);

    auto* fn = V(b.create_function(lit("test_fn"), lit("/test"), 1));
    auto entry = V(b.create_block(fn, lit("entry")));
    auto prelude = V(b.create_block(fn, lit("prelude")));
    auto resume = V(b.create_block(fn, lit("resume")));

    u32 payloads[1] = {50};
    u8 kinds[1] = {static_cast<u8>(jit::YieldKind::Timer)};
    VOK(b.set_yield_payload(fn, payloads, 1, kinds));
    BlockId resume_blocks[2] = {prelude, resume};
    VOK(b.set_explicit_resume_blocks(fn, resume_blocks, 2));

    b.set_insert_point(fn, prelude);
    VOK(b.emit_jmp(entry));

    b.set_insert_point(fn, entry);
    VOK(b.emit_yield_event(static_cast<u8>(jit::YieldKind::Timer), 50, 1));

    b.set_insert_point(fn, resume);
    VOK(b.emit_ret_status(204));

    auto result = verify_function(fn);
    REQUIRE(result.ok);
    CHECK_EQ(result.summary.reachable_block_count, 3u);
    CHECK_EQ(result.summary.branch_edge_count, 2u);

    ctx.destroy();
}

TEST(RirVerifier, RejectsExplicitResumeStateZeroThatSkipsEntry) {
    TestContext ctx;
    REQUIRE(ctx.init());

    Builder b;
    b.init(&ctx.mod);

    auto* fn = V(b.create_function(lit("test_fn"), lit("/test"), 1));
    auto entry = V(b.create_block(fn, lit("entry")));
    auto resume = V(b.create_block(fn, lit("resume")));

    u32 payloads[1] = {50};
    u8 kinds[1] = {static_cast<u8>(jit::YieldKind::Timer)};
    VOK(b.set_yield_payload(fn, payloads, 1, kinds));
    BlockId resume_blocks[2] = {entry, resume};
    VOK(b.set_explicit_resume_blocks(fn, resume_blocks, 2));
    fn->resume_blocks[0] = resume.id;

    b.set_insert_point(fn, entry);
    VOK(b.emit_yield_event(static_cast<u8>(jit::YieldKind::Timer), 50, 1));

    b.set_insert_point(fn, resume);
    VOK(b.emit_ret_status(204));

    auto result = verify_function(fn);
    REQUIRE(!result.ok);
    CHECK_EQ(static_cast<u8>(result.issue.code),
             static_cast<u8>(VerifyIssueCode::UnreachableBlock));
    CHECK_EQ(result.issue.block_index, entry.id);

    ctx.destroy();
}

TEST(RirVerifier, RejectsNonExplicitStateZeroThatSkipsEntry) {
    TestContext ctx;
    REQUIRE(ctx.init());

    Builder b;
    b.init(&ctx.mod);

    auto* fn = V(b.create_function(lit("test_fn"), lit("/test"), 1));
    auto entry = V(b.create_block(fn, lit("entry")));
    auto stale_entry = V(b.create_block(fn, lit("stale_entry")));
    auto terminal = V(b.create_block(fn, lit("terminal")));

    u32 payloads[1] = {50};
    u8 kinds[1] = {static_cast<u8>(jit::YieldKind::Timer)};
    VOK(b.set_yield_payload(fn, payloads, 1, kinds));
    VOK(b.set_state_zero_entry_resume(fn, terminal, stale_entry));

    b.set_insert_point(fn, entry);
    VOK(b.emit_yield_event(static_cast<u8>(jit::YieldKind::Timer), 50, 1));

    b.set_insert_point(fn, stale_entry);
    VOK(b.emit_ret_status(202));

    b.set_insert_point(fn, terminal);
    VOK(b.emit_ret_status(204));

    auto result = verify_function(fn);
    REQUIRE(!result.ok);
    CHECK_EQ(static_cast<u8>(result.issue.code),
             static_cast<u8>(VerifyIssueCode::UnreachableBlock));
    CHECK_EQ(result.issue.block_index, entry.id);

    ctx.destroy();
}

TEST(RirVerifier, RejectsYieldWithoutResumeMapping) {
    TestContext ctx;
    REQUIRE(ctx.init());

    Builder b;
    b.init(&ctx.mod);

    auto* fn = V(b.create_function(lit("test_fn"), lit("/test"), 1));
    auto entry = V(b.create_block(fn, lit("entry")));

    u32 payloads[1] = {50};
    u8 kinds[1] = {static_cast<u8>(jit::YieldKind::Timer)};
    VOK(b.set_yield_payload(fn, payloads, 1, kinds));

    b.set_insert_point(fn, entry);
    VOK(b.emit_yield_event(static_cast<u8>(jit::YieldKind::Timer), 50, 1));

    auto result = verify_function(fn);
    REQUIRE(!result.ok);
    CHECK_EQ(static_cast<u8>(result.issue.code),
             static_cast<u8>(VerifyIssueCode::MissingYieldResumeMapping));

    ctx.destroy();
}

TEST(RirVerifier, RejectsInvalidYieldNextState) {
    TestContext ctx;
    REQUIRE(ctx.init());

    Builder b;
    b.init(&ctx.mod);

    auto* fn = V(b.create_function(lit("test_fn"), lit("/test"), 1));
    auto entry = V(b.create_block(fn, lit("entry")));
    auto resume = V(b.create_block(fn, lit("resume")));

    u32 payloads[1] = {50};
    u8 kinds[1] = {static_cast<u8>(jit::YieldKind::Timer)};
    VOK(b.set_yield_payload(fn, payloads, 1, kinds));
    BlockId resume_blocks[2] = {entry, resume};
    VOK(b.set_explicit_resume_blocks(fn, resume_blocks, 2));

    b.set_insert_point(fn, entry);
    VOK(b.emit_yield_event(static_cast<u8>(jit::YieldKind::Timer), 50, 1));
    fn->blocks[entry.id].insts[0].imm.i64_val =
        (static_cast<i64>(jit::YieldKind::Timer) << 48) | (static_cast<i64>(2) << 32) | 50;

    b.set_insert_point(fn, resume);
    VOK(b.emit_ret_status(204));

    auto result = verify_function(fn);
    REQUIRE(!result.ok);
    CHECK_EQ(static_cast<u8>(result.issue.code),
             static_cast<u8>(VerifyIssueCode::InvalidYieldNextState));
    CHECK_EQ(result.issue.target_index, 2u);

    ctx.destroy();
}

TEST(RirVerifier, RejectsInvalidEncodedYieldKind) {
    TestContext ctx;
    REQUIRE(ctx.init());

    Builder b;
    b.init(&ctx.mod);

    auto* fn = V(b.create_function(lit("test_fn"), lit("/test"), 1));
    auto entry = V(b.create_block(fn, lit("entry")));
    auto resume = V(b.create_block(fn, lit("resume")));

    u32 payloads[1] = {50};
    u8 kinds[1] = {static_cast<u8>(jit::YieldKind::Timer)};
    VOK(b.set_yield_payload(fn, payloads, 1, kinds));
    BlockId resume_blocks[2] = {entry, resume};
    VOK(b.set_explicit_resume_blocks(fn, resume_blocks, 2));

    b.set_insert_point(fn, entry);
    VOK(b.emit_yield_event(static_cast<u8>(jit::YieldKind::Timer), 50, 1));
    fn->blocks[entry.id].insts[0].imm.i64_val =
        (static_cast<i64>(99) << 48) | (static_cast<i64>(1) << 32) | 50;

    b.set_insert_point(fn, resume);
    VOK(b.emit_ret_status(204));

    auto result = verify_function(fn);
    REQUIRE(!result.ok);
    CHECK_EQ(static_cast<u8>(result.issue.code),
             static_cast<u8>(VerifyIssueCode::InvalidYieldKind));
    CHECK_EQ(result.issue.target_index, 99u);

    ctx.destroy();
}

TEST(RirVerifier, RejectsUnsupportedLoweredYieldKind) {
    TestContext ctx;
    REQUIRE(ctx.init());

    Builder b;
    b.init(&ctx.mod);

    auto* fn = V(b.create_function(lit("test_fn"), lit("/test"), 1));
    auto entry = V(b.create_block(fn, lit("entry")));
    auto resume = V(b.create_block(fn, lit("resume")));

    u32 payloads[1] = {50};
    u8 kinds[1] = {static_cast<u8>(jit::YieldKind::HttpPost)};
    VOK(b.set_yield_payload(fn, payloads, 1, kinds));
    BlockId resume_blocks[2] = {entry, resume};
    VOK(b.set_explicit_resume_blocks(fn, resume_blocks, 2));

    b.set_insert_point(fn, entry);
    VOK(b.emit_yield_event(static_cast<u8>(jit::YieldKind::HttpPost), 50, 1));

    b.set_insert_point(fn, resume);
    VOK(b.emit_ret_status(204));

    auto result = verify_function(fn);
    REQUIRE(!result.ok);
    CHECK_EQ(static_cast<u8>(result.issue.code),
             static_cast<u8>(VerifyIssueCode::InvalidYieldKind));
    CHECK_EQ(result.issue.target_index, static_cast<u32>(jit::YieldKind::HttpPost));

    ctx.destroy();
}

TEST(RirVerifier, RejectsRuntimeUnsupportedDownstreamSendYield) {
    TestContext ctx;
    REQUIRE(ctx.init());

    Builder b;
    b.init(&ctx.mod);

    auto* fn = V(b.create_function(lit("test_fn"), lit("/test"), 1));
    auto entry = V(b.create_block(fn, lit("entry")));
    auto resume = V(b.create_block(fn, lit("resume")));

    u32 payloads[1] = {0};
    u8 kinds[1] = {static_cast<u8>(jit::YieldKind::Send)};
    VOK(b.set_yield_payload(fn, payloads, 1, kinds));
    BlockId resume_blocks[2] = {entry, resume};
    VOK(b.set_explicit_resume_blocks(fn, resume_blocks, 2));

    b.set_insert_point(fn, entry);
    VOK(b.emit_yield_event(static_cast<u8>(jit::YieldKind::Send), 0, 1));

    b.set_insert_point(fn, resume);
    VOK(b.emit_ret_status(204));

    auto result = verify_function(fn);
    REQUIRE(!result.ok);
    CHECK_EQ(static_cast<u8>(result.issue.code),
             static_cast<u8>(VerifyIssueCode::InvalidYieldRuntimeProtocol));
    CHECK_EQ(result.issue.target_index, static_cast<u32>(jit::YieldKind::Send));
    CHECK_EQ(result.issue.detail_index, 0u);

    ctx.destroy();
}

TEST(RirVerifier, RejectsUpstreamConnectYieldWithoutTargetPayload) {
    TestContext ctx;
    REQUIRE(ctx.init());

    Builder b;
    b.init(&ctx.mod);

    auto* fn = V(b.create_function(lit("test_fn"), lit("/test"), 1));
    auto entry = V(b.create_block(fn, lit("entry")));
    auto resume = V(b.create_block(fn, lit("resume")));

    u32 payloads[1] = {0};
    u8 kinds[1] = {static_cast<u8>(jit::YieldKind::UpstreamConnect)};
    VOK(b.set_yield_payload(fn, payloads, 1, kinds));
    BlockId resume_blocks[2] = {entry, resume};
    VOK(b.set_explicit_resume_blocks(fn, resume_blocks, 2));

    b.set_insert_point(fn, entry);
    VOK(b.emit_yield_event(static_cast<u8>(jit::YieldKind::UpstreamConnect), 0, 1));

    b.set_insert_point(fn, resume);
    VOK(b.emit_ret_status(204));

    auto result = verify_function(fn);
    REQUIRE(!result.ok);
    CHECK_EQ(static_cast<u8>(result.issue.code),
             static_cast<u8>(VerifyIssueCode::InvalidYieldRuntimeProtocol));
    CHECK_EQ(result.issue.target_index, static_cast<u32>(jit::YieldKind::UpstreamConnect));
    CHECK_EQ(result.issue.detail_index, 0u);

    ctx.destroy();
}

TEST(RirVerifier, RejectsUpstreamIoYieldWithoutTargetPayload) {
    const jit::YieldKind kinds[] = {jit::YieldKind::UpstreamRecv, jit::YieldKind::UpstreamSend};

    for (jit::YieldKind yield_kind : kinds) {
        TestContext ctx;
        REQUIRE(ctx.init());

        Builder b;
        b.init(&ctx.mod);

        auto* fn = V(b.create_function(lit("test_fn"), lit("/test"), 1));
        auto entry = V(b.create_block(fn, lit("entry")));
        auto resume = V(b.create_block(fn, lit("resume")));

        u32 payloads[1] = {0};
        u8 encoded_kinds[1] = {static_cast<u8>(yield_kind)};
        VOK(b.set_yield_payload(fn, payloads, 1, encoded_kinds));
        BlockId resume_blocks[2] = {entry, resume};
        VOK(b.set_explicit_resume_blocks(fn, resume_blocks, 2));

        b.set_insert_point(fn, entry);
        VOK(b.emit_yield_event(static_cast<u8>(yield_kind), 0, 1));

        b.set_insert_point(fn, resume);
        VOK(b.emit_ret_status(204));

        auto result = verify_function(fn);
        REQUIRE(!result.ok);
        CHECK_EQ(static_cast<u8>(result.issue.code),
                 static_cast<u8>(VerifyIssueCode::InvalidYieldRuntimeProtocol));
        CHECK_EQ(result.issue.target_index, static_cast<u32>(yield_kind));
        CHECK_EQ(result.issue.detail_index, 0u);

        ctx.destroy();
    }
}

TEST(RirVerifier, RuntimeProtocolModelClassifiesSchedulableUpstreamYield) {
    auto check =
        VerifyRuntimeProtocolModel::check_yield(static_cast<u8>(jit::YieldKind::UpstreamRecv), 2);
    REQUIRE(check.ok);
    CHECK_EQ(static_cast<u8>(check.reason), static_cast<u8>(VerifyRuntimeProtocolReason::Ok));
    CHECK_EQ(static_cast<u8>(check.pending_op),
             static_cast<u8>(VerifyRuntimePendingOp::UpstreamRecv));
    CHECK_EQ(static_cast<u8>(check.callback_slot),
             static_cast<u8>(VerifyRuntimeCallbackSlot::UpstreamRecv));
}

TEST(RirVerifier, RuntimeProtocolModelMapsConnectToUpstreamSendSlot) {
    auto check = VerifyRuntimeProtocolModel::check_yield(
        static_cast<u8>(jit::YieldKind::UpstreamConnect), 1);
    REQUIRE(check.ok);
    CHECK_EQ(static_cast<u8>(check.pending_op),
             static_cast<u8>(VerifyRuntimePendingOp::UpstreamConnect));
    CHECK_EQ(static_cast<u8>(check.callback_slot),
             static_cast<u8>(VerifyRuntimeCallbackSlot::UpstreamSend));
}

TEST(RirVerifier, RuntimeProtocolModelAddsFailureTransitionForUpstreamYield) {
    auto check = VerifyRuntimeProtocolModel::check_yield(
        static_cast<u8>(jit::YieldKind::UpstreamConnect), 1);
    REQUIRE(check.ok);
    CHECK(check.submit_transition);
    CHECK(check.completion_transition);
    CHECK(check.fail_closed_transition);
    CHECK_EQ(static_cast<u8>(check.pending_op),
             static_cast<u8>(VerifyRuntimePendingOp::UpstreamConnect));
    CHECK_EQ(static_cast<u8>(check.callback_slot),
             static_cast<u8>(VerifyRuntimeCallbackSlot::UpstreamSend));
}

TEST(RirVerifier, RuntimeProtocolModelMarksTimerSchedulingFailureClosed) {
    auto check =
        VerifyRuntimeProtocolModel::check_yield(static_cast<u8>(jit::YieldKind::Timer), 50);
    REQUIRE(check.ok);
    CHECK(check.submit_transition);
    CHECK(check.completion_transition);
    CHECK(check.fail_closed_transition);
    CHECK_EQ(check.submit_transition_count, 1u);
    CHECK_EQ(check.completion_transition_count, 1u);
    CHECK_EQ(check.fail_closed_transition_count, 1u);
    CHECK_EQ(static_cast<u8>(check.pending_op), static_cast<u8>(VerifyRuntimePendingOp::Timer));
    CHECK_EQ(static_cast<u8>(check.callback_slot),
             static_cast<u8>(VerifyRuntimeCallbackSlot::HandlerTimer));
}

TEST(RirVerifier, RuntimeProtocolModelCountsTimedAnyTimerAndRecvTransitions) {
    auto check = VerifyRuntimeProtocolModel::check_yield(static_cast<u8>(jit::YieldKind::Any), 25);
    REQUIRE(check.ok);
    CHECK(check.submit_transition);
    CHECK(check.completion_transition);
    CHECK(check.fail_closed_transition);
    CHECK_EQ(check.submit_transition_count, 2u);
    CHECK_EQ(check.completion_transition_count, 2u);
    CHECK_EQ(check.fail_closed_transition_count, 2u);
    CHECK_EQ(static_cast<u8>(check.pending_op),
             static_cast<u8>(VerifyRuntimePendingOp::DownstreamRecv));
    CHECK_EQ(static_cast<u8>(check.callback_slot),
             static_cast<u8>(VerifyRuntimeCallbackSlot::DownstreamRecv));
    CHECK_EQ(static_cast<u8>(check.secondary_pending_op),
             static_cast<u8>(VerifyRuntimePendingOp::Timer));
    CHECK_EQ(static_cast<u8>(check.secondary_callback_slot),
             static_cast<u8>(VerifyRuntimeCallbackSlot::HandlerTimer));
}

TEST(RirVerifier, RuntimeProtocolModelReportsUnsupportedEventYield) {
    auto check = VerifyRuntimeProtocolModel::check_yield(static_cast<u8>(jit::YieldKind::Send), 0);
    REQUIRE(!check.ok);
    CHECK_EQ(static_cast<u8>(check.reason),
             static_cast<u8>(VerifyRuntimeProtocolReason::UnsupportedEventYield));
    CHECK_EQ(static_cast<u8>(check.pending_op), static_cast<u8>(VerifyRuntimePendingOp::None));
    CHECK_EQ(static_cast<u8>(check.callback_slot),
             static_cast<u8>(VerifyRuntimeCallbackSlot::None));
}

TEST(RirVerifier, HandlerAutomatonSummarizesTimerYieldAndTerminal) {
    TestContext ctx;
    REQUIRE(ctx.init());

    Builder b;
    b.init(&ctx.mod);

    auto* fn = V(b.create_function(lit("test_fn"), lit("/test"), 1));
    auto entry = V(b.create_block(fn, lit("entry")));
    auto resume = V(b.create_block(fn, lit("resume")));

    u32 payloads[1] = {50};
    u8 kinds[1] = {static_cast<u8>(jit::YieldKind::Timer)};
    VOK(b.set_yield_payload(fn, payloads, 1, kinds));
    BlockId resume_blocks[2] = {entry, resume};
    VOK(b.set_explicit_resume_blocks(fn, resume_blocks, 2));

    b.set_insert_point(fn, entry);
    VOK(b.emit_yield_event(static_cast<u8>(jit::YieldKind::Timer), 50, 1));

    b.set_insert_point(fn, resume);
    VOK(b.emit_ret_status(204));

    auto result = verify_function(fn);
    REQUIRE(result.ok);

    VerifyHandlerAutomaton automaton{};
    REQUIRE(build_verify_handler_automaton(fn, automaton));
    CHECK_EQ(automaton.node_count, 2u);
    CHECK_EQ(automaton.yield_count, 1u);
    CHECK_EQ(automaton.terminal_count, 1u);
    CHECK_EQ(automaton.edge_count, 1u);
    CHECK_EQ(automaton.runtime_submit_count, 1u);
    CHECK_EQ(automaton.runtime_completion_count, 1u);
    CHECK_EQ(automaton.runtime_fail_closed_count, 1u);
    CHECK_EQ(static_cast<u8>(automaton.nodes[entry.id].kind),
             static_cast<u8>(VerifyHandlerNodeKind::Yield));
    CHECK_EQ(automaton.nodes[entry.id].target_count, 1u);
    CHECK_EQ(automaton.nodes[entry.id].targets[0], resume.id);
    CHECK_EQ(automaton.nodes[entry.id].yield_kind, static_cast<u8>(jit::YieldKind::Timer));
    CHECK_EQ(automaton.nodes[entry.id].yield_payload, 50u);
    CHECK_EQ(automaton.nodes[entry.id].next_state, 1u);
    auto check = verify_handler_automaton(automaton);
    REQUIRE(check.ok);

    ctx.destroy();
}

TEST(RirVerifier, HandlerAutomatonSummarizesTimedAnyAsTimerAndRecv) {
    TestContext ctx;
    REQUIRE(ctx.init());

    Builder b;
    b.init(&ctx.mod);

    auto* fn = V(b.create_function(lit("test_fn"), lit("/test"), 1));
    auto entry = V(b.create_block(fn, lit("entry")));
    auto resume = V(b.create_block(fn, lit("resume")));

    u32 payloads[1] = {25};
    u8 kinds[1] = {static_cast<u8>(jit::YieldKind::Any)};
    VOK(b.set_yield_payload(fn, payloads, 1, kinds));
    BlockId resume_blocks[2] = {entry, resume};
    VOK(b.set_explicit_resume_blocks(fn, resume_blocks, 2));

    b.set_insert_point(fn, entry);
    VOK(b.emit_yield_event(static_cast<u8>(jit::YieldKind::Any), 25, 1));

    b.set_insert_point(fn, resume);
    VOK(b.emit_ret_status(204));

    auto result = verify_function(fn);
    REQUIRE(result.ok);

    VerifyHandlerAutomaton automaton{};
    REQUIRE(build_verify_handler_automaton(fn, automaton));
    CHECK_EQ(automaton.node_count, 2u);
    CHECK_EQ(automaton.yield_count, 1u);
    CHECK_EQ(automaton.terminal_count, 1u);
    CHECK_EQ(automaton.edge_count, 1u);
    CHECK_EQ(automaton.runtime_submit_count, 2u);
    CHECK_EQ(automaton.runtime_completion_count, 2u);
    CHECK_EQ(automaton.runtime_fail_closed_count, 2u);
    CHECK_EQ(static_cast<u8>(automaton.nodes[entry.id].runtime.pending_op),
             static_cast<u8>(VerifyRuntimePendingOp::DownstreamRecv));
    CHECK_EQ(static_cast<u8>(automaton.nodes[entry.id].runtime.callback_slot),
             static_cast<u8>(VerifyRuntimeCallbackSlot::DownstreamRecv));
    CHECK_EQ(static_cast<u8>(automaton.nodes[entry.id].runtime.secondary_pending_op),
             static_cast<u8>(VerifyRuntimePendingOp::Timer));
    CHECK_EQ(static_cast<u8>(automaton.nodes[entry.id].runtime.secondary_callback_slot),
             static_cast<u8>(VerifyRuntimeCallbackSlot::HandlerTimer));

    ctx.destroy();
}

TEST(RirVerifier, HandlerAutomatonRejectsNonYieldingControlCycle) {
    TestContext ctx;
    REQUIRE(ctx.init());

    Builder b;
    b.init(&ctx.mod);

    auto* fn = V(b.create_function(lit("test_fn"), lit("/test"), 0));
    auto entry = V(b.create_block(fn, lit("entry")));

    b.set_insert_point(fn, entry);
    VOK(b.emit_jmp(entry));

    auto result = verify_function(fn);
    REQUIRE(!result.ok);
    CHECK_EQ(static_cast<u8>(result.issue.code),
             static_cast<u8>(VerifyIssueCode::NonYieldingControlCycle));
    CHECK_EQ(result.issue.block_index, entry.id);
    CHECK_EQ(result.issue.target_index, entry.id);

    VerifyHandlerAutomaton automaton{};
    REQUIRE(build_verify_handler_automaton(fn, automaton));
    CHECK_EQ(automaton.node_count, 1u);
    CHECK_EQ(static_cast<u8>(automaton.nodes[entry.id].kind),
             static_cast<u8>(VerifyHandlerNodeKind::Jump));
    CHECK_EQ(automaton.nodes[entry.id].target_count, 1u);
    CHECK_EQ(automaton.nodes[entry.id].targets[0], entry.id);

    auto check = verify_handler_automaton(automaton);
    REQUIRE(!check.ok);
    CHECK_EQ(static_cast<u8>(check.issue.code),
             static_cast<u8>(VerifyHandlerCheckIssueCode::NonYieldingCycle));
    CHECK_EQ(check.issue.node_index, entry.id);
    CHECK_EQ(check.issue.target_index, entry.id);

    ctx.destroy();
}

TEST(RirVerifier, HandlerAutomatonSummarizesUpstreamFailurePath) {
    TestContext ctx;
    REQUIRE(ctx.init());

    Builder b;
    b.init(&ctx.mod);

    auto* fn = V(b.create_function(lit("test_fn"), lit("/test"), 1));
    auto entry = V(b.create_block(fn, lit("entry")));
    auto resume = V(b.create_block(fn, lit("resume")));

    u32 payloads[1] = {1};
    u8 kinds[1] = {static_cast<u8>(jit::YieldKind::UpstreamConnect)};
    VOK(b.set_yield_payload(fn, payloads, 1, kinds));
    BlockId resume_blocks[2] = {entry, resume};
    VOK(b.set_explicit_resume_blocks(fn, resume_blocks, 2));

    b.set_insert_point(fn, entry);
    VOK(b.emit_yield_event(static_cast<u8>(jit::YieldKind::UpstreamConnect), 1, 1));

    b.set_insert_point(fn, resume);
    VOK(b.emit_ret_status(204));

    auto result = verify_function(fn);
    REQUIRE(result.ok);

    VerifyHandlerAutomaton automaton{};
    REQUIRE(build_verify_handler_automaton(fn, automaton));
    CHECK_EQ(automaton.node_count, 2u);
    CHECK_EQ(automaton.yield_count, 1u);
    CHECK_EQ(automaton.terminal_count, 1u);
    CHECK_EQ(automaton.edge_count, 1u);
    CHECK_EQ(automaton.runtime_submit_count, 1u);
    CHECK_EQ(automaton.runtime_completion_count, 1u);
    CHECK_EQ(automaton.runtime_fail_closed_count, 1u);
    CHECK_EQ(static_cast<u8>(automaton.nodes[entry.id].runtime.pending_op),
             static_cast<u8>(VerifyRuntimePendingOp::UpstreamConnect));
    CHECK_EQ(static_cast<u8>(automaton.nodes[entry.id].runtime.callback_slot),
             static_cast<u8>(VerifyRuntimeCallbackSlot::UpstreamSend));

    ctx.destroy();
}

TEST(RirVerifier, RejectsYieldTerminatorMetadataMismatch) {
    TestContext ctx;
    REQUIRE(ctx.init());

    Builder b;
    b.init(&ctx.mod);

    auto* fn = V(b.create_function(lit("test_fn"), lit("/test"), 1));
    auto entry = V(b.create_block(fn, lit("entry")));
    auto resume = V(b.create_block(fn, lit("resume")));

    u32 payloads[1] = {50};
    u8 kinds[1] = {static_cast<u8>(jit::YieldKind::Timer)};
    VOK(b.set_yield_payload(fn, payloads, 1, kinds));
    BlockId resume_blocks[2] = {entry, resume};
    VOK(b.set_explicit_resume_blocks(fn, resume_blocks, 2));

    b.set_insert_point(fn, entry);
    VOK(b.emit_yield_event(static_cast<u8>(jit::YieldKind::Timer), 75, 1));

    b.set_insert_point(fn, resume);
    VOK(b.emit_ret_status(204));

    auto result = verify_function(fn);
    REQUIRE(!result.ok);
    CHECK_EQ(static_cast<u8>(result.issue.code),
             static_cast<u8>(VerifyIssueCode::YieldMetadataMismatch));
    CHECK_EQ(result.issue.target_index, 1u);

    ctx.destroy();
}

TEST(RirVerifier, RejectsDuplicateYieldNextState) {
    TestContext ctx;
    REQUIRE(ctx.init());

    Builder b;
    b.init(&ctx.mod);

    auto* fn = V(b.create_function(lit("test_fn"), lit("/test"), 1));
    auto entry = V(b.create_block(fn, lit("entry")));
    auto resume1 = V(b.create_block(fn, lit("resume1")));
    auto resume2 = V(b.create_block(fn, lit("resume2")));

    u32 payloads[2] = {50, 100};
    u8 kinds[2] = {static_cast<u8>(jit::YieldKind::Timer), static_cast<u8>(jit::YieldKind::Timer)};
    VOK(b.set_yield_payload(fn, payloads, 2, kinds));
    BlockId resume_blocks[3] = {entry, resume1, resume2};
    VOK(b.set_explicit_resume_blocks(fn, resume_blocks, 3));

    b.set_insert_point(fn, entry);
    VOK(b.emit_yield_event(static_cast<u8>(jit::YieldKind::Timer), 50, 1));

    b.set_insert_point(fn, resume1);
    VOK(b.emit_yield_event(static_cast<u8>(jit::YieldKind::Timer), 100, 2));
    fn->blocks[resume1.id].insts[0].imm.i64_val =
        (static_cast<i64>(jit::YieldKind::Timer) << 48) | (static_cast<i64>(1) << 32) | 100;

    b.set_insert_point(fn, resume2);
    VOK(b.emit_ret_status(204));

    auto result = verify_function(fn);
    REQUIRE(!result.ok);
    CHECK_EQ(static_cast<u8>(result.issue.code),
             static_cast<u8>(VerifyIssueCode::DuplicateYieldNextState));
    CHECK_EQ(result.issue.block_index, resume1.id);
    CHECK_EQ(result.issue.target_index, 1u);

    ctx.destroy();
}

TEST(RirVerifier, RejectsDeadYieldMetadataMismatchWhenReachabilityRelaxed) {
    TestContext ctx;
    REQUIRE(ctx.init());

    Builder b;
    b.init(&ctx.mod);

    auto* fn = V(b.create_function(lit("test_fn"), lit("/test"), 1));
    auto entry = V(b.create_block(fn, lit("entry")));
    auto dead_yield = V(b.create_block(fn, lit("dead_yield")));
    auto resume = V(b.create_block(fn, lit("resume")));

    u32 payloads[1] = {50};
    u8 kinds[1] = {static_cast<u8>(jit::YieldKind::Timer)};
    VOK(b.set_yield_payload(fn, payloads, 1, kinds));
    BlockId resume_blocks[2] = {entry, resume};
    VOK(b.set_explicit_resume_blocks(fn, resume_blocks, 2));

    b.set_insert_point(fn, entry);
    VOK(b.emit_ret_status(204));

    b.set_insert_point(fn, dead_yield);
    VOK(b.emit_yield_event(static_cast<u8>(jit::YieldKind::Timer), 99, 1));

    b.set_insert_point(fn, resume);
    VOK(b.emit_ret_status(204));

    VerifyOptions relaxed{};
    relaxed.require_all_blocks_reachable = false;
    auto result = verify_function(fn, 0, relaxed);
    REQUIRE(!result.ok);
    CHECK_EQ(static_cast<u8>(result.issue.code),
             static_cast<u8>(VerifyIssueCode::YieldMetadataMismatch));
    CHECK_EQ(result.issue.block_index, dead_yield.id);
    CHECK_EQ(result.issue.target_index, 1u);

    ctx.destroy();
}

TEST(RirVerifier, RejectsUnreachableBlockByDefault) {
    TestContext ctx;
    REQUIRE(ctx.init());

    Builder b;
    b.init(&ctx.mod);

    auto* fn = V(b.create_function(lit("test_fn"), lit("/test"), 1));
    auto entry = V(b.create_block(fn, lit("entry")));
    auto dead = V(b.create_block(fn, lit("dead")));

    b.set_insert_point(fn, entry);
    VOK(b.emit_ret_status(204));
    b.set_insert_point(fn, dead);
    VOK(b.emit_ret_status(500));

    auto result = verify_function(fn);
    REQUIRE(!result.ok);
    CHECK_EQ(static_cast<u8>(result.issue.code),
             static_cast<u8>(VerifyIssueCode::UnreachableBlock));
    CHECK_EQ(result.issue.block_index, dead.id);

    VerifyOptions relaxed{};
    relaxed.require_all_blocks_reachable = false;
    auto relaxed_result = verify_function(fn, 0, relaxed);
    REQUIRE(relaxed_result.ok);
    CHECK_EQ(relaxed_result.summary.reachable_block_count, 1u);

    ctx.destroy();
}

TEST(RirBuilder, ValueIdSentinel) {
    CHECK_EQ(kNoValue.id, 0xFFFFFFFFu);
    ValueId v{0};
    CHECK(v != kNoValue);
    ValueId v2{0};
    CHECK(v == v2);
}

TEST(RirBuilder, OptionalOps) {
    TestContext ctx;
    REQUIRE(ctx.init());

    Builder b;
    b.init(&ctx.mod);

    auto* fn = V(b.create_function(lit("test_fn"), lit("/test"), 1));
    auto entry = V(b.create_block(fn, lit("entry")));
    b.set_insert_point(fn, entry);

    auto hdr = V(b.emit_req_header(lit("X-Token")));
    auto is_nil = V(b.emit_opt_is_nil(hdr));

    CHECK_EQ(static_cast<u8>(fn->values[is_nil.id].type->kind), static_cast<u8>(TypeKind::Bool));

    auto* t_str = V(b.make_type(TypeKind::Str));
    auto unwrapped = V(b.emit_opt_unwrap(hdr, t_str));
    CHECK_EQ(static_cast<u8>(fn->values[unwrapped.id].type->kind), static_cast<u8>(TypeKind::Str));

    ctx.destroy();
}

TEST(RirBuilder, DomainOps) {
    TestContext ctx;
    REQUIRE(ctx.init());

    Builder b;
    b.init(&ctx.mod);

    auto* fn = V(b.create_function(lit("test_fn"), lit("/test"), 1));
    auto entry = V(b.create_block(fn, lit("entry")));
    b.set_insert_point(fn, entry);

    auto now = V(b.emit_time_now());
    CHECK_EQ(static_cast<u8>(fn->values[now.id].type->kind), static_cast<u8>(TypeKind::Time));

    auto prev = V(b.emit_time_now());
    auto diff = V(b.emit_time_diff(now, prev));
    CHECK_EQ(static_cast<u8>(fn->values[diff.id].type->kind), static_cast<u8>(TypeKind::Duration));

    auto ip = V(b.emit_req_remote_addr());
    auto in_cidr = V(b.emit_ip_in_cidr(ip, lit("10.0.0.0/8")));
    CHECK_EQ(static_cast<u8>(fn->values[in_cidr.id].type->kind), static_cast<u8>(TypeKind::Bool));

    ctx.destroy();
}

// ── Overflow tests ──────────────────────────────────────────────────

TEST(RirBuilder, InstructionOverflow) {
    TestContext ctx;
    REQUIRE(ctx.init());

    Builder b;
    b.init(&ctx.mod);

    auto* fn = V(b.create_function(lit("big_fn"), lit("/big"), 1));
    auto entry = V(b.create_block(fn, lit("entry")));
    b.set_insert_point(fn, entry);

    for (u32 i = 0; i < 40; i++) {
        auto vid = V(b.emit_const_i32(static_cast<i32>(i)));
        CHECK(vid != kNoValue);
    }

    CHECK_EQ(fn->value_count, 40u);
    CHECK_EQ(fn->entry()->inst_count, 40u);

    ValueId last = {fn->value_count - 1};
    CHECK_EQ(fn->entry()->insts[39].result, last);
    CHECK_EQ(fn->entry()->insts[39].imm.i32_val, 39);

    ctx.destroy();
}

TEST(RirBuilder, ValueOverflow) {
    TestContext ctx;
    REQUIRE(ctx.init());

    Builder b;
    b.init(&ctx.mod);

    auto* fn = V(b.create_function(lit("huge_fn"), lit("/huge"), 1));

    const char* labels[] = {
        "blk_0", "blk_1", "blk_2", "blk_3", "blk_4", "blk_5", "blk_6", "blk_7", "blk_8"};
    for (u32 blk_idx = 0; blk_idx < 9; blk_idx++) {
        auto bid = V(b.create_block(fn, lit(labels[blk_idx])));
        b.set_insert_point(fn, bid);

        for (u32 i = 0; i < 32; i++) {
            auto vid = V(b.emit_const_i32(static_cast<i32>(blk_idx * 32 + i)));
            CHECK(vid != kNoValue);
        }
    }

    CHECK_EQ(fn->value_count, 288u);
    CHECK(fn->values[257].type != nullptr);

    ctx.destroy();
}

// ── Yield tests ─────────────────────────────────────────────────────

TEST(RirBuilder, YieldHttpGetNoHeaders) {
    TestContext ctx;
    REQUIRE(ctx.init());

    Builder b;
    b.init(&ctx.mod);

    auto* fn = V(b.create_function(lit("test_fn"), lit("/test"), 1));
    auto entry = V(b.create_block(fn, lit("entry")));
    b.set_insert_point(fn, entry);

    auto vid = V(b.emit_yield_http_get(lit("http://auth/verify"), kNoValue));
    CHECK(vid != kNoValue);
    CHECK_EQ(fn->yield_count, 1u);

    auto& inst = fn->entry()->insts[0];
    CHECK_EQ(static_cast<u8>(inst.op), static_cast<u8>(Opcode::YieldHttpGet));
    CHECK_EQ(inst.operand_count, 0u);

    char print_data[512];
    PrintBuf pb;
    pb.init(print_data, sizeof(print_data), -1);
    print_instruction(pb, inst, *fn);

    Str output = {pb.data, pb.len};
    bool found_bogus = false;
    Str bogus = lit("%4294967295");
    for (u32 i = 0; i + bogus.len <= output.len; i++) {
        if (output.slice(i, i + bogus.len).eq(bogus)) {
            found_bogus = true;
            break;
        }
    }
    CHECK(!found_bogus);

    ctx.destroy();
}

TEST(RirBuilder, YieldHttpGetWithHeaders) {
    TestContext ctx;
    REQUIRE(ctx.init());

    Builder b;
    b.init(&ctx.mod);

    auto* fn = V(b.create_function(lit("test_fn"), lit("/test"), 1));
    auto entry = V(b.create_block(fn, lit("entry")));
    b.set_insert_point(fn, entry);

    auto headers = V(b.emit_const_str(lit("Bearer xyz")));
    auto vid = V(b.emit_yield_http_get(lit("http://auth/verify"), headers));
    CHECK(vid != kNoValue);

    auto& inst = fn->entry()->insts[1];
    CHECK_EQ(inst.operand_count, 1u);
    CHECK_EQ(inst.operands[0].id, headers.id);

    ctx.destroy();
}

TEST(RirModule, MultipleFunctions) {
    TestContext ctx;
    REQUIRE(ctx.init());

    Builder b;
    b.init(&ctx.mod);

    auto* fn1 = V(b.create_function(lit("handle_get_users"), lit("/users"), 1));
    auto* fn2 = V(b.create_function(lit("handle_post_orders"), lit("/orders"), 2));

    CHECK_EQ(ctx.mod.func_count, 2u);
    CHECK(fn1->name.eq(lit("handle_get_users")));
    CHECK(fn2->name.eq(lit("handle_post_orders")));

    auto e1 = V(b.create_block(fn1, lit("entry")));
    auto e2 = V(b.create_block(fn2, lit("entry")));
    CHECK_EQ(e1.id, 0u);
    CHECK_EQ(e2.id, 0u);

    ctx.destroy();
}

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
