#include "fixtures/jwt_lifetime.h"
#include "rut/common/types.h"
#include "rut/compiler/analyze.h"
#include "rut/compiler/ast.h"
#include "rut/compiler/hir.h"
#include "rut/compiler/lexer.h"
#include "rut/compiler/lower_rir.h"
#include "rut/compiler/mir.h"
#include "rut/compiler/mir_build.h"
#include "rut/compiler/parser.h"
#include "rut/jit/codegen.h"
#include "rut/jit/handler_abi.h"
#include "rut/jit/jit_engine.h"
#include "rut/native_program.h"
#include "rut/runtime/arena.h"
#include "rut/runtime/slice_pool.h"
#include "test.h"
#include <filesystem>
#include <fstream>
#include <ios>
#include <iterator>
#include <memory>
#include <string>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

using namespace rut;
namespace {
std::string auth_path() {
    return (std::filesystem::path(__FILE__).parent_path().parent_path() /
            "examples/middleware/auth.rut")
        .string();
}
std::string policy_source(const std::string& module, const std::string& groups) {
    std::string source = "import * as auth from \"" + module + "\"\n";
    source += "import * as groups from \"" + groups + "\"\n";
    const char* const kPolicies[] = {
        "requireAny(claims, \"readers\", "
        "\"auditors\")",
        "requireAll(claims, \"readers\", "
        "\"auditors\")",
        "requireAny(claims, \"readers\", "
        "\"readers\")",
        "requireAll(claims, \"readers\", "
        "\"readers\")",
        "requireAny(claims, \"\", "
        "\"auditors\")",
        "requireAny(claims, \"readers\", "
        "\"\")",
        "requireAll(claims, \"\", "
        "\"auditors\")",
        "requireAll(claims, \"readers\", "
        "\"\")",
    };
    for (u32 i = 0; i < sizeof(kPolicies) / sizeof(kPolicies[0]); ++i) {
        source += "route GET \"/" + std::to_string(i) +
                  "\" {\n"
                  "let claims = auth.jwtDocumentHs256(req.authorization.or(\"\"), \"";
        source += test::jwt_lifetime::kSecret;
        source +=
            "\")\nlet identity = auth.jwtIdentity(claims, \"issuer\", \"gateway\", "
            "\"groups-policy\")\nlet authorized = groups.";
        source += kPolicies[i];
        source += "\nreturn 204\n}\n";
    }
    return source;
}
std::string claims(const std::string& fields) {
    return "{\"sub\":\"alice\",\"iss\":\"issuer\",\"aud\":\"gateway\",\"exp\":4102444800" + fields +
           "}";
}

template <typename Invoke>
void matrix(test::TestCase* _tc, Invoke invoke) {
    auto check_headers = [&](u32 route, const std::string& headers, u16 expected) {
        const std::string kRequest =
            "GET /" + std::to_string(route) + " HTTP/1.1\r\nHost: localhost\r\n" + headers + "\r\n";
        CHECK_EQ(invoke(route, kRequest).status_code, expected);
    };
    auto check = [&](const std::string& document, u16 any, u16 all) {
        const std::string kToken = test::jwt_lifetime::make_token(document);
        REQUIRE(!kToken.empty());
        const std::string kHeaders =
            "Authorization: Bearer " + kToken +
            "\r\nX-Consumer-ID: mallory\r\nX-Consumer-Groups: readers auditors\r\n";
        check_headers(0, kHeaders, any);
        check_headers(1, kHeaders, all);
    };
    check(claims(",\"groups\":[\"readers\",\"auditors\"]"), 204, 204);
    check(claims(",\"groups\":[\"readers\"]"), 204, 403);
    check(claims(",\"groups\":[\"auditors\"]"), 204, 403);
    check(claims(",\"groups\":[\"other\"]"), 403, 403);
    check(claims(",\"groups\":[\"Readers\",\"reader\",\"auditors:extra\"]"), 403, 403);
    check(claims(",\"groups\":[\"readers\\u0000\",\"auditors\\u0000\"]"), 403, 403);
    check(claims(",\"groups\":[\"r\\u0065aders\",\"auditors\"]"), 204, 204);
    check(claims(",\"gr\\u006fups\":[\"readers\",\"auditors\"]"), 204, 204);
    check(claims(",\"scope\":\"readers auditors\""), 403, 403);
    check(claims(""), 403, 403);
    const char* malformed[] = {"null",
                               "true",
                               "42",
                               "\"readers auditors\"",
                               "[]",
                               "[\"readers\",null]",
                               "[\"readers\",\"auditors\",1]",
                               "[\"readers\",\"\"]",
                               "[false,\"readers\",\"auditors\"]"};
    for (const char* value : malformed)
        check(claims(std::string(",\"groups\":") + value), 403, 403);
    check(claims(",\"groups\":[\"readers\"],\"groups\":[\"auditors\"]"), 401, 401);
    check(claims(",\"groups\":[\"readers\"],\"gr\\u006fups\":[\"auditors\"]"), 401, 401);
    check(
        "{\"sub\":\"alice\",\"iss\":\"wrong\",\"aud\":\"gateway\",\"exp\":4102444800,\"groups\":["
        "\"readers\",\"auditors\"]}",
        401,
        401);
    check(
        "{\"sub\":\"alice\",\"iss\":\"issuer\",\"aud\":\"other\",\"exp\":4102444800,\"groups\":["
        "\"readers\",\"auditors\"]}",
        401,
        401);
    check(
        "{\"sub\":\"alice\",\"iss\":\"issuer\",\"aud\":\"gateway\",\"exp\":1,\"groups\":["
        "\"readers\",\"auditors\"]}",
        401,
        401);
    check(
        "{\"iss\":\"issuer\",\"aud\":\"gateway\",\"exp\":4102444800,\"groups\":[\"readers\","
        "\"auditors\"]}",
        401,
        401);
    check(
        "{\"sub\":\"\",\"iss\":\"issuer\",\"aud\":\"gateway\",\"exp\":4102444800,\"groups\":["
        "\"readers\",\"auditors\"]}",
        401,
        401);
    const std::string kToken =
        test::jwt_lifetime::make_token(claims(",\"groups\":[\"readers\",\"auditors\"]"));
    const std::string kHeaders = "Authorization: Bearer " + kToken + "\r\n";
    for (u32 i = 0; i < 4; ++i) {
        check_headers(i, kHeaders, 204);
        check_headers(i, "", 401);
        check_headers(i, "X-Consumer-Groups: readers auditors\r\n", 401);
        check_headers(i, kHeaders + kHeaders, 401);
        std::string forged = kToken;
        forged[forged.find_last_of('.') + 1] =
            kToken[forged.find_last_of('.') + 1] == 'A' ? 'B' : 'A';
        check_headers(i, "Authorization: Bearer " + forged + "\r\n", 401);
    }
    const std::string kAuditor =
        "Authorization: Bearer " +
        test::jwt_lifetime::make_token(claims(",\"groups\":[\"auditors\"]")) + "\r\n";
    check_headers(2, kAuditor, 403);
    check_headers(3, kAuditor, 403);
    for (u32 i = 4; i < 8; ++i) {
        check_headers(i, kHeaders, 503);
        check_headers(i, "", 401);
    }
}

struct TempSource {
    char path[4096]{};
    int fd = -1;
    TempSource() {
        const char* dir = getenv("TMPDIR");
        if (snprintf(path, sizeof(path), "%s/rut-jwt-groups-XXXXXX", dir ? dir : "/tmp") >=
            static_cast<int>(sizeof(path)))
            return;
        fd = mkstemp(path);
    }
    bool append(const std::string& value) {
        u32 offset = 0;
        while (offset < value.size()) {
            const auto kN = write(fd, value.data() + offset, value.size() - offset);
            if (kN <= 0) return false;
            offset += static_cast<u32>(kN);
        }
        return true;
    }
    ~TempSource() {
        if (fd >= 0) close(fd);
        if (path[0]) unlink(path);
    }
};
}  // namespace

TEST(jwt_group_policies, jit_authenticates_before_group_union_and_intersection) {
    const auto kSource = policy_source(
        auth_path(),
        (std::filesystem::path(auth_path()).parent_path() / "jwt_groups.rut").string());
    auto tokens = lex({kSource.data(), static_cast<u32>(kSource.size())});
    REQUIRE(tokens);
    auto ast = parse_file(tokens.value());
    REQUIRE(ast);
    std::unique_ptr<AstFile> const kAstOwner(ast.value());
    const auto kSourcePath = (std::filesystem::path(__FILE__).parent_path().parent_path() /
                              "examples/jwt-group-kPolicies.rut")
                                 .string();
    auto hir =
        analyze_file(*ast.value(), {kSourcePath.data(), static_cast<u32>(kSourcePath.size())});
    REQUIRE(hir);
    std::unique_ptr<HirModule> const kHirOwner(hir.value());
    auto mir = build_mir(*hir.value());
    REQUIRE(mir);
    std::unique_ptr<MirModule> const kMirOwner(mir.value());
    FrontendRirModule rir{};
    REQUIRE(lower_to_rir(*mir.value(), rir));
    auto cg = jit::codegen(rir.module);
    REQUIRE(cg.ok);
    jit::JitEngine engine;
    REQUIRE(engine.init());
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    SlicePool pool;
    REQUIRE(pool.init(32));
    SliceArena arena;
    REQUIRE(arena.init(&pool));
    matrix(_tc, [&](u32 route, const std::string& request) {
        arena.reset();
        char name[32];
        snprintf(name, sizeof(name), "handler_route_%u", route);
        auto handler = reinterpret_cast<jit::HandlerFn>(engine.lookup(name));
        if (!handler) return jit::HandlerResult{};
        const auto kResult =
            jit::HandlerResult::unpack(handler(nullptr,
                                               nullptr,
                                               reinterpret_cast<const u8*>(request.data()),
                                               static_cast<u32>(request.size()),
                                               &arena));
        if (kResult.status_code == 401 || kResult.status_code == 403) {
            const bool kValid =
                kResult.next_state > 0 && kResult.next_state <= rir.module.header_set_count;
            CHECK(kValid);
            if (kValid) {
                const auto& set = rir.module.header_sets[kResult.next_state - 1];
                CHECK_EQ(set.count, 1u);
                CHECK(rir.module.header_keys[set.offset].eq(lit_str("WWW-Authenticate")));
                CHECK(rir.module.header_values[set.offset].eq(
                    kResult.status_code == 401 ? lit_str("Bearer")
                                               : lit_str("Bearer error=\"insufficient_scope\"")));
            }
        }
        return kResult;
    });
    arena.destroy();
    pool.destroy();
    engine.shutdown();
    rir.destroy();
}

TEST(jwt_group_policies, native_policies_survive_source_and_module_removal) {
    std::ifstream input(auth_path(), std::ios::binary);
    REQUIRE(input.good());
    const std::string kModule((std::istreambuf_iterator<char>(input)),
                              std::istreambuf_iterator<char>());
    TempSource imported;
    REQUIRE(imported.fd >= 0);
    REQUIRE(imported.append(kModule));
    std::ifstream groups_input(std::filesystem::path(auth_path()).parent_path() / "jwt_groups.rut");
    REQUIRE(groups_input.good());
    std::string const kGroupsModule((std::istreambuf_iterator<char>(groups_input)),
                                    std::istreambuf_iterator<char>());
    TempSource groups;
    REQUIRE(groups.fd >= 0);
    REQUIRE(groups.append(kGroupsModule));
    TempSource source;
    REQUIRE(source.fd >= 0);
    REQUIRE(source.append(policy_source(imported.path, groups.path)));
    MmapArena storage;
    REQUIRE(storage.init(sizeof(NativeProgram) + 4096));
    auto* program = storage.alloc_t<NativeProgram>();
    REQUIRE(program);
    char error[512]{};
    bool const kLoaded = load_native_program(source.path, *program, error, sizeof(error));
    if (!kLoaded) fprintf(stderr, "%s\n", error);
    REQUIRE(kLoaded);
    REQUIRE_EQ(program->config.route_count, 8u);
    REQUIRE_EQ(unlink(source.path), 0);
    REQUIRE_EQ(unlink(imported.path), 0);
    REQUIRE_EQ(unlink(groups.path), 0);
    SlicePool pool;
    REQUIRE(pool.init(32));
    SliceArena arena;
    REQUIRE(arena.init(&pool));
    matrix(_tc, [&](u32 route, const std::string& request) {
        arena.reset();
        jit::HandlerCtx ctx{};
        if (route >= RouteConfig::kMaxRoutes || route >= program->config.route_count) {
            CHECK(false);
            return jit::HandlerResult{};
        }
        const auto kResult = jit::HandlerResult::unpack(
            program->config.routes[route].fn(nullptr,
                                             &ctx,
                                             reinterpret_cast<const u8*>(request.data()),
                                             static_cast<u32>(request.size()),
                                             &arena));
        if (kResult.status_code == 401 || kResult.status_code == 403) {
            const auto& config = program->config;
            const bool kValid =
                kResult.next_state > 0 && kResult.next_state <= config.response_header_set_count;
            CHECK(kValid);
            if (kValid) {
                const auto& set = config.response_header_sets[kResult.next_state - 1];
                CHECK_EQ(set.count, 1u);
                const auto& key = config.header_keys[set.offset];
                const auto& value = config.header_values[set.offset];
                CHECK((Str{key.data, key.len}.eq(lit_str("WWW-Authenticate"))));
                CHECK((Str{value.data, value.len}.eq(
                    kResult.status_code == 401 ? lit_str("Bearer")
                                               : lit_str("Bearer error=\"insufficient_scope\""))));
            }
        }
        return kResult;
    });
    arena.destroy();
    pool.destroy();
    program->destroy();
    storage.destroy();
}

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
