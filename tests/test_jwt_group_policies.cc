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

#include <fcntl.h>
#include <limits.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

using namespace rut;
namespace {
constexpr char kSecret[] = "jwt-lifetime-test-secret-abcdefghijklmnopqrstuvwxyz";
struct Text {
    char value[8192]{};
    u32 len = 0;
    bool valid = true;
    Text() = default;
    Text(const char* s) { append(s); }
    static Text invalid() {
        Text value;
        value.valid = false;
        return value;
    }
    bool append(Str s) {
        if (s.len >= sizeof(value) - len) {
            valid = false;
            return false;
        }
        memcpy(value + len, s.ptr, s.len);
        len += s.len;
        value[len] = 0;
        return true;
    }
    bool append(const char* s) { return append({s, static_cast<u32>(strlen(s))}); }
    bool append(char c) {
        if (len + 1 >= sizeof(value)) {
            valid = false;
            return false;
        }
        value[len++] = c;
        value[len] = 0;
        return true;
    }
    const char* data() const { return value; }
    u32 size() const { return len; }
    bool empty() const { return !len; }
    bool good() const { return valid; }
    Text& operator+=(const char* s) {
        append(s);
        return *this;
    }
    Text& operator+=(const Text& s) {
        if (!s.good()) valid = false;
        append({s.value, s.len});
        return *this;
    }
    Text& operator+=(char c) {
        append(c);
        return *this;
    }
    friend Text operator+(Text a, const char* b) {
        a += b;
        return a;
    }
    friend Text operator+(Text a, const Text& b) {
        a += b;
        return a;
    }
    friend Text operator+(const char* a, const Text& b) {
        Text x(a);
        x += b;
        return x;
    }
    u32 find_last_of(char c) const {
        for (u32 i = len; i; i--)
            if (value[i - 1] == c) return i - 1;
        return len;
    }
};
Text num(u32 n) {
    char b[16];
    snprintf(b, sizeof(b), "%u", n);
    return Text(b);
}
Text base64url(const unsigned char* p, u32 n) {
    Text out;
    if (n > static_cast<u32>(INT_MAX) - 2) return Text::invalid();
    const u32 kRequired = 4 * ((n + 2) / 3);
    if (kRequired + 1 > sizeof(out.value)) return Text::invalid();
    const int kEncoded =
        EVP_EncodeBlock(reinterpret_cast<unsigned char*>(out.value), p, static_cast<int>(n));
    if (kEncoded <= 0 || static_cast<u32>(kEncoded) != kRequired) return Text::invalid();
    out.len = static_cast<u32>(kEncoded);
    out.value[out.len] = 0;
    for (u32 i = 0; i < out.len; i++) {
        if (out.value[i] == '+')
            out.value[i] = '-';
        else if (out.value[i] == '/')
            out.value[i] = '_';
    }
    while (out.len && out.value[out.len - 1] == '=') out.value[--out.len] = 0;
    return out;
}
Text token(const Text& claims) {
    if (!claims.good()) return Text::invalid();
    const Text kHeader("{\"alg\":\"HS256\",\"typ\":\"JWT\"}");
    Text x = base64url((const unsigned char*)kHeader.data(), kHeader.size());
    x += '.';
    x += base64url((const unsigned char*)claims.data(), claims.size());
    if (!x.good()) return Text::invalid();
    unsigned char sig[EVP_MAX_MD_SIZE]{};
    unsigned int n = 0;
    if (!HMAC(EVP_sha256(),
              kSecret,
              sizeof(kSecret) - 1,
              (const unsigned char*)x.data(),
              x.size(),
              sig,
              &n))
        return Text::invalid();
    x += '.';
    x += base64url(sig, n);
    if (!x.good()) return Text::invalid();
    return x;
}
Text auth_path() {
    char b[4096];
    const int kInitial = snprintf(b, sizeof(b), "%s", __FILE__);
    if (kInitial < 0 || static_cast<u32>(kInitial) >= sizeof(b)) return Text::invalid();
    char* s = strrchr(b, '/');
    if (s) *s = 0;
    const size_t kUsed = strlen(b);
    const int kWritten = snprintf(b + kUsed, sizeof(b) - kUsed, "/../examples/middleware/auth.rut");
    if (kWritten < 0 || static_cast<size_t>(kWritten) >= sizeof(b) - kUsed) return Text::invalid();
    return Text(b);
}
Text sibling(const char* name) {
    Text p = auth_path();
    if (!p.good()) return Text::invalid();
    const u32 kSlash = p.find_last_of('/');
    p.len = kSlash;
    p.value[kSlash] = 0;
    p += "/";
    p += name;
    return p;
}
Text policy_source(const Text& module, const Text& groups) {
    Text source = "import * as auth from \"" + module + "\"\n";
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
        source += "route GET \"/" + num(i) +
                  "\" {\n"
                  "let claims = auth.jwtDocumentHs256(req.authorization.or(\"\"), \"";
        source += kSecret;
        source +=
            "\")\nlet identity = auth.jwtIdentity(claims, \"issuer\", \"gateway\", "
            "\"groups-policy\")\nlet authorized = groups.";
        source += kPolicies[i];
        source += "\nreturn 204\n}\n";
    }
    return source;
}
Text claims(const Text& fields) {
    return "{\"sub\":\"alice\",\"iss\":\"issuer\",\"aud\":\"gateway\",\"exp\":4102444800" + fields +
           "}";
}

template <typename Invoke>
void matrix(test::TestCase* _tc, Invoke invoke) {
    auto check_headers = [&](u32 route, const Text& headers, u16 expected) {
        const Text kRequest =
            "GET /" + num(route) + " HTTP/1.1\r\nHost: localhost\r\n" + headers + "\r\n";
        REQUIRE(kRequest.good());
        CHECK_EQ(invoke(route, kRequest).status_code, expected);
    };
    auto check = [&](const Text& document, u16 any, u16 all) {
        const Text kToken = token(document);
        REQUIRE(!kToken.empty());
        const Text kHeaders =
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
    for (const char* value : malformed) check(claims(Text(",\"groups\":") + value), 403, 403);
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
    const Text kToken = token(claims(",\"groups\":[\"readers\",\"auditors\"]"));
    const Text kHeaders = "Authorization: Bearer " + kToken + "\r\n";
    for (u32 i = 0; i < 4; ++i) {
        check_headers(i, kHeaders, 204);
        check_headers(i, "", 401);
        check_headers(i, "X-Consumer-Groups: readers auditors\r\n", 401);
        check_headers(i, kHeaders + kHeaders, 401);
        Text forged = kToken;
        const u32 kDot = forged.find_last_of('.');
        forged.value[kDot + 1] = kToken.value[kDot + 1] == 'A' ? 'B' : 'A';
        check_headers(i, "Authorization: Bearer " + forged + "\r\n", 401);
    }
    const Text kAuditorToken = token(claims(",\"groups\":[\"auditors\"]"));
    const Text kAuditor = "Authorization: Bearer " + kAuditorToken + "\r\n";
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
    bool append(const Text& value) { return value.good() && append(value.data(), value.size()); }
    bool append(const char* data, u32 length) {
        u32 offset = 0;
        while (offset < length) {
            const auto kN = write(fd, data + offset, length - offset);
            if (kN <= 0) return false;
            offset += static_cast<u32>(kN);
        }
        return true;
    }
    bool copy_from(const Text& path) {
        if (!path.good()) return false;
        const int kInput = open(path.data(), O_RDONLY);
        if (kInput < 0) return false;
        char buffer[4096];
        bool ok = true;
        for (;;) {
            const ssize_t kRead = read(kInput, buffer, sizeof(buffer));
            if (kRead < 0) {
                ok = false;
                break;
            }
            if (kRead == 0) break;
            if (!append(buffer, static_cast<u32>(kRead))) {
                ok = false;
                break;
            }
        }
        close(kInput);
        return ok;
    }
    ~TempSource() {
        if (fd >= 0) close(fd);
        if (path[0]) unlink(path);
    }
};
TEST(jwt_group_policies, bounded_helpers_reject_overflow_before_consuming_text) {
    char too_large[8192]{};
    Text overflow_text;
    CHECK(!overflow_text.append({too_large, sizeof(too_large)}));
    CHECK(!overflow_text.good());

    TempSource temp;
    CHECK(temp.fd >= 0);
    CHECK(!temp.append(overflow_text));

    const unsigned char kBytes[6142]{};
    const Text kLargest = base64url(kBytes, 6141);
    CHECK(kLargest.good());
    CHECK_EQ(kLargest.size(), 8188u);
    const Text kTooLarge = base64url(kBytes, sizeof(kBytes));
    CHECK(!kTooLarge.good());
}
struct SlicePoolGuard {
    SlicePool* value;
    ~SlicePoolGuard() { value->destroy(); }
};
struct SliceArenaGuard {
    SliceArena* value;
    ~SliceArenaGuard() { value->destroy(); }
};
struct MmapArenaGuard {
    MmapArena* value;
    ~MmapArenaGuard() { value->destroy(); }
};
struct NativeProgramGuard {
    NativeProgram* value;
    ~NativeProgramGuard() { value->destroy(); }
};
struct JitEngineGuard {
    jit::JitEngine* value;
    ~JitEngineGuard() { value->shutdown(); }
};
struct RirGuard {
    FrontendRirModule* value;
    ~RirGuard() { value->destroy(); }
};
}  // namespace

TEST(jwt_group_policies, jit_authenticates_before_group_union_and_intersection) {
    const auto kSource = policy_source(auth_path(), sibling("jwt_groups.rut"));
    REQUIRE(kSource.good());
    auto tokens = lex({kSource.data(), kSource.size()});
    REQUIRE(tokens);
    auto ast = parse_file(tokens.value());
    REQUIRE(ast);
    struct AstOwner {
        AstFile* p;
        ~AstOwner() { delete p; }
    } const kAstOwner{ast.value()};
    const auto kSourcePath = sibling("../jwt-group-policies.rut");
    REQUIRE(kSourcePath.good());
    auto hir = analyze_file(*ast.value(), {kSourcePath.data(), kSourcePath.size()});
    REQUIRE(hir);
    struct HirOwner {
        HirModule* p;
        ~HirOwner() { delete p; }
    } const kHirOwner{hir.value()};
    auto mir = build_mir(*hir.value());
    REQUIRE(mir);
    struct MirOwner {
        MirModule* p;
        ~MirOwner() { delete p; }
    } const kMirOwner{mir.value()};
    FrontendRirModule rir{};
    REQUIRE(lower_to_rir(*mir.value(), rir));
    const RirGuard kRirGuard{&rir};
    auto cg = jit::codegen(rir.module);
    REQUIRE(cg.ok);
    jit::JitEngine engine;
    REQUIRE(engine.init());
    const JitEngineGuard kEngineGuard{&engine};
    REQUIRE(engine.compile(cg.mod, cg.ctx));
    SlicePool pool;
    REQUIRE(pool.init(32));
    const SlicePoolGuard kPoolGuard{&pool};
    SliceArena arena;
    REQUIRE(arena.init(&pool));
    const SliceArenaGuard kArenaGuard{&arena};
    matrix(_tc, [&](u32 route, const Text& request) {
        arena.reset();
        char name[32];
        snprintf(name, sizeof(name), "handler_route_%u", route);
        auto handler = reinterpret_cast<jit::HandlerFn>(engine.lookup(name));
        if (!handler) return jit::HandlerResult{};
        const auto kResult = jit::HandlerResult::unpack(handler(
            nullptr, nullptr, reinterpret_cast<const u8*>(request.data()), request.size(), &arena));
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
}

TEST(jwt_group_policies, native_policies_survive_source_and_module_removal) {
    REQUIRE(access(auth_path().data(), R_OK) == 0);
    TempSource imported;
    REQUIRE(imported.fd >= 0);
    REQUIRE(imported.copy_from(auth_path()));
    REQUIRE(access(sibling("jwt_groups.rut").data(), R_OK) == 0);
    TempSource groups;
    REQUIRE(groups.fd >= 0);
    REQUIRE(groups.copy_from(sibling("jwt_groups.rut")));
    TempSource source;
    REQUIRE(source.fd >= 0);
    const Text kPolicySource = policy_source(imported.path, groups.path);
    REQUIRE(source.append(kPolicySource));
    MmapArena storage;
    REQUIRE(storage.init(sizeof(NativeProgram) + 4096));
    const MmapArenaGuard kStorageGuard{&storage};
    auto* program = storage.alloc_t<NativeProgram>();
    REQUIRE(program);
    const NativeProgramGuard kProgramGuard{program};
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
    const SlicePoolGuard kPoolGuard{&pool};
    SliceArena arena;
    REQUIRE(arena.init(&pool));
    const SliceArenaGuard kArenaGuard{&arena};
    matrix(_tc, [&](u32 route, const Text& request) {
        arena.reset();
        jit::HandlerCtx ctx{};
        if (route >= RouteConfig::kMaxRoutes || route >= program->config.route_count) {
            CHECK(false);
            return jit::HandlerResult{};
        }
        const auto kResult = jit::HandlerResult::unpack(program->config.routes[route].fn(
            nullptr, &ctx, reinterpret_cast<const u8*>(request.data()), request.size(), &arena));
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
}

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
