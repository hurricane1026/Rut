#include "rut/compiler/analyze.h"
#include "rut/compiler/lexer.h"
#include "rut/compiler/lower_rir.h"
#include "rut/compiler/mir_build.h"
#include "rut/compiler/parser.h"
#include "rut/runtime/route_method.h"
#include "rut/sim/simulate_engine.h"
#include "test.h"

#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

using namespace rut;
using namespace rut::sim;

namespace {

static CaptureEntry make_entry(const char* req, u16 status, const char* upstream = nullptr) {
    CaptureEntry entry{};
    u32 len = 0;
    while (req[len]) len++;
    const u32 bounded_len =
        len > CaptureEntry::kMaxHeaderLen ? static_cast<u32>(CaptureEntry::kMaxHeaderLen) : len;
    __builtin_memcpy(entry.raw_headers, req, bounded_len);
    entry.raw_header_len = static_cast<u16>(bounded_len);
    entry.resp_status = status;
    if (upstream) {
        u32 i = 0;
        while (upstream[i] && i + 1 < sizeof(entry.upstream_name)) {
            entry.upstream_name[i] = upstream[i];
            i++;
        }
        entry.upstream_name[i] = '\0';
    }
    return entry;
}

static bool init_engine(const Manifest& manifest, ModuleContext& ctx, Engine& engine) {
    if (!build_module_from_manifest(manifest, ctx)) return false;
    return engine.init(ctx.module, manifest.upstreams, manifest.upstream_count);
}

static Str arena_copy(MmapArena& arena, const char* src, u32 len) {
    char* mem = arena.alloc_array<char>(len + 1);
    if (!mem) __builtin_trap();
    for (u32 i = 0; i < len; i++) mem[i] = src[i];
    mem[len] = '\0';
    return {mem, len};
}

static bool load_manifest_text(const char* text, Manifest* manifest) {
    char path[] = "/tmp/rut_sim_manifest_XXXXXX";
    const i32 fd = mkstemp(path);
    if (fd < 0) return false;
    const size_t len = strlen(text);
    const bool ok =
        write(fd, text, len) == static_cast<ssize_t>(len) && load_manifest(path, *manifest);
    close(fd);
    unlink(path);
    return ok;
}

static bool read_all_fd(i32 fd, char* buf, u32 cap, u32* out_len) {
    if (out_len) *out_len = 0;
    if (cap == 0) {
        char discard[256];
        for (;;) {
            const ssize_t n = read(fd, discard, sizeof(discard));
            if (n < 0) {
                if (errno == EINTR) continue;
                return false;
            }
            if (n == 0) return true;
        }
    }

    u32 pos = 0;
    char discard[256];
    for (;;) {
        char* dst = discard;
        u32 to_read = sizeof(discard);
        if (pos + 1 < cap) {
            dst = buf + pos;
            to_read = cap - 1 - pos;
        }

        const ssize_t n = read(fd, dst, to_read);
        if (n < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        if (n == 0) break;

        if (pos + 1 < cap) {
            const u32 remaining = cap - 1 - pos;
            const u32 stored = static_cast<u32>(n) > remaining ? remaining : static_cast<u32>(n);
            pos += stored;
        }
    }
    buf[pos] = '\0';
    if (out_len) *out_len = pos;
    return true;
}

static bool read_ready_fd(i32 fd, char* buf, u32 cap, u32* pos, bool* done) {
    if (*done) return true;

    char discard[256];
    char* dst = discard;
    u32 to_read = sizeof(discard);
    if (*pos + 1 < cap) {
        dst = buf + *pos;
        to_read = cap - 1 - *pos;
    }

    const ssize_t n = read(fd, dst, to_read);
    if (n < 0) {
        if (errno == EINTR || errno == EAGAIN) return true;
        return false;
    }
    if (n == 0) {
        *done = true;
        return true;
    }

    if (*pos + 1 < cap) {
        const u32 remaining = cap - 1 - *pos;
        const u32 stored = static_cast<u32>(n) > remaining ? remaining : static_cast<u32>(n);
        *pos += stored;
        buf[*pos] = '\0';
    }
    return true;
}

static bool read_pipes_interleaved(i32 out_fd,
                                   char* out_buf,
                                   u32 out_cap,
                                   u32* out_len,
                                   i32 err_fd,
                                   char* err_buf,
                                   u32 err_cap,
                                   u32* err_len) {
    if (out_len) *out_len = 0;
    if (err_len) *err_len = 0;
    if (out_cap > 0) out_buf[0] = '\0';
    if (err_cap > 0) err_buf[0] = '\0';

    u32 out_pos = 0;
    u32 err_pos = 0;
    bool out_done = false;
    bool err_done = false;
    while (!out_done || !err_done) {
        pollfd fds[2];
        nfds_t nfds = 0;
        if (!out_done) {
            fds[nfds].fd = out_fd;
            fds[nfds].events = POLLIN | POLLHUP;
            fds[nfds].revents = 0;
            nfds++;
        }
        if (!err_done) {
            fds[nfds].fd = err_fd;
            fds[nfds].events = POLLIN | POLLHUP;
            fds[nfds].revents = 0;
            nfds++;
        }

        const int poll_rc = poll(fds, nfds, -1);
        if (poll_rc < 0) {
            if (errno == EINTR) continue;
            return false;
        }

        nfds_t idx = 0;
        if (!out_done) {
            if (fds[idx].revents & (POLLERR | POLLNVAL)) return false;
            if ((fds[idx].revents & (POLLIN | POLLHUP)) &&
                !read_ready_fd(out_fd, out_buf, out_cap, &out_pos, &out_done)) {
                return false;
            }
            idx++;
        }
        if (!err_done) {
            if (fds[idx].revents & (POLLERR | POLLNVAL)) return false;
            if ((fds[idx].revents & (POLLIN | POLLHUP)) &&
                !read_ready_fd(err_fd, err_buf, err_cap, &err_pos, &err_done)) {
                return false;
            }
        }
    }

    if (out_len) *out_len = out_pos;
    if (err_len) *err_len = err_pos;
    return true;
}

static bool run_simulate_cli(const char* arg1,
                             const char* arg2,
                             i32* exit_code,
                             char* stdout_buf,
                             u32 stdout_cap,
                             char* stderr_buf,
                             u32 stderr_cap) {
    i32 out_pipe[2];
    i32 err_pipe[2];
    if (pipe(out_pipe) != 0) return false;
    if (pipe(err_pipe) != 0) {
        close(out_pipe[0]);
        close(out_pipe[1]);
        return false;
    }

    const pid_t pid = fork();
    if (pid < 0) {
        close(out_pipe[0]);
        close(out_pipe[1]);
        close(err_pipe[0]);
        close(err_pipe[1]);
        return false;
    }

    if (pid == 0) {
        dup2(out_pipe[1], 1);
        dup2(err_pipe[1], 2);
        close(out_pipe[0]);
        close(out_pipe[1]);
        close(err_pipe[0]);
        close(err_pipe[1]);
        if (arg1 && arg2) {
            execl(RUT_SIMULATE_BIN_PATH,
                  RUT_SIMULATE_BIN_PATH,
                  arg1,
                  arg2,
                  static_cast<char*>(nullptr));
        } else {
            execl(RUT_SIMULATE_BIN_PATH, RUT_SIMULATE_BIN_PATH, static_cast<char*>(nullptr));
        }
        _exit(127);
    }

    close(out_pipe[1]);
    close(err_pipe[1]);

    u32 stdout_len = 0;
    u32 stderr_len = 0;
    const bool io_ok = read_pipes_interleaved(out_pipe[0],
                                              stdout_buf,
                                              stdout_cap,
                                              &stdout_len,
                                              err_pipe[0],
                                              stderr_buf,
                                              stderr_cap,
                                              &stderr_len);
    close(out_pipe[0]);
    close(err_pipe[0]);

    i32 status = 0;
    if (waitpid(pid, &status, 0) < 0) return false;
    if (!io_ok) return false;
    if (!WIFEXITED(status)) return false;
    *exit_code = WEXITSTATUS(status);
    return true;
}

static bool write_capture_file(i32 fd,
                               u64 declared_count,
                               const CaptureEntry* entries,
                               u32 entry_count,
                               const CaptureEntry* partial_entry = nullptr,
                               u32 partial_len = 0) {
    CaptureFileHeader hdr;
    capture_file_header_init(&hdr);
    hdr.entry_count = declared_count;
    if (write(fd, &hdr, sizeof(hdr)) != static_cast<ssize_t>(sizeof(hdr))) return false;
    for (u32 i = 0; i < entry_count; i++) {
        if (capture_write_entry(fd, entries[i]) != 0) return false;
    }
    if (partial_entry && partial_len > 0) {
        if (partial_len > sizeof(CaptureEntry)) return false;
        if (write(fd, partial_entry, partial_len) != static_cast<ssize_t>(partial_len))
            return false;
    }
    return true;
}

}  // namespace

TEST(simulate_engine, load_manifest_file) {
    char path[] = "/tmp/rut_sim_manifest_XXXXXX";
    i32 fd = mkstemp(path);
    REQUIRE(fd >= 0);

    static const char kManifest[] =
        "# comment\n"
        "upstream 7 api-v1\n"
        "route GET /health status 204\n"
        "route ANY /api proxy 7\n";
    REQUIRE(write(fd, kManifest, sizeof(kManifest) - 1) ==
            static_cast<ssize_t>(sizeof(kManifest) - 1));
    close(fd);

    Manifest manifest;
    REQUIRE(load_manifest(path, manifest));
    CHECK_EQ(manifest.upstream_count, 1u);
    CHECK_EQ(manifest.route_count, 2u);
    CHECK_EQ(manifest.upstreams[0].id, 7u);
    CHECK_EQ(manifest.routes[0].status_code, 204u);
    CHECK_EQ(manifest.routes[1].upstream_id, 7u);

    unlink(path);
}

TEST(simulate_engine, load_manifest_accepts_whitespace_comments_and_forward_refs) {
    static const char kManifest[] =
        "\n"
        "   # comment before content\n"
        "\troute GET /health status 204   \n"
        "route ANY /api proxy 7   # trailing comment\n"
        "   \n"
        "upstream 7 api-v1\n";

    Manifest manifest;
    REQUIRE(load_manifest_text(kManifest, &manifest));
    CHECK_EQ(manifest.upstream_count, 1u);
    CHECK_EQ(manifest.route_count, 2u);
    CHECK_EQ(manifest.routes[0].status_code, 204u);
    CHECK_EQ(manifest.routes[1].upstream_id, 7u);
}

TEST(simulate_engine, static_status_match) {
    Manifest manifest{};
    manifest.route_count = 1;
    manifest.routes[0].method = kRouteMethodGet;
    strcpy(manifest.routes[0].pattern, "/health");
    manifest.routes[0].action = ManifestAction::ReturnStatus;
    manifest.routes[0].status_code = 204;

    ModuleContext ctx;
    Engine engine;
    REQUIRE(init_engine(manifest, ctx, engine));

    const auto result =
        simulate_one(engine, make_entry("GET /health HTTP/1.1\r\nHost: x\r\n\r\n", 204));
    CHECK_EQ(result.verdict, Verdict::Match);
    CHECK_EQ(result.actual_status, 204u);

    engine.shutdown();
    ctx.destroy();
}

// Helper: compile a .rut source to an RIR module owned by `rir`.
// The caller must keep `rir` alive for as long as the Engine.
static bool compile_to_rir(const char* src, FrontendRirModule& rir) {
    auto lexed = lex(Str{src, static_cast<u32>(strlen(src))});
    if (!lexed) {
        return false;
    }
    auto ast = parse_file(lexed.value());
    if (!ast) {
        return false;
    }
    std::unique_ptr<AstFile> ast_owned(ast.value());
    auto hir = analyze_file(*ast_owned);
    if (!hir) {
        return false;
    }
    std::unique_ptr<HirModule> hir_owned(hir.value());
    auto mir = build_mir(*hir_owned);
    if (!mir) {
        return false;
    }
    std::unique_ptr<MirModule> mir_owned(mir.value());
    auto lowered = lower_to_rir(*mir_owned, rir);
    if (!lowered) {
        return false;
    }
    return true;
}

TEST(simulate_engine, wait_handler_drives_state_machine_to_terminal_status) {
    // Source handler: one wait(500) then return 204. The simulate engine
    // must drive the yield chain to completion offline (skipping the
    // actual 500ms) and report the terminal status.
    const char* src = "route GET \"/sleep\" { wait(500) return 204 }\n";
    FrontendRirModule rir{};
    REQUIRE(compile_to_rir(src, rir));

    Engine engine;
    REQUIRE(engine.init(rir.module, nullptr, 0));

    const auto result =
        simulate_one(engine, make_entry("GET /sleep HTTP/1.1\r\nHost: x\r\n\r\n", 204));
    CHECK_EQ(result.verdict, Verdict::Match);
    CHECK_EQ(result.action, jit::HandlerAction::ReturnStatus);
    CHECK_EQ(result.actual_status, 204u);
    CHECK_EQ(result.yield_count, 1u);

    engine.shutdown();
    rir.destroy();
}

TEST(simulate_engine, let_before_wait_drives_to_terminal) {
    // Slice 1 acceptance: a let before a wait runs when the terminal
    // state reaches the entry block, and the yield chain still drives
    // to the terminal status cleanly. The let's value doesn't
    // participate in the return here — that's covered by
    // let_used_after_wait_in_if below.
    const char* src = "route GET \"/x\" { let k = 200 wait(50) return 200 }\n";
    FrontendRirModule rir{};
    REQUIRE(compile_to_rir(src, rir));
    Engine engine;
    REQUIRE(engine.init(rir.module, nullptr, 0));
    const auto result = simulate_one(engine, make_entry("GET /x HTTP/1.1\r\nHost: x\r\n\r\n", 200));
    CHECK_EQ(result.verdict, Verdict::Match);
    CHECK_EQ(result.actual_status, 200u);
    CHECK_EQ(result.yield_count, 1u);
    engine.shutdown();
    rir.destroy();
}

TEST(simulate_engine, let_used_after_wait_in_if) {
    // The real test of slice 1: the let's value has to survive the
    // yield and actually drive the branch in the terminal block.
    // The pure-constant initializer is re-materialized fresh in the
    // terminal block, so the branch compares against the correct
    // value without any HandlerCtx slot storage.
    const char* src =
        "route GET \"/x\" { let code = 201 wait(50) if code == 201 { return 201 } else { return "
        "500 } }\n";
    FrontendRirModule rir{};
    REQUIRE(compile_to_rir(src, rir));
    Engine engine;
    REQUIRE(engine.init(rir.module, nullptr, 0));
    const auto result = simulate_one(engine, make_entry("GET /x HTTP/1.1\r\nHost: x\r\n\r\n", 201));
    CHECK_EQ(result.verdict, Verdict::Match);
    CHECK_EQ(result.actual_status, 201u);
    CHECK_EQ(result.yield_count, 1u);
    engine.shutdown();
    rir.destroy();
}

TEST(simulate_engine, multiple_waits_all_drive_then_return) {
    const char* src = "route GET \"/multi\" { wait(100) wait(200) wait(300) return 201 }\n";
    FrontendRirModule rir{};
    REQUIRE(compile_to_rir(src, rir));

    Engine engine;
    REQUIRE(engine.init(rir.module, nullptr, 0));

    const auto result =
        simulate_one(engine, make_entry("GET /multi HTTP/1.1\r\nHost: x\r\n\r\n", 201));
    CHECK_EQ(result.verdict, Verdict::Match);
    CHECK_EQ(result.actual_status, 201u);
    CHECK_EQ(result.yield_count, 3u);

    engine.shutdown();
    rir.destroy();
}

TEST(simulate_engine, wait_result_fields_survive_later_waits) {
    const char* src =
        "route GET \"/x\" { let first = wait(50) let second = wait(downstream.recv()) if "
        "first.timer { guard second.ok else { return 500 } return 204 } else { return 502 } }\n";
    FrontendRirModule rir{};
    REQUIRE(compile_to_rir(src, rir));

    Engine engine;
    REQUIRE(engine.init(rir.module, nullptr, 0));

    const auto result = simulate_one(engine, make_entry("GET /x HTTP/1.1\r\nHost: x\r\n\r\n", 408));
    CHECK_EQ(result.verdict, Verdict::Match);
    CHECK_EQ(result.actual_status, 204u);
    CHECK_EQ(result.yield_count, 2u);

    engine.shutdown();
    rir.destroy();
}

TEST(simulate_engine, wait_any_statement_uses_concrete_wait_kind) {
    const char* src =
        "route GET \"/x\" { wait any { downstream.recv() => { return 204 } timer(50) => { return "
        "408 } } }\n";
    FrontendRirModule rir{};
    REQUIRE(compile_to_rir(src, rir));
    REQUIRE_GE(rir.module.func_count, 1u);
    REQUIRE_GE(rir.module.functions[0].yield_count, 1u);
    CHECK_EQ(rir.module.functions[0].yield_kinds[0], static_cast<u8>(jit::YieldKind::Any));
    CHECK_EQ(rir.module.functions[0].yield_payload[0], 50u);

    Engine engine;
    REQUIRE(engine.init(rir.module, nullptr, 0));

    const auto result = simulate_one(engine, make_entry("GET /x HTTP/1.1\r\nHost: x\r\n\r\n", 408));
    CHECK_EQ(result.verdict, Verdict::Match);
    CHECK_EQ(result.actual_status, 408u);
    CHECK_EQ(result.yield_count, 1u);

    engine.shutdown();
    rir.destroy();
}

TEST(simulate_engine, wait_any_expression_can_resume_with_timer_predicate) {
    const char* src =
        "route GET \"/x\" { let ev = wait(any(downstream.recv(), timer(50))) if ev.timer { "
        "return 408 } else { return 204 } }\n";
    FrontendRirModule rir{};
    REQUIRE(compile_to_rir(src, rir));

    Engine engine;
    REQUIRE(engine.init(rir.module, nullptr, 0));

    const auto result = simulate_one(engine, make_entry("GET /x HTTP/1.1\r\nHost: x\r\n\r\n", 408));
    CHECK_EQ(result.verdict, Verdict::Match);
    CHECK_EQ(result.actual_status, 408u);
    CHECK_EQ(result.yield_count, 1u);

    engine.shutdown();
    rir.destroy();
}

TEST(simulate_engine, timer_wait_result_matches_runtime_zero) {
    const char* src =
        "route GET \"/x\" { let ev = wait(50) if ev.result == 0 { return 204 } else { return 500 } "
        "}\n";
    FrontendRirModule rir{};
    REQUIRE(compile_to_rir(src, rir));

    Engine engine;
    REQUIRE(engine.init(rir.module, nullptr, 0));

    const auto result = simulate_one(engine, make_entry("GET /x HTTP/1.1\r\nHost: x\r\n\r\n", 204));
    CHECK_EQ(result.verdict, Verdict::Match);
    CHECK_EQ(result.actual_status, 204u);
    CHECK_EQ(result.yield_count, 1u);

    engine.shutdown();
    rir.destroy();
}

TEST(simulate_engine, forward_upstream_match) {
    Manifest manifest{};
    manifest.upstream_count = 1;
    manifest.upstreams[0].id = 7;
    strcpy(manifest.upstreams[0].name, "api-v1");
    manifest.route_count = 1;
    manifest.routes[0].method = 0;
    strcpy(manifest.routes[0].pattern, "/api");
    manifest.routes[0].action = ManifestAction::Forward;
    manifest.routes[0].upstream_id = 7;

    ModuleContext ctx;
    Engine engine;
    REQUIRE(init_engine(manifest, ctx, engine));

    const auto result = simulate_one(
        engine, make_entry("GET /api/users HTTP/1.1\r\nHost: x\r\n\r\n", 502, "api-v1"));
    CHECK_EQ(result.verdict, Verdict::Match);
    CHECK_EQ(result.action, jit::HandlerAction::Forward);

    engine.shutdown();
    ctx.destroy();
}

TEST(simulate_engine, default_200_when_no_route_matches) {
    Manifest manifest{};

    ModuleContext ctx;
    REQUIRE(ctx.init(1));
    Engine engine;
    REQUIRE(engine.init(ctx.module, manifest.upstreams, manifest.upstream_count));

    const auto result =
        simulate_one(engine, make_entry("GET /miss HTTP/1.1\r\nHost: x\r\n\r\n", 200));
    CHECK_EQ(result.verdict, Verdict::Match);
    CHECK_EQ(result.actual_status, 200u);

    engine.shutdown();
    ctx.destroy();
}

TEST(simulate_engine, simulate_one_route_action_matrix) {
    Manifest manifest{};
    manifest.upstream_count = 1;
    manifest.upstreams[0].id = 7;
    strcpy(manifest.upstreams[0].name, "api-v1");
    manifest.route_count = 3;
    manifest.routes[0].method = kRouteMethodGet;
    strcpy(manifest.routes[0].pattern, "/static");
    manifest.routes[0].action = ManifestAction::ReturnStatus;
    manifest.routes[0].status_code = 204;
    manifest.routes[1].method = kRouteMethodPost;
    strcpy(manifest.routes[1].pattern, "/post-only");
    manifest.routes[1].action = ManifestAction::ReturnStatus;
    manifest.routes[1].status_code = 202;
    manifest.routes[2].method = kRouteMethodGet;
    strcpy(manifest.routes[2].pattern, "/api");
    manifest.routes[2].action = ManifestAction::Forward;
    manifest.routes[2].upstream_id = 7;

    ModuleContext ctx;
    Engine engine;
    REQUIRE(init_engine(manifest, ctx, engine));

    struct MatrixCase {
        const char* name;
        CaptureEntry entry;
        Verdict verdict;
        jit::HandlerAction action;
        u16 actual_status;
        const char* actual_upstream;
    };

    const MatrixCase cases[] = {
        {"static status",
         make_entry("GET /static HTTP/1.1\r\nHost: x\r\n\r\n", 204),
         Verdict::Match,
         jit::HandlerAction::ReturnStatus,
         204,
         ""},
        {"default status",
         make_entry("GET /missing HTTP/1.1\r\nHost: x\r\n\r\n", 200),
         Verdict::Match,
         jit::HandlerAction::ReturnStatus,
         200,
         ""},
        {"default upstream mismatch",
         make_entry("GET /missing HTTP/1.1\r\nHost: x\r\n\r\n", 200, "api-v1"),
         Verdict::Mismatch,
         jit::HandlerAction::ReturnStatus,
         200,
         ""},
        {"method default",
         make_entry("GET /post-only HTTP/1.1\r\nHost: x\r\n\r\n", 200),
         Verdict::Match,
         jit::HandlerAction::ReturnStatus,
         200,
         ""},
        {"method match",
         make_entry("POST /post-only HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n", 202),
         Verdict::Match,
         jit::HandlerAction::ReturnStatus,
         202,
         ""},
        {"static mismatch",
         make_entry("GET /static HTTP/1.1\r\nHost: x\r\n\r\n", 201),
         Verdict::Mismatch,
         jit::HandlerAction::ReturnStatus,
         204,
         ""},
        {"forward match",
         make_entry("GET /api/users HTTP/1.1\r\nHost: x\r\n\r\n", 502, "api-v1"),
         Verdict::Match,
         jit::HandlerAction::Forward,
         0,
         "api-v1"},
        {"forward mismatch",
         make_entry("GET /api/users HTTP/1.1\r\nHost: x\r\n\r\n", 502, "wrong"),
         Verdict::Mismatch,
         jit::HandlerAction::Forward,
         0,
         "api-v1"},
        {"malformed capture",
         make_entry("GET /static HTTP/1.1\r\nHost: x\r\n", 204),
         Verdict::Failed,
         jit::HandlerAction::ReturnStatus,
         0,
         ""},
    };

    for (const auto& tc : cases) {
        const auto result = simulate_one(engine, tc.entry);
        CHECK_MSG(result.verdict == tc.verdict, tc.name);
        CHECK_MSG(result.action == tc.action, tc.name);
        CHECK_MSG(result.actual_status == tc.actual_status, tc.name);
        CHECK_MSG(strcmp(result.actual_upstream, tc.actual_upstream) == 0, tc.name);
    }

    engine.shutdown();
    ctx.destroy();
}

TEST(simulate_engine, simulate_file_route_action_matrix_summary) {
    Manifest manifest{};
    manifest.upstream_count = 1;
    manifest.upstreams[0].id = 7;
    strcpy(manifest.upstreams[0].name, "api-v1");
    manifest.route_count = 3;
    manifest.routes[0].method = kRouteMethodGet;
    strcpy(manifest.routes[0].pattern, "/static");
    manifest.routes[0].action = ManifestAction::ReturnStatus;
    manifest.routes[0].status_code = 204;
    manifest.routes[1].method = kRouteMethodPost;
    strcpy(manifest.routes[1].pattern, "/post-only");
    manifest.routes[1].action = ManifestAction::ReturnStatus;
    manifest.routes[1].status_code = 202;
    manifest.routes[2].method = kRouteMethodGet;
    strcpy(manifest.routes[2].pattern, "/api");
    manifest.routes[2].action = ManifestAction::Forward;
    manifest.routes[2].upstream_id = 7;

    ModuleContext ctx;
    Engine engine;
    REQUIRE(init_engine(manifest, ctx, engine));

    CaptureEntry entries[] = {
        make_entry("GET /static HTTP/1.1\r\nHost: x\r\n\r\n", 204),
        make_entry("GET /missing HTTP/1.1\r\nHost: x\r\n\r\n", 200),
        make_entry("GET /missing HTTP/1.1\r\nHost: x\r\n\r\n", 200, "api-v1"),
        make_entry("GET /post-only HTTP/1.1\r\nHost: x\r\n\r\n", 200),
        make_entry("POST /post-only HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n", 202),
        make_entry("GET /static HTTP/1.1\r\nHost: x\r\n\r\n", 201),
        make_entry("GET /api/users HTTP/1.1\r\nHost: x\r\n\r\n", 502, "api-v1"),
        make_entry("GET /api/users HTTP/1.1\r\nHost: x\r\n\r\n", 502, "wrong"),
        make_entry("GET /static HTTP/1.1\r\nHost: x\r\n", 204),
    };

    char path[] = "/tmp/rut_sim_matrix_capture_XXXXXX";
    i32 fd = mkstemp(path);
    REQUIRE(fd >= 0);
    REQUIRE(write_capture_file(fd, 9, entries, 9));
    close(fd);

    ReplayReader reader;
    REQUIRE(reader.open(path) == 0);
    const auto summary = simulate_file(engine, reader);
    CHECK_EQ(summary.total, 9u);
    CHECK_EQ(summary.matched, 5u);
    CHECK_EQ(summary.mismatched, 3u);
    CHECK_EQ(summary.failed, 1u);
    CHECK_EQ(summary.unsupported, 0u);

    reader.close();
    unlink(path);
    engine.shutdown();
    ctx.destroy();
}

TEST(simulate_engine, param_prefix_route_matches) {
    Manifest manifest{};
    manifest.route_count = 1;
    manifest.routes[0].method = kRouteMethodGet;
    strcpy(manifest.routes[0].pattern, "/users/:id");
    manifest.routes[0].action = ManifestAction::ReturnStatus;
    manifest.routes[0].status_code = 201;

    ModuleContext ctx;
    Engine engine;
    REQUIRE(init_engine(manifest, ctx, engine));

    const auto result =
        simulate_one(engine, make_entry("GET /users/123/profile HTTP/1.1\r\nHost: x\r\n\r\n", 201));
    CHECK_EQ(result.verdict, Verdict::Match);

    engine.shutdown();
    ctx.destroy();
}

TEST(simulate_engine, param_route_rejects_empty_segment) {
    Manifest manifest{};
    manifest.route_count = 1;
    manifest.routes[0].method = kRouteMethodGet;
    strcpy(manifest.routes[0].pattern, "/users/:id");
    manifest.routes[0].action = ManifestAction::ReturnStatus;
    manifest.routes[0].status_code = 201;

    ModuleContext ctx;
    Engine engine;
    REQUIRE(init_engine(manifest, ctx, engine));

    const auto result =
        simulate_one(engine, make_entry("GET /users/ HTTP/1.1\r\nHost: x\r\n\r\n", 200));
    CHECK_EQ(result.verdict, Verdict::Match);
    CHECK_EQ(result.actual_status, 200u);

    engine.shutdown();
    ctx.destroy();
}

TEST(simulate_engine, colon_inside_segment_matches_literal_colon) {
    Manifest manifest{};
    manifest.route_count = 1;
    manifest.routes[0].method = kRouteMethodGet;
    strcpy(manifest.routes[0].pattern, "/v1:beta");
    manifest.routes[0].action = ManifestAction::ReturnStatus;
    manifest.routes[0].status_code = 201;

    ModuleContext ctx;
    Engine engine;
    REQUIRE(init_engine(manifest, ctx, engine));

    const auto literal_match =
        simulate_one(engine, make_entry("GET /v1:beta HTTP/1.1\r\nHost: x\r\n\r\n", 201));
    CHECK_EQ(literal_match.verdict, Verdict::Match);
    CHECK_EQ(literal_match.actual_status, 201u);

    const auto literal_miss =
        simulate_one(engine, make_entry("GET /v1x HTTP/1.1\r\nHost: x\r\n\r\n", 200));
    CHECK_EQ(literal_miss.verdict, Verdict::Match);
    CHECK_EQ(literal_miss.actual_status, 200u);

    engine.shutdown();
    ctx.destroy();
}

TEST(simulate_engine, make_entry_clamps_long_headers) {
    char req[CaptureEntry::kMaxHeaderLen + 32];
    for (u32 i = 0; i + 1 < sizeof(req); i++) req[i] = 'a';
    req[sizeof(req) - 1] = '\0';

    const auto entry = make_entry(req, 204);
    CHECK_EQ(entry.raw_header_len, static_cast<u16>(CaptureEntry::kMaxHeaderLen));
}

TEST(simulate_engine, load_manifest_rejects_overflowing_u32) {
    char path[] = "/tmp/rut_sim_manifest_XXXXXX";
    i32 fd = mkstemp(path);
    REQUIRE(fd >= 0);

    static const char kManifest[] = "upstream 42949672960 api-v1\n";
    REQUIRE(write(fd, kManifest, sizeof(kManifest) - 1) ==
            static_cast<ssize_t>(sizeof(kManifest) - 1));
    close(fd);

    Manifest manifest;
    CHECK(!load_manifest(path, manifest));
    unlink(path);
}

TEST(simulate_engine, load_manifest_rejects_too_long_pattern) {
    char pattern[160];
    pattern[0] = '/';
    for (u32 i = 1; i + 1 < sizeof(pattern); i++) pattern[i] = 'a';
    pattern[sizeof(pattern) - 1] = '\0';

    char manifest_buf[256];
    const i32 manifest_len =
        snprintf(manifest_buf, sizeof(manifest_buf), "route GET %s status 204\n", pattern);
    REQUIRE(manifest_len > 0);

    char path[] = "/tmp/rut_sim_manifest_XXXXXX";
    i32 fd = mkstemp(path);
    REQUIRE(fd >= 0);
    REQUIRE(write(fd, manifest_buf, static_cast<size_t>(manifest_len)) == manifest_len);
    close(fd);

    Manifest manifest;
    CHECK(!load_manifest(path, manifest));
    unlink(path);
}

TEST(simulate_engine, load_manifest_rejects_too_long_upstream_name) {
    char name[64];
    for (u32 i = 0; i + 1 < sizeof(name); i++) name[i] = 'a';
    name[sizeof(name) - 1] = '\0';

    char manifest_buf[128];
    const i32 manifest_len = snprintf(manifest_buf, sizeof(manifest_buf), "upstream 7 %s\n", name);
    REQUIRE(manifest_len > 0);

    char path[] = "/tmp/rut_sim_manifest_XXXXXX";
    i32 fd = mkstemp(path);
    REQUIRE(fd >= 0);
    REQUIRE(write(fd, manifest_buf, static_cast<size_t>(manifest_len)) == manifest_len);
    close(fd);

    Manifest manifest;
    CHECK(!load_manifest(path, manifest));
    unlink(path);
}

TEST(simulate_engine, load_manifest_rejects_invalid_inputs) {
    struct Case {
        const char* text;
    };

    static const Case kCases[] = {
        {"upstream x api-v1\n"},
        {"upstream 65536 api-v1\n"},
        {"upstream 7 api-v1 extra\n"},
        {"route FETCH /x status 204\n"},
        {"route GET /x bounce 7\n"},
        {"route GET /x status 70000\n"},
        {"route GET /x proxy 65536\n"},
        {"route GET /x status 42949672960\n"},
        {"route GET /x proxy 42949672960\n"},
        {"route GET /x status\n"},
        {"route GET /x status 204 extra\n"},
        {"unknown thing here\n"},
        {"upstream 7 api-v1\nupstream 7 api-v2\n"},
        {"route GET /x proxy 7\n"},
    };

    for (const auto& tc : kCases) {
        Manifest manifest;
        CHECK(!load_manifest_text(tc.text, &manifest));
    }
}

TEST(simulate_engine, load_manifest_failure_clears_partial_state) {
    Manifest manifest{};
    manifest.route_count = 3;
    manifest.upstream_count = 2;
    manifest.routes[0].status_code = 503;
    strcpy(manifest.upstreams[0].name, "stale");

    CHECK(!load_manifest_text("upstream 7 api-v1\nroute GET /x proxy 9\n", &manifest));
    CHECK_EQ(manifest.route_count, 0u);
    CHECK_EQ(manifest.upstream_count, 0u);
    CHECK_EQ(manifest.routes[0].status_code, 200u);
    CHECK_EQ(manifest.routes[0].upstream_id, 0u);
    CHECK_EQ(manifest.upstreams[0].name[0], '\0');
}

TEST(simulate_engine, load_manifest_rejects_too_large_file) {
    char path[] = "/tmp/rut_sim_manifest_XXXXXX";
    i32 fd = mkstemp(path);
    REQUIRE(fd >= 0);
    const i32 rc = ftruncate(fd, static_cast<off_t>(1ULL << 32));
    if (rc != 0) {
        const i32 truncate_errno = errno;
        close(fd);
        unlink(path);
        if (truncate_errno == ENOSPC
#ifdef EDQUOT
            || truncate_errno == EDQUOT
#endif
#ifdef EFBIG
            || truncate_errno == EFBIG
#endif
        ) {
            return;
        }
        REQUIRE(rc == 0);
    }
    close(fd);

    Manifest manifest;
    CHECK(!load_manifest(path, manifest));
    unlink(path);
}

TEST(simulate_engine, module_context_destroy_resets_state) {
    ModuleContext ctx{};
    REQUIRE(ctx.init(2));
    CHECK(ctx.arena.current != nullptr);
    CHECK(ctx.module.arena == &ctx.arena);
    CHECK(ctx.module.functions != nullptr);
    CHECK(ctx.module.struct_defs != nullptr);

    ctx.destroy();
    CHECK_EQ(ctx.arena.current, nullptr);
    CHECK_EQ(ctx.module.arena, nullptr);
    CHECK_EQ(ctx.module.functions, nullptr);
    CHECK_EQ(ctx.module.struct_defs, nullptr);
    CHECK_EQ(ctx.module.func_count, 0u);
    CHECK_EQ(ctx.module.func_cap, 0u);
    CHECK_EQ(ctx.module.struct_count, 0u);
    CHECK_EQ(ctx.module.struct_cap, 0u);

    ctx.destroy();
    CHECK_EQ(ctx.arena.current, nullptr);
    CHECK_EQ(ctx.module.arena, nullptr);
}

TEST(simulate_engine, module_context_init_clears_stale_state_before_reuse) {
    ModuleContext ctx{};
    ctx.module.name = {"stale", 5};
    ctx.module.arena = reinterpret_cast<MmapArena*>(1);
    ctx.module.functions = reinterpret_cast<rir::Function*>(1);
    ctx.module.func_count = 99;
    ctx.module.func_cap = 99;
    ctx.module.struct_defs = reinterpret_cast<rir::StructDef**>(1);
    ctx.module.struct_count = 88;
    ctx.module.struct_cap = 88;

    REQUIRE(ctx.init(2, 3));
    CHECK_EQ(ctx.module.name.len, 17u);
    CHECK(ctx.module.arena == &ctx.arena);
    CHECK(ctx.module.functions != nullptr);
    CHECK_EQ(ctx.module.func_count, 0u);
    CHECK_EQ(ctx.module.func_cap, 2u);
    CHECK(ctx.module.struct_defs != nullptr);
    CHECK_EQ(ctx.module.struct_count, 0u);
    CHECK_EQ(ctx.module.struct_cap, 3u);

    ctx.destroy();
}

TEST(simulate_engine, build_module_rejects_invalid_route_count_without_init) {
    Manifest manifest{};
    manifest.route_count = Manifest::kMaxRoutes + 1;

    ModuleContext ctx{};
    CHECK(!build_module_from_manifest(manifest, ctx));
    CHECK_EQ(ctx.arena.current, nullptr);
    CHECK_EQ(ctx.module.arena, nullptr);
    CHECK_EQ(ctx.module.functions, nullptr);
}

TEST(simulate_engine, engine_init_accepts_codegen_truncated_handler_symbol_names) {
    Manifest manifest{};
    manifest.route_count = 1;
    manifest.routes[0].method = kRouteMethodGet;
    strcpy(manifest.routes[0].pattern, "/long-name");
    manifest.routes[0].action = ManifestAction::ReturnStatus;
    manifest.routes[0].status_code = 204;

    ModuleContext ctx{};
    REQUIRE(build_module_from_manifest(manifest, ctx));

    char long_name[248];
    for (u32 i = 0; i < 247; i++) long_name[i] = 'a';
    long_name[247] = '\0';
    ctx.module.functions[0].name = arena_copy(ctx.arena, long_name, 247);

    Engine engine;
    REQUIRE(engine.init(ctx.module, manifest.upstreams, manifest.upstream_count));

    const auto result =
        simulate_one(engine, make_entry("GET /long-name HTTP/1.1\r\nHost: x\r\n\r\n", 204));
    CHECK_EQ(result.verdict, Verdict::Match);

    engine.shutdown();
    ctx.destroy();
}

TEST(simulate_engine, engine_init_rejects_overlong_compiled_route_patterns) {
    Manifest manifest{};
    manifest.route_count = 1;
    manifest.routes[0].method = kRouteMethodGet;
    strcpy(manifest.routes[0].pattern, "/ok");
    manifest.routes[0].action = ManifestAction::ReturnStatus;
    manifest.routes[0].status_code = 200;

    ModuleContext ctx{};
    REQUIRE(build_module_from_manifest(manifest, ctx));

    char pattern[129];
    pattern[0] = '/';
    for (u32 i = 1; i < 128; i++) pattern[i] = 'p';
    pattern[128] = '\0';
    ctx.module.functions[0].route_pattern = arena_copy(ctx.arena, pattern, 128);

    Engine engine;
    engine.route_count = 7;
    engine.upstream_count = 5;
    CHECK(!engine.init(ctx.module, manifest.upstreams, manifest.upstream_count));
    CHECK_EQ(engine.route_count, 0u);
    CHECK_EQ(engine.upstream_count, 0u);

    ctx.destroy();
}

TEST(simulate_engine, engine_init_can_reinitialize_existing_engine) {
    Manifest manifest_a{};
    manifest_a.route_count = 1;
    manifest_a.routes[0].method = kRouteMethodGet;
    strcpy(manifest_a.routes[0].pattern, "/first");
    manifest_a.routes[0].action = ManifestAction::ReturnStatus;
    manifest_a.routes[0].status_code = 201;

    Manifest manifest_b{};
    manifest_b.route_count = 1;
    manifest_b.routes[0].method = kRouteMethodGet;
    strcpy(manifest_b.routes[0].pattern, "/second");
    manifest_b.routes[0].action = ManifestAction::ReturnStatus;
    manifest_b.routes[0].status_code = 202;

    ModuleContext ctx_a{};
    ModuleContext ctx_b{};
    REQUIRE(build_module_from_manifest(manifest_a, ctx_a));
    REQUIRE(build_module_from_manifest(manifest_b, ctx_b));

    Engine engine;
    REQUIRE(engine.init(ctx_a.module, manifest_a.upstreams, manifest_a.upstream_count));
    REQUIRE(engine.init(ctx_b.module, manifest_b.upstreams, manifest_b.upstream_count));

    const auto first_after_reinit =
        simulate_one(engine, make_entry("GET /first HTTP/1.1\r\nHost: x\r\n\r\n", 200));
    CHECK_EQ(first_after_reinit.verdict, Verdict::Match);
    CHECK_EQ(first_after_reinit.actual_status, 200u);

    const auto second_after_reinit =
        simulate_one(engine, make_entry("GET /second HTTP/1.1\r\nHost: x\r\n\r\n", 202));
    CHECK_EQ(second_after_reinit.verdict, Verdict::Match);
    CHECK_EQ(second_after_reinit.actual_status, 202u);

    engine.shutdown();
    ctx_b.destroy();
    ctx_a.destroy();
}

TEST(simulate_engine, engine_init_clears_state_on_precondition_failure) {
    Manifest manifest{};
    manifest.route_count = 1;
    manifest.routes[0].method = kRouteMethodGet;
    strcpy(manifest.routes[0].pattern, "/ok");
    manifest.routes[0].action = ManifestAction::ReturnStatus;
    manifest.routes[0].status_code = 200;

    ModuleContext ctx{};
    REQUIRE(build_module_from_manifest(manifest, ctx));

    Engine engine;
    REQUIRE(engine.init(ctx.module, manifest.upstreams, manifest.upstream_count));
    CHECK_EQ(engine.route_count, 1u);

    CHECK(!engine.init(ctx.module, manifest.upstreams, Engine::kMaxUpstreams + 1));
    CHECK_EQ(engine.route_count, 0u);
    CHECK_EQ(engine.upstream_count, 0u);

    ctx.destroy();
}

TEST(simulate_engine, param_route_matching_matrix) {
    struct Case {
        const char* req;
        u16 expected_status;
    };

    Manifest manifest{};
    manifest.route_count = 2;
    manifest.routes[0].method = kRouteMethodGet;
    strcpy(manifest.routes[0].pattern, "/users/:id");
    manifest.routes[0].action = ManifestAction::ReturnStatus;
    manifest.routes[0].status_code = 201;
    manifest.routes[1].method = kRouteMethodGet;
    strcpy(manifest.routes[1].pattern, "/teams/:team/members/:member");
    manifest.routes[1].action = ManifestAction::ReturnStatus;
    manifest.routes[1].status_code = 202;

    ModuleContext ctx;
    Engine engine;
    REQUIRE(init_engine(manifest, ctx, engine));

    static const Case kCases[] = {
        {"GET /users/123 HTTP/1.1\r\nHost: x\r\n\r\n", 201},
        {"GET /users/123?active=1 HTTP/1.1\r\nHost: x\r\n\r\n", 201},
        {"GET /users/ HTTP/1.1\r\nHost: x\r\n\r\n", 200},
        {"GET /users HTTP/1.1\r\nHost: x\r\n\r\n", 200},
        {"GET /teams/alpha/members/bravo HTTP/1.1\r\nHost: x\r\n\r\n", 202},
        {"GET /teams/alpha/members/ HTTP/1.1\r\nHost: x\r\n\r\n", 200},
    };

    for (const auto& tc : kCases) {
        const auto result = simulate_one(engine, make_entry(tc.req, tc.expected_status));
        CHECK_EQ(result.verdict, Verdict::Match);
        CHECK_EQ(result.actual_status, tc.expected_status);
    }

    engine.shutdown();
    ctx.destroy();
}

TEST(simulate_engine, simulate_one_rejects_malformed_capture_headers) {
    Manifest manifest{};
    manifest.route_count = 1;
    manifest.routes[0].method = kRouteMethodGet;
    strcpy(manifest.routes[0].pattern, "/ok");
    manifest.routes[0].action = ManifestAction::ReturnStatus;
    manifest.routes[0].status_code = 200;

    ModuleContext ctx;
    Engine engine;
    REQUIRE(init_engine(manifest, ctx, engine));

    struct Case {
        const char* raw;
        u16 len_override;
    };
    static const Case kCases[] = {
        {"", 0},
        {"garbage\r\n\r\n", 0},
        {"GET /ok HTTP/1.1\r\nHost: x\r\n", 0},
        {"GET /ok HTTP/1.1\r\nBad Header\r\n\r\n", 0},
        {"GET /ok HTTP/1.1\r\nHost: x\r\n\r\n", 8},
    };

    for (const auto& tc : kCases) {
        CaptureEntry entry = make_entry(tc.raw, 200);
        if (tc.len_override != 0) entry.raw_header_len = tc.len_override;
        const auto result = simulate_one(engine, entry);
        CHECK_EQ(result.verdict, Verdict::Failed);
        CHECK_EQ(result.actual_status, 0u);
    }

    engine.shutdown();
    ctx.destroy();
}

TEST(simulate_engine, summary_counts_mismatch) {
    Manifest manifest{};
    manifest.upstream_count = 1;
    manifest.upstreams[0].id = 9;
    strcpy(manifest.upstreams[0].name, "edge");
    manifest.route_count = 2;
    manifest.routes[0].method = kRouteMethodGet;
    strcpy(manifest.routes[0].pattern, "/ok");
    manifest.routes[0].action = ManifestAction::ReturnStatus;
    manifest.routes[0].status_code = 200;
    manifest.routes[1].method = kRouteMethodGet;
    strcpy(manifest.routes[1].pattern, "/api");
    manifest.routes[1].action = ManifestAction::Forward;
    manifest.routes[1].upstream_id = 9;

    ModuleContext ctx;
    Engine engine;
    REQUIRE(init_engine(manifest, ctx, engine));

    char path[] = "/tmp/rut_sim_capture_XXXXXX";
    i32 fd = mkstemp(path);
    REQUIRE(fd >= 0);
    CaptureFileHeader hdr;
    capture_file_header_init(&hdr);
    hdr.entry_count = 3;
    REQUIRE(write(fd, &hdr, sizeof(hdr)) == static_cast<ssize_t>(sizeof(hdr)));
    REQUIRE(capture_write_entry(fd, make_entry("GET /ok HTTP/1.1\r\nHost: x\r\n\r\n", 200)) == 0);
    REQUIRE(capture_write_entry(
                fd, make_entry("GET /api/x HTTP/1.1\r\nHost: x\r\n\r\n", 503, "edge")) == 0);
    REQUIRE(capture_write_entry(
                fd, make_entry("GET /api/y HTTP/1.1\r\nHost: x\r\n\r\n", 503, "wrong")) == 0);
    close(fd);

    ReplayReader reader;
    REQUIRE(reader.open(path) == 0);
    const auto summary = simulate_file(engine, reader);
    CHECK_EQ(summary.total, 3u);
    CHECK_EQ(summary.matched, 2u);
    CHECK_EQ(summary.mismatched, 1u);
    CHECK_EQ(summary.failed, 0u);

    reader.close();
    unlink(path);
    engine.shutdown();
    ctx.destroy();
}

TEST(simulate_engine, simulate_file_counts_malformed_entries_as_failed) {
    Manifest manifest{};
    manifest.route_count = 1;
    manifest.routes[0].method = kRouteMethodGet;
    strcpy(manifest.routes[0].pattern, "/ok");
    manifest.routes[0].action = ManifestAction::ReturnStatus;
    manifest.routes[0].status_code = 200;

    ModuleContext ctx;
    Engine engine;
    REQUIRE(init_engine(manifest, ctx, engine));

    CaptureEntry entries[] = {
        make_entry("GET /ok HTTP/1.1\r\nHost: x\r\n\r\n", 200),
        make_entry("GET /ok HTTP/1.1\r\nHost: x\r\n", 200),
        make_entry("BAD /ok HTTP/1.1\r\nHost: x\r\n\r\n", 200),
    };

    char path[] = "/tmp/rut_sim_bad_capture_XXXXXX";
    i32 fd = mkstemp(path);
    REQUIRE(fd >= 0);
    REQUIRE(write_capture_file(fd, 3, entries, 3));
    close(fd);

    ReplayReader reader;
    REQUIRE(reader.open(path) == 0);
    const auto summary = simulate_file(engine, reader);
    CHECK_EQ(summary.total, 3u);
    CHECK_EQ(summary.matched, 1u);
    CHECK_EQ(summary.failed, 2u);
    CHECK_EQ(summary.mismatched, 0u);
    CHECK_EQ(summary.unsupported, 0u);

    reader.close();
    unlink(path);
    engine.shutdown();
    ctx.destroy();
}

TEST(simulate_engine, simulate_file_counts_truncated_capture_as_failed) {
    struct Case {
        const char* name;
        u64 declared_count;
        u32 full_count;
        u32 partial_len;
        u32 expected_total;
        u32 expected_matched;
        u32 expected_failed;
    };

    Manifest manifest{};
    manifest.route_count = 1;
    manifest.routes[0].method = kRouteMethodGet;
    strcpy(manifest.routes[0].pattern, "/ok");
    manifest.routes[0].action = ManifestAction::ReturnStatus;
    manifest.routes[0].status_code = 200;

    ModuleContext ctx{};
    Engine engine;
    REQUIRE(init_engine(manifest, ctx, engine));

    const CaptureEntry entries[] = {
        make_entry("GET /ok HTTP/1.1\r\nHost: x\r\n\r\n", 200),
        make_entry("GET /ok HTTP/1.1\r\nHost: x\r\n\r\n", 200),
    };
    static const Case kCases[] = {
        {"header_only", 1, 0, 0, 1, 0, 1},
        {"missing_second_entry", 2, 1, 0, 2, 1, 1},
        {"partial_second_entry", 2, 1, sizeof(CaptureEntry) / 2, 2, 1, 1},
    };

    for (const auto& tc : kCases) {
        char path[] = "/tmp/rut_sim_capture_XXXXXX";
        i32 fd = mkstemp(path);
        REQUIRE(fd >= 0);
        REQUIRE(write_capture_file(fd,
                                   tc.declared_count,
                                   entries,
                                   tc.full_count,
                                   tc.partial_len ? &entries[1] : nullptr,
                                   tc.partial_len));
        close(fd);

        ReplayReader reader;
        REQUIRE(reader.open(path) == 0);
        const auto summary = simulate_file(engine, reader);
        CHECK_EQ(summary.total, tc.expected_total);
        CHECK_EQ(summary.matched, tc.expected_matched);
        CHECK_EQ(summary.failed, tc.expected_failed);
        CHECK_EQ(summary.mismatched, 0u);
        reader.close();
        unlink(path);
    }

    engine.shutdown();
    ctx.destroy();
}

TEST(simulate_engine, format_result_uses_mismatch_label) {
    SimulateResult result{};
    result.verdict = Verdict::Mismatch;
    result.method = static_cast<u8>(LogHttpMethod::Get);
    strcpy(result.path, "/api");
    result.action = jit::HandlerAction::ReturnStatus;
    result.expected_status = 200;
    result.actual_status = 503;

    char buf[256];
    const u32 len = format_result(result, buf, sizeof(buf));
    REQUIRE(len > 0);
    CHECK(strstr(buf, "MISMATCH") != nullptr);
    CHECK(strstr(buf, "MISS ") == nullptr);
}

TEST(simulate_engine, format_result_failed_status_uses_placeholder) {
    SimulateResult result{};
    result.verdict = Verdict::Failed;
    result.method = static_cast<u8>(LogHttpMethod::Get);
    strcpy(result.path, "/bad");
    result.action = jit::HandlerAction::ReturnStatus;
    result.expected_status = 502;

    char buf[256];
    const u32 len = format_result(result, buf, sizeof(buf));
    REQUIRE(len > 0);
    CHECK(strstr(buf, "502 -> -") != nullptr);
}

TEST(simulate_engine, format_result_yield_uses_placeholders) {
    SimulateResult result{};
    result.verdict = Verdict::Unsupported;
    result.method = static_cast<u8>(LogHttpMethod::Get);
    strcpy(result.path, "/yield");
    result.action = jit::HandlerAction::Yield;
    strcpy(result.expected_upstream, "edge");
    result.expected_status = 204;

    char buf[256];
    const u32 len = format_result(result, buf, sizeof(buf));
    REQUIRE(len > 0);
    CHECK(strstr(buf, "yield - -> -") != nullptr);
    CHECK(strstr(buf, "204 ->") == nullptr);
}

TEST(simulate_engine, read_all_fd_drains_bytes_beyond_output_buffer) {
    i32 pipefd[2];
    REQUIRE(pipe(pipefd) == 0);

    char payload[512];
    for (u32 i = 0; i < sizeof(payload); i++) payload[i] = 'a';
    REQUIRE(write(pipefd[1], payload, sizeof(payload)) == static_cast<ssize_t>(sizeof(payload)));
    close(pipefd[1]);

    char buf[32];
    u32 out_len = 0;
    REQUIRE(read_all_fd(pipefd[0], buf, sizeof(buf), &out_len));
    CHECK_EQ(out_len, static_cast<u32>(sizeof(buf) - 1));

    char tail[8];
    const ssize_t tail_n = read(pipefd[0], tail, sizeof(tail));
    CHECK_EQ(tail_n, 0);
    close(pipefd[0]);
}

TEST(simulate_engine, read_all_fd_accepts_zero_capacity_buffer) {
    i32 pipefd[2];
    REQUIRE(pipe(pipefd) == 0);
    REQUIRE(write(pipefd[1], "abc", 3) == 3);
    close(pipefd[1]);

    u32 out_len = 99;
    REQUIRE(read_all_fd(pipefd[0], nullptr, 0, &out_len));
    CHECK_EQ(out_len, 0u);
    close(pipefd[0]);
}

TEST(simulate_engine, read_all_fd_preserves_terminator_for_exact_fit) {
    i32 pipefd[2];
    REQUIRE(pipe(pipefd) == 0);
    REQUIRE(write(pipefd[1], "abcd", 4) == 4);
    close(pipefd[1]);

    char buf[5];
    u32 out_len = 0;
    REQUIRE(read_all_fd(pipefd[0], buf, sizeof(buf), &out_len));
    CHECK_EQ(out_len, 4u);
    CHECK_STREQ(buf, "abcd");
    close(pipefd[0]);
}

TEST(simulate_engine, read_pipes_interleaved_fails_on_poll_error_event) {
    i32 out_pipe[2];
    i32 err_pipe[2];
    REQUIRE(pipe(out_pipe) == 0);
    REQUIRE(pipe(err_pipe) == 0);

    close(out_pipe[0]);
    close(out_pipe[1]);

    char stdout_buf[16];
    char stderr_buf[16];
    u32 stdout_len = 0;
    u32 stderr_len = 0;
    CHECK(!read_pipes_interleaved(out_pipe[0],
                                  stdout_buf,
                                  sizeof(stdout_buf),
                                  &stdout_len,
                                  err_pipe[0],
                                  stderr_buf,
                                  sizeof(stderr_buf),
                                  &stderr_len));

    close(err_pipe[0]);
    close(err_pipe[1]);
}

TEST(simulate_engine, read_pipes_interleaved_collects_both_streams) {
    i32 out_pipe[2];
    i32 err_pipe[2];
    REQUIRE(pipe(out_pipe) == 0);
    REQUIRE(pipe(err_pipe) == 0);

    REQUIRE(write(out_pipe[1], "stdout-data", 11) == 11);
    REQUIRE(write(err_pipe[1], "stderr-data", 11) == 11);
    close(out_pipe[1]);
    close(err_pipe[1]);

    char stdout_buf[32];
    char stderr_buf[32];
    u32 stdout_len = 0;
    u32 stderr_len = 0;
    REQUIRE(read_pipes_interleaved(out_pipe[0],
                                   stdout_buf,
                                   sizeof(stdout_buf),
                                   &stdout_len,
                                   err_pipe[0],
                                   stderr_buf,
                                   sizeof(stderr_buf),
                                   &stderr_len));
    CHECK_EQ(stdout_len, 11u);
    CHECK_EQ(stderr_len, 11u);
    CHECK_STREQ(stdout_buf, "stdout-data");
    CHECK_STREQ(stderr_buf, "stderr-data");

    close(out_pipe[0]);
    close(err_pipe[0]);
}

TEST(simulate_engine, cli_usage_mentions_param_prefix_matching) {
    char stdout_buf[64];
    char stderr_buf[512];
    i32 exit_code = -1;

    REQUIRE(run_simulate_cli(nullptr,
                             nullptr,
                             &exit_code,
                             stdout_buf,
                             sizeof(stdout_buf),
                             stderr_buf,
                             sizeof(stderr_buf)));
    CHECK_EQ(exit_code, 2);
    CHECK_EQ(stdout_buf[0], '\0');
    CHECK(strstr(stderr_buf, "Usage: rut-simulate") != nullptr);
    CHECK(strstr(stderr_buf, "prefix-matched") != nullptr);
    CHECK(strstr(stderr_buf, "':param'") != nullptr);
}

TEST(simulate_engine, cli_fails_on_truncated_capture) {
    struct Case {
        const char* name;
        u64 declared_count;
        u32 full_count;
        u32 partial_len;
        const char* total_line;
        const char* failed_line;
    };

    char manifest_path[] = "/tmp/rut_sim_manifest_XXXXXX";
    i32 manifest_fd = mkstemp(manifest_path);
    REQUIRE(manifest_fd >= 0);
    static const char kManifest[] = "route GET /ok status 200\n";
    REQUIRE(write(manifest_fd, kManifest, sizeof(kManifest) - 1) ==
            static_cast<ssize_t>(sizeof(kManifest) - 1));
    close(manifest_fd);

    const CaptureEntry entries[] = {
        make_entry("GET /ok HTTP/1.1\r\nHost: x\r\n\r\n", 200),
        make_entry("GET /ok HTTP/1.1\r\nHost: x\r\n\r\n", 200),
    };
    static const Case kCases[] = {
        {"header_only", 1, 0, 0, "Total: 1", "Failed: 1"},
        {"partial_second_entry", 2, 1, sizeof(CaptureEntry) / 2, "Total: 2", "Failed: 1"},
    };

    for (const auto& tc : kCases) {
        char capture_path[] = "/tmp/rut_sim_capture_XXXXXX";
        i32 capture_fd = mkstemp(capture_path);
        REQUIRE(capture_fd >= 0);
        REQUIRE(write_capture_file(capture_fd,
                                   tc.declared_count,
                                   entries,
                                   tc.full_count,
                                   tc.partial_len ? &entries[1] : nullptr,
                                   tc.partial_len));
        close(capture_fd);

        char stdout_buf[512];
        char stderr_buf[512];
        i32 exit_code = -1;
        REQUIRE(run_simulate_cli(manifest_path,
                                 capture_path,
                                 &exit_code,
                                 stdout_buf,
                                 sizeof(stdout_buf),
                                 stderr_buf,
                                 sizeof(stderr_buf)));
        CHECK_EQ(exit_code, 1);
        CHECK(strstr(stderr_buf, "Capture file is truncated or unreadable") != nullptr);
        CHECK(strstr(stdout_buf, tc.total_line) != nullptr);
        CHECK(strstr(stdout_buf, tc.failed_line) != nullptr);

        unlink(capture_path);
    }

    unlink(manifest_path);
}

TEST(simulate_engine, format_summary_supports_u64_counters) {
    SimulateSummary summary{};
    summary.total = (1ULL << 32) + 7;
    summary.matched = 3;
    summary.mismatched = 2;
    summary.failed = (1ULL << 32) + 1;
    summary.unsupported = 4;

    char buf[256];
    const u32 len = format_summary(summary, buf, sizeof(buf));
    REQUIRE(len > 0);
    CHECK(strstr(buf, "Total: 4294967303") != nullptr);
    CHECK(strstr(buf, "Failed: 4294967297") != nullptr);
}

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
