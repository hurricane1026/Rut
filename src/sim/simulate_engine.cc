#include "rut/sim/simulate_engine.h"

#include "rut/common/types.h"
#include "rut/compiler/rir.h"
#include "rut/compiler/rir_builder.h"
#include "rut/jit/codegen.h"
#include "rut/jit/handler_abi.h"
#include "rut/jit/jit_engine.h"
#include "rut/runtime/access_log.h"
#include "rut/runtime/arena.h"
#include "rut/runtime/connection.h"
#include "rut/runtime/connection_base.h"
#include "rut/runtime/http_parser.h"
#include "rut/runtime/route_method.h"
#include "rut/runtime/traffic_capture.h"
#include "rut/runtime/traffic_replay.h"

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

namespace rut::sim {

namespace {

static u32 cstr_len(const char* s) {
    u32 n = 0;
    while (s[n]) n++;
    return n;
}

static void copy_cstr(char* dst, u32 dst_size, const char* src) {
    if (dst_size == 0) return;
    u32 i = 0;
    while (i + 1 < dst_size && src[i]) {
        dst[i] = src[i];
        i++;
    }
    dst[i] = '\0';
}

static bool streq(const char* a, const char* b) {
    u32 i = 0;
    while (a[i] && b[i]) {
        if (a[i] != b[i]) return false;
        i++;
    }
    return a[i] == b[i];
}

static bool parse_u32_token(const char* s, u32 len, u32* out) {
    if (len == 0) return false;
    u32 v = 0;
    for (u32 i = 0; i < len; i++) {
        if (s[i] < '0' || s[i] > '9') return false;
        const u32 digit = static_cast<u32>(s[i] - '0');
        if (v > (static_cast<u32>(-1) - digit) / 10) return false;
        v = v * 10 + digit;
    }
    *out = v;
    return true;
}

static u8 parse_method_token(const char* s, u32 len, bool* ok) {
    *ok = true;
    if (len == 3 && s[0] == 'A' && s[1] == 'N' && s[2] == 'Y') return kRouteMethodAny;
    if (len == 3 && s[0] == 'G' && s[1] == 'E' && s[2] == 'T') return kRouteMethodGet;
    if (len == 4 && s[0] == 'P' && s[1] == 'O' && s[2] == 'S' && s[3] == 'T')
        return kRouteMethodPost;
    if (len == 3 && s[0] == 'P' && s[1] == 'U' && s[2] == 'T') return kRouteMethodPut;
    if (len == 6 && s[0] == 'D' && s[1] == 'E' && s[2] == 'L' && s[3] == 'E' && s[4] == 'T' &&
        s[5] == 'E')
        return kRouteMethodDelete;
    if (len == 5 && s[0] == 'P' && s[1] == 'A' && s[2] == 'T' && s[3] == 'C' && s[4] == 'H')
        return kRouteMethodPatch;
    if (len == 4 && s[0] == 'H' && s[1] == 'E' && s[2] == 'A' && s[3] == 'D')
        return kRouteMethodHead;
    if (len == 7 && s[0] == 'O' && s[1] == 'P' && s[2] == 'T' && s[3] == 'I' && s[4] == 'O' &&
        s[5] == 'N' && s[6] == 'S')
        return kRouteMethodOptions;
    if (len == 7 && s[0] == 'C' && s[1] == 'O' && s[2] == 'N' && s[3] == 'N' && s[4] == 'E' &&
        s[5] == 'C' && s[6] == 'T')
        return kRouteMethodConnect;
    if (len == 5 && s[0] == 'T' && s[1] == 'R' && s[2] == 'A' && s[3] == 'C' && s[4] == 'E')
        return kRouteMethodTrace;
    *ok = false;
    return 0;
}

static u8 http_route_method_key(HttpMethod method) {
    return route_method_key(method);
}

static u8 log_method(HttpMethod method) {
    switch (method) {
        case HttpMethod::GET:
            return static_cast<u8>(LogHttpMethod::Get);
        case HttpMethod::POST:
            return static_cast<u8>(LogHttpMethod::Post);
        case HttpMethod::PUT:
            return static_cast<u8>(LogHttpMethod::Put);
        case HttpMethod::DELETE:
            return static_cast<u8>(LogHttpMethod::Delete);
        case HttpMethod::PATCH:
            return static_cast<u8>(LogHttpMethod::Patch);
        case HttpMethod::HEAD:
            return static_cast<u8>(LogHttpMethod::Head);
        case HttpMethod::OPTIONS:
            return static_cast<u8>(LogHttpMethod::Options);
        case HttpMethod::CONNECT:
            return static_cast<u8>(LogHttpMethod::Connect);
        case HttpMethod::TRACE:
            return static_cast<u8>(LogHttpMethod::Trace);
        case HttpMethod::Unknown:
            return static_cast<u8>(LogHttpMethod::Other);
    }
    return static_cast<u8>(LogHttpMethod::Other);
}

static const ManifestUpstream* find_upstream(const Engine& engine, u16 id) {
    for (u32 i = 0; i < engine.upstream_count; i++) {
        if (engine.upstreams[i].id == id) return &engine.upstreams[i];
    }
    return nullptr;
}

static bool manifest_has_upstream_id(const Manifest& manifest, u16 id) {
    for (u32 i = 0; i < manifest.upstream_count; i++) {
        if (manifest.upstreams[i].id == id) return true;
    }
    return false;
}

static bool validate_manifest(const Manifest& manifest) {
    for (u32 i = 0; i < manifest.upstream_count; i++) {
        for (u32 j = i + 1; j < manifest.upstream_count; j++) {
            if (manifest.upstreams[i].id == manifest.upstreams[j].id) return false;
        }
    }
    for (u32 i = 0; i < manifest.route_count; i++) {
        const auto& route = manifest.routes[i];
        if (route.action == ManifestAction::Forward &&
            !manifest_has_upstream_id(manifest, route.upstream_id))
            return false;
    }
    return true;
}

static bool copy_str_into_arena(MmapArena& arena, const char* src, u32 len, Str* out) {
    char* mem = arena.alloc_array<char>(len + 1);
    if (!mem) return false;
    for (u32 i = 0; i < len; i++) mem[i] = src[i];
    mem[len] = '\0';
    out->ptr = mem;
    out->len = len;
    return true;
}

static bool route_matches(const Engine::CompiledRoute& route, const char* path, u32 path_len) {
    u32 pi = 0;
    u32 ri = 0;
    while (ri < route.pattern_len) {
        const bool kParamSegment =
            route.pattern[ri] == ':' && (ri == 0 || route.pattern[ri - 1] == '/');
        if (kParamSegment) {
            ri++;
            while (ri < route.pattern_len && route.pattern[ri] != '/') ri++;
            const u32 param_start = pi;
            while (pi < path_len && path[pi] != '/' && path[pi] != '?') pi++;
            if (pi == param_start) return false;
            continue;
        }
        if (pi >= path_len) return false;
        if (path[pi] == '?') return false;
        if (route.pattern[ri] != path[pi]) return false;
        ri++;
        pi++;
    }
    return true;
}

static const Engine::CompiledRoute* select_route(const Engine& engine,
                                                 u8 method_key,
                                                 const char* path,
                                                 u32 path_len) {
    for (u32 i = 0; i < engine.route_count; i++) {
        const auto& route = engine.routes[i];
        if (route.method != 0 && route.method != method_key) continue;
        if (route_matches(route, path, path_len)) return &route;
    }
    return nullptr;
}

static u32 visible_path_len(Str path) {
    u32 n = 0;
    while (n < path.len && path.ptr[n] != '?') n++;
    return n;
}

static const char* verdict_str(Verdict verdict) {
    switch (verdict) {
        case Verdict::Match:
            return "MATCH";
        case Verdict::Mismatch:
            return "MISMATCH";
        case Verdict::Failed:
            return "FAIL";
        case Verdict::Unsupported:
            return "UNSUPPORTED";
    }
    return "FAIL";
}

static const char* action_str(jit::HandlerAction action) {
    switch (action) {
        case jit::HandlerAction::ReturnStatus:
            return "status";
        case jit::HandlerAction::Forward:
            return "forward";
        case jit::HandlerAction::Yield:
            return "yield";
    }
    return "status";
}

static void put_str(char* buf, u32 buf_size, u32* pos, const char* s) {
    while (*s && *pos + 1 < buf_size) buf[(*pos)++] = *s++;
}

static void put_u32(char* buf, u32 buf_size, u32* pos, u32 value) {
    char tmp[11];
    u32 n = 0;
    if (value == 0) {
        tmp[n++] = '0';
    } else {
        while (value > 0) {
            tmp[n++] = static_cast<char>('0' + value % 10);
            value /= 10;
        }
    }
    while (n > 0 && *pos + 1 < buf_size) buf[(*pos)++] = tmp[--n];
}

static void put_u64(char* buf, u32 buf_size, u32* pos, u64 value) {
    char tmp[21];
    u32 n = 0;
    if (value == 0) {
        tmp[n++] = '0';
    } else {
        while (value > 0) {
            tmp[n++] = static_cast<char>('0' + value % 10);
            value /= 10;
        }
    }
    while (n > 0 && *pos + 1 < buf_size) buf[(*pos)++] = tmp[--n];
}

static void put_name(char* buf, u32 buf_size, u32* pos, const char* s) {
    for (u32 i = 0; s[i] && *pos + 1 < buf_size; i++) buf[(*pos)++] = s[i];
}

}  // namespace

bool ModuleContext::init(u32 func_cap, u32 struct_cap) {
    destroy();

    if (!arena.init(4096)) return false;

    rir::Module next{};
    next.name = {"simulate_manifest", 17};
    next.arena = &arena;
    next.func_cap = func_cap == 0 ? 1 : func_cap;
    next.functions = arena.alloc_array<rir::Function>(next.func_cap);
    if (!next.functions) {
        arena.destroy();
        module = {};
        return false;
    }
    next.struct_cap = struct_cap == 0 ? 1 : struct_cap;
    next.struct_defs = arena.alloc_array<rir::StructDef*>(next.struct_cap);
    if (!next.struct_defs) {
        arena.destroy();
        module = {};
        return false;
    }

    module = next;
    return true;
}

void ModuleContext::destroy() {
    arena.destroy();
    module = {};
}

bool load_manifest(const char* path, Manifest& out) {
    out = Manifest{};
    Manifest parsed{};

    const i32 kFd = ::open(path, O_RDONLY);
    if (kFd < 0) return false;

    struct stat st;
    if (fstat(kFd, &st) < 0) {
        ::close(kFd);
        return false;
    }
    if (st.st_size <= 0) {
        ::close(kFd);
        return true;
    }
    if (static_cast<u64>(st.st_size) > static_cast<u64>(static_cast<u32>(-1))) {
        ::close(kFd);
        return false;
    }

    void* map = mmap(nullptr, static_cast<u64>(st.st_size), PROT_READ, MAP_PRIVATE, kFd, 0);
    ::close(kFd);
    if (map == MAP_FAILED) return false;

    const char* data = static_cast<const char*>(map);
    const u32 kSize = static_cast<u32>(st.st_size);
    u32 pos = 0;

    while (pos < kSize) {
        while (pos < kSize && (data[pos] == ' ' || data[pos] == '\t' || data[pos] == '\r')) pos++;
        if (pos >= kSize) break;
        if (data[pos] == '\n') {
            pos++;
            continue;
        }
        if (data[pos] == '#') {
            while (pos < kSize && data[pos] != '\n') pos++;
            continue;
        }

        struct Token {
            const char* ptr = nullptr;
            u32 len = 0;
        };
        Token tokens[5]{};
        u32 tok_count = 0;
        while (pos < kSize && data[pos] != '\n') {
            while (pos < kSize && (data[pos] == ' ' || data[pos] == '\t' || data[pos] == '\r'))
                pos++;
            if (pos >= kSize || data[pos] == '\n' || data[pos] == '#') break;
            if (tok_count >= 5) {
                munmap(map, static_cast<u64>(st.st_size));
                return false;
            }
            tokens[tok_count].ptr = data + pos;
            while (pos < kSize && data[pos] != '\n' && data[pos] != ' ' && data[pos] != '\t' &&
                   data[pos] != '\r')
                pos++;
            tokens[tok_count].len = static_cast<u32>((data + pos) - tokens[tok_count].ptr);
            tok_count++;
        }
        while (pos < kSize && data[pos] != '\n') pos++;
        if (pos < kSize && data[pos] == '\n') pos++;
        if (tok_count == 0) continue;

        if (tokens[0].len == 8 && __builtin_memcmp(tokens[0].ptr, "upstream", 8) == 0) {
            if (tok_count != 3 || parsed.upstream_count >= Manifest::kMaxUpstreams) {
                munmap(map, static_cast<u64>(st.st_size));
                return false;
            }
            u32 id = 0;
            if (!parse_u32_token(tokens[1].ptr, tokens[1].len, &id) || id > 65535) {
                munmap(map, static_cast<u64>(st.st_size));
                return false;
            }
            auto& up = parsed.upstreams[parsed.upstream_count];
            if (tokens[2].len >= sizeof(up.name)) {
                munmap(map, static_cast<u64>(st.st_size));
                return false;
            }
            parsed.upstream_count++;
            up.id = static_cast<u16>(id);
            u32 copy_len = tokens[2].len;
            for (u32 i = 0; i < copy_len; i++) up.name[i] = tokens[2].ptr[i];
            up.name[copy_len] = '\0';
            continue;
        }

        if (tokens[0].len == 5 && __builtin_memcmp(tokens[0].ptr, "route", 5) == 0) {
            if (tok_count != 5 || parsed.route_count >= Manifest::kMaxRoutes) {
                munmap(map, static_cast<u64>(st.st_size));
                return false;
            }
            bool method_ok = false;
            const u8 kMethod = parse_method_token(tokens[1].ptr, tokens[1].len, &method_ok);
            if (!method_ok) {
                munmap(map, static_cast<u64>(st.st_size));
                return false;
            }
            auto& route = parsed.routes[parsed.route_count++];
            route.method = kMethod;
            if (tokens[2].len >= sizeof(route.pattern)) {
                munmap(map, static_cast<u64>(st.st_size));
                return false;
            }
            const u32 kPatternLen = tokens[2].len;
            for (u32 i = 0; i < kPatternLen; i++) route.pattern[i] = tokens[2].ptr[i];
            route.pattern[kPatternLen] = '\0';

            if (tokens[3].len == 6 && __builtin_memcmp(tokens[3].ptr, "status", 6) == 0) {
                u32 code = 0;
                if (!parse_u32_token(tokens[4].ptr, tokens[4].len, &code) || code > 65535) {
                    munmap(map, static_cast<u64>(st.st_size));
                    return false;
                }
                route.action = ManifestAction::ReturnStatus;
                route.status_code = static_cast<u16>(code);
            } else if ((tokens[3].len == 7 && __builtin_memcmp(tokens[3].ptr, "forward", 7) == 0) ||
                       (tokens[3].len == 5 && __builtin_memcmp(tokens[3].ptr, "proxy", 5) == 0)) {
                u32 id = 0;
                if (!parse_u32_token(tokens[4].ptr, tokens[4].len, &id) || id > 65535) {
                    munmap(map, static_cast<u64>(st.st_size));
                    return false;
                }
                route.action = ManifestAction::Forward;
                route.upstream_id = static_cast<u16>(id);
            } else {
                munmap(map, static_cast<u64>(st.st_size));
                return false;
            }
            continue;
        }

        munmap(map, static_cast<u64>(st.st_size));
        return false;
    }

    const bool kOk = validate_manifest(parsed);
    munmap(map, static_cast<u64>(st.st_size));
    if (kOk) out = parsed;
    return kOk;
}

bool build_module_from_manifest(const Manifest& manifest, ModuleContext& ctx) {
    if (manifest.route_count > Manifest::kMaxRoutes) return false;
    if (!ctx.init(manifest.route_count == 0 ? 1 : manifest.route_count)) return false;
    const auto kFail = [&ctx]() {
        ctx.destroy();
        return false;
    };

    rir::Builder b;
    b.init(&ctx.module);

    for (u32 i = 0; i < manifest.route_count; i++) {
        char name_buf[32];
        name_buf[0] = 'r';
        name_buf[1] = 'o';
        name_buf[2] = 'u';
        name_buf[3] = 't';
        name_buf[4] = 'e';
        name_buf[5] = '_';
        u32 pos = 6;
        u32 v = i;
        char tmp[10];
        u32 tn = 0;
        if (v == 0) {
            tmp[tn++] = '0';
        } else {
            while (v > 0) {
                tmp[tn++] = static_cast<char>('0' + v % 10);
                v /= 10;
            }
        }
        while (tn > 0 && pos + 1 < sizeof(name_buf)) name_buf[pos++] = tmp[--tn];
        name_buf[pos] = '\0';

        Str name;
        if (!copy_str_into_arena(ctx.arena, name_buf, cstr_len(name_buf), &name)) return kFail();
        Str pattern;
        if (!copy_str_into_arena(ctx.arena,
                                 manifest.routes[i].pattern,
                                 cstr_len(manifest.routes[i].pattern),
                                 &pattern))
            return kFail();

        auto fn = b.create_function(name, pattern, manifest.routes[i].method);
        if (!fn) return kFail();
        auto entry = b.create_block(fn.value(), {"entry", 5});
        if (!entry) return kFail();
        b.set_insert_point(fn.value(), entry.value());

        if (manifest.routes[i].action == ManifestAction::ReturnStatus) {
            if (!b.emit_ret_status(manifest.routes[i].status_code)) return kFail();
        } else {
            auto upstream = b.emit_const_i32(manifest.routes[i].upstream_id);
            if (!upstream) return kFail();
            if (!b.emit_ret_forward(upstream.value())) return kFail();
        }
    }

    return true;
}

bool Engine::init(const rir::Module& module,
                  const ManifestUpstream* upstream_list,
                  u32 upstreams_len) {
    shutdown();
    if (upstreams_len > kMaxUpstreams || module.func_count > kMaxRoutes) return false;

    auto fail = [this]() {
        shutdown();
        return false;
    };

    if (!jit.init()) return false;
    auto cg = jit::codegen(module);
    if (!cg.ok) return fail();
    if (!jit.compile(cg.mod, cg.ctx)) return fail();

    CompiledRoute next_routes[kMaxRoutes]{};
    ManifestUpstream next_upstreams[kMaxUpstreams]{};
    u32 next_route_count = 0;
    for (u32 i = 0; i < upstreams_len; i++) next_upstreams[i] = upstream_list[i];

    for (u32 i = 0; i < module.func_count; i++) {
        const auto& fn = module.functions[i];
        if (next_route_count >= kMaxRoutes) return fail();
        char symbol[256];
        jit::format_handler_symbol(fn.name, symbol, sizeof(symbol));

        void* addr = jit.lookup(symbol);
        if (!addr) return fail();

        if (fn.route_pattern.len >= sizeof(next_routes[0].pattern)) return fail();

        auto& route = next_routes[next_route_count++];
        route.method = route_method_key_from_legacy_char(fn.http_method);
        route.pattern_len = fn.route_pattern.len;
        for (u32 j = 0; j < route.pattern_len; j++) route.pattern[j] = fn.route_pattern.ptr[j];
        route.pattern[route.pattern_len] = '\0';
        route.fn = reinterpret_cast<jit::HandlerFn>(addr);
    }

    for (u32 i = 0; i < next_route_count; i++) routes[i] = next_routes[i];
    for (u32 i = 0; i < upstreams_len; i++) upstreams[i] = next_upstreams[i];
    route_count = next_route_count;
    upstream_count = upstreams_len;
    return true;
}

void Engine::shutdown() {
    jit.shutdown();
    route_count = 0;
    upstream_count = 0;
}

SimulateResult simulate_one(Engine& engine, const CaptureEntry& entry) {
    SimulateResult result{};
    result.expected_status = entry.resp_status;
    copy_cstr(result.expected_upstream, sizeof(result.expected_upstream), entry.upstream_name);

    HttpParser parser;
    ParsedRequest req;
    parser.reset();
    req.reset();
    if (parser.parse(entry.raw_headers, entry.raw_header_len, &req) != ParseStatus::Complete) {
        result.verdict = Verdict::Failed;
        return result;
    }

    result.method = log_method(req.method);
    const u32 kPathLen = visible_path_len(req.path);
    u32 copy_len = kPathLen;
    if (copy_len >= sizeof(result.path)) copy_len = sizeof(result.path) - 1;
    for (u32 i = 0; i < copy_len; i++) result.path[i] = req.path.ptr[i];
    result.path[copy_len] = '\0';

    const auto* route =
        select_route(engine, http_route_method_key(req.method), req.path.ptr, kPathLen);
    if (!route) {
        result.action = jit::HandlerAction::ReturnStatus;
        result.actual_status = 200;
        result.verdict = (entry.resp_status == 200 && entry.upstream_name[0] == '\0')
                             ? Verdict::Match
                             : Verdict::Mismatch;
        return result;
    }

    Connection conn;
    conn.reset();
    struct HandlerFrame {
        jit::HandlerCtx ctx{};
        u64 slots[ConnectionBase::kMaxJitHandlerSlots]{};
    } frame;
    jit::HandlerCtx& ctx = frame.ctx;
    ctx.state = 0;
    ctx.handler_idx = 0;
    ctx.slot_count = ConnectionBase::kMaxJitHandlerSlots;

    // Drive the handler's state machine to completion. Yields are the
    // handler's signal "I need I/O, resume me with state=next_state".
    // In simulate mode we skip the actual I/O (timers don't tick, no
    // sockets open) and just advance the state — the point of this
    // engine is to verify the routing/branching logic offline, not to
    // reproduce wall-clock latency.
    //
    // Cap iteration to catch infinite-yield bugs (handler claiming it
    // needs to yield but never setting a terminal state). kMaxHandlerYields
    // is deliberately small: real handlers yield at most a handful of times
    // per spec (submit + wait batches, not loops).
    static constexpr u32 kMaxHandlerYields = 32;
    jit::HandlerResult unpacked{};
    for (u32 iter = 0; iter < kMaxHandlerYields; iter++) {
        const u64 kPacked =
            route->fn(&conn, &ctx, entry.raw_headers, entry.raw_header_len, nullptr);
        unpacked = jit::HandlerResult::unpack(kPacked);
        if (unpacked.action != jit::HandlerAction::Yield) break;
        result.yield_count++;
        // Advance to the continuation segment. Simulate mode treats the
        // requested wait as immediately completed and sets the synthetic
        // wake-up event. For wait(any), choose a concrete event kind so
        // event predicates observe a deterministic branch in offline tests.
        jit::YieldKind resume_kind = unpacked.yield_kind;
        if (resume_kind == jit::YieldKind::Any) {
            // Use the timeout winner when a timer arm exists (Any with
            // non-zero payload), otherwise fall back to recv.
            resume_kind = (unpacked.yield_payload_u32() == 0u) ? jit::YieldKind::Recv
                                                                : jit::YieldKind::Timer;
        }
        ctx.resume_event_kind = static_cast<u32>(resume_kind);
        ctx.resume_event_result = (resume_kind == jit::YieldKind::Timer) ? 0 : 1;
        ctx.state = unpacked.next_state;
    }
    if (unpacked.action == jit::HandlerAction::Yield) {
        // Exceeded the cap — treat as failure rather than silently
        // returning a stale state.
        result.verdict = Verdict::Failed;
        return result;
    }
    result.action = unpacked.action;

    if (unpacked.action == jit::HandlerAction::ReturnStatus) {
        result.actual_status = unpacked.status_code;
        result.verdict =
            (unpacked.status_code == entry.resp_status && entry.upstream_name[0] == '\0')
                ? Verdict::Match
                : Verdict::Mismatch;
        return result;
    }

    if (unpacked.action == jit::HandlerAction::Forward) {
        const auto* upstream = find_upstream(engine, unpacked.upstream_id);
        if (!upstream) {
            result.verdict = Verdict::Failed;
            return result;
        }
        copy_cstr(result.actual_upstream, sizeof(result.actual_upstream), upstream->name);
        result.verdict = streq(result.actual_upstream, result.expected_upstream)
                             ? Verdict::Match
                             : Verdict::Mismatch;
        return result;
    }

    result.verdict = Verdict::Unsupported;
    return result;
}

SimulateSummary simulate_file(Engine& engine, ReplayReader& reader) {
    SimulateSummary summary{};
    CaptureEntry entry{};
    while (reader.next(entry) == 0) {
        summary.total++;
        const SimulateResult kSimResult = simulate_one(engine, entry);
        accumulate_summary(summary, kSimResult.verdict);
    }
    finalize_summary(summary, reader);
    return summary;
}

void accumulate_summary(SimulateSummary& summary, Verdict verdict) {
    switch (verdict) {
        case Verdict::Match:
            summary.matched++;
            break;
        case Verdict::Mismatch:
            summary.mismatched++;
            break;
        case Verdict::Failed:
            summary.failed++;
            break;
        case Verdict::Unsupported:
            summary.unsupported++;
            break;
    }
}

void finalize_summary(SimulateSummary& summary, const ReplayReader& reader) {
    const u64 kExpectedTotal = reader.entry_count();
    if (summary.total < kExpectedTotal) {
        const u64 kMissing = kExpectedTotal - summary.total;
        summary.failed += kMissing;
        summary.total += kMissing;
    }
}

u32 format_result(const SimulateResult& result, char* buf, u32 buf_size) {
    u32 pos = 0;
    put_str(buf, buf_size, &pos, verdict_str(result.verdict));
    put_str(buf, buf_size, &pos, " ");

    static const char* const kMethodNames[] = {
        "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "CONNECT", "TRACE", "OTHER"};
    const u8 kMethodIdx = result.method < 10 ? result.method : 9;
    put_str(buf, buf_size, &pos, kMethodNames[kMethodIdx]);
    put_str(buf, buf_size, &pos, " ");
    put_str(buf, buf_size, &pos, result.path[0] ? result.path : "/");
    put_str(buf, buf_size, &pos, " ");
    put_str(buf, buf_size, &pos, action_str(result.action));
    put_str(buf, buf_size, &pos, " ");

    if (result.action == jit::HandlerAction::Forward) {
        put_name(buf, buf_size, &pos, result.expected_upstream[0] ? result.expected_upstream : "-");
        put_str(buf, buf_size, &pos, " -> ");
        put_name(buf, buf_size, &pos, result.actual_upstream[0] ? result.actual_upstream : "-");
    } else if (result.action == jit::HandlerAction::Yield) {
        put_str(buf, buf_size, &pos, "- -> -");
    } else if (result.verdict == Verdict::Failed || result.verdict == Verdict::Unsupported) {
        put_u32(buf, buf_size, &pos, result.expected_status);
        put_str(buf, buf_size, &pos, " -> -");
    } else {
        put_u32(buf, buf_size, &pos, result.expected_status);
        put_str(buf, buf_size, &pos, " -> ");
        put_u32(buf, buf_size, &pos, result.actual_status);
    }

    if (pos + 1 < buf_size) buf[pos++] = '\n';
    if (pos < buf_size) buf[pos] = '\0';
    return pos;
}

u32 format_summary(const SimulateSummary& summary, char* buf, u32 buf_size) {
    u32 pos = 0;
    put_str(buf, buf_size, &pos, "--- Simulate Summary ---\n");
    put_str(buf, buf_size, &pos, "Total: ");
    put_u64(buf, buf_size, &pos, summary.total);
    put_str(buf, buf_size, &pos, "\nMatched: ");
    put_u64(buf, buf_size, &pos, summary.matched);
    put_str(buf, buf_size, &pos, "\nMismatched: ");
    put_u64(buf, buf_size, &pos, summary.mismatched);
    put_str(buf, buf_size, &pos, "\nFailed: ");
    put_u64(buf, buf_size, &pos, summary.failed);
    put_str(buf, buf_size, &pos, "\nUnsupported: ");
    put_u64(buf, buf_size, &pos, summary.unsupported);
    if (pos + 1 < buf_size) buf[pos++] = '\n';
    if (pos < buf_size) buf[pos] = '\0';
    return pos;
}

}  // namespace rut::sim
