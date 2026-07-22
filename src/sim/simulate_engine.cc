#include "rut/sim/simulate_engine.h"

#include "rut/common/types.h"
#include "rut/compiler/rir.h"
#include "rut/compiler/rir_builder.h"
#include "rut/harness/handler_execution.h"
#include "rut/jit/codegen.h"
#include "rut/jit/handler_abi.h"
#include "rut/jit/jit_engine.h"
#include "rut/runtime/access_log.h"
#include "rut/runtime/arena.h"
#include "rut/runtime/connection.h"
#include "rut/runtime/connection_base.h"
#include "rut/runtime/http_parser.h"
#include "rut/runtime/jit_dispatch.h"
#include "rut/runtime/route_method.h"
#include "rut/runtime/sim_engine.h"
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

static bool rir_function_needs_req_body(const rir::Function& fn) {
    if (fn.blocks == nullptr) return false;
    for (u32 bi = 0; bi < fn.block_count; bi++) {
        const auto& block = fn.blocks[bi];
        if (block.insts == nullptr) continue;
        for (u32 ii = 0; ii < block.inst_count; ii++) {
            if (block.insts[ii].op == rir::Opcode::ReqBody) return true;
        }
    }
    return false;
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

static bool route_matches(const Engine::CompiledRoute& route,
                          const char* path,
                          u32 path_len,
                          RouteParam* out_params = nullptr,
                          u32* out_param_count = nullptr,
                          u32 out_param_cap = 0,
                          u32* out_depth = nullptr,
                          u32* out_static_segments = nullptr,
                          u64* out_static_mask = nullptr) {
    u32 pi = 0;
    u32 ri = 0;
    u32 param_count = 0;
    u32 stored_param_count = 0;
    u32 depth = 0;
    u32 static_segments = 0;
    u64 static_mask = 0;
    while (ri < route.pattern_len) {
        const bool kParamSegment =
            route.pattern[ri] == ':' && (ri == 0 || route.pattern[ri - 1] == '/');
        if (kParamSegment) {
            depth++;
            const u32 name_start = ri + 1;
            ri = name_start;
            while (ri < route.pattern_len && route.pattern[ri] != '/') ri++;
            const u32 name_len = ri - name_start;
            const u32 param_start = pi;
            while (pi < path_len && path[pi] != '/' && path[pi] != '?' && path[pi] != '#') pi++;
            if (pi == param_start) return false;
            if (out_params && stored_param_count < out_param_cap) {
                out_params[stored_param_count++] = {
                    route.pattern + name_start, name_len, path + param_start, pi - param_start};
            }
            param_count++;
            continue;
        }
        if (pi >= path_len) return false;
        if (path[pi] == '?' || path[pi] == '#') return false;
        if (route.pattern[ri] != path[pi]) return false;
        if ((ri == 0 || route.pattern[ri - 1] == '/') && route.pattern[ri] != '/') {
            depth++;
            static_segments++;
            if (depth < 64) static_mask |= 1ull << (63 - depth);
        }
        ri++;
        pi++;
    }
    if (out_param_count) *out_param_count = out_params ? stored_param_count : param_count;
    if (out_depth) *out_depth = depth;
    if (out_static_segments) *out_static_segments = static_segments;
    if (out_static_mask) *out_static_mask = static_mask;
    return true;
}

static const Engine::CompiledRoute* select_route(const Engine& engine,
                                                 u8 method_key,
                                                 const char* path,
                                                 u32 path_len,
                                                 RouteParam* out_params = nullptr,
                                                 u32* out_param_count = nullptr,
                                                 u32 out_param_cap = 0) {
    const Engine::CompiledRoute* best = nullptr;
    u32 best_depth = 0;
    u32 best_static_segments = 0;
    u64 best_static_mask = 0;
    bool best_method_specific = false;
    RouteParam best_params[kMaxRouteParams]{};
    u32 best_param_count = 0;

    for (u32 i = 0; i < engine.route_count; i++) {
        const auto& route = engine.routes[i];
        if (route.method != 0 && route.method != method_key) continue;
        const bool method_specific = route.method != 0;
        RouteParam candidate_params[kMaxRouteParams]{};
        u32 param_count = 0;
        u32 depth = 0;
        u32 static_segments = 0;
        u64 static_mask = 0;
        if (route_matches(route,
                          path,
                          path_len,
                          candidate_params,
                          &param_count,
                          kMaxRouteParams,
                          &depth,
                          &static_segments,
                          &static_mask)) {
            if (best == nullptr || depth > best_depth ||
                (depth == best_depth && static_segments > best_static_segments) ||
                (depth == best_depth && static_segments == best_static_segments &&
                 static_mask > best_static_mask) ||
                (depth == best_depth && static_segments == best_static_segments &&
                 static_mask == best_static_mask && method_specific && !best_method_specific)) {
                best = &route;
                best_depth = depth;
                best_static_segments = static_segments;
                best_static_mask = static_mask;
                best_method_specific = method_specific;
                best_param_count = param_count < out_param_cap ? param_count : out_param_cap;
                for (u32 j = 0; j < best_param_count; j++) best_params[j] = candidate_params[j];
            }
        }
    }
    if (best) {
        if (out_params) {
            for (u32 i = 0; i < best_param_count; i++) out_params[i] = best_params[i];
        }
        if (out_param_count) *out_param_count = best_param_count;
        return best;
    }
    if (out_param_count) *out_param_count = 0;
    return nullptr;
}

static u32 visible_path_len(Str path) {
    u32 n = 0;
    while (n < path.len && path.ptr[n] != '?' && path.ptr[n] != '#') n++;
    return n;
}

static u8 non_match_verdict_rank(Verdict verdict) {
    switch (verdict) {
        case Verdict::Mismatch:
            return 0;
        case Verdict::Unsupported:
            return 1;
        case Verdict::Failed:
            return 2;
        case Verdict::Match:
            return 3;
    }
    return 2;
}

static SimulateResult prefer_non_match_result(const SimulateResult& lhs,
                                              const SimulateResult& rhs) {
    return non_match_verdict_rank(lhs.verdict) <= non_match_verdict_rank(rhs.verdict) ? lhs : rhs;
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

static SimulateResult finalize_handler_result(const Engine& engine,
                                              const CaptureEntry& entry,
                                              SimulateResult result,
                                              const jit::HandlerResult& unpacked,
                                              const jit::HandlerCtx& context) {
    if (unpacked.action == jit::HandlerAction::Yield) {
        result.verdict = Verdict::Failed;
        return result;
    }

    result.action = unpacked.action;
    if (unpacked.action == jit::HandlerAction::ReturnStatus) {
        result.actual_status =
            unpacked.upstream_id == jit::HandlerResult::kDynamicResponseBody &&
                    (context.response_body_valid == 0 || context.response_body_data == nullptr) &&
                    !response_status_forbids_body(unpacked.status_code)
                ? 500
                : unpacked.status_code;
        result.verdict =
            (result.actual_status == entry.resp_status && entry.upstream_name[0] == '\0')
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

static SimulateResult drive_handler_to_completion(const Engine& engine,
                                                  const Engine::CompiledRoute& route,
                                                  const CaptureEntry& entry,
                                                  Connection& conn,
                                                  harness::HandlerExecution execution,
                                                  harness::DeterministicEnvironment environment,
                                                  SimulateResult result,
                                                  u32 max_yields);

template <u32 N>
static void copy_char_array(char (&dst)[N], const char (&src)[N]) {
    for (u32 i = 0; i < N; i++) dst[i] = src[i];
}

static Str copy_req_path_canon(const Connection& src, Connection& dst) {
    const char* src_begin = src.req_path;
    const char* src_end = src.req_path + Connection::kMaxReqPathLen;
    if (src.req_path_canon.ptr >= src_begin && src.req_path_canon.ptr < src_end) {
        const auto offset = static_cast<u32>(src.req_path_canon.ptr - src_begin);
        if (offset < Connection::kMaxReqPathLen) {
            return {dst.req_path + offset, src.req_path_canon.len};
        }
    }
    return src.req_path_canon;
}

static void copy_sim_connection_state(Connection& dst, const Connection& src) {
    dst.reset();

    dst.on_recv = src.on_recv;
    dst.on_send = src.on_send;
    dst.on_upstream_recv = src.on_upstream_recv;
    dst.on_upstream_send = src.on_upstream_send;
    dst.fd = src.fd;
    dst.id = src.id;
    dst.state = src.state;
    dst.shard_id = src.shard_id;
    dst.flags = src.flags;
    dst.timer_slot = src.timer_slot;
    dst.upstream_fd = src.upstream_fd;
    dst.upstream_idx = src.upstream_idx;
    dst.handler_state = src.handler_state;
    dst.pending_yield_kind = src.pending_yield_kind;
    dst.resume_event_kind = src.resume_event_kind;
    dst.resume_event_result = src.resume_event_result;
    dst.handler_ctx = nullptr;
    dst.pending_handler_fn = src.pending_handler_fn;
    dst.handler_gen = src.handler_gen;
    dst.request_config = src.request_config;
    dst.yield_timespec = src.yield_timespec;
    dst.yield_timer_gen = src.yield_timer_gen;
    dst.keep_alive = src.keep_alive;
    dst.tls_active = src.tls_active;
    dst.tls_handshake_complete = src.tls_handshake_complete;
    dst.tls = src.tls;
    dst.pipeline_depth = src.pipeline_depth;
    dst.pipeline_stash_len = src.pipeline_stash_len;
    dst.req_header_end = src.req_header_end;
    dst.req_content_length = src.req_content_length;
    dst.req_initial_send_len = src.req_initial_send_len;
    dst.req_malformed = src.req_malformed;
    dst.req_body_mode = src.req_body_mode;
    dst.req_body_remaining = src.req_body_remaining;
    dst.req_chunk_parser = src.req_chunk_parser;
    dst.resp_body_mode = src.resp_body_mode;
    dst.resp_body_remaining = src.resp_body_remaining;
    dst.resp_chunk_parser = src.resp_chunk_parser;
    dst.resp_body_sent = src.resp_body_sent;
    dst.upstream_send_len = src.upstream_send_len;
    dst.recv_armed = src.recv_armed;
    dst.send_armed = src.send_armed;
    dst.upstream_recv_armed = src.upstream_recv_armed;
    dst.upstream_send_armed = src.upstream_send_armed;
    dst.yield_armed = src.yield_armed;
    dst.yield_timeout_armed = src.yield_timeout_armed;
    dst.resp_status = src.resp_status;
    dst.req_method = src.req_method;
    dst.req_size = src.req_size;
    dst.peer_addr = src.peer_addr;
    dst.peer_port = src.peer_port;
    copy_char_array(dst.req_path, src.req_path);
    dst.req_path_canon = copy_req_path_canon(src, dst);
    dst.upstream_us = src.upstream_us;
    copy_char_array(dst.upstream_name, src.upstream_name);
    dst.upstream_start_us = src.upstream_start_us;
    dst.capture_buf = src.capture_buf;
    dst.capture_header_len = src.capture_header_len;
    dst.req_start_us = src.req_start_us;
    dst.pending_ops = src.pending_ops;
}

static SimulateResult simulate_resume_candidate(const Engine& engine,
                                                const Engine::CompiledRoute& route,
                                                const CaptureEntry& entry,
                                                Connection& conn,
                                                harness::HandlerExecution execution,
                                                harness::DeterministicEnvironment environment,
                                                const jit::HandlerResult& yielded,
                                                jit::YieldKind resume_kind,
                                                SimulateResult result,
                                                u32 max_yields) {
    execution.connection = &conn;
    harness::DeterministicCompletion completion{};
    const auto completion_status =
        resume_kind == jit::YieldKind::Timer
            ? environment.complete_timer(yielded.yield_payload_u32(), ~u64{0}, completion)
            : environment.complete_now(
                  resume_kind, rut::sim_synthetic_resume_result(resume_kind), completion);
    if (completion_status != harness::CompletionStatus::Ready) {
        result.verdict = Verdict::Failed;
        return result;
    }
    execution.apply_resume(yielded, completion.kind, completion.result);
    return drive_handler_to_completion(
        engine, route, entry, conn, execution, environment, result, max_yields);
}

static SimulateResult drive_handler_to_completion(const Engine& engine,
                                                  const Engine::CompiledRoute& route,
                                                  const CaptureEntry& entry,
                                                  Connection& conn,
                                                  harness::HandlerExecution execution,
                                                  harness::DeterministicEnvironment environment,
                                                  SimulateResult result,
                                                  u32 max_yields) {
    if (result.yield_count >= max_yields) {
        result.verdict = Verdict::Failed;
        return result;
    }

    jit::HandlerResult unpacked{};
    for (u32 iter = result.yield_count; iter < max_yields; iter++) {
        execution.connection = &conn;
        unpacked = execution.invoke();
        if (unpacked.action != jit::HandlerAction::Yield) break;
        result.yield_count++;

        if (unpacked.yield_kind == jit::YieldKind::Any && unpacked.yield_payload_u32() != 0u) {
            Connection recv_conn;
            copy_sim_connection_state(recv_conn, conn);
            const SimulateResult recv_result = simulate_resume_candidate(engine,
                                                                         route,
                                                                         entry,
                                                                         recv_conn,
                                                                         execution,
                                                                         environment,
                                                                         unpacked,
                                                                         jit::YieldKind::Recv,
                                                                         result,
                                                                         max_yields);
            if (recv_result.verdict == Verdict::Match) return recv_result;

            Connection timer_conn;
            copy_sim_connection_state(timer_conn, conn);
            const SimulateResult timer_result = simulate_resume_candidate(engine,
                                                                          route,
                                                                          entry,
                                                                          timer_conn,
                                                                          execution,
                                                                          environment,
                                                                          unpacked,
                                                                          jit::YieldKind::Timer,
                                                                          result,
                                                                          max_yields);
            if (timer_result.verdict == Verdict::Match) return timer_result;
            return prefer_non_match_result(recv_result, timer_result);
        }

        jit::YieldKind resume_kind = unpacked.yield_kind;
        if (resume_kind == jit::YieldKind::Any) resume_kind = jit::YieldKind::Recv;
        harness::DeterministicCompletion completion{};
        const auto completion_status =
            resume_kind == jit::YieldKind::Timer
                ? environment.complete_timer(unpacked.yield_payload_u32(), ~u64{0}, completion)
                : environment.complete_now(
                      resume_kind, rut::sim_synthetic_resume_result(resume_kind), completion);
        if (completion_status != harness::CompletionStatus::Ready) {
            result.verdict = Verdict::Failed;
            return result;
        }
        execution.apply_resume(unpacked, completion.kind, completion.result);
    }

    return finalize_handler_result(engine, entry, result, unpacked, execution.frame.context);
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
        route.needs_req_body = rir_function_needs_req_body(fn);
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

    RouteParam route_params[kMaxRouteParams]{};
    u32 route_param_count = 0;
    const auto* route = select_route(engine,
                                     http_route_method_key(req.method),
                                     req.path.ptr,
                                     kPathLen,
                                     route_params,
                                     &route_param_count,
                                     kMaxRouteParams);
    if (!route) {
        result.action = jit::HandlerAction::ReturnStatus;
        result.actual_status = 200;
        result.verdict = (entry.resp_status == 200 && entry.upstream_name[0] == '\0')
                             ? Verdict::Match
                             : Verdict::Mismatch;
        return result;
    }
    if (route->needs_req_body) {
        result.verdict = Verdict::Unsupported;
        return result;
    }

    Connection conn;
    conn.reset();
    harness::HandlerExecution execution{};
    execution.init(route->fn, &conn, entry.raw_headers, entry.raw_header_len);
    execution.frame.context.route_param_count = route_param_count;
    for (u32 i = 0; i < route_param_count; i++)
        execution.frame.context.route_params[i] = route_params[i];

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
    harness::DeterministicEnvironment environment{};
    return drive_handler_to_completion(
        engine, *route, entry, conn, execution, environment, result, kMaxHandlerYields);
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
