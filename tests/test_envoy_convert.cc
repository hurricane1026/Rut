#include "fixtures/envoy_milestone_s.inc"
#include "fixtures/envoy_routes_a.inc"
#include "fixtures/envoy_routes_b.inc"
#include "fixtures/envoy_routes_c.inc"
#include "fixtures/envoy_routes_shadowed_siblings.inc"
#include "rut/compiler/lexer.h"
#include "rut/envoy/converter.h"
#include "rut/envoy/parser.h"
#include "test.h"
#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <utility>
#include <vector>

#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#if defined(__linux__)
#include <sys/ptrace.h>
#include <sys/syscall.h>
#endif
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

using namespace rut;

namespace {

// `RutSource` is 128 KiB (PR8's ordered route-list capacity, see
// include/rut/envoy/converter.h). Every `lower_to_rut` result a test keeps
// around (as opposed to consuming immediately in one expression) is kept out
// of the stack frame the same way this file already keeps a `JsonDocument`
// out of it (`static envoy::JsonDocument doc;`, used throughout): a small
// fixed pool of function-local static storage, round-robined across calls,
// rather than a heap allocation. No test holds more than 3 results live at
// once (`api_all_capabilities_matches_golden`) and every result already read
// is fully consumed via CHECK/REQUIRE before the call that would recycle its
// slot, so 4 slots leaves headroom without needing per-call-site storage.
constexpr u32 kLowerResultSlots = 4;

FrontendResult<envoy::RutSource>* lower_result_slot() {
    static FrontendResult<envoy::RutSource> slots[kLowerResultSlots];
    static u32 next = 0;
    FrontendResult<envoy::RutSource>* slot = &slots[next];
    next = (next + 1u) % kLowerResultSlots;
    return slot;
}

FrontendResult<envoy::RutSource>* lower_heap(const envoy::Bootstrap& model) {
    FrontendResult<envoy::RutSource>* slot = lower_result_slot();
    *slot = envoy::lower_to_rut(model);
    return slot;
}

FrontendResult<envoy::RutSource>* lower_heap(const envoy::Bootstrap& model,
                                             const envoy::RutCapabilities& caps) {
    FrontendResult<envoy::RutSource>* slot = lower_result_slot();
    *slot = envoy::lower_to_rut(model, caps);
    return slot;
}

const char* g_executable = nullptr;

// All three `RutCapabilities` flags set true (include/rut/envoy/converter.h),
// so golden/happy-path tests exercise the full lowering without tripping any
// BLOCKED_BY_RUT check.
envoy::RutCapabilities all_capabilities_true() {
    return envoy::RutCapabilities{
        .request_envoy_h1 = true, .response_envoy_h1 = true, .local_reply_envoy_h1 = true};
}

Str str(const std::string& s) {
    return Str{s.data(), static_cast<u32>(s.size())};
}

std::string to_string(Str s) {
    return std::string(s.ptr, s.len);
}

// ── Subprocess helpers (adapted from tests/test_nginx_convert.cc) ─────

struct RunResult {
    int status = -1;
    std::string out;
    std::string err;
};

bool write_file(const std::string& path, const std::string& contents) {
    const int fd = open(path.c_str(), O_CREAT | O_TRUNC | O_WRONLY, 0600);
    if (fd < 0) return false;
    size_t offset = 0u;
    while (offset < contents.size()) {
        const ssize_t count = write(fd, contents.data() + offset, contents.size() - offset);
        if (count > 0) {
            offset += static_cast<size_t>(count);
            continue;
        }
        if (count < 0 && errno == EINTR) continue;
        close(fd);
        return false;
    }
    return close(fd) == 0;
}

std::string read_fd(int fd) {
    std::string result;
    lseek(fd, 0, SEEK_SET);
    char buffer[4096];
    for (;;) {
        const ssize_t count = read(fd, buffer, sizeof(buffer));
        if (count > 0) {
            result.append(buffer, static_cast<size_t>(count));
            continue;
        }
        if (count < 0 && errno == EINTR) continue;
        break;
    }
    close(fd);
    return result;
}

bool wait_bounded(pid_t child, int* status) {
    timespec started{};
    clock_gettime(CLOCK_MONOTONIC, &started);
    for (;;) {
        const pid_t waited = waitpid(child, status, WNOHANG);
        if (waited == child) return true;
        if (waited < 0 && errno == EINTR) continue;
        if (waited < 0) return false;
        timespec now{};
        clock_gettime(CLOCK_MONOTONIC, &now);
        const time_t elapsed_seconds = now.tv_sec - started.tv_sec;
        const long elapsed_nanoseconds = now.tv_nsec - started.tv_nsec;
        if (elapsed_seconds > 5 || (elapsed_seconds == 5 && elapsed_nanoseconds >= 0)) {
            kill(child, SIGKILL);
            while (waitpid(child, status, 0) < 0 && errno == EINTR) {
            }
            return false;
        }
        usleep(1000);
    }
}

bool make_capture_files(int fds[2]) {
    char output_template[] = "/tmp/rut-envoy-convert-out-XXXXXX";
    char error_template[] = "/tmp/rut-envoy-convert-err-XXXXXX";
    fds[0] = mkstemp(output_template);
    fds[1] = mkstemp(error_template);
    if (fds[0] < 0 || fds[1] < 0) {
        unlink(output_template);
        unlink(error_template);
        if (fds[0] >= 0) close(fds[0]);
        if (fds[1] >= 0) close(fds[1]);
        return false;
    }
    unlink(output_template);
    unlink(error_template);
    return true;
}

// Runs `executable` with exactly `args` as argv[1..]; argv[0] is `executable`.
RunResult run_with_args(const char* executable, const std::vector<std::string>& args) {
    RunResult result;
    int capture[2]{};
    if (!make_capture_files(capture)) return result;

    // PR #692 round-4 review: build argv before fork(), not after. A caller
    // running this concurrently with another live thread (the TOCTOU stress
    // test's writer thread, since replaced by the deterministic ptrace-driven
    // `cli_input_rewrite_during_read_is_detected`) forks with that thread still holding
    // whatever locks it held at that instant — fork() duplicates only the
    // calling thread, so a lock an unduplicated thread held (e.g. inside
    // malloc's arena) stays held forever in the child. `std::vector<char*>`
    // construction and `push_back` growth both allocate, so doing that
    // inside the child between fork() and exec() risks exactly that
    // deadlock. Building argv in the parent keeps every allocation there;
    // the child performs only async-signal-safe calls (dup2/close/execv/
    // _exit).
    std::vector<char*> argv;
    argv.push_back(const_cast<char*>(executable));
    for (const auto& arg : args) argv.push_back(const_cast<char*>(arg.c_str()));
    argv.push_back(nullptr);

    const pid_t child = fork();
    if (child == 0) {
        if (dup2(capture[0], STDOUT_FILENO) < 0 || dup2(capture[1], STDERR_FILENO) < 0) _exit(126);
        close(capture[0]);
        close(capture[1]);
        execv(executable, argv.data());
        _exit(127);
    }
    if (child < 0) {
        close(capture[0]);
        close(capture[1]);
        return result;
    }
    wait_bounded(child, &result.status);
    result.out = read_fd(capture[0]);
    result.err = read_fd(capture[1]);
    return result;
}

RunResult run_converter(const char* executable, const std::string& input) {
    return run_with_args(executable, {"--format", "bootstrap-json", input});
}

// RAII temp directory: `mkdtemp`s a fresh `/tmp/rut-envoy-convert-XXXXXX` on
// construction and, on destruction, unlinks every entry directly inside it
// (this suite never creates subdirectories, so a flat scan is enough) before
// `rmdir`ing the directory itself. Every `TEST` below used to call a bare
// `make_temp_dir()` with no matching cleanup, leaking one directory (plus
// whatever JSON/fifo/etc. it wrote) per run — 1044 stale
// `/tmp/rut-envoy-convert-*` directories had accumulated from prior test
// runs before this fix. Non-copyable/movable: exactly one directory per
// instance, removed exactly once.
class TempDir {
public:
    TempDir() {
        char pattern[] = "/tmp/rut-envoy-convert-XXXXXX";
        char* result = mkdtemp(pattern);
        if (result != nullptr) path_ = result;
    }

    ~TempDir() { remove_all(); }

    TempDir(const TempDir&) = delete;
    TempDir& operator=(const TempDir&) = delete;
    TempDir(TempDir&&) = delete;
    TempDir& operator=(TempDir&&) = delete;

    [[nodiscard]] bool ok() const { return !path_.empty(); }
    [[nodiscard]] const std::string& path() const { return path_; }

private:
    void remove_all() {
        if (path_.empty()) return;
        DIR* dir = opendir(path_.c_str());
        if (dir != nullptr) {
            struct dirent* entry;
            while ((entry = readdir(dir)) != nullptr) {
                const std::string name = entry->d_name;
                if (name == "." || name == "..") continue;
                unlink((path_ + "/" + name).c_str());
            }
            closedir(dir);
        }
        rmdir(path_.c_str());
    }

    std::string path_;
};

std::string expected_location(const std::string& path, Span span) {
    char buf[512];
    snprintf(buf,
             sizeof(buf),
             "%s:%u:%u: ",
             path.c_str(),
             span.line == 0u ? 1u : span.line,
             span.col == 0u ? 1u : span.col);
    return buf;
}

// ── Milestone-S bootstrap JSON, assembled so each test can vary exactly one
// of the two increment-2 fields (docs/envoy-converter.md, "milestone-S"). ──

// Replace the first occurrence of `from` with `to`; the caller guarantees it
// is present (mirrors tests/test_envoy_parser.cc's `replace`).
bool replace_first(std::string* text, const std::string& from, const std::string& to) {
    const auto pos = text->find(from);
    if (pos == std::string::npos) return false;
    text->replace(pos, from.size(), to);
    return true;
}

// Replace every occurrence of `from` with `to` (same length in both callers
// below, so this never changes the string's length).
std::string replace_all(std::string text, const std::string& from, const std::string& to) {
    size_t pos = 0;
    while ((pos = text.find(from, pos)) != std::string::npos) {
        text.replace(pos, from.size(), to);
        pos += to.size();
    }
    return text;
}

std::string milestone_json(bool suppress_present,
                           bool suppress_value,
                           bool timeout_present,
                           const char* timeout_value,
                           const char* listener_address = "0.0.0.0") {
    // Same shape as the milestone bootstrap in docs/envoy-converter.md and
    // tests/test_envoy_parser.cc's `Bootstrap`, kept here as plain literals so
    // this test binary has no dependency on that file's anonymous namespace.
    std::string listeners = R"([{
"name": "ingress",
"address": {"socket_address": {"address": "0.0.0.0", "port_value": 8080}},
"filter_chains": [{"filters": [{
"name": "envoy.filters.network.http_connection_manager",
"typed_config": {
"@type": "type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager",
"stat_prefix": "ingress",
"codec_type": "HTTP1",
"generate_request_id": false,
"route_config": {"name": "local", "virtual_hosts": [{
"name": "all",
"domains": ["*"],
"routes": [{"match": {"prefix": "/"}, "route": {"cluster": "backend"}}]
}]},
"http_filters": [{"name": "envoy.filters.http.router",
"typed_config": {"@type": "type.googleapis.com/envoy.extensions.filters.http.router.v3.Router"}}]
}}]}]
}])";
    std::string clusters = R"([{
"name": "backend",
"type": "STATIC",
"connect_timeout": "5s",
"load_assignment": {"cluster_name": "backend", "endpoints": [{"lb_endpoints": [{
"endpoint": {"address": {"socket_address": {"address": "127.0.0.1", "port_value": 9000}}}
}]}]}
}])";

    if (std::string(listener_address) != "0.0.0.0") {
        replace_first(&listeners,
                      "\"address\": \"0.0.0.0\"",
                      std::string("\"address\": \"") + listener_address + "\"");
    }
    if (timeout_present) {
        replace_first(&listeners,
                      "\"route\": {\"cluster\": \"backend\"}",
                      std::string("\"route\": {\"cluster\": \"backend\", \"timeout\": \"") +
                          timeout_value + "\"}");
    }
    if (suppress_present) {
        replace_first(
            &listeners,
            "\"typed_config\": {\"@type\": "
            "\"type.googleapis.com/envoy.extensions.filters.http.router.v3.Router\"}",
            std::string("\"typed_config\": {\"@type\": "
                        "\"type.googleapis.com/envoy.extensions.filters.http.router.v3.Router\", "
                        "\"suppress_envoy_headers\": ") +
                (suppress_value ? "true" : "false") + "}");
    }

    std::string text = "{\n\"static_resources\": {\n";
    text += "\"listeners\": " + listeners + ",\n";
    text += "\"clusters\": " + clusters + "\n";
    text += "}\n}\n";
    return text;
}

std::string milestone_s_json(const char* listener_address = "0.0.0.0") {
    return milestone_json(
        /*suppress_present=*/true,
        /*suppress_value=*/true,
        /*timeout_present=*/true,
        /*timeout_value=*/"0s",
        listener_address);
}

// Variants of the milestone-S bootstrap exercising the increment-4 shapes
// that the converter must reject before the six capability checks
// (docs/envoy-converter.md, "Capability validation"): `direct_response`,
// `redirect`.

std::string direct_response_json(rut::test::TestCase* _tc) {
    std::string text = milestone_s_json();
    CHECK(replace_first(&text,
                        "\"route\": {\"cluster\": \"backend\", \"timeout\": \"0s\"}",
                        "\"direct_response\": {\"status\": 200}"));
    return text;
}

std::string redirect_json(rut::test::TestCase* _tc) {
    std::string text = milestone_s_json();
    CHECK(
        replace_first(&text,
                      "\"route\": {\"cluster\": \"backend\", \"timeout\": \"0s\"}",
                      "\"redirect\": {\"path_redirect\": \"/new\", \"response_code\": \"FOUND\"}"));
    return text;
}

// A local-only route table: the single route is `direct_response`, and
// `static_resources.clusters` is omitted entirely (docs/envoy-compatibility.md,
// "Allow local-only route tables to omit clusters"). Matches Envoy, which
// needs no upstream cluster when nothing forwards.
std::string direct_response_no_clusters_json(rut::test::TestCase* _tc) {
    std::string text = direct_response_json(_tc);
    const std::string clusters_literal = R"([{
"name": "backend",
"type": "STATIC",
"connect_timeout": "5s",
"load_assignment": {"cluster_name": "backend", "endpoints": [{"lb_endpoints": [{
"endpoint": {"address": {"socket_address": {"address": "127.0.0.1", "port_value": 9000}}}
}]}]}
}])";
    CHECK(replace_first(&text, ",\n\"clusters\": " + clusters_literal + "\n", "\n"));
    return text;
}

// ── PR 8: ordered route-list bootstraps ────────────────────────────────
//
// A general builder for the increment-4 shapes: an arbitrary ordered
// `routes` array and `clusters` array (both already JSON-encoded by the
// caller), dropped into the same milestone-S envelope (`suppress_envoy_headers:
// true`, `generate_request_id: false`) so every route can carry
// `"timeout": "0s"` and clear the six capability checks once
// `RutCapabilities` are all true.
std::string route_list_json(const std::string& routes_json, const std::string& clusters_json) {
    std::string text = "{\n\"static_resources\": {\n\"listeners\": [{\n";
    text += "\"name\": \"ingress\",\n";
    text +=
        "\"address\": {\"socket_address\": {\"address\": \"0.0.0.0\", \"port_value\": 8080}},\n";
    text += "\"filter_chains\": [{\"filters\": [{\n";
    text += "\"name\": \"envoy.filters.network.http_connection_manager\",\n";
    text += "\"typed_config\": {\n";
    text +=
        "\"@type\": "
        "\"type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3."
        "HttpConnectionManager\",\n";
    text += "\"stat_prefix\": \"ingress\",\n";
    text += "\"codec_type\": \"HTTP1\",\n";
    text += "\"generate_request_id\": false,\n";
    text += "\"route_config\": {\"name\": \"local\", \"virtual_hosts\": [{\n";
    text += "\"name\": \"all\",\n";
    text += "\"domains\": [\"*\"],\n";
    text += "\"routes\": " + routes_json + "\n";
    text += "}]},\n";
    text += "\"http_filters\": [{\"name\": \"envoy.filters.http.router\",\n";
    text +=
        "\"typed_config\": {\"@type\": "
        "\"type.googleapis.com/envoy.extensions.filters.http.router.v3.Router\", "
        "\"suppress_envoy_headers\": true}}]\n";
    text += "}}]}]\n";
    text += "}],\n";
    text += "\"clusters\": " + clusters_json + "\n";
    text += "}\n}\n";
    return text;
}

std::string prefix_route_json(const std::string& prefix, const std::string& cluster_name) {
    return "{\"match\": {\"prefix\": \"" + prefix + "\"}, \"route\": {\"cluster\": \"" +
           cluster_name + "\", \"timeout\": \"0s\"}}";
}

std::string path_route_json(const std::string& path, const std::string& cluster_name) {
    return "{\"match\": {\"path\": \"" + path + "\"}, \"route\": {\"cluster\": \"" + cluster_name +
           "\", \"timeout\": \"0s\"}}";
}

std::string cluster_json(const std::string& name, int port) {
    return "{\"name\": \"" + name +
           "\", \"type\": \"STATIC\", \"connect_timeout\": \"5s\", \"load_assignment\": "
           "{\"cluster_name\": \"" +
           name +
           "\", \"endpoints\": [{\"lb_endpoints\": [{\"endpoint\": {\"address\": "
           "{\"socket_address\": {\"address\": \"127.0.0.1\", \"port_value\": " +
           std::to_string(port) + "}}}}]}]}}";
}

std::string json_array(const std::vector<std::string>& items) {
    std::string out = "[";
    for (size_t i = 0; i < items.size(); i++) {
        if (i != 0u) out += ", ";
        out += items[i];
    }
    out += "]";
    return out;
}

// Goldens (a)-(c) and (f) from envoy-pr-plan.md, PR 8 "Tests" — see the
// algorithm doc comment in src/envoy/converter.cc for why each one lowers
// the way it does. Cluster ports and names match the fixtures under
// tests/fixtures/envoy_routes_<letter>.inc exactly (regenerated by hand-
// running rut::envoy::lower_to_rut on each of these bootstraps). (d) and (e)
// were originally golden (successful-lowering) scenarios too, but Codex
// review on this PR (#695) showed both require the node's-own-literal 404
// fallback that only `route exact` could emit, and `route exact`'s strict
// local-response admission cannot serve every method Envoy's real no-route
// 404 answers (TRACE/CONNECT close the connection instead) — see
// `blocked_on_node_own_literal_needs_all_method_fallback` and
// `blocked_on_shadowed_exact_needs_all_method_fallback` below, which now
// exercise those same two scenarios as BLOCKED_BY_RUT.

// (a) prefix "/api/" declared before the catch-all "/".
std::string routes_scenario_a_json() {
    return route_list_json(
        json_array({prefix_route_json("/api/", "api_backend"), prefix_route_json("/", "backend")}),
        json_array({cluster_json("backend", 9000), cluster_json("api_backend", 9001)}));
}

// (b) the catch-all "/" declared before prefix "/api/".
std::string routes_scenario_b_json() {
    return route_list_json(
        json_array({prefix_route_json("/", "backend"), prefix_route_json("/api/", "api_backend")}),
        json_array({cluster_json("backend", 9000), cluster_json("api_backend", 9001)}));
}

// (c) exact path "/healthz" declared before the catch-all "/".
std::string routes_scenario_c_json() {
    return route_list_json(
        json_array(
            {path_route_json("/healthz", "health_backend"), prefix_route_json("/", "backend")}),
        json_array({cluster_json("backend", 9000), cluster_json("health_backend", 9001)}));
}

// (d) prefix "/api/" only, no catch-all declared: node "/api" ends with only
// its own (now-unconditional) prefix arm and no earlier exact arm, so the
// literal path "/api" itself has no Envoy route — BLOCKED_BY_RUT (see the
// comment above; this used to be a golden).
std::string routes_scenario_d_json() {
    return route_list_json(json_array({prefix_route_json("/api/", "api_backend")}),
                           json_array({cluster_json("api_backend", 9001)}));
}

// (e) prefix "/api/" declared before an exact path under it, "/api/x"
// (permanently shadowed and omitted from the emitted RUT) — but node "/api"
// still ends with only its own prefix arm and no earlier exact arm for the
// literal "/api" itself, so this is BLOCKED_BY_RUT the same way (d) is (see
// the comment above; this used to be a golden).
std::string routes_scenario_e_json() {
    return route_list_json(
        json_array(
            {prefix_route_json("/api/", "api_backend"), path_route_json("/api/x", "dead_backend")}),
        json_array({cluster_json("api_backend", 9001), cluster_json("dead_backend", 9002)}));
}

// (f) exact path "/api" declared before prefix "/api/" naming the same
// literal: node "/api" ends with the own-prefix arm turned unconditional,
// but the EARLIER conditional exact arm for "/api" already resolves the
// literal path correctly, so this is NOT blocked (Codex P1 on this PR: the
// converter used to request the `route exact "/api"` 404 fallback here too,
// which would have shadowed this earlier arm and returned 404 for "/api"
// instead of forwarding through it).
std::string routes_scenario_f_json() {
    return route_list_json(
        json_array(
            {path_route_json("/api", "exact_backend"), prefix_route_json("/api/", "api_backend")}),
        json_array({cluster_json("exact_backend", 9001), cluster_json("api_backend", 9002)}));
}

// (g) exact path "/healthz" declared twice, identically, before the
// catch-all "/". Envoy's first-match semantics make the second occurrence
// unreachable (the first exact route already resolves "/healthz"), so
// `build_node_plan` must skip it (Codex round-8 review) instead of emitting
// a second, dead conditional arm plus a duplicated forwarding policy. Same
// clusters/targets as scenario (c), so the lowered output must be
// byte-identical to (c)'s golden.
std::string routes_scenario_g_json() {
    return route_list_json(
        json_array({path_route_json("/healthz", "health_backend"),
                    path_route_json("/healthz", "health_backend"),
                    prefix_route_json("/", "backend")}),
        json_array({cluster_json("backend", 9000), cluster_json("health_backend", 9001)}));
}

// ── Brute-force equivalence: Envoy first-match vs. the lowered structure ──
//
// A route-list model used only by the two independent simulations below (not
// by `rut::envoy::parse_bootstrap_json`): one entry per Envoy route, in
// declared order.
struct SimRoute {
    bool is_prefix;
    std::string text;  // prefix (as declared, may or may not end in "/") or exact path
    std::string cluster;
};

bool sim_is_under(const std::string& node, const std::string& p) {
    if (node == "/") return true;
    if (node == p) return true;
    if (p.size() <= node.size()) return false;
    return p.compare(0, node.size(), node) == 0 && p[node.size()] == '/';
}

bool sim_is_strict_ancestor(const std::string& m, const std::string& node) {
    return m != node && sim_is_under(m, node);
}

std::string sim_strip_trailing_slash(const std::string& prefix) {
    if (prefix == "/") return "/";
    return prefix.substr(0, prefix.size() - 1);
}

// Envoy's real semantics: first declared route (in list order) whose match
// applies. `prefix` is a plain byte-prefix test; `path` is exact equality.
std::string envoy_first_match(const std::vector<SimRoute>& routes, const std::string& path) {
    for (const SimRoute& route : routes) {
        if (route.is_prefix) {
            if (route.text == "/" || path.compare(0, route.text.size(), route.text) == 0)
                return route.cluster;
        } else if (route.text == path) {
            return route.cluster;
        }
    }
    return "<404>";
}

// The structure PR8 lowers to: exact routes win over the trie (RUT's
// exact_strict_local_response fast path runs before match_canonical, see the
// VERIFY note in src/envoy/converter.cc), then the longest matching declared
// node, then that node's own if/else arm chain. Written independently of
// src/envoy/converter.cc's build_node_plan so a bug in the converter is not
// also baked into the "expected" side of this test.
std::string sim_dispatch(const std::vector<SimRoute>& routes, const std::string& path) {
    std::vector<std::string> nodes = {"/"};
    for (const SimRoute& route : routes) {
        if (!route.is_prefix || route.text == "/") continue;
        const std::string node = sim_strip_trailing_slash(route.text);
        if (std::find(nodes.begin(), nodes.end(), node) == nodes.end()) nodes.push_back(node);
    }
    auto longest_node = [&](const std::string& p) {
        std::string best = "/";
        for (const std::string& n : nodes) {
            if (n.size() > best.size() && sim_is_under(n, p)) best = n;
        }
        return best;
    };
    const std::string node = longest_node(path);

    if (path == node && node != "/") {
        // route_exact(node): the first route (Envoy order) that is either an
        // exact match on `node` itself or a strict-ancestor prefix.
        for (const SimRoute& route : routes) {
            if (!route.is_prefix && route.text == node) return route.cluster;
            if (route.is_prefix) {
                const std::string m = sim_strip_trailing_slash(route.text);
                if (sim_is_strict_ancestor(m, node)) return route.cluster;
            }
        }
        return "<404>";
    }

    // The node's own body only ever sees `path != node` here (a non-root
    // node's own literal text is always diverted to the `route_exact` branch
    // above; root's own arm matches `path == "/"` too, so root never reaches
    // this comment's premise but is handled by the explicit `node == "/"`
    // check below). That makes an exact route naming `node` itself
    // irrelevant here (it can never match) and the node's own prefix arm
    // unconditional the first time it is reached (its real condition,
    // `pathOnly != node`, is trivially true) — no "have we seen the node's
    // own prefix yet" bookkeeping is needed in this branch.
    for (const SimRoute& route : routes) {
        if (!route.is_prefix) {
            if (route.text == node) continue;  // irrelevant: never matches here
            const std::string owner = longest_node(route.text);
            if (owner != node) continue;
            if (path == route.text) return route.cluster;
            continue;
        }
        const std::string m = sim_strip_trailing_slash(route.text);
        if (m == node) return route.cluster;  // node's own arm: unconditional here
        if (sim_is_strict_ancestor(m, node)) return route.cluster;
        // strict descendant or unrelated: irrelevant to this node
    }
    return "<404>";  // unreachable for a well-formed model (see converter.cc)
}

// ── Drive the actual emitted RUT text, not a second independent model ──
//
// `sim_dispatch` above models what the converter *should* produce,
// independently of `src/envoy/converter.cc`, so a probe/expectation bug
// there cannot also hide a converter bug. But comparing `envoy_first_match`
// against `sim_dispatch` alone never reads the real `lower_to_rut` output:
// a bug in `build_node_plan` (wrong arm order, wrong cluster, a dropped
// node) would not fail the brute-force tests below (Codex P1 on PR #695
// round 3). `rut_dispatch` closes that gap by parsing the fixed, documented
// shape `put_route_node` / `put_route_arms` emit (the algorithm doc comment
// above `build_node_plan` in src/envoy/converter.cc) out of the emitted RUT
// text itself, then re-running the SAME node-selection rule (`sim_is_under`,
// already used to check `rut_dispatch` isn't just `sim_dispatch` again) over
// that PARSED structure.
//
// Scope limit (Codex P1 on PR #695 round 4): `sim_is_under`'s node selection
// is this test's OWN segment-aware model, not the real RUT compiler's
// dispatch engine. It proves `build_node_plan`'s if/else arm logic is
// correct GIVEN a segment-aware node lookup -- including the `/apix` /
// `/api.` / `/api/` boundary probes below, which stay on the `"/"` node
// rather than falsely reaching `"/api"` -- but it cannot prove which engine
// (`RouteTrie` vs `ART`) the compiled module actually gets, because it never
// builds a real `RouteConfig` or calls `configure_route_dispatch`
// (`include/rut/runtime/compile_to_config.h`). That selection is a separate,
// confirmed divergence tracked in docs/envoy-compatibility.md ("Segment-
// boundary dispatch") and in the algorithm doc comment above
// `build_node_plan`, src/envoy/converter.cc -- out of this file's reach.

// One `\` or `"` byte unescaped (inverse of `Writer::put_escaped`,
// src/envoy/converter.cc); every prefix/path in the fixtures below is
// already escape-free, so this only guards against a fixture growing one.
std::string rut_unescape(const std::string& s) {
    std::string out;
    for (size_t i = 0; i < s.size(); i++) {
        if (s[i] == '\\' && i + 1u < s.size()) {
            i++;
        }
        out += s[i];
    }
    return out;
}

struct RutArm {
    bool is_exact = false;     // meaningless for the chain's last (terminal) arm
    std::string compare_text;  // meaningless for the chain's last (terminal) arm
    u32 cluster_index = 0;
};

struct RutNode {
    std::string text;
    std::vector<RutArm> arms;  // last entry is the chain's unconditional terminator
};

// Parses every ANY-method `route "N" { ... }` block out of `rut_text`
// (skipping the byte-identical `route HEAD "N" { ... }` variant: both share
// the same arm structure, see `put_route_node`). Relies only on the fixed
// textual shape `put_route_arms` emits: an ordered, alternating sequence of
// `req.pathOnly (==|!=) "text"` conditions and `forward(envoy_cluster_N`
// calls, with exactly one more call than conditions (the trailing call is
// the chain's terminator).
std::vector<RutNode> parse_rut_route_nodes(const std::string& rut_text) {
    std::vector<RutNode> nodes;
    size_t pos = 0;
    while (true) {
        pos = rut_text.find("\nroute \"", pos);
        if (pos == std::string::npos) break;
        const size_t text_start = pos + std::string("\nroute \"").size();
        const size_t text_end = rut_text.find("\" {\n", text_start);
        if (text_end == std::string::npos) break;
        RutNode node;
        node.text = rut_unescape(rut_text.substr(text_start, text_end - text_start));

        const size_t body_start = text_end + std::string("\" {\n").size();
        size_t i = body_start;
        int depth = 1;
        for (; i < rut_text.size() && depth > 0; i++) {
            if (rut_text[i] == '{')
                depth++;
            else if (rut_text[i] == '}')
                depth--;
        }
        const std::string body = rut_text.substr(body_start, i - 1u - body_start);

        std::vector<std::pair<bool, std::string>> conditions;
        size_t cpos = 0;
        while (true) {
            cpos = body.find("req.pathOnly ", cpos);
            if (cpos == std::string::npos) break;
            const size_t op_start = cpos + std::string("req.pathOnly ").size();
            const bool is_exact = body.compare(op_start, 2u, "==") == 0;
            const size_t q1 = body.find('"', op_start);
            const size_t q2 = body.find('"', q1 + 1u);
            conditions.emplace_back(is_exact, rut_unescape(body.substr(q1 + 1u, q2 - q1 - 1u)));
            cpos = q2 + 1u;
        }
        std::vector<u32> clusters;
        size_t fpos = 0;
        while (true) {
            fpos = body.find("forward(envoy_cluster_", fpos);
            if (fpos == std::string::npos) break;
            const size_t num_start = fpos + std::string("forward(envoy_cluster_").size();
            size_t num_end = num_start;
            while (num_end < body.size() && std::isdigit(static_cast<unsigned char>(body[num_end])))
                num_end++;
            clusters.push_back(
                static_cast<u32>(std::stoul(body.substr(num_start, num_end - num_start))));
            fpos = num_end;
        }
        for (size_t k = 0; k < conditions.size(); k++) {
            RutArm arm;
            arm.is_exact = conditions[k].first;
            arm.compare_text = conditions[k].second;
            arm.cluster_index = k < clusters.size() ? clusters[k] : 0u;
            node.arms.push_back(arm);
        }
        RutArm terminal;
        terminal.cluster_index = clusters.empty() ? 0u : clusters.back();
        node.arms.push_back(terminal);
        nodes.push_back(node);
        pos = i;
    }
    return nodes;
}

std::string rut_cluster_name(const std::vector<std::string>& cluster_names, u32 index) {
    return index < cluster_names.size() ? cluster_names[index] : "<bad-cluster-index>";
}

// Re-runs the SAME "longest declared node the probe falls under" selection
// (`sim_is_under`) over the PARSED real output, then walks that node's
// parsed arm chain exactly as `req.pathOnly ==`/`!=` comparisons would at
// runtime.
std::string rut_dispatch(const std::vector<RutNode>& nodes,
                         const std::vector<std::string>& cluster_names,
                         const std::string& probe) {
    std::string best = "/";
    for (const RutNode& n : nodes) {
        if (n.text.size() > best.size() && sim_is_under(n.text, probe)) best = n.text;
    }
    const RutNode* node = nullptr;
    for (const RutNode& n : nodes) {
        if (n.text == best) {
            node = &n;
            break;
        }
    }
    if (node == nullptr || node->arms.empty()) return "<404>";  // no emitted node applies
    for (size_t i = 0; i < node->arms.size(); i++) {
        const RutArm& arm = node->arms[i];
        if (i + 1u == node->arms.size()) return rut_cluster_name(cluster_names, arm.cluster_index);
        const bool matches =
            arm.is_exact ? (probe == arm.compare_text) : (probe != arm.compare_text);
        if (matches) return rut_cluster_name(cluster_names, arm.cluster_index);
    }
    return "<404>";  // unreachable: the last arm is always the terminator
}

}  // namespace

// ── CLI ─────────────────────────────────────────────────────────────

TEST(envoy_convert, cli_usage_errors) {
    const TempDir temp_dir;
    REQUIRE(temp_dir.ok());
    const std::string& directory = temp_dir.path();
    const std::string path = directory + "/input.json";
    REQUIRE(write_file(path, milestone_s_json()));

    const RunResult no_args = run_with_args(g_executable, {});
    REQUIRE(WIFEXITED(no_args.status));
    CHECK_EQ(WEXITSTATUS(no_args.status), 2);
    CHECK(no_args.out.empty());
    CHECK(no_args.err.find("usage: ") == 0u);

    const RunResult wrong_format = run_with_args(g_executable, {"--format", "yaml", path});
    REQUIRE(WIFEXITED(wrong_format.status));
    CHECK_EQ(WEXITSTATUS(wrong_format.status), 2);
    CHECK(wrong_format.out.empty());
    CHECK(wrong_format.err.find("usage: ") == 0u);

    const RunResult missing_input = run_with_args(g_executable, {"--format", "bootstrap-json"});
    REQUIRE(WIFEXITED(missing_input.status));
    CHECK_EQ(WEXITSTATUS(missing_input.status), 2);
    CHECK(missing_input.out.empty());
    CHECK(missing_input.err.find("usage: ") == 0u);
}

TEST(envoy_convert, cli_input_errors) {
    const TempDir temp_dir;
    REQUIRE(temp_dir.ok());
    const std::string& directory = temp_dir.path();

    const RunResult missing = run_converter(g_executable, directory + "/does-not-exist.json");
    REQUIRE(WIFEXITED(missing.status));
    CHECK_EQ(WEXITSTATUS(missing.status), 1);
    CHECK(missing.out.empty());

    const RunResult directory_input = run_converter(g_executable, directory);
    REQUIRE(WIFEXITED(directory_input.status));
    CHECK_EQ(WEXITSTATUS(directory_input.status), 1);
    CHECK(directory_input.out.empty());

    const std::string large_path = directory + "/large.json";
    std::string oversized(1024u * 1024u + 1u, ' ');
    REQUIRE(write_file(large_path, oversized));
    const RunResult large = run_converter(g_executable, large_path);
    REQUIRE(WIFEXITED(large.status));
    CHECK_EQ(WEXITSTATUS(large.status), 1);
    CHECK(large.out.empty());

    const std::string fifo_path = directory + "/input.fifo";
    REQUIRE_EQ(mkfifo(fifo_path.c_str(), 0600), 0);
    const RunResult fifo = run_converter(g_executable, fifo_path);
    REQUIRE(WIFEXITED(fifo.status));
    CHECK_EQ(WEXITSTATUS(fifo.status), 1);
    CHECK(fifo.out.empty());
}

// PR #692 round-3 review: `read_input` (src/envoy/main.cc) used to compare
// only `after.st_size` against the byte count it actually read, which cannot
// catch another process rewriting the file in place with different content of
// the *same* length while the read is in progress. Round 3 added the
// dev/inode/size/mtime/ctime comparison, round 8 the second full read with a
// byte-for-byte comparison.
//
// PR #692 CI (Sanitizer job, run 36197715715): this used to be a free-running
// stress test — a writer thread looped `pwrite(content_a)`/`pwrite(content_b)`
// while the converter ran 300 times, and every run had to report either
// "input changed" or the clean BLOCKED_BY_RUT diagnostic. One run in 300
// printed neither. Mechanism: an in-place `pwrite` is not atomic with respect
// to a concurrent `pread` on Linux — ext4 (the CI runner's /tmp) and tmpfs
// buffered reads take no inode lock, and the writer copies the new bytes into
// the page cache one page at a time, with `file_modified()` (the mtime/ctime
// bump) done *before* the first page is copied. A writer preempted between
// two page copies (routine under ASan slowdown on a loaded runner) therefore
// leaves the file itself holding a torn mixture — new first page, old later
// pages — with its final timestamps already in place, for as long as it stays
// off-CPU. A converter run that fits entirely inside that stall sees
// identical metadata before and after, and two byte-identical reads of the
// torn mixture: an honest snapshot of what the file contained, which the
// CLI then lowered on its merits ("route cluster does not name a declared
// cluster"). No reader-side check can tell that apart from a file that simply
// contains those bytes, so the old test's "only A or B" oracle was wrong,
// not the CLI.
//
// These tests instead drive the rewrite deterministically: the converter runs
// under `ptrace` and is paused at fixed syscall-entry points on its own input
// descriptor inside `read_input`, where the test rewrites the file (same
// size, in place) before letting the syscall proceed. Every case has exactly
// one correct outcome. The contract they pin (docs/envoy-converter.md,
// "Input format"): any change that lands between the `before` fstat and the
// end of the second read is reported as "input changed while it was being
// read"; a change after the second read cannot affect the result; a torn
// state the file itself holds across the whole read window is converted as
// that content (and here fails closed on validation).

// What the CLI prints for a clean, stable read of `contents` at `path`,
// derived from the library with the capabilities this binary ships
// (`lower_to_rut(model)` uses `kShippedRutCapabilities`), so the same test is
// correct on a branch where milestone-S is still BLOCKED_BY_RUT and on one
// where it converts. Mirrors `main()` in src/envoy/main.cc: a parse or
// lowering error is one located diagnostic on stderr with exit 1; success is
// the lowered RUT on stdout, then the connect_timeout warning and (when
// `needs_h2c_preface_warning`) `kH2cPrefaceWarningText` on stderr, exit 0.
struct CliOutcome {
    bool parsed = false;
    int exit_code = 1;
    std::string out;
    std::string err;
};

CliOutcome expected_cli_outcome(const std::string& path, const std::string& contents) {
    static envoy::JsonDocument doc;
    CliOutcome outcome;
    auto parsed = envoy::parse_bootstrap_json(str(contents), doc);
    if (!parsed) {
        outcome.err =
            expected_location(path, parsed.error().span) + to_string(parsed.error().detail) + "\n";
        return outcome;
    }
    outcome.parsed = true;
    auto lowered = envoy::lower_to_rut(parsed.value());
    if (!lowered) {
        outcome.err = expected_location(path, lowered.error().span) +
                      to_string(lowered.error().detail) + "\n";
        return outcome;
    }
    outcome.exit_code = 0;
    outcome.out = to_string(lowered.value().view());
    outcome.err = "warning: connect_timeout \"" +
                  to_string(parsed.value().clusters[0].connect_timeout.text) +
                  "\" has no Rut runtime equivalent (no per-upstream connect-establishment "
                  "timeout surface); the value is accepted but not enforced\n";
    if (envoy::needs_h2c_preface_warning(parsed.value()))
        outcome.err += envoy::kH2cPrefaceWarningText;
    return outcome;
}

// A macro, not a function: the CHECK/REQUIRE macros need the enclosing
// TEST's context.
#define CHECK_CLI_OUTCOME(result, expected)                           \
    do {                                                              \
        REQUIRE(WIFEXITED((result).status));                          \
        CHECK_EQ(WEXITSTATUS((result).status), (expected).exit_code); \
        CHECK_EQ((result).out, (expected).out);                       \
        CHECK_EQ((result).err, (expected).err);                       \
    } while (0)

struct RaceFixture {
    std::string content_a;
    std::string content_b;
    // What the file holds while a writer replacing content_a with content_b
    // is stalled after its first page: the route (first page) already names
    // "backend1", the cluster (after the 8 KiB pad) still "backend0".
    std::string torn;
};

RaceFixture make_race_fixture() {
    RaceFixture fixture;
    std::string base = milestone_s_json();
    // A pad between `listeners` and `clusters` (insignificant JSON
    // whitespace) puts the route's cluster reference and the two cluster
    // spellings on different pages, as in the CI failure.
    if (!replace_first(&base, ",\n\"clusters\"", ",\n" + std::string(8192, ' ') + "\"clusters\""))
        return fixture;
    fixture.content_a = replace_all(base, "backend", "backend0");
    fixture.content_b = replace_all(base, "backend", "backend1");
    fixture.torn = fixture.content_a;
    if (!replace_first(&fixture.torn, "backend0", "backend1")) fixture.torn.clear();
    return fixture;
}

// A torn file that stays torn for the whole read is read faithfully: the
// converter reports what those bytes mean, which for this mixture is the
// mismatched-cluster error from `parse_bootstrap_json` itself — raised before
// lowering, so it holds whatever capabilities the binary ships and is never
// the clean outcome (a BLOCKED_BY_RUT diagnostic or a successful lowering).
TEST(envoy_convert, cli_input_static_torn_content_is_converted_as_is) {
    const TempDir temp_dir;
    REQUIRE(temp_dir.ok());
    const std::string path = temp_dir.path() + "/torn.json";
    const RaceFixture fixture = make_race_fixture();
    REQUIRE_FALSE(fixture.torn.empty());
    REQUIRE_EQ(fixture.torn.size(), fixture.content_a.size());
    REQUIRE(write_file(path, fixture.torn));

    const CliOutcome expected = expected_cli_outcome(path, fixture.torn);
    REQUIRE_FALSE(expected.parsed);
    REQUIRE_EQ(expected.exit_code, 1);
    CHECK(expected.err.find("route cluster does not name a declared cluster") != std::string::npos);
    const RunResult result = run_converter(g_executable, path);
    CHECK_CLI_OUTCOME(result, expected);
}

#if defined(__linux__)

// Syscall-entry points inside `read_input` (src/envoy/main.cc) at which
// `run_converter_with_rewrites` pauses the converter, all on the converter's
// own input descriptor.
enum class ReadPoint : u8 {
    // Entry of the 1st offset-0 `pread`: after the `before` fstat, before
    // the first read.
    FirstReadStart,
    // Entry of the 2nd offset-0 `pread`: after the first read and the
    // `after` fstat, before the verification read.
    SecondReadStart,
    // Entry of `close(input)`: after both reads.
    InputClose,
};

struct Rewrite {
    ReadPoint at;
    const std::string* contents = nullptr;
    // PR #692 round-15 review: when set, `run_converter_with_rewrites`
    // renames `*rename_from` onto `path` at `at` instead of pwrite-ing
    // `*contents` in place. This drives the atomic-replace publishing model
    // (docs/envoy-converter.md, "Input format") the round-8 dual-read check
    // alone cannot observe, since a rename swaps the pathname's target
    // inode rather than the open descriptor's content. Mutually exclusive
    // with `contents`.
    const std::string* rename_from = nullptr;
};

struct TracedRun {
    RunResult run;
    size_t rewrites_done = 0u;
};

bool is_input_fd(pid_t pid, u64 fd, const struct stat& input) {
    char proc_path[64];
    snprintf(proc_path,
             sizeof(proc_path),
             "/proc/%d/fd/%llu",
             static_cast<int>(pid),
             static_cast<unsigned long long>(fd));
    struct stat info{};
    return stat(proc_path, &info) == 0 && info.st_dev == input.st_dev &&
           info.st_ino == input.st_ino;
}

bool pwrite_all(int fd, const std::string& contents) {
    size_t offset = 0u;
    while (offset < contents.size()) {
        const ssize_t count = pwrite(
            fd, contents.data() + offset, contents.size() - offset, static_cast<off_t>(offset));
        if (count > 0) {
            offset += static_cast<size_t>(count);
            continue;
        }
        if (count < 0 && errno == EINTR) continue;
        return false;
    }
    return true;
}

bool waitpid_retry(pid_t child, int* status) {
    for (;;) {
        if (waitpid(child, status, 0) == child) return true;
        if (errno != EINTR) return false;
    }
}

// Runs the converter on `path` under ptrace. When the converter reaches
// `rewrites[k].at` (in order), the test either rewrites `path` in place at
// offset 0 with `*rewrites[k].contents` (same length, no O_TRUNC) or, when
// `rewrites[k].rename_from` is set instead, renames that path onto `path`
// (PR #692 round-15 review), while the converter is stopped at that
// syscall's entry, then lets the syscall run. Detaches after the last
// rewrite or at the input's close, whichever comes first, so the converter
// always exits untraced (LeakSanitizer's exit-time scan must ptrace the
// process itself). `rewrites_done` reports how many rewrites ran.
TracedRun run_converter_with_rewrites(const char* executable,
                                      const std::string& path,
                                      const std::vector<Rewrite>& rewrites) {
    TracedRun traced;
    struct stat input{};
    if (stat(path.c_str(), &input) != 0) return traced;
    const int writer = open(path.c_str(), O_WRONLY | O_CLOEXEC);
    if (writer < 0) return traced;
    int capture[2]{};
    if (!make_capture_files(capture)) {
        close(writer);
        return traced;
    }
    const std::string format_flag = "--format";
    const std::string format = "bootstrap-json";
    std::vector<char*> argv{const_cast<char*>(executable),
                            const_cast<char*>(format_flag.c_str()),
                            const_cast<char*>(format.c_str()),
                            const_cast<char*>(path.c_str()),
                            nullptr};

    const pid_t child = fork();
    if (child == 0) {
        if (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) != 0) _exit(125);
        if (dup2(capture[0], STDOUT_FILENO) < 0 || dup2(capture[1], STDERR_FILENO) < 0) _exit(126);
        close(capture[0]);
        close(capture[1]);
        execv(executable, argv.data());
        _exit(127);
    }
    if (child < 0) {
        close(capture[0]);
        close(capture[1]);
        close(writer);
        return traced;
    }

    int status = 0;
    bool reaped = false;
    // First stop: the SIGTRAP a PTRACE_TRACEME child takes on execv.
    if (!waitpid_retry(child, &status)) {
        kill(child, SIGKILL);
    } else if (!WIFSTOPPED(status)) {
        reaped = true;
    } else if (ptrace(PTRACE_SETOPTIONS,
                      child,
                      nullptr,
                      reinterpret_cast<void*>(static_cast<intptr_t>(
                          PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXEC | PTRACE_O_EXITKILL))) != 0) {
        kill(child, SIGKILL);
    } else {
        u32 offset_zero_reads = 0u;
        int deliver = 0;
        for (;;) {
            if (ptrace(PTRACE_SYSCALL,
                       child,
                       nullptr,
                       reinterpret_cast<void*>(static_cast<intptr_t>(deliver))) != 0) {
                kill(child, SIGKILL);
                break;
            }
            deliver = 0;
            if (!waitpid_retry(child, &status)) {
                kill(child, SIGKILL);
                break;
            }
            if (WIFEXITED(status) || WIFSIGNALED(status)) {
                reaped = true;
                break;
            }
            if (!WIFSTOPPED(status)) continue;
            const int stop_signal = WSTOPSIG(status);
            if (stop_signal != (SIGTRAP | 0x80)) {
                // A ptrace event stop (e.g. a re-exec) carries no signal to
                // deliver; a genuine signal-delivery stop is passed through.
                if ((status >> 16) == 0) deliver = stop_signal;
                continue;
            }
            __ptrace_syscall_info info{};
            if (ptrace(
                    PTRACE_GET_SYSCALL_INFO, child, reinterpret_cast<void*>(sizeof(info)), &info) <=
                    0 ||
                info.op != PTRACE_SYSCALL_INFO_ENTRY)
                continue;
            bool reached = false;
            ReadPoint point = ReadPoint::InputClose;
            if (info.entry.nr == SYS_pread64 && info.entry.args[3] == 0u &&
                is_input_fd(child, info.entry.args[0], input)) {
                offset_zero_reads++;
                reached = offset_zero_reads <= 2u;
                point = offset_zero_reads == 1u ? ReadPoint::FirstReadStart
                                                : ReadPoint::SecondReadStart;
            } else if (info.entry.nr == SYS_close &&
                       is_input_fd(child, info.entry.args[0], input)) {
                reached = true;
                point = ReadPoint::InputClose;
            }
            if (!reached) continue;
            if (point == rewrites[traced.rewrites_done].at) {
                const Rewrite& rewrite = rewrites[traced.rewrites_done];
                const bool ok = rewrite.rename_from != nullptr
                                    ? rename(rewrite.rename_from->c_str(), path.c_str()) == 0
                                    : pwrite_all(writer, *rewrite.contents);
                if (!ok) {
                    kill(child, SIGKILL);
                    break;
                }
                traced.rewrites_done++;
            }
            // `read_input` closes the input on every path out of it, so the
            // close also ends tracing when an earlier check already failed
            // and the remaining points will never be reached.
            if (traced.rewrites_done == rewrites.size() || point == ReadPoint::InputClose) {
                if (ptrace(PTRACE_DETACH, child, nullptr, nullptr) != 0) kill(child, SIGKILL);
                break;
            }
        }
    }
    if (reaped)
        traced.run.status = status;
    else
        wait_bounded(child, &traced.run.status);
    traced.run.out = read_fd(capture[0]);
    traced.run.err = read_fd(capture[1]);
    close(writer);
    return traced;
}

// Each case is fully deterministic; the loop only guards against the harness
// itself depending on timing (e.g. whether a rewrite happened to land in the
// same filesystem timestamp tick as the previous one).
TEST(envoy_convert, cli_input_rewrite_during_read_is_detected) {
    const TempDir temp_dir;
    REQUIRE(temp_dir.ok());
    const std::string path = temp_dir.path() + "/racing.json";
    const RaceFixture fixture = make_race_fixture();
    REQUIRE_FALSE(fixture.torn.empty());
    REQUIRE_EQ(fixture.content_a.size(), fixture.content_b.size());
    REQUIRE_NE(fixture.content_a, fixture.content_b);

    // The clean outcome of a stable read of content_a: BLOCKED_BY_RUT while
    // `kShippedRutCapabilities` lacks a milestone capability, a successful
    // conversion once it has them all (see `expected_cli_outcome`).
    const CliOutcome clean_a = expected_cli_outcome(path, fixture.content_a);
    REQUIRE(clean_a.parsed);
    REQUIRE(clean_a.exit_code == 0 || clean_a.err.find("BLOCKED_BY_RUT") != std::string::npos);
    CliOutcome changed;
    changed.err = path + ":1:1: input changed while it was being read\n";

    struct Case {
        const char* name;
        std::vector<Rewrite> rewrites;
        size_t min_rewrites;
        const CliOutcome* expected;
    };
    const Case cases[] = {
        // A writer mid-rewrite while read 1 runs (read 1 sees the torn
        // mixture), finishing before read 2: caught by the metadata check
        // when the timestamps ticked, else by the content comparison — the
        // second rewrite is then reached and makes read 2 differ. Same
        // outcome either way.
        {"torn first read, writer finishes before second read",
         {{ReadPoint::FirstReadStart, &fixture.torn},
          {ReadPoint::SecondReadStart, &fixture.content_a}},
         1u,
         &changed},
        // Same-size rewrite after the metadata check: only the round-8
        // byte comparison can catch it.
        {"rewrite between the two reads",
         {{ReadPoint::SecondReadStart, &fixture.content_b}},
         1u,
         &changed},
        {"torn state between the two reads",
         {{ReadPoint::SecondReadStart, &fixture.torn}},
         1u,
         &changed},
        // After both reads agreed the converter owns a stable snapshot of
        // content_a; a later rewrite cannot reach the result.
        {"rewrite after the second read",
         {{ReadPoint::InputClose, &fixture.content_b}},
         1u,
         &clean_a},
    };
    for (int iteration = 0; iteration < 5; iteration++) {
        for (const Case& c : cases) {
            REQUIRE(write_file(path, fixture.content_a));
            const TracedRun traced = run_converter_with_rewrites(g_executable, path, c.rewrites);
            if (traced.run.err != c.expected->err)
                fprintf(stderr,
                        "case '%s' (iteration %d, %zu rewrite(s) done): unexpected stderr: %s\n",
                        c.name,
                        iteration,
                        traced.rewrites_done,
                        traced.run.err.c_str());
            CHECK(traced.rewrites_done >= c.min_rewrites);
            CHECK_CLI_OUTCOME(traced.run, *c.expected);
        }
    }
}

// PR #692 round-15 review: rereading the same descriptor twice (the round-8
// checks exercised above) cannot observe a writer that publishes via
// `rename(tmp, filename)` — the atomic-replace model
// docs/envoy-converter.md's "Input format" already asks writers to use. The
// open descriptor keeps referring to the original, now-unlinked-but-open
// inode, so both `pread`s and both `fstat`s in `read_input` see it
// completely unchanged even though `filename` itself now names a different
// file. This drives that replacement deterministically at the last point
// `read_input` still holds the descriptor open (`ReadPoint::InputClose`, the
// entry to its own `close`) and confirms the converter reports the same
// "input changed while it was being read" diagnostic — and that an
// otherwise-identical run with no rename at all still converts cleanly, so
// the new pathname check doesn't false-positive on a file nobody touched.
TEST(envoy_convert, cli_input_rename_during_read_is_detected) {
    const TempDir temp_dir;
    REQUIRE(temp_dir.ok());
    const std::string path = temp_dir.path() + "/renaming.json";
    const std::string new_path = temp_dir.path() + "/renaming.json.new";
    const std::string content_a = milestone_s_json();
    // The replacement file's content is irrelevant to this check: by the
    // time the rename lands (at `InputClose`), `read_input` has already
    // finished both reads of the pre-rename content and only re-resolves
    // `filename`'s identity, never its bytes, afterward.
    const std::string content_b = "not read";

    const CliOutcome clean_a = expected_cli_outcome(path, content_a);
    REQUIRE(clean_a.parsed);
    REQUIRE(clean_a.exit_code == 0 || clean_a.err.find("BLOCKED_BY_RUT") != std::string::npos);
    CliOutcome changed;
    changed.err = path + ":1:1: input changed while it was being read\n";

    for (int iteration = 0; iteration < 5; iteration++) {
        // A publisher's atomic rename lands exactly while the converter is
        // stopped at its own `close(fd)` entry, after both reads have
        // already agreed on the pre-rename content.
        REQUIRE(write_file(path, content_a));
        REQUIRE(write_file(new_path, content_b));
        const std::vector<Rewrite> rename_at_close{
            {ReadPoint::InputClose, /*contents=*/nullptr, /*rename_from=*/&new_path}};
        const TracedRun traced = run_converter_with_rewrites(g_executable, path, rename_at_close);
        CHECK_EQ(traced.rewrites_done, 1u);
        CHECK_CLI_OUTCOME(traced.run, changed);

        // No rename at all: the same content, read the same (untraced) way,
        // must still convert cleanly.
        REQUIRE(write_file(path, content_a));
        const RunResult clean_run = run_converter(g_executable, path);
        CHECK_CLI_OUTCOME(clean_run, clean_a);
    }
}

#endif  // defined(__linux__)

TEST(envoy_convert, cli_parse_error_is_source_located) {
    const TempDir temp_dir;
    REQUIRE(temp_dir.ok());
    const std::string& directory = temp_dir.path();
    std::string text = milestone_s_json();
    const std::string marker = "\"static_resources\": {";
    const auto pos = text.find(marker);
    REQUIRE_NE(pos, std::string::npos);
    text.insert(pos, "\"admin\": {}, ");

    static envoy::JsonDocument doc;
    auto parsed = envoy::parse_bootstrap_json(str(text), doc);
    REQUIRE_FALSE(parsed);
    CHECK(parsed.error().code == FrontendError::UnsupportedSyntax);
    CHECK(to_string(parsed.error().detail).find("unsupported field") != std::string::npos);

    const std::string path = directory + "/malformed.json";
    REQUIRE(write_file(path, text));
    const RunResult result = run_converter(g_executable, path);
    REQUIRE(WIFEXITED(result.status));
    CHECK_EQ(WEXITSTATUS(result.status), 1);
    CHECK(result.out.empty());
    const std::string expected_prefix = expected_location(path, parsed.error().span);
    CHECK_EQ(result.err.compare(0, expected_prefix.size(), expected_prefix), 0);
    CHECK(result.err.find("unsupported field") != std::string::npos);
}

TEST(envoy_convert, cli_milestone_s_fails_closed_with_request_gap) {
    const TempDir temp_dir;
    REQUIRE(temp_dir.ok());
    const std::string& directory = temp_dir.path();
    const std::string text = milestone_s_json();
    const std::string path = directory + "/milestone.json";
    REQUIRE(write_file(path, text));

    static envoy::JsonDocument doc;
    auto parsed = envoy::parse_bootstrap_json(str(text), doc);
    REQUIRE(parsed);
    const Span span = parsed.value()
                          .listener.filter_chain.hcm.route_config.virtual_host.routes[0]
                          .action.cluster_span;

    const RunResult result = run_converter(g_executable, path);
    REQUIRE(WIFEXITED(result.status));
    CHECK_EQ(WEXITSTATUS(result.status), 1);
    CHECK(result.out.empty());
    const std::string expected_prefix = expected_location(path, span);
    CHECK_EQ(result.err.compare(0, expected_prefix.size(), expected_prefix), 0);
    CHECK(result.err.find("RUT request_policy lacks host: \"preserve\"") != std::string::npos);
}

// ── API-level capability gating ───────────────────────────────────────

TEST(envoy_convert, blocked_without_suppress_envoy_headers) {
    {
        const std::string text = milestone_json(
            /*suppress_present=*/false, false, /*timeout_present=*/true, "0s");
        static envoy::JsonDocument doc;
        auto parsed = envoy::parse_bootstrap_json(str(text), doc);
        REQUIRE(parsed);
        const envoy::RouterFilter& router = parsed.value().listener.filter_chain.hcm.router;
        auto lowered = lower_heap(parsed.value());
        REQUIRE_FALSE(*lowered);
        CHECK(lowered->error().code == FrontendError::UnsupportedSyntax);
        CHECK(to_string(lowered->error().detail).find("suppress_envoy_headers: true") !=
              std::string::npos);
        CHECK_EQ(lowered->error().span.line, router.span.line);
        CHECK_EQ(lowered->error().span.col, router.span.col);
    }
    {
        const std::string text = milestone_json(
            /*suppress_present=*/true, false, /*timeout_present=*/true, "0s");
        static envoy::JsonDocument doc;
        auto parsed = envoy::parse_bootstrap_json(str(text), doc);
        REQUIRE(parsed);
        const envoy::RouterFilter& router = parsed.value().listener.filter_chain.hcm.router;
        REQUIRE(router.suppress_envoy_headers_present);
        auto lowered = lower_heap(parsed.value());
        REQUIRE_FALSE(*lowered);
        CHECK(lowered->error().code == FrontendError::UnsupportedSyntax);
        CHECK(to_string(lowered->error().detail).find("suppress_envoy_headers: true") !=
              std::string::npos);
        CHECK_EQ(lowered->error().span.line, router.suppress_envoy_headers_span.line);
        CHECK_EQ(lowered->error().span.col, router.suppress_envoy_headers_span.col);
    }
}

TEST(envoy_convert, blocked_on_route_timeout) {
    {
        const std::string text = milestone_json(
            /*suppress_present=*/true, true, /*timeout_present=*/false, "");
        static envoy::JsonDocument doc;
        auto parsed = envoy::parse_bootstrap_json(str(text), doc);
        REQUIRE(parsed);
        const envoy::RouteAction& action =
            parsed.value().listener.filter_chain.hcm.route_config.virtual_host.routes[0].action;
        REQUIRE_FALSE(action.timeout_present);
        auto lowered = lower_heap(parsed.value());
        REQUIRE_FALSE(*lowered);
        CHECK(lowered->error().code == FrontendError::UnsupportedSyntax);
        CHECK(to_string(lowered->error().detail).find("default 15s route timeout") !=
              std::string::npos);
        CHECK_EQ(lowered->error().span.line, action.span.line);
        CHECK_EQ(lowered->error().span.col, action.span.col);
    }
    {
        const std::string text = milestone_json(
            /*suppress_present=*/true, true, /*timeout_present=*/true, "15s");
        static envoy::JsonDocument doc;
        auto parsed = envoy::parse_bootstrap_json(str(text), doc);
        REQUIRE(parsed);
        const envoy::RouteAction& action =
            parsed.value().listener.filter_chain.hcm.route_config.virtual_host.routes[0].action;
        REQUIRE(action.timeout_present);
        CHECK_EQ(action.timeout.milliseconds, 15000u);
        auto lowered = lower_heap(parsed.value());
        REQUIRE_FALSE(*lowered);
        CHECK(lowered->error().code == FrontendError::UnsupportedSyntax);
        CHECK(to_string(lowered->error().detail).find("non-zero route timeout") !=
              std::string::npos);
        CHECK_EQ(lowered->error().span.line, action.timeout.span.line);
        CHECK_EQ(lowered->error().span.col, action.timeout.span.col);
    }
}

TEST(envoy_convert, api_all_capabilities_matches_golden) {
    std::string text = milestone_s_json();
    static envoy::JsonDocument doc;
    auto parsed = envoy::parse_bootstrap_json(str(text), doc);
    REQUIRE(parsed);

    const envoy::RutCapabilities all_true = all_capabilities_true();
    auto lowered = lower_heap(parsed.value(), all_true);
    REQUIRE(*lowered);
    const Str golden = lit_str(kEnvoyMilestoneSGolden);
    REQUIRE_EQ((*lowered).value().len, golden.len);
    CHECK((*lowered).value().view().eq(golden));
    CHECK_EQ((*lowered).value().data[(*lowered).value().len], '\0');
    CHECK_LT((*lowered).value().len, envoy::RutSource::kCapacity);

    auto lowered_again = lower_heap(parsed.value(), all_true);
    REQUIRE(*lowered_again);
    CHECK((*lowered_again).value().view().eq(golden));

    // Overwriting the JSON source after lowering, for a `Bootstrap` copy
    // whose Str views still borrow that now-mutated buffer, must fail
    // closed rather than silently keep routing as root or silently accept a
    // forged router filter identity. Before Codex P2 on PR #695 round 4,
    // `validate()`'s one-byte-prefix check was length-only, so
    // `strip_trailing_slash` (src/envoy/converter.cc) treated ANY length-1
    // prefix as the literal "/" regardless of its actual byte -- this test
    // used to assert that mutating the buffer to all 'x' left the golden
    // output unchanged for exactly that reason. `validate()` now checks the
    // byte too (the same fix that rejects a hand-built one-byte prefix that
    // isn't "/", see `api_forged_model_rejected`'s
    // `one_byte_non_slash_prefix`), so the mutated prefix ("x", not "/") is
    // correctly rejected instead of silently matched as root: the old
    // "immune to post-parse mutation" behavior was the bug, not a feature
    // worth preserving. (The mutated router filter name -- also no longer
    // "envoy.filters.http.router" -- and the mutated network filter name --
    // also no longer "envoy.filters.network.http_connection_manager" --
    // would independently fail closed too, per PR #692 round-4's and
    // round-5's checks respectively; the prefix check simply fires first.)
    // PR8's multi-route lowering (the envoy_routes_<letter> goldens below)
    // already emits real borrowed path/prefix text and was never held to
    // the old invariant either.
    const envoy::Bootstrap model_copy = parsed.value();
    for (char& c : text) c = 'x';
    auto lowered_after_mutation = lower_heap(model_copy, all_true);
    REQUIRE_FALSE(*lowered_after_mutation);
    CHECK_EQ(lowered_after_mutation->error().code, FrontendError::UnexpectedToken);
}

// PR #692 round-7 review: the milestone bootstrap's HCM requires
// `codec_type: "HTTP1"`, so the h2c-preface divergence
// (docs/envoy-compatibility.md, "HTTP1-only HCM rejects a client that opens
// with the h2c connection preface") is not gated behind a `RutCapabilities`
// flag; `rut-envoy-convert` instead accepts and warns on stderr after a
// successful conversion (src/envoy/main.cc, `warn_h2c_preface`), same as the
// `connect_timeout` divergence. The real CLI binary can't reach that print
// today (`kShippedRutCapabilities` is still all-false, so every real
// conversion fails closed before reaching it — see
// cli_milestone_s_fails_closed_with_request_gap above), so this test asserts
// the library-level predicate and message the CLI calls, and confirms the
// milestone fixture keeps lowering to the unchanged golden RUT text once all
// three capabilities land.
TEST(envoy_convert, api_milestone_needs_h2c_preface_warning) {
    const std::string text = milestone_s_json();
    static envoy::JsonDocument doc;
    auto parsed = envoy::parse_bootstrap_json(str(text), doc);
    REQUIRE(parsed);
    CHECK(parsed.value().listener.filter_chain.hcm.codec_type == envoy::CodecType::Http1);
    CHECK(envoy::needs_h2c_preface_warning(parsed.value()));

    const envoy::RutCapabilities all_true = all_capabilities_true();
    auto lowered = envoy::lower_to_rut(parsed.value(), all_true);
    REQUIRE(lowered);
    const Str golden = lit_str(kEnvoyMilestoneSGolden);
    CHECK(lowered.value().view().eq(golden));

    const std::string warning_text(envoy::kH2cPrefaceWarningText);
    CHECK(warning_text.find("h2c connection preface") != std::string::npos);
    CHECK(warning_text.find("HTTP1") != std::string::npos);
    CHECK(warning_text.find("docs/envoy-compatibility.md") != std::string::npos);
}

TEST(envoy_convert, api_exact_listener_address) {
    const std::string text = milestone_s_json("127.0.0.1");
    static envoy::JsonDocument doc;
    auto parsed = envoy::parse_bootstrap_json(str(text), doc);
    REQUIRE(parsed);
    const envoy::RutCapabilities all_true = all_capabilities_true();
    auto lowered = lower_heap(parsed.value(), all_true);
    REQUIRE(*lowered);
    const std::string out = to_string((*lowered).value().view());
    CHECK_EQ(out.rfind("listen 127.0.0.1:8080\n", 0), 0u);
}

TEST(envoy_convert, api_forged_model_rejected) {
    const std::string text = milestone_s_json();
    static envoy::JsonDocument doc;
    auto parsed = envoy::parse_bootstrap_json(str(text), doc);
    REQUIRE(parsed);
    const envoy::RutCapabilities all_true = all_capabilities_true();

    envoy::Bootstrap listener_port_zero = parsed.value();
    listener_port_zero.listener.address.port = 0;
    CHECK_FALSE(envoy::lower_to_rut(listener_port_zero, all_true));

    envoy::Bootstrap endpoint_port_zero = parsed.value();
    endpoint_port_zero.clusters[0].endpoint.address.port = 0;
    CHECK_FALSE(envoy::lower_to_rut(endpoint_port_zero, all_true));

    envoy::Bootstrap mismatched_cluster = parsed.value();
    mismatched_cluster.listener.filter_chain.hcm.route_config.virtual_host.routes[0]
        .action.cluster = lit_str("other");
    CHECK_FALSE(envoy::lower_to_rut(mismatched_cluster, all_true));

    // PR #692 round-4 review: a hand-mutated router filter identity must not
    // lower successfully either. `validate()` only inspected
    // `suppress_envoy_headers` on the router filter; a caller retargeting
    // `router.name` at some other filter (e.g. a Lua filter) or clearing
    // `has_typed_config` used to still lower, silently dropping whatever
    // behavior the model actually named.
    envoy::Bootstrap forged_router_name = parsed.value();
    forged_router_name.listener.filter_chain.hcm.router.name = lit_str("envoy.filters.http.lua");
    const auto forged_router_name_result = envoy::lower_to_rut(forged_router_name, all_true);
    CHECK_FALSE(forged_router_name_result);
    CHECK(forged_router_name_result.error().code == FrontendError::UnexpectedToken);
    CHECK(to_string(forged_router_name_result.error().detail).find("router filter name") !=
          std::string::npos);

    envoy::Bootstrap cleared_typed_config = parsed.value();
    cleared_typed_config.listener.filter_chain.hcm.router.has_typed_config = false;
    const auto cleared_typed_config_result = envoy::lower_to_rut(cleared_typed_config, all_true);
    CHECK_FALSE(cleared_typed_config_result);
    CHECK(cleared_typed_config_result.error().code == FrontendError::UnexpectedToken);
    CHECK(to_string(cleared_typed_config_result.error().detail).find("typed_config is required") !=
          std::string::npos);

    // PR #692 round-3 review's defensive `match.prefix == "/"` check (a
    // hand-mutated non-"/" prefix must not lower successfully) no longer
    // applies once PR8 lowers arbitrary declared prefixes by construction
    // (see the algorithm doc comment in src/envoy/converter.cc): a forged
    // "/admin" or length-1 non-"/" prefix now lowers to its own route node
    // like any other declared prefix instead of being rejected.

    // An empty prefix bypasses the parser's `prefix_shape_ok`, which never
    // admits one; unguarded, `strip_trailing_slash` would compute
    // `prefix.len - 1u` on a zero length and slice with a huge underflowed
    // length instead of failing closed.
    envoy::Bootstrap empty_prefix = parsed.value();
    empty_prefix.listener.filter_chain.hcm.route_config.virtual_host.routes[0].match.prefix = Str{};
    CHECK_FALSE(envoy::lower_to_rut(empty_prefix, all_true));

    // A prefix that neither is "/" nor starts and ends with '/' bypasses the
    // same parser invariant.
    envoy::Bootstrap malformed_prefix = parsed.value();
    malformed_prefix.listener.filter_chain.hcm.route_config.virtual_host.routes[0].match.prefix =
        lit_str("/api");
    CHECK_FALSE(envoy::lower_to_rut(malformed_prefix, all_true));

    // A prefix segment beginning with ':' would become a RUT route
    // parameter, not a literal match.
    envoy::Bootstrap param_prefix = parsed.value();
    param_prefix.listener.filter_chain.hcm.route_config.virtual_host.routes[0].match.prefix =
        lit_str("/:tenant/");
    CHECK_FALSE(envoy::lower_to_rut(param_prefix, all_true));

    // A prefix containing "//" collapses, in Rut's route trie, to the same
    // node text as its single-slash form -- bypasses the parser (which never
    // produces one), so a hand-built model must be rejected here instead.
    envoy::Bootstrap double_slash_prefix = parsed.value();
    double_slash_prefix.listener.filter_chain.hcm.route_config.virtual_host.routes[0].match.prefix =
        lit_str("/api//");
    CHECK_FALSE(envoy::lower_to_rut(double_slash_prefix, all_true));

    // A hand-built exact path carrying a control byte (e.g. a newline)
    // bypasses the parser's `validate_route_match_bytes`; `put_escaped`
    // only escapes `\` and `"`, so an unvalidated newline would otherwise be
    // copied into the generated RUT literal verbatim.
    envoy::Bootstrap control_byte_path = parsed.value();
    control_byte_path.listener.filter_chain.hcm.route_config.virtual_host.routes[0].match.kind =
        envoy::RouteMatchKind::Path;
    control_byte_path.listener.filter_chain.hcm.route_config.virtual_host.routes[0].match.path =
        Str{"/ok\n", 4u};
    CHECK_FALSE(envoy::lower_to_rut(control_byte_path, all_true));

    // A hand-built exact path over 64 bytes bypasses the parser's length
    // bound the same way.
    static const std::string oversized = "/" + std::string(64u, 'a');
    envoy::Bootstrap oversized_path = parsed.value();
    oversized_path.listener.filter_chain.hcm.route_config.virtual_host.routes[0].match.kind =
        envoy::RouteMatchKind::Path;
    oversized_path.listener.filter_chain.hcm.route_config.virtual_host.routes[0].match.path =
        str(oversized);
    CHECK_FALSE(envoy::lower_to_rut(oversized_path, all_true));

    // A hand-built model can also drop every declared cluster while its
    // route still forwards; the empty-cluster allowance is only for
    // direct_response/redirect routes.
    envoy::Bootstrap no_clusters_forward = parsed.value();
    no_clusters_forward.clusters.len = 0;
    CHECK_FALSE(envoy::lower_to_rut(no_clusters_forward, all_true));

    // PR #692 round-5 review: the same forgery is possible one level up, on
    // the network filter that wraps the HTTP connection manager.
    // `filter_chain.filter_name` retargeted at another network filter (e.g.
    // "envoy.filters.network.tcp_proxy") used to still lower, silently
    // discarding whatever network filter the model actually named.
    envoy::Bootstrap forged_filter_name = parsed.value();
    forged_filter_name.listener.filter_chain.filter_name =
        lit_str("envoy.filters.network.tcp_proxy");
    const auto forged_filter_name_result = envoy::lower_to_rut(forged_filter_name, all_true);
    CHECK_FALSE(forged_filter_name_result);
    CHECK(forged_filter_name_result.error().code == FrontendError::UnexpectedToken);
    CHECK(to_string(forged_filter_name_result.error().detail).find("network filter name") !=
          std::string::npos);

    // A cleared (default-constructed) `filter_name` — as a hand-built
    // `Bootstrap` that never populated the field would have — must be
    // rejected the same way as an explicitly wrong one.
    envoy::Bootstrap cleared_filter_name = parsed.value();
    cleared_filter_name.listener.filter_chain.filter_name = Str{};
    const auto cleared_filter_name_result = envoy::lower_to_rut(cleared_filter_name, all_true);
    CHECK_FALSE(cleared_filter_name_result);
    CHECK(cleared_filter_name_result.error().code == FrontendError::UnexpectedToken);
    CHECK(to_string(cleared_filter_name_result.error().detail).find("network filter name") !=
          std::string::npos);

    // A cleared `hcm.type_url_span` — the model's only record that
    // `parse_hcm`'s `expect_type_url` ever checked the typed_config's
    // `@type` against the v3 HttpConnectionManager type — must also be
    // rejected: a hand-built `Bootstrap` that never ran that check leaves
    // this span at its default `Span{}`.
    envoy::Bootstrap cleared_hcm_type_url = parsed.value();
    cleared_hcm_type_url.listener.filter_chain.hcm.type_url_span = Span{};
    const auto cleared_hcm_type_url_result = envoy::lower_to_rut(cleared_hcm_type_url, all_true);
    CHECK_FALSE(cleared_hcm_type_url_result);
    CHECK(cleared_hcm_type_url_result.error().code == FrontendError::UnexpectedToken);
    CHECK(to_string(cleared_hcm_type_url_result.error().detail).find("typed_config is required") !=
          std::string::npos);

    // PR #692 round-6 review: a cleared `hcm.generate_request_id_span` —
    // the model's only record that `parse_hcm` ever saw and accepted
    // `generate_request_id: false` — must also be rejected. A hand-built
    // `Bootstrap` that never set the field (or a caller who cleared it after
    // parsing) leaves this span at its default `Span{}`, the same forgery
    // shape as `cleared_hcm_type_url` above.
    envoy::Bootstrap cleared_generate_request_id = parsed.value();
    cleared_generate_request_id.listener.filter_chain.hcm.generate_request_id_span = Span{};
    const auto cleared_generate_request_id_result =
        envoy::lower_to_rut(cleared_generate_request_id, all_true);
    CHECK_FALSE(cleared_generate_request_id_result);
    CHECK(cleared_generate_request_id_result.error().code == FrontendError::UnexpectedToken);
    CHECK(to_string(cleared_generate_request_id_result.error().detail)
              .find("generate_request_id: false is required") != std::string::npos);

    // PR #692 round-8 review: a cleared `cluster.load_assignment_name_present`
    // — the model's only record that `parse_bootstrap_json` ever saw and
    // validated `load_assignment.cluster_name` — must also be rejected. A
    // hand-built `Bootstrap` that never populated `load_assignment` (or a
    // caller who cleared the bit on a parsed copy) still has a matching
    // `action.cluster` / `cluster.name` pair and would otherwise lower
    // successfully, emitting a working gateway for a bootstrap Envoy would
    // reject at startup.
    envoy::Bootstrap cleared_load_assignment_name = parsed.value();
    cleared_load_assignment_name.clusters[0].load_assignment_name_present = false;
    const auto cleared_load_assignment_name_result =
        envoy::lower_to_rut(cleared_load_assignment_name, all_true);
    CHECK_FALSE(cleared_load_assignment_name_result);
    CHECK(cleared_load_assignment_name_result.error().code == FrontendError::UnexpectedToken);
    CHECK(to_string(cleared_load_assignment_name_result.error().detail)
              .find("load_assignment.cluster_name is required") != std::string::npos);

    // PR #692 round-9 review, ported to the route-list model: an
    // empty/empty `action.cluster` / cluster `name` pairing must not lower
    // successfully. `Str::eq` treats two empty views as equal, so clearing
    // both names on a parsed copy used to still pass the cluster-identity
    // check and reach the hard-coded `envoy_cluster_0` upstream. The
    // route-list `validate()` now checks every declared cluster's `name`
    // for emptiness in its own loop, before ever comparing it against
    // `action.cluster` (src/envoy/converter.cc), so this forgery is now
    // caught by that earlier, more specific diagnostic instead of the
    // cluster-identity mismatch message.
    envoy::Bootstrap empty_cluster_names = parsed.value();
    empty_cluster_names.listener.filter_chain.hcm.route_config.virtual_host.routes[0]
        .action.cluster = Str{};
    empty_cluster_names.clusters[0].name = Str{};
    const auto empty_cluster_names_result = envoy::lower_to_rut(empty_cluster_names, all_true);
    CHECK_FALSE(empty_cluster_names_result);
    CHECK(empty_cluster_names_result.error().code == FrontendError::UnexpectedToken);
    CHECK(to_string(empty_cluster_names_result.error().detail)
              .find("cluster name must be a non-empty string") != std::string::npos);

    // The `action.cluster`-side emptiness check still fires independently
    // when the declared cluster's own name stays non-empty (so the
    // per-cluster loop above passes), proving the empty/empty forgery is
    // not only caught incidentally by that loop. Codex round-6 review
    // ported this check onto the same null-safe, non-empty-string
    // diagnostic as the declared-cluster-name check above, so the message
    // here is "must be a non-empty string", not the cluster-identity
    // mismatch message.
    envoy::Bootstrap empty_action_cluster_only = parsed.value();
    empty_action_cluster_only.listener.filter_chain.hcm.route_config.virtual_host.routes[0]
        .action.cluster = Str{};
    const auto empty_action_cluster_only_result =
        envoy::lower_to_rut(empty_action_cluster_only, all_true);
    CHECK_FALSE(empty_action_cluster_only_result);
    CHECK(empty_action_cluster_only_result.error().code == FrontendError::UnexpectedToken);
    CHECK(to_string(empty_action_cluster_only_result.error().detail)
              .find("route cluster must be a non-empty string") != std::string::npos);

    // PR #692 round-9 review: a cleared `virtual_host.domains_span` — the
    // model's only record that parsing established `domains: ["*"]` — must
    // also be rejected. The generated route has no host dimension, so
    // accepting a model with missing domain evidence would widen routing
    // beyond what the model claims.
    envoy::Bootstrap cleared_domains_span = parsed.value();
    cleared_domains_span.listener.filter_chain.hcm.route_config.virtual_host.domains_span = Span{};
    const auto cleared_domains_span_result = envoy::lower_to_rut(cleared_domains_span, all_true);
    CHECK_FALSE(cleared_domains_span_result);
    CHECK(cleared_domains_span_result.error().code == FrontendError::UnexpectedToken);
    CHECK(to_string(cleared_domains_span_result.error().detail)
              .find("virtual host domains must be") != std::string::npos);

    // PR #692 round-9 review: `codec_type` must be revalidated, not just
    // `hcm.type_url_span`. A cleared `codec_type_present`, or `codec_type`
    // set back to `Auto` while `codec_type_present` stays true, must not
    // lower successfully — either forgery admits downstream h2c on this
    // plaintext listener, which is explicitly outside this milestone.
    envoy::Bootstrap cleared_codec_type_present = parsed.value();
    cleared_codec_type_present.listener.filter_chain.hcm.codec_type_present = false;
    const auto cleared_codec_type_present_result =
        envoy::lower_to_rut(cleared_codec_type_present, all_true);
    CHECK_FALSE(cleared_codec_type_present_result);
    CHECK(cleared_codec_type_present_result.error().code == FrontendError::UnexpectedToken);
    CHECK(to_string(cleared_codec_type_present_result.error().detail)
              .find("codec_type must be explicit HTTP1") != std::string::npos);

    envoy::Bootstrap forged_codec_type_auto = parsed.value();
    forged_codec_type_auto.listener.filter_chain.hcm.codec_type = envoy::CodecType::Auto;
    const auto forged_codec_type_auto_result =
        envoy::lower_to_rut(forged_codec_type_auto, all_true);
    CHECK_FALSE(forged_codec_type_auto_result);
    CHECK(forged_codec_type_auto_result.error().code == FrontendError::UnexpectedToken);
    CHECK(to_string(forged_codec_type_auto_result.error().detail)
              .find("codec_type must be explicit HTTP1") != std::string::npos);

    // PR #692 round-9 review: `suppress_envoy_headers` must be revalidated
    // for presence too, not just value. A hand-built model with
    // `suppress_envoy_headers = true` but `suppress_envoy_headers_present =
    // false` used to lower successfully, even though an omitted field
    // defaults to `false` in real Envoy.
    envoy::Bootstrap forged_suppress_envoy_headers = parsed.value();
    forged_suppress_envoy_headers.listener.filter_chain.hcm.router.suppress_envoy_headers = true;
    forged_suppress_envoy_headers.listener.filter_chain.hcm.router.suppress_envoy_headers_present =
        false;
    const auto forged_suppress_envoy_headers_result =
        envoy::lower_to_rut(forged_suppress_envoy_headers, all_true);
    CHECK_FALSE(forged_suppress_envoy_headers_result);
    CHECK(forged_suppress_envoy_headers_result.error().code == FrontendError::UnsupportedSyntax);
    CHECK(to_string(forged_suppress_envoy_headers_result.error().detail)
              .find("suppress_envoy_headers: true on the router filter") != std::string::npos);

    // PR #692 round-10 review: a zeroed `cluster.connect_timeout` must not
    // lower successfully. The parser requires a strictly positive value
    // (`parse_duration(..., allow_zero=false)`), and Envoy itself rejects a
    // zero `connect_timeout` at startup, but the emitted RUT program never
    // reads this field so nothing else would catch the forgery.
    envoy::Bootstrap zero_connect_timeout = parsed.value();
    zero_connect_timeout.clusters[0].connect_timeout.milliseconds = 0;
    const auto zero_connect_timeout_result = envoy::lower_to_rut(zero_connect_timeout, all_true);
    CHECK_FALSE(zero_connect_timeout_result);
    CHECK(zero_connect_timeout_result.error().code == FrontendError::UnexpectedToken);
    CHECK(to_string(zero_connect_timeout_result.error().detail).find("duration must be positive") !=
          std::string::npos);

    // PR #692 round-10 review: a cleared `hcm.stat_prefix` must not lower
    // successfully either. The parser requires it non-empty, but the
    // emitted RUT program never reads this field.
    envoy::Bootstrap empty_stat_prefix = parsed.value();
    empty_stat_prefix.listener.filter_chain.hcm.stat_prefix = Str{};
    const auto empty_stat_prefix_result = envoy::lower_to_rut(empty_stat_prefix, all_true);
    CHECK_FALSE(empty_stat_prefix_result);
    CHECK(empty_stat_prefix_result.error().code == FrontendError::UnexpectedToken);
    CHECK(to_string(empty_stat_prefix_result.error().detail)
              .find("stat_prefix must be a non-empty string") != std::string::npos);

    // PR #692 round-10 review: a cleared `virtual_host.name` must not lower
    // successfully either. The parser requires it non-empty, but the
    // emitted RUT program never reads this field.
    envoy::Bootstrap empty_virtual_host_name = parsed.value();
    empty_virtual_host_name.listener.filter_chain.hcm.route_config.virtual_host.name = Str{};
    const auto empty_virtual_host_name_result =
        envoy::lower_to_rut(empty_virtual_host_name, all_true);
    CHECK_FALSE(empty_virtual_host_name_result);
    CHECK(empty_virtual_host_name_result.error().code == FrontendError::UnexpectedToken);
    CHECK(to_string(empty_virtual_host_name_result.error().detail)
              .find("virtual host name must be a non-empty string") != std::string::npos);

    // PR #692 round-12 review, ported to the route-list model (PR 8's
    // `routes[]`/`clusters[]`): an overlong `action.cluster` (paired with an
    // equally overlong, still-equal declared cluster `name`, so the prior
    // non-empty/equality check alone still passes) must not lower
    // successfully. `name_string` (src/envoy/parser.cc:179-185) rejects
    // every name over `kMaxEnvoyNameLen` during parsing, but nothing before
    // this fix re-enforced that bound at lowering time.
    const std::string overlong_name(static_cast<size_t>(envoy::kMaxEnvoyNameLen) + 1u, 'a');
    envoy::Bootstrap overlong_cluster_names = parsed.value();
    overlong_cluster_names.listener.filter_chain.hcm.route_config.virtual_host.routes[0]
        .action.cluster = str(overlong_name);
    overlong_cluster_names.clusters[0].name = str(overlong_name);
    const auto overlong_cluster_names_result =
        envoy::lower_to_rut(overlong_cluster_names, all_true);
    CHECK_FALSE(overlong_cluster_names_result);
    CHECK(overlong_cluster_names_result.error().code == FrontendError::UnsupportedSyntax);
    CHECK(to_string(overlong_cluster_names_result.error().detail)
              .find("name exceeds the bounded length") != std::string::npos);

    // PR #692 round-12 review: an overlong `hcm.stat_prefix` must not lower
    // successfully either, the same class of gap the cluster-name length
    // check above closes.
    envoy::Bootstrap overlong_stat_prefix = parsed.value();
    overlong_stat_prefix.listener.filter_chain.hcm.stat_prefix = str(overlong_name);
    const auto overlong_stat_prefix_result = envoy::lower_to_rut(overlong_stat_prefix, all_true);
    CHECK_FALSE(overlong_stat_prefix_result);
    CHECK(overlong_stat_prefix_result.error().code == FrontendError::UnsupportedSyntax);
    CHECK(to_string(overlong_stat_prefix_result.error().detail)
              .find("name exceeds the bounded length") != std::string::npos);

    // PR #692 round-12 review: an overlong `virtual_host.name` must not
    // lower successfully either, the same class of gap the checks above
    // close.
    envoy::Bootstrap overlong_virtual_host_name = parsed.value();
    overlong_virtual_host_name.listener.filter_chain.hcm.route_config.virtual_host.name =
        str(overlong_name);
    const auto overlong_virtual_host_name_result =
        envoy::lower_to_rut(overlong_virtual_host_name, all_true);
    CHECK_FALSE(overlong_virtual_host_name_result);
    CHECK(overlong_virtual_host_name_result.error().code == FrontendError::UnsupportedSyntax);
    CHECK(to_string(overlong_virtual_host_name_result.error().detail)
              .find("name exceeds the bounded length") != std::string::npos);

    // PR #692 round-12 review, ported to the route-list model: presence of
    // a declared cluster's `load_assignment_name_present` is not proof that
    // the *current* `name`/`action.cluster` still match what
    // `parse_bootstrap_json` validated `load_assignment.cluster_name`
    // against. Renaming both `action.cluster` and the declared cluster's
    // `name` to the same new string (so the equality check between them
    // still passes) while leaving the presence bit true and
    // `load_assignment_name` holding the stale, parsed "backend" value must
    // not lower successfully.
    envoy::Bootstrap renamed_cluster_stale_load_assignment = parsed.value();
    renamed_cluster_stale_load_assignment.listener.filter_chain.hcm.route_config.virtual_host
        .routes[0]
        .action.cluster = lit_str("renamed");
    renamed_cluster_stale_load_assignment.clusters[0].name = lit_str("renamed");
    const auto renamed_cluster_stale_load_assignment_result =
        envoy::lower_to_rut(renamed_cluster_stale_load_assignment, all_true);
    CHECK_FALSE(renamed_cluster_stale_load_assignment_result);
    CHECK(renamed_cluster_stale_load_assignment_result.error().code ==
          FrontendError::UnexpectedToken);
    CHECK(to_string(renamed_cluster_stale_load_assignment_result.error().detail)
              .find("load_assignment.cluster_name must equal the cluster name") !=
          std::string::npos);

    // PR #692 round-15 review: `listener.name` and `hcm.route_config.name`
    // are optional (`name_string(..., allow_empty=true)`,
    // src/envoy/parser.cc:350-352 and :538-540) but the parser still bounds
    // either by `kMaxEnvoyNameLen` when present. An overlong, non-empty
    // value for either must not lower successfully.
    envoy::Bootstrap overlong_listener_name = parsed.value();
    overlong_listener_name.listener.name = str(overlong_name);
    const auto overlong_listener_name_result =
        envoy::lower_to_rut(overlong_listener_name, all_true);
    CHECK_FALSE(overlong_listener_name_result);
    CHECK(overlong_listener_name_result.error().code == FrontendError::UnsupportedSyntax);
    CHECK(to_string(overlong_listener_name_result.error().detail)
              .find("name exceeds the bounded length") != std::string::npos);

    envoy::Bootstrap overlong_route_config_name = parsed.value();
    overlong_route_config_name.listener.filter_chain.hcm.route_config.name = str(overlong_name);
    const auto overlong_route_config_name_result =
        envoy::lower_to_rut(overlong_route_config_name, all_true);
    CHECK_FALSE(overlong_route_config_name_result);
    CHECK(overlong_route_config_name_result.error().code == FrontendError::UnsupportedSyntax);
    CHECK(to_string(overlong_route_config_name_result.error().detail)
              .find("name exceeds the bounded length") != std::string::npos);

    // Codex round-5 review: a hand-built model can set `action.kind` to a
    // value outside {Forward, DirectResponse, Redirect} (the parser never
    // produces this). `validate()` used to infer Forward by elimination
    // after ruling out DirectResponse/Redirect, so this out-of-range
    // discriminator would fall through and lower as a forwarding route even
    // though it names no recognized action.
    envoy::Bootstrap forged_action_kind = parsed.value();
    forged_action_kind.listener.filter_chain.hcm.route_config.virtual_host.routes[0].action.kind =
        static_cast<envoy::RouteActionKind>(99);
    const auto forged_action_kind_result = envoy::lower_to_rut(forged_action_kind, all_true);
    CHECK_FALSE(forged_action_kind_result);
    CHECK(forged_action_kind_result.error().code == FrontendError::UnexpectedToken);
    CHECK(
        to_string(forged_action_kind_result.error().detail).find("action kind is not recognized") !=
        std::string::npos);

    // Codex round-6 review (693) / Codex round-5 review on PR #695
    // (independently the same class of finding, against the route-list
    // model's own `build_node_plan`): a hand-built model can set
    // `match.kind` to a value outside {Prefix, Path} (the parser never
    // produces this); `validate()`'s per-route loop (src/envoy/converter.cc)
    // now rejects any `match.kind` outside {Prefix, Path} up front. Forged
    // out-of-bounds `clusters.len` / `virtual_host.routes.len` are covered by
    // `api_forged_multi_route_model_rejected` below (Codex round-6 review;
    // kept there rather than duplicated here). A forged `match.kind` outside
    // {Prefix, Path} is covered later in this test (Codex round-5 review,
    // below the byte-content forgeries) rather than duplicated here too.

    // A one-byte prefix that is not "/" bypasses the parser's
    // `prefix_shape_ok` (which requires a length-1 prefix to literally BE
    // "/", by content, not merely by length). Before the fix, `shape_ok`
    // here checked length only, so this backed, non-"/" one-byte prefix was
    // silently accepted and `strip_trailing_slash` treated it as root
    // (Codex P2 on PR #695 round 4).
    envoy::Bootstrap one_byte_non_slash_prefix = parsed.value();
    one_byte_non_slash_prefix.listener.filter_chain.hcm.route_config.virtual_host.routes[0]
        .match.prefix = lit_str("x");
    CHECK_FALSE(envoy::lower_to_rut(one_byte_non_slash_prefix, all_true));

    // A direct-model `Str{nullptr, 1}` one-byte prefix must also fail
    // closed rather than dereference `ptr[0]` (the same finding: the
    // pre-fix `shape_ok` never checked `ptr != nullptr` for the length-1
    // case either).
    envoy::Bootstrap null_one_byte_prefix = parsed.value();
    null_one_byte_prefix.listener.filter_chain.hcm.route_config.virtual_host.routes[0]
        .match.prefix = Str{nullptr, 1u};
    CHECK_FALSE(envoy::lower_to_rut(null_one_byte_prefix, all_true));

    // A hand-built exact path containing a byte (`"`) the RUT lexer treats
    // as an escape introducer bypasses the parser's `validate_route_match_
    // bytes`/`plain_string` (which rejects any JSON string with an escape
    // outright). Before the fix, `put_escaped` silently inserted a `\`
    // before this byte, changing the runtime string's byte content instead
    // of preserving it (Codex P2 on PR #695 round 4).
    envoy::Bootstrap quote_byte_path = parsed.value();
    quote_byte_path.listener.filter_chain.hcm.route_config.virtual_host.routes[0].match.kind =
        envoy::RouteMatchKind::Path;
    quote_byte_path.listener.filter_chain.hcm.route_config.virtual_host.routes[0].match.path =
        Str{"/a\"b", 4u};
    CHECK_FALSE(envoy::lower_to_rut(quote_byte_path, all_true));

    // Same for a literal backslash byte.
    envoy::Bootstrap backslash_byte_path = parsed.value();
    backslash_byte_path.listener.filter_chain.hcm.route_config.virtual_host.routes[0].match.kind =
        envoy::RouteMatchKind::Path;
    backslash_byte_path.listener.filter_chain.hcm.route_config.virtual_host.routes[0].match.path =
        Str{"/a\\b", 4u};
    CHECK_FALSE(envoy::lower_to_rut(backslash_byte_path, all_true));

    // Codex round-5 review: a hand-built model can set `match.kind` to a
    // value outside {Prefix, Path} (the parser never produces this).
    // `validate()` used to shape-check only the two known kinds and then
    // treat every non-`Path` kind as a prefix when building the text/emit
    // plan, so this forged discriminator used to reach `build_node_plan`
    // with an unvalidated, default-empty `match.prefix` -- underflowing
    // `strip_trailing_slash`'s `prefix.len - 1u` into a huge out-of-bounds
    // view instead of failing closed.
    envoy::Bootstrap forged_match_kind = parsed.value();
    forged_match_kind.listener.filter_chain.hcm.route_config.virtual_host.routes[0].match.kind =
        static_cast<envoy::RouteMatchKind>(7);
    const auto forged_match_kind_result = envoy::lower_to_rut(forged_match_kind, all_true);
    CHECK_FALSE(forged_match_kind_result);
    CHECK(forged_match_kind_result.error().code == FrontendError::UnexpectedToken);
    CHECK(to_string(forged_match_kind_result.error().detail).find("match kind is not recognized") !=
          std::string::npos);
}

TEST(envoy_convert, api_forged_multi_route_model_rejected) {
    // These forgeries are only reachable once a model has more than one
    // route/cluster admitted (this PR's `build_lowering_plan`); scenario
    // (a)'s two routes/two clusters give a hand-built model with a
    // "later" (index-1) route and a same-length declared cluster name to
    // mutate.
    const std::string text = routes_scenario_a_json();
    static envoy::JsonDocument doc;
    auto parsed = envoy::parse_bootstrap_json(str(text), doc);
    REQUIRE(parsed);
    REQUIRE_EQ(parsed.value().listener.filter_chain.hcm.route_config.virtual_host.routes.len, 2u);
    REQUIRE_EQ(parsed.value().clusters.len, 2u);
    const envoy::RutCapabilities all_true = all_capabilities_true();

    // Codex round-6 review: `action.cluster` on the later (index-1) route
    // reaches `Str::eq` against every declared cluster name without ever
    // being validated as backed/non-empty/bounded itself (unlike the
    // declared names on the other side of that comparison, reapplied by an
    // earlier round). `Str::eq` checks length first, so a `Str{nullptr, 7}`
    // forgery -- matching declared cluster "backend"'s 7-byte length --
    // would dereference the null pointer instead of failing closed.
    envoy::Bootstrap forged_cluster_view = parsed.value();
    forged_cluster_view.listener.filter_chain.hcm.route_config.virtual_host.routes[1]
        .action.cluster = Str{nullptr, 7u};
    const auto forged_cluster_view_result = envoy::lower_to_rut(forged_cluster_view, all_true);
    CHECK_FALSE(forged_cluster_view_result);
    CHECK(forged_cluster_view_result.error().code == FrontendError::UnexpectedToken);
    CHECK(to_string(forged_cluster_view_result.error().detail).find("non-empty string") !=
          std::string::npos);

    // An empty (zero-length, unbacked) `action.cluster` on the later route
    // must be rejected the same way -- `Str::eq`'s length check alone would
    // let this one through safely (no dereference), but it still must not
    // silently resolve to `cluster_index_of`'s "unreachable" fallback index.
    envoy::Bootstrap empty_cluster_view = parsed.value();
    empty_cluster_view.listener.filter_chain.hcm.route_config.virtual_host.routes[1]
        .action.cluster = Str{};
    CHECK_FALSE(envoy::lower_to_rut(empty_cluster_view, all_true));

    // An oversized `action.cluster` (129 bytes) on the later route bypasses
    // the parser's `name_string` length bound the same way.
    static const std::string oversized_cluster(129u, 'a');
    envoy::Bootstrap oversized_cluster_view = parsed.value();
    oversized_cluster_view.listener.filter_chain.hcm.route_config.virtual_host.routes[1]
        .action.cluster = str(oversized_cluster);
    const auto oversized_cluster_view_result =
        envoy::lower_to_rut(oversized_cluster_view, all_true);
    CHECK_FALSE(oversized_cluster_view_result);
    CHECK(oversized_cluster_view_result.error().code == FrontendError::UnsupportedSyntax);
    CHECK(to_string(oversized_cluster_view_result.error().detail).find("bounded length") !=
          std::string::npos);

    // Codex round-6 review: a hand-built model can set the later (index-1)
    // route's `action.kind` to a value outside {Forward, DirectResponse,
    // Redirect}. `validate()`'s per-route loop already applies the same
    // `action.kind != RouteActionKind::Forward` check to every route
    // (not just index 0), so this is already rejected; locked in here as a
    // regression case for the specifically-multi-route shape the review
    // raised.
    envoy::Bootstrap forged_later_action_kind = parsed.value();
    forged_later_action_kind.listener.filter_chain.hcm.route_config.virtual_host.routes[1]
        .action.kind = static_cast<envoy::RouteActionKind>(77);
    const auto forged_later_action_kind_result =
        envoy::lower_to_rut(forged_later_action_kind, all_true);
    CHECK_FALSE(forged_later_action_kind_result);
    CHECK(forged_later_action_kind_result.error().code == FrontendError::UnexpectedToken);
    CHECK(to_string(forged_later_action_kind_result.error().detail)
              .find("action kind is not recognized") != std::string::npos);

    // Codex round-6 review: `FixedVec::len` is public and unguarded by its
    // own accessor, so a hand-built model can set `model.clusters.len` past
    // `kMaxEnvoyClusters` (8) while the underlying `data` array stays that
    // size; every `model.clusters[i]` access in `validate` (and
    // `build_lowering_plan`/`cluster_index_of` after it) would then read out
    // of bounds instead of producing a diagnostic.
    envoy::Bootstrap forged_cluster_count = parsed.value();
    forged_cluster_count.clusters.len = envoy::kMaxEnvoyClusters + 1u;
    const auto forged_cluster_count_result = envoy::lower_to_rut(forged_cluster_count, all_true);
    CHECK_FALSE(forged_cluster_count_result);
    CHECK(forged_cluster_count_result.error().code == FrontendError::UnexpectedToken);
    CHECK(to_string(forged_cluster_count_result.error().detail).find("bounded capacity") !=
          std::string::npos);

    // Same forged-count hazard, applied to the public routes vector.
    envoy::Bootstrap forged_route_count = parsed.value();
    forged_route_count.listener.filter_chain.hcm.route_config.virtual_host.routes.len =
        envoy::kMaxEnvoyRoutes + 1u;
    const auto forged_route_count_result = envoy::lower_to_rut(forged_route_count, all_true);
    CHECK_FALSE(forged_route_count_result);
    CHECK(forged_route_count_result.error().code == FrontendError::UnexpectedToken);
    CHECK(to_string(forged_route_count_result.error().detail).find("bounded capacity") !=
          std::string::npos);
}

TEST(envoy_convert, colon_segment_allowed_in_exact_path_with_root_prefix) {
    // An exact `path` match is never emitted as a route declaration (only
    // ever compared as a string literal, `req.pathOnly == "..."`), unlike a
    // `prefix` match that becomes a `route "<node_text>" { ... }`
    // declaration route_trie.h would treat a ':' segment in specially. A
    // path containing "/:tenant" alongside a root prefix must lower
    // successfully instead of being rejected for a parameter-capture risk
    // it does not carry.
    const std::string text = route_list_json(
        json_array(
            {path_route_json("/:tenant", "tenant_backend"), prefix_route_json("/", "backend")}),
        json_array({cluster_json("tenant_backend", 9001), cluster_json("backend", 9000)}));
    static envoy::JsonDocument doc;
    auto parsed = envoy::parse_bootstrap_json(str(text), doc);
    REQUIRE(parsed);
    const envoy::RutCapabilities all_true{true, true, true};
    auto lowered = lower_heap(parsed.value(), all_true);
    REQUIRE(*lowered);
    const std::string out = to_string((*lowered).value().view());
    CHECK(out.find("req.pathOnly == \"/:tenant\"") != std::string::npos);
}

TEST(envoy_convert, prefix_containing_double_slash_is_rejected_end_to_end) {
    // Unlike the hand-built-model case above, this goes through the real
    // JSON parser: `route_match_byte_ok` (src/envoy/parser.cc) allows '/'
    // freely and `prefix_shape_ok` only checks the first/last byte, so a
    // configured "//api/v1/" prefix parses successfully and must be caught
    // by the converter instead.
    const std::string text =
        route_list_json(json_array({prefix_route_json("/api//v1/", "backend")}),
                        json_array({cluster_json("backend", 9000)}));
    static envoy::JsonDocument doc;
    auto parsed = envoy::parse_bootstrap_json(str(text), doc);
    REQUIRE(parsed);
    const envoy::RouteMatch& match =
        parsed.value().listener.filter_chain.hcm.route_config.virtual_host.routes[0].match;
    REQUIRE(match.prefix.eq(lit_str("/api//v1/")));

    const envoy::RutCapabilities all_true{true, true, true};
    auto lowered = lower_heap(parsed.value(), all_true);
    REQUIRE_FALSE(*lowered);
    CHECK(lowered->error().code == FrontendError::UnsupportedSyntax);
    CHECK(to_string(lowered->error().detail).find("\"//\"") != std::string::npos);
}

TEST(envoy_convert, api_forged_duplicate_cluster_name_rejected) {
    const std::string text = routes_scenario_a_json();
    static envoy::JsonDocument doc;
    auto parsed = envoy::parse_bootstrap_json(str(text), doc);
    REQUIRE(parsed);
    REQUIRE_EQ(parsed.value().clusters.len, 2u);
    const envoy::RutCapabilities all_true{true, true, true};

    // The JSON parser already rejects a duplicate cluster name
    // (parse_clusters); a hand-built model bypasses it. Without the
    // defensive check, `cluster_index_of` would silently resolve every
    // "backend"-named route to clusters[0] while both endpoints are still
    // emitted as separate upstreams.
    envoy::Bootstrap duplicate_cluster_name = parsed.value();
    duplicate_cluster_name.clusters[1].name = duplicate_cluster_name.clusters[0].name;
    CHECK_FALSE(envoy::lower_to_rut(duplicate_cluster_name, all_true));
}

TEST(envoy_convert, api_forged_malformed_cluster_name_rejected) {
    // Codex round-5 review: `parse_cluster` (src/envoy/parser.cc) guarantees
    // every parsed cluster name is backed, non-empty, and bounded, but a
    // hand-built model bypasses that. Before the fix, the duplicate-name
    // comparison ran directly on `model.clusters[i].name`, so a malformed
    // later name reaching `Str::eq` (which compares by length first, then
    // dereferences both `ptr`s byte-by-byte once lengths match) would
    // dereference a null pointer instead of producing a diagnostic.
    const std::string text = routes_scenario_a_json();
    static envoy::JsonDocument doc;
    auto parsed = envoy::parse_bootstrap_json(str(text), doc);
    REQUIRE(parsed);
    REQUIRE_EQ(parsed.value().clusters.len, 2u);
    REQUIRE_EQ(parsed.value().clusters[0].name.len, 7u);  // "backend"
    const envoy::RutCapabilities all_true{true, true, true};

    // A null-backed name, the same length as clusters[0]'s ("backend", 7
    // bytes) so `Str::eq`'s length check does not short-circuit before the
    // byte loop would dereference the null pointer.
    envoy::Bootstrap null_cluster_name = parsed.value();
    null_cluster_name.clusters[1].name = Str{nullptr, 7u};
    const auto null_cluster_name_result = envoy::lower_to_rut(null_cluster_name, all_true);
    CHECK_FALSE(null_cluster_name_result);
    CHECK(null_cluster_name_result.error().code == FrontendError::UnexpectedToken);
    CHECK(to_string(null_cluster_name_result.error().detail).find("non-empty string") !=
          std::string::npos);

    // An empty name bypasses the parser's `name_string(..., allow_empty:
    // false, ...)` the same way.
    envoy::Bootstrap empty_cluster_name = parsed.value();
    empty_cluster_name.clusters[1].name = Str{};
    CHECK_FALSE(envoy::lower_to_rut(empty_cluster_name, all_true));

    // A name over `kMaxEnvoyNameLen` (128) bytes bypasses the parser's
    // length bound the same way.
    static const std::string oversized_name(129u, 'a');
    envoy::Bootstrap oversized_cluster_name = parsed.value();
    oversized_cluster_name.clusters[1].name = str(oversized_name);
    const auto oversized_cluster_name_result =
        envoy::lower_to_rut(oversized_cluster_name, all_true);
    CHECK_FALSE(oversized_cluster_name_result);
    CHECK(oversized_cluster_name_result.error().code == FrontendError::UnsupportedSyntax);
    CHECK(to_string(oversized_cluster_name_result.error().detail).find("bounded length") !=
          std::string::npos);
}

// ── Increment 4: reject direct_response / redirect before the six
//    capability checks (multiple routes and clusters are lowered by this PR;
//    see the golden_routes_* and cli_two_routes_blocked_by_first_capability
//    tests below) ─────────────────────────────────────────────────────────

TEST(envoy_convert, blocked_on_direct_response) {
    const std::string text = direct_response_json(_tc);
    static envoy::JsonDocument doc;
    auto parsed = envoy::parse_bootstrap_json(str(text), doc);
    REQUIRE(parsed);
    const envoy::RouteAction& action =
        parsed.value().listener.filter_chain.hcm.route_config.virtual_host.routes[0].action;
    REQUIRE(action.kind == envoy::RouteActionKind::DirectResponse);

    const envoy::RutCapabilities all_true{true, true, true};
    auto lowered = lower_heap(parsed.value(), all_true);
    REQUIRE_FALSE(*lowered);
    CHECK(lowered->error().code == FrontendError::UnsupportedSyntax);
    CHECK(to_string(lowered->error().detail).find("direct_response is not lowered yet") !=
          std::string::npos);
    CHECK_EQ(lowered->error().span.line, action.span.line);
    CHECK_EQ(lowered->error().span.col, action.span.col);
}

TEST(envoy_convert, local_only_route_table_omits_clusters) {
    const std::string text = direct_response_no_clusters_json(_tc);
    static envoy::JsonDocument doc;
    auto parsed = envoy::parse_bootstrap_json(str(text), doc);
    REQUIRE(parsed);
    CHECK_EQ(parsed.value().clusters.len, 0u);
    const envoy::RouteAction& action =
        parsed.value().listener.filter_chain.hcm.route_config.virtual_host.routes[0].action;
    REQUIRE(action.kind == envoy::RouteActionKind::DirectResponse);

    const envoy::RutCapabilities all_true{true, true, true};
    auto lowered = envoy::lower_to_rut(parsed.value(), all_true);
    REQUIRE_FALSE(lowered);
    CHECK(lowered.error().code == FrontendError::UnsupportedSyntax);
    // The missing cluster set must not itself be rejected: a local-only
    // route table reaches the same "not lowered yet" diagnostic a
    // declared-cluster direct_response gets (PR 9 lowers it for real).
    CHECK(to_string(lowered.error().detail).find("direct_response is not lowered yet") !=
          std::string::npos);
}

TEST(envoy_convert, blocked_on_redirect) {
    const std::string text = redirect_json(_tc);
    static envoy::JsonDocument doc;
    auto parsed = envoy::parse_bootstrap_json(str(text), doc);
    REQUIRE(parsed);
    const envoy::RouteAction& action =
        parsed.value().listener.filter_chain.hcm.route_config.virtual_host.routes[0].action;
    REQUIRE(action.kind == envoy::RouteActionKind::Redirect);

    const envoy::RutCapabilities all_true{true, true, true};
    auto lowered = lower_heap(parsed.value(), all_true);
    REQUIRE_FALSE(*lowered);
    CHECK(lowered->error().code == FrontendError::UnsupportedSyntax);
    CHECK(to_string(lowered->error().detail).find("redirect is not lowered yet") !=
          std::string::npos);
    CHECK_EQ(lowered->error().span.line, action.span.line);
    CHECK_EQ(lowered->error().span.col, action.span.col);
}

// ── PR 8: ordered route-list lowering ──────────────────────────────────
//
// TODO(PR3-PR5): once the RUT policy vocabulary these goldens use
// (`host: "preserve"`, `header_order: "upstream"`, the Envoy local_response
// layout) exists in the compiler, add the lex/parse/analyze/MIR/RIR
// round-trip test for each golden here, mirroring
// tests/test_nginx_parser.cc's `golden_compiles`-style checks (see PR5's
// `cli_milestone_s_converts` / `golden_compiles` in envoy-pr-plan.md). Today
// none of the five goldens below even lex cleanly against
// LexedTokens::kMaxTokens once the multi-node output grows past a couple of
// nodes, and `local_response`'s `connection_header` / `header_names` /
// `header_order` fields are rejected by the current parser — both gaps are
// pre-existing (the single-route milestone-S golden already fails the same
// way) and are PR3-PR5's job, not this PR's.

// Codex round-6 review (P1): scenario (a) used to be a golden SUCCESS case,
// pinning `kEnvoyRoutesAGolden` byte for byte. Direct measurement against the
// real frontend lexer (`rut::lex`, linked test-only above) showed that exact
// golden text -- 8804 bytes, well under `RutSource::kCapacity` -- fails to
// lex with `TooManyTokens` at byte 8400, because `LexedTokens::kMaxTokens`
// is only 932 tokens (tests/fixtures/envoy_routes_a.inc has the full
// citation). So the converter was reporting success for a program `rut`
// itself cannot load. `lower_to_rut` now fails closed on this exact shape;
// this test locks that in instead of the stale byte-for-byte pin.
// `kEnvoyRoutesAGolden` is kept (unused by this test) as the evidence for
// that exact byte-8400 measurement.
TEST(envoy_convert, golden_routes_a_prefix_then_root) {
    const std::string text = routes_scenario_a_json();
    static envoy::JsonDocument doc;
    auto parsed = envoy::parse_bootstrap_json(str(text), doc);
    REQUIRE(parsed);
    const envoy::RutCapabilities all_true{true, true, true};
    const auto lowered = envoy::lower_to_rut(parsed.value(), all_true);
    CHECK_FALSE(lowered);
    CHECK(lowered.error().code == FrontendError::TooManyTokens);
    CHECK(to_string(lowered.error().detail).find("lexer token budget") != std::string::npos);
}

// Codex round-6 review (P1): measures `converter.cc`'s conservative
// token-count estimate against the REAL frontend lexer (`rut::lex`, linked
// test-only above -- see tests/CMakeLists.txt's comment on this target) for
// the exact texts the estimate is meant to bound. Pins the current
// numbers so a lexer or converter-emission change that moves them is caught
// here rather than only showing up as a mysterious golden-test failure:
//   - `kEnvoyRoutesAGolden` (scenario a, the shape `lower_to_rut` now
//     rejects): the real lexer fails with `TooManyTokens` at byte 8400 of
//     8804 -- confirming the rejection above is correct, not overly
//     conservative for a program that would have actually worked.
//   - `kEnvoyRoutesBGolden` / `kEnvoyRoutesCGolden` (the two golden shapes
//     that still succeed, scenarios b/c below): 360 and 668 real tokens,
//     comfortably under `LexedTokens::kMaxTokens` (932 today; #697,
//     unmerged as of this PR, raises it to 4096 -- see
//     docs/envoy-converter.md). `kEnvoyRoutesBGolden`'s count dropped from
//     655 (two live nodes) to 360 (root-only) under Codex round-9: "/api"
//     is now dropped as globally shadowed by the earlier "/" instead of
//     being planned as a dead node (see envoy_routes_b.inc).
TEST(envoy_convert, token_budget_goldens_match_the_real_lexer) {
    const Str golden_a = lit_str(kEnvoyRoutesAGolden);
    const auto lexed_a = lex(golden_a);
    REQUIRE_FALSE(lexed_a);
    CHECK(lexed_a.error().code == FrontendError::TooManyTokens);
    CHECK_EQ(lexed_a.error().span.start, 8400u);
    CHECK_EQ(golden_a.len, 8804u);

    const Str golden_b = lit_str(kEnvoyRoutesBGolden);
    const auto lexed_b = lex(golden_b);
    REQUIRE(lexed_b);
    CHECK_EQ(lexed_b.value().tokens.len, 360u);
    CHECK_LT(lexed_b.value().tokens.len, LexedTokens::kMaxTokens);

    const Str golden_c = lit_str(kEnvoyRoutesCGolden);
    const auto lexed_c = lex(golden_c);
    REQUIRE(lexed_c);
    CHECK_EQ(lexed_c.value().tokens.len, 668u);
    CHECK_LT(lexed_c.value().tokens.len, LexedTokens::kMaxTokens);
}

// Codex round-9 review: "/" declared before "/api/" makes "/api" globally
// shadowed (root byte-prefixes everything), so `build_lowering_plan` now
// drops it before registering it as a node at all -- the golden is
// root-only (see envoy_routes_b.inc's updated comment and doc).
TEST(envoy_convert, golden_routes_b_root_then_prefix) {
    const std::string text = routes_scenario_b_json();
    static envoy::JsonDocument doc;
    auto parsed = envoy::parse_bootstrap_json(str(text), doc);
    REQUIRE(parsed);
    const envoy::RutCapabilities all_true{true, true, true};
    auto lowered = lower_heap(parsed.value(), all_true);
    REQUIRE(*lowered);
    const Str golden = lit_str(kEnvoyRoutesBGolden);
    REQUIRE_EQ((*lowered).value().len, golden.len);
    CHECK((*lowered).value().view().eq(golden));
}

// Codex round-9 review's own example (P2 on PR #695): "/" declared before
// TWO distinct sibling prefixes, "/api/" and "/admin/". Before the fix,
// `build_lowering_plan` registered both dead nodes anyway (each shadowed by
// the earlier "/", but still planned), emitting a full HEAD/any-method
// forwarding block for each -- about 938 real lexer tokens for this exact
// shape, over `LexedTokens::kMaxTokens` (932), even though the equivalent
// root-only program fits comfortably. This pins both the golden text (must
// be root-only, byte for byte) and the real token count, so a regression
// that goes back to registering shadowed siblings is caught two ways: a
// content mismatch here, and (independently) a real `TooManyTokens` failure
// from `rut::lex` on the field the `estimate_conservative_token_count`
// budget check in `lower_to_rut` is supposed to prevent from ever shipping.
TEST(envoy_convert, shadowed_siblings_dropped_before_registration) {
    const std::string text =
        route_list_json(json_array({prefix_route_json("/", "backend"),
                                    prefix_route_json("/api/", "api_backend"),
                                    prefix_route_json("/admin/", "admin_backend")}),
                        json_array({cluster_json("backend", 9000),
                                    cluster_json("api_backend", 9001),
                                    cluster_json("admin_backend", 9002)}));
    static envoy::JsonDocument doc;
    auto parsed = envoy::parse_bootstrap_json(str(text), doc);
    REQUIRE(parsed);
    const envoy::RutCapabilities all_true{true, true, true};
    auto lowered = lower_heap(parsed.value(), all_true);
    REQUIRE(*lowered);
    const Str golden = lit_str(kEnvoyRoutesShadowedSiblingsGolden);
    REQUIRE_EQ((*lowered).value().len, golden.len);
    CHECK((*lowered).value().view().eq(golden));

    const auto lexed = lex((*lowered).value().view());
    REQUIRE(lexed);
    CHECK_EQ(lexed.value().tokens.len, 364u);
    CHECK_LT(lexed.value().tokens.len, LexedTokens::kMaxTokens);
}

// General form of the rule above (Codex round-9 decision: not just root):
// an EARLIER prefix "/api/" is a byte-prefix of the LATER prefix
// "/api/v1/", so "/api/v1" is globally shadowed -- dropped before it is
// ever registered as a node -- even though nothing here is root and both
// prefixes happen to forward to the same cluster (chosen to keep the
// fixture minimal; shadowing does not depend on cluster identity). "/api"'s
// own bare-literal gap (the unrelated 404-shape limitation documented in
// `blocked_on_node_own_literal_needs_all_method_fallback`) is resolved with
// an exact route for "/api" itself declared before its own prefix (the
// already-established golden(f) pattern), NOT a root catch-all: a root
// ancestor would force "/api" into an if/else chain, and two if/else-shaped
// nodes together exceed `LexedTokens::kMaxTokens` at the current (932)
// budget even with nothing else in the config (confirmed by direct
// measurement) -- unrelated to this shadowing fix, but it rules out reusing
// the `golden_routes_b_root_then_prefix`-style fixture shape here.
TEST(envoy_convert, prefix_shadowed_by_earlier_prefix_dropped) {
    const std::string text = route_list_json(json_array({path_route_json("/api", "api"),
                                                         prefix_route_json("/api/", "api"),
                                                         prefix_route_json("/api/v1/", "api")}),
                                             json_array({cluster_json("api", 9001)}));
    static envoy::JsonDocument doc;
    auto parsed = envoy::parse_bootstrap_json(str(text), doc);
    REQUIRE(parsed);
    const envoy::RutCapabilities all_true{true, true, true};
    auto lowered = lower_heap(parsed.value(), all_true);
    REQUIRE(*lowered);
    const std::string out = to_string((*lowered).value().view());
    // "/api/v1" never appears anywhere -- the node was dropped outright, not
    // merely rendered unreachable inside some other node's arm chain.
    CHECK(out.find("/api/v1") == std::string::npos);
    CHECK(out.find("route \"/api\" {") != std::string::npos);
    CHECK(out.find("route HEAD \"/api\" {") != std::string::npos);
}

// Prefix-then-path form of the same rule: an earlier prefix "/api/" is a
// byte-prefix of the later exact path "/api/x", so the exact route is
// globally shadowed. This arm-level drop (`saw_own_prefix`, pre-existing
// since round 7/8) is unchanged by round-9, but this pins it as a SUCCESS
// case (an exact route for "/api" itself, declared first, resolves "/api"'s
// own bare-literal gap the same way golden(f) does -- see the comment above
// for why a root catch-all is not used instead) so the drop is visible in
// the emitted text instead of being masked by the unrelated
// `blocked_on_shadowed_exact_needs_all_method_fallback` BLOCKED_BY_RUT
// case, which exercises the same route shape without an own-literal route.
TEST(envoy_convert, prefix_shadowed_exact_path_arm_dropped) {
    const std::string text =
        route_list_json(json_array({path_route_json("/api", "api"),
                                    prefix_route_json("/api/", "api"),
                                    path_route_json("/api/x", "dead")}),
                        json_array({cluster_json("api", 9001), cluster_json("dead", 9002)}));
    static envoy::JsonDocument doc;
    auto parsed = envoy::parse_bootstrap_json(str(text), doc);
    REQUIRE(parsed);
    const envoy::RutCapabilities all_true{true, true, true};
    auto lowered = lower_heap(parsed.value(), all_true);
    REQUIRE(*lowered);
    const std::string out = to_string((*lowered).value().view());
    CHECK(out.find("/api/x") == std::string::npos);
    // "dead" is cluster index 1 (declared order api=0, dead=1): it must
    // never appear as a forward target, only as an (unused) upstream.
    CHECK(out.find("forward(envoy_cluster_1") == std::string::npos);
    CHECK(out.find("forward(envoy_cluster_0") != std::string::npos);
}

// The reverse declaration order proves order, not text length, decides
// shadowing (Codex round-9 decision): the MORE specific prefix "/api/v1/"
// declared BEFORE the broader "/api/" is not shadowed by it
// (`is_strict_ancestor("/api", "/api/v1")` is true, but the shadow check in
// `build_lowering_plan` only ever looks at nodes already KEPT earlier in
// declaration order, and "/api" is not one of them yet when "/api/v1" is
// registered) -- both nodes are kept and planned. Two real (if/else-shaped)
// nodes together exceed `LexedTokens::kMaxTokens` at the current (932)
// budget (confirmed above and by `golden_routes_a_prefix_then_root`), so
// this cannot be asserted as a byte-for-byte success like the other cases;
// instead it is asserted two ways, both purely from `lower_to_rut`'s
// observable result (no internal test hook into `build_lowering_plan`):
//   - this order (specific first) fails with `TooManyTokens`, not
//     `BLOCKED_BY_RUT` or success -- proving BOTH nodes were planned all
//     the way to a fully generated RUT text (a `BLOCKED_BY_RUT` failure
//     happens during planning, before any text is generated at all; and a
//     single surviving node this shape would fit comfortably under budget,
//     as `prefix_shadowed_by_earlier_prefix_dropped` above measures).
//   - the reverse order (general "/api/" first, "/api/v1/" second, in
//     `general_prefix_before_specific_shadows_specific` below) DOES shadow
//     "/api/v1" and succeeds, well under budget, with only "/api" emitted
//     -- the direct contrast that isolates order (not size) as the cause of
//     the first case's `TooManyTokens`.
TEST(envoy_convert, specific_prefix_before_general_prefix_keeps_both) {
    const std::string text = route_list_json(
        json_array({prefix_route_json("/api/v1/", "specific"),
                    path_route_json("/api", "general"),
                    prefix_route_json("/api/", "general")}),
        json_array({cluster_json("specific", 9001), cluster_json("general", 9002)}));
    static envoy::JsonDocument doc;
    auto parsed = envoy::parse_bootstrap_json(str(text), doc);
    REQUIRE(parsed);
    const envoy::RutCapabilities all_true{true, true, true};
    const auto lowered = envoy::lower_to_rut(parsed.value(), all_true);
    CHECK_FALSE(lowered);
    CHECK(lowered.error().code == FrontendError::TooManyTokens);
    CHECK(to_string(lowered.error().detail).find("lexer token budget") != std::string::npos);
}

// Companion to the test above: same three routes, "/api/"'s prefix declared
// BEFORE "/api/v1/"'s. This time "/api/v1" IS shadowed and dropped, so only
// one (if/else-shaped) node is planned -- well under the token budget --
// proving the previous test's `TooManyTokens` result really does come from
// keeping both nodes (declaration order), not merely from this route
// shape's size in general.
TEST(envoy_convert, general_prefix_before_specific_shadows_specific) {
    const std::string text = route_list_json(
        json_array({path_route_json("/api", "general"),
                    prefix_route_json("/api/", "general"),
                    prefix_route_json("/api/v1/", "specific")}),
        json_array({cluster_json("general", 9001), cluster_json("specific", 9002)}));
    static envoy::JsonDocument doc;
    auto parsed = envoy::parse_bootstrap_json(str(text), doc);
    REQUIRE(parsed);
    const envoy::RutCapabilities all_true{true, true, true};
    auto lowered = lower_heap(parsed.value(), all_true);
    REQUIRE(*lowered);
    const std::string out = to_string((*lowered).value().view());
    CHECK(out.find("/api/v1") == std::string::npos);
    CHECK(out.find("route \"/api\" {") != std::string::npos);
    // "specific" is cluster index 1 (declared order general=0, specific=1):
    // it must never appear as a forward target, only as an (unused)
    // upstream.
    CHECK(out.find("forward(envoy_cluster_1") == std::string::npos);
    CHECK(out.find("forward(envoy_cluster_0") != std::string::npos);
}

TEST(envoy_convert, golden_routes_c_exact_then_root) {
    const std::string text = routes_scenario_c_json();
    static envoy::JsonDocument doc;
    auto parsed = envoy::parse_bootstrap_json(str(text), doc);
    REQUIRE(parsed);
    const envoy::RutCapabilities all_true{true, true, true};
    auto lowered = lower_heap(parsed.value(), all_true);
    REQUIRE(*lowered);
    const Str golden = lit_str(kEnvoyRoutesCGolden);
    REQUIRE_EQ((*lowered).value().len, golden.len);
    CHECK((*lowered).value().view().eq(golden));
}

// Codex round-8 review: two identical exact routes ("/healthz", "/healthz")
// before a catch-all ("/") used to duplicate both the conditional arm and
// its forwarding policy in the emitted root node -- dead weight that could
// push an otherwise in-budget arm chain past the lexer's token limit. The
// dedup in `build_node_plan` (`has_exact_arm`, src/envoy/converter.cc) drops
// the second identical route, so this must lower to the exact same output as
// scenario (c)'s single "/healthz" + "/" golden, and must stay within the
// real lexer's token budget (not just the converter's own estimate).
TEST(envoy_convert, golden_routes_g_duplicate_exact_deduped) {
    const std::string text = routes_scenario_g_json();
    static envoy::JsonDocument doc;
    auto parsed = envoy::parse_bootstrap_json(str(text), doc);
    REQUIRE(parsed);
    REQUIRE_EQ(parsed.value().listener.filter_chain.hcm.route_config.virtual_host.routes.len, 3u);
    const envoy::RutCapabilities all_true{true, true, true};
    auto lowered = lower_heap(parsed.value(), all_true);
    REQUIRE(*lowered);
    const Str golden = lit_str(kEnvoyRoutesCGolden);
    REQUIRE_EQ((*lowered).value().len, golden.len);
    CHECK((*lowered).value().view().eq(golden));

    const auto lexed = lex((*lowered).value().view());
    REQUIRE(lexed);
    CHECK_EQ(lexed.value().tokens.len, 668u);
    CHECK_LT(lexed.value().tokens.len, LexedTokens::kMaxTokens);
}

// Formerly golden (d) ("prefix /api/ only, no catch-all declared"): node
// "/api" ends with only its own (now-unconditional) prefix arm, so "/api"
// itself has no Envoy route, and `route exact "/api"`'s strict local-response
// admission cannot serve every method Envoy's real 404 would (Codex P1) — see
// routes_scenario_d_json's comment above.
TEST(envoy_convert, blocked_on_node_own_literal_needs_all_method_fallback) {
    const std::string text = routes_scenario_d_json();
    static envoy::JsonDocument doc;
    auto parsed = envoy::parse_bootstrap_json(str(text), doc);
    REQUIRE(parsed);
    const envoy::RutCapabilities all_true{true, true, true};
    auto lowered = lower_heap(parsed.value(), all_true);
    REQUIRE_FALSE(*lowered);
    CHECK(lowered->error().code == FrontendError::UnsupportedSyntax);
    CHECK(
        to_string(lowered->error().detail).find("no-route 404 for this node's own literal path") !=
        std::string::npos);
}

// Formerly golden (e) ("prefix /api/ declared before an exact path under it,
// /api/x"): the same node's-own-literal gap as (d) above, plus the
// declaration-order shadowing of the exact "/api/x" route (dropped before
// ever reaching this failure) — see routes_scenario_e_json's comment above.
TEST(envoy_convert, blocked_on_shadowed_exact_needs_all_method_fallback) {
    const std::string text = routes_scenario_e_json();
    static envoy::JsonDocument doc;
    auto parsed = envoy::parse_bootstrap_json(str(text), doc);
    REQUIRE(parsed);
    const envoy::RutCapabilities all_true{true, true, true};
    auto lowered = lower_heap(parsed.value(), all_true);
    REQUIRE_FALSE(*lowered);
    CHECK(lowered->error().code == FrontendError::UnsupportedSyntax);
    CHECK(
        to_string(lowered->error().detail).find("no-route 404 for this node's own literal path") !=
        std::string::npos);
}

// (f): an exact route for a node's own literal path declared BEFORE that
// node's own prefix route resolves the literal correctly through the earlier
// conditional arm; the node must NOT be blocked, and no `route exact` 404
// fallback should be emitted for it (Codex P1 on this PR: it used to be,
// shadowing the earlier arm with an always-404 route) — see
// routes_scenario_f_json's comment above.
TEST(envoy_convert, golden_routes_f_exact_then_own_prefix_not_blocked) {
    const std::string text = routes_scenario_f_json();
    static envoy::JsonDocument doc;
    auto parsed = envoy::parse_bootstrap_json(str(text), doc);
    REQUIRE(parsed);
    const envoy::RutCapabilities all_true{true, true, true};
    auto lowered = lower_heap(parsed.value(), all_true);
    REQUIRE(*lowered);
    const std::string out = to_string((*lowered).value().view());
    CHECK(out.find("route exact \"/api\"") == std::string::npos);
    CHECK(out.find("if req.pathOnly == \"/api\" {") != std::string::npos);
    CHECK(out.find("forward(envoy_cluster_0") != std::string::npos);
    CHECK(out.find("forward(envoy_cluster_1") != std::string::npos);
}

// A no-catch-all node with exact arms and no ancestor to resolve the
// remainder has no RUT form (converter.cc, "Root has no such escape hatch").
TEST(envoy_convert, blocked_root_exact_arms_without_catch_all) {
    const std::string text =
        route_list_json(json_array({path_route_json("/healthz", "health_backend")}),
                        json_array({cluster_json("health_backend", 9001)}));
    static envoy::JsonDocument doc;
    auto parsed = envoy::parse_bootstrap_json(str(text), doc);
    REQUIRE(parsed);
    const envoy::RutCapabilities all_true{true, true, true};
    auto lowered = lower_heap(parsed.value(), all_true);
    REQUIRE_FALSE(*lowered);
    CHECK(lowered->error().code == FrontendError::UnsupportedSyntax);
    CHECK(to_string(lowered->error().detail).find("no-route 404 inside a route branch") !=
          std::string::npos);
}

// A model with no catch-all and no exact arms for root simply omits
// `route "/"`; Rut's own `unmatched` policy already covers it. Uses scenario
// (f) rather than (d) (see routes_scenario_d_json's comment above: (d) is
// now BLOCKED_BY_RUT on node "/api", not on root) — neither of (f)'s two
// routes is owned by or ancestor to root, so root is still omitted here.
TEST(envoy_convert, root_omitted_without_catch_all_or_exact_arms) {
    const std::string text = routes_scenario_f_json();
    static envoy::JsonDocument doc;
    auto parsed = envoy::parse_bootstrap_json(str(text), doc);
    REQUIRE(parsed);
    const envoy::RutCapabilities all_true{true, true, true};
    auto lowered = lower_heap(parsed.value(), all_true);
    REQUIRE(*lowered);
    const std::string out = to_string((*lowered).value().view());
    CHECK(out.find("route \"/\" {") == std::string::npos);
    CHECK(out.find("route HEAD \"/\" {") == std::string::npos);
}

// A two-route bootstrap is lowered (not rejected) by this PR, so with the
// shipped (all-false) capabilities it still fails closed, but now on the
// same capability diagnostic the single-route milestone-S bootstrap hits
// (check 4, `request_envoy_h1`) rather than a "multiple routes" rejection.
TEST(envoy_convert, cli_two_routes_blocked_by_first_capability) {
    const TempDir temp_dir;
    REQUIRE(temp_dir.ok());
    const std::string& directory = temp_dir.path();
    const std::string text = routes_scenario_a_json();
    const std::string path = directory + "/two_routes.json";
    REQUIRE(write_file(path, text));

    static envoy::JsonDocument doc;
    auto parsed = envoy::parse_bootstrap_json(str(text), doc);
    REQUIRE(parsed);
    REQUIRE_EQ(parsed.value().listener.filter_chain.hcm.route_config.virtual_host.routes.len, 2u);
    const Span span = parsed.value()
                          .listener.filter_chain.hcm.route_config.virtual_host.routes[0]
                          .action.cluster_span;

    const RunResult result = run_converter(g_executable, path);
    REQUIRE(WIFEXITED(result.status));
    CHECK_EQ(WEXITSTATUS(result.status), 1);
    CHECK(result.out.empty());
    const std::string expected_prefix = expected_location(path, span);
    CHECK_EQ(result.err.compare(0, expected_prefix.size(), expected_prefix), 0);
    CHECK(result.err.find("RUT request_policy lacks host: \"preserve\"") != std::string::npos);
}

// Brute-force equivalence: for a route list rich enough to exercise exact
// arms, a node's own prefix arm, shadowing by an earlier ancestor prefix, and
// a node whose own literal path resolves through `route exact` (both to a
// forward and to a 404), every probe path must get the same answer from
// Envoy's real first-match semantics and from the "longest node, then arm
// chain" structure PR8 lowers to.
TEST(envoy_convert, brute_force_equivalence_ordered_route_list) {
    const std::vector<SimRoute> routes = {
        {false, "/healthz", "health"},
        {false, "/api/x", "apix"},
        {true, "/api/", "api"},
        {true, "/api/v1/", "apiv1"},
        {true, "/", "root"},
    };

    const std::string text = route_list_json(json_array({path_route_json("/healthz", "health"),
                                                         path_route_json("/api/x", "apix"),
                                                         prefix_route_json("/api/", "api"),
                                                         prefix_route_json("/api/v1/", "apiv1"),
                                                         prefix_route_json("/", "root")}),
                                             json_array({cluster_json("health", 9001),
                                                         cluster_json("apix", 9002),
                                                         cluster_json("api", 9003),
                                                         cluster_json("apiv1", 9004),
                                                         cluster_json("root", 9000)}));
    static envoy::JsonDocument doc;
    auto parsed = envoy::parse_bootstrap_json(str(text), doc);
    REQUIRE(parsed);
    const envoy::RutCapabilities all_true{true, true, true};

    // Codex round-6 review (P1): this 5-route, 3-node ("/", "/api",
    // "/api/v1") shape is exactly the kind of realistic, in-bounds
    // (kMaxEnvoyRoutes = 8) configuration the token-budget finding warned
    // about -- confirmed by direct measurement against the real frontend
    // lexer (rut::lex, linked test-only above): even the smaller 2-node,
    // single-arm-per-node scenarios (b)/(c) use 655-668 of the 932-token
    // budget, and this scenario's extra node and if/else arms (for
    // "/healthz" and "/api/x" each shadowing their owning node's own prefix)
    // push it well past `LexedTokens::kMaxTokens` -- so `lower_to_rut` must
    // now reject it instead of returning a program `rut` cannot load. This
    // was a golden, real-emission cross-check (`rut_dispatch` against the
    // parsed route nodes) before the fix; that path is no longer reachable
    // for this scenario, so it is replaced by asserting the new fail-closed
    // diagnostic. `envoy_first_match`/`sim_dispatch` below are pure
    // simulations with no lowering dependency, so their self-consistency
    // check over all 40+ probes still stands independent of the budget.
    const auto lowered_result = envoy::lower_to_rut(parsed.value(), all_true);
    CHECK_FALSE(lowered_result);
    CHECK(lowered_result.error().code == FrontendError::TooManyTokens);
    CHECK(to_string(lowered_result.error().detail).find("lexer token budget") != std::string::npos);

    const std::vector<std::string> probes = {
        "/",          "/healthz",    "/healthzz",   "/health",     "/api",
        "/api/",      "/api/x",      "/api/y",      "/api/x/",     "/api/x/y",
        "/apiz",      "/apix",       "/api.",       "/api2",       "/api/v1",
        "/api/v1/",   "/api/v1/foo", "/api/v1x",    "/api/v10",    "/api/v1/foo/bar",
        "/other",     "/a",          "/ap",         "/apihealthz", "/healthz/x",
        "/api/xx",    "/api/x2",     "/api//x",     "/API",        "/API/X",
        "/api/v1/v1", "/api/health", "/health/api", "/api/v",      "/api/v1/healthz",
        "/apixx",     "//",          "/api/./x",    "/api/../x",   "/very/long/unrelated/path",
        "/api/x/",
    };
    REQUIRE(probes.size() >= 40u);

    for (const std::string& probe : probes) {
        const std::string expected = envoy_first_match(routes, probe);
        const std::string actual = sim_dispatch(routes, probe);
        CHECK_EQ(expected, actual);
    }
}

// Extends the brute-force probes for the path shape Codex flagged on this PR
// (P1): an exact route naming a node's own literal path, declared BEFORE
// that node's own prefix route, with no root catch-all to fall back on
// (routes_scenario_f_json above). `sim_dispatch`'s independent "route_exact
// wins over the trie" reimplementation (not `build_node_plan` itself)
// already resolves `path == node` by walking routes in declared order, so
// this exercises the same shape `golden_routes_f_exact_then_own_prefix_not_
// blocked` pins byte for byte, from the other, converter-independent
// direction.
TEST(envoy_convert, brute_force_equivalence_exact_before_own_prefix_no_catch_all) {
    const std::vector<SimRoute> routes = {
        {false, "/api", "exact_backend"},
        {true, "/api/", "api_backend"},
    };

    // Same shape as `routes_scenario_f_json()` (golden_routes_f), lowered
    // here too so the probes below can also be checked against the REAL
    // emitted RUT text, not only the independent `sim_dispatch` model.
    const std::string text = routes_scenario_f_json();
    static envoy::JsonDocument doc;
    auto parsed = envoy::parse_bootstrap_json(str(text), doc);
    REQUIRE(parsed);
    const envoy::RutCapabilities all_true{true, true, true};
    auto lowered = lower_heap(parsed.value(), all_true);
    REQUIRE(*lowered);
    const std::vector<RutNode> rut_nodes =
        parse_rut_route_nodes(to_string((*lowered).value().view()));
    REQUIRE_EQ(rut_nodes.size(), 1u);  // "/api" (no root declared)
    std::vector<std::string> cluster_names;
    for (u32 i = 0; i < parsed.value().clusters.len; i++)
        cluster_names.push_back(to_string(parsed.value().clusters[i].name));

    const std::vector<std::string> probes = {
        "/",
        "/api",
        "/api/",
        "/api/x",
        "/api/x/y",
        "/apiz",
        "/api2",
        "/ap",
        "/other",
        "//api",
    };

    for (const std::string& probe : probes) {
        const std::string expected = envoy_first_match(routes, probe);
        const std::string actual = sim_dispatch(routes, probe);
        CHECK_EQ(expected, actual);
        const std::string rut_actual = rut_dispatch(rut_nodes, cluster_names, probe);
        CHECK_EQ(expected, rut_actual);
    }
    // The node's own literal forwards through the earlier exact route, not
    // through a `route exact "/api"` 404 (there is none: no root catch-all
    // means this scenario has no ancestor to fall back on either, so the
    // ONLY way "/api" resolves at all is the earlier exact arm).
    CHECK_EQ(sim_dispatch(routes, "/api"), "exact_backend");
    CHECK_EQ(envoy_first_match(routes, "/api"), "exact_backend");
    CHECK_EQ(rut_dispatch(rut_nodes, cluster_names, "/api"), "exact_backend");
}

int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: test_envoy_convert <path to rut-envoy-convert> [test options]\n");
        return 2;
    }
    g_executable = argv[1];
    // Forward any options after the converter path (e.g. --filter=...) to the
    // runner, with argv[0] kept in front so it sees the usual argv shape.
    argv[1] = argv[0];
    return rut::test::run_all(argc - 1, argv + 1);
}
