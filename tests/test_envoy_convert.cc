#include "fixtures/envoy_milestone_s.inc"
#include "rut/envoy/converter.h"
#include "rut/envoy/parser.h"
#include "test.h"
#include <atomic>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <thread>
#include <vector>

#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

using namespace rut;

namespace {

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
    // test's writer thread below) forks with that thread still holding
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

// PR #692 round-8 review: a fatal `REQUIRE` inside the polling loop of
// `cli_input_toctou_same_size_rewrite_never_admits_torn_read` below used to
// `return` from the test while the racing writer thread was still joinable
// (`stop`/`writer.join()` ran only after the loop). Destroying a joinable
// `std::thread` calls `std::terminate`, so a single failed iteration aborted
// the whole test binary instead of just failing that test. This guard stops
// and joins the writer no matter how the enclosing scope is left — a normal
// fall-through, or an early `REQUIRE` return — mirroring `TempDir` above.
class StopAndJoinThread {
public:
    StopAndJoinThread(std::atomic<bool>& stop, std::thread& thread)
        : stop_(stop), thread_(thread) {}

    ~StopAndJoinThread() {
        stop_.store(true, std::memory_order_relaxed);
        if (thread_.joinable()) thread_.join();
    }

    StopAndJoinThread(const StopAndJoinThread&) = delete;
    StopAndJoinThread& operator=(const StopAndJoinThread&) = delete;
    StopAndJoinThread(StopAndJoinThread&&) = delete;
    StopAndJoinThread& operator=(StopAndJoinThread&&) = delete;

private:
    std::atomic<bool>& stop_;
    std::thread& thread_;
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
// the *same* length while the read is in progress — the size check trivially
// passes throughout.
//
// PR #692 round-4 review: the original version of this test used
// same-length but otherwise-invalid `content_a`/`content_b` (a repeated 'A'
// vs a repeated 'B' byte), and both fail to parse at byte 0 with the exact
// same content-agnostic "unexpected byte in JSON value" detail (the message
// never quotes the offending byte — see `src/envoy/json.cc`). Every torn
// mixture of the two also starts with either 'A' or 'B', so it produces that
// identical message too; the test could not tell a genuinely torn read from
// a clean one and would pass even against the pre-round-3 size-only check.
//
// `content_a`/`content_b` below fix this: both are the full milestone-S
// bootstrap (the same shape `milestone_s_json()` produces, which parses
// successfully and is only ever blocked by the `request_envoy_h1` capability
// gate — see `cli_milestone_s_fails_closed_with_request_gap` above), and
// differ *only* in one cluster identifier that is spelled out three times —
// the route's `cluster`, the static cluster's `name`, and its
// `load_assignment.cluster_name` (all three must agree; `validate()` checks
// the first two, and `parse_bootstrap_json` the third) — as either
// "backend0" (content_a) or "backend1" (content_b), both 8 bytes, so the two
// documents are byte-for-byte the same length and only ever disagree on that
// one trailing digit at each of the three spots. A large whitespace pad
// between the `listeners` and `clusters` sections (JSON insignificant
// whitespace, so still valid) pushes the first occurrence and the other two
// onto different pages, widening the same window the round-3 fix closed.
// A self-consistent read of either document (all three digits '0' or all
// three '1') reaches the identical, expected `request_envoy_h1`
// BLOCKED_BY_RUT diagnostic computed once below via the library API. A torn
// read that mixes '0' and '1' across those three spots — a route naming one
// cluster revision while the declared cluster is the other, precisely the
// "listener from one revision combined with an endpoint from another"
// scenario the round-3 comment in `read_input` describes — makes
// `action.cluster.eq(model.cluster.name)` fail instead, with a different
// diagnostic and error code (`invalid()`/`UnexpectedToken`, "route cluster
// does not name a declared cluster") that cannot be confused with the
// expected one. A torn read that instead breaks JSON syntax fails
// `parse_bootstrap_json` and does not print the expected diagnostic either.
// So exactly one of "input changed" or the expected BLOCKED_BY_RUT message
// is a passing outcome; anything else — including that mismatched-cluster
// diagnostic — is a torn read the TOCTOU check let through and must fail
// this test.
TEST(envoy_convert, cli_input_toctou_same_size_rewrite_never_admits_torn_read) {
    const TempDir temp_dir;
    REQUIRE(temp_dir.ok());
    const std::string& directory = temp_dir.path();
    const std::string path = directory + "/racing.json";

    std::string base = milestone_s_json();
    REQUIRE(
        replace_first(&base, ",\n\"clusters\"", ",\n" + std::string(8192, ' ') + "\"clusters\""));
    const std::string content_a = replace_all(base, "backend", "backend0");
    const std::string content_b = replace_all(base, "backend", "backend1");
    REQUIRE_EQ(content_a.size(), content_b.size());
    REQUIRE_NE(content_a, content_b);
    REQUIRE(write_file(path, content_a));

    static envoy::JsonDocument doc_a;
    auto parsed_a = envoy::parse_bootstrap_json(str(content_a), doc_a);
    REQUIRE(parsed_a);
    static envoy::JsonDocument doc_b;
    auto parsed_b = envoy::parse_bootstrap_json(str(content_b), doc_b);
    REQUIRE(parsed_b);

    auto lowered_a = envoy::lower_to_rut(parsed_a.value());
    REQUIRE_FALSE(lowered_a);
    auto lowered_b = envoy::lower_to_rut(parsed_b.value());
    REQUIRE_FALSE(lowered_b);
    const std::string expected_detail = to_string(lowered_a.error().detail);
    CHECK(expected_detail.find("BLOCKED_BY_RUT") != std::string::npos);
    CHECK_EQ(expected_detail, to_string(lowered_b.error().detail));
    CHECK_EQ(lowered_a.error().span.line, lowered_b.error().span.line);
    CHECK_EQ(lowered_a.error().span.col, lowered_b.error().span.col);
    const std::string expected_prefix = expected_location(path, lowered_a.error().span);

    const int fd = open(path.c_str(), O_WRONLY, 0600);
    REQUIRE(fd >= 0);

    std::atomic<bool> stop{false};
    std::thread writer([&] {
        while (!stop.load(std::memory_order_relaxed)) {
            // Never O_TRUNC, never changes the length: an in-place same-size
            // rewrite is exactly the case the old size-only check could not
            // detect.
            (void)pwrite(fd, content_a.data(), content_a.size(), 0);
            (void)pwrite(fd, content_b.data(), content_b.size(), 0);
        }
    });
    // Declared immediately after the thread starts and before the first
    // fatal `REQUIRE` below, so an early return from this test (or an
    // exception) still stops and joins `writer` during unwind instead of
    // destroying a joinable thread.
    StopAndJoinThread join_writer(stop, writer);

    u32 changed_detected = 0;
    constexpr int kIterations = 300;
    for (int i = 0; i < kIterations; i++) {
        const RunResult result = run_converter(g_executable, path);
        REQUIRE(WIFEXITED(result.status));
        CHECK_EQ(WEXITSTATUS(result.status), 1);
        CHECK(result.out.empty());
        const bool is_changed_error =
            result.err.find("input changed while it was being read") != std::string::npos;
        const bool is_expected_blocked =
            result.err.compare(0, expected_prefix.size(), expected_prefix) == 0 &&
            result.err.find(expected_detail) != std::string::npos;
        // Exactly one of the two known-good outcomes, never both, never
        // neither — in particular never the mismatched-cluster diagnostic a
        // torn read across the three spellings would produce.
        CHECK(is_changed_error != is_expected_blocked);
        if (is_changed_error) changed_detected++;
    }

    stop.store(true, std::memory_order_relaxed);
    writer.join();
    close(fd);

    // Informational only (scheduling-dependent, so not a hard requirement —
    // a slow or heavily loaded machine must not make this test flaky). When
    // it fires, every occurrence is a same-size in-place rewrite the new
    // dev/inode/mtime/ctime comparison caught that the old `after.st_size !=
    // used` check could never have seen.
    fprintf(stderr,
            "cli_input_toctou_same_size_rewrite_never_admits_torn_read: caught %u/%d same-size "
            "races\n",
            changed_detected,
            kIterations);
}

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
    const Span span =
        parsed.value()
            .listener.filter_chain.hcm.route_config.virtual_host.route.action.cluster_span;

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
        auto lowered = envoy::lower_to_rut(parsed.value());
        REQUIRE_FALSE(lowered);
        CHECK(lowered.error().code == FrontendError::UnsupportedSyntax);
        CHECK(to_string(lowered.error().detail).find("suppress_envoy_headers: true") !=
              std::string::npos);
        CHECK_EQ(lowered.error().span.line, router.span.line);
        CHECK_EQ(lowered.error().span.col, router.span.col);
    }
    {
        const std::string text = milestone_json(
            /*suppress_present=*/true, false, /*timeout_present=*/true, "0s");
        static envoy::JsonDocument doc;
        auto parsed = envoy::parse_bootstrap_json(str(text), doc);
        REQUIRE(parsed);
        const envoy::RouterFilter& router = parsed.value().listener.filter_chain.hcm.router;
        REQUIRE(router.suppress_envoy_headers_present);
        auto lowered = envoy::lower_to_rut(parsed.value());
        REQUIRE_FALSE(lowered);
        CHECK(lowered.error().code == FrontendError::UnsupportedSyntax);
        CHECK(to_string(lowered.error().detail).find("suppress_envoy_headers: true") !=
              std::string::npos);
        CHECK_EQ(lowered.error().span.line, router.suppress_envoy_headers_span.line);
        CHECK_EQ(lowered.error().span.col, router.suppress_envoy_headers_span.col);
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
            parsed.value().listener.filter_chain.hcm.route_config.virtual_host.route.action;
        REQUIRE_FALSE(action.timeout_present);
        auto lowered = envoy::lower_to_rut(parsed.value());
        REQUIRE_FALSE(lowered);
        CHECK(lowered.error().code == FrontendError::UnsupportedSyntax);
        CHECK(to_string(lowered.error().detail).find("default 15s route timeout") !=
              std::string::npos);
        CHECK_EQ(lowered.error().span.line, action.span.line);
        CHECK_EQ(lowered.error().span.col, action.span.col);
    }
    {
        const std::string text = milestone_json(
            /*suppress_present=*/true, true, /*timeout_present=*/true, "15s");
        static envoy::JsonDocument doc;
        auto parsed = envoy::parse_bootstrap_json(str(text), doc);
        REQUIRE(parsed);
        const envoy::RouteAction& action =
            parsed.value().listener.filter_chain.hcm.route_config.virtual_host.route.action;
        REQUIRE(action.timeout_present);
        CHECK_EQ(action.timeout.milliseconds, 15000u);
        auto lowered = envoy::lower_to_rut(parsed.value());
        REQUIRE_FALSE(lowered);
        CHECK(lowered.error().code == FrontendError::UnsupportedSyntax);
        CHECK(to_string(lowered.error().detail).find("non-zero route timeout") !=
              std::string::npos);
        CHECK_EQ(lowered.error().span.line, action.timeout.span.line);
        CHECK_EQ(lowered.error().span.col, action.timeout.span.col);
    }
}

TEST(envoy_convert, api_all_capabilities_matches_golden) {
    std::string text = milestone_s_json();
    static envoy::JsonDocument doc;
    auto parsed = envoy::parse_bootstrap_json(str(text), doc);
    REQUIRE(parsed);

    const envoy::RutCapabilities all_true = all_capabilities_true();
    auto lowered = envoy::lower_to_rut(parsed.value(), all_true);
    REQUIRE(lowered);
    const Str golden = lit_str(kEnvoyMilestoneSGolden);
    REQUIRE_EQ(lowered.value().len, golden.len);
    CHECK(lowered.value().view().eq(golden));
    CHECK_EQ(lowered.value().data[lowered.value().len], '\0');
    CHECK_LT(lowered.value().len, envoy::RutSource::kCapacity);

    auto lowered_again = envoy::lower_to_rut(parsed.value(), all_true);
    REQUIRE(lowered_again);
    CHECK(lowered_again.value().view().eq(golden));

    // Overwriting the JSON source after lowering must not change output
    // bytes: no borrowed source text reaches the emitted RUT, only numeric
    // model fields do. The bytes backing `route.match.prefix`,
    // `router.name`, and `filter_chain.filter_name` are left untouched (PR
    // #692 round-3 review added a defensive `validate()` check that the
    // prefix is exactly "/", round-4 added one that the router filter name
    // is exactly "envoy.filters.http.router", and round-5 added one that the
    // network filter name is exactly
    // "envoy.filters.network.http_connection_manager" — see
    // api_forged_model_rejected below — so corrupting any borrowed range
    // would correctly fail lowering rather than exercise the property this
    // test is about).
    const envoy::Bootstrap model_copy = parsed.value();
    const Str prefix =
        model_copy.listener.filter_chain.hcm.route_config.virtual_host.route.match.prefix;
    const Str router_name = model_copy.listener.filter_chain.hcm.router.name;
    const Str filter_name = model_copy.listener.filter_chain.filter_name;
    REQUIRE(prefix.ptr >= text.data() && prefix.ptr < text.data() + text.size());
    REQUIRE(router_name.ptr >= text.data() && router_name.ptr < text.data() + text.size());
    REQUIRE(filter_name.ptr >= text.data() && filter_name.ptr < text.data() + text.size());
    const size_t prefix_offset = static_cast<size_t>(prefix.ptr - text.data());
    const size_t router_name_offset = static_cast<size_t>(router_name.ptr - text.data());
    const size_t filter_name_offset = static_cast<size_t>(filter_name.ptr - text.data());
    for (size_t i = 0; i < text.size(); i++) {
        const bool in_prefix = i >= prefix_offset && i < prefix_offset + prefix.len;
        const bool in_router_name =
            i >= router_name_offset && i < router_name_offset + router_name.len;
        const bool in_filter_name =
            i >= filter_name_offset && i < filter_name_offset + filter_name.len;
        if (!in_prefix && !in_router_name && !in_filter_name) text[i] = 'x';
    }
    auto lowered_after_mutation = envoy::lower_to_rut(model_copy, all_true);
    REQUIRE(lowered_after_mutation);
    CHECK(lowered_after_mutation.value().view().eq(golden));
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
    auto lowered = envoy::lower_to_rut(parsed.value(), all_true);
    REQUIRE(lowered);
    const std::string out = to_string(lowered.value().view());
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
    endpoint_port_zero.cluster.endpoint.address.port = 0;
    CHECK_FALSE(envoy::lower_to_rut(endpoint_port_zero, all_true));

    envoy::Bootstrap mismatched_cluster = parsed.value();
    mismatched_cluster.listener.filter_chain.hcm.route_config.virtual_host.route.action.cluster =
        lit_str("other");
    CHECK_FALSE(envoy::lower_to_rut(mismatched_cluster, all_true));

    // PR #692 round-3 review: a hand-mutated `match.prefix` must not lower
    // successfully. The emitted route is always the literal `"/"` catch-all
    // (put_forward_route never reads `match.prefix`), so without this check
    // a forged "/admin" prefix would silently widen what the generated RUT
    // actually matches relative to what the model claims.
    envoy::Bootstrap forged_prefix = parsed.value();
    forged_prefix.listener.filter_chain.hcm.route_config.virtual_host.route.match.prefix =
        lit_str("/admin");
    const auto forged_prefix_result = envoy::lower_to_rut(forged_prefix, all_true);
    CHECK_FALSE(forged_prefix_result);
    CHECK(forged_prefix_result.error().code == FrontendError::UnexpectedToken);
    CHECK(to_string(forged_prefix_result.error().detail).find("match prefix") != std::string::npos);

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
    cleared_load_assignment_name.cluster.load_assignment_name_present = false;
    const auto cleared_load_assignment_name_result =
        envoy::lower_to_rut(cleared_load_assignment_name, all_true);
    CHECK_FALSE(cleared_load_assignment_name_result);
    CHECK(cleared_load_assignment_name_result.error().code == FrontendError::UnexpectedToken);
    CHECK(to_string(cleared_load_assignment_name_result.error().detail)
              .find("load_assignment.cluster_name is required") != std::string::npos);

    // PR #692 round-9 review: an empty/empty `action.cluster` /
    // `cluster.name` pairing must not lower successfully. `Str::eq` treats
    // two empty views as equal, so clearing both names on a parsed copy used
    // to still pass the cluster-identity check above and reach the
    // hard-coded `envoy_cluster_0` upstream.
    envoy::Bootstrap empty_cluster_names = parsed.value();
    empty_cluster_names.listener.filter_chain.hcm.route_config.virtual_host.route.action.cluster =
        Str{};
    empty_cluster_names.cluster.name = Str{};
    const auto empty_cluster_names_result = envoy::lower_to_rut(empty_cluster_names, all_true);
    CHECK_FALSE(empty_cluster_names_result);
    CHECK(empty_cluster_names_result.error().code == FrontendError::UnexpectedToken);
    CHECK(to_string(empty_cluster_names_result.error().detail)
              .find("route cluster does not name a declared cluster") != std::string::npos);

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
}

int main(int argc, char** argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: test_envoy_convert <path to rut-envoy-convert>\n");
        return 2;
    }
    g_executable = argv[1];
    return rut::test::run_all(1, argv);
}
