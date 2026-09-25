#include "fixtures/envoy_milestone_s.inc"
#include "rut/envoy/converter.h"
#include "rut/envoy/parser.h"
#include "test.h"
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

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
    const pid_t child = fork();
    if (child == 0) {
        if (dup2(capture[0], STDOUT_FILENO) < 0 || dup2(capture[1], STDERR_FILENO) < 0) _exit(126);
        close(capture[0]);
        close(capture[1]);
        std::vector<char*> argv;
        argv.push_back(const_cast<char*>(executable));
        for (const auto& arg : args) argv.push_back(const_cast<char*>(arg.c_str()));
        argv.push_back(nullptr);
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

std::string make_temp_dir() {
    char pattern[] = "/tmp/rut-envoy-convert-XXXXXX";
    char* path = mkdtemp(pattern);
    return path == nullptr ? std::string{} : std::string(path);
}

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
    const std::string directory = make_temp_dir();
    REQUIRE_FALSE(directory.empty());
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
    const std::string directory = make_temp_dir();
    REQUIRE_FALSE(directory.empty());

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

TEST(envoy_convert, cli_parse_error_is_source_located) {
    const std::string directory = make_temp_dir();
    REQUIRE_FALSE(directory.empty());
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
    const std::string directory = make_temp_dir();
    REQUIRE_FALSE(directory.empty());
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
    // model fields do.
    const envoy::Bootstrap model_copy = parsed.value();
    for (char& c : text) c = 'x';
    auto lowered_after_mutation = envoy::lower_to_rut(model_copy, all_true);
    REQUIRE(lowered_after_mutation);
    CHECK(lowered_after_mutation.value().view().eq(golden));
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
}

int main(int argc, char** argv) {
    if (argc != 2) return 2;
    g_executable = argv[1];
    return rut::test::run_all(1, argv);
}
