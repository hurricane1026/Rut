#include "rut/nginx/converter.h"
#include "rut/nginx/parser.h"
#include "test.h"
#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

namespace {

const char* g_executable = nullptr;

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
    char output_template[] = "/tmp/rut-nginx-convert-out-XXXXXX";
    char error_template[] = "/tmp/rut-nginx-convert-err-XXXXXX";
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

RunResult run_converter(const char* executable,
                        const char* format,
                        const std::string& input,
                        const std::string& path) {
    RunResult result;
    int capture[2]{};
    if (!make_capture_files(capture)) return result;
    const pid_t child = fork();
    if (child == 0) {
        if (dup2(capture[0], STDOUT_FILENO) < 0 || dup2(capture[1], STDERR_FILENO) < 0) _exit(126);
        close(capture[0]);
        close(capture[1]);
        execl(executable, executable, "--format", format, input.c_str(), nullptr);
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
    (void)path;
    return result;
}

RunResult run_converter_to_file(const char* executable,
                                const char* format,
                                const std::string& input,
                                const std::string& output_path) {
    RunResult result;
    int error_pipe[2]{};
    if (pipe(error_pipe) != 0) return result;
    const pid_t child = fork();
    if (child == 0) {
        const int output = open(output_path.c_str(), O_WRONLY);
        if (output < 0 || dup2(output, STDOUT_FILENO) < 0 || dup2(error_pipe[1], STDERR_FILENO) < 0)
            _exit(126);
        if (output >= 0) close(output);
        close(error_pipe[0]);
        close(error_pipe[1]);
        execl(executable, executable, "--format", format, input.c_str(), nullptr);
        _exit(127);
    }
    close(error_pipe[1]);
    if (child < 0) {
        close(error_pipe[0]);
        return result;
    }
    wait_bounded(child, &result.status);
    result.err = read_fd(error_pipe[0]);
    return result;
}

RunResult run_converter_to_broken_pipe(const char* executable,
                                       const char* format,
                                       const std::string& input) {
    RunResult result;
    int output_pipe[2]{};
    int error_pipe[2]{};
    if (pipe(output_pipe) != 0 || pipe(error_pipe) != 0) return result;
    const pid_t child = fork();
    if (child == 0) {
        if (dup2(output_pipe[1], STDOUT_FILENO) < 0 || dup2(error_pipe[1], STDERR_FILENO) < 0)
            _exit(126);
        close(output_pipe[0]);
        close(output_pipe[1]);
        close(error_pipe[0]);
        close(error_pipe[1]);
        execl(executable, executable, "--format", format, input.c_str(), nullptr);
        _exit(127);
    }
    close(output_pipe[0]);
    close(output_pipe[1]);
    close(error_pipe[1]);
    if (child < 0) {
        close(error_pipe[0]);
        return result;
    }
    wait_bounded(child, &result.status);
    result.err = read_fd(error_pipe[0]);
    return result;
}

RunResult run_converter_wrong_argc(const char* executable) {
    RunResult result;
    int capture[2]{};
    if (!make_capture_files(capture)) return result;
    const pid_t child = fork();
    if (child == 0) {
        if (dup2(capture[0], STDOUT_FILENO) < 0 || dup2(capture[1], STDERR_FILENO) < 0) _exit(126);
        close(capture[0]);
        close(capture[1]);
        execl(executable, executable, "--format", "server", nullptr);
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

std::string make_temp_dir() {
    char pattern[] = "/tmp/rut-nginx-convert-XXXXXX";
    char* path = mkdtemp(pattern);
    return path == nullptr ? std::string{} : std::string(path);
}

}  // namespace

TEST(nginx_convert, server_and_http_outputs_match_api_without_opening_access_log) {
    const std::string directory = make_temp_dir();
    REQUIRE_FALSE(directory.empty());
    const std::string server_path = directory + "/server.conf";
    const std::string access_path = directory + "/must-not-be-created.log";
    const std::string server_source =
        "server { listen 127.0.0.1:8080; location / { proxy_read_timeout 1s; "
        "proxy_pass http://127.0.0.1:9000; } }\n";
    const std::string http_source =
        "http { log_format compat \"$request_length\"; access_log " + access_path +
        " compat; server { listen 127.0.0.1:8080; location / { proxy_read_timeout 1s; "
        "proxy_pass http://127.0.0.1:9000; } } }\n";
    REQUIRE(write_file(server_path, server_source));
    const std::string http_path = directory + "/http.conf";
    REQUIRE(write_file(http_path, http_source));

    const auto server_parsed =
        rut::nginx::parse({server_source.data(), static_cast<rut::u32>(server_source.size())});
    REQUIRE(server_parsed);
    const auto server_lowered = rut::nginx::lower_to_rut(server_parsed.value());
    REQUIRE(server_lowered);
    const auto http_parsed = rut::nginx::parse_http_profile(
        {http_source.data(), static_cast<rut::u32>(http_source.size())});
    REQUIRE(http_parsed);
    const auto http_lowered = rut::nginx::lower_to_rut(http_parsed.value());
    REQUIRE(http_lowered);

    const RunResult server_run = run_converter(g_executable, "server", server_path, server_path);
    REQUIRE(WIFEXITED(server_run.status));
    CHECK_EQ(WEXITSTATUS(server_run.status), 0);
    CHECK(server_run.err.empty());
    CHECK(server_run.out == std::string(server_lowered.value().data, server_lowered.value().len));

    const RunResult http_run = run_converter(g_executable, "http", http_path, http_path);
    REQUIRE(WIFEXITED(http_run.status));
    CHECK_EQ(WEXITSTATUS(http_run.status), 0);
    CHECK(http_run.err.empty());
    CHECK(http_run.out == std::string(http_lowered.value().data, http_lowered.value().len));
    CHECK(access(access_path.c_str(), F_OK) != 0);
}

TEST(nginx_convert, access_log_off_cli_matches_server_output_without_log_declaration) {
    const std::string directory = make_temp_dir();
    REQUIRE_FALSE(directory.empty());
    const std::string server_source =
        "server { listen 127.0.0.1:8080; location / { proxy_pass http://127.0.0.1:9000; } }\n";
    const std::string http_source =
        "http { access_log off; server { listen 127.0.0.1:8080; location / { "
        "proxy_pass http://127.0.0.1:9000; } } }\n";
    const std::string complete_source = "events {}\n" + http_source;
    const std::string server_path = directory + "/server.conf";
    const std::string http_path = directory + "/off-http.conf";
    const std::string complete_path = directory + "/off-complete.conf";
    REQUIRE(write_file(server_path, server_source));
    REQUIRE(write_file(http_path, http_source));
    REQUIRE(write_file(complete_path, complete_source));

    const auto server_parsed =
        rut::nginx::parse({server_source.data(), static_cast<rut::u32>(server_source.size())});
    REQUIRE(server_parsed);
    const auto server_lowered = rut::nginx::lower_to_rut(server_parsed.value());
    REQUIRE(server_lowered);
    const std::string expected(server_lowered.value().data, server_lowered.value().len);

    for (const auto& invocation :
         {std::pair<const char*, std::string>{"http", http_path}, {"nginx-http", complete_path}}) {
        const RunResult result =
            run_converter(g_executable, invocation.first, invocation.second, invocation.second);
        REQUIRE(WIFEXITED(result.status));
        CHECK_EQ(WEXITSTATUS(result.status), 0);
        CHECK(result.err.empty());
        CHECK_EQ(result.out, expected);
        CHECK_EQ(result.out.find("accessLog {"), std::string::npos);
    }
}

TEST(nginx_convert, nginx_http_output_matches_complete_api_and_rejects_unsupported_envelopes) {
    const std::string directory = make_temp_dir();
    REQUIRE_FALSE(directory.empty());
    const std::string access_path = directory + "/must-not-be-created.log";
    const std::string source =
        "events {}\n"
        "http { log_format compat \"$request_length\"; access_log " +
        access_path +
        " compat; server { listen 127.0.0.1:8080; location / { proxy_read_timeout 1s; "
        "proxy_buffering on; proxy_pass http://127.0.0.1:9000; } } }\n";
    const std::string path = directory + "/complete.conf";
    REQUIRE(write_file(path, source));
    const auto diagnostic_prefix = [](const std::string& filename,
                                      const std::string& input,
                                      const std::string& token) {
        const size_t offset = input.find(token);
        if (offset == std::string::npos) return std::string{};
        const size_t line_start =
            input.rfind('\n', offset) == std::string::npos ? 0u : input.rfind('\n', offset) + 1u;
        const unsigned line = static_cast<unsigned>(
            std::count(input.begin(), input.begin() + static_cast<ptrdiff_t>(offset), '\n') + 1u);
        const unsigned col = static_cast<unsigned>(offset - line_start + 1u);
        return filename + ":" + std::to_string(line) + ":" + std::to_string(col) + ": ";
    };
    const auto parsed =
        rut::nginx::parse_nginx_http_config({source.data(), static_cast<rut::u32>(source.size())});
    REQUIRE(parsed);
    const auto lowered = rut::nginx::lower_to_rut(parsed.value());
    REQUIRE(lowered);
    const RunResult converted = run_converter(g_executable, "nginx-http", path, path);
    REQUIRE(WIFEXITED(converted.status));
    CHECK_EQ(WEXITSTATUS(converted.status), 0);
    CHECK(converted.err.empty());
    CHECK(converted.out == std::string(lowered.value().data, lowered.value().len));
    CHECK(access(access_path.c_str(), F_OK) != 0);

    const RunResult old_http = run_converter(g_executable, "http", path, path);
    REQUIRE(WIFEXITED(old_http.status));
    CHECK_EQ(WEXITSTATUS(old_http.status), 1);
    CHECK(old_http.out.empty());
    CHECK(old_http.err.find(diagnostic_prefix(path, source, "events")) == 0u);
    CHECK(old_http.err.find("expected bounded http profile") != std::string::npos);

    const std::string unsupported_source =
        "events { worker_connections 64; }\n" + source.substr(source.find("http"));
    const std::string unsupported_path = directory + "/unsupported-complete.conf";
    REQUIRE(write_file(unsupported_path, unsupported_source));
    const RunResult unsupported =
        run_converter(g_executable, "nginx-http", unsupported_path, unsupported_path);
    REQUIRE(WIFEXITED(unsupported.status));
    CHECK_EQ(WEXITSTATUS(unsupported.status), 1);
    CHECK(unsupported.out.empty());
    CHECK(unsupported.err.find(
              diagnostic_prefix(unsupported_path, unsupported_source, "worker_connections")) == 0u);
    CHECK(unsupported.err.find("events directives are unsupported") != std::string::npos);

    const std::string unsupported_global_source = "worker_processes 1;\n" + source;
    const std::string unsupported_global_path = directory + "/unsupported-global.conf";
    REQUIRE(write_file(unsupported_global_path, unsupported_global_source));
    const RunResult unsupported_global =
        run_converter(g_executable, "nginx-http", unsupported_global_path, unsupported_global_path);
    REQUIRE(WIFEXITED(unsupported_global.status));
    CHECK_EQ(WEXITSTATUS(unsupported_global.status), 1);
    CHECK(unsupported_global.out.empty());
    CHECK(unsupported_global.err.find(diagnostic_prefix(
              unsupported_global_path, unsupported_global_source, "worker_processes")) == 0u);
    CHECK(unsupported_global.err.find("expected leading events block") != std::string::npos);

    const std::string unsupported_nested_source =
        "events {}\nhttp { log_format compat \"$request_length\"; access_log " + access_path +
        " compat; server { listen 127.0.0.1:8080; location / { add_header X-Test yes; } } }\n";
    const std::string unsupported_nested_path = directory + "/unsupported-nested.conf";
    REQUIRE(write_file(unsupported_nested_path, unsupported_nested_source));
    const RunResult unsupported_nested =
        run_converter(g_executable, "nginx-http", unsupported_nested_path, unsupported_nested_path);
    REQUIRE(WIFEXITED(unsupported_nested.status));
    CHECK_EQ(WEXITSTATUS(unsupported_nested.status), 1);
    CHECK(unsupported_nested.out.empty());
    CHECK(unsupported_nested.err.find(diagnostic_prefix(
              unsupported_nested_path, unsupported_nested_source, "add_header")) == 0u);
    CHECK(unsupported_nested.err.find("unknown location directive") != std::string::npos);
}

TEST(nginx_convert, rejects_usage_missing_malformed_and_special_inputs_without_stdout) {
    const std::string directory = make_temp_dir();
    REQUIRE_FALSE(directory.empty());
    const std::string malformed_path = directory + "/malformed.conf";
    REQUIRE(write_file(malformed_path, "server { location / { proxy_pass; }"));
    const RunResult malformed =
        run_converter(g_executable, "server", malformed_path, malformed_path);
    REQUIRE(WIFEXITED(malformed.status));
    CHECK_EQ(WEXITSTATUS(malformed.status), 1);
    CHECK(malformed.out.empty());
    CHECK(malformed.err.find(malformed_path + ":") == 0u);

    const RunResult wrong_format =
        run_converter(g_executable, "guess", malformed_path, malformed_path);
    REQUIRE(WIFEXITED(wrong_format.status));
    CHECK_EQ(WEXITSTATUS(wrong_format.status), 2);
    CHECK(wrong_format.out.empty());
    CHECK(wrong_format.err.find("usage:") == 0u);

    const RunResult missing = run_converter(
        g_executable, "server", directory + "/missing.conf", directory + "/missing.conf");
    REQUIRE(WIFEXITED(missing.status));
    CHECK_EQ(WEXITSTATUS(missing.status), 1);
    CHECK(missing.out.empty());

    const std::string empty_path = directory + "/empty.conf";
    REQUIRE(write_file(empty_path, std::string{}));
    const RunResult empty = run_converter(g_executable, "server", empty_path, empty_path);
    REQUIRE(WIFEXITED(empty.status));
    CHECK_EQ(WEXITSTATUS(empty.status), 1);
    CHECK(empty.out.empty());

    const std::string wrapper_path = directory + "/wrapper.conf";
    REQUIRE(write_file(wrapper_path,
                       "events {}\nhttp { server { listen 127.0.0.1:8080; location / { "
                       "proxy_pass http://127.0.0.1:9000; } } }\n"));
    const RunResult wrapper = run_converter(g_executable, "server", wrapper_path, wrapper_path);
    REQUIRE(WIFEXITED(wrapper.status));
    CHECK_EQ(WEXITSTATUS(wrapper.status), 1);
    CHECK(wrapper.out.empty());

    const std::string unsupported_path = directory + "/unsupported.conf";
    REQUIRE(write_file(unsupported_path,
                       "server { listen 8080; location / { add_header X-Test yes; "
                       "proxy_pass http://127.0.0.1:9000; } }\n"));
    const RunResult unsupported =
        run_converter(g_executable, "server", unsupported_path, unsupported_path);
    REQUIRE(WIFEXITED(unsupported.status));
    CHECK_EQ(WEXITSTATUS(unsupported.status), 1);
    CHECK(unsupported.out.empty());

    const std::string wrong_grammar_path = directory + "/wrong-grammar.conf";
    REQUIRE(write_file(wrong_grammar_path,
                       "server { listen 127.0.0.1:8080; location / { proxy_pass "
                       "http://127.0.0.1:9000; } }\n"));
    const RunResult wrong_grammar =
        run_converter(g_executable, "http", wrong_grammar_path, wrong_grammar_path);
    REQUIRE(WIFEXITED(wrong_grammar.status));
    CHECK_EQ(WEXITSTATUS(wrong_grammar.status), 1);
    CHECK(wrong_grammar.out.empty());

    const RunResult wrong_argc = run_converter_wrong_argc(g_executable);
    REQUIRE(WIFEXITED(wrong_argc.status));
    CHECK_EQ(WEXITSTATUS(wrong_argc.status), 2);
    CHECK(wrong_argc.out.empty());
    CHECK(wrong_argc.err.find("usage:") == 0u);

    const std::string fifo_path = directory + "/input.fifo";
    REQUIRE_EQ(mkfifo(fifo_path.c_str(), 0600), 0);
    const RunResult fifo = run_converter(g_executable, "server", fifo_path, fifo_path);
    REQUIRE(WIFEXITED(fifo.status));
    CHECK_EQ(WEXITSTATUS(fifo.status), 1);
    CHECK(fifo.out.empty());
}

TEST(nginx_convert, rejects_oversized_input_before_conversion) {
    const std::string directory = make_temp_dir();
    REQUIRE_FALSE(directory.empty());
    const std::string path = directory + "/large.conf";
    std::string oversized(1024u * 1024u + 1u, '#');
    oversized.back() = '\n';
    REQUIRE(write_file(path, oversized));
    const RunResult result = run_converter(g_executable, "server", path, path);
    REQUIRE(WIFEXITED(result.status));
    CHECK_EQ(WEXITSTATUS(result.status), 1);
    CHECK(result.out.empty());
    CHECK(result.err.find("1 MiB") != std::string::npos);
}

TEST(nginx_convert, accepts_exact_one_mib_regular_input_with_valid_prefix) {
    const std::string directory = make_temp_dir();
    REQUIRE_FALSE(directory.empty());
    const std::string path = directory + "/boundary.conf";
    const std::string prefix =
        "server { listen 127.0.0.1:8080; location / { proxy_pass "
        "http://127.0.0.1:9000; } }\n";
    REQUIRE_LT(prefix.size(), 1024u * 1024u);
    std::string boundary = prefix;
    boundary.append(1024u * 1024u - boundary.size(), ' ');
    REQUIRE_EQ(boundary.size(), 1024u * 1024u);
    REQUIRE(write_file(path, boundary));
    const RunResult result = run_converter(g_executable, "server", path, path);
    REQUIRE(WIFEXITED(result.status));
    CHECK_EQ(WEXITSTATUS(result.status), 0);
    CHECK(result.err.empty());
    CHECK_FALSE(result.out.empty());
}

TEST(nginx_convert, rejects_embedded_nul_after_valid_prefix) {
    const std::string directory = make_temp_dir();
    REQUIRE_FALSE(directory.empty());
    const std::string path = directory + "/nul.conf";
    std::string source =
        "server { listen 127.0.0.1:8080; location / { proxy_pass "
        "http://127.0.0.1:9000; } }\n";
    source.push_back('\0');
    source += "server { listen 127.0.0.1:1; }\n";
    REQUIRE(write_file(path, source));
    const RunResult result = run_converter(g_executable, "server", path, path);
    REQUIRE(WIFEXITED(result.status));
    CHECK_EQ(WEXITSTATUS(result.status), 1);
    CHECK(result.out.empty());
    CHECK(result.err.find(path + ":") == 0u);
}

TEST(nginx_convert, rejects_directory_and_reports_long_filename_without_overread) {
    const std::string directory = make_temp_dir();
    REQUIRE_FALSE(directory.empty());
    const RunResult directory_result = run_converter(g_executable, "server", directory, directory);
    REQUIRE(WIFEXITED(directory_result.status));
    CHECK_EQ(WEXITSTATUS(directory_result.status), 1);
    CHECK(directory_result.out.empty());
    std::string nested = directory;
    while (nested.size() <= 300u) {
        nested += "/nested";
        REQUIRE_EQ(mkdir(nested.c_str(), 0700), 0);
    }
    const std::string long_path = nested + "/bad.conf";
    REQUIRE(write_file(long_path, "server {"));
    const RunResult long_result = run_converter(g_executable, "server", long_path, long_path);
    REQUIRE(WIFEXITED(long_result.status));
    CHECK_EQ(WEXITSTATUS(long_result.status), 1);
    CHECK(long_result.out.empty());
    CHECK(long_result.err.find(long_path + ":") == 0u);
}

TEST(nginx_convert, output_failures_are_reported_without_sigpipe_termination) {
    const std::string directory = make_temp_dir();
    REQUIRE_FALSE(directory.empty());
    const std::string path = directory + "/valid.conf";
    const std::string source =
        "server { listen 127.0.0.1:8080; location / { proxy_pass "
        "http://127.0.0.1:9000; } }\n";
    REQUIRE(write_file(path, source));
    const RunResult full = run_converter_to_file(g_executable, "server", path, "/dev/full");
    REQUIRE(WIFEXITED(full.status));
    CHECK_EQ(WEXITSTATUS(full.status), 1);
    CHECK(full.out.empty());
    CHECK(full.err.find("stdout:1:1: output write failed") == 0u);
    const RunResult broken = run_converter_to_broken_pipe(g_executable, "server", path);
    REQUIRE(WIFEXITED(broken.status));
    CHECK_EQ(WEXITSTATUS(broken.status), 1);
    CHECK(broken.err.find("stdout:1:1: output write failed") == 0u);
}

int main(int argc, char** argv) {
    if (argc != 2) return 2;
    g_executable = argv[1];
    return rut::test::run_all(1, argv);
}
