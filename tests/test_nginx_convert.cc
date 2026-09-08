#include "rut/nginx/converter.h"
#include "rut/nginx/parser.h"
#include "test.h"
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
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

std::string read_pipe(int fd) {
    std::string result;
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

RunResult run_converter(const char* executable,
                        const char* format,
                        const std::string& input,
                        const std::string& path) {
    RunResult result;
    int output_pipe[2]{};
    int error_pipe[2]{};
    if (pipe(output_pipe) != 0 || pipe(error_pipe) != 0) return result;
    const pid_t child = fork();
    if (child == 0) {
        dup2(output_pipe[1], STDOUT_FILENO);
        dup2(error_pipe[1], STDERR_FILENO);
        close(output_pipe[0]);
        close(output_pipe[1]);
        close(error_pipe[0]);
        close(error_pipe[1]);
        execl(executable, executable, "--format", format, input.c_str(), nullptr);
        _exit(127);
    }
    close(output_pipe[1]);
    close(error_pipe[1]);
    if (child < 0) {
        close(output_pipe[0]);
        close(error_pipe[0]);
        return result;
    }
    result.out = read_pipe(output_pipe[0]);
    result.err = read_pipe(error_pipe[0]);
    waitpid(child, &result.status, 0);
    (void)path;
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

    const RunResult missing =
        run_converter(g_executable, "server", std::string{}, directory + "/missing.conf");
    REQUIRE(WIFEXITED(missing.status));
    CHECK_EQ(WEXITSTATUS(missing.status), 1);
    CHECK(missing.out.empty());

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

int main(int argc, char** argv) {
    if (argc != 2) return 2;
    g_executable = argv[1];
    return rut::test::run_all(1, argv);
}
