#include "rut/runtime/access_log_startup.h"
#include "test.h"
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

using namespace rut;

namespace {

AccessLogSinkSpec source_spec(const std::string& path) {
    AccessLogSinkSpec spec{};
    spec.present = true;
    spec.format = AccessLogFormatProfile::DownstreamRequestBytesLine;
    spec.publication = AccessLogPublicationProfile::LiveEachRecord;
    spec.path_len = static_cast<u16>(path.size());
    for (u32 i = 0; i < spec.path_len; i++) spec.path[i] = path[i];
    spec.path[spec.path_len] = '\0';
    return spec;
}

std::string make_temp_dir(const char* pattern) {
    char path[128]{};
    u32 i = 0;
    for (; pattern[i] != '\0'; i++) path[i] = pattern[i];
    path[i] = '\0';
    char* created = mkdtemp(path);
    return created == nullptr ? std::string{} : std::string(created);
}

bool write_file(const std::string& path, const std::string& bytes, mode_t mode = 0600) {
    const i32 fd = open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode);
    if (fd < 0) return false;
    u32 written = 0;
    while (written < bytes.size()) {
        const ssize_t n = write(fd, bytes.data() + written, bytes.size() - written);
        if (n <= 0) {
            close(fd);
            return false;
        }
        written += static_cast<u32>(n);
    }
    return close(fd) == 0;
}

std::string read_file(const std::string& path) {
    std::ifstream input(path, std::ios::binary);
    return std::string(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
}

i32 open_fd_count() {
    DIR* dir = opendir("/proc/self/fd");
    if (dir == nullptr) return -1;
    i32 count = 0;
    while (dirent* entry = readdir(dir)) {
        if (entry->d_name[0] == '.' &&
            (entry->d_name[1] == '\0' || (entry->d_name[1] == '.' && entry->d_name[2] == '\0')))
            continue;
        count++;
    }
    closedir(dir);
    return count;
}

}  // namespace

TEST(access_log_startup, resolution_preserves_legacy_absence_semantics) {
    AccessLogStartupInputs inputs{};
    inputs.cli_level = 3;
    auto disabled = resolve_access_log_startup(inputs);
    REQUIRE(disabled);
    CHECK(disabled->mode == AccessLogStartupMode::Disabled);
    CHECK_EQ(disabled->legacy_path, nullptr);

    inputs.cli_compression_present = true;
    inputs.cli_compression = true;
    inputs.cli_level_present = true;
    inputs.environment_compression_present = true;
    auto still_disabled = resolve_access_log_startup(inputs);
    REQUIRE(still_disabled);
    CHECK(still_disabled->mode == AccessLogStartupMode::Disabled);
    CHECK_EQ(still_disabled->legacy_path, nullptr);

    char path[] = "/tmp/legacy-access.log";
    inputs.cli_path_present = true;
    inputs.cli_path = path;
    inputs.cli_compression = true;
    inputs.cli_level = 4;
    auto legacy = resolve_access_log_startup(inputs);
    REQUIRE(legacy);
    CHECK(legacy->mode == AccessLogStartupMode::LegacyCli);
    CHECK_EQ(legacy->legacy_path, path);
    CHECK(legacy->legacy_compression);
    CHECK_EQ(legacy->legacy_level, 4);
    CHECK_FALSE(legacy->source_live.present);
}

TEST(access_log_startup, source_resolution_is_owned_and_every_explicit_control_conflicts) {
    AccessLogStartupInputs inputs{};
    inputs.source = source_spec("/tmp/source-access.log");
    inputs.cli_level = 3;
    auto source = resolve_access_log_startup(inputs);
    REQUIRE(source);
    CHECK(source->mode == AccessLogStartupMode::SourceLive);
    CHECK(access_log_sink_spec_valid(source->source_live));
    CHECK_EQ(std::string(source->source_live.path, source->source_live.path_len),
             "/tmp/source-access.log");
    inputs.source.path[5] = 'X';
    CHECK_EQ(std::string(source->source_live.path, source->source_live.path_len),
             "/tmp/source-access.log");

    inputs.source = source_spec("/tmp/source-access.log");
    inputs.cli_path_present = true;
    inputs.cli_path = inputs.source.path;
    auto equal_path = resolve_access_log_startup(inputs);
    REQUIRE_FALSE(equal_path);
    CHECK(equal_path.error() == AccessLogStartupResolutionError::ConflictingCliPath);

    inputs.cli_path_present = false;
    inputs.cli_path = nullptr;
    inputs.cli_compression_present = true;
    inputs.cli_compression = false;
    auto default_compression = resolve_access_log_startup(inputs);
    REQUIRE_FALSE(default_compression);
    CHECK(default_compression.error() ==
          AccessLogStartupResolutionError::ConflictingCliCompression);

    inputs.cli_compression_present = false;
    inputs.cli_level_present = true;
    inputs.cli_level = 3;
    auto default_level = resolve_access_log_startup(inputs);
    REQUIRE_FALSE(default_level);
    CHECK(default_level.error() == AccessLogStartupResolutionError::ConflictingCliLevel);

    inputs.cli_level_present = false;
    inputs.environment_compression_present = true;
    auto environment = resolve_access_log_startup(inputs);
    REQUIRE_FALSE(environment);
    CHECK(environment.error() ==
          AccessLogStartupResolutionError::ConflictingEnvironmentCompression);
}

TEST(access_log_startup, forged_absent_and_present_source_specs_fail_closed) {
    AccessLogStartupInputs inputs{};
    inputs.source.path[255] = 'x';
    auto forged_absent = resolve_access_log_startup(inputs);
    REQUIRE_FALSE(forged_absent);
    CHECK(forged_absent.error() == AccessLogStartupResolutionError::InvalidSourceSpec);

    inputs.source = source_spec("/tmp/source-access.log");
    inputs.source.format = AccessLogFormatProfile::None;
    auto forged_format = resolve_access_log_startup(inputs);
    REQUIRE_FALSE(forged_format);
    CHECK(forged_format.error() == AccessLogStartupResolutionError::InvalidSourceSpec);

    inputs.source = source_spec("/tmp/source-access.log");
    inputs.source.publication = static_cast<AccessLogPublicationProfile>(255u);
    auto forged_publication = resolve_access_log_startup(inputs);
    REQUIRE_FALSE(forged_publication);
    CHECK(forged_publication.error() == AccessLogStartupResolutionError::InvalidSourceSpec);

    inputs.source = source_spec("/tmp/source-access.log");
    inputs.source.path[inputs.source.path_len + 1u] = 'x';
    auto forged_tail = resolve_access_log_startup(inputs);
    REQUIRE_FALSE(forged_tail);
    CHECK(forged_tail.error() == AccessLogStartupResolutionError::InvalidSourceSpec);

    inputs = AccessLogStartupInputs{};
    inputs.cli_path_present = true;
    auto missing_cli_pointer = resolve_access_log_startup(inputs);
    REQUIRE_FALSE(missing_cli_pointer);
    CHECK(missing_cli_pointer.error() == AccessLogStartupResolutionError::InvalidCliPath);
}

TEST(access_log_startup, source_opener_creates_appends_and_owns_exact_descriptor_flags) {
    const std::string dir = make_temp_dir("/tmp/rut-access-log-startup-open-XXXXXX");
    REQUIRE_FALSE(dir.empty());
    const std::string path = dir + "/access.log";
    REQUIRE(write_file(path, "seed"));
    const i32 before = open_fd_count();
    REQUIRE_GE(before, 0);

    auto opened = open_source_access_log(source_spec(path));
    REQUIRE(opened);
    REQUIRE(opened->get() >= 0);
    const i32 descriptor_flags = fcntl(opened->get(), F_GETFD);
    const i32 status_flags = fcntl(opened->get(), F_GETFL);
    REQUIRE_GE(descriptor_flags, 0);
    REQUIRE_GE(status_flags, 0);
    CHECK((descriptor_flags & FD_CLOEXEC) != 0);
    CHECK_EQ(status_flags & O_ACCMODE, O_WRONLY);
    CHECK((status_flags & O_APPEND) != 0);
    CHECK((status_flags & O_NONBLOCK) != 0);
    REQUIRE_EQ(write(opened->get(), "-next", 5), 5);

    SourceAccessLogFd moved(static_cast<SourceAccessLogFd&&>(opened.value()));
    CHECK_EQ(opened->get(), -1);
    REQUIRE(moved.get() >= 0);
    moved.reset();
    CHECK_EQ(moved.get(), -1);
    CHECK_EQ(read_file(path), "seed-next");
    CHECK_EQ(open_fd_count(), before);

    const std::string created_path = dir + "/created.log";
    const mode_t current_umask = umask(0);
    umask(current_umask);
    auto created = open_source_access_log(source_spec(created_path));
    REQUIRE(created);
    struct stat created_status{};
    REQUIRE_EQ(fstat(created->get(), &created_status), 0);
    CHECK_EQ(created_status.st_mode & 0777u, 0644u & ~current_umask);
    created->reset();
    CHECK_EQ(open_fd_count(), before);
    std::filesystem::remove_all(dir);
}

TEST(access_log_startup, source_opener_rejects_non_regular_and_path_failures_without_fd_leaks) {
    const std::string dir = make_temp_dir("/tmp/rut-access-log-startup-reject-XXXXXX");
    REQUIRE_FALSE(dir.empty());
    const i32 baseline = open_fd_count();
    REQUIRE_GE(baseline, 0);
    const auto check_open_failure = [&](const std::string& path) {
        auto result = open_source_access_log(source_spec(path));
        REQUIRE_FALSE(result);
        CHECK(result.error().kind == SourceAccessLogOpenErrorKind::OpenFailed);
        CHECK_GT(result.error().system_error, 0);
        CHECK_EQ(open_fd_count(), baseline);
    };

    const std::string regular = dir + "/regular.log";
    REQUIRE(write_file(regular, "retained"));
    const std::string symlink_path = dir + "/final-link.log";
    REQUIRE_EQ(symlink(regular.c_str(), symlink_path.c_str()), 0);
    check_open_failure(symlink_path);
    CHECK_EQ(read_file(regular), "retained");

    const std::string fifo_path = dir + "/sink.fifo";
    REQUIRE_EQ(mkfifo(fifo_path.c_str(), 0600), 0);
    check_open_failure(fifo_path);
    check_open_failure(dir);
    check_open_failure(dir + "/missing/access.log");

    auto device = open_source_access_log(source_spec("/dev/null"));
    REQUIRE_FALSE(device);
    CHECK(device.error().kind == SourceAccessLogOpenErrorKind::NotRegularFile);
    CHECK_EQ(device.error().system_error, 0);
    CHECK_EQ(open_fd_count(), baseline);

    if (geteuid() != 0) {
        const std::string denied = dir + "/denied.log";
        REQUIRE(write_file(denied, "kept"));
        REQUIRE_EQ(chmod(denied.c_str(), 0000), 0);
        check_open_failure(denied);
        REQUIRE_EQ(chmod(denied.c_str(), 0600), 0);
        CHECK_EQ(read_file(denied), "kept");
    }

    AccessLogSinkSpec invalid = source_spec(regular);
    invalid.path[invalid.path_len + 1u] = 'x';
    auto invalid_result = open_source_access_log(invalid);
    REQUIRE_FALSE(invalid_result);
    CHECK(invalid_result.error().kind == SourceAccessLogOpenErrorKind::InvalidSpec);
    CHECK_EQ(invalid_result.error().system_error, 0);
    CHECK_EQ(open_fd_count(), baseline);
    std::filesystem::remove_all(dir);
}

#ifdef RUT_ACCESS_LOG_STARTUP_PROCESS_TEST
namespace {

struct ProcessResult {
    i32 status = 0;
    std::string output;
    bool status_valid = false;
    bool forced_kill = false;
    bool shutdown_signal_sent = false;
};

bool child_blocks_signal(pid_t child, i32 signal_number) {
    std::ifstream status("/proc/" + std::to_string(child) + "/status");
    std::string key;
    while (status >> key) {
        if (key != "SigBlk:") {
            std::string ignored;
            std::getline(status, ignored);
            continue;
        }
        unsigned long long mask = 0;
        status >> std::hex >> mask;
        const unsigned shift = static_cast<unsigned>(signal_number - 1);
        return shift < 64u && (mask & (1ull << shift)) != 0u;
    }
    return false;
}

ProcessResult run_rut(const std::vector<std::string>& args,
                      bool enable_env_compression = false,
                      bool terminate_after_listening = false) {
    i32 output_pipe[2];
    if (pipe(output_pipe) != 0) return {};
    const pid_t child = fork();
    if (child == 0) {
        close(output_pipe[0]);
        if (dup2(output_pipe[1], STDOUT_FILENO) < 0 || dup2(output_pipe[1], STDERR_FILENO) < 0)
            _exit(126);
        close(output_pipe[1]);
        if (enable_env_compression)
            setenv("RUE_ACCESS_LOG_COMPRESS", "1", 1);
        else
            unsetenv("RUE_ACCESS_LOG_COMPRESS");
        std::vector<char*> argv;
        argv.reserve(args.size() + 1u);
        for (const std::string& arg : args) argv.push_back(const_cast<char*>(arg.c_str()));
        argv.push_back(nullptr);
        execv(argv[0], argv.data());
        _exit(127);
    }
    if (child < 0) {
        close(output_pipe[0]);
        close(output_pipe[1]);
        return {};
    }
    close(output_pipe[1]);
    ProcessResult result{};
    const i32 old_flags = fcntl(output_pipe[0], F_GETFL);
    if (old_flags >= 0) (void)fcntl(output_pipe[0], F_SETFL, old_flags | O_NONBLOCK);
    char bytes[1024];
    bool reaped = false;
    bool termination_sent = false;
    for (u32 attempt = 0; attempt < 50u && !reaped; attempt++) {
        struct pollfd ready{output_pipe[0], POLLIN | POLLHUP, 0};
        (void)poll(&ready, 1, 100);
        for (;;) {
            const ssize_t n = read(output_pipe[0], bytes, sizeof(bytes));
            if (n > 0) {
                result.output.append(bytes, static_cast<size_t>(n));
                continue;
            }
            if (n < 0 && errno == EINTR) continue;
            break;
        }
        if (terminate_after_listening && !termination_sent &&
            result.output.find("Listening on") != std::string::npos &&
            child_blocks_signal(child, SIGTERM)) {
            if (kill(child, SIGTERM) == 0) {
                result.shutdown_signal_sent = true;
                termination_sent = true;
            }
        }
        const pid_t waited = waitpid(child, &result.status, WNOHANG);
        reaped = waited == child;
        if (reaped) result.status_valid = true;
        if (waited < 0 && errno != EINTR) break;
    }
    if (!reaped) {
        result.forced_kill = true;
        (void)kill(child, SIGKILL);
        reaped = waitpid(child, &result.status, 0) == child;
        if (reaped) result.status_valid = true;
    }
    for (;;) {
        const ssize_t n = read(output_pipe[0], bytes, sizeof(bytes));
        if (n > 0) {
            result.output.append(bytes, static_cast<size_t>(n));
            continue;
        }
        if (n < 0 && errno == EINTR) continue;
        break;
    }
    close(output_pipe[0]);
    return result;
}

#ifdef RUT_ACCESS_LOG_STARTUP_SOURCE_PROCESS_TEST
bool exited_one(const ProcessResult& result) {
    return result.status_valid && !result.forced_kill && WIFEXITED(result.status) &&
           WEXITSTATUS(result.status) == 1;
}

std::string source_with_sink(const std::string& sink) {
    return "accessLog { path: \"" + sink +
           "\", format: downstreamRequestBytes, publication: live }\n"
           "route GET \"/\" { return 204 }\n";
}
#endif

}  // namespace

#ifdef RUT_ACCESS_LOG_STARTUP_SOURCE_PROCESS_TEST
TEST(access_log_startup, public_main_validates_source_sink_then_gates_before_listening) {
    const std::string dir = make_temp_dir("/tmp/rut-access-log-startup-main-XXXXXX");
    REQUIRE_FALSE(dir.empty());
    const std::string program = dir + "/app.rut";
    const std::string sink = dir + "/source.log";
    REQUIRE(write_file(program, source_with_sink(sink)));

    ProcessResult result =
        run_rut({RUT_SERVER_BINARY, program, "--shards", "1", "--no-pin", "--drain", "0"});
    REQUIRE(exited_one(result));
    CHECK(result.output.find("source accessLog requires reliable live publication support") !=
          std::string::npos);
    CHECK(result.output.find("Listening on") == std::string::npos);
    CHECK(result.output.find("Backend:") == std::string::npos);
    struct stat status{};
    REQUIRE_EQ(stat(sink.c_str(), &status), 0);
    CHECK(S_ISREG(status.st_mode));
    CHECK_EQ(status.st_size, 0);

    const std::string missing_sink = dir + "/missing/source.log";
    REQUIRE(write_file(program, source_with_sink(missing_sink)));
    result = run_rut({RUT_SERVER_BINARY, program, "--shards", "1", "--no-pin", "--drain", "0"});
    REQUIRE(exited_one(result));
    CHECK(result.output.find("Failed to open source accessLog:") != std::string::npos);
    CHECK(result.output.find("open failed") != std::string::npos);
    CHECK(result.output.find("reliable live publication") == std::string::npos);
    CHECK(result.output.find("Listening on") == std::string::npos);
    std::filesystem::remove_all(dir);
}

TEST(access_log_startup, public_main_conflicts_before_creating_any_source_sink) {
    const std::string dir = make_temp_dir("/tmp/rut-access-log-startup-conflict-XXXXXX");
    REQUIRE_FALSE(dir.empty());
    const std::string program = dir + "/app.rut";
    struct Conflict {
        std::vector<std::string> options;
        const char* diagnostic;
        bool environment = false;
    };
    const Conflict conflicts[] = {
        {{"--access-log", "SAME"}, "Conflicting source accessLog and --access-log", false},
        {{"--access-log-compress"},
         "Conflicting source accessLog and --access-log-compress",
         false},
        {{"--access-log-level", "3"}, "Conflicting source accessLog and --access-log-level", false},
        {{}, "Conflicting source accessLog and RUE_ACCESS_LOG_COMPRESS=1", true},
    };
    for (u32 i = 0; i < sizeof(conflicts) / sizeof(conflicts[0]); i++) {
        const std::string sink = dir + "/source-" + std::to_string(i) + ".log";
        REQUIRE(write_file(program, source_with_sink(sink)));
        std::vector<std::string> command = {
            RUT_SERVER_BINARY, program, "--shards", "1", "--no-pin", "--drain", "0"};
        for (const std::string& option : conflicts[i].options)
            command.push_back(option == "SAME" ? sink : option);
        ProcessResult result = run_rut(command, conflicts[i].environment);
        REQUIRE(exited_one(result));
        CHECK(result.output.find(conflicts[i].diagnostic) != std::string::npos);
        CHECK(result.output.find("Listening on") == std::string::npos);
        CHECK_FALSE(std::filesystem::exists(sink));
    }
    std::filesystem::remove_all(dir);
}
#endif

TEST(access_log_startup, public_main_source_absence_keeps_legacy_cli_startup_path) {
    const std::string dir = make_temp_dir("/tmp/rut-access-log-startup-legacy-XXXXXX");
    REQUIRE_FALSE(dir.empty());
    i32 occupied_8080 = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    REQUIRE(occupied_8080 >= 0);
    struct sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    address.sin_port = htons(8080u);
    const i32 bind_result =
        bind(occupied_8080, reinterpret_cast<const struct sockaddr*>(&address), sizeof(address));
    if (bind_result == 0) {
        const i32 listen_result = listen(occupied_8080, 1);
        if (listen_result != 0) {
            close(occupied_8080);
            occupied_8080 = -1;
        }
        REQUIRE_EQ(listen_result, 0);
    } else {
        REQUIRE_EQ(errno, EADDRINUSE);
        close(occupied_8080);
        occupied_8080 = -1;
    }
    const std::string sink = dir + "/legacy.log";
    ProcessResult result = run_rut({RUT_SERVER_BINARY,
                                    "0",
                                    "--shards",
                                    "1",
                                    "--no-pin",
                                    "--drain",
                                    "0",
                                    "--access-log",
                                    sink,
                                    "--access-log-level",
                                    "3"},
                                   false,
                                   true);
    if (occupied_8080 >= 0) close(occupied_8080);
    CHECK(result.output.find("Listening on") != std::string::npos);
    CHECK(result.output.find("source accessLog") == std::string::npos);
    CHECK(result.output.find("Failed to open access log") == std::string::npos);
    struct stat status{};
    REQUIRE_EQ(stat(sink.c_str(), &status), 0);
    CHECK(S_ISREG(status.st_mode));
    CHECK(result.shutdown_signal_sent);
    CHECK_FALSE(result.forced_kill);
    REQUIRE(result.status_valid);
    CHECK(WIFEXITED(result.status));
    if (WIFEXITED(result.status)) CHECK_EQ(WEXITSTATUS(result.status), 0);
    std::filesystem::remove_all(dir);
}
#endif

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
