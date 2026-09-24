#include "fixtures/envoy_milestone_s.inc"
#include "rut/envoy/converter.h"
#include "rut/envoy/parser.h"
#include "test.h"
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <string>
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
                  to_string(parsed.value().cluster.connect_timeout.text) +
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
    // PR3 shipped `request_envoy_h1` and PR4 shipped `response_envoy_h1`, so
    // the shipped CLI now clears checks 4 and 5 (host preserve + lowercase
    // request headers; upstream header order) and fails closed one check
    // later, at check 6 (local reply layout), located at the route_config span.
    const TempDir temp_dir;
    REQUIRE(temp_dir.ok());
    const std::string& directory = temp_dir.path();
    const std::string text = milestone_s_json();
    const std::string path = directory + "/milestone.json";
    REQUIRE(write_file(path, text));

    static envoy::JsonDocument doc;
    auto parsed = envoy::parse_bootstrap_json(str(text), doc);
    REQUIRE(parsed);
    const Span span = parsed.value().listener.filter_chain.hcm.route_config.span;

    const RunResult result = run_converter(g_executable, path);
    REQUIRE(WIFEXITED(result.status));
    CHECK_EQ(WEXITSTATUS(result.status), 1);
    CHECK(result.out.empty());
    const std::string expected_prefix = expected_location(path, span);
    CHECK_EQ(result.err.compare(0, expected_prefix.size(), expected_prefix), 0);
    CHECK(result.err.find("local_response/failure_policy layout") != std::string::npos);
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

    // PR #692 round-10 review: a zeroed `cluster.connect_timeout` must not
    // lower successfully. The parser requires a strictly positive value
    // (`parse_duration(..., allow_zero=false)`), and Envoy itself rejects a
    // zero `connect_timeout` at startup, but the emitted RUT program never
    // reads this field so nothing else would catch the forgery.
    envoy::Bootstrap zero_connect_timeout = parsed.value();
    zero_connect_timeout.cluster.connect_timeout.milliseconds = 0;
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

    // PR #692 round-12 review: an overlong `action.cluster` (paired with an
    // equally overlong, still-equal `cluster.name`, so the prior
    // non-empty/equality check alone still passes) must not lower
    // successfully. `name_string` (src/envoy/parser.cc:179-185) rejects
    // every name over `kMaxEnvoyNameLen` during parsing, but nothing before
    // this fix re-enforced that bound at lowering time.
    const std::string overlong_name(static_cast<size_t>(envoy::kMaxEnvoyNameLen) + 1u, 'a');
    envoy::Bootstrap overlong_cluster_names = parsed.value();
    overlong_cluster_names.listener.filter_chain.hcm.route_config.virtual_host.route.action
        .cluster = str(overlong_name);
    overlong_cluster_names.cluster.name = str(overlong_name);
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

    // PR #692 round-12 review: presence of
    // `cluster.load_assignment_name_present` is not proof that the
    // *current* `cluster.name`/`action.cluster` still match what
    // `parse_bootstrap_json` validated `load_assignment.cluster_name`
    // against. Renaming both `action.cluster` and `cluster.name` to the
    // same new string (so the equality check between them still passes)
    // while leaving the presence bit true and `load_assignment_name`
    // holding the stale, parsed "backend" value must not lower successfully.
    envoy::Bootstrap renamed_cluster_stale_load_assignment = parsed.value();
    renamed_cluster_stale_load_assignment.listener.filter_chain.hcm.route_config.virtual_host.route
        .action.cluster = lit_str("renamed");
    renamed_cluster_stale_load_assignment.cluster.name = lit_str("renamed");
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
