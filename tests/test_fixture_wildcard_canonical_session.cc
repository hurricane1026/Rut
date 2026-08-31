#include "fixture_anonymous_log_capture.h"
#include "fixture_executable_exec_handoff.h"
#include "fixture_executable_lease.h"
#include "fixture_wildcard_paused_child_lease.h"
#include "fixture_wildcard_source_lease.h"
#include "fixture_worker_protocol.h"
#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

namespace capture = rut::test::fixture_anonymous_log_capture;
namespace child = rut::test::fixture_wildcard_paused_child_lease;
namespace executable = rut::test::fixture_executable_lease;
namespace handoff = rut::test::fixture_executable_exec_handoff;
namespace protocol = rut::test::fixture_worker_protocol;
namespace source = rut::test::fixture_wildcard_source_lease;

namespace {

using Clock = std::chrono::steady_clock;
constexpr char kSourceBytes[] = "listen :0\nroute GET \"/\" { return 204 }\n";
constexpr char kSourceBasename[] = "canonical.rut";

bool check(bool condition, const char* message) {
    if (!condition) std::fprintf(stderr, "FAIL: %s (errno=%d)\n", message, errno);
    return condition;
}

Clock::time_point deadline(int milliseconds = 7000) {
    return Clock::now() + std::chrono::milliseconds(milliseconds);
}

struct PrivateDirectory {
    std::string path;
    int fd = -1;

    bool create() {
        std::array<char, 64> pattern{};
        std::snprintf(pattern.data(), pattern.size(), "/tmp/rut377-canonical-XXXXXX");
        char* const created = mkdtemp(pattern.data());
        if (created == nullptr) return false;
        path = created;
        if (chmod(path.c_str(), 0700) != 0) return false;
        fd = open(path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        return fd >= 0;
    }

    bool settle() {
        bool ok = true;
        if (fd >= 0) {
            ok = close(fd) == 0;
            fd = -1;
        }
        if (!path.empty()) {
            if (rmdir(path.c_str()) == 0)
                path.clear();
            else
                ok = false;
        }
        return ok;
    }

    ~PrivateDirectory() {
        if (fd >= 0) (void)close(fd);
        if (!path.empty()) (void)rmdir(path.c_str());
    }
};

struct OwnedFd {
    int value = -1;

    bool close_owned() {
        if (value < 0) return true;
        const int detached = value;
        value = -1;
        return close(detached) == 0;
    }

    ~OwnedFd() {
        if (value >= 0) (void)close(value);
    }
};

bool fd_snapshot(std::vector<int>& descriptors) {
    descriptors.clear();
    DIR* directory = opendir("/proc/self/fd");
    if (directory == nullptr) return false;
    const int own_fd = dirfd(directory);
    errno = 0;
    while (dirent* entry = readdir(directory)) {
        int value = -1;
        const char* const begin = entry->d_name;
        const char* const end = begin + std::char_traits<char>::length(begin);
        const auto [parsed_end, parse_error] = std::from_chars(begin, end, value, 10);
        if (parse_error == std::errc{} && parsed_end == end && value >= 0 && value != own_fd)
            descriptors.push_back(value);
        errno = 0;
    }
    const int read_error = errno;
    const bool closed = closedir(directory) == 0;
    if (read_error != 0 || !closed) return false;
    std::sort(descriptors.begin(), descriptors.end());
    return std::adjacent_find(descriptors.begin(), descriptors.end()) == descriptors.end();
}

bool child_snapshot(std::vector<pid_t>& children) {
    children.clear();
    std::string text;
    if (!protocol::read_file(
            "/proc/self/task/" + std::to_string(getpid()) + "/children", text, 65536))
        return false;
    const char* cursor = text.data();
    const char* const end = cursor + text.size();
    while (cursor != end) {
        while (cursor != end && (*cursor == ' ' || *cursor == '\n' || *cursor == '\t')) ++cursor;
        if (cursor == end) break;
        pid_t value = -1;
        const auto [parsed_end, parse_error] = std::from_chars(cursor, end, value, 10);
        if (parse_error != std::errc{} || parsed_end == cursor || value <= 0) return false;
        children.push_back(value);
        cursor = parsed_end;
    }
    std::sort(children.begin(), children.end());
    return std::adjacent_find(children.begin(), children.end()) == children.end();
}

bool canonical_executable(std::string& path) {
    std::array<char, PATH_MAX> resolved{};
    if (realpath(RUT_SERVER_BINARY, resolved.data()) == nullptr) return false;
    path = resolved.data();
    return !path.empty();
}

bool pidfd_live(int descriptor) {
    pollfd observed{descriptor, POLLIN | POLLERR | POLLHUP, 0};
    for (;;) {
        const int result = poll(&observed, 1, 0);
        if (result < 0 && errno == EINTR) continue;
        return result == 0 && observed.revents == 0;
    }
}

std::string encode_arguments(std::span<const std::string_view> arguments) {
    std::string encoded;
    for (const std::string_view argument : arguments) {
        encoded.append(argument.data(), argument.size());
        encoded.push_back('\0');
    }
    return encoded;
}

struct StartupEvidence {
    std::string backend;
    unsigned int port = 0u;
};

bool parse_startup_bytes(const std::string& bytes,
                         const std::string& exact_source_path,
                         StartupEvidence& evidence) {
    evidence = {};
    if (bytes.empty() || bytes.size() > capture::kMaxCaptureBytes || bytes.back() != '\n' ||
        bytes.find('\0') != std::string::npos ||
        static_cast<std::size_t>(std::count(bytes.begin(), bytes.end(), '\n')) != 3u ||
        bytes.find("TLS") != std::string::npos || bytes.find("Failed") != std::string::npos ||
        bytes.find("Fatal") != std::string::npos)
        return false;

    const std::size_t first_end = bytes.find('\n');
    const std::size_t second_end = bytes.find('\n', first_end + 1u);
    const std::size_t third_end = bytes.find('\n', second_end + 1u);
    if (first_end == std::string::npos || second_end == std::string::npos ||
        third_end != bytes.size() - 1u)
        return false;
    const std::string loaded = bytes.substr(0u, first_end);
    const std::string backend = bytes.substr(first_end + 1u, second_end - first_end - 1u);
    const std::string listening = bytes.substr(second_end + 1u, third_end - second_end - 1u);
    if (loaded != "Loaded program: " + exact_source_path + " (opt O2)" ||
        (backend != "Backend: epoll" && backend != "Backend: io_uring"))
        return false;

    constexpr std::string_view prefix = "Listening on port ";
    constexpr std::string_view suffix = " with 1 shard(s)";
    if (!listening.starts_with(prefix) || !listening.ends_with(suffix) ||
        listening.size() <= prefix.size() + suffix.size())
        return false;
    const std::string_view port_text(listening.data() + prefix.size(),
                                     listening.size() - prefix.size() - suffix.size());
    unsigned int port = 0u;
    const auto [parsed_end, parse_error] =
        std::from_chars(port_text.data(), port_text.data() + port_text.size(), port, 10);
    if (parse_error != std::errc{} || parsed_end != port_text.data() + port_text.size() ||
        port == 0u || port > 65535u || std::to_string(port) != port_text)
        return false;
    evidence.backend = backend;
    evidence.port = port;
    return true;
}

bool wait_for_strict_startup(capture::AnonymousLogCapture& output,
                             const std::string& source_path,
                             Clock::time_point until,
                             std::string& bytes,
                             StartupEvidence& evidence) {
    capture::Diagnostic diagnostic;
    for (;;) {
        if (!output.snapshot(bytes, diagnostic)) return false;
        if (parse_startup_bytes(bytes, source_path, evidence)) return true;
        if (bytes.size() >= output.max_bytes() || Clock::now() >= until) return false;
        (void)poll(nullptr, 0, 5);
    }
}

bool evidence_mutations_rejected(const std::string& canonical,
                                 const std::string& source_path,
                                 const StartupEvidence& evidence) {
    StartupEvidence parsed;
    std::vector<std::string> mutations;

    std::string wrong_path = canonical;
    wrong_path.replace(wrong_path.find(source_path), source_path.size(), source_path + ".wrong");
    mutations.push_back(wrong_path);

    std::string wrong_opt = canonical;
    wrong_opt.replace(wrong_opt.find("(opt O2)"), 8u, "(opt O1)");
    mutations.push_back(wrong_opt);

    std::string wrong_backend = canonical;
    wrong_backend.replace(
        wrong_backend.find(evidence.backend), evidence.backend.size(), "Backend: epoll (TLS)");
    mutations.push_back(wrong_backend);

    const std::size_t first_end = canonical.find('\n');
    const std::size_t second_end = canonical.find('\n', first_end + 1u);
    mutations.push_back(canonical.substr(first_end + 1u, second_end - first_end) +
                        canonical.substr(0u, first_end + 1u) + canonical.substr(second_end + 1u));

    mutations.push_back(canonical.substr(0u, canonical.size() - 1u));
    mutations.push_back(canonical + "extra\n");
    mutations.push_back(canonical + canonical.substr(first_end + 1u, second_end - first_end));

    std::string embedded_nul = canonical;
    embedded_nul[embedded_nul.size() / 2u] = '\0';
    mutations.push_back(embedded_nul);
    mutations.push_back(std::string(capture::kMaxCaptureBytes + 1u, 'x'));

    const std::string port = std::to_string(evidence.port);
    const std::size_t port_offset = canonical.find("Listening on port ") + 18u;
    std::string zero_port = canonical;
    zero_port.replace(port_offset, port.size(), "0");
    mutations.push_back(zero_port);
    std::string overflow_port = canonical;
    overflow_port.replace(port_offset, port.size(), "65536");
    mutations.push_back(overflow_port);
    std::string noncanonical_port = canonical;
    noncanonical_port.replace(port_offset, port.size(), "0" + port);
    mutations.push_back(noncanonical_port);

    return std::all_of(mutations.begin(), mutations.end(), [&](const std::string& mutation) {
        return mutation != canonical && !parse_startup_bytes(mutation, source_path, parsed);
    });
}

bool run_one_canonical_session() {
    std::vector<int> baseline_fds;
    std::vector<pid_t> baseline_children;
    if (!check(fd_snapshot(baseline_fds), "baseline FD snapshot") ||
        !check(child_snapshot(baseline_children), "baseline direct-child snapshot"))
        return false;

    // Declaration order is the reverse of defensive destruction order:
    // child -> handoff -> null -> capture -> executable -> source -> directory.
    PrivateDirectory directory;
    source::WildcardAttemptSourceLease source_lease;
    executable::ExecutableLease executable_lease;
    capture::AnonymousLogCapture output;
    OwnedFd null_input;
    handoff::ExecutableExecHandoffLease handoff_lease;
    child::PausedChildLease child_lease;

    source::Diagnostic source_diagnostic;
    executable::Diagnostic executable_diagnostic;
    capture::Diagnostic capture_diagnostic;
    handoff::Diagnostic handoff_diagnostic;
    child::Diagnostic child_diagnostic;
    std::string executable_path;
    std::string source_path;
    std::string directory_path;
    const auto until = deadline();
    bool ok = true;

    if (!check(directory.create(), "private directory creation") ||
        !check(source::WildcardAttemptSourceLease::create_exact_bytes(directory.fd,
                                                                      directory.path,
                                                                      kSourceBasename,
                                                                      kSourceBytes,
                                                                      source_lease,
                                                                      source_diagnostic),
               "exact ordinary-RUT source lease") ||
        !check(canonical_executable(executable_path), "canonical public rut path") ||
        !check(executable::ExecutableLease::create(
                   executable_path, executable_lease, executable_diagnostic),
               "public rut executable lease") ||
        !check(capture::AnonymousLogCapture::create(
                   capture::kMaxCaptureBytes, output, capture_diagnostic),
               "bounded startup capture"))
        return false;
    source_path = source_lease.path();
    directory_path = directory.path;
    null_input.value = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (!check(null_input.value >= 0, "borrowed /dev/null") ||
        !check(handoff::ExecutableExecHandoffLease::create(
                   executable_lease, handoff_lease, handoff_diagnostic),
               "executable handoff"))
        return false;

    const std::array<std::string_view, 9> arguments = {
        executable_path, source_path, "--shards", "1", "--no-pin", "--drain", "0", "--opt", "2"};
    const std::string expected_cmdline = encode_arguments(arguments);
    const bool no_access_log_configuration =
        std::string_view{kSourceBytes}.find("access_log") == std::string_view::npos &&
        std::none_of(arguments.begin(), arguments.end(), [](std::string_view argument) {
            return argument.find("access-log") != std::string_view::npos;
        });
    child::ChildDescriptorPlan plan;
    if (!check(no_access_log_configuration, "source/argv unexpectedly configure an access log") ||
        !check(
            handoff_lease.make_child_plan_with_arguments(
                null_input.value, output.descriptor(), false, arguments, plan, handoff_diagnostic),
            "exact nine-argument child plan") ||
        !check(child::PausedChildLease::create_prepared(until, plan, child_lease, child_diagnostic),
               "prepared public rut child"))
        return false;

    const pid_t launched_pid = child_lease.child_pid();
    const auto settlement = child_lease.settlement_receipt();
    handoff::ExecObservation observation;
    const bool exec_observed =
        handoff_lease.release_and_observe(
            executable_lease, child_lease, until, observation, handoff_diagnostic) &&
        observation.outcome == handoff::ExecOutcome::ExecObservedLive &&
        observation.first.cmdline == expected_cmdline &&
        observation.second.cmdline == expected_cmdline;
    ok = check(exec_observed, "public rut exec observation") && ok;

    std::string readiness_bytes;
    StartupEvidence readiness_evidence;
    bool readiness = false;
    if (exec_observed) {
        std::string candidate;
        StartupEvidence candidate_evidence;
        if (wait_for_strict_startup(output, source_path, until, candidate, candidate_evidence)) {
            protocol::ProcIdentity first_proc;
            protocol::ProcIdentity second_proc;
            capture::Diagnostic first_snapshot_diagnostic;
            capture::Diagnostic second_snapshot_diagnostic;
            std::string first_snapshot;
            std::string second_snapshot;
            StartupEvidence first_evidence;
            StartupEvidence second_evidence;
            readiness = pidfd_live(child_lease.observation_pidfd()) &&
                        protocol::read_proc(launched_pid, first_proc) &&
                        protocol::same_process_identity(observation.second, first_proc) &&
                        executable_lease.revalidate(executable_diagnostic) &&
                        source_lease.revalidate(source_diagnostic) &&
                        output.snapshot(first_snapshot, first_snapshot_diagnostic) &&
                        parse_startup_bytes(first_snapshot, source_path, first_evidence) &&
                        protocol::read_proc(launched_pid, second_proc) &&
                        protocol::same_process_identity(first_proc, second_proc) &&
                        pidfd_live(child_lease.observation_pidfd()) &&
                        executable_lease.revalidate(executable_diagnostic) &&
                        source_lease.revalidate(source_diagnostic) &&
                        output.snapshot(second_snapshot, second_snapshot_diagnostic) &&
                        parse_startup_bytes(second_snapshot, source_path, second_evidence) &&
                        first_snapshot == second_snapshot && first_snapshot == candidate &&
                        first_evidence.backend == second_evidence.backend &&
                        first_evidence.port == second_evidence.port;
            if (readiness) {
                readiness_bytes = first_snapshot;
                readiness_evidence = first_evidence;
            }
        }
    }
    ok = check(readiness, "strict bracketed startup readiness") && ok;
    if (readiness)
        ok = check(evidence_mutations_rejected(readiness_bytes, source_path, readiness_evidence),
                   "copied startup evidence mutation rejection") &&
             ok;

    // Stop authority is exclusively PausedChildLease::cleanup(). Capture is
    // never sealed until the retained settlement proves terminal+reaped.
    const bool child_cleaned = child_lease.active() && child_lease.cleanup(until, child_diagnostic);
    const bool exact_settlement =
        child_cleaned && settlement && settlement->child_pid == launched_pid &&
        settlement->terminal && settlement->reaped && settlement->error_number == 0 &&
        WIFSIGNALED(settlement->wait_status) && WTERMSIG(settlement->wait_status) == SIGKILL;
    ok = check(exact_settlement, "SIGKILL terminal+reaped child settlement") && ok;

    const bool handoff_closed = exact_settlement && handoff_lease.close(handoff_diagnostic);
    ok = check(handoff_closed, "post-reap handoff settlement") && ok;
    const bool null_closed = handoff_closed && null_input.close_owned();
    ok = check(null_closed, "borrowed /dev/null parent close") && ok;

    bool capture_closed = false;
    if (exact_settlement) {
        std::string final_bytes;
        capture::Diagnostic settle_diagnostic;
        capture::Diagnostic snapshot_diagnostic;
        capture::Diagnostic close_diagnostic;
        const bool settled = output.settle(settle_diagnostic);
        const bool final_snapshot = settled && output.snapshot(final_bytes, snapshot_diagnostic);
        const bool final_exact = final_snapshot && readiness && final_bytes == readiness_bytes &&
                                 parse_startup_bytes(final_bytes, source_path, readiness_evidence);
        capture_closed = output.close(close_diagnostic);
        ok = check(settled && final_snapshot && final_exact && capture_closed,
                   "sealed final startup capture") &&
             ok;
    } else {
        ok = check(false, "capture settlement withheld after uncertain child cleanup") && ok;
    }

    const bool executable_closed = capture_closed && executable_lease.close(executable_diagnostic);
    ok = check(executable_closed, "public rut executable settlement") && ok;
    const bool source_removed = executable_closed && source_lease.remove(source_diagnostic);
    ok = check(source_removed, "ordinary-RUT source removal") && ok;
    if (source_removed)
        ok = check(access(source_path.c_str(), F_OK) != 0 && errno == ENOENT,
                   "source path residue") &&
             ok;
    const bool directory_removed = source_removed && directory.settle();
    ok = check(directory_removed, "private directory settlement") && ok;
    if (directory_removed)
        ok = check(access(directory_path.c_str(), F_OK) != 0 && errno == ENOENT,
                   "private directory residue") &&
             ok;

    std::vector<int> final_fds;
    std::vector<pid_t> final_children;
    int wait_status = 0;
    errno = 0;
    const bool no_waitable_child = waitpid(-1, &wait_status, WNOHANG) == -1 && errno == ECHILD;
    ok = check(protocol::target_gone_or_reused(observation.second), "public rut process residue") &&
         ok;
    ok = check(no_waitable_child, "waitable direct-child residue") && ok;
    ok = check(fd_snapshot(final_fds) && final_fds == baseline_fds, "owned FD residue") && ok;
    ok = check(child_snapshot(final_children) && final_children == baseline_children,
               "direct-child residue") &&
         ok;
    return ok;
}

}  // namespace

int main() {
    if (!run_one_canonical_session()) return 1;
    std::puts("PASS: #377 one fresh canonical public RUT session");
    return 0;
}
