#include "fixture_anonymous_log_capture.h"
#include "fixture_executable_lease.h"
#include "fixture_private_directory_lease.h"
#include "fixture_public_rut_session_attempt.h"
#include "fixture_wildcard_source_lease.h"
#include "fixture_worker_protocol.h"
#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <dirent.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

namespace capture = rut::test::fixture_anonymous_log_capture;
namespace attempt = rut::test::fixture_public_rut_session_attempt;
namespace executable = rut::test::fixture_executable_lease;
namespace private_directory = rut::test::fixture_private_directory_lease;
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

bool path_absent_no_follow(const std::string& path) {
    struct stat status{};
    errno = 0;
    return lstat(path.c_str(), &status) != 0 && errno == ENOENT;
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

bool exact_empty_environment(pid_t pid) {
    std::string environment;
    return pid > 0 &&
           protocol::read_file("/proc/" + std::to_string(pid) + "/environ", environment, 1u) &&
           environment.empty();
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

    std::string source_path;
    std::string directory_path;
    std::shared_ptr<const private_directory::SettlementReceipt> directory_receipt;
    protocol::ProcIdentity launched_identity;
    bool launched_identity_known = false;
    bool ok = true;
    {
        // Reverse destruction: attempt -> executable -> source -> directory.
        private_directory::PrivateDirectoryLease directory;
        source::WildcardAttemptSourceLease source_lease;
        executable::ExecutableLease executable_lease;
        attempt::PublicRutAttemptLease public_attempt;
        directory_receipt = directory.settlement_receipt();

        private_directory::Diagnostic directory_diagnostic;
        source::Diagnostic source_diagnostic;
        executable::Diagnostic executable_diagnostic;
        attempt::Diagnostic attempt_diagnostic;
        std::string executable_path;
        const auto until = deadline();
        const auto record = [&](bool result, const char* message) {
            ok = check(result, message) && ok;
            return result;
        };

        const bool directory_created = record(
            private_directory::PrivateDirectoryLease::create(directory, directory_diagnostic),
            "private directory creation");
        directory_path = directory.path();
        const bool source_created =
            directory_created &&
            record(source::WildcardAttemptSourceLease::create_exact_bytes(directory.descriptor(),
                                                                          directory.path(),
                                                                          kSourceBasename,
                                                                          kSourceBytes,
                                                                          source_lease,
                                                                          source_diagnostic),
                   "exact ordinary-RUT source lease");
        if (source_created) source_path = source_lease.path();
        const bool executable_path_known =
            source_created &&
            record(canonical_executable(executable_path), "canonical public rut path");
        const bool executable_created =
            executable_path_known &&
            record(executable::ExecutableLease::create(
                       executable_path, executable_lease, executable_diagnostic),
                   "public rut executable lease");

        const std::array<std::string_view, 9> arguments = {executable_path,
                                                           source_path,
                                                           "--shards",
                                                           "1",
                                                           "--no-pin",
                                                           "--drain",
                                                           "0",
                                                           "--opt",
                                                           "2"};
        const std::string expected_cmdline = encode_arguments(arguments);
        const bool no_access_log_configuration =
            std::string_view{kSourceBytes}.find("accessLog") == std::string_view::npos &&
            std::none_of(arguments.begin(), arguments.end(), [](std::string_view argument) {
                return argument.find("access-log") != std::string_view::npos;
            });
        (void)record(no_access_log_configuration,
                     "source/argv unexpectedly configure an access log");
        attempt::HooksForTesting hooks;
        const bool prepared =
            executable_created && no_access_log_configuration &&
            record(public_attempt.prepare(
                       source_lease, executable_lease, arguments, until, hooks, attempt_diagnostic),
                   "reusable exact public-RUT attempt prepare");
        const pid_t launched_pid = prepared ? public_attempt.child_pid() : -1;
        const auto settlement = prepared ? public_attempt.settlement_receipt() : nullptr;

        bool exec_observed = false;
        if (prepared) {
            exec_observed = public_attempt.exec_and_observe(
                                source_lease, executable_lease, until, attempt_diagnostic) &&
                            public_attempt.state() == attempt::State::ExecObservedLive &&
                            public_attempt.exec_observation().first.cmdline == expected_cmdline &&
                            public_attempt.exec_observation().second.cmdline == expected_cmdline;
            (void)record(exec_observed, "public rut exec observation");
            if (exec_observed) {
                launched_identity = public_attempt.exec_observation().second;
                launched_identity_known = true;
            }
        }

        std::string readiness_bytes;
        StartupEvidence readiness_evidence;
        bool readiness = false;
        if (exec_observed) {
            for (;;) {
                std::string candidate;
                StartupEvidence candidate_evidence;
                if (!public_attempt.snapshot_capture(candidate, attempt_diagnostic)) break;
                if (parse_startup_bytes(candidate, source_path, candidate_evidence)) {
                    protocol::ProcIdentity first_proc;
                    protocol::ProcIdentity second_proc;
                    protocol::ProcIdentity third_proc;
                    std::string first_snapshot;
                    std::string second_snapshot;
                    StartupEvidence first_evidence;
                    StartupEvidence second_evidence;
                    readiness =
                        pidfd_live(public_attempt.observation_pidfd()) &&
                        protocol::read_proc(launched_pid, first_proc) &&
                        protocol::same_process_identity(public_attempt.exec_observation().second,
                                                        first_proc) &&
                        source_lease.revalidate(source_diagnostic) &&
                        executable_lease.revalidate(executable_diagnostic) &&
                        exact_empty_environment(launched_pid) &&
                        public_attempt.snapshot_capture(first_snapshot, attempt_diagnostic) &&
                        parse_startup_bytes(first_snapshot, source_path, first_evidence) &&
                        protocol::read_proc(launched_pid, second_proc) &&
                        protocol::same_process_identity(first_proc, second_proc) &&
                        pidfd_live(public_attempt.observation_pidfd()) &&
                        exact_empty_environment(launched_pid) &&
                        executable_lease.revalidate(executable_diagnostic) &&
                        source_lease.revalidate(source_diagnostic) &&
                        public_attempt.snapshot_capture(second_snapshot, attempt_diagnostic) &&
                        parse_startup_bytes(second_snapshot, source_path, second_evidence) &&
                        first_snapshot == second_snapshot && first_snapshot == candidate &&
                        first_evidence.backend == second_evidence.backend &&
                        first_evidence.port == second_evidence.port &&
                        source_lease.revalidate(source_diagnostic) &&
                        executable_lease.revalidate(executable_diagnostic) &&
                        exact_empty_environment(launched_pid) &&
                        protocol::read_proc(launched_pid, third_proc) &&
                        protocol::same_process_identity(second_proc, third_proc) &&
                        pidfd_live(public_attempt.observation_pidfd());
                    if (readiness) {
                        readiness_bytes = first_snapshot;
                        readiness_evidence = first_evidence;
                    }
                    break;
                }
                if (candidate.size() >= capture::kMaxCaptureBytes || Clock::now() >= until) break;
                (void)poll(nullptr, 0, 5);
            }
            (void)record(readiness, "strict post-bracketed startup readiness");
            if (readiness)
                (void)record(
                    evidence_mutations_rejected(readiness_bytes, source_path, readiness_evidence),
                    "copied startup evidence mutation rejection");
        }

        const bool exact_settlement =
            prepared &&
            record(public_attempt.settle_killed(SIGKILL, until, attempt_diagnostic),
                   "SIGKILL terminal+reaped attempt settlement") &&
            settlement && settlement->child_pid == launched_pid && settlement->terminal &&
            settlement->reaped && settlement->error_number == 0 &&
            WIFSIGNALED(settlement->wait_status) && WTERMSIG(settlement->wait_status) == SIGKILL;
        if (exact_settlement) {
            StartupEvidence final_evidence;
            (void)record(
                public_attempt.sealed_capture_bytes() == readiness_bytes &&
                    parse_startup_bytes(
                        public_attempt.sealed_capture_bytes(), source_path, final_evidence) &&
                    final_evidence.backend == readiness_evidence.backend &&
                    final_evidence.port == readiness_evidence.port,
                "sealed final startup evidence");
            (void)record(public_attempt.close_evidence(attempt_diagnostic),
                         "startup capture evidence close");
            if (executable_created)
                (void)record(executable_lease.close(executable_diagnostic),
                             "public rut executable settlement");
            if (source_created)
                (void)record(source_lease.remove(source_diagnostic), "ordinary-RUT source removal");
            if (directory_created)
                (void)record(directory.settle(directory_diagnostic),
                             "private directory settlement");
        } else {
            (void)record(false, "settlement retained after uncertain attempt cleanup");
        }
    }

    std::vector<int> final_fds;
    std::vector<pid_t> final_children;
    if (launched_identity_known)
        ok = check(protocol::target_gone_or_reused(launched_identity),
                   "exact public rut process residue") &&
             ok;
    if (!source_path.empty())
        ok = check(path_absent_no_follow(source_path),
                   "source path residue after fallback cleanup") &&
             ok;
    if (!directory_path.empty())
        ok = check(path_absent_no_follow(directory_path),
                   "private directory residue after fallback cleanup") &&
             ok;
    if (directory_receipt)
        ok =
            check(directory_receipt->attempted && directory_receipt->object_removed &&
                      directory_receipt->namespace_synced && directory_receipt->descriptor_closed &&
                      directory_receipt->settlement_complete &&
                      directory_receipt->path == directory_path &&
                      !directory_receipt->original_basename.empty() &&
                      directory_receipt->original_residue == private_directory::Residue::Absent &&
                      directory_receipt->candidate_residue == private_directory::Residue::Absent &&
                      directory_receipt->state == private_directory::State::Removed,
                  "private directory retained settlement receipt") &&
            ok;
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
