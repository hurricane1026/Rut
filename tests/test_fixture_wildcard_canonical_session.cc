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
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/fs.h>
#include <poll.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/syscall.h>
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
    struct Identity {
        dev_t device = 0;
        ino_t inode = 0;
        mode_t mode = 0;
        uid_t uid = static_cast<uid_t>(-1);
        gid_t gid = static_cast<gid_t>(-1);
    };

    std::string path;
    std::string basename;
    int parent_fd = -1;
    int fd = -1;
    Identity identity;
    bool active = false;

    static Identity make_identity(const struct stat& status) {
        return {status.st_dev, status.st_ino, status.st_mode, status.st_uid, status.st_gid};
    }

    static bool same_identity(const struct stat& status, const Identity& expected) {
        return S_ISDIR(status.st_mode) && status.st_dev == expected.device &&
               status.st_ino == expected.inode && status.st_mode == expected.mode &&
               status.st_uid == expected.uid && status.st_gid == expected.gid &&
               (status.st_mode & 0777) == 0700;
    }

    static int rename_noreplace(int directory, const char* old_name, const char* new_name) {
#ifdef SYS_renameat2
        return static_cast<int>(
            syscall(SYS_renameat2, directory, old_name, directory, new_name, RENAME_NOREPLACE));
#else
        (void)directory;
        (void)old_name;
        (void)new_name;
        errno = ENOSYS;
        return -1;
#endif
    }

    bool validate_named(const std::string& name, const Identity& expected) const {
        struct stat held{};
        struct stat named{};
        return parent_fd >= 0 && fd >= 0 && fstat(fd, &held) == 0 &&
               fstatat(parent_fd, name.c_str(), &named, AT_SYMLINK_NOFOLLOW) == 0 &&
               same_identity(held, identity) && same_identity(named, expected);
    }

    bool create() {
        parent_fd = open("/tmp", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (parent_fd < 0) return false;
        std::array<char, 64> pattern{};
        std::snprintf(pattern.data(), pattern.size(), "/tmp/rut377-canonical-XXXXXX");
        char* const created = mkdtemp(pattern.data());
        if (created == nullptr) return false;
        path = created;
        basename = path.substr(std::string_view{"/tmp/"}.size());
        fd = openat(parent_fd, basename.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (fd < 0 || fchmod(fd, 0700) != 0) return false;
        struct stat status{};
        if (fstat(fd, &status) != 0 || !S_ISDIR(status.st_mode) || status.st_uid != getuid() ||
            status.st_gid != getgid() || (status.st_mode & 0777) != 0700)
            return false;
        identity = make_identity(status);
        active = true;
        return validate_named(basename, identity);
    }

    bool settle() {
        if (!active || !validate_named(basename, identity)) return false;
        const std::string quarantine = basename + ".quarantine";
        if (rename_noreplace(parent_fd, basename.c_str(), quarantine.c_str()) != 0) return false;
        if (!validate_named(quarantine, identity)) {
            (void)rename_noreplace(parent_fd, quarantine.c_str(), basename.c_str());
            return false;
        }
        if (unlinkat(parent_fd, quarantine.c_str(), AT_REMOVEDIR) != 0) {
            (void)rename_noreplace(parent_fd, quarantine.c_str(), basename.c_str());
            return false;
        }
        active = false;
        const bool synced = fsync(parent_fd) == 0;
        const int directory_slot = fd;
        fd = -1;
        const bool directory_closed = close(directory_slot) == 0;
        const int parent_slot = parent_fd;
        parent_fd = -1;
        const bool parent_closed = close(parent_slot) == 0;
        if (synced && directory_closed && parent_closed) {
            path.clear();
            basename.clear();
            return true;
        }
        return false;
    }

    bool replace_entry_for_testing(Identity& replacement) {
        if (!active || !validate_named(basename, identity)) return false;
        const std::string saved = basename + ".saved";
        if (rename_noreplace(parent_fd, basename.c_str(), saved.c_str()) != 0) return false;
        if (mkdirat(parent_fd, basename.c_str(), 0700) != 0) {
            (void)rename_noreplace(parent_fd, saved.c_str(), basename.c_str());
            return false;
        }
        struct stat status{};
        if (fstatat(parent_fd, basename.c_str(), &status, AT_SYMLINK_NOFOLLOW) != 0) return false;
        replacement = make_identity(status);
        return !same_identity(status, identity);
    }

    bool replacement_intact_for_testing(const Identity& replacement) const {
        struct stat status{};
        return parent_fd >= 0 &&
               fstatat(parent_fd, basename.c_str(), &status, AT_SYMLINK_NOFOLLOW) == 0 &&
               same_identity(status, replacement);
    }

    bool restore_after_replacement_for_testing(const Identity& replacement) {
        const std::string saved = basename + ".saved";
        if (!replacement_intact_for_testing(replacement) ||
            unlinkat(parent_fd, basename.c_str(), AT_REMOVEDIR) != 0 ||
            rename_noreplace(parent_fd, saved.c_str(), basename.c_str()) != 0)
            return false;
        return fsync(parent_fd) == 0 && validate_named(basename, identity);
    }

    ~PrivateDirectory() {
        if (active) (void)settle();
        if (fd >= 0) (void)close(fd);
        if (parent_fd >= 0) (void)close(parent_fd);
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

bool directory_replacement_refusal_test() {
    PrivateDirectory directory;
    PrivateDirectory::Identity replacement;
    if (!check(directory.create(), "directory replacement setup") ||
        !check(directory.replace_entry_for_testing(replacement), "directory replacement injection"))
        return false;
    const bool refused = !directory.settle();
    const bool replacement_preserved = directory.replacement_intact_for_testing(replacement);
    const bool restored = directory.restore_after_replacement_for_testing(replacement);
    const bool removed = restored && directory.settle();
    return check(refused && replacement_preserved && restored && removed,
                 "directory replacement was removed or prevented exact retry");
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

    std::string source_path;
    std::string directory_path;
    protocol::ProcIdentity launched_identity;
    bool launched_identity_known = false;
    bool ok = true;
    {
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
        const auto until = deadline();
        const auto record = [&](bool result, const char* message) {
            ok = check(result, message) && ok;
            return result;
        };

        const bool directory_created = record(directory.create(), "private directory creation");
        directory_path = directory.path;
        bool source_created = false;
        if (directory_created) {
            source_created =
                record(source::WildcardAttemptSourceLease::create_exact_bytes(directory.fd,
                                                                              directory.path,
                                                                              kSourceBasename,
                                                                              kSourceBytes,
                                                                              source_lease,
                                                                              source_diagnostic),
                       "exact ordinary-RUT source lease");
            if (source_created) source_path = source_lease.path();
        }

        const bool executable_path_known =
            source_created &&
            record(canonical_executable(executable_path), "canonical public rut path");
        bool executable_created = false;
        if (executable_path_known)
            executable_created =
                record(executable::ExecutableLease::create(
                           executable_path, executable_lease, executable_diagnostic),
                       "public rut executable lease");

        bool capture_created = false;
        if (executable_created)
            capture_created = record(capture::AnonymousLogCapture::create(
                                         capture::kMaxCaptureBytes, output, capture_diagnostic),
                                     "bounded startup capture");

        if (capture_created) {
            null_input.value = open("/dev/null", O_RDONLY | O_CLOEXEC);
            (void)record(null_input.value >= 0, "borrowed /dev/null");
        }
        bool handoff_created = false;
        if (null_input.value >= 0)
            handoff_created = record(handoff::ExecutableExecHandoffLease::create(
                                         executable_lease, handoff_lease, handoff_diagnostic),
                                     "executable handoff");

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
        if (handoff_created)
            (void)record(no_access_log_configuration,
                         "source/argv unexpectedly configure an access log");

        child::ChildDescriptorPlan plan;
        bool plan_made = false;
        if (handoff_created && no_access_log_configuration)
            plan_made = record(handoff_lease.make_child_plan_with_arguments(null_input.value,
                                                                            output.descriptor(),
                                                                            false,
                                                                            arguments,
                                                                            plan,
                                                                            handoff_diagnostic),
                               "exact nine-argument child plan");

        bool child_created = false;
        if (plan_made)
            child_created = record(child::PausedChildLease::create_prepared(
                                       until, plan, child_lease, child_diagnostic),
                                   "prepared public rut child");

        pid_t launched_pid = -1;
        std::shared_ptr<const child::SettlementReceipt> settlement;
        if (child_created) {
            launched_pid = child_lease.child_pid();
            settlement = child_lease.settlement_receipt();
            launched_identity = child_lease.identity();
            launched_identity_known = true;
        }

        handoff::ExecObservation observation;
        bool exec_observed = false;
        if (child_created) {
            exec_observed =
                handoff_lease.release_and_observe(
                    executable_lease, child_lease, until, observation, handoff_diagnostic) &&
                observation.outcome == handoff::ExecOutcome::ExecObservedLive &&
                observation.first.cmdline == expected_cmdline &&
                observation.second.cmdline == expected_cmdline;
            (void)record(exec_observed, "public rut exec observation");
            if (exec_observed) launched_identity = observation.second;
        }

        std::string readiness_bytes;
        StartupEvidence readiness_evidence;
        bool readiness = false;
        if (exec_observed) {
            std::string candidate;
            StartupEvidence candidate_evidence;
            if (wait_for_strict_startup(
                    output, source_path, until, candidate, candidate_evidence)) {
                protocol::ProcIdentity first_proc;
                protocol::ProcIdentity second_proc;
                protocol::ProcIdentity third_proc;
                capture::Diagnostic first_snapshot_diagnostic;
                capture::Diagnostic second_snapshot_diagnostic;
                std::string first_snapshot;
                std::string second_snapshot;
                StartupEvidence first_evidence;
                StartupEvidence second_evidence;
                readiness = pidfd_live(child_lease.observation_pidfd()) &&
                            protocol::read_proc(launched_pid, first_proc) &&
                            protocol::same_process_identity(observation.second, first_proc) &&
                            exact_empty_environment(launched_pid) &&
                            executable_lease.revalidate(executable_diagnostic) &&
                            source_lease.revalidate(source_diagnostic) &&
                            output.snapshot(first_snapshot, first_snapshot_diagnostic) &&
                            parse_startup_bytes(first_snapshot, source_path, first_evidence) &&
                            protocol::read_proc(launched_pid, second_proc) &&
                            protocol::same_process_identity(first_proc, second_proc) &&
                            pidfd_live(child_lease.observation_pidfd()) &&
                            exact_empty_environment(launched_pid) &&
                            executable_lease.revalidate(executable_diagnostic) &&
                            source_lease.revalidate(source_diagnostic) &&
                            output.snapshot(second_snapshot, second_snapshot_diagnostic) &&
                            parse_startup_bytes(second_snapshot, source_path, second_evidence) &&
                            first_snapshot == second_snapshot && first_snapshot == candidate &&
                            first_evidence.backend == second_evidence.backend &&
                            first_evidence.port == second_evidence.port &&
                            protocol::read_proc(launched_pid, third_proc) &&
                            protocol::same_process_identity(second_proc, third_proc) &&
                            pidfd_live(child_lease.observation_pidfd()) &&
                            exact_empty_environment(launched_pid) &&
                            executable_lease.revalidate(executable_diagnostic) &&
                            source_lease.revalidate(source_diagnostic);
                if (readiness) {
                    readiness_bytes = first_snapshot;
                    readiness_evidence = first_evidence;
                }
            }
            (void)record(readiness, "strict post-bracketed startup readiness");
            if (readiness)
                (void)record(
                    evidence_mutations_rejected(readiness_bytes, source_path, readiness_evidence),
                    "copied startup evidence mutation rejection");
        }

        // Stop authority is exclusively PausedChildLease::cleanup(). Once
        // exact reap is known, every following owner is attempted in order;
        // one failure never suppresses an independent later settlement.
        bool exact_settlement = false;
        if (child_created) {
            const bool child_cleaned =
                child_lease.active() && child_lease.cleanup(until, child_diagnostic);
            exact_settlement = child_cleaned && settlement &&
                               settlement->child_pid == launched_pid && settlement->terminal &&
                               settlement->reaped && settlement->error_number == 0 &&
                               WIFSIGNALED(settlement->wait_status) &&
                               WTERMSIG(settlement->wait_status) == SIGKILL;
            (void)record(exact_settlement, "SIGKILL terminal+reaped child settlement");
        }

        const bool safe_to_settle_writers = !child_created || exact_settlement;
        if (safe_to_settle_writers) {
            if (handoff_created)
                (void)record(handoff_lease.close(handoff_diagnostic),
                             "post-child handoff settlement");
            if (null_input.value >= 0)
                (void)record(null_input.close_owned(), "borrowed /dev/null parent close");
            if (capture_created) {
                std::string final_bytes;
                capture::Diagnostic settle_diagnostic;
                capture::Diagnostic snapshot_diagnostic;
                capture::Diagnostic close_diagnostic;
                const bool settled = output.settle(settle_diagnostic);
                (void)record(settled, "startup capture settlement");
                const bool snapshotted = output.snapshot(final_bytes, snapshot_diagnostic);
                (void)record(snapshotted, "final startup capture snapshot");
                if (readiness) {
                    StartupEvidence final_evidence;
                    (void)record(
                        snapshotted && final_bytes == readiness_bytes &&
                            parse_startup_bytes(final_bytes, source_path, final_evidence) &&
                            final_evidence.backend == readiness_evidence.backend &&
                            final_evidence.port == readiness_evidence.port,
                        "sealed final startup evidence");
                }
                (void)record(output.close(close_diagnostic), "startup capture close");
            }
            if (executable_created)
                (void)record(executable_lease.close(executable_diagnostic),
                             "public rut executable settlement");
            if (source_created)
                (void)record(source_lease.remove(source_diagnostic), "ordinary-RUT source removal");
            if (directory_created) (void)record(directory.settle(), "private directory settlement");
        } else {
            (void)record(false, "settlement retained after uncertain child cleanup");
        }
    }

    std::vector<int> final_fds;
    std::vector<pid_t> final_children;
    if (launched_identity_known)
        ok = check(protocol::target_gone_or_reused(launched_identity),
                   "exact public rut process residue") &&
             ok;
    if (!source_path.empty())
        ok = check(access(source_path.c_str(), F_OK) != 0 && errno == ENOENT,
                   "source path residue after fallback cleanup") &&
             ok;
    if (!directory_path.empty())
        ok = check(access(directory_path.c_str(), F_OK) != 0 && errno == ENOENT,
                   "private directory residue after fallback cleanup") &&
             ok;
    ok = check(fd_snapshot(final_fds) && final_fds == baseline_fds, "owned FD residue") && ok;
    ok = check(child_snapshot(final_children) && final_children == baseline_children,
               "direct-child residue") &&
         ok;
    return ok;
}

}  // namespace

int main() {
    if (!directory_replacement_refusal_test() || !run_one_canonical_session()) return 1;
    std::puts("PASS: #377 one fresh canonical public RUT session");
    return 0;
}
