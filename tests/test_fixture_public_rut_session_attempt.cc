#include "fixture_private_directory_lease.h"
#include "fixture_public_rut_session_attempt.h"
#include "fixture_worker_protocol.h"
#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <functional>
#include <string>
#include <string_view>
#include <vector>

#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <sys/stat.h>
#include <unistd.h>
namespace attempt = rut::test::fixture_public_rut_session_attempt;
namespace directory = rut::test::fixture_private_directory_lease;
namespace executable = rut::test::fixture_executable_lease;
namespace protocol = rut::test::fixture_worker_protocol;
namespace source = rut::test::fixture_wildcard_source_lease;
namespace {

using Clock = std::chrono::steady_clock;
constexpr char kSource[] = "listen :0\nroute GET \"/\" { return 204 }\n";

bool check(bool condition, const char* message) {
    if (!condition) std::fprintf(stderr, "FAIL: %s (errno=%d)\n", message, errno);
    return condition;
}

bool fd_snapshot(std::vector<int>& descriptors) {
    descriptors.clear();
    DIR* directory_handle = opendir("/proc/self/fd");
    if (directory_handle == nullptr) return false;
    const int own = dirfd(directory_handle);
    errno = 0;
    while (dirent* entry = readdir(directory_handle)) {
        int value = -1;
        const char* begin = entry->d_name;
        const char* end = begin + std::strlen(begin);
        const auto [parsed, error] = std::from_chars(begin, end, value);
        if (error == std::errc{} && parsed == end && value >= 0 && value != own)
            descriptors.push_back(value);
        errno = 0;
    }
    const int read_error = errno;
    const bool closed = closedir(directory_handle) == 0;
    std::sort(descriptors.begin(), descriptors.end());
    return read_error == 0 && closed &&
           std::adjacent_find(descriptors.begin(), descriptors.end()) == descriptors.end();
}

bool child_snapshot(std::vector<pid_t>& children) {
    children.clear();
    std::string text;
    if (!protocol::read_file(
            "/proc/self/task/" + std::to_string(getpid()) + "/children", text, 65536u))
        return false;
    const char* cursor = text.data();
    const char* const end = cursor + text.size();
    while (cursor != end) {
        while (cursor != end && (*cursor == ' ' || *cursor == '\n' || *cursor == '\t')) ++cursor;
        if (cursor == end) break;
        pid_t child = -1;
        const auto [parsed, error] = std::from_chars(cursor, end, child);
        if (error != std::errc{} || parsed == cursor || child <= 0) return false;
        children.push_back(child);
        cursor = parsed;
    }
    std::sort(children.begin(), children.end());
    return std::adjacent_find(children.begin(), children.end()) == children.end();
}

bool absent(const std::string& path) {
    struct stat status{};
    return !path.empty() && lstat(path.c_str(), &status) != 0 && errno == ENOENT;
}

struct Owners {
    directory::PrivateDirectoryLease directory;
    source::WildcardAttemptSourceLease source;
    executable::ExecutableLease executable;
    std::string executable_path;
    std::string source_path;
    std::string directory_path;

    bool create() {
        directory::Diagnostic directory_diagnostic;
        source::Diagnostic source_diagnostic;
        executable::Diagnostic executable_diagnostic;
        std::array<char, PATH_MAX> resolved{};
        if (!directory::PrivateDirectoryLease::create(directory, directory_diagnostic) ||
            !source::WildcardAttemptSourceLease::create_exact_bytes(directory.descriptor(),
                                                                    directory.path(),
                                                                    "attempt.rut",
                                                                    kSource,
                                                                    source,
                                                                    source_diagnostic) ||
            realpath("/proc/self/exe", resolved.data()) == nullptr)
            return false;
        executable_path = resolved.data();
        source_path = source.path();
        directory_path = directory.path();
        return executable::ExecutableLease::create(
            executable_path, executable, executable_diagnostic);
    }

    bool close() {
        executable::Diagnostic executable_diagnostic;
        source::Diagnostic source_diagnostic;
        directory::Diagnostic directory_diagnostic;
        const bool executable_closed = executable.close(executable_diagnostic);
        const bool source_removed = source.remove(source_diagnostic);
        const bool directory_removed = directory.settle(directory_diagnostic);
        return executable_closed && source_removed && directory_removed;
    }
};

std::array<std::string_view, 3> arguments(const Owners& owners, std::string_view mode) {
    return {owners.executable_path, owners.source_path, mode};
}

bool prepare_ok(attempt::PublicRutAttemptLease& lease,
                Owners& owners,
                std::string_view mode,
                const attempt::HooksForTesting& hooks,
                attempt::Diagnostic& diagnostic) {
    const auto argv = arguments(owners, mode);
    return check(lease.prepare(owners.source,
                               owners.executable,
                               argv,
                               Clock::now() + std::chrono::seconds(2),
                               hooks,
                               diagnostic),
                 "attempt prepare");
}

bool observe_ok(attempt::PublicRutAttemptLease& lease,
                Owners& owners,
                attempt::Diagnostic& diagnostic) {
    return check(
        lease.exec_and_observe(
            owners.source, owners.executable, Clock::now() + std::chrono::seconds(2), diagnostic),
        "attempt exec observation");
}

bool run_case(const char* name, const std::function<bool(Owners&)>& body) {
    std::vector<int> baseline_fds;
    std::vector<pid_t> baseline_children;
    if (!check(fd_snapshot(baseline_fds), "case baseline FD set") ||
        !check(child_snapshot(baseline_children), "case baseline child PID set"))
        return false;
    std::string source_path;
    std::string directory_path;
    bool ok = true;
    {
        Owners owners;
        ok = check(owners.create(), "case owners") && ok;
        source_path = owners.source_path;
        directory_path = owners.directory_path;
        if (ok) ok = body(owners) && ok;
        ok = check(owners.close(), "case owner settlement") && ok;
    }
    std::vector<int> final_fds;
    std::vector<pid_t> final_children;
    ok = check(absent(source_path), "case source residue") && ok;
    ok = check(absent(directory_path), "case directory residue") && ok;
    ok = check(fd_snapshot(final_fds) && final_fds == baseline_fds, "case exact FD residue") && ok;
    ok = check(child_snapshot(final_children) && final_children == baseline_children,
               "case exact child PID residue") &&
         ok;
    if (!ok) std::fprintf(stderr, "CASE FAILED: %s\n", name);
    return ok;
}

bool partial_prepare(Owners& owners, attempt::PrepareFailurePoint point) {
    attempt::HooksForTesting hooks;
    hooks.prepare_failure = point;
    attempt::Diagnostic diagnostic;
    std::shared_ptr<const attempt::CleanupState> cleanup;
    bool rejected = false;
    {
        attempt::PublicRutAttemptLease lease;
        cleanup = lease.cleanup_state();
        const auto argv = arguments(owners, "--attempt-live");
        rejected = !lease.prepare(owners.source,
                                  owners.executable,
                                  argv,
                                  Clock::now() + std::chrono::seconds(2),
                                  hooks,
                                  diagnostic) &&
                   lease.state() == attempt::State::Failed;
    }
    return check(
        rejected && cleanup && cleanup->destructor_attempted &&
            !cleanup->destructor_reportable_success &&
            cleanup->diagnostic.phase == attempt::FailurePhase::Injected &&
            cleanup->diagnostic.error_number == EIO &&
            cleanup->child_attempted == (point >= attempt::PrepareFailurePoint::AfterChild) &&
            cleanup->child_settled == cleanup->child_attempted &&
            cleanup->handoff_attempted == (point >= attempt::PrepareFailurePoint::AfterHandoff) &&
            cleanup->handoff_closed == cleanup->handoff_attempted &&
            cleanup->null_attempted == (point >= attempt::PrepareFailurePoint::AfterNullInput) &&
            cleanup->null_closed == cleanup->null_attempted && cleanup->capture_settle_attempted &&
            cleanup->capture_settled && cleanup->capture_close_attempted && cleanup->capture_closed,
        "partial prepare exact destructor evidence");
}

bool exec_failure(Owners& owners) {
    const std::string bad_path = owners.directory_path + "/bad-exec";
    int writer = openat(owners.directory.descriptor(),
                        "bad-exec",
                        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                        0700);
    const char bytes[] = "not-an-executable\n";
    bool made = writer >= 0;
    if (writer >= 0) {
        made =
            write(writer, bytes, sizeof(bytes) - 1u) == static_cast<ssize_t>(sizeof(bytes) - 1u) &&
            fsync(writer) == 0;
        made = close(writer) == 0 && made;
    }
    executable::ExecutableLease bad_executable;
    executable::Diagnostic executable_diagnostic;
    made = made &&
           executable::ExecutableLease::create(bad_path, bad_executable, executable_diagnostic);
    bool result = check(made, "invalid executable lease");
    attempt::HooksForTesting hooks;
    attempt::Diagnostic diagnostic;
    if (made) {
        attempt::PublicRutAttemptLease lease;
        const std::array<std::string_view, 3> argv = {
            bad_path, owners.source_path, "--attempt-live"};
        result = check(lease.prepare(owners.source,
                                     bad_executable,
                                     argv,
                                     Clock::now() + std::chrono::seconds(2),
                                     hooks,
                                     diagnostic),
                       "exec-failure prepare") &&
                 result;
        result = check(!lease.exec_and_observe(owners.source,
                                               bad_executable,
                                               Clock::now() + std::chrono::seconds(2),
                                               diagnostic),
                       "exec failure rejected") &&
                 result;
        result = check(lease.exec_observation().outcome ==
                           rut::test::fixture_executable_exec_handoff::ExecOutcome::ExecFailure,
                       "honest exec-failure evidence") &&
                 result;
    }
    if (bad_executable.active())
        result =
            check(bad_executable.close(executable_diagnostic), "bad executable close") && result;
    result = check(unlinkat(owners.directory.descriptor(), "bad-exec", 0) == 0,
                   "bad executable removal") &&
             result;
    return result;
}

bool early_death(Owners& owners) {
    attempt::HooksForTesting hooks;
    hooks.handoff.post_eof_delay_ms = 100u;
    attempt::Diagnostic diagnostic;
    attempt::PublicRutAttemptLease lease;
    return prepare_ok(lease, owners, "--attempt-exit1", hooks, diagnostic) &&
           observe_ok(lease, owners, diagnostic) &&
           check(lease.state() == attempt::State::EarlyDeath, "honest early-death state") &&
           check(lease.settle_natural(1, Clock::now() + std::chrono::seconds(2), diagnostic),
                 "early-death natural settlement") &&
           check(lease.close_evidence(diagnostic), "early-death evidence close");
}

bool live_kill_and_owned_evidence(Owners& owners) {
    attempt::HooksForTesting hooks;
    attempt::Diagnostic diagnostic;
    attempt::PublicRutAttemptLease lease;
    std::string argv0 = owners.executable_path;
    std::string argv1 = owners.source_path;
    std::string mode = "--attempt-live";
    const std::array<std::string_view, 3> argv = {argv0, argv1, mode};
    if (!check(lease.prepare(owners.source,
                             owners.executable,
                             argv,
                             Clock::now() + std::chrono::seconds(2),
                             hooks,
                             diagnostic),
               "live prepare"))
        return false;
    const std::string expected_cmdline = argv0 + '\0' + argv1 + '\0' + mode + '\0';
    argv0.assign("poisoned-executable");
    argv1.assign("poisoned-source");
    mode.assign("poisoned-mode");
    if (!check(lease.expected_cmdline() == expected_cmdline,
               "owned argv/path evidence survives caller poisoning") ||
        !observe_ok(lease, owners, diagnostic) ||
        !check(lease.state() == attempt::State::ExecObservedLive, "ExecObservedLive state"))
        return false;
    const pid_t child_pid = lease.child_pid();
    const auto settlement = lease.settlement_receipt();
    protocol::ProcIdentity after_rejection;
    pollfd pidfd{lease.observation_pidfd(), POLLIN | POLLERR | POLLHUP, 0};
    if (!check(
            !lease.settle_killed(SIGTERM, Clock::now() + std::chrono::seconds(1), diagnostic) &&
                diagnostic.phase == attempt::FailurePhase::Argument &&
                diagnostic.error_number == EINVAL &&
                lease.state() == attempt::State::ExecObservedLive &&
                lease.child_pid() == child_pid && settlement && !settlement->terminal &&
                !settlement->reaped && poll(&pidfd, 1, 0) == 0 && pidfd.revents == 0 &&
                protocol::read_proc(child_pid, after_rejection) &&
                protocol::same_process_identity(lease.exec_observation().second, after_rejection),
            "non-SIGKILL rejection preserves exact live child") ||
        !check(lease.settle_killed(SIGKILL, Clock::now() + std::chrono::seconds(2), diagnostic),
               "live SIGKILL/reap") ||
        !check(lease.state() == attempt::State::KilledReapedEvidenceOpen &&
                   lease.snapshot_capture(mode, diagnostic) && mode == lease.sealed_capture_bytes(),
               "sealed evidence retained") ||
        !check(!lease.settle_killed(SIGKILL, Clock::now() + std::chrono::seconds(1), diagnostic),
               "double settlement rejected") ||
        !check(lease.close_evidence(diagnostic), "explicit evidence close") ||
        !check(!lease.close_evidence(diagnostic), "double close rejected"))
        return false;
    return true;
}

bool natural_exit(Owners& owners, bool timeout_first) {
    attempt::HooksForTesting hooks;
    attempt::Diagnostic diagnostic;
    attempt::PublicRutAttemptLease lease;
    if (!prepare_ok(lease, owners, "--attempt-delay-exit1", hooks, diagnostic) ||
        !observe_ok(lease, owners, diagnostic))
        return false;
    if (timeout_first &&
        (!check(!lease.settle_natural(1, Clock::now() + std::chrono::milliseconds(5), diagnostic),
                "natural timeout") ||
         !check(lease.state() == attempt::State::ExecObservedLive,
                "timeout retains live authority")))
        return false;
    return check(lease.settle_natural(1, Clock::now() + std::chrono::seconds(2), diagnostic),
                 "natural terminal exit 1") &&
           check(lease.state() == attempt::State::NaturalReapedEvidenceOpen,
                 "natural reaped evidence state") &&
           check(lease.close_evidence(diagnostic), "natural evidence close");
}

bool synchronous_validation_failures(Owners& owners) {
    attempt::HooksForTesting hooks;
    attempt::Diagnostic diagnostic;
    attempt::PublicRutAttemptLease lease;
    if (!prepare_ok(lease, owners, "--attempt-live", hooks, diagnostic)) return false;
    executable::ExecutableLease foreign;
    const bool executable_rejected = !lease.exec_and_observe(
        owners.source, foreign, Clock::now() + std::chrono::seconds(1), diagnostic);
    if (!check(executable_rejected && diagnostic.phase == attempt::FailurePhase::Executable,
               "synchronous executable validation failure") ||
        chmod(owners.source_path.c_str(), 0644) != 0)
        return false;
    const bool source_rejected = !lease.exec_and_observe(
        owners.source, owners.executable, Clock::now() + std::chrono::seconds(1), diagnostic);
    const bool restored = chmod(owners.source_path.c_str(), 0600) == 0;
    return check(source_rejected && diagnostic.phase == attempt::FailurePhase::Source,
                 "synchronous source validation failure") &&
           check(restored, "source mode restoration");
}

struct CloseContext {
    unsigned calls = 0u;
    unsigned fail_on = 0u;
};

int close_then_fail_selected(int descriptor, void* opaque) {
    auto& context = *static_cast<CloseContext*>(opaque);
    ++context.calls;
    const int result = close(descriptor);
    if (context.calls == context.fail_on) {
        errno = EINTR;
        return -1;
    }
    return result;
}

bool fail_capture_close = false;
int capture_close(int descriptor) {
    const int result = close(descriptor);
    if (!fail_capture_close) return result;
    fail_capture_close = false;
    errno = EINTR;
    return -1;
}

bool close_uncertainty(Owners& owners, unsigned kind) {
    CloseContext context;
    context.fail_on = kind == 0u ? 4u : 1u;
    attempt::HooksForTesting hooks;
    if (kind == 0u) {
        hooks.handoff.close_fd = close_then_fail_selected;
        hooks.handoff.context = &context;
    } else if (kind == 1u) {
        hooks.close_null_input = close_then_fail_selected;
        hooks.null_context = &context;
    } else {
        hooks.capture.close = capture_close;
    }
    attempt::Diagnostic diagnostic;
    std::shared_ptr<const attempt::CleanupState> cleanup;
    bool result;
    {
        attempt::PublicRutAttemptLease lease;
        cleanup = lease.cleanup_state();
        result = prepare_ok(lease, owners, "--attempt-live", hooks, diagnostic) &&
                 observe_ok(lease, owners, diagnostic);
        const bool settled =
            lease.settle_killed(SIGKILL, Clock::now() + std::chrono::seconds(2), diagnostic);
        if (kind == 2u) {
            fail_capture_close = true;
            result = settled && !lease.close_evidence(diagnostic) && result;
        } else {
            result = !settled && result;
        }
        result = lease.state() == attempt::State::Failed && result;
    }
    const std::array phases = {attempt::FailurePhase::Handoff,
                               attempt::FailurePhase::NullInput,
                               attempt::FailurePhase::Close};
    const bool false_success = kind == 0u ? cleanup->handoff_attempted && !cleanup->handoff_closed
                               : kind == 1u
                                   ? cleanup->null_attempted && !cleanup->null_closed
                                   : cleanup->capture_close_attempted && !cleanup->capture_closed;
    return check(result && cleanup && cleanup->destructor_attempted &&
                     !cleanup->destructor_reportable_success &&
                     cleanup->diagnostic.phase == phases[kind] &&
                     cleanup->diagnostic.error_number == EINTR && false_success,
                 "close uncertainty retained post-destructor failure");
}

}  // namespace

int main(int argc, char** argv) {
    if (argc == 3 && std::string_view(argv[2]) == "--attempt-live") {
        for (;;) pause();
    }
    if (argc == 3 && std::string_view(argv[2]) == "--attempt-exit1") return 1;
    if (argc == 3 && std::string_view(argv[2]) == "--attempt-delay-exit1") {
        (void)poll(nullptr, 0, 150);
        return 1;
    }

    bool ok = true;
    constexpr std::array partial_points = {attempt::PrepareFailurePoint::AfterCapture,
                                           attempt::PrepareFailurePoint::AfterNullInput,
                                           attempt::PrepareFailurePoint::AfterHandoff,
                                           attempt::PrepareFailurePoint::AfterPlan,
                                           attempt::PrepareFailurePoint::AfterChild};
    for (const auto point : partial_points)
        ok = run_case("partial prepare",
                      [point](Owners& owners) { return partial_prepare(owners, point); }) &&
             ok;
    ok = run_case("exec failure", exec_failure) && ok;
    ok = run_case("early death", early_death) && ok;
    ok = run_case("live kill and evidence", live_kill_and_owned_evidence) && ok;
    ok = run_case("natural exit", [](Owners& owners) { return natural_exit(owners, false); }) && ok;
    ok = run_case("natural timeout retry",
                  [](Owners& owners) { return natural_exit(owners, true); }) &&
         ok;
    ok = run_case("synchronous validation", synchronous_validation_failures) && ok;
    ok = run_case("handoff close uncertainty",
                  [](Owners& owners) { return close_uncertainty(owners, 0u); }) &&
         ok;
    ok = run_case("null close uncertainty",
                  [](Owners& owners) { return close_uncertainty(owners, 1u); }) &&
         ok;
    ok = run_case("capture close uncertainty",
                  [](Owners& owners) { return close_uncertainty(owners, 2u); }) &&
         ok;
    if (!ok) return 1;
    std::puts("PASS: #377 reusable public RUT attempt lease");
    return 0;
}
