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
#include <sys/wait.h>
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

bool empty_cleanup(Owners& owners) {
    std::vector<int> baseline_fds;
    std::vector<pid_t> baseline_children;
    if (!check(fd_snapshot(baseline_fds), "empty cleanup baseline FD set") ||
        !check(child_snapshot(baseline_children), "empty cleanup baseline child PID set"))
        return false;
    attempt::PublicRutAttemptLease lease;
    attempt::Diagnostic diagnostic;
    const auto cleanup = lease.cleanup_state();
    if (!check(lease.cleanup(Clock::now(), diagnostic), "empty cleanup") ||
        !check(lease.state() == attempt::State::EvidenceClosed &&
                   cleanup->explicit_cleanup_complete &&
                   cleanup->explicit_cleanup_reportable_success,
               "empty cleanup terminal state"))
        return false;

    const attempt::CleanupState before_prepare = *cleanup;
    const auto argv = arguments(owners, "--attempt-live");
    attempt::HooksForTesting hooks;
    if (!check(!lease.prepare(owners.source,
                              owners.executable,
                              argv,
                              Clock::now() + std::chrono::seconds(2),
                              hooks,
                              diagnostic) &&
                   diagnostic.phase == attempt::FailurePhase::Argument &&
                   diagnostic.error_number == EINVAL &&
                   lease.state() == attempt::State::EvidenceClosed,
               "prepare after cleanup rejects before owner acquisition"))
        return false;

    std::vector<int> after_prepare_fds;
    std::vector<pid_t> after_prepare_children;
    source::Diagnostic source_diagnostic;
    executable::Diagnostic executable_diagnostic;
    if (!check(fd_snapshot(after_prepare_fds) && after_prepare_fds == baseline_fds,
               "cleanup prepare rejection exact FD set") ||
        !check(
            child_snapshot(after_prepare_children) && after_prepare_children == baseline_children,
            "cleanup prepare rejection exact child PID set") ||
        !check(owners.source.revalidate(source_diagnostic),
               "cleanup prepare rejection preserves source owner") ||
        !check(owners.executable.revalidate(executable_diagnostic),
               "cleanup prepare rejection preserves executable owner") ||
        !check(lease.cleanup(Clock::now(), diagnostic), "empty cleanup replay") ||
        !check(cleanup->explicit_cleanup_calls == 2u &&
                   cleanup->explicit_cleanup_complete == before_prepare.explicit_cleanup_complete &&
                   cleanup->explicit_cleanup_reportable_success ==
                       before_prepare.explicit_cleanup_reportable_success &&
                   cleanup->child_attempted == before_prepare.child_attempted &&
                   cleanup->child_settled == before_prepare.child_settled &&
                   cleanup->handoff_attempted == before_prepare.handoff_attempted &&
                   cleanup->handoff_closed == before_prepare.handoff_closed &&
                   cleanup->null_attempted == before_prepare.null_attempted &&
                   cleanup->null_closed == before_prepare.null_closed &&
                   cleanup->capture_settle_attempted == before_prepare.capture_settle_attempted &&
                   cleanup->capture_settled == before_prepare.capture_settled &&
                   cleanup->capture_close_attempted == before_prepare.capture_close_attempted &&
                   cleanup->capture_closed == before_prepare.capture_closed,
               "cleanup prepare rejection and replay have no owner operations"))
        return false;
    return check(fd_snapshot(after_prepare_fds) && after_prepare_fds == baseline_fds,
                 "empty cleanup replay exact FD set") &&
           check(child_snapshot(after_prepare_children) &&
                     after_prepare_children == baseline_children,
                 "empty cleanup replay exact child PID set");
}

bool partial_prepare(Owners& owners, attempt::PrepareFailurePoint point) {
    attempt::HooksForTesting hooks;
    hooks.prepare_failure = point;
    attempt::Diagnostic diagnostic;
    std::shared_ptr<const attempt::CleanupState> cleanup;
    bool rejected = false;
    bool explicitly_cleaned = false;
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
        const attempt::Diagnostic prepare_diagnostic = diagnostic;
        explicitly_cleaned = lease.cleanup(Clock::now() + std::chrono::seconds(2), diagnostic) &&
                             diagnostic.phase == attempt::FailurePhase::None &&
                             lease.state() == attempt::State::EvidenceClosed;
        const unsigned child_attempts = cleanup->child_attempted ? 1u : 0u;
        const unsigned handoff_attempts = cleanup->handoff_attempted ? 1u : 0u;
        const unsigned null_attempts = cleanup->null_attempted ? 1u : 0u;
        const unsigned capture_settle_attempts = cleanup->capture_settle_attempted ? 1u : 0u;
        const unsigned capture_close_attempts = cleanup->capture_close_attempted ? 1u : 0u;
        explicitly_cleaned =
            check(lease.cleanup(Clock::now(), diagnostic), "partial cleanup idempotent replay") &&
            check(cleanup->explicit_cleanup_calls == 2u &&
                      static_cast<unsigned>(cleanup->child_attempted) == child_attempts &&
                      static_cast<unsigned>(cleanup->handoff_attempted) == handoff_attempts &&
                      static_cast<unsigned>(cleanup->null_attempted) == null_attempts &&
                      static_cast<unsigned>(cleanup->capture_settle_attempted) ==
                          capture_settle_attempts &&
                      static_cast<unsigned>(cleanup->capture_close_attempted) ==
                          capture_close_attempts,
                  "partial cleanup does not repeat owned operations") &&
            prepare_diagnostic.phase == attempt::FailurePhase::Injected &&
            prepare_diagnostic.error_number == EIO && explicitly_cleaned;
    }
    return check(
        rejected && explicitly_cleaned && cleanup && cleanup->explicit_cleanup_attempted &&
            cleanup->explicit_cleanup_complete && cleanup->explicit_cleanup_reportable_success &&
            cleanup->explicit_cleanup_diagnostic.phase == attempt::FailurePhase::None &&
            cleanup->destructor_attempted && !cleanup->destructor_reportable_success &&
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
        const auto settlement = lease.settlement_receipt();
        const bool bounded_cleanup =
            lease.cleanup(Clock::now() + std::chrono::seconds(2), diagnostic);
        result = check(bounded_cleanup, "exec-failure bounded cleanup") &&
                 check(settlement && settlement->terminal && settlement->reaped &&
                           settlement->error_number == 0 && WIFEXITED(settlement->wait_status) &&
                           WEXITSTATUS(settlement->wait_status) == 131,
                       "exec-failure natural settlement receipt") &&
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

bool live_bounded_cleanup(Owners& owners) {
    attempt::HooksForTesting hooks;
    attempt::Diagnostic diagnostic;
    attempt::PublicRutAttemptLease lease;
    if (!prepare_ok(lease, owners, "--attempt-live", hooks, diagnostic) ||
        !observe_ok(lease, owners, diagnostic))
        return false;
    const pid_t child_pid = lease.child_pid();
    const auto settlement = lease.settlement_receipt();
    const auto cleanup_state = lease.cleanup_state();
    const auto cleanup_deadline = Clock::now() + std::chrono::seconds(2);
    if (!check(lease.cleanup(cleanup_deadline, diagnostic), "independent live cleanup deadline") ||
        !check(Clock::now() < cleanup_deadline, "live cleanup honored caller deadline") ||
        !check(lease.state() == attempt::State::EvidenceClosed && settlement &&
                   settlement->child_pid == child_pid && settlement->terminal &&
                   settlement->reaped && WIFSIGNALED(settlement->wait_status) &&
                   WTERMSIG(settlement->wait_status) == SIGKILL,
               "live cleanup exact terminal receipt") ||
        !check(cleanup_state->child_attempted && cleanup_state->child_settled &&
                   cleanup_state->handoff_closed && cleanup_state->null_closed &&
                   cleanup_state->capture_settled && cleanup_state->capture_closed,
               "live cleanup fixed owner settlement"))
        return false;
    return check(lease.cleanup(Clock::now(), diagnostic), "live cleanup idempotent replay") &&
           check(cleanup_state->explicit_cleanup_calls == 2u, "live cleanup replay call evidence");
}

bool live_cleanup_deadline_retry(Owners& owners) {
    attempt::HooksForTesting hooks;
    attempt::Diagnostic diagnostic;
    attempt::PublicRutAttemptLease lease;
    if (!prepare_ok(lease, owners, "--attempt-live", hooks, diagnostic) ||
        !observe_ok(lease, owners, diagnostic))
        return false;
    const auto settlement = lease.settlement_receipt();
    const auto cleanup = lease.cleanup_state();
    if (!check(!lease.cleanup(Clock::now(), diagnostic) &&
                   diagnostic.phase == attempt::FailurePhase::Child &&
                   diagnostic.error_number == ETIMEDOUT,
               "expired cleanup deadline fails bounded") ||
        !check(settlement && !settlement->terminal && !settlement->reaped &&
                   cleanup->child_attempted && !cleanup->child_settled &&
                   !cleanup->handoff_attempted && !cleanup->null_attempted &&
                   !cleanup->capture_settle_attempted && !cleanup->capture_close_attempted,
               "expired cleanup preserves child-used owners"))
        return false;
    return check(lease.cleanup(Clock::now() + std::chrono::seconds(2), diagnostic),
                 "later independent cleanup deadline succeeds") &&
           check(settlement->terminal && settlement->reaped &&
                     WIFSIGNALED(settlement->wait_status) &&
                     WTERMSIG(settlement->wait_status) == SIGKILL &&
                     cleanup->explicit_cleanup_complete &&
                     cleanup->explicit_cleanup_reportable_success && cleanup->handoff_closed &&
                     cleanup->null_closed && cleanup->capture_settled && cleanup->capture_closed,
                 "deadline retry settles exact child and owners");
}

bool live_post_sigkill_deadline_retry(Owners& owners) {
    attempt::HooksForTesting hooks;
    hooks.child.post_sigkill_delay_ms = 40u;
    attempt::Diagnostic diagnostic;
    attempt::PublicRutAttemptLease lease;
    if (!prepare_ok(lease, owners, "--attempt-live", hooks, diagnostic) ||
        !observe_ok(lease, owners, diagnostic))
        return false;
    const pid_t child_pid = lease.child_pid();
    const auto settlement = lease.settlement_receipt();
    const auto cleanup = lease.cleanup_state();
    const auto first_deadline = Clock::now() + std::chrono::milliseconds(5);
    if (!check(!lease.cleanup(first_deadline, diagnostic) &&
                   diagnostic.phase == attempt::FailurePhase::Child &&
                   diagnostic.error_number == ETIMEDOUT && Clock::now() >= first_deadline,
               "post-signal cleanup crosses caller deadline") ||
        !check(settlement && settlement->child_pid == child_pid &&
                   settlement->sigkill_attempts == 1u && settlement->sigkill_sent &&
                   !settlement->terminal && !settlement->reaped && cleanup->child_attempted &&
                   !cleanup->child_settled && !cleanup->handoff_attempted &&
                   !cleanup->null_attempted && !cleanup->capture_settle_attempted &&
                   !cleanup->capture_close_attempted,
               "post-signal timeout preserves exact owned signal receipt and owners"))
        return false;

    if (!check(lease.cleanup(Clock::now() + std::chrono::seconds(2), diagnostic),
               "post-signal cleanup retry reaps without resignal") ||
        !check(settlement->sigkill_attempts == 1u && settlement->sigkill_sent &&
                   settlement->terminal && settlement->reaped &&
                   WIFSIGNALED(settlement->wait_status) &&
                   WTERMSIG(settlement->wait_status) == SIGKILL &&
                   lease.state() == attempt::State::EvidenceClosed &&
                   cleanup->explicit_cleanup_complete &&
                   cleanup->explicit_cleanup_reportable_success && !cleanup->child_settled &&
                   cleanup->handoff_closed && cleanup->null_closed && cleanup->capture_settled &&
                   cleanup->capture_closed &&
                   cleanup->diagnostic.phase == attempt::FailurePhase::Child &&
                   cleanup->diagnostic.error_number == ETIMEDOUT,
               "post-signal retry exact terminal receipt and owner settlement"))
        return false;

    const attempt::CleanupState completed = *cleanup;
    const auto completed_receipt = *settlement;
    return check(lease.cleanup(Clock::now(), diagnostic), "post-signal completed cleanup replay") &&
           check(cleanup->explicit_cleanup_calls == completed.explicit_cleanup_calls + 1u &&
                     cleanup->child_attempted == completed.child_attempted &&
                     cleanup->child_settled == completed.child_settled &&
                     cleanup->handoff_attempted == completed.handoff_attempted &&
                     cleanup->handoff_closed == completed.handoff_closed &&
                     cleanup->null_attempted == completed.null_attempted &&
                     cleanup->null_closed == completed.null_closed &&
                     cleanup->capture_settle_attempted == completed.capture_settle_attempted &&
                     cleanup->capture_settled == completed.capture_settled &&
                     cleanup->capture_close_attempted == completed.capture_close_attempted &&
                     cleanup->capture_closed == completed.capture_closed &&
                     settlement->sigkill_attempts == completed_receipt.sigkill_attempts &&
                     settlement->sigkill_sent == completed_receipt.sigkill_sent &&
                     settlement->terminal == completed_receipt.terminal &&
                     settlement->reaped == completed_receipt.reaped &&
                     settlement->wait_status == completed_receipt.wait_status,
                 "post-signal completed replay performs no owner operation");
}

bool natural_timeout_then_cleanup(Owners& owners) {
    attempt::HooksForTesting hooks;
    attempt::Diagnostic diagnostic;
    attempt::PublicRutAttemptLease lease;
    if (!prepare_ok(lease, owners, "--attempt-live", hooks, diagnostic) ||
        !observe_ok(lease, owners, diagnostic) ||
        !check(!lease.settle_natural(1, Clock::now(), diagnostic) &&
                   diagnostic.phase == attempt::FailurePhase::Wait &&
                   diagnostic.error_number == ETIMEDOUT &&
                   lease.state() == attempt::State::ExecObservedLive,
               "natural settlement timeout preserves cleanup authority"))
        return false;
    const auto settlement = lease.settlement_receipt();
    return check(lease.cleanup(Clock::now() + std::chrono::seconds(2), diagnostic),
                 "cleanup after natural settlement timeout") &&
           check(settlement && settlement->terminal && settlement->reaped &&
                     WIFSIGNALED(settlement->wait_status) &&
                     WTERMSIG(settlement->wait_status) == SIGKILL,
                 "timeout cleanup exact killed receipt");
}

bool closed_evidence_cleanup_replay(Owners& owners) {
    attempt::HooksForTesting hooks;
    hooks.handoff.post_eof_delay_ms = 100u;
    attempt::Diagnostic diagnostic;
    attempt::PublicRutAttemptLease lease;
    if (!prepare_ok(lease, owners, "--attempt-exit1", hooks, diagnostic) ||
        !observe_ok(lease, owners, diagnostic) ||
        !lease.settle_natural(1, Clock::now() + std::chrono::seconds(2), diagnostic) ||
        !lease.close_evidence(diagnostic))
        return false;
    const auto cleanup_state = lease.cleanup_state();
    const auto before = *cleanup_state;
    return check(lease.cleanup(Clock::now(), diagnostic), "closed evidence cleanup") &&
           check(lease.cleanup(Clock::now(), diagnostic), "closed evidence cleanup replay") &&
           check(cleanup_state->explicit_cleanup_calls == 2u &&
                     cleanup_state->child_attempted == before.child_attempted &&
                     cleanup_state->child_settled == before.child_settled &&
                     cleanup_state->handoff_attempted == before.handoff_attempted &&
                     cleanup_state->handoff_closed == before.handoff_closed &&
                     cleanup_state->null_attempted == before.null_attempted &&
                     cleanup_state->null_closed == before.null_closed &&
                     cleanup_state->capture_settle_attempted == before.capture_settle_attempted &&
                     cleanup_state->capture_settled == before.capture_settled &&
                     cleanup_state->capture_close_attempted == before.capture_close_attempted &&
                     cleanup_state->capture_closed == before.capture_closed,
                 "closed evidence cleanup does not repeat settled owners");
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

bool explicit_cleanup_close_failure(Owners& owners) {
    CloseContext context;
    // release_and_observe retires three status writers first; fail the first
    // handoff descriptor close performed by attempt cleanup.
    context.fail_on = 4u;
    attempt::HooksForTesting hooks;
    hooks.handoff.close_fd = close_then_fail_selected;
    hooks.handoff.context = &context;
    attempt::Diagnostic diagnostic;
    attempt::PublicRutAttemptLease lease;
    if (!prepare_ok(lease, owners, "--attempt-live", hooks, diagnostic) ||
        !observe_ok(lease, owners, diagnostic))
        return false;
    const auto settlement = lease.settlement_receipt();
    const auto cleanup = lease.cleanup_state();
    if (!check(!lease.cleanup(Clock::now() + std::chrono::seconds(2), diagnostic) &&
                   diagnostic.phase == attempt::FailurePhase::Handoff &&
                   diagnostic.error_number == EINTR,
               "explicit cleanup retains first close failure") ||
        !check(settlement && settlement->terminal && settlement->reaped &&
                   WIFSIGNALED(settlement->wait_status) &&
                   WTERMSIG(settlement->wait_status) == SIGKILL,
               "close failure follows exact child settlement") ||
        !check(cleanup->child_attempted && cleanup->child_settled && cleanup->handoff_attempted &&
                   !cleanup->handoff_closed && cleanup->null_attempted && cleanup->null_closed &&
                   cleanup->capture_settle_attempted && cleanup->capture_settled &&
                   cleanup->capture_close_attempted && cleanup->capture_closed &&
                   cleanup->explicit_cleanup_complete &&
                   !cleanup->explicit_cleanup_reportable_success,
               "close failure still cleans remaining owners"))
        return false;
    const unsigned calls_after_cleanup = context.calls;
    return check(!lease.cleanup(Clock::now(), diagnostic) &&
                     diagnostic.phase == attempt::FailurePhase::Handoff &&
                     diagnostic.error_number == EINTR,
                 "failed cleanup idempotent diagnostic replay") &&
           check(context.calls == calls_after_cleanup && cleanup->explicit_cleanup_calls == 2u,
                 "failed cleanup does not repeat closes");
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
    ok = run_case("empty cleanup", empty_cleanup) && ok;
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
    ok = run_case("live bounded cleanup", live_bounded_cleanup) && ok;
    ok = run_case("live cleanup deadline retry", live_cleanup_deadline_retry) && ok;
    ok = run_case("live post-sigkill deadline retry", live_post_sigkill_deadline_retry) && ok;
    ok = run_case("natural timeout then cleanup", natural_timeout_then_cleanup) && ok;
    ok = run_case("closed evidence cleanup replay", closed_evidence_cleanup_replay) && ok;
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
    ok = run_case("explicit cleanup close failure", explicit_cleanup_close_failure) && ok;
    if (!ok) return 1;
    std::puts("PASS: #377 reusable public RUT attempt lease");
    return 0;
}
