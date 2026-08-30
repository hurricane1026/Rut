#include "fixture_anonymous_log_capture.h"
#include "fixture_wildcard_paused_child_lease.h"
#include "fixture_wildcard_source_lease.h"
#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

#include <dirent.h>
#include <fcntl.h>
#include <linux/kcmp.h>
#include <poll.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

namespace capture = rut::test::fixture_anonymous_log_capture;
namespace child = rut::test::fixture_wildcard_paused_child_lease;
namespace listener = rut::test::fixture_privileged_listener;
namespace source = rut::test::fixture_wildcard_source_lease;

namespace {

using Clock = std::chrono::steady_clock;
constexpr listener::ListenerPlan kPlan{0x0a010203u, 0x0a010204u, 8080u};
constexpr char kBasename[] = "wildcard-attempt.rut";

Clock::time_point deadline(int milliseconds = 2000) {
    return Clock::now() + std::chrono::milliseconds(milliseconds);
}

bool check(bool condition, const char* message) {
    if (!condition) std::fprintf(stderr, "FAIL: %s (errno=%d)\n", message, errno);
    return condition;
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
    const bool close_ok = closedir(directory) == 0;
    if (read_error != 0 || !close_ok) {
        descriptors.clear();
        return false;
    }
    std::sort(descriptors.begin(), descriptors.end());
    return std::adjacent_find(descriptors.begin(), descriptors.end()) == descriptors.end();
}

bool child_snapshot(std::vector<pid_t>& children) {
    children.clear();
    std::string text;
    if (!rut::test::fixture_worker_protocol::read_file(
            "/proc/self/task/" + std::to_string(getpid()) + "/children", text, 65536))
        return false;
    const char* cursor = text.data();
    const char* const end = cursor + text.size();
    while (cursor != end) {
        while (cursor != end && (*cursor == ' ' || *cursor == '\n' || *cursor == '\t')) ++cursor;
        if (cursor == end) break;
        pid_t value = 0;
        const auto [parsed_end, parse_error] = std::from_chars(cursor, end, value, 10);
        if (parse_error != std::errc{} || parsed_end == cursor) {
            children.clear();
            return false;
        }
        children.push_back(value);
        cursor = parsed_end;
    }
    std::sort(children.begin(), children.end());
    return std::adjacent_find(children.begin(), children.end()) == children.end();
}

struct PrivateDirectory {
    std::string path;
    int fd = -1;

    bool create() {
        std::array<char, 64> pattern{};
        std::snprintf(pattern.data(), pattern.size(), "/tmp/rut377-compose-XXXXXX");
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
        if (fd >= 0) close(fd);
        if (!path.empty()) rmdir(path.c_str());
    }
};

bool create_source(PrivateDirectory& directory,
                   source::WildcardAttemptSourceLease& lease,
                   source::Diagnostic& diagnostic) {
    return directory.create() &&
           source::WildcardAttemptSourceLease::create(
               directory.fd, directory.path, kBasename, kPlan, lease, diagnostic);
}

bool settle_capture(capture::AnonymousLogCapture& output) {
    capture::Diagnostic settle_diagnostic;
    capture::Diagnostic snapshot_diagnostic;
    capture::Diagnostic close_diagnostic;
    std::string bytes;
    const bool settled = output.settle(settle_diagnostic);
    const bool snapshotted = output.snapshot(bytes, snapshot_diagnostic);
    const bool empty = bytes.empty();
    const bool closed = output.close(close_diagnostic);
    return settled && snapshotted && empty && closed;
}

bool canonical_composition() {
    std::vector<int> baseline_fds;
    std::vector<pid_t> baseline_children;
    if (!check(fd_snapshot(baseline_fds), "canonical baseline fd snapshot") ||
        !check(child_snapshot(baseline_children), "canonical baseline child snapshot"))
        return false;
    PrivateDirectory directory;
    source::WildcardAttemptSourceLease source_lease;
    source::Diagnostic source_diagnostic;
    capture::AnonymousLogCapture output;
    capture::Diagnostic capture_diagnostic;
    child::PausedChildLease child_lease;
    child::Diagnostic child_diagnostic;
    const bool created =
        check(create_source(directory, source_lease, source_diagnostic), "canonical source") &&
        check(capture::AnonymousLogCapture::create(4096, output, capture_diagnostic),
              "canonical capture") &&
        check(child::PausedChildLease::create_prepared(
                  deadline(), {output.descriptor()}, child_lease, child_diagnostic),
              "canonical prepared child");
    if (!created) return false;
    const std::string source_path = source_lease.path();
    bool ok = true;
    ok = check(child_lease.validate_paused(deadline(), child_diagnostic),
               "canonical mode-aware validation") &&
         ok;
    ok = check(child_lease.validate_prepared(deadline(), child_diagnostic),
               "canonical prepared validation") &&
         ok;
    ok = check(source_lease.revalidate(source_diagnostic), "canonical source validation") && ok;
    const bool released = child_lease.release(deadline(), child_diagnostic);
    ok = check(released, "canonical inert release") && ok;
    const bool child_inactive = !child_lease.active();
    ok = check(child_inactive, "canonical child not settled") && ok;
    if (child_inactive)
        ok = check(settle_capture(output), "canonical capture settlement") && ok;
    else
        ok = check(false, "canonical capture settlement withheld") && ok;
    // Source settlement remains independently attemptable even if another
    // settlement check above failed.
    const bool source_removed = source_lease.remove(source_diagnostic);
    ok = check(source_removed, "canonical source removal") && ok;
    if (source_removed) {
        ok = check(access(source_path.c_str(), F_OK) != 0 && errno == ENOENT,
                   "canonical source residue") &&
             ok;
        ok = check(directory.settle(), "canonical directory settlement") && ok;
    }
    std::vector<int> final_fds;
    std::vector<pid_t> final_children;
    const bool fd_read = fd_snapshot(final_fds);
    const bool child_read = child_snapshot(final_children);
    ok = check(fd_read && final_fds == baseline_fds, "canonical fd residue") && ok;
    ok = check(child_read && final_children == baseline_children, "canonical child residue") && ok;
    return ok;
}

bool plain_rejects_prepared_validation() {
    child::PausedChildLease lease;
    child::Diagnostic diagnostic;
    return check(child::PausedChildLease::create(deadline(), lease, diagnostic), "plain create") &&
           check(!lease.validate_prepared(deadline(), diagnostic),
                 "plain accepted prepared validation") &&
           check(diagnostic.phase == child::FailurePhase::Argument, "plain prepared diagnostic") &&
           check(lease.validate_paused(deadline(), diagnostic), "plain mode-aware validation") &&
           check(lease.release(deadline(), diagnostic), "plain release");
}

bool output_slot_mutation(bool clear_cloexec) {
    std::vector<int> baseline_fds;
    std::vector<pid_t> baseline_children;
    if (!check(fd_snapshot(baseline_fds), "mutation baseline fd snapshot") ||
        !check(child_snapshot(baseline_children), "mutation baseline child snapshot"))
        return false;
    PrivateDirectory directory;
    source::WildcardAttemptSourceLease source_lease;
    source::Diagnostic source_diagnostic;
    capture::AnonymousLogCapture output;
    capture::Diagnostic capture_diagnostic;
    child::PausedChildLease lease;
    child::Diagnostic diagnostic;
    if (!check(create_source(directory, source_lease, source_diagnostic), "mutation source") ||
        !check(capture::AnonymousLogCapture::create(4096, output, capture_diagnostic),
               "mutation capture") ||
        !check(child::PausedChildLease::create_prepared(
                   deadline(), {output.descriptor()}, lease, diagnostic),
               "mutation child") ||
        !check(lease.validate_prepared(deadline(), diagnostic), "mutation public validation"))
        return false;

    const int slot = output.descriptor();
    const int saved = fcntl(slot, F_DUPFD_CLOEXEC, 0);
    int replacement = -1;
    bool mutation_ok = saved >= 0;
    if (clear_cloexec) {
        const int flags = fcntl(slot, F_GETFD);
        mutation_ok = mutation_ok && flags >= 0 && fcntl(slot, F_SETFD, flags & ~FD_CLOEXEC) == 0;
    } else {
        replacement = open("/dev/null", O_WRONLY | O_CLOEXEC);
        mutation_ok = mutation_ok && replacement >= 0 && dup2(replacement, slot) == slot &&
                      fcntl(slot, F_SETFD, FD_CLOEXEC) == 0;
    }
    bool ok = check(mutation_ok, "output mutation setup");
    const bool rejected = !lease.release(deadline(), diagnostic);
    ok = check(rejected, "prior public validation authorized mutated release") && ok;
    ok =
        check(diagnostic.phase == child::FailurePhase::Descriptors, "output mutation diagnostic") &&
        ok;
    ok = check(lease.active(), "output mutation settled child") && ok;
    // The source has independent ownership and can settle after the child
    // release refusal; this does not authorize capture settlement.
    const bool source_removed = source_lease.remove(source_diagnostic);
    ok = check(source_removed, "independent source settlement") && ok;
    ok = check(dup2(saved, slot) == slot && fcntl(slot, F_SETFD, FD_CLOEXEC) == 0,
               "output mutation restore") &&
         ok;
    if (saved >= 0) close(saved);
    if (replacement >= 0) close(replacement);
    ok = check(lease.validate_prepared(deadline(), diagnostic),
               "output mutation retry validation") &&
         ok;
    const bool released = lease.release(deadline(), diagnostic);
    ok = check(released, "output mutation release retry") && ok;
    const bool child_inactive = !lease.active();
    ok = check(child_inactive, "output mutation child still active") && ok;
    if (child_inactive)
        ok = check(settle_capture(output), "independent capture settlement") && ok;
    else
        ok = check(false, "independent capture settlement withheld") && ok;
    if (source_removed) ok = check(directory.settle(), "mutation directory settlement") && ok;
    std::vector<int> final_fds;
    std::vector<pid_t> final_children;
    const bool fd_read = fd_snapshot(final_fds);
    const bool child_read = child_snapshot(final_children);
    ok = check(fd_read && final_fds == baseline_fds, "output mutation fd residue") && ok;
    ok =
        check(child_read && final_children == baseline_children, "output mutation child residue") &&
        ok;
    return ok;
}

bool sparse_high_descriptor_closure() {
    std::vector<int> baseline_fds;
    std::vector<pid_t> baseline_children;
    if (!check(fd_snapshot(baseline_fds), "sparse baseline fd snapshot") ||
        !check(child_snapshot(baseline_children), "sparse baseline child snapshot"))
        return false;
    const int low = open("/dev/null", O_RDONLY | O_CLOEXEC);
    const int high = low >= 0 ? fcntl(low, F_DUPFD_CLOEXEC, 512) : -1;
    if (low >= 0) close(low);
    capture::AnonymousLogCapture output;
    capture::Diagnostic capture_diagnostic;
    child::PausedChildLease lease;
    child::Diagnostic diagnostic;
    bool ok =
        check(high >= 512, "sparse high fd creation") &&
        check(capture::AnonymousLogCapture::create(4096, output, capture_diagnostic),
              "sparse capture") &&
        check(child::PausedChildLease::create_prepared(
                  deadline(), {output.descriptor()}, lease, diagnostic),
              "sparse child") &&
        check(access(("/proc/" + std::to_string(lease.child_pid()) + "/fd/" + std::to_string(high))
                         .c_str(),
                     F_OK) != 0 &&
                  errno == ENOENT,
              "sparse high fd inherited") &&
        check(lease.validate_prepared(deadline(), diagnostic), "sparse validation") &&
        check(lease.release(deadline(), diagnostic), "sparse release") &&
        check(settle_capture(output), "sparse capture settlement");
    if (high >= 0) close(high);
    std::vector<int> final_fds;
    std::vector<pid_t> final_children;
    const bool fd_read = fd_snapshot(final_fds);
    const bool child_read = child_snapshot(final_children);
    ok = check(fd_read && final_fds == baseline_fds, "sparse fd residue") && ok;
    ok = check(child_read && final_children == baseline_children, "sparse child residue") && ok;
    return ok;
}

bool prepared_release_retry_latch() {
    std::vector<int> baseline_fds;
    std::vector<pid_t> baseline_children;
    if (!check(fd_snapshot(baseline_fds), "latch baseline fd snapshot") ||
        !check(child_snapshot(baseline_children), "latch baseline child snapshot"))
        return false;
    capture::AnonymousLogCapture output;
    capture::Diagnostic capture_diagnostic;
    child::PausedChildLease lease;
    child::Diagnostic diagnostic;
    child::HooksForTesting hooks;
    hooks.post_release_delay_ms = 100;
    if (!check(capture::AnonymousLogCapture::create(4096, output, capture_diagnostic),
               "latch capture") ||
        !check(child::PausedChildLease::create_prepared_with_hooks_for_testing(
                   deadline(), {output.descriptor()}, hooks, lease, diagnostic),
               "latch child"))
        return false;
    const int slot = output.descriptor();
    const int saved = fcntl(slot, F_DUPFD_CLOEXEC, 0);
    const int replacement = open("/dev/null", O_WRONLY | O_CLOEXEC);
    bool ok = check(saved >= 0 && replacement >= 0, "latch mutation descriptors");
    const bool first_release = lease.release(deadline(5), diagnostic);
    ok = check(!first_release, "latch initial release did not time out") && ok;
    ok =
        check(diagnostic.phase == child::FailurePhase::Wait && diagnostic.error_number == ETIMEDOUT,
              "latch timeout diagnostic") &&
        ok;
    ok = check(dup2(replacement, slot) == slot && fcntl(slot, F_SETFD, FD_CLOEXEC) == 0,
               "latch output replacement") &&
         ok;
    pollfd exited{lease.observation_pidfd(), POLLIN | POLLERR | POLLHUP, 0};
    ok = check(poll(&exited, 1, 2000) == 1, "latch child exit") && ok;
    // Only the successful pre-send authorization internal to the first
    // release may authorize this retry; the now-wrong output slot cannot.
    ok = check(lease.release(deadline(), diagnostic), "latch release retry") && ok;
    ok = check(dup2(saved, slot) == slot && fcntl(slot, F_SETFD, FD_CLOEXEC) == 0,
               "latch output restore") &&
         ok;
    if (saved >= 0) close(saved);
    if (replacement >= 0) close(replacement);
    const bool child_inactive = !lease.active();
    ok = check(child_inactive, "latch child still active") && ok;
    if (child_inactive)
        ok = check(settle_capture(output), "latch capture settlement") && ok;
    else
        ok = check(false, "latch capture settlement withheld") && ok;
    std::vector<int> final_fds;
    std::vector<pid_t> final_children;
    const bool fd_read = fd_snapshot(final_fds);
    const bool child_read = child_snapshot(final_children);
    ok = check(fd_read && final_fds == baseline_fds, "latch fd residue") && ok;
    ok = check(child_read && final_children == baseline_children, "latch child residue") && ok;
    return ok;
}

struct ValidationHookState {
    bool deny_kcmp = false;
    bool deny_procfs = false;
};

int hooked_kcmp(pid_t first, pid_t second, int first_fd, int second_fd, void* opaque) {
    auto& state = *static_cast<ValidationHookState*>(opaque);
    if (state.deny_kcmp) {
        errno = EPERM;
        return -1;
    }
#ifdef SYS_kcmp
    return static_cast<int>(syscall(SYS_kcmp, first, second, KCMP_FILE, first_fd, second_fd));
#else
    (void)first;
    (void)second;
    (void)first_fd;
    (void)second_fd;
    errno = ENOSYS;
    return -1;
#endif
}

bool hooked_procfs(void* opaque) {
    return !static_cast<ValidationHookState*>(opaque)->deny_procfs;
}

bool fail_closed_validation_hooks() {
    std::vector<int> baseline_fds;
    std::vector<pid_t> baseline_children;
    if (!check(fd_snapshot(baseline_fds), "hook baseline fd snapshot") ||
        !check(child_snapshot(baseline_children), "hook baseline child snapshot"))
        return false;
    capture::AnonymousLogCapture output;
    capture::Diagnostic capture_diagnostic;
    child::PausedChildLease lease;
    child::Diagnostic diagnostic;
    ValidationHookState state;
    child::HooksForTesting hooks;
    hooks.kcmp_file = hooked_kcmp;
    hooks.prepared_procfs_allowed = hooked_procfs;
    hooks.prepared_validation_context = &state;
    if (!check(capture::AnonymousLogCapture::create(4096, output, capture_diagnostic),
               "hook capture") ||
        !check(child::PausedChildLease::create_prepared_with_hooks_for_testing(
                   deadline(), {output.descriptor()}, hooks, lease, diagnostic),
               "hook child"))
        return false;
    state.deny_kcmp = true;
    bool ok = check(!lease.validate_prepared(deadline(), diagnostic), "kcmp denial accepted") &&
              check(diagnostic.phase == child::FailurePhase::Descriptors &&
                        diagnostic.error_number == EPERM,
                    "kcmp denial diagnostic");
    state.deny_kcmp = false;
    state.deny_procfs = true;
    ok = check(!lease.validate_prepared(deadline(), diagnostic), "procfs denial accepted") &&
         check(diagnostic.phase == child::FailurePhase::Descriptors &&
                   diagnostic.error_number == EACCES,
               "procfs denial diagnostic") &&
         ok;
    state.deny_procfs = false;
    ok = check(lease.validate_prepared(deadline(), diagnostic), "hook validation recovery") && ok;
    const bool released = lease.release(deadline(), diagnostic);
    ok = check(released, "hook release") && ok;
    const bool child_inactive = !lease.active();
    ok = check(child_inactive, "hook child still active") && ok;
    if (child_inactive)
        ok = check(settle_capture(output), "hook capture settlement") && ok;
    else
        ok = check(false, "hook capture settlement withheld") && ok;
    std::vector<int> final_fds;
    std::vector<pid_t> final_children;
    const bool fd_read = fd_snapshot(final_fds);
    const bool child_read = child_snapshot(final_children);
    ok = check(fd_read && final_fds == baseline_fds, "hook fd residue") && ok;
    ok = check(child_read && final_children == baseline_children, "hook child residue") && ok;
    return ok;
}

bool child_close_failure_and_independent_settlement() {
    std::vector<int> baseline_fds;
    std::vector<pid_t> baseline_children;
    if (!check(fd_snapshot(baseline_fds), "failure baseline fd snapshot") ||
        !check(child_snapshot(baseline_children), "failure baseline child snapshot"))
        return false;
    PrivateDirectory directory;
    source::WildcardAttemptSourceLease source_lease;
    source::Diagnostic source_diagnostic;
    capture::AnonymousLogCapture output;
    capture::Diagnostic capture_diagnostic;
    const int low = open("/dev/null", O_RDONLY | O_CLOEXEC);
    const int high = low >= 0 ? fcntl(low, F_DUPFD_CLOEXEC, 700) : -1;
    if (low >= 0) close(low);
    child::HooksForTesting hooks;
    hooks.child_close_failure_fd = high;
    child::PausedChildLease lease;
    child::Diagnostic diagnostic;
    bool ok = check(high >= 700, "close failure high fd");
    const bool source_created = create_source(directory, source_lease, source_diagnostic);
    ok = check(source_created, "close failure source") && ok;
    const bool capture_created =
        capture::AnonymousLogCapture::create(4096, output, capture_diagnostic);
    ok = check(capture_created, "close failure capture") && ok;
    bool child_rejected = false;
    if (source_created && capture_created && high >= 700)
        child_rejected = !child::PausedChildLease::create_prepared_with_hooks_for_testing(
            deadline(), {output.descriptor()}, hooks, lease, diagnostic);
    ok = check(child_rejected, "child close EINTR accepted") && ok;
    ok = check(!lease.active(), "failed child lease became active") && ok;
    std::vector<pid_t> after_failure_children;
    const bool failure_children_read = child_snapshot(after_failure_children);
    const bool child_inactive =
        !lease.active() && failure_children_read && after_failure_children == baseline_children;
    ok = check(child_inactive, "failed child was not reaped") && ok;
    bool source_removed = false;
    if (source_created) {
        source_removed = source_lease.remove(source_diagnostic);
        ok = check(source_removed, "failed child source settlement") && ok;
    }
    if (capture_created && child_inactive)
        ok = check(settle_capture(output), "failed child capture settlement") && ok;
    else if (capture_created)
        ok = check(false, "failed child capture settlement withheld") && ok;
    if (source_removed) ok = check(directory.settle(), "failed child directory settlement") && ok;
    if (high >= 0) close(high);
    std::vector<int> final_fds;
    std::vector<pid_t> final_children;
    const bool fd_read = fd_snapshot(final_fds);
    const bool child_read = child_snapshot(final_children);
    ok = check(fd_read && final_fds == baseline_fds, "failed child fd residue") && ok;
    ok = check(child_read && final_children == baseline_children, "failed child process residue") &&
         ok;
    return ok;
}

}  // namespace

int main() {
    bool ok = true;
    ok = canonical_composition() && ok;
    ok = plain_rejects_prepared_validation() && ok;
    ok = output_slot_mutation(false) && ok;
    ok = output_slot_mutation(true) && ok;
    ok = sparse_high_descriptor_closure() && ok;
    ok = prepared_release_retry_latch() && ok;
    ok = fail_closed_validation_hooks() && ok;
    ok = child_close_failure_and_independent_settlement() && ok;
    if (!ok) return 1;
    std::puts("wildcard lease composition tests passed");
    return 0;
}
