#include "fixture_wildcard_paused_child_lease.h"
#include <cassert>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <stdexcept>

#include <dirent.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

namespace {

using rut::test::fixture_wildcard_paused_child_lease::Diagnostic;
using rut::test::fixture_wildcard_paused_child_lease::FailurePhase;
using rut::test::fixture_wildcard_paused_child_lease::HooksForTesting;
using rut::test::fixture_wildcard_paused_child_lease::PausedChildLease;

using Clock = std::chrono::steady_clock;

Clock::time_point deadline(int milliseconds = 2000) {
    return Clock::now() + std::chrono::milliseconds(milliseconds);
}

int fd_count() {
    DIR* directory = opendir("/proc/self/fd");
    if (directory == nullptr) return -1;
    int count = 0;
    while (readdir(directory) != nullptr) ++count;
    closedir(directory);
    return count;
}

int child_count() {
    std::ifstream children("/proc/self/task/" + std::to_string(getpid()) + "/children");
    if (!children) return -1;
    int count = 0;
    pid_t pid = 0;
    while (children >> pid) ++count;
    return count;
}

struct CloseHookState {
    int fail_fd = -1;
    bool fired = false;
};

int close_after_real_close(int fd, void* opaque) {
    auto* state = static_cast<CloseHookState*>(opaque);
    const int result = close(fd);
    if (result == 0 && state != nullptr && (state->fail_fd < 0 || fd == state->fail_fd) &&
        !state->fired) {
        state->fired = true;
        errno = EINTR;
        return -1;
    }
    return result;
}

volatile sig_atomic_t signal_count = 0;
void count_signal(int) {
    ++signal_count;
}

void check(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
}

void kill_by_pidfd(pid_t pid, const char* message) {
    const int pidfd = static_cast<int>(syscall(SYS_pidfd_open, pid, 0u));
    check(pidfd >= 0, message);
    check(syscall(SYS_pidfd_send_signal, pidfd, SIGKILL, nullptr, 0u) == 0, message);
    close(pidfd);
}

void canonical() {
    const int baseline = fd_count();
    check(baseline >= 0, "fd directory");
    PausedChildLease lease;
    Diagnostic diagnostic;
    check(PausedChildLease::create(deadline(), lease, diagnostic), "canonical create");
    check(lease.active() && lease.child_pid() > 0 && lease.observation_pidfd() >= 0,
          "canonical state");
    check(lease.validate_paused(deadline(), diagnostic), "canonical validation");
    check(lease.release(deadline(), diagnostic), "canonical release");
    check(!lease.active() && lease.released(), "canonical settled");
    check(fd_count() == baseline, "canonical fd baseline");
}

void sibling_rejection() {
    int pipefd[2] = {-1, -1};
    check(pipe(pipefd) == 0, "sibling pipe");
    const pid_t sibling = fork();
    check(sibling >= 0, "sibling fork");
    if (sibling == 0) {
        close(pipefd[0]);
        pause();
        _exit(0);
    }
    close(pipefd[1]);
    PausedChildLease lease;
    Diagnostic diagnostic;
    check(!PausedChildLease::create(deadline(), lease, diagnostic), "sibling accepted");
    check(diagnostic.phase == FailurePhase::Children, "sibling diagnostic");
    kill_by_pidfd(sibling, "sibling kill");
    check(waitpid(sibling, nullptr, 0) == sibling, "sibling reap");
    close(pipefd[0]);
}

void sibling_after_ready() {
    PausedChildLease lease;
    Diagnostic diagnostic;
    check(PausedChildLease::create(deadline(), lease, diagnostic), "post sibling create");
    const pid_t sibling = fork();
    check(sibling >= 0, "post sibling fork");
    if (sibling == 0) pause();
    check(waitpid(lease.child_pid(), nullptr, WNOHANG) == 0, "leased child died on sibling");
    check(waitpid(sibling, nullptr, WNOHANG) == 0, "sibling died on creation");
    check(!lease.validate_paused(deadline(), diagnostic), "post sibling accepted");
    check(diagnostic.phase == FailurePhase::Children, "post sibling phase");
    kill_by_pidfd(sibling, "post sibling kill");
    check(waitpid(sibling, nullptr, 0) == sibling, "post sibling reap");
    check(lease.validate_paused(deadline(), diagnostic), "post sibling recovery");
    check(lease.release(deadline(), diagnostic), "post sibling release");
}

void cloexec_and_independent_pidfd() {
    Diagnostic diagnostic;
    PausedChildLease lease;
    check(PausedChildLease::create(deadline(), lease, diagnostic), "mutation create");
    const int slot = lease.observation_pidfd();
    const int saved = dup(slot);
    check(saved >= 0, "mutation save");
    const int flags = fcntl(slot, F_GETFD);
    check(flags >= 0 && fcntl(slot, F_SETFD, flags & ~FD_CLOEXEC) == 0,
          "clear observation cloexec");
    check(!lease.cleanup(deadline(), diagnostic), "cleared cloexec accepted");
    check(lease.active(), "cleared cloexec lost authority");
    check(dup2(saved, slot) == slot && fcntl(slot, F_SETFD, FD_CLOEXEC) == 0,
          "restore observation cloexec");
    close(saved);
    const int original = dup(slot);
    check(original >= 0, "save original pidfd");
    const int independent = static_cast<int>(syscall(SYS_pidfd_open, lease.child_pid(), 0u));
    check(independent >= 0, "independent pidfd");
    const int replacement = dup(independent);
    check(replacement >= 0 && dup2(independent, slot) == slot, "replace independent pidfd");
    close(independent);
    check(!lease.cleanup(deadline(), diagnostic), "independent pidfd accepted");
    check(fcntl(slot, F_GETFD) >= 0, "independent pidfd was closed");
    check(dup2(original, slot) == slot, "restore independent replacement");
    check(fcntl(slot, F_SETFD, FD_CLOEXEC) == 0, "restore independent cloexec");
    close(original);
    close(replacement);
    check(lease.cleanup(deadline(), diagnostic), "independent recovery");
}

void wrong_observation_recovery() {
    PausedChildLease lease;
    Diagnostic diagnostic;
    check(PausedChildLease::create(deadline(), lease, diagnostic), "wrong create");
    const int slot = lease.observation_pidfd();
    const int saved = dup(slot);
    check(saved >= 0, "save pidfd");
    const int nullfd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    check(nullfd >= 0 && dup2(nullfd, slot) == slot, "replace pidfd");
    close(nullfd);
    check(!lease.cleanup(deadline(), diagnostic), "wrong pidfd cleanup accepted");
    check(lease.active(), "wrong pidfd lost authority");
    check(dup2(saved, slot) == slot, "restore pidfd");
    check(fcntl(slot, F_SETFD, FD_CLOEXEC) == 0, "restore cloexec");
    close(saved);
    check(lease.cleanup(deadline(), diagnostic), "restored cleanup");
}

void dead_child_reap() {
    PausedChildLease lease;
    Diagnostic diagnostic;
    check(PausedChildLease::create(deadline(), lease, diagnostic), "dead create");
    const int slot = lease.observation_pidfd();
    const int saved = dup(slot);
    check(saved >= 0, "dead save");
    check(syscall(SYS_pidfd_send_signal, saved, SIGKILL, nullptr, 0u) == 0, "dead signal");
    pollfd dead{saved, POLLIN | POLLERR | POLLHUP, 0};
    check(poll(&dead, 1, 2000) == 1, "dead wait");
    const int nullfd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    check(nullfd >= 0 && dup2(nullfd, slot) == slot, "dead replace");
    close(nullfd);
    check(!lease.cleanup(deadline(), diagnostic), "dead wrong pidfd accepted");
    check(dup2(saved, slot) == slot, "dead restore");
    check(fcntl(slot, F_SETFD, FD_CLOEXEC) == 0, "dead restore cloexec");
    close(saved);
    check(lease.cleanup(deadline(), diagnostic), "dead reap retry");
}

void expired_and_destructor() {
    Diagnostic diagnostic;
    PausedChildLease lease;
    check(PausedChildLease::create(deadline(), lease, diagnostic), "expired create");
    check(!lease.release(Clock::now() - std::chrono::milliseconds(1), diagnostic),
          "expired release accepted");
    check(lease.release(deadline(), diagnostic), "release retry");
    PausedChildLease expired_cleanup;
    check(PausedChildLease::create(deadline(), expired_cleanup, diagnostic),
          "expired cleanup create");
    check(!expired_cleanup.cleanup(Clock::now() - std::chrono::milliseconds(1), diagnostic),
          "expired cleanup accepted");
    check(expired_cleanup.cleanup(deadline(), diagnostic), "expired cleanup recovery");
    std::shared_ptr<const rut::test::fixture_wildcard_paused_child_lease::CleanupState> evidence;
    {
        PausedChildLease scoped;
        check(PausedChildLease::create(deadline(), scoped, diagnostic), "destructor create");
        evidence = scoped.cleanup_state();
        check(!evidence->attempted && scoped.active(), "destructor pre-evidence");
    }
    check(evidence->attempted && !evidence->succeeded, "destructor evidence");
}

int failing_pidfd(pid_t, unsigned int) {
    errno = ENOSYS;
    return -1;
}

void creation_failures() {
    Diagnostic diagnostic;
    PausedChildLease lease;
    const int baseline_fds = fd_count();
    const int baseline_children = child_count();
    HooksForTesting fork_hooks;
    fork_hooks.fail_fork = true;
    check(
        !PausedChildLease::create_with_hooks_for_testing(deadline(), fork_hooks, lease, diagnostic),
        "fork failure accepted");
    check(diagnostic.phase == FailurePhase::Fork, "fork failure phase");
    check(fd_count() == baseline_fds && child_count() == baseline_children, "fork failure residue");
    HooksForTesting pidfd_hooks;
    pidfd_hooks.pidfd_open = failing_pidfd;
    check(!PausedChildLease::create_with_hooks_for_testing(
              deadline(), pidfd_hooks, lease, diagnostic),
          "pidfd failure accepted");
    check(diagnostic.phase == FailurePhase::Pidfd, "pidfd failure phase");
    check(fd_count() == baseline_fds && child_count() == baseline_children,
          "pidfd failure residue");
}

void close_uncertainty() {
    Diagnostic diagnostic;
    PausedChildLease lease;
    check(PausedChildLease::create(deadline(), lease, diagnostic), "close uncertainty create");
    check(close(lease.observation_pidfd()) == 0, "close observation externally");
    check(!lease.cleanup(deadline(), diagnostic), "closed observation accepted");
    check(lease.cleanup_state()->attempted && !lease.cleanup_state()->succeeded,
          "cleanup uncertainty evidence");
}

void injected_close_uncertainty() {
    Diagnostic diagnostic;
    CloseHookState state;
    HooksForTesting hooks;
    hooks.close_fd = close_after_real_close;
    hooks.close_context = &state;
    PausedChildLease lease;
    check(PausedChildLease::create_with_hooks_for_testing(deadline(), hooks, lease, diagnostic),
          "release close hook create");
    check(!lease.release(deadline(), diagnostic), "release close uncertainty accepted");
    check(state.fired && !lease.cleanup_state()->succeeded, "release close hook evidence");

    CloseHookState pidfd_state;
    hooks.close_context = &pidfd_state;
    PausedChildLease pidfd_lease;
    check(
        PausedChildLease::create_with_hooks_for_testing(deadline(), hooks, pidfd_lease, diagnostic),
        "pidfd close hook create");
    pidfd_state.fail_fd = pidfd_lease.observation_pidfd();
    check(!pidfd_lease.cleanup(deadline(), diagnostic), "pidfd close uncertainty accepted");
    check(pidfd_state.fired, "pidfd close hook evidence");
}

void interrupted_waits() {
    struct sigaction action{};
    action.sa_handler = count_signal;
    sigemptyset(&action.sa_mask);
    check(sigaction(SIGALRM, &action, nullptr) == 0, "install alarm");
    itimerval timer{};
    timer.it_value.tv_usec = 1000;
    timer.it_interval.tv_usec = 1000;
    check(setitimer(ITIMER_REAL, &timer, nullptr) == 0, "start alarm");
    PausedChildLease lease;
    Diagnostic diagnostic;
    HooksForTesting hooks;
    hooks.child_delay_ms = 100;
    check(PausedChildLease::create_with_hooks_for_testing(deadline(), hooks, lease, diagnostic),
          "eintr create");
    check(signal_count > 0, "no causal EINTR signal");
    check(lease.release(deadline(), diagnostic), "eintr release");
    timer = {};
    check(setitimer(ITIMER_REAL, &timer, nullptr) == 0, "stop alarm");
}

}  // namespace

int main() {
    try {
        canonical();
        sibling_rejection();
        sibling_after_ready();
        wrong_observation_recovery();
        cloexec_and_independent_pidfd();
        dead_child_reap();
        expired_and_destructor();
        creation_failures();
        close_uncertainty();
        injected_close_uncertainty();
        interrupted_waits();
        std::cout << "paused wildcard child lease tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
