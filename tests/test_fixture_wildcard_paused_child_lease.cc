#include "fixture_wildcard_paused_child_lease.h"
#include <cassert>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdio>
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
    check(!lease.validate_paused(deadline(), diagnostic), "post sibling accepted");
    check(diagnostic.phase == FailurePhase::Children, "post sibling phase");
    kill_by_pidfd(sibling, "post sibling kill");
    check(waitpid(sibling, nullptr, 0) == sibling, "post sibling reap");
    check(lease.validate_paused(deadline(), diagnostic), "post sibling recovery");
    check(lease.release(deadline(), diagnostic), "post sibling release");
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
    {
        PausedChildLease scoped;
        check(PausedChildLease::create(deadline(), scoped, diagnostic), "destructor create");
    }
}

int failing_pidfd(pid_t, unsigned int) {
    errno = ENOSYS;
    return -1;
}

void creation_failures() {
    Diagnostic diagnostic;
    PausedChildLease lease;
    HooksForTesting fork_hooks;
    fork_hooks.fail_fork = true;
    check(
        !PausedChildLease::create_with_hooks_for_testing(deadline(), fork_hooks, lease, diagnostic),
        "fork failure accepted");
    check(diagnostic.phase == FailurePhase::Fork, "fork failure phase");
    HooksForTesting pidfd_hooks;
    pidfd_hooks.pidfd_open = failing_pidfd;
    check(!PausedChildLease::create_with_hooks_for_testing(
              deadline(), pidfd_hooks, lease, diagnostic),
          "pidfd failure accepted");
    check(diagnostic.phase == FailurePhase::Pidfd, "pidfd failure phase");
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

void interrupted_waits() {
    struct sigaction action{};
    action.sa_handler = [](int) {};
    sigemptyset(&action.sa_mask);
    check(sigaction(SIGALRM, &action, nullptr) == 0, "install alarm");
    itimerval timer{};
    timer.it_value.tv_usec = 1000;
    timer.it_interval.tv_usec = 1000;
    check(setitimer(ITIMER_REAL, &timer, nullptr) == 0, "start alarm");
    PausedChildLease lease;
    Diagnostic diagnostic;
    check(PausedChildLease::create(deadline(), lease, diagnostic), "eintr create");
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
        dead_child_reap();
        expired_and_destructor();
        creation_failures();
        close_uncertainty();
        interrupted_waits();
        std::cout << "paused wildcard child lease tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
