#pragma once

#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

namespace rut::test {

class ScopedChildSubreaper {
    int previous_ = 0;
    bool enabled_ = false;

public:
    ScopedChildSubreaper() = default;
    ScopedChildSubreaper(const ScopedChildSubreaper&) = delete;
    ScopedChildSubreaper& operator=(const ScopedChildSubreaper&) = delete;
    ~ScopedChildSubreaper() {
        if (enabled_) (void)prctl(PR_SET_CHILD_SUBREAPER, previous_);
    }
    bool enable() {
        if (enabled_) return true;
        if (prctl(PR_GET_CHILD_SUBREAPER, &previous_) != 0) return false;
        if (prctl(PR_SET_CHILD_SUBREAPER, 1) != 0) return false;
        enabled_ = true;
        return true;
    }
};

inline volatile sig_atomic_t control_stop_requested = 0;
inline void request_control_stop(int) {
    control_stop_requested = 1;
}

inline long long control_now_ms() {
    timespec now{};
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return -1;
    return static_cast<long long>(now.tv_sec) * 1000 + now.tv_nsec / 1000000;
}

// Called only in the newly forked supervisor, before it creates any children.
// Every child of this process therefore belongs to this control. Orphans are
// adopted even if they changed process groups (e.g. the native compiler).
inline int supervise_forked_control(int (*run)(void*), void* context, int expected_exit = 86) {
    ScopedChildSubreaper subreaper;
    if (!subreaper.enable()) return 125;
    control_stop_requested = 0;
    struct sigaction action{};
    action.sa_handler = request_control_stop;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGTERM, &action, nullptr) != 0) return 125;
    const pid_t supervisor = getpid();
    const pid_t worker = fork();
    if (worker < 0) return 125;
    if (worker == 0) {
        if (prctl(PR_SET_PDEATHSIG, SIGKILL) != 0 || getppid() != supervisor) _exit(125);
        action.sa_handler = SIG_DFL;
        (void)sigaction(SIGTERM, &action, nullptr);
        _exit(run(context));
    }
    int status = 0;
    bool reaped = false;
    while (!control_stop_requested) {
        const pid_t result = waitpid(worker, &status, WNOHANG);
        if (result == worker) {
            reaped = true;
            break;
        }
        if (result < 0 && errno != EINTR) break;
        (void)poll(nullptr, 0, 5);
    }
    const bool stopped = control_stop_requested != 0;
    bool leftovers = false;
    const long long started = control_now_ms();
    if (started < 0) return 125;
    const long long deadline = started + 2000;
    for (;;) {
        int descendant_status = 0;
        const pid_t result = waitpid(-1, &descendant_status, WNOHANG);
        if (result < 0 && errno == ECHILD) {
            if (stopped) return 124;
            // An otherwise expected result cannot conceal leaked descendants.
            if (!reaped) return 125;
            if (WIFEXITED(status)) {
                if (leftovers) {
                    fprintf(stderr,
                            "control supervisor: worker_exit=%d leftover_descendants_reaped=1\n",
                            WEXITSTATUS(status));
                    if (WEXITSTATUS(status) == expected_exit) return 125;
                }
                return WEXITSTATUS(status);
            }
            if (WIFSIGNALED(status)) {
                const int signal = WTERMSIG(status);
                action.sa_handler = SIG_DFL;
                (void)sigaction(signal, &action, nullptr);
                (void)kill(getpid(), signal);
            }
            return 125;
        }
        if (result > 0) {
            if (result == worker) {
                status = descendant_status;
                reaped = true;
            } else {
                leftovers = true;
            }
        } else if (result < 0 && errno != EINTR) {
            return 125;
        }
        const long long now = control_now_ms();
        if (now < 0 || now >= deadline) return 125;
        // Do not reap during this scan: each PID remains reserved by a child
        // until the next wait, so signals cannot hit an unrelated reused PID.
        char path[96];
        snprintf(path, sizeof(path), "/proc/self/task/%ld/children", static_cast<long>(getpid()));
        FILE* children = fopen(path, "r");
        if (children == nullptr) return 125;
        char token[32];
        bool ok = true;
        while (fscanf(children, "%31s", token) == 1) {
            errno = 0;
            char* end = nullptr;
            const long child = strtol(token, &end, 10);
            if (errno != 0 || end == token || *end != '\0' || child > INT_MAX) {
                ok = false;
                break;
            }
            const long long scan_time = control_now_ms();
            if (scan_time < 0 || scan_time >= deadline) {
                ok = false;
                break;
            }
            if (child <= 0 || child == getpid()) {
                ok = false;
                break;
            }
            if (child != worker) leftovers = true;
            if (kill(static_cast<pid_t>(child), SIGKILL) != 0 && errno != ESRCH) ok = false;
        }
        if (ferror(children)) ok = false;
        fclose(children);
        if (!ok) return 125;
        (void)poll(nullptr, 0, 5);
    }
}

}  // namespace rut::test
