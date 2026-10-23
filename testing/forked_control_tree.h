#pragma once

#include <ctype.h>
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

inline constexpr int kControlCleanupDeadlineMs = 2000;
inline constexpr int kControlFallbackPasses = 400;
inline constexpr int kControlFallbackPollMs = 5;
inline constexpr int kControlReapBudgetMs =
    kControlCleanupDeadlineMs + kControlFallbackPasses * kControlFallbackPollMs + 2000;

inline volatile sig_atomic_t control_seek_failures = 0;

enum class ControlProcfsCapability : unsigned char {
    Supported,
    Unsupported,
    Error,
};

inline ControlProcfsCapability control_procfs_capability_from_errno(int error) {
    return error == ENOENT ? ControlProcfsCapability::Unsupported : ControlProcfsCapability::Error;
}

inline bool control_rewind(FILE* file) {
    if (control_seek_failures > 0) {
        control_seek_failures = control_seek_failures - 1;
        return false;
    }
    return fseek(file, 0, SEEK_SET) == 0;
}

inline ControlProcfsCapability probe_control_procfs_capability() {
    char path[64] = {};
    const int length =
        snprintf(path, sizeof(path), "/proc/self/task/%ld/children", static_cast<long>(getpid()));
    if (length < 0 || static_cast<size_t>(length) >= sizeof(path))
        return ControlProcfsCapability::Error;
    FILE* file = fopen(path, "r");
    if (file == nullptr) return control_procfs_capability_from_errno(errno);
    errno = 0;
    const int first = fgetc(file);
    const bool read_error = first == EOF && ferror(file);
    if (!control_rewind(file)) {
        (void)fclose(file);
        return ControlProcfsCapability::Error;
    }
    const int close_result = fclose(file);
    return read_error || close_result != 0 ? ControlProcfsCapability::Error
                                           : ControlProcfsCapability::Supported;
}

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
inline volatile sig_atomic_t control_clock_failures = 0;
inline volatile sig_atomic_t control_proc_open_failures = 0;
inline volatile sig_atomic_t control_read_failures = 0;
inline volatile sig_atomic_t control_persistent_read_after_preflight = 0;
inline volatile sig_atomic_t control_defer_cleanup_until_deadline = 0;
inline volatile sig_atomic_t control_fail_reopen_after_preflight = 0;
inline volatile sig_atomic_t control_scan_failures = 0;
inline void request_control_stop(int) {
    control_stop_requested = 1;
}

class ScopedControlFile {
    FILE* file_;

public:
    explicit ScopedControlFile(FILE* file) : file_(file) {}
    ScopedControlFile(const ScopedControlFile&) = delete;
    ScopedControlFile& operator=(const ScopedControlFile&) = delete;
    ~ScopedControlFile() {
        if (file_ != nullptr) fclose(file_);
    }
    FILE* get() const { return file_; }
    void close() {
        if (file_ != nullptr) {
            fclose(file_);
            file_ = nullptr;
        }
    }
};

inline long long control_now_ms() {
    if (control_clock_failures > 0) {
        control_clock_failures = control_clock_failures - 1;
        return -1;
    }
    timespec now{};
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return -1;
    return static_cast<long long>(now.tv_sec) * 1000 + now.tv_nsec / 1000000;
}

inline bool control_parse_child_pid(const char* token, pid_t self, pid_t& child_pid) {
    if (token[0] == '\0') return false;
    unsigned long value = 0;
    for (const char* cursor = token; *cursor != '\0'; ++cursor) {
        if (*cursor < '0' || *cursor > '9') return false;
        const unsigned digit = static_cast<unsigned>(*cursor - '0');
        if (value > (static_cast<unsigned long>(INT_MAX) - digit) / 10) return false;
        value = value * 10 + digit;
    }
    child_pid = static_cast<pid_t>(value);
    if (child_pid <= 0 || child_pid == self) return false;
    return true;
}

inline bool control_next_child_token(FILE* children, char (&token)[32], bool& has_token) {
    if (control_read_failures > 0) {
        control_read_failures = control_read_failures - 1;
        // Test seam: model a persistent retained-stream read error; this is not stdio I/O.
        errno = EIO;
        has_token = false;
        return false;
    }
    has_token = false;
    int character = fgetc(children);
    while (character != EOF && isspace(static_cast<unsigned char>(character)))
        character = fgetc(children);
    if (character == EOF) return !ferror(children);
    has_token = true;
    unsigned length = 0;
    while (character != EOF && !isspace(static_cast<unsigned char>(character))) {
        if (length + 1 >= sizeof(token)) return false;
        token[length++] = static_cast<char>(character);
        character = fgetc(children);
    }
    if (character == EOF && ferror(children)) return false;
    token[length] = '\0';
    return true;
}

inline bool control_validate_children(FILE* children, pid_t self, unsigned& count) {
    if (!control_rewind(children)) return false;
    clearerr(children);
    count = 0;
    char token[32];
    bool has_token = false;
    for (;;) {
        if (!control_next_child_token(children, token, has_token)) return false;
        if (!has_token) return true;
        pid_t child = -1;
        if (!control_parse_child_pid(token, self, child)) return false;
        ++count;
    }
}

inline bool control_signal_children(
    FILE* children, pid_t self, pid_t worker, bool worker_reaped, bool& leftovers) {
    if (!control_rewind(children)) return false;
    clearerr(children);
    char token[32];
    bool has_token = false;
    for (;;) {
        if (!control_next_child_token(children, token, has_token)) return false;
        if (!has_token) return true;
        pid_t child = -1;
        if (!control_parse_child_pid(token, self, child)) return false;
        if (child != worker) leftovers = true;
        if (child != worker || !worker_reaped) {
            if (kill(child, SIGKILL) != 0 && errno != ESRCH) return false;
        }
    }
}

inline void fallback_control_cleanup(FILE* children,
                                     pid_t worker,
                                     bool worker_reaped,
                                     bool worker_group_owned) {
    if (!worker_reaped) {
        (void)kill(worker, SIGKILL);
        if (worker_group_owned) (void)kill(-worker, SIGKILL);
    }
    // Keep retrying enumeration for a fixed number of passes. A broken clock
    // must not turn cleanup into an unbounded wait, and a broken procfs must
    // never cause a broad kill of unrelated processes.
    for (unsigned pass = 0; pass < kControlFallbackPasses; ++pass) {
        int status = 0;
        for (;;) {
            const pid_t result = waitpid(-1, &status, WNOHANG);
            if (result < 0 && (errno == ECHILD || errno == EINTR)) break;
            if (result <= 0) break;
        }
        if (children != nullptr) {
            const bool scan_failed = control_scan_failures > 0;
            if (scan_failed) control_scan_failures = control_scan_failures - 1;
            unsigned count = 0;
            bool ignored_leftovers = false;
            // A permanent read/parse failure means unknown descendants remain undiscovered;
            // bounded cleanup must never report that as successful cleanup.
            if (!scan_failed && control_validate_children(children, getpid(), count))
                (void)control_signal_children(
                    children, getpid(), worker, worker_reaped, ignored_leftovers);
        }
        (void)poll(nullptr, 0, kControlFallbackPollMs);
    }
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
    char children_path[96];
    snprintf(children_path,
             sizeof(children_path),
             "/proc/self/task/%ld/children",
             static_cast<long>(supervisor));
    ScopedControlFile children_owner(control_proc_open_failures > 0 ? nullptr
                                                                    : fopen(children_path, "r"));
    FILE* children = children_owner.get();
    if (control_proc_open_failures > 0) control_proc_open_failures = control_proc_open_failures - 1;
    if (children == nullptr) return 125;
    unsigned preflight_count = 0;
    if (!control_validate_children(children, supervisor, preflight_count)) {
        return 125;
    }
    if (!control_rewind(children)) return 125;
    clearerr(children);
    if (control_fail_reopen_after_preflight) control_proc_open_failures = INT_MAX;
    if (control_persistent_read_after_preflight) control_read_failures = INT_MAX;
    const pid_t worker = fork();
    if (worker < 0) {
        return 125;
    }
    if (worker == 0) {
        fclose(children);
        if (prctl(PR_SET_PDEATHSIG, SIGKILL) != 0 || getppid() != supervisor) _exit(125);
        action.sa_handler = SIG_DFL;
        (void)sigaction(SIGTERM, &action, nullptr);
        _exit(run(context));
    }
    const bool worker_group_owned = setpgid(worker, worker) == 0;
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
    if (started < 0) {
        fallback_control_cleanup(children, worker, reaped, worker_group_owned);
        return 125;
    }
    const long long deadline = started + kControlCleanupDeadlineMs;
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
                children_owner.close();
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
        if (now < 0 || now >= deadline) {
            fallback_control_cleanup(children, worker, reaped, worker_group_owned);
            return 125;
        }
        if (control_defer_cleanup_until_deadline) {
            (void)poll(nullptr, 0, kControlFallbackPollMs);
            continue;
        }
        // Do not reap during this scan: each PID remains reserved by a child
        // until the next wait, so signals cannot hit an unrelated reused PID.
        bool ok = true;
        const bool scan_failed = control_scan_failures > 0;
        if (scan_failed) control_scan_failures = control_scan_failures - 1;
        unsigned count = 0;
        if (scan_failed || !control_validate_children(children, supervisor, count) ||
            !control_signal_children(children, supervisor, worker, reaped, leftovers))
            ok = false;
        if (scan_failed) ok = false;
        if (ferror(children)) ok = false;
        if (!ok) {
            fallback_control_cleanup(children, worker, reaped, worker_group_owned);
            // If the retained procfs stream remains unreadable, descendants that escaped
            // before the failure cannot be discovered; this path is deliberately failure-only.
            return 125;
        }
        (void)poll(nullptr, 0, kControlFallbackPollMs);
    }
}

}  // namespace rut::test
