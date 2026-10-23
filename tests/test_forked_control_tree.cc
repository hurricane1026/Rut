#include "forked_control_tree.h"
#include "test.h"

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

namespace {

bool wait_terminal(pid_t pid, int& status, unsigned attempts = 600) {
    for (unsigned i = 0; i < attempts; ++i) {
        const pid_t kResult = waitpid(pid, &status, WNOHANG);
        if (kResult == pid) return true;
        if (kResult < 0 && errno != EINTR) return false;
        (void)poll(nullptr, 0, 5);
    }
    return false;
}

enum class ControlExit : unsigned char {
    Stall,
    ManyStalls,
    UnexpectedStatus,
    Signal,
    ExpectedStatus
};

bool cleanup_case(ControlExit mode,
                  sig_atomic_t clock_failures = 0,
                  sig_atomic_t proc_open_failures = 0,
                  sig_atomic_t scan_failures = 0,
                  int expected_status_override = -1,
                  sig_atomic_t fail_reopen_after_preflight = 0) {
    rut::test::ScopedChildSubreaper subreaper;
    if (!subreaper.enable()) return false;
    int channel[2];
    if (pipe(channel) != 0) return false;
    const int kHeld = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socklen_t size = sizeof(address);
    if (kHeld < 0 || bind(kHeld, reinterpret_cast<sockaddr*>(&address), size) != 0 ||
        getsockname(kHeld, reinterpret_cast<sockaddr*>(&address), &size) != 0) {
        if (kHeld >= 0) close(kHeld);
        close(channel[0]);
        close(channel[1]);
        return false;
    }
    struct Context {
        int* channel;
        ControlExit mode;
    } context{channel, mode};
    rut::test::control_clock_failures = clock_failures;
    rut::test::control_proc_open_failures = proc_open_failures;
    rut::test::control_scan_failures = scan_failures;
    rut::test::control_fail_reopen_after_preflight = fail_reopen_after_preflight;
    const pid_t kControl = fork();
    if (kControl == 0) {
        _exit(rut::test::supervise_forked_control(
            [](void* opaque) -> int {
                auto& context = *static_cast<Context*>(opaque);
                close(context.channel[0]);
                const unsigned sentinel_count = context.mode == ControlExit::ManyStalls ? 80 : 1;
                pid_t first_sentinel = -1;
                for (unsigned i = 0; i < sentinel_count; ++i) {
                    const pid_t sentinel = fork();
                    if (sentinel < 0) return 41;
                    if (sentinel == 0) {
                        close(context.channel[1]);
                        if (setpgid(0, 0) != 0) _exit(42);
                        for (;;) pause();
                    }
                    if (setpgid(sentinel, sentinel) != 0) return 44;
                    if (first_sentinel < 0) first_sentinel = sentinel;
                }
                if (write(context.channel[1], &first_sentinel, sizeof(first_sentinel)) !=
                    sizeof(first_sentinel))
                    return 43;
                close(context.channel[1]);
                if (context.mode == ControlExit::UnexpectedStatus) return 87;
                if (context.mode == ControlExit::ExpectedStatus) return 86;
                if (context.mode == ControlExit::Signal) (void)kill(getpid(), SIGKILL);
                for (;;) pause();
            },
            &context));
    }
    rut::test::control_clock_failures = 0;
    rut::test::control_proc_open_failures = 0;
    rut::test::control_scan_failures = 0;
    rut::test::control_fail_reopen_after_preflight = 0;
    close(channel[1]);
    close(kHeld);
    if (kControl < 0) {
        close(channel[0]);
        return false;
    }
    pollfd ready{channel[0], POLLIN, 0};
    pid_t sentinel = -1;
    bool ok = poll(&ready, 1, 3000) > 0 &&
              read(channel[0], &sentinel, sizeof(sentinel)) == sizeof(sentinel) && sentinel > 0;
    close(channel[0]);

    // A different child's exit status must remain available to its owner.
    const pid_t kUnrelated = fork();
    if (kUnrelated == 0) _exit(73);
    if (kUnrelated < 0) ok = false;
    int control_status = 0;
    if ((mode == ControlExit::Stall || mode == ControlExit::ManyStalls) &&
        kill(kControl, SIGTERM) != 0)
        ok = false;
    if (!wait_terminal(kControl, control_status)) {
        (void)kill(kControl, SIGKILL);
        (void)wait_terminal(kControl, control_status);
        ok = false;
    }
    // A success-shaped worker result with leftover children is rejected too.
    if (mode == ControlExit::Signal)
        ok = ok && WIFSIGNALED(control_status) && WTERMSIG(control_status) == SIGKILL;
    else {
        const int expected_status =
            expected_status_override >= 0
                ? expected_status_override
                : (mode == ControlExit::Stall || mode == ControlExit::ManyStalls ? 124
                   : mode == ControlExit::UnexpectedStatus                       ? 87
                                                                                 : 125);
        ok = ok && WIFEXITED(control_status) && WEXITSTATUS(control_status) == expected_status;
    }
    if (sentinel > 0) {
        errno = 0;
        const bool sentinel_gone = kill(sentinel, 0) == -1 && errno == ESRCH;
        if (!sentinel_gone) {
            ok = false;
        }
        errno = 0;
        int status = 0;
        const pid_t reaped = waitpid(sentinel, &status, WNOHANG);
        if (reaped == 0) {
            ok = false;
            (void)kill(sentinel, SIGKILL);
            int cleanup_status = 0;
            (void)wait_terminal(sentinel, cleanup_status);
        } else if (reaped == sentinel) {
            // It is already reaped; never signal a potentially reused PID.
            ok = false;
        } else if (reaped != -1 || errno != ECHILD) {
            ok = false;
        }
    }
    if (kUnrelated > 0) {
        int status = 0;
        if (!wait_terminal(kUnrelated, status) || !WIFEXITED(status) || WEXITSTATUS(status) != 73)
            ok = false;
    }
    const int kRebound = socket(AF_INET, SOCK_STREAM, 0);
    if (kRebound < 0)
        ok = false;
    else {
        if (bind(kRebound, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) ok = false;
        close(kRebound);
    }
    return ok;
}

}  // namespace

TEST(forked_control, stalled_tree_is_reaped_and_port_released) {
    CHECK(cleanup_case(ControlExit::Stall));
}

TEST(forked_control, unexpected_exit_tree_is_reaped) {
    CHECK(cleanup_case(ControlExit::UnexpectedStatus));
}

TEST(forked_control, signaled_tree_is_reaped) {
    CHECK(cleanup_case(ControlExit::Signal));
}

TEST(forked_control, expected_status_does_not_hide_leftover_descendants) {
    CHECK(cleanup_case(ControlExit::ExpectedStatus));
}

TEST(forked_control, clean_expected_exit_is_preserved) {
    const pid_t kChild = fork();
    REQUIRE(kChild >= 0);
    if (kChild == 0)
        _exit(rut::test::supervise_forked_control([](void*) -> int { return 86; }, nullptr));
    int status = 0;
    CHECK(wait_terminal(kChild, status));
    CHECK(WIFEXITED(status));
    CHECK_EQ(WEXITSTATUS(status), 86);
}

TEST(forked_control, restores_subreaper_state) {
    int before = -1;
    REQUIRE_EQ(prctl(PR_GET_CHILD_SUBREAPER, &before), 0);
    {
        rut::test::ScopedChildSubreaper scope;
        REQUIRE(scope.enable());
        REQUIRE(scope.enable());
        int enabled = 0;
        CHECK_EQ(prctl(PR_GET_CHILD_SUBREAPER, &enabled), 0);
        CHECK_EQ(enabled, 1);
    }
    int after = -1;
    CHECK_EQ(prctl(PR_GET_CHILD_SUBREAPER, &after), 0);
    CHECK_EQ(after, before);
}

TEST(forked_control, procfs_scan_failure_falls_back_and_reaps_tree) {
    CHECK(cleanup_case(ControlExit::UnexpectedStatus, 0, 0, 1, 125));
}

TEST(forked_control, large_children_snapshot_is_fully_reaped) {
    CHECK(cleanup_case(ControlExit::ManyStalls));
}

TEST(forked_control, procfs_open_failure_before_worker_is_fail_closed) {
    rut::test::control_proc_open_failures = INT_MAX;
    int marker[2];
    REQUIRE_EQ(pipe(marker), 0);
    const pid_t child = fork();
    REQUIRE(child >= 0);
    if (child == 0) {
        close(marker[0]);
        struct Context {
            int fd;
        } context{marker[1]};
        _exit(rut::test::supervise_forked_control(
            [](void* opaque) -> int {
                const auto& context = *static_cast<Context*>(opaque);
                (void)write(context.fd, "x", 1);
                return 86;
            },
            &context));
    }
    close(marker[1]);
    rut::test::control_proc_open_failures = 0;
    int status = 0;
    bool exited = wait_terminal(child, status);
    CHECK(exited);
    if (!exited) {
        (void)kill(child, SIGKILL);
        exited = wait_terminal(child, status);
        CHECK(exited);
    }
    CHECK(WIFEXITED(status));
    CHECK_EQ(WEXITSTATUS(status), 125);
    char marker_byte = 0;
    pollfd marker_ready{marker[0], POLLIN | POLLHUP, 0};
    CHECK(poll(&marker_ready, 1, 100) >= 0);
    CHECK((marker_ready.revents & (POLLIN | POLLHUP)) != 0);
    CHECK((marker_ready.revents & (POLLERR | POLLNVAL)) == 0);
    if ((marker_ready.revents & (POLLIN | POLLHUP)) != 0 &&
        (marker_ready.revents & (POLLERR | POLLNVAL)) == 0)
        CHECK_EQ(read(marker[0], &marker_byte, 1), 0);
    close(marker[0]);
}

TEST(forked_control, procfs_read_failure_before_worker_is_fail_closed) {
    rut::test::control_read_failures = INT_MAX;
    int marker[2];
    REQUIRE_EQ(pipe(marker), 0);
    const pid_t child = fork();
    REQUIRE(child >= 0);
    if (child == 0) {
        close(marker[0]);
        struct Context {
            int fd;
        } context{marker[1]};
        _exit(rut::test::supervise_forked_control(
            [](void* opaque) -> int {
                const auto& context = *static_cast<Context*>(opaque);
                (void)write(context.fd, "x", 1);
                return 86;
            },
            &context));
    }
    close(marker[1]);
    rut::test::control_read_failures = 0;
    int status = 0;
    bool exited = wait_terminal(child, status);
    CHECK(exited);
    if (!exited) {
        (void)kill(child, SIGKILL);
        exited = wait_terminal(child, status);
        CHECK(exited);
    }
    CHECK(WIFEXITED(status));
    CHECK_EQ(WEXITSTATUS(status), 125);
    char marker_byte = 0;
    pollfd marker_ready{marker[0], POLLIN | POLLHUP, 0};
    CHECK(poll(&marker_ready, 1, 100) >= 0);
    CHECK((marker_ready.revents & (POLLIN | POLLHUP)) != 0);
    CHECK((marker_ready.revents & (POLLERR | POLLNVAL)) == 0);
    if ((marker_ready.revents & (POLLIN | POLLHUP)) != 0 &&
        (marker_ready.revents & (POLLERR | POLLNVAL)) == 0)
        CHECK_EQ(read(marker[0], &marker_byte, 1), 0);
    close(marker[0]);
}

TEST(forked_control, persistent_postlaunch_read_failure_is_bounded) {
    rut::test::ScopedChildSubreaper subreaper;
    REQUIRE(subreaper.enable());
    rut::test::control_persistent_read_after_preflight = 1;
    int channel[2];
    REQUIRE_EQ(pipe(channel), 0);
    const pid_t control = fork();
    REQUIRE(control >= 0);
    if (control == 0) {
        close(channel[0]);
        struct Context {
            int fd;
        } context{channel[1]};
        _exit(rut::test::supervise_forked_control(
            [](void* opaque) -> int {
                const auto& context = *static_cast<Context*>(opaque);
                const pid_t sentinel = fork();
                if (sentinel < 0) return 41;
                if (sentinel == 0) {
                    close(context.fd);
                    if (setpgid(0, 0) != 0) _exit(42);
                    for (;;) pause();
                }
                if (setpgid(sentinel, sentinel) != 0) return 43;
                (void)write(context.fd, &sentinel, sizeof(sentinel));
                return 87;
            },
            &context));
    }
    close(channel[1]);
    rut::test::control_persistent_read_after_preflight = 0;
    pid_t sentinel = -1;
    pollfd ready{channel[0], POLLIN | POLLHUP, 0};
    const int ready_result = poll(&ready, 1, 3000);
    CHECK(ready_result >= 0);
    CHECK((ready.revents & (POLLERR | POLLNVAL)) == 0);
    const bool sentinel_readable = ready_result > 0 && (ready.revents & POLLIN) != 0;
    CHECK(sentinel_readable);
    if (!sentinel_readable) {
        (void)kill(control, SIGKILL);
        int abandoned_status = 0;
        CHECK(wait_terminal(control, abandoned_status));
        (void)fcntl(channel[0], F_SETFL, O_NONBLOCK);
        pid_t abandoned_sentinel = -1;
        const ssize_t drained = read(channel[0], &abandoned_sentinel, sizeof(abandoned_sentinel));
        if (drained == sizeof(abandoned_sentinel) && abandoned_sentinel > 0) {
            int abandoned_sentinel_status = 0;
            const pid_t observed = waitpid(abandoned_sentinel, &abandoned_sentinel_status, WNOHANG);
            CHECK_EQ(observed, 0);
            if (observed == 0) {
                (void)kill(abandoned_sentinel, SIGKILL);
                CHECK(wait_terminal(abandoned_sentinel, abandoned_sentinel_status));
            }
        }
        close(channel[0]);
        return;
    }
    CHECK_EQ(read(channel[0], &sentinel, sizeof(sentinel)), sizeof(sentinel));
    close(channel[0]);
    CHECK(sentinel > 0);
    CHECK_EQ(getpgid(sentinel), sentinel);
    const pid_t sibling = fork();
    REQUIRE(sibling >= 0);
    if (sibling == 0) _exit(73);
    int status = 0;
    const bool exited = wait_terminal(control, status, 2000);
    CHECK(exited);
    if (!exited) {
        (void)kill(control, SIGKILL);
        CHECK(wait_terminal(control, status));
    }
    CHECK(WIFEXITED(status));
    CHECK_EQ(WEXITSTATUS(status), 125);
    if (sentinel > 0) {
        int sentinel_status = 0;
        const pid_t observed = waitpid(sentinel, &sentinel_status, WNOHANG);
        CHECK_EQ(observed, 0);
        if (observed == 0) {
            CHECK_EQ(kill(sentinel, SIGKILL), 0);
            CHECK(wait_terminal(sentinel, sentinel_status));
        }
    }
    int sibling_status = 0;
    CHECK(wait_terminal(sibling, sibling_status));
    CHECK(WIFEXITED(sibling_status));
    CHECK_EQ(WEXITSTATUS(sibling_status), 73);
}

TEST(forked_control, deadline_fallback_reaps_escaped_group_without_hardkill) {
    rut::test::ScopedChildSubreaper subreaper;
    REQUIRE(subreaper.enable());
    rut::test::control_defer_cleanup_until_deadline = 1;
    int channel[2];
    REQUIRE_EQ(pipe(channel), 0);
    const pid_t control = fork();
    REQUIRE(control >= 0);
    if (control == 0) {
        close(channel[0]);
        struct Context {
            int fd;
        } context{channel[1]};
        _exit(rut::test::supervise_forked_control(
            [](void* opaque) -> int {
                const auto& context = *static_cast<Context*>(opaque);
                const pid_t sentinel = fork();
                if (sentinel < 0) return 41;
                if (sentinel == 0) {
                    close(context.fd);
                    if (setpgid(0, 0) != 0) _exit(42);
                    for (;;) pause();
                }
                if (setpgid(sentinel, sentinel) != 0) return 43;
                (void)write(context.fd, &sentinel, sizeof(sentinel));
                return 87;
            },
            &context));
    }
    close(channel[1]);
    rut::test::control_defer_cleanup_until_deadline = 0;
    pid_t sentinel = -1;
    auto abort_control = [&]() {
        (void)kill(control, SIGKILL);
        int control_status = 0;
        (void)wait_terminal(control, control_status);
        (void)fcntl(channel[0], F_SETFL, O_NONBLOCK);
        if (read(channel[0], &sentinel, sizeof(sentinel)) == sizeof(sentinel) && sentinel > 0) {
            int sentinel_status = 0;
            const pid_t observed = waitpid(sentinel, &sentinel_status, WNOHANG);
            if (observed == 0) {
                (void)kill(sentinel, SIGKILL);
                (void)wait_terminal(sentinel, sentinel_status);
            }
        }
        close(channel[0]);
    };
    pollfd ready{channel[0], POLLIN, 0};
    const int ready_result = poll(&ready, 1, 3000);
    if (ready_result != 1 || (ready.revents & POLLIN) == 0 ||
        (ready.revents & (POLLERR | POLLNVAL)) != 0) {
        CHECK(false);
        abort_control();
        return;
    }
    if (read(channel[0], &sentinel, sizeof(sentinel)) != sizeof(sentinel) || sentinel <= 0) {
        CHECK(false);
        abort_control();
        return;
    }
    close(channel[0]);
    const pid_t sibling = fork();
    REQUIRE(sibling >= 0);
    if (sibling == 0) _exit(73);
    int status = 0;
    const bool exited = wait_terminal(control, status, rut::test::kControlReapBudgetMs / 5);
    CHECK(exited);
    if (!exited) {
        (void)kill(control, SIGKILL);
        CHECK(wait_terminal(control, status));
    }
    CHECK(WIFEXITED(status));
    CHECK_EQ(WEXITSTATUS(status), 125);
    int sentinel_status = 0;
    const pid_t observed = waitpid(sentinel, &sentinel_status, WNOHANG);
    CHECK_NE(observed, 0);
    if (observed == 0) {
        CHECK_EQ(kill(sentinel, SIGKILL), 0);
        CHECK(wait_terminal(sentinel, sentinel_status));
    } else if (observed == sentinel) {
        CHECK(WIFSIGNALED(sentinel_status));
    } else {
        CHECK(observed < 0 && errno == ECHILD);
        errno = 0;
        CHECK_EQ(kill(sentinel, 0), -1);
        CHECK_EQ(errno, ESRCH);
    }
    int sibling_status = 0;
    CHECK(wait_terminal(sibling, sibling_status));
    CHECK(WIFEXITED(sibling_status));
    CHECK_EQ(WEXITSTATUS(sibling_status), 73);
}

TEST(forked_control, retained_children_fd_survives_reopen_failure) {
    CHECK(cleanup_case(ControlExit::UnexpectedStatus, 0, 0, 0, 87, 1));
}

TEST(forked_control, clock_failure_falls_back_and_reaps_tree) {
    CHECK(cleanup_case(ControlExit::UnexpectedStatus, 1, 0, 0, 125));
}

TEST(forked_control, children_snapshot_rejects_malformed_pid_tokens) {
    const char* invalid[] = {"-1", "0", "2147483648", "12x"};
    for (const char* token : invalid) {
        pid_t child = -1;
        CHECK_FALSE(rut::test::control_parse_child_pid(token, getpid(), child));
    }
    pid_t self = -1;
    CHECK_FALSE(rut::test::control_parse_child_pid("42", 42, self));
    char snapshot_data[] = "2147483647\n";
    FILE* snapshot = fmemopen(snapshot_data, sizeof(snapshot_data) - 1, "r");
    REQUIRE(snapshot != nullptr);
    unsigned count = 0;
    CHECK(rut::test::control_validate_children(snapshot, getpid(), count));
    fclose(snapshot);
    char malformed_data[] = "000000000000000000000000000000001\n";
    snapshot = fmemopen(malformed_data, sizeof(malformed_data) - 1, "r");
    REQUIRE(snapshot != nullptr);
    CHECK_FALSE(rut::test::control_validate_children(snapshot, getpid(), count));
    fclose(snapshot);
}

TEST(forked_control, procfs_capability_classifies_unsupported_separately) {
    CHECK_EQ(rut::test::control_procfs_capability_from_errno(ENOENT),
             rut::test::ControlProcfsCapability::Unsupported);
    CHECK_EQ(rut::test::control_procfs_capability_from_errno(EACCES),
             rut::test::ControlProcfsCapability::Error);
    rut::test::control_seek_failures = 1;
    CHECK_EQ(rut::test::probe_control_procfs_capability(),
             rut::test::ControlProcfsCapability::Error);
    rut::test::control_seek_failures = 0;
}

int main(int argc, char** argv) {
    const rut::test::ControlProcfsCapability capability =
        rut::test::probe_control_procfs_capability();
    if (capability == rut::test::ControlProcfsCapability::Unsupported) {
        fprintf(stderr,
                "SKIP: forked-control tests require /proc task children support "
                "(CONFIG_CHECKPOINT_RESTORE)\n");
        return 77;
    }
    if (capability == rut::test::ControlProcfsCapability::Error) {
        fprintf(stderr, "ERROR: forked-control capability probe could not read procfs children\n");
        return 1;
    }
    return rut::test::run_all(argc, argv);
}
