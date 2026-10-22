#include "forked_control_tree.h"
#include "test.h"

#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

namespace {

bool wait_terminal(pid_t pid, int& status) {
    for (unsigned i = 0; i < 600; ++i) {
        const pid_t kResult = waitpid(pid, &status, WNOHANG);
        if (kResult == pid) return true;
        if (kResult < 0 && errno != EINTR) return false;
        (void)poll(nullptr, 0, 5);
    }
    return false;
}

enum class ControlExit : unsigned char { Stall, UnexpectedStatus, Signal, ExpectedStatus };

bool cleanup_case(ControlExit mode) {
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
    const pid_t kControl = fork();
    if (kControl == 0) {
        _exit(rut::test::supervise_forked_control(
            [](void* opaque) -> int {
                auto& context = *static_cast<Context*>(opaque);
                close(context.channel[0]);
                const pid_t kSentinel = fork();
                if (kSentinel < 0) return 41;
                if (kSentinel == 0) {
                    close(context.channel[1]);
                    // Native compilation also creates its own group. Such a child
                    // must still be killed and reaped by this control's supervisor.
                    if (setpgid(0, 0) != 0) _exit(42);
                    for (;;) pause();
                }
                if (setpgid(kSentinel, kSentinel) != 0) return 44;
                if (write(context.channel[1], &kSentinel, sizeof(kSentinel)) != sizeof(kSentinel))
                    return 43;
                close(context.channel[1]);
                if (context.mode == ControlExit::UnexpectedStatus) return 87;
                if (context.mode == ControlExit::ExpectedStatus) return 86;
                if (context.mode == ControlExit::Signal) (void)kill(getpid(), SIGKILL);
                for (;;) pause();
            },
            &context));
    }
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
    if (mode == ControlExit::Stall && kill(kControl, SIGTERM) != 0) ok = false;
    if (!wait_terminal(kControl, control_status)) {
        (void)kill(kControl, SIGKILL);
        (void)wait_terminal(kControl, control_status);
        ok = false;
    }
    // A success-shaped worker result with leftover children is rejected too.
    if (mode == ControlExit::Signal)
        ok = ok && WIFSIGNALED(control_status) && WTERMSIG(control_status) == SIGKILL;
    else
        ok = ok && WIFEXITED(control_status) &&
             WEXITSTATUS(control_status) == (mode == ControlExit::Stall              ? 124
                                             : mode == ControlExit::UnexpectedStatus ? 87
                                                                                     : 125);
    if (sentinel > 0) {
        errno = 0;
        if (kill(sentinel, 0) != -1 || errno != ESRCH) ok = false;
        errno = 0;
        int status = 0;
        if (waitpid(sentinel, &status, WNOHANG) != -1 || errno != ECHILD) ok = false;
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

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
