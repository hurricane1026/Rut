#include "fixture_anonymous_log_capture.h"
#include <array>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <memory>
#include <string>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

namespace capture = rut::test::fixture_anonymous_log_capture;

namespace {

bool check(bool condition, const char* message) {
    if (!condition) std::fprintf(stderr, "FAIL: %s (errno=%d)\n", message, errno);
    return condition;
}

bool write_all(int fd, const void* data, std::size_t size) {
    const auto* bytes = static_cast<const unsigned char*>(data);
    std::size_t offset = 0u;
    while (offset < size) {
        const ssize_t result = write(fd, bytes + offset, size - offset);
        if (result < 0 && errno == EINTR) continue;
        if (result <= 0) return false;
        offset += static_cast<std::size_t>(result);
    }
    return true;
}

struct PreadInjection {
    unsigned interruptions = 0u;
};

PreadInjection* active_pread_injection = nullptr;

ssize_t eintr_once_pread(int fd, void* buffer, std::size_t count, off_t offset) {
    if (active_pread_injection != nullptr && active_pread_injection->interruptions == 0u) {
        ++active_pread_injection->interruptions;
        errno = EINTR;
        return -1;
    }
    return pread(fd, buffer, count, offset);
}

ssize_t oversized_read(int, void*, std::size_t count, off_t) {
    return static_cast<ssize_t>(count + 1u);
}

struct CloseInjection {
    bool called = false;
};

CloseInjection* active_close_injection = nullptr;

int uncertain_close(int fd) {
    if (active_close_injection != nullptr) active_close_injection->called = true;
    const int result = close(fd);
    if (result == 0) {
        errno = EINTR;
        return -1;
    }
    return result;
}

bool identity_and_initial_seals_test() {
    capture::AnonymousLogCapture log;
    capture::Diagnostic diagnostic;
    const bool created = capture::AnonymousLogCapture::create(128u, log, diagnostic);
    struct stat status{};
    const int seals = created ? fcntl(log.descriptor(), F_GET_SEALS) : -1;
    const int flags = created ? fcntl(log.descriptor(), F_GETFD) : -1;
    const bool stat_ok = created && fstat(log.descriptor(), &status) == 0;
    return check(created && diagnostic.phase == capture::FailurePhase::None,
                 "memfd capture creation failed") &&
           check(stat_ok && S_ISREG(status.st_mode) && (status.st_mode & 07777) == 0600 &&
                     status.st_uid == getuid() && status.st_gid == getgid() &&
                     status.st_nlink == 0 && status.st_dev != 0 && status.st_ino != 0 &&
                     status.st_size == 128,
                 "anonymous capture identity or fixed capacity is wrong") &&
           check(flags >= 0 && (flags & FD_CLOEXEC) != 0, "capture FD is not CLOEXEC") &&
           check(seals >= 0 &&
                     (seals & (F_SEAL_GROW | F_SEAL_SHRINK)) == (F_SEAL_GROW | F_SEAL_SHRINK),
                 "initial grow/shrink seals are missing");
}

bool fork_stdout_stderr_and_snapshot_test() {
    capture::AnonymousLogCapture log;
    capture::Diagnostic diagnostic;
    if (!capture::AnonymousLogCapture::create(128u, log, diagnostic))
        return check(false, "fork capture creation failed");
    int gate[2] = {-1, -1};
    int release_pipe[2] = {-1, -1};
    int report[2] = {-1, -1};
    if (pipe2(gate, O_CLOEXEC) != 0 || pipe2(release_pipe, O_CLOEXEC) != 0 ||
        pipe2(report, O_CLOEXEC) != 0)
        return check(false, "fork capture pipe setup failed");
    const int original = log.descriptor();
    const pid_t child = fork();
    if (child < 0) {
        close(gate[0]);
        close(gate[1]);
        close(release_pipe[0]);
        close(release_pipe[1]);
        close(report[0]);
        close(report[1]);
        return check(false, "fork capture child creation failed");
    }
    if (child == 0) {
        close(gate[0]);
        close(release_pipe[1]);
        close(report[0]);
        const int child_flags = fcntl(original, F_GETFD);
        const unsigned char cloexec = child_flags >= 0 && (child_flags & FD_CLOEXEC) != 0 ? 1u : 0u;
        (void)write(report[1], &cloexec, sizeof(cloexec));
        if (dup2(original, STDOUT_FILENO) < 0 || dup2(original, STDERR_FILENO) < 0) _exit(2);
        const char first[] = {'A', '\n', 'B'};
        if (!write_all(STDOUT_FILENO, first, sizeof(first))) _exit(3);
        const unsigned char ready = 1u;
        if (!write_all(gate[1], &ready, sizeof(ready))) _exit(4);
        unsigned char release = 0u;
        if (read(release_pipe[0], &release, sizeof(release)) != 1) _exit(5);
        const char second[] = {'\0', 'C', '\n', 'D'};
        if (!write_all(STDERR_FILENO, second, sizeof(second))) _exit(6);
        _exit(0);
    }
    close(gate[1]);
    close(release_pipe[0]);
    close(report[1]);
    unsigned char cloexec = 0u;
    const bool report_ok = read(report[0], &cloexec, sizeof(cloexec)) == 1;
    close(report[0]);
    unsigned char ready = 0u;
    const bool ready_ok = read(gate[0], &ready, sizeof(ready)) == 1;
    std::string first_snapshot;
    const bool first_ok = log.snapshot(first_snapshot, diagnostic);
    const unsigned char release = 1u;
    const bool release_ok = write_all(release_pipe[1], &release, sizeof(release));
    close(release_pipe[1]);
    close(gate[0]);
    int status = 0;
    const bool waited = waitpid(child, &status, 0) == child;
    std::string final_snapshot;
    const bool final_ok = log.snapshot(final_snapshot, diagnostic);
    const std::string expected_first("A\nB", 3u);
    const std::string expected_final("A\nB\0C\nD", 7u);
    return check(report_ok && cloexec == 1u && (fcntl(original, F_GETFD) & FD_CLOEXEC) != 0,
                 "original capture FD lost CLOEXEC across fork/dup2") &&
           check(ready_ok && ready == 1u && first_ok && first_snapshot == expected_first,
                 "snapshot did not capture the first fragmented stdout bytes") &&
           check(release_ok && waited && WIFEXITED(status) && WEXITSTATUS(status) == 0 &&
                     final_ok && final_snapshot == expected_final,
                 "shared stdout/stderr OFD bytes or embedded NUL were not exact");
}

bool limit_and_settlement_test() {
    capture::AnonymousLogCapture log;
    capture::Diagnostic diagnostic;
    if (!capture::AnonymousLogCapture::create(8u, log, diagnostic))
        return check(false, "limit capture creation failed");
    const std::string exact("12345678", 8u);
    const bool exact_written = write_all(log.descriptor(), exact.data(), exact.size());
    errno = 0;
    const char extra = 'X';
    const ssize_t overflow = write(log.descriptor(), &extra, 1u);
    const int overflow_error = errno;
    std::string bytes;
    const bool exact_read = log.snapshot(bytes, diagnostic);
    const bool settled = log.settle(diagnostic);
    const int seals = fcntl(log.descriptor(), F_GET_SEALS);
    errno = 0;
    const ssize_t post_seal = write(log.descriptor(), &extra, 1u);
    return check(exact_written && overflow < 0 &&
                     (overflow_error == ENOSPC || overflow_error == EFBIG ||
                      overflow_error == EPERM) &&
                     exact_read && bytes == exact,
                 "fixed capacity did not physically stop an over-limit write") &&
           check(settled && seals >= 0 &&
                     (seals & (F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_WRITE | F_SEAL_SEAL)) ==
                         (F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_WRITE | F_SEAL_SEAL),
                 "final writer seals were not settled") &&
           check(post_seal < 0 && errno == EPERM, "post-settlement write was accepted");
}

bool empty_eintr_and_validation_test() {
    capture::AnonymousLogCapture empty;
    capture::Diagnostic diagnostic;
    if (!capture::AnonymousLogCapture::create(32u, empty, diagnostic))
        return check(false, "empty capture creation failed");
    std::string bytes("sentinel");
    const bool empty_ok = empty.snapshot(bytes, diagnostic) && bytes.empty();
    const char value = 'Q';
    const bool wrote = write(empty.descriptor(), &value, 1u) == 1;
    PreadInjection injection;
    active_pread_injection = &injection;
    const bool eintr_ok =
        empty.snapshot_at_offset_for_testing(1, bytes, eintr_once_pread, diagnostic) &&
        bytes == "Q" && injection.interruptions == 1u;
    active_pread_injection = nullptr;
    capture::Diagnostic invalid_diagnostic;
    const bool negative_rejected =
        !empty.snapshot_at_offset_for_testing(-1, bytes, pread, invalid_diagnostic) &&
        invalid_diagnostic.phase == capture::FailurePhase::Offset;
    const bool wide_rejected =
        !empty.snapshot_at_offset_for_testing(33, bytes, pread, invalid_diagnostic) &&
        invalid_diagnostic.phase == capture::FailurePhase::Offset;
    const bool oversized_rejected =
        !empty.snapshot_at_offset_for_testing(1, bytes, oversized_read, invalid_diagnostic) &&
        invalid_diagnostic.phase == capture::FailurePhase::Read;
    return check(empty_ok && wrote && eintr_ok, "empty or EINTR snapshot behavior is wrong") &&
           check(negative_rejected && wide_rejected && oversized_rejected,
                 "invalid offset/trailing read validation was not fail-closed");
}

bool close_move_and_no_path_test() {
    capture::AnonymousLogCapture source;
    capture::Diagnostic diagnostic;
    if (!capture::AnonymousLogCapture::create(32u, source, diagnostic))
        return check(false, "move capture creation failed");
    const int original = source.descriptor();
    const auto state = source.cleanup_state();
    capture::AnonymousLogCapture moved(std::move(source));
    const bool moved_ok =
        source.descriptor() < 0 && moved.descriptor() == original && moved.cleanup_state() == state;
    const char value = 'M';
    const bool wrote = write(moved.descriptor(), &value, 1u) == 1;
    const bool closed = moved.close(diagnostic);
    const bool state_ok = state->attempted && state->succeeded && moved.descriptor() < 0;

    capture::AnonymousLogCapture uncertain;
    CloseInjection injection;
    active_close_injection = &injection;
    const capture::HooksForTesting hooks{nullptr, uncertain_close};
    const bool uncertain_created = capture::AnonymousLogCapture::create_with_hooks_for_testing(
        16u, hooks, uncertain, diagnostic);
    auto uncertain_state = uncertain.cleanup_state();
    const bool uncertain_closed = !uncertain.close(diagnostic);
    active_close_injection = nullptr;
    const bool uncertainty_ok = uncertain_created && uncertain_closed && injection.called &&
                                uncertain.descriptor() < 0 && uncertain_state->attempted &&
                                !uncertain_state->succeeded &&
                                uncertain_state->diagnostic.phase == capture::FailurePhase::Close;

    std::shared_ptr<const capture::CleanupState> destructor_state;
    CloseInjection destructor_injection;
    {
        capture::AnonymousLogCapture destructor_capture;
        active_close_injection = &destructor_injection;
        const capture::HooksForTesting destructor_hooks{nullptr, uncertain_close};
        const bool destructor_created = capture::AnonymousLogCapture::create_with_hooks_for_testing(
            16u, destructor_hooks, destructor_capture, diagnostic);
        destructor_state = destructor_capture.cleanup_state();
        if (!destructor_created) return check(false, "destructor uncertainty setup failed");
    }
    active_close_injection = nullptr;
    const bool destructor_uncertainty_ok =
        destructor_injection.called && destructor_state && destructor_state->attempted &&
        !destructor_state->succeeded &&
        destructor_state->diagnostic.phase == capture::FailurePhase::Close;

    const int ordinary =
        open("/tmp/rut377-anonymous-log-ordinary", O_WRONLY | O_CREAT | O_TRUNC, 0600);
    const bool ordinary_ok =
        ordinary >= 0 && write_all(ordinary, "ordinary", 8u) && close(ordinary) == 0;
    const bool capture_created = capture::AnonymousLogCapture::create(16u, uncertain, diagnostic);
    std::array<char, 128> fd_target{};
    const ssize_t fd_target_size =
        capture_created
            ? readlink(
                  (std::string("/proc/self/fd/") + std::to_string(uncertain.descriptor())).c_str(),
                  fd_target.data(),
                  fd_target.size() - 1u)
            : -1;
    if (fd_target_size >= 0) fd_target[static_cast<std::size_t>(fd_target_size)] = '\0';
    const int ordinary_read = open("/tmp/rut377-anonymous-log-ordinary", O_RDONLY | O_CLOEXEC);
    std::array<char, 16> ordinary_bytes{};
    const ssize_t ordinary_count =
        ordinary_read >= 0 ? read(ordinary_read, ordinary_bytes.data(), ordinary_bytes.size()) : -1;
    if (ordinary_read >= 0) close(ordinary_read);
    unlink("/tmp/rut377-anonymous-log-ordinary");
    const bool no_path = capture_created && fd_target_size > 0 &&
                         std::string(fd_target.data(), static_cast<std::size_t>(fd_target_size))
                                 .find("memfd:rut377-anonymous-log") != std::string::npos &&
                         ordinary_ok && ordinary_count == 8 &&
                         std::string(ordinary_bytes.data(), 8u) == "ordinary";
    return check(moved_ok && wrote && closed && state_ok, "move or explicit close was unsafe") &&
           check(uncertainty_ok, "close uncertainty was not retained without retry") &&
           check(destructor_uncertainty_ok, "destructor close uncertainty was not retained") &&
           check(no_path, "anonymous capture interfered with a similarly named ordinary file");
}

}  // namespace

int main() {
    const bool ok = identity_and_initial_seals_test() && fork_stdout_stderr_and_snapshot_test() &&
                    limit_and_settlement_test() && empty_eintr_and_validation_test() &&
                    close_move_and_no_path_test();
    if (!ok) return 1;
    std::puts("PASS: #377 bounded anonymous log capture");
    return 0;
}
