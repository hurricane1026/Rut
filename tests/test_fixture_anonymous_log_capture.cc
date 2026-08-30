#include "fixture_anonymous_log_capture.h"
#include <array>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <memory>
#include <string>

#include <fcntl.h>
#include <poll.h>
#include <signal.h>
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

bool read_bounded(int fd, void* data, std::size_t size) {
    pollfd descriptor{fd, POLLIN, 0};
    const int ready = poll(&descriptor, 1u, 1000);
    return ready == 1 && (descriptor.revents & (POLLIN | POLLHUP)) != 0 &&
           read(fd, data, size) == static_cast<ssize_t>(size);
}

void close_pair(int (&pair)[2]) {
    for (int& fd : pair) {
        if (fd >= 0) close(fd);
        fd = -1;
    }
}

bool reap_bounded(pid_t child, int& status) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(1);
    for (;;) {
        const pid_t result = waitpid(child, &status, WNOHANG);
        if (result == child) return true;
        if (result < 0 && errno != EINTR) return false;
        if (std::chrono::steady_clock::now() >= deadline) {
            (void)kill(child, SIGKILL);
            while (waitpid(child, &status, 0) < 0 && errno == EINTR) {
            }
            return false;
        }
        (void)poll(nullptr, 0u, 10);
    }
}

struct PrivateDirectory {
    std::array<char, 64> path{};
    int fd = -1;
    bool directory_created = false;
    bool ordinary_created = false;
    dev_t ordinary_device = 0;
    ino_t ordinary_inode = 0;

    bool create() {
        std::array<char, 64> pattern{};
        std::snprintf(pattern.data(), pattern.size(), "/tmp/rut377-anonymous-XXXXXX");
        char* const created = mkdtemp(pattern.data());
        if (created == nullptr) return false;
        std::snprintf(path.data(), path.size(), "%s", created);
        directory_created = true;
        fd = open(path.data(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        return fd >= 0 && fchmod(fd, 0700) == 0;
    }

    int create_ordinary() {
        if (fd < 0) return -1;
        const int ordinary = openat(fd,
                                    "anonymous-log-ordinary",
                                    O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                                    0600);
        if (ordinary >= 0) {
            struct stat status{};
            ordinary_created = fstat(ordinary, &status) == 0 && S_ISREG(status.st_mode);
            if (ordinary_created) {
                ordinary_device = status.st_dev;
                ordinary_inode = status.st_ino;
            } else {
                close(ordinary);
                (void)unlinkat(fd, "anonymous-log-ordinary", 0);
                return -1;
            }
        }
        return ordinary;
    }

    ~PrivateDirectory() {
        if (fd >= 0) {
            struct stat current{};
            const bool same_ordinary =
                ordinary_created &&
                fstatat(fd, "anonymous-log-ordinary", &current, AT_SYMLINK_NOFOLLOW) == 0 &&
                current.st_dev == ordinary_device && current.st_ino == ordinary_inode &&
                S_ISREG(current.st_mode);
            if (same_ordinary && unlinkat(fd, "anonymous-log-ordinary", 0) != 0)
                std::fprintf(stderr, "FAIL: private ordinary cleanup errno=%d\n", errno);
            close(fd);
        }
        if (directory_created && rmdir(path.data()) != 0)
            std::fprintf(stderr, "FAIL: private directory cleanup errno=%d\n", errno);
    }
};

struct PreadInjection {
    unsigned interruptions = 0u;
    unsigned partial_reads = 0u;
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

ssize_t eof_read(int, void*, std::size_t, off_t) {
    return 0;
}

PreadInjection* active_partial_injection = nullptr;

ssize_t partial_read(int fd, void* buffer, std::size_t count, off_t offset) {
    if (active_partial_injection != nullptr && count > 1u) {
        ++active_partial_injection->partial_reads;
        return pread(fd, buffer, 1u, offset);
    }
    return pread(fd, buffer, count, offset);
}

struct CloseInjection {
    bool called = false;
    unsigned calls = 0u;
    int fd = -1;
};

CloseInjection* active_close_injection = nullptr;

int uncertain_close(int fd) {
    if (active_close_injection != nullptr) active_close_injection->called = true;
    (void)fd;
    errno = EINTR;
    return -1;
}

int recording_close(int fd) {
    if (active_close_injection != nullptr) {
        active_close_injection->called = true;
        ++active_close_injection->calls;
        active_close_injection->fd = fd;
    }
    return close(fd);
}

void mutate_after_final_seal(int fd) {
    (void)fchmod(fd, 0640);
}

bool identity_and_initial_seals_test() {
    capture::AnonymousLogCapture log;
    capture::Diagnostic diagnostic;
    const bool created = capture::AnonymousLogCapture::create(128u, log, diagnostic);
    struct stat status{};
    const int seals = created ? fcntl(log.descriptor(), F_GET_SEALS) : -1;
    const int flags = created ? fcntl(log.descriptor(), F_GETFD) : -1;
    const bool stat_ok = created && fstat(log.descriptor(), &status) == 0;
    capture::Diagnostic invalid_diagnostic;
    capture::AnonymousLogCapture invalid;
    const bool invalid_zero =
        !capture::AnonymousLogCapture::create(0u, invalid, invalid_diagnostic) &&
        invalid.descriptor() < 0;
    const bool invalid_wide = !capture::AnonymousLogCapture::create(
                                  capture::kMaxCaptureBytes + 1u, invalid, invalid_diagnostic) &&
                              invalid.descriptor() < 0;
    return check(created && diagnostic.phase == capture::FailurePhase::None,
                 "memfd capture creation failed") &&
           check(stat_ok && S_ISREG(status.st_mode) && (status.st_mode & 07777) == 0600 &&
                     status.st_uid == getuid() && status.st_gid == getgid() &&
                     status.st_nlink == 0 && status.st_dev != 0 && status.st_ino != 0 &&
                     status.st_size == 128,
                 "anonymous capture identity or fixed capacity is wrong") &&
           check(flags >= 0 && (flags & FD_CLOEXEC) != 0, "capture FD is not CLOEXEC") &&
           check(seals == (F_SEAL_GROW | F_SEAL_SHRINK), "initial seals are not exact") &&
           check(invalid_zero && invalid_wide, "invalid capture bounds were accepted");
}

bool creation_failure_cleanup_test() {
    const std::array<capture::CreationFailurePoint, 3> points = {
        capture::CreationFailurePoint::Fchmod,
        capture::CreationFailurePoint::GetFd,
        capture::CreationFailurePoint::Fstat,
    };
    for (const capture::CreationFailurePoint point : points) {
        capture::AnonymousLogCapture capture_under_test;
        capture::Diagnostic diagnostic;
        CloseInjection close_record;
        active_close_injection = &close_record;
        const capture::HooksForTesting hooks{nullptr, recording_close, nullptr, point};
        errno = EAGAIN;
        const bool created = capture::AnonymousLogCapture::create_with_hooks_for_testing(
            64u, hooks, capture_under_test, diagnostic);
        active_close_injection = nullptr;
        const auto state = capture_under_test.cleanup_state();
        const bool raw_fd_closed =
            close_record.fd >= 0 && (fcntl(close_record.fd, F_GETFD) < 0 && errno == EBADF);
        const bool failed_and_clean =
            !created && diagnostic.phase == capture::FailurePhase::Identity &&
            diagnostic.error_number == EIO && !capture_under_test.active() && raw_fd_closed &&
            close_record.called && close_record.calls == 1u && state && state->attempted &&
            state->succeeded;
        const auto retained_state = state;
        const bool reuse_rejected =
            !capture::AnonymousLogCapture::create(64u, capture_under_test, diagnostic) &&
            diagnostic.phase == capture::FailurePhase::Close &&
            capture_under_test.cleanup_state() == retained_state && state->attempted &&
            state->succeeded;
        if (!check(failed_and_clean && close_record.calls == 1u && reuse_rejected,
                   "creation-stage failure lost cleanup ownership/evidence"))
            return false;
    }
    return true;
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
        pipe2(report, O_CLOEXEC) != 0) {
        close_pair(gate);
        close_pair(release_pipe);
        close_pair(report);
        return check(false, "fork capture pipe setup failed");
    }
    struct sigaction ignore_sigpipe{};
    ignore_sigpipe.sa_handler = SIG_IGN;
    sigemptyset(&ignore_sigpipe.sa_mask);
    struct sigaction old_sigpipe{};
    if (sigaction(SIGPIPE, &ignore_sigpipe, &old_sigpipe) != 0) {
        close_pair(gate);
        close_pair(release_pipe);
        close_pair(report);
        return check(false, "fork capture SIGPIPE setup failed");
    }
    const int original = log.descriptor();
    const pid_t child = fork();
    if (child < 0) {
        close_pair(gate);
        close_pair(release_pipe);
        close_pair(report);
        (void)sigaction(SIGPIPE, &old_sigpipe, nullptr);
        return check(false, "fork capture child creation failed");
    }
    if (child == 0) {
        close(gate[0]);
        close(release_pipe[1]);
        close(report[0]);
        const int child_flags = fcntl(original, F_GETFD);
        if (dup2(original, STDOUT_FILENO) < 0 || dup2(original, STDERR_FILENO) < 0) _exit(2);
        const int stdout_flags = fcntl(STDOUT_FILENO, F_GETFD);
        const int stderr_flags = fcntl(STDERR_FILENO, F_GETFD);
        const unsigned char descriptor_report = static_cast<unsigned char>(
            (child_flags >= 0 && (child_flags & FD_CLOEXEC) != 0 ? 1u : 0u) |
            (stdout_flags >= 0 && (stdout_flags & FD_CLOEXEC) == 0 ? 2u : 0u) |
            (stderr_flags >= 0 && (stderr_flags & FD_CLOEXEC) == 0 ? 4u : 0u));
        if (!write_all(report[1], &descriptor_report, sizeof(descriptor_report))) _exit(2);
        const char first[] = {'A', '\n', 'B'};
        if (!write_all(STDOUT_FILENO, first, sizeof(first))) _exit(3);
        const unsigned char ready = 1u;
        if (!write_all(gate[1], &ready, sizeof(ready))) _exit(4);
        unsigned char release = 0u;
        if (!read_bounded(release_pipe[0], &release, sizeof(release))) _exit(5);
        const char second[] = {'\0', 'C', '\n', 'D'};
        if (!write_all(STDERR_FILENO, second, sizeof(second))) _exit(6);
        _exit(0);
    }
    close(gate[1]);
    close(release_pipe[0]);
    close(report[1]);
    unsigned char descriptor_report = 0u;
    const bool report_ok = read_bounded(report[0], &descriptor_report, sizeof(descriptor_report));
    close(report[0]);
    unsigned char ready = 0u;
    const bool ready_ok = read_bounded(gate[0], &ready, sizeof(ready));
    std::string first_snapshot;
    const bool first_ok = log.snapshot(first_snapshot, diagnostic);
    const unsigned char release = 1u;
    const bool release_ok = write_all(release_pipe[1], &release, sizeof(release));
    close(release_pipe[1]);
    close(gate[0]);
    int status = 0;
    const bool waited = reap_bounded(child, status);
    (void)sigaction(SIGPIPE, &old_sigpipe, nullptr);
    std::string final_snapshot;
    const bool final_ok = log.snapshot(final_snapshot, diagnostic);
    const std::string expected_first("A\nB", 3u);
    const std::string expected_final("A\nB\0C\nD", 7u);
    return check(
               report_ok && descriptor_report == 7u && (fcntl(original, F_GETFD) & FD_CLOEXEC) != 0,
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
                     seals == (F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_WRITE | F_SEAL_SEAL),
                 "final writer seals were not exact") &&
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
    const char suffix[] = {'A', 'B'};
    const bool suffix_written = write_all(empty.descriptor(), suffix, sizeof(suffix));
    PreadInjection partial_injection;
    active_partial_injection = &partial_injection;
    const bool partial_ok =
        empty.snapshot_at_offset_for_testing(3, bytes, partial_read, diagnostic) &&
        bytes == "QAB" && partial_injection.partial_reads >= 2u;
    active_partial_injection = nullptr;
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
    const bool eof_rejected =
        !empty.snapshot_at_offset_for_testing(1, bytes, eof_read, invalid_diagnostic) &&
        invalid_diagnostic.phase == capture::FailurePhase::Read;
    return check(empty_ok && wrote && eintr_ok && suffix_written && partial_ok,
                 "empty, short-read, or EINTR snapshot behavior is wrong") &&
           check(negative_rejected && wide_rejected && oversized_rejected && eof_rejected,
                 "invalid offset/trailing read validation was not fail-closed");
}

bool mutation_and_duplicate_settlement_test() {
    capture::Diagnostic diagnostic;
    std::string bytes;

    capture::AnonymousLogCapture mode;
    if (!capture::AnonymousLogCapture::create(16u, mode, diagnostic)) return false;
    const bool mode_changed = fchmod(mode.descriptor(), 0640) == 0;
    errno = EAGAIN;
    const bool mode_rejected = mode_changed && !mode.snapshot(bytes, diagnostic) &&
                               diagnostic.phase == capture::FailurePhase::Identity &&
                               diagnostic.error_number == EINVAL;

    capture::AnonymousLogCapture cloexec;
    if (!capture::AnonymousLogCapture::create(16u, cloexec, diagnostic)) return false;
    const bool cloexec_changed = fcntl(cloexec.descriptor(), F_SETFD, 0) == 0;
    errno = EAGAIN;
    const bool cloexec_rejected = cloexec_changed && !cloexec.snapshot(bytes, diagnostic) &&
                                  diagnostic.phase == capture::FailurePhase::Identity &&
                                  diagnostic.error_number == EINVAL;

    capture::AnonymousLogCapture seals;
    if (!capture::AnonymousLogCapture::create(16u, seals, diagnostic)) return false;
    const bool unexpected_seal = fcntl(seals.descriptor(), F_ADD_SEALS, F_SEAL_SEAL) == 0;
    errno = EAGAIN;
    const bool seal_rejected = unexpected_seal && !seals.settle(diagnostic) &&
                               diagnostic.phase == capture::FailurePhase::Seal &&
                               diagnostic.error_number == EINVAL;
    const int unchanged_seals = fcntl(seals.descriptor(), F_GET_SEALS);

    capture::AnonymousLogCapture offset;
    if (!capture::AnonymousLogCapture::create(16u, offset, diagnostic)) return false;
    const int duplicate = dup(offset.descriptor());
    const bool offset_changed = duplicate >= 0 && lseek(duplicate, 17, SEEK_SET) == 17;
    const bool offset_rejected = offset_changed && !offset.snapshot(bytes, diagnostic) &&
                                 diagnostic.phase == capture::FailurePhase::Offset;
    if (duplicate >= 0) close(duplicate);

    capture::AnonymousLogCapture settled;
    if (!capture::AnonymousLogCapture::create(16u, settled, diagnostic)) return false;
    const int writer = dup(settled.descriptor());
    const char payload[] = {'x', '\0', 'y'};
    const bool duplicate_writer = writer >= 0 && write_all(writer, payload, sizeof(payload));
    const bool settled_ok = duplicate_writer && settled.settle(diagnostic) && settled.settled();
    errno = 0;
    const ssize_t duplicate_write = writer >= 0 ? write(writer, "z", 1u) : 0;
    const int duplicate_error = errno;
    if (writer >= 0) close(writer);
    const bool settled_write_rejected = duplicate_write < 0 && duplicate_error == EPERM;
    const bool settled_snapshot =
        settled.snapshot(bytes, diagnostic) && bytes == std::string(payload, sizeof(payload));

    capture::AnonymousLogCapture final_mutation;
    const capture::HooksForTesting final_mutation_hooks{nullptr, nullptr, mutate_after_final_seal};
    if (!capture::AnonymousLogCapture::create_with_hooks_for_testing(
            16u, final_mutation_hooks, final_mutation, diagnostic))
        return false;
    const char final_byte = 'f';
    const bool final_write = write(final_mutation.descriptor(), &final_byte, 1u) == 1;
    const bool final_mutation_rejected = final_write && !final_mutation.settle(diagnostic) &&
                                         diagnostic.phase == capture::FailurePhase::Identity &&
                                         diagnostic.error_number == EINVAL &&
                                         final_mutation.settled();
    const bool final_restored =
        fchmod(final_mutation.descriptor(), 0600) == 0 && final_mutation.close(diagnostic);

    return check(mode_rejected && cloexec_rejected && seal_rejected && offset_rejected &&
                     unchanged_seals == (F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL),
                 "metadata, CLOEXEC, seal, or shared-offset mutation was accepted") &&
           check(settled_ok && settled_write_rejected && settled_snapshot,
                 "settlement with a duplicate writer was not immutable") &&
           check(final_mutation_rejected && final_restored,
                 "post-seal final identity validation was not causal");
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
    const bool successful_reuse_rejected =
        !capture::AnonymousLogCapture::create(32u, moved, diagnostic) &&
        diagnostic.phase == capture::FailurePhase::Close && moved.cleanup_state() == state &&
        state->attempted && state->succeeded;

    capture::AnonymousLogCapture uncertain;
    CloseInjection injection;
    active_close_injection = &injection;
    const capture::HooksForTesting hooks{nullptr, uncertain_close};
    const bool uncertain_created = capture::AnonymousLogCapture::create_with_hooks_for_testing(
        16u, hooks, uncertain, diagnostic);
    const int uncertain_fd = uncertain.descriptor();
    auto uncertain_state = uncertain.cleanup_state();
    const bool uncertain_closed = !uncertain.close(diagnostic);
    const bool uncertain_fd_remains_valid = uncertain_fd >= 0 && fcntl(uncertain_fd, F_GETFD) >= 0;
    active_close_injection = nullptr;
    const bool uncertainty_ok = uncertain_created && uncertain_closed && injection.called &&
                                uncertain_fd_remains_valid && uncertain.descriptor() < 0 &&
                                uncertain_state->attempted && !uncertain_state->succeeded &&
                                uncertain_state->diagnostic.phase == capture::FailurePhase::Close;
    if (uncertain_fd >= 0) close(uncertain_fd);

    std::shared_ptr<const capture::CleanupState> destructor_state;
    CloseInjection destructor_injection;
    int destructor_fd = -1;
    {
        capture::AnonymousLogCapture destructor_capture;
        active_close_injection = &destructor_injection;
        const capture::HooksForTesting destructor_hooks{nullptr, uncertain_close};
        const bool destructor_created = capture::AnonymousLogCapture::create_with_hooks_for_testing(
            16u, destructor_hooks, destructor_capture, diagnostic);
        destructor_fd = destructor_capture.descriptor();
        destructor_state = destructor_capture.cleanup_state();
        if (!destructor_created) return check(false, "destructor uncertainty setup failed");
    }
    active_close_injection = nullptr;
    const bool destructor_fd_remains_valid =
        destructor_fd >= 0 && fcntl(destructor_fd, F_GETFD) >= 0;
    // The destructor deliberately does not retry an uncertain close; the test
    // retains and explicitly closes the still-valid raw descriptor.
    if (destructor_fd >= 0) close(destructor_fd);
    const bool destructor_uncertainty_ok =
        destructor_injection.called && destructor_state && destructor_state->attempted &&
        !destructor_state->succeeded && destructor_fd_remains_valid &&
        destructor_state->diagnostic.phase == capture::FailurePhase::Close;

    const bool reuse_rejected = !capture::AnonymousLogCapture::create(16u, uncertain, diagnostic) &&
                                diagnostic.phase == capture::FailurePhase::Close &&
                                uncertain.descriptor() < 0;
    PrivateDirectory directory;
    const bool directory_created = directory.create();
    const int ordinary = directory_created ? directory.create_ordinary() : -1;
    bool ordinary_ok = ordinary >= 0;
    if (ordinary_ok) {
        ordinary_ok = write_all(ordinary, "ordinary", 8u);
    }
    capture::AnonymousLogCapture victim;
    capture::Diagnostic replacement_diagnostic;
    const bool victim_created =
        capture::AnonymousLogCapture::create(16u, victim, replacement_diagnostic);
    const int victim_fd = victim_created ? victim.descriptor() : -1;
    const bool replaced = ordinary_ok && victim_created && victim_fd != ordinary &&
                          dup2(ordinary, victim_fd) == victim_fd;
    const bool replacement_close_rejected =
        replaced && !victim.close(replacement_diagnostic) &&
        replacement_diagnostic.phase == capture::FailurePhase::Close &&
        replacement_diagnostic.error_number == EINVAL;
    const bool replacement_remains_open =
        replaced && fcntl(victim_fd, F_GETFD) >= 0 && fcntl(ordinary, F_GETFD) >= 0;
    if (victim_fd >= 0 && replaced) close(victim_fd);
    if (ordinary >= 0) close(ordinary);
    capture::AnonymousLogCapture unrelated;
    const bool capture_created = capture::AnonymousLogCapture::create(16u, unrelated, diagnostic);
    std::array<char, 128> fd_target{};
    const ssize_t fd_target_size =
        capture_created
            ? readlink(
                  (std::string("/proc/self/fd/") + std::to_string(unrelated.descriptor())).c_str(),
                  fd_target.data(),
                  fd_target.size() - 1u)
            : -1;
    if (fd_target_size >= 0) fd_target[static_cast<std::size_t>(fd_target_size)] = '\0';
    const int ordinary_read =
        directory_created
            ? openat(directory.fd, "anonymous-log-ordinary", O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
            : -1;
    std::array<char, 16> ordinary_bytes{};
    const ssize_t ordinary_count =
        ordinary_read >= 0 ? read(ordinary_read, ordinary_bytes.data(), ordinary_bytes.size()) : -1;
    if (ordinary_read >= 0) close(ordinary_read);
    const bool no_path =
        reuse_rejected && directory_created && capture_created && replacement_close_rejected &&
        replacement_remains_open && fd_target_size > 0 &&
        std::string(fd_target.data(), static_cast<std::size_t>(fd_target_size))
                .find("memfd:rut377-anonymous-log") != std::string::npos &&
        ordinary_ok && ordinary_count == 8 && std::string(ordinary_bytes.data(), 8u) == "ordinary";
    return check(moved_ok && wrote && closed && state_ok && successful_reuse_rejected,
                 "move or explicit close was unsafe") &&
           check(uncertainty_ok, "close uncertainty was not retained without retry") &&
           check(destructor_uncertainty_ok, "destructor close uncertainty was not retained") &&
           check(no_path, "anonymous capture interfered with a similarly named ordinary file");
}

}  // namespace

int main() {
    const bool ok = identity_and_initial_seals_test() && creation_failure_cleanup_test() &&
                    fork_stdout_stderr_and_snapshot_test() && limit_and_settlement_test() &&
                    empty_eintr_and_validation_test() && mutation_and_duplicate_settlement_test() &&
                    close_move_and_no_path_test();
    if (!ok) return 1;
    std::puts("PASS: #377 bounded anonymous log capture");
    return 0;
}
