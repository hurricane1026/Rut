#include "fixture_wildcard_attempt_child.h"
#include <array>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <string>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

namespace child_lease = rut::test::fixture_wildcard_attempt_child;
namespace source_lease = rut::test::fixture_wildcard_source_lease;
namespace listener = rut::test::fixture_privileged_listener;

namespace {

constexpr listener::ListenerPlan kPlan{0x0a010203u, 0x0a010204u, 8080u};

bool check(bool condition, const char* message) {
    if (!condition) std::fprintf(stderr, "FAIL: %s (errno=%d)\n", message, errno);
    return condition;
}

struct TempDirectory {
    std::string path;
    int fd = -1;
    bool open() {
        std::array<char, 64> pattern{};
        std::snprintf(pattern.data(), pattern.size(), "/tmp/rut377-child-XXXXXX");
        char* created = mkdtemp(pattern.data());
        if (created == nullptr) return false;
        path = created;
        if (chmod(path.c_str(), 0700) != 0) return false;
        fd = ::open(path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        return fd >= 0;
    }
    ~TempDirectory() {
        if (fd >= 0) close(fd);
        if (!path.empty()) rmdir(path.c_str());
    }
};

bool absent(int directory, const char* name) {
    struct stat status{};
    errno = 0;
    return fstatat(directory, name, &status, AT_SYMLINK_NOFOLLOW) < 0 && errno == ENOENT;
}

bool canonical() {
    TempDirectory directory;
    source_lease::WildcardAttemptSourceLease source;
    child_lease::WildcardAttemptChildLease child;
    source_lease::Diagnostic source_diagnostic;
    child_lease::Diagnostic diagnostic;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(15);
    if (!check(directory.open(), "temporary private directory setup failed") ||
        !check(source_lease::WildcardAttemptSourceLease::create(
                   directory.fd, directory.path, "wildcard.rut", kPlan, source, source_diagnostic),
               "source lease setup failed"))
        return false;
    const bool created = child_lease::WildcardAttemptChildLease::create(
        source, "attempt.log", deadline, child, diagnostic);
    if (!check(created, "paused child creation failed")) {
        std::fprintf(stderr,
                     "child phase=%u error=%d\n",
                     static_cast<unsigned>(diagnostic.phase),
                     diagnostic.error_number);
        return false;
    }
    const auto bound = child.identity();
    const bool identity_mutations = !rut::test::fixture_worker_protocol::same_process_identity(
                                        [&] {
                                            auto v = bound;
                                            ++v.pid;
                                            return v;
                                        }(),
                                        bound) &&
                                    !rut::test::fixture_worker_protocol::same_process_identity(
                                        [&] {
                                            auto v = bound;
                                            ++v.ppid;
                                            return v;
                                        }(),
                                        bound) &&
                                    !rut::test::fixture_worker_protocol::same_process_identity(
                                        [&] {
                                            auto v = bound;
                                            ++v.pgid;
                                            return v;
                                        }(),
                                        bound) &&
                                    !rut::test::fixture_worker_protocol::same_process_identity(
                                        [&] {
                                            auto v = bound;
                                            ++v.sid;
                                            return v;
                                        }(),
                                        bound) &&
                                    !rut::test::fixture_worker_protocol::same_process_identity(
                                        [&] {
                                            auto v = bound;
                                            ++v.start;
                                            return v;
                                        }(),
                                        bound) &&
                                    !rut::test::fixture_worker_protocol::same_process_identity(
                                        [&] {
                                            auto v = bound;
                                            ++v.uid;
                                            return v;
                                        }(),
                                        bound) &&
                                    !rut::test::fixture_worker_protocol::same_process_identity(
                                        [&] {
                                            auto v = bound;
                                            ++v.gid;
                                            return v;
                                        }(),
                                        bound) &&
                                    !rut::test::fixture_worker_protocol::same_process_identity(
                                        [&] {
                                            auto v = bound;
                                            ++v.netns;
                                            return v;
                                        }(),
                                        bound);
    if (!check(child.active() && child.child_pid() > 1 && child.pidfd() >= 0 &&
                   child.log_descriptor() >= 0,
               "paused child did not retain required descriptors") ||
        !check(identity_mutations, "required ProcIdentity mutation table was vacuous") ||
        !check(child.validate_paused(deadline, diagnostic), "paused child revalidation failed") ||
        !check(child.release(deadline, diagnostic), "one-shot release failed") ||
        !check(!child.active() && child.released(), "release did not settle child") ||
        !check(child.cleanup(deadline, diagnostic), "post-release cleanup failed") ||
        !check(child.cleanup_state()->attempted && child.cleanup_state()->succeeded,
               "cleanup state was not observable") ||
        !check(absent(directory.fd, "attempt.log"), "log artifact remained") ||
        !check(source.active(), "child lease unexpectedly took source ownership")) {
        std::fprintf(stderr,
                     "cleanup phase=%u error=%d\n",
                     static_cast<unsigned>(diagnostic.phase),
                     diagnostic.error_number);
        return false;
    }
    if (!check(source.remove(source_diagnostic), "caller-owned source cleanup failed"))
        return false;
    return check(absent(directory.fd, "wildcard.rut"), "source artifact remained");
}

bool sibling_rejected() {
    TempDirectory directory;
    source_lease::WildcardAttemptSourceLease source;
    child_lease::WildcardAttemptChildLease child;
    source_lease::Diagnostic source_diagnostic;
    child_lease::Diagnostic diagnostic;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(15);
    if (!directory.open() ||
        !source_lease::WildcardAttemptSourceLease::create(
            directory.fd, directory.path, "wildcard.rut", kPlan, source, source_diagnostic) ||
        !child_lease::WildcardAttemptChildLease::create(
            source, "attempt.log", deadline, child, diagnostic))
        return false;
    const pid_t sibling = fork();
    if (!check(sibling >= 0, "sibling fork failed")) return false;
    if (sibling == 0) pause();
    const bool rejected = !child.scan_direct_children(deadline, diagnostic) &&
                          diagnostic.phase == child_lease::FailurePhase::Proc;
    kill(sibling, SIGTERM);
    int status = 0;
    waitpid(sibling, &status, 0);
    const bool cleaned = child.cleanup(deadline, diagnostic);
    source.remove(source_diagnostic);
    return check(rejected && cleaned, "unexpected sibling was not rejected safely");
}

bool early_death_and_double_release() {
    TempDirectory directory;
    source_lease::WildcardAttemptSourceLease source;
    child_lease::WildcardAttemptChildLease child;
    source_lease::Diagnostic source_diagnostic;
    child_lease::Diagnostic diagnostic;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(15);
    if (!directory.open() ||
        !source_lease::WildcardAttemptSourceLease::create(
            directory.fd, directory.path, "wildcard.rut", kPlan, source, source_diagnostic) ||
        !child_lease::WildcardAttemptChildLease::create(
            source, "attempt.log", deadline, child, diagnostic))
        return false;
#ifdef SYS_pidfd_send_signal
    const bool killed = syscall(SYS_pidfd_send_signal, child.pidfd(), SIGKILL, nullptr, 0u) == 0;
#else
    const bool killed = false;
#endif
    if (!check(killed, "early child kill failed") ||
        !check(!child.release(deadline, diagnostic),
               "early child release unexpectedly succeeded") ||
        !check(child.cleanup(deadline, diagnostic), "dead child cleanup failed")) {
        std::fprintf(stderr,
                     "dead cleanup phase=%u error=%d\n",
                     static_cast<unsigned>(diagnostic.phase),
                     diagnostic.error_number);
        return false;
    }
    source.remove(source_diagnostic);

    source_lease::WildcardAttemptSourceLease second_source;
    child_lease::WildcardAttemptChildLease second;
    if (!source_lease::WildcardAttemptSourceLease::create(directory.fd,
                                                          directory.path,
                                                          "wildcard-second.rut",
                                                          kPlan,
                                                          second_source,
                                                          source_diagnostic) ||
        !child_lease::WildcardAttemptChildLease::create(
            second_source, "attempt-second.log", deadline, second, diagnostic) ||
        !second.release(deadline, diagnostic) || second.release(deadline, diagnostic) ||
        diagnostic.phase != child_lease::FailurePhase::Argument ||
        !second.cleanup(deadline, diagnostic))
        return false;
    return second_source.remove(source_diagnostic);
}

bool log_replacement_preserved() {
    TempDirectory directory;
    source_lease::WildcardAttemptSourceLease source;
    child_lease::WildcardAttemptChildLease child;
    source_lease::Diagnostic source_diagnostic;
    child_lease::Diagnostic diagnostic;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(15);
    if (!directory.open() ||
        !source_lease::WildcardAttemptSourceLease::create(
            directory.fd, directory.path, "wildcard.rut", kPlan, source, source_diagnostic) ||
        !child_lease::WildcardAttemptChildLease::create(
            source, "attempt.log", deadline, child, diagnostic) ||
        !child.release(deadline, diagnostic))
        return false;
    const bool moved = renameat(directory.fd, "attempt.log", directory.fd, "original.log") == 0;
    const int replacement = openat(
        directory.fd, "attempt.log", O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    const bool wrote = replacement >= 0 && write(replacement, "replacement", 11u) == 11;
    if (replacement >= 0) close(replacement);
    const bool rejected = moved && wrote && !child.cleanup(deadline, diagnostic);
    const bool intact = !absent(directory.fd, "attempt.log");
    unlinkat(directory.fd, "attempt.log", 0);
    unlinkat(directory.fd, "original.log", 0);
    source.remove(source_diagnostic);
    return check(rejected && intact, "log replacement was not preserved fail-closed");
}

bool source_replacement_blocks_release() {
    TempDirectory directory;
    source_lease::WildcardAttemptSourceLease source;
    child_lease::WildcardAttemptChildLease child;
    source_lease::Diagnostic source_diagnostic;
    child_lease::Diagnostic diagnostic;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(15);
    if (!directory.open() ||
        !source_lease::WildcardAttemptSourceLease::create(
            directory.fd, directory.path, "wildcard.rut", kPlan, source, source_diagnostic) ||
        !child_lease::WildcardAttemptChildLease::create(
            source, "attempt.log", deadline, child, diagnostic))
        return false;
    if (renameat(directory.fd, "wildcard.rut", directory.fd, "source-original.rut") != 0)
        return false;
    const int replacement = openat(
        directory.fd, "wildcard.rut", O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    const bool replacement_written =
        replacement >= 0 && write(replacement, "replacement", 11u) == 11;
    if (replacement >= 0) close(replacement);
    const bool blocked = replacement_written && !child.release(deadline, diagnostic);
    const bool replacement_intact = !absent(directory.fd, "wildcard.rut");
    unlinkat(directory.fd, "wildcard.rut", 0);
    renameat(directory.fd, "source-original.rut", directory.fd, "wildcard.rut");
    const bool settled = child.release(deadline, diagnostic) && child.cleanup(deadline, diagnostic);
    source.remove(source_diagnostic);
    return check(blocked && replacement_intact && settled,
                 "source replacement was not rejected/preserved before release");
}

bool log_hardlink_blocks_cleanup() {
    TempDirectory directory;
    source_lease::WildcardAttemptSourceLease source;
    child_lease::WildcardAttemptChildLease child;
    source_lease::Diagnostic source_diagnostic;
    child_lease::Diagnostic diagnostic;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(15);
    if (!directory.open() ||
        !source_lease::WildcardAttemptSourceLease::create(
            directory.fd, directory.path, "wildcard.rut", kPlan, source, source_diagnostic) ||
        !child_lease::WildcardAttemptChildLease::create(
            source, "attempt.log", deadline, child, diagnostic) ||
        !child.release(deadline, diagnostic))
        return false;
    const bool linked =
        linkat(directory.fd, "attempt.log", directory.fd, "attempt-hardlink.rut", 0) == 0;
    const bool blocked = linked && !child.cleanup(deadline, diagnostic) &&
                         child.cleanup_state()->attempted && !child.cleanup_state()->succeeded;
    const bool original_intact = !absent(directory.fd, "attempt.log");
    unlinkat(directory.fd, "attempt-hardlink.rut", 0);
    const bool settled = child.cleanup(deadline, diagnostic);
    source.remove(source_diagnostic);
    return check(blocked && original_intact && settled,
                 "log hard-link mutation did not fail closed");
}

bool pidfd_and_deadline_gates() {
    TempDirectory directory;
    source_lease::WildcardAttemptSourceLease source;
    child_lease::WildcardAttemptChildLease child;
    source_lease::Diagnostic source_diagnostic;
    child_lease::Diagnostic diagnostic;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(15);
    if (!directory.open() ||
        !source_lease::WildcardAttemptSourceLease::create(
            directory.fd, directory.path, "wildcard.rut", kPlan, source, source_diagnostic) ||
        !child_lease::WildcardAttemptChildLease::create(
            source, "attempt.log", deadline, child, diagnostic))
        return false;
    const int saved_pidfd = dup(child.pidfd());
    const int wrong = open("/dev/null", O_RDONLY | O_CLOEXEC);
    const bool replaced =
        saved_pidfd >= 0 && wrong >= 0 && dup2(wrong, child.pidfd()) == child.pidfd();
    if (wrong >= 0) close(wrong);
    const bool non_pidfd_rejected = replaced && !child.validate_paused(deadline, diagnostic);
    const bool restored = replaced && dup2(saved_pidfd, child.pidfd()) == child.pidfd();
    if (saved_pidfd >= 0) close(saved_pidfd);
    const bool clear_cloexec = restored && fcntl(child.pidfd(), F_SETFD, 0) == 0;
    const bool cloexec_rejected = clear_cloexec && !child.validate_paused(deadline, diagnostic);
    const bool reset_cloexec = fcntl(child.pidfd(), F_SETFD, FD_CLOEXEC) == 0;
    const auto expired = std::chrono::steady_clock::now() - std::chrono::milliseconds(1);
    const bool deadline_rejected = !child.release(expired, diagnostic);
    const bool settled = child.release(deadline, diagnostic) && child.cleanup(deadline, diagnostic);
    source.remove(source_diagnostic);
    return check(
        non_pidfd_rejected && cloexec_rejected && reset_cloexec && deadline_rejected && settled,
        "pidfd/deadline gates were not fail-closed");
}

}  // namespace

int main() {
    return canonical() && sibling_rejected() && early_death_and_double_release() &&
                   log_replacement_preserved() && source_replacement_blocks_release() &&
                   log_hardlink_blocks_cleanup() && pidfd_and_deadline_gates()
               ? 0
               : 1;
}
