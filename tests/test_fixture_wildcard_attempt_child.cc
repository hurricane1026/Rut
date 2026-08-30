#include "fixture_wildcard_attempt_child.h"
#include <array>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <string>

#include <fcntl.h>
#include <sys/stat.h>
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
    if (!check(child.active() && child.child_pid() > 1 && child.pidfd() >= 0 &&
                   child.log_descriptor() >= 0,
               "paused child did not retain required descriptors") ||
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
    if (!check(kill(child.child_pid(), SIGKILL) == 0, "early child kill failed") ||
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

}  // namespace

int main() {
    return canonical() && sibling_rejected() && early_death_and_double_release() &&
                   log_replacement_preserved()
               ? 0
               : 1;
}
