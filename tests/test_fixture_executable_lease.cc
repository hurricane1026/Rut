#include "fixture_executable_lease.h"
#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include <dirent.h>
#include <fcntl.h>
#include <linux/kcmp.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

namespace executable = rut::test::fixture_executable_lease;

namespace {

bool check(bool condition, const char* message) {
    if (!condition) std::fprintf(stderr, "FAIL: %s (errno=%d)\n", message, errno);
    return condition;
}

bool fd_snapshot(std::vector<int>& descriptors) {
    descriptors.clear();
    DIR* directory = opendir("/proc/self/fd");
    if (directory == nullptr) return false;
    const int snapshot_fd = dirfd(directory);
    errno = 0;
    while (dirent* entry = readdir(directory)) {
        int value = 0;
        const char* const begin = entry->d_name;
        const char* const end = begin + std::strlen(begin);
        const auto [parsed, error] = std::from_chars(begin, end, value);
        if (error == std::errc{} && parsed == end && value >= 0 && value != snapshot_fd)
            descriptors.push_back(value);
        errno = 0;
    }
    const int read_error = errno;
    const bool close_ok = closedir(directory) == 0;
    if (read_error != 0 || !close_ok) {
        descriptors.clear();
        return false;
    }
    std::sort(descriptors.begin(), descriptors.end());
    return std::adjacent_find(descriptors.begin(), descriptors.end()) == descriptors.end();
}

bool same_snapshot(const std::vector<int>& expected, const char* message) {
    std::vector<int> current;
    return check(fd_snapshot(current), "could not obtain complete /proc FD snapshot") &&
           check(current == expected, message);
}

bool write_all(int fd, const unsigned char* data, std::size_t size) {
    std::size_t offset = 0u;
    while (offset < size) {
        const ssize_t count = write(fd, data + offset, size - offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return false;
        offset += static_cast<std::size_t>(count);
    }
    return true;
}

struct PrivateDirectory {
    using RmdirForTesting = int (*)(const char* path);

    std::array<char, 96> path{};
    int descriptor = -1;
    bool directory_created = false;
    RmdirForTesting rmdir_for_testing = rmdir;

    bool create_with_pattern(const char* pattern) {
        std::snprintf(path.data(), path.size(), "%s", pattern);
        if (mkdtemp(path.data()) == nullptr) return false;
        directory_created = true;
        descriptor = open(path.data(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        return descriptor >= 0 && fchmod(descriptor, 0700) == 0;
    }

    bool create() { return create_with_pattern("/tmp/rut377-executable-XXXXXX"); }

    std::string child(const char* name) const { return std::string(path.data()) + "/" + name; }

    bool executable(const char* name = "program", mode_t mode = 0700) const {
        const int source = open("/bin/true", O_RDONLY | O_CLOEXEC);
        const int target =
            openat(descriptor, name, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
        if (source < 0 || target < 0) {
            if (source >= 0) close(source);
            if (target >= 0) close(target);
            return false;
        }
        std::array<unsigned char, 4096> bytes{};
        bool okay = true;
        for (;;) {
            const ssize_t count = read(source, bytes.data(), bytes.size());
            if (count < 0 && errno == EINTR) continue;
            if (count < 0) {
                okay = false;
                break;
            }
            if (count == 0) break;
            if (!write_all(target, bytes.data(), static_cast<std::size_t>(count))) {
                okay = false;
                break;
            }
        }
        okay = okay && fsync(target) == 0 && fchmod(target, mode) == 0;
        if (close(source) != 0) okay = false;
        if (close(target) != 0) okay = false;
        return okay;
    }

    ~PrivateDirectory() {
        if (descriptor >= 0) {
            DIR* directory = fdopendir(dup(descriptor));
            if (directory != nullptr) {
                while (dirent* entry = readdir(directory)) {
                    if (std::strcmp(entry->d_name, ".") == 0 ||
                        std::strcmp(entry->d_name, "..") == 0)
                        continue;
                    if (unlinkat(descriptor, entry->d_name, 0) != 0)
                        std::fprintf(stderr,
                                     "FAIL: temporary executable cleanup %s errno=%d\n",
                                     entry->d_name,
                                     errno);
                }
                closedir(directory);
            }
            close(descriptor);
        }
        if (directory_created && rmdir_for_testing(path.data()) != 0)
            std::fprintf(stderr, "FAIL: temporary directory cleanup errno=%d\n", errno);
    }
};

unsigned rmdir_calls = 0u;

int recording_rmdir(const char* path) {
    ++rmdir_calls;
    return rmdir(path);
}

bool failed_mkdtemp_cleanup_test() {
    rmdir_calls = 0u;
    {
        PrivateDirectory directory;
        directory.rmdir_for_testing = recording_rmdir;
        errno = 0;
        if (!check(
                !directory.create_with_pattern("/proc/rut377-executable-no-parent/child-XXXXXX") &&
                    errno == ENOENT && !directory.directory_created && directory.descriptor < 0,
                "deterministic mkdtemp failure precondition"))
            return false;
    }
    return check(rmdir_calls == 0u, "failed mkdtemp attempted rmdir cleanup");
}

bool self_kcmp(int first, int second) {
#ifdef SYS_kcmp
    errno = 0;
    return syscall(SYS_kcmp, getpid(), getpid(), KCMP_FILE, first, second) == 0;
#else
    (void)first;
    (void)second;
    return false;
#endif
}

bool new_owned_fds(const std::vector<int>& baseline,
                   int observation,
                   std::array<int, 2>& authorities,
                   std::vector<int>& current) {
    if (!fd_snapshot(current)) return false;
    std::vector<int> added;
    std::set_difference(current.begin(),
                        current.end(),
                        baseline.begin(),
                        baseline.end(),
                        std::back_inserter(added));
    if (added.size() != 3u || std::find(added.begin(), added.end(), observation) == added.end())
        return false;
    std::size_t at = 0u;
    for (const int descriptor : added)
        if (descriptor != observation) authorities[at++] = descriptor;
    return at == authorities.size();
}

bool canonical_custody_test() {
    PrivateDirectory directory;
    std::vector<int> baseline;
    if (!check(directory.create() && directory.executable(), "canonical setup") ||
        !check(fd_snapshot(baseline), "canonical baseline snapshot"))
        return false;
    executable::ExecutableLease lease;
    executable::Diagnostic diagnostic;
    if (!check(executable::ExecutableLease::create(directory.child("program"), lease, diagnostic),
               "canonical create"))
        return false;
    std::array<int, 2> authorities{-1, -1};
    std::vector<int> active;
    struct stat status{};
    const int observation_flags = fcntl(lease.observation_fd(), F_GETFD);
    const int observation_status = fcntl(lease.observation_fd(), F_GETFL);
    const bool identity = fstat(lease.observation_fd(), &status) == 0;
    const auto evidence = lease.cleanup_state();
    const bool okay =
        check(
            lease.active() && new_owned_fds(baseline, lease.observation_fd(), authorities, active),
            "canonical exact three-FD custody") &&
        check(observation_flags >= 0 && (observation_flags & FD_CLOEXEC) != 0 &&
                  observation_status >= 0 && (observation_status & O_PATH) == O_PATH,
              "canonical observation flags") &&
        check(fcntl(authorities[0], F_GETFD) >= 0 &&
                  (fcntl(authorities[0], F_GETFD) & FD_CLOEXEC) != 0 &&
                  fcntl(authorities[1], F_GETFD) >= 0 &&
                  (fcntl(authorities[1], F_GETFD) & FD_CLOEXEC) != 0 &&
                  self_kcmp(lease.observation_fd(), authorities[0]) &&
                  self_kcmp(lease.observation_fd(), authorities[1]) &&
                  self_kcmp(authorities[0], authorities[1]),
              "canonical private authorities exact OFD") &&
        check(identity && lease.identity().device == static_cast<std::uint64_t>(status.st_dev) &&
                  lease.identity().inode == static_cast<std::uint64_t>(status.st_ino) &&
                  lease.identity().mode == static_cast<std::uint64_t>(status.st_mode) &&
                  lease.identity().uid == static_cast<std::uint64_t>(status.st_uid) &&
                  lease.identity().gid == static_cast<std::uint64_t>(status.st_gid),
              "canonical stored identity") &&
        check(lease.revalidate(diagnostic), "canonical revalidate") &&
        check(lease.close(diagnostic), "canonical close") &&
        check(!lease.active() && evidence->semantic_validation.succeeded &&
                  evidence->custody_validation.succeeded && evidence->observation.attempted &&
                  evidence->observation.succeeded && evidence->authority_one.attempted &&
                  evidence->authority_one.succeeded && evidence->authority_two.attempted &&
                  evidence->authority_two.succeeded && evidence->reportable_success,
              "canonical cleanup evidence") &&
        same_snapshot(baseline, "canonical exact FD residue") &&
        check(!lease.close(diagnostic) && diagnostic.phase == executable::FailurePhase::Close &&
                  diagnostic.error_number == EALREADY,
              "canonical double close accepted") &&
        check(!executable::ExecutableLease::create(directory.child("program"), lease, diagnostic) &&
                  diagnostic.phase == executable::FailurePhase::Argument,
              "canonical create after terminal accepted") &&
        same_snapshot(baseline, "canonical terminal operation residue");
    return okay;
}

bool argument_and_policy_rejection_test() {
    PrivateDirectory directory;
    std::vector<int> baseline;
    if (!check(directory.create() && directory.executable("program", 0700) &&
                   directory.executable("nonexec", 0600) &&
                   directory.executable("group-writable", 0720) &&
                   directory.executable("world-writable", 0702),
               "rejection setup") ||
        !check(fd_snapshot(baseline), "rejection baseline"))
        return false;
    if (symlinkat("program", directory.descriptor, "link") != 0 ||
        mkdirat(directory.descriptor, "subdir", 0700) != 0)
        return check(false, "rejection symlink/directory setup");
    bool okay = true;
    const std::array<std::string, 7> rejected = {
        "program",
        directory.child("./program"),
        directory.child("link"),
        directory.child("subdir"),
        directory.child("nonexec"),
        directory.child("group-writable"),
        directory.child("world-writable"),
    };
    for (const std::string& path : rejected) {
        executable::ExecutableLease lease;
        executable::Diagnostic diagnostic;
        const bool accepted = executable::ExecutableLease::create(path, lease, diagnostic);
        okay = check(!accepted && !lease.active(), "invalid executable input accepted") && okay;
        okay = same_snapshot(baseline, "invalid executable left FD residue") && okay;
    }
    executable::ExecutableLease fresh_after_argument;
    executable::Diagnostic fresh_diagnostic;
    const bool invalid_preopen =
        !executable::ExecutableLease::create("program", fresh_after_argument, fresh_diagnostic);
    const bool valid_after_argument = executable::ExecutableLease::create(
        directory.child("program"), fresh_after_argument, fresh_diagnostic);
    okay = check(invalid_preopen && valid_after_argument &&
                     fresh_after_argument.close(fresh_diagnostic),
                 "pre-open argument rejection did not leave object fresh") &&
           okay;
    executable::ExecutableLease seeded_canonical;
    executable::Diagnostic seeded_diagnostic;
    errno = EBUSY;
    okay = check(!executable::ExecutableLease::create(
                     directory.child("./program"), seeded_canonical, seeded_diagnostic) &&
                     seeded_diagnostic.phase == executable::FailurePhase::Canonical &&
                     seeded_diagnostic.error_number == EINVAL,
                 "canonical mismatch inherited ambient errno") &&
           okay;
    executable::ExecutableLease seeded_policy;
    errno = EBUSY;
    okay = check(!executable::ExecutableLease::create(
                     directory.child("nonexec"), seeded_policy, seeded_diagnostic) &&
                     seeded_diagnostic.phase == executable::FailurePhase::Policy &&
                     seeded_diagnostic.error_number == EACCES,
                 "policy mismatch inherited ambient errno") &&
           okay;
    executable::ExecutableLease seeded_identity;
    errno = EBUSY;
    okay = check(!executable::ExecutableLease::create(
                     directory.child("subdir"), seeded_identity, seeded_diagnostic) &&
                     seeded_diagnostic.phase == executable::FailurePhase::Identity &&
                     seeded_diagnostic.error_number == EINVAL,
                 "initial identity mismatch inherited ambient errno") &&
           okay;
    if (geteuid() == 0) {
        if (fchownat(directory.descriptor, "program", 1, static_cast<gid_t>(-1), 0) != 0)
            return check(false, "root wrong-owner setup");
        executable::ExecutableLease lease;
        executable::Diagnostic diagnostic;
        okay = check(!executable::ExecutableLease::create(
                         directory.child("program"), lease, diagnostic),
                     "wrong-owner executable accepted") &&
               okay;
    }
    std::array<gid_t, 32> groups{};
    const int group_count = getgroups(static_cast<int>(groups.size()), groups.data());
    gid_t alternate_group = getegid();
    for (int index = 0; index < group_count; ++index)
        if (groups[static_cast<std::size_t>(index)] != getegid()) {
            alternate_group = groups[static_cast<std::size_t>(index)];
            break;
        }
    if (alternate_group != getegid() && directory.executable("alternate-gid", 0700) &&
        fchownat(
            directory.descriptor, "alternate-gid", static_cast<uid_t>(-1), alternate_group, 0) ==
            0) {
        executable::ExecutableLease lease;
        executable::Diagnostic diagnostic;
        const bool accepted = executable::ExecutableLease::create(
            directory.child("alternate-gid"), lease, diagnostic);
        okay =
            check(accepted && lease.identity().gid == static_cast<std::uint64_t>(alternate_group),
                  "supplementary-group executable was incorrectly rejected") &&
            okay;
        okay =
            check(accepted && lease.close(diagnostic), "supplementary-group executable cleanup") &&
            okay;
    }
    unlinkat(directory.descriptor, "link", 0);
    unlinkat(directory.descriptor, "subdir", AT_REMOVEDIR);
    return okay && same_snapshot(baseline, "rejection final residue");
}

bool pathname_replacement_test() {
    PrivateDirectory directory;
    std::vector<int> baseline;
    if (!check(directory.create() && directory.executable(), "pathname setup") ||
        !check(fd_snapshot(baseline), "pathname baseline"))
        return false;
    executable::ExecutableLease lease;
    executable::Diagnostic diagnostic;
    if (!check(executable::ExecutableLease::create(directory.child("program"), lease, diagnostic),
               "pathname create") ||
        !check(
            renameat(directory.descriptor, "program", directory.descriptor, "saved-program") == 0 &&
                directory.executable("program"),
            "pathname replacement setup"))
        return false;
    errno = EBUSY;
    const bool rejected = !lease.revalidate(diagnostic) &&
                          diagnostic.phase == executable::FailurePhase::Path &&
                          diagnostic.error_number == EINVAL;
    if (unlinkat(directory.descriptor, "program", 0) != 0 ||
        renameat(directory.descriptor, "saved-program", directory.descriptor, "program") != 0)
        return check(false, "pathname restoration");
    if (!check(rejected, "different-inode pathname replacement accepted") ||
        !check(lease.revalidate(diagnostic), "restored pathname rejected") ||
        !check(lease.close(diagnostic), "pathname close"))
        return false;

    executable::ExecutableLease cleanup_lease;
    if (!check(executable::ExecutableLease::create(
                   directory.child("program"), cleanup_lease, diagnostic),
               "pathname cleanup create") ||
        !check(
            renameat(
                directory.descriptor, "program", directory.descriptor, "cleanup-saved-program") ==
                    0 &&
                directory.executable("program"),
            "pathname cleanup replacement"))
        return false;
    struct stat replacement_before{};
    struct stat replacement_after{};
    const bool replacement_known =
        fstatat(directory.descriptor, "program", &replacement_before, AT_SYMLINK_NOFOLLOW) == 0;
    const bool cleanup_rejected =
        !cleanup_lease.revalidate(diagnostic) && diagnostic.phase == executable::FailurePhase::Path;
    const bool cleanup_closed = cleanup_lease.close(diagnostic);
    const bool replacement_preserved =
        fstatat(directory.descriptor, "program", &replacement_after, AT_SYMLINK_NOFOLLOW) == 0 &&
        replacement_after.st_dev == replacement_before.st_dev &&
        replacement_after.st_ino == replacement_before.st_ino;
    return check(replacement_known && cleanup_rejected,
                 "pathname drift cleanup precondition was not causal") &&
           check(cleanup_closed && replacement_preserved,
                 "pathname drift prevented custody cleanup or changed replacement") &&
           same_snapshot(baseline, "pathname residue");
}

bool observation_mutation_test(bool same_inode_new_ofd) {
    PrivateDirectory directory;
    std::vector<int> baseline;
    if (!check(directory.create() && directory.executable() && directory.executable("other"),
               "observation setup") ||
        !check(fd_snapshot(baseline), "observation baseline"))
        return false;
    executable::ExecutableLease lease;
    executable::Diagnostic diagnostic;
    if (!check(executable::ExecutableLease::create(directory.child("program"), lease, diagnostic),
               "observation create"))
        return false;
    std::array<int, 2> authorities{-1, -1};
    std::vector<int> active;
    if (!check(new_owned_fds(baseline, lease.observation_fd(), authorities, active),
               "observation authority discovery"))
        return false;
    const int slot = lease.observation_fd();
    const int saved = fcntl(slot, F_DUPFD_CLOEXEC, 0);
    const std::string replacement_path = same_inode_new_ofd
                                             ? "/proc/self/fd/" + std::to_string(authorities[0])
                                             : directory.child("other");
    const int replacement = open(replacement_path.c_str(), O_PATH | O_CLOEXEC);
    if (!check(saved >= 0 && replacement >= 0 && dup2(replacement, slot) == slot &&
                   fcntl(slot, F_SETFD, FD_CLOEXEC) == 0,
               "observation replacement"))
        return false;
    const bool rejected =
        !lease.revalidate(diagnostic) &&
        (same_inode_new_ofd ? diagnostic.phase == executable::FailurePhase::Kcmp
                            : diagnostic.phase == executable::FailurePhase::Identity);
    const bool preserved = fcntl(slot, F_GETFD) >= 0 && self_kcmp(slot, replacement);
    const bool close_rejected = !lease.close(diagnostic) && lease.active() &&
                                fcntl(slot, F_GETFD) >= 0 && self_kcmp(slot, replacement);
    if (dup2(saved, slot) != slot || fcntl(slot, F_SETFD, FD_CLOEXEC) != 0)
        return check(false, "observation exact restoration");
    close(saved);
    close(replacement);
    return check(rejected && preserved, "observation mutation was accepted or foreign FD closed") &&
           check(close_rejected, "close accepted foreign observation") &&
           check(lease.revalidate(diagnostic), "restored exact observation rejected") &&
           check(lease.close(diagnostic), "restored observation close") &&
           same_snapshot(baseline, "observation mutation residue");
}

bool cloexec_recovery_test() {
    PrivateDirectory directory;
    std::vector<int> baseline;
    if (!check(directory.create() && directory.executable(), "cloexec setup") ||
        !check(fd_snapshot(baseline), "cloexec baseline"))
        return false;
    executable::ExecutableLease lease;
    executable::Diagnostic diagnostic;
    if (!check(executable::ExecutableLease::create(directory.child("program"), lease, diagnostic),
               "cloexec create"))
        return false;
    const int slot = lease.observation_fd();
    if (fcntl(slot, F_SETFD, 0) != 0) return check(false, "clear cloexec");
    const bool rejected =
        !lease.revalidate(diagnostic) && diagnostic.phase == executable::FailurePhase::Identity;
    if (fcntl(slot, F_SETFD, FD_CLOEXEC) != 0) return check(false, "restore cloexec");
    return check(rejected, "cleared observation CLOEXEC accepted") &&
           check(lease.revalidate(diagnostic), "restored CLOEXEC rejected") &&
           check(lease.close(diagnostic), "cloexec close") &&
           same_snapshot(baseline, "cloexec residue");
}

struct KcmpInjection {
    int error_number = 0;
    bool enabled = true;
};

int denied_kcmp(int first, int second, void* context) {
    const auto* injection = static_cast<const KcmpInjection*>(context);
    if (injection != nullptr && !injection->enabled) {
#ifdef SYS_kcmp
        return static_cast<int>(syscall(SYS_kcmp, getpid(), getpid(), KCMP_FILE, first, second));
#else
        errno = ENOSYS;
        return -1;
#endif
    }
    errno = injection == nullptr ? EIO : injection->error_number;
    return -1;
}

struct AccessInjection {
    int error_number = 0;
};

int denied_access(int, void* context) {
    const auto* injection = static_cast<const AccessInjection*>(context);
    errno = injection == nullptr ? EIO : injection->error_number;
    return -1;
}

struct CloseInjection {
    unsigned calls = 0u;
    unsigned fail_call = 0u;
    int failure = EINTR;
};

int real_close_then_error(int descriptor, void* context) {
    auto* injection = static_cast<CloseInjection*>(context);
    const int result = close(descriptor);
    if (injection != nullptr) {
        ++injection->calls;
        if (result == 0 && injection->calls == injection->fail_call) {
            errno = injection->failure;
            return -1;
        }
    }
    return result;
}

bool create_failure_cleanup_test() {
    PrivateDirectory directory;
    std::vector<int> baseline;
    if (!check(directory.create() && directory.executable(), "create failure setup") ||
        !check(fd_snapshot(baseline), "create failure baseline"))
        return false;
    bool okay = true;
    for (const executable::CreationFailurePoint point : {
             executable::CreationFailurePoint::AfterOpen,
             executable::CreationFailurePoint::AfterFirstDuplicate,
             executable::CreationFailurePoint::AfterDuplicate,
             executable::CreationFailurePoint::IdentityValidation,
         }) {
        executable::ExecutableLease lease;
        executable::Diagnostic diagnostic;
        CloseInjection close_injection;
        const executable::HooksForTesting hooks{
            nullptr, real_close_then_error, nullptr, &close_injection, point};
        const bool created = executable::ExecutableLease::create_with_hooks_for_testing(
            directory.child("program"), hooks, lease, diagnostic);
        const executable::Diagnostic creation_diagnostic = diagnostic;
        const unsigned expected = point == executable::CreationFailurePoint::AfterOpen ? 1u
                                  : point == executable::CreationFailurePoint::AfterFirstDuplicate
                                      ? 2u
                                      : 3u;
        const auto evidence = lease.cleanup_state();
        const bool terminal_reuse =
            !executable::ExecutableLease::create(directory.child("program"), lease, diagnostic) &&
            diagnostic.phase == executable::FailurePhase::Argument;
        const executable::FailurePhase expected_phase =
            point == executable::CreationFailurePoint::AfterOpen ? executable::FailurePhase::Open
            : point == executable::CreationFailurePoint::AfterFirstDuplicate ||
                    point == executable::CreationFailurePoint::AfterDuplicate
                ? executable::FailurePhase::Duplicate
                : executable::FailurePhase::Identity;
        okay =
            check(!created && !lease.active() && creation_diagnostic.phase == expected_phase &&
                      creation_diagnostic.error_number == EIO &&
                      close_injection.calls == expected && evidence->observation.attempts == 1u &&
                      evidence->authority_one.attempts == (expected >= 2u ? 1u : 0u) &&
                      evidence->authority_two.attempts == (expected == 3u ? 1u : 0u) &&
                      evidence->creation_cleanup &&
                      evidence->creation_diagnostic.phase == expected_phase && terminal_reuse,
                  "creation failure cleanup was not exact") &&
            okay;
        okay = same_snapshot(baseline, "creation failure FD residue") && okay;
    }
    for (const int denied : {ENOSYS, EPERM}) {
        executable::ExecutableLease lease;
        executable::Diagnostic diagnostic;
        KcmpInjection injection{denied};
        const executable::HooksForTesting hooks{
            denied_kcmp, nullptr, nullptr, &injection, executable::CreationFailurePoint::None};
        const bool created = executable::ExecutableLease::create_with_hooks_for_testing(
            directory.child("program"), hooks, lease, diagnostic);
        okay = check(!created && diagnostic.phase == executable::FailurePhase::Kcmp &&
                         diagnostic.error_number == denied && !lease.active() &&
                         lease.cleanup_state()->observation.attempts == 1u &&
                         lease.cleanup_state()->authority_one.attempts == 1u &&
                         lease.cleanup_state()->authority_two.attempts == 1u,
                     "kcmp denial did not fail closed with exact cleanup") &&
               okay;
        okay = same_snapshot(baseline, "kcmp denial FD residue") && okay;
    }
    for (const int denied : {ENOSYS, ENOTSUP, EACCES}) {
        executable::ExecutableLease lease;
        executable::Diagnostic diagnostic;
        AccessInjection injection{denied};
        const executable::HooksForTesting hooks{
            nullptr, nullptr, denied_access, &injection, executable::CreationFailurePoint::None};
        errno = EBUSY;
        const bool created = executable::ExecutableLease::create_with_hooks_for_testing(
            directory.child("program"), hooks, lease, diagnostic);
        okay = check(!created && diagnostic.phase == executable::FailurePhase::Policy &&
                         diagnostic.error_number == denied && !lease.active() &&
                         lease.cleanup_state()->observation.attempts == 1u &&
                         lease.cleanup_state()->authority_one.attempts == 1u &&
                         lease.cleanup_state()->authority_two.attempts == 1u,
                     "FD-relative access denial did not fail closed exactly") &&
               okay;
        okay = same_snapshot(baseline, "access denial FD residue") && okay;
    }
    return okay;
}

bool creation_close_uncertainty_test() {
    PrivateDirectory directory;
    std::vector<int> baseline;
    if (!check(directory.create() && directory.executable(), "creation uncertainty setup") ||
        !check(fd_snapshot(baseline), "creation uncertainty baseline"))
        return false;
    executable::ExecutableLease lease;
    executable::Diagnostic diagnostic;
    CloseInjection injection{0u, 2u, EINTR};
    const executable::HooksForTesting hooks{nullptr,
                                            real_close_then_error,
                                            nullptr,
                                            &injection,
                                            executable::CreationFailurePoint::AfterDuplicate};
    const bool created = executable::ExecutableLease::create_with_hooks_for_testing(
        directory.child("program"), hooks, lease, diagnostic);
    const auto evidence = lease.cleanup_state();
    return check(!created && diagnostic.phase == executable::FailurePhase::Duplicate &&
                     diagnostic.error_number == EIO && injection.calls == 3u &&
                     evidence->creation_cleanup && evidence->observation.attempts == 1u &&
                     evidence->observation.succeeded && evidence->authority_one.attempts == 1u &&
                     !evidence->authority_one.succeeded &&
                     evidence->authority_one.error_number == EINTR &&
                     evidence->authority_two.attempts == 1u && evidence->authority_two.succeeded,
                 "creation close uncertainty was retried or obscured") &&
           same_snapshot(baseline, "creation uncertainty residue");
}

bool metadata_and_link_test() {
    PrivateDirectory directory;
    std::vector<int> baseline;
    if (!check(directory.create() && directory.executable(), "metadata setup") ||
        !check(fd_snapshot(baseline), "metadata baseline"))
        return false;
    executable::ExecutableLease lease;
    executable::Diagnostic diagnostic;
    if (!check(executable::ExecutableLease::create(directory.child("program"), lease, diagnostic),
               "metadata create"))
        return false;
    const std::int64_t initial_ctime_seconds = lease.identity().ctime_seconds;
    const std::int64_t initial_ctime_nanoseconds = lease.identity().ctime_nanoseconds;
    if (linkat(directory.descriptor, "program", directory.descriptor, "program-hardlink", 0) != 0)
        return check(false, "hardlink add");
    const bool link_added = lease.revalidate(diagnostic);
    if (unlinkat(directory.descriptor, "program-hardlink", 0) != 0)
        return check(false, "hardlink remove");
    const bool link_removed = lease.revalidate(diagnostic);
    const bool initial_identity_retained =
        lease.identity().ctime_seconds == initial_ctime_seconds &&
        lease.identity().ctime_nanoseconds == initial_ctime_nanoseconds;
    if (fchmodat(directory.descriptor, "program", 0720, 0) != 0)
        return check(false, "metadata drift");
    const bool drift_rejected =
        !lease.revalidate(diagnostic) && (diagnostic.phase == executable::FailurePhase::Identity ||
                                          diagnostic.phase == executable::FailurePhase::Policy);
    // Semantic drift does not remove ownership authority from cleanup.
    const auto explicit_evidence = lease.cleanup_state();
    const bool closed = lease.close(diagnostic);
    if (!check(link_added && link_removed && initial_identity_retained,
               "hard-link transition rejected or rewrote initial identity") ||
        !check(drift_rejected, "metadata drift accepted") ||
        !check(closed && !explicit_evidence->semantic_validation.succeeded &&
                   explicit_evidence->custody_validation.succeeded,
               "metadata drift evidence was overwritten by ownership cleanup"))
        return false;

    if (!check(directory.executable("content-program"), "content drift setup")) return false;
    std::shared_ptr<const executable::CleanupState> destructor_evidence;
    {
        executable::ExecutableLease content;
        if (!check(executable::ExecutableLease::create(
                       directory.child("content-program"), content, diagnostic),
                   "content drift create"))
            return false;
        destructor_evidence = content.cleanup_state();
        const int writer = openat(directory.descriptor, "content-program", O_WRONLY | O_CLOEXEC);
        const bool truncated = writer >= 0 && ftruncate(writer, 1) == 0;
        const bool writer_closed = writer >= 0 && close(writer) == 0;
        if (!check(truncated && writer_closed, "content drift mutation")) return false;
        errno = EBUSY;
        if (!check(!content.revalidate(diagnostic) &&
                       diagnostic.phase == executable::FailurePhase::Identity &&
                       diagnostic.error_number == EINVAL,
                   "content drift accepted"))
            return false;
        // Destructor must use custody, not semantic metadata, for cleanup.
    }
    return check(destructor_evidence->destructor && destructor_evidence->observation.succeeded &&
                     destructor_evidence->authority_one.succeeded &&
                     destructor_evidence->authority_two.succeeded &&
                     !destructor_evidence->semantic_validation.succeeded &&
                     destructor_evidence->custody_validation.succeeded &&
                     !destructor_evidence->reportable_success,
                 "content drift prevented destructor ownership cleanup") &&
           same_snapshot(baseline, "metadata residue");
}

bool uncertain_close_case(unsigned fail_call, int failure) {
    PrivateDirectory directory;
    std::vector<int> baseline;
    if (!check(directory.create() && directory.executable(), "close setup") ||
        !check(fd_snapshot(baseline), "close baseline"))
        return false;
    executable::ExecutableLease lease;
    executable::Diagnostic diagnostic;
    CloseInjection injection{0u, fail_call, failure};
    const executable::HooksForTesting hooks{nullptr,
                                            real_close_then_error,
                                            nullptr,
                                            &injection,
                                            executable::CreationFailurePoint::None};
    if (!check(executable::ExecutableLease::create_with_hooks_for_testing(
                   directory.child("program"), hooks, lease, diagnostic),
               "uncertain close create"))
        return false;
    const auto evidence = lease.cleanup_state();
    const bool closed = lease.close(diagnostic);
    const std::array<const executable::CloseOutcome*, 3> outcomes = {
        &evidence->observation, &evidence->authority_one, &evidence->authority_two};
    bool outcomes_exact = true;
    for (std::size_t index = 0; index < outcomes.size(); ++index)
        outcomes_exact =
            outcomes_exact && outcomes[index]->attempts == 1u &&
            (index + 1u == fail_call
                 ? (!outcomes[index]->succeeded && outcomes[index]->error_number == failure)
                 : (outcomes[index]->succeeded && outcomes[index]->error_number == 0));
    return check(!closed && !lease.active() &&
                     diagnostic.phase == executable::FailurePhase::Close &&
                     diagnostic.error_number == failure && injection.calls == 3u,
                 "uncertain close did not attempt all three exactly once") &&
           check(outcomes_exact && !evidence->reportable_success,
                 "uncertain close outcomes were not independent") &&
           same_snapshot(baseline, "uncertain close retried or leaked FD");
}

bool uncertain_close_test() {
    return uncertain_close_case(1u, EINTR) && uncertain_close_case(2u, EIO) &&
           uncertain_close_case(3u, EINTR);
}

bool destructor_close_uncertainty_test() {
    PrivateDirectory directory;
    std::vector<int> baseline;
    if (!check(directory.create() && directory.executable(), "destructor uncertainty setup") ||
        !check(fd_snapshot(baseline), "destructor uncertainty baseline"))
        return false;
    CloseInjection injection;
    std::shared_ptr<const executable::CleanupState> evidence;
    {
        executable::ExecutableLease lease;
        executable::Diagnostic diagnostic;
        const executable::HooksForTesting hooks{nullptr,
                                                real_close_then_error,
                                                nullptr,
                                                &injection,
                                                executable::CreationFailurePoint::None};
        if (!check(executable::ExecutableLease::create_with_hooks_for_testing(
                       directory.child("program"), hooks, lease, diagnostic),
                   "destructor uncertainty create"))
            return false;
        evidence = lease.cleanup_state();
        injection.fail_call = 2u;
        injection.failure = EINTR;
    }
    return check(injection.calls == 3u && evidence->destructor && evidence->observation.succeeded &&
                     evidence->authority_one.attempted && !evidence->authority_one.succeeded &&
                     evidence->authority_one.error_number == EINTR &&
                     evidence->authority_two.succeeded && !evidence->reportable_success,
                 "destructor close uncertainty was retried or obscured") &&
           same_snapshot(baseline, "destructor uncertainty residue");
}

enum class SlotMutation : std::uint8_t { DifferentInode, SameInodeNewOfd, ClearCloexec };

const executable::CloseOutcome& close_outcome(const executable::CleanupState& state,
                                              std::size_t index) {
    if (index == 0u) return state.observation;
    if (index == 1u) return state.authority_one;
    return state.authority_two;
}

bool slot_mutation_test(std::size_t slot_index, SlotMutation mutation) {
    PrivateDirectory directory;
    std::vector<int> baseline;
    if (!check(directory.create() && directory.executable() && directory.executable("other"),
               "slot mutation setup") ||
        !check(fd_snapshot(baseline), "slot mutation baseline"))
        return false;
    executable::ExecutableLease lease;
    executable::Diagnostic diagnostic;
    if (!check(executable::ExecutableLease::create(directory.child("program"), lease, diagnostic),
               "slot mutation create"))
        return false;
    std::array<int, 2> authorities{-1, -1};
    std::vector<int> active;
    if (!check(new_owned_fds(baseline, lease.observation_fd(), authorities, active),
               "slot mutation authority discovery"))
        return false;
    const std::array<int, 3> slots = {lease.observation_fd(), authorities[0], authorities[1]};
    const int slot = slots[slot_index];
    if (mutation == SlotMutation::ClearCloexec) {
        if (!check(fcntl(slot, F_SETFD, 0) == 0, "slot clear CLOEXEC")) return false;
        errno = EBUSY;
        const bool semantic_rejected = !lease.revalidate(diagnostic) &&
                                       diagnostic.phase == executable::FailurePhase::Identity &&
                                       diagnostic.error_number == EINVAL;
        errno = EBUSY;
        const bool close_rejected = !lease.close(diagnostic) && lease.active() &&
                                    diagnostic.phase == executable::FailurePhase::Identity &&
                                    diagnostic.error_number == EINVAL;
        if (!check(fcntl(slot, F_SETFD, FD_CLOEXEC) == 0, "slot restore CLOEXEC")) return false;
        return check(semantic_rejected && close_rejected,
                     "slot CLOEXEC mismatch was not deterministic/retryable") &&
               check(lease.revalidate(diagnostic), "slot CLOEXEC restoration rejected") &&
               check(lease.close(diagnostic), "slot CLOEXEC restored close") &&
               same_snapshot(baseline, "slot CLOEXEC residue");
    }

    const int saved = fcntl(slot, F_DUPFD_CLOEXEC, 0);
    const std::string replacement_path =
        mutation == SlotMutation::DifferentInode
            ? directory.child("other")
            : "/proc/self/fd/" + std::to_string(slots[(slot_index + 1u) % slots.size()]);
    const int replacement = open(replacement_path.c_str(), O_PATH | O_CLOEXEC);
    const int foreign_saved = replacement >= 0 ? fcntl(replacement, F_DUPFD_CLOEXEC, 0) : -1;
    if (!check(saved >= 0 && replacement >= 0 && foreign_saved >= 0 &&
                   dup2(replacement, slot) == slot && fcntl(slot, F_SETFD, FD_CLOEXEC) == 0 &&
                   close(replacement) == 0,
               "slot replacement"))
        return false;
    errno = EBUSY;
    const bool semantic_rejected =
        !lease.revalidate(diagnostic) &&
        diagnostic.error_number == (mutation == SlotMutation::DifferentInode ? EINVAL : EXDEV);
    errno = EBUSY;
    const bool close_rejected = !lease.close(diagnostic) && lease.active() &&
                                diagnostic.phase == executable::FailurePhase::Kcmp &&
                                diagnostic.error_number == EXDEV;
    const bool foreign_preserved = fcntl(slot, F_GETFD) >= 0 && self_kcmp(slot, foreign_saved);
    if (!check(dup2(saved, slot) == slot && fcntl(slot, F_SETFD, FD_CLOEXEC) == 0,
               "slot exact restoration"))
        return false;
    close(saved);
    close(foreign_saved);
    return check(semantic_rejected && close_rejected && foreign_preserved,
                 "slot mutation was accepted or foreign descriptor closed") &&
           check(lease.revalidate(diagnostic), "slot exact restoration rejected") &&
           check(lease.close(diagnostic), "slot restored close") &&
           same_snapshot(baseline, "slot mutation final residue");
}

bool canonical_destructor_test() {
    PrivateDirectory directory;
    std::vector<int> baseline;
    if (!check(directory.create() && directory.executable(), "destructor setup") ||
        !check(fd_snapshot(baseline), "destructor baseline"))
        return false;
    std::shared_ptr<const executable::CleanupState> evidence;
    {
        executable::ExecutableLease lease;
        executable::Diagnostic diagnostic;
        if (!check(
                executable::ExecutableLease::create(directory.child("program"), lease, diagnostic),
                "canonical destructor create"))
            return false;
        evidence = lease.cleanup_state();
    }
    return check(evidence->destructor && !evidence->reportable_success &&
                     evidence->custody_validation.succeeded && evidence->observation.succeeded &&
                     evidence->authority_one.succeeded && evidence->authority_two.succeeded,
                 "canonical destructor evidence") &&
           same_snapshot(baseline, "canonical destructor residue");
}

bool destructor_single_replacement_test(std::size_t slot_index) {
    PrivateDirectory directory;
    std::vector<int> baseline;
    if (!check(directory.create() && directory.executable(), "majority destructor setup") ||
        !check(fd_snapshot(baseline), "majority destructor baseline"))
        return false;
    std::shared_ptr<const executable::CleanupState> evidence;
    int foreign_slot = -1;
    int foreign_saved = -1;
    {
        executable::ExecutableLease lease;
        executable::Diagnostic diagnostic;
        if (!check(
                executable::ExecutableLease::create(directory.child("program"), lease, diagnostic),
                "majority destructor create"))
            return false;
        std::array<int, 2> authorities{-1, -1};
        std::vector<int> active;
        if (!check(new_owned_fds(baseline, lease.observation_fd(), authorities, active),
                   "majority destructor discovery"))
            return false;
        const std::array<int, 3> slots = {lease.observation_fd(), authorities[0], authorities[1]};
        foreign_slot = slots[slot_index];
        const std::string path =
            "/proc/self/fd/" + std::to_string(slots[(slot_index + 1u) % slots.size()]);
        const int replacement = open(path.c_str(), O_PATH | O_CLOEXEC);
        foreign_saved = replacement >= 0 ? fcntl(replacement, F_DUPFD_CLOEXEC, 0) : -1;
        if (!check(replacement >= 0 && foreign_saved >= 0 &&
                       dup2(replacement, foreign_slot) == foreign_slot &&
                       fcntl(foreign_slot, F_SETFD, FD_CLOEXEC) == 0 && close(replacement) == 0,
                   "majority destructor replacement"))
            return false;
        evidence = lease.cleanup_state();
    }
    bool majority_closed = evidence->custody_validation.succeeded;
    for (std::size_t index = 0; index < 3u; ++index) {
        const auto& outcome = close_outcome(*evidence, index);
        majority_closed =
            majority_closed &&
            (index == slot_index ? (!outcome.attempted && outcome.error_number == EXDEV)
                                 : (outcome.attempted && outcome.succeeded));
    }
    const bool foreign_preserved = fcntl(foreign_slot, F_GETFD) >= 0 &&
                                   fcntl(foreign_saved, F_GETFD) >= 0 &&
                                   self_kcmp(foreign_slot, foreign_saved);
    close(foreign_slot);
    close(foreign_saved);
    return check(evidence->destructor && !evidence->reportable_success && majority_closed,
                 "destructor did not close only exact original majority") &&
           check(foreign_preserved, "destructor closed same-inode foreign slot") &&
           same_snapshot(baseline, "majority destructor final residue");
}

bool destructor_cleared_observation_test() {
    PrivateDirectory directory;
    std::vector<int> baseline;
    if (!check(directory.create() && directory.executable(), "CLOEXEC destructor setup") ||
        !check(fd_snapshot(baseline), "CLOEXEC destructor baseline"))
        return false;
    std::shared_ptr<const executable::CleanupState> evidence;
    {
        executable::ExecutableLease lease;
        executable::Diagnostic diagnostic;
        if (!check(
                executable::ExecutableLease::create(directory.child("program"), lease, diagnostic),
                "CLOEXEC destructor create") ||
            !check(fcntl(lease.observation_fd(), F_SETFD, 0) == 0, "CLOEXEC destructor mutation") ||
            !check(!lease.revalidate(diagnostic) &&
                       diagnostic.phase == executable::FailurePhase::Identity,
                   "CLOEXEC destructor semantic rejection"))
            return false;
        evidence = lease.cleanup_state();
    }
    return check(!evidence->semantic_validation.succeeded &&
                     evidence->custody_validation.succeeded && evidence->observation.succeeded &&
                     evidence->authority_one.succeeded && evidence->authority_two.succeeded,
                 "destructor overwrote semantics or refused exact CLOEXEC-drift custody") &&
           same_snapshot(baseline, "CLOEXEC destructor residue");
}

bool destructor_no_proof_test(bool independent_no_majority) {
    PrivateDirectory directory;
    std::vector<int> baseline;
    if (!check(directory.create() && directory.executable(), "no-proof destructor setup") ||
        !check(fd_snapshot(baseline), "no-proof destructor baseline"))
        return false;
    std::shared_ptr<const executable::CleanupState> evidence;
    std::array<int, 3> preserved{-1, -1, -1};
    int anchor = -1;
    KcmpInjection injection{EPERM, false};
    {
        executable::ExecutableLease lease;
        executable::Diagnostic diagnostic;
        const executable::HooksForTesting hooks{
            denied_kcmp, nullptr, nullptr, &injection, executable::CreationFailurePoint::None};
        if (!check(executable::ExecutableLease::create_with_hooks_for_testing(
                       directory.child("program"), hooks, lease, diagnostic),
                   "no-proof destructor create"))
            return false;
        std::array<int, 2> authorities{-1, -1};
        std::vector<int> active;
        if (!check(new_owned_fds(baseline, lease.observation_fd(), authorities, active),
                   "no-proof destructor discovery"))
            return false;
        preserved = {lease.observation_fd(), authorities[0], authorities[1]};
        if (independent_no_majority) {
            anchor = fcntl(preserved[0], F_DUPFD_CLOEXEC, 0);
            if (!check(anchor >= 0, "independent no-majority anchor")) return false;
            for (const int slot : preserved) {
                const std::string path = "/proc/self/fd/" + std::to_string(anchor);
                const int replacement = open(path.c_str(), O_PATH | O_CLOEXEC);
                if (!check(replacement >= 0 && dup2(replacement, slot) == slot &&
                               fcntl(slot, F_SETFD, FD_CLOEXEC) == 0 && close(replacement) == 0,
                           "independent no-majority replacement"))
                    return false;
            }
        } else {
            injection.enabled = true;
        }
        evidence = lease.cleanup_state();
    }
    bool all_preserved = true;
    for (const int descriptor : preserved)
        all_preserved = all_preserved && fcntl(descriptor, F_GETFD) >= 0;
    const bool none_closed =
        !evidence->custody_validation.succeeded && !evidence->observation.attempted &&
        !evidence->authority_one.attempted && !evidence->authority_two.attempted;
    for (const int descriptor : preserved) close(descriptor);
    if (anchor >= 0) close(anchor);
    return check(evidence->destructor && none_closed && all_preserved,
                 "no-proof destructor guessed custody or made false residue claim") &&
           same_snapshot(baseline, "no-proof destructor final residue");
}

bool destructor_excluded_two_replacement_limit_test() {
    PrivateDirectory directory;
    std::vector<int> baseline;
    if (!check(directory.create() && directory.executable(), "excluded majority setup") ||
        !check(fd_snapshot(baseline), "excluded majority baseline"))
        return false;
    std::shared_ptr<const executable::CleanupState> evidence;
    std::array<int, 3> slots{-1, -1, -1};
    int original_anchor = -1;
    int foreign_witness = -1;
    {
        executable::ExecutableLease lease;
        executable::Diagnostic diagnostic;
        if (!check(
                executable::ExecutableLease::create(directory.child("program"), lease, diagnostic),
                "excluded majority create"))
            return false;
        std::array<int, 2> authorities{-1, -1};
        std::vector<int> active;
        if (!check(new_owned_fds(baseline, lease.observation_fd(), authorities, active),
                   "excluded majority discovery"))
            return false;
        slots = {lease.observation_fd(), authorities[0], authorities[1]};
        original_anchor = fcntl(slots[2], F_DUPFD_CLOEXEC, 0);
        const std::string path = "/proc/self/fd/" + std::to_string(original_anchor);
        const int new_ofd = original_anchor >= 0 ? open(path.c_str(), O_PATH | O_CLOEXEC) : -1;
        foreign_witness = new_ofd >= 0 ? fcntl(new_ofd, F_DUPFD_CLOEXEC, 0) : -1;
        if (!check(original_anchor >= 0 && new_ofd >= 0 && foreign_witness >= 0 &&
                       dup2(new_ofd, slots[0]) == slots[0] && dup2(new_ofd, slots[1]) == slots[1] &&
                       fcntl(slots[0], F_SETFD, FD_CLOEXEC) == 0 &&
                       fcntl(slots[1], F_SETFD, FD_CLOEXEC) == 0 && self_kcmp(slots[0], slots[1]) &&
                       !self_kcmp(slots[0], slots[2]) && close(new_ofd) == 0,
                   "excluded coordinated replacement"))
            return false;
        evidence = lease.cleanup_state();
    }
    errno = 0;
    const int first_flags = fcntl(slots[0], F_GETFD);
    const int first_error = errno;
    errno = 0;
    const int second_flags = fcntl(slots[1], F_GETFD);
    const int second_error = errno;
    const bool foreign_majority_closed =
        first_flags < 0 && first_error == EBADF && second_flags < 0 && second_error == EBADF &&
        evidence->observation.attempted && evidence->observation.succeeded &&
        evidence->authority_one.attempted && evidence->authority_one.succeeded;
    const bool original_minority_preserved =
        fcntl(slots[2], F_GETFD) >= 0 && fcntl(original_anchor, F_GETFD) >= 0 &&
        self_kcmp(slots[2], original_anchor) && !evidence->authority_two.attempted &&
        evidence->authority_two.error_number == EXDEV;
    const bool witness_preserved = fcntl(foreign_witness, F_GETFD) >= 0;
    close(slots[2]);
    close(original_anchor);
    close(foreign_witness);
    return check(evidence->destructor && evidence->custody_validation.succeeded &&
                     foreign_majority_closed && original_minority_preserved && witness_preserved,
                 "excluded two-slot false-majority limitation was not demonstrated exactly") &&
           same_snapshot(baseline, "excluded majority final residue");
}

}  // namespace

int main() {
    bool okay = true;
    okay = failed_mkdtemp_cleanup_test() && okay;
    okay = canonical_custody_test() && okay;
    okay = argument_and_policy_rejection_test() && okay;
    okay = pathname_replacement_test() && okay;
    okay = observation_mutation_test(false) && okay;
    okay = observation_mutation_test(true) && okay;
    okay = cloexec_recovery_test() && okay;
    okay = create_failure_cleanup_test() && okay;
    okay = creation_close_uncertainty_test() && okay;
    okay = metadata_and_link_test() && okay;
    okay = uncertain_close_test() && okay;
    okay = destructor_close_uncertainty_test() && okay;
    for (std::size_t slot = 0u; slot < 3u; ++slot) {
        okay = slot_mutation_test(slot, SlotMutation::DifferentInode) && okay;
        okay = slot_mutation_test(slot, SlotMutation::SameInodeNewOfd) && okay;
        okay = slot_mutation_test(slot, SlotMutation::ClearCloexec) && okay;
    }
    okay = canonical_destructor_test() && okay;
    okay = destructor_single_replacement_test(0u) && okay;
    okay = destructor_single_replacement_test(1u) && okay;
    okay = destructor_single_replacement_test(2u) && okay;
    okay = destructor_cleared_observation_test() && okay;
    okay = destructor_no_proof_test(false) && okay;
    okay = destructor_no_proof_test(true) && okay;
    okay = destructor_excluded_two_replacement_limit_test() && okay;
    if (okay) std::puts("PASS: executable lease custody and cleanup tests");
    return okay ? 0 : 1;
}
