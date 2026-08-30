#include "fixture_executable_lease.h"
#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <cstdio>
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
    std::array<char, 96> path{};
    int descriptor = -1;

    bool create() {
        std::snprintf(path.data(), path.size(), "/tmp/rut377-executable-XXXXXX");
        if (mkdtemp(path.data()) == nullptr) return false;
        descriptor = open(path.data(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        return descriptor >= 0 && fchmod(descriptor, 0700) == 0;
    }

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
        if (path[0] != '\0' && rmdir(path.data()) != 0)
            std::fprintf(stderr, "FAIL: temporary directory cleanup errno=%d\n", errno);
    }
};

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
                   int& authority,
                   std::vector<int>& current) {
    if (!fd_snapshot(current)) return false;
    std::vector<int> added;
    std::set_difference(current.begin(),
                        current.end(),
                        baseline.begin(),
                        baseline.end(),
                        std::back_inserter(added));
    if (added.size() != 2u || std::find(added.begin(), added.end(), observation) == added.end())
        return false;
    authority = added[0] == observation ? added[1] : added[0];
    return true;
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
    int authority = -1;
    std::vector<int> active;
    struct stat status{};
    const int observation_flags = fcntl(lease.observation_fd(), F_GETFD);
    const int observation_status = fcntl(lease.observation_fd(), F_GETFL);
    const bool identity = fstat(lease.observation_fd(), &status) == 0;
    const auto evidence = lease.cleanup_state();
    const bool okay =
        check(lease.active() && new_owned_fds(baseline, lease.observation_fd(), authority, active),
              "canonical exact two-FD custody") &&
        check(observation_flags >= 0 && (observation_flags & FD_CLOEXEC) != 0 &&
                  observation_status >= 0 && (observation_status & O_PATH) == O_PATH,
              "canonical observation flags") &&
        check(fcntl(authority, F_GETFD) >= 0 && (fcntl(authority, F_GETFD) & FD_CLOEXEC) != 0 &&
                  self_kcmp(lease.observation_fd(), authority),
              "canonical private authority exact OFD") &&
        check(identity && lease.identity().device == static_cast<std::uint64_t>(status.st_dev) &&
                  lease.identity().inode == static_cast<std::uint64_t>(status.st_ino) &&
                  lease.identity().mode == static_cast<std::uint64_t>(status.st_mode) &&
                  lease.identity().uid == static_cast<std::uint64_t>(status.st_uid) &&
                  lease.identity().gid == static_cast<std::uint64_t>(status.st_gid),
              "canonical stored identity") &&
        check(lease.revalidate(diagnostic), "canonical revalidate") &&
        check(lease.close(diagnostic), "canonical close") &&
        check(!lease.active() && evidence->validation_succeeded &&
                  evidence->observation.attempted && evidence->observation.succeeded &&
                  evidence->authority.attempted && evidence->authority.succeeded &&
                  evidence->reportable_success,
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
    const bool rejected =
        !lease.revalidate(diagnostic) && diagnostic.phase == executable::FailurePhase::Path;
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
    int authority = -1;
    std::vector<int> active;
    if (!check(new_owned_fds(baseline, lease.observation_fd(), authority, active),
               "observation authority discovery"))
        return false;
    const int slot = lease.observation_fd();
    const int saved = fcntl(slot, F_DUPFD_CLOEXEC, 0);
    const std::string replacement_path = same_inode_new_ofd
                                             ? "/proc/self/fd/" + std::to_string(authority)
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
};

int denied_kcmp(int, int, void* context) {
    const auto* injection = static_cast<const KcmpInjection*>(context);
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
             executable::CreationFailurePoint::AfterDuplicate,
             executable::CreationFailurePoint::IdentityValidation,
         }) {
        executable::ExecutableLease lease;
        executable::Diagnostic diagnostic;
        CloseInjection close_injection;
        const executable::HooksForTesting hooks{
            nullptr, real_close_then_error, &close_injection, point};
        const bool created = executable::ExecutableLease::create_with_hooks_for_testing(
            directory.child("program"), hooks, lease, diagnostic);
        const unsigned expected = point == executable::CreationFailurePoint::AfterOpen ? 1u : 2u;
        const auto evidence = lease.cleanup_state();
        const bool terminal_reuse =
            !executable::ExecutableLease::create(directory.child("program"), lease, diagnostic) &&
            diagnostic.phase == executable::FailurePhase::Argument;
        okay =
            check(!created && !lease.active() && close_injection.calls == expected &&
                      evidence->observation.attempts == 1u &&
                      evidence->authority.attempts == (expected == 2u ? 1u : 0u) && terminal_reuse,
                  "creation failure cleanup was not exact") &&
            okay;
        okay = same_snapshot(baseline, "creation failure FD residue") && okay;
    }
    for (const int denied : {ENOSYS, EPERM}) {
        executable::ExecutableLease lease;
        executable::Diagnostic diagnostic;
        KcmpInjection injection{denied};
        const executable::HooksForTesting hooks{
            denied_kcmp, nullptr, &injection, executable::CreationFailurePoint::None};
        const bool created = executable::ExecutableLease::create_with_hooks_for_testing(
            directory.child("program"), hooks, lease, diagnostic);
        okay = check(!created && diagnostic.phase == executable::FailurePhase::Kcmp &&
                         diagnostic.error_number == denied && !lease.active() &&
                         lease.cleanup_state()->observation.attempts == 1u &&
                         lease.cleanup_state()->authority.attempts == 1u,
                     "kcmp denial did not fail closed with exact cleanup") &&
               okay;
        okay = same_snapshot(baseline, "kcmp denial FD residue") && okay;
    }
    return okay;
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
    const bool closed = lease.close(diagnostic);
    if (!check(link_added && link_removed && initial_identity_retained,
               "hard-link transition rejected or rewrote initial identity") ||
        !check(drift_rejected, "metadata drift accepted") ||
        !check(closed, "metadata drift prevented ownership cleanup"))
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
        if (!check(!content.revalidate(diagnostic) &&
                       diagnostic.phase == executable::FailurePhase::Identity,
                   "content drift accepted"))
            return false;
        // Destructor must use custody, not semantic metadata, for cleanup.
    }
    return check(destructor_evidence->destructor && destructor_evidence->observation.succeeded &&
                     destructor_evidence->authority.succeeded &&
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
    const executable::HooksForTesting hooks{
        nullptr, real_close_then_error, &injection, executable::CreationFailurePoint::None};
    if (!check(executable::ExecutableLease::create_with_hooks_for_testing(
                   directory.child("program"), hooks, lease, diagnostic),
               "uncertain close create"))
        return false;
    const auto evidence = lease.cleanup_state();
    const bool closed = lease.close(diagnostic);
    const bool observation_failed = fail_call == 1u;
    return check(!closed && !lease.active() &&
                     diagnostic.phase == executable::FailurePhase::Close &&
                     diagnostic.error_number == failure && injection.calls == 2u,
                 "uncertain close did not attempt both exactly once") &&
           check(evidence->observation.attempts == 1u &&
                     evidence->observation.succeeded != observation_failed &&
                     evidence->observation.error_number == (observation_failed ? failure : 0) &&
                     evidence->authority.attempts == 1u &&
                     evidence->authority.succeeded == observation_failed &&
                     evidence->authority.error_number == (observation_failed ? 0 : failure) &&
                     !evidence->reportable_success,
                 "uncertain close outcomes were not independent") &&
           same_snapshot(baseline, "uncertain close retried or leaked FD");
}

bool uncertain_close_test() {
    return uncertain_close_case(1u, EINTR) && uncertain_close_case(2u, EIO);
}

bool destructor_test(bool foreign_observation) {
    PrivateDirectory directory;
    std::vector<int> baseline;
    if (!check(directory.create() && directory.executable() && directory.executable("other"),
               "destructor setup") ||
        !check(fd_snapshot(baseline), "destructor baseline"))
        return false;
    std::shared_ptr<const executable::CleanupState> evidence;
    int foreign_slot = -1;
    int foreign_saved = -1;
    {
        executable::ExecutableLease lease;
        executable::Diagnostic diagnostic;
        if (!check(
                executable::ExecutableLease::create(directory.child("program"), lease, diagnostic),
                "destructor create"))
            return false;
        evidence = lease.cleanup_state();
        if (foreign_observation) {
            foreign_slot = lease.observation_fd();
            const int replacement = open(directory.child("other").c_str(), O_PATH | O_CLOEXEC);
            foreign_saved = fcntl(replacement, F_DUPFD_CLOEXEC, 0);
            if (!check(replacement >= 0 && foreign_saved >= 0 &&
                           dup2(replacement, foreign_slot) == foreign_slot &&
                           fcntl(foreign_slot, F_SETFD, FD_CLOEXEC) == 0,
                       "destructor foreign replacement"))
                return false;
            close(replacement);
        }
    }
    if (!check(evidence && evidence->destructor && !evidence->reportable_success,
               "destructor claimed reportable success"))
        return false;
    if (!foreign_observation)
        return check(evidence->observation.succeeded && evidence->authority.succeeded,
                     "canonical destructor did not settle both owned FDs") &&
               same_snapshot(baseline, "canonical destructor residue");
    const bool foreign_preserved = fcntl(foreign_slot, F_GETFD) >= 0 &&
                                   fcntl(foreign_saved, F_GETFD) >= 0 &&
                                   self_kcmp(foreign_slot, foreign_saved);
    const bool authority_settled = !evidence->observation.attempted &&
                                   evidence->authority.attempted && evidence->authority.succeeded;
    close(foreign_slot);
    close(foreign_saved);
    return check(foreign_preserved, "destructor closed foreign observation") &&
           check(authority_settled, "destructor did not safely settle private authority") &&
           same_snapshot(baseline, "foreign destructor final residue");
}

}  // namespace

int main() {
    bool okay = true;
    okay = canonical_custody_test() && okay;
    okay = argument_and_policy_rejection_test() && okay;
    okay = pathname_replacement_test() && okay;
    okay = observation_mutation_test(false) && okay;
    okay = observation_mutation_test(true) && okay;
    okay = cloexec_recovery_test() && okay;
    okay = create_failure_cleanup_test() && okay;
    okay = metadata_and_link_test() && okay;
    okay = uncertain_close_test() && okay;
    okay = destructor_test(false) && okay;
    okay = destructor_test(true) && okay;
    if (okay) std::puts("PASS: executable lease custody and cleanup tests");
    return okay ? 0 : 1;
}
