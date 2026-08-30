#include "fixture_executable_lease.h"

#include <array>
#include <cerrno>
#include <cstdio>
#include <cstdlib>

#include <fcntl.h>
#include <linux/kcmp.h>
#include <linux/limits.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

namespace rut::test::fixture_executable_lease {
namespace {

void fail(Diagnostic& diagnostic, FailurePhase phase, int error_number = 0) {
    diagnostic = {phase, error_number == 0 ? EINVAL : error_number};
}

ExecutableIdentity make_identity(const struct stat& status) {
    return {static_cast<std::uint64_t>(status.st_dev),
            static_cast<std::uint64_t>(status.st_ino),
            static_cast<std::uint64_t>(status.st_mode),
            static_cast<std::uint64_t>(status.st_uid),
            static_cast<std::uint64_t>(status.st_gid),
            static_cast<std::uint64_t>(status.st_size),
            static_cast<std::int64_t>(status.st_mtim.tv_sec),
            static_cast<std::int64_t>(status.st_mtim.tv_nsec),
            static_cast<std::int64_t>(status.st_ctim.tv_sec),
            static_cast<std::int64_t>(status.st_ctim.tv_nsec)};
}

bool same_object(const struct stat& status, const ExecutableIdentity& expected) {
    return S_ISREG(status.st_mode) && status.st_dev != 0 && status.st_ino != 0 &&
           static_cast<std::uint64_t>(status.st_dev) == expected.device &&
           static_cast<std::uint64_t>(status.st_ino) == expected.inode;
}

bool same_metadata_except_ctime(const struct stat& status, const ExecutableIdentity& expected) {
    return same_object(status, expected) && status.st_size >= 0 &&
           static_cast<std::uint64_t>(status.st_mode) == expected.mode &&
           static_cast<std::uint64_t>(status.st_uid) == expected.uid &&
           static_cast<std::uint64_t>(status.st_gid) == expected.gid &&
           static_cast<std::uint64_t>(status.st_size) == expected.size &&
           static_cast<std::int64_t>(status.st_mtim.tv_sec) == expected.mtime_seconds &&
           static_cast<std::int64_t>(status.st_mtim.tv_nsec) == expected.mtime_nanoseconds;
}

bool same_current_ctime(const struct stat& first, const struct stat& second) {
    return first.st_ctim.tv_sec == second.st_ctim.tv_sec &&
           first.st_ctim.tv_nsec == second.st_ctim.tv_nsec;
}

bool descriptor_flags(int descriptor, bool require_cloexec, int& error_number) {
    errno = 0;
    const int descriptor_flags = fcntl(descriptor, F_GETFD);
    if (descriptor_flags < 0) {
        error_number = errno == 0 ? EIO : errno;
        return false;
    }
    errno = 0;
    const int status_flags = fcntl(descriptor, F_GETFL);
    if (status_flags < 0) {
        error_number = errno == 0 ? EIO : errno;
        return false;
    }
    if ((require_cloexec && (descriptor_flags & FD_CLOEXEC) == 0) ||
        (status_flags & O_PATH) != O_PATH) {
        error_number = EINVAL;
        return false;
    }
    error_number = 0;
    return true;
}

int ordinary_kcmp(int first, int second, void*) {
#ifdef SYS_kcmp
    return static_cast<int>(syscall(SYS_kcmp, getpid(), getpid(), KCMP_FILE, first, second));
#else
    (void)first;
    (void)second;
    errno = ENOSYS;
    return -1;
#endif
}

int ordinary_close(int descriptor, void*) {
    return ::close(descriptor);
}

int ordinary_access(int descriptor, void*) {
#ifdef SYS_faccessat2
    return static_cast<int>(
        syscall(SYS_faccessat2, descriptor, "", X_OK, AT_EMPTY_PATH | AT_EACCESS));
#else
    (void)descriptor;
    errno = ENOSYS;
    return -1;
#endif
}

}  // namespace

ExecutableLease::ExecutableLease() : cleanup_state_(std::make_shared<CleanupState>()) {}

ExecutableLease::~ExecutableLease() {
    if (!active_) return;
    Diagnostic diagnostic;
    (void)close_active(true, diagnostic);
    if (cleanup_state_) {
        cleanup_state_->destructor = true;
        cleanup_state_->reportable_success = false;
        cleanup_state_->diagnostic = diagnostic.phase == FailurePhase::None
                                         ? Diagnostic{FailurePhase::Cleanup, ECANCELED}
                                         : diagnostic;
    }
    if (diagnostic.phase != FailurePhase::None && diagnostic.error_number != ECANCELED &&
        cleanup_state_.use_count() == 1) {
        std::fprintf(stderr,
                     "FAIL [#377 executable lease destructor]: phase=%u errno=%d\n",
                     static_cast<unsigned>(diagnostic.phase),
                     diagnostic.error_number);
    }
}

bool ExecutableLease::create(const std::string& canonical_absolute_path,
                             ExecutableLease& lease,
                             Diagnostic& diagnostic) {
    return create_impl(canonical_absolute_path, nullptr, lease, diagnostic);
}

bool ExecutableLease::create_with_hooks_for_testing(const std::string& canonical_absolute_path,
                                                    const HooksForTesting& hooks,
                                                    ExecutableLease& lease,
                                                    Diagnostic& diagnostic) {
    return create_impl(canonical_absolute_path, &hooks, lease, diagnostic);
}

bool ExecutableLease::create_impl(const std::string& canonical_absolute_path,
                                  const HooksForTesting* hooks,
                                  ExecutableLease& lease,
                                  Diagnostic& diagnostic) {
    diagnostic = {};
    if (lease.active_ || lease.terminal_ || lease.observation_fd_ >= 0 ||
        lease.authority_one_fd_ >= 0 || lease.authority_two_fd_ >= 0 ||
        canonical_absolute_path.empty() || canonical_absolute_path.front() != '/' ||
        canonical_absolute_path.find('\0') != std::string::npos ||
        canonical_absolute_path.size() >= PATH_MAX) {
        fail(diagnostic, FailurePhase::Argument, EINVAL);
        return false;
    }
    std::array<char, PATH_MAX> resolved{};
    errno = 0;
    char* const canonical = realpath(canonical_absolute_path.c_str(), resolved.data());
    if (canonical == nullptr) {
        fail(diagnostic, FailurePhase::Canonical, errno == 0 ? EIO : errno);
        return false;
    }
    if (canonical_absolute_path != canonical) {
        fail(diagnostic, FailurePhase::Canonical, EINVAL);
        return false;
    }

#ifdef O_PATH
    const int opened = open(canonical_absolute_path.c_str(), O_PATH | O_CLOEXEC | O_NOFOLLOW);
#else
    const int opened = -1;
    errno = ENOTSUP;
#endif
    if (opened < 0) {
        fail(diagnostic, FailurePhase::Open, errno == 0 ? EIO : errno);
        return false;
    }
    // Any acquired FD makes this object single-use even if creation fails.
    lease.observation_fd_ = opened;
    lease.active_ = true;
    lease.terminal_ = false;
    lease.path_ = canonical_absolute_path;
    lease.cleanup_state_ = std::make_shared<CleanupState>();
    lease.kcmp_for_testing_ = hooks == nullptr ? nullptr : hooks->kcmp;
    lease.close_for_testing_ = hooks == nullptr ? nullptr : hooks->close;
    lease.access_for_testing_ = hooks == nullptr ? nullptr : hooks->access;
    lease.hook_context_ = hooks == nullptr ? nullptr : hooks->context;
    const CreationFailurePoint failure_point =
        hooks == nullptr ? CreationFailurePoint::None : hooks->creation_failure;
    if (failure_point == CreationFailurePoint::AfterOpen)
        return lease.fail_after_acquire({FailurePhase::Open, EIO}, diagnostic);

    lease.authority_one_fd_ = fcntl(lease.observation_fd_, F_DUPFD_CLOEXEC, STDERR_FILENO + 1);
    if (lease.authority_one_fd_ < 0)
        return lease.fail_after_acquire({FailurePhase::Duplicate, errno == 0 ? EIO : errno},
                                        diagnostic);
    if (failure_point == CreationFailurePoint::AfterFirstDuplicate)
        return lease.fail_after_acquire({FailurePhase::Duplicate, EIO}, diagnostic);
    lease.authority_two_fd_ = fcntl(lease.observation_fd_, F_DUPFD_CLOEXEC, STDERR_FILENO + 1);
    if (lease.authority_two_fd_ < 0)
        return lease.fail_after_acquire({FailurePhase::Duplicate, errno == 0 ? EIO : errno},
                                        diagnostic);
    if (failure_point == CreationFailurePoint::AfterDuplicate)
        return lease.fail_after_acquire({FailurePhase::Duplicate, EIO}, diagnostic);

    struct stat status{};
    if (failure_point == CreationFailurePoint::IdentityValidation)
        return lease.fail_after_acquire({FailurePhase::Identity, EIO}, diagnostic);
    errno = 0;
    if (fstat(lease.observation_fd_, &status) != 0)
        return lease.fail_after_acquire({FailurePhase::Identity, errno == 0 ? EIO : errno},
                                        diagnostic);
    if (!S_ISREG(status.st_mode) || status.st_dev == 0 || status.st_ino == 0 || status.st_size < 0)
        return lease.fail_after_acquire({FailurePhase::Identity, EINVAL}, diagnostic);
    lease.identity_ = make_identity(status);

    if (!lease.revalidate(diagnostic)) {
        const Diagnostic original = diagnostic;
        return lease.fail_after_acquire(original, diagnostic);
    }
    return true;
}

bool ExecutableLease::validate_policy(int descriptor, Diagnostic& diagnostic) const {
    struct stat status{};
    errno = 0;
    if (fstat(descriptor, &status) != 0) {
        fail(diagnostic, FailurePhase::Policy, errno == 0 ? EIO : errno);
        return false;
    }
    if (!S_ISREG(status.st_mode) || status.st_uid != geteuid() || (status.st_mode & S_IXUSR) == 0 ||
        (status.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
        fail(diagnostic, FailurePhase::Policy, EACCES);
        return false;
    }
    const AccessForTesting operation =
        access_for_testing_ == nullptr ? ordinary_access : access_for_testing_;
    errno = 0;
    if (operation(descriptor, hook_context_) != 0) {
        fail(diagnostic, FailurePhase::Policy, errno == 0 ? EIO : errno);
        return false;
    }
    return true;
}

bool ExecutableLease::validate_descriptor(int descriptor,
                                          bool require_metadata,
                                          Diagnostic& diagnostic) const {
    int flag_error = 0;
    if (descriptor < 0 || !descriptor_flags(descriptor, true, flag_error)) {
        fail(diagnostic,
             FailurePhase::Identity,
             descriptor < 0 ? EBADF : (flag_error == 0 ? EINVAL : flag_error));
        return false;
    }
    struct stat status{};
    errno = 0;
    if (fstat(descriptor, &status) != 0) {
        fail(diagnostic, FailurePhase::Identity, errno == 0 ? EIO : errno);
        return false;
    }
    if (!same_object(status, identity_)) {
        fail(diagnostic, FailurePhase::Identity, EINVAL);
        return false;
    }
    if (require_metadata && !same_metadata_except_ctime(status, identity_)) {
        fail(diagnostic, FailurePhase::Identity, EINVAL);
        return false;
    }
    if (require_metadata && !validate_policy(descriptor, diagnostic)) return false;
    return true;
}

bool ExecutableLease::same_open_file_description(int first,
                                                 int second,
                                                 Diagnostic& diagnostic) const {
    errno = 0;
    const KcmpForTesting compare = kcmp_for_testing_ == nullptr ? ordinary_kcmp : kcmp_for_testing_;
    const int result = compare(first, second, hook_context_);
    if (result == 0) return true;
    fail(diagnostic, FailurePhase::Kcmp, result > 0 ? EXDEV : (errno == 0 ? EIO : errno));
    return false;
}

void ExecutableLease::record_semantic_validation(bool succeeded,
                                                 const Diagnostic& diagnostic) const {
    if (!cleanup_state_) return;
    ++cleanup_state_->semantic_validation.attempts;
    cleanup_state_->semantic_validation.succeeded = succeeded;
    cleanup_state_->semantic_validation.diagnostic = diagnostic;
}

void ExecutableLease::record_custody_validation(bool succeeded,
                                                const Diagnostic& diagnostic) const {
    if (!cleanup_state_) return;
    ++cleanup_state_->custody_validation.attempts;
    cleanup_state_->custody_validation.succeeded = succeeded;
    cleanup_state_->custody_validation.diagnostic = diagnostic;
}

bool ExecutableLease::validate_custody(Diagnostic& diagnostic) const {
    diagnostic = {};
    if (!active_ || terminal_ || observation_fd_ < 0 || authority_one_fd_ < 0 ||
        authority_two_fd_ < 0) {
        fail(diagnostic, FailurePhase::Argument, active_ ? EBADF : EALREADY);
        return false;
    }
    if (!validate_descriptor(observation_fd_, false, diagnostic) ||
        !validate_descriptor(authority_one_fd_, false, diagnostic) ||
        !validate_descriptor(authority_two_fd_, false, diagnostic) ||
        !same_open_file_description(observation_fd_, authority_one_fd_, diagnostic) ||
        !same_open_file_description(observation_fd_, authority_two_fd_, diagnostic) ||
        !same_open_file_description(authority_one_fd_, authority_two_fd_, diagnostic))
        return false;
    return true;
}

bool ExecutableLease::authorize_cleanup(bool require_cloexec,
                                        std::array<bool, 3>& original_members,
                                        Diagnostic& diagnostic) const {
    // This finite majority is defensive only under the documented at-most-one
    // slot-replacement boundary. Two coordinated foreign slots sharing one new
    // OFD are indistinguishable from an original majority and are out of scope.
    original_members = {};
    diagnostic = {};
    const std::array<int, 3> descriptors = {observation_fd_, authority_one_fd_, authority_two_fd_};
    std::array<bool, 3> candidates{};
    for (std::size_t index = 0; index < descriptors.size(); ++index) {
        int flag_error = 0;
        if (descriptors[index] < 0 ||
            !descriptor_flags(descriptors[index], require_cloexec, flag_error)) {
            if (require_cloexec) {
                fail(diagnostic,
                     FailurePhase::Identity,
                     descriptors[index] < 0 ? EBADF : flag_error);
                return false;
            }
            continue;
        }
        struct stat status{};
        errno = 0;
        if (fstat(descriptors[index], &status) != 0) continue;
        candidates[index] = same_object(status, identity_);
    }

    enum class Relation : std::uint8_t { Unknown, Different, Same };
    std::array<std::array<Relation, 3>, 3> relations{};
    unsigned same_edges = 0u;
    int comparison_error = 0;
    bool any_different = false;
    for (std::size_t first = 0; first < descriptors.size(); ++first) {
        for (std::size_t second = first + 1u; second < descriptors.size(); ++second) {
            if (!candidates[first] || !candidates[second]) {
                relations[first][second] = Relation::Different;
                any_different = true;
                continue;
            }
            errno = 0;
            const KcmpForTesting compare =
                kcmp_for_testing_ == nullptr ? ordinary_kcmp : kcmp_for_testing_;
            const int result = compare(descriptors[first], descriptors[second], hook_context_);
            if (result == 0) {
                relations[first][second] = Relation::Same;
                ++same_edges;
            } else if (result > 0) {
                relations[first][second] = Relation::Different;
                any_different = true;
            } else {
                relations[first][second] = Relation::Unknown;
                if (comparison_error == 0) comparison_error = errno == 0 ? EIO : errno;
            }
        }
    }
    if (same_edges == 0u) {
        fail(diagnostic,
             FailurePhase::Kcmp,
             comparison_error != 0 ? comparison_error : (any_different ? EXDEV : EIO));
        return false;
    }
    for (std::size_t first = 0; first < descriptors.size(); ++first)
        for (std::size_t second = first + 1u; second < descriptors.size(); ++second)
            if (relations[first][second] == Relation::Same) {
                original_members[first] = true;
                original_members[second] = true;
            }
    const unsigned member_count = static_cast<unsigned>(original_members[0]) +
                                  static_cast<unsigned>(original_members[1]) +
                                  static_cast<unsigned>(original_members[2]);
    if (member_count < 2u) {
        fail(diagnostic, FailurePhase::Kcmp, EINVAL);
        original_members = {};
        return false;
    }
    return true;
}

bool ExecutableLease::revalidate(Diagnostic& diagnostic) const {
    diagnostic = {};
    if (!validate_custody(diagnostic)) {
        record_semantic_validation(false, diagnostic);
        return false;
    }
    struct stat observation{};
    struct stat authority_one{};
    struct stat authority_two{};
    struct stat path_status{};
    errno = 0;
    if (fstat(observation_fd_, &observation) != 0 ||
        fstat(authority_one_fd_, &authority_one) != 0 ||
        fstat(authority_two_fd_, &authority_two) != 0) {
        fail(diagnostic, FailurePhase::Identity, errno == 0 ? EIO : errno);
        record_semantic_validation(false, diagnostic);
        return false;
    }
    if (!same_metadata_except_ctime(observation, identity_) ||
        !same_metadata_except_ctime(authority_one, identity_) ||
        !same_metadata_except_ctime(authority_two, identity_) ||
        !same_current_ctime(observation, authority_one) ||
        !same_current_ctime(observation, authority_two)) {
        fail(diagnostic, FailurePhase::Identity, EINVAL);
        record_semantic_validation(false, diagnostic);
        return false;
    }
    errno = 0;
    if (lstat(path_.c_str(), &path_status) != 0 || !same_object(path_status, identity_) ||
        !same_metadata_except_ctime(path_status, identity_) ||
        !same_current_ctime(path_status, observation)) {
        fail(diagnostic, FailurePhase::Path, errno == 0 ? EINVAL : errno);
        record_semantic_validation(false, diagnostic);
        return false;
    }
    // Initial ctime remains diagnostic evidence only. nlink is deliberately
    // not invariant, so revalidation requires merely that the current path and
    // all three exact-OFD members agree on current ctime. This does not detect
    // an excluded same-size/mtime-restored content or ACL mutation.
    if (!validate_policy(observation_fd_, diagnostic) ||
        !validate_policy(authority_one_fd_, diagnostic) ||
        !validate_policy(authority_two_fd_, diagnostic)) {
        record_semantic_validation(false, diagnostic);
        return false;
    }
    record_semantic_validation(true, diagnostic);
    return true;
}

bool ExecutableLease::close_one(int& descriptor, CloseOutcome& outcome, Diagnostic& diagnostic) {
    if (descriptor < 0) return true;
    const int closing = descriptor;
    descriptor = -1;  // Never retry an uncertain close against a reused slot.
    ++outcome.attempts;
    outcome.attempted = true;
    const CloseForTesting operation =
        close_for_testing_ == nullptr ? ordinary_close : close_for_testing_;
    errno = 0;
    if (operation(closing, hook_context_) == 0) {
        outcome.succeeded = true;
        outcome.error_number = 0;
        return true;
    }
    outcome.succeeded = false;
    outcome.error_number = errno == 0 ? EIO : errno;
    if (diagnostic.phase == FailurePhase::None)
        diagnostic = {FailurePhase::Close, outcome.error_number};
    return false;
}

bool ExecutableLease::close_active(bool destructor, Diagnostic& diagnostic) {
    diagnostic = {};
    if (!active_ || terminal_) {
        fail(diagnostic, FailurePhase::Close, EALREADY);
        return false;
    }
    Diagnostic custody;
    std::array<bool, 3> original_members{};
    bool authorized = authorize_cleanup(!destructor, original_members, custody);
    const bool every_member = original_members[0] && original_members[1] && original_members[2];
    if (authorized && !destructor && !every_member) {
        authorized = false;
        custody = {FailurePhase::Kcmp, EXDEV};
    }
    record_custody_validation(authorized, custody);
    if (!authorized && !destructor) {
        diagnostic = custody;
        if (cleanup_state_) cleanup_state_->diagnostic = diagnostic;
        return false;
    }

    bool success = true;
    if (authorized) {
        // Detach every field before the first close. Under the documented
        // at-most-one-slot-replacement boundary, a destructor closes only the
        // original exact-OFD majority and preserves the foreign numeric slot.
        std::array<int, 3> descriptors = {observation_fd_, authority_one_fd_, authority_two_fd_};
        observation_fd_ = -1;
        authority_one_fd_ = -1;
        authority_two_fd_ = -1;
        active_ = false;
        terminal_ = true;
        std::array<CloseOutcome*, 3> outcomes = {&cleanup_state_->observation,
                                                 &cleanup_state_->authority_one,
                                                 &cleanup_state_->authority_two};
        for (std::size_t index = 0; index < descriptors.size(); ++index) {
            if (original_members[index]) {
                if (!close_one(descriptors[index], *outcomes[index], diagnostic)) success = false;
            } else {
                outcomes[index]->error_number = EXDEV;
                success = false;
            }
        }
    } else {
        // No exact majority: preserve every unproven numeric slot. Destruction
        // cannot retry, but it must not guess based on flags or inode identity.
        cleanup_state_->observation.error_number = custody.error_number;
        cleanup_state_->authority_one.error_number = custody.error_number;
        cleanup_state_->authority_two.error_number = custody.error_number;
        observation_fd_ = -1;
        authority_one_fd_ = -1;
        authority_two_fd_ = -1;
        active_ = false;
        terminal_ = true;
        diagnostic = custody;
        success = false;
    }
    cleanup_state_->destructor = destructor;
    cleanup_state_->reportable_success = !destructor && success;
    cleanup_state_->diagnostic = destructor && diagnostic.phase == FailurePhase::None
                                     ? Diagnostic{FailurePhase::Cleanup, ECANCELED}
                                     : diagnostic;
    return !destructor && success;
}

bool ExecutableLease::close(Diagnostic& diagnostic) {
    return close_active(false, diagnostic);
}

bool ExecutableLease::fail_after_acquire(const Diagnostic& original, Diagnostic& diagnostic) {
    // These descriptors have not been returned to the caller. Creation owns
    // every acquired field unconditionally and settles each one exactly once.
    Diagnostic close_diagnostic;
    int observation = observation_fd_;
    int authority_one = authority_one_fd_;
    int authority_two = authority_two_fd_;
    observation_fd_ = -1;
    authority_one_fd_ = -1;
    authority_two_fd_ = -1;
    active_ = false;
    terminal_ = true;
    if (observation >= 0)
        (void)close_one(observation, cleanup_state_->observation, close_diagnostic);
    if (authority_one >= 0)
        (void)close_one(authority_one, cleanup_state_->authority_one, close_diagnostic);
    if (authority_two >= 0)
        (void)close_one(authority_two, cleanup_state_->authority_two, close_diagnostic);
    cleanup_state_->creation_cleanup = true;
    cleanup_state_->creation_diagnostic = original;
    diagnostic = original;
    if (cleanup_state_) cleanup_state_->diagnostic = original;
    return false;
}

}  // namespace rut::test::fixture_executable_lease
