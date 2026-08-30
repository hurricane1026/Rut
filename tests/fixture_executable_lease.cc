#include "fixture_executable_lease.h"

#include <array>
#include <cerrno>
#include <cstdio>
#include <limits>

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

bool same_ctime(const struct stat& status, std::int64_t seconds, std::int64_t nanoseconds) {
    return static_cast<std::int64_t>(status.st_ctim.tv_sec) == seconds &&
           static_cast<std::int64_t>(status.st_ctim.tv_nsec) == nanoseconds;
}

bool descriptor_flags(int descriptor, int& error_number) {
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
    if ((descriptor_flags & FD_CLOEXEC) == 0 || (status_flags & O_PATH) != O_PATH) {
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

bool effective_execute_access(int descriptor, int& error_number) {
#ifdef SYS_faccessat2
    errno = 0;
    const int result =
        static_cast<int>(syscall(SYS_faccessat2, descriptor, "", X_OK, AT_EMPTY_PATH | AT_EACCESS));
    if (result == 0) {
        error_number = 0;
        return true;
    }
    if (errno != ENOSYS) {
        error_number = errno == 0 ? EACCES : errno;
        return false;
    }
#else
    (void)descriptor;
#endif
    // Older Linux kernels have no FD-relative effective-ID access primitive.
    // The owner-execute/effective-owner policy remains enforced from fstat.
    error_number = 0;
    return true;
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
    if (diagnostic.phase != FailurePhase::None && diagnostic.error_number != ECANCELED) {
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
        lease.authority_fd_ >= 0 || canonical_absolute_path.empty() ||
        canonical_absolute_path.front() != '/' ||
        canonical_absolute_path.find('\0') != std::string::npos ||
        canonical_absolute_path.size() >= PATH_MAX) {
        fail(diagnostic, FailurePhase::Argument, EINVAL);
        return false;
    }
    std::array<char, PATH_MAX> resolved{};
    errno = 0;
    if (realpath(canonical_absolute_path.c_str(), resolved.data()) == nullptr ||
        canonical_absolute_path != resolved.data()) {
        fail(diagnostic, FailurePhase::Canonical, errno == 0 ? EINVAL : errno);
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
    lease.hook_context_ = hooks == nullptr ? nullptr : hooks->context;
    const CreationFailurePoint failure_point =
        hooks == nullptr ? CreationFailurePoint::None : hooks->creation_failure;
    if (failure_point == CreationFailurePoint::AfterOpen)
        return lease.fail_after_acquire({FailurePhase::Open, EIO}, diagnostic);

    lease.authority_fd_ = fcntl(lease.observation_fd_, F_DUPFD_CLOEXEC, STDERR_FILENO + 1);
    if (lease.authority_fd_ < 0)
        return lease.fail_after_acquire({FailurePhase::Duplicate, errno == 0 ? EIO : errno},
                                        diagnostic);
    if (failure_point == CreationFailurePoint::AfterDuplicate)
        return lease.fail_after_acquire({FailurePhase::Duplicate, EIO}, diagnostic);

    struct stat status{};
    if (failure_point == CreationFailurePoint::IdentityValidation ||
        fstat(lease.observation_fd_, &status) != 0 || !S_ISREG(status.st_mode) ||
        status.st_dev == 0 || status.st_ino == 0 || status.st_size < 0) {
        return lease.fail_after_acquire({FailurePhase::Identity,
                                         failure_point == CreationFailurePoint::IdentityValidation
                                             ? EIO
                                             : (errno == 0 ? EINVAL : errno)},
                                        diagnostic);
    }
    lease.identity_ = make_identity(status);
    lease.accepted_ctime_seconds_ = lease.identity_.ctime_seconds;
    lease.accepted_ctime_nanoseconds_ = lease.identity_.ctime_nanoseconds;

    if (!lease.revalidate(diagnostic)) {
        const Diagnostic original = diagnostic;
        return lease.fail_after_acquire(original, diagnostic);
    }
    return true;
}

bool ExecutableLease::validate_policy(int descriptor, Diagnostic& diagnostic) const {
    struct stat status{};
    if (fstat(descriptor, &status) != 0) {
        fail(diagnostic, FailurePhase::Policy, errno == 0 ? EIO : errno);
        return false;
    }
    if (!S_ISREG(status.st_mode) || status.st_uid != geteuid() || (status.st_mode & S_IXUSR) == 0 ||
        (status.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
        fail(diagnostic, FailurePhase::Policy, EACCES);
        return false;
    }
    int access_error = 0;
    if (!effective_execute_access(descriptor, access_error)) {
        fail(diagnostic, FailurePhase::Policy, access_error);
        return false;
    }
    return true;
}

bool ExecutableLease::validate_descriptor(int descriptor,
                                          bool require_metadata,
                                          Diagnostic& diagnostic) const {
    int flag_error = 0;
    if (descriptor < 0 || !descriptor_flags(descriptor, flag_error)) {
        fail(diagnostic,
             FailurePhase::Identity,
             descriptor < 0 ? EBADF : (flag_error == 0 ? EINVAL : flag_error));
        return false;
    }
    struct stat status{};
    if (fstat(descriptor, &status) != 0 || !same_object(status, identity_)) {
        fail(diagnostic, FailurePhase::Identity, errno == 0 ? EINVAL : errno);
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

void ExecutableLease::record_validation(bool succeeded, const Diagnostic& diagnostic) const {
    if (!cleanup_state_) return;
    ++cleanup_state_->validation_attempts;
    cleanup_state_->validation_succeeded = succeeded;
    cleanup_state_->validation_diagnostic = diagnostic;
}

bool ExecutableLease::validate_custody(Diagnostic& diagnostic) const {
    diagnostic = {};
    if (!active_ || terminal_ || observation_fd_ < 0 || authority_fd_ < 0) {
        fail(diagnostic, FailurePhase::Argument, active_ ? EBADF : EALREADY);
        return false;
    }
    if (!validate_descriptor(observation_fd_, false, diagnostic) ||
        !validate_descriptor(authority_fd_, false, diagnostic) ||
        !same_open_file_description(observation_fd_, authority_fd_, diagnostic))
        return false;
    return true;
}

bool ExecutableLease::revalidate(Diagnostic& diagnostic) const {
    diagnostic = {};
    if (!validate_custody(diagnostic)) {
        record_validation(false, diagnostic);
        return false;
    }
    struct stat observation{};
    struct stat authority{};
    struct stat path_status{};
    if (fstat(observation_fd_, &observation) != 0 || fstat(authority_fd_, &authority) != 0) {
        fail(diagnostic, FailurePhase::Identity, errno == 0 ? EIO : errno);
        record_validation(false, diagnostic);
        return false;
    }
    if (!same_metadata_except_ctime(observation, identity_) ||
        !same_metadata_except_ctime(authority, identity_) ||
        observation.st_mode != authority.st_mode || observation.st_uid != authority.st_uid ||
        observation.st_gid != authority.st_gid || observation.st_size != authority.st_size ||
        observation.st_mtim.tv_sec != authority.st_mtim.tv_sec ||
        observation.st_mtim.tv_nsec != authority.st_mtim.tv_nsec ||
        observation.st_ctim.tv_sec != authority.st_ctim.tv_sec ||
        observation.st_ctim.tv_nsec != authority.st_ctim.tv_nsec) {
        fail(diagnostic, FailurePhase::Identity, EINVAL);
        record_validation(false, diagnostic);
        return false;
    }
    errno = 0;
    if (lstat(path_.c_str(), &path_status) != 0 || !same_object(path_status, identity_) ||
        !same_metadata_except_ctime(path_status, identity_) ||
        path_status.st_ctim.tv_sec != observation.st_ctim.tv_sec ||
        path_status.st_ctim.tv_nsec != observation.st_ctim.tv_nsec) {
        fail(diagnostic, FailurePhase::Path, errno == 0 ? EINVAL : errno);
        record_validation(false, diagnostic);
        return false;
    }
    // Linux changes ctime for link-count and some pathname transitions. nlink
    // is intentionally not an invariant, and a temporary different-inode
    // pathname replacement must remain restore/retry capable. Once the exact
    // path binding is back and all mode/owner/size/mtime fields are unchanged,
    // advance the common ctime baseline shared by path and both pinned FDs.
    // Content or other metadata drift remains independently fail-closed.
    if (!same_ctime(observation, accepted_ctime_seconds_, accepted_ctime_nanoseconds_)) {
        accepted_ctime_seconds_ = static_cast<std::int64_t>(observation.st_ctim.tv_sec);
        accepted_ctime_nanoseconds_ = static_cast<std::int64_t>(observation.st_ctim.tv_nsec);
    }
    if (!validate_policy(observation_fd_, diagnostic) ||
        !validate_policy(authority_fd_, diagnostic)) {
        record_validation(false, diagnostic);
        return false;
    }
    record_validation(true, diagnostic);
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
    const bool exact_pair = validate_custody(custody);
    record_validation(exact_pair, custody);
    if (!exact_pair && !destructor) {
        diagnostic = custody;
        if (cleanup_state_) cleanup_state_->diagnostic = diagnostic;
        return false;
    }

    bool success = true;
    if (exact_pair) {
        // Detach both fields before the first close, then attempt independently.
        int observation = observation_fd_;
        int authority = authority_fd_;
        observation_fd_ = -1;
        authority_fd_ = -1;
        active_ = false;
        terminal_ = true;
        success = close_one(observation, cleanup_state_->observation, diagnostic);
        if (!close_one(authority, cleanup_state_->authority, diagnostic)) success = false;
    } else {
        // Destruction cannot offer restore/retry. Never touch an unproven
        // observation slot. The never-exposed private authority is settled only
        // when its O_PATH/CLOEXEC/object custody remains independently valid.
        cleanup_state_->observation.error_number = custody.error_number;
        Diagnostic authority_diagnostic;
        if (validate_descriptor(authority_fd_, false, authority_diagnostic)) {
            if (!close_one(authority_fd_, cleanup_state_->authority, diagnostic)) success = false;
        } else {
            cleanup_state_->authority.error_number = authority_diagnostic.error_number;
            success = false;
            if (diagnostic.phase == FailurePhase::None) diagnostic = authority_diagnostic;
        }
        observation_fd_ = -1;  // Foreign/unproven numeric slot is not owned.
        active_ = false;
        terminal_ = true;
        if (diagnostic.phase == FailurePhase::None) diagnostic = custody;
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
    int authority = authority_fd_;
    observation_fd_ = -1;
    authority_fd_ = -1;
    active_ = false;
    terminal_ = true;
    if (observation >= 0)
        (void)close_one(observation, cleanup_state_->observation, close_diagnostic);
    if (authority >= 0) (void)close_one(authority, cleanup_state_->authority, close_diagnostic);
    cleanup_state_->validation_succeeded = false;
    cleanup_state_->validation_diagnostic = original;
    diagnostic = original;
    if (cleanup_state_) cleanup_state_->diagnostic = original;
    return false;
}

}  // namespace rut::test::fixture_executable_lease
