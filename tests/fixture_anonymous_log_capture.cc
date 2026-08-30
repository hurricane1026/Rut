#include "fixture_anonymous_log_capture.h"

#include <cerrno>
#include <cstdint>

#include <fcntl.h>
#include <linux/memfd.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

namespace rut::test::fixture_anonymous_log_capture {
namespace {

constexpr int kInitialSeals = F_SEAL_GROW | F_SEAL_SHRINK;
constexpr int kFinalSeals = kInitialSeals | F_SEAL_WRITE | F_SEAL_SEAL;

void fail(Diagnostic& diagnostic, FailurePhase phase, int error_number = 0) {
    diagnostic = {phase, error_number};
}

Identity make_identity(const struct stat& status) {
    return {static_cast<std::uint64_t>(status.st_dev),
            static_cast<std::uint64_t>(status.st_ino),
            static_cast<std::uint64_t>(status.st_mode),
            static_cast<std::uint64_t>(status.st_uid),
            static_cast<std::uint64_t>(status.st_gid)};
}

bool same_identity(const struct stat& status, const Identity& expected) {
    return S_ISREG(status.st_mode) && status.st_dev != 0 && status.st_ino != 0 &&
           static_cast<std::uint64_t>(status.st_dev) == expected.device &&
           static_cast<std::uint64_t>(status.st_ino) == expected.inode &&
           static_cast<std::uint64_t>(status.st_mode) == expected.mode &&
           static_cast<std::uint64_t>(status.st_uid) == expected.uid &&
           static_cast<std::uint64_t>(status.st_gid) == expected.gid &&
           (status.st_mode & 07777) == 0600 && status.st_nlink == 0;
}

bool valid_fd_flags(int fd, int& error_number) {
    errno = 0;
    const int flags = fcntl(fd, F_GETFD);
    if (flags < 0) {
        error_number = errno;
        return false;
    }
    if ((flags & FD_CLOEXEC) == 0) {
        error_number = EINVAL;
        return false;
    }
    error_number = 0;
    return true;
}

bool valid_seals(int fd, int expected, int& error_number) {
    errno = 0;
    const int seals = fcntl(fd, F_GET_SEALS);
    if (seals < 0) {
        error_number = errno;
        return false;
    }
    if (seals != expected) {
        error_number = EINVAL;
        return false;
    }
    error_number = 0;
    return true;
}

bool fd_matches_object(int fd, const Identity& expected, int& error_number) {
    errno = 0;
    struct stat status{};
    if (fstat(fd, &status) != 0) {
        error_number = errno;
        return false;
    }
    // Metadata (mode/uid/gid) is deliberately not part of this close guard:
    // those fields are mutable and are independently revalidated by the lease.
    // Refuse only a missing/replaced numeric descriptor; matching dev/inode of
    // the regular, unlinked memfd is the stable object identity.
    if (!S_ISREG(status.st_mode) || status.st_nlink != 0 || status.st_dev == 0 ||
        status.st_ino == 0 || static_cast<std::uint64_t>(status.st_dev) != expected.device ||
        static_cast<std::uint64_t>(status.st_ino) != expected.inode) {
        error_number = EINVAL;
        return false;
    }
    error_number = 0;
    return true;
}

}  // namespace

AnonymousLogCapture::AnonymousLogCapture() : cleanup_state_(std::make_shared<CleanupState>()) {}

AnonymousLogCapture::AnonymousLogCapture(AnonymousLogCapture&& other) noexcept
    : fd_(other.fd_),
      max_bytes_(other.max_bytes_),
      identity_(other.identity_),
      cleanup_state_(other.cleanup_state_),
      pread_for_testing_(other.pread_for_testing_),
      close_for_testing_(other.close_for_testing_),
      after_final_seal_for_testing_(other.after_final_seal_for_testing_),
      settled_(other.settled_) {
    other.fd_ = -1;
    other.max_bytes_ = 0u;
    other.identity_ = {};
    other.pread_for_testing_ = nullptr;
    other.close_for_testing_ = nullptr;
    other.after_final_seal_for_testing_ = nullptr;
    other.settled_ = false;
}

AnonymousLogCapture::~AnonymousLogCapture() {
    if (fd_ >= 0) {
        Diagnostic diagnostic;
        (void)close_owned(close_for_testing_, diagnostic);
    }
}

bool AnonymousLogCapture::create(std::size_t max_bytes,
                                 AnonymousLogCapture& capture,
                                 Diagnostic& diagnostic) {
    return create_impl(max_bytes, nullptr, capture, diagnostic);
}

bool AnonymousLogCapture::create_with_hooks_for_testing(std::size_t max_bytes,
                                                        const HooksForTesting& hooks,
                                                        AnonymousLogCapture& capture,
                                                        Diagnostic& diagnostic) {
    return create_impl(max_bytes, &hooks, capture, diagnostic);
}

bool AnonymousLogCapture::create_impl(std::size_t max_bytes,
                                      const HooksForTesting* hooks,
                                      AnonymousLogCapture& capture,
                                      Diagnostic& diagnostic) {
    diagnostic = {};
    if (max_bytes == 0u || max_bytes > kMaxCaptureBytes || capture.fd_ >= 0) {
        fail(diagnostic, FailurePhase::Argument, EINVAL);
        return false;
    }
    if (capture.cleanup_state_ != nullptr && capture.cleanup_state_->attempted &&
        !capture.cleanup_state_->succeeded) {
        fail(diagnostic, FailurePhase::Close, EALREADY);
        return false;
    }

#ifdef SYS_memfd_create
    const int created = static_cast<int>(
        syscall(SYS_memfd_create, "rut377-anonymous-log", MFD_CLOEXEC | MFD_ALLOW_SEALING));
#else
    const int created = -1;
    errno = ENOSYS;
#endif
    if (created < 0) {
        fail(diagnostic, FailurePhase::Syscall, errno);
        return false;
    }

    // Ownership starts at successful memfd_create. Every later failure closes
    // exactly once, without retrying an uncertain Linux close result.
    capture.fd_ = created;
    capture.max_bytes_ = max_bytes;
    capture.pread_for_testing_ = hooks == nullptr ? nullptr : hooks->pread;
    capture.close_for_testing_ = hooks == nullptr ? nullptr : hooks->close;
    capture.after_final_seal_for_testing_ = hooks == nullptr ? nullptr : hooks->after_final_seal;
    capture.cleanup_state_ = std::make_shared<CleanupState>();
    capture.settled_ = false;

    auto fail_created = [&](FailurePhase phase, int error_number) {
        Diagnostic original{phase, error_number};
        Diagnostic close_diagnostic;
        (void)capture.close_owned(capture.close_for_testing_, close_diagnostic);
        diagnostic = original;
        return false;
    };

    if (fchmod(capture.fd_, 0600) != 0) return fail_created(FailurePhase::Identity, errno);
    int validation_error = 0;
    if (!valid_fd_flags(capture.fd_, validation_error))
        return fail_created(FailurePhase::Identity, validation_error);

    struct stat status{};
    if (fstat(capture.fd_, &status) != 0) return fail_created(FailurePhase::Identity, errno);
    if (!S_ISREG(status.st_mode) || status.st_dev == 0 || status.st_ino == 0 ||
        (status.st_mode & 07777) != 0600 || status.st_uid != getuid() ||
        status.st_gid != getgid() || status.st_nlink != 0) {
        return fail_created(FailurePhase::Identity, EINVAL);
    }
    capture.identity_ = make_identity(status);

    if (ftruncate(capture.fd_, static_cast<off_t>(max_bytes)) != 0)
        return fail_created(FailurePhase::Capacity, errno);
    if (fcntl(capture.fd_, F_ADD_SEALS, kInitialSeals) != 0)
        return fail_created(FailurePhase::Seal, errno);
    if (!valid_seals(capture.fd_, kInitialSeals, validation_error))
        return fail_created(FailurePhase::Seal, validation_error);
    if (!capture.validate_identity_and_capacity(diagnostic)) {
        const Diagnostic original = diagnostic;
        return fail_created(original.phase, original.error_number);
    }
    return true;
}

bool AnonymousLogCapture::validate_identity_and_capacity(Diagnostic& diagnostic) const {
    diagnostic = {};
    if (fd_ < 0 || max_bytes_ == 0u) {
        fail(diagnostic, FailurePhase::Argument, EINVAL);
        return false;
    }
    struct stat status{};
    if (fstat(fd_, &status) != 0) {
        fail(diagnostic, FailurePhase::Identity, errno);
        return false;
    }
    if (!same_identity(status, identity_) || status.st_size < 0 ||
        static_cast<std::uint64_t>(status.st_size) != max_bytes_) {
        fail(diagnostic, FailurePhase::Identity, EINVAL);
        return false;
    }
    int validation_error = 0;
    if (!valid_fd_flags(fd_, validation_error)) {
        fail(diagnostic, FailurePhase::Identity, validation_error);
        return false;
    }
    const int expected_seals = settled_ ? kFinalSeals : kInitialSeals;
    if (!valid_seals(fd_, expected_seals, validation_error)) {
        fail(diagnostic, FailurePhase::Seal, validation_error);
        return false;
    }
    return true;
}

bool AnonymousLogCapture::validate_offset(off_t offset, Diagnostic& diagnostic) const {
    if (offset < 0 || static_cast<std::uintmax_t>(offset) > max_bytes_) {
        fail(diagnostic, FailurePhase::Offset, EINVAL);
        return false;
    }
    return true;
}

bool AnonymousLogCapture::snapshot(std::string& bytes, Diagnostic& diagnostic) const {
    diagnostic = {};
    if (!validate_identity_and_capacity(diagnostic)) return false;
    errno = 0;
    const off_t offset = lseek(fd_, 0, SEEK_CUR);
    if (offset < 0) {
        fail(diagnostic, FailurePhase::Offset, errno);
        return false;
    }
    if (!validate_offset(offset, diagnostic)) return false;
    return snapshot_at_offset(offset, bytes, pread_for_testing_, diagnostic);
}

bool AnonymousLogCapture::snapshot_at_offset_for_testing(off_t offset,
                                                         std::string& bytes,
                                                         PreadForTesting operation,
                                                         Diagnostic& diagnostic) const {
    diagnostic = {};
    if (!validate_identity_and_capacity(diagnostic)) return false;
    if (!validate_offset(offset, diagnostic)) return false;
    return snapshot_at_offset(offset, bytes, operation, diagnostic);
}

bool AnonymousLogCapture::snapshot_at_offset(off_t offset,
                                             std::string& bytes,
                                             PreadForTesting operation,
                                             Diagnostic& diagnostic) const {
    diagnostic = {};
    if (!validate_offset(offset, diagnostic)) return false;
    const PreadForTesting reader = operation == nullptr ? pread : operation;
    bytes.clear();
    if (offset == 0) {
        // There is no logical EOF read here: the memfd is intentionally
        // pre-sized to max_bytes and therefore has zero-filled capacity.
        return true;
    }
    bytes.resize(static_cast<std::size_t>(offset));
    std::size_t read_offset = 0u;
    while (read_offset < bytes.size()) {
        const ssize_t result = reader(fd_,
                                      bytes.data() + read_offset,
                                      bytes.size() - read_offset,
                                      static_cast<off_t>(read_offset));
        if (result < 0 && errno == EINTR) continue;
        if (result <= 0 || static_cast<std::size_t>(result) > bytes.size() - read_offset) {
            fail(diagnostic, FailurePhase::Read, result < 0 ? errno : EIO);
            bytes.clear();
            return false;
        }
        read_offset += static_cast<std::size_t>(result);
    }
    return true;
}

bool AnonymousLogCapture::settle(Diagnostic& diagnostic) {
    diagnostic = {};
    if (!validate_identity_and_capacity(diagnostic)) return false;
    const off_t offset = lseek(fd_, 0, SEEK_CUR);
    if (offset < 0) {
        fail(diagnostic, FailurePhase::Offset, errno);
        return false;
    }
    if (!validate_offset(offset, diagnostic)) return false;
    if (fcntl(fd_, F_ADD_SEALS, F_SEAL_WRITE | F_SEAL_SEAL) != 0) {
        fail(diagnostic, FailurePhase::Seal, errno);
        return false;
    }
    int validation_error = 0;
    if (!valid_seals(fd_, kFinalSeals, validation_error)) {
        fail(diagnostic, FailurePhase::Seal, validation_error);
        return false;
    }
    settled_ = true;
    if (after_final_seal_for_testing_ != nullptr) after_final_seal_for_testing_(fd_);
    // Keep the physical final state even if this last independent check sees
    // a concurrent/replacement mutation; callers must treat the false return
    // as terminal and may still inspect the settled descriptor state.
    if (!validate_identity_and_capacity(diagnostic)) return false;
    const off_t final_offset = lseek(fd_, 0, SEEK_CUR);
    if (final_offset < 0) {
        fail(diagnostic, FailurePhase::Offset, errno);
        return false;
    }
    if (!validate_offset(final_offset, diagnostic)) return false;
    return true;
}

void AnonymousLogCapture::record_cleanup(bool succeeded, const Diagnostic& diagnostic) {
    if (!cleanup_state_) cleanup_state_ = std::make_shared<CleanupState>();
    cleanup_state_->attempted = true;
    cleanup_state_->succeeded = succeeded;
    cleanup_state_->diagnostic = diagnostic;
}

bool AnonymousLogCapture::close_owned(CloseForTesting operation, Diagnostic& diagnostic) {
    diagnostic = {};
    if (fd_ < 0) {
        if (cleanup_state_ != nullptr && cleanup_state_->attempted && !cleanup_state_->succeeded) {
            diagnostic = cleanup_state_->diagnostic;
            return false;
        }
        return true;
    }
    const int owned = fd_;
    int identity_error = 0;
    if (!fd_matches_object(owned, identity_, identity_error)) {
        fd_ = -1;
        fail(diagnostic, FailurePhase::Close, identity_error);
        record_cleanup(false, diagnostic);
        return false;
    }
    fd_ = -1;
    errno = 0;
    const int result = operation == nullptr ? ::close(owned) : operation(owned);
    if (result == 0) {
        record_cleanup(true, diagnostic);
        return true;
    }
    const int error_number = errno == 0 ? EIO : errno;
    fail(diagnostic, FailurePhase::Close, error_number);
    record_cleanup(false, diagnostic);
    return false;
}

bool AnonymousLogCapture::close(Diagnostic& diagnostic) {
    return close_owned(close_for_testing_, diagnostic);
}

}  // namespace rut::test::fixture_anonymous_log_capture
