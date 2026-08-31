#include "fixture_wildcard_source_lease.h"

#include <array>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <limits>

#include <fcntl.h>
#include <linux/fs.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

namespace rut::test::fixture_wildcard_source_lease {
namespace {

constexpr unsigned kQuarantineAttempts = 32u;
constexpr unsigned kFinalizeWriteAttempts = 512u;

void fail(Diagnostic& diagnostic, FailurePhase phase, int error_number = 0) {
    diagnostic = {phase, error_number};
}

DirectoryIdentity make_directory_identity(const struct stat& status) {
    return {static_cast<std::uint64_t>(status.st_dev),
            static_cast<std::uint64_t>(status.st_ino),
            static_cast<std::uint64_t>(status.st_mode),
            static_cast<std::uint64_t>(status.st_uid),
            static_cast<std::uint64_t>(status.st_gid)};
}

SourceIdentity make_source_identity(const struct stat& status) {
    return {static_cast<std::uint64_t>(status.st_dev),
            static_cast<std::uint64_t>(status.st_ino),
            static_cast<std::uint64_t>(status.st_mode),
            static_cast<std::uint64_t>(status.st_uid),
            static_cast<std::uint64_t>(status.st_gid),
            static_cast<std::uint64_t>(status.st_size)};
}

bool same_directory(const struct stat& status, const DirectoryIdentity& expected) {
    return S_ISDIR(status.st_mode) &&
           static_cast<std::uint64_t>(status.st_dev) == expected.device &&
           static_cast<std::uint64_t>(status.st_ino) == expected.inode &&
           static_cast<std::uint64_t>(status.st_mode) == expected.mode &&
           static_cast<std::uint64_t>(status.st_uid) == expected.uid &&
           static_cast<std::uint64_t>(status.st_gid) == expected.gid &&
           (status.st_mode & 0777) == 0700;
}

bool same_source(const struct stat& status, const SourceIdentity& expected, bool require_link) {
    return S_ISREG(status.st_mode) &&
           static_cast<std::uint64_t>(status.st_dev) == expected.device &&
           static_cast<std::uint64_t>(status.st_ino) == expected.inode &&
           static_cast<std::uint64_t>(status.st_mode) == expected.mode &&
           static_cast<std::uint64_t>(status.st_uid) == expected.uid &&
           static_cast<std::uint64_t>(status.st_gid) == expected.gid && status.st_size >= 0 &&
           static_cast<std::uint64_t>(status.st_size) == expected.size &&
           status.st_nlink == (require_link ? 1u : 0u) && (status.st_mode & 0777) == 0600;
}

bool same_source_object(const struct stat& status,
                        const SourceIdentity& expected,
                        bool require_link) {
    return S_ISREG(status.st_mode) &&
           static_cast<std::uint64_t>(status.st_dev) == expected.device &&
           static_cast<std::uint64_t>(status.st_ino) == expected.inode &&
           static_cast<std::uint64_t>(status.st_mode) == expected.mode &&
           static_cast<std::uint64_t>(status.st_uid) == expected.uid &&
           static_cast<std::uint64_t>(status.st_gid) == expected.gid && status.st_size >= 0 &&
           status.st_nlink == (require_link ? 1u : 0u) && (status.st_mode & 0777) == 0600;
}

bool same_owned_source_descriptor(const struct stat& status, const SourceIdentity& expected) {
    return S_ISREG(status.st_mode) &&
           static_cast<std::uint64_t>(status.st_dev) == expected.device &&
           static_cast<std::uint64_t>(status.st_ino) == expected.inode &&
           static_cast<std::uint64_t>(status.st_mode) == expected.mode &&
           static_cast<std::uint64_t>(status.st_uid) == expected.uid &&
           static_cast<std::uint64_t>(status.st_gid) == expected.gid && status.st_size >= 0 &&
           (status.st_mode & 0777) == 0600;
}

bool descriptor_flags(int fd, int access_mode, bool nonblocking) {
    errno = 0;
    const int descriptor = fcntl(fd, F_GETFD);
    if (descriptor < 0 || (descriptor & FD_CLOEXEC) == 0) return false;
    errno = 0;
    const int status = fcntl(fd, F_GETFL);
    return status >= 0 && (status & O_ACCMODE) == access_mode &&
           ((status & O_NONBLOCK) != 0) == nonblocking && (status & (O_APPEND | O_ASYNC)) == 0;
}

int real_ftruncate(int fd, off_t length, void*) {
    return ftruncate(fd, length);
}

ssize_t real_pwrite(int fd, const void* buffer, std::size_t count, off_t offset, void*) {
    return pwrite(fd, buffer, count, offset);
}

int real_fsync(int fd, void*) {
    return fsync(fd);
}

int real_close(int fd, void*) {
    return close(fd);
}

bool safe_path_component(const std::string& value) {
    if (value.empty() || value == "." || value == ".." || value.size() > 128u) return false;
    for (const unsigned char byte : value)
        if (byte < 0x21u || byte > 0x7eu || byte == '/') return false;
    return true;
}

bool write_all(int fd, const std::string& bytes) {
    std::size_t offset = 0u;
    while (offset < bytes.size()) {
        const ssize_t count = write(fd, bytes.data() + offset, bytes.size() - offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return false;
        offset += static_cast<std::size_t>(count);
    }
    return true;
}

bool close_checked(int& fd) {
    if (fd < 0) return true;
    const int closing = fd;
    fd = -1;
    return close(closing) == 0;
}

int rename_noreplace(int old_directory,
                     const char* old_name,
                     int new_directory,
                     const char* new_name) {
#ifdef SYS_renameat2
    return static_cast<int>(
        syscall(SYS_renameat2, old_directory, old_name, new_directory, new_name, RENAME_NOREPLACE));
#else
    (void)old_directory;
    (void)old_name;
    (void)new_directory;
    (void)new_name;
    errno = ENOSYS;
    return -1;
#endif
}

ssize_t retrying_pread(
    PreadForTesting operation, int fd, void* buffer, std::size_t count, off_t offset) {
    for (;;) {
        const ssize_t result = operation(fd, buffer, count, offset);
        if (result < 0 && errno == EINTR) continue;
        return result;
    }
}

bool read_exact_buffer(int fd,
                       const char* expected,
                       std::size_t expected_size,
                       PreadForTesting operation,
                       Diagnostic& diagnostic) {
    diagnostic = {};
    std::array<char, 256> buffer{};
    if (fd < 0 || operation == nullptr || expected == nullptr || expected_size == 0u ||
        expected_size >= buffer.size()) {
        fail(diagnostic, FailurePhase::Bytes, EINVAL);
        return false;
    }
    std::size_t offset = 0u;
    while (offset < expected_size) {
        const ssize_t count = retrying_pread(operation,
                                             fd,
                                             buffer.data() + offset,
                                             expected_size - offset,
                                             static_cast<off_t>(offset));
        if (count <= 0) {
            fail(diagnostic, FailurePhase::Bytes, count < 0 ? errno : EIO);
            return false;
        }
        offset += static_cast<std::size_t>(count);
    }
    char trailing = '\0';
    const ssize_t trailing_count =
        retrying_pread(operation, fd, &trailing, 1u, static_cast<off_t>(expected_size));
    if (trailing_count < 0 || trailing_count != 0 ||
        std::memcmp(buffer.data(), expected, expected_size) != 0) {
        fail(diagnostic, FailurePhase::Bytes, trailing_count < 0 ? errno : EINVAL);
        return false;
    }
    return true;
}

bool random_quarantine_name(std::string& name) {
    std::array<unsigned char, 16> random{};
    std::size_t offset = 0u;
    while (offset < random.size()) {
        const ssize_t count =
            getrandom(random.data() + offset, random.size() - offset, GRND_NONBLOCK);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return false;
        offset += static_cast<std::size_t>(count);
    }
    constexpr char hex[] = "0123456789abcdef";
    name = ".rut377-quarantine-";
    name.reserve(name.size() + random.size() * 2u);
    for (const unsigned char byte : random) {
        name.push_back(hex[byte >> 4u]);
        name.push_back(hex[byte & 0x0fu]);
    }
    return true;
}

}  // namespace

bool read_exact_bytes_for_testing(int fd,
                                  const std::string& expected,
                                  PreadForTesting operation,
                                  Diagnostic& diagnostic) {
    return read_exact_buffer(fd, expected.data(), expected.size(), operation, diagnostic);
}

WildcardAttemptSourceLease::WildcardAttemptSourceLease()
    : cleanup_state_(std::make_shared<CleanupState>()) {}

WildcardAttemptSourceLease::~WildcardAttemptSourceLease() {
    if (cleanup_required_) {
        Diagnostic diagnostic;
        const bool removed = quarantine_and_remove(nullptr, nullptr, diagnostic);
        record_cleanup(removed, diagnostic);
        if (!removed) {
            std::fprintf(stderr,
                         "FAIL [#377 wildcard source lease destructor]: phase=%u errno=%d\n",
                         static_cast<unsigned>(diagnostic.phase),
                         diagnostic.error_number);
        }
    }
    active_ = false;
    Diagnostic close_diagnostic;
    close_descriptors(close_diagnostic);
    if (close_diagnostic.phase != FailurePhase::None) {
        record_cleanup(false, close_diagnostic);
        std::fprintf(stderr,
                     "FAIL [#377 wildcard source lease descriptor close]: errno=%d\n",
                     close_diagnostic.error_number);
    }
}

bool WildcardAttemptSourceLease::create(int identity_bound_directory_fd,
                                        const std::string& directory_path,
                                        const std::string& basename,
                                        const fixture_privileged_listener::ListenerPlan& plan,
                                        WildcardAttemptSourceLease& lease,
                                        Diagnostic& diagnostic) {
    return create_impl(
        identity_bound_directory_fd, directory_path, basename, plan, nullptr, lease, diagnostic);
}

bool WildcardAttemptSourceLease::create_exact_bytes(int identity_bound_directory_fd,
                                                    const std::string& directory_path,
                                                    const std::string& basename,
                                                    const std::string& exact_bytes,
                                                    WildcardAttemptSourceLease& lease,
                                                    Diagnostic& diagnostic) {
    return create_exact_bytes_impl(identity_bound_directory_fd,
                                   directory_path,
                                   basename,
                                   exact_bytes,
                                   nullptr,
                                   lease,
                                   diagnostic);
}

bool WildcardAttemptSourceLease::create_with_hooks_for_testing(
    int identity_bound_directory_fd,
    const std::string& directory_path,
    const std::string& basename,
    const fixture_privileged_listener::ListenerPlan& plan,
    const SourceLeaseHooksForTesting& hooks,
    WildcardAttemptSourceLease& lease,
    Diagnostic& diagnostic) {
    return create_impl(
        identity_bound_directory_fd, directory_path, basename, plan, &hooks, lease, diagnostic);
}

bool WildcardAttemptSourceLease::stage(int identity_bound_directory_fd,
                                       const std::string& directory_path,
                                       const std::string& basename,
                                       WildcardAttemptSourceLease& lease,
                                       Diagnostic& diagnostic) {
    return stage_impl(
        identity_bound_directory_fd, directory_path, basename, nullptr, lease, diagnostic);
}

bool WildcardAttemptSourceLease::stage_with_hooks_for_testing(
    int identity_bound_directory_fd,
    const std::string& directory_path,
    const std::string& basename,
    const StagedSourceHooksForTesting& hooks,
    WildcardAttemptSourceLease& lease,
    Diagnostic& diagnostic) {
    return stage_impl(
        identity_bound_directory_fd, directory_path, basename, &hooks, lease, diagnostic);
}

bool WildcardAttemptSourceLease::stage_impl(int identity_bound_directory_fd,
                                            const std::string& directory_path,
                                            const std::string& basename,
                                            const StagedSourceHooksForTesting* hooks,
                                            WildcardAttemptSourceLease& lease,
                                            Diagnostic& diagnostic) {
    diagnostic = {};
    if (lease.state_ != State::Fresh || lease.active_ || lease.cleanup_required_ ||
        lease.directory_fd_ >= 0 || lease.source_fd_ >= 0 || lease.writer_fd_ >= 0 ||
        identity_bound_directory_fd < 0 || directory_path.empty() ||
        directory_path.find('\0') != std::string::npos || directory_path.front() != '/' ||
        directory_path.back() == '/' || !safe_path_component(basename)) {
        fail(diagnostic, FailurePhase::Argument, EINVAL);
        return false;
    }

    const int retained_directory =
        fcntl(identity_bound_directory_fd, F_DUPFD_CLOEXEC, STDERR_FILENO + 1);
    struct stat directory_status{};
    struct stat path_directory_status{};
    const bool directory_ok =
        retained_directory >= 0 && fstat(retained_directory, &directory_status) == 0 &&
        fstatat(AT_FDCWD, directory_path.c_str(), &path_directory_status, AT_SYMLINK_NOFOLLOW) ==
            0 &&
        S_ISDIR(directory_status.st_mode) &&
        directory_status.st_dev == path_directory_status.st_dev &&
        directory_status.st_ino == path_directory_status.st_ino &&
        directory_status.st_uid == getuid() && directory_status.st_gid == getgid() &&
        (directory_status.st_mode & 0777) == 0700 &&
        descriptor_flags(retained_directory, O_RDONLY, false);
    const int directory_error = errno == 0 ? ESTALE : errno;
    if (!directory_ok) {
        if (retained_directory >= 0) (void)close(retained_directory);
        fail(diagnostic, FailurePhase::Directory, directory_error);
        return false;
    }

    const int writer = openat(retained_directory,
                              basename.c_str(),
                              O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                              0600);
    if (writer < 0) {
        const int error_number = errno;
        (void)close(retained_directory);
        fail(diagnostic, FailurePhase::Create, error_number);
        return false;
    }

    lease.directory_fd_ = retained_directory;
    lease.writer_fd_ = writer;
    lease.cleanup_required_ = true;
    lease.owned_entry_known_ = true;
    lease.directory_path_ = directory_path;
    lease.basename_ = basename;
    lease.owned_basename_ = basename;
    lease.path_ = directory_path + "/" + basename;
    lease.directory_identity_ = make_directory_identity(directory_status);
    lease.cleanup_state_ = std::make_shared<CleanupState>();
    lease.staged_hooks_ = hooks == nullptr ? StagedSourceHooksForTesting{} : *hooks;

    struct stat writer_status{};
    if (lease.staged_hooks_.stage_fault == StageFaultForTesting::InitialIdentity) {
        const Diagnostic original{FailurePhase::Create, EIO};
        return lease.fail_created(original, diagnostic);
    }
    if (fstat(writer, &writer_status) != 0) {
        const Diagnostic original{FailurePhase::Create, errno == 0 ? ESTALE : errno};
        return lease.fail_created(original, diagnostic);
    }
    lease.source_identity_ = make_source_identity(writer_status);
    lease.source_identity_known_ = true;
    if (!S_ISREG(writer_status.st_mode) || writer_status.st_uid != getuid() ||
        writer_status.st_gid != getgid() || (writer_status.st_mode & 0777) != 0600 ||
        writer_status.st_nlink != 1u || writer_status.st_size != 0 ||
        !descriptor_flags(writer, O_WRONLY, false) ||
        lease.staged_hooks_.stage_fault == StageFaultForTesting::InitialFlags) {
        const Diagnostic original{
            FailurePhase::Create,
            lease.staged_hooks_.stage_fault == StageFaultForTesting::InitialFlags
                ? ECANCELED
                : (errno == 0 ? ESTALE : errno)};
        return lease.fail_created(original, diagnostic);
    }

    lease.source_fd_ = openat(
        retained_directory, basename.c_str(), O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW);
    struct stat reader_status{};
    struct stat entry_status{};
    const bool opened =
        lease.source_fd_ >= 0 && fstat(lease.source_fd_, &reader_status) == 0 &&
        fstatat(retained_directory, basename.c_str(), &entry_status, AT_SYMLINK_NOFOLLOW) == 0 &&
        same_source(reader_status, lease.source_identity_, true) &&
        same_source(entry_status, lease.source_identity_, true) &&
        descriptor_flags(lease.source_fd_, O_RDONLY, true) && fsync(retained_directory) == 0;
    const int opened_error = errno == 0 ? ESTALE : errno;
    if (!opened) {
        const Diagnostic original{FailurePhase::Lease, opened_error};
        return lease.fail_created(original, diagnostic);
    }
    lease.state_ = State::Staged;
    return true;
}

bool WildcardAttemptSourceLease::create_impl(int identity_bound_directory_fd,
                                             const std::string& directory_path,
                                             const std::string& basename,
                                             const fixture_privileged_listener::ListenerPlan& plan,
                                             const SourceLeaseHooksForTesting* hooks,
                                             WildcardAttemptSourceLease& lease,
                                             Diagnostic& diagnostic) {
    std::string expected;
    fixture_privileged_listener::Diagnostic listener_diagnostic;
    if (!fixture_privileged_listener::build_listener_source(
            plan,
            fixture_privileged_listener::ListenerSourceKind::Wildcard,
            expected,
            listener_diagnostic) ||
        expected.empty() || expected.find('\0') != std::string::npos) {
        fail(diagnostic, FailurePhase::Argument, EINVAL);
        return false;
    }
    return create_exact_bytes_impl(
        identity_bound_directory_fd, directory_path, basename, expected, hooks, lease, diagnostic);
}

bool WildcardAttemptSourceLease::create_exact_bytes_impl(int identity_bound_directory_fd,
                                                         const std::string& directory_path,
                                                         const std::string& basename,
                                                         const std::string& exact_bytes,
                                                         const SourceLeaseHooksForTesting* hooks,
                                                         WildcardAttemptSourceLease& lease,
                                                         Diagnostic& diagnostic) {
    diagnostic = {};
    if (lease.state_ != State::Fresh || lease.active_ || lease.cleanup_required_ ||
        lease.directory_fd_ >= 0 || lease.source_fd_ >= 0 || lease.writer_fd_ >= 0 ||
        identity_bound_directory_fd < 0 || directory_path.empty() ||
        directory_path.find('\0') != std::string::npos || directory_path.front() != '/' ||
        directory_path.back() == '/' || !safe_path_component(basename) || exact_bytes.empty() ||
        exact_bytes.size() > 255u || exact_bytes.find('\0') != std::string::npos) {
        fail(diagnostic, FailurePhase::Argument, EINVAL);
        return false;
    }

    const int retained_directory =
        fcntl(identity_bound_directory_fd, F_DUPFD_CLOEXEC, STDERR_FILENO + 1);
    struct stat directory_status{};
    struct stat path_directory_status{};
    const int path_directory =
        open(directory_path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    const bool directory_ok =
        retained_directory >= 0 && path_directory >= 0 &&
        fstat(retained_directory, &directory_status) == 0 &&
        fstat(path_directory, &path_directory_status) == 0 && S_ISDIR(directory_status.st_mode) &&
        directory_status.st_dev == path_directory_status.st_dev &&
        directory_status.st_ino == path_directory_status.st_ino &&
        directory_status.st_uid == getuid() && directory_status.st_gid == getgid() &&
        (directory_status.st_mode & 0777) == 0700;
    const int directory_error = errno;
    if (path_directory >= 0) (void)close(path_directory);
    if (!directory_ok) {
        if (retained_directory >= 0) (void)close(retained_directory);
        fail(diagnostic, FailurePhase::Directory, directory_error);
        return false;
    }

    const int writer = openat(retained_directory,
                              basename.c_str(),
                              O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                              0600);
    if (writer < 0) {
        const int error_number = errno;
        (void)close(retained_directory);
        fail(diagnostic, FailurePhase::Create, error_number);
        return false;
    }

    // Ownership begins at successful O_EXCL, before the first operation that
    // can fail. From here every exit uses quarantine_and_remove.
    lease.directory_fd_ = retained_directory;
    lease.source_fd_ = writer;
    lease.source_fd_is_created_ = true;
    lease.cleanup_required_ = true;
    lease.owned_entry_known_ = true;
    lease.directory_path_ = directory_path;
    lease.basename_ = basename;
    lease.owned_basename_ = basename;
    lease.path_ = directory_path + "/" + basename;
    lease.expected_bytes_ = exact_bytes;
    lease.directory_identity_ = make_directory_identity(directory_status);
    lease.cleanup_state_ = std::make_shared<CleanupState>();

    struct stat created_status{};
    if (fstat(lease.source_fd_, &created_status) != 0 || !S_ISREG(created_status.st_mode) ||
        created_status.st_uid != getuid() || created_status.st_gid != getgid() ||
        (created_status.st_mode & 0777) != 0600 || created_status.st_nlink != 1u) {
        const Diagnostic original{FailurePhase::Create, errno};
        return lease.fail_created(original, diagnostic);
    }
    lease.source_identity_ = make_source_identity(created_status);
    lease.source_identity_known_ = true;

    if (!write_all(lease.source_fd_, exact_bytes) || fsync(lease.source_fd_) != 0 ||
        fstat(lease.source_fd_, &created_status) != 0 || !S_ISREG(created_status.st_mode) ||
        created_status.st_uid != getuid() || created_status.st_gid != getgid() ||
        (created_status.st_mode & 0777) != 0600 || created_status.st_nlink != 1u ||
        created_status.st_size < 0 ||
        static_cast<std::uint64_t>(created_status.st_size) != exact_bytes.size()) {
        const Diagnostic original{FailurePhase::Write, errno};
        return lease.fail_created(original, diagnostic);
    }
    lease.source_identity_ = make_source_identity(created_status);

    if (!close_checked(lease.source_fd_)) {
        const Diagnostic original{FailurePhase::Close, errno};
        lease.source_fd_is_created_ = false;
        return lease.fail_created(original, diagnostic);
    }
    lease.source_fd_is_created_ = false;

    if (hooks != nullptr && hooks->before_reopen != nullptr)
        hooks->before_reopen(lease.directory_fd_, lease.basename_.c_str(), hooks->context);

    lease.source_fd_ = openat(lease.directory_fd_,
                              lease.basename_.c_str(),
                              O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW);
    struct stat reader_status{};
    struct stat entry_status{};
    const bool reopened =
        lease.source_fd_ >= 0 && fstat(lease.source_fd_, &reader_status) == 0 &&
        fstatat(lease.directory_fd_, lease.basename_.c_str(), &entry_status, AT_SYMLINK_NOFOLLOW) ==
            0 &&
        same_source(reader_status, lease.source_identity_, true) &&
        same_source(entry_status, lease.source_identity_, true) && fsync(lease.directory_fd_) == 0;
    const int reopen_error = errno;
    if (!reopened) {
        const Diagnostic original{FailurePhase::Lease, reopen_error};
        return lease.fail_created(original, diagnostic);
    }

    lease.active_ = true;
    lease.state_ = State::Active;
    if (!lease.revalidate(diagnostic)) {
        const Diagnostic original = diagnostic;
        return lease.fail_created(original, diagnostic);
    }
    return true;
}

bool WildcardAttemptSourceLease::finalize_exact_bytes(const std::string& exact_bytes,
                                                      Diagnostic& diagnostic) {
    diagnostic = {};
    if (state_ != State::Staged) {
        fail(diagnostic, FailurePhase::State, state_ == State::Fresh ? EINVAL : EALREADY);
        return false;
    }
    if (exact_bytes.empty() || exact_bytes.size() > 255u ||
        exact_bytes.find('\0') != std::string::npos) {
        fail(diagnostic, FailurePhase::Argument, EINVAL);
        return false;
    }

    if (staged_hooks_.before_finalize_identity != nullptr)
        staged_hooks_.before_finalize_identity(
            directory_fd_, basename_.c_str(), writer_fd_, source_fd_, staged_hooks_.context);
    if (!validate_directory(diagnostic) ||
        !validate_staged_sources(true, true, source_identity_, diagnostic)) {
        state_ = State::FinalizeFailed;
        return false;
    }

    const auto truncate_operation = staged_hooks_.ftruncate_operation == nullptr
                                        ? real_ftruncate
                                        : staged_hooks_.ftruncate_operation;
    const auto write_operation =
        staged_hooks_.pwrite_operation == nullptr ? real_pwrite : staged_hooks_.pwrite_operation;
    const auto sync_operation =
        staged_hooks_.fsync_operation == nullptr ? real_fsync : staged_hooks_.fsync_operation;
    auto terminal = [&](FailurePhase phase, int error_number) {
        state_ = State::FinalizeFailed;
        active_ = false;
        fail(diagnostic, phase, error_number == 0 ? EIO : error_number);
        return false;
    };

    errno = 0;
    if (truncate_operation(writer_fd_, 0, staged_hooks_.context) != 0)
        return terminal(FailurePhase::Finalize, errno);
    std::size_t offset = 0u;
    unsigned write_attempts = 0u;
    while (offset < exact_bytes.size()) {
        if (write_attempts == kFinalizeWriteAttempts) return terminal(FailurePhase::Write, EAGAIN);
        ++write_attempts;
        errno = 0;
        const ssize_t count = write_operation(writer_fd_,
                                              exact_bytes.data() + offset,
                                              exact_bytes.size() - offset,
                                              static_cast<off_t>(offset),
                                              staged_hooks_.context);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0 || static_cast<std::size_t>(count) > exact_bytes.size() - offset)
            return terminal(FailurePhase::Write, count < 0 ? errno : EIO);
        offset += static_cast<std::size_t>(count);
    }
    errno = 0;
    if (truncate_operation(
            writer_fd_, static_cast<off_t>(exact_bytes.size()), staged_hooks_.context) != 0)
        return terminal(FailurePhase::Finalize, errno);
    errno = 0;
    if (sync_operation(writer_fd_, staged_hooks_.context) != 0)
        return terminal(FailurePhase::Finalize, errno);

    if (staged_hooks_.after_finalize_sync != nullptr)
        staged_hooks_.after_finalize_sync(
            directory_fd_, basename_.c_str(), writer_fd_, source_fd_, staged_hooks_.context);

    SourceIdentity candidate = source_identity_;
    candidate.size = exact_bytes.size();
    if (!validate_directory(diagnostic) ||
        !validate_staged_sources(true, false, candidate, diagnostic)) {
        state_ = State::FinalizeFailed;
        return false;
    }
    if (!read_exact_buffer(source_fd_, exact_bytes.data(), exact_bytes.size(), pread, diagnostic)) {
        state_ = State::FinalizeFailed;
        return false;
    }
    std::memcpy(staged_expected_bytes_.data(), exact_bytes.data(), exact_bytes.size());
    staged_expected_size_ = exact_bytes.size();
    source_identity_ = candidate;
    active_ = true;
    state_ = State::Active;
    return true;
}

bool WildcardAttemptSourceLease::validate_directory(Diagnostic& diagnostic) const {
    struct stat held{};
    struct stat path{};
    if (directory_fd_ < 0 || fstat(directory_fd_, &held) != 0) {
        fail(diagnostic, FailurePhase::Directory, directory_fd_ < 0 ? EBADF : errno);
        return false;
    }
    if (fstatat(AT_FDCWD, directory_path_.c_str(), &path, AT_SYMLINK_NOFOLLOW) != 0) {
        fail(diagnostic, FailurePhase::Directory, errno);
        return false;
    }
    if (!same_directory(held, directory_identity_) || !same_directory(path, directory_identity_) ||
        !descriptor_flags(directory_fd_, O_RDONLY, false)) {
        fail(diagnostic, FailurePhase::Directory, ESTALE);
        return false;
    }
    return true;
}

bool WildcardAttemptSourceLease::validate_open_source(bool require_link,
                                                      Diagnostic& diagnostic) const {
    struct stat held{};
    if (source_fd_ < 0 || fstat(source_fd_, &held) != 0) {
        fail(diagnostic, FailurePhase::Lease, source_fd_ < 0 ? EBADF : errno);
        return false;
    }
    if (!same_source(held, source_identity_, require_link) ||
        !descriptor_flags(source_fd_, O_RDONLY, true)) {
        fail(diagnostic, FailurePhase::Lease, ESTALE);
        return false;
    }
    return true;
}

bool WildcardAttemptSourceLease::validate_staged_sources(bool require_link,
                                                         bool require_empty,
                                                         const SourceIdentity& expected,
                                                         Diagnostic& diagnostic) const {
    struct stat writer{};
    struct stat reader{};
    struct stat entry{};
    if (writer_fd_ < 0 || source_fd_ < 0 || fstat(writer_fd_, &writer) != 0 ||
        fstat(source_fd_, &reader) != 0 ||
        fstatat(directory_fd_, basename_.c_str(), &entry, AT_SYMLINK_NOFOLLOW) != 0) {
        fail(diagnostic, FailurePhase::Lease, errno == 0 ? EBADF : errno);
        return false;
    }
    const bool expected_size =
        require_empty
            ? (writer.st_size == 0 && reader.st_size == 0 && entry.st_size == 0)
            : (writer.st_size >= 0 && static_cast<std::uint64_t>(writer.st_size) == expected.size);
    if (!same_source_object(writer, expected, require_link) ||
        !same_source_object(reader, expected, require_link) ||
        !same_source_object(entry, expected, require_link) || writer.st_size != reader.st_size ||
        writer.st_size != entry.st_size || !expected_size ||
        !descriptor_flags(writer_fd_, O_WRONLY, false) ||
        !descriptor_flags(source_fd_, O_RDONLY, true)) {
        fail(diagnostic, FailurePhase::Lease, ESTALE);
        return false;
    }
    return true;
}

bool WildcardAttemptSourceLease::validate_staged_detached(Diagnostic& diagnostic) const {
    struct stat writer{};
    struct stat reader{};
    struct stat entry{};
    if (!active_ || writer_fd_ < 0 || source_fd_ < 0) {
        fail(diagnostic, FailurePhase::Lease, EBADF);
        return false;
    }
    if (!validate_directory(diagnostic)) return false;
    if (fstat(writer_fd_, &writer) != 0 || fstat(source_fd_, &reader) != 0 ||
        !same_source(writer, source_identity_, false) ||
        !same_source(reader, source_identity_, false) ||
        !descriptor_flags(writer_fd_, O_WRONLY, false) ||
        !descriptor_flags(source_fd_, O_RDONLY, true)) {
        fail(diagnostic, FailurePhase::Lease, errno == 0 ? ESTALE : errno);
        return false;
    }
    if (!read_exact_bytes(diagnostic)) return false;
    errno = 0;
    if (fstatat(directory_fd_, basename_.c_str(), &entry, AT_SYMLINK_NOFOLLOW) == 0 ||
        errno != ENOENT) {
        fail(diagnostic, FailurePhase::Path, errno == 0 ? ESTALE : errno);
        return false;
    }
    return true;
}

bool WildcardAttemptSourceLease::read_exact_bytes(Diagnostic& diagnostic) const {
    if (writer_fd_ >= 0)
        return read_exact_buffer(
            source_fd_, staged_expected_bytes_.data(), staged_expected_size_, pread, diagnostic);
    return read_exact_bytes_for_testing(source_fd_, expected_bytes_, pread, diagnostic);
}

bool WildcardAttemptSourceLease::revalidate(Diagnostic& diagnostic) const {
    diagnostic = {};
    if (!active_ || state_ != State::Active || !validate_directory(diagnostic) ||
        (writer_fd_ >= 0 ? !validate_staged_sources(true, false, source_identity_, diagnostic)
                         : !validate_open_source(true, diagnostic)))
        return false;
    struct stat entry{};
    if (fstatat(directory_fd_, basename_.c_str(), &entry, AT_SYMLINK_NOFOLLOW) != 0) {
        fail(diagnostic, FailurePhase::Path, errno);
        return false;
    }
    if (!same_source(entry, source_identity_, true)) {
        fail(diagnostic, FailurePhase::Path, ESTALE);
        return false;
    }
    return read_exact_bytes(diagnostic);
}

bool WildcardAttemptSourceLease::validate_detached_after_unlink(Diagnostic& diagnostic) const {
    diagnostic = {};
    if (!active_ || !validate_directory(diagnostic) || !validate_open_source(false, diagnostic) ||
        !read_exact_bytes(diagnostic))
        return false;
    struct stat entry{};
    errno = 0;
    if (fstatat(directory_fd_, basename_.c_str(), &entry, AT_SYMLINK_NOFOLLOW) == 0 ||
        errno != ENOENT) {
        fail(diagnostic, FailurePhase::Path, errno == 0 ? ESTALE : errno);
        return false;
    }
    return true;
}

bool WildcardAttemptSourceLease::quarantine_and_remove(BoundaryHookForTesting hook,
                                                       void* context,
                                                       Diagnostic& diagnostic) {
    diagnostic = {};
    if (!cleanup_required_ || !owned_entry_known_ || directory_fd_ < 0 ||
        !validate_directory(diagnostic)) {
        if (diagnostic.phase == FailurePhase::None)
            fail(diagnostic, FailurePhase::Quarantine, ESTALE);
        return false;
    }

    SourceIdentity expected = source_identity_;
    if (!source_identity_known_) {
        struct stat held{};
        const int authority = writer_fd_ >= 0 ? writer_fd_ : source_fd_;
        if (authority < 0 || fstat(authority, &held) != 0 || !S_ISREG(held.st_mode) ||
            held.st_uid != getuid() || held.st_gid != getgid() || (held.st_mode & 0777) != 0600 ||
            held.st_nlink != 1u || held.st_size < 0) {
            fail(diagnostic, FailurePhase::Quarantine, authority < 0 ? EBADF : errno);
            return false;
        }
        expected = make_source_identity(held);
        source_identity_ = expected;
        source_identity_known_ = true;
    } else if (!active_ && source_fd_is_created_ && source_fd_ >= 0) {
        struct stat held{};
        if (fstat(source_fd_, &held) != 0 || !S_ISREG(held.st_mode) || held.st_uid != getuid() ||
            held.st_gid != getgid() || held.st_size < 0) {
            fail(diagnostic, FailurePhase::Quarantine, errno);
            return false;
        }
        expected = make_source_identity(held);
        source_identity_ = expected;
    }

    struct stat reader{};
    struct stat writer{};
    struct stat entry{};
    const bool reader_owned = source_fd_ < 0 ? writer_fd_ >= 0
                                             : (fstat(source_fd_, &reader) == 0 &&
                                                same_source_object(reader, expected, true));
    const bool writer_owned = writer_fd_ < 0 || (fstat(writer_fd_, &writer) == 0 &&
                                                 same_source_object(writer, expected, true));
    const bool entry_owned =
        fstatat(directory_fd_, owned_basename_.c_str(), &entry, AT_SYMLINK_NOFOLLOW) == 0 &&
        same_source_object(entry, expected, true);
    if (!reader_owned || !writer_owned || !entry_owned) {
        fail(diagnostic, FailurePhase::Quarantine, ESTALE);
        return false;
    }

    if (hook != nullptr) hook(directory_fd_, owned_basename_.c_str(), context);

    const std::string source_name = owned_basename_;
    std::string quarantine_name;
    int rename_error = EEXIST;
    for (unsigned attempt = 0u; attempt < kQuarantineAttempts; ++attempt) {
        if (!random_quarantine_name(quarantine_name)) {
            fail(diagnostic, FailurePhase::Quarantine, errno == 0 ? EIO : errno);
            return false;
        }
        if (rename_noreplace(
                directory_fd_, source_name.c_str(), directory_fd_, quarantine_name.c_str()) == 0) {
            rename_error = 0;
            break;
        }
        rename_error = errno;
        if (rename_error != EEXIST) break;
    }
    if (rename_error != 0) {
        fail(diagnostic, FailurePhase::Quarantine, rename_error);
        return false;
    }
    owned_basename_ = quarantine_name;

    struct stat quarantined{};
    const bool quarantine_stated =
        fstatat(directory_fd_, quarantine_name.c_str(), &quarantined, AT_SYMLINK_NOFOLLOW) == 0;
    const int quarantine_stat_error = errno;
    if (!quarantine_stated || !same_source_object(quarantined, expected, true)) {
        const int mismatch_error = quarantine_stated ? ESTALE : quarantine_stat_error;
        const int restored = rename_noreplace(
            directory_fd_, quarantine_name.c_str(), directory_fd_, source_name.c_str());
        const int restore_error = errno;
        // The quarantined object proved not to be ours. Never unlink it, even
        // when restoration is blocked by another replacement.
        owned_entry_known_ = false;
        if (restored != 0) {
            fail(diagnostic, FailurePhase::Restore, restore_error);
            return false;
        }
        if (fsync(directory_fd_) != 0) {
            fail(diagnostic, FailurePhase::Restore, errno);
            return false;
        }
        fail(diagnostic, FailurePhase::Quarantine, mismatch_error);
        return false;
    }

    if (unlinkat(directory_fd_, quarantine_name.c_str(), 0) != 0) {
        fail(diagnostic, FailurePhase::Remove, errno);
        return false;
    }
    cleanup_required_ = false;
    owned_entry_known_ = false;
    const auto cleanup_sync = staged_hooks_.cleanup_fsync_operation == nullptr
                                  ? real_fsync
                                  : staged_hooks_.cleanup_fsync_operation;
    errno = 0;
    const bool directory_synced = cleanup_sync(directory_fd_, staged_hooks_.context) == 0;
    const int sync_error = errno == 0 ? EIO : errno;
    struct stat residue{};
    errno = 0;
    const bool original_absent =
        fstatat(directory_fd_, source_name.c_str(), &residue, AT_SYMLINK_NOFOLLOW) != 0 &&
        errno == ENOENT;
    errno = 0;
    const bool quarantine_absent =
        fstatat(directory_fd_, quarantine_name.c_str(), &residue, AT_SYMLINK_NOFOLLOW) != 0 &&
        errno == ENOENT;
    const bool reader_detached = source_fd_ < 0 ? writer_fd_ >= 0
                                                : (fstat(source_fd_, &reader) == 0 &&
                                                   same_source_object(reader, expected, false));
    const bool writer_detached = writer_fd_ < 0 || (fstat(writer_fd_, &writer) == 0 &&
                                                    same_source_object(writer, expected, false));
    if (!original_absent || !quarantine_absent || !reader_detached || !writer_detached) {
        fail(diagnostic, FailurePhase::Remove, ESTALE);
        return false;
    }
    unlink_evidence_complete_ = true;
    if (!directory_synced) {
        fail(diagnostic, FailurePhase::Remove, sync_error);
        return false;
    }
    return true;
}

bool WildcardAttemptSourceLease::remove(Diagnostic& diagnostic) {
    return remove_with_hook_for_testing(nullptr, nullptr, diagnostic);
}

bool WildcardAttemptSourceLease::remove_with_hook_for_testing(BoundaryHookForTesting hook,
                                                              void* context,
                                                              Diagnostic& diagnostic) {
    diagnostic = {};
    if (state_ != State::Active && state_ != State::Staged && state_ != State::FinalizeFailed) {
        fail(diagnostic, FailurePhase::State, EINVAL);
        record_cleanup(false, diagnostic);
        return false;
    }
    if (state_ == State::Active && !revalidate(diagnostic)) {
        record_cleanup(false, diagnostic);
        return false;
    }
    owned_basename_ = basename_;
    owned_entry_known_ = true;
    const bool namespace_settled = quarantine_and_remove(hook, context, diagnostic);
    const Diagnostic namespace_diagnostic = diagnostic;
    if (!namespace_settled && cleanup_required_) {
        record_cleanup(false, diagnostic);
        return false;
    }

    const bool detached = state_ != State::Active
                              ? unlink_evidence_complete_
                              : (writer_fd_ >= 0 ? validate_staged_detached(diagnostic)
                                                 : validate_detached_after_unlink(diagnostic));
    active_ = false;
    Diagnostic close_diagnostic;
    close_descriptors(close_diagnostic);
    if (!namespace_settled)
        diagnostic = namespace_diagnostic;
    else if (detached && close_diagnostic.phase != FailurePhase::None)
        diagnostic = close_diagnostic;
    const bool succeeded =
        namespace_settled && detached && close_diagnostic.phase == FailurePhase::None;
    state_ = State::Removed;
    record_cleanup(succeeded, diagnostic);
    return succeeded;
}

bool WildcardAttemptSourceLease::fail_created(const Diagnostic& original, Diagnostic& diagnostic) {
    Diagnostic cleanup_diagnostic;
    const bool removed = quarantine_and_remove(nullptr, nullptr, cleanup_diagnostic);
    active_ = false;
    Diagnostic close_diagnostic;
    close_descriptors(close_diagnostic);
    const bool closed = close_diagnostic.phase == FailurePhase::None;
    const bool cleanup_succeeded = removed && closed;
    state_ = cleanup_succeeded ? State::Removed : State::FinalizeFailed;
    if (!removed)
        diagnostic = cleanup_diagnostic;
    else if (!closed)
        diagnostic = close_diagnostic;
    else
        diagnostic = original;
    record_cleanup(cleanup_succeeded, cleanup_succeeded ? Diagnostic{} : diagnostic);
    return false;
}

bool WildcardAttemptSourceLease::same_source_identity(
    const WildcardAttemptSourceLease& other) const {
    return active_ && other.active_ && source_identity_.device == other.source_identity_.device &&
           source_identity_.inode == other.source_identity_.inode;
}

void WildcardAttemptSourceLease::record_cleanup(bool succeeded, const Diagnostic& diagnostic) {
    if (!cleanup_state_->attempted) {
        cleanup_state_->attempted = true;
        cleanup_state_->succeeded = succeeded;
        cleanup_state_->diagnostic = diagnostic;
    } else if (!succeeded && cleanup_state_->succeeded) {
        cleanup_state_->succeeded = false;
        cleanup_state_->diagnostic = diagnostic;
    }
}

void WildcardAttemptSourceLease::close_descriptors(Diagnostic& diagnostic) {
    diagnostic = {};
    const auto close_operation =
        staged_hooks_.close_operation == nullptr ? real_close : staged_hooks_.close_operation;
    auto close_owned_source = [&](int& fd) {
        if (fd < 0) return true;
        struct stat status{};
        if (!source_identity_known_ || fstat(fd, &status) != 0 ||
            !same_owned_source_descriptor(status, source_identity_))
            return false;
        const int detached = fd;
        fd = -1;
        errno = 0;
        return close_operation(detached, staged_hooks_.context) == 0;
    };
    const bool writer_closed = close_owned_source(writer_fd_);
    const int writer_error = errno == 0 ? EIO : errno;
    const bool source_closed = close_owned_source(source_fd_);
    const int source_error = errno == 0 ? EIO : errno;
    source_fd_is_created_ = false;
    bool directory_closed = true;
    int directory_error = 0;
    if (directory_fd_ >= 0) {
        struct stat status{};
        if (fstat(directory_fd_, &status) != 0 || !same_directory(status, directory_identity_) ||
            !descriptor_flags(directory_fd_, O_RDONLY, false)) {
            directory_closed = false;
            directory_error = errno == 0 ? ESTALE : errno;
        } else {
            const int detached = directory_fd_;
            directory_fd_ = -1;
            errno = 0;
            directory_closed = close_operation(detached, staged_hooks_.context) == 0;
            directory_error = errno == 0 ? EIO : errno;
        }
    }
    if (!writer_closed || !source_closed || !directory_closed)
        fail(diagnostic,
             FailurePhase::Close,
             !writer_closed ? writer_error : (!source_closed ? source_error : directory_error));
}

}  // namespace rut::test::fixture_wildcard_source_lease
