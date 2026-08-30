#include "fixture_wildcard_source_lease.h"

#include <array>
#include <cerrno>
#include <cstdio>
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
    diagnostic = {};
    std::array<char, 256> buffer{};
    if (fd < 0 || operation == nullptr || expected.empty() || expected.size() >= buffer.size()) {
        fail(diagnostic, FailurePhase::Bytes, EINVAL);
        return false;
    }
    std::size_t offset = 0u;
    while (offset < expected.size()) {
        const ssize_t count = retrying_pread(operation,
                                             fd,
                                             buffer.data() + offset,
                                             expected.size() - offset,
                                             static_cast<off_t>(offset));
        if (count <= 0) {
            fail(diagnostic, FailurePhase::Bytes, count < 0 ? errno : EIO);
            return false;
        }
        offset += static_cast<std::size_t>(count);
    }
    char trailing = '\0';
    const ssize_t trailing_count =
        retrying_pread(operation, fd, &trailing, 1u, static_cast<off_t>(expected.size()));
    if (trailing_count < 0 || trailing_count != 0 ||
        std::string(buffer.data(), expected.size()) != expected) {
        fail(diagnostic, FailurePhase::Bytes, trailing_count < 0 ? errno : EINVAL);
        return false;
    }
    return true;
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

bool WildcardAttemptSourceLease::create_impl(int identity_bound_directory_fd,
                                             const std::string& directory_path,
                                             const std::string& basename,
                                             const fixture_privileged_listener::ListenerPlan& plan,
                                             const SourceLeaseHooksForTesting* hooks,
                                             WildcardAttemptSourceLease& lease,
                                             Diagnostic& diagnostic) {
    diagnostic = {};
    if (lease.active_ || lease.cleanup_required_ || lease.directory_fd_ >= 0 ||
        lease.source_fd_ >= 0 || identity_bound_directory_fd < 0 || directory_path.empty() ||
        directory_path.find('\0') != std::string::npos || directory_path.front() != '/' ||
        directory_path.back() == '/' || !safe_path_component(basename)) {
        fail(diagnostic, FailurePhase::Argument, EINVAL);
        return false;
    }

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
    lease.expected_bytes_ = expected;
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

    if (!write_all(lease.source_fd_, expected) || fsync(lease.source_fd_) != 0 ||
        fstat(lease.source_fd_, &created_status) != 0 || !S_ISREG(created_status.st_mode) ||
        created_status.st_uid != getuid() || created_status.st_gid != getgid() ||
        (created_status.st_mode & 0777) != 0600 || created_status.st_nlink != 1u ||
        created_status.st_size < 0 ||
        static_cast<std::uint64_t>(created_status.st_size) != expected.size()) {
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
    if (!lease.revalidate(diagnostic)) {
        const Diagnostic original = diagnostic;
        return lease.fail_created(original, diagnostic);
    }
    return true;
}

bool WildcardAttemptSourceLease::validate_directory(Diagnostic& diagnostic) const {
    struct stat held{};
    struct stat path{};
    if (directory_fd_ < 0 || fstat(directory_fd_, &held) != 0) {
        fail(diagnostic, FailurePhase::Directory, directory_fd_ < 0 ? EBADF : errno);
        return false;
    }
    const int path_fd =
        open(directory_path_.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (path_fd < 0) {
        fail(diagnostic, FailurePhase::Directory, errno);
        return false;
    }
    if (fstat(path_fd, &path) != 0) {
        const int error_number = errno;
        (void)close(path_fd);
        fail(diagnostic, FailurePhase::Directory, error_number);
        return false;
    }
    if (!same_directory(held, directory_identity_) || !same_directory(path, directory_identity_)) {
        (void)close(path_fd);
        fail(diagnostic, FailurePhase::Directory, ESTALE);
        return false;
    }
    if (close(path_fd) != 0) {
        fail(diagnostic, FailurePhase::Close, errno);
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
    if (!same_source(held, source_identity_, require_link)) {
        fail(diagnostic, FailurePhase::Lease, ESTALE);
        return false;
    }
    return true;
}

bool WildcardAttemptSourceLease::read_exact_bytes(Diagnostic& diagnostic) const {
    return read_exact_bytes_for_testing(source_fd_, expected_bytes_, pread, diagnostic);
}

bool WildcardAttemptSourceLease::revalidate(Diagnostic& diagnostic) const {
    diagnostic = {};
    if (!active_ || !validate_directory(diagnostic) || !validate_open_source(true, diagnostic))
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
        if (!source_fd_is_created_ || source_fd_ < 0 || fstat(source_fd_, &held) != 0 ||
            !S_ISREG(held.st_mode) || held.st_uid != getuid() || held.st_gid != getgid() ||
            held.st_size < 0) {
            fail(diagnostic, FailurePhase::Quarantine, source_fd_ < 0 ? EBADF : errno);
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
    if (!quarantine_stated || !same_source(quarantined, expected, true)) {
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
    if (fsync(directory_fd_) != 0) {
        fail(diagnostic, FailurePhase::Remove, errno);
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
    if (!active_) {
        fail(diagnostic, FailurePhase::Argument, EINVAL);
        record_cleanup(false, diagnostic);
        return false;
    }
    if (!revalidate(diagnostic)) {
        record_cleanup(false, diagnostic);
        return false;
    }
    owned_basename_ = basename_;
    owned_entry_known_ = true;
    if (!quarantine_and_remove(hook, context, diagnostic)) {
        record_cleanup(false, diagnostic);
        return false;
    }

    const bool detached = validate_detached_after_unlink(diagnostic);
    active_ = false;
    Diagnostic close_diagnostic;
    close_descriptors(close_diagnostic);
    if (detached && close_diagnostic.phase != FailurePhase::None) diagnostic = close_diagnostic;
    const bool succeeded = detached && close_diagnostic.phase == FailurePhase::None;
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
    } else if (!succeeded) {
        cleanup_state_->succeeded = false;
        cleanup_state_->diagnostic = diagnostic;
    }
}

void WildcardAttemptSourceLease::close_descriptors(Diagnostic& diagnostic) {
    const bool source_closed = close_checked(source_fd_);
    const int source_error = errno;
    source_fd_is_created_ = false;
    const bool directory_closed = close_checked(directory_fd_);
    if (!source_closed || !directory_closed)
        fail(diagnostic, FailurePhase::Close, !source_closed ? source_error : errno);
}

}  // namespace rut::test::fixture_wildcard_source_lease
