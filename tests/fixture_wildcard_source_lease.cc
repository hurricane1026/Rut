#include "fixture_wildcard_source_lease.h"

#include <array>
#include <cerrno>
#include <cstdio>
#include <limits>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace rut::test::fixture_wildcard_source_lease {
namespace {

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

}  // namespace

WildcardAttemptSourceLease::WildcardAttemptSourceLease()
    : cleanup_state_(std::make_shared<CleanupState>()) {}

WildcardAttemptSourceLease::~WildcardAttemptSourceLease() {
    if (active_) {
        Diagnostic diagnostic;
        if (!remove(diagnostic)) {
            record_cleanup(false, diagnostic);
            std::fprintf(stderr,
                         "FAIL [#377 wildcard source lease destructor]: phase=%u errno=%d\n",
                         static_cast<unsigned>(diagnostic.phase),
                         diagnostic.error_number);
        }
    }
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
    diagnostic = {};
    if (lease.active_ || lease.directory_fd_ >= 0 || lease.source_fd_ >= 0 ||
        identity_bound_directory_fd < 0 || directory_path.empty() ||
        directory_path.front() != '/' || directory_path.back() == '/' ||
        !safe_path_component(basename)) {
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
    if (path_directory >= 0) close(path_directory);
    if (!directory_ok) {
        if (retained_directory >= 0) close(retained_directory);
        fail(diagnostic, FailurePhase::Directory, directory_error);
        return false;
    }

    struct stat created_status{};
    int writer = openat(retained_directory,
                        basename.c_str(),
                        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                        0600);
    if (writer < 0) {
        const int error_number = errno;
        close(retained_directory);
        fail(diagnostic, FailurePhase::Create, error_number);
        return false;
    }

    bool created = fstat(writer, &created_status) == 0;
    if (!created || !write_all(writer, expected) || fsync(writer) != 0 ||
        fstat(writer, &created_status) != 0 || !S_ISREG(created_status.st_mode) ||
        created_status.st_uid != getuid() || created_status.st_gid != getgid() ||
        (created_status.st_mode & 0777) != 0600 || created_status.st_nlink != 1u ||
        created_status.st_size < 0 ||
        static_cast<std::uint64_t>(created_status.st_size) != expected.size()) {
        const int error_number = errno;
        close(writer);
        struct stat current{};
        if (created &&
            fstatat(retained_directory, basename.c_str(), &current, AT_SYMLINK_NOFOLLOW) == 0 &&
            current.st_dev == created_status.st_dev && current.st_ino == created_status.st_ino)
            (void)unlinkat(retained_directory, basename.c_str(), 0);
        close(retained_directory);
        fail(diagnostic, FailurePhase::Write, error_number);
        return false;
    }
    if (close(writer) != 0) {
        const int error_number = errno;
        (void)unlinkat(retained_directory, basename.c_str(), 0);
        close(retained_directory);
        fail(diagnostic, FailurePhase::Close, error_number);
        return false;
    }
    writer = -1;

    const int reader =
        openat(retained_directory, basename.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    struct stat reader_status{};
    struct stat entry_status{};
    const SourceIdentity expected_identity = make_source_identity(created_status);
    const bool reopened =
        reader >= 0 && fstat(reader, &reader_status) == 0 &&
        fstatat(retained_directory, basename.c_str(), &entry_status, AT_SYMLINK_NOFOLLOW) == 0 &&
        same_source(reader_status, expected_identity, true) &&
        same_source(entry_status, expected_identity, true) && fsync(retained_directory) == 0;
    const int reopen_error = errno;
    if (!reopened) {
        if (reader >= 0) close(reader);
        struct stat current{};
        if (fstatat(retained_directory, basename.c_str(), &current, AT_SYMLINK_NOFOLLOW) == 0 &&
            current.st_dev == created_status.st_dev && current.st_ino == created_status.st_ino)
            (void)unlinkat(retained_directory, basename.c_str(), 0);
        close(retained_directory);
        fail(diagnostic, FailurePhase::Lease, reopen_error);
        return false;
    }

    lease.directory_fd_ = retained_directory;
    lease.source_fd_ = reader;
    lease.active_ = true;
    lease.directory_path_ = directory_path;
    lease.basename_ = basename;
    lease.path_ = directory_path + "/" + basename;
    lease.expected_bytes_ = expected;
    lease.directory_identity_ = make_directory_identity(directory_status);
    lease.source_identity_ = expected_identity;
    lease.cleanup_state_ = std::make_shared<CleanupState>();
    if (!lease.revalidate(diagnostic)) {
        Diagnostic cleanup_diagnostic;
        (void)lease.remove(cleanup_diagnostic);
        return false;
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
        close(path_fd);
        fail(diagnostic, FailurePhase::Directory, error_number);
        return false;
    }
    if (!same_directory(held, directory_identity_) || !same_directory(path, directory_identity_)) {
        close(path_fd);
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
    std::array<char, 256> buffer{};
    if (expected_bytes_.empty() || expected_bytes_.size() >= buffer.size()) {
        fail(diagnostic, FailurePhase::Bytes, EOVERFLOW);
        return false;
    }
    std::size_t offset = 0u;
    while (offset < expected_bytes_.size()) {
        const ssize_t count = pread(source_fd_,
                                    buffer.data() + offset,
                                    expected_bytes_.size() - offset,
                                    static_cast<off_t>(offset));
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) {
            fail(diagnostic, FailurePhase::Bytes, count < 0 ? errno : EIO);
            return false;
        }
        offset += static_cast<std::size_t>(count);
    }
    char trailing = '\0';
    const ssize_t trailing_count =
        pread(source_fd_, &trailing, 1u, static_cast<off_t>(expected_bytes_.size()));
    if (trailing_count < 0 || trailing_count != 0 ||
        std::string(buffer.data(), expected_bytes_.size()) != expected_bytes_) {
        fail(diagnostic, FailurePhase::Bytes, trailing_count < 0 ? errno : EINVAL);
        return false;
    }
    return true;
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
        fail(diagnostic, FailurePhase::Path, errno);
        return false;
    }
    return true;
}

bool WildcardAttemptSourceLease::remove(Diagnostic& diagnostic) {
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
    if (unlinkat(directory_fd_, basename_.c_str(), 0) != 0) {
        fail(diagnostic, FailurePhase::Remove, errno);
        record_cleanup(false, diagnostic);
        return false;
    }
    struct stat entry{};
    errno = 0;
    if (fstatat(directory_fd_, basename_.c_str(), &entry, AT_SYMLINK_NOFOLLOW) == 0 ||
        errno != ENOENT || fsync(directory_fd_) != 0) {
        fail(diagnostic, FailurePhase::Remove, errno);
        record_cleanup(false, diagnostic);
        return false;
    }
    active_ = false;
    close_descriptors(diagnostic);
    const bool succeeded = diagnostic.phase == FailurePhase::None;
    record_cleanup(succeeded, diagnostic);
    return succeeded;
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
    }
}

void WildcardAttemptSourceLease::close_descriptors(Diagnostic& diagnostic) {
    const bool source_closed = close_checked(source_fd_);
    const int source_error = errno;
    const bool directory_closed = close_checked(directory_fd_);
    if (!source_closed || !directory_closed)
        fail(diagnostic, FailurePhase::Close, !source_closed ? source_error : errno);
}

}  // namespace rut::test::fixture_wildcard_source_lease
